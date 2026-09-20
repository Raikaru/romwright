#!/usr/bin/env python3
"""m18-001: robustness dispatch fixtures, scored against annotations.

Hand-built x86-64 assembly with nm-extracted ground truth -- no stock
oracle. Each fixture declares its branch label and case labels; the gate
compares the store's `native-import:switch` xref sets against the
annotated sets exactly. Fixtures whose recovery is legitimately beyond
the analysis (loop-carried state, runtime-patched pointers, encoded
bytes) accept refusal as a passing outcome, recorded separately from
exact recovery. Anything else -- a wrong edge -- fails.

Fixtures (tests/fixtures-src/robust/):
  asm_table.s   guarded PIC table, exact: br_dispatch -> case0..4
  asm_flat.s    loop-carried flattened dispatch: exact or refuse
  asm_opaque.s  opaque predicate + table: exact or refuse
  selfmod.s     runtime-patched pointer: sm_case1 must never be claimed
  packed        XOR blob + decoder stub: no xrefs into blob/codebuf
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / 'tests' / 'fixtures-src' / 'robust'
CLI = ROOT / 'target' / 'release' / 'romwright-cli'


def run(command, **kwargs):
    return subprocess.run(command, cwd=ROOT, text=True, capture_output=True,
                          check=True, timeout=180, **kwargs)


def build(work: Path) -> dict[str, Path]:
    binaries = {}
    plans = {
        'asm_table': (['clang', '-nostdlib', '-o'], ['asm_table.s'], 102),
        'asm_flat': (['clang', '-nostdlib', '-o'], ['asm_flat.s'], 0),
        'asm_opaque': (['clang', '-nostdlib', '-o'], ['asm_opaque.s'], 201),
        'selfmod': (['clang', '-nostdlib', '-o'], ['selfmod.s'], 11),
    }
    for name, (prefix, sources, exit_code) in plans.items():
        out = work / f'{name}.bin'
        run([*prefix, str(out), *[str(SRC / s) for s in sources]])
        completed = subprocess.run([str(out)], capture_output=True, timeout=30)
        assert completed.returncode == exit_code, (name, completed.returncode)
        binaries[name] = out
    payload = work / 'payload.o'
    run(['clang', '-c', str(SRC / 'asm_table.s'), '-o', str(payload)])
    packed_src = work / 'packed.s'
    proc = run([sys.executable, str(SRC / 'pack_gen.py'), str(payload), str(packed_src)])
    blob_len = int(proc.stdout.split()[1])
    packed = work / 'packed.bin'
    run(['clang', '-nostdlib', '-o', str(packed), str(packed_src)])
    binaries['packed'] = packed
    binaries['__blob_len__'] = blob_len
    return binaries


def symbols(binary: Path) -> dict[str, int]:
    out = run(['nm', '-P', str(binary)]).stdout
    table = {}
    for line in out.splitlines():
        row = line.split()
        if len(row) >= 3 and row[1] in 'TtDdRrBb':
            table[row[0]] = int(row[2], 16)
    return table


def switch_xrefs(project: Path) -> dict[int, set[int]]:
    connection = sqlite3.connect(project / 'project.sqlite')
    try:
        tables: dict[int, set[int]] = {}
        for source, destination in connection.execute(
                "SELECT src, dst FROM xrefs WHERE provenance = 'native-import:switch'"):
            tables.setdefault(int(source, 16), set()).add(int(destination, 16))
        return tables
    finally:
        connection.close()


def check_exact(name: str, got: dict[int, set[int]], branch: int,
                cases: list[int], results: dict) -> None:
    if got.get(branch, set()) == set(cases):
        results[name] = {'outcome': 'exact', 'targets': len(cases)}
    elif branch not in got:
        results[name] = {'outcome': 'refused'}
    else:
        results[name] = {'outcome': 'WRONG',
                         'expected': sorted(cases),
                         'recovered': sorted(got[branch])}
        raise AssertionError(f'{name}: wrong edges: {results[name]}')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='romwright-m18-robust-') as temporary:
        work = Path(temporary)
        binaries = build(work)
        blob_len = binaries.pop('__blob_len__')
        results: dict[str, dict] = {}
        projects: dict[str, Path] = {}
        for name, binary in binaries.items():
            project = work / f'{name}.project'
            run([str(CLI), 'import', str(binary), '--name', name,
                 '--project', str(project)])
            projects[name] = project
        table = symbols(binaries['asm_table'])
        check_exact('asm_table', switch_xrefs(projects['asm_table']),
                    table['br_dispatch'],
                    [table[f'case{i}'] for i in range(5)], results)
        table = symbols(binaries['asm_flat'])
        check_exact('asm_flat', switch_xrefs(projects['asm_flat']),
                    table['br_flat'], [table['state0'], table['state1']], results)
        table = symbols(binaries['asm_opaque'])
        check_exact('asm_opaque', switch_xrefs(projects['asm_opaque']),
                    table['br_opq'], [table[f'c{i}'] for i in range(4)], results)
        table = symbols(binaries['selfmod'])
        got = switch_xrefs(projects['selfmod'])
        branch, live, patched = table['br_sm'], table['sm_case0'], table['sm_case1']
        if got.get(branch, set()) == {live}:
            results['selfmod'] = {'outcome': 'exact-at-rest'}
        elif branch not in got:
            results['selfmod'] = {'outcome': 'refused'}
        else:
            results['selfmod'] = {'outcome': 'WRONG', 'recovered': sorted(got[branch])}
            assert patched not in got.get(branch, set()), f'selfmod: claimed runtime-only {patched:x}'
            raise AssertionError(f"selfmod: wrong edges: {results['selfmod']}")
        table = symbols(binaries['packed'])
        blob, codebuf = table['blob'], table['codebuf']
        got = switch_xrefs(projects['packed'])
        bad = [(f'{s:x}', f'{d:x}') for s, targets in got.items() for d in targets
               if blob <= s < blob + blob_len or blob <= d < blob + blob_len
               or codebuf <= d < codebuf + blob_len]
        if bad:
            results['packed'] = {'outcome': 'WRONG', 'touches': bad}
            raise AssertionError(f'packed: xrefs into blob/codebuf: {bad}')
        results['packed'] = {'outcome': 'refused-blob', 'switch_xrefs': sum(len(t) for t in got.values())}
        summary = {name: result['outcome'] for name, result in results.items()}
        print(json.dumps(summary))
        if args.report:
            args.report.write_text(json.dumps(dict(results=results), indent=2) + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
