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
        'asm_opaque': (['clang', '-nostdlib', '-o'], ['asm_opaque.s'], 0),
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
    """Switch-table xrefs only (`native-import:switch` provenance)."""
    return xref_map(project,
                    "provenance = 'native-import:switch'")


def computed_jumps(project: Path) -> dict[int, set[int]]:
    """Computed jumps resolved outside switch recovery (e.g. constant
    propagation). Switch recovery explicitly skips these branches
    (`native.rs` computed-jump exclusion), so a switch-only query is
    blind to them -- including genuinely recovered stub edges."""
    return xref_map(project,
                    "kind = 'COMPUTED_JUMP' AND provenance != 'native-import:switch'")


def xref_map(project: Path, predicate: str) -> dict[int, set[int]]:
    connection = sqlite3.connect(project / 'project.sqlite')
    try:
        tables: dict[int, set[int]] = {}
        for source, destination in connection.execute(
                f'SELECT src, dst FROM xrefs WHERE {predicate}'):
            tables.setdefault(int(source, 16), set()).add(int(destination, 16))
        return tables
    finally:
        connection.close()

def check_exact(name, got, branch, cases, results, mandatory):
    """Exact-set check against annotations, never owner/decode scoring.

    `mandatory` fixtures (baseline capability) fail when the branch is
    missing entirely; refusal-allowed fixtures record the refusal as a
    separate outcome. Anything else is a wrong edge and fails.
    """
    if got.get(branch, set()) == set(cases):
        results[name] = {'outcome': 'exact', 'targets': len(cases)}
    elif branch not in got:
        if mandatory:
            results[name] = {'outcome': 'WRONG',
                             'expected': sorted(cases), 'recovered': []}
            raise AssertionError(f'{name}: wrong edges: {results[name]}')
        results[name] = {'outcome': 'refused'}
    else:
        results[name] = {'outcome': 'WRONG',
                         'expected': sorted(cases),
                         'recovered': sorted(got[branch])}
        raise AssertionError(f'{name}: wrong edges: {results[name]}')


def assert_no_computed(name, project, branch, results):
    """Pin a branch absent from non-switch computed jumps."""
    found = computed_jumps(project).get(branch, set())
    if found:
        results[name] = {'outcome': 'WRONG', 'computed': sorted(found)}
        raise AssertionError(f'{name}: wrong edges: {results[name]}')
def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    # Negative control: the mandatory path must reject empty recovery.
    # If this passes silently, every fixture below is vacuous.
    try:
        check_exact('__control__', {}, 0x1000, [0x2000], {}, True)
    except AssertionError:
        pass
    else:
        raise SystemExit('negative control failed: empty recovery accepted')
    results: dict[str, dict] = {}
    results['__control__'] = {'outcome': 'rejects-empty'}
    with tempfile.TemporaryDirectory(prefix='romwright-m18-robust-') as temporary:
        work = Path(temporary)
        binaries = build(work)
        blob_len = binaries.pop('__blob_len__')
        projects: dict[str, Path] = {}
        for name, binary in binaries.items():
            project = work / f'{name}.project'
            run([str(CLI), 'import', str(binary), '--name', name,
                 '--project', str(project)])
            projects[name] = project
        # Baseline capability: missing branch fails, not "refused".
        # Every fixture also pins its branch absent from non-switch
        # computed jumps: recovery must flow through switch_tables,
        # not a parallel resolution path the switch query can't see.
        table = symbols(binaries['asm_table'])
        project = projects['asm_table']
        check_exact('asm_table', switch_xrefs(project),
                    table['br_dispatch'],
                    [table[f'case{i}'] for i in range(5)], results, True)
        assert_no_computed('asm_table', project, table['br_dispatch'], results)
        table = symbols(binaries['asm_flat'])
        project = projects['asm_flat']
        check_exact('asm_flat', switch_xrefs(project),
                    table['br_flat'], [table['state0'], table['state1']], results, False)
        assert_no_computed('asm_flat', project, table['br_flat'], results)
        table = symbols(binaries['asm_opaque'])
        project = projects['asm_opaque']
        check_exact('asm_opaque', switch_xrefs(project),
                    table['br_opq'], [table[f'c{i}'] for i in range(4)], results, False)
        assert_no_computed('asm_opaque', project, table['br_opq'], results)
        # Runtime truth is sm_case1 (the store executes before the
        # jump; exit code 11 proves it). The at-rest sm_case0 alone
        # is a stale-pointer wrong edge; absence is refusal.
        table = symbols(binaries['selfmod'])
        project = projects['selfmod']
        got = switch_xrefs(project)
        branch, stale, live = table['br_sm'], table['sm_case0'], table['sm_case1']
        if got.get(branch, set()) == {live}:
            results['selfmod'] = {'outcome': 'exact-live'}
        elif branch not in got:
            results['selfmod'] = {'outcome': 'refused'}
        else:
            results['selfmod'] = {'outcome': 'WRONG', 'recovered': sorted(got[branch])}
            raise AssertionError(f"selfmod: wrong edges: {results['selfmod']}")
        assert_no_computed('selfmod', project, branch, results)
        # The decoder stub resolves by constant propagation
        # (br_dec -> codebuf), which switch recovery explicitly
        # skips -- a switch-only query is blind to it. That edge is
        # statically sound (the stub unconditionally jumps there);
        # the blob itself must stay untouched by every xref kind.
        table = symbols(binaries['packed'])
        project = projects['packed']
        blob, codebuf = table['blob'], table['codebuf']
        branch = table['br_dec']
        stub = computed_jumps(project).get(branch, set())
        if stub != {codebuf}:
            results['packed'] = {'outcome': 'WRONG', 'stub': sorted(stub)}
            raise AssertionError(f"packed: stub edge wrong: {results['packed']}")
        all_xrefs = switch_xrefs(project)
        for source, targets in computed_jumps(project).items():
            all_xrefs.setdefault(source, set()).update(targets)
        bad = [(f'{s:x}', f'{d:x}') for s, targets in all_xrefs.items() for d in targets
               if (s, d) != (branch, codebuf)
               and (blob <= s < blob + blob_len or blob <= d < blob + blob_len
                    or codebuf <= d < codebuf + blob_len)]
        if bad:
            results['packed'] = {'outcome': 'WRONG', 'touches': bad}
            raise AssertionError(f'packed: xrefs into blob/codebuf: {bad}')
        results['packed'] = {'outcome': 'stub-resolved'}
        summary = {name: result['outcome'] for name, result in results.items()}
        print(json.dumps(summary))
        if args.report:
            args.report.write_text(json.dumps(dict(results=results), indent=2) + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
