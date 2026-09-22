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
import os
import shutil
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
        'asm_overlap': (['clang', '-nostdlib', '-o'], ['asm_overlap.s'], 121),
        'selfmod': (['clang', '-nostdlib', '-o'], ['selfmod.s'], 11),
        'asm_call': (['clang', '-nostdlib', '-o'], ['asm_call.s'], 7),
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
    # Second packer family: ADD-encoded blob with a subb-loop stub
    # jumping through %rdx instead of %rdi. Same contract as packed:
    # stub edge resolves, blob and codebuf stay untouched.
    repacked_src = work / 'repack.s'
    proc = run([sys.executable, str(SRC / 'pack_gen.py'), str(payload),
                str(repacked_src), '--encoding', 'add'])
    repack_blob_len = int(proc.stdout.split()[1])
    repacked = work / 'repack.bin'
    run(['clang', '-nostdlib', '-o', str(repacked), str(repacked_src)])
    binaries['repack'] = repacked
    binaries['__repack_blob_len__'] = repack_blob_len
    # Executable packed binary: self-contained PIC payload decoded
    # into mmap'd RWX and CALLED. Exit 102 proves end-to-end
    # execution of the decoded bytes (dispatch(2) == 102).
    payload_x = work / 'payload_exec.o'
    run(['clang', '-c', str(SRC / 'payload_exec.s'), '-o', str(payload_x)])
    packed_x_src = work / 'packed_exec.s'
    proc = run([sys.executable, str(SRC / 'pack_exec.py'), str(payload_x), str(packed_x_src)])
    blob_x_len = int(proc.stdout.split()[1])
    packed_x = work / 'packed_exec.bin'
    run(['clang', '-nostdlib', '-o', str(packed_x), str(packed_x_src)])
    completed = subprocess.run([str(packed_x)], capture_output=True, timeout=30)
    assert completed.returncode == 102, ('packed_exec', completed.returncode)
    binaries['packed_exec'] = packed_x
    binaries['__blob_x_len__'] = blob_x_len
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
    """Computed jumps AND calls resolved outside switch recovery (e.g.
    constant propagation; calls emit COMPUTED_CALL). Switch recovery
    explicitly skips these branches, so a switch-only query is blind
    to them -- including genuinely recovered stub edges and wrong
    call targets alike (`br_exec` is CALLIND)."""
    return xref_map(project,
                    "kind IN ('COMPUTED_JUMP', 'COMPUTED_CALL')"
                    " AND provenance != 'native-import:switch'")


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

def check_packed_exec(project, table, blob_len, results, key):
    """Executable packed binary: `call *%r15` targets an mmap return,
    so any claimed edge is wrong; the blob must stay untouched by
    control-flow xrefs (switch, COMPUTED_JUMP, COMPUTED_CALL)."""
    xblob = table['blob']
    branch = table['br_exec']
    all_xrefs = switch_xrefs(project)
    for source, targets in computed_jumps(project).items():
        all_xrefs.setdefault(source, set()).update(targets)
    if branch in all_xrefs:
        results[key] = {'outcome': 'WRONG',
                        'recovered': sorted(all_xrefs[branch])}
        raise AssertionError(f'{key}: wrong edges: {results[key]}')
    bad = [(f'{s:x}', f'{d:x}') for s, targets in all_xrefs.items() for d in targets
           if xblob <= s < xblob + blob_len or xblob <= d < xblob + blob_len]
    if bad:
        results[key] = {'outcome': 'WRONG', 'touches': bad}
        raise AssertionError(f'{key}: xrefs into blob: {bad}')
    results[key] = {'outcome': 'exec-refused'}


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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    # The abstract interpretation runs here: it can only add tables
    # (never remove worker rows), and the union scoring absorbs both.
    # The cache stays off so every run measures real phase work.
    os.environ['ROMWRIGHT_SJA'] = '1'
    os.environ['ROMWRIGHT_NO_IMPORT_CACHE'] = '1'
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
        blob_x_len = binaries.pop('__blob_x_len__')
        repack_blob_len = binaries.pop('__repack_blob_len__')
        projects: dict[str, Path] = {}
        for name, binary in binaries.items():
            project = work / f'{name}.project'
            run([str(CLI), 'import', str(binary), '--name', name,
                 '--project', str(project)])
            projects[name] = project
        # Each annotated branch is scored on the UNION of switch and
        # non-switch computed jumps: recovery through either path
        # counts (a future br_sm -> sm_case1 constant-propagation hit
        # is the exact-live recovery we want, not a violation), and
        # anything outside the oracle is a wrong edge.
        def union(project):
            merged = switch_xrefs(project)
            for source, targets in computed_jumps(project).items():
                merged.setdefault(source, set()).update(targets)
            return merged
        # Baseline capability: missing branch fails, not "refused".
        table = symbols(binaries['asm_table'])
        check_exact('asm_table', union(projects['asm_table']),
                    table['br_dispatch'],
                    [table[f'case{i}'] for i in range(5)], results, True)
        table = symbols(binaries['asm_flat'])
        check_exact('asm_flat', union(projects['asm_flat']),
                    table['br_flat'], [table['state0'], table['state1']], results, False)
        table = symbols(binaries['asm_opaque'])
        check_exact('asm_opaque', union(projects['asm_opaque']),
                    table['br_opq'], [table[f'c{i}'] for i in range(4)], results, False)
        # Mid-instruction entry: only table-driven decoding reaches real1.
        # Refusal is honest (adversarial entry); a ghost edge from linear
        # misdecode is a wrong edge and fails.
        table = symbols(binaries['asm_overlap'])
        check_exact('asm_overlap', union(projects['asm_overlap']),
                    table['br_over'], [table['case0'], table['real1']], results, False)
        # Odd-address indirect call: the target must keep bit 0 and
        # the call kind. The fixture is only valid with an odd
        # target; assert that first so the check can't pass vacuously.
        table = symbols(binaries['asm_call'])
        assert table['oddtarget'] & 1, table
        check_exact('asm_call', union(projects['asm_call']),
                    table['br_call'], [table['oddtarget']], results, True)
        kinds = sqlite3.connect(projects['asm_call'] / 'project.sqlite').execute(
            'SELECT DISTINCT kind FROM xrefs WHERE src = ?',
            (f'{table["br_call"]:08x}',)).fetchall()
        assert ('COMPUTED_CALL',) in kinds, kinds
        # Runtime truth is sm_case1 (the store executes before the
        # jump; exit code 11 proves it). The at-rest sm_case0 alone
        # is a stale-pointer wrong edge; absence is refusal.
        table = symbols(binaries['selfmod'])
        got = union(projects['selfmod'])
        branch, stale, live = table['br_sm'], table['sm_case0'], table['sm_case1']
        if got.get(branch, set()) == {live}:
            results['selfmod'] = {'outcome': 'exact-live'}
        elif branch not in got:
            results['selfmod'] = {'outcome': 'refused'}
        else:
            results['selfmod'] = {'outcome': 'WRONG', 'recovered': sorted(got[branch])}
            raise AssertionError(f"selfmod: wrong edges: {results['selfmod']}")
        # The decoder stub resolves by constant propagation
        # (br_dec -> codebuf): scored in the same union, sound (the
        # stub unconditionally jumps there); the blob itself must
        # stay untouched by every xref kind.
        table = symbols(binaries['packed'])
        project = projects['packed']
        blob, codebuf = table['blob'], table['codebuf']
        branch = table['br_dec']
        all_xrefs = union(project)
        if all_xrefs.get(branch, set()) != {codebuf}:
            results['packed'] = {'outcome': 'WRONG', 'stub': sorted(all_xrefs.get(branch, set()))}
            raise AssertionError(f"packed: stub edge wrong: {results['packed']}")
        bad = [(f'{s:x}', f'{d:x}') for s, targets in all_xrefs.items() for d in targets
               if (s, d) != (branch, codebuf)
               and (blob <= s < blob + blob_len or blob <= d < blob + blob_len
                    or codebuf <= d < codebuf + blob_len)]
        if bad:
            results['packed'] = {'outcome': 'WRONG', 'touches': bad}
            raise AssertionError(f'packed: xrefs into blob/codebuf: {bad}')
        results['packed'] = {'outcome': 'stub-resolved'}
        # Second packer family (ADD blob, subb loop, jmp through %rdx):
        # same contract -- stub edge exact, blob and codebuf untouched.
        table = symbols(binaries['repack'])
        project = projects['repack']
        blob, codebuf = table['blob'], table['codebuf']
        branch = table['br_dec']
        all_xrefs = union(project)
        if all_xrefs.get(branch, set()) != {codebuf}:
            results['repack'] = {'outcome': 'WRONG', 'stub': sorted(all_xrefs.get(branch, set()))}
            raise AssertionError(f"repack: stub edge wrong: {results['repack']}")
        bad = [(f'{s:x}', f'{d:x}') for s, targets in all_xrefs.items() for d in targets
               if (s, d) != (branch, codebuf)
               and (blob <= s < blob + repack_blob_len or blob <= d < blob + repack_blob_len
                    or codebuf <= d < codebuf + repack_blob_len)]
        if bad:
            results['repack'] = {'outcome': 'WRONG', 'touches': bad}
            raise AssertionError(f'repack: xrefs into blob/codebuf: {bad}')
        results['repack'] = {'outcome': 'stub-resolved'}
        # payload ran): the `call *%r15` target is an mmap return no
        # static analysis can know, so any claimed edge is wrong;
        # the blob must stay untouched by control-flow xrefs (switch,
        # COMPUTED_JUMP, COMPUTED_CALL -- DATA/READ references to the
        # blob are legitimate: the decoder reads it).
        table = symbols(binaries['packed_exec'])
        check_packed_exec(projects['packed_exec'], table, blob_x_len,
                          results, 'packed_exec')
        # Negative control: an injected wrong COMPUTED_CALL at br_exec
        # must fail the check -- proving it is not blind to call
        # resolution the way the switch-only query was.
        tampered = work / 'packed_exec.tamper'
        shutil.copytree(projects['packed_exec'], tampered)
        connection = sqlite3.connect(tampered / 'project.sqlite')
        try:
            program = connection.execute('SELECT id FROM programs LIMIT 1').fetchone()[0]
            connection.execute(
                'INSERT INTO xrefs (program_id, src, dst, kind, provenance)'
                " VALUES (?, ?, ?, 'COMPUTED_CALL', 'native-analysis:constant-propagation')",
                (program, f'{table["br_exec"]:08x}', f'{table["blob"] + 8:08x}'))
            connection.commit()
        finally:
            connection.close()
        try:
            check_packed_exec(tampered, table, blob_x_len, {}, '__control_call__')
        except AssertionError:
            results['__control_call__'] = {'outcome': 'rejects-injected-call'}
        else:
            raise SystemExit('negative control failed: injected COMPUTED_CALL accepted')
        summary = {name: result['outcome'] for name, result in results.items()}
        print(json.dumps(summary))
        if args.report:
            args.report.write_text(json.dumps(dict(results=results), indent=2) + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
