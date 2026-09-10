#!/usr/bin/env python3
"""Positive indirect-switch recovery through standalone and warm native workers."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'benchmarks'))
from prototype_gate import run_api
from switch_gate import stock_targets, target_sets

SOURCE = r'''
volatile int sink;
__attribute__((noinline)) int plain(int value) { return value + 1; }
__attribute__((noinline)) int dispatch(int value) {
    switch (value) {
    case 0: case 1: sink += 11; break;
    case 2: sink -= 13; break;
    case 3: sink *= 3; break;
    case 4: sink ^= 17; break;
    case 5: sink |= 19; break;
    case 6: sink += 23; break;
    case 7: default: sink &= 127; break;
    }
    return sink;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ghidra', type=Path, default=Path(os.environ.get(
        'VENTRIS_GHIDRA', str(Path.home() / 'ghidra_12.1.3_PUBLIC'))))
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    env = dict(os.environ, VENTRIS_GHIDRA=str(args.ghidra.resolve()), DEBUGINFOD_URLS='')
    for name in ('VENTRIS_SLA', 'VENTRIS_LANGUAGE', 'VENTRIS_LANGUAGE_DIR', 'VENTRIS_SPECS'):
        env.pop(name, None)

    def run(command, **kwargs):
        return subprocess.run(command, cwd=ROOT, env=env, text=True,
            capture_output=True, check=True, timeout=120, **kwargs)

    with tempfile.TemporaryDirectory(prefix='ventris-m2-switch-') as temporary:
        work = Path(temporary)
        twin, binary = work / 'fixture.unstripped', work / 'fixture.bin'
        run(['clang', '-O2', '-g', '-funwind-tables', '-fno-pie', '-no-pie',
            '-nostdlib', '-Wl,-e,dispatch', '-x', 'c', '-', '-o', str(twin)], input=SOURCE)
        symbols = {row[0]: int(row[2], 16) for line in run(['nm', '-P', str(twin)]).stdout.splitlines()
            if len(row := line.split()) >= 3 and row[0] in ('dispatch', 'plain')}
        assert set(symbols) == {'dispatch', 'plain'}, symbols
        shutil.copyfile(twin, binary)
        run(['llvm-strip', '--strip-all', str(binary)])
        oracle_work = work / 'oracle'
        oracle_work.mkdir()
        oracle = stock_targets(args.ghidra.resolve(), binary,
            dict(language='x86:LE:64:default', compiler='gcc'), oracle_work)
        expected = target_sets(oracle['functions'][f"{symbols['dispatch']:08x}"])
        assert len(expected) == 1 and len(next(iter(expected.values()))) == 7, oracle
        assert oracle['functions'][f"{symbols['plain']:08x}"] == [], oracle
        project = work / 'project'
        cli = str(ROOT / 'target/release/lre-cli')
        run([cli, 'import', str(binary), '--project', str(project)])
        standalone = json.loads(run([cli, 'decompile-doc', str(binary),
            hex(symbols['dispatch']), '--project', str(project)]).stdout)
        pooled = run_api(ROOT, project, [('decompile_doc', dict(binary=str(binary),
            program=binary.name, address=dict(space='Ram', offset=symbols[name])))
            for name in ('dispatch', 'plain', 'dispatch')], 120, env)
        for document in (standalone, pooled[0], pooled[2]):
            assert target_sets(document.get('jump_tables')) == expected, document
        assert pooled[1].get('jump_tables') == [], pooled[1]
        assert len({document['revision'] for document in pooled}) == 1, pooled
        report = dict(task='m2-007', scope='temporary positive acceptance, not locked corpus',
            commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
            passed=True, oracle=oracle, standalone=standalone['jump_tables'],
            pooled=[document['jump_tables'] for document in pooled])
        if args.report:
            args.report.write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(dict(passed=True, tables=1, distinct_targets=7,
            standalone=1, pooled=3, empty_function_verified=True)))


if __name__ == '__main__':
    main()
