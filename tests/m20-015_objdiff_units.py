#!/usr/bin/env python3
"""m20-015: objdiff unit mapping puts each function in its TU object.

`export-objdiff` groups a program's functions into objdiff units by
splits.txt extents. Ground truth is nm: three leaf functions split
across two TUs must land in exactly their TU's unit with the right
vram/size, with target_path/base_path shaped for objdiff. No
compiler or objdiff binary runs here; the interop surface (which
function lands in which object) is asserted, not the round trip.
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
CLI = ROOT / 'target' / 'release' / 'romwright-cli'


def run(command, **kwargs):
    return subprocess.run(command, cwd=ROOT, text=True, capture_output=True,
                          check=True, timeout=600, **kwargs)


def symbols(binary: Path) -> dict[str, int]:
    out = run(['nm', '-P', str(binary)]).stdout
    table = {}
    for line in out.splitlines():
        row = line.split()
        if len(row) >= 3 and row[1] in 'Tt':
            table[row[0]] = int(row[2], 16)
    return table


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--report', type=Path, default=None)
    args = parser.parse_args()
    results: dict[str, dict] = {}
    with tempfile.TemporaryDirectory(prefix='romwright-m20-015-') as temporary:
        work = Path(temporary)
        outdir = work / 'objdiff'
        target = outdir / 'target'
        target.mkdir(parents=True)
        run(['clang', '-c', str(ROOT / 'tests/fixtures-src/tu_a.c'),
             '-o', str(target / 'tu_a.o')])
        run(['clang', '-c', str(ROOT / 'tests/fixtures-src/tu_b.c'),
             '-o', str(target / 'tu_b.o')])
        binary = work / 'units.bin'
        run(['clang', '-o', str(binary), str(target / 'tu_a.o'), str(target / 'tu_b.o')])
        table = symbols(binary)
        assert {'fa', 'fb', 'fc'} <= set(table), table
        splits = work / 'splits.txt'
        splits.write_text(
            'tu_a.c:\n'
            f'\t.text start:{table["fa"]:#x} end:{table["fb"]:#x}\n'
            f'\t.text start:{table["fb"]:#x} end:{table["fc"]:#x}\n'
            'tu_b.c:\n'
            f'\t.text start:{table["fc"]:#x} end:{table["main"]:#x}\n')
        project = work / 'units.project'
        run([str(CLI), 'import', str(binary), '--name', 'units',
             '--project', str(project)])
        proc = run([str(CLI), 'export-objdiff', 'units', str(outdir),
                    '--splits', str(splits), '--target-root', 'target',
                    '--project', str(project)])
        report = json.loads(proc.stdout)
        assert report['units'] == 2, report
        config = json.loads((outdir / 'objdiff.json').read_text())
        assert config['min_version'].startswith('2.'), config
        units = {unit['metadata']['source_path']: unit for unit in config['units']}
        assert set(units) == {'tu_a.c', 'tu_b.c'}, set(units)
        got_a = {row['name']: row for row in units['tu_a.c']['metadata']['functions']}
        got_b = {row['name']: row for row in units['tu_b.c']['metadata']['functions']}
        assert set(got_a) == {'fa', 'fb'}, set(got_a)
        assert set(got_b) == {'fc'}, set(got_b)
        for name, row in (('fa', got_a['fa']), ('fb', got_a['fb']), ('fc', got_b['fc'])):
            assert int(row['vram'], 16) == table[name], (name, row)
            assert row['size'] > 0, (name, row)
        assert units['tu_a.c']['target_path'].endswith('target/tu_a.o'), units
        assert units['tu_a.c']['base_path'].endswith('build/tu_a.o'), units
        # objdiff reads `complete` for its complete_* measures: always written.
        assert units['tu_a.c']['metadata']['complete'] is False, units
        results['units'] = {'outcome': 'mapped', 'tus': 2}
    print(json.dumps(dict(results=results), indent=2))
    if args.report is not None:
        args.report.write_text(json.dumps(dict(id='m20-015', passed=True, results=results), indent=2) + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
