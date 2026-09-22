#!/usr/bin/env python3
"""m1-010: macOS Mach-O import, synthetic plus real.

A synthetic thin-64 image (built by tests/fixtures-src/macho_gen.py,
ground truth by construction) must import with exact mappings,
permissions, language and symbol names. The real
`KOTOR2sub` fat binary must import its x86_64 slice (skipped when the
file is absent -- it lives outside the repo); only aggregates are
asserted there, never an exact count. Truncated and 32-bit-only
inputs must refuse with an error, never a crash or a DOL misread.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GEN = ROOT / 'tests' / 'fixtures-src' / 'macho_gen.py'
CLI = ROOT / 'target' / 'release' / 'romwright-cli'
KOTOR2SUB = Path.home() / 'Nihilus' / 'KOTOR2sub'


def run(command, **kwargs):
    return subprocess.run(command, cwd=ROOT, text=True, capture_output=True,
                          check=True, timeout=600, **kwargs)


def store(project: Path) -> sqlite3.Connection:
    return sqlite3.connect(project / 'project.sqlite')


def test_synthetic(work: Path, results: dict) -> None:
    image = work / 'mini.macho'
    proc = run([sys.executable, str(GEN), str(image)])
    assert proc.stdout.split()[0] == 'macho', proc.stdout
    project = work / 'mini.project'
    proc = run([str(CLI), 'import', str(image), '--name', 'mini',
                '--project', str(project)])
    assert 'imported mini natively' in (proc.stdout + proc.stderr), proc.stdout
    connection = store(project)
    try:
        programs = connection.execute('SELECT name, language FROM programs').fetchall()
        assert programs == [('mini', 'x86:LE:64:default')], programs
        functions = dict(connection.execute('SELECT entry, name FROM functions').fetchall())
        assert functions == {'100000000': 'main'}, functions
        regions = connection.execute(
            'SELECT start, size, permissions FROM memory_regions ORDER BY start').fetchall()
        assert regions == [('100000000', 6, 'r-x'), ('100001000', 4, 'rw-')], regions
    finally:
        connection.close()
    results['synthetic'] = {'outcome': 'exact'}


def test_thirty_two_bit_refuses(work: Path, results: dict) -> None:
    # Thin 32-bit header: recognised as Mach-O, refused as unsupported.
    image = work / 'mini32.macho'
    image.write_bytes(struct.pack('<8I', 0xFEEDFACE, 7, 3, 2, 0, 0, 0, 0))
    project = work / 'mini32.project'
    proc = subprocess.run([str(CLI), 'import', str(image), '--name', 'mini32',
                           '--project', str(project)],
                          cwd=ROOT, text=True, capture_output=True, timeout=600)
    assert proc.returncode != 0, proc.stdout
    assert 'Mach-O' in (proc.stdout + proc.stderr), proc.stdout
    results['thin32'] = {'outcome': 'refused'}


def test_truncated_refuses(work: Path, results: dict) -> None:
    image = work / 'truncated.macho'
    image.write_bytes(b'\xcf\xfa\xed\xfe\x07\x00\x00\x01\x03\x00\x00\x00')
    project = work / 'truncated.project'
    proc = subprocess.run([str(CLI), 'import', str(image), '--name', 'trunc',
                           '--project', str(project)],
                          cwd=ROOT, text=True, capture_output=True, timeout=600)
    assert proc.returncode != 0, proc.stdout
    results['truncated'] = {'outcome': 'refused'}


def test_kotor2sub(work: Path, results: dict) -> None:
    if not KOTOR2SUB.is_file():
        results['kotor2sub'] = {'outcome': 'skipped', 'reason': 'file absent'}
        print('m1-010: SKIPPED kotor2sub (file absent)')
        return
    project = work / 'kotor2sub.project'
    proc = run([str(CLI), 'import', str(KOTOR2SUB), '--name', 'kotor2sub',
                '--project', str(project)])
    assert 'imported kotor2sub natively' in (proc.stdout + proc.stderr), proc.stdout
    connection = store(project)
    try:
        programs = connection.execute('SELECT name, language FROM programs').fetchall()
        assert programs == [('kotor2sub', 'x86:LE:64:default')], programs
        count = connection.execute('SELECT COUNT(*) FROM functions').fetchone()[0]
        assert count > 20000, count
        main = connection.execute(
            'SELECT entry FROM functions WHERE name = ?', ('main',)).fetchall()
        assert main == [('1000043e7',)], main
        regions = connection.execute(
            'SELECT start, permissions FROM memory_regions ORDER BY start').fetchall()
        assert len(regions) == 3, regions
        assert regions[0][1] == 'r-x', regions
        assert regions[0][0] == '100000000', regions
    finally:
        connection.close()
    results['kotor2sub'] = {'outcome': 'imported', 'functions': count}


def test_i386_slice(work: Path, results: dict) -> None:
    # The fat fallback slice loads as 32-bit when extracted: same
    # loader contract, `x86:LE:32` language.
    if not KOTOR2SUB.is_file():
        results['i386'] = {'outcome': 'skipped', 'reason': 'file absent'}
        return
    import struct as struct_
    with open(KOTOR2SUB, 'rb') as handle:
        head = handle.read(0x100)
        narch = struct_.unpack('>I', head[4:8])[0]
        arch = None
        for index in range(narch):
            cpu, _, off, size, _ = struct_.unpack(
                '>5I', head[8 + index * 20:28 + index * 20])
            if cpu & 0xFFFFFF == 7 and cpu != 0x01000007:
                arch = (off, size)
        assert arch is not None, 'no i386 slice'
        handle.seek(arch[0])
        image = work / 'kotor2sub-i386.bin'
        image.write_bytes(handle.read(arch[1]))
    project = work / 'i386.project'
    proc = run([str(CLI), 'import', str(image), '--name', 'kotor2sub32',
                '--project', str(project)])
    assert 'imported kotor2sub32 natively' in (proc.stdout + proc.stderr), proc.stdout
    connection = store(project)
    try:
        programs = connection.execute('SELECT name, language FROM programs').fetchall()
        assert programs == [('kotor2sub32', 'x86:LE:32:default')], programs
        count = connection.execute('SELECT COUNT(*) FROM functions').fetchone()[0]
        assert count > 10000, count
    finally:
        connection.close()
    results['i386'] = {'outcome': 'imported', 'functions': count}

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--report', type=Path, default=None)
    parser.add_argument('--work', type=Path, default=None)
    args = parser.parse_args()
    results: dict[str, dict] = {}
    if args.work is not None:
        args.work.mkdir(parents=True, exist_ok=True)
        test_synthetic(args.work, results)
        test_thirty_two_bit_refuses(args.work, results)
        test_truncated_refuses(args.work, results)
        test_kotor2sub(args.work, results)
        test_i386_slice(args.work, results)
    else:
        with tempfile.TemporaryDirectory(prefix='romwright-m1-010-') as temporary:
            work = Path(temporary)
            test_synthetic(work, results)
            test_thirty_two_bit_refuses(work, results)
            test_truncated_refuses(work, results)
            test_kotor2sub(work, results)
            test_i386_slice(work, results)
    print(json.dumps(dict(results=results), indent=2))
    if args.report is not None:
        args.report.write_text(json.dumps(dict(results=results), indent=2) + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
