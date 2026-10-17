#!/usr/bin/env python3
"""m20-016: a GameCube disc imports as one program: boot DOL + RELs, linked.

P3.1. The game code of many GameCube titles lives in a REL module on the disc
(Animal Crossing: `files/foresta.rel.szs`), not in the boot DOL. The fixture
(tests/fixtures-src/gcm_gen.py, ground truth by construction) is a disc with
a DOL and one Yaz0-compressed REL, as a raw GCM and as CISO at two block
sizes. For every container the gate asserts that

* the import is one program, whose regions are the DOL's text and the REL's
  text, data and bss placed after the DOL (dtk `rel merge` placement:
  align32(arena_lo + 0x2000), sections on 32-byte boundaries);
* the module table has two rows (`main.dol` kind dol, `mod` kind rel), so a
  reference is cross-module only where it crosses between them;
* the relocated bytes are what the format's rules give (computed here, not
  read back from the loader): REL24 to the DOL, the HA/LO pair, three ADDR32
  words;
* functions cover both modules, including the two that nothing calls and only
  the data relocations reach;
* `module_xrefs` holds the REL -> DOL call and data reference;

and that the three containers agree with each other, and that damage is
named: a CISO cut short is refused, a Yaz0 stream that lies about its size
leaves the DOL imported with the REL named in a diagnostic.

Usage:
    python3 tests/m20-016_gc_disc.py [--report OUT.json]
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GEN = ROOT / 'tests' / 'fixtures-src' / 'gcm_gen.py'
CLI = Path(os.environ.get('ROMWRIGHT_CLI', ROOT / 'target' / 'release' / 'romwright-cli'))

DOL = 0x8000_3100
TEXT, DATA, BSS = 0x8000_5120, 0x8000_5140, 0x8000_5160
F1, F2 = TEXT + 8, TEXT + 0x14
EXPECTED_REGIONS = [
    ('80003100', 16, 'r-x'), ('80005120', 0x1C, 'r-x'),
    ('80005140', 12, 'rw-'), ('80005160', 0x20, 'rw-'),
]
EXPECTED_MODULES = [('main.dol', 'dol', 'sys/main.dol'), ('mod', 'rel', 'files/mod.rel.szs')]
RELOCATIONS = 6  # REL24 + ADDR32 against the DOL; HA, LO, two ADDR32 against itself


def run(command, **kwargs):
    return subprocess.run(command, cwd=ROOT, text=True, capture_output=True,
                          check=True, timeout=600, **kwargs)


def words(image: Path, base: int, count: int) -> list[int]:
    out = run([str(CLI), 'mem', str(image), f'{base:x}', str(4 * count)]).stdout
    raw = bytes.fromhex(out.strip().replace(' ', ''))
    assert len(raw) == 4 * count, (base, out)
    return [int.from_bytes(raw[i:i + 4], 'big') for i in range(0, len(raw), 4)]


def expected_text() -> list[int]:
    ha = (DATA + 0x8000) >> 16 & 0xFFFF
    return [
        0x4800_0001 | (DOL - TEXT) & 0x03FF_FFFC,   # bl DOL (REL24)
        0x4E80_0020,
        0x3C60_0000 | ha,                           # lis r3,ha(data)
        0x3863_0000 | DATA & 0xFFFF,                # addi r3,r3,lo(data)
        0x4E80_0020,
        0x4BFF_FFED,                                # bl _prolog, already linked in the file
        0x4E80_0020,
    ]


def check(image: Path, work: Path, label: str) -> dict:
    project = work / f'{label}.project'
    proc = run([str(CLI), 'import', str(image), '--name', 'gc', '--project', str(project)])
    assert 'imported gc natively' in proc.stdout + proc.stderr, proc.stdout + proc.stderr
    db = sqlite3.connect(project / 'project.sqlite')
    try:
        programs = db.execute('SELECT name, language FROM programs').fetchall()
        assert programs == [('gc', 'PowerPC:BE:32:Gekko_Broadway')], programs
        pid = db.execute('SELECT id FROM programs').fetchone()[0]
        regions = db.execute('SELECT start, size, permissions FROM memory_regions '
                             'WHERE program_id = ? ORDER BY start', (pid,)).fetchall()
        assert regions == EXPECTED_REGIONS, regions
        modules = db.execute('SELECT name, kind, file_id, load_vaddr, size, file_off FROM modules '
                             'WHERE program_id = ? ORDER BY module_id', (pid,)).fetchall()
        assert [m[:3] for m in modules] == EXPECTED_MODULES, modules
        assert [m[3] for m in modules] == ['80003100', '80005120'], modules
        assert modules[1][4] == BSS + 0x20 - TEXT, modules
        # `file_off` is where each module's stored bytes begin in the disc
        # (logical offsets: a CISO's block map is undone): the boot DOL the
        # header names, and the Yaz0 stream of the REL's FST entry.
        raw = (work / 'disc.gcm').read_bytes()
        dol_at, szs_at = int.from_bytes(raw[0x420:0x424], 'big'), raw.find(b'Yaz0')
        assert szs_at > dol_at > 0, (dol_at, szs_at)
        assert [m[5] for m in modules] == [dol_at, szs_at], (modules, dol_at, szs_at)
        functions = {int(row[0], 16) for row in db.execute(
            'SELECT entry FROM functions WHERE program_id = ?', (pid,))}
        assert functions == {DOL, TEXT, F1, F2}, sorted(hex(f) for f in functions)
        names = dict(db.execute('SELECT entry, name FROM functions WHERE program_id = ?',
                                (pid,)).fetchall())
        assert names['80005120'] == '_prolog', names
        xrefs = db.execute(
            'SELECT x.from_addr, x.to_addr FROM module_xrefs x '
            'JOIN modules m ON m.module_id = x.module_id WHERE m.program_id = ?',
            (pid,)).fetchall()
        crossing = {(int(a, 16), int(b, 16)) for a, b in xrefs}
        # The `bl` in _prolog and the data word holding the DOL's address.
        assert (TEXT, DOL) in crossing and (DATA + 8, DOL) in crossing, \
            sorted((hex(a), hex(b)) for a, b in crossing)
        # No reference inside one module is a cross-module one.
        for source, target in crossing:
            assert (source >= TEXT) != (target >= TEXT), (hex(source), hex(target))
        diagnostics = db.execute('SELECT severity, stage, message FROM import_diagnostics '
                                 'WHERE program_id = ? AND stage = ?', (pid, 'rel')).fetchall()
        assert diagnostics and f'{RELOCATIONS} relocations applied' in diagnostics[0][2], diagnostics
    finally:
        db.close()
    assert words(image, TEXT, 7) == expected_text(), label
    assert words(image, DATA, 3) == [F1, F2, DOL], label
    return {'regions': len(regions), 'modules': len(modules), 'functions': len(functions),
            'module_xrefs': len(xrefs)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--report', type=Path, default=None)
    args = parser.parse_args()
    results: dict[str, dict] = {}
    with tempfile.TemporaryDirectory(prefix='romwright-m20-016-') as temporary:
        work = Path(temporary)
        images = {
            'gcm': (work / 'disc.gcm', []),
            'ciso-32k': (work / 'disc32k.ciso', ['--ciso', '0x8000']),
            'ciso-2m': (work / 'disc2m.ciso', ['--ciso', '0x200000']),
        }
        for label, (path, flags) in images.items():
            run([sys.executable, str(GEN), str(path), *flags])
            results[label] = check(path, work, label)
        assert len({tuple(r.items()) for r in results.values()}) == 1, results

        # A CISO whose stored blocks were cut short is refused, by name.
        cut = work / 'cut.ciso'
        data = images['ciso-32k'][0].read_bytes()
        cut.write_bytes(data[:0x8000 + 0x1000])
        proc = subprocess.run([str(CLI), 'import', str(cut), '--name', 'cut',
                               '--project', str(work / 'cut.project')],
                              cwd=ROOT, text=True, capture_output=True, timeout=600)
        assert proc.returncode != 0, proc.stdout
        results['cut_ciso'] = {'outcome': 'refused'}

        # A Yaz0 stream that claims more than it can hold: the DOL still
        # imports, and the diagnostic names the REL file.
        lie = bytearray(images['gcm'][0].read_bytes())
        at = lie.find(b'Yaz0')
        assert at > 0
        lie[at + 4:at + 8] = (0x7FFF_FFFF).to_bytes(4, 'big')
        path = work / 'lie.gcm'
        path.write_bytes(bytes(lie))
        project = work / 'lie.project'
        run([str(CLI), 'import', str(path), '--name', 'lie', '--project', str(project)])
        db = sqlite3.connect(project / 'project.sqlite')
        try:
            regions = db.execute('SELECT start FROM memory_regions').fetchall()
            assert regions == [('80003100',)], regions
            messages = [row[0] for row in db.execute('SELECT message FROM import_diagnostics')]
            assert any('files/mod.rel.szs' in m for m in messages), messages
        finally:
            db.close()
        results['bad_yaz0'] = {'outcome': 'dol_only_with_diagnostic'}
    print(json.dumps(dict(results=results), indent=2))
    if args.report is not None:
        args.report.write_text(json.dumps(dict(id='m20-016', passed=True, results=results), indent=2) + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
