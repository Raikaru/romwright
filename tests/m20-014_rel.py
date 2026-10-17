#!/usr/bin/env python3
"""m20-014: REL sections land as modules, and their relocations apply.

The fixture (built by tests/fixtures-src/rel_gen.py, ground truth by
construction, a real version-2 REL that `dtk rel info` parses) is a
two-section module: section 0 executes at the synthetic base, section 1
does not. Its import table names the DOL (module 0) and the module itself:
a `bl` to an absolute DOL address (R_PPC_REL24), a `lis`/`addi` pair
loading the address of data+4 (R_PPC_ADDR16_HA / _LO), and a data word
holding the address of text+0xc (R_PPC_ADDR32). The gate asserts exact
regions, permissions and language, the relocated bytes (computed here from
the format's rules, not read back from the loader), plus named refusal for
a section that points past EOF and for truncation.
"""

from __future__ import annotations

import argparse
import os
import shutil
import json
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GEN = ROOT / 'tests' / 'fixtures-src' / 'rel_gen.py'
CLI = Path(os.environ.get('ROMWRIGHT_CLI', ROOT / 'target' / 'release' / 'romwright-cli'))


def run(command, **kwargs):
    return subprocess.run(command, cwd=ROOT, text=True, capture_output=True,
                          check=True, timeout=600, **kwargs)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--report', type=Path, default=None)
    args = parser.parse_args()
    results: dict[str, dict] = {}
    with tempfile.TemporaryDirectory(prefix='romwright-m20-014-') as temporary:
        work = Path(temporary)
        image = work / 'mod.rel'
        proc = run([sys.executable, str(GEN), str(image)])
        assert proc.stdout.split()[:2] == ['rel', 'sections=2'], proc.stdout
        project = work / 'mod.project'
        proc = run([str(CLI), 'import', str(image), '--name', 'mod',
                    '--project', str(project)])
        assert 'imported mod natively' in (proc.stdout + proc.stderr), proc.stdout
        connection = sqlite3.connect(project / 'project.sqlite')
        try:
            programs = connection.execute(
                'SELECT name, language FROM programs').fetchall()
            assert programs == [('mod', 'PowerPC:BE:32:Gekko_Broadway')], programs
            regions = connection.execute(
                'SELECT start, size, permissions FROM memory_regions ORDER BY start'
            ).fetchall()
            assert regions == [('80000000', 16, 'r-x'), ('90000000', 8, 'rw-')], regions
        finally:
            connection.close()
        results['valid'] = {'outcome': 'exact'}
        # Relocated bytes. Text at 0x80000000, data at 0x90000000.
        text_base, data_base, dol = 0x8000_0000, 0x9000_0000, 0x8000_3100
        target = data_base + 4
        ha = (target + 0x8000) >> 16 & 0xFFFF
        want_text = [
            0x4800_0001 | (dol - text_base) & 0x03FF_FFFC,   # bl REL24
            0x3C60_0000 | ha,                                # lis HA
            0x3863_0000 | target & 0xFFFF,                   # addi LO
            0x4E80_0020,
        ]
        want_data = [text_base + 0xC, 0xDEAD_BEEF]
        for base, words in ((text_base, want_text), (data_base, want_data)):
            proc = run([str(CLI), 'mem', str(image), f'{base:x}', str(4 * len(words))])
            got = bytes.fromhex(proc.stdout.strip().replace(' ', ''))
            assert got == b''.join(w.to_bytes(4, 'big') for w in words), (
                f'{base:#x}: {got.hex()} != {[hex(w) for w in words]}')
        results['relocations'] = {
            'outcome': 'exact', 'words_compared': len(want_text) + len(want_data)}
        # Where decomp-toolkit is installed (DTK=/path/to/dtk or `dtk` on PATH)
        # its reader must agree about the fixture's relocation table.
        dtk = os.environ.get('DTK') or shutil.which('dtk')
        if dtk:
            info = run([dtk, 'rel', 'info', '-r', str(image)]).stdout
            for line in ('PpcRel24 -> 0:0:0x80003100', 'PpcAddr16Ha -> 1:0:0x4',
                         'PpcAddr16Lo -> 1:0:0x4', 'Absolute -> 1:1:0xC'):
                assert line in info, (line, info)
            results['dtk_parity'] = {'outcome': 'exact', 'relocation_lines': 4}
        bad = work / 'mod-bad.rel'
        run([sys.executable, str(GEN), str(bad), '--bad-offset'])
        project = work / 'mod-bad.project'
        proc = subprocess.run([str(CLI), 'import', str(bad), '--name', 'modbad',
                               '--project', str(project)],
                              cwd=ROOT, text=True, capture_output=True, timeout=600)
        assert proc.returncode != 0, proc.stdout
        assert 'REL section outside file' in (proc.stdout + proc.stderr), proc.stdout
        results['bad_offset'] = {'outcome': 'refused'}
        trunc = work / 'trunc.rel'
        trunc.write_bytes(b'\x00' * 16)
        project = work / 'trunc.project'
        proc = subprocess.run([str(CLI), 'import', str(trunc), '--name', 'trunc',
                               '--project', str(project)],
                              cwd=ROOT, text=True, capture_output=True, timeout=600)
        assert proc.returncode != 0, proc.stdout
        results['truncated'] = {'outcome': 'refused'}
    print(json.dumps(dict(results=results), indent=2))
    if args.report is not None:
        args.report.write_text(json.dumps(dict(id='m20-014', passed=True, results=results), indent=2) + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
