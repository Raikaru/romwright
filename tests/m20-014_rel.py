#!/usr/bin/env python3
"""m20-014: REL sections land as modules.

The GameCube REL loader exists but never had a fixture on disk. The
fixture (built by tests/fixtures-src/rel_gen.py, ground truth by
construction) is a two-section module: section 0 executes at the
synthetic base, section 1 does not. The gate asserts exact regions,
permissions and language, plus named refusal for a section that
points past EOF and for truncation.
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
GEN = ROOT / 'tests' / 'fixtures-src' / 'rel_gen.py'
CLI = ROOT / 'target' / 'release' / 'romwright-cli'


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
            assert regions == [('80000000', 12, 'r-x'), ('90000000', 4, 'rw-')], regions
        finally:
            connection.close()
        results['valid'] = {'outcome': 'exact'}
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
        args.report.write_text(json.dumps(dict(results=results), indent=2) + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
