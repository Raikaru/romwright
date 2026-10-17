#!/usr/bin/env python3
"""m12-002: decomp.me scratch score recording, offline.

The decomp.me API round trip needs the network, but both local ends
are gateable: a recorded `GET /api/scratch/<slug>` response must
record its score as a comment on the addressed function, and a
response without any score must fail loudly instead of recording
nothing. Ground truth is the response fixture, not the service.
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--report', type=Path, default=None)
    args = parser.parse_args()
    results: dict[str, dict] = {}
    with tempfile.TemporaryDirectory(prefix='romwright-m12-002-') as temporary:
        work = Path(temporary)
        target = work / 'target'
        target.mkdir()
        run(['clang', '-c', str(ROOT / 'tests/fixtures-src/tu_a.c'),
             '-o', str(target / 'tu_a.o')])
        run(['clang', '-c', str(ROOT / 'tests/fixtures-src/tu_b.c'),
             '-o', str(target / 'tu_b.o')])
        binary = work / 'units.bin'
        run(['clang', '-o', str(binary), str(target / 'tu_a.o'), str(target / 'tu_b.o')])
        out = run(['nm', '-P', str(binary)]).stdout
        addresses = {}
        for line in out.splitlines():
            row = line.split()
            if len(row) >= 3 and row[1] in 'Tt':
                addresses[row[0]] = int(row[2], 16)
        project = work / 'units.project'
        run([str(CLI), 'import', str(binary), '--name', 'units',
             '--project', str(project)])
        response = work / 'scratch.json'
        response.write_text(json.dumps({
            'slug': 'AbC123', 'name': 'fa', 'score': 87.5,
            'match_override': False,
        }) + '\n')
        proc = run([str(CLI), 'import-score', 'units', f'{addresses["fa"]:#x}',
                    str(response), '--project', str(project)])
        assert 'recorded score 87.50%' in (proc.stdout + proc.stderr), proc.stdout
        connection = sqlite3.connect(project / 'project.sqlite')
        try:
            bodies = [row[0] for row in connection.execute('SELECT text FROM comments')]
            assert any('87.50%' in body and 'AbC123' in body for body in bodies), bodies
        finally:
            connection.close()
        results['recorded'] = {'outcome': 'commented'}
        bad = work / 'bad.json'
        bad.write_text(json.dumps({'slug': 'NoScore', 'name': 'fb'}) + '\n')
        proc = subprocess.run([str(CLI), 'import-score', 'units', f'{addresses["fb"]:#x}',
                               str(bad), '--project', str(project)],
                              cwd=ROOT, text=True, capture_output=True, timeout=600)
        assert proc.returncode != 0, proc.stdout
        assert 'score' in (proc.stdout + proc.stderr).lower(), proc.stdout
        results['scoreless'] = {'outcome': 'refused'}
    print(json.dumps(dict(results=results), indent=2))
    if args.report is not None:
        # The id is the task's; this file is the offline half (`m12-002_cross_compiler.py` needs a private pair).
        args.report.write_text(json.dumps(dict(id='m12-002', passed=True, results=results), indent=2) + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
