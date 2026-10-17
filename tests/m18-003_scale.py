#!/usr/bin/env python3
"""m18-003: scale gate -- a ~100MB image must import bounded.

Methodology is machine-normalized, not absolute: a 10MB and a 100MB
fixture of the same shape are imported, and the wall-time ratio must
stay under RATIO_MAX (linear scaling predicts ~10x; the bound catches
superlinear blowups with headroom for fixed costs and noise). Marker
dispatches (nm ground truth, like m18-001) must recover exactly at
both sizes: scale may cost time, never precision. Generous absolute
sanity bounds (WALL_MAX_S, RSS_MAX_KB) catch hangs/OOMs, documented
here rather than tuned to any machine.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / 'tests' / 'fixtures-src' / 'robust'
CLI = ROOT / 'target' / 'release' / 'romwright-cli'

SIZES_MB = (10, 100)
RATIO_MAX = 20.0
WALL_MAX_S = 900.0
RSS_MAX_KB = 2_000_000


def run(command, **kwargs):
    return subprocess.run(command, cwd=ROOT, text=True, capture_output=True,
                          check=True, timeout=1200, **kwargs)


def build(work: Path) -> dict[int, Path]:
    binaries = {}
    for megabytes in SIZES_MB:
        src = work / f'scale{megabytes}.s'
        proc = run([sys.executable, str(SRC / 'scale_gen.py'),
                    str(megabytes), str(src)])
        assert proc.stdout.split() == ['scale_mb', str(megabytes)], proc.stdout
        out = work / f'scale{megabytes}.bin'
        run(['clang', '-nostdlib', '-o', str(out), str(src)])
        actual_mb = out.stat().st_size / (1024 * 1024)
        assert actual_mb >= megabytes, (megabytes, actual_mb)
        binaries[megabytes] = out
    return binaries

def symbols(binary: Path) -> dict[str, int]:
    out = run(['nm', '-P', str(binary)]).stdout
    table = {}
    for line in out.splitlines():
        row = line.split()
        if len(row) >= 3 and row[1] in 'TtDdRrBb':
            table[row[0]] = int(row[2], 16)
    return table


def wall_seconds(stamp: str) -> float:
    # /usr/bin/time -v format: [[h:]m:]s[.cs]
    parts = stamp.split(':')
    return float(parts[-1]) + 60.0 * sum(
        int(part) * 60 ** index for index, part in enumerate(reversed(parts[:-1])))
def timed_import(binary: Path, project: Path) -> tuple[float, int]:
    # The import cache would measure a file copy, not analysis: the
    # cache module's own docs require this switch for cost gates.
    env = dict(os.environ)
    env['ROMWRIGHT_NO_IMPORT_CACHE'] = '1'
    proc = subprocess.run(['/usr/bin/time', '-v', str(CLI), 'import',
                           str(binary), '--name', 'scale',
                           '--project', str(project)],
                          cwd=ROOT, text=True, capture_output=True, timeout=1200,
                          env=env)
    assert proc.returncode == 0, (binary, proc.returncode, proc.stderr[-2000:])
    wall = re.search(r'wall clock\) time.*\):\s*(\S+)', proc.stderr)
    rss = re.search(r'Maximum resident set size[^:]*:\s*(\d+)', proc.stderr)
    assert wall and rss, proc.stderr[-2000:]
    return wall_seconds(wall.group(1)), int(rss.group(1))


def xrefs_by_branch(project: Path) -> dict[int, set[int]]:
    connection = sqlite3.connect(project / 'project.sqlite')
    try:
        rows = connection.execute(
            "SELECT src, dst FROM xrefs WHERE kind IN "
            "('COMPUTED_JUMP', 'COMPUTED_CALL')").fetchall()
    finally:
        connection.close()
    merged: dict[int, set[int]] = {}
    for src, dst in rows:
        merged.setdefault(int(src, 16), set()).add(int(dst, 16))
    return merged


def check_markers(name: str, binary: Path, project: Path, results: dict) -> None:
    table = symbols(binary)
    got = xrefs_by_branch(project)
    for index in range(3):
        branch = table[f'mk{index}_br']
        want = {table[f'mk{index}_c{case}'] for case in range(4)}
        actual = got.get(branch, set())
        assert actual == want, (name, index, sorted(actual), sorted(want))
    results[name] = {'outcome': 'exact', 'markers': 3}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--report', type=Path, default=None)
    args = parser.parse_args()
    results: dict[str, dict] = {}
    with tempfile.TemporaryDirectory(prefix='romwright-m18-scale-') as temporary:
        work = Path(temporary)
        binaries = build(work)
        stats = {}
        for megabytes, binary in binaries.items():
            project = work / f'scale{megabytes}.project'
            wall, rss = timed_import(binary, project)
            stats[megabytes] = (wall, rss)
            check_markers(f'scale{megabytes}', binary, project, results)
    small, large = SIZES_MB
    small_wall = stats[small][0] or 0.01  # avoid div-by-zero on fast machines
    ratio = stats[large][0] / small_wall
    assert stats[large][0] < WALL_MAX_S, stats
    assert stats[large][1] < RSS_MAX_KB, stats
    assert ratio < RATIO_MAX, (ratio, stats)
    results['scale'] = {'outcome': 'bounded',
                        f'wall_s_{small}mb': round(stats[small][0], 2),
                        f'wall_s_{large}mb': round(stats[large][0], 2),
                        f'rss_kb_{large}mb': stats[large][1],
                        'wall_ratio': round(ratio, 2)}
    print(json.dumps(dict(results=results), indent=2))
    if args.report is not None:
        args.report.write_text(json.dumps(dict(id='m18-003', passed=True, results=results), indent=2) + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
