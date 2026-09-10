#!/usr/bin/env python3
"""Build .vsig databases from the pinned static archives (m2-011).

Package identity and license are declared here, never inferred by the tool:
the cross sysroots come from the SHA-256-pinned Debian packages in
tools/fetch_cross_sysroots.py (see docs/third-party.md).
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from gen_oracle import digest

# (id, sysroot-relative archive, package, license)
SOURCES = [
    ('aarch64_libc', 'aarch64/usr/aarch64-linux-gnu/lib/libc.a',
        'libc6-dev-arm64-cross_2.36-8cross1', 'LGPL-2.1-or-later'),
    ('i386_libc', 'i386/usr/i686-linux-gnu/lib/libc.a',
        'libc6-dev-i386-cross_2.36-8cross1', 'LGPL-2.1-or-later'),
    ('powerpc_libc', 'powerpc/usr/powerpc-linux-gnu/lib/libc.a',
        'libc6-dev-powerpc-cross_2.36-8cross1', 'LGPL-2.1-or-later'),
    ('aarch64_libm', 'aarch64/usr/aarch64-linux-gnu/lib/libm.a',
        'libc6-dev-arm64-cross_2.36-8cross1', 'LGPL-2.1-or-later'),
]


def build(cli, archive, package, license_id, output, report, timeout):
    result = subprocess.run([str(cli), 'signatures', 'build', '--archive', str(archive),
        '--package', package, '--license', license_id, '--out', str(output),
        '--report', str(report)], capture_output=True, text=True, timeout=timeout)
    if result.returncode or not output.is_file() or not report.is_file():
        raise ValueError(f'signature build failed: {result.stdout[-2000:]} {result.stderr[-2000:]}')
    return json.loads(report.read_text())


def inspect(cli, database, timeout):
    result = subprocess.run([str(cli), 'signatures', 'info', '--db', str(database)],
        capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise ValueError(f'signature info failed: {result.stderr[-2000:]}')
    return json.loads(result.stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sysroots', type=Path, default=ROOT / 'third_party/sysroots')
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--timeout', type=int, default=900)
    args = parser.parse_args()
    subprocess.run(['cargo', 'build', '-q', '--release', '-p', 'lre-cli'], cwd=ROOT, check=True)
    cli = ROOT / 'target/release/lre-cli'
    rows = []
    with tempfile.TemporaryDirectory(prefix='vsig-gate-') as temporary:
        work = Path(temporary)
        for name, relative, package, license_id in SOURCES:
            row = dict(id=name, status='skipped', package=package, license=license_id)
            archive = args.sysroots / relative
            try:
                if not archive.is_file():
                    raise FileNotFoundError(f'missing pinned archive: {relative}')
                row['archive_sha256'] = digest(archive)
                built = build(cli, archive, package, license_id, work / f'{name}.vsig',
                    work / f'{name}.json', args.timeout)
                rebuilt = build(cli, archive, package, license_id, work / f'{name}-again.vsig',
                    work / f'{name}-again.json', args.timeout)
                database = work / f'{name}.vsig'
                if database.read_bytes() != (work / f'{name}-again.vsig').read_bytes():
                    raise ValueError('rebuild is not byte-identical')
                info = inspect(cli, database, args.timeout)
                if info['records'] != built['records'] or info['languages'] != [built['language']]:
                    raise ValueError('database contents disagree with the build report')
                if built['records'] == 0:
                    raise ValueError('archive produced no signatures')
                row.update(status='pass', language=built['language'],
                    members=built['members'], functions=built['functions'],
                    records=built['records'], skipped=built['skipped'],
                    compared_bytes_min=info['compared_bytes_min'],
                    database_bytes=database.stat().st_size,
                    database_sha256=digest(database),
                    rebuild_identical=True,
                    report_records_match=built['records'] == rebuilt['records'])
            except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
                row.setdefault('reason', str(error))
                if not isinstance(error, FileNotFoundError):
                    row['status'] = 'fail'
            rows.append(row)
            print(f"{row['status'].upper()} {name}: records={row.get('records')} "
                f"bytes={row.get('database_bytes')} {row.get('reason', '')}", flush=True)
    summary = {status: sum(row['status'] == status for row in rows)
        for status in ('pass', 'fail', 'skipped')}
    totals = dict(records=sum(row.get('records', 0) for row in rows),
        database_bytes=sum(row.get('database_bytes', 0) for row in rows))
    report = dict(gate='signatures', milestone='M2', task='m2-011',
        commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
        date=datetime.now(timezone.utc).isoformat(), gate_sha256=digest(Path(__file__)),
        comparison='record count and byte size of databases built from pinned static'
            ' archives, with byte-identical rebuilds; not an II.3 metric',
        sources=rows, summary=summary, totals=totals,
        passed=summary['fail'] == 0 and summary['pass'] != 0)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(summary=summary, totals=totals, passed=report['passed'])))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
