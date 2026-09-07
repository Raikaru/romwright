#!/usr/bin/env python3
"""Score signature matching against unstripped truth (m2-012).

Gate inputs, not corpus members: a corpus source is statically linked with the
pinned cross toolchain so the pinned `libc.a` bodies land in the image, then
stripped. The unstripped twin supplies the names a match is checked against.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'benchmarks'))
from gen_corpus import ARCHITECTURES
from gen_oracle import digest
from prototype_gate import run_api

# Helpers every static glibc link pulls in; naming them is the ratified goal.
HELPERS = ('strlen', 'memcpy', 'memset', 'strcmp', 'memchr', 'malloc', 'free', 'abort')
PACKAGES = {
    'aarch64': ('libc6-dev-arm64-cross_2.36-8cross1', 'LGPL-2.1-or-later'),
    'i386': ('libc6-dev-i386-cross_2.36-8cross1', 'LGPL-2.1-or-later'),
    'powerpc': ('libc6-dev-powerpc-cross_2.36-8cross1', 'LGPL-2.1-or-later'),
}


def truth(binary):
    """Function symbol names by address, including aliases."""
    listing = subprocess.run(['readelf', '-sW', str(binary)], capture_output=True,
        text=True, check=True).stdout
    names = {}
    for line in listing.splitlines():
        parts = line.split()
        if len(parts) < 8 or 'FUNC' not in parts:
            continue
        try:
            address = int(parts[1], 16)
        except ValueError:
            continue
        name = parts[-1].split('@')[0]
        if address and name:
            names.setdefault(address, set()).add(name)
    if not names:
        raise ValueError(f'no function symbols in {binary}')
    return names


def build_database(cli, archive, package, license_id, out, timeout):
    result = subprocess.run([str(cli), 'signatures', 'build', '--archive', str(archive),
        '--package', package, '--license', license_id, '--out', str(out)],
        capture_output=True, text=True, timeout=timeout)
    if result.returncode or not out.is_file():
        raise ValueError(f'database build failed: {result.stderr[-2000:]}')
    return json.loads(result.stdout)


def link_static(architecture, source, out, timeout):
    config = ARCHITECTURES[architecture]
    command = list(config['c_compiler'])
    if config['sysroot']:
        command.append(f"--sysroot={config['sysroot']}")
    command += config['extra_flags']
    command += ['-static', '-O2', '-g', str(source), '-o', str(out)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    if result.returncode or not out.is_file():
        raise ValueError(f'static link failed: {result.stderr[-2000:]}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sysroots', type=Path, default=ROOT / 'third_party/sysroots')
    parser.add_argument('--source', type=Path, default=ROOT / 'tests/corpus-src/plain.c')
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--timeout', type=int, default=900)
    args = parser.parse_args()
    env = dict(os.environ, DEBUGINFOD_URLS='')
    for name in ('VENTRIS_SLA', 'VENTRIS_LANGUAGE', 'VENTRIS_LANGUAGE_DIR', 'VENTRIS_SPECS'):
        env.pop(name, None)
    subprocess.run(['cargo', 'build', '-q', '-p', 'lre-cli', '-p', 'lre-api', '-p', 'lre-worker'],
        cwd=ROOT, env=env, check=True)
    cli = ROOT / 'target/debug/lre-cli'
    rows = []
    with tempfile.TemporaryDirectory(prefix='match-gate-') as temporary:
        work = Path(temporary)
        for architecture, (package, license_id) in PACKAGES.items():
            row = dict(id=architecture, status='skipped', package=package, license=license_id)
            try:
                target = ARCHITECTURES[architecture]['target']
                archive = args.sysroots / architecture / 'usr' / target / 'lib' / 'libc.a'
                if not archive.is_file():
                    raise FileNotFoundError(f'missing pinned archive for {architecture}')
                database = work / f'{architecture}.vsig'
                built = build_database(cli, archive, package, license_id, database, args.timeout)
                twin = work / f'{architecture}.unstripped'
                link_static(architecture, args.source, twin, args.timeout)
                binary = work / f'{architecture}.bin'
                binary.write_bytes(twin.read_bytes())
                subprocess.run(['llvm-strip', '--strip-all', str(binary)], check=True)
                symbols = truth(twin)
                program = f'match_{architecture}'
                imported, matches, functions = run_api(ROOT, work / f'{architecture}-project', [
                    ('import_native', dict(binary=str(binary), name=program,
                        signatures=[str(database)])),
                    ('signature_matches', dict(program=program)),
                    ('functions', dict(program=program))], args.timeout, env)
                if imported['language'] != built['language']:
                    raise ValueError('database and image languages differ')
                named = {row['entry']['offset']: row['name'] for row in functions}
                correct, wrong = [], []
                for match in matches:
                    address = match['function']['offset']
                    if match['name'] in symbols.get(address, set()):
                        correct.append(match['name'])
                    else:
                        wrong.append(dict(address=format(address, '08x'), name=match['name'],
                            truth=sorted(symbols.get(address, set()))))
                    if not 0.0 < match['confidence'] <= 1.0:
                        raise ValueError(f'match confidence out of range: {match}')
                    if match['provenance']['kind'] != 'inferred':
                        raise ValueError('a signature match is not an assertion')
                    if named.get(address) != match['name']:
                        raise ValueError('a match did not name its function')
                helpers = sorted(name for name in HELPERS if name in set(correct))
                row.update(status='pass', language=built['language'],
                    database_records=built['records'], database_bytes=database.stat().st_size,
                    binary_sha256=digest(binary), functions=len(functions),
                    matches=len(matches), correct=len(correct), false_positives=len(wrong),
                    false_positive_rate=len(wrong) / len(matches) if matches else None,
                    helpers_named=helpers, wrong=wrong[:20])
                if len(helpers) < 4:
                    raise ValueError(f'named too few CRT helpers: {helpers}')
                if wrong:
                    raise ValueError(f'{len(wrong)} matches contradict the twin symbols')
            except FileNotFoundError as error:
                row['reason'] = str(error)
            except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
                row.update(status='fail', reason=str(error))
            rows.append(row)
            print(f"{row['status'].upper()} {architecture}: matches={row.get('matches')} "
                f"correct={row.get('correct')} fp={row.get('false_positives')} "
                f"helpers={row.get('helpers_named')} {row.get('reason', '')}", flush=True)
    summary = {status: sum(row['status'] == status for row in rows)
        for status in ('pass', 'fail', 'skipped')}
    matches = sum(row.get('matches', 0) for row in rows)
    false_positives = sum(row.get('false_positives', 0) for row in rows)
    totals = dict(matches=matches, correct=sum(row.get('correct', 0) for row in rows),
        false_positives=false_positives,
        false_positive_rate=false_positives / matches if matches else None)
    report = dict(gate='signature-match', milestone='M2', task='m2-012',
        commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
        date=datetime.now(timezone.utc).isoformat(), gate_sha256=digest(Path(__file__)),
        comparison='named library functions and their false-positive rate against unstripped'
            ' statically linked twins; gate inputs, not corpus members; not an II.3 metric',
        architectures=rows, summary=summary, totals=totals,
        passed=summary['fail'] == 0 and summary['pass'] != 0 and false_positives == 0)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(summary=summary, totals=totals, passed=report['passed'])))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
