#!/usr/bin/env python3
"""Score MSVC RTTI class recovery against the linker's own map file (m2-014).

Truth is the `??_R4<class>@@6B...` complete-object-locator symbols a link emits:
one per class with a vtable. The fixture is freestanding, so it needs no MSVC
installation; the locked MSVC corpus entry, when present, declares no classes
and therefore checks that recovery invents none.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'benchmarks'))
from gen_oracle import digest
from prototype_gate import run_api

# (id, clang target triple, lld-link machine)
TARGETS = [
    ('x86_64_msvc', 'x86_64-pc-windows-msvc', 'x64'),
    ('i386_msvc', 'i386-pc-windows-msvc', 'x86'),
]
LOCATOR = re.compile(r'\?\?_R4([^\s@]+(?:@[^\s@]+)*)@@6')


def demangle(reversed_name):
    """`Widget@app` from a map symbol reads outermost-last, like the ABI."""
    parts = [part for part in reversed_name.split('@') if part]
    return '::'.join(reversed(parts))


def truth(map_file):
    return {demangle(name) for name in LOCATOR.findall(map_file.read_text())}


def build(target, machine, source, out, map_file, timeout):
    obj = out.with_suffix('.obj')
    compile_command = ['clang++', f'--target={target}', '-O2', '-c', '-o', str(obj), str(source)]
    result = subprocess.run(compile_command, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise ValueError(f'fixture compile failed: {result.stderr[-2000:]}')
    link = ['lld-link', '/nodefaultlib', '/entry:mainCRTStartup', '/subsystem:console',
        f'/machine:{machine}', f'/out:{out}', f'/map:{map_file}', str(obj)]
    result = subprocess.run(link, capture_output=True, text=True, timeout=timeout)
    if result.returncode or not out.is_file():
        raise ValueError(f'fixture link failed: {result.stdout[-1000:]} {result.stderr[-2000:]}')


def recover(work, binary, program, timeout, env):
    imported, classes = run_api(ROOT, work / f'{program}-project', [
        ('import_native', dict(binary=str(binary), name=program)),
        ('classes', dict(program=program))], timeout, env)
    for row in classes:
        if row['provenance']['kind'] != 'inferred' or not row['provenance']['source']:
            raise ValueError(f'a class fact is not inferred: {row}')
        if row['typeinfo']['space'] != 'Ram' or row['vtable']['space'] != 'Ram':
            raise ValueError(f'a class fact is not in RAM: {row}')
    return imported, classes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus-dir', type=Path)
    parser.add_argument('--source', type=Path, default=ROOT / 'tests/fixtures-src/msvc_rtti.cpp')
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--timeout', type=int, default=900)
    args = parser.parse_args()
    env = dict(os.environ, DEBUGINFOD_URLS='')
    for name in ('ROMWRIGHT_SLA', 'ROMWRIGHT_LANGUAGE', 'ROMWRIGHT_LANGUAGE_DIR', 'ROMWRIGHT_SPECS'):
        env.pop(name, None)
    subprocess.run(['cargo', 'build', '-q', '--release', '-p', 'romwright-api', '-p', 'romwright-worker'],
        cwd=ROOT, env=env, check=True)
    rows = []
    with tempfile.TemporaryDirectory(prefix='msvc-rtti-gate-') as temporary:
        work = Path(temporary)
        for name, target, machine in TARGETS:
            row = dict(id=name, status='skipped', target=target)
            try:
                binary = work / f'{name}.exe'
                map_file = work / f'{name}.map'
                build(target, machine, args.source, binary, map_file, args.timeout)
                expected = truth(map_file)
                if not expected:
                    raise ValueError('link map lists no complete object locators')
                imported, classes = recover(work, binary, name, args.timeout, env)
                found = {row['name'] for row in classes}
                row.update(status='pass' if found == expected else 'fail',
                    language=imported['language'], sha256=digest(binary),
                    locators=len(expected), classes=len(classes),
                    missing=sorted(expected - found), invented=sorted(found - expected),
                    names=sorted(found),
                    kinds={kind: sum(row['kind'] == kind for row in classes)
                        for kind in sorted({row['kind'] for row in classes})},
                    bases=sum(len(row['bases']) for row in classes),
                    virtual_bases=sum(sum(base['virtual_base'] for base in row['bases'])
                        for row in classes))
                if found != expected:
                    row['reason'] = 'recovered classes differ from the link map'
            except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
                row.update(status='fail', reason=str(error))
            rows.append(row)
            print(f"{row['status'].upper()} {name}: locators={row.get('locators')} "
                f"classes={row.get('classes')} missing={row.get('missing')} "
                f"invented={row.get('invented')} {row.get('reason', '')}", flush=True)
        if args.corpus_dir:
            lock = json.loads((ROOT / 'tests/corpus.lock.json').read_text())
            for recipe in (entry for entry in lock['entries'] if entry['format'] == 'pe'):
                name = f"corpus_{recipe['architecture']}_{recipe['variant']}"
                row = dict(id=name, status='skipped', target=recipe['architecture'])
                try:
                    binary = (args.corpus_dir / recipe['binary']).resolve()
                    if not binary.is_file():
                        raise FileNotFoundError(f'missing corpus binary {recipe["binary"]}')
                    _, classes = recover(work, binary, name, args.timeout, env)
                    row.update(status='pass' if not classes else 'fail',
                        sha256=digest(binary), classes=len(classes),
                        names=sorted(row['name'] for row in classes))
                    if classes:
                        row['reason'] = 'a class was invented for a source with no classes'
                except FileNotFoundError as error:
                    row['reason'] = str(error)
                except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
                    row.update(status='fail', reason=str(error))
                rows.append(row)
                print(f"{row['status'].upper()} {name}: classes={row.get('classes')} "
                    f"{row.get('reason', '')}", flush=True)
    summary = {status: sum(row['status'] == status for row in rows)
        for status in ('pass', 'fail', 'skipped')}
    totals = dict(locators=sum(row.get('locators', 0) for row in rows),
        classes=sum(row.get('classes', 0) for row in rows),
        bases=sum(row.get('bases', 0) for row in rows),
        virtual_bases=sum(row.get('virtual_bases', 0) for row in rows),
        missing=sum(len(row.get('missing', ())) for row in rows),
        invented=sum(len(row.get('invented', ())) for row in rows))
    report = dict(gate='msvc-rtti', milestone='M2', task='m2-014',
        commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
        date=datetime.now(timezone.utc).isoformat(), gate_sha256=digest(Path(__file__)),
        source_sha256=digest(args.source),
        comparison="recovered classes against the link map's complete object locators;"
            ' fixtures are gate inputs, not corpus members; not an II.3 metric',
        targets=rows, summary=summary, totals=totals,
        passed=summary['fail'] == 0 and summary['pass'] != 0)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(summary=summary, totals=totals, passed=report['passed'])))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
