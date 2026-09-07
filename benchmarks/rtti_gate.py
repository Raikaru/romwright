#!/usr/bin/env python3
"""Score Itanium C++ class recovery against the compiler's own vtables (m2-013).

Truth is the unstripped twin's `_ZTV<name>` symbols: the compiler emits exactly
one primary vtable per polymorphic class. The locked corpus C++ entries define
no classes, so they check the other direction — recovery must invent none.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'benchmarks'))
from gen_corpus import ARCHITECTURES
from gen_oracle import digest
from prototype_gate import run_api

# Gate inputs: (id, architecture, extra link flags). Both link modes matter:
# a non-PIE link copies the ABI type_info vtables into the image, a PIE link
# binds them through a relocation instead.
FIXTURES = [
    ('x86_64_nopie', 'x86_64', ['-fno-pie', '-no-pie']),
    ('x86_64_pie', 'x86_64', ['-fPIE', '-pie']),
    ('aarch64_pie', 'aarch64', ['-fPIE', '-pie']),
    ('powerpc_nopie', 'powerpc', ['-fno-pie', '-no-pie']),
]


def vtable_classes(binary):
    """Mangled class names from `_ZTV*` symbols, excluding the ABI's own."""
    listing = subprocess.run(['readelf', '-sW', str(binary)], capture_output=True,
        text=True, check=True).stdout
    names = set()
    for line in listing.splitlines():
        parts = line.split()
        if len(parts) < 8 or 'OBJECT' not in parts or parts[6] == 'UND':
            continue
        name = parts[-1].split('@')[0]
        if name.startswith('_ZTV') and not name.startswith('_ZTVN10__cxxabiv1'):
            names.add(name.removeprefix('_ZTV'))
    return names


def compile_fixture(architecture, flags, source, out, timeout):
    config = ARCHITECTURES[architecture]
    command = list(config['cxx_compiler'])
    if config['sysroot']:
        command.append(f"--sysroot={config['sysroot']}")
    command += config['extra_flags']
    command += ['-O2', '-g', *flags, str(source), '-o', str(out)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    if result.returncode or not out.is_file():
        raise ValueError(f'fixture link failed: {result.stderr[-2000:]}')


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
    parser.add_argument('--source', type=Path, default=ROOT / 'tests/fixtures-src/rtti.cpp')
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--timeout', type=int, default=900)
    args = parser.parse_args()
    env = dict(os.environ, DEBUGINFOD_URLS='')
    for name in ('VENTRIS_SLA', 'VENTRIS_LANGUAGE', 'VENTRIS_LANGUAGE_DIR', 'VENTRIS_SPECS'):
        env.pop(name, None)
    subprocess.run(['cargo', 'build', '-q', '-p', 'lre-api', '-p', 'lre-worker'],
        cwd=ROOT, env=env, check=True)
    rows = []
    with tempfile.TemporaryDirectory(prefix='rtti-gate-') as temporary:
        work = Path(temporary)
        for name, architecture, flags in FIXTURES:
            row = dict(id=name, status='skipped', architecture=architecture, link=' '.join(flags))
            try:
                twin = work / f'{name}.unstripped'
                compile_fixture(architecture, flags, args.source, twin, args.timeout)
                binary = work / f'{name}.bin'
                shutil.copyfile(twin, binary)
                subprocess.run(['llvm-strip', '--strip-all', str(binary)], check=True)
                truth = vtable_classes(twin)
                if not truth:
                    raise ValueError('fixture twin declares no vtables')
                imported, classes = recover(work, binary, name, args.timeout, env)
                found = {row['mangled'] for row in classes}
                row.update(status='pass' if found == truth else 'fail',
                    language=imported['language'], sha256=digest(binary),
                    vtables=len(truth), classes=len(classes),
                    missing=sorted(truth - found), invented=sorted(found - truth),
                    names=sorted(row['name'] for row in classes),
                    kinds={kind: sum(row['kind'] == kind for row in classes)
                        for kind in sorted({row['kind'] for row in classes})},
                    bases=sum(len(row['bases']) for row in classes))
                if found != truth:
                    row['reason'] = 'recovered classes differ from the twin vtables'
            except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
                row.update(status='fail', reason=str(error))
            rows.append(row)
            print(f"{row['status'].upper()} {name}: vtables={row.get('vtables')} "
                f"classes={row.get('classes')} missing={row.get('missing')} "
                f"invented={row.get('invented')} {row.get('reason', '')}", flush=True)
        if args.corpus_dir:
            lock = json.loads((ROOT / 'tests/corpus.lock.json').read_text())
            for recipe in (entry for entry in lock['entries'] if entry['variant'] == 'cpp_o2'):
                name = f"corpus_{recipe['architecture']}_cpp_o2"
                row = dict(id=name, status='skipped', architecture=recipe['architecture'],
                    link='locked corpus entry')
                try:
                    binary = (args.corpus_dir / recipe['binary']).resolve()
                    twin = (args.corpus_dir / recipe['unstripped_twin']).resolve()
                    if not binary.is_file():
                        raise FileNotFoundError(f'missing corpus binary {recipe["binary"]}')
                    truth = vtable_classes(twin)
                    _, classes = recover(work, binary, name, args.timeout, env)
                    found = {row['mangled'] for row in classes}
                    row.update(status='pass' if found == truth else 'fail',
                        sha256=digest(binary), vtables=len(truth), classes=len(classes),
                        missing=sorted(truth - found), invented=sorted(found - truth))
                    if found != truth:
                        row['reason'] = 'a class was invented for a source with no classes'
                except FileNotFoundError as error:
                    row['reason'] = str(error)
                except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
                    row.update(status='fail', reason=str(error))
                rows.append(row)
                print(f"{row['status'].upper()} {name}: vtables={row.get('vtables')} "
                    f"classes={row.get('classes')} {row.get('reason', '')}", flush=True)
    summary = {status: sum(row['status'] == status for row in rows)
        for status in ('pass', 'fail', 'skipped')}
    totals = dict(vtables=sum(row.get('vtables', 0) for row in rows),
        classes=sum(row.get('classes', 0) for row in rows),
        bases=sum(row.get('bases', 0) for row in rows),
        missing=sum(len(row.get('missing', ())) for row in rows),
        invented=sum(len(row.get('invented', ())) for row in rows))
    report = dict(gate='itanium-rtti', milestone='M2', task='m2-013',
        commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
        date=datetime.now(timezone.utc).isoformat(), gate_sha256=digest(Path(__file__)),
        source_sha256=digest(args.source),
        comparison='recovered classes against the unstripped twins\' `_ZTV` vtable symbols;'
            ' fixtures are gate inputs, not corpus members; not an II.3 metric',
        targets=rows, summary=summary, totals=totals,
        passed=summary['fail'] == 0 and summary['pass'] != 0)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(summary=summary, totals=totals, passed=report['passed'])))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
