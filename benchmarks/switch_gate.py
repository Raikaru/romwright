#!/usr/bin/env python3
"""Stock switch target export and exact branch/target-set comparison."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from gen_oracle import address, digest, provenance
from xref_gate import address as typed_address

EXPORTER = ROOT / 'scripts/ExportSwitchTargets.java'


def target_sets(tables):
    """Compare edges, not case multiplicity; transport retains the original rows."""
    if not isinstance(tables, list):
        raise ValueError('Recovered switch metadata is unavailable')
    result = {}
    for table in tables:
        space, branch = typed_address(table['branch'])
        if space != 'ram' or branch in result:
            raise ValueError('Invalid or duplicate switch branch')
        targets = set()
        for target in table['targets']:
            space, offset = typed_address(target)
            if space != 'ram':
                raise ValueError('Switch target is not in RAM')
            targets.add(offset)
        if not targets:
            raise ValueError('Recovered table has no targets')
        result[branch] = targets
    return result


def stock_targets(install, binary, context, work, timeout=180):
    output = work / 'switches.json'
    command = [str(install / 'support/analyzeHeadless'), str(work), 'switch-targets',
        '-import', str(binary), '-processor', context['language'], '-cspec', context['compiler'],
        '-scriptPath', str(EXPORTER.parent), '-postScript', EXPORTER.name, str(output), '-deleteProject']
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, start_new_session=True, env=dict(os.environ, DEBUGINFOD_URLS=''))
    try:
        log, _ = process.communicate(timeout=timeout)
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.communicate()
        raise
    if process.returncode or not output.is_file():
        raise ValueError(f'Stock switch export failed: {log[-4000:]}')
    result = json.loads(output.read_text())
    if any(result.get(key) != value for key, value in context.items()):
        raise ValueError('Stock switch language/compiler mismatch')
    functions = {address(entry): tables for entry, tables in result['functions'].items()}
    if len(functions) != len(result['functions']) or not functions:
        raise ValueError('Invalid stock function set')
    for tables in functions.values():
        target_sets(tables)
    upstream = provenance(install)
    return dict(schema_version=1, sha256=digest(binary), exporter_sha256=digest(EXPORTER),
        producer='ghidra-headless', upstream_version=upstream['upstream_version'],
        upstream_revision=upstream['upstream_revision'], **context,
        image_base=address(result['image_base']), functions=functions)


def main():
    import argparse
    from datetime import datetime, timezone
    import tempfile
    from gen_native_specs import FILES, validate_bundle
    from gen_oracle import write_reference
    from gen_prototype_oracle import reference_path
    from prototype_gate import run_api

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus-dir', type=Path, required=True)
    parser.add_argument('--oracle-dir', type=Path, default=ROOT / 'oracle/switches-v1')
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--ghidra', type=Path, default=Path(os.environ.get(
        'VENTRIS_GHIDRA', str(Path.home() / 'ghidra_12.1.3_PUBLIC'))))
    parser.add_argument('--timeout', type=int, default=180)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error('timeout must be positive')
    env = dict(os.environ, VENTRIS_GHIDRA=str(args.ghidra.resolve()), DEBUGINFOD_URLS='')
    for name in ('VENTRIS_SLA', 'VENTRIS_LANGUAGE', 'VENTRIS_LANGUAGE_DIR', 'VENTRIS_SPECS'):
        env.pop(name, None)
    subprocess.run(['cargo', 'build', '-q', '-p', 'lre-api', '-p', 'lre-worker'],
        cwd=ROOT, env=env, check=True)
    lock = json.loads((ROOT / 'tests/corpus.lock.json').read_text())
    recipes = {row['architecture'] + '_' + row['variant']: row
        for row in lock['entries']
        if row['format'] == 'elf' and row['architecture'] in set(lock['oracle_matrix']['architectures'])}
    rows = []
    with tempfile.TemporaryDirectory(prefix='switch-native-gate-') as temporary:
        work = Path(temporary)
        checked = work / 'inputs.json'
        # Reuse the existing full source/recipe/stripped/twin/context validation.
        # Its arity scores do not participate in this switch comparison.
        subprocess.run([sys.executable, str(ROOT / 'scripts/gen_prototype_oracle.py'),
            '--check', '--corpus-dir', str(args.corpus_dir), '--ghidra', str(args.ghidra),
            '--report', str(checked)], cwd=ROOT, env=env, check=False, timeout=args.timeout)
        for checked_row in json.loads(checked.read_text())['corpus']:
            row = {key: checked_row[key] for key in
                ('id', 'status', 'sha256', 'twin_sha256', 'analysis_context', 'reason')
                if key in checked_row}
            if row['status'] != 'pass':
                rows.append(row)
                continue
            try:
                recipe = recipes[row['id']]
                binary = (args.corpus_dir / recipe['binary']).resolve()
                twin = (args.corpus_dir / recipe['unstripped_twin']).resolve()
                if digest(binary) != row['sha256'] or digest(twin) != row['twin_sha256']:
                    raise ValueError('Corpus input changed after validation')
                oracle_work = work / row['id']
                oracle_work.mkdir()
                try:
                    reference = stock_targets(args.ghidra.resolve(), binary,
                        row['analysis_context'], oracle_work, args.timeout)
                except (OSError, ValueError, subprocess.SubprocessError) as error:
                    row.update(status='skipped', reason=f'Stock oracle unavailable: {error}')
                    rows.append(row)
                    continue
                identity = {key: value for key, value in reference.items()
                    if key not in ('functions', 'image_base')}
                destination = reference_path(args.oracle_dir, identity)
                if destination.exists():
                    if json.loads(destination.read_text()) != reference:
                        raise ValueError('Fresh switch export differs from immutable reference')
                else:
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    write_reference(destination, reference)
                row.update(reference=str(destination.relative_to(args.oracle_dir)),
                    reference_sha256=digest(destination))
                language = reference['language']
                specs = ROOT / 'native/specs'
                if language != 'x86:LE:64:default':
                    validate_bundle(specs, {key: reference[key] for key in
                        ('language', 'compiler', 'upstream_version', 'upstream_revision')})
                    specs /= language.replace(':', '-')
                row['native_specs_sha256'] = {name: digest(specs / name) for name in FILES}
                project = oracle_work / 'native'
                imported, functions = run_api(ROOT, project, [
                    ('import_native', dict(binary=str(binary), name=row['id'])),
                    ('functions', dict(program=row['id']))], args.timeout, env)
                if imported['language'] != language or not functions:
                    raise ValueError('Native language mismatch or empty function set')
                docs = run_api(ROOT, project, [('decompile_doc', dict(binary=str(binary),
                    program=row['id'], address=function['entry'])) for function in functions],
                    args.timeout, env)
                observed = {}
                for function, doc in zip(functions, docs):
                    if doc['address'] != function['entry']:
                        raise ValueError('Native document address mismatch')
                    space, entry = typed_address(doc['address'])
                    if space != 'ram' or format(entry, '08x') in observed:
                        raise ValueError('Invalid or duplicate native function address')
                    observed[format(entry, '08x')] = target_sets(doc.get('jump_tables'))
                expected = {entry: target_sets(tables) for entry, tables in reference['functions'].items()}
                native_tables = {entry: tables for entry, tables in observed.items() if tables}
                stock_tables = {entry: tables for entry, tables in expected.items() if tables}
                if digest(binary) != row['sha256'] or digest(twin) != row['twin_sha256']:
                    raise ValueError('Corpus input changed during analysis')
                row.update(status='pass' if native_tables == stock_tables else 'fail',
                    native_functions=len(observed), stock_functions=len(expected),
                    native_tables=sum(map(len, native_tables.values())),
                    stock_tables=sum(map(len, stock_tables.values())),
                    native_only_functions=sorted(observed.keys() - expected.keys()),
                    stock_only_functions=sorted(expected.keys() - observed.keys()),
                    mismatched_functions=sorted(entry for entry in native_tables.keys() | stock_tables.keys()
                        if native_tables.get(entry) != stock_tables.get(entry)))
                # Keep nonempty native tables as evidence; the immutable stock
                # reference retains the full function set, including empties.
                row['recovered'] = {format(typed_address(doc['address'])[1], '08x'): doc['jump_tables']
                    for doc in docs if doc['jump_tables']}
            except OSError as error:
                row.update(status='skipped', reason=str(error))
            except (ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
                row.update(status='fail', reason=str(error))
            rows.append(row)
            print(f"{row['status'].upper()} {row['id']}: native={row.get('native_tables')} "
                f"stock={row.get('stock_tables')} {row.get('reason', '')}", flush=True)
    summary = {status: sum(row['status'] == status for row in rows) for status in ('pass', 'fail', 'skipped')}
    report = dict(gate='switches', milestone='M2', task='m2-007',
        commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
        date=datetime.now(timezone.utc).isoformat(),
        comparison='exact recovered function/branch/target sets; not an II.3 metric or full M2 gate',
        corpus=rows, summary=summary, passed=len(rows) == 20 and summary['pass'] == 20)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(summary=summary, passed=report['passed'])))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
