#!/usr/bin/env python3
"""Compare persisted non-returning function sets with stock analysis on the locked corpus."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from gen_native_specs import FILES, validate_bundle
from gen_oracle import address, digest, provenance, write_reference
from gen_prototype_oracle import reference_path
from prototype_gate import run_api
from xref_gate import address as typed_address

EXPORTER = ROOT / 'scripts/ExportReturnBehaviors.java'


def stock_behaviors(install, binary, context, work, timeout):
    if not EXPORTER.is_file():
        raise OSError(f'Missing stock return-behavior exporter: {EXPORTER}')
    output = work / 'return-behaviors.json'
    process = subprocess.Popen([str(install / 'support/analyzeHeadless'), str(work), 'return-behaviors',
        '-import', str(binary), '-processor', context['language'], '-cspec', context['compiler'],
        '-scriptPath', str(EXPORTER.parent), '-postScript', EXPORTER.name, str(output), '-deleteProject'],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, start_new_session=True,
        env=dict(os.environ, DEBUGINFOD_URLS=''))
    try:
        log, _ = process.communicate(timeout=timeout)
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        raise
    if process.returncode or not output.is_file():
        raise ValueError(f'Stock return-behavior export failed: {log[-4000:]}')
    result = json.loads(output.read_text())
    if any(result.get(key) != value for key, value in context.items()):
        raise ValueError('Stock return-behavior language/compiler mismatch')
    functions = {address(entry): value for entry, value in result['functions'].items()}
    if not functions or len(functions) != len(result['functions']) or any(
            type(value) is not bool for value in functions.values()):
        raise ValueError('Invalid stock return-behavior function set')
    upstream = provenance(install)
    return dict(schema_version=1, sha256=digest(binary), exporter_sha256=digest(EXPORTER),
        producer='ghidra-headless', upstream_version=upstream['upstream_version'],
        upstream_revision=upstream['upstream_revision'], **context,
        image_base=address(result['image_base']), functions=functions)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus-dir', type=Path, required=True)
    parser.add_argument('--oracle-dir', type=Path, default=ROOT / 'oracle/nonreturn-v1')
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
        for row in lock['entries'] if row['format'] == 'elf'}
    rows = []
    with tempfile.TemporaryDirectory(prefix='nonreturn-native-gate-') as temporary:
        work = Path(temporary)
        checked = work / 'inputs.json'
        # Reuse source, recipe, stripped/twin and analysis-context validation;
        # prototype arity scores do not participate in this comparison.
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
                    reference = stock_behaviors(args.ghidra.resolve(), binary,
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
                        raise ValueError('Fresh return-behavior export differs from immutable reference')
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
                context = dict(binary=str(binary), program=row['id'])
                imported, functions, analysis, facts, repeated = run_api(ROOT, oracle_work / 'native', [
                    ('import_native', dict(binary=str(binary), name=row['id'])),
                    ('functions', dict(program=row['id'])), ('infer_nonreturning', context),
                    ('return_behaviors', dict(program=row['id'])), ('infer_nonreturning', context)],
                    args.timeout, env)
                if imported['language'] != language or not functions:
                    raise ValueError('Native language mismatch or empty function set')
                observed = set()
                for fact in facts:
                    space, entry = typed_address(fact['function'])
                    if space != 'ram' or not fact['no_return'] or fact['provenance']['kind'] != 'inferred':
                        raise ValueError('Invalid inferred native return-behavior fact')
                    observed.add(format(entry, '08x'))
                expected = {entry for entry, value in reference['functions'].items() if value}
                if repeated['changed'] or repeated['revision'] != analysis['revision']:
                    raise ValueError('Repeated return analysis is not revision-idempotent')
                if digest(binary) != row['sha256'] or digest(twin) != row['twin_sha256']:
                    raise ValueError('Corpus input changed during analysis')
                row.update(status='pass' if observed == expected else 'fail',
                    native_functions=len(functions), stock_functions=len(reference['functions']),
                    native_nonreturning=sorted(observed), stock_nonreturning=sorted(expected),
                    unknown_functions=len(analysis['unknown']), rediscovered_callers=len(analysis['rediscovered']),
                    native_only=sorted(observed - expected), stock_only=sorted(expected - observed))
            except OSError as error:
                row.update(status='skipped', reason=str(error))
            except (ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
                row.update(status='fail', reason=str(error))
            rows.append(row)
            print(f"{row['status'].upper()} {row['id']}: native={row.get('native_nonreturning')} "
                f"stock={row.get('stock_nonreturning')} {row.get('reason', '')}", flush=True)
    summary = {status: sum(row['status'] == status for row in rows) for status in ('pass', 'fail', 'skipped')}
    report = dict(gate='nonreturn', milestone='M2', task='m2-008',
        commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
        date=datetime.now(timezone.utc).isoformat(),
        comparison='exact non-returning function sets; not an II.3 metric or full M2 gate',
        corpus=rows, summary=summary, passed=len(rows) == 20 and summary['pass'] == 20)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(summary=summary, passed=report['passed'])))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
