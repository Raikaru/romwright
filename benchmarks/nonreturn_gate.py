#!/usr/bin/env python3
"""Compare persisted non-returning function sets with stock analysis on the locked corpus."""
import argparse
from datetime import datetime, timezone
import gzip
import hashlib
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
from gen_oracle import address, digest, provenance, validate_reference, write_reference
from gen_function_scoring import POLICY, expected_view, validate_view
from gen_prototype_oracle import reference_path
from prototype_gate import run_api, write_native_report
from xref_gate import address as typed_address

EXPORTER = ROOT / 'scripts/ExportReturnBehaviors.java'


def compare_return_flags(observed, expected):
    """Stock false is absence of a positive flag, not a returning assertion."""
    return dict(stock_positives_covered=expected <= observed,
        native_only=sorted(observed - expected), stock_only=sorted(expected - observed))


def bounds_score(functions, bodies, eligible):
    """II.3: exact matched entry, exact range count, ±16 bytes at each end."""
    matched = correct = 0
    mismatches = []
    for function in functions:
        space, entry = typed_address(function['entry'])
        key = format(entry, '08x')
        if space != 'ram' or key not in eligible:
            continue
        matched += 1
        ranges = bodies[key]
        size = function['size']
        native = [[key, format(entry + size - 1, '08x')]] if size else []
        valid = (len(ranges) == 1 and size > 0
            and abs(int(ranges[0][0], 16) - entry) <= 16
            and abs(int(ranges[0][1], 16) - (entry + size - 1)) <= 16)
        correct += int(valid)
        if not valid:
            mismatches.append(dict(entry=key, native=native, reference=ranges))
    return dict(matched=matched, correct=correct,
        **{'fn.bounds': correct / matched if matched else None}, mismatches=mismatches)

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
    bodies = {address(entry): [[address(start), address(end)] for start, end in ranges]
        for entry, ranges in result['bodies'].items()}
    if set(bodies) != set(functions) or len(bodies) != len(result['bodies']):
        raise ValueError('Stock body evidence does not cover the function set')
    for ranges in bodies.values():
        previous = -1
        for start, end in ranges:
            if int(start, 16) <= previous or int(end, 16) < int(start, 16):
                raise ValueError('Invalid stock function body range ordering')
            previous = int(end, 16)
    upstream = provenance(install)
    return dict(schema_version=1, sha256=digest(binary), exporter_sha256=digest(EXPORTER),
        producer='ghidra-headless', upstream_version=upstream['upstream_version'],
        upstream_revision=upstream['upstream_revision'], **context,
        image_base=address(result['image_base']), functions=functions, bodies=bodies)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus-dir', type=Path, required=True)
    parser.add_argument('--oracle-dir', type=Path, default=ROOT / 'oracle/nonreturn-v1')
    parser.add_argument('--raw-oracle-dir', type=Path, default=ROOT / 'oracle')
    parser.add_argument('--scoring-dir', type=Path, default=ROOT / 'oracle/scoring-v1')
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
                raw_path = args.raw_oracle_dir / f"{row['sha256']}.json"
                scoring_path = args.scoring_dir / raw_path.name
                raw = json.loads(raw_path.read_text())
                validate_reference(raw, dict(schema_version=1, sha256=row['sha256'],
                    binary_size=binary.stat().st_size, **provenance(args.ghidra),
                    address_basis='ghidra'))
                view = json.loads(scoring_path.read_text())
                validate_view(view, raw, expected_view(binary, raw_path))
                eligible = set(view['entries'])
                row.update(scoring_policy=POLICY, scoring_sha256=digest(scoring_path),
                    raw_reference_sha256=digest(raw_path), excluded_functions=len(view['excluded']))
                oracle_work = work / row['id']
                oracle_work.mkdir()
                try:
                    reference = stock_behaviors(args.ghidra.resolve(), binary,
                        row['analysis_context'], oracle_work, args.timeout)
                except (OSError, ValueError, subprocess.SubprocessError) as error:
                    row.update(status='skipped', reason=f'Stock oracle unavailable: {error}')
                    rows.append(row)
                    continue
                if set(reference['functions']) != set(raw['entries']):
                    raise ValueError('Fresh behavior/body evidence differs from raw function set')
                identity = {key: value for key, value in reference.items()
                    if key not in ('functions', 'bodies', 'image_base')}
                destination = reference_path(args.oracle_dir, identity)
                if destination.exists():
                    if json.loads(destination.read_text()) != reference:
                        raise ValueError('Fresh return-behavior export differs from immutable reference')
                else:
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    write_reference(destination, reference)
                row.update(reference=str(destination.relative_to(args.oracle_dir)),
                    reference_sha256=digest(destination))
                evidence = gzip.compress(json.dumps(dict(return_behavior=reference,
                    raw_oracle=raw, scoring_view=view), indent=2).encode(), mtime=0)
                evidence_sha = hashlib.sha256(evidence).hexdigest()
                evidence_path = args.report.parent / (args.report.stem + '-references') / (
                    f"{row['id']}-{evidence_sha[:16]}.json.gz")
                evidence_path.parent.mkdir(parents=True, exist_ok=True)
                if evidence_path.exists() and evidence_path.read_bytes() != evidence:
                    raise ValueError('Immutable reference evidence changed')
                if not evidence_path.exists():
                    evidence_path.write_bytes(evidence)
                row['reference_evidence'] = dict(
                    path=evidence_path.relative_to(args.report.parent).as_posix(),
                    sha256=evidence_sha)
                language = reference['language']
                specs = ROOT / 'native/specs'
                if language != 'x86:LE:64:default':
                    validate_bundle(specs, {key: reference[key] for key in
                        ('language', 'compiler', 'upstream_version', 'upstream_revision')})
                    specs /= language.replace(':', '-')
                row['native_specs_sha256'] = {name: digest(specs / name) for name in FILES}
                context = dict(binary=str(binary), program=row['id'])
                imported, functions, analysis, facts, refreshed, repeated = run_api(ROOT, oracle_work / 'native', [
                    ('import_native', dict(binary=str(binary), name=row['id'])),
                    ('functions', dict(program=row['id'])), ('infer_nonreturning', context),
                    ('return_behaviors', dict(program=row['id'])),
                    ('functions', dict(program=row['id'])), ('infer_nonreturning', context)],
                    args.timeout, env)
                if imported['language'] != language or not functions:
                    raise ValueError('Native language mismatch or empty function set')
                observed = set()
                for fact in facts:
                    space, entry = typed_address(fact['function'])
                    if space != 'ram' or not fact['no_return'] or fact['provenance']['kind'] != 'inferred':
                        raise ValueError('Invalid inferred native return-behavior fact')
                    observed.add(format(entry, '08x'))
                expected = {entry for entry, value in reference['functions'].items()
                    if value and entry in eligible}
                observed -= {item['entry'] for item in view['excluded']}
                comparison = compare_return_flags(observed, expected)
                before = bounds_score(functions, reference['bodies'], eligible)
                after = bounds_score(refreshed, reference['bodies'], eligible)
                if repeated['changed'] or repeated['revision'] != analysis['revision']:
                    raise ValueError('Repeated return analysis is not revision-idempotent')
                if digest(binary) != row['sha256'] or digest(twin) != row['twin_sha256']:
                    raise ValueError('Corpus input changed during analysis')
                bounds_preserved = (before['matched'] == after['matched'] > 0
                    and after['correct'] >= before['correct'])
                for score in (before, after):
                    score['incorrect'] = score.pop('mismatches')
                row.update(status='pass' if comparison['stock_positives_covered'] and bounds_preserved else 'fail',
                    native_functions=len(functions), stock_functions=len(eligible),
                    scores=dict(before=before, after=after),
                    native_nonreturning=sorted(observed), stock_nonreturning=sorted(expected),
                    unknown_functions=len(analysis['unknown']), rediscovered_callers=len(analysis['rediscovered']),
                    **comparison)
            except OSError as error:
                row.update(status='skipped', reason=str(error))
            except (ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
                row.update(status='fail', reason=str(error))
            rows.append(row)
            print(f"{row['status'].upper()} {row['id']}: native={row.get('native_nonreturning')} "
                f"stock={row.get('stock_nonreturning')} {row.get('reason', '')}", flush=True)
    summary = {status: sum(row['status'] == status for row in rows) for status in ('pass', 'fail', 'skipped')}
    optimized = [row for row in rows if recipes[row['id']]['variant'].endswith('_o2')]
    bounds = {}
    for phase in ('before', 'after'):
        scores = [row['scores'][phase] for row in optimized if 'scores' in row]
        matched = sum(score['matched'] for score in scores)
        correct = sum(score['correct'] for score in scores)
        bounds[phase] = dict(matched=matched, correct=correct,
            **{'fn.bounds': correct / matched if matched else None})
    improved = (bounds['after']['matched'] == bounds['before']['matched'] > 0
        and bounds['after']['correct'] > bounds['before']['correct'])
    report = dict(gate='nonreturn', milestone='M2', task='m2-008',
        commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
        date=datetime.now(timezone.utc).isoformat(),
        gate_sha256=digest(Path(__file__)), exporter_sha256=digest(EXPORTER),
        optimized_bounds_scope='all locked *_o2 recipes, not architecture-filtered',
        comparison='code-functions-v1 stock positive flags and II.3 fn.bounds; stock false is unknown; not the full M2 gate',
        optimized_bounds=bounds, optimized_bounds_improved=improved,
        corpus=rows, summary=summary, passed=len(rows) == 20 and summary['pass'] == 20 and improved)
    write_native_report(args.report, report, recipes)
    print(json.dumps(dict(summary=summary, passed=report['passed'])))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
