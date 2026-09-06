"""Frozen II.3 prototype arity scoring shared by reference and native gates."""
import hashlib
import json


def score_arity(truth, observed):
    matched = sorted(truth.keys() & observed.keys())
    if not matched:
        raise ValueError('no functions matched the DWARF truth')
    incorrect = []
    for entry in matched:
        actual, expected = observed[entry], truth[entry]['arity']
        if actual is not None and (type(actual) is not int or actual < 0):
            raise ValueError(f'invalid observed arity at {entry}: {actual!r}')
        if actual != expected:
            incorrect.append(dict(entry=entry, expected=expected, actual=actual))
    correct = len(matched) - len(incorrect)
    return dict(matched=len(matched), correct=correct, value=correct / len(matched),
        incorrect=incorrect, unmatched_truth=sorted(truth.keys() - observed.keys()))


def write_arity_report(path, report):
    """Keep complete mismatch evidence readable without oversized report commits."""
    path.parent.mkdir(parents=True, exist_ok=True)
    for row in report['corpus']:
        for producer, score in row.get('scores', {}).items():
            incorrect = score.pop('incorrect', None)
            if incorrect is None:
                continue
            score['incorrect_count'] = len(incorrect)
            if incorrect:
                data = ''.join(json.dumps(item) + '\n' for item in incorrect).encode()
                sha = hashlib.sha256(data).hexdigest()
                detail = path.parent / (path.stem + '-mismatches') / (
                    f"{row['id']}-{producer}-{sha[:16]}.jsonl")
                detail.parent.mkdir(parents=True, exist_ok=True)
                detail.write_bytes(data)
                score['incorrect_evidence'] = dict(
                    path=detail.relative_to(path.parent).as_posix(), sha256=sha)
    path.write_text(json.dumps(report, indent=2) + '\n')


def write_native_report(path, report, recipes):
    """Link architecture detail without oversized aggregate report commits."""
    evidence = {}
    for architecture in dict.fromkeys(recipe['architecture'] for recipe in recipes.values()):
        rows = [row for row in report['corpus'] if recipes[row['id']]['architecture'] == architecture]
        detail = {key: value for key, value in report.items() if key not in ('corpus', 'summary', 'passed')}
        detail.update(architecture=architecture, corpus=rows)
        destination = path.with_name(path.stem + '-' + architecture + '.json')
        write_arity_report(destination, detail)
        evidence[architecture] = dict(path=destination.name,
            sha256=hashlib.sha256(destination.read_bytes()).hexdigest())
    report['corpus'] = [
        dict({key: value for key, value in row.items()
              if key in ('id', 'status', 'metrics', 'thresholds', 'reason')},
             evidence=evidence[recipes[row['id']]['architecture']])
        for row in report['corpus']]
    write_arity_report(path, report)


def run_api(root, project, requests, timeout, env):
    """Bound the finite API batch and its native children as one process group."""
    import os
    import signal
    import subprocess
    process = subprocess.Popen(
        [str(root / 'target/debug/lre-api'), '--project', str(project)],
        cwd=root, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, start_new_session=True)
    payload = ''.join(json.dumps(dict(api=2, id=index, method=method, params=params)) + '\n'
        for index, (method, params) in enumerate(requests))
    try:
        stdout, stderr = process.communicate(payload, timeout=timeout)
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.communicate()
        raise
    if process.returncode:
        raise ValueError(f'Native API exited {process.returncode}: {stderr[-4000:]}')
    replies = [json.loads(line) for line in stdout.splitlines()]
    if len(replies) != len(requests) or any(reply['id'] != index for index, reply in enumerate(replies)):
        raise ValueError('Native API response sequence mismatch')
    errors = [dict(request=requests[index], error=reply['error'])
        for index, reply in enumerate(replies) if reply.get('error')]
    if errors:
        raise ValueError(json.dumps(errors))
    return [reply['result'] for reply in replies]


def main():
    import argparse
    from datetime import datetime, timezone
    import os
    from pathlib import Path
    import platform
    import subprocess
    import sys
    import tempfile
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root / 'scripts'))
    from gen_corpus import get_load_segments
    from gen_oracle import digest
    from gen_native_specs import FILES, validate_bundle
    from dwarf_arity import extract
    from ui_gate import physical_memory_gb
    from xref_gate import address as typed_address

    def address(value):
        space, offset = typed_address(value)
        if space != 'ram':
            raise ValueError(f'Native function is not in RAM: {value!r}')
        return format(offset, '08x')

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus-dir', type=Path, required=True)
    parser.add_argument('--oracle-dir', type=Path, default=root / 'oracle/prototypes-v1')
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--ghidra', type=Path, default=Path(os.environ.get(
        'VENTRIS_GHIDRA', str(Path.home() / 'ghidra_12.1.3_PUBLIC'))))
    parser.add_argument('--budget-ms', type=int, default=60000)
    parser.add_argument('--timeout', type=int, default=180)
    args = parser.parse_args()
    if args.budget_ms < 0 or args.timeout <= 0:
        parser.error('budget must be nonnegative and timeout must be positive')
    env = dict(os.environ, VENTRIS_GHIDRA=str(args.ghidra.resolve()), DEBUGINFOD_URLS='')
    for name in ('VENTRIS_SLA', 'VENTRIS_LANGUAGE', 'VENTRIS_LANGUAGE_DIR', 'VENTRIS_SPECS'):
        env.pop(name, None)
    subprocess.run(['cargo', 'build', '-q', '-p', 'lre-api', '-p', 'lre-worker'],
        cwd=root, env=env, check=True)
    lock = json.loads((root / 'tests/corpus.lock.json').read_text())
    recipes = {row['architecture'] + '_' + row['variant']: row
        for row in lock['entries'] if row['format'] == 'elf'}
    rows = []
    with tempfile.TemporaryDirectory(prefix='prototype-native-gate-') as temporary:
        work = Path(temporary)
        checked = work / 'reference.json'
        # This existing check validates the full lock, sources, stripped/twin
        # hashes and immutable reference contexts. It never regenerates stock.
        subprocess.run([sys.executable, str(root / 'scripts/gen_prototype_oracle.py'),
            '--check', '--corpus-dir', str(args.corpus_dir), '--oracle-dir', str(args.oracle_dir),
            '--ghidra', str(args.ghidra), '--report', str(checked)],
            cwd=root, env=env, check=False, timeout=args.timeout)
        references = json.loads(checked.read_text())
        for checked_row in references['corpus']:
            row = {key: value for key, value in checked_row.items()
                if key not in ('scores', 'metrics', 'thresholds', 'runs')}
            row.update(metrics={}, thresholds={}, runs=1)
            if row['status'] != 'pass':
                rows.append(row)
                print(f"{row['status'].upper()} {row['id']}: {row.get('reason')}", flush=True)
                continue
            try:
                recipe = recipes[row['id']]
                binary = (args.corpus_dir / recipe['binary']).resolve()
                twin = (args.corpus_dir / recipe['unstripped_twin']).resolve()
                baseline = args.oracle_dir / row['reference']
                if digest(baseline) != row['reference_sha256']:
                    raise ValueError('Immutable reference changed after validation')
                reference = json.loads(baseline.read_text())
                if digest(binary) != row['sha256'] or digest(twin) != row['twin_sha256']:
                    raise ValueError('Corpus input changed after validation')
                specs = root / 'native/specs'
                language = reference['language']
                if language != 'x86:LE:64:default':
                    validate_bundle(specs, {key: reference[key] for key in
                        ('language', 'compiler', 'upstream_version', 'upstream_revision')})
                    specs = specs / language.replace(':', '-')
                row['native_specs_sha256'] = {name: digest(specs / name) for name in FILES}
                project = work / row['id']
                context = dict(binary=str(binary), program=row['id'])
                imported, functions = run_api(root, project, [
                    ('import_native', dict(binary=str(binary), name=row['id'])),
                    ('functions', dict(program=row['id']))], args.timeout, env)
                if imported['language'] != row['analysis_context']['language']:
                    raise ValueError('Native/reference language mismatch')
                inference, stored = run_api(root, project, [
                    ('infer_prototypes', dict(**context, budget_ms=args.budget_ms)),
                    ('prototypes', dict(program=row['id']))], args.timeout, env)
                docs = run_api(root, project, [
                    ('decompile_doc', dict(**context, address=function['entry']))
                    for function in functions], args.timeout, env)
                persisted = {address(prototype['function']) for prototype in stored}
                observed = {address(function['entry']): None for function in functions}
                for function, doc in zip(functions, docs):
                    entry = address(function['entry'])
                    if doc['address'] != function['entry']:
                        raise ValueError('Native document address mismatch')
                    if entry in persisted and doc.get('prototype') is not None:
                        observed[entry] = len(doc['prototype']['parameters'])
                # Only the scoring process reads DWARF. Neither the inference
                # request nor its function list is selected from the oracle.
                load_base = min(start for start, size, _, _, _ in get_load_segments(binary.read_bytes()) if size)
                truth = extract(twin, int(reference['image_base'], 16) - load_base)
                if digest(binary) != row['sha256'] or digest(twin) != row['twin_sha256']:
                    raise ValueError('Corpus input changed during native analysis')
                native = score_arity(truth['functions'], observed)
                ghidra = score_arity(truth['functions'], reference['arities'])
                threshold = ghidra['value'] - 0.02
                row.update(status='pass' if native['value'] >= threshold else 'fail',
                    inference=inference, native_functions=len(functions), persisted_prototypes=len(stored),
                    scores=dict(native=native, ghidra=ghidra),
                    metrics={'proto.arity': native['value'], 'ghidra.proto.arity': ghidra['value']},
                    thresholds={'proto.arity': threshold})
            except OSError as error:
                row.update(status='skipped', reason=str(error))
            except (ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
                row.update(status='fail', reason=str(error))
            rows.append(row)
            print(f"{row['status'].upper()} {row['id']}: {row.get('reason', row['metrics'])}", flush=True)
    summary = {status: sum(row['status'] == status for row in rows) for status in ('pass', 'fail', 'skipped')}
    report = dict(gate='prototypes', milestone='M2', task='m2-006',
        commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
        date=datetime.now(timezone.utc).isoformat(),
        machine=dict(os=platform.platform(), cpu=platform.processor() or platform.machine(), ram_gb=physical_memory_gb()),
        budget_ms=args.budget_ms, dwarf_reader_sha256=digest(root / 'benchmarks/dwarf_arity.py'),
        native_patch_sha256=digest(root / 'native/ghidra-opt-sleigh.patch'),
        corpus=rows, summary=summary, passed=len(rows) == 20 and summary['pass'] == 20)
    write_native_report(args.report, report, recipes)
    print(json.dumps(dict(summary=summary, passed=report['passed'])))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
