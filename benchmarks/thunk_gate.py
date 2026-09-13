#!/usr/bin/env python3
"""Compare persisted thunk facts with stock thunk analysis on libc (m2-009)."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import gate_cache

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from gen_oracle import address, digest, provenance, write_reference
from gen_prototype_oracle import reference_path
from prototype_gate import run_api
from ui_gate import default_binary
from xref_gate import address as typed_address

EXPORTER = ROOT / 'scripts/ExportThunks.java'
TOLERANCE = 0.01


def export_thunks(install, binary, work, timeout):
    """One `analyzeHeadless` run of the pinned thunk exporter."""
    if not EXPORTER.is_file():
        raise OSError(f'Missing stock thunk exporter: {EXPORTER}')
    output = work / 'thunks.json'
    process = subprocess.Popen([str(install / 'support/analyzeHeadless'), str(work), 'thunks',
        '-import', str(binary), '-scriptPath', str(EXPORTER.parent),
        '-postScript', EXPORTER.name, str(output), '-deleteProject'],
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
        raise ValueError(f'Stock thunk export failed: {log[-4000:]}')
    return json.loads(output.read_text())


def stock_thunks(install, binary, work, timeout):
    """Stock's thunk facts for one image, reused across gate runs.

    Four gates (`m5-008`..`m5-011`) ask stock the same questions about the
    same corpus rows; the answer depends on the bytes, on the exporter script
    and on the pinned install, so it is keyed by exactly those and by nothing
    else (`benchmarks/gate_cache.py`). Every shape check below still runs on
    the reused answer.
    """
    result = gate_cache.document(
        gate_cache.stock_key(binary, install, artifact='thunks',
                             exporter_sha256=digest(EXPORTER)),
        lambda: export_thunks(install, binary, work, timeout))
    thunks = {address(entry): dict(fact, thunked=None if fact['thunked'] is None
        else address(fact['thunked'])) for entry, fact in result['thunks'].items()}
    if len(thunks) != len(result['thunks']) or not thunks:
        raise ValueError('Invalid stock thunk export')
    if type(result['functions']) is not int or result['functions'] < len(thunks):
        raise ValueError('Stock thunk count exceeds its function set')
    upstream = provenance(install)
    return dict(schema_version=1, sha256=digest(binary), exporter_sha256=digest(EXPORTER),
        producer='ghidra-headless', upstream_version=upstream['upstream_version'],
        upstream_revision=upstream['upstream_revision'], language=result['language'],
        compiler=result['compiler'], image_base=address(result['image_base']),
        functions=result['functions'], thunks=thunks)


def evidence(report, name, rows):
    """Keep complete address lists out of the aggregate report."""
    data = ''.join(json.dumps(row) + '\n' for row in rows).encode()
    sha = hashlib.sha256(data).hexdigest()
    path = report.parent / (report.stem + '-thunks') / f'{name}-{sha[:16]}.jsonl'
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_bytes() != data:
        raise ValueError('Immutable thunk evidence changed')
    path.write_bytes(data)
    return dict(count=len(rows), path=path.relative_to(report.parent).as_posix(), sha256=sha)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=None)
    parser.add_argument('--oracle-dir', type=Path, default=ROOT / 'oracle/thunks-v1')
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--ghidra', type=Path, default=Path(os.environ.get(
        'ROMWRIGHT_GHIDRA', str(Path.home() / 'ghidra_12.1.3_PUBLIC'))))
    parser.add_argument('--timeout', type=int, default=1800)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error('timeout must be positive')
    env = dict(os.environ, ROMWRIGHT_GHIDRA=str(args.ghidra.resolve()), DEBUGINFOD_URLS='')
    for name in ('ROMWRIGHT_SLA', 'ROMWRIGHT_LANGUAGE', 'ROMWRIGHT_LANGUAGE_DIR', 'ROMWRIGHT_SPECS'):
        env.pop(name, None)
    row = dict(status='skipped')
    try:
        binary = (args.binary or default_binary()).resolve()
        subprocess.run(['cargo', 'build', '-q', '--release', '-p', 'romwright-api', '-p', 'romwright-worker'],
            cwd=ROOT, env=env, check=True)
        row.update(binary=str(binary), sha256=digest(binary))
        with tempfile.TemporaryDirectory(prefix='thunk-gate-') as temporary:
            work = Path(temporary)
            reference = stock_thunks(args.ghidra.resolve(), binary, work, args.timeout)
            identity = {key: value for key, value in reference.items()
                if key not in ('thunks', 'image_base', 'functions')}
            destination = reference_path(args.oracle_dir, identity)
            if destination.exists():
                if json.loads(destination.read_text()) != reference:
                    raise ValueError('Fresh thunk export differs from immutable reference')
            else:
                destination.parent.mkdir(parents=True, exist_ok=True)
                write_reference(destination, reference)
            imported, functions, thunks = run_api(ROOT, work / 'native', [
                ('import_native', dict(binary=str(binary), name='libc')),
                ('functions', dict(program='libc')),
                ('thunks', dict(program='libc'))], args.timeout, env)
            if imported['language'] != reference['language']:
                raise ValueError('Native and stock languages differ')
            if digest(binary) != row['sha256']:
                raise ValueError('Input changed during analysis')
        entries = {typed_address(function['entry'])[1] for function in functions}
        native = {}
        for fact in thunks:
            space, entry = typed_address(fact['function'])
            target_space, target = typed_address(fact['thunked'])
            if space != 'ram' or target_space != 'ram' or entry not in entries:
                raise ValueError('Invalid native thunk fact')
            if fact['provenance']['kind'] != 'inferred' or not fact['provenance']['source']:
                raise ValueError('Native thunk fact lacks inferred provenance')
            native[format(entry, '08x')] = dict(kind=fact['kind'], thunked=format(target, '08x'))
        if len(native) != len(thunks):
            raise ValueError('Duplicate native thunk facts')
        expected = set(reference['thunks'])
        observed = set(native)
        ratio = abs(len(observed) - len(expected)) / len(expected)
        row.update(status='pass' if ratio <= TOLERANCE else 'fail',
            reference=str(destination.relative_to(args.oracle_dir)),
            reference_sha256=digest(destination), language=reference['language'],
            compiler=reference['compiler'], stock_functions=reference['functions'],
            native_functions=len(functions), stock_thunks=len(expected),
            native_thunks=len(observed), count_ratio=ratio, tolerance=TOLERANCE,
            native_kinds={kind: sum(fact['kind'] == kind for fact in native.values())
                for kind in sorted({fact['kind'] for fact in native.values()})},
            stock_external_thunks=sum(fact['external'] for fact in reference['thunks'].values()),
            matched=evidence(args.report, 'matched', sorted(observed & expected)),
            native_only=evidence(args.report, 'native-only', [dict(entry=entry, **native[entry])
                for entry in sorted(observed - expected)]),
            stock_only=evidence(args.report, 'stock-only', [dict(entry=entry,
                **reference['thunks'][entry]) for entry in sorted(expected - observed)]))
    except OSError as error:
        row['reason'] = str(error)
    except (ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        row.update(status='fail', reason=str(error))
    report = dict(gate='thunk', milestone='M2', task='m2-009',
        commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
        date=datetime.now(timezone.utc).isoformat(), gate_sha256=digest(Path(__file__)),
        exporter_sha256=digest(EXPORTER),
        comparison=f'thunk function counts on one host libc within +/-{TOLERANCE:.0%};'
            ' not an II.3 metric or the full M2 gate',
        corpus=[row], summary={status: int(row['status'] == status)
            for status in ('pass', 'fail', 'skipped')}, passed=row['status'] == 'pass')
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(status=row['status'], stock=row.get('stock_thunks'),
        native=row.get('native_thunks'), ratio=row.get('count_ratio'),
        reason=row.get('reason'), passed=report['passed'])))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
