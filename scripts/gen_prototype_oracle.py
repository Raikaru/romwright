#!/usr/bin/env python3
"""Export fresh stock parameter-ID arities; DWARF is scoring truth only."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import tempfile

from gen_corpus import get_load_segments, parse_elf_sections, validate_elf_twin
from gen_oracle import ROOT, address, digest, provenance, write_reference
sys.path.insert(0, str(ROOT / 'benchmarks'))
from dwarf_arity import extract
from prototype_gate import score_arity, write_arity_report
from ui_gate import physical_memory_gb
from xref_gate import CONTEXTS

EXPORTER = ROOT / 'scripts/ExportPrototypeArity.java'
ANALYSIS = dict(command='DecompilerParameterIdCmd', clear_level='ANALYSIS',
    commit_data_types=True, commit_void_return=False, decompiler_timeout_secs=60, passes=1)


def producer_context(install):
    upstream = provenance(install)
    return dict(producer='ghidra-headless', upstream_version=upstream['upstream_version'],
        upstream_revision=upstream['upstream_revision'], exporter_sha256=digest(EXPORTER),
        analysis=ANALYSIS, language_selection='explicit', address_basis='ghidra')


def reference_path(root, expected):
    fingerprint = hashlib.sha256(json.dumps(expected, sort_keys=True).encode()).hexdigest()[:16]
    return root / expected['language'].replace(':', '-') / expected['compiler'] / fingerprint / (
        'baseline-' + expected['sha256'] + '.json')


def export(install, binary, context, work, timeout):
    output = work / 'arities.json'
    command = [str(install / 'support/analyzeHeadless'), str(work), 'prototype-arity',
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
        raise ValueError(f'Stock parameter-ID export failed: {log[-4000:]}')
    result = json.loads(output.read_text())
    if any(result.get(key) != value for key, value in context.items()):
        raise ValueError('Stock parameter-ID language/compiler mismatch')
    arities = {address(entry): arity for entry, arity in result['arities'].items()}
    if len(arities) != len(result['arities']) or not arities or any(
            type(value) is not int or value < 0 for value in arities.values()):
        raise ValueError('Invalid stock arity export')
    return dict(image_base=address(result['image_base']), arities=arities)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus-dir', type=Path, required=True)
    parser.add_argument('--oracle-dir', type=Path, default=ROOT / 'oracle/prototypes-v1')
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--ghidra', type=Path, default=Path(os.environ.get(
        'ROMWRIGHT_GHIDRA', str(Path.home() / 'ghidra_12.1.3_PUBLIC'))))
    parser.add_argument('--timeout', type=int, default=180)
    parser.add_argument('--check', action='store_true',
        help='verify and score immutable references without rerunning stock analysis')
    args = parser.parse_args()
    lock = json.loads((ROOT / 'tests/corpus.lock.json').read_text())
    required = [row for row in lock['entries']
        if row['format'] == 'elf' and row['architecture'] in set(lock['oracle_matrix']['architectures'])]
    actual, setup_error = {}, None
    try:
        manifest = json.loads((args.corpus_dir / 'manifest.json').read_text())
        if manifest['sources'] != lock['sources']:
            raise ValueError('Corpus source manifest mismatch')
        for name, info in lock['sources'].items():
            if digest(ROOT / 'tests/corpus-src' / name) != info['sha256']:
                raise ValueError(f'Corpus source changed: {name}')
        for item in manifest['entries']:
            key = (item['architecture'], item['variant'])
            if key in actual:
                raise ValueError('Duplicate corpus row')
            actual[key] = item
        producer = producer_context(args.ghidra)
    except (OSError, ValueError, KeyError) as error:
        setup_error = error
    rows = []
    for recipe in required:
        key = (recipe['architecture'], recipe['variant'])
        row = dict(id='_'.join(key), status='skipped', metrics={}, thresholds={}, runs=0 if args.check else 1)
        try:
            if setup_error:
                raise setup_error
            item = actual.get(key)
            if not item or item.get('status') != 'ok':
                raise FileNotFoundError('Required corpus row missing or skipped')
            if item['command'] != recipe['command'] or item['binary'] != recipe['binary']:
                raise ValueError('Corpus recipe mismatch')
            binary = (args.corpus_dir / recipe['binary']).resolve()
            twin = (args.corpus_dir / recipe['unstripped_twin']).resolve()
            sha = digest(binary)
            if sha != item['binary_sha256'] or digest(twin) != item['unstripped_twin_sha256']:
                raise ValueError('Corpus binary/twin hash mismatch')
            validate_elf_twin(binary, twin)
            data = binary.read_bytes()
            if any(name.startswith(('.debug_', '.zdebug_')) or name in (
                    '.gnu_debuglink', '.gnu_debugaltlink', '.gnu_debugdata')
                    for name, _ in parse_elf_sections(data)):
                raise ValueError('Stock input must not contain or link DWARF truth')
            context = CONTEXTS[key[0]]
            expected = dict(schema_version=1, sha256=sha, binary_size=binary.stat().st_size,
                **producer, **context)
            destination = reference_path(args.oracle_dir, expected)
            if args.check:
                reference = json.loads(destination.read_text())
                if any(reference.get(key) != value for key, value in expected.items()):
                    raise ValueError('Immutable reference context mismatch')
                if not reference['arities'] or any(
                        address(entry) != entry or type(arity) is not int or arity < 0
                        for entry, arity in reference['arities'].items()):
                    raise ValueError('Invalid immutable arity reference')
            else:
                with tempfile.TemporaryDirectory(prefix='prototype-reference-') as work:
                    reference = dict(**expected, **export(args.ghidra, binary, context, Path(work), args.timeout))
            if digest(binary) != sha or digest(twin) != item['unstripped_twin_sha256']:
                raise ValueError('Input changed during export')
            load_base = min(address for address, size, _, _, _ in get_load_segments(data) if size)
            truth = extract(twin, int(reference['image_base'], 16) - load_base)
            if digest(twin) != truth['binary_sha256'] or truth['binary_sha256'] != item['unstripped_twin_sha256']:
                raise ValueError('DWARF twin changed during projection')
            score = score_arity(truth['functions'], reference['arities'])
            if not args.check:
                destination.parent.mkdir(parents=True, exist_ok=True)
                if destination.exists():
                    if json.loads(destination.read_text()) != reference:
                        raise ValueError('Fresh analysis differs from immutable baseline; existing reference retained')
                else:
                    write_reference(destination, reference)
            row.update(status='pass', sha256=sha, twin_sha256=truth['binary_sha256'],
                reference=str(destination.relative_to(args.oracle_dir)), reference_sha256=digest(destination),
                analysis_context=context, truth_functions=len(truth['functions']),
                unmapped_truth=truth['unmapped'],
                scores={'ghidra': score}, metrics={'ghidra.proto.arity': score['value']})
        except (OSError, subprocess.SubprocessError) as error:
            row['reason'] = str(error)
        except (ValueError, KeyError, TypeError, AssertionError) as error:
            row.update(status='fail', reason=str(error))
        rows.append(row)
        print(f"{row['status'].upper()} {row['id']}: {row.get('reason', row['metrics'])}", flush=True)
    summary = {status: sum(row['status'] == status for row in rows) for status in ('pass', 'fail', 'skipped')}
    report = dict(gate='m2-006-b2-reference', milestone='M2',
        commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
        date=datetime.now(timezone.utc).isoformat(),
        machine=dict(os=platform.platform(), cpu=platform.processor() or platform.machine(), ram_gb=physical_memory_gb()),
        dwarf_reader_sha256=digest(ROOT / 'benchmarks/dwarf_arity.py'),
        corpus=rows, summary=summary, passed=len(rows) == 20 and summary['pass'] == 20)
    write_arity_report(args.report, report)
    print(json.dumps(dict(summary=summary, passed=report['passed'])))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
