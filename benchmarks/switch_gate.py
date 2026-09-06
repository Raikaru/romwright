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
