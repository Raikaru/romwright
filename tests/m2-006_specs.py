#!/usr/bin/env python3
"""Validate prepared bundles and recover a real two-input function on each ABI."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'benchmarks'))
sys.path.insert(0, str(ROOT / 'scripts'))
from prototype_gate import run_api
from gen_oracle import digest
from gen_prototype_oracle import producer_context, reference_path
from xref_gate import CONTEXTS


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus-dir', type=Path, required=True)
    args = parser.parse_args()
    subprocess.run([sys.executable, str(ROOT / 'scripts/gen_native_specs.py'),
        '--corpus-dir', str(args.corpus_dir), '--check'], cwd=ROOT, check=True)
    install = Path(os.environ.get('VENTRIS_GHIDRA', str(Path.home() / 'ghidra_12.1.3_PUBLIC')))
    producer = producer_context(install)
    env = os.environ.copy()
    for name in ('VENTRIS_SLA', 'VENTRIS_LANGUAGE', 'VENTRIS_LANGUAGE_DIR', 'VENTRIS_SPECS'):
        env.pop(name, None)
    results = []
    with tempfile.TemporaryDirectory(prefix='ventris-native-specs-') as temporary:
        for architecture in ('i386', 'aarch64', 'powerpc'):
            binary = (args.corpus_dir / (architecture + '_plain_o0.bin')).resolve()
            context = CONTEXTS[architecture]
            expected = dict(schema_version=1, sha256=digest(binary), binary_size=binary.stat().st_size,
                **producer, **context)
            baseline = json.loads(reference_path(ROOT / 'oracle/prototypes-v1', expected).read_text())
            project = Path(temporary) / architecture
            imported, functions = run_api(ROOT, project, [
                ('import_native', dict(binary=str(binary), name='fixture')),
                ('functions', dict(program='fixture'))], 60, env)
            assert imported['language'] == context['language'], imported
            entries = {format(row['entry']['offset'], '08x'): row['entry'] for row in functions}
            # Select only from already discovered native entries; never seed discovery.
            entry = min(key for key in entries if baseline['arities'].get(key) == 2)
            doc, = run_api(ROOT, project, [('decompile_doc', dict(binary=str(binary),
                program='fixture', address=entries[entry]))], 60, env)
            assert len(doc['prototype']['parameters']) == 2, (architecture, doc)
            results.append(dict(architecture=architecture, entry=entry, parameters=2))
    print(json.dumps(dict(passed=True, results=results)))


if __name__ == '__main__':
    main()
