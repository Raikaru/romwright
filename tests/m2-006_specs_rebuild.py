#!/usr/bin/env python3
"""Equivalent ELF inputs must reproduce specs without rewriting their provenance."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus-dir', type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads((args.corpus_dir / 'manifest.json').read_text())
    architectures = {'i386', 'aarch64', 'powerpc'}
    with tempfile.TemporaryDirectory(prefix='romwright-spec-rebuild-') as temporary:
        work = Path(temporary)
        corpus, specs = work / 'corpus', work / 'specs'
        corpus.mkdir()
        specs.mkdir()
        changed = set()
        for row in manifest['entries']:
            if row['architecture'] not in architectures or row['variant'] != 'plain_o0':
                continue
            # Unmapped trailing padding changes the producer-input hash, not
            # the language/compiler context or the exported static documents.
            data = (args.corpus_dir / row['binary']).read_bytes() + b'\0'
            (corpus / row['binary']).write_bytes(data)
            row['binary_sha256'] = hashlib.sha256(data).hexdigest()
            changed.add(row['architecture'])
        assert changed == architectures, changed
        (corpus / 'manifest.json').write_text(json.dumps(manifest))
        originals = {}
        for name in ('x86-LE-32-default', 'AARCH64-LE-64-v8A', 'PowerPC-BE-32-default'):
            source = ROOT / 'native/specs' / (name + '.manifest.json')
            destination = specs / source.name
            shutil.copyfile(source, destination)
            originals[destination] = destination.read_bytes()
        command = ['python3', str(ROOT / 'scripts/gen_native_specs.py'),
            '--corpus-dir', str(corpus), '--out-dir', str(specs)]
        subprocess.run(command, cwd=ROOT, check=True, timeout=600)
        subprocess.run(command + ['--check'], cwd=ROOT, check=True, timeout=60)
        assert all(path.read_bytes() == before for path, before in originals.items())
        print(json.dumps(dict(passed=True, equivalent_inputs=3, manifests_unchanged=True)))


if __name__ == '__main__':
    main()
