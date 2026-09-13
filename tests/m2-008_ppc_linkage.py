#!/usr/bin/env python3
"""Relocation-proven PPC import names must seed only non-returning callees."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'benchmarks'))
from prototype_gate import run_api


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus-dir', type=Path, required=True)
    args = parser.parse_args()
    lock = json.loads((ROOT / 'tests/corpus.lock.json').read_text())
    recipe = next(row for row in lock['entries']
        if row['architecture'] == 'powerpc' and row['variant'] == 'cpp_o2')
    binary = (args.corpus_dir / recipe['binary']).resolve()
    twin = args.corpus_dir / recipe['unstripped_twin']
    symbols = subprocess.run(['nm', '-n', str(twin)], capture_output=True,
        text=True, check=True).stdout.splitlines()
    entries = {}
    for name in ('__cxa_throw', 'printf'):
        matches = [line.split() for line in symbols
            if line.endswith('.plt_call32.' + name)]
        assert len(matches) == 1, (name, matches)
        entries[name] = int(matches[0][0], 16)
    env = os.environ.copy()
    for key in ('ROMWRIGHT_SLA', 'ROMWRIGHT_LANGUAGE', 'ROMWRIGHT_LANGUAGE_DIR', 'ROMWRIGHT_SPECS'):
        env.pop(key, None)
    with tempfile.TemporaryDirectory(prefix='romwright-ppc-linkage-') as temporary:
        _, functions, report, facts, repeated = run_api(ROOT, Path(temporary) / 'project', [
            ('import_native', dict(binary=str(binary), name='cpp')),
            ('functions', dict(program='cpp')),
            ('infer_nonreturning', dict(binary=str(binary), program='cpp')),
            ('return_behaviors', dict(program='cpp')),
            ('infer_nonreturning', dict(binary=str(binary), program='cpp'))], 180, env)
        by_entry = {row['entry']['offset']: row for row in functions}
        for name, entry in entries.items():
            assert by_entry[entry]['name'] == name, (name, by_entry[entry])
        nonreturning = {row['function']['offset'] for row in facts if row['no_return']}
        assert entries['__cxa_throw'] in nonreturning, facts
        assert entries['printf'] not in nonreturning, facts
        assert not repeated['changed'] and repeated['revision'] == report['revision'], repeated
        print(json.dumps(dict(passed=True, entries=entries, nonreturning=sorted(nonreturning))))


if __name__ == '__main__':
    main()
