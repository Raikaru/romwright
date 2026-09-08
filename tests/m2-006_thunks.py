#!/usr/bin/env python3
"""Unknown library thunks must not erase a caller's recovered parameters."""
import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'benchmarks'))
from dwarf_arity import extract
from prototype_gate import run_api


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus-dir', type=Path, required=True)
    parser.add_argument('--architecture', choices=('x86_64', 'powerpc'), default='x86_64')
    args = parser.parse_args()
    lock = json.loads((ROOT / 'tests/corpus.lock.json').read_text())
    recipe = next(row for row in lock['entries']
        if row['architecture'] == args.architecture and row['variant'] == 'cpp_o2')
    binary = (args.corpus_dir / recipe['binary']).resolve()
    truth = extract(args.corpus_dir / recipe['unstripped_twin'])
    entry, main = next((entry, row) for entry, row in truth['functions'].items() if row['name'] == 'main')
    assert main['arity'] == 2, main
    env = os.environ.copy()
    env.pop('VENTRIS_SLA', None)
    with tempfile.TemporaryDirectory(prefix='ventris-m2-thunks-') as temporary:
        project = Path(temporary) / 'project'
        context = dict(binary=str(binary), program='cpp')
        target = dict(**context, address=dict(space='Ram', offset=int(entry, 16)))
        _, before, report, after, prototypes, symbols = run_api(ROOT, project, [
            ('import_native', dict(binary=str(binary), name='cpp')),
            ('decompile_doc', target),
            ('infer_prototypes', dict(**context, budget_ms=60000)),
            ('decompile_doc', target),
            ('prototypes', dict(program='cpp')),
            ('symbols', dict(program='cpp'))], 120, env)
        assert len(before['prototype']['parameters']) == 2, before
        assert len(after['prototype']['parameters']) == 2, after
        imported = {row['address']['offset'] for row in symbols if row['external']}
        assert imported, symbols
        # What this protects is the caller: an *inferred* prototype on an
        # unknown library thunk would be recovered from a body that never
        # returns to its caller, and would erase the caller's parameters. A
        # prototype the pinned type archive *declares* for the name the image
        # imports is the opposite -- the fact that makes the caller's text
        # right (m4-009) -- so the rule is about where a prototype came from,
        # not merely where it sits.
        attached = [row for row in prototypes if row['function']['offset'] in imported]
        recovered = [row for row in attached
                     if row['provenance'].get('evidence') != 'declared']
        assert not recovered, recovered
        assert all(row['provenance']['source'] == 'native-import:type-archive'
                   for row in attached), attached
        assert any(row['function'] == target['address'] for row in prototypes), prototypes
        print(json.dumps(dict(passed=True, architecture=args.architecture, entry=entry,
            parameters=2, rounds=report['rounds'], imported_symbols=len(imported))))


if __name__ == '__main__':
    main()
