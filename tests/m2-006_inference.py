#!/usr/bin/env python3
"""Real API acceptance for bounded inferred prototypes and assertion retention."""
import json
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    root = Path(__file__).resolve().parents[1]
    binary = root / 'tests/fixtures-src/tiny_bin'
    env = os.environ.copy()
    env.pop('VENTRIS_SLA', None)
    with tempfile.TemporaryDirectory(prefix='ventris-m2-006-') as temporary:
        project = Path(temporary) / 'project'

        def invoke(requests):
            response = subprocess.run([str(root / 'target/debug/lre-api'), '--project', str(project)],
                cwd=root, env=env, input=''.join(json.dumps(dict(api=2, id=index,
                    method=method, params=params)) + '\n' for index, (method, params) in enumerate(requests)),
                text=True, capture_output=True, check=True, timeout=120)
            rows = [json.loads(line) for line in response.stdout.splitlines()]
            assert len(rows) == len(requests), rows
            errors = [row for row in rows if row.get('error')]
            assert not errors, errors
            return [row['result'] for row in rows]

        context = dict(binary=str(binary), program='tiny_bin')
        inference = dict(**context, budget_ms=60000)
        address = dict(space='Ram', offset=0x400466)
        decompile = dict(**context, address=address)
        _, functions, report, jobs = invoke([
            ('import_native', dict(binary=str(binary), name='tiny_bin')),
            ('functions', dict(program='tiny_bin')),
            ('infer_prototypes', inference), ('jobs_page', dict(limit=1000))])
        assert 1 <= report['rounds'] <= 3, report
        assert report['stop_reason'] in ('converged', 'round_limit'), report
        entries = {row['entry']['offset'] for row in functions}
        analyzed = [row['address'] for row in jobs['rows']]
        assert set(analyzed[:len(entries)]) == entries, jobs
        assert len(analyzed) <= 3 * len(entries), jobs
        # add has no callees; main calls add and must see its first inferred fact.
        assert 0x400466 not in analyzed[len(entries):], jobs
        assert 0x40047a in analyzed[len(entries):], jobs
        stored, doc = invoke([('prototypes', dict(program='tiny_bin')), ('decompile_doc', decompile)])
        inferred = next(row for row in stored if row['function'] == address)
        assert inferred['provenance']['kind'] == 'inferred', inferred
        assert inferred['provenance']['source'], inferred
        assert doc['prototype']['return_type']['name'] == 'int', doc
        assert len(doc['prototype']['parameters']) == 2, doc

        before, cancelled, after, jobs = invoke([
            ('prototypes', dict(program='tiny_bin')),
            ('infer_prototypes', dict(**context, budget_ms=0)),
            ('prototypes', dict(program='tiny_bin')), ('jobs_page', {})])
        assert cancelled['rounds'] == 0 and cancelled['stop_reason'] == 'budget', cancelled
        assert before == after and jobs['total'] == 0, (cancelled, jobs)

        assertion = dict(function=address, signature='int add(int left, int right)',
            calling_convention=None, return_type='int',
            provenance=dict(kind='asserted', source='inference-acceptance', confidence=None))
        operation = dict(op_id='assert-add', actor='acceptance', lamport=1,
            kind='set_prototype', payload=json.dumps(assertion), applied=False, provenance='acceptance')
        # Warm a worker before changing the facts. The final document must not
        # reuse its old parameter names, even after another inference run.
        _, _, _, repeated, stored, doc = invoke([
            ('decompile_doc', decompile),
            ('append_collab_op', dict(program='tiny_bin', operation=operation)),
            ('apply_collab_op', dict(program='tiny_bin', op_id='assert-add')),
            ('infer_prototypes', inference),
            ('prototypes', dict(program='tiny_bin')),
            ('decompile_doc', decompile)])
        assert repeated['rounds'] <= 3, repeated
        assert next(row for row in stored if row['function'] == address) == assertion, stored
        assert [parameter['name'] for parameter in doc['prototype']['parameters']] == ['left', 'right'], doc
        print(json.dumps(dict(passed=True, rounds=report['rounds'],
            repeated_rounds=repeated['rounds'], inferred_add_parameters=2, assertion_retained=True)))


if __name__ == '__main__':
    main()
