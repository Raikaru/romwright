#!/usr/bin/env python3
"""A warm caller must consume newly asserted callee facts before analysis."""
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


def main():
    root = Path(__file__).resolve().parents[1]
    binary = root / 'tests/fixtures-src/tiny_bin'
    context = dict(binary=str(binary), program='tiny_bin')
    add = dict(space='Ram', offset=0x400466)
    caller = dict(**context, address=dict(space='Ram', offset=0x40047a))
    assertion = dict(function=add, signature='int add(int left)',
        calling_convention=None, return_type='int',
        provenance=dict(kind='asserted', source='revision-acceptance', confidence=None))
    operation = dict(op_id='assert-callee', actor='acceptance', lamport=1,
        kind='set_prototype', payload=json.dumps(assertion), applied=False, provenance='acceptance')
    requests = [
        ('import_native', dict(binary=str(binary), name='tiny_bin')),
        ('decompile_doc', caller),
        ('append_collab_op', dict(program='tiny_bin', operation=operation)),
        ('apply_collab_op', dict(program='tiny_bin', op_id='assert-callee')),
        # Do not decompile add first: that would accidentally activate the callee
        # and hide the missing caller-side application path.
        ('decompile_doc', caller),
        ('decompile_doc', dict(**context, address=add)),
    ]
    env = dict(os.environ)
    env.pop('VENTRIS_SLA', None)
    with tempfile.TemporaryDirectory(prefix='ventris-m2-006-revision-') as temporary:
        response = subprocess.run([str(root / 'target/debug/lre-api'), '--project', temporary],
            cwd=root, env=env, input=''.join(json.dumps(dict(api=2, id=index,
                method=method, params=params)) + '\n' for index, (method, params) in enumerate(requests)),
            text=True, capture_output=True, check=True, timeout=120)
    replies = [json.loads(line) for line in response.stdout.splitlines()]
    assert len(replies) == len(requests) and all(not row.get('error') for row in replies), replies
    before, after, callee = (replies[index]['result'] for index in (1, 4, 5))

    def call_arity(doc):
        # This controlled fixture calls add with literals, without nested calls.
        calls = re.findall(r'\badd\s*\(([^()]*)\)', ''.join(token['text'] for token in doc['tokens']))
        assert len(calls) == 1, doc
        return len(calls[0].split(',')) if calls[0].strip() else 0

    assert call_arity(before) == 2, before
    assert call_arity(after) == 1, after
    assert after['revision'] > before['revision'], (before, after)
    assert [parameter['name'] for parameter in callee['prototype']['parameters']] == ['left'], callee
    print(json.dumps(dict(passed=True, caller_arguments_before=2, caller_arguments_after=1,
        revision_before=before['revision'], revision_after=after['revision'])))


if __name__ == '__main__':
    main()
