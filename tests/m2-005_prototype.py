#!/usr/bin/env python3
"""Exercise native prototype recovery through standalone and warm API workers."""
import argparse
import datetime
import json
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    binary = root / 'tests/fixtures-src/tiny_bin'
    env = os.environ.copy()
    # Both entrypoints must resolve the fixture's language without requiring
    # callers to set a process-global SLA just to make pooled analysis work.
    env.pop('VENTRIS_SLA', None)

    def run(command, **kwargs):
        return subprocess.run(command, cwd=root, env=env, text=True,
            capture_output=True, check=True, timeout=60, **kwargs)

    with tempfile.TemporaryDirectory(prefix='ventris-m2-005-') as temporary:
        project = Path(temporary) / 'project'
        cli = str(root / 'target/release/lre-cli')
        run([cli, 'import', str(binary), '--project', str(project)])
        standalone = json.loads(run([cli, 'decompile-doc', str(binary),
            '0x400466', '--project', str(project)]).stdout)
        requests = [dict(api=2, id=index, method='decompile_doc', params=dict(
            binary=str(binary), program='tiny_bin', address=dict(space='Ram', offset=address)))
            for index, address in enumerate([0x400466, 0x40047a, 0x400466])]
        requests.append(dict(api=2, id=3, method='jobs_page', params={}))
        response = run([str(root / 'target/release/lre-api'), '--project', str(project)],
            input=''.join(json.dumps(request) + '\n' for request in requests))
        replies = [json.loads(line) for line in response.stdout.splitlines()]
        assert len(replies) == 4, replies
        assert all(not reply.get('error') for reply in replies), replies
        pooled = [reply['result'] for reply in replies[:3]]
        for doc in [standalone, pooled[0], pooled[2]]:
            proto = doc['prototype']
            assert proto['return_type']['name'] == 'int', doc
            assert not proto['variadic'], proto
            assert [parameter['data_type']['name'] for parameter in proto['parameters']] == ['int', 'int'], proto
        assert standalone['prototype'] == pooled[0]['prototype'] == pooled[2]['prototype']
        assert pooled[1]['prototype'] is not None, pooled[1]
        assert pooled[1]['address']['offset'] == 0x40047a
        jobs = replies[3]['result']
        assert jobs['pool']['idle_workers'] == 1, jobs
        assert jobs['pool']['restarts'] == 0, jobs
        assert [row['state'] for row in jobs['rows']] == ['succeeded'] * 3, jobs

    def summary(doc):
        return dict(address=doc['address'], revision=doc['revision'], prototype=doc['prototype'],
            text=''.join(token['text'] for token in doc['tokens']))

    report = dict(task='m2-005', implementation_commit=run(['git', 'rev-parse', 'HEAD']).stdout.strip(),
        measured_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        standalone=summary(standalone), pooled=[summary(doc) for doc in pooled], jobs=jobs)
    if args.report:
        args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(passed=True, standalone=1, pooled=3,
        calling_convention=standalone['prototype']['calling_convention'],
        parameters=len(standalone['prototype']['parameters']), idle_workers=jobs['pool']['idle_workers'])))


if __name__ == '__main__':
    main()
