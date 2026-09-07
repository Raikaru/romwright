#!/usr/bin/env python3
"""The user path is native; the bridge is reachable only as an oracle (m2-015).

Checks the cutover itself, not one command's output: `import`, `decompile`,
`decompile-doc` and `disasm` run natively with no JVM reachable, the `-native`
verbs are gone, `--oracle` routes to the bridge, the docs say so, and
continuous integration never takes a bridge path outside oracle generation.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / 'target/debug/lre-cli'
REMOVED = ('import-native', 'decompile-native', 'decompile-native-doc', 'disasm-native')
# Repository text that must no longer name a removed verb.
TRACKED = ('*.rs', '*.py', '*.sh', '*.md', '*.yml', '*.cpp', '*.h')


def run(args, env, timeout=180):
    return subprocess.run([str(CLI), *args], capture_output=True, text=True,
        timeout=timeout, env=env, cwd=ROOT)


def producer(project):
    with sqlite3.connect(project / 'project.sqlite') as database:
        rows = database.execute('SELECT producer FROM provenance').fetchall()
    return sorted({row[0] for row in rows})


def stale_references():
    """Every tracked file still naming a removed verb."""
    listing = subprocess.check_output(['git', 'ls-files', *TRACKED], cwd=ROOT, text=True)
    stale = {}
    for name in listing.split():
        path = ROOT / name
        if not path.is_file() or path.resolve() == Path(__file__).resolve():
            continue
        text = path.read_text(errors='ignore')
        hits = [verb for verb in REMOVED if verb in text]
        if hits:
            stale[name] = hits
    return stale


def ci_bridge_steps():
    """CI steps that take a bridge path without generating an oracle."""
    workflow = (ROOT / '.github/workflows/ci.yml').read_text()
    steps = re.split(r'\n      - (?:name|uses):', workflow)
    offenders = []
    for step in steps:
        bridge = ('VENTRIS_SERVICE_JAR' in step or 'ventris-service.jar' in step
            or re.search(r'--oracle(?![-\w])', step))
        if bridge and 'oracle' not in step.split('\n')[0].lower():
            offenders.append(step.split('\n')[0].strip())
    return offenders


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / 'tests/fixtures-src/tiny_bin')
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    subprocess.run(['cargo', 'build', '-q', '-p', 'lre-cli'], cwd=ROOT, check=True)
    # No JVM may be reachable on any default path. The native decompiler still
    # reads SLEIGH language data from the Ghidra install, so `store` keeps that
    # install while `bare` removes it too: an import needs neither.
    store = dict(os.environ, VENTRIS_SERVICE_JAR=str(ROOT / 'does/not/exist.jar'),
        DEBUGINFOD_URLS='')
    for name in ('VENTRIS_SLA', 'VENTRIS_LANGUAGE', 'VENTRIS_LANGUAGE_DIR', 'VENTRIS_SPECS'):
        store.pop(name, None)
    env = dict(store, VENTRIS_GHIDRA=str(ROOT / 'does/not/exist'))
    evidence = {}
    with tempfile.TemporaryDirectory(prefix='m2-015-') as temporary:
        work = Path(temporary)
        project = work / 'project'
        result = run(['import', str(args.binary), '--name', 'tiny', '--project', str(project)], env)
        assert result.returncode == 0, f'default import needs no JVM: {result.stderr}'
        assert producer(project) == ['native-import'], producer(project)
        evidence['import'] = result.stdout.strip()
        functions = run(['functions', 'tiny', '--project', str(project)], env)
        assert functions.returncode == 0 and functions.stdout.strip(), functions.stderr
        rows = [line.split() for line in functions.stdout.strip().splitlines()]
        # A named body, not a stub: the native decompiler needs real code.
        entry = next(row[0] for row in rows if row[-1] in ('add', 'main'))
        evidence['functions'] = len(rows)
        for command in (['disasm', str(args.binary), entry, '-n', '4'],
                ['decompile', str(args.binary), entry, '--name', 'tiny',
                    '--project', str(project)],
                ['decompile-doc', str(args.binary), entry, '--name', 'tiny',
                    '--project', str(project)]):
            result = run(command, store)
            assert result.returncode == 0 and result.stdout.strip(), \
                f'{command[0]} must run natively: {result.stderr[-400:]}'
            evidence[command[0]] = len(result.stdout.strip().splitlines())
        for verb in REMOVED:
            result = run([verb, str(args.binary)], store)
            assert result.returncode != 0 and 'unknown command' in result.stderr, \
                f'{verb} must be gone: {result.stdout} {result.stderr}'
        # `--oracle` must reach for the bridge, and only then.
        oracle = run(['import', str(args.binary), '--oracle', '--project', str(work / 'oracle')],
            env)
        # Only the bridge reports these prerequisites; no native path can.
        reached = oracle.stderr + oracle.stdout
        assert oracle.returncode != 0 and ('no Ghidra jars' in reached
            or 'exist.jar' in reached), \
            f'--oracle must launch the bridge: {oracle.stdout} {oracle.stderr}'
        evidence['oracle_routing'] = oracle.stderr.strip()[:160]
        evidence['sleigh_data'] = 'native decompile reads SLEIGH languages, never a JVM'
        jar = ROOT / 'service/build/ventris-service.jar'
        installed = Path(os.environ.get('VENTRIS_GHIDRA', Path.home() / 'ghidra_12.1.3_PUBLIC'))
        if jar.is_file() and installed.is_dir():
            bridged = work / 'bridged'
            real = dict(os.environ, DEBUGINFOD_URLS='')
            real.pop('VENTRIS_SERVICE_JAR', None)
            result = run(['import', str(args.binary), '--oracle', '--project', str(bridged),
                '--ghidra', str(installed)], real, timeout=900)
            assert result.returncode == 0, f'bridge oracle import failed: {result.stderr[-600:]}'
            assert producer(bridged) == ['ghidra-bridge'], producer(bridged)
            evidence['oracle_import'] = result.stdout.strip()
        else:
            evidence['oracle_import'] = 'skipped: no service jar or Ghidra install'
    stale = stale_references()
    assert not stale, f'removed verbs still referenced: {stale}'
    readme = (ROOT / 'README.md').read_text()
    assert 'lre-cli import <binary>' in readme and '--oracle' in readme, \
        'README must document the native default and the oracle flag'
    offenders = ci_bridge_steps()
    assert not offenders, f'CI takes a bridge path outside oracle generation: {offenders}'
    evidence.update(passed=True, task='m2-015', removed_verbs=list(REMOVED),
        ci_bridge_steps=offenders)
    if args.report:
        args.report.write_text(json.dumps(evidence, indent=2) + '\n')
    print(json.dumps(evidence))


if __name__ == '__main__':
    main()
