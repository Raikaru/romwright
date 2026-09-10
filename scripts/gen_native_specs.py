#!/usr/bin/env python3
"""Provision static native specs once; --check needs no running JVM."""
import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile

from gen_oracle import ROOT, bridge_command, digest, provenance, write_reference
sys.path.insert(0, str(ROOT / 'benchmarks'))
from xref_gate import CONTEXTS

FILES = ('pspec.xml', 'cspec.xml', 'tspec.xml', 'coretypes.xml', 'registers.txt')
ARCHITECTURES = ('i386', 'aarch64', 'powerpc')
# The bridge digest records which bridge build exported the bundle; a later
# export from a different bridge build is not a different bundle. The
# upstream version/revision ARE requirements -- the gates pass them to
# validate_bundle to guard that the bundle came from the same Ghidra
# revision as the reference it is scored against.
PROVENANCE = ('bridge_sources_sha256', 'representative_sha256')


def bundle_paths(root, language):
    name = language.replace(':', '-')
    return root / name, root / (name + '.manifest.json')
def validate_bundle(root, expected):
    directory, manifest_path = bundle_paths(root, expected['language'])
    manifest = json.loads(manifest_path.read_text())
    if any(manifest.get(key) != value for key, value in expected.items()
           if key not in PROVENANCE):
        raise ValueError(f'Bundle context mismatch: {manifest_path}')
    if set(manifest['files']) != set(FILES):
        raise ValueError(f'Incomplete bundle manifest: {manifest_path}')
    for name, record in manifest['files'].items():
        path = directory / name
        if digest(path) != record['sha256'] or path.stat().st_size != record['bytes']:
            raise ValueError(f'Bundle hash mismatch: {path}')
    return manifest


def export_bundle(command, binary, context, work, timeout):
    output = work / 'bundle'
    requests = [
        dict(id=1, method='import', params=dict(session='specs', path=str(binary), **context)),
        dict(id=2, method='dump_specs', params=dict(session='specs', outdir=str(output))),
        dict(id=3, method='close', params=dict(session='specs')),
    ]
    process = subprocess.Popen(command + ['--project-dir', str(work / 'project')],
        cwd=ROOT, env=dict(os.environ, DEBUGINFOD_URLS=''), text=True,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    try:
        stdout, stderr = process.communicate(''.join(json.dumps(row) + '\n' for row in requests), timeout=timeout)
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.communicate()
        raise
    if process.returncode:
        raise ValueError(f'Spec exporter exited {process.returncode}: {stderr[-4000:]}')
    replies = {}
    for line in stdout.splitlines():
        if not line.strip().startswith('{'):
            continue
        reply = json.loads(line)
        if reply.get('id') in (1, 2, 3):
            if reply['id'] in replies or reply.get('error'):
                raise ValueError(f'Spec export RPC failed: {reply}')
            replies[reply['id']] = reply['result']
    if set(replies) != {1, 2, 3} or not replies[2].get('ok') or not replies[3].get('ok'):
        raise ValueError('Incomplete spec export response')
    if any(replies[1].get(key) != value for key, value in context.items()):
        raise ValueError('Spec export language/compiler mismatch')
    return output


def platform_bundle(args, producer, command):
    """Provisions one bundle for a platform language from an explicit image.

    A console language has no corpus row -- corpus membership is a reserved
    decision -- so the representative is named on the command line and
    recorded by digest. The bundle is Ghidra's spec data for that language;
    the image only proves which language was loaded.
    """
    context = {'language': args.language, 'compiler': args.compiler}
    expected = dict(schema_version=1, producer='dump_specs', **producer, **context)
    if not args.check:
        binary = args.input.resolve()
        with tempfile.TemporaryDirectory(prefix='native-spec-export-') as temporary:
            output = export_bundle(command, binary, context, Path(temporary), args.timeout)
            result = dict(**expected, representative_sha256=digest(binary),
                files={name: dict(sha256=digest(output / name),
                    bytes=(output / name).stat().st_size) for name in FILES})
            directory, destination = bundle_paths(args.out_dir, context['language'])
            if destination.exists():
                recorded = json.loads(destination.read_text())
                required = {key: value for key, value in
                    dict(**expected, files=result['files']).items()
                    if key not in PROVENANCE}
                if any(recorded.get(key) != value for key, value in required.items()):
                    raise ValueError(f'Fresh export differs from recorded manifest: {destination}')
            directory.mkdir(parents=True, exist_ok=True)
            for name in FILES:
                shutil.copyfile(output / name, directory / name)
            if not destination.exists():
                write_reference(destination, result)
    checked = validate_bundle(args.out_dir, expected)
    print(json.dumps(dict(language=context['language'], compiler=context['compiler'],
        files=len(checked['files']), checked=args.check)))
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus-dir', type=Path)
    parser.add_argument('--input', type=Path,
        help='representative image for a platform language (no corpus row)')
    parser.add_argument('--language', help='explicit language id for --input')
    parser.add_argument('--compiler', default='default', help='compiler spec for --input')
    parser.add_argument('--out-dir', type=Path, default=ROOT / 'native/specs')
    parser.add_argument('--ghidra', type=Path, default=Path(os.environ.get(
        'VENTRIS_GHIDRA', str(Path.home() / 'ghidra_12.1.3_PUBLIC'))))
    parser.add_argument('--java', default='java')
    parser.add_argument('--timeout', type=int, default=180)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    args.out_dir = args.out_dir.resolve()
    args.ghidra = args.ghidra.resolve()
    if args.language:
        producer = provenance(args.ghidra)
        producer = {key: producer[key]
            for key in ('upstream_version', 'upstream_revision', 'bridge_sources_sha256')}
        if not args.check:
            if args.input is None or not args.input.is_file():
                raise ValueError('A platform bundle needs --input <image>')
            if not args.out_dir.exists():
                args.out_dir.mkdir(parents=True, exist_ok=True)
        return platform_bundle(args, producer, None if args.check else
            bridge_command(args.ghidra, args.java))
    if args.corpus_dir is None:
        raise ValueError('--corpus-dir is required without --language')
    args.corpus_dir = args.corpus_dir.resolve()
    lock = json.loads((ROOT / 'tests/corpus.lock.json').read_text())
    manifest = json.loads((args.corpus_dir / 'manifest.json').read_text())
    if manifest['sources'] != lock['sources']:
        raise ValueError('Corpus source manifest mismatch')
    for name, record in lock['sources'].items():
        if digest(ROOT / 'tests/corpus-src' / name) != record['sha256']:
            raise ValueError(f'Corpus source changed: {name}')
    producer = provenance(args.ghidra)
    producer = {key: producer[key] for key in ('upstream_version', 'upstream_revision', 'bridge_sources_sha256')}
    command = None if args.check else bridge_command(args.ghidra, args.java)
    if not args.check:
        args.out_dir.mkdir(parents=True, exist_ok=True)
    for architecture in ARCHITECTURES:
        recipe = next(row for row in lock['entries']
            if row['architecture'] == architecture and row['variant'] == 'plain_o0')
        matches = [row for row in manifest['entries']
            if row['architecture'] == architecture and row['variant'] == 'plain_o0']
        if len(matches) != 1 or matches[0].get('status') != 'ok':
            raise ValueError(f'Required provisioning input missing: {architecture}')
        item = matches[0]
        if item['command'] != recipe['command'] or item['binary'] != recipe['binary']:
            raise ValueError(f'Corpus recipe mismatch: {architecture}')
        binary = (args.corpus_dir / recipe['binary']).resolve()
        if digest(binary) != item['binary_sha256']:
            raise ValueError(f'Corpus binary hash mismatch: {binary}')
        context = CONTEXTS[architecture]
        expected = dict(schema_version=1, producer='dump_specs', **producer, **context)
        if not args.check:
            with tempfile.TemporaryDirectory(prefix='native-spec-export-') as temporary:
                output = export_bundle(command, binary, context, Path(temporary), args.timeout)
                if digest(binary) != item['binary_sha256']:
                    raise ValueError('Provisioning input changed during export')
                result = dict(**expected, representative_sha256=item['binary_sha256'],
                    files={name: dict(sha256=digest(output / name),
                        bytes=(output / name).stat().st_size) for name in FILES})
                directory, destination = bundle_paths(args.out_dir, context['language'])
                if destination.exists():
                    recorded = json.loads(destination.read_text())
                    # The first producer input remains provenance, not a
                    # requirement that equivalent corpus rebuilds be identical.
                    required = {key: value for key, value in
                    dict(**expected, files=result['files']).items()
                    if key not in PROVENANCE}
                    if any(recorded.get(key) != value for key, value in required.items()):
                        raise ValueError(f'Fresh export differs from recorded manifest: {destination}')
                directory.mkdir(parents=True, exist_ok=True)
                for name in FILES:
                    shutil.copyfile(output / name, directory / name)
                if not destination.exists():
                    write_reference(destination, result)
        checked = validate_bundle(args.out_dir, expected)
        print(json.dumps(dict(language=context['language'], compiler=context['compiler'],
            files=len(checked['files']), checked=args.check)))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
