#!/usr/bin/env python3
"""Real compiler regressions: source scope, relocation identity and job ownership."""
import argparse
import json
import os
from pathlib import Path
import select
import shutil
import signal
import struct
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
SOURCE = 'unsigned unrelated_value = 1;\nunsigned step(void) { return 1; }\nunsigned other(void) { return 2; }\n'


class Api:
    def __init__(self, executable, project, objdiff):
        self.process = subprocess.Popen([str(executable), '--project', str(project)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, env=dict(os.environ, ROMWRIGHT_OBJDIFF=str(objdiff)))
        self.sequence = 0

    def call(self, method, **params):
        self.sequence += 1
        request = dict(api=2, id=self.sequence, method=method, params=params)
        self.process.stdin.write(json.dumps(request) + '\n')
        self.process.stdin.flush()
        if not select.select([self.process.stdout], [], [], 45)[0]:
            raise AssertionError(f'{method} did not answer within 45 seconds')
        response = json.loads(self.process.stdout.readline())
        if 'error' in response:
            raise RuntimeError(response['error'])
        return response['result']

    def workspace(self, **operation):
        return self.call('matching_workspace', program='fixture', operation=operation)

    def run(self, binary, **operation):
        return self.call('matching_run', program='fixture', binary=str(binary), budget_ms=30000, operation=operation)

    def close(self, invalid_input=False):
        if invalid_input:
            self.process.stdin.buffer.write(b'\xff\n')
            self.process.stdin.buffer.flush()
        if not self.process.stdin.closed:
            self.process.stdin.close()
        self.process.wait(timeout=5)
        assert self.process.returncode == (1 if invalid_input else 0)


def profile(compiler, arguments=None, environment=None):
    return dict(name='test', recipe=dict(compiler=str(compiler), arguments=arguments or [],
        environment=environment or {}), tools={}, compile_arguments=['-c', '{source}', '-o', '{output}'],
        version_arguments=['--version'])


def setup(api, target, source, compiler_profile, project=None, name='regression', filename='unit.c'):
    return api.workspace(operation='setup', setup=dict(name=name, symbol='step', source=filename,
        files={filename: dict(kind='text', text=source, redistributable=True)},
        target=dict(kind='path', path=str(target), redistributable=True),
        profiles=[compiler_profile], project=project))


def rejects(action):
    try:
        action()
    except RuntimeError:
        return
    raise AssertionError('Invalid evidence or modified tool was accepted')


def corrupt_symbol(data, duplicate):
    """Alter real ELF64 symbol metadata without changing instruction bytes."""
    result = bytearray(data)
    assert result[:6] == b'\x7fELF\x02\x01'
    offset = struct.unpack_from('<Q', result, 40)[0]
    width, count = struct.unpack_from('<HH', result, 58)
    sections = [struct.unpack_from('<IIQQQQIIQQ', result, offset + i * width) for i in range(count)]
    symbols = next(section for section in sections if section[1] == 2)
    strings = sections[symbols[6]]
    entries = {}
    for position in range(symbols[4], symbols[4] + symbols[5], symbols[9]):
        name_offset = struct.unpack_from('<I', result, position)[0]
        start = strings[4] + name_offset
        name = bytes(result[start:result.index(0, start)]).decode()
        entries[name] = (position, name_offset)
    if duplicate:
        struct.pack_into('<I', result, entries['bar'][0], entries['foo'][1])
    else:
        result[entries['foo'][0] + 4] = 0x20 | (result[entries['foo'][0] + 4] & 15)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--api', type=Path, default=ROOT / 'target/release/romwright-api')
    parser.add_argument('--compiler', type=Path, default=shutil.which('clang'))
    parser.add_argument('--objdiff', type=Path, required=True)
    args = parser.parse_args()
    if not args.compiler or not shutil.which('bwrap') or not hasattr(os, 'pidfd_open'):
        raise SystemExit('Requires Clang, bubblewrap, Linux pidfds and a built API')
    compiler = args.compiler.absolute()
    with tempfile.TemporaryDirectory(prefix='matching-regression-') as directory:
        root = Path(directory)
        source = root / 'unit.c'
        target = root / 'target.o'
        source.write_text(SOURCE)
        subprocess.run([str(compiler), '-O2', '-c', str(source), '-o', str(target)], check=True)
        api = Api(args.api.resolve(), root / 'store', args.objdiff.resolve())
        child_fd = None
        child_group = None
        report = {}
        try:
            api.call('import_native', binary=str(target), name='fixture', analyse=False)
            project = root / 'project'
            project.mkdir()
            wrong = SOURCE.replace('step(void) { return 1;', 'step(void) { return 2;')
            (project / 'unit.c').write_text(wrong)
            binding = dict(root=str(project), sources={'unit.c': 'unit.c'},
                build=dict(executable=str(compiler), arguments=['-O2', '-c', 'unit.c', '-o', 'unit.o'], environment={}),
                objects={'step': 'unit.o'}, generated=[])
            created = setup(api, target, wrong, profile(compiler, ['-O2']), binding)
            candidate = api.workspace(operation='replace', candidate=created['candidate']['id'], file='unit.c',
                source=SOURCE.replace('unrelated_value = 1', 'unrelated_value = 2'), label='Target fix with unrelated data change')
            patch = api.run(target, operation='prepare_patch', candidate=candidate['id'], profile='test')
            check = api.run(target, operation='verify_patch', patch=patch, apply=True)
            assert check['build_succeeded'] and check['diagnosis']['similarity'] == 100
            assert not check['applied'] and 'unit.o::unrelated_value' in check['unexpected_symbols'], check
            assert (project / 'unit.c').read_text() == wrong
            report['unrelated_data_application_refused'] = True
            bundle = api.workspace(operation='export', workspace=created['workspace']['id'])
            api.workspace(operation='import', request=dict(bundle=bundle))
            bundle['project_checks'].append(bundle['project_checks'][0])
            rejects(lambda: api.workspace(operation='import', request=dict(bundle=bundle)))
            report['duplicate_project_history_rejected'] = True

            wrapper = project / 'compiler.sh'
            wrapper.write_text('#!/bin/sh\nif [ "$1" != "--version" ]; then printf "\\n# modified\\n" >> "$0"; fi\nexec ' + str(compiler) + ' "$@"\n')
            wrapper.chmod(0o700)
            original_tool = wrapper.read_bytes()
            binding['build']['executable'] = str(wrapper)
            created = setup(api, target, SOURCE, profile(wrapper, ['-O2']), binding, 'private tool integrity')
            patch = api.run(target, operation='prepare_patch', candidate=created['candidate']['id'], profile='test')
            rejects(lambda: api.run(target, operation='verify_patch', patch=patch, apply=True))
            assert wrapper.read_bytes() == original_tool and (project / 'unit.c').read_text() == wrong
            report['private_tool_mutation_refused'] = True

            assembly = '.text\n.globl step,foo,bar\n.type step,@function\nstep: call foo\nret\n.size step,.-step\n.type foo,@function\nfoo: ret\n.size foo,.-foo\n.type bar,@function\nbar: ret\n.size bar,.-bar\n.section .note.GNU-stack,"",@progbits\n'
            asm = root / 'unit.s'
            original_object = root / 'assembly.o'
            asm.write_text(assembly)
            subprocess.run([str(compiler), '-c', str(asm), '-o', str(original_object)], check=True)
            for duplicate in [False, True]:
                reference = root / ('duplicate.o' if duplicate else 'weak.o')
                reference.write_bytes(corrupt_symbol(original_object.read_bytes(), duplicate))
                created = setup(api, reference, assembly, profile(compiler), filename='unit.s')
                trial = api.run(target, operation='trial', candidate=created['candidate']['id'], profile='test')
                assert trial['diagnosis']['exact_instructions'] is True
                assert trial['diagnosis']['exact_relocations'] is (None if duplicate else False)
                if not duplicate:
                    bundle = api.workspace(operation='export', workspace=created['workspace']['id'])
                    api.workspace(operation='import', request=dict(bundle=bundle))
                    bundle['workspace']['profiles'][0]['recipe']['arguments'].append('-fwrapv')
                    rejects(lambda: api.workspace(operation='import', request=dict(bundle=bundle)))
            report['relocation_binding_and_ambiguity_preserved'] = True
            report['inconsistent_recipe_history_rejected'] = True

            sleeper = root / 'slow-clang.sh'
            sleeper.write_text('#!/bin/sh\nif [ "$1" = "--version" ]; then exec ' + str(compiler) + ' --version; fi\n/bin/sleep 30 &\nprintf "%s\\n" "$!" > "$MATCHING_CHILD_PID"\nwait\nexec ' + str(compiler) + ' "$@"\n')
            sleeper.chmod(0o700)
            report['shutdown_ms'] = {}
            for mode in ['eof', 'invalid_utf8']:
                if mode != 'eof':
                    api = Api(args.api.resolve(), root / 'store', args.objdiff.resolve())
                marker = root / (mode + '.pid')
                created = setup(api, target, SOURCE, profile(sleeper, ['-O2'], {'MATCHING_CHILD_PID': str(marker)}))
                api.call('job_submit', op='matching', program='fixture', binary=str(target), budget_ms=60000,
                    operation=dict(operation='trial', candidate=created['candidate']['id'], profile='test'))
                deadline = time.monotonic() + 5
                while not marker.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                child = int(marker.read_text())
                child_fd = os.pidfd_open(child)
                child_group = os.getpgid(child)
                started = time.monotonic()
                api.close(invalid_input=mode == 'invalid_utf8')
                if not select.select([child_fd], [], [], 1)[0]:
                    raise AssertionError(f'Compiler child survived API shutdown ({mode})')
                assert not list((root / 'store').glob('.matching-*')), 'Shutdown left private compiler files behind'
                report['shutdown_ms'][mode] = round((time.monotonic() - started) * 1000)
                os.close(child_fd)
                child_fd = None
            report['passed'] = True
            print(json.dumps(report, indent=2))
        finally:
            if child_fd is not None:
                if not select.select([child_fd], [], [], 0)[0]:
                    os.killpg(child_group, signal.SIGKILL)
                os.close(child_fd)
            if api.process.poll() is None:
                api.process.kill()
                api.process.wait(timeout=5)


if __name__ == '__main__':
    main()
