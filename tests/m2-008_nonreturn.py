#!/usr/bin/env python3
"""Real nonreturn inference, caller rediscovery, and worker snapshot acceptance."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'benchmarks'))
from prototype_gate import run_api

SOURCE = r'''
.text
.globl entry, relay, stop, ordinary, unknown, indirect, dead_entry, dead_relay
.type entry,@function
entry:
.cfi_startproc
 test %edi,%edi
 je normal
 call relay
dead_entry:
 call ordinary
normal:
 xor %eax,%eax
 ret
.cfi_endproc
.size entry,.-entry
.type relay,@function
relay:
.cfi_startproc
 call stop
dead_relay:
 call ordinary
 ret
.cfi_endproc
.size relay,.-relay
.type stop,@function
stop:
.cfi_startproc
 jmp stop
.cfi_endproc
.size stop,.-stop
.type ordinary,@function
ordinary:
.cfi_startproc
 mov $7,%eax
 ret
.cfi_endproc
.size ordinary,.-ordinary
.type unknown,@function
unknown:
.cfi_startproc
 jmp *%rdi
.cfi_endproc
.size unknown,.-unknown
.type indirect,@function
indirect:
.cfi_startproc
 call *%rdi
 ret
.cfi_endproc
.size indirect,.-indirect
.section .note.GNU-stack,"",@progbits
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    env = dict(os.environ, DEBUGINFOD_URLS='')
    for name in ('VENTRIS_SLA', 'VENTRIS_LANGUAGE', 'VENTRIS_LANGUAGE_DIR', 'VENTRIS_SPECS'):
        env.pop(name, None)
    with tempfile.TemporaryDirectory(prefix='ventris-nonreturn-') as temporary:
        work = Path(temporary)
        twin, binary, project = work / 'fixture.unstripped', work / 'fixture.bin', work / 'project'
        subprocess.run(['gcc', '-nostdlib', '-no-pie', '-Wl,-e,entry', '-x', 'assembler', '-',
            '-o', str(twin)], input=SOURCE, text=True, check=True, capture_output=True)
        names = {'entry', 'relay', 'stop', 'ordinary', 'unknown', 'indirect', 'dead_entry', 'dead_relay'}
        symbols = {parts[0]: int(parts[2], 16) for line in subprocess.check_output(
            ['nm', '-P', str(twin)], text=True).splitlines()
            if len(parts := line.split()) >= 3 and parts[0] in names}
        assert set(symbols) == names, symbols
        shutil.copyfile(twin, binary)
        subprocess.run(['llvm-strip', '--strip-all', str(binary)], check=True)
        address = lambda name: dict(space='Ram', offset=symbols[name])
        context = dict(binary=str(binary), program='fixture')
        invoke = lambda requests: run_api(ROOT, project, requests, 120, env)
        refs = lambda name: ('xrefs', dict(program='fixture', address=address(name), incoming=False))
        doc = ('decompile_doc', dict(**context, address=address('relay')))
        before = invoke([('import_native', dict(binary=str(binary), name='fixture'))] + [
            ('rename', dict(program='fixture', address=address(name), name=name))
            for name in names if not name.startswith('dead_')] + [refs('dead_entry'), refs('dead_relay'), doc])
        for rows in before[-3:-1]:
            assert any(row['to'] == address('ordinary') and 'CALL' in row['kind'] for row in rows), rows
        assert any(token['text'] == 'ordinary' for token in before[-1]['tokens']), before[-1]
        # Keep a child warm across publication: revision invalidation must prevent
        # the old returning-callee assumptions from surviving the inference.
        _, report, after_doc = invoke([doc, ('infer_nonreturning', context), doc])
        facts, entry_refs, relay_refs, functions = invoke([
            ('return_behaviors', dict(program='fixture')), refs('dead_entry'), refs('dead_relay'),
            ('functions', dict(program='fixture'))])
        inferred = {row['function']['offset'] for row in facts if row['no_return']}
        assert inferred == {symbols['stop'], symbols['relay']}, facts
        assert all(row['provenance']['kind'] == 'inferred' and row['provenance']['source'] for row in facts), facts
        assert not any('CALL' in row['kind'] for row in entry_refs + relay_refs), (entry_refs, relay_refs)
        relay = next(row for row in functions if row['entry'] == address('relay'))
        assert relay['name'] == 'relay' and relay['size'] == symbols['dead_relay'] - symbols['relay'], relay
        assert not any(token['text'] == 'ordinary' for token in after_doc['tokens']), after_doc
        assert after_doc['revision'] > before[-1]['revision'], (before[-1], after_doc)
        standalone = subprocess.run([str(ROOT / 'target/debug/lre-cli'), 'decompile-native-doc',
            str(binary), hex(symbols['relay']), '--project', str(project), '--name', 'fixture'],
            capture_output=True, text=True, check=True, timeout=120, env=env)
        assert not any(token['text'] == 'ordinary' for token in json.loads(standalone.stdout)['tokens'])
        repeated, final_doc, final_facts = invoke([('infer_nonreturning', context), doc,
            ('return_behaviors', dict(program='fixture'))])
        assert repeated['changed'] == [] and final_doc['revision'] == after_doc['revision'], repeated
        assert final_facts == facts, (final_facts, facts)
        evidence = dict(task='m2-008', passed=True, scope='temporary positive acceptance, not locked corpus',
            inferred_functions=2, returning_controls=2, unresolved_indirect_controls=1,
            removed_call_xrefs=2, standalone=1, pooled=True, report=report, repeated=repeated)
        if args.report:
            args.report.write_text(json.dumps(evidence, indent=2) + '\n')
        print(json.dumps(evidence))


if __name__ == '__main__':
    main()
