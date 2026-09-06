#!/usr/bin/env python3
"""Real nonreturn inference, caller rediscovery, and worker snapshot acceptance."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sqlite3
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'benchmarks'))
from prototype_gate import run_api

SOURCE = r'''
.text
.globl entry, relay, stop, ordinary, unknown, indirect, dead_entry, dead_relay
.globl known_caller, dead_known, hint_loop
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
.type known_caller,@function
known_caller:
.cfi_startproc
 xor %edi,%edi
 call exit@PLT
dead_known:
 call ordinary
 ret
.cfi_endproc
.size known_caller,.-known_caller
.type hint_loop,@function
hint_loop:
.cfi_startproc
.Ldispatch:
 and $3,%edi
 lea .Ltargets(%rip),%rdx
 movslq (%rdx,%rdi,4),%rax
 add %rdx,%rax
 jmp *%rax
.Lcase0:
 add $1,%edi
 jmp .Ldispatch
.Lcase1:
 add $2,%edi
 jmp .Ldispatch
.Lcase2:
 xor $1,%edi
 jmp .Ldispatch
.Lcase3:
 sub $1,%edi
 jmp .Ldispatch
.cfi_endproc
.size hint_loop,.-hint_loop
.section .rodata
.p2align 2
.Ltargets:
 .long .Lcase0-.Ltargets, .Lcase1-.Ltargets, .Lcase2-.Ltargets, .Lcase3-.Ltargets
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
            '-o', str(twin), '-lc'], input=SOURCE, text=True, check=True, capture_output=True)
        names = {'entry', 'relay', 'stop', 'ordinary', 'unknown', 'indirect', 'dead_entry', 'dead_relay'}
        names.update({'known_caller', 'dead_known', 'hint_loop'})
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
        _, initial_functions = invoke([
            ('import_native', dict(binary=str(binary), name='fixture')),
            ('functions', dict(program='fixture'))])
        exit_entry = next(row['entry'] for row in initial_functions if row['name'] == 'exit')
        known_doc = ('decompile_doc', dict(**context, address=address('known_caller')))
        assertion = dict(function=address('stop'), signature='void stop(void)',
            calling_convention=None, return_type='void',
            provenance=dict(kind='asserted', source='nonreturn-acceptance', confidence=None))
        operation = dict(op_id='assert-stop', actor='acceptance', lamport=1,
            kind='set_prototype', payload=json.dumps(assertion), applied=False, provenance='acceptance')
        before = invoke([
            ('rename', dict(program='fixture', address=address(name), name=name))
            for name in names if not name.startswith('dead_')] + [
                ('append_collab_op', dict(program='fixture', operation=operation)),
                ('apply_collab_op', dict(program='fixture', op_id='assert-stop')),
                refs('dead_entry'), refs('dead_relay'), doc])
        for rows in before[-3:-1]:
            assert any(row['to'] == address('ordinary') and 'CALL' in row['kind'] for row in rows), rows
        assert any(token['text'] == 'ordinary' for token in before[-1]['tokens']), before[-1]
        known_before = invoke([refs('dead_known'), known_doc])
        assert any('CALL' in row['kind'] for row in known_before[0]), known_before
        assert any(token['text'] == 'ordinary' for token in known_before[1]['tokens']), known_before[1]
        hint_before = invoke([('decompile_doc', dict(**context, address=address('hint_loop')))])[0]
        assert len(hint_before['jump_tables']) == 1, hint_before['jump_tables']
        assert len({row['offset'] for row in hint_before['jump_tables'][0]['targets']}) == 4, hint_before['jump_tables']
        assert hint_before['prototype'].get('no_return') is True, hint_before['prototype']
        # Keep a child warm across publication: revision invalidation must prevent
        # the old returning-callee assumptions from surviving the inference.
        _, report, after_doc = invoke([doc, ('infer_nonreturning', context), doc])
        facts, entry_refs, relay_refs, functions, prototypes = invoke([
            ('return_behaviors', dict(program='fixture')), refs('dead_entry'), refs('dead_relay'),
            ('functions', dict(program='fixture')), ('prototypes', dict(program='fixture'))])
        assert prototypes == [assertion], prototypes
        inferred = {row['function']['offset'] for row in facts if row['no_return']}
        assert inferred == {symbols['stop'], symbols['relay'], symbols['known_caller'],
            symbols['hint_loop'], exit_entry['offset']}, facts
        assert all(row['provenance']['kind'] == 'inferred' and row['provenance']['source'] for row in facts), facts
        assert not any('CALL' in row['kind'] for row in entry_refs + relay_refs), (entry_refs, relay_refs)
        relay = next(row for row in functions if row['entry'] == address('relay'))
        assert relay['name'] == 'relay' and relay['size'] == symbols['dead_relay'] - symbols['relay'], relay
        known = next(row for row in functions if row['entry'] == address('known_caller'))
        assert known['size'] == symbols['dead_known'] - symbols['known_caller'], known
        known_refs, known_after = invoke([refs('dead_known'), known_doc])
        assert not any('CALL' in row['kind'] for row in known_refs), known_refs
        assert not any(token['text'] == 'ordinary' for token in known_after['tokens']), known_after
        assert known_after['prototype']['no_return'] is True, known_after
        assert not any(token['text'] == 'ordinary' for token in after_doc['tokens']), after_doc
        assert after_doc['prototype']['no_return'] is True, after_doc
        assert after_doc['revision'] > before[-1]['revision'], (before[-1], after_doc)
        standalone = subprocess.run([str(ROOT / 'target/debug/lre-cli'), 'decompile-native-doc',
            str(binary), hex(symbols['relay']), '--project', str(project), '--name', 'fixture'],
            capture_output=True, text=True, check=True, timeout=120, env=env)
        assert not any(token['text'] == 'ordinary' for token in json.loads(standalone.stdout)['tokens'])
        repeated, final_doc, final_facts = invoke([('infer_nonreturning', context), doc,
            ('return_behaviors', dict(program='fixture'))])
        assert repeated['changed'] == [] and final_doc['revision'] == after_doc['revision'], repeated
        assert final_facts == facts, (final_facts, facts)
        # Seed store states through its SQL schema; the public DB setter's
        # ownership/revision behavior has its own Rust coverage.
        def put_return(name, no_return, kind):
            with sqlite3.connect(project / 'project.sqlite') as database:
                database.execute('''INSERT INTO return_behaviors
                    (program_id, function, no_return, provenance, provenance_kind, confidence)
                    SELECT program_id, entry, ?, ?, ?, NULL FROM functions WHERE name=?
                    ON CONFLICT(program_id, function) DO UPDATE SET
                    no_return=excluded.no_return, provenance=excluded.provenance,
                    provenance_kind=excluded.provenance_kind, confidence=NULL''',
                    (no_return, facts[0]['provenance']['source'] if kind == 'inferred'
                        else 'nonreturn-acceptance', kind, name))
                database.execute('UPDATE programs SET revision=revision+1')
                database.execute('''INSERT INTO revision_events(program_id, revision, kind, detail)
                    SELECT id, revision, 'return-behavior', 'acceptance input' FROM programs''')
        # A stale positive must not validate itself through the worker snapshot.
        put_return('ordinary', True, 'inferred')
        revalidated, revalidated_facts = invoke([('infer_nonreturning', context),
            ('return_behaviors', dict(program='fixture'))])
        assert address('ordinary') in revalidated['changed'], revalidated
        assert revalidated_facts == facts, revalidated_facts
        # Assertions override both a known name and an inferred callee; callers'
        # original returning continuations and their owned call edges return.
        put_return('exit', False, 'asserted')
        put_return('stop', False, 'asserted')
        retracted, restored_doc, restored_known, restored_facts = invoke([
            ('infer_nonreturning', context), doc, known_doc,
            ('return_behaviors', dict(program='fixture'))])
        assert any(token['text'] == 'ordinary' for token in restored_doc['tokens']), restored_doc
        assert any(token['text'] == 'ordinary' for token in restored_known['tokens']), restored_known
        for rows in invoke([refs('dead_entry'), refs('dead_relay'), refs('dead_known')]):
            assert any(row['to'] == address('ordinary') and 'CALL' in row['kind'] for row in rows), rows
        assert {row['function']['offset'] for row in restored_facts if row['no_return']} == {symbols['hint_loop']}, restored_facts
        assert sum(row['provenance']['kind'] == 'asserted' and not row['no_return'] for row in restored_facts) == 2, restored_facts
        evidence = dict(task='m2-008', passed=True, scope='temporary positive acceptance, not locked corpus',
            inferred_functions=5, returning_controls=2, unresolved_indirect_controls=2,
            removed_call_xrefs=3, restored_call_xrefs=3, stale_inference_retracted=1,
            asserted_return_controls=2, standalone=1, pooled=True,
            report=report, repeated=repeated, revalidated=revalidated, retracted=retracted)
        if args.report:
            args.report.write_text(json.dumps(evidence, indent=2) + '\n')
        print(json.dumps(evidence))


if __name__ == '__main__':
    main()
