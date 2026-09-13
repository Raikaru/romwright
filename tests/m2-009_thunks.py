#!/usr/bin/env python3
"""Thunk facts cover linkage stubs and entry jumps, never mid-body tail calls."""
import argparse
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'benchmarks'))
from prototype_gate import run_api

SOURCE = r'''
.text
.globl entry, real, direct_thunk, skip_thunk, tail_caller, ordinary
.type entry,@function
entry:
.cfi_startproc
 call direct_thunk
 call skip_thunk
 mov $1,%edi
 call tail_caller
 call ordinary
 call puts@PLT
 xor %eax,%eax
 ret
.cfi_endproc
.size entry,.-entry
.type real,@function
real:
.cfi_startproc
 mov $7,%eax
 ret
.cfi_endproc
.size real,.-real
.type direct_thunk,@function
direct_thunk:
.cfi_startproc
 jmp real
.cfi_endproc
.size direct_thunk,.-direct_thunk
.type skip_thunk,@function
skip_thunk:
.cfi_startproc
 nop
 jmp real
.cfi_endproc
.size skip_thunk,.-skip_thunk
.type tail_caller,@function
tail_caller:
.cfi_startproc
 test %edi,%edi
 je .Ltail
 mov $2,%eax
 ret
.Ltail:
 jmp real
.cfi_endproc
.size tail_caller,.-tail_caller
.type ordinary,@function
ordinary:
.cfi_startproc
 mov $3,%eax
 ret
.cfi_endproc
.size ordinary,.-ordinary
.section .note.GNU-stack,"",@progbits
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    env = dict(os.environ, DEBUGINFOD_URLS='')
    for name in ('ROMWRIGHT_SLA', 'ROMWRIGHT_LANGUAGE', 'ROMWRIGHT_LANGUAGE_DIR', 'ROMWRIGHT_SPECS'):
        env.pop(name, None)
    with tempfile.TemporaryDirectory(prefix='romwright-thunks-') as temporary:
        work = Path(temporary)
        twin, binary, project = work / 'fixture.unstripped', work / 'fixture.bin', work / 'project'
        subprocess.run(['gcc', '-nostdlib', '-no-pie', '-Wl,-e,entry', '-x', 'assembler', '-',
            '-o', str(twin), '-lc'], input=SOURCE, text=True, check=True, capture_output=True)
        names = {'entry', 'real', 'direct_thunk', 'skip_thunk', 'tail_caller', 'ordinary'}
        symbols = {parts[0]: int(parts[2], 16) for line in subprocess.check_output(
            ['nm', '-P', str(twin)], text=True).splitlines()
            if len(parts := line.split()) >= 3 and parts[0] in names}
        assert set(symbols) == names, symbols
        shutil.copyfile(twin, binary)
        subprocess.run(['llvm-strip', '--strip-all', str(binary)], check=True)
        address = lambda name: dict(space='Ram', offset=symbols[name])
        invoke = lambda requests: run_api(ROOT, project, requests, 120, env)
        functions, thunks = invoke([
            ('import_native', dict(binary=str(binary), name='fixture')),
            ('functions', dict(program='fixture')),
            ('thunks', dict(program='fixture'))])[1:]
        by_entry = {row['entry']['offset']: row for row in functions}
        rows = {row['function']['offset']: row for row in thunks}
        assert len(rows) == len(thunks), thunks
        for name in ('direct_thunk', 'skip_thunk'):
            row = rows[symbols[name]]
            assert row['thunked'] == address('real') and row['kind'] == 'direct', (name, row)
        linkage = [row for row in thunks if row['kind'] == 'linkage']
        assert len(linkage) == 1, linkage
        stub = linkage[0]['function']['offset']
        assert by_entry[stub]['name'] == 'puts', (stub, by_entry.get(stub))
        # The proven import slot is data, never a code entry of its own.
        assert linkage[0]['thunked']['space'] == 'Ram', linkage[0]
        assert linkage[0]['thunked']['offset'] not in by_entry, linkage[0]
        assert all(row['provenance']['kind'] == 'inferred' and row['provenance']['source']
            for row in thunks), thunks
        for name in ('entry', 'real', 'tail_caller', 'ordinary'):
            assert symbols[name] not in rows, (name, rows.get(symbols[name]))
        tail = by_entry[symbols['tail_caller']]
        assert tail['size'] > symbols['real'] - symbols['tail_caller'] or tail['size'] >= 8, tail
        repeated = invoke([('import_native', dict(binary=str(binary), name='fixture')),
            ('thunks', dict(program='fixture'))])[1]
        assert repeated == thunks, (repeated, thunks)
        # An analyst assertion is a separate owner: re-import must not drop it.
        # The stripped fixture has generated names, so seed by proven address.
        with sqlite3.connect(project / 'project.sqlite') as database:
            database.execute('''INSERT INTO thunks
                (program_id, function, thunked, kind, provenance, provenance_kind, confidence)
                SELECT id, ?, ?, 'direct', 'thunk-acceptance', 'asserted', NULL FROM programs
                WHERE name = 'fixture' ''',
                (format(symbols['ordinary'], '08x'), format(symbols['real'], '08x')))
            database.execute('UPDATE programs SET revision = revision + 1')
        asserted = invoke([('import_native', dict(binary=str(binary), name='fixture')),
            ('thunks', dict(program='fixture'))])[1]
        kept = [row for row in asserted if row['provenance']['kind'] == 'asserted']
        assert len(kept) == 1 and kept[0]['function'] == address('ordinary'), asserted
        assert [row for row in asserted if row['provenance']['kind'] == 'inferred'] == thunks, asserted
        evidence = dict(task='m2-009', passed=True,
            scope='temporary positive acceptance, not the locked corpus or libc gate',
            direct_thunks=2, linkage_thunks=1, tail_calls_excluded=1, asserted_preserved=1,
            thunks=thunks)
        if args.report:
            args.report.write_text(json.dumps(evidence, indent=2) + '\n')
        print(json.dumps(evidence))


if __name__ == '__main__':
    main()
