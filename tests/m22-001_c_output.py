#!/usr/bin/env python3
"""M22-001: measure decompiled C for matching decomp (plan item P4.6).

For a fixed pokeemerald function set, three C candidates are produced and
scored against the original agbcc objects:

  romwright      pokeemerald.gba (stripped ROM) imported once with the CLI,
                 function names asserted from the ELF symbol table
                 (`assert-names`), prototypes of the target and its callees
                 asserted from the public headers (`assert-prototypes`),
                 then `export-c --address`.
  romwright-elf  the same flow on pokeemerald.elf, whose symbol table also
                 names data objects -- the symbol information m2c gets from
                 the object's relocations. Reported separately so the
                 stripped-ROM number is never flattered.
  m2c            mechanical GNU Thumb assembly of the function extracted from
                 the original object (the prior harness's reference_asm
                 extractor, embedded below; reassembly parity is checked per
                 function), decompiled with `m2c -t gba-gcc-c --valid-syntax
                 --context context.h`.
  stock          stock Ghidra `stock-header-export` outputs from the
                 2026-09-16 harness, reused where they exist (5 functions);
                 Ghidra is not re-run.

Every candidate is compiled twice with agbcc -O2 through the proven driver:
  context     `#include "context.h"` + candidate   (headline number)
  standalone  candidate alone
and each object is diffed against the original object's function with
objdiff-cli; the similarity is the target-side symbol `match_percent`.
A candidate that is missing or fails to compile scores 0 with its error kept.

Token distance: Levenshtein over C tokens of the function definition
(declarations and comments dropped), with pokeemerald/Ghidra type aliases
mapped to one spelling, integer literals normalised to decimal, and every
other identifier replaced by `ID`, measured against m2c's C.

Function selection rule (fixed, deterministic): the named list FUNCTIONS
below, checked in with this script. It holds the five functions of the
2026-09-16 comparison plus whole C translation-unit families picked to span
sizes and shapes: RNG leaves (random.o), fixed-point trig (trig.o), CRC and
bit loops (util.o), string loops (string_util.o), multiply/divide helpers
(math_util.o), range checks and flag bit arithmetic (event_data.o), task
array struct access with calls (task.o), a switch with calls
(battle_util.o GetMoveTarget) and compiler-helper division (pokemon.o).

Context rule (one shared context.h for every layer): pokeemerald integer
typedefs, `TaskFunc`, m2c's own `m2c_macros.h` (the documented companion of
--valid-syntax output), prototypes copied from include/*.h or the unit's .c
for the targets and their direct callees, and extern declarations for every
data symbol the functions reference. Types other than integer
typedefs/pointers to them are erased: struct/function pointers become
`void *`, enums become `int`, and struct/aggregate globals become
`unsigned char NAME[size]` with the size taken from the ELF symbol.

Exit status is non-zero only if the harness itself breaks (missing tool,
reassembly parity failure, crash), never because a layer scores low.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

HOME = Path.home()
REPO = Path(__file__).resolve().parent.parent
POKEEMERALD = HOME / 'opt/pokeemerald-src'
OBJ_ROOT = POKEEMERALD / 'build/emerald/src'
ROM = HOME / 'ventris-corpus/extracted/gba-pokeemerald/pokeemerald.gba'
ELF = HOME / 'ventris-corpus/extracted/gba-pokeemerald/pokeemerald.elf'
PRIOR = HOME / 'tmp/romwright-product-20260916'
DRIVER = PRIOR / 'agbcc-driver.py'
M2C = PRIOR / 'baselines/m2c/m2c.py'
M2C_MACROS = PRIOR / 'baselines/m2c/m2c_macros.h'
STOCK = PRIOR / 'stock-header-export'
AGBCC = POKEEMERALD / 'tools/agbcc/bin/agbcc'
BINUTILS = HOME / 'opt/arm-none-eabi/bin'
AS = BINUTILS / 'arm-none-eabi-as'
OBJDUMP = BINUTILS / 'arm-none-eabi-objdump'
READELF = BINUTILS / 'arm-none-eabi-readelf'
OBJDIFF = HOME / 'Projects/agent-under-fire/dtk-template/build/tools/objdiff-cli'
CLI = REPO / 'target/release/romwright-cli'

# (function, translation unit object under build/emerald/src)
FUNCTIONS = [
    ('Random', 'random'), ('Random2', 'random'), ('SeedRng', 'random'),
    ('Sin', 'trig'), ('Cos', 'trig'), ('Sin2', 'trig'), ('Cos2', 'trig'),
    ('CalcCRC16', 'util'), ('CalcCRC16WithTable', 'util'),
    ('CalcByteArraySum', 'util'), ('CountTrailingZeroBits', 'util'),
    ('StringCopy', 'string_util'), ('StringLength', 'string_util'),
    ('StringCompare', 'string_util'), ('StringAppend', 'string_util'),
    ('StringCopyN', 'string_util'), ('StringFill', 'string_util'),
    ('GetExtCtrlCodeLength', 'string_util'),
    ('ConvertIntToDecimalStringN', 'string_util'),
    ('MathUtil_Mul16', 'math_util'), ('MathUtil_Div16', 'math_util'),
    ('MathUtil_Mul32', 'math_util'),
    ('VarGet', 'event_data'), ('VarSet', 'event_data'),
    ('GetVarPointer', 'event_data'), ('FlagSet', 'event_data'),
    ('FlagGet', 'event_data'),
    ('FindTaskIdByFunc', 'task'), ('CreateTask', 'task'), ('DestroyTask', 'task'),
    ('GetMoveTarget', 'battle_util'),
    ('GetNatureFromPersonality', 'pokemon'), ('IsShinyOtIdPersonality', 'pokemon'),
]

LAYERS = ('romwright', 'romwright-elf', 'm2c', 'stock')
PROGRAM = 'emerald'


class HarnessError(Exception):
    """The measurement itself is broken (not a candidate losing)."""


def run(argv, *, timeout=600, env=None, cwd=None, input_text=None):
    started = time.monotonic()
    try:
        result = subprocess.run([str(a) for a in argv], capture_output=True, text=True,
                                timeout=timeout, env=env, cwd=cwd, input=input_text)
        exit_code, stdout, stderr = result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired as error:
        exit_code, stdout, stderr = -9, error.stdout or '', f'timeout after {timeout}s'
        stdout = stdout.decode(errors='replace') if isinstance(stdout, bytes) else stdout
    return {'argv': [str(a) for a in argv], 'exit': exit_code, 'stdout': stdout,
            'stderr': stderr, 'seconds': round(time.monotonic() - started, 3)}


# ---------------------------------------------------------------------------
# Reference assembly (embedded from ~/tmp/romwright-product-20260916/
# reference_asm.py; mechanical GNU Thumb extraction, no C source consumed).
# ---------------------------------------------------------------------------

BRANCHES = ('b', 'beq', 'bne', 'bcs', 'bcc', 'bhs', 'blo', 'bmi', 'bpl', 'bvs', 'bvc',
            'bhi', 'bls', 'bge', 'blt', 'bgt', 'ble')


def extract_asm(object_path, name):
    """Returns (assembly text, referenced symbol names by relocation kind)."""
    with open(object_path, 'rb') as stream:
        image = ELFFile(stream)
        table = image.get_section_by_name('.symtab')
        matches = table.get_symbol_by_name(name) or []
        if len(matches) != 1:
            raise HarnessError(f'{name}: function symbol missing or ambiguous in {object_path}')
        symbol = matches[0]
        if not symbol['st_value'] & 1:
            raise HarnessError(f'{name}: not marked Thumb')
        section_index = symbol['st_shndx']
        section = image.get_section(section_index)
        start = symbol['st_value'] & ~1
        end = start + symbol['st_size']
        data = section.data()
        symbols = list(table.iter_symbols())
        relocations = {}
        for rs in image.iter_sections():
            if not isinstance(rs, RelocationSection) or rs['sh_info'] != section_index:
                continue
            targets = image.get_section(rs['sh_link'])
            for relocation in rs.iter_relocations():
                offset = relocation['r_offset']
                if start <= offset < end:
                    relocations[offset] = (relocation['r_info_type'],
                                           targets.get_symbol(relocation['r_info_sym']))
        referenced = {'call': set(), 'data': set()}

        def expression(target, addend, kind):
            if target.name:
                referenced[kind].add(target.name)
                return target.name + (f' + {addend}' if addend > 0 else f' - {-addend}' if addend else '')
            if target['st_shndx'] == section_index and start <= addend < end:
                return f'.L_ref_{addend:x}'
            candidates = [s for s in symbols if s.name and s['st_shndx'] == target['st_shndx']
                          and s['st_info']['type'] in ('STT_OBJECT', 'STT_FUNC') and s['st_value'] <= addend]
            if not candidates:
                raise HarnessError(f'{name}: cannot name section relocation at {addend:x}')
            base = max(candidates, key=lambda s: s['st_value'])
            return expression(base, addend - base['st_value'], kind)

        result = subprocess.run([str(OBJDUMP), '-drz', f'--start-address={start}',
                                 f'--stop-address={end}', str(object_path)],
                                check=True, capture_output=True, text=True)
        rows = []
        expected = start
        for line in result.stdout.splitlines():
            fields = line.split('\t')
            if len(fields) < 3 or not re.fullmatch(r'\s*[0-9a-f]+:', fields[0]):
                continue
            address = int(fields[0].strip()[:-1], 16)
            raw = ''.join(fields[1].split())
            if not re.fullmatch(r'[0-9a-f]+', raw):
                continue
            if address != expected:
                raise HarnessError(f'{name}: disassembly gap at {expected:x}')
            expected += len(raw) // 2
            mnemonic = fields[2].strip().removesuffix('.n')
            operands_with_comment = ' '.join(fields[3:]).strip()
            operands = operands_with_comment.split('@', 1)[0].strip()
            branch_target = re.search(r'\b([0-9a-f]+)\s+<[^>]+>', operands_with_comment)
            if address in relocations:
                kind, target = relocations[address]
                if kind == 2:
                    if mnemonic != '.word':
                        raise HarnessError(f'{name}: ABS32 relocation is not a literal word')
                    operands = expression(target, int.from_bytes(data[address:address + 4], 'little'), 'data')
                elif kind == 10:
                    if mnemonic != 'bl':
                        raise HarnessError(f'{name}: THM_CALL relocation is not a Thumb BL')
                    high = int.from_bytes(data[address:address + 2], 'little')
                    low = int.from_bytes(data[address + 2:address + 4], 'little')
                    addend = ((high & 0x7ff) << 12) | ((low & 0x7ff) << 1)
                    if addend & (1 << 22):
                        addend -= 1 << 23
                    operands = expression(target, addend + 4, 'call')
                else:
                    raise HarnessError(f'{name}: unsupported ARM relocation {kind}')
            elif mnemonic == 'ldr' and '[pc,' in operands:
                if branch_target is None:
                    raise HarnessError(f'{name}: literal load has no decoded target')
                operands = operands.split(',', 1)[0] + ', .L_ref_' + branch_target[1]
            elif mnemonic in ('add', 'adds') and ', pc,' in operands:
                if branch_target is None:
                    raise HarnessError(f'{name}: ADR has no decoded target')
                mnemonic = 'adr'
                operands = operands.split(',', 1)[0] + ', .L_ref_' + branch_target[1]
            elif mnemonic in BRANCHES:
                if branch_target is None:
                    raise HarnessError(f'{name}: branch has no decoded target')
                destination = int(branch_target[1], 16)
                if not start <= destination < end:
                    raise HarnessError(f'{name}: unrelocated branch leaves the function')
                operands = f'.L_ref_{destination:x}'
            elif mnemonic == 'bl' and branch_target is not None:
                # agbcc resolves a call to a function of the same section at
                # assembly time, leaving no relocation. Name the callee so
                # the extracted function stays self-contained.
                destination = int(branch_target[1], 16)
                callees = [s for s in symbols if s.name and s['st_shndx'] == section_index
                           and s['st_info']['type'] == 'STT_FUNC' and s['st_value'] & ~1 == destination]
                if len(callees) != 1:
                    raise HarnessError(f'{name}: unrelocated call to unnamed {destination:x}')
                referenced['call'].add(callees[0].name)
                operands = callees[0].name
            elif branch_target is not None and mnemonic not in ('.word', '.short'):
                raise HarnessError(f'{name}: unhandled symbolic instruction: {line}')
            rows.extend([f'.L_ref_{address:x}:', f'    {mnemonic} {operands}'.rstrip()])
        if expected != end:
            raise HarnessError(f'{name}: disassembly does not cover the complete symbol')
        labels = set(re.findall(r'\.L_ref_[0-9a-f]+', '\n'.join(rows[1::2])))
        rows = [row for row in rows if not row.endswith(':') or row[:-1] in labels]
        prefix = ['.syntax unified', '.thumb', '.text', '.balign 4']
        if start % 4:
            prefix.append(f'.space {start % 4}')
        text = '\n'.join(prefix + [f'.global {name}', f'.type {name}, %function', '.thumb_func',
                                   name + ':'] + rows + [f'.size {name}, . - {name}', ''])
        referenced['data'].discard(name)
        return text, {k: sorted(v) for k, v in referenced.items()}


# ---------------------------------------------------------------------------
# Context header
# ---------------------------------------------------------------------------

PRELUDE = """typedef signed char s8;
typedef unsigned char u8;
typedef short s16;
typedef unsigned short u16;
typedef int s32;
typedef unsigned int u32;
typedef long long s64;
typedef unsigned long long u64;
typedef u8 bool8;
typedef u16 bool16;
typedef u32 bool32;
typedef void *TaskFunc;
#define NULL ((void *)0)
#define TRUE 1
#define FALSE 0
"""
PRIMITIVES = {'s8', 'u8', 's16', 'u16', 's32', 'u32', 's64', 'u64', 'bool8', 'bool16',
              'bool32', 'int', 'char', 'short', 'long', 'unsigned', 'signed', 'void', 'TaskFunc'}
# Ghidra spellings for asserted prototypes (`assert-prototypes`), matching the
# 2026-09-16 benchmark's "native primitive aliases".
GHIDRA_TYPES = {'u8': 'byte', 'bool8': 'byte', 's8': 'sbyte', 'u16': 'ushort', 'bool16': 'ushort',
                's16': 'short', 'u32': 'uint', 'bool32': 'uint', 's32': 'int', 'u64': 'ulonglong',
                's64': 'longlong', 'int': 'int', 'void': 'void', 'char': 'char', 'short': 'short',
                'TaskFunc': 'void *'}
COMPILER_HELPERS = re.compile(r'^__(u?(div|mod)si3|call_via_r\d|(ash|lsh)[lr]di3|muldi3|u?divdi3|u?moddi3)$')
# The C library declarations pokeemerald gets from agbcc's <string.h>.
LIBC = {'memset': ('void *', 'void *s, int c, u32 n'), 'memcpy': ('void *', 'void *d, const void *s, u32 n')}


def load_elf_symbols():
    """ELF FUNC/OBJECT symbols by name -> [(address, size)] (readelf: pyelftools
    iteration over the 360k-entry table takes a minute)."""
    functions, objects = {}, {}
    listing = subprocess.run([str(READELF), '-sW', str(ELF)], check=True, capture_output=True, text=True)
    for line in listing.stdout.splitlines():
        fields = line.split()
        if len(fields) != 8 or fields[6] == 'UND' or fields[3] not in ('FUNC', 'OBJECT'):
            continue
        value, size, name = int(fields[1], 16), int(fields[2], 0), fields[7]
        if fields[3] == 'FUNC':
            functions.setdefault(name, []).append((value & ~1, size))
        else:
            objects.setdefault(name, []).append((value, size))
    return functions, objects


class Declarations:
    """Prototype/extern lookup in the public headers and a unit's own .c."""

    def __init__(self):
        self.headers = [p.read_text(errors='replace') for p in sorted((POKEEMERALD / 'include').rglob('*.h'))]
        self.units = {}

    def _texts(self, unit):
        if unit not in self.units:
            path = POKEEMERALD / 'src' / f'{unit}.c'
            self.units[unit] = path.read_text(errors='replace') if path.exists() else ''
        return self.headers + [self.units[unit]]

    def prototype(self, name, unit):
        pattern = re.compile(r'^[ \t]*((?:static\s+|inline\s+|NOINLINE\s+)*[A-Za-z_][\w \t\*]*?[\s\*])'
                             + re.escape(name) + r'\s*\(([^;{)]*(?:\([^)]*\)[^;{)]*)*)\)\s*(;|\n?\{)', re.M)
        for text in self._texts(unit):
            match = pattern.search(text)
            if match:
                return match.group(1).strip(), match.group(2).strip()
        return None

    def variable(self, name, unit):
        pattern = re.compile(r'^[ \t]*((?:extern|static|const|EWRAM_DATA|IWRAM_DATA|COMMON_DATA|ALIGNED\(\d+\)|\s)*)'
                             r'([A-Za-z_][\w \t\*]*?)\s*\b' + re.escape(name) + r'\b\s*((?:\[[^\]]*\])*)\s*(=|;)', re.M)
        for text in self._texts(unit):
            match = pattern.search(text)
            if match:
                qualifiers, base, dims = match.group(1), match.group(2).strip(), match.group(3)
                const = 'const' in qualifiers.split() or base.startswith('const ')
                return base.removeprefix('const ').strip(), const, dims
        return None


def split_params(text):
    params, depth, current = [], 0, ''
    for char in text:
        if char == ',' and depth == 0:
            params.append(current.strip())
            current = ''
            continue
        depth += char == '('
        depth -= char == ')'
        current += char
    if current.strip():
        params.append(current.strip())
    return params


def erase_type(type_text):
    """Maps a declared type to the context's type vocabulary; None if unsupported."""
    text = ' '.join(type_text.replace('*', ' * ').split())
    words = text.split()
    pointers = words.count('*')
    core = [w for w in words if w not in ('*', 'const', 'static', 'inline', 'NOINLINE', 'volatile')]
    const = 'const' in words
    if not core:
        return None
    if core[0] in ('struct', 'union'):
        return 'void *' if pointers else None
    if core[0] == 'enum':
        return 'int' + ' *' * pointers
    if all(w in PRIMITIVES for w in core):
        return ('const ' if const else '') + ' '.join(core) + ' *' * pointers
    return 'void *' if pointers else None


def parse_param(param):
    """-> (context type, name) or None; function pointers become void *."""
    if param in ('void', ''):
        return None
    if '(' in param:
        match = re.search(r'\(\s*\*\s*(\w+)\s*\)', param)
        return 'void *', (match.group(1) if match else 'fn')
    match = re.fullmatch(r'(.*?)(\w+)\s*((?:\[[^\]]*\])*)', param)
    type_text, name, dims = match.group(1), match.group(2), match.group(3)
    if not type_text.strip():
        return erase_type(name), 'arg'
    if dims:
        type_text += ' *'
    return erase_type(type_text), name


def to_ghidra(context_type):
    words = context_type.replace('*', ' * ').split()
    const = 'const ' if 'const' in words else ''
    words = [w for w in words if w != 'const']
    pointers = words.count('*')
    base = ' '.join(w for w in words if w != '*')
    if base.startswith('unsigned') or base.startswith('signed'):
        base = {'unsigned char': 'byte', 'unsigned short': 'ushort', 'unsigned int': 'uint',
                'signed char': 'sbyte', 'unsigned': 'uint'}.get(base, base)
    ghidra = GHIDRA_TYPES.get(base, base)
    return const + ghidra + ' *' * pointers


def build_context(functions, decls, elf_objects, elf_functions):
    """-> (context text, prototypes JSON rows (without addresses), notes)."""
    lines, notes, prototypes, seen = [], [], {}, set()
    wanted_functions, wanted_data = [], []
    for name, unit, refs in functions:
        wanted_functions.append((name, unit))
        for callee in refs['call']:
            if not COMPILER_HELPERS.match(callee):
                wanted_functions.append((callee, unit))
        for symbol in refs['data']:
            (wanted_functions if symbol in elf_functions else wanted_data).append((symbol, unit))
    for name, unit in wanted_functions:
        if name in seen:
            continue
        seen.add(name)
        found = decls.prototype(name, unit) or LIBC.get(name)
        if not found:
            notes.append(f'no prototype found for function {name}')
            continue
        return_type = erase_type(found[0])
        params = [parse_param(p) for p in split_params(found[1])]
        params = [p for p in params if p is not None]
        if return_type is None or any(p[0] is None for p in params):
            notes.append(f'unsupported prototype for {name}: {found[0]} {name}({found[1]})')
            continue
        joined = ', '.join(f'{t} {n}' for t, n in params) or 'void'
        if name not in LIBC:  # agbcc declares the libc builtins itself; a redeclaration is an -Werror conflict
            lines.append(f'{return_type} {name}({joined});')
        ghidra = ', '.join(f'{to_ghidra(t)} {n}' for t, n in params) or 'void'
        prototypes[name] = f'{to_ghidra(return_type)} {name}({ghidra})'
    data_lines = []
    for name, unit in wanted_data:
        if name in seen:
            continue
        seen.add(name)
        if not re.fullmatch(r'[A-Za-z_]\w*', name):
            notes.append(f'data {name}: not a C identifier (function-local static); not declarable')
            continue
        found = decls.variable(name, unit)
        sizes = {size for _, size in elf_objects.get(name, [])}
        size = max(sizes) if sizes else None
        declared = None
        if found:
            base, const, dims = found
            erased = erase_type(base)
            trailing = re.findall(r'\[([^\]]*)\]', dims)[1:]
            if erased and all(re.fullmatch(r'\s*(0x[0-9a-fA-F]+|\d+)\s*', d) for d in trailing):
                qualifier = 'const ' if const and not erased.startswith('const') else ''
                suffix = ('[]' + ''.join(f'[{d.strip()}]' for d in trailing)) if dims else ''
                declared = f'extern {qualifier}{erased} {name}{suffix};'
        if declared is None:
            if size:
                declared = f'extern unsigned char {name}[{size}];'
                notes.append(f'data {name}: erased to unsigned char[{size}]')
            else:
                declared = f'extern unsigned char {name}[];'
                notes.append(f'data {name}: no declaration or ELF size; unsized byte array')
        data_lines.append(declared)
    macros = M2C_MACROS.read_text()
    text = (PRELUDE + '\n' + macros + '\n' + '\n'.join(sorted(data_lines)) + '\n\n'
            + '\n'.join(lines) + '\n')
    return text, prototypes, notes


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def compile_candidate(source, output):
    return run([sys.executable, DRIVER, '--cpp', '/usr/bin/gcc', '--cc', AGBCC,
                '--assembler', AS, source, '-o', output], timeout=120)


def objdiff(target, candidate, symbol, record):
    result = run([OBJDIFF, 'diff', '-1', target, '-2', candidate, symbol,
                  '--format', 'json', '-o', record], timeout=120)
    similarity = None
    if result['exit'] == 0 and Path(record).exists():
        data = json.loads(Path(record).read_text())
        for row in data.get('left', {}).get('symbols', []):
            if row.get('name') == symbol:
                similarity = float(row.get('match_percent', 0.0))
                break
        if similarity is None:
            similarity = 0.0
    return result, similarity


TYPE_ALIASES = {
    'u8': 'uchar', 'bool8': 'uchar', 'byte': 'uchar', 'uchar': 'uchar', 'undefined1': 'uchar',
    's8': 'schar', 'sbyte': 'schar', 'u16': 'ushort', 'ushort': 'ushort', 'bool16': 'ushort',
    'undefined2': 'ushort', 'word': 'ushort', 's16': 'short', 'u32': 'uint', 'uint': 'uint',
    'bool32': 'uint', 'undefined4': 'uint', 'dword': 'uint', 's32': 'int', 'M2C_UNK': 'int',
    'M2C_UNK32': 'int', 'M2C_UNK16': 'short', 'M2C_UNK8': 'schar', 'undefined': 'uchar',
}
MULTI_WORD = [('unsigned char', 'uchar'), ('signed char', 'schar'), ('unsigned short', 'ushort'),
              ('unsigned int', 'uint'), ('unsigned long', 'uint'), ('long long', 'longlong')]
KEYWORDS = {'if', 'else', 'while', 'do', 'for', 'switch', 'case', 'default', 'break', 'continue',
            'return', 'goto', 'sizeof', 'void', 'char', 'short', 'int', 'long', 'const', 'volatile',
            'static', 'struct', 'union', 'enum', 'unsigned', 'signed', 'uchar', 'schar', 'ushort',
            'uint', 'longlong'}
TOKEN = re.compile(r'0[xX][0-9a-fA-F]+[uUlL]*|\d+[uUlL]*|[A-Za-z_]\w*|\'(?:\\.|[^\'])*\'|'
                   r'"(?:\\.|[^"])*"|<<=|>>=|->|\+\+|--|<<|>>|<=|>=|==|!=|&&|\|\||[-+*/%&|^!~<>=]=?|[^\s\w]')


def function_definition(text, name):
    """The definition of `name` (signature through matching brace), or None."""
    text = re.sub(r'/\*.*?\*/', ' ', text, flags=re.S)
    text = re.sub(r'//[^\n]*', ' ', text)
    text = re.sub(r'^\s*#[^\n]*', ' ', text, flags=re.M)
    for match in re.finditer(r'\b' + re.escape(name) + r'\s*\(', text):
        close = text.find(')', match.end())
        brace = text.find('{', match.end())
        semicolon = text.find(';', match.end())
        if brace == -1 or (semicolon != -1 and semicolon < brace):
            continue
        start = text.rfind('\n', 0, match.start()) + 1
        prefix = text[start:match.start()]
        if not prefix.strip() and start > 0:
            start = text.rfind('\n', 0, start - 1) + 1
        depth, index = 0, brace
        while index < len(text):
            depth += text[index] == '{'
            depth -= text[index] == '}'
            if depth == 0:
                return text[start:index + 1]
            index += 1
        del close
    return None


def tokens(text):
    for long, short in MULTI_WORD:
        text = re.sub(r'\b' + long + r'\b', short, text)
    out = []
    for token in TOKEN.findall(text):
        if token[0].isdigit():
            digits = re.sub(r'[uUlL]+$', '', token)
            out.append(str(int(digits, 16) if digits.lower().startswith('0x') else int(digits)))
        elif token[0].isalpha() or token[0] == '_':
            token = TYPE_ALIASES.get(token, token)
            out.append(token if token in KEYWORDS else 'ID')
        else:
            out.append(token)
    return out


def levenshtein(a, b):
    if len(a) < len(b):
        a, b = b, a
    previous = list(range(len(b) + 1))
    for i, x in enumerate(a, 1):
        current = [i]
        for j, y in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (x != y)))
        previous = current
    return previous[-1]


# ---------------------------------------------------------------------------
# Candidate producers
# ---------------------------------------------------------------------------

def cli_env():
    env = dict(os.environ)
    env['ROMWRIGHT_NO_IMPORT_CACHE'] = '1'
    env['ROMWRIGHT_NO_FACT_PACK'] = '1'
    return env


def romwright_project(work, layer, binary, elf_functions, prototypes, fresh, log):
    project = work / f'project-{layer}'
    record = {'project': str(project), 'binary': str(binary)}
    exists = (project / 'project.sqlite').exists()
    if fresh and exists:
        shutil.rmtree(project)
        exists = False
    if exists:
        listing = run([CLI, 'programs', '--project', project], env=cli_env(), timeout=120)
        exists = listing['exit'] == 0 and PROGRAM in listing['stdout']
        if not exists:
            shutil.rmtree(project)
    if exists:
        record['import'] = {'reused': True}
    else:
        log(f'  importing {binary.name} into {project} (one import, reused afterwards)')
        result = run([CLI, 'import', binary, '--name', PROGRAM, '--project', project],
                     env=cli_env(), timeout=3600)
        record['import'] = {k: result[k] for k in ('argv', 'exit', 'seconds')}
        record['import']['stderr_tail'] = result['stderr'][-2000:]
        if result['exit'] != 0:
            raise HarnessError(f'romwright import of {binary} failed: {result["stderr"][-500:]}')
    names = []
    for name, rows in sorted(elf_functions.items()):
        addresses = {address for address, _ in rows}
        if len(addresses) == 1 and re.fullmatch(r'[A-Za-z_]\w*', name):
            address = addresses.pop()
            if 0x08000000 <= address < 0x0a000000:
                names.append({'function': f'{address:x}', 'name': name})
    names_path = work / f'{layer}-names.json'
    names_path.write_text(json.dumps(names))
    result = run([CLI, 'assert-names', PROGRAM, names_path, '--project', project], env=cli_env())
    record['assert_names'] = {'exit': result['exit'], 'stdout': result['stdout'].strip(),
                              'stderr': result['stderr'][-500:], 'supplied': len(names)}
    rows = []
    for name, signature in sorted(prototypes.items()):
        addresses = {address for address, _ in elf_functions.get(name, [])}
        if len(addresses) == 1:
            rows.append({'function': f'{addresses.pop():x}', 'signature': signature})
    protos_path = work / f'{layer}-prototypes.json'
    protos_path.write_text(json.dumps(rows, indent=1))
    result = run([CLI, 'assert-prototypes', PROGRAM, protos_path, '--source',
                  'm22-001 context.h (public pokeemerald declarations)', '--project', project], env=cli_env())
    record['assert_prototypes'] = {'exit': result['exit'], 'stdout': result['stdout'].strip(),
                                   'stderr': result['stderr'][-500:], 'supplied': len(rows)}
    return project, record


def romwright_export(project, binary, address, outdir):
    if outdir.exists():
        shutil.rmtree(outdir)
    outdir.mkdir(parents=True)
    result = run([CLI, 'export-c', binary, PROGRAM, outdir, '--address', f'{address:x}',
                  '--project', project], env=cli_env(), timeout=600)
    files = sorted(outdir.glob('*.c'))
    text = '\n'.join(f.read_text(errors='replace') for f in files) if files else None
    report = None
    try:
        report = json.loads(result['stdout'])
    except (json.JSONDecodeError, ValueError):
        pass
    return text, {'argv': result['argv'], 'exit': result['exit'], 'seconds': result['seconds'],
                  'stderr': result['stderr'][-2000:], 'report': report,
                  'files': [str(f) for f in files]}


def m2c_candidate(asm_path, name, context_path):
    result = run([sys.executable, M2C, '-t', 'gba-gcc-c', '--valid-syntax', '--no-cache',
                  '--context', context_path, '-f', name, asm_path], timeout=300)
    text = result['stdout'] if result['exit'] == 0 and result['stdout'].strip() else None
    return text, {'argv': result['argv'], 'exit': result['exit'], 'seconds': result['seconds'],
                  'stderr': result['stderr'][-2000:]}


def stock_candidate(name, outdir):
    source = STOCK / name / f'{name}.c'
    if not source.exists():
        return None, {'available': False, 'reason': 'no prior stock-header-export output; Ghidra not re-run'}
    header = STOCK / name / f'{name}.h'
    outdir.mkdir(parents=True, exist_ok=True)
    if header.exists():
        shutil.copy(header, outdir / header.name)
    return source.read_text(errors='replace'), {'available': True, 'source': str(source)}


def score(layer_dir, name, candidate, context_text, target_object):
    """Compile/objdiff the candidate in both TU wrappings."""
    variants = {}
    for variant in ('context', 'standalone'):
        vdir = layer_dir / variant
        vdir.mkdir(parents=True, exist_ok=True)
        for extra in layer_dir.glob('*.h'):
            shutil.copy(extra, vdir / extra.name)
        entry = {'compile_exit': None, 'similarity': 0.0, 'error': None}
        if candidate is None:
            entry['error'] = 'no candidate'
            variants[variant] = entry
            continue
        source = vdir / f'{name}.c'
        if variant == 'context':
            (vdir / 'context.h').write_text(context_text)
            source.write_text('#include "context.h"\n' + candidate)
        else:
            source.write_text(candidate)
        output = vdir / f'{name}.o'
        if output.exists():
            output.unlink()
        compiled = compile_candidate(source, output)
        entry['compile_exit'] = compiled['exit']
        if compiled['exit'] != 0:
            entry['error'] = (compiled['stderr'] + compiled['stdout'])[-3000:]
            variants[variant] = entry
            continue
        diff, similarity = objdiff(target_object, output, name, vdir / 'objdiff.json')
        entry['objdiff_exit'] = diff['exit']
        entry['objdiff_record'] = str(vdir / 'objdiff.json')
        if similarity is None:
            entry['error'] = 'objdiff failed: ' + diff['stderr'][-1000:]
            similarity = 0.0
        entry['similarity'] = similarity
        variants[variant] = entry
    return variants


# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    parser.add_argument('--work', type=Path, default=Path('/home/raikaru/romwright-probes/c-output'))
    parser.add_argument('--report', type=Path, default=None)
    parser.add_argument('--fresh-import', action='store_true',
                        help='re-import even if a project with the program already exists')
    parser.add_argument('--only', default='', help='comma-separated function subset (debugging)')
    args = parser.parse_args()
    work = args.work.resolve()
    report_path = (args.report or work / 'report.json').resolve()
    work.mkdir(parents=True, exist_ok=True)
    quiet = lambda message: print(message, file=sys.stderr, flush=True)  # noqa: E731

    for tool in (ROM, ELF, DRIVER, M2C, M2C_MACROS, AGBCC, AS, OBJDUMP, OBJDIFF, CLI):
        if not Path(tool).exists():
            raise HarnessError(f'missing prerequisite: {tool}')
    selected = [(n, u) for n, u in FUNCTIONS if not args.only or n in args.only.split(',')]

    elf_functions, elf_objects = load_elf_symbols()
    decls = Declarations()

    quiet('extracting reference assembly and checking reassembly parity')
    extracted = []
    functions_report = {}
    for name, unit in selected:
        target_object = OBJ_ROOT / f'{unit}.o'
        fdir = work / 'functions' / name
        fdir.mkdir(parents=True, exist_ok=True)
        asm, refs = extract_asm(target_object, name)
        (fdir / 'target.s').write_text(asm)
        assembled = run([AS, '-mcpu=arm7tdmi', '-o', fdir / 'target.o', fdir / 'target.s'])
        if assembled['exit'] != 0:
            raise HarnessError(f'{name}: reference assembly does not assemble: {assembled["stderr"]}')
        _, parity = objdiff(target_object, fdir / 'target.o', name, fdir / 'parity-objdiff.json')
        if parity != 100.0:
            raise HarnessError(f'{name}: reassembled reference is {parity}% of the original, not 100%')
        addresses = {a for a, _ in elf_functions.get(name, [])}
        if len(addresses) != 1:
            raise HarnessError(f'{name}: ELF address missing or ambiguous')
        address = addresses.pop()
        size = next(s for a, s in elf_functions[name] if a == address)
        extracted.append((name, unit, refs))
        functions_report[name] = {'unit': unit, 'target_object': str(target_object), 'address': f'{address:#x}',
                                  'size': size, 'references': refs, 'asm_parity': parity, 'layers': {}}

    context_text, prototypes, context_notes = build_context(extracted, decls, elf_objects, elf_functions)
    context_path = work / 'context.h'
    context_path.write_text(context_text)

    projects = {}
    for layer, binary in (('romwright', ROM), ('romwright-elf', ELF)):
        quiet(f'preparing {layer} project')
        projects[layer] = romwright_project(work, layer, binary, elf_functions, prototypes,
                                            args.fresh_import, quiet)

    for name, unit, _refs in extracted:
        entry = functions_report[name]
        address = int(entry['address'], 16)
        target_object = Path(entry['target_object'])
        quiet(f'{name}: producing and scoring candidates')
        texts = {}
        for layer in LAYERS:
            ldir = work / 'layers' / layer / name
            if ldir.exists():
                shutil.rmtree(ldir)
            ldir.mkdir(parents=True)
            if layer.startswith('romwright'):
                project, _ = projects[layer]
                binary = ROM if layer == 'romwright' else ELF
                text, produce = romwright_export(project, binary, address, ldir / 'export')
            elif layer == 'm2c':
                text, produce = m2c_candidate(work / 'functions' / name / 'target.s', name, context_path)
            else:
                text, produce = stock_candidate(name, ldir)
            if text is not None:
                (ldir / 'candidate.c').write_text(text)
            texts[layer] = text
            variants = score(ldir, name, text, context_text, target_object)
            entry['layers'][layer] = {'produce': produce, 'candidate': str(ldir / 'candidate.c') if text else None,
                                      'variants': variants,
                                      'compile_exit': variants['context']['compile_exit'],
                                      'similarity': variants['context']['similarity']}
        reference = texts.get('m2c') and function_definition(texts['m2c'], name)
        reference_tokens = tokens(reference) if reference else None
        for layer in LAYERS:
            layer_entry = entry['layers'][layer]
            definition = texts[layer] and function_definition(texts[layer], name)
            if reference_tokens is None or not definition:
                layer_entry['token_distance_to_m2c'] = None
                continue
            own = tokens(definition)
            distance = levenshtein(own, reference_tokens)
            layer_entry['token_distance_to_m2c'] = {
                'distance': distance, 'tokens': len(own), 'm2c_tokens': len(reference_tokens),
                'normalized': round(distance / max(len(own), len(reference_tokens), 1), 4)}

    summary = {}
    for layer in LAYERS:
        rows = [f['layers'][layer] for f in functions_report.values()]
        available = [r for r in rows if r['candidate'] is not None or layer != 'stock']
        best = [max(r['variants']['context']['similarity'], r['variants']['standalone']['similarity'])
                for r in available]
        summary[layer] = {
            'functions': len(available),
            'mean_similarity': round(sum(r['similarity'] for r in available) / len(available), 3) if available else None,
            'compiled': sum(r['compile_exit'] == 0 for r in available),
            'exact': sum(r['similarity'] >= 100.0 for r in available),
            'mean_similarity_best_wrapping': round(sum(best) / len(best), 3) if best else None,
            'compiled_any_wrapping': sum(any(v['compile_exit'] == 0 for v in r['variants'].values())
                                         for r in available),
        }
    report = {
        'schema': 'm22-001-c-output/1',
        'generated': time.strftime('%Y-%m-%dT%H:%M:%S%z'),
        'selection_rule': 'fixed named list FUNCTIONS in tests/m22-001_c_output.py',
        'headline': 'context variant: #include "context.h" + candidate; similarity = objdiff target-side '
                    'symbol match_percent; missing/failed candidates score 0',
        'toolchain': {'driver': str(DRIVER), 'agbcc': str(AGBCC), 'as': str(AS), 'objdiff': str(OBJDIFF),
                      'm2c': str(M2C), 'romwright_cli': str(CLI)},
        'context': {'path': str(context_path), 'notes': context_notes, 'asserted_prototypes': prototypes},
        'romwright_projects': {k: v[1] for k, v in projects.items()},
        'summary': summary,
        'functions': functions_report,
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=1))
    parts = []
    for layer in LAYERS:
        s = summary[layer]
        parts.append(f'{layer}: mean {s["mean_similarity"]}% compiled {s["compiled"]}/{s["functions"]} '
                     f'100% {s["exact"]}')
    print('m22-001 ' + ' | '.join(parts) + f' | report {report_path}')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except HarnessError as error:
        print(f'm22-001 harness error: {error}', file=sys.stderr)
        sys.exit(2)
