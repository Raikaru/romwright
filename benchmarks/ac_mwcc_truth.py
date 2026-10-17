#!/usr/bin/env python3
"""MWCC (GameCube) truth for Animal Crossing's game code, from ac-decomp (CC0).

Names, sizes and REL-relative offsets come from the decomp's dtk
`config/GAFE01_00/foresta/symbols.txt`; the C prototype of each function is
read from the decomp's own `src/**/*.c` and `*.c_inc` definitions (the
sources are matching, so a prototype is what the compiler saw). A symbol that
two sources define (two file-statics of one name) is dropped: the name does
not identify one function.

Each row also records which MWCC register-save helpers the function calls
(`_savegpr_N`, `_savefpr_N`, ...). The helpers are DOL code
(`config/GAFE01_00/symbols.txt` gives each entry's address), and the call
sites are read from an import's own `xrefs` (a `bl` operand is the same
bytes in every tool; the REL's is only meaningful after relocation).

Subcommands: `truth` (build the JSON), `sample` (fixed samples).
"""
import argparse
import json
from pathlib import Path
import random
import re
import sqlite3
import sys

SYMBOL = re.compile(r'^(?P<name>\S+) = \.(?P<section>[\w.]+):0x(?P<offset>[0-9A-Fa-f]+);(?: //(?P<attrs>.*))?$')
SCALARS = {'u8', 's8', 'u16', 's16', 'u32', 's32', 'u64', 's64', 'f32', 'f64', 'int', 'char', 'short', 'long',
           'unsigned', 'signed', 'float', 'double', 'BOOL', 'bool', 'size_t', 'void', 'u_char', 'u_short', 'u_int',
           'u_long', 'wchar_t', 'uintptr_t', 'intptr_t', 'ptrdiff_t', 'int8_t', 'int16_t', 'int32_t', 'int64_t',
           'uint8_t', 'uint16_t', 'uint32_t', 'uint64_t', 'f32_t', 'f64_t'}


def strip(text):
    """Comments, preprocessor lines (with continuations) and string bodies removed."""
    text = re.sub(r'/\*.*?\*/', ' ', text, flags=re.S)
    text = re.sub(r'//[^\n]*', ' ', text)
    out, continued = [], False
    for line in text.split('\n'):
        if continued or line.lstrip().startswith('#'):
            continued = line.rstrip().endswith('\\')
            out.append('')
            continue
        out.append(line)
    return '\n'.join(out)


def top_level(text):
    """(header, body) per function definition at brace depth 0; also typedef bodies."""
    defs, depth, stmt, current, i, n = [], 0, 0, None, 0, len(text)
    while i < n:
        c = text[i]
        if c in '"\'':
            quote, i = c, i + 1
            while i < n and text[i] != quote:
                i += 2 if text[i] == '\\' else 1
        elif c == '{':
            if depth == 0:
                header = text[stmt:i].strip()
                current = None
                if header.endswith(')') and '=' not in header.split('(')[0] and not header.startswith('typedef'):
                    current = (header, i)
                elif header.startswith('typedef'):
                    current = ('typedef:' + header, i)
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                stmt = i + 1
                if current and current[0].startswith('typedef:'):
                    # `typedef struct {...} name;` -- the name follows the brace
                    tail = re.match(r'\s*([^;{]*);', text[i + 1:])
                    if tail:
                        defs.append((current[0] + ' }' + tail[1], text[current[1]:i + 1]))
                    current = None
                elif current:
                    defs.append((current[0], text[current[1]:i + 1]))
                    current = None
        elif c == ';' and depth == 0:
            stmt = i + 1
        i += 1
    return defs


def typedefs(root):
    """name -> 'int' | 'float' | 'double' | 'agg' from every header under include/ and src/."""
    kinds = {}
    for path in list(root.glob('include/**/*.h')) + list(root.glob('src/**/*.h')):
        text = strip(path.read_text(errors='replace'))
        for match in re.finditer(r'typedef\s+(?:unsigned\s+|signed\s+)?(?:long\s+)?(\w+)\s+(\w+)\s*;', text):
            base, name = match[1], match[2]
            if base in ('struct', 'union', 'enum'):
                continue
            kinds.setdefault(name, base)
        for header, _ in top_level(text):
            if header.startswith('typedef:'):
                name = re.search(r'\}\s*\**\s*(\w+)\s*$', header)
                if name and 'enum' in header.split('{')[0]:
                    kinds.setdefault(name[1], 'int')
                elif name:
                    kinds.setdefault(name[1], 'agg')
    return kinds


def classify(text, kinds):
    """'f4' | 'f8' | 'i4' | 'i8' | 'agg' for one parameter declaration."""
    text = re.sub(r'\b(const|volatile|register|struct|union|enum)\b', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    if '*' in text or '[' in text or re.search(r'\(\s*\*', text):
        return 'i4'
    words = [w for w in text.split(' ') if w]
    # the trailing identifier is the parameter name when a type precedes it
    candidates = [words[:cut] for cut in range(len(words), 0, -1)]
    for head in candidates:
        base = head[-1]
        seen = 0
        while base in kinds and seen < 6:
            base = kinds[base]
            seen += 1
        joined = ' '.join(head)
        if base in ('f32', 'float') or joined == 'f32':
            return 'f4'
        if base in ('f64', 'double'):
            return 'f8'
        if base == 'agg':
            return 'agg'
        if base in ('s64', 'u64', 'longlong') or 'long long' in joined or joined.startswith('s64') or joined.startswith('u64'):
            return 'i8'
        if base in SCALARS:
            return 'i4'
    return 'unknown'


def split_params(text):
    depth, parts, current = 0, [], ''
    for char in text:
        if char in '([':
            depth += 1
        elif char in ')]':
            depth -= 1
        if char == ',' and depth == 0:
            parts.append(current)
            current = ''
        else:
            current += char
    if current.strip():
        parts.append(current)
    return [p.strip() for p in parts]


def load_symbols(path, section='text'):
    rows = {}
    for line in Path(path).read_text(errors='replace').splitlines():
        match = SYMBOL.match(line.strip())
        if not match or match['section'] != section:
            continue
        attrs = match['attrs'] or ''
        if 'type:function' not in attrs:
            continue
        size = re.search(r'size:0x([0-9A-Fa-f]+)', attrs)
        rows.setdefault(match['name'], []).append(
            dict(offset=int(match['offset'], 16), size=int(size[1], 16) if size else 0,
                 static='scope:local' in attrs))
    return rows


def dol_sleds(path):
    """Sled entry address -> helper name for every `_savegpr_N`-style label."""
    sleds = {}
    for line in Path(path).read_text(errors='replace').splitlines():
        match = SYMBOL.match(line.strip())
        if match and re.fullmatch(r'_(save|rest)[gf]pr_\d+', match['name']):
            sleds[int(match['offset'], 16)] = match['name']
    return sleds


def build(decomp, project, program):
    symbols = load_symbols(decomp / 'config/GAFE01_00/foresta/symbols.txt')
    kinds = typedefs(decomp)
    definitions = {}
    for path in sorted(list((decomp / 'src').rglob('*.c')) + list((decomp / 'src').rglob('*.c_inc'))):
        for header, _ in top_level(strip(path.read_text(errors='replace'))):
            if header.startswith('typedef:'):
                continue
            header = re.sub(r'\s+', ' ', header)
            match = re.match(r'^(.*?)([A-Za-z_]\w*)\s*\((.*)\)$', header)
            if match:
                definitions.setdefault(match[2], []).append(dict(
                    file=str(path.relative_to(decomp)), ret=match[1].strip(), params=match[3].strip()))
    sleds = dol_sleds(decomp / 'config/GAFE01_00/symbols.txt')
    db = sqlite3.connect(f'file:{project}/project.sqlite?mode=ro', uri=True)
    pid = db.execute('SELECT id FROM programs WHERE name = ?', (program,)).fetchone()[0]
    rel_text = next(int(start, 16) for name, start, size, perm in db.execute(
        'SELECT name, start, size, permissions FROM memory_regions WHERE program_id = ?', (pid,))
        if name.endswith('rel1.sec1') and 'x' in perm)
    calls = {}
    for src, dst in db.execute('SELECT src, dst FROM xrefs WHERE program_id = ? AND kind IN ("CALL", "call", "UNCONDITIONAL_CALL")', (pid,)):
        target = int(dst.split(':')[-1], 16)
        if target in sleds:
            calls.setdefault(int(src.split(':')[-1], 16), set()).add(sleds[target])
    if not calls:
        kinds_seen = db.execute('SELECT DISTINCT kind FROM xrefs WHERE program_id = ?', (pid,)).fetchall()
        raise SystemExit(f'no sled call xrefs found; xref kinds: {kinds_seen}')
    rows, skipped = [], dict(ambiguous=0, no_source=0, aggregate=0, unknown=0)
    for name, entries in sorted(symbols.items()):
        if len(entries) != 1 or len(definitions.get(name, [])) > 1:
            skipped['ambiguous'] += 1
            continue
        if name not in definitions:
            skipped['no_source'] += 1
            continue
        entry, definition = entries[0], definitions[name][0]
        params = definition['params']
        classes = [] if params in ('', 'void') else [classify(p, kinds) for p in split_params(params) if p != '...']
        if 'agg' in classes:
            skipped['aggregate'] += 1
            continue
        if 'unknown' in classes:
            skipped['unknown'] += 1
            continue
        low, high = rel_text + entry['offset'], rel_text + entry['offset'] + entry['size']
        helpers = sorted({h for site, hs in calls.items() if low <= site < high for h in hs})
        rows.append(dict(name=name, offset=entry['offset'], size=entry['size'], static=entry['static'],
                         file=definition['file'], ret=definition['ret'], params=params, classes=classes,
                         helpers=helpers))
    return dict(functions=len(symbols), with_source=len(rows), skipped=skipped, rel_text=rel_text, rows=rows)


def sample(truth, seed, size, subset):
    rows = truth['rows']
    if subset == 'sled26':
        # calls _savegpr_26 or deeper: the long callee-saved runs
        rows = [r for r in rows if any(re.fullmatch(r'_savegpr_(1[4-9]|2[0-6])', h) for h in r['helpers'])]
    elif subset == 'fpr':
        rows = [r for r in rows if any('fpr' in h for h in r['helpers'])]
    rows = sorted(rows, key=lambda r: r['offset'])
    return sorted(random.Random(seed).sample(rows, min(size, len(rows))), key=lambda r: r['offset'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    t = sub.add_parser('truth')
    t.add_argument('--decomp', type=Path, required=True)
    t.add_argument('--project', type=Path, required=True)
    t.add_argument('--program', default='gc')
    t.add_argument('--out', type=Path, required=True)
    s = sub.add_parser('sample')
    s.add_argument('--truth', type=Path, required=True)
    s.add_argument('--seed', type=int, default=23)
    s.add_argument('--size', type=int, default=200)
    s.add_argument('--subset', choices=('all', 'sled26', 'fpr'), default='all')
    s.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if args.command == 'truth':
        truth = build(args.decomp, args.project, args.program)
        args.out.write_text(json.dumps(truth, indent=1))
        print({k: v for k, v in truth.items() if k != 'rows'})
    else:
        truth = json.loads(args.truth.read_text())
        args.out.write_text(json.dumps(sample(truth, args.seed, args.size, args.subset), indent=1))


if __name__ == '__main__':
    main()
