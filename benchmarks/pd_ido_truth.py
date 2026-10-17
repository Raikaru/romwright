#!/usr/bin/env python3
"""IDO o32 truth for the Perfect Dark NTSC-final game segment (P2.4).

Truth is the public decomp (`n64decomp/perfect_dark`, MIT, cloned beside the
ROM, never committed): function names and C prototypes from its sources, and
addresses from the ROM's own bytes. The decomp ships no symbol map, so
addresses are *derived*, not read:

1. The game segment is inflated from the ROM: a table of 32-bit offsets, one
   Rare-zlib chunk (16-bit magic 0x1173, 3 header bytes, raw deflate) per
   0x1000 output bytes. Written from those format facts, not from the decomp's
   `tools/extract`. It loads at 0x7f000000 (`ld/pd.ld`).
2. Binary function extents are walked from the segment's first byte: a
   function ends at the first `jr ra` + delay slot that no branch (or jump
   table entry, bounded by its `sltiu`) reaches past, or at the next `jal`
   target. Nothing from the decompilers under test is used.
3. Source functions are listed in link order (`ld/gamefiles.*.inc`), from the
   preprocessed sources (`VERSION=2`, the ntsc-final build), IDO emitting a
   file's functions in source order.
4. The exact `func0fXXXXXX` names are anchors (their name is their address).
   Between two consecutive anchors the mapping is source order == address
   order only when both sides count the same number of functions; unequal
   intervals (a function nothing calls and the walk merged, or a static the
   compiler dropped) are discarded whole.
5. Every kept function is checked by its calls: each callee whose address is
   known must be a `jal` target inside the function. Zero violations are
   reported (a shifted mapping fails this at once).

Subcommands: `extract` (ROM -> game.bin), `truth` (build the JSON),
`sample` (fixed 200-function sample + the float subset).
"""
import argparse
import json
import os
from pathlib import Path
import random
import re
import struct
import subprocess
import sys
import zlib

BASE = 0x7F000000
TEXT_PAD = 0x7F1A78C0  # first byte past the last function in the ntsc-final game segment


# ---- ROM -> game segment ---------------------------------------------------

GAME_SEGMENT_ROM = 0x4FC40  # where the ntsc-final game segment starts in the ROM
CHUNK_MAGIC = 0x1173
CHUNK_BYTES = 0x1000


def inflate_chunk(rom, at):
    """One Rare zlib chunk at `at`: a 16-bit magic, three bytes of header, then
    a raw deflate stream (no zlib wrapper). Returns the bytes it inflates to."""
    if int.from_bytes(rom[at:at + 2], 'big') != CHUNK_MAGIC:
        raise ValueError(f'no Rare zlib chunk at {at:#x}')
    return zlib.decompressobj(wbits=-15).decompress(rom[at + 5:at + 5 + 2 * CHUNK_BYTES])


def extract_game(rom):
    """The game segment, inflated. The ROM holds a big-endian table of 32-bit
    offsets from the segment start; an entry points two bytes ahead of the
    chunk's magic. Every chunk inflates to 0x1000 bytes except the last, and a
    table entry whose chunk has no magic ends the table."""
    out = bytearray()
    for slot in range(0, len(rom) - GAME_SEGMENT_ROM, 4):
        entry = int.from_bytes(rom[GAME_SEGMENT_ROM + slot:GAME_SEGMENT_ROM + slot + 4], 'big')
        at = GAME_SEGMENT_ROM + entry + 2
        if int.from_bytes(rom[at:at + 2], 'big') != CHUNK_MAGIC:
            break
        chunk = inflate_chunk(rom, at)
        out += chunk
        if len(chunk) < CHUNK_BYTES:
            break
    return bytes(out)


# ---- source side -------------------------------------------------------------

STUBS_NAME = '.pd-stubs'


def preprocess(root, path, stubs):
    """cpp output; generated headers the build makes from assets are stubbed empty."""
    stubs.mkdir(parents=True, exist_ok=True)
    for _ in range(800):
        command = ['gcc', '-E', '-P', '-DVERSION=2', '-DMATCHING=1', '-DPAL=0', '-DPIRACYCHECKS=1',
                   '-DROM_SIZE=32', '-D_LANGUAGE_C', '-D_MIPSEB', f'-I{root}/include',
                   f'-I{root}/include/PR', f'-I{root}/src/include', f'-I{stubs}', '-w', str(path)]
        result = subprocess.run(command, capture_output=True, text=True)
        missing = re.search(r'fatal error: (\S+): No such file', result.stderr)
        if not missing:
            return result.stdout
        target = stubs / missing[1]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.touch()
    raise RuntimeError(result.stderr[:500])


def top_level_functions(text):
    """(header, body) for each function definition at brace depth 0."""
    out = []
    depth = 0
    stmt = 0
    current = None
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c in '"\'':
            quote = c
            i += 1
            while i < n and text[i] != quote:
                i += 2 if text[i] == '\\' else 1
        elif c == '{':
            if depth == 0:
                header = text[stmt:i].strip()
                current = None
                if header.endswith(')') and '=' not in header.split('(')[0] and not header.startswith('typedef'):
                    current = (header, i)
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                stmt = i + 1
                if current:
                    out.append((current[0], text[current[1]:i + 1]))
                    current = None
        elif c == ';' and depth == 0:
            stmt = i + 1
        i += 1
    return out


def parse_header(header):
    header = re.sub(r'\s+', ' ', header)
    match = re.match(r'^(.*?)([A-Za-z_]\w*)\s*\((.*)\)$', header)
    if not match:
        return None
    return dict(name=match[2], ret=match[1].strip(), params=match[3].strip(),
                static=bool(re.search(r'\bstatic\b', match[1])))


KEYWORDS = set('if while for switch return sizeof else do case default goto break continue'.split())


def switches(body):
    """Case-label count of each switch statement (nested switches counted apart)."""
    results = []
    for match in re.finditer(r'\bswitch\s*\(', body):
        i = body.index('{', match.end())
        # skip the controlling expression's parentheses first
        depth_paren = 1
        j = match.end()
        while depth_paren:
            depth_paren += {'(': 1, ')': -1}.get(body[j], 0)
            j += 1
        i = body.index('{', j)
        depth = 0
        cases = default = 0
        k = i
        stack_nested = []
        while k < len(body):
            c = body[k]
            if c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0:
                    break
            k += 1
        inner = body[i + 1:k]
        # remove nested switch bodies from the count
        while True:
            nested = re.search(r'\bswitch\s*\(', inner)
            if not nested:
                break
            p = nested.end()
            depth_paren = 1
            while depth_paren:
                depth_paren += {'(': 1, ')': -1}.get(inner[p], 0)
                p += 1
            q = inner.index('{', p)
            depth = 0
            while True:
                depth += {'{': 1, '}': -1}.get(inner[q], 0)
                q += 1
                if depth == 0:
                    break
            inner = inner[:nested.start()] + inner[q:]
        cases = len(re.findall(r'\bcase\b', inner))
        default = len(re.findall(r'\bdefault\s*:', inner))
        results.append(dict(cases=cases, default=default))
    return results


def source_functions(root, path, stubs):
    out = []
    for header, body in top_level_functions(preprocess(root, path, stubs)):
        parsed = parse_header(header)
        if not parsed:
            continue
        parsed['calls'] = [c for c in re.findall(r'\b([A-Za-z_]\w*)\s*\(', body) if c not in KEYWORDS]
        parsed['switches'] = switches(body)
        out.append(parsed)
    return out


# ---- binary side -------------------------------------------------------------

class Image:
    def __init__(self, data, base):
        self.data, self.base = data, base

    def word(self, address):
        offset = address - self.base
        if offset < 0 or offset + 4 > len(self.data):
            return None
        return struct.unpack('>I', self.data[offset:offset + 4])[0]


def _signed16(value):
    return value - 0x10000 if value & 0x8000 else value


def _branch_target(pc, word):
    op = word >> 26
    regimm = (word >> 16) & 0x1F
    if op in (4, 5, 6, 7, 0x14, 0x15, 0x16, 0x17) or (op == 1 and regimm in (0, 1, 2, 3)) \
            or (op == 0x11 and ((word >> 21) & 0x1F) == 8):
        return pc + 4 + (_signed16(word & 0xFFFF) << 2)
    return None


def _jump_table(image, pc):
    """(table address, entry count, default target) for the `jr rs` at `pc`, or None."""
    rs = (image.word(pc) >> 21) & 0x1F
    load = None
    for back in range(1, 9):
        word = image.word(pc - 4 * back)
        if word is not None and word >> 26 == 0x23 and (word >> 16) & 0x1F == rs:
            load = (pc - 4 * back, word)
            break
    if load is None:
        return None
    high = None
    for back in range(1, 12):
        word = image.word(load[0] - 4 * back)
        if word is not None and word >> 26 == 0xF:
            high = (word & 0xFFFF) << 16
            break
    if high is None:
        return None
    count = default = None
    for back in range(1, 16):
        word = image.word(load[0] - 4 * back)
        if word is not None and word >> 26 == 0xB:  # sltiu
            count = word & 0xFFFF
            guard = (word >> 16) & 0x1F  # the flag register the range check writes
            # the guard branch that leaves the table is the default target
            for ahead in range(1, 5):
                at = load[0] - 4 * back + 4 * ahead
                branch = image.word(at)
                if branch is not None and branch >> 26 in (4, 5, 0x14, 0x15) \
                        and (branch >> 21) & 0x1F == guard and (branch >> 16) & 0x1F == 0:
                    default = at + 4 + (_signed16(branch & 0xFFFF) << 2)
                    break
            break
    return (high + _signed16(load[1] & 0xFFFF)) & 0xFFFFFFFF, count, default


def _walk(image, start, limit, bounds):
    pos = reach = start
    tables = []
    while pos < limit:
        if pos > start and pos in bounds:
            return pos, tables
        word = image.word(pos)
        if word is None:
            return None, tables
        target = _branch_target(pos, word)
        if target is not None and target >= start:
            reach = max(reach, target)
        if word >> 26 == 0 and word & 0x3F == 8:  # jr
            if (word >> 21) & 0x1F == 31:
                if pos + 8 > reach:
                    return pos + 8, tables
            else:
                table = _jump_table(image, pos)
                if table:
                    address, count, default = table
                    row = dict(jr=pos, table=address, entries=count, default=default)
                    tables.append(row)
                    n = 0
                    while count is None or n < count:
                        value = image.word(address + 4 * n)
                        if value is None or not start <= value < start + 0x20000 or value & 3:
                            break
                        reach = max(reach, value)
                        row.setdefault('targets', []).append(value)
                        n += 1
                        if count is None and n > 2000:
                            break
                    # entries that leave the default are the cases a decompiler can show
                    row['cases'] = sum(1 for t in row.get('targets', []) if t != default)
        pos += 4
    return None, tables


def jal_targets(image, low, high, top):
    out = set()
    for address in range(low, high, 4):
        word = image.word(address)
        if word >> 26 == 3:
            out.add(top | ((word & 0x3FFFFFF) << 2))
    return out


def walk_chain(image, start, stop, bounds):
    entries = []
    pos = start
    while pos < stop:
        while pos < stop and image.word(pos) == 0:
            pos += 4
        if pos >= stop:
            break
        end, tables = _walk(image, pos, stop, bounds)
        if end is None:
            break
        entries.append(dict(address=pos, end=end, tables=tables))
        pos = end
    return entries


# ---- assignment --------------------------------------------------------------

def build_truth(root, game, work):
    inc = (root / 'ld/gamefiles.ntsc-final.inc').read_text()
    files = re.findall(r'build/ROMID/(\S+?)\.o \(section\)', inc)
    stubs = work / STUBS_NAME
    flat = []
    for name in files:
        c_path, s_path = root / f'src/{name}.c', root / f'src/{name}.s'
        if c_path.exists():
            for fn in source_functions(root, c_path, stubs):
                flat.append(dict(file=name, kind='c', **fn))
        elif s_path.exists():
            for label in re.findall(r'^(?:glabel|ENTRY|LEAF|NESTED)\s*\(?\s*(\w+)', s_path.read_text(), re.M):
                flat.append(dict(file=name, kind='s', name=label, ret='?', params='?', static=False,
                                 calls=[], switches=[]))
    image = Image(game, BASE)
    bounds = jal_targets(image, BASE, TEXT_PAD + 0x40, 0x70000000)
    entries = walk_chain(image, BASE, TEXT_PAD, bounds)
    index = {entry['address']: i for i, entry in enumerate(entries)}
    anchors = [(0, 0)]
    for i, fn in enumerate(flat):
        match = re.match(r'func0f([0-9a-f]{6})$', fn['name'])
        if match and BASE + int(match[1], 16) in index:
            anchors.append((i, index[BASE + int(match[1], 16)]))
    if len(flat) == len(entries):
        anchors.append((len(flat), len(entries)))
    anchors = sorted(set(anchors))
    assigned = {}
    for (si, ci), (sj, cj) in zip(anchors, anchors[1:]):
        if sj - si == cj - ci:
            for k in range(sj - si):
                assigned[si + k] = entries[ci + k]
    for si, ci in anchors:
        if si < len(flat) and flat[si]['name'].startswith('func0f'):
            assigned[si] = entries[ci]
    by_name = {}
    for i, entry in assigned.items():
        by_name.setdefault(flat[i]['name'], []).append(entry['address'])
    rows, violations = [], 0
    for i, entry in sorted(assigned.items()):
        fn = flat[i]
        jals = jal_targets(image, entry['address'], entry['end'], 0x70000000)
        known = [c for c in set(fn['calls']) if len(by_name.get(c, [])) == 1 and c != fn['name']]
        hit = [c for c in known if by_name[c][0] in jals]
        violations += len(known) - len(hit)
        rows.append(dict(file=fn['file'], kind=fn['kind'], name=fn['name'], address=entry['address'],
                         end=entry['end'], static=fn['static'], ret=fn['ret'], params=fn['params'],
                         switches=fn['switches'], tables=entry['tables'],
                         known_calls=len(known), hit_calls=len(hit)))
    return dict(source_functions=len(flat), binary_functions=len(entries), anchors=len(anchors),
                assigned=len(rows), call_violations=violations, functions=rows)


def sample(truth, seed, size, subset='all'):
    """Named C functions with a usable prototype, sorted, then seeded.

    `all`: any function. `float`: a float/double parameter somewhere (where the
    hole rule bites). `switch`: the binary has a jump table and the source a
    switch with case labels.
    """
    rows = [r for r in truth['functions'] if r['kind'] == 'c' and r['params'] not in ('', '?')]
    if subset == 'float':
        rows = [r for r in rows if re.search(r'\b(f32|f64|float|double)\b', r['params'])]
    elif subset == 'switch':
        rows = [r for r in rows if r['tables'] and sum(s['cases'] for s in r['switches'])]
    rows.sort(key=lambda r: r['address'])
    chosen = random.Random(seed).sample(rows, min(size, len(rows)))
    return sorted(chosen, key=lambda r: r['address'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    e = sub.add_parser('extract')
    e.add_argument('--rom', type=Path, required=True)
    e.add_argument('--out', type=Path, required=True)
    t = sub.add_parser('truth')
    t.add_argument('--decomp', type=Path, required=True, help='n64decomp/perfect_dark checkout')
    t.add_argument('--game', type=Path, required=True, help='game.bin from `extract`')
    t.add_argument('--out', type=Path, required=True)
    s = sub.add_parser('sample')
    s.add_argument('--truth', type=Path, required=True)
    s.add_argument('--seed', type=int, default=24)
    s.add_argument('--size', type=int, default=200)
    s.add_argument('--subset', choices=('all', 'float', 'switch'), default='all')
    s.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if args.command == 'extract':
        args.out.write_bytes(extract_game(args.rom.read_bytes()))
    elif args.command == 'truth':
        truth = build_truth(args.decomp, args.game.read_bytes(), args.out.parent)
        args.out.write_text(json.dumps(truth, indent=1))
        print({k: v for k, v in truth.items() if k != 'functions'})
    else:
        truth = json.loads(args.truth.read_text())
        args.out.write_text(json.dumps(sample(truth, args.seed, args.size, args.subset), indent=1))


if __name__ == '__main__':
    main()
