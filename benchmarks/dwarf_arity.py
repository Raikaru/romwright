#!/usr/bin/env python3
"""Project readelf DWARF output into M2 arity truth; never used by runtime analysis."""
import argparse
from functools import cache
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from gen_corpus import get_load_segments

DIE = re.compile(r'^\s*<(\d+)><([0-9a-fA-F]+)>:\s*Abbrev Number:\s*(\d+)(?:\s*\((DW_TAG_\w+)\))?')
ATTRIBUTE = re.compile(r'^\s*<[0-9a-fA-F]+>\s+(DW_AT_\w+)\s*:\s*(.*)$')
FORM = re.compile(r'^\((?:str\w*|indirect string[^)]*|addr\w*|data\d+|ref\w*|flag\w*|implicit_const|line_strp|sec_offset|sdata|udata)\)\s*:?\s*')
INDEX = re.compile(r'^\((?:offset|index):[^)]*\)\s*:?\s*')


def payload(value):
    value = FORM.sub('', value, count=1)
    return INDEX.sub('', value, count=1).strip()


def integer(value):
    value = payload(value)
    match = re.match(r'(0x[0-9a-fA-F]+|\d+)(?:\s|$)', value)
    if not match:
        raise ValueError(f'unsupported DWARF scalar: {value}')
    return int(match[1], 16 if match[1].startswith('0x') else 10)


def parse_info(text):
    """Return concrete subprograms keyed by link-time entry, not inline instances.

    Count every formal parameter (including artificial ones); neither return
    types nor unspecified/variadic markers add an arity slot. Abstract-origin
    parameters with no concrete location remain part of the DWARF signature.
    """
    nodes = {}
    stack = []
    current = None
    for line in text.splitlines():
        match = DIE.match(line)
        if match:
            depth, offset, abbreviation = int(match[1]), int(match[2], 16), int(match[3])
            del stack[depth:]
            current = None
            if not abbreviation:
                continue
            if depth != len(stack) or not match[4] or offset in nodes:
                raise ValueError(f'ambiguous DWARF DIE nesting/offset: {line}')
            current = dict(tag=match[4], attributes={}, children=[])
            nodes[offset] = current
            if stack:
                nodes[stack[-1]]['children'].append(offset)
            stack.append(offset)
        elif current is not None and (match := ATTRIBUTE.match(line)):
            current['attributes'][match[1]] = match[2]
    if not nodes:
        raise ValueError('no DWARF DIEs found')

    def origin(offset):
        attributes = nodes[offset]['attributes']
        value = attributes.get('DW_AT_abstract_origin', attributes.get('DW_AT_specification'))
        if value is None:
            return None
        match = re.search(r'<(?:0x)?([0-9a-fA-F]+)>', value)
        target = int(match[1], 16) if match else None
        if target not in nodes:
            raise ValueError(f'missing DWARF origin for {offset:#x}: {value}')
        return target

    @cache
    def lineage(offset):
        result = []
        seen = set()
        while offset is not None:
            if offset in seen:
                raise ValueError('cyclic DWARF origin/specification')
            seen.add(offset)
            result.append(offset)
            offset = origin(offset)
        return tuple(result)

    def attribute(offset, name):
        for inherited in lineage(offset):
            value = nodes[inherited]['attributes'].get(name)
            if value is not None:
                return value
        return None

    def parameters(offset):
        inherited = []
        for part in reversed(lineage(offset)):
            own = [child for child in nodes[part]['children']
                   if nodes[child]['tag'] == 'DW_TAG_formal_parameter']
            if not own:
                continue
            if not any(origin(child) is not None for child in own):
                inherited = own
                continue
            positions = {lineage(child)[-1]: index for index, child in enumerate(inherited)}
            for child in own:
                key = lineage(child)[-1]
                if key in positions:
                    inherited[positions[key]] = child
                else:
                    positions[key] = len(inherited)
                    inherited.append(child)
        return inherited

    functions = {}
    for offset, node in nodes.items():
        if node['tag'] != 'DW_TAG_subprogram':
            continue
        # Entry/ranges describe this concrete instance, not its declaration.
        attrs = node['attributes']
        entry = attrs.get('DW_AT_entry_pc', attrs.get('DW_AT_low_pc'))
        if entry is None:
            if 'DW_AT_ranges' in attrs:
                raise ValueError(f'DWARF range-only subprogram requires entry resolution: {offset:#x}')
            continue
        entry = integer(entry)
        inputs = parameters(offset)
        name = attribute(offset, 'DW_AT_name')
        row = dict(die=f'{offset:x}', name=payload(name) if name else None,
            arity=len(inputs), parameters=[dict(die=f'{child:x}', artificial=(
                integer(value) != 0 if (value := attribute(child, 'DW_AT_artificial')) else False))
                for child in inputs], variadic=any(nodes[child]['tag'] == 'DW_TAG_unspecified_parameters'
                    for part in lineage(offset) for child in nodes[part]['children']))
        if entry in functions:
            if functions[entry]['arity'] != row['arity']:
                raise ValueError(f'conflicting DWARF arities at {entry:#x}')
            functions[entry].setdefault('aliases', []).append(row)
        else:
            functions[entry] = row
    return functions


def extract(binary, load_bias=0):
    data = Path(binary).read_bytes()
    executable = [(address, size) for address, size, flags, _, _ in get_load_segments(data) if flags & 1]
    env = dict(os.environ, LC_ALL='C', DEBUGINFOD_URLS='')
    result = subprocess.run(['readelf', '--debug-dump=info', '--wide', str(binary)],
        text=True, capture_output=True, check=True, timeout=60, env=env)
    if result.stderr.strip():
        raise ValueError(f'readelf did not provide a clean truth export: {result.stderr.strip()}')
    functions = {}
    unmapped = []
    for entry, row in parse_info(result.stdout).items():
        if not any(start <= entry < start + size for start, size in executable):
            unmapped.append(dict(link_entry=f'{entry:08x}', **row))
            continue
        functions[f'{entry + load_bias:08x}'] = dict(link_entry=f'{entry:08x}', **row)
    if not functions:
        raise ValueError('no executable DWARF subprogram entries')
    return dict(schema=1, binary_sha256=hashlib.sha256(data).hexdigest(), load_bias=load_bias,
        functions=dict(sorted(functions.items())), unmapped=unmapped)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--load-bias', type=lambda value: int(value, 0), default=0)
    parser.add_argument('--out', type=Path)
    args = parser.parse_args()
    report = extract(args.binary, args.load_bias)
    encoded = json.dumps(report, indent=2) + '\n'
    if args.out:
        args.out.write_text(encoded)
    else:
        print(encoded, end='')


if __name__ == '__main__':
    main()
