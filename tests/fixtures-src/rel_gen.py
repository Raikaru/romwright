#!/usr/bin/env python3
"""Minimal GameCube REL fixture generator.

Emits a two-section relocatable module: an executable `.text` with
three PowerPC instructions and a data section, plus empty relocation
and import tables. Ground truth for the m20-014 gate is this file's
construction: section 0 executes at synthetic base + 0, section 1
does not execute at base + 0x10000000.

Usage: rel_gen.py <out> [--bad-offset]
`--bad-offset` points section 0 past EOF: recognised as REL, refused
at import with "REL section outside file".
"""

import struct
import sys

SYNTHETIC_BASE = 0x8000_0000
TEXT = bytes.fromhex('60000000600000004e800020')
DATA = bytes.fromhex('deadbeef')


def main() -> int:
    out, bad = sys.argv[1], len(sys.argv) > 2 and sys.argv[2] == '--bad-offset'
    text_off = 0x58
    data_off = text_off + len(TEXT)
    end = data_off + len(DATA)
    header = struct.pack('>8I', 1, 0, 2, 0x48, 0, 0, 1, 0)
    header += struct.pack('>4I', 0, 0, 0, 0)
    header += struct.pack('>6I', 0, 0, 0, 0, 4, 4)
    assert len(header) == 0x48, len(header)
    section0_off = (1 << 32) - 8 if bad else (text_off | 1)
    sections = struct.pack('>2I', section0_off & 0xFFFFFFFF, len(TEXT))
    sections += struct.pack('>2I', data_off, len(DATA))
    with open(out, 'wb') as handle:
        handle.write(header + sections + TEXT + DATA)
    print(f'rel sections=2 text_off={text_off:#x} bad={bad}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
