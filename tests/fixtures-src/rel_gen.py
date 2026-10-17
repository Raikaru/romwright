#!/usr/bin/env python3
"""GameCube REL fixture generator (real format: version 2 header).

Two entry points:

* `build_rel(...)` -- a general builder. Sections, relocation streams and
  imports are described as data and laid out the way decomp-toolkit's
  `rel make` lays them out (header, section table, section bytes,
  relocation streams, import table). Used by gcm_gen.py for the disc fixture
  and checked against `dtk rel info` when a `dtk` binary is available.
* `main()` -- the m20-014 fixture: a two-section module (section 0 executable
  `.text`, section 1 data) with two imports. Ground truth for the gate is this
  file's construction:

  - section 0 executes at synthetic base + 0, section 1 does not, at
    base + 0x10000000 (standalone placement, no DOL beside it);
  - the import table carries module 0 (the DOL) and module 1 (itself);
  - after relocation the text is
    `bl 0x80003100 ; lis r3,hi(data+4) ; addi r3,r3,lo(data+4) ; blr`
    and data word 0 holds the address of text+0xc.

Usage: rel_gen.py <out> [--bad-offset]
`--bad-offset` points section 0 past EOF: recognised as REL, refused
at import with "REL section outside file".
"""

import struct
import sys

# Relocation types (ELF PowerPC numbering plus the Dolphin extensions).
R_PPC_ADDR32 = 1
R_PPC_ADDR16_LO = 4
R_PPC_ADDR16_HI = 5
R_PPC_ADDR16_HA = 6
R_PPC_REL24 = 10
R_PPC_REL14 = 11
R_DOLPHIN_NOP = 201
R_DOLPHIN_SECTION = 202
R_DOLPHIN_END = 203

SYNTHETIC_BASE = 0x8000_0000
WINDOW = 0x1000_0000


def record(offset, kind, section, addend):
    return struct.pack('>HBBI', offset, kind, section, addend)


def stream(relocs):
    """Encode `relocs` -- (source_section, place, kind, target_section,
    addend), already sorted by section then place -- as one import's
    relocation stream: SECTION switches, NOP-padded deltas, END."""
    out = b''
    section, at = None, 0
    for source, place, kind, target, addend in relocs:
        if source != section:
            out += record(0, R_DOLPHIN_SECTION, source, 0)
            section, at = source, 0
        delta = place - at
        assert delta >= 0, 'relocations must be sorted by place'
        while delta > 0xFFFF:
            out += record(0xFFFF, R_DOLPHIN_NOP, 0, 0)
            delta -= 0xFFFF
        out += record(delta, kind, target, addend)
        at = place
    return out + record(0, R_DOLPHIN_END, 0, 0)


def build_rel(module_id, sections, imports, prolog=None, bss_size=0):
    """A version-2 REL.

    sections: list of (bytes | None, exec); `None` bytes with a size in
      `bss_size` is the bss, `(b'', False)` an empty section.
    imports: list of (target_module, relocs) for `stream`.
    prolog: (section, offset) or None.
    """
    header_size = 0x48
    table = header_size
    cursor = table + 8 * len(sections)
    entries = []
    blobs = []
    for data, executable in sections:
        if data is None:  # bss
            entries.append((0, bss_size))
        elif not data:
            entries.append((0, 0))
        else:
            cursor = (cursor + 3) & ~3
            entries.append((cursor | (1 if executable else 0), len(data)))
            blobs.append((cursor, data))
            cursor += len(data)
    cursor = (cursor + 3) & ~3
    rel_off = cursor
    streams = b''
    imp_entries = []
    for target, relocs in imports:
        imp_entries.append((target, rel_off + len(streams)))
        streams += stream(relocs)
    imp_off = rel_off + len(streams)
    prolog_section, prolog_offset = prolog or (0, 0)
    header = struct.pack('>12I', module_id, 0, 0, len(sections), table, 0, 0, 2,
                         bss_size, rel_off, imp_off, 8 * len(imp_entries))
    header += struct.pack('>4B', prolog_section, 0, 0, 0)
    header += struct.pack('>5I', prolog_offset, 0, 0, 4, 8)
    assert len(header) == header_size, len(header)
    out = bytearray(header)
    for offset, size in entries:
        out += struct.pack('>2I', offset & 0xFFFFFFFF, size)
    for offset, data in blobs:
        out += b'\0' * (offset - len(out))
        out += data
    out += b'\0' * (rel_off - len(out))
    out += streams
    for target, offset in imp_entries:
        out += struct.pack('>2I', target, offset)
    return bytes(out)


# m20-014 fixture -------------------------------------------------------

TEXT_WORDS = (0x48000001, 0x3C600000, 0x38630000, 0x4E800020)
DOL_TARGET = 0x8000_3100


def fixture(bad=False):
    text = b''.join(struct.pack('>I', word) for word in TEXT_WORDS)
    data = struct.pack('>2I', 0, 0xDEADBEEF)
    to_dol = [(0, 0, R_PPC_REL24, 0, DOL_TARGET)]
    to_self = [
        (0, 6, R_PPC_ADDR16_HA, 1, 4),   # halfword of `lis`
        (0, 10, R_PPC_ADDR16_LO, 1, 4),  # halfword of `addi`
        (1, 0, R_PPC_ADDR32, 0, 0xC),    # data word 0 -> text+0xc
    ]
    image = bytearray(build_rel(1, [(text, True), (data, False)],
                                [(0, to_dol), (1, to_self)]))
    if bad:
        # Section 0's offset: past the end of the file.
        image[0x48:0x4C] = struct.pack('>I', 0xFFFFFFF8)
    return bytes(image), len(text), len(data)


def main() -> int:
    out, bad = sys.argv[1], len(sys.argv) > 2 and sys.argv[2] == '--bad-offset'
    image, text_size, data_size = fixture(bad)
    with open(out, 'wb') as handle:
        handle.write(image)
    print(f'rel sections=2 text={text_size} data={data_size} bad={bad}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
