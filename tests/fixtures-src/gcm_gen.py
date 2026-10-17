#!/usr/bin/env python3
"""Synthetic GameCube disc: boot DOL + `files/mod.rel.szs`, as raw GCM or CISO.

Ground truth for the m20-016 gate is this file's construction. The disc holds

* `sys/main.dol`: one text section at 0x80003100 of four words
  (`li r3,0; li r4,0; li r5,0; blr`: one function), entry 0x80003100;
* `files/mod.rel.szs`: a real-layout REL (module 1; section 0 null, 1 text,
  2 data, 3 bss of 0x20) compressed with Yaz0 (a small LZ77 encoder below, so
  the decoder meets real back-references, overlapping ones included).

The REL's text, with the DOL placed first and the REL after it at
`align32(align32(0x80003110) + 0x2000)` = 0x80005120 (no stack initializer
in this DOL, so the loader's fallback base):

    0x80005120  _prolog:  bl <DOL 0x80003100> ; blr          (REL24, module 0)
    0x80005128  f1:       lis r3,hi(data) ; addi r3,r3,lo(data) ; blr
                                                  (ADDR16_HA / ADDR16_LO, self)
    0x80005134  f2:       bl _prolog ; blr         (pre-applied, not relocated)

and the data section at 0x80005140 holds three words: &f1 and &f2 (ADDR32,
self; nothing calls them, so only the relocations reach them) and the
DOL's 0x80003100 (ADDR32, module 0). The bss follows at 0x80005160.

Usage: gcm_gen.py <out> [--ciso BLOCK_SIZE]
"""

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rel_gen  # noqa: E402

GC_MAGIC = 0xC2339F3D
DOL_ADDRESS = 0x8000_3100
DOL_WORDS = (0x38600000, 0x38800000, 0x38A00000, 0x4E800020)  # li r3,0; li r4,0; li r5,0; blr
DOL_PATH = 'sys/main.dol'
REL_PATH = 'files/mod.rel.szs'


def yaz0_compress(data: bytes) -> bytes:
    """Greedy Yaz0: longest match in the 4096-byte window, minimum 3."""
    out = bytearray(b'Yaz0' + struct.pack('>I', len(data)) + b'\0' * 8)
    at = 0
    while at < len(data):
        flags, chunk = 0, bytearray()
        for bit in range(8):
            if at >= len(data):
                break
            best, best_from = 0, 0
            for start in range(max(0, at - 0x1000), at):
                length = 0
                while (length < 0x111 and at + length < len(data)
                       and data[start + length] == data[at + length]):
                    length += 1
                if length > best:
                    best, best_from = length, start
            if best >= 3:
                distance = at - best_from - 1
                if best <= 0x11:
                    chunk += bytes([(best - 2) << 4 | distance >> 8, distance & 0xFF])
                else:
                    chunk += bytes([distance >> 8, distance & 0xFF, best - 0x12])
                at += best
            else:
                flags |= 0x80 >> bit
                chunk.append(data[at])
                at += 1
        out.append(flags)
        out += chunk
    return bytes(out)


def dol_bytes() -> bytes:
    text = b''.join(struct.pack('>I', word) for word in DOL_WORDS)
    header = bytearray(0x100)
    struct.pack_into('>I', header, 0x00, 0x100)          # text 0 file offset
    struct.pack_into('>I', header, 0x48, DOL_ADDRESS)    # text 0 address
    struct.pack_into('>I', header, 0x90, len(text))      # text 0 size
    struct.pack_into('>I', header, 0xE0, DOL_ADDRESS)    # entry
    return bytes(header) + text


def rel_bytes() -> bytes:
    words = [
        0x48000001, 0x4E800020,                 # _prolog: bl DOL ; blr
        0x3C600000, 0x38630000, 0x4E800020,     # f1: lis ; addi ; blr
        0x4BFFFFED, 0x4E800020,                 # f2: bl _prolog (-0x14) ; blr
    ]
    text = b''.join(struct.pack('>I', word) for word in words)
    data = b'\0' * 12
    to_dol = [
        (1, 0x00, rel_gen.R_PPC_REL24, 0, DOL_ADDRESS),
        (2, 0x08, rel_gen.R_PPC_ADDR32, 0, DOL_ADDRESS),
    ]
    to_self = [
        (1, 0x0A, rel_gen.R_PPC_ADDR16_HA, 2, 0),
        (1, 0x0E, rel_gen.R_PPC_ADDR16_LO, 2, 0),
        (2, 0x00, rel_gen.R_PPC_ADDR32, 1, 0x08),
        (2, 0x04, rel_gen.R_PPC_ADDR32, 1, 0x14),
    ]
    return rel_gen.build_rel(
        1, [(b'', False), (text, True), (data, False), (None, False)],
        [(0, to_dol), (1, to_self)], prolog=(1, 0), bss_size=0x20)


def fst(entries):
    """FST for `{dir/name: (offset, size)}`; one directory level."""
    dirs = []
    for path in entries:
        if path.split('/')[0] not in dirs:
            dirs.append(path.split('/')[0])
    names = bytearray()

    def name(text):
        at = len(names)
        names.extend(text.encode() + b'\0')
        return at

    rows = [(1, 0, 0, 1 + len(dirs) + len(entries))]
    for directory in dirs:
        row = len(rows)
        rows.append([1, name(directory), 0, 0])
        for path, (offset, size) in entries.items():
            if path.startswith(directory + '/'):
                rows.append((0, name(path.split('/', 1)[1]), offset, size))
        rows[row][3] = len(rows)
    out = b''.join(struct.pack('>I', flag << 24 | name_at) + struct.pack('>II', a, b)
                   for flag, name_at, a, b in rows)
    return out + bytes(names)


def gcm_bytes() -> bytes:
    dol = dol_bytes()
    szs = yaz0_compress(rel_bytes())
    dol_at = 0x2800
    szs_at = (dol_at + len(dol) + 0x1F) & ~0x1F
    table_at = (szs_at + len(szs) + 0x1F) & ~0x1F
    table = fst({DOL_PATH: (dol_at, len(dol)), REL_PATH: (szs_at, len(szs))})
    image = bytearray(table_at + len(table))
    image[0:6] = b'GTSTEA'
    struct.pack_into('>I', image, 0x1C, GC_MAGIC)
    image[0x20:0x2A] = b'RelFixture'
    struct.pack_into('>3I', image, 0x420, dol_at, table_at, len(table))
    image[dol_at:dol_at + len(dol)] = dol
    image[szs_at:szs_at + len(szs)] = szs
    image[table_at:] = table
    return bytes(image)


def ciso_bytes(image: bytes, block: int) -> bytes:
    """CISO: 0x8000 header (magic, LE block size, 1-byte block map), then
    the non-zero blocks back to back; the last block is stored short."""
    header = bytearray(0x8000)
    header[0:4] = b'CISO'
    struct.pack_into('<I', header, 4, block)
    body = bytearray()
    for index in range(0, len(image), block):
        chunk = image[index:index + block]
        if any(chunk):
            header[8 + index // block] = 1
            body += chunk
    return bytes(header + body)


def main() -> int:
    out = sys.argv[1]
    image = gcm_bytes()
    if '--ciso' in sys.argv:
        block = int(sys.argv[sys.argv.index('--ciso') + 1], 0)
        image = ciso_bytes(image, block)
    Path(out).write_bytes(image)
    print(f'gcm bytes={len(image)} ciso={"--ciso" in sys.argv}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
