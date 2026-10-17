#!/usr/bin/env python3
"""The N64 header checksums: n64crc.py fix IN OUT | check ROM | swap IN OUT ORDER

CRC1 (0x10) and CRC2 (0x14) cover the 1 MiB at 0x1000 and depend on the boot code's
CIC variant (n64brew "CIC-NUS", "ROM header"). A built ROM whose code changed needs
them recomputed; `fix` does that and leaves the ROM alone when the boot code is not a
known CIC, or when the retail header was not consistent to begin with (`check`).
`swap` converts a z64 (big-endian) image to .v64 (byte-swapped) or .n64 (word-swapped).
"""
import struct
import sys
import zlib
from pathlib import Path

M = 0xFFFFFFFF
# CRC32 of the 0xFC0 boot code bytes at 0x40 -> (cic, seed)
CICS = {
    0x6170A4A1: ("6101", 0xF8CA4DDC),
    0x90BB6CB5: ("6102", 0xF8CA4DDC),
    0x0B050EE0: ("6103", 0xA3886759),
    0x98BC2C86: ("6105", 0xDF26F436),
    0xACC8580A: ("6106", 0x1FEA617A),
}


def rol(value, count):
    count &= 31
    return ((value << count) | (value >> (32 - count))) & M if count else value


def compute(rom):
    """`(cic, crc1, crc2)` or None when the boot code is not a known CIC."""
    if len(rom) < 0x101000:
        return None
    cic = CICS.get(zlib.crc32(rom[0x40:0x1000]))
    if cic is None:
        return None
    name, seed = cic
    t1 = t2 = t3 = t4 = t5 = t6 = seed
    words = struct.unpack(">%dI" % (0x100000 // 4), rom[0x1000:0x101000])
    ipl = struct.unpack(">%dI" % (0x1000 // 4), rom[0x0:0x1000])
    for index, d in enumerate(words):
        i = index * 4
        if ((t6 + d) & M) < t6:
            t4 = (t4 + 1) & M
        t6 = (t6 + d) & M
        t3 ^= d
        r = rol(d, d)
        t5 = (t5 + r) & M
        t2 = t2 ^ r if t2 > d else t2 ^ t6 ^ d
        if name == "6105":
            t1 = (t1 + (ipl[(0x40 + 0x710 + (i & 0xFF)) // 4] ^ d)) & M
        else:
            t1 = (t1 + (t5 ^ d)) & M
    if name == "6103":
        crc1, crc2 = ((t6 ^ t4) + t3) & M, ((t5 ^ t2) + t1) & M
    elif name == "6106":
        crc1, crc2 = ((t6 * t4) + t3) & M, ((t5 * t2) + t1) & M
    else:
        crc1, crc2 = t6 ^ t4 ^ t3, t5 ^ t2 ^ t1
    return name, crc1, crc2


def header_crcs(rom):
    return struct.unpack(">II", rom[0x10:0x18])


def check(rom):
    found = compute(rom)
    if found is None:
        return "unknown CIC or ROM shorter than 1 MiB + 0x1000: checksums not reproduced"
    cic, c1, c2 = found
    h1, h2 = header_crcs(rom)
    return f"CIC-{cic}: computed {c1:08x} {c2:08x}, header {h1:08x} {h2:08x} -> " + ("consistent" if (c1, c2) == (h1, h2) else "MISMATCH")


def fix(rom):
    found = compute(rom)
    if found is None:
        return rom
    cic, c1, c2 = found
    return rom[:0x10] + struct.pack(">II", c1, c2) + rom[0x18:]


def swap(rom, order):
    if order == "z64":
        return rom
    n = len(rom) - len(rom) % 4
    body = bytearray(rom[:n])
    if order == "v64":      # byte-swapped: 37 80 40 12
        body[0::2], body[1::2] = rom[1:n:2], rom[0:n:2]
    elif order == "n64":    # little-endian words: 40 12 37 80
        body[0::4], body[1::4], body[2::4], body[3::4] = rom[3:n:4], rom[2:n:4], rom[1:n:4], rom[0:n:4]
    else:
        raise SystemExit(f"unknown byte order {order!r}")
    return bytes(body) + rom[n:]


def main():
    command, *rest = sys.argv[1:]
    if command == "check":
        print(check(Path(rest[0]).read_bytes()))
    elif command == "fix":
        Path(rest[1]).write_bytes(fix(Path(rest[0]).read_bytes()))
    elif command == "swap":
        Path(rest[1]).write_bytes(swap(Path(rest[0]).read_bytes(), rest[2]))
    else:
        raise SystemExit(__doc__)


main()
