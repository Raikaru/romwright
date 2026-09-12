#!/usr/bin/env python3
"""Minimal PowerPC32-BE ELF exercising SDA globals end to end.

One function `get_err` loads a word through `r13` and returns it; the word
is the OBJECT symbol `HadError` in `.sdata`, with `_SDA_BASE_` ABS beside
it -- the base.elf (`RunNextModule`) shape reduced to two instructions:

    lwz r3, 8(r13)
    blr

Usage: ppc_sda.py OUT
"""
import struct
import sys

TEXT_ADDR = 0x10000
SDATA_ADDR = 0x11000
SBSS_ADDR = 0x11010
HADERROR_ADDR = 0x11008
SDA_BASE = 0x11000


def main(out):
    text = struct.pack(">II", 0x806D0008, 0x4E800020)  # lwz r3,8(r13); blr
    sdata = bytearray(16)
    struct.pack_into(">I", sdata, HADERROR_ADDR - SDATA_ADDR, 7)

    strtab = b"\x00get_err\x00HadError\x00_SDA_BASE_\x00"
    shstrtab = b"\x00.text\x00.sdata\x00.sbss\x00.symtab\x00.strtab\x00.shstrtab\x00"

    def sym(name_off, value, size, info, shndx):
        return struct.pack(">IIIBBH", name_off, value, size, info, 0, shndx)

    symtab = b"".join([
        sym(0, 0, 0, 0, 0),
        sym(1, TEXT_ADDR, 8, 0x12, 1),          # FUNC get_err
        sym(9, HADERROR_ADDR, 4, 0x11, 2),      # OBJECT HadError
        sym(18, SDA_BASE, 0, 0x10, 0xFFF1),     # NOTYPE ABS _SDA_BASE_
    ])

    blobs = [("text", text), ("sdata", bytes(sdata)), ("symtab", symtab),
             ("strtab", strtab), ("shstrtab", shstrtab)]
    off = 52
    layout = {}
    for name, blob in blobs:
        layout[name] = off
        off += len(blob)
    shoff = off

    def sh(name_off, typ, flags, addr, offset, size, link, info, align, entsize):
        return struct.pack(">IIIIIIIIII", name_off, typ, flags, addr,
                           offset, size, link, info, align, entsize)

    shstr = {".text": 1, ".sdata": 7, ".sbss": 14, ".symtab": 20,
             ".strtab": 28, ".shstrtab": 36}
    sects = [sh(0, 0, 0, 0, 0, 0, 0, 0, 0, 0)]
    sects.append(sh(shstr[".text"], 1, 6, TEXT_ADDR, layout["text"], len(text), 0, 0, 4, 0))
    sects.append(sh(shstr[".sdata"], 1, 3, SDATA_ADDR, layout["sdata"], 16, 0, 0, 4, 0))
    sects.append(sh(shstr[".sbss"], 8, 3, SBSS_ADDR, 0, 16, 0, 0, 4, 0))
    sects.append(sh(shstr[".symtab"], 2, 0, 0, layout["symtab"], len(symtab), 5, 1, 4, 16))
    sects.append(sh(shstr[".strtab"], 3, 0, 0, layout["strtab"], len(strtab), 0, 0, 1, 0))
    sects.append(sh(shstr[".shstrtab"], 3, 0, 0, layout["shstrtab"], len(shstrtab), 0, 0, 1, 0))

    ident = b"\x7fELF" + bytes([1, 2, 1, 0]) + bytes(8)
    ehdr = ident + struct.pack(">HHIIIIIHHHHHH",
                               2, 20, 1, TEXT_ADDR, 0, shoff, 0, 52, 0, 0, 40, 7, 6)

    img = bytearray()
    img += ehdr
    for _, blob in blobs:
        img += blob
    for s in sects:
        img += s
    with open(out, "wb") as f:
        f.write(img)
    print(f"wrote {out} ({len(img)} bytes)")


main(sys.argv[1])
