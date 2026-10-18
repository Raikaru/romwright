#!/usr/bin/env python3
"""Tiny binaries the setup and release smoke tests import, written on demand.

`ps2_elf` is a PlayStation 2 Emotion Engine ELF: `e_machine` MIPS with the
`EF_MIPS_ARCH_3` / `MACH_5900` flags, which `r5900.opinion` selects as
`r5900:LE:32:default`. That language is not in the Ghidra release; it is compiled
by `packaging/languages.py` from `native/languages/r5900`, so importing and
decompiling this file proves a setup (or a release archive) carries the languages
romwright adds, not only Ghidra's own. One function at 0x00100000:

    jr   ra
    addu v0, a0, a1        (delay slot)       ->  return param_1 + param_2;

    python packaging/smoke_fixtures.py out.elf
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

ENTRY = 0x00100000
LANGUAGE = "r5900:LE:32:default"
FUNCTION_SIZE = 12


def ps2_elf() -> bytes:
    code = struct.pack("<3I", 0x03E00008, 0x00851021, 0x00000000)  # jr ra; addu v0,a0,a1; nop
    text_offset = 0x100
    shstrtab = b"\0.text\0.shstrtab\0"
    shstr_offset = text_offset + len(code)
    section_table = shstr_offset + len(shstrtab)
    section_table = (section_table + 3) & ~3
    header = struct.pack(
        "<16sHHIIIIIHHHHHH",
        b"\x7fELF\x01\x01\x01" + b"\0" * 9,  # ELFCLASS32, little endian, version 1
        2, 8, 1, ENTRY, 52, section_table,  # ET_EXEC, EM_MIPS, version, entry, phoff, shoff
        0x20920000, 52, 32, 1, 40, 3, 2,  # flags (ARCH_3 | MACH_5900), ehsize, phentsize, phnum, shentsize, shnum, shstrndx
    )
    program = struct.pack("<8I", 1, text_offset, ENTRY, ENTRY, len(code), len(code), 5, 0x1000)
    null_section = b"\0" * 40
    text = struct.pack("<10I", 1, 1, 6, ENTRY, text_offset, len(code), 0, 0, 4, 0)  # .text PROGBITS AX
    names = struct.pack("<10I", 7, 3, 0, 0, shstr_offset, len(shstrtab), 0, 0, 1, 0)  # .shstrtab STRTAB
    image = bytearray(header + program)
    image += b"\0" * (text_offset - len(image))
    image += code + shstrtab
    image += b"\0" * (section_table - len(image))
    image += null_section + text + names
    return bytes(image)


def write_ps2_elf(path: Path) -> Path:
    path.write_bytes(ps2_elf())
    return path


if __name__ == "__main__":
    print(write_ps2_elf(Path(sys.argv[1])))
