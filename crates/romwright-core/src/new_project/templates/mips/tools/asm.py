#!/usr/bin/env python3
"""Assemble splat .s files into one object: asm.py AS OUT SRC [SRC...]

Flags and byte order come from config/project.json (compiler.asflags, compiler.endian).

Two corrections to what splat writes:

* splat emits `.align 3` ahead of 8-byte-aligned functions. GNU as then rounds
  the whole `.text` section up to 8 bytes, which would grow the object by up to
  4 bytes and shift every later function away from the retail address. The
  link places each object with SUBALIGN(1), so the directive can only do harm
  here: it is dropped (alignments of 4 and below are kept) before assembling.
* Some bytes a discovery pass called code are not (data inside a "function",
  a false entry in a data section). The assembler rejects the words that are
  not instructions (`jalr $zero,$zero`, 64-bit multiplies the R5900 lacks), and
  branches in such data name `.L<address>` labels that exist in no file (the
  link would fail on them). The listing carries every instruction's raw word in
  its comment, so such a file is assembled with each instruction as a `.word`:
  the bytes are the retail bytes either way, only the symbolic operands are
  lost. The note this prints names the file; such a unit is data, not a
  decompilation target.
* The assembler can also accept a word and encode it differently (a COP2
  macro whose canonical form is another bit pattern). Every instruction in the
  listing carries its retail word, so the object's `.text` is compared with
  them (relocated fields masked), and a unit that does not reproduce them is
  assembled as raw words too.
"""
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ORDER = json.loads((ROOT / "config" / "project.json").read_text())["compiler"].get("endian", "little")
# splat's listings are written to be pulled into a C file by an INCLUDE_ASM macro
# under asm/nonmatchings/, which supplies this context.
PRELUDE = '.include "macro.inc"\n.set noat\n.set noreorder\n.section .text, "ax"\n'
DROP = re.compile(r"(?m)^[ \t]*\.align[ \t]+[3-9][ \t]*(?:#.*)?\n")
# `    /* 141250 00240250 1000C22C */  sltiu      $v0, $a2, 0x10`
LABEL_USE = re.compile(r"\.L[0-9A-Fa-f]{8}\b")
LABEL_DEF = re.compile(r"^\s*(?:(?:jlabel|alabel|glabel|dlabel|ehlabel)\s+)?(\.L[0-9A-Fa-f]{8})(?::|\s*$)", re.M)
INSTRUCTION = re.compile(r"^(\s*)/\*\s*[0-9A-Fa-f]+\s+[0-9A-Fa-f]+\s+([0-9A-Fa-f]{8})\s*\*/\s+\S.*$")


def text_and_relocations(path):
    """`.text` bytes and `{offset: relocation type}` of an ELF32 object."""
    data = Path(path).read_bytes()
    shoff = int.from_bytes(data[0x20:0x24], ORDER)
    entsize, count, strndx = (int.from_bytes(data[at:at + 2], ORDER) for at in (0x2E, 0x30, 0x32))
    sections = []
    for index in range(count):
        row = data[shoff + index * entsize: shoff + (index + 1) * entsize]
        sections.append(tuple(int.from_bytes(row[at:at + 4], ORDER) for at in (0, 4, 16, 20)))  # name, type, offset, size
    names = sections[strndx]

    def name_of(section):
        start = names[2] + section[0]
        return data[start:data.index(b"\0", start)].decode()

    text, relocations = b"", {}
    for section in sections:
        if name_of(section) == ".text":
            text = data[section[2]:section[2] + section[3]]
        elif name_of(section) == ".rel.text":
            blob = data[section[2]:section[2] + section[3]]
            for at in range(0, len(blob), 8):
                relocations[int.from_bytes(blob[at:at + 4], ORDER)] = blob[at + 7] if ORDER == "big" else blob[at + 4]
    return text, relocations


def reproduces_listing(out, text):
    """True when the object's `.text` equals the retail words the listing carries
    (relocated fields masked). Files with no instruction comments (binary
    includes) are not checked."""
    if ".incbin" in text:
        return True
    expected = [int.from_bytes(bytes.fromhex(m.group(2)), ORDER) for m in map(INSTRUCTION.match, text.split("\n")) if m]
    if not expected:
        return True
    built, relocations = text_and_relocations(out)
    if len(built) != 4 * len(expected):
        return False
    for index, want in enumerate(expected):
        got = int.from_bytes(built[4 * index:4 * index + 4], ORDER)
        kind = relocations.get(4 * index)
        if kind is None:
            mask = 0xFFFFFFFF
        elif kind in (2, 3):          # R_MIPS_32 / REL32: a whole pointer
            mask = 0
        elif kind == 4:               # R_MIPS_26: the jump target
            mask = 0xFC000000
        else:                         # HI16 / LO16 / GPREL16 / PC16 ...: the immediate
            mask = 0xFFFF0000
        if (got ^ want) & mask:
            return False
    return True


def as_words(text):
    out = []
    for line in text.split("\n"):
        m = INSTRUCTION.match(line)
        if m:
            word = int.from_bytes(bytes.fromhex(m.group(2)), ORDER)
            out.append(f"{m.group(1)}.word 0x{word:08x}")
        else:
            out.append(line)
    return "\n".join(out)


def assemble(assembler, flags, out, text):
    return subprocess.run(
        [assembler, *flags, "-Iinclude", "-o", out, "-"],
        input=text.encode("utf-8", "surrogateescape"),
        stderr=subprocess.PIPE,
        cwd=ROOT,
    )


def main():
    assembler, out, *sources = sys.argv[1:]
    flags = json.loads((ROOT / "config" / "project.json").read_text())["compiler"]["asflags"]
    text = ""
    for src in sources:
        with open(src, "r", encoding="utf-8", errors="surrogateescape") as handle:
            body = DROP.sub("", handle.read())
            text += (PRELUDE if "/nonmatchings/" in Path(src).as_posix() else "") + body + "\n"
    dangling = set(LABEL_USE.findall(text)) - set(LABEL_DEF.findall(text))
    if dangling:
        retry = assemble(assembler, flags, out, as_words(text))
        if retry.returncode == 0:
            sys.stderr.write(f"note: {' '.join(sources[:3])}: assembled as raw words (branches to {len(dangling)} label(s) outside the file)\n")
            return 0
    result = assemble(assembler, flags, out, text)
    if result.returncode == 0 and not reproduces_listing(out, text):
        retry = assemble(assembler, flags, out, as_words(text))
        if retry.returncode == 0:
            sys.stderr.write(f"note: {' '.join(sources[:3])}: assembled as raw words (the assembler encodes an instruction differently from retail)\n")
            return 0
    if result.returncode:
        first = result.stderr.decode(errors="replace").strip().splitlines()
        retry = assemble(assembler, flags, out, as_words(text))
        if retry.returncode == 0:
            reason = next((l for l in first if "Error" in l), "assembler error")
            sys.stderr.write(f"note: {' '.join(sources[:3])}: assembled as raw words ({reason.split('Error: ')[-1][:90]})\n")
            return 0
    if result.returncode:
        sys.stderr.write(f"{' '.join(sources[:3])}:\n" + result.stderr.decode(errors="replace"))
    return result.returncode


sys.exit(main())
