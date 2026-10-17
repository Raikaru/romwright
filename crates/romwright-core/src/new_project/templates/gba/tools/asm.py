#!/usr/bin/env python3
"""Assemble one assembly unit and prove it reproduces the retail bytes: asm.py OUT SRC

Paths of the tools come from build/tools.json (written by configure.py), flags
from config/project.json (compiler.asflags).

Every instruction and data line of a unit ends in `@ ADDRESS [raw halfwords/word]`.
The unit's retail bytes are read from orig/ at those addresses and compared with
the object's `.text`, relocated fields masked. GNU as is not the tool that
wrote the retail bytes: it can pick another encoding (Thumb `adds r0, r0, #1`
as the 8-bit form, a `mov` between low registers) or refuse a word. A line whose
bytes differ is rewritten as `.inst.n` / `.inst.w` / `.inst` of its retail word
(still code for objdiff, symbolic operands lost) and the unit assembled again;
a unit the assembler rejects, or whose size changes, is assembled with every line
raw. The note this prints names the unit.
"""
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LINE = re.compile(r"^\t(?P<text>[^\t]+?)\t@ (?P<addr>[0-9a-f]{8})(?: (?P<hex>[0-9a-f]{4,8}(?: [0-9a-f]{4})?))?\s*$")
# ARM ELF REL relocations: type -> mask of the bytes the linker rewrites, per 4-byte word at the offset.
MASKS = {
    1: 0x00FFFFFF,      # R_ARM_PC24
    2: 0xFFFFFFFF,      # R_ARM_ABS32
    3: 0xFFFFFFFF,      # R_ARM_REL32
    4: 0x00800FFF,      # R_ARM_LDR_PC_G0
    10: 0x07FF07FF,     # R_ARM_THM_CALL (two halfwords, low word first in memory)
    11: 0x000000FF,     # R_ARM_THM_PC8
    28: 0x00FFFFFF,     # R_ARM_CALL
    29: 0x00FFFFFF,     # R_ARM_JUMP24
    102: 0x000007FF,    # R_ARM_THM_JUMP11
    103: 0x000000FF,    # R_ARM_THM_JUMP8
}


def tools():
    return json.loads((ROOT / "build" / "tools.json").read_text())


def object_text(path):
    """(.text bytes, [(offset, type)]) of an ELF32 LE object."""
    data = Path(path).read_bytes()
    shoff, = struct.unpack_from("<I", data, 0x20)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x2E)
    sections = []
    for i in range(shnum):
        name, kind, _flags, _addr, offset, size, link, info = struct.unpack_from("<IIIIIIII", data, shoff + i * shentsize)
        sections.append((name, kind, offset, size, link, info))
    strtab = sections[shstrndx]

    def name_of(n):
        start = strtab[2] + n
        return data[start:data.index(b"\0", start)].decode()

    text_index = next((i for i, s in enumerate(sections) if name_of(s[0]) == ".text"), None)
    if text_index is None:
        return b"", []
    text = data[sections[text_index][2]:sections[text_index][2] + sections[text_index][3]]
    relocations = []
    for _name, kind, offset, size, _link, info in sections:
        if kind == 9 and info == text_index:  # SHT_REL
            for k in range(size // 8):
                r_offset, r_info = struct.unpack_from("<II", data, offset + 8 * k)
                relocations.append((r_offset, r_info & 0xFF))
        elif kind == 4 and info == text_index:  # SHT_RELA
            for k in range(size // 12):
                r_offset, r_info, _addend = struct.unpack_from("<IIi", data, offset + 12 * k)
                relocations.append((r_offset, r_info & 0xFF))
    return text, relocations


def parse(source):
    """Lines of the unit with an address: [(line index, address, byte length, kind, hex)]."""
    rows = []
    for index, line in enumerate(source.split("\n")):
        match = LINE.match(line)
        if not match:
            continue
        text, address, raw = match.group("text"), int(match.group("addr"), 16), match.group("hex")
        if text.startswith(".4byte"):
            rows.append((index, address, 4, "word", None))
        elif text.startswith(".2byte"):
            rows.append((index, address, 2, "half", None))
        elif text.startswith(".byte"):
            rows.append((index, address, 1, "byte", None))
        elif raw is not None:
            length = len(raw.replace(" ", "")) // 2
            rows.append((index, address, length, "insn", raw))
    return rows


def raw_line(row, retail, lo, mode):
    _index, address, length, kind, raw = row
    value = int.from_bytes(retail[address - lo:address - lo + length], "little")
    if kind == "word":
        return f"\t.4byte {value:#010x}\t@ {address:08x}"
    if kind == "half":
        return f"\t.2byte {value:#06x}\t@ {address:08x}"
    if kind == "byte":
        return f"\t.byte {value:#04x}\t@ {address:08x}"
    halves = raw.split()
    if mode == "thumb" and length == 2:
        return f"\t.inst.n {int(halves[0], 16):#06x}\t@ {address:08x} {raw}"
    if mode == "thumb":
        return f"\t.inst.w {(int(halves[0], 16) << 16) | int(halves[1], 16):#010x}\t@ {address:08x} {raw}"
    return f"\t.inst {int(halves[0], 16):#010x}\t@ {address:08x} {raw}"


def assemble(tool_paths, flags, out, text):
    return subprocess.run(
        [tool_paths["as"], *flags, "-I", str(ROOT / "include"), "-o", str(out), "-"],
        input=text, capture_output=True, text=True, cwd=ROOT,
    )


def mismatches(text, relocations, rows, retail, lo):
    """Rows whose object bytes differ from the retail bytes outside relocated fields."""
    fields = {}
    for offset, kind in relocations:
        fields[offset] = MASKS.get(kind, 0xFFFFFFFF)
    bad = []
    for row in rows:
        _index, address, length, _kind, _raw = row
        at = address - lo
        if at + length > len(text):
            bad.append(row)
            continue
        got, want = text[at:at + length], retail[at:at + length]
        if got == want:
            continue
        for i in range(length):
            if got[i] == want[i]:
                continue
            mask = 0
            for offset, field in fields.items():
                if offset <= at + i < offset + 4:
                    mask = (field >> (8 * (at + i - offset))) & 0xFF
                    break
            if (got[i] ^ want[i]) & ~mask & 0xFF:
                bad.append(row)
                break
    return bad


def main():
    out, source_path = sys.argv[1:3]
    project = json.loads((ROOT / "config" / "project.json").read_text())
    tool_paths = tools()
    flags = project["compiler"]["asflags"]
    source = Path(source_path).read_text()
    lines = source.split("\n")
    rows = parse(source)
    mode = "thumb" if "\n.thumb\n" in source else "arm"
    if not rows:
        return assemble_or_fail(tool_paths, flags, out, source)
    base = project["image"]["base"]
    lo, hi = rows[0][1], rows[-1][1] + rows[-1][2]
    with open(ROOT / project["image"]["orig"], "rb") as handle:
        handle.seek(lo - base)
        retail = handle.read(hi - lo)
    raw_rows = set()
    for attempt in range(4):
        current = list(lines)
        for row in rows:
            if row[0] in raw_rows:
                current[row[0]] = raw_line(row, retail, lo, mode)
        result = assemble(tool_paths, flags, out, "\n".join(current))
        if result.returncode != 0:
            # An error names a line of the unit: that line becomes raw, anything else gives up.
            named = {int(m.group(1)) - 1 for m in re.finditer(r"<stdin>:(\d+): Error", result.stderr)}
            hit = {row[0] for row in rows if row[0] in named} - raw_rows
            if not hit:
                break
            raw_rows |= hit
            continue
        text, relocations = object_text(out)
        if len(text) != hi - lo:
            break
        bad = mismatches(text, relocations, rows, retail, lo)
        if not bad:
            if raw_rows:
                note(source_path, f"{len(raw_rows)} line(s) kept as raw words")
            return 0
        raw_rows |= {row[0] for row in bad}
    # Last resort: every line raw.
    current = list(lines)
    for row in rows:
        current[row[0]] = raw_line(row, retail, lo, mode)
    note(source_path, "assembled with every line as raw words (the symbolic text did not reproduce the retail bytes)")
    return assemble_or_fail(tool_paths, flags, out, "\n".join(current))


def note(source_path, message):
    """Printed, and appended to build/asm_notes.txt so a whole build's degraded units can be counted."""
    print(f"note: {source_path}: {message}", file=sys.stderr)
    with open(ROOT / "build" / "asm_notes.txt", "a") as handle:
        handle.write(f"{source_path}: {message}\n")


def assemble_or_fail(tool_paths, flags, out, text):
    result = assemble(tool_paths, flags, out, text)
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
    return result.returncode


sys.exit(main())
