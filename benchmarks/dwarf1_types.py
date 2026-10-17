#!/usr/bin/env python3
"""Metrowerks DWARF 1 type truth, read with no help from the Rust importer.

SLUS_209.50 (PS2, Capcom Fighting Evolution) carries a 6.3 MB `.debug`
section in DWARF 1 ("MW MIPS C Compiler"), which readelf, llvm-dwarfdump and
pyelftools do not read. This is an independent decoder written from the
DWARF 1.1.0 draft; it shares no code with
crates/romwright-core/src/native/mdebug/dwarf1.rs, which is the point: the
differential in `dwarf1_diff.py` compares the two.

It produces the DIE graph `dwarf_types.parse` builds from readelf text
(`{offset: {"tag", "attributes", "children"}}` with DWARF 2+ tag and
attribute names), so `dwarf_types.classify` and `console_research.dwarf_truth`
score it exactly as they score the DWARF 2+ images. Types DWARF 1 states by
attribute (`fund_type`, `mod_fund_type`, `user_def_type`, `mod_u_d_type`) are
turned into the nodes DWARF 2 would have (base, pointer, const and volatile
types) at synthetic offsets above the section.

Differences from the Rust reader, on purpose:

* nesting comes from recursive descent: a DIE whose `AT_sibling` lies past
  its own end owns the entries up to the null that closes its list, and the
  next sibling is reached by jumping to the sibling offset;
* the width of `long` is measured from the image's own struct layouts (the
  gap between a `long` member and the next member), not written down.

Nothing here guesses: a type that cannot be resolved is left to
`dwarf_types.classify` to call `unknown`, which is scored as absent truth.
"""
import argparse
import collections
import json
from pathlib import Path
import struct
import sys

SHT_MIPS_DEBUG = 0x70000005

# DWARF 1.1.0 tags -> the DWARF 2+ tag that carries the same meaning.
TAGS = {
    0x01: "DW_TAG_array_type", 0x04: "DW_TAG_enumeration_type",
    0x05: "DW_TAG_formal_parameter", 0x06: "DW_TAG_subprogram",
    0x07: "DW_TAG_variable", 0x0b: "DW_TAG_lexical_block",
    0x0c: "DW_TAG_variable", 0x0d: "DW_TAG_member",
    0x0f: "DW_TAG_pointer_type", 0x10: "DW_TAG_reference_type",
    0x11: "DW_TAG_compile_unit", 0x13: "DW_TAG_structure_type",
    0x14: "DW_TAG_subprogram", 0x15: "DW_TAG_subroutine_type",
    0x16: "DW_TAG_typedef", 0x17: "DW_TAG_union_type",
    0x18: "DW_TAG_unspecified_parameters", 0x1f: "DW_TAG_subprogram",
    0x02: "DW_TAG_class_type",
}

# Attribute numbers (the code with its form nibble shifted out).
A_SIBLING, A_LOCATION, A_NAME = 0x01, 0x02, 0x03
A_FUND, A_MOD_FUND, A_USER, A_MOD_USER = 0x05, 0x06, 0x07, 0x08
A_BYTE_SIZE, A_LOW_PC = 0x0B, 0x11

# Fundamental types: FT code -> (DW_ATE encoding, size in bytes). `None` size
# is a width the stream does not state; those classify as unknown. `long`
# is filled in from the image (`measure_long`).
FUNDAMENTAL = {
    0x01: (6, 1), 0x02: (6, 1), 0x03: (8, 1),
    0x04: (5, 2), 0x05: (5, 2), 0x06: (7, 2),
    0x07: (5, 4), 0x08: (5, 4), 0x09: (7, 4),
    0x0A: (5, "long"), 0x0B: (5, "long"), 0x0C: (7, "long"),
    0x0E: (4, 4), 0x0F: (4, 8), 0x15: (2, 1),
}
VOID = 0x14
FT_POINTER = 0x0D
SYNTHETIC = 0x10000000


class Die:
    __slots__ = ("offset", "tag", "attrs", "children")

    def __init__(self, offset, tag):
        self.offset, self.tag, self.attrs, self.children = offset, tag, {}, []


def sections(data):
    """(name, type, file offset, size) of an ELF32 little-endian image."""
    if data[:4] != b"\x7fELF" or data[4] != 1 or data[5] != 1:
        raise ValueError("not a little-endian ELF32")
    shoff, = struct.unpack_from("<I", data, 0x20)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x2E)
    headers = [struct.unpack_from("<IIIIIIIIII", data, shoff + i * shentsize) for i in range(shnum)]
    strings = headers[shstrndx][4]
    out = []
    for name, kind, _flags, _addr, off, size, *_ in headers:
        end = data.index(b"\0", strings + name)
        out.append((data[strings + name:end].decode(), kind, off, size))
    return out


def debug_stream(path):
    """The `.debug` bytes when the image carries a Metrowerks DWARF 1 stream."""
    data = Path(path).read_bytes()
    try:
        found = [(off, size) for name, kind, off, size in sections(data)
                 if name == ".debug" and kind == SHT_MIPS_DEBUG]
    except (ValueError, struct.error):
        return None
    if not found:
        return None
    off, size = found[0]
    blob = data[off:off + size]
    # First DIE: a compile unit (tag 0x11) after its 4-byte length.
    if len(blob) < 8 or struct.unpack_from("<H", blob, 4)[0] != 0x11:
        return None
    return blob


def read_attributes(blob, p, end):
    attrs = {}
    while p + 2 <= end:
        code, = struct.unpack_from("<H", blob, p)
        p += 2
        attribute, form = code >> 4, code & 0xF
        if form in (1, 2, 6):
            value, = struct.unpack_from("<I", blob, p)
            p += 4
        elif form == 5:
            value, = struct.unpack_from("<H", blob, p)
            p += 2
        elif form == 7:
            value, = struct.unpack_from("<Q", blob, p)
            p += 8
        elif form == 3:
            n, = struct.unpack_from("<H", blob, p)
            value = bytes(blob[p + 2:p + 2 + n])
            p += 2 + n
        elif form == 4:
            n, = struct.unpack_from("<I", blob, p)
            value = bytes(blob[p + 4:p + 4 + n])
            p += 4 + n
        elif form == 8:
            nul = blob.index(b"\0", p)
            value = bytes(blob[p:nul]).decode("latin-1")
            p = nul + 1
        else:
            raise ValueError(f"unknown DWARF 1 form {form} at {p:#x}")
        attrs.setdefault(attribute, value)
    return attrs


def read_die(blob, off):
    """(Die or None, offset after it). None is a null entry."""
    length, = struct.unpack_from("<I", blob, off)
    if length < 6:
        return None, off + max(length, 4)
    end = off + length
    tag, = struct.unpack_from("<H", blob, off + 4)
    die = Die(off, tag)
    die.attrs = read_attributes(blob, off + 6, end)
    sibling = die.attrs.get(A_SIBLING)
    if sibling is None or sibling <= end:
        return die, end
    cursor = end
    while cursor < sibling:
        child, cursor = read_die(blob, cursor)
        if child is None:
            break
        die.children.append(child)
    return die, sibling


def read_tree(blob):
    roots, off = [], 0
    while off + 4 <= len(blob):
        die, off = read_die(blob, off)
        if die is not None:
            roots.append(die)
    return roots


def walk(dies):
    for die in dies:
        yield die
        yield from walk(die.children)


def location_offset(block):
    """A member's offset: `OP_CONST c4, OP_ADD`."""
    if len(block) == 6 and block[0] == 0x04 and block[5] == 0x07:
        return struct.unpack_from("<I", block, 1)[0]
    return None


def measure_long(roots):
    """Bytes in a `long`, from struct layout: the gap from a `long` member to
    the next member of the same struct. Unions (gap 0) and the last member
    have no gap and are not evidence."""
    gaps = collections.Counter()
    for die in walk(roots):
        if die.tag != 0x13:
            continue
        members = [(m.attrs.get(A_LOCATION), m) for m in die.children if m.tag == 0x0D]
        for (here, member), (there, _) in zip(members, members[1:]):
            if member.attrs.get(A_FUND) not in (0x0A, 0x0B, 0x0C):
                continue
            a = location_offset(here or b"")
            b = location_offset(there or b"")
            if a is not None and b is not None and b > a:
                gaps[b - a] += 1
    if not gaps:
        raise ValueError("no struct layout measures `long`")
    size, count = gaps.most_common(1)[0]
    if size not in (4, 8) or count < 10:
        raise ValueError(f"`long` width not established by struct layout: {dict(gaps)}")
    return size, dict(gaps)


class Graph:
    """Builds DWARF 2+-shaped nodes from DWARF 1 DIEs."""

    def __init__(self, roots):
        self.long_size, self.long_evidence = measure_long(roots)
        self.nodes = {}
        self.next_synthetic = SYNTHETIC
        self.fundamentals = {}
        self.roots = roots

    def synth(self, tag, attributes):
        key = self.next_synthetic
        self.next_synthetic += 1
        self.nodes[key] = {"tag": tag, "attributes": attributes, "children": []}
        return key

    def unknown(self, size=1):
        """A base type no class applies to. It keeps a nonzero size and no
        encoding: `console_research.dwarf_truth` reads a zero-size base type
        as mwcc's `void`, and `dwarf_types.classify` reads an encoding it
        does not know as `unknown`."""
        return self.synth("DW_TAG_base_type", {
            "DW_AT_byte_size": f"(data1) {size}", "DW_AT_encoding": "(data1) 0"})

    def fundamental(self, ft):
        """A node for one FT_* code; None for `void`."""
        if ft == VOID:
            return None
        if ft not in self.fundamentals:
            if ft == FT_POINTER:
                key = self.synth("DW_TAG_pointer_type", {})
            elif ft in FUNDAMENTAL:
                encoding, size = FUNDAMENTAL[ft]
                size = self.long_size if size == "long" else size
                key = self.synth("DW_TAG_base_type", {
                    "DW_AT_byte_size": f"(data1) {size}",
                    "DW_AT_encoding": f"(data1) {encoding}"})
            else:
                # Includes the 16-byte `I128`/`UI128` (FT 0xa510), which
                # states no signedness.
                key = self.unknown(16 if ft == 0xA510 else 1)
            self.fundamentals[ft] = key
        return self.fundamentals[ft]

    def wrap(self, modifiers, base):
        """Apply DWARF 1 modifiers (outermost first) to `base`."""
        for modifier in reversed(modifiers):
            attributes = {} if base is None else {"DW_AT_type": f"<0x{base:x}>"}
            tag = {1: "DW_TAG_pointer_type", 2: "DW_TAG_reference_type",
                   3: "DW_TAG_const_type", 4: "DW_TAG_volatile_type"}.get(modifier)
            if tag is None:
                return self.unknown()
            base = self.synth(tag, attributes)
        return base

    def type_of(self, die, missing):
        """The node key of a DIE's type, or None for `void`. `missing` is what
        a DIE with no type attribute means: "void" for a return, "unknown"
        for a parameter."""
        a = die.attrs
        if A_FUND in a:
            return self.fundamental(a[A_FUND])
        if A_USER in a:
            return a[A_USER]
        if A_MOD_FUND in a:
            block = a[A_MOD_FUND]
            ft, = struct.unpack_from("<H", block, len(block) - 2)
            return self.wrap(list(block[:-2]), self.fundamental(ft))
        if A_MOD_USER in a:
            block = a[A_MOD_USER]
            ref, = struct.unpack_from("<I", block, len(block) - 4)
            return self.wrap(list(block[:-4]), ref)
        return self.unknown() if missing == "unknown" else None

    def build(self):
        for die in walk(self.roots):
            tag = TAGS.get(die.tag)
            if tag is None:
                continue
            attributes = {}
            if A_NAME in die.attrs:
                attributes["DW_AT_name"] = f"(string) {die.attrs[A_NAME]}"
            if A_BYTE_SIZE in die.attrs:
                attributes["DW_AT_byte_size"] = f"(data4) {die.attrs[A_BYTE_SIZE]}"
            if A_LOW_PC in die.attrs:
                attributes["DW_AT_low_pc"] = f"(addr) {die.attrs[A_LOW_PC]:#x}"
            if A_LOCATION in die.attrs:
                # Raw DWARF 1 location program; `locals_truth.py` decodes it.
                attributes["DW_AT_location"] = "(dwarf1) bytes: " + " ".join(
                    f"{byte:02x}" for byte in die.attrs[A_LOCATION])
            if die.tag in (0x16, 0x0F, 0x10, 0x05, 0x06, 0x14, 0x15, 0x1F, 0x0D, 0x07, 0x0C):
                target = self.type_of(die, "unknown" if die.tag == 0x05 else "void")
                if target is not None:
                    attributes["DW_AT_type"] = f"<0x{target:x}>"
            self.nodes[die.offset] = {
                "tag": tag, "attributes": attributes,
                "children": [c.offset for c in die.children if c.tag in TAGS],
            }
        # A DWARF 2+ subprogram's formal parameters are its children; the
        # nodes above already list them. DWARF 1 `0x07` is a global variable
        # and `0x0c` a local; both map to DW_TAG_variable, which
        # `dwarf_types` ignores outside subprograms.
        return self.nodes


def read(path):
    """(DIE graph, facts about the stream) of a Metrowerks DWARF 1 image, or
    None when the image carries no such stream."""
    blob = debug_stream(path)
    if blob is None:
        return None
    graph = Graph(read_tree(blob))
    result = graph.build()
    return result, {"long_size": graph.long_size, "long_evidence": graph.long_evidence}


def nodes(path):
    """The DIE graph alone, in `dwarf_types.parse`'s shape."""
    found = read(path)
    return found[0] if found else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    arguments = parser.parse_args()
    found = read(arguments.binary)
    if found is None:
        sys.exit("no Metrowerks DWARF 1 .debug stream")
    graph, facts = found
    functions = sum(1 for n in graph.values()
                    if n["tag"] == "DW_TAG_subprogram" and "DW_AT_low_pc" in n["attributes"])
    print(json.dumps({"dies": len(graph), "functions": functions, **facts}))


if __name__ == "__main__":
    main()
