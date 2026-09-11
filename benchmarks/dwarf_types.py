#!/usr/bin/env python3
"""DWARF type truth: what the compiler said each parameter and return is.

`dwarf_arity.py` already reads concrete `DW_TAG_subprogram` entries and their
formal parameters out of an unstripped twin. This adds the one attribute it
deliberately ignores -- `DW_AT_type` -- resolved through the qualifier and
typedef chain to a small, comparable class:

    void | bool | int<N> | uint<N> | float<N> | ptr | code | aggregate

The classes are the ones a binary type inference can actually be scored on.
A `struct tm *` is `ptr` because that is what the machine holds and what any
inference over p-code can hope to prove; the pointee is a separate question
(and a later milestone). `int<N>`/`uint<N>` keep their width because width is
recoverable and signedness is exactly what a comparison instruction reveals.
`code` is a pointer to a subroutine, which is worth separating from `ptr`
because it is the one an indirect call proves.

Nothing here guesses: a type that cannot be resolved to a class is reported
as `unknown` and scored as absent truth rather than as a wrong answer.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dwarf_arity import DIE, ATTRIBUTE, dwarf_dump_tool, get_load_segments, integer, payload  # noqa: E402
import os  # noqa: E402
import subprocess  # noqa: E402

# `DW_AT_encoding` codes (DWARF 5, table 7.11). readelf prints the number
# and its name -- "(data1) 5\t(signed)" -- so the number is what to read:
# the name is a rendering and differs between binutils versions.
SIGNED_ENCODINGS = {0x05, 0x06}       # signed, signed_char
UNSIGNED_ENCODINGS = {0x07, 0x08}     # unsigned, unsigned_char
FLOAT_ENCODINGS = {0x04}              # float
BOOLEAN_ENCODINGS = {0x02}            # boolean
# Tags that wrap a type without changing what the machine holds.
TRANSPARENT = {
    "DW_TAG_typedef",
    "DW_TAG_const_type",
    "DW_TAG_volatile_type",
    "DW_TAG_restrict_type",
    "DW_TAG_atomic_type",
    "DW_TAG_immutable_type",
}
AGGREGATE = {
    "DW_TAG_structure_type",
    "DW_TAG_union_type",
    "DW_TAG_class_type",
    "DW_TAG_array_type",
}


def parse(text):
    """The DIE graph, as `dwarf_arity.parse_info` builds it but kept whole so
    types can be resolved across it."""
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
                raise ValueError(f"ambiguous DWARF DIE nesting/offset: {line}")
            current = {"tag": match[4], "attributes": {}, "children": []}
            nodes[offset] = current
            if stack:
                nodes[stack[-1]]["children"].append(offset)
            stack.append(offset)
        elif current is not None and (match := ATTRIBUTE.match(line)):
            current["attributes"][match[1]] = match[2]
    if not nodes:
        raise ValueError("no DWARF DIEs found")
    return nodes


def lineage(nodes, offset, depth=0):
    """A DIE and the declarations it inherits from.

    A concrete instance carries its location and little else: the name and
    the type live on the abstract instance it points at with
    `DW_AT_abstract_origin`, or on the declaration named by
    `DW_AT_specification`. `dwarf_arity` walks the same chain to count
    parameters; types have to walk it too or every optimised build reads as
    `void`.
    """
    chain = [offset]
    seen = {offset}
    while True:
        attributes = nodes.get(chain[-1], {}).get("attributes", {})
        value = attributes.get("DW_AT_abstract_origin", attributes.get("DW_AT_specification"))
        target = reference(value)
        if target is None or target in seen or target not in nodes or len(chain) > 16:
            return chain
        seen.add(target)
        chain.append(target)


def inherited(nodes, offset, name):
    for part in lineage(nodes, offset):
        value = nodes[part]["attributes"].get(name)
        if value is not None:
            return value
    return None


def reference(value):
    match = re.search(r"<(?:0x)?([0-9a-fA-F]+)>", value or "")
    return int(match[1], 16) if match else None


def classify(nodes, offset, depth=0):
    """One type DIE, as the class the machine can be scored on."""
    if offset is None:
        return "void"
    if depth > 16 or offset not in nodes:
        return "unknown"
    node = nodes[offset]
    tag = node["tag"]
    attributes = node["attributes"]
    if tag in TRANSPARENT:
        return classify(nodes, reference(attributes.get("DW_AT_type")), depth + 1)
    if tag in ("DW_TAG_pointer_type", "DW_TAG_reference_type",
               "DW_TAG_rvalue_reference_type"):
        pointee = reference(attributes.get("DW_AT_type"))
        target = nodes.get(pointee, {}).get("tag") if pointee is not None else None
        while target in TRANSPARENT:
            pointee = reference(nodes[pointee]["attributes"].get("DW_AT_type"))
            target = nodes.get(pointee, {}).get("tag") if pointee is not None else None
        # A pointer to a subroutine is what an indirect call proves.
        return "code" if target == "DW_TAG_subroutine_type" else "ptr"
    if tag in AGGREGATE:
        return "aggregate"
    if tag == "DW_TAG_enumeration_type":
        size = attributes.get("DW_AT_byte_size")
        return f"int{integer(size) * 8}" if size else "unknown"
    if tag == "DW_TAG_base_type":
        size = attributes.get("DW_AT_byte_size")
        if not size:
            return "unknown"
        raw = attributes.get("DW_AT_encoding") or ""
        match = re.search(r"\)\s*(\d+)", raw) or re.search(r"(\d+)", raw)
        encoding = int(match[1]) if match else -1
        bits = integer(size) * 8
        if encoding in BOOLEAN_ENCODINGS:
            return "bool"
        if encoding in FLOAT_ENCODINGS:
            return f"float{bits}"
        if encoding in SIGNED_ENCODINGS:
            return f"int{bits}"
        if encoding in UNSIGNED_ENCODINGS:
            return f"uint{bits}"
        return "unknown"
    if tag == "DW_TAG_subroutine_type":
        return "code"
    return "unknown"


def extract(binary, load_bias=0):
    data = Path(binary).read_bytes()
    executable = [(address, size) for address, size, flags, _, _ in get_load_segments(data)
                  if flags & 1]
    environment = dict(os.environ, LC_ALL="C", DEBUGINFOD_URLS="")
    # System readelf is ELF-only; BFD objdump reads PE DWARF identically.
    tool = dwarf_dump_tool(data)
    result = subprocess.run(
        [*tool, str(binary)],
        text=True, capture_output=True, check=True, timeout=120, env=environment)
    if result.stderr.strip():
        raise ValueError(f"readelf did not provide a clean truth export: {result.stderr.strip()}")
    nodes = parse(result.stdout)
    functions = {}
    for offset, node in nodes.items():
        if node["tag"] != "DW_TAG_subprogram":
            continue
        attributes = node["attributes"]
        entry = attributes.get("DW_AT_entry_pc", attributes.get("DW_AT_low_pc"))
        if entry is None:
            continue
        entry = integer(entry)
        if not any(start <= entry < start + size for start, size in executable):
            continue
        parameters = [
            classify(nodes, reference(inherited(nodes, child, "DW_AT_type")))
            for child in node["children"]
            if nodes[child]["tag"] == "DW_TAG_formal_parameter"
        ]
        # An optimised build keeps the parameter list on the abstract
        # instance, so a concrete one with no children of its own inherits
        # the whole signature rather than reading as niladic.
        if not parameters:
            for part in lineage(nodes, offset)[1:]:
                parameters = [
                    classify(nodes, reference(inherited(nodes, child, "DW_AT_type")))
                    for child in nodes[part]["children"]
                    if nodes[child]["tag"] == "DW_TAG_formal_parameter"
                ]
                if parameters:
                    break
        name = inherited(nodes, offset, "DW_AT_name")
        row = {
            "name": payload(name) if name else None,
            "returns": classify(nodes, reference(inherited(nodes, offset, "DW_AT_type"))),
            "parameters": parameters,
        }
        key = f"{entry + load_bias:08x}"
        # A declaration and its definition describe one function; keep the
        # one that names parameter types at all.
        if key not in functions or len(row["parameters"]) > len(functions[key]["parameters"]):
            functions[key] = row
    if not functions:
        raise ValueError("no executable DWARF subprogram entries")
    return {
        "schema": 1,
        "binary_sha256": hashlib.sha256(data).hexdigest(),
        "load_bias": load_bias,
        "functions": dict(sorted(functions.items())),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--load-bias", type=lambda value: int(value, 0), default=0)
    parser.add_argument("--out", type=Path)
    arguments = parser.parse_args()
    report = extract(arguments.binary, arguments.load_bias)
    encoded = json.dumps(report, indent=2) + "\n"
    if arguments.out:
        arguments.out.write_text(encoded)
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
