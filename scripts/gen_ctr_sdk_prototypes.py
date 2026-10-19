#!/usr/bin/env python3
"""Writes oracle/library-prototypes-v1/ctr_sdk.json: the Nintendo CTR SDK (nn::, nw::)
function declarations that 3DS games' DWARF debug streams state, spelled in
the language types the decompiler's parser resolves.

Input (not committed, 7 MB): `ctrsdk_prototypes.json`, one row per function the
games' DWARF declares: `qualified_scope`, `name`, `return_type`, `params[].type`
(the receiver of a member is its first parameter), spelled as C types with
typedef names kept (`s32`, `bit32`, `struct nnhidCTRTouchPanelReader *`).

  python3 scripts/gen_ctr_sdk_prototypes.py --input ctrsdk_prototypes.json [--check]

Keys. A function is keyed by its scope and name joined with `_`
(`nn::hid::CTR::TouchPanelReader::ReadLatest` is
`nn_hid_CTR_TouchPanelReader_ReadLatest`), the spelling a project's function
names use once `::` is not allowed in a symbol. Only a key whose every
declaration agrees (after the type mapping below) is written: an overload set
or a name two games declare differently names no prototype, because nothing
here says which one a function is.

Types (nothing is invented; what the rows do not state is dropped, not guessed):
  * the SDK's scalar typedefs (`nn/types.h`: s8..s64, u8..u64, f32, f64, bit8..bit64,
    uptr, char8) and `std::size_t` map to the C type of that width on ARM11 (ILP32);
  * `struct nn::Result` and `struct nn::Handle`, by value, are one 32-bit word in the
    SDK and travel in r0 (`uint`); every other by-value struct or typedef the rows
    do not define has no known size, and a function that takes or returns one is left out;
  * `enum X` by value is a register-sized `int`;
  * a pointer to a scalar keeps its target (`u8 *` -> `byte *`); a pointer to
    anything the rows do not lay out (a struct, class, enum, array, function) is an
    `undefined4` slot (a pointer to a pointer: `undefined4 *`). The layouts are not in the
    rows, so none is made up, and the decompiler is left to type the slot from its use.
    (`void *` there makes the decompiler cast every access of the pointer back; see docs/new-project.md.)
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "oracle/library-prototypes-v1/ctr_sdk.json"

# Names are the decompiler's core / base type names (ARM11, ILP32): its core types have `byte` and
# `sbyte` for the 8-bit integers, not `uchar`.
SCALARS = {
    "void": "void", "bool": "bool", "char": "char", "signed char": "sbyte", "unsigned char": "byte",
    "short": "short", "unsigned short": "ushort", "int": "int", "unsigned int": "uint",
    "long": "long", "unsigned long": "ulong", "long long": "longlong", "unsigned long long": "ulonglong",
    "float": "float", "double": "double",
    "s8": "sbyte", "u8": "byte", "s16": "short", "u16": "ushort", "s32": "int", "u32": "uint",
    "s64": "longlong", "u64": "ulonglong", "f32": "float", "f64": "double",
    "bit8": "byte", "bit16": "ushort", "bit32": "uint", "bit64": "ulonglong",
    "uptr": "uint", "stdsize_t": "uint", "char8": "char",
}
# A pointer-sized slot whose type nothing in the rows states. The decompiler types such a slot from
# the function's own use (`int *`, `char *`, ...); `void *` would instead lock it to a pointer to nothing.
OPAQUE = "undefined4"
# One 32-bit word by value (nn::Result is a packed 32-bit code; nn::Handle a 32-bit kernel handle).
WORD_STRUCTS = {"struct nnResult": "uint", "struct nnHandle": "uint"}


def convert(text: str) -> str | None:
    text = text.strip()
    pointer = re.fullmatch(r"(.*?)\s*((?:\*\s*)+)", text)
    if pointer:
        depth = pointer.group(2).count("*")
        target = pointer.group(1).strip()
        if target in SCALARS:
            return " ".join([SCALARS[target]] + ["*"] * depth)
        # The target is laid out nowhere in the rows: the pointer is one word of unknown type, and one
        # level of `*` less than it has, so a pointer to a pointer is a pointer to a word.
        return " ".join([OPAQUE] + ["*"] * (depth - 1))
    if "(" in text:  # `unsigned char (*)[4]`, `void (*)(int)`: a pointer to something laid out elsewhere
        return OPAQUE
    if text in SCALARS:
        return SCALARS[text]
    if text in WORD_STRUCTS:
        return WORD_STRUCTS[text]
    if text.startswith("enum "):
        return "int"
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--check", action="store_true", help="fail if the committed file differs")
    arguments = parser.parse_args()
    raw = arguments.input.read_bytes()
    functions = json.loads(raw)["functions"]

    groups: dict[str, list[dict]] = collections.defaultdict(list)
    for function in functions:
        scope = function["qualified_scope"]
        groups[(scope + "::" + function["name"]).replace("::", "_")].append(function)

    table: dict[str, dict] = {}
    skipped = collections.Counter()
    for key, group in sorted(groups.items()):
        signatures = set()
        for function in group:
            ret = convert(function["return_type"])
            params = [convert(p["type"]) for p in function["params"]]
            if ret is None or any(p is None or p == "void" for p in params):
                signatures.add(None)
            else:
                signatures.add((ret, tuple(params)))
        if None in signatures:
            skipped["unsized by-value type"] += 1
        elif len(signatures) > 1:
            skipped["declarations disagree"] += 1
        else:
            ret, params = next(iter(signatures))
            table[key] = {
                "return_type": ret,
                "parameters": [{"name": "", "type": p} for p in params],
            }
    document = {
        "archive": "ctrsdk_prototypes.json: DWARF function declarations of " + ", ".join(sorted({f["source"] for f in functions})),
        "archive_sha256": hashlib.sha256(raw).hexdigest(),
        "generator": "scripts/gen_ctr_sdk_prototypes.py",
        "declared": len(groups),
        "skipped": dict(skipped),
        "functions": table,
    }
    text = json.dumps(document, sort_keys=True, indent=1) + "\n"
    if arguments.check:
        if not OUTPUT.is_file() or OUTPUT.read_text() != text:
            raise SystemExit(f"{OUTPUT.relative_to(ROOT)} differs from the generator")
        print(f"{OUTPUT.relative_to(ROOT)} matches ({len(table)} declarations)")
        return 0
    OUTPUT.write_text(text)
    print(f"wrote {OUTPUT.relative_to(ROOT)}: {len(table)} declarations of {len(groups)} names; skipped {dict(skipped)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
