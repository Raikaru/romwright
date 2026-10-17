#!/usr/bin/env python3
"""Writes oracle/library-prototypes-v1/runtime_helpers.json: the compiler
run-time helper routines whose signatures two public documents state.

Sources (facts only; no library source was read):
  gccint  GCC Internals, chapter "The GCC low-level runtime library"
          https://gcc.gnu.org/onlinedocs/gccint/Libgcc.html -- sections 3.1
          (integer routines) and 3.2 (soft-float routines). Its functions are
          declared with illustrative C types ("`long` to DImode", "`long
          long` to TImode"), because the routines take a machine *mode*, not
          a C type, so the table records the mode and the runtime resolves it
          against the image's own type widths.
  rtabi   Run-time ABI for the Arm Architecture (Arm Limited, CC-BY-SA-4.0)
          https://github.com/ARM-software/abi-aa/blob/main/rtabi32/rtabi32.rst
          -- the `__aeabi_*` helpers: floating-point (double/single
          arithmetic, comparison, conversion), long long, integer division,
          unaligned access, memory. Those are plain C declarations on a
          32-bit target and are recorded the same way (modes SI/DI/SF/DF).

Modes (`GCC Internals`, Machine Modes): `si` 4-byte, `di` 8-byte, `ti` 16-byte
integer; `u` prefix = unsigned; `sf` 4-byte, `df` 8-byte, `xf` x87 extended
float; `tf` is IEEE quad. `hi` 2-byte integer (the half-float storage word of
the RTABI), `cmp` the target's word-sized comparison result (CMPtype, "typically
word-sized"), `usize` size_t, a trailing `*` a pointer to the mode, `void*`.

Left out on purpose, with the reason: the complex routines (`__mulsc3`, ...:
a `complex` return has no C spelling in the language documents), the
bit-precise `_BitInt` routines (limb width is a target parameter with no type
name), the decimal-float and fixed-point chapters (`_Decimal32`, `_Fract`,
`_Accum` are in no language's type document, so no row could ever be
applied), `__value_in_regs` aggregate returns (`__aeabi_ldivmod`,
`__aeabi_idivmod`: a struct in registers), the obsolete `__aeabi_fneg` /
`__aeabi_dneg`, and the C++ vector helpers (function-pointer parameters).

  python3 scripts/gen_runtime_helpers.py [--check]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "oracle/library-prototypes-v1/runtime_helpers.json"

rows: dict[str, dict] = {}


def add(name: str, ret: str, params: list[str], source: str, names: list[str] | None = None) -> None:
    if name in rows:
        raise SystemExit(f"duplicate {name}")
    names = names or [chr(ord("a") + i) for i in range(len(params))]
    rows[name] = {"return": ret, "source": source,
                  "parameters": [{"name": n, "type": t} for n, t in zip(names, params)]}


def unsigned(mode: str) -> str:
    return "u" + mode


INT = "gccint 3.1"
FLT = "gccint 3.2"
ARM = "rtabi"

# ---- gccint 3.1.1 arithmetic -------------------------------------------------
for m in ("si", "di", "ti"):
    for op in ("ashl", "ashr", "lshr"):
        add(f"__{op}{m}3", m, [m, "si"], INT + ".1")
    for op in ("div", "mod", "mul"):
        add(f"__{op}{m}3", m, [m, m], INT + ".1")
    for op in ("udiv", "umod"):
        add(f"__{op}{m}3", unsigned(m), [unsigned(m)] * 2, INT + ".1")
for m in ("di", "ti"):
    add(f"__neg{m}2", m, [m], INT + ".1")
    add(f"__udivmod{m}4", unsigned(m), [unsigned(m), unsigned(m), unsigned(m) + "*"], INT + ".1")
# ---- 3.1.2 comparison (return int) ---------------------------------------------
for m in ("di", "ti"):
    add(f"__cmp{m}2", "si", [m, m], INT + ".2")
    add(f"__ucmp{m}2", "si", [unsigned(m)] * 2, INT + ".2")
# ---- 3.1.3 trapping arithmetic -------------------------------------------------
for m in ("si", "di"):
    add(f"__absv{m}2", m, [m], INT + ".3")
    add(f"__negv{m}2", m, [m], INT + ".3")
    for op in ("addv", "mulv", "subv"):
        add(f"__{op}{m}3", m, [m, m], INT + ".3")
# ---- 3.1.4 bit operations ------------------------------------------------------
for m in ("si", "di", "ti"):
    for op in ("clz", "ctz", "parity", "popcount"):
        add(f"__{op}{m}2", "si", [unsigned(m)], INT + ".4")
for m in ("di", "ti"):
    add(f"__ffs{m}2", "si", [unsigned(m)], INT + ".4")
add("__bswapsi2", "si", ["si"], INT + ".4")
add("__bswapdi2", "di", ["di"], INT + ".4")

# ---- gccint 3.2.1 arithmetic ---------------------------------------------------
FLOATS = ("sf", "df", "tf", "xf")
for m in FLOATS:
    for op in ("add", "sub", "mul", "div"):
        add(f"__{op}{m}3", m, [m, m], FLT + ".1")
    add(f"__neg{m}2", m, [m], FLT + ".1")
# ---- 3.2.2 conversion ----------------------------------------------------------
for name, src, dst in [("extendsfdf2", "sf", "df"), ("extendsftf2", "sf", "tf"), ("extendsfxf2", "sf", "xf"),
                       ("extenddftf2", "df", "tf"), ("extenddfxf2", "df", "xf"),
                       ("truncxfdf2", "xf", "df"), ("trunctfdf2", "tf", "df"), ("truncxfsf2", "xf", "sf"),
                       ("trunctfsf2", "tf", "sf"), ("truncdfsf2", "df", "sf")]:
    add(f"__{name}", dst, [src], FLT + ".2")
for f in FLOATS:
    for i in ("si", "di", "ti"):
        add(f"__fix{f}{i}", i, [f], FLT + ".2")
        add(f"__fixuns{f}{i}", unsigned(i), [f], FLT + ".2")
        add(f"__float{i}{f}", f, [i], FLT + ".2")
        add(f"__floatun{i}{f}", f, [unsigned(i)], FLT + ".2")
# ---- 3.2.3 comparison (CMPtype) -------------------------------------------------
for f in ("sf", "df", "tf"):
    for op in ("cmp", "unord", "eq", "ne", "ge", "lt", "le", "gt"):
        add(f"__{op}{f}2", "cmp", [f, f], FLT + ".3")
# ---- 3.2.4 other ----------------------------------------------------------------
for f in FLOATS:
    add(f"__powi{f}2", f, [f, "si"], FLT + ".4")

# ---- RTABI: floating point ------------------------------------------------------
for name, ret, params in [
    ("dadd", "df", ["df", "df"]), ("ddiv", "df", ["df", "df"]), ("dmul", "df", ["df", "df"]),
    ("drsub", "df", ["df", "df"]), ("dsub", "df", ["df", "df"]),
    ("cdcmpeq", "void", ["df", "df"]), ("cdcmple", "void", ["df", "df"]), ("cdrcmple", "void", ["df", "df"]),
    ("dcmpeq", "si", ["df", "df"]), ("dcmplt", "si", ["df", "df"]), ("dcmple", "si", ["df", "df"]),
    ("dcmpge", "si", ["df", "df"]), ("dcmpgt", "si", ["df", "df"]), ("dcmpun", "si", ["df", "df"]),
    ("fadd", "sf", ["sf", "sf"]), ("fdiv", "sf", ["sf", "sf"]), ("fmul", "sf", ["sf", "sf"]),
    ("frsub", "sf", ["sf", "sf"]), ("fsub", "sf", ["sf", "sf"]),
    ("cfcmpeq", "void", ["sf", "sf"]), ("cfcmple", "void", ["sf", "sf"]), ("cfrcmple", "void", ["sf", "sf"]),
    ("fcmpeq", "si", ["sf", "sf"]), ("fcmplt", "si", ["sf", "sf"]), ("fcmple", "si", ["sf", "sf"]),
    ("fcmpge", "si", ["sf", "sf"]), ("fcmpgt", "si", ["sf", "sf"]), ("fcmpun", "si", ["sf", "sf"]),
    ("d2iz", "si", ["df"]), ("d2uiz", "usi", ["df"]), ("d2lz", "di", ["df"]), ("d2ulz", "udi", ["df"]),
    ("f2iz", "si", ["sf"]), ("f2uiz", "usi", ["sf"]), ("f2lz", "di", ["sf"]), ("f2ulz", "udi", ["sf"]),
    ("d2f", "sf", ["df"]), ("f2d", "df", ["sf"]),
    ("h2f", "sf", ["hi"]), ("h2f_alt", "sf", ["hi"]), ("f2h", "hi", ["sf"]), ("f2h_alt", "hi", ["sf"]),
    ("d2h", "hi", ["df"]), ("d2h_alt", "hi", ["df"]),
    ("i2d", "df", ["si"]), ("ui2d", "df", ["usi"]), ("l2d", "df", ["di"]), ("ul2d", "df", ["udi"]),
    ("i2f", "sf", ["si"]), ("ui2f", "sf", ["usi"]), ("l2f", "sf", ["di"]), ("ul2f", "sf", ["udi"]),
]:
    add(f"__aeabi_{name}", ret, params, ARM + " floating-point helpers")
# ---- RTABI: long long, integer division, unaligned access, memory -----------------
add("__aeabi_lmul", "di", ["di", "di"], ARM + " long long")
add("__aeabi_llsl", "di", ["di", "si"], ARM + " long long")
add("__aeabi_llsr", "di", ["di", "si"], ARM + " long long")
add("__aeabi_lasr", "di", ["di", "si"], ARM + " long long")
add("__aeabi_lcmp", "si", ["di", "di"], ARM + " long long")
add("__aeabi_ulcmp", "si", ["udi", "udi"], ARM + " long long")
add("__aeabi_idiv", "si", ["si", "si"], ARM + " integer division", ["numerator", "denominator"])
add("__aeabi_uidiv", "usi", ["usi", "usi"], ARM + " integer division", ["numerator", "denominator"])
add("__aeabi_idiv0", "si", ["si"], ARM + " integer division", ["return_value"])
add("__aeabi_ldiv0", "di", ["di"], ARM + " integer division", ["return_value"])
add("__aeabi_uread4", "si", ["void*"], ARM + " unaligned access", ["address"])
add("__aeabi_uwrite4", "si", ["si", "void*"], ARM + " unaligned access", ["value", "address"])
add("__aeabi_uread8", "di", ["void*"], ARM + " unaligned access", ["address"])
add("__aeabi_uwrite8", "di", ["di", "void*"], ARM + " unaligned access", ["value", "address"])
for suffix in ("8", "4", ""):
    add(f"__aeabi_memcpy{suffix}", "void", ["void*", "void*", "usize"], ARM + " memory", ["dest", "src", "n"])
    add(f"__aeabi_memmove{suffix}", "void", ["void*", "void*", "usize"], ARM + " memory", ["dest", "src", "n"])
    add(f"__aeabi_memset{suffix}", "void", ["void*", "usize", "si"], ARM + " memory", ["dest", "n", "c"])
    add(f"__aeabi_memclr{suffix}", "void", ["void*", "usize"], ARM + " memory", ["dest", "n"])
add("__aeabi_read_tp", "void*", [], ARM + " thread-local storage")

DOCUMENT = {
    "generator": "scripts/gen_runtime_helpers.py",
    "sources": [
        "GCC Internals, 'The GCC low-level runtime library', sections 3.1 and 3.2 "
        "(https://gcc.gnu.org/onlinedocs/gccint/Libgcc.html)",
        "Run-time ABI for the Arm Architecture, 2025Q4, Arm Limited, CC-BY-SA-4.0 "
        "(https://github.com/ARM-software/abi-aa/blob/main/rtabi32/rtabi32.rst)",
    ],
    "modes": "si/di/ti: 4/8/16-byte integer, u-prefixed unsigned; sf/df/xf/tf: floating point; hi: 2-byte "
             "integer; cmp: word-sized comparison result; usize: size_t; trailing '*': pointer; void, void*",
    "functions": rows,
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="fail if the committed file differs")
    arguments = parser.parse_args()
    text = json.dumps(DOCUMENT, sort_keys=True, indent=1) + "\n"
    if arguments.check:
        if not OUTPUT.is_file() or OUTPUT.read_text() != text:
            raise SystemExit(f"{OUTPUT.relative_to(ROOT)} differs from the generator")
        print(f"{OUTPUT.relative_to(ROOT)} matches ({len(rows)} routines)")
        return 0
    OUTPUT.write_text(text)
    print(f"wrote {OUTPUT.relative_to(ROOT)}: {len(rows)} routines")
    return 0


if __name__ == "__main__":
    sys.exit(main())
