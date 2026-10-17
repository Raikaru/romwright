#!/usr/bin/env python3
"""P4.1: psyq-style GTE macro lifting on a synthetic PlayStation executable.

The PSX language (`native/languages/psx`, `gte.sinc`) decodes COP2, so without
the lifter a function using the GTE prints one raw statement per `lwc2`,
`swc2`, `ctc2` and command (`VXY0 = *param_1;`, `gte_rtpt(1,0);`). The printer
IR pass `printc/gte.rs` folds them back into one call per macro
(`gte_ldv3(...)`, `gte_RTPT()`, `gte_stsxy3(...)`). This gate builds a PS-EXE
from encoded words (no compiler, no SDK: the words are the documented COP2
encodings of psx-spx, written here), decompiles every function twice -- with
`ROMWRIGHT_GTE_MACROS=0` and with the pass on -- and checks:

  1. each function's lifted text is exactly the expected macro calls;
  2. with the pass off the same function prints the raw statements, so the
     pass is the only difference (no GTE register statement remains lifted
     text, and no non-GTE line changes);
  3. a function of the RTPS/RTPT/NCLIP/AVSZ3 family that stock MIPS shows as
     8 or more raw instruction lines prints as at most 6 lines.

usage: tests/p4-1_gte_macros.py [--keep] [--json OUT]
env:   ROMWRIGHT_CLI (default target/release/romwright-cli),
       ROMWRIGHT_WORKER, ROMWRIGHT_GHIDRA_OPT (the build to test),
       ROMWRIGHT_GHIDRA (install holding the PSX language)
"""
import argparse
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CLI = Path(os.environ.get("ROMWRIGHT_CLI", ROOT / "target" / "release" / "romwright-cli"))
BASE = 0x80010000

# --------------------------------------------------------------- encodings
# psx-spx "Geometry Transformation Engine (GTE)": COP2 is primary opcode 0x12,
# lwc2/swc2 are 0x32/0x3a, and a command word has bit 25 set, sf in bit 19,
# mx 18:17, v 16:15, cv 14:13, lm bit 10 and the command number in 5:0.

R = {"zero": 0, "sp": 29, "v0": 2, "v1": 3, "a0": 4, "a1": 5, "a2": 6, "a3": 7, "t0": 8, "t1": 9,
     "t2": 10, "t3": 11, "t4": 12, "t5": 13, "t6": 14, "t7": 15, "ra": 31}
D = ["VXY0", "VZ0", "VXY1", "VZ1", "VXY2", "VZ2", "RGBC", "OTZ", "IR0", "IR1", "IR2", "IR3",
     "SXY0", "SXY1", "SXY2", "SXYP", "SZ0", "SZ1", "SZ2", "SZ3", "RGB0", "RGB1", "RGB2", "RES1",
     "MAC0", "MAC1", "MAC2", "MAC3", "IRGB", "ORGB", "LZCS", "LZCR"]
C = ["RT11RT12", "RT13RT21", "RT22RT23", "RT31RT32", "RT33", "TRX", "TRY", "TRZ", "L11L12",
     "L13L21", "L22L23", "L31L32", "L33", "RBK", "GBK", "BBK", "LR1LR2", "LR3LG1", "LG2LG3",
     "LB1LB2", "LB3", "RFC", "GFC", "BFC", "OFX", "OFY", "H", "DQA", "DQB", "ZSF3", "ZSF4", "FLAG"]
CMD = {"RTPS": 0x01, "NCLIP": 0x06, "OP": 0x0C, "DPCS": 0x10, "INTPL": 0x11, "MVMVA": 0x12,
       "NCDS": 0x13, "CDP": 0x14, "NCDT": 0x16, "NCCS": 0x1B, "CC": 0x1C, "NCS": 0x1E,
       "NCT": 0x20, "SQR": 0x28, "DCPL": 0x29, "DPCT": 0x2A, "AVSZ3": 0x2D, "AVSZ4": 0x2E,
       "RTPT": 0x30, "GPF": 0x3D, "GPL": 0x3E, "NCCT": 0x3F}
NOP = 0
JR_RA = 0x03E00008


def lwc2(reg, off, base): return (0x32 << 26) | (R[base] << 21) | (D.index(reg) << 16) | (off & 0xFFFF)
def swc2(reg, off, base): return (0x3A << 26) | (R[base] << 21) | (D.index(reg) << 16) | (off & 0xFFFF)
def lw(rt, off, base): return (0x23 << 26) | (R[base] << 21) | (R[rt] << 16) | (off & 0xFFFF)
def lui(rt, imm): return (0x0F << 26) | (R[rt] << 16) | imm
def addiu(rt, rs, imm): return (0x09 << 26) | (R[rs] << 21) | (R[rt] << 16) | (imm & 0xFFFF)
def mtc2(rt, reg): return (0x12 << 26) | (4 << 21) | (R[rt] << 16) | (D.index(reg) << 11)
def ctc2(rt, reg): return (0x12 << 26) | (6 << 21) | (R[rt] << 16) | (C.index(reg) << 11)
def mfc2(rt, reg): return (0x12 << 26) | (0 << 21) | (R[rt] << 16) | (D.index(reg) << 11)
def bgtz(rs, words): return (0x07 << 26) | (R[rs] << 21) | (words & 0xFFFF)  # offset in words from the delay slot


def cmd(name, sf=1, lm=0, mx=0, v=0, cv=0):
    return (0x12 << 26) | (1 << 25) | (sf << 19) | (mx << 17) | (v << 15) | (cv << 13) | (lm << 10) | CMD[name]


def ret(): return [JR_RA, NOP]


# --------------------------------------------------------------- functions
# name -> (words, expected lifted body lines). `params` are the registers the
# routine reads; the printer names them param_1, param_2, ...

FUNCTIONS = {}


def fn(name, words, lifted, stock_min=None):
    FUNCTIONS[name] = (words, lifted, stock_min)


# Three vertices through RTPT, the winding test, three screen positions, the
# average Z: ldv3 / RTPT / NCLIP / stsxy3 / AVSZ3 in a row.
fn("project_triangle",
   [lwc2("VXY0", 0, "a0"), lwc2("VZ0", 4, "a0"), lwc2("VXY1", 8, "a0"), lwc2("VZ1", 12, "a0"),
    lwc2("VXY2", 16, "a0"), lwc2("VZ2", 20, "a0"), NOP, NOP,
    cmd("RTPT"), cmd("NCLIP", sf=0),
    swc2("SXY0", 0, "a1"), swc2("SXY1", 8, "a1"), swc2("SXY2", 16, "a1"),
    cmd("AVSZ3"), mfc2("v0", "OTZ")] + ret(),
   ["gte_ldv3(param_1,&param_1[2],&param_1[4]);", "gte_RTPT();", "gte_NCLIP();",
    "gte_stsxy3(param_2,&param_2[2],&param_2[4]);", "gte_AVSZ3();", "return OTZ;"],
   stock_min=8)

# One vertex through RTPS: its screen position, depth, interpolation factor
# and the ordering-table Z, each stored through its own pointer.
fn("project_vertex",
   [lwc2("VXY0", 0, "a0"), lwc2("VZ0", 4, "a0"), NOP, NOP, cmd("RTPS"),
    swc2("SXY2", 0, "a1"), swc2("SZ3", 0, "a2"), swc2("IR0", 0, "a3"), swc2("OTZ", 0, "a0")] + ret(),
   ["gte_ldv0(param_1);", "gte_RTPS();", "gte_stsxy(param_2);", "gte_stsz(param_3);",
    "gte_stdp(param_4);", "gte_stotz(param_1);"],
   stock_min=8)

# Four depths through AVSZ4, the ordering-table index stored.
fn("average_depth4",
   [lwc2("SZ0", 0, "a0"), lwc2("SZ1", 4, "a0"), lwc2("SZ2", 8, "a0"), lwc2("SZ3", 12, "a0"),
    NOP, NOP, cmd("AVSZ4"), swc2("OTZ", 0, "a1")] + ret(),
   ["gte_ldsz4(param_1,&param_1[1],&param_1[2],&param_1[3]);", "gte_AVSZ4();", "gte_stotz(param_2);"])

# Lighting: a colour in, NCDS (sf=1, lm=1), the result colour out; then a
# matrix-vector multiply and its three unlimited results.
fn("light_vertex",
   [lwc2("VXY0", 0, "a0"), lwc2("VZ0", 4, "a0"), lwc2("RGBC", 0, "a1"), NOP, NOP,
    cmd("NCDS", sf=1, lm=1), swc2("RGB2", 0, "a2"),
    cmd("MVMVA", sf=1, mx=0, v=0, cv=0, lm=0),
    swc2("MAC1", 0, "a3"), swc2("MAC2", 4, "a3"), swc2("MAC3", 8, "a3")] + ret(),
   ["gte_ldv0(param_1);", "gte_ldrgb(param_2);", "gte_NCDS(1,1);", "gte_strgb(param_3);",
    "gte_MVMVA(1,0,0,0,0);", "gte_stlvnl(param_4);"])

# The rotation matrix and the translation vector from one structure.
fn("load_transform",
   [lw("t0", 0, "a0"), lw("t1", 4, "a0"), lw("t2", 8, "a0"), lw("t3", 12, "a0"), lw("t4", 16, "a0"),
    lw("t5", 20, "a0"), lw("t6", 24, "a0"), lw("t7", 28, "a0"),
    ctc2("t0", "RT11RT12"), ctc2("t1", "RT13RT21"), ctc2("t2", "RT22RT23"),
    ctc2("t3", "RT31RT32"), ctc2("t4", "RT33"),
    ctc2("t5", "TRX"), ctc2("t6", "TRY"), ctc2("t7", "TRZ")] + ret(),
   ["gte_SetRotMatrix(param_1);", "gte_SetTransMatrix(param_1);"],
   stock_min=8)

# Absolute addresses: the arguments are the globals' addresses.
fn("global_vertex",
   [lui("t0", 0x8012), lwc2("VXY0", 0x3450, "t0"), lwc2("VZ0", 0x3454, "t0"), NOP, NOP,
    cmd("RTPS"), lui("t1", 0x8012), swc2("SXY2", 0x3460, "t1")] + ret(),
   ["gte_ldv0(&uRam80123450);", "gte_RTPS();", "gte_stsxy(&uRam80123460);"])

# What is not a macro stays as written: a register moved in from a GPR, a
# command with the non-default flags, a lone half of a vertex.
fn("left_as_written",
   [mtc2("a0", "VXY0"), cmd("RTPT", sf=0, lm=1), lwc2("VZ1", 8, "a1"), NOP, NOP,
    cmd("NCLIP", sf=0)] + ret(),
   ["VXY0 = param_1;", "gte_RTPT(0,1);", "gte_ldvz1((unsigned int *)(param_2 + 8));", "gte_NCLIP();"])

# A loop around a vertex: the macros are inside the loop body.
fn("project_array",
   [lwc2("VXY0", 0, "a0"), lwc2("VZ0", 4, "a0"), NOP, NOP, cmd("RTPS"),
    swc2("SXY2", 0, "a1"), addiu("a0", "a0", 8), addiu("a1", "a1", 4), addiu("a2", "a2", -1),
    bgtz("a2", -10 & 0xFFFF), NOP] + ret(),
   None)


def sw(rt, off, base): return (0x2B << 26) | (R[base] << 21) | (R[rt] << 16) | (off & 0xFFFF)
def jal(address): return (0x03 << 26) | ((address >> 2) & 0x03FFFFFF)


def build(work: Path):
    """The PS-EXE and each function's address. The entry saves `ra`, calls
    every function in turn (so flow discovery finds each one) and returns."""
    entry_words = 2 + 2 * len(FUNCTIONS) + 5
    words = [NOP] * entry_words
    addresses = {}
    for name, (body_words, _, _) in FUNCTIONS.items():
        addresses[name] = BASE + 4 * len(words)
        words.extend(body_words)
    entry = [addiu("sp", "sp", -8), sw("ra", 4, "sp")]
    for name in FUNCTIONS:
        entry += [jal(addresses[name]), NOP]
    entry += [lw("ra", 4, "sp"), JR_RA, addiu("sp", "sp", 8)]
    entry += [NOP] * (entry_words - len(entry))
    assert len(entry) == entry_words
    words[0:entry_words] = entry
    image = b"".join(struct.pack("<I", w & 0xFFFFFFFF) for w in words)
    header = bytearray(0x800)
    header[0:8] = b"PS-X EXE"
    struct.pack_into("<I", header, 0x10, BASE)         # initial PC
    struct.pack_into("<I", header, 0x18, BASE)         # destination
    struct.pack_into("<I", header, 0x1C, len(image))   # image size
    struct.pack_into("<I", header, 0x30, 0x801FFF00)   # stack base
    exe = work / "gte.exe"
    exe.write_bytes(bytes(header) + image)
    return exe, addresses


def run(args, env=None, check=True):
    result = subprocess.run([str(CLI)] + args, capture_output=True, text=True,
                            env={**os.environ, **(env or {})}, cwd=ROOT)
    if check and result.returncode:
        raise SystemExit(f"{' '.join(args)}: {result.stderr.strip()[-600:]}")
    return result.stdout


def body(text: str):
    """The statement lines between the braces, stripped."""
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if line.strip() == "{")
    end = max(i for i, line in enumerate(lines) if line.strip() == "}")
    statements = [line.strip() for line in lines[start + 1:end] if line.strip()]
    # A trailing bare `return;` is the function end, not a statement under test.
    return statements[:-1] if statements[-1:] == ["return;"] else statements


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--json", type=Path)
    options = parser.parse_args()
    work = Path(tempfile.mkdtemp(prefix="p4-1-"))
    failures, rows = [], []
    try:
        exe, addresses = build(work)
        project = work / "project"
        run(["import", str(exe), "--name", "psx", "--project", str(project)],
            env={"ROMWRIGHT_NO_IMPORT_CACHE": "1"})
        for name, (words, lifted, stock_min) in FUNCTIONS.items():
            address = f"{addresses[name]:#x}"
            out = {}
            for mode in ("0", "1"):
                out[mode] = body(run(["decompile", str(exe), address, "--name", "psx",
                                      "--project", str(project)],
                                     env={"ROMWRIGHT_GTE_MACROS": mode}))
            raw, got = out["0"], out["1"]
            # Instructions a stock MIPS disassembly shows: every word but the
            # delay-slot and load-delay nops.
            shown = sum(1 for w in words if w != NOP)
            row = {"function": name, "address": address, "stock_instruction_lines": shown,
                   "raw_statement_lines": len(raw), "lifted_lines": len(got), "lifted": got}
            rows.append(row)
            if lifted is not None and got != lifted:
                failures.append(f"{name}: lifted {got} != expected {lifted}")
            gte_register = re.compile(r"\b(" + "|".join(D + C) + r")\b(?!\()")
            if lifted is not None and name != "left_as_written":
                if any(gte_register.search(line) and not line.startswith("return") for line in got):
                    failures.append(f"{name}: a raw GTE register statement remains: {got}")
            if not any(gte_register.search(line) or "gte_" in line for line in raw):
                failures.append(f"{name}: pass off prints no GTE statement: {raw}")
            if stock_min is not None:
                if shown < stock_min:
                    failures.append(f"{name}: stock MIPS shows {shown} lines, fixture is under {stock_min}")
                if len(got) > 6 or len(raw) < stock_min - 2:
                    failures.append(f"{name}: {len(raw)} raw -> {len(got)} lifted statement lines")
            if name == "project_array":
                joined = "\n".join(got)
                for needle in ("gte_ldv0(", "gte_RTPS();", "gte_stsxy("):
                    if needle not in joined:
                        failures.append(f"{name}: no `{needle}` in the loop body: {got}")
                if gte_register.search(joined.replace("gte_", "")) and "VXY0" in joined:
                    failures.append(f"{name}: raw GTE statement left in the loop: {got}")
            # the non-GTE lines are identical with the pass on and off
            keep = lambda lines: [l for l in lines if not (gte_register.search(l) or "gte_" in l)]
            if keep(raw) != keep(got):
                failures.append(f"{name}: non-GTE lines differ: {keep(raw)} vs {keep(got)}")
        print(f"{'function':<20}{'stock insn':>11}{'raw stmts':>10}{'lifted':>8}")
        for row in rows:
            print(f"{row['function']:<20}{row['stock_instruction_lines']:>11}"
                  f"{row['raw_statement_lines']:>10}{row['lifted_lines']:>8}")
        if options.json:
            options.json.write_text(json.dumps(rows, indent=2) + "\n")
    finally:
        if not options.keep:
            shutil.rmtree(work, ignore_errors=True)
        else:
            print("kept", work)
    if failures:
        print("\nFAIL")
        for failure in failures:
            print(" -", failure)
        sys.exit(1)
    print("\nPASS: every function prints its expected macro calls; the pass is the only difference")


if __name__ == "__main__":
    main()
