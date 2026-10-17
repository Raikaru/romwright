#!/usr/bin/env python3
"""Compile one C unit the way the AGB SDK's compiler is driven: cc.py OUT SRC

    cpp (arm-none-eabi-cpp, -nostdinc -undef, agbcc's include directory) | agbcc <cflags> | as

agbcc is GCC 2.95-derived and only compiles C: it reads preprocessed source
and writes assembly. Tool paths come from build/tools.json, flags from
config/project.json (compiler.cflags, compiler.asflags).
"""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main():
    out, source = sys.argv[1:3]
    paths = json.loads((ROOT / "build" / "tools.json").read_text())
    project = json.loads((ROOT / "config" / "project.json").read_text())
    cflags = project["compiler"]["cflags"]
    asflags = project["compiler"]["asflags"]
    cpp = subprocess.run(
        [paths["cpp"], "-nostdinc", "-undef", "-I", paths["agbcc_include"], "-iquote", "include", source],
        capture_output=True, cwd=ROOT,
    )
    if cpp.returncode != 0:
        sys.stderr.buffer.write(cpp.stderr)
        return cpp.returncode
    asm_path = Path(out).with_suffix(".s")
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    cc = subprocess.run([paths["agbcc"], *cflags, "-o", str(asm_path)], input=cpp.stdout, capture_output=True, cwd=ROOT)
    sys.stderr.buffer.write(cc.stderr)
    if cc.returncode != 0:
        return cc.returncode
    # pret appends this too: the unit ends on a word boundary with zero fill, as the retail slot's padding is
    # (without it `as` pads the section end with Thumb nops).
    with open(asm_path, "a") as handle:
        handle.write("\t.align 2, 0\n")
    asm = subprocess.run([paths["as"], *asflags, "-o", out, str(asm_path)], capture_output=True, cwd=ROOT)
    sys.stderr.buffer.write(asm.stderr)
    return asm.returncode


sys.exit(main())
