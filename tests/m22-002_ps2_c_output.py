#!/usr/bin/env python3
"""M22-002: decompiled C against matched Persona 4 (PS2) sources.

The PS2 counterpart of m22-001 (pokeemerald, GBA). A fixed, seeded sample of
the Persona 4 decompilation's matched functions is decompiled by each tool,
each candidate is compiled with the compiler the function's translation unit
is built with, and the result is scored against the retail bytes.

Matched function: a function `tools/verify.py` of the decompilation reports
MATCH (compiled from C, byte-identical to the retail SLUS_217.82 modulo
relocation fields, zero padding after it). The repo, its commit and its
toolchain (MWCCPS2 3.0.1 b210 / b119 under wibo, GNU r5900 assembler) are
pinned below; the harness clones the repo itself, runs the repo's own
`setup`, `split`, `regenerate-asm` and `verify` steps, and stops with the
missing prerequisite if any of them cannot run.

Candidates (layers):

  romwright  `romwright-cli export-c` on the stripped retail ELF. The program
             is imported once; function names are asserted from the repo's
             `config/symbol_addrs.txt` (`assert-names`), and the prototypes of
             the target and of its callees are asserted from the unit's own
             declarations (`assert-prototypes`, types erased to Ghidra
             primitives and `void *`, the m22-001 rule).
  m2c        the pip `m2c` run as an external tool, `-t mipsee-mwcc-c
             --valid-syntax --context <context>`, on the function's splat
             assembly from the repo's `asm/code*.s`. Mechanical edits only,
             recorded per function: gp-relative operands become
             `%gp_rel(symbol)($gp)` (the symbol information m2c gets from
             object relocations in m22-001; here from the repo symbol table)
             and jump tables are added from the retail image.
  stock      stock Ghidra 12.1.3 headless on the same ELF (`-processor
             r5900:LE:32:default`, default auto-analysis), decompiled with
             `scripts/ExportDecompiledC.java` (the C text plus an `extern` line per global
             symbol the text names, typed as Ghidra types it); the function is
             created at the address when auto-analysis did not find it. The
             decompiled name is replaced by the target's name, and a fixed
             typedef header for Ghidra's primitive names is prepended.

Context rule (one shared context per function, same for every layer): the
unit's own declarations as the compiler sees them -- `mwccps2 -E` of the
unit, reduced to typedefs, struct/union/enum definitions, `extern` and
function declarations, with every data definition turned into an `extern`
declaration and every function definition into a prototype -- plus the
`#pragma` lines in force at the target (optimisation level, scheduling:
per-function compiler configuration, replayed from the unit's source in
order). The unit's own text for the target itself is never part of the
context; its prototype is, as in m22-001.

Every candidate is compiled twice through the repo's `mwccgap` driver with the
unit's compiler and flags (`tools/verify.py` helpers: b210 default, b119 for
`config/compiler_units.txt`, `,p` for `config/speed_units.txt`):

  context     prelude + context + pragmas + m2c macros + candidate (headline)
  standalone  prelude + pragmas + m2c macros + candidate
  best        per function, the better of the two (compiled in either, exact in
              either, the higher percent): reported beside the headline, because
              a type mismatch against the unit's declarations fails a context
              compile that the same text passes standalone

and scored against the retail bytes of the function:

  exact       verify.py's MATCH criterion: same length, every byte equal
              outside relocation fields, zero padding after (the retail
              window); `exact_symbols` additionally requires every
              relocation's symbol+addend to resolve to the retail operand
              (verify.py's wrong_symbol_relocations).
  percent     objdiff-cli 3.6.1 `match_percent` of the target-side symbol
              (`functionRelocDiffs=none`, the repo's own objdiff
              convention: retail bytes carry no relocations).

A candidate that is missing, fails to compile, or does not define the target
symbol scores 0 and counts in the compile-failure share.

Function selection (fixed, deterministic): MATCH rows of the verify report, 32
to 1024 bytes, whose definition is found in the preprocessed unit and has no
inline assembly; the rows are shuffled with `random.Random(SEED)` after
sorting by address and the first N accepted rows are the sample. Two lanes:

  --compiler mwcc   (default) the units MWCCPS2 builds (not config/gcc_units.txt)
  --compiler eegcc  the units retail built with ee-gcc 2.96 (config/gcc_units.txt:
                    the CRI ADX/SFD/ACS middleware, Sony SDK). The context is
                    `ee-gcc -E` of the unit (INCLUDE_ASM removed), candidates are
                    compiled with the repo's tools/eegcc_shim.py (`-O2 -G0`, GNU
                    as 2.12-ee) and m2c runs as `-t mipsee-gcc-c`. ee-gcc and the
                    assembler are i386 ELFs with a fixed /lib/ld-linux.so.2: where
                    the host has no such loader the harness re-executes itself in
                    a bubblewrap mount namespace that supplies the user's 32-bit
                    glibc (`--glibc32`, default ~/opt/glibc32/usr/lib) at that
                    path; nothing on the host is written.

Exit status is non-zero only if the harness itself breaks, never because a
layer scores low. One command (see docs/console-research.md, "m22-002"):

    python3 tests/m22-002_ps2_c_output.py
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import random
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

HOME = Path.home()
REPO = Path(__file__).resolve().parent.parent

P4_URL = "https://github.com/Raikaru/Persona4-Decompilation.git"
P4_COMMIT = "509519da5809d4958d55520e7d257b75cb69cd51"
P4_ELF_SHA1 = "4eeec0360cf2715535d9f7e52eb69d786fb0158c"
TOOLCHAIN = Path("/var/tmp/p4ci")
GHIDRA = Path(os.environ.get("ROMWRIGHT_GHIDRA") or HOME / "ghidra_12.1.3_PUBLIC")
OBJDIFF = Path(os.environ.get("OBJDIFF_CLI") or HOME / "Projects/agent-under-fire/dtk-template/build/tools/objdiff-cli")
GHIDRA_SCRIPTS = REPO / "scripts"
M2C_MACROS_URL = "https://raw.githubusercontent.com/matt-kempster/m2c/{commit}/m2c_macros.h"
DEFAULT_WORK = HOME / ".cache" / "romwright" / "m22-ps2"
DEFAULT_REPORT = REPO / "benchmarks" / "reports" / "m22-ps2_p4.json"
PROGRAM = "p4usa"
SEED = 20261010
SAMPLE = 200
SIZE_MIN, SIZE_MAX = 32, 1024
GP = 0x007690F0
IMAGE_VRAM = 0x00100000
LAYERS = ("romwright", "m2c", "stock")
VARIANTS = ("context", "standalone")
REPORTED = ("context", "standalone", "best")
GHIDRA_LANGUAGE = "r5900:LE:32:default"
STOCK_TIMEOUT = 3600
GLIBC32 = Path(os.environ.get("P4_EEGCC_LD_LIBRARY_PATH") or HOME / "opt" / "glibc32" / "usr" / "lib")
DEFAULT_EE_REPORT = REPO / "benchmarks" / "reports" / "m22-ps2_p4_eegcc.json"
SANDBOX_MARK = "M22_EE_SANDBOX"
COMPILERS = ("mwcc", "eegcc")


class HarnessError(Exception):
    """The measurement itself is broken (not a candidate losing)."""


def log(message):
    print(message, file=sys.stderr, flush=True)


def run(argv, *, timeout=600, env=None, cwd=None, input_text=None):
    started = time.monotonic()
    try:
        result = subprocess.run([str(a) for a in argv], capture_output=True, text=True,
                                timeout=timeout, env=env, cwd=cwd, input=input_text)
        exit_code, stdout, stderr = result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired as error:
        exit_code, stdout, stderr = -9, error.stdout or "", f"timeout after {timeout}s"
        stdout = stdout.decode(errors="replace") if isinstance(stdout, bytes) else stdout
    return {"argv": [str(a) for a in argv], "exit": exit_code, "stdout": stdout,
            "stderr": stderr, "seconds": round(time.monotonic() - started, 3)}


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# C structure: top-level chunks of a preprocessed translation unit
# ---------------------------------------------------------------------------

def mask_c(text):
    """`text` with comments and the insides of string/char literals blanked
    (same length, newlines kept), for structural scanning."""
    out = list(text)
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            end = text.find("*/", i + 2)
            end = n if end == -1 else end + 2
            for k in range(i, end):
                if out[k] != "\n":
                    out[k] = " "
            i = end
        elif c == "/" and i + 1 < n and text[i + 1] == "/":
            end = text.find("\n", i)
            end = n if end == -1 else end
            for k in range(i, end):
                out[k] = " "
            i = end
        elif c in "\"'":
            k = i + 1
            while k < n and text[k] != c:
                k += 2 if text[k] == "\\" else 1
            for m in range(i + 1, min(k, n)):
                if out[m] != "\n":
                    out[m] = " "
            i = k + 1
        else:
            i += 1
    return "".join(out)


KNR_HEAD = re.compile(r"^\s*[^;{}=()]*\b\w+\s*\(\s*\w+(\s*,\s*\w+)*\s*\)\s*[A-Za-z_]")
FUNCDEF_NAME = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
KEYWORDS = {"if", "for", "while", "switch", "return", "sizeof", "typedef", "struct", "union", "enum",
            "static", "extern", "const", "volatile", "inline", "register", "unsigned", "signed"}


def split_chunks(text):
    """Top-level chunks of C text: dicts with kind (`pp`, `funcdef`, `decl`), text,
    masked text, the start offset, and for a function definition its name,
    head (return type and parameters) and body span."""
    masked = mask_c(text)
    chunks, i, n = [], 0, len(text)
    while i < n:
        while i < n and masked[i].isspace():
            i += 1
        if i >= n:
            break
        start = i
        if masked[i] == "#":
            j = i
            while True:
                e = text.find("\n", j)
                if e == -1:
                    e = n
                    break
                if e > 0 and text[e - 1] == "\\":
                    j = e + 1
                    continue
                break
            chunks.append({"kind": "pp", "text": text[start:e], "masked": masked[start:e], "start": start})
            i = e + 1
            continue
        paren = brace = 0
        first_brace = None
        knr = False
        j = i
        while j < n:
            c = masked[j]
            if c in "([":
                paren += 1
            elif c in ")]":
                paren -= 1
            elif c == "{":
                if brace == 0 and first_brace is None:
                    first_brace = j
                brace += 1
            elif c == "}":
                brace -= 1
                if brace == 0 and paren == 0 and first_brace is not None:
                    head = masked[start:first_brace].strip()
                    if (head.endswith(")") or knr) and "=" not in head and not head.startswith("typedef"):
                        j += 1
                        break
            elif c == ";" and brace == 0 and paren == 0:
                if first_brace is None and KNR_HEAD.match(masked[start:j]):
                    knr = True
                else:
                    j += 1
                    break
            j += 1
        chunk = {"text": text[start:j], "masked": masked[start:j], "start": start}
        head = masked[start:first_brace].strip() if first_brace is not None else ""
        if first_brace is not None and (head.endswith(")") or knr) and "=" not in head \
                and not head.startswith("typedef") and chunk["masked"].rstrip().endswith("}"):
            chunk["kind"] = "funcdef"
            found = FUNCDEF_NAME.search(head)
            chunk["name"] = found.group(1) if found else None
            if knr and found:
                close = match_paren(text, start + found.end() - 1)
                chunk["head"] = text[start:close + 1].strip()
                chunk["knr"] = True
            else:
                chunk["head"] = text[start:first_brace].strip()
            chunk["body"] = text[first_brace:j]
        else:
            chunk["kind"] = "decl"
        chunks.append(chunk)
        i = j
    return chunks


def match_paren(text, opening):
    depth = 0
    for index in range(opening, len(text)):
        depth += text[index] == "("
        depth -= text[index] == ")"
        if depth == 0:
            return index
    return -1


def split_params(text):
    params, depth, current = [], 0, ""
    for char in text:
        if char == "," and depth == 0:
            params.append(current.strip())
            current = ""
            continue
        depth += char == "("
        depth -= char == ")"
        current += char
    if current.strip():
        params.append(current.strip())
    return params


def squash(text):
    return " ".join(text.split())


def declaration_text(chunk):
    """The context text a declaration chunk contributes, or None.

    Typedefs, tag definitions and `extern`/function declarations are kept; a
    data definition (initialised or not) becomes an `extern` declaration and a
    function definition a prototype (so a unit's own gp variables keep their
    declared size, which decides small-data addressing)."""
    masked = squash(chunk["masked"])
    if chunk["kind"] == "funcdef":
        head = re.sub(r"\basm\b\s*", "", squash(chunk["head"]))
        head = re.sub(r"^(static|inline|extern)\s+", "", head)
        head = re.sub(r"^(static|inline)\s+", "", head)
        if chunk.get("knr"):
            head = re.sub(r"\(.*\)\s*$", "()", head, flags=re.S)
        return head + ";"
    if not masked.endswith(";"):
        return None
    text = squash(chunk["text"])
    if masked.startswith("typedef"):
        return text
    if re.match(r"(struct|union|enum)\b[^=()]*(\{|;)", masked) and "=" not in masked.split("{")[0]:
        return text
    if masked.startswith("extern"):
        return text if "=" not in masked.split("{")[0] else re.sub(r"\s*=.*$", ";", text)
    # data definition or prototype
    top = masked.split("{")[0]
    if "=" in top:
        return externalise(text[:top.index("=")].rstrip())
    if "(" in top and not re.match(r"^[^()]*\(\s*\*", top):
        return re.sub(r"^static\s+", "", text)
    return externalise(text.rstrip(";").rstrip())


def externalise(declarator):
    declarator = declarator.strip()
    if len(declarator.replace("static", " ").split()) < 2:
        return None
    if "," in re.sub(r"\([^)]*\)|\[[^\]]*\]|\{[^}]*\}", "", declarator):
        return None
    declarator = re.sub(r"^static\s+", "", declarator)
    if declarator.startswith("extern"):
        return declarator + ";"
    return "extern " + declarator + ";"


def strip_attributes(text):
    """`text` without its `__attribute__((...))` groups: `T d[] __attribute__((aligned(8)))` is a data
    declarator, not a function named `__attribute__` taking `(aligned(8))`."""
    while True:
        found = re.search(r"__attribute__\s*\(", text)
        if not found:
            return text
        closing = match_paren(text, found.end() - 1)
        if closing == -1:
            return text[:found.start()].rstrip()
        text = (text[:found.start()].rstrip() + " " + text[closing + 1:].lstrip()).strip()


def prototype_of(chunk):
    """(return type, parameter text, name) of a function definition or declaration chunk, or None."""
    text = re.sub(r"\basm\b\s*", "", squash(chunk.get("head") or chunk["masked"]))
    text = re.sub(r"^(static|inline|extern)\s+", "", text).rstrip(";")
    text = strip_attributes(text)
    if chunk.get("knr"):
        text = re.sub(r"\(.*\)\s*$", "()", text)
    found = FUNCDEF_NAME.search(text)
    if not found or found.group(1) in KEYWORDS or text.lstrip().startswith("typedef"):
        return None
    opening = found.end() - 1
    closing = match_paren(text, opening)
    if closing == -1 or text[closing + 1:].strip():
        return None
    return text[:found.start()].strip(), text[opening + 1:closing].strip(), found.group(1)


# ---------------------------------------------------------------------------
# Types for asserted prototypes (Ghidra primitives, struct pointers erased)
# ---------------------------------------------------------------------------

GHIDRA_PRIMITIVES = {
    "void": "void", "char": "char", "signed char": "sbyte", "unsigned char": "byte",
    "short": "short", "signed short": "short", "unsigned short": "ushort", "int": "int", "signed int": "int",
    "signed": "int", "unsigned": "uint", "unsigned int": "uint", "long": "int", "signed long": "int",
    "unsigned long": "uint", "long long": "longlong", "signed long long": "longlong",
    "unsigned long long": "ulonglong", "float": "float", "double": "double",
}
QUALIFIERS = {"const", "volatile", "static", "extern", "inline", "register"}


def update_typedefs(table, masked):
    """Record a simple typedef (`typedef <type> <name>;`) or a function-pointer typedef (a pointer to an unnamed struct)."""
    text = squash(masked)
    found = re.fullmatch(r"typedef\s+(.+?)(?:\s+|(?<=\*)\s*)(\w+)\s*;", text)
    if found and "(" not in text and "{" not in text:
        table[found.group(2)] = found.group(1)
        return
    pointer = re.fullmatch(r"typedef\s+.*\(\s*\*\s*(\w+)\s*\).*;", text)
    if pointer:
        table[pointer.group(1)] = "struct __function *"


def typedef_table(context):
    table = {}
    for chunk in split_chunks(context):
        update_typedefs(table, chunk["masked"])
    return table


PRIMITIVE_WORDS = {"char", "short", "int", "long", "unsigned", "signed", "float", "double", "void"}


def analyse_type(type_text, typedefs, depth=0):
    """(resolves to a C primitive, pointer depth) of a type, following typedefs."""
    words = type_text.replace("*", " * ").split()
    pointers = words.count("*")
    core = [w for w in words if w != "*" and w not in QUALIFIERS]
    if not core or core[0] in ("struct", "union", "enum"):
        return False, pointers
    if all(w in PRIMITIVE_WORDS for w in core):
        return True, pointers
    if len(core) == 1 and core[0] in typedefs and depth < 8:
        primitive, inner = analyse_type(typedefs[core[0]], typedefs, depth + 1)
        return primitive, pointers + inner
    return False, pointers


def erase_c_type(type_text, typedefs):
    """The context rule's spelling of a type (m22-001): pointers to anything but integer/float typedefs and
    primitives become `void *`, qualifiers are dropped, everything else keeps its spelling."""
    primitive, pointers = analyse_type(type_text, typedefs)
    words = [w for w in type_text.replace("*", " * ").split() if w not in ("const", "volatile")]
    if pointers and not primitive:
        return "void " + "*" * pointers
    return " ".join(words).replace(" *", " *").replace("* *", "**")


def erase_prototype(proto, typedefs):
    ret, params, name = proto
    if not params.strip():
        return erase_c_type(ret, typedefs), "", name
    rows = []
    for param in split_params(params):
        if param in ("", "void", "..."):
            rows.append(param)
            continue
        if "(" in param:
            found = re.search(r"\(\s*\*\s*(\w*)\s*\)", param)
            rows.append("void *" + (found.group(1) if found else ""))
            continue
        found = re.fullmatch(r"(.*?)(\w+)\s*((?:\[[^\]]*\])*)", param)
        base, pname, dims = (found.group(1), found.group(2), found.group(3)) if found and found.group(1).strip() else (param, "", "")
        erased = erase_c_type(base + (" *" if dims else ""), typedefs)
        rows.append(f"{erased} {pname}".strip() if not erased.endswith("*") else f"{erased}{pname}")
    return erase_c_type(ret, typedefs), ", ".join(r for r in rows if r) or "void", name


def erase_extern(text, typedefs):
    """`extern T *name;` with T a struct/typedef'd aggregate: `extern void *name;`"""
    found = re.fullmatch(r"extern\s+([^()=\[\]]*?)(\*+)\s*(\w+)\s*;", text)
    if not found:
        return text
    primitive, pointers = analyse_type(found.group(1) + found.group(2), typedefs)
    return text if primitive else f"extern void {'*' * pointers}{found.group(3)};"


def erase_type(type_text, typedefs, depth=0):
    """Ghidra type text for a C type, or None when it cannot be spelled."""
    text = " ".join(type_text.replace("*", " * ").split())
    words = [w for w in text.split() if w not in QUALIFIERS]
    pointers = words.count("*")
    core = [w for w in words if w != "*"]
    if not core:
        return None
    if core[0] in ("struct", "union", "enum"):
        return "void *" if pointers else None
    joined = " ".join(w for w in core if w != "int" or len(core) == 1 or core[0] in ("signed", "unsigned") and len(core) == 2)
    joined = {"short int": "short", "long int": "long", "unsigned short int": "unsigned short",
              "unsigned long int": "unsigned long", "long long int": "long long"}.get(" ".join(core), joined)
    if joined in GHIDRA_PRIMITIVES:
        return GHIDRA_PRIMITIVES[joined] + " *" * pointers
    if len(core) == 1 and core[0] in typedefs and depth < 8:
        inner = erase_type(typedefs[core[0]], typedefs, depth + 1)
        if inner is None:
            return "void *" + " *" * (pointers - 1) if pointers else None
        return inner + " *" * pointers
    known = {"u8": "byte", "s8": "sbyte", "u16": "ushort", "s16": "short", "u32": "uint", "s32": "int",
             "u64": "ulonglong", "s64": "longlong", "f32": "float", "f64": "double", "size_t": "uint"}
    if len(core) == 1 and core[0] in known:
        return known[core[0]] + " *" * pointers
    return "void *" + " *" * (pointers - 1) if pointers else None


def asserted_signature(proto, typedefs):
    ret, params, name = proto
    if not params.strip():
        return None, "unspecified parameters"
    return_type = erase_type(ret, typedefs)
    if return_type is None:
        return None, f"return type {ret!r}"
    rows = []
    for index, param in enumerate(p for p in split_params(params) if p not in ("", "void")):
        if param == "...":
            rows.append("...")
            continue
        if "(" in param:
            rows.append(f"void * param_{index + 1}")
            continue
        found = re.fullmatch(r"(.*?)(\w+)\s*((?:\[[^\]]*\])*)", param)
        base, dims = (found.group(1), found.group(3)) if found and found.group(1).strip() else (param, "")
        if dims:
            base += " *"
        erased = erase_type(base, typedefs)
        if erased is None:
            return None, f"parameter {param!r}"
        rows.append(f"{erased.replace('* *', '**')} param_{index + 1}")
    return f"{return_type.replace('* *', '**')} {name}({', '.join(rows) if rows else 'void'})", None


# ---------------------------------------------------------------------------
# Repository, toolchain, verify
# ---------------------------------------------------------------------------

def write_wrappers(work, toolchain):
    bindir = work / "bin"
    bindir.mkdir(parents=True, exist_ok=True)
    scripts = {"mwcc.sh": toolchain / "mwccps2.exe", "mwcc-b119.sh": toolchain / "cw3.0.1b119" / "mwccps2.exe",
               "mwld.sh": toolchain / "mwldps2.exe"}
    for name, exe in scripts.items():
        path = bindir / name
        path.write_text(f'#!/bin/sh\nexec wibo "{exe}" "$@"\n')
        path.chmod(0o755)
    return bindir


def system_objcopy():
    """The distribution's MIPS objcopy, as the repo's Dockerfile pins Debian's (the decompals one can leave an
    invalid .symtab sh_info on the objects the repo's tools rewrite)."""
    for path in ("/usr/bin/mipsel-linux-gnu-objcopy", "/usr/bin/mips64-linux-gnu-objcopy", "/usr/bin/mips-linux-gnu-objcopy"):
        if Path(path).is_file():
            return path
    return shutil.which("mipsel-linux-gnu-objcopy") or ""


def p4_env(work, toolchain, bindir, eegcc=None):
    """The repo's tool environment. `eegcc` (the directory of the 32-bit glibc) additionally configures the
    repo's ee-gcc 2.96 shim, ee-gcc itself and the EE assembler, which the MWCC lane never sees."""
    env = dict(os.environ)
    tmp = work / "tmp"
    tmp.mkdir(parents=True, exist_ok=True)
    env.update(
        P4_MWCC=str(bindir / "mwcc.sh"), P4_MWCC_CW3_0_1B119=str(bindir / "mwcc-b119.sh"),
        P4_RETAIL_ELF=str(toolchain / "SLUS_217.82"),
        P4_AS=os.environ.get("P4_AS") or shutil.which("mipsel-linux-gnu-as") or "",
        P4_OBJCOPY=os.environ.get("P4_OBJCOPY") or system_objcopy(),
        TMPDIR=str(tmp))
    for key in ("P4_EEGCC_ROOT", "P4_EEGCC_AS", "P4_EEGCC_LD_LIBRARY_PATH"):
        env.pop(key, None)
    if eegcc:
        env.update(P4_EEGCC_ROOT=str(toolchain / "ee-gcc-2.96"), P4_EEGCC_AS=str(toolchain / "ee-binutils" / "bin" / "as"),
                   P4_EEGCC_LD_LIBRARY_PATH=str(eegcc))
    return env


def ensure_ee_loader(args):
    """ee-gcc and the EE assembler are i386 ELFs whose interpreter is the fixed path `/lib/ld-linux.so.2`. On a host
    without it (no 32-bit glibc installed) the process is re-executed in a bubblewrap mount namespace where a tmpfs
    overlay on the directory `/lib` resolves to holds the user's 32-bit loader at that name; nothing on the host is
    written. The 32-bit libraries come from `--glibc32` through `P4_EEGCC_LD_LIBRARY_PATH` (the shim sets
    `LD_LIBRARY_PATH` for ee-gcc itself)."""
    if args.compiler != "eegcc" or os.environ.get(SANDBOX_MARK) or Path("/lib/ld-linux.so.2").exists():
        return
    loader = args.glibc32 / "ld-linux.so.2"
    if not shutil.which("bwrap"):
        raise HarnessError("the ee-gcc lane needs /lib/ld-linux.so.2 or bwrap (bubblewrap) to provide it")
    if not loader.is_file():
        raise HarnessError(f"32-bit loader missing: {loader} (--glibc32)")
    lib = os.path.realpath("/lib")
    os.environ[SANDBOX_MARK] = "1"
    os.execvp("bwrap", ["bwrap", "--dev-bind", "/", "/", "--overlay-src", lib, "--tmp-overlay", lib,
                        "--bind", str(loader), f"{lib}/ld-linux.so.2", sys.executable, *sys.argv])


def preflight(args):
    missing = []
    for path, what in ((args.toolchain / "mwccps2.exe", "MWCCPS2 3.0.1 b210"),
                       (args.toolchain / "cw3.0.1b119" / "mwccps2.exe", "MWCCPS2 3.0.1 b119"),
                       (args.toolchain / "SLUS_217.82", "retail SLUS_217.82"),
                       (OBJDIFF, "objdiff-cli"), (args.cli, "romwright-cli"), (args.worker, "romwright-worker"),
                       (args.ghidra_opt, "ghidra_opt (native/build_ghidra_opt.sh)")):
        if not Path(path).is_file():
            missing.append(f"{what}: {path}")
    for tool in ("wibo", "m2c", "git", "make"):
        if not shutil.which(tool):
            missing.append(f"{tool} on PATH")
    if not shutil.which("mipsel-linux-gnu-as") and not os.environ.get("P4_AS"):
        missing.append("GNU r5900 assembler (mipsel-linux-gnu-as, or P4_AS)")
    if "stock" in args.layers and not (GHIDRA / "support" / "analyzeHeadless").is_file() and not args.stock_json:
        missing.append(f"Ghidra 12.1.3 install: {GHIDRA} (ROMWRIGHT_GHIDRA)")
    if args.compiler == "eegcc":
        for path, what in ((args.toolchain / "ee-gcc-2.96" / "bin" / "ee-gcc", "ee-gcc 2.96"),
                           (args.toolchain / "ee-binutils" / "bin" / "as", "EE assembler (ee-as 2.12)"),
                           (args.glibc32 / "ld-linux.so.2", "32-bit glibc loader (--glibc32)"),
                           (args.glibc32 / "libc.so.6", "32-bit libc (--glibc32)")):
            if not Path(path).is_file():
                missing.append(f"{what}: {path}")
    if missing:
        raise HarnessError("missing prerequisite(s): " + "; ".join(missing))
    sha1 = hashlib.sha1((args.toolchain / "SLUS_217.82").read_bytes()).hexdigest()
    if sha1 != P4_ELF_SHA1:
        raise HarnessError(f"retail ELF sha1 {sha1} is not {P4_ELF_SHA1}")


def ensure_repo(args, env):
    repo = args.repo or args.work / "p4repo"
    if not (repo / ".git").exists():
        log(f"cloning {P4_URL} into {repo}")
        result = run(["git", "clone", "--quiet", P4_URL, repo], timeout=900)
        if result["exit"] != 0:
            raise HarnessError(f"git clone failed: {result['stderr'][-500:]}")
    head = run(["git", "-C", repo, "rev-parse", "HEAD"])["stdout"].strip()
    if head != args.commit:
        if args.repo:
            raise HarnessError(f"{repo} is at {head}, not the pinned {args.commit}")
        result = run(["git", "-C", repo, "checkout", "--quiet", "--detach", args.commit])
        if result["exit"] != 0:
            raise HarnessError(f"git checkout {args.commit} failed: {result['stderr'][-500:]}")
    steps = [("image", [sys.executable, "tools/build.py", "--setup-only"]),
             ("split", ["make", "split"]),
             ("regenerate-asm", ["make", "regenerate-asm"])]
    for label, argv in steps:
        marker = repo / "build" / f".m22-002-{label}"
        if marker.exists() and marker.read_text().strip() == args.commit:
            continue
        log(f"repo setup: {label}")
        result = run(argv, cwd=repo, env=env, timeout=3600)
        if result["exit"] != 0:
            raise HarnessError(f"repo setup `{' '.join(map(str, argv))}` failed: {(result['stdout'] + result['stderr'])[-800:]}")
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(args.commit + "\n")
    return repo


def verify_report(args, repo, env):
    eegcc = args.compiler == "eegcc"
    path = args.work / ("verify_report_eegcc.json" if eegcc else "verify_report.json")
    stamp = path.with_suffix(".stamp")
    material = args.commit + sha256_file(args.toolchain / "mwccps2.exe") + sha256_file(args.toolchain / "cw3.0.1b119" / "mwccps2.exe")
    if eegcc:
        material += sha256_file(args.toolchain / "ee-gcc-2.96" / "bin" / "ee-gcc") + sha256_file(repo / "tools" / "eegcc_shim.py")
    key = hashlib.sha256(material.encode()).hexdigest()
    if path.exists() and stamp.exists() and stamp.read_text() == key and not args.refresh_verify:
        return json.loads(path.read_text()), path
    if eegcc:
        # the units retail built with ee-gcc 2.96 (config/gcc_units.txt), verified through the repo's eegcc_shim
        units = [line.split("#", 1)[0].strip() for line in (repo / "config" / "gcc_units.txt").read_text().splitlines()]
        argv = [sys.executable, "tools/verify.py", "--json", path, *[unit for unit in units if unit]]
    else:
        argv = [sys.executable, "tools/verify.py", "--skip-gcc-units", "--json", path]
    log("running the repo's tools/verify.py (" + ("the ee-gcc units, about 30 seconds" if eegcc else "about 3 minutes") + ")")
    result = run(argv, cwd=repo, env=env, timeout=3600)
    if result["exit"] != 0 or not path.exists():
        raise HarnessError(f"tools/verify.py failed: {(result['stdout'] + result['stderr'])[-800:]}")
    stamp.write_text(key)
    return json.loads(path.read_text()), path


# ---------------------------------------------------------------------------
# Unit context
# ---------------------------------------------------------------------------

class Project:
    """The repo's tools, loaded in this process (tools/verify.py, gen_objdiff.py)."""

    def __init__(self, repo, env):
        os.environ.update({k: v for k, v in env.items() if k.startswith("P4_") or k == "TMPDIR"})
        sys.path.insert(0, str(repo / "tools"))
        import verify  # noqa: PLC0415
        import gen_objdiff  # noqa: PLC0415
        self.repo, self.V, self.G = repo, verify, gen_objdiff
        self.cfg = verify.load_config()
        target = json.loads((repo / "config" / "target.json").read_text())
        windows = json.loads((repo / "tools" / "slus21782_functions.json").read_text())
        self.retail = verify.RetailElf(self.cfg["retail_elf"], target, windows["sha1"])
        self.gp, self.data_table = verify.symbol_addresses()
        self.image = (repo / "image.bin").read_bytes()
        self.names, self.addresses = self._symbols()
        self.asm = self._index_asm()
        self._units = {}

    def _symbols(self):
        names, addresses = {}, {}
        for line in (self.repo / "config" / "symbol_addrs.txt").read_text().splitlines():
            found = re.match(r"\s*([A-Za-z_][\w.$]*)\s*=\s*(0x[0-9A-Fa-f]+)\s*;(.*)$", line)
            if not found:
                continue
            kind = re.search(r"type:(\w+)", found.group(3))
            names[found.group(1)] = (int(found.group(2), 16), kind.group(1) if kind else None)
            addresses.setdefault(int(found.group(2), 16), found.group(1))
        return names, addresses

    def _index_asm(self):
        functions = {}
        for path in (self.repo / "asm" / "code1.s", self.repo / "asm" / "code2.s"):
            current = None
            for line in path.read_text(errors="replace").splitlines():
                found = re.match(r"\s*glabel\s+(\S+)", line)
                if found:
                    current = [found.group(1), None, []]
                    continue
                if current is None:
                    continue
                if line.startswith("endlabel"):
                    if current[1] is not None:
                        functions[current[1]] = (current[0], current[2])
                    current = None
                    continue
                address = ASM_ADDRESS.search(line)
                if address and current[1] is None:
                    current[1] = int(address.group(1), 16)
                current[2].append(line)
        return functions

    def gcc_includes(self, path):
        """The `-I` flags the repo's verify gives an ee-gcc unit (config/version_flags.txt, by the unit's key)."""
        try:
            key = self.V.compiler_units().get(path.resolve().relative_to(self.repo).as_posix())
        except ValueError:
            key = None
        return [flag for flag in self.V.version_flags().get(key or "eegcc296", []) if flag.startswith("-I")]

    def unit(self, relative):
        """Preprocessed unit (the unit's compiler and flags: MWCC `-E`, or ee-gcc `-E` for a unit built with ee-gcc
        2.96): chunks and pragma list."""
        if relative in self._units:
            return self._units[relative]
        path = (self.repo / relative).resolve()
        if self.V.is_gcc_unit(path):
            compiler = str(Path(os.environ["P4_EEGCC_ROOT"]) / "bin" / "ee-gcc")
            flags = ["-O2", "-G0", *self.cfg["compile_flags"], *self.gcc_includes(path)]
            # INCLUDE_ASM/INCLUDE_RODATA splice retail assembly; the declarations do not need them
            env = dict(os.environ, LD_LIBRARY_PATH=os.environ["P4_EEGCC_LD_LIBRARY_PATH"])
            result = run([compiler, "-E", *flags, "-DINCLUDE_ASM(a,b,c)=", "-DINCLUDE_RODATA(a,b,c)=", relative],
                         cwd=self.repo, timeout=300, env=env)
            text = re.sub(r"(?m)^# \d+ .*$", "", result["stdout"])
        else:
            compiler = self.V.unit_compiler(path, self.cfg)
            flags = self.V.unit_compile_flags(path, self.cfg["compile_flags"])
            result = run([compiler, "-E", *flags, relative], cwd=self.repo, timeout=300)
            text = re.sub(r"/\* #line [^\n]*\*/", "", result["stdout"])
        if result["exit"] != 0 or not text.strip():
            self._units[relative] = None
            return None
        self._units[relative] = {"chunks": split_chunks(text), "compiler": compiler, "flags": flags,
                                 "path": path, "source": path.read_text(errors="replace")}
        return self._units[relative]


ASM_ADDRESS = re.compile(r"/\*\s*[0-9A-Fa-f]+\s+([0-9A-Fa-f]{8})\s+[0-9A-Fa-f]{8}\s*\*/")


def source_pragmas(source, marker_line):
    """`#pragma` lines of the unit's source in force at `marker_line`: those
    before it, outside `#if 0`-style inactive branches, in order."""
    lines = mask_c(source).splitlines()[:max(marker_line - 1, 0)]
    stack, out = [], []
    undefined = {"NON_MATCHING", "RWDEBUG", "RWSUPPRESSINLINE", "DUNROAMIN"}
    for line in lines:
        stripped = line.strip()
        directive = re.match(r"#\s*(\w+)\s*(.*)", stripped)
        if not directive:
            continue
        name, rest = directive.group(1), directive.group(2)
        if name in ("if", "ifdef", "ifndef"):
            active = True
            if name == "if":
                condition = re.sub(r"/\*.*?\*/|//.*", "", rest).strip()
                if re.fullmatch(r"\(?\s*0\s*\)?", condition):
                    active = False
                elif re.fullmatch(r"\(?\s*defined\s*\(?\s*(\w+)\s*\)?\s*\)?", condition):
                    active = re.fullmatch(r"\(?\s*defined\s*\(?\s*(\w+)\s*\)?\s*\)?", condition).group(1) not in undefined
            elif name == "ifdef":
                active = not rest.split() or rest.split()[0] not in undefined
            stack.append([active, active])
        elif name == "else" and stack:
            stack[-1][0] = not stack[-1][1]
            stack[-1][1] = True
        elif name == "elif" and stack:
            stack[-1][0] = not stack[-1][1]
            stack[-1][1] = stack[-1][1] or stack[-1][0]
        elif name == "endif" and stack:
            stack.pop()
        elif name == "pragma" and all(item[0] for item in stack):
            out.append("#pragma " + rest)
    return out


def build_context(unit, name, marker_line):
    """-> (context text, pragma lines, prototypes {name: (ret, params, name)}, target chunk)."""
    target = next((c for c in unit["chunks"] if c["kind"] == "funcdef" and c.get("name") == name), None)
    if target is None:
        return None
    lines, protos, seen, typedefs = [], {}, set(), {}
    for chunk in unit["chunks"]:
        if chunk["kind"] == "pp":
            continue
        text = declaration_text(chunk)
        if text is None:
            continue
        masked = squash(chunk["masked"])
        if masked.startswith("typedef"):
            update_typedefs(typedefs, masked)
        else:
            proto = prototype_of(chunk) if "=" not in chunk["masked"].split("{")[0] else None
            if proto:
                proto = erase_prototype(proto, typedefs)
                protos.setdefault(proto[2], proto)
                text = f"{proto[0]} {proto[2]}({proto[1]});"
            else:
                text = erase_extern(text, typedefs)
        if text in seen:
            continue
        seen.add(text)
        lines.append(text)
    return "\n".join(lines) + "\n", source_pragmas(unit["source"], marker_line), protos, target


# ---------------------------------------------------------------------------
# m2c input: the function's assembly, mechanically adapted
# ---------------------------------------------------------------------------

GP_MEMORY = re.compile(r"(?<![\w%])(-?(?:0x[0-9A-Fa-f]+|\d+))\(\$(?:28|gp)\)")
GP_ADDRESS = re.compile(r"^(?P<head>.*?\b(?:addiu|daddiu)\s+\$\w+,\s*)\$(?:28|gp),\s*(?P<imm>-?(?:0x[0-9A-Fa-f]+|\d+))\s*$")


def gp_symbol(project, imm_text):
    """(symbol, address) of the gp-relative operand: the repo's name for the address, else `D_<address>`."""
    address = (GP + int(imm_text, 0)) & 0xFFFFFFFF
    name = project.addresses.get(address)
    if name and project.names[name][1] != "func":
        return name, address
    return f"D_{address:08X}", address


def signed_addend(text):
    value = int(text, 16)
    return value - 0x10000 if value & 0x8000 else value


def offset_text(addend):
    return "" if addend == 0 else (f" + {addend:#x}" if addend > 0 else f" - {-addend:#x}")


def rewrite_gp(project, lines, relocations=None):
    """gp-relative operands as `%gp_rel(symbol)($gp)`: the object's relocation symbol (and addend) where the
    verify report has one at that instruction, else the repo's name for the address, else `D_<address>`."""
    relocations = relocations or {}
    out, rewrites, from_object = [], 0, 0
    for line in lines:
        code = line.split("*/", 1)[1] if "*/" in line else line
        prefix = line[:len(line) - len(code)]
        located = ASM_ADDRESS.search(line)
        reloc = relocations.get(int(located.group(1), 16)) if located else None
        reloc = reloc if reloc and reloc["r_type"] == 7 else None

        def operand(imm_text):
            nonlocal from_object
            if reloc:
                from_object += 1
                return reloc["symbol"] + offset_text(signed_addend(reloc["addend"]) if "addend" in reloc else 0)
            return gp_symbol(project, imm_text)[0]
        address_form = GP_ADDRESS.match(code)
        if address_form:
            code = f"{address_form.group('head')}$gp, %gp_rel({operand(address_form.group('imm'))})"
            rewrites += 1
        else:
            def replace(found):
                nonlocal rewrites
                rewrites += 1
                return f"%gp_rel({operand(found.group(1))})($gp)"
            code = GP_MEMORY.sub(replace, code)
        out.append(prefix + code)
    return out, rewrites, from_object


CALL_TARGET = re.compile(r"^(\s*(?:jal|j)\s+)\S+")


def rename_calls(lines, relocations):
    """Call targets named as the object's R_MIPS_26 relocations name them (the unit's own symbols)."""
    out, renamed = [], 0
    for line in lines:
        located = ASM_ADDRESS.search(line)
        reloc = relocations.get(int(located.group(1), 16)) if located else None
        if reloc and reloc["r_type"] == 4:
            code = line.split("*/", 1)[1]
            new = CALL_TARGET.sub(lambda m: m.group(1) + reloc["symbol"], code, count=1)
            if new != code:
                line = line[:len(line) - len(code)] + new
                renamed += 1
        out.append(line)
    return out, renamed


def add_jump_tables(project, lines, start, end):
    """Rows for `jtbl_<addr>` references: labels at the targets and the table in .rodata, read from the retail image."""
    text = "\n".join(lines)
    tables = sorted({int(m, 16) for m in re.findall(r"jtbl_([0-9A-Fa-f]{8})", text)})
    if not tables:
        return lines, [], []
    labelled = set(re.findall(r"^\s*\.L([0-9A-Fa-f]{8})\s*:", text, re.M))
    instruction_lines = {}
    for index, line in enumerate(lines):
        found = ASM_ADDRESS.search(line)
        if found:
            instruction_lines[int(found.group(1), 16)] = index
    inserts, tail, notes = {}, [".section .rodata"], []
    for position, table in enumerate(tables):
        limit = tables[position + 1] if position + 1 < len(tables) else table + 4 * 512
        words, address = [], table
        while address + 4 <= limit and len(words) < 512:
            offset = address - IMAGE_VRAM
            value = int.from_bytes(project.image[offset:offset + 4], "little")
            if not (start <= value < end) or value % 4:
                break
            words.append(value)
            address += 4
        if not words:
            notes.append(f"jtbl_{table:08X}: no entries inside the function")
            continue
        tail.append(f"glabel jtbl_{table:08X}")
        for value in words:
            tail.append(f"    .word .L{value:08X}")
            if f"{value:08X}" not in labelled and value in instruction_lines:
                inserts[instruction_lines[value]] = f"  .L{value:08X}:"
                labelled.add(f"{value:08X}")
        notes.append(f"jtbl_{table:08X}: {len(words)} entries")
    result = []
    for index, line in enumerate(lines):
        if index in inserts:
            result.append(inserts[index])
        result.append(line)
    return result, tail, notes


def object_relocations(address, relocations):
    """{instruction address: relocation} for the symbol-bearing call and gp-relative relocations of the
    function's verify-report row (the symbol information an object file gives m2c in m22-001)."""
    return {address + r["offset"]: r for r in relocations if r.get("symbol") and r["r_type"] in (4, 7)}


def m2c_assembly(project, name, address, relocations):
    entry = project.asm.get(address)
    if entry is None:
        raise HarnessError(f"{name}: no splat assembly at {address:08x}")
    located = object_relocations(address, relocations)
    lines = list(entry[1])
    end = address + 4 * sum(1 for line in lines if ASM_ADDRESS.search(line))
    lines, renamed = rename_calls(lines, located)
    lines, gp_rewrites, gp_from_object = rewrite_gp(project, lines, located)
    lines, tail, notes = add_jump_tables(project, lines, address, end)
    body = f".set noat\n.set noreorder\n.text\nglabel {name}\n" + "\n".join(lines) + "\n"
    if len(tail) > 1:
        body += "\n".join(tail) + "\n"
    return body, {"gp_operands_rewritten": gp_rewrites, "gp_symbols_from_object": gp_from_object,
                  "calls_renamed_from_object": renamed, "jump_tables": notes}


# ---------------------------------------------------------------------------
# Candidate producers
# ---------------------------------------------------------------------------

def m2c_info():
    version = run(["pip", "show", "m2c"])["stdout"]
    commit = None
    for path in (HOME / ".local/lib").glob("python*/site-packages/m2c-*.dist-info/direct_url.json"):
        commit = json.loads(path.read_text()).get("vcs_info", {}).get("commit_id")
    found = re.search(r"^Version:\s*(\S+)", version, re.M)
    return {"version": found.group(1) if found else None, "commit": commit, "path": shutil.which("m2c")}


def m2c_macros(work, commit):
    path = work / f"m2c_macros_{(commit or 'unknown')[:8]}.h"
    if not path.exists():
        if not commit:
            raise HarnessError("cannot tell the installed m2c's commit (direct_url.json), so m2c_macros.h cannot be fetched")
        result = run(["curl", "-sfL", M2C_MACROS_URL.format(commit=commit), "-o", path])
        if result["exit"] != 0:
            raise HarnessError(f"fetching m2c_macros.h for {commit}: {result['stderr'][-300:]}")
    return path.read_text()


def m2c_candidate(work_dir, name, assembly, context_path, target="mipsee-mwcc-c"):
    asm_path = work_dir / "input.s"
    asm_path.write_text(assembly)
    base = ["m2c", "-t", target, "--valid-syntax", "--no-cache", "-f", name]
    result = run([*base, "--context", context_path, asm_path], timeout=300)
    note = None
    if result["exit"] != 0 or not result["stdout"].strip():
        first = result
        result = run([*base, asm_path], timeout=300)
        note = {"context_dropped": True, "context_error": (first["stderr"] + first["stdout"])[-600:]}
    text = result["stdout"] if result["exit"] == 0 and result["stdout"].strip() else None
    return text, {"argv": result["argv"], "exit": result["exit"], "seconds": result["seconds"],
                  "stderr": result["stderr"][-1500:], **(note or {})}


def import_romwright(args, work, env, log_):
    project = work / "project"
    exists = (project / "project.sqlite").exists()
    if exists and args.fresh_import:
        shutil.rmtree(project)
        exists = False
    if exists:
        listing = run([args.cli, "programs", "--project", project], env=env, timeout=120)
        exists = listing["exit"] == 0 and PROGRAM in listing["stdout"]
        if not exists:
            shutil.rmtree(project)
    record = {"project": str(project), "binary": str(args.toolchain / "SLUS_217.82")}
    if exists:
        record["import"] = {"reused": True}
    else:
        log_("importing the retail ELF into the romwright project (one import, reused afterwards)")
        result = run([args.cli, "import", args.toolchain / "SLUS_217.82", "--name", PROGRAM, "--project", project],
                     env=env, timeout=3600)
        record["import"] = {k: result[k] for k in ("argv", "exit", "seconds")}
        record["import"]["stderr_tail"] = result["stderr"][-1500:]
        if result["exit"] != 0 or "degraded" in result["stdout"] + result["stderr"]:
            raise HarnessError(f"romwright import failed or degraded: {(result['stdout'] + result['stderr'])[-600:]}")
    return project, record


def romwright_names(work, env, args):
    pairs = [{"function": f"{address:x}", "name": name}
             for name, (address, kind) in sorted(args._project_names.items(), key=lambda kv: kv[1][0])
             if kind == "func"]
    path = work / "names.json"
    path.write_text(json.dumps(pairs))
    result = run([args.cli, "assert-names", PROGRAM, path, "--project", work / "project"], env=env, timeout=900)
    return {"supplied": len(pairs), "exit": result["exit"], "stdout": result["stdout"].strip()[-300:],
            "stderr": result["stderr"][-500:]}


def romwright_candidate(args, work, env, row, context_path, protos, typedefs, needed):
    """Assert the target and callee prototypes, then export-c at the function's address."""
    asserted, notes = [], []
    # the unit's own names for the target and its callees (the object's relocation symbols)
    named = {row["address"]: row["name"]}
    for reloc in row["relocations"]:
        if reloc["r_type"] == 4 and reloc.get("symbol") and reloc.get("retail_target"):
            named[int(reloc["retail_target"], 16)] = reloc["symbol"]
    by_name = {symbol: address for address, symbol in named.items()}
    fdir = row["dir"] / "romwright"
    fdir.mkdir(parents=True, exist_ok=True)
    (fdir / "names.json").write_text(json.dumps([{"function": f"{a:x}", "name": n} for a, n in sorted(named.items())]))
    result = run([args.cli, "assert-names", PROGRAM, fdir / "names.json", "--project", work / "project"], env=env, timeout=300)
    names_record = {"supplied": len(named), "exit": result["exit"], "stderr": result["stderr"][-300:]}
    for symbol in needed:
        proto = protos.get(symbol)
        address = by_name.get(symbol) or symbol_address(args, symbol)
        if proto is None or address is None:
            continue
        signature, why = asserted_signature(proto, typedefs)
        if signature is None:
            notes.append(f"{symbol}: not asserted ({why})")
            continue
        asserted.append({"function": f"{address:x}", "signature": signature})
    record = {"asserted": len(asserted), "notes": notes, "assert_names": names_record}
    if asserted:
        path = fdir / "prototypes.json"
        path.write_text(json.dumps(asserted, indent=1))
        result = run([args.cli, "assert-prototypes", PROGRAM, path, "--source", "m22-002 unit declarations",
                      "--project", work / "project"], env=env, timeout=300)
        record["assert_prototypes"] = {"exit": result["exit"], "stderr": result["stderr"][-500:]}
    outdir = fdir / "export"
    shutil.rmtree(outdir, ignore_errors=True)
    outdir.mkdir()
    result = run([args.cli, "export-c", args.toolchain / "SLUS_217.82", PROGRAM, outdir, "--address", f"{row['address']:x}",
                  "--context", context_path, "--project", work / "project"], env=env, timeout=900)
    files = sorted(outdir.glob("*.c"))
    text = "\n".join(f.read_text(errors="replace") for f in files) if files else None
    record.update(argv=result["argv"], exit=result["exit"], seconds=result["seconds"], stderr=result["stderr"][-1500:])
    return text, record


def symbol_address(args, symbol):
    found = args._project_names.get(symbol)
    if found:
        return found[0]
    pattern = re.fullmatch(r"func_([0-9A-Fa-f]{8})", symbol)
    return int(pattern.group(1), 16) if pattern else None


def stock_export(args, addresses, directory):
    """Stock Ghidra headless on the retail ELF; the decompiled C of every address (cached by address set)."""
    directory.mkdir(parents=True, exist_ok=True)
    listing = directory / "addresses.txt"
    listing.write_text("".join(f"{a:x}\n" for a in addresses))
    output = directory / "signatures.json"
    key = hashlib.sha256(json.dumps([sorted(addresses), GHIDRA_LANGUAGE,
                                     sha256_file(GHIDRA_SCRIPTS / "ExportDecompiledC.java")]).encode()).hexdigest()[:16]
    stamp = directory / "signatures.key"
    if output.exists() and stamp.exists() and stamp.read_text() == key:
        return json.loads(output.read_text()), {"cached": True, "key": key}
    project = directory / "project"
    shutil.rmtree(project, ignore_errors=True)
    project.mkdir()
    argv = [str(GHIDRA / "support" / "analyzeHeadless"), str(project), "proj", "-import",
            str(args.toolchain / "SLUS_217.82"), "-processor", GHIDRA_LANGUAGE, "-scriptPath", str(GHIDRA_SCRIPTS),
            "-postScript", "ExportDecompiledC.java", str(listing), str(output), "120", "-deleteProject"]
    env = {k: v for k, v in os.environ.items() if not k.startswith("ROMWRIGHT_")}
    env.update(GHIDRA_HEADLESS_MAXMEM=os.environ.get("GHIDRA_HEADLESS_MAXMEM", "8G"), DEBUGINFOD_URLS="")
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env,
                               start_new_session=True)
    started = time.monotonic()
    try:
        stdout, stderr = process.communicate(timeout=args.stock_timeout)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate()
        (directory / "headless.log").write_text(stdout + stderr)
        raise HarnessError(f"stock Ghidra did not finish within {args.stock_timeout} s (log {directory / 'headless.log'})")
    finally:
        shutil.rmtree(project, ignore_errors=True)
    (directory / "headless.log").write_text(stdout + stderr)
    if not output.exists():
        raise HarnessError(f"stock Ghidra produced no export (log {directory / 'headless.log'}): {(stdout + stderr)[-600:]}")
    stamp.write_text(key)
    return json.loads(output.read_text()), {"cached": False, "key": key, "seconds": round(time.monotonic() - started, 1),
                                           "ghidra": str(GHIDRA)}


GHIDRA_PRELUDE = """typedef unsigned char undefined;
typedef unsigned char undefined1;
typedef unsigned short undefined2;
typedef unsigned int undefined4;
typedef unsigned long long undefined8;
typedef unsigned char byte;
typedef signed char sbyte;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long long ulonglong;
typedef long long longlong;
typedef unsigned long ulong;
typedef int (*code)();
"""


GP_NAME_FULL = re.compile(r"\b(?:p*)(?:uc|us|ul|c|s|i|u|l|f|d|b)Gp[0-9a-f]{8}\b")
# the type prefix Ghidra's decompiler puts on a global it has no symbol for (iGpffff9db0: an int)
GP_PREFIX_TYPES = {"c": "char", "uc": "byte", "s": "short", "us": "ushort", "i": "int", "u": "uint", "l": "longlong",
                   "ul": "ulonglong", "f": "float", "d": "double", "b": "byte"}


def stock_candidate(row, stock):
    entry = stock["functions"].get(f"{row['address']:x}")
    if not entry or not entry.get("c"):
        return None, {"available": False, "error": (entry or {}).get("error", "no export row")}
    text = entry["c"]
    found = re.search(r"\b(FUN_[0-9a-fA-F]+|[A-Za-z_]\w*)\s*\(", text.split("{", 1)[0])
    if found and found.group(1) != row["name"]:
        text = re.sub(r"\b" + re.escape(found.group(1)) + r"\b", row["name"], text)
    declarations = sorted(set(entry.get("declarations") or []))
    declared = {m for d in declarations for m in re.findall(r"(\w+)(?:\[\d+\])?;$", d)}
    for match in sorted(set(m.group(0) for m in GP_NAME_FULL.finditer(text))):
        if match not in declared:
            stars, prefix = re.match(r"(p*)(uc|us|ul|c|s|i|u|l|f|d|b)Gp", match).groups()
            declarations.append(f"extern {GP_PREFIX_TYPES[prefix]}{' *' * len(stars)} {match};")
    if declarations:
        text = "\n".join(declarations) + "\n" + text
    return text, {"available": True, "existed": bool(entry.get("existed")), "ghidra_name": found.group(1) if found else None,
                  "declarations": len(declarations)}


# ---------------------------------------------------------------------------
# Compile and score
# ---------------------------------------------------------------------------

MACRO_SKELETON = "{macros}\n"
NULL_DEFINE = "#define NULL ((void*)0)\n"
LIBC = "void *memcpy(void *dest, const void *src, unsigned int n);\n"
STD_TYPEDEFS = [("unsigned char", "u8"), ("signed char", "s8"), ("unsigned short", "u16"), ("short", "s16"),
                ("unsigned int", "u32"), ("int", "s32"), ("unsigned long long", "u64"), ("long long", "s64"),
                ("float", "f32"), ("double", "f64")]


def missing_typedefs(*texts):
    defined = " ".join(texts)
    return "".join(f"typedef {base} {name};\n" for base, name in STD_TYPEDEFS
                   if not re.search(r"\btypedef\b[^;{]*\b" + name + r"\s*;", defined))


def compose(variant, context, pragmas, macros, candidate, extra_prelude=""):
    prelude = missing_typedefs(context if variant == "context" else "", extra_prelude)
    parts = [prelude, NULL_DEFINE, extra_prelude]
    if variant == "context":
        parts.append(context)
    declared = context if variant == "context" else ""
    parts += [LIBC if not re.search(r"\bmemcpy\b", declared) else "", macros, "\n".join(pragmas), "", candidate]
    return "\n".join(parts)


ERROR_LINE = re.compile(r"^#\s+Error:[^\n]*\n#\s+([^\n]+)", re.M)
GCC_ERROR_LINE = re.compile(r"^[^\n:]*\.c:\d+:\s*(?!warning)([^\n]+)", re.M)


def compile_candidate(project, source, output, row, args):
    if args.compiler == "eegcc":
        # the repo's own route for an ee-gcc unit (verify.py `_compile_gcc`): its shim, with the unit's include roots
        command = [sys.executable, str(project.repo / "tools" / "eegcc_shim.py"), "-c", *project.cfg["compile_flags"],
                   *row["includes"], "-o", str(output), str(source)]
    else:
        command = project.V._mwccgap_command(row["unit_path"], project.cfg, output)
        command[2], command[3] = str(source), str(output)
    if output.exists():
        output.unlink()
    result = run(command, cwd=project.repo, timeout=180)
    output_text = result["stdout"] + result["stderr"]
    errors = ERROR_LINE.findall(output_text) + (GCC_ERROR_LINE.findall(output_text) if args.compiler == "eegcc" else [])
    return result, errors


def score_object(project, args, output, name, retail_row, directory):
    """-> dict with symbol presence, exact flags and objdiff percent."""
    entry = {"symbol": False, "exact": False, "exact_symbols": False, "percent": 0.0}
    try:
        obj = project.V.ObjectFile(output)
        body, relocations = obj.function(name)
    except (KeyError, ValueError, OSError) as error:
        entry["error"] = f"no symbol {name} in the object ({error})"
        return entry
    entry.update(symbol=True, size=len(body))
    retail = retail_row["retail"]
    padded = project.retail.bytes_at(retail_row["address"], retail_row["window"])
    differences, first = project.V.compare(body, relocations, padded)
    entry["byte_differences"] = differences if len(body) == retail_row["size"] else None
    entry["exact"] = differences == 0 and len(body) <= len(padded) and len(body) == retail_row["size"] \
        and not any(padded[len(body):])
    if entry["exact"]:
        result = {"relocations": project.V.decode_reloc_values(
            [dict(r) for r in relocations], padded, body)}
        entry["exact_symbols"] = not project.V.wrong_symbol_relocations(result, project.gp, project.data_table)
    flags = project.G._elf_flags(obj.data)
    target = directory / "target.o"
    base = directory / "base.o"
    target.write_bytes(project.G.build_elf_object(retail, [], name, flags))
    base.write_bytes(project.G.build_elf_object(body, relocations, name, flags))
    record = directory / "objdiff.json"
    result = run([OBJDIFF, "diff", "-1", target, "-2", base, name, "--format", "json", "-o", record,
                  "-c", "functionRelocDiffs=none"], timeout=120)
    percent = None
    if result["exit"] == 0 and record.exists():
        for symbol in json.loads(record.read_text()).get("left", {}).get("symbols", []):
            if symbol.get("name") == name:
                percent = float(symbol.get("match_percent", 0.0))
    if percent is None:
        entry["error"] = "objdiff failed: " + result["stderr"][-500:]
        percent = 0.0
    entry["percent"] = percent
    return entry


def normalise_error(message):
    message = re.sub(r"'[^']*'", "'X'", message)
    message = re.sub(r"\b\d+\b", "N", message)
    return message.strip()[:100]


def score_candidate(project, args, row, layer, text, context, pragmas, macros):
    variants = {}
    ldir = row["dir"] / layer
    ldir.mkdir(parents=True, exist_ok=True)
    extra = ""
    if layer in ("stock", "romwright") or layer.startswith("search-"):
        extra = "".join(line + "\n" for line in GHIDRA_PRELUDE.splitlines()
                        if not re.search(r"\btypedef\b[^;{]*\b" + re.escape(re.findall(r"(\w+)\)?\(?\)?;$", line)[0]) + r"\b", context))
    for variant in VARIANTS:
        vdir = ldir / variant
        vdir.mkdir(parents=True, exist_ok=True)
        entry = {"compiled": False, "produced": text is not None, "exact": False, "exact_symbols": False,
                 "percent": 0.0}
        variants[variant] = entry
        if text is None:
            entry["error"] = "no candidate"
            continue
        source = vdir / "candidate.c"
        shown = context
        if layer == "stock":
            # stock prints its own signature for the target; the unit's prototype for it is not part of its input
            shown = "\n".join(line for line in context.splitlines()
                              if not re.search(r"\b" + re.escape(row["name"]) + r"\s*\(", line))
        source.write_text(compose(variant, shown, pragmas, macros, text, extra))
        output = vdir / "candidate.o"
        result, errors = compile_candidate(project, source, output, row, args)
        entry["compile_exit"] = result["exit"]
        entry["seconds"] = result["seconds"]
        if result["exit"] != 0 or not output.exists():
            entry["errors"] = errors[:5]
            entry["error"] = "; ".join(errors[:2]) or (result["stderr"] + result["stdout"])[-300:].strip()
            continue
        scored = score_object(project, args, output, row["name"], row, vdir)
        entry.update(scored)
        entry["compiled"] = scored["symbol"]
    parts = list(variants.values())
    variants["best"] = {key: (any(v[key] for v in parts) if key != "percent" else max(v[key] for v in parts))
                        for key in ("produced", "compiled", "exact", "exact_symbols", "percent")}
    return variants


# ---------------------------------------------------------------------------
# Selection and report
# ---------------------------------------------------------------------------

def search_layer(project, args, cli_env, row, context_path, context, macros, text, default_variants):
    """The `romwright-search` layer entry (docs/match.md): the default print when it does not compile or is exact, else the best of the
    product command's variants (tests/match_search_arm.py). The variants are exported while the store is as the default print saw it."""
    import concurrent.futures
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import match_search_arm
    headline = default_variants["context"]
    if text is None or not headline["compiled"] or headline["exact"]:
        reason = "no candidate" if text is None else "exact" if headline["exact"] else "default does not compile"
        return {"produce": {"search": None, "reason": reason}, "variants": default_variants}

    def export(words, tag):
        outdir = row["dir"] / "search" / tag / "export"
        shutil.rmtree(outdir, ignore_errors=True)
        outdir.mkdir(parents=True)
        variant_env = dict(cli_env)
        variant_env.update(word.split("=", 1) for word in words)
        run([args.cli, "export-c", args.toolchain / "SLUS_217.82", PROGRAM, outdir, "--address", f"{row['address']:x}",
             "--context", context_path, "--project", args.work / "project"], env=variant_env, timeout=900)
        files = sorted(outdir.glob("*.c"))
        result = "\n".join(f.read_text(errors="replace") for f in files) if files else None
        shutil.rmtree(outdir.parent, ignore_errors=True)
        return result

    def score(candidate, tag):
        return score_candidate(project, args, row, "search-" + tag, candidate, context, row["pragmas"], macros)

    tmp = args.work / "tmp"
    tmp.mkdir(exist_ok=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, os.cpu_count() or 4)) as pool:
        label, winner, variants, record = match_search_arm.search_row(args.cli, args.search, pool, tmp, export, score, text, default_variants)
    for stale in row["dir"].glob("search-*"):
        shutil.rmtree(stale, ignore_errors=True)
    if winner is not None:
        (row["dir"] / "romwright-search").mkdir(exist_ok=True)
        (row["dir"] / "romwright-search" / "raw.c").write_text(winner)
    return {"produce": {"search": record}, "variants": variants}


def select_functions(project, report, args):
    eegcc = args.compiler == "eegcc"
    rows = sorted((r for r in report["results"] if r["status"] == "MATCH"
                   and SIZE_MIN <= r["object_size"] <= SIZE_MAX and project.V.is_gcc_unit(project.repo / r["file"]) == eegcc),
                  key=lambda r: int(r["addr"], 16))
    order = list(range(len(rows)))
    random.Random(args.seed).shuffle(order)
    chosen, rejected = [], {}
    for index in order:
        if len(chosen) >= args.n:
            break
        r = rows[index]
        unit = project.unit(r["file"])
        if unit is None:
            rejected["unit does not preprocess"] = rejected.get("unit does not preprocess", 0) + 1
            continue
        built = build_context(unit, r["name"], r["line"])
        if built is None:
            rejected["no definition in the preprocessed unit"] = rejected.get("no definition in the preprocessed unit", 0) + 1
            continue
        context, pragmas, protos, chunk = built
        if eegcc:
            pragmas = []  # ee-gcc's configuration is the shim's fixed `-O2 -G0`, not per-function pragmas
        if re.search(r"\basm\b|__asm", chunk["body"]):
            rejected["inline assembly in the body"] = rejected.get("inline assembly in the body", 0) + 1
            continue
        address = int(r["addr"], 16)
        if address not in project.asm:
            rejected["no splat assembly"] = rejected.get("no splat assembly", 0) + 1
            continue
        retail_bytes = project.retail.bytes_at(address, r["object_size"])
        chosen.append({
            "name": r["name"], "address": address, "file": r["file"], "line": r["line"], "size": r["object_size"],
            "window": r["window"], "retail": retail_bytes, "context": context, "pragmas": pragmas,
            "protos": protos, "relocations": r.get("relocations", []), "unit_path": unit["path"],
            "compiler": ("ee-gcc 2.96 -O2 -G0" if eegcc else ("b119" if "b119" in str(unit["compiler"]) else "b210") + " " + " ".join(f for f in unit["flags"] if f.startswith("-O"))),
            "flags": unit["flags"], "origin": project.V.code_origin(r["file"], address),
            "includes": project.gcc_includes(unit["path"]) if eegcc else [],
            "family": "promoted" if r["file"].startswith("src/promoted/") else ("cri" if r["file"].startswith("src/cri/") else "other")})
    chosen.sort(key=lambda r: r["address"])
    return chosen, rejected, len(rows)


def sign_test(wins, losses):
    n = wins + losses
    if n == 0:
        return 1.0
    k = min(wins, losses)
    return min(1.0, 2 * sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n)


def summarise(functions, layers):
    def block(rows, layer, variant):
        entries = [r["layers"][layer]["variants"][variant] for r in rows]
        n = len(entries)
        if not n:
            return None
        compiled = [e for e in entries if e["compiled"]]
        percents = [e["percent"] for e in entries]
        return {
            "functions": n,
            "produced": sum(e["produced"] for e in entries),
            "compiled": len(compiled),
            "compile_failure_share": round(1 - len(compiled) / n, 4),
            "exact": sum(e["exact"] for e in entries),
            "exact_symbols": sum(e["exact_symbols"] for e in entries),
            "mean_percent": round(sum(percents) / n, 3),
            "mean_percent_compiled": round(sum(e["percent"] for e in compiled) / len(compiled), 3) if compiled else None,
            "percent_ge_90": sum(p >= 90 for p in percents),
            "percent_100": sum(p >= 100 for p in percents),
        }

    rows = list(functions.values())
    summary = {"overall": {}, "by_family": {}, "by_origin": {}, "by_compiler": {}, "by_size": {}, "paired": {}}
    groups = {"overall": {"all": rows}}
    for key, name in (("family", "by_family"), ("origin", "by_origin"), ("compiler", "by_compiler")):
        values = sorted({r[key] for r in rows})
        groups[name] = {v: [r for r in rows if r[key] == v] for v in values}
    buckets = [("32-63", 32, 63), ("64-127", 64, 127), ("128-255", 128, 255), ("256-1024", 256, 1024)]
    groups["by_size"] = {label: [r for r in rows if lo <= r["size"] <= hi] for label, lo, hi in buckets}
    for group, members in groups.items():
        for label, subset in members.items():
            summary[group][label] = {layer: {variant: block(subset, layer, variant) for variant in REPORTED}
                                     for layer in layers}
            summary[group][label]["n"] = len(subset)
    for first, second in (("romwright", "m2c"), ("romwright", "stock"), ("m2c", "stock")):
        if first not in layers or second not in layers:
            continue
        for variant in REPORTED:
            wins = sum(r["layers"][first]["variants"][variant]["percent"] > r["layers"][second]["variants"][variant]["percent"] for r in rows)
            losses = sum(r["layers"][first]["variants"][variant]["percent"] < r["layers"][second]["variants"][variant]["percent"] for r in rows)
            summary["paired"][f"{first}_vs_{second}_{variant}"] = {
                "wins": wins, "losses": losses, "ties": len(rows) - wins - losses,
                "p_two_sided": round(sign_test(wins, losses), 6)}
    errors = {}
    for layer in layers:
        counts = {}
        for r in rows:
            entry = r["layers"][layer]["variants"]["context"]
            if entry["produced"] and not entry["compiled"]:
                keys = [normalise_error(e) for e in entry.get("errors", [])[:1]] or [normalise_error(entry.get("error", "")) or "object lacks the target symbol"]
                for key in keys:
                    counts[key] = counts.get(key, 0) + 1
        errors[layer] = dict(sorted(counts.items(), key=lambda kv: -kv[1])[:8])
    summary["compile_errors_context"] = errors
    return summary


def markdown(report):
    s, layers = report["summary"], report["layers"]
    lines = [f"# m22-002: C output on matched Persona 4 functions (PS2, {'ee-gcc 2.96 units' if report.get('lane') == 'eegcc' else 'MWCCPS2 units'})", "",
             f"Generated {report['generated']}. Sample: {report['sample']['n']} matched functions, seed {report['sample']['seed']}, "
             f"from {report['sample']['eligible']} eligible rows of the repo's verify report. "
             f"Repo {report['repo']['url']} at `{report['repo']['commit'][:12]}`.", "",
             "Scores are against the retail bytes of each function. `exact` is verify.py's MATCH criterion; "
             "`percent` is objdiff `match_percent` (functionRelocDiffs=none); a candidate that was not produced or does not compile counts as 0. "
             "`compile-failure share` = 1 - compiled / functions, so a function a tool produced nothing for is a failure.", ""]
    for variant in REPORTED:
        lines += [f"## {variant} variant" + (" (headline)" if variant == "context" else ""), "",
                  "| layer | functions | produced | compiled | compile-failure share | exact | exact (symbols too) | mean percent | mean percent (compiled) | percent >= 90 |",
                  "|---|---|---|---|---|---|---|---|---|---|"]
        for layer in layers:
            b = s["overall"]["all"][layer][variant]
            lines.append(f"| {layer} | {b['functions']} | {b['produced']} | {b['compiled']} | {b['compile_failure_share']:.1%} | "
                         f"{b['exact']} | {b['exact_symbols']} | {b['mean_percent']} | {b['mean_percent_compiled']} | {b['percent_ge_90']} |")
        lines.append("")
    lines += ["## Paired comparison on percent (functions where the first layer scores higher / lower)", "",
              "| pair | wins | losses | ties | two-sided sign-test p |", "|---|---|---|---|---|"]
    for key, row in s["paired"].items():
        lines.append(f"| {key} | {row['wins']} | {row['losses']} | {row['ties']} | {row['p_two_sided']} |")
    for group, title in (("by_family", "unit family (promoted = src/promoted, produced with m2c in the loop)"),
                         ("by_origin", "code origin"), ("by_compiler", "compiler"), ("by_size", "function size (bytes)")):
        lines += ["", f"## By {title}, context variant", "",
                  "| group | n | " + " | ".join(f"{layer} exact / mean % / fail" for layer in layers) + " |",
                  "|---|---|" + "---|" * len(layers)]
        for label, block in s[group].items():
            cells = []
            for layer in layers:
                b = block[layer]["context"]
                cells.append(f"{b['exact']} / {b['mean_percent']} / {b['compile_failure_share']:.0%}" if b else "-")
            lines.append(f"| {label} | {block['n']} | " + " | ".join(cells) + " |")
    lines += ["", "## Compile failures of the context variant (first error, normalised)", ""]
    for layer in layers:
        lines.append(f"**{layer}**: " + ("; ".join(f"{message} x{count}" for message, count in s["compile_errors_context"][layer].items()) or "none"))
        lines.append("")
    lines += ["## Limits", ""] + [f"- {item}" for item in report["limits"]]
    return "\n".join(lines) + "\n"


MWCC_LIMIT = ("Persona 4 only; MWCCPS2 3.0.1 b210 (default, `-O2`), b210 `-O2,p` speed units and b119 (`-O4,p`) units are in scope; "
              "units built with ee-gcc 2.96 (`config/gcc_units.txt`) are the separate `--compiler eegcc` lane "
              "(`m22-ps2_p4_eegcc.{json,md}`).")
EEGCC_LIMIT = ("Persona 4 only; the units retail built with ee-gcc 2.96-ee-001003-1 (`config/gcc_units.txt`: the CRI ADX/SFD/ACS library, "
               "the Sony SDK and a few promoted units), compiled `-O2 -G0` through the repo's `tools/eegcc_shim.py` and GNU `as` 2.12-ee. "
               "ee-gcc and the EE assembler are i386 ELFs with a fixed `/lib/ld-linux.so.2` interpreter; on a host without it the harness "
               "runs inside a bubblewrap mount namespace that supplies the user's 32-bit loader at that path (tmpfs overlay, nothing "
               "on the host changes). Every function is vendor code (CRI middleware, Sony SDK): the decompilation's sources for it were "
               "written by hand against retail, with no m2c in the loop. m2c runs as `-t mipsee-gcc-c`; there is no per-function "
               "`#pragma` state (ee-gcc is configured by the shim's fixed flags), and the context is `ee-gcc -E` of the unit with "
               "INCLUDE_ASM/INCLUDE_RODATA removed.")


MWCC_PROMOTED = ("The matched set is the decompilation's own, and its sources were produced with m2c (and sometimes romwright) in the loop "
                 "(`tools/m2c_bulk.py` promotes verified m2c candidates into `src/promoted`). The `promoted` and `other` strata are reported "
                 "separately; the m2c number on `promoted` is an upper bound, not a measure of m2c on unseen code.")


def limits(lane="mwcc"):
    return ([EEGCC_LIMIT] if lane == "eegcc" else [MWCC_LIMIT, MWCC_PROMOTED]) + LIMITS


LIMITS = [
    "Per-function `#pragma` state (optimisation level, scheduling) is replayed from the unit's source for every layer: it is the compiler "
    "configuration the match depends on, but a decompiler cannot choose it. `#if` branches are evaluated by a fixed rule "
    "(`#if 0`, `NON_MATCHING`, `RWDEBUG`, `RWSUPPRESSINLINE`, `DUNROAMIN` inactive).",
    "The context is the unit's own declarations, including the target's prototype and every data declaration of the unit, as in m22-001. "
    "romwright and m2c are given them (assert-prototypes / --context); stock Ghidra is not: its text keeps its own signatures, so the unit's prototype "
    "for the target is dropped from the context of its compiles, and its globals are declared as Ghidra typed them (`ExportDecompiledC.java`; "
    "gp-named globals the script could not resolve from the prefix Ghidra put on the name).",
    "romwright prototypes are asserted sequentially in address order into one project; a callee absent from a unit's declarations keeps a prototype "
    "asserted for an earlier unit.",
    "`export-c --context` also hands the unit's declarations to the printer, which casts a pointer where the context declares an integer (and the "
    "reverse), takes the declared return type for a local a callee's result is assigned to, prints the target with the declared parameter types and drops "
    "arguments a declaration does not have. The standalone variant is the same text compiled without those declarations, so what it fails on is "
    "what the text leaves to them (a callee left to `Supplied declaration required`, a callee result assigned to a local of the other kind).",
    "m2c reads the repo's splat assembly. Its input differs from the repo file only by `%gp_rel(symbol)($gp)` operands and jump-table "
    "rows (recorded per function). Reassembly parity is not checked (the repo's own regenerate-asm proves the fallback files byte-exact; the "
    "rewrite preserves register and offset by construction).",
    "Retail bytes carry no relocations, so objdiff ignores relocation targets (`functionRelocDiffs=none`); `exact_symbols` is the stricter count.",
    "A function counts as compiled only if the object defines the target symbol; the compile-failure share counts a function the tool produced no text for "
    "as a failure (`produced` is the other column).",
    "The sample is up to 200 functions from the eligible rows; the sign tests treat functions as independent although they share units and pragma state, so their p values are indicative.",
    "romwright's import of the retail ELF is `partial` (switch decompile budget on a few functions, recorded under `romwright_project`); a matched function "
    "that import did not discover has no `export-c` candidate.",
    "Stock Ghidra's text is not meant to compile; its candidates get typedefs for Ghidra's primitive names and nothing else (no CONCAT/SUB macros).",
]


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--work", type=Path, default=DEFAULT_WORK)
    parser.add_argument("--report", type=Path, help="JSON report; the .md is written beside it "
                        "(default benchmarks/reports/m22-ps2_p4.json, or m22-ps2_p4_eegcc.json with --compiler eegcc)")
    parser.add_argument("--compiler", choices=COMPILERS, default="mwcc",
                        help="the lane: matched functions of the units built with MWCCPS2 (default), or with ee-gcc 2.96 "
                             "(config/gcc_units.txt; needs ee-gcc, the EE assembler and a 32-bit glibc)")
    parser.add_argument("--glibc32", type=Path, default=GLIBC32,
                        help="directory with the 32-bit ld-linux.so.2 and libc.so.6 the i386 ee-gcc and EE assembler run on")
    parser.add_argument("--repo", type=Path, help="existing checkout of the decompilation at the pinned commit")
    parser.add_argument("--commit", default=P4_COMMIT)
    parser.add_argument("--toolchain", type=Path, default=TOOLCHAIN)
    parser.add_argument("--n", type=int, default=SAMPLE)
    parser.add_argument("--seed", type=int, default=SEED)
    parser.add_argument("--layers", default=",".join(LAYERS))
    parser.add_argument("--only", default="", help="comma-separated function names (debugging; the report is then not the pinned run)")
    parser.add_argument("--cli", type=Path, default=Path(os.environ.get("ROMWRIGHT_CLI") or REPO / "target/release/romwright-cli"))
    parser.add_argument("--worker", type=Path, default=Path(os.environ.get("ROMWRIGHT_WORKER") or REPO / "target/release/romwright-worker"))
    parser.add_argument("--ghidra-opt", type=Path, default=Path(os.environ.get("ROMWRIGHT_GHIDRA_OPT") or REPO / "native/build/ghidra_opt"))
    parser.add_argument("--stock-json", type=Path, help="stock Ghidra export (signatures.json) for these addresses, instead of running Ghidra")
    parser.add_argument("--stock-timeout", type=int, default=STOCK_TIMEOUT)
    parser.add_argument("--stock-export-only", type=Path, metavar="ADDRESSES_FILE",
                        help="only run stock Ghidra on the ELF for the hex addresses in this file; writes <work>/stock/signatures.json")
    parser.add_argument("--sample-out", type=Path, metavar="FILE",
                        help="write the sample's hex addresses (for --stock-export-only on another host) and exit")
    parser.add_argument("--fresh-import", action="store_true")
    parser.add_argument("--refresh-verify", action="store_true")
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--redo-report", type=Path, metavar="REPORT_JSON",
                        help="recompute summary, limits and markdown of an existing report from its function rows (no tools run)")
    parser.add_argument("--search", type=int, default=0, metavar="N",
                        help="near-miss search (docs/match.md): for each function whose default romwright print compiles and is not exact, "
                             "try up to N alternative printings (`romwright-cli match --plan`) and add the `romwright-search` layer")
    args = parser.parse_args()
    args.report = args.report or (DEFAULT_EE_REPORT if args.compiler == "eegcc" else DEFAULT_REPORT)
    args.layers = [layer for layer in args.layers.split(",") if layer]
    if args.search:
        if "romwright" not in args.layers:
            parser.error("--search needs the romwright layer")
        args.layers.insert(args.layers.index("romwright") + 1, "romwright-search")
    if args.selftest:
        return selftest()
    if args.redo_report:
        report = json.loads(args.redo_report.read_text())
        report["summary"] = summarise(report["functions"], report["layers"])
        report["limits"] = limits(report.get("lane", "mwcc"))
        args.redo_report.write_text(json.dumps(report, indent=1))
        args.redo_report.with_suffix(".md").write_text(markdown(report))
        print(f"m22-002 report rewritten: {args.redo_report}")
        return 0
    args.work = args.work.resolve()
    args.work.mkdir(parents=True, exist_ok=True)

    if args.stock_export_only:
        addresses = [int(line, 16) for line in args.stock_export_only.read_text().split() if line]
        _, info = stock_export(args, addresses, args.work / "stock")
        print(json.dumps(info))
        return 0

    ensure_ee_loader(args)
    preflight(args)
    bindir = write_wrappers(args.work, args.toolchain)
    env = p4_env(args.work, args.toolchain, bindir, args.glibc32 if args.compiler == "eegcc" else None)
    repo = ensure_repo(args, env)
    report, report_path = verify_report(args, repo, env)
    project = Project(repo, env)
    args._project_names = project.names

    log("selecting the sample")
    functions, rejected, eligible = select_functions(project, report, args)
    if args.only:
        wanted = set(args.only.split(","))
        functions = [f for f in functions if f["name"] in wanted]
    log(f"{len(functions)} functions ({eligible} eligible; rejected {rejected})")

    if args.sample_out:
        args.sample_out.write_text("".join(f"{f['address']:x}\n" for f in functions))
        print(f"{len(functions)} addresses written to {args.sample_out}")
        return 0

    macros_info = m2c_info()
    macros = m2c_macros(args.work, macros_info["commit"])
    # ROMWRIGHT_STRUCTS is the one other setting a run may carry in: it selects the struct layer under test.
    cli_env = {k: v for k, v in os.environ.items()
               if not k.startswith("ROMWRIGHT_") or k in ("ROMWRIGHT_GHIDRA", "ROMWRIGHT_STRUCTS")}
    cli_env.update(ROMWRIGHT_GHIDRA_OPT=str(args.ghidra_opt), ROMWRIGHT_WORKER=str(args.worker),
                   ROMWRIGHT_NO_IMPORT_CACHE="1", ROMWRIGHT_NO_FACT_PACK="1", ROMWRIGHT_GHIDRA=str(GHIDRA), TMPDIR=str(args.work / "tmp"))

    layers_report = {}
    romwright_record = None
    if "romwright" in args.layers:
        _, romwright_record = import_romwright(args, args.work, cli_env, log)
        romwright_record["assert_names"] = romwright_names(args.work, cli_env, args)
    stock = None
    if "stock" in args.layers:
        addresses = sorted(f["address"] for f in functions)
        if args.stock_json:
            stock = {"functions": json.loads(args.stock_json.read_text())["functions"]}
            stock_info = {"cached": True, "source": str(args.stock_json)}
        else:
            log("running stock Ghidra headless (analysis + decompile of the sample)")
            data, stock_info = stock_export(args, addresses, args.work / "stock")
            stock = {"functions": data["functions"]}
        stock["info"] = stock_info
        stock["functions"] = {f"{int(k, 16):x}": v for k, v in stock["functions"].items()}

    out = {}
    for row in functions:
        name, address = row["name"], row["address"]
        row["dir"] = args.work / "functions" / f"{address:08x}_{name}"
        row["dir"].mkdir(parents=True, exist_ok=True)
        log(f"{name} {address:08x} ({row['file']}, {row['size']} bytes)")
        context_path = row["dir"] / "context.c"
        typedefs_text = missing_typedefs(row["context"]) + row["context"]
        # the context m2c and romwright read is exactly what the compile sees
        context = typedefs_text
        context_path.write_text(context)
        row["context_text"] = context
        entry = {"name": name, "address": f"{address:#x}", "file": row["file"], "line": row["line"], "size": row["size"],
                 "compiler": row["compiler"], "flags": row["flags"], "origin": row["origin"], "family": row["family"],
                 "pragmas": row["pragmas"], "layers": {}}
        assembly, asm_note = m2c_assembly(project, name, address, row["relocations"])
        needed = [name] + sorted(set(re.findall(r"\b(?:jal|j)\s+([A-Za-z_]\w*)", assembly)) - {name})
        for layer in args.layers:
            if layer == "romwright-search":
                continue  # produced with the romwright layer
            if layer == "romwright":
                typedefs = typedef_table(context)
                text, produce = romwright_candidate(args, args.work, cli_env, row, context_path, row["protos"], typedefs, needed)
            elif layer == "m2c":
                mdir = row["dir"] / "m2c"
                mdir.mkdir(exist_ok=True)
                text, produce = m2c_candidate(mdir, name, assembly, context_path,
                                              "mipsee-gcc-c" if args.compiler == "eegcc" else "mipsee-mwcc-c")
                produce.update(asm_note)
            else:
                text, produce = stock_candidate(row, stock)
            if text is not None:
                (row["dir"] / layer).mkdir(exist_ok=True)
                (row["dir"] / layer / "raw.c").write_text(text)
            variants = score_candidate(project, args, row, layer, text, context, row["pragmas"], macros)
            entry["layers"][layer] = {"produce": produce, "variants": variants}
            if layer == "romwright" and args.search:
                entry["layers"]["romwright-search"] = search_layer(project, args, cli_env, row, context_path, context, macros, text, variants)
        out[f"{address:08x}"] = entry

    summary = summarise(out, args.layers)
    generated = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    cli_sha = sha256_file(args.cli)
    result = {
        "schema": "m22-002-ps2-c-output/1", "lane": args.compiler,
        "generated": generated,
        "layers": args.layers,
        "repo": {"url": P4_URL, "commit": args.commit, "verify_summary": report.get("summary"),
                 "verify_report": str(report_path)},
        "sample": {"n": len(out), "requested": args.n, "seed": args.seed, "eligible": eligible, "rejected": rejected,
                   "size_bytes": [SIZE_MIN, SIZE_MAX], "partial": bool(args.only)},
        "toolchain": {
            "mwcc_b210_sha1": hashlib.sha1((args.toolchain / "mwccps2.exe").read_bytes()).hexdigest(),
            "mwcc_b119_sha1": hashlib.sha1((args.toolchain / "cw3.0.1b119" / "mwccps2.exe").read_bytes()).hexdigest(),
            "retail_elf_sha1": P4_ELF_SHA1, "wibo": shutil.which("wibo"), "objdiff": str(OBJDIFF),
            "objdiff_version": run([OBJDIFF, "--version"])["stdout"].strip(),
            "assembler": project.cfg and os.environ.get("P4_AS"),
            "m2c": macros_info, "ghidra": str(GHIDRA) if "stock" in args.layers else None,
            "romwright": {"cli": str(args.cli), "cli_sha256": cli_sha, "worker_sha256": sha256_file(args.worker),
                          "ghidra_opt_sha256": sha256_file(args.ghidra_opt)},
        },
        "romwright_project": romwright_record,
        "stock": stock["info"] if stock else None,
        "summary": summary,
        "limits": limits(args.compiler),
        "functions": out,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=1))
    args.report.with_suffix(".md").write_text(markdown(result))
    parts = []
    for layer in args.layers:
        b = summary["overall"]["all"][layer]["context"]
        parts.append(f"{layer}: exact {b['exact']}/{b['functions']} mean {b['mean_percent']}% compile-fail {b['compile_failure_share']:.1%}")
    print("m22-002 " + " | ".join(parts) + f" | report {args.report}")
    return 0


def selftest():
    text = """typedef unsigned char u8;
extern u32 func_001(u8 *a, s32 b);
static u64 iGp = 1;
u32 table[] = { 1, 2, 3 };
struct S { u32 x; };
typedef struct S S;
// comment with ; and { in it
s32 helper(S *s, int (*cb)(void))
{
    if (s) { return 1; }
    return "}" [0];
}
static void inner(void) { }
extern void use(void);
"""
    knr = split_chunks("s32 f(a, b)\ns32 a;\ns32 b;\n{\n    return a + b;\n}\nextern s32 g(s32 x);\n")
    assert [c["kind"] for c in knr] == ["funcdef", "decl"] and knr[0]["name"] == "f" and declaration_text(knr[0]) == "s32 f();", knr
    chunks = split_chunks(text)
    kinds = [c["kind"] for c in chunks]
    assert kinds == ["decl", "decl", "decl", "decl", "decl", "decl", "funcdef", "funcdef", "decl"], kinds
    assert chunks[6]["name"] == "helper" and chunks[7]["name"] == "inner"
    decls = [declaration_text(c) for c in chunks]
    assert decls[1] == "extern u32 func_001(u8 *a, s32 b);", decls[1]
    assert decls[2] == "extern u64 iGp;", decls[2]
    assert decls[3] == "extern u32 table[];", decls[3]
    assert decls[6] == "s32 helper(S *s, int (*cb)(void));", decls[6]
    assert decls[7] == "void inner(void);", decls[7]
    assert prototype_of(chunks[6]) == ("s32", "S *s, int (*cb)(void)", "helper")
    typedefs = typedef_table("typedef unsigned char u8;\ntypedef u8 bool;\ntypedef struct S S;\ntypedef int (*code)();\n")
    assert asserted_signature(("bool", "u8 *p, s32 n, code *cb, S *s", "f"), typedefs)[0] == \
        "byte f(byte * param_1, int param_2, void ** param_3, void * param_4)", asserted_signature(("bool", "u8 *p, s32 n, code *cb, S *s", "f"), typedefs)
    assert asserted_signature(("void", "S s", "g"), typedefs)[0] is None
    handles = typedef_table("typedef struct H_OBJ *Hn;\ntypedef char *Str;\n")
    assert handles == {"Hn": "struct H_OBJ *", "Str": "char *"}, handles
    assert asserted_signature(("int", "Hn h, Str s", "check"), handles)[0] == "int check(void * param_1, char * param_2)", \
        asserted_signature(("int", "Hn h, Str s", "check"), handles)
    td = {"u8": "unsigned char", "S": "struct S", "code": "struct __function *", "Mode": "int"}
    assert erase_prototype(("const S *", "S *a, const u8 *b, code cb, int (*f)(void), Mode m, u8 v[]", "g"), td) == \
        ("void *", "void *a, u8 *b, void *cb, void *f, Mode m, u8 *v", "g"), erase_prototype(("const S *", "S *a, const u8 *b, code cb, int (*f)(void), Mode m, u8 v[]", "g"), td)
    attributed = split_chunks("extern struct S D[] __attribute__((aligned(8)));\nextern void f(int a) __attribute__((noreturn));\n")
    assert prototype_of(attributed[0]) is None and prototype_of(attributed[1]) == ("void", "int a", "f"), [prototype_of(c) for c in attributed]
    assert declaration_text(attributed[0]) == "extern struct S D[] __attribute__((aligned(8)));", declaration_text(attributed[0])
    assert erase_extern("extern S *x;", td) == "extern void *x;" and erase_extern("extern u8 *y;", td) == "extern u8 *y;"
    assert source_pragmas("/* #pragma no */\n#pragma yes /* tail\n#pragma no2 */\nfunc\n", 4) == ["#pragma yes"]
    pragmas = source_pragmas("#pragma a\n#if 0\n#pragma b\n#else\n#pragma c\n#endif\n#ifdef NON_MATCHING\n#pragma d\n#endif\n#pragma e\nfunc\n", 11)
    assert pragmas == ["#pragma a", "#pragma c", "#pragma e"], pragmas

    class Fake:
        addresses = {0x763180: "iGpffffa090", 0x761108: "func_x"}
        names = {"iGpffffa090": (0x763180, "data"), "func_x": (0x761108, "func")}
    rewritten, count, _ = rewrite_gp(Fake, ["    /* 0 00192560 90A082DF */  ld         $2, -0x5F70($28)",
                                         "    /* 4 00192564 90A084FF */  addiu      $4, $28, 0x18",
                                         "    /* 8 00192568 00000000 */  lw         $2, 0x4($29)"])
    assert count == 2, rewritten
    assert "%gp_rel(iGpffffa090)($gp)" in rewritten[0] and "%gp_rel(D_00769108)" in rewritten[1] and rewritten[2].endswith("0x4($29)")
    assert sign_test(10, 0) < 0.01 and sign_test(5, 5) == 1.0
    print("m22-002 selftest ok")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except HarnessError as error:
        print(f"m22-002 harness error: {error}", file=sys.stderr)
        sys.exit(2)
