#!/usr/bin/env python3
"""Where romwright's C output loses on the m22-004 (x86 PE) lanes: compile-failure classes and byte-difference classes.

The PC counterpart of tests/m22-003/failure_classes.py. Input: a lane report (`--report`) and the lane's `--artifacts` directory
(per function: `candidate.c`, `compile.log`, `bytes.json` with the candidate's and retail bytes and the candidate's relocations).

    failure_classes.py REPORT.json ARTIFACTS_DIR [--out STEM]

Every non-exact function is one class:

  not produced              no function at the truth address (discovery)
  compile: <error class>    the first compiler error, grouped (see COMPILE_RULES)
  bytes: <class>            compiled, not exact; the first of
      length (shorter|longer)            the instruction counts differ (the remaining difference is described by the tags)
      single instruction                 one instruction differs
      register allocation                same instructions, registers differ
      scheduling / order                 same instruction multiset, different order
      stack frame size                   only `esp`/`ebp` displacements and `sub esp, N` differ
      immediates / displacements         same shapes, operand values differ (struct offsets, constants, strides)
      relocation target                  the instructions are equal but a relocation names the wrong address (strict check)
      different instructions             the same length with different mnemonics
  tags (a function may carry several, they say *what* the instructions that differ are): x87, switch table, rep string op,
  inlined call (candidate calls, retail has code or the reverse), 64-bit helper (`__allmul` ...), `__ftol`, security cookie,
  `call` count differs, branch inversion.
"""
from __future__ import annotations

import argparse
import collections
import difflib
import json
import re
import sys
from pathlib import Path

try:
    import capstone
except ImportError:  # pragma: no cover
    sys.exit("failure_classes.py needs the capstone Python module")

MD = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
MD.detail = False

COMPILE_RULES = [
    ("undeclared stack/local identifier (stack layout)", re.compile(r"'(stack0x|local_|in_|unaff_|extraout_)[^']*'\s*:?\s*undeclared|undeclared identifier.*stack0x|stack0x", re.I)),
    ("partial member access (x._N_M_)", re.compile(r"\._\d+_\d+_|is not a member|left of '\.\w*' must have", re.I)),
    ("undeclared identifier", re.compile(r"C2065|undeclared identifier|undeclared \(first use", re.I)),
    ("syntax: type or keyword", re.compile(r"C2061|C2143|C2146|C2059|C2146|C2086|C2371|expected", re.I)),
    ("conflicting / incompatible types", re.compile(r"C2371|C2373|C2440|C2446|C2449|C2037|C2223|C2297|C2036|C2198|C2106|C2100|C2109|C2064|C2114|C2171|C2172|C2173|C2088|C2105|conflicting|incompatible", re.I)),
    ("not an l-value / assignment", re.compile(r"C2105|C2106|l-value|lvalue", re.I)),
    ("redefinition / duplicate", re.compile(r"C2374|C2084|C2365|redefin", re.I)),
    ("too many / too few arguments", re.compile(r"C2198|C4087|too (many|few)", re.I)),
    ("label / goto", re.compile(r"C2143|C2047|label", re.I)),
    ("inline asm / keyword", re.compile(r"C2415|C2400|__asm|__declspec", re.I)),
]

BRANCH = re.compile(r"^(j\w+|loop\w*)$")
REGS = re.compile(r"\b(e?[abcd]x|e?[sd]i|e?[sb]p|[abcd][lh]|st\(\d\)|xmm\d)\b")
HEX = re.compile(r"0x[0-9a-f]+|\b\d+\b")


def decode(blob: bytes, address: int = 0x1000):
    return list(MD.disasm(blob, address))


BIG = re.compile(r"0x([0-9a-f]{6,8})\b")
# an image address: a PE32 image of a game maps inside 0x400000-0x2000000; larger immediates (`0x7fffffff`, `0xffffff00`) are constants
IMAGE_LOW, IMAGE_HIGH = 0x400000, 0x2000000


NOP = re.compile(r"^(nop|lea (e..), \[\2( \+ 0)?\]|lea (e..), (cs|ds):\[\4\]|mov (e..), \6|xchg ax, ax|int3)\b|^nop ")


def is_padding(ins) -> bool:
    """Alignment padding (`nop`, `lea esi, [esi]`, `mov edi, edi`, `int3`): not code either side's source chose."""
    return bool(NOP.match(f"{ins.mnemonic} {ins.op_str}".strip()))


def texts(instructions, retail: bool):
    """Per instruction: (mnemonic, operands) with image addresses (>= 0x400000) reduced to 0 on the retail side (a relocation
    field is zero in the object) and branch/call targets to `T`."""
    out = []
    for ins in instructions:
        if is_padding(ins):
            continue
        mnemonic, ops = ins.mnemonic, ins.op_str
        if BRANCH.match(mnemonic) or mnemonic == "call":
            ops = "T" if not ("[" in ops or re.search(r"\b[er]?[a-d]x|e[sd]i|ebp|esp\b", ops)) else BIG.sub("0x0", ops)
        elif retail:
            ops = BIG.sub(lambda m: "0x0" if int(m.group(1), 16) >= 0x400000 else m.group(0), ops)
        ops = re.sub(r" \+ 0x0\b(?!\w)", "", ops)
        ops = re.sub(r"\b0x0\b", "0", ops)
        out.append((mnemonic, ops))
    return out


def shape(item):
    mnemonic, ops = item
    return mnemonic, HEX.sub("N", REGS.sub("R", ops))


def regs_only(a, b):
    return shape(a) == shape(b) and HEX.sub("N", a[1]) != HEX.sub("N", b[1]) and not (HEX.findall(a[1]) != HEX.findall(b[1]))


def mnemonic_group(mnemonic: str) -> str:
    if mnemonic.startswith("f"):
        return "x87"
    if BRANCH.match(mnemonic) or mnemonic == "call" or mnemonic.startswith("ret"):
        return "control flow and calls"
    if mnemonic.startswith(("rep", "movs", "stos", "scas", "cmps")):
        return "string operations"
    if mnemonic in ("push", "pop") or (mnemonic == "add" or mnemonic == "sub"):
        return "stack and arithmetic"
    return "moves and arithmetic"


def stack_related(item):
    return bool(re.search(r"\[(esp|ebp)", item[1])) or (item[0] in ("sub", "add") and item[1].startswith("esp,"))


def classify(cand: bytes, retail: bytes, relocations, size: int, wrong_relocs: int):
    ctext = texts(decode(cand), False)
    rtext = texts(decode(retail[:size]), True)
    cm, rm = [t[0] for t in ctext], [t[0] for t in rtext]
    tags = set()
    for label, check in (("x87", lambda m: m.startswith("f")),
                         ("rep string op", lambda m: m.startswith("rep") or m in ("movsd", "movsb", "stosd", "stosb", "scasb", "cmpsb", "movsw", "stosw"))):
        if any(check(m) for m in cm) != any(check(m) for m in rm) or (label == "x87" and any(check(m) for m in rm) and ctext != rtext):
            tags.add(label)
    if any(m == "jmp" and re.search(r"\*4", o) for m, o in ctext + rtext):
        tags.add("switch table")
    if cm.count("call") != rm.count("call"):
        tags.add("call count differs")

    def float_call_pairs(items):
        # an x87 value computed and left on the stack across a `call`: the argument of `__ftol` (the runtime's float-to-integer helper)
        return sum(1 for a, b in zip(items, items[1:]) if a[0].startswith("f") and not a[0].startswith(("fst", "fcomp", "fnst", "fldcw", "fnclex")) and b[0] == "call")
    if float_call_pairs(rtext) > float_call_pairs(ctext):
        tags.add("float-to-int helper (`__ftol`) argument lost")
    if any(re.match(r"xor e.., (esp|ebp)", f"{m} {o}") for m, o in rtext) != any(re.match(r"xor e.., (esp|ebp)", f"{m} {o}") for m, o in ctext):
        tags.add("security cookie")
    if [m in ("imul", "mul") for m in cm].count(True) != [m in ("imul", "mul") for m in rm].count(True) or \
            [m in ("shl", "sar", "shr") for m in cm].count(True) != [m in ("shl", "sar", "shr") for m in rm].count(True):
        tags.add("mul/shift strength reduction")
    if (cm.count("add"), ) != (rm.count("add"), ) and sum(1 for m, o in ctext if m == "add" and o.startswith("esp,")) != sum(1 for m, o in rtext if m == "add" and o.startswith("esp,")):
        tags.add("argument cleanup (`add esp`) differs")
    sm = difflib.SequenceMatcher(None, [shape(t) for t in ctext], [shape(t) for t in rtext], autojunk=False)
    hunks, reg, imm, structural = [], 0, 0, 0
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            for a, b in zip(ctext[i1:i2], rtext[j1:j2]):
                if a != b:
                    if HEX.findall(a[1]) != HEX.findall(b[1]):
                        imm += 1
                    else:
                        reg += 1
            continue
        structural += max(i2 - i1, j2 - j1)
        hunks.append({"cand": [f"{m} {o}" for m, o in ctext[i1:i2]], "retail": [f"{m} {o}" for m, o in rtext[j1:j2]]})
    edits = structural + reg + imm
    if not structural:
        if not (reg or imm):
            return ("relocation target" if wrong_relocs else "exact after normalising"), tags, 0, hunks
        if imm and not reg:
            stack = all(stack_related(a) for a, b in zip(ctext, rtext) if a != b)
            return ("stack frame size" if stack else "immediates / displacements"), tags, edits, hunks
        if edits == 1:
            return "single instruction", tags, 1, hunks
        return ("register allocation" if not imm else "register allocation + immediates"), tags, edits, hunks
    if len(ctext) != len(rtext):
        kind = "length (candidate longer)" if len(ctext) > len(rtext) else "length (candidate shorter)"
        if abs(len(ctext) - len(rtext)) <= 2 and structural <= 3:
            kind = "few instructions differ in count"
        else:
            # what the differing instructions are made of
            weight = collections.Counter()
            for hunk in hunks:
                for text in hunk["cand"] + hunk["retail"]:
                    weight[mnemonic_group(text.split()[0])] += 1
            if weight:
                kind += f", mostly {weight.most_common(1)[0][0]}"
        return kind, tags, edits, hunks
    if sorted(ctext) == sorted(rtext):
        return "scheduling / order", tags, edits, hunks
    if edits == 1:
        return "single instruction", tags, 1, hunks
    return "different instructions (same length)", tags, edits, hunks


def compile_class(message: str) -> str:
    text = " ".join((message or "").split())
    for name, rx in COMPILE_RULES:
        if rx.search(text):
            return name
    return "other"


def analyse(report, artifacts: Path):
    classes = collections.defaultdict(list)
    tagged = collections.Counter()
    rows = {}
    for entry in report["functions"]:
        key = entry["address"]
        if entry["exact"]:
            continue
        if not entry["produced"]:
            cls = "not produced"
        elif not entry["compiled"]:
            log = artifacts / key / "compile.log"
            text = log.read_text(errors="replace") if log.exists() else entry.get("error", "")
            first = re.search(r"error (C\d+):\s*([^\n]*)", text)
            message = (first.group(0) if first else entry.get("error", ""))
            cls = "compile: " + compile_class(message)
            rows[key] = {"detail": message[:160]}
        else:
            raw = artifacts / key / "bytes.json"
            if not raw.exists():
                cls = "bytes: no artifact"
            else:
                data = json.loads(raw.read_text())
                kind, tags, edits, hunks = classify(bytes.fromhex(data["candidate"]), bytes.fromhex(data["retail"]), data["relocations"], data["size"], entry.get("relocs_wrong", 0))
                cls = "bytes: " + kind
                rows[key] = {"tags": sorted(tags), "edits": edits, "hunks": hunks[:12]}
                for tag in tags:
                    tagged[tag] += 1
        classes[cls].append(key)
        rows.setdefault(key, {})["class"] = cls
    return classes, tagged, rows


# class -> who owns the cause (the layer a fix belongs to). Filled from the functions read for docs/pc-project.md, not guessed.
OWNERS = {
    "not produced": "importer discovery (no function at the truth address)",
    "compile: undeclared stack/local identifier (stack layout)": "stack/global layout (`stack0x...`: SymbolLayout)",
    "compile: partial member access (x._N_M_)": "stack/global layout",
    "compile: conflicting / incompatible types": "decompiler type recovery (a stack slot used as a pointer and as a float)",
    "compile: syntax: type or keyword": "declarations of callees the decompiler named like a library function (`memcpy` with four arguments)",
    "compile: other": "mixed (the compiler crashed, call arity of a recursive call)",
    "bytes: length (candidate longer)": "decompiler structure and expression shape: the C is another source of the same behaviour",
    "bytes: length (candidate shorter)": "decompiler structure; x87 values the decompiler types as integers; inlined runtime code",
    "bytes: few instructions differ in count": "one or two instructions: float copies (`fld/fstp` for `mov`), `__ftol`, argument cleanup",
    "bytes: different instructions (same length)": "operand order of a compare, constants, register choice",
    "bytes: register allocation": "the compiler's allocation of the same instructions",
    "bytes: register allocation + immediates": "register allocation and constants",
    "bytes: single instruction": "one instruction (a compare form, a constant)",
    "bytes: stack frame size": "argument cleanup (`add esp, N`) merged or split",
    "bytes: scheduling / order": "evaluation order",
}


def markdown(title, report, classes, tagged):
    o = report["summary"]["overall"]
    lines = [f"# {title}", "", f"{o['exact']} exact / {o['compiled']} compiled / {o['mean_percent']} mean of {o['functions']} (tag `{report['tag']}`).", "",
             "| class | functions | cause / owner |", "|---|---|---|"]
    for cls, keys in sorted(classes.items(), key=lambda kv: -len(kv[1])):
        owner = OWNERS.get(cls) or next((v for k, v in OWNERS.items() if cls.startswith(k)), "")
        lines.append(f"| {cls} | {len(keys)} | {owner} |")
    if tagged:
        lines += ["", "Tags (what the differing instructions involve; a function may carry several):", ""]
        lines += [f"- {tag}: {count}" for tag, count in tagged.most_common()]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("report")
    parser.add_argument("artifacts")
    parser.add_argument("--out", default=None)
    args = parser.parse_args()
    report = json.loads(Path(args.report).read_text())
    classes, tagged, rows = analyse(report, Path(args.artifacts))
    result = {"tag": report["tag"], "fixture": report["fixture"]["id"], "overall": report["summary"]["overall"],
              "classes": {k: len(v) for k, v in sorted(classes.items(), key=lambda kv: -len(kv[1]))}, "tags": dict(tagged.most_common()),
              "functions": {k: rows.get(k, {}) | {"class": c} for c, keys in classes.items() for k in keys}}
    text = markdown(f"m22-004 failure classes: {report['fixture']['id']}", report, classes, tagged)
    if args.out:
        Path(args.out).with_suffix(".json").write_text(json.dumps(result, indent=1) + "\n")
        Path(args.out).with_suffix(".md").write_text(text)
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
