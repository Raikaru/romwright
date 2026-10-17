"""Classes of compile failures and of byte differences, shared by the m22-003 harness (which records them per candidate) and
`failure_classes.py` (which tallies them across lanes).

Compile diagnostics are classified from the compiler's own first message (gcc 2.x and MWCC wording); byte differences from a
word-level comparison of the candidate function and the retail bytes (MIPS fields decoded by hand from the ISA, nothing else).
"""
from __future__ import annotations

import difflib
import re

# ---------------------------------------------------------------------------
# Compile diagnostics
# ---------------------------------------------------------------------------

# (class, regex on the first message); first match wins. The class names are the table's rows.
DIAGNOSTIC_RULES = [
    ("no candidate produced", r"^no candidate"),
    ("object lacks the target symbol", r"^no symbol .* in the object"),
    ("128-bit (quadword) integer operation", r"unsupported wide integer|\bTImode\b|__int128|illegal type: 'long long long'"),
    ("incomplete type", r"incomplete (type|struct|union|class)|storage size of .* isn't known|illegal use of incomplete|size of .* unknown"),
    ("member access on a type the context lacks",
     r"structure has no member|request for member .* in something not a structure|is not a struct/union/class member|not a struct/union/class"
     r"|dereferencing pointer to incomplete|`.*' is not a member|illegal use of '.*'$|has no member"),
    ("conflicting types / redeclaration",
     r"conflicting types for|redeclared|redefinition of|illegal name overloading|previous declaration|redefined"),
    ("undeclared identifier", r"undeclared|undefined identifier|not declared|implicit declaration|Supplied declaration required"),
    ("illegal or unknown type name", r"^illegal type$|^illegal type\b|unknown type name|illegal type;|undefined type"),
    ("call does not match prototype",
     r"function call '.*' does not match|too (few|many) arguments|incompatible type for argument|passing arg|argument .* of .* from incompatible"),
    ("type mismatch (assignment, operand, return, cast)",
     r"incompatible types|illegal implicit conversion|cannot convert|invalid operands|invalid type argument|cast specifies (array|function) type"
     r"|illegal return value|pointer/array required|illegal constant expression|illegal use of|invalid (lvalue|use)|assignment to|lvalue required"
     r"|cast .* to .* of different size|illegal (operand|pointer)|incompatible|unsigned .* operand"),
    ("syntax error", r"parse error|syntax error|'.*' expected|expected .* before|missing terminating|illegal token|illegal function definition"
     r"|illegal declaration|stray|unterminated|illegal character|empty character constant"),
    ("assembler rejected the compiler's output", r"Assembler messages|Error: unrecognized opcode|Error: Rest of line ignored|\.end directive|Error: .*\bregister\b"
     r"|problematic short loop|assembler failed"),
    ("unit post-processing rejected the candidate object", r"postprocess_object|dng_main: expected"),
    ("wrapper or driver message (not a source diagnostic)", r"dropping Cygnus-only|^sn-cc-wrap|^eegcc_shim|Internal error|Segmentation|cannot run"),
]
COMPILED_RULES = [(name, re.compile(rx, re.I)) for name, rx in DIAGNOSTIC_RULES]
KNOWN = [name for name, _ in DIAGNOSTIC_RULES] + ["other"]


def normalise(message: str) -> str:
    message = re.sub(r"'[^']*'", "'X'", message)
    message = re.sub(r"`[^']*'", "`X'", message)
    message = re.sub(r"\b\d+\b", "N", message)
    return " ".join(message.split())[:110]


def classify_message(message: str) -> str:
    text = " ".join((message or "").split())
    for name, rx in COMPILED_RULES:
        if rx.search(text):
            return name
    return "other"


# gcc: `file:LINE: message` / `file:LINE:COL: message`; MWCC: a block `#   LINE: code` / `#   Error: ^` / `#   message`.
GCC_DIAGNOSTIC = re.compile(r"^(?P<file>[^\n:]*):(?P<line>\d+):(?>(?:\d+:)?\s*)(?!warning)(?P<msg>[^\n]+)", re.M)
MWCC_DIAGNOSTIC = re.compile(r"^#\s+(?P<line>\d+):\s?(?P<code>[^\n]*)\n#\s+Error:[^\n]*\n#\s+(?P<msg>[^\n]+)", re.M)


GCC_RELATED = re.compile(r"^[^\n:]*:(?P<line>\d+):(?>(?:\d+:)?\s*)(?P<msg>(?:previous|this is the location of the previous)[^\n]*)", re.M)


def parse_diagnostics(log_text: str, source_text: str | None, limit: int = 3):
    """The first compile errors of a log: [{message, line, source, around, related}], in order of appearance. MWCC prints the offending
    source line itself; for gcc it is taken from `source_text` (the file the harness wrote) by line number. `around` is the line
    and the two before it (a definition head ends on the line before its `{`); `related` is the line of a `previous declaration`
    note that follows a conflicting-types error."""
    found = []
    for match in MWCC_DIAGNOSTIC.finditer(log_text):
        found.append((match.start(), {"message": match.group("msg").strip(), "line": int(match.group("line")),
                                      "source": match.group("code").strip()[:200], "around": None, "related": None}))
    lines = source_text.splitlines() if source_text else []

    def text_at(number):
        return lines[number - 1].strip()[:200] if 0 < number <= len(lines) else None

    related = [(m.start(), int(m.group("line"))) for m in GCC_RELATED.finditer(log_text)]
    for match in GCC_DIAGNOSTIC.finditer(log_text):
        message = match.group("msg").strip()
        if message.startswith(("In function", "(Each undeclared", "for each function", "warning:", "previous declaration", "this is the location")):
            continue
        number = int(match.group("line"))
        usable = match.group("file").endswith((".c", ".cc", ".cpp", ".i"))
        around = [t for t in (text_at(n) for n in range(number - 2, number + 1)) if t] if usable and lines else None
        follow = next((n for pos, n in related if pos > match.start()), None) if "conflicting" in message or "redeclar" in message else None
        found.append((match.start(), {"message": message, "line": number, "source": text_at(number) if usable else None,
                                      "around": around, "related": {"line": follow, "source": text_at(follow)} if follow else None}))
    found.sort(key=lambda item: item[0])
    unique, seen = [], set()
    for _, item in found:
        key = (item["message"], item["line"])
        if key not in seen:
            seen.add(key)
            unique.append(item)
    for item in unique:
        item["class"] = classify_message(item["message"])
    return unique[:limit]


# ---------------------------------------------------------------------------
# Byte differences (R5900 / MIPS fields)
# ---------------------------------------------------------------------------

LOADS = {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x1A, 0x1B, 0x37, 0x1E, 0x31, 0x35, 0x39, 0x3D}
STORES = {0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x3F, 0x1F, 0x39, 0x3D, 0x38, 0x3C}
LOAD_STORE = LOADS | STORES | {0x31, 0x35, 0x39, 0x3D}
SP = 29


def fields(word: int):
    return {"op": word >> 26, "rs": (word >> 21) & 31, "rt": (word >> 16) & 31, "rd": (word >> 11) & 31, "sa": (word >> 6) & 31,
            "funct": word & 63, "imm": word & 0xFFFF, "target": word & 0x03FFFFFF}


def is_extension(word: int) -> bool:
    """sll/sra by 16/24/32-ish or andi/ori: the shape of a sign or zero extension the compiler inserts for a narrow type."""
    f = fields(word)
    return (f["op"] == 0 and f["funct"] in (0, 3) and f["sa"] in (16, 24, 8)) or f["op"] in (0x0C,) or (f["op"] == 0 and f["funct"] in (4, 7, 0x3C, 0x3F))


BRANCHES = {1, 4, 5, 6, 7, 0x14, 0x15, 0x16, 0x17}


def classify_word_pair(a: int, b: int) -> str:
    """How two different instruction words differ: register, stack, immediate, width/sign (type), branch, or instruction."""
    fa, fb = fields(a), fields(b)
    if not (fa["op"] == fb["op"] and (fa["op"] != 0 or fa["funct"] == fb["funct"])):
        if fa["op"] in LOAD_STORE and fb["op"] in LOAD_STORE and (fa["rs"], fa["rt"], fa["imm"]) == (fb["rs"], fb["rt"], fb["imm"]):
            return "access width or signedness"
        return "different instruction"
    if fa["op"] in (2, 3):
        return "branch/call target"
    if fa["op"] == 0:
        if (fa["rs"], fa["rt"], fa["rd"]) == (fb["rs"], fb["rt"], fb["rd"]):
            return "shift amount" if fa["sa"] != fb["sa"] else "different instruction"
        return "register"
    regs_same = (fa["rs"], fa["rt"]) == (fb["rs"], fb["rt"])
    if fa["imm"] == fb["imm"]:
        return "register"
    if fa["op"] in BRANCHES:
        return "branch target"
    if regs_same:
        return "stack offset" if fa["rs"] == SP else "immediate"
    if fa["rs"] == SP and fb["rs"] == SP:
        return "stack offset"
    return "register and immediate"


def is_nop_or_move(word: int) -> bool:
    f = fields(word)
    return word == 0 or (f["op"] == 0 and f["funct"] in (0x21, 0x25, 0x2D, 0x2C) and f["rt"] == 0)  # addu/or/daddu/dadd rd,rs,$zero


def is_frame_adjust(word: int) -> bool:
    f = fields(word)
    return f["op"] in (9, 0x19) and f["rs"] == SP and f["rt"] == SP


def is_stack_access(word: int) -> bool:
    f = fields(word)
    return f["op"] in LOAD_STORE and f["rs"] == SP


def word_kind(word: int) -> str:
    """A coarse kind of an instruction word, to say what a structural difference is made of."""
    f = fields(word)
    if word == 0:
        return "nop"
    if f["op"] == 0 and f["funct"] in (0x21, 0x25, 0x2D, 0x2C) and f["rt"] == 0:
        return "register copy"
    if f["op"] in (9, 0x19) and f["rs"] == SP and f["rt"] == SP:
        return "stack frame adjust"
    if f["op"] in LOAD_STORE:
        return "memory access"
    if f["op"] in BRANCHES or f["op"] in (2, 3) or (f["op"] == 0 and f["funct"] in (8, 9)):
        return "branch or call"
    if f["op"] == 0x11:
        return "floating point"
    if f["op"] == 0x12:
        return "vector unit"
    return "arithmetic or immediate"


def describe_mix(words) -> tuple[dict, str]:
    mix: dict[str, int] = {}
    for w in words:
        k = word_kind(w)
        mix[k] = mix.get(k, 0) + 1
    total = max(sum(mix.values()), 1)
    share = lambda *names: sum(mix.get(n, 0) for n in names) / total  # noqa: E731
    if share("branch or call") >= 0.25:
        label = "control flow (branches, calls)"
    elif share("memory access") >= 0.5:
        label = "memory accesses (temporaries, spills, widths)"
    elif share("nop", "register copy") >= 0.5:
        label = "nops and register copies"
    elif share("floating point", "vector unit") >= 0.5:
        label = "floating-point or vector sequence"
    else:
        label = "mixed arithmetic (expression shape)"
    return mix, label


def normal(word: int) -> int:
    """A word without its branch offset: code that shifts moves every branch's offset without changing the branch."""
    return word & ~0xFFFF if (word >> 26) in BRANCHES else word


def classify_diff(body: bytes, mask: bytes, retail: bytes) -> dict:
    """Classify the candidate function against the retail bytes. `mask` has 0xFF where a byte is compared (relocation fields 0).
    -> {"kind": ..., "differing_words": n, "length_delta_words": d, "pairs": {class: count}}"""
    cand = [int.from_bytes(body[i:i + 4], "little") for i in range(0, len(body) - len(body) % 4, 4)]
    ref = [int.from_bytes(retail[i:i + 4], "little") for i in range(0, len(retail) - len(retail) % 4, 4)]
    keep = [int.from_bytes(mask[i:i + 4], "little") for i in range(0, len(mask) - len(mask) % 4, 4)] if mask else [0xFFFFFFFF] * len(cand)
    keep += [0xFFFFFFFF] * (max(len(cand), len(ref)) - len(keep))
    cand_m = [w & keep[i] for i, w in enumerate(cand)]
    ref_m = [w & keep[i] for i, w in enumerate(ref)]
    out = {"differing_words": 0, "length_delta_words": len(cand) - len(ref), "pairs": {}}
    if len(cand) == len(ref):
        pairs = {}
        for a, b in zip(cand_m, ref_m):
            if a != b:
                kind = classify_word_pair(a, b)
                pairs[kind] = pairs.get(kind, 0) + 1
        out["pairs"] = pairs
        out["differing_words"] = sum(pairs.values())
        if not pairs:
            out["kind"] = "exact"
        elif out["differing_words"] == 1:
            out["kind"] = "single instruction: " + next(iter(pairs))
        elif sorted(map(normal, cand_m)) == sorted(map(normal, ref_m)):
            out["kind"] = "same instructions, different order (scheduling)"
        elif set(pairs) <= {"register"}:
            out["kind"] = "register allocation"
        elif set(pairs) <= {"stack offset"}:
            out["kind"] = "stack layout"
        elif set(pairs) <= {"register", "stack offset", "register and immediate", "immediate"}:
            out["kind"] = "register allocation and stack layout"
        elif set(pairs) <= {"access width or signedness"}:
            out["kind"] = "access width or signedness (type or cast)"
        elif out["differing_words"] <= 4:
            out["kind"] = "few instructions differ (<= 4)"
        else:
            differing = [a for a, b in zip(cand_m, ref_m) if a != b] + [b for a, b in zip(cand_m, ref_m) if a != b]
            out["mix"], label = describe_mix(differing)
            out["kind"] = "same length, many instructions differ: " + label
        return out
    # different length: what was inserted or removed
    matcher = difflib.SequenceMatcher(a=[normal(w) for w in cand_m], b=[normal(w) for w in ref_m], autojunk=False)
    extra, missing = [], []
    for tag, a0, a1, b0, b1 in matcher.get_opcodes():
        if tag in ("delete", "replace"):
            extra += cand_m[a0:a1]
        if tag in ("insert", "replace"):
            missing += ref_m[b0:b1]
    both = extra + missing
    out["differing_words"] = len(both)
    out["extra_words"], out["missing_words"] = len(extra), len(missing)
    if both and all(is_extension(w) for w in both):
        out["kind"] = "length differs: extension instructions (type or cast)"
    elif both and all(is_nop_or_move(w) for w in both):
        out["kind"] = "length differs: nops or register copies (allocation or scheduling)"
    elif both and all(is_frame_adjust(w) or is_stack_access(w) for w in both):
        out["kind"] = "length differs: stack frame and spills (stack layout)"
    elif len(both) <= 4:
        out["kind"] = "length differs: few instructions (<= 4)"
    else:
        out["mix"], label = describe_mix(both)
        out["kind"] = "length differs: " + label
    return out
