#!/usr/bin/env python3
"""Locals, stack slots and return types against the compiler's DWARF (supplement).

`console_research.py` scores a printed signature (arity, parameter and return
types) against DWARF. This scores the rest of what DWARF states about a
function, for the printed C of our decompiler and of stock Ghidra on the same
functions:

  locals       the number of automatic locals the printed body declares
               against the number the compiler's DWARF says the function has
               (`DW_TAG_variable` in the function and its lexical blocks, not
               statics, not variables with no location; inlined callees'
               variables are not counted), summed and per function: exactly
               equal / over (declared more) / under;
  stack slots  DWARF locals that live on the stack against the stack slots
               the printed C names (`local_<hex>`, `uStack_<hex>`, ... in the
               body, plus the slots our `<function>_stack` frame comment lists),
               as entry-relative offsets: recall (a DWARF stack local has a
               printed slot at its offset) and precision (a printed slot has
               a DWARF local there). MIPS images only: DWARF states the
               offset from the stack pointer after the prologue, and the
               entry-relative offset needs the frame size, which is read from
               the function's own `addiu/daddiu sp, sp, -N`. ARM images have
               no such decode here and are not scored on offsets;
  local types  each DWARF local's class (`int32`, `ptr`, ... as
               `dwarf_types.py`) against the classes of the declared locals,
               matched as a multiset per function (exact first, then
               width-equal-sign-unknown), as recall and precision, plus the
               exact class agreement of the locals matched by stack offset;
  returns      the return class of the printed signature against DWARF's, by
               `type_headtohead.score` (exact / partial / wrong), which the
               harness folds into its type slots but does not report apart.

Printed locals are read from the C text with one parser for both tools, so a
difference is the tool's output, not the parser's. Register-held locals have
tool-specific names (`temp_v0` ours, `iVar1` stock) and are counted as
declared locals; `in_*`, `unaff_*` and `param_*` are inputs, not locals.
Variables DWARF calls locals include source variables the compiler kept in
registers or folded away, so the count is a measure of how close the printed
body is to the source's variable set, not of correctness: both tools are
scored against the same number.

Usage:
  locals_truth.py IMAGE --ours LABEL=DIR [--ours LABEL=DIR ...]
                  [--stock stock.json] [--out report.json]
  locals_truth.py --spec spec.json --out report.json     (several images; also writes report.md)
DIR holds `<address>.c` files (the harness keeps them under
`<cache>/results/<tools>/<image>/<config>-<n>-<seed>/`); stock.json is the
output of `benchmarks/ghidra/ExportDecompiledC.java`.
"""
import argparse
import collections
import json
from pathlib import Path
import re
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import console_research as cr  # noqa: E402
import dwarf1_types  # noqa: E402
import dwarf_types  # noqa: E402
import type_headtohead  # noqa: E402

CORPUS = cr.M21.CORPUS
# image id -> (unstripped truth ELF, architecture of the frame-size decode)
IMAGES = {
    "ps2-capcom-fighting-evolution": ("ps2-capcom-fighting-evolution/SLUS_209.50", "mips"),
    "ps2-dungeon-game": ("ps2-dungeon-game/dungeon_game.elf", "mips"),
    "psp-puzzle-bobble-pocket": (cr.PSP_BOOT, "mips"),
    "psp-puzzle-bobble-pocket-symtab": (cr.PSP_BOOT, "mips"),
    "gba-pokeemerald": ("gba-pokeemerald/pokeemerald.elf", "arm"),
    "nds-pokeheartgold-arm9": ("nds-pokeheartgold/pokeheartgold.elf", "arm"),
}


# --- truth -------------------------------------------------------------

def hex_bytes(text: str) -> list[int]:
    """The bytes of a readelf/pyelftools/DWARF 1 block rendering."""
    match = re.search(r"(?:block|bytes):\s*([0-9a-fA-F ]+)", text)
    return [int(token, 16) for token in match[1].split()] if match else []


def sleb(data: list[int], at: int) -> tuple[int, int]:
    result = shift = 0
    while at < len(data):
        byte = data[at]
        at += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            if byte & 0x40:
                result -= 1 << shift
            break
    return result, at


def decode_location(text: str | None) -> tuple[str, int | None]:
    """(kind, offset): `none`, `list`, `register`, `stack` (offset from the
    frame base register), `static` (address) or `other`."""
    if not text:
        return "none", None
    if text.startswith("(loclist)") or "location list" in text or re.match(r"^\s*(?:\(\w+\)\s*)?0x[0-9a-f]+\s*(\(|$)", text):
        return "list", None
    data = hex_bytes(text)
    if not data:
        return "other", None
    if text.startswith("(dwarf1)"):
        # DWARF 1.1.0 location atoms: OP_REG 01 reg4; OP_BASEREG 02 reg4
        # [OP_CONST 04 c4, OP_ADD 07]; OP_ADDR 03 addr4.
        if data[0] == 0x01 and len(data) == 5:
            return "register", int.from_bytes(bytes(data[1:5]), "little")
        if data[0] == 0x03 and len(data) == 5:
            return "static", int.from_bytes(bytes(data[1:5]), "little")
        if data[0] == 0x02 and len(data) == 11 and data[5] == 0x04 and data[10] == 0x07:
            return "stack", struct.unpack("<i", bytes(data[6:10]))[0]
        if data[0] == 0x02 and len(data) == 5:
            return "stack", 0
        return "other", None
    op = data[0]
    if 0x50 <= op <= 0x6F:
        return "register", op - 0x50
    if op == 0x91:
        return "stack", sleb(data, 1)[0]
    if 0x70 <= op <= 0x8F:
        return "stack", sleb(data, 1)[0]
    if op == 0x03 and len(data) == 5:
        return "static", int.from_bytes(bytes(data[1:5]), "little")
    return "other", None


def frame_base_is_sp(node: dict) -> bool:
    """DWARF 2+ frame base `DW_OP_reg29` (MIPS sp) or `DW_OP_reg13` (ARM sp);
    DWARF 1's locals are always sp-based."""
    text = node["attributes"].get("DW_AT_frame_base", "")
    return bool(re.search(r"DW_OP_reg(?:29|13)\b", text)) or not text


class Truth:
    """Per entry: returns class, parameter classes, locals."""

    def __init__(self, image: str, corpus: Path):
        relative, self.arch = IMAGES[image]
        self.elf = corpus / relative
        found = dwarf1_types.read(self.elf)
        if found:
            self.nodes, self.reader = found[0], "dwarf1-python"
        else:
            self.nodes = cr.readelf_nodes(self.elf)
            self.reader = "readelf"
            if self.nodes is None:
                self.nodes, self.reader = cr.pyelftools_nodes(self.elf), "pyelftools-tolerant"
        self.data = self.elf.read_bytes()
        self.segments = dwarf_types.get_load_segments(self.data)
        self.functions = self.collect()

    def classify(self, offset):
        node = self.nodes.get(offset)
        if (node and node["tag"] == "DW_TAG_base_type"
                and dwarf_types.integer(node["attributes"].get("DW_AT_byte_size", "0")) == 0):
            return "void"
        return dwarf_types.classify(self.nodes, offset)

    def type_class(self, offset):
        return self.classify(dwarf_types.reference(dwarf_types.inherited(self.nodes, offset, "DW_AT_type")))

    def locals_of(self, offset, depth=0):
        """Automatic locals of a subprogram or lexical block."""
        out = []
        for child in self.nodes[offset]["children"]:
            node = self.nodes[child]
            if node["tag"] == "DW_TAG_variable":
                kind, value = decode_location(node["attributes"].get("DW_AT_location"))
                name = dwarf_types.inherited(self.nodes, child, "DW_AT_name")
                out.append({"name": dwarf_types.payload(name) if name else None,
                            "class": self.type_class(child), "kind": kind, "value": value})
            elif node["tag"] == "DW_TAG_lexical_block" and depth < 32:
                out += self.locals_of(child, depth + 1)
        return out

    def code_bytes(self, address: int, length: int) -> bytes | None:
        for vaddr, memsz, _flags, offset, filesz in self.segments:
            if vaddr <= address < vaddr + min(memsz, filesz):
                start = offset + address - vaddr
                return self.data[start:start + length]
        return None

    def mips_frame_size(self, entry: int) -> int:
        """Bytes the prologue subtracts from sp: `addiu/daddiu sp, sp, -N`
        among the first instructions (0 for a frameless leaf)."""
        code = self.code_bytes(entry, 64)
        for at in range(0, len(code or b"") - 3, 4):
            word, = struct.unpack_from("<I", code, at)
            if word >> 16 in (0x27BD, 0x67BD) and word & 0x8000:
                return 0x10000 - (word & 0xFFFF)
        return 0

    def collect(self):
        rows = {}
        executable = [(a, s) for a, s, f, _, _ in self.segments if f & 1]
        # A PSP image's unrelocated DW_AT_low_pc is an offset into `.text`.
        bases = cr.M21.section_relative_bases(self.elf)
        text = next(addr for name, addr in bases.values() if name == ".text") if bases else 0
        for offset, node in self.nodes.items():
            if node["tag"] != "DW_TAG_subprogram":
                continue
            attributes = node["attributes"]
            entry = attributes.get("DW_AT_entry_pc", attributes.get("DW_AT_low_pc"))
            if entry is None:
                continue
            entry = (dwarf_types.integer(entry) & ~1) + text
            if not any(a <= entry < a + s for a, s in executable):
                continue
            parameters = [self.type_class(c) for c in node["children"]
                          if self.nodes[c]["tag"] == "DW_TAG_formal_parameter"]
            locals_ = self.locals_of(offset)
            sp_based = frame_base_is_sp(node) if self.reader != "pyelftools-tolerant" else False
            frame = self.mips_frame_size(entry) if self.arch == "mips" and sp_based else None
            for local in locals_:
                if local["kind"] == "stack":
                    local["offset"] = None if frame is None else local["value"] - frame
            rows[entry] = {"returns": self.classify(dwarf_types.reference(
                dwarf_types.inherited(self.nodes, offset, "DW_AT_type"))),
                "parameters": parameters, "locals": locals_}
        return rows


# --- printed C -----------------------------------------------------------

STACK_NAME = re.compile(r"^(?:local|[a-z]*Stack)_([0-9a-fA-F]+)$")
INPUT_NAME = re.compile(r"^(?:in_|unaff_|param_)")
STATEMENT = re.compile(r"^(?:if|for|while|do|switch|return|goto|case|default|break|continue|else)\b|[(=]|^\s*\w+:$")


def definition(text: str):
    """(name, return-type text, body lines) of the first function defined."""
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.strip() != "{" or line != line.lstrip():
            continue
        head, back = [], index - 1
        while back >= 0 and not lines[back].strip():
            back -= 1
        while back >= 0 and lines[back].strip() and not re.search(r"[;}]\s*$|\*/\s*$", lines[back]):
            head.insert(0, lines[back].strip())
            back -= 1
        header = " ".join(head)
        match = re.search(r"([A-Za-z_]\w*)\s*\(", header)
        if match:
            return match[1], lines[index + 1:]
    return None, []


def declared_locals(body: list[str]) -> list[dict]:
    """The declarations at the top of a body, before its first statement."""
    out = []
    for line in body:
        stripped = line.strip()
        if not stripped or stripped.startswith(("/*", "//", "*")):
            continue
        if not stripped.endswith(";") or STATEMENT.search(stripped):
            break
        declaration = stripped[:-1]
        match = re.match(r"^(.*?)([A-Za-z_]\w*)\s*(\[[^\]]*\])?$", declaration)
        if not match:
            break
        type_text, name, array = match[1].strip(), match[2], match[3]
        if not type_text:
            break
        if INPUT_NAME.match(name):
            continue
        stack = STACK_NAME.match(name)
        klass = ("aggregate", None) if array or re.search(r"\b(struct|union)\b", type_text) else cr.classify_c(type_text)
        out.append({"name": name, "type": type_text + (array or ""),
                    "class": klass,
                    "offset": -int(stack[1], 16) if stack else None,
                    "stack": bool(stack)})
    return out


FRAME_SLOT = re.compile(r"/\*\s*0x([0-9a-fA-F]+):\s*\w+\s*\*/")


def frame_slots(text: str) -> set[int]:
    """Entry-relative offsets of the stack slots our printed C lists in its
    `<function>_stack` frame comment (the stack variables the store holds and
    the decompiler was told). The body names such a slot with whatever the
    printer picked (`temp_v3`), so the comment is where a declared slot shows;
    stock prints no such comment."""
    head = text.split("\n{", 1)[0]
    return {-int(match[1], 16) for match in FRAME_SLOT.finditer(head)}


def printed(text: str):
    name, body = definition(text)
    if name is None:
        return None
    found = cr.signature(text, name)
    return {"name": name, "returns": found[0] if found else None, "locals": declared_locals(body),
            "frame": frame_slots(text)}


# --- scoring ---------------------------------------------------------------

def truth_class(text: str):
    return type_headtohead.norm_truth(text)


def class_match(want: str, got) -> int:
    """2 exact, 1 partial, 0 no, by type_headtohead's slot rule."""
    exact, partial, _wrong = type_headtohead.score(truth_class(want), got)
    return 2 if exact else 1 if partial else 0


def multiset_scores(wants: list[str], gots: list) -> tuple[int, int]:
    """Greedy pairing: exact pairs first, then partial pairs among the rest."""
    wants, gots = list(wants), list(gots)
    exact = partial = 0
    for level in (2, 1):
        i = 0
        while i < len(wants):
            hit = next((j for j, got in enumerate(gots) if class_match(wants[i], got) == level), None)
            if hit is None:
                i += 1
                continue
            del wants[i], gots[hit]
            exact += level == 2
            partial += level == 1
    return exact, partial


def score_function(truth: dict, ours: dict) -> dict:
    autos = [local for local in truth["locals"] if local["kind"] not in ("static", "none")]
    declared = ours["locals"]
    stack_truth = {local["offset"] for local in autos if local["kind"] == "stack" and local.get("offset") is not None}
    stack_truth_known = all(local.get("offset") is not None for local in autos if local["kind"] == "stack")
    stack_printed = {local["offset"] for local in declared if local["stack"]} | ours.get("frame", set())
    exact, partial = multiset_scores([local["class"] for local in autos], [local["class"] for local in declared])
    pair_exact = pair_total = 0
    by_offset = {local["offset"]: local for local in declared if local["stack"]}
    for local in autos:
        if local["kind"] == "stack" and local.get("offset") in by_offset:
            pair_total += 1
            pair_exact += class_match(local["class"], by_offset[local["offset"]]["class"]) == 2
    row = {"truth_locals": len(autos), "printed_locals": len(declared),
           "class_exact": exact, "class_partial": partial,
           "stack_truth": len(stack_truth) if stack_truth_known else None,
           "stack_printed": len(stack_printed),
           "stack_matched": len(stack_truth & stack_printed) if stack_truth_known else None,
           "stack_pairs": pair_total, "stack_pairs_exact": pair_exact}
    returns = cr.classify_c(ours["returns"] or "")
    exact_r, partial_r, wrong_r = type_headtohead.score(truth_class(truth["returns"]), returns)
    row["return"] = "unscored" if (exact_r, partial_r, wrong_r) == (0, 0, 0) else \
        "exact" if exact_r else "partial" if partial_r else "wrong"
    return row


def aggregate(rows: list[dict]) -> dict:
    n = len(rows)
    t = sum(r["truth_locals"] for r in rows)
    p = sum(r["printed_locals"] for r in rows)
    known = [r for r in rows if r["stack_truth"] is not None]
    stack_t = sum(r["stack_truth"] for r in known)
    stack_p = sum(r["stack_printed"] for r in known)
    stack_m = sum(r["stack_matched"] for r in known)
    returns = collections.Counter(r["return"] for r in rows)
    scored = returns["exact"] + returns["partial"] + returns["wrong"]
    ratio = lambda a, b: round(a / b, 4) if b else None  # noqa: E731
    return {
        "functions": n,
        "truth_locals": t, "printed_locals": p,
        "count_exact": ratio(sum(r["truth_locals"] == r["printed_locals"] for r in rows), n),
        "over": ratio(sum(r["printed_locals"] > r["truth_locals"] for r in rows), n),
        "under": ratio(sum(r["printed_locals"] < r["truth_locals"] for r in rows), n),
        "mean_abs_error": round(sum(abs(r["truth_locals"] - r["printed_locals"]) for r in rows) / n, 3) if n else None,
        "class_recall": ratio(sum(r["class_exact"] + r["class_partial"] for r in rows), t),
        "class_exact_recall": ratio(sum(r["class_exact"] for r in rows), t),
        "class_precision": ratio(sum(r["class_exact"] + r["class_partial"] for r in rows), p),
        "stack": {"functions": len(known), "truth_slots": stack_t, "printed_slots": stack_p,
                  "matched": stack_m, "recall": ratio(stack_m, stack_t), "precision": ratio(stack_m, stack_p),
                  "pairs": sum(r["stack_pairs"] for r in known),
                  "pairs_class_exact": sum(r["stack_pairs_exact"] for r in known)},
        "returns": {**{k: returns[k] for k in ("exact", "partial", "wrong", "unscored")},
                    "exact_rate": ratio(returns["exact"], scored)},
    }


def score_tool(truth: Truth, files: dict[int, dict], only: set[int] | None = None) -> dict:
    rows = []
    for entry, parsed in files.items():
        if entry not in truth.functions or (only is not None and entry not in only):
            continue
        rows.append(score_function(truth.functions[entry], parsed))
    return aggregate(rows)


def read_dir(path: Path) -> dict[int, dict]:
    out = {}
    for file in sorted(path.glob("*.c")):
        try:
            entry = int(file.stem, 16)
        except ValueError:
            continue
        parsed = printed(file.read_text(errors="replace"))
        if parsed:
            sidecar = file.with_suffix(".stack")
            if sidecar.is_file():
                # `locals_doc.py`: the stack slots the decompiler itself names,
                # which the printed C's renaming can hide.
                parsed["frame"] = parsed["frame"] | set(json.loads(sidecar.read_text()))
            out[entry] = parsed
    return out


def read_stock(path: Path) -> dict[int, dict]:
    out = {}
    for key, row in json.loads(path.read_text())["functions"].items():
        if row.get("c"):
            parsed = printed(row["c"])
            if parsed:
                out[int(key, 16)] = parsed
    return out


def run_image(image: str, corpus: Path, ours: dict[str, str], stock: str | None) -> dict:
    truth = Truth(image, corpus)
    report = {"image": image, "reader": truth.reader, "truth_functions": len(truth.functions), "tools": {}}
    tools = {f"ours:{label}": read_dir(Path(directory)) for label, directory in ours.items()}
    if stock:
        tools["stock"] = read_stock(Path(stock))
    common = None
    for entries in tools.values():
        keys = {e for e in entries if e in truth.functions}
        common = keys if common is None else common & keys
    for label, entries in tools.items():
        report["tools"][label] = {"all_scored": score_tool(truth, entries),
                                  "common": score_tool(truth, entries, common)}
    report["common_functions"] = len(common or ())
    return report


def markdown(reports: list[dict]) -> str:
    fmt = lambda v: "-" if v is None else (f"{v:.4f}" if isinstance(v, float) else str(v))  # noqa: E731
    out = ["# Locals, stack slots and return classes against DWARF (supplement)", "",
           "Scored by `benchmarks/locals_truth.py`; definitions in its docstring. `common` rows score only the "
           "functions every listed tool produced C for, so ours and stock are compared on the same functions.", ""]
    for report in reports:
        out += [f"## {report['image']} (truth: {report['reader']}, {report['truth_functions']} functions)", "",
                f"Functions in common: {report['common_functions']}.", "",
                "| tool | set | functions | DWARF locals | printed locals | count exact | over | under | MAE | "
                "class recall | class precision |", "|---|---|---|---|---|---|---|---|---|---|---|"]
        for label, sets in report["tools"].items():
            for name, a in sets.items():
                out.append(f"| {label} | {name} | {a['functions']} | {a['truth_locals']} | {a['printed_locals']} | "
                           f"{fmt(a['count_exact'])} | {fmt(a['over'])} | {fmt(a['under'])} | "
                           f"{fmt(a['mean_abs_error'])} | {fmt(a['class_recall'])} | {fmt(a['class_precision'])} |")
        out += ["", "| tool | set | stack: DWARF slots | printed slots | matched | recall | precision | "
                "pairs class-exact | return exact / partial / wrong | return exact rate |",
                "|---|---|---|---|---|---|---|---|---|---|"]
        for label, sets in report["tools"].items():
            for name, a in sets.items():
                st, rt = a["stack"], a["returns"]
                out.append(f"| {label} | {name} | {fmt(st['truth_slots'])} | {fmt(st['printed_slots'])} | "
                           f"{fmt(st['matched'])} | {fmt(st['recall'])} | {fmt(st['precision'])} | "
                           f"{st['pairs_class_exact']} / {st['pairs']} | {rt['exact']} / {rt['partial']} / "
                           f"{rt['wrong']} | {fmt(rt['exact_rate'])} |")
        out.append("")
    return "\n".join(out) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("image", nargs="?", choices=sorted(IMAGES))
    parser.add_argument("--corpus", type=Path, default=CORPUS)
    parser.add_argument("--ours", action="append", default=[], metavar="LABEL=DIR")
    parser.add_argument("--stock", type=Path)
    parser.add_argument("--spec", type=Path, help='JSON {"images": {ID: {"ours": {LABEL: DIR}, "stock": FILE|null}}}')
    parser.add_argument("--out", type=Path, help="JSON report; markdown is written next to it (.md)")
    args = parser.parse_args()
    if args.spec:
        spec = json.loads(args.spec.read_text())["images"]
        reports = [run_image(image, args.corpus, row["ours"], row.get("stock")) for image, row in spec.items()]
    elif args.image:
        ours = dict(item.partition("=")[::2] for item in args.ours)
        reports = [run_image(args.image, args.corpus, ours, str(args.stock) if args.stock else None)]
    else:
        parser.error("name an image or give --spec")
    text = json.dumps({"schema": "locals-truth/1", "reports": reports}, indent=1)
    if args.out:
        args.out.write_text(text + "\n")
        args.out.with_suffix(".md").write_text(markdown(reports))
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
