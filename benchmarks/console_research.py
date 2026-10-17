#!/usr/bin/env python3
"""How much each decompiler research component helps on console games.

Every research component is a runtime toggle (an environment variable read
by `RuntimeConfig::from_env`, crates/romwright-core/src/session.rs). This
harness runs the console images m21-001 scores, once per configuration, and
measures what each toggle changes:

  1. discovery    recall/precision against the image's truth, scored exactly
                  as m21-001 does (import-time configurations only);
  2. printed C    `export-c --address` (the m2c-shaped C m22-001 compiles)
                  on a fixed, size-stratified sample of functions per image:
                  success rate, gotos, labels, `/* irregular */` functions,
                  native warnings, lines, median/max wall time per function;
  3. DWARF        parameter arity and scalar type agreement of the printed
                  signature against the compiler's DWARF (gba, nds,
                  ps2-dungeon), classified by benchmarks/dwarf_types.py and
                  scored by benchmarks/type_headtohead.py's slot rule;
  4. end to end   m22-001's objdiff `match_percent` for its fixed pokeemerald
                  function list (decompile-time configurations only; m22's
                  functions are imported, its file is not modified).

Stages. Which stage reads a toggle was read from the code, not assumed:

  import      ROMWRIGHT_NO_SWITCH_VSA, ROMWRIGHT_NO_SWITCH_DECOMPILER
              (native.rs switch recovery), ROMWRIGHT_PROMOTE_TAILCALLS
              (native/discovery.rs). One import per image per distinct set.
  prototypes  optional `infer_prototypes` API job (worker-client), which
              persists FuncProtos the decompiler later applies; it reads
              ROMWRIGHT_REGISTER_PARAMS. Run on a reflink copy of the import.
  decompile   ROMWRIGHT_IR_PASSES (passed to export-c as `--transforms`,
              which overrides the env there) and ROMWRIGHT_REGISTER_PARAMS
              (`register_params::augment` in export_m2c).

ROMWRIGHT_REGISTER_PARAMS is in the import cache key but no import code
reads it, so it does not split imports here.

Caching and resumption. Under --cache (default ~/.cache/romwright/research-
eval): stripped binaries, DWARF truth, one project per (image sha256, import
environment, tool fingerprint), prototype-stage copies, the function sample,
and one result file per (image, configuration). A project is only used once
its `done.json` marker exists; a result file is only reused when its key
(tool fingerprint, sample, environment) matches. Re-running the same command
continues where an interrupted run stopped. The tool fingerprint is the
sha256 of romwright-cli, romwright-worker and ghidra_opt, so a
rebuild invalidates projects and results instead of mixing builds.

Verdicts. Decompiler output is deterministic, so any difference between two
configurations on the same sample is exact, not noise. The thresholds below
are a materiality floor, not a noise estimate: a rate metric (recall,
precision, success, arity, type agreement, objdiff similarity) must move by
at least RATE_THRESHOLD (0.5 percentage points); a count metric (gotos,
labels, irregular functions, warnings) by at least COUNT_THRESHOLD (1%) of
the reference total and at least 1. Count metrics are compared over the
functions both configurations decompiled, so a configuration cannot look
cleaner by failing more. `helps` = some judged metric improves materially
and none worsens; `hurts` = the reverse; `mixed` = both; `neutral` = none.
Lines and time are reported, never judged.

Truth-contract images (`--corpus-wave`). The images the corpus builders stage
under `<corpus>/<id>/truth/{meta.json,functions.tsv[,types/]}` run through the
same stages with image specs read from meta.json (console_research_wave.py,
docs/console-research.md "Truth contract"). `functions.tsv` is the truth
(kind `tsv`, tests/m21-001_real_images.py `tsv_rows`); each of its modules
(`main`, REL/overlay names) is placed where the importer put it (the
project's `modules` table, a program of its own, or a separate import of the
module's staged file) and scored over that module's ranges. The sample size
and seeds come from `-n` / `--seeds` (500 and 1,2 here); results are per
seed and combined (the union of the samples). Discovery is also scored on
`verified=1` rows only, as a documented supplement beside the frozen
metric. `--stock` runs stock Ghidra headless (benchmarks/import_speed.py's
per-image analyzeHeadless configuration; ghidra/ExportFunctionEntries.java
and scripts/ExportDecompiledSignatures.java) on the main module for the
comparison column; the report carries per-platform tables and one-sided
sign tests over games.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import hashlib
import importlib.util
import json
import os
import random
import re
import shutil
import signal
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "benchmarks"))
import dwarf1_types  # noqa: E402
import dwarf_types  # noqa: E402
import type_headtohead  # noqa: E402
import console_research_wave as wave  # noqa: E402

TARGET = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target" / "eval"))
GHIDRA_OPT = ROOT / "native" / "build" / "ghidra_opt"
CACHE = Path.home() / ".cache" / "romwright" / "research-eval"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


M21 = load_module("m21_real_images", ROOT / "tests" / "m21-001_real_images.py")

IR = "ROMWRIGHT_IR_PASSES"
NO_VSA = "ROMWRIGHT_NO_SWITCH_VSA"
NO_SWITCH_DECOMPILER = "ROMWRIGHT_NO_SWITCH_DECOMPILER"
REGISTER_PARAMS = "ROMWRIGHT_REGISTER_PARAMS"
TAILCALLS = "ROMWRIGHT_PROMOTE_TAILCALLS"
STRUCTURING = "ROMWRIGHT_RUST_STRUCTURING"
IMPORT_VARS = {NO_VSA, NO_SWITCH_DECOMPILER, TAILCALLS}
PROTOTYPE_VARS = {REGISTER_PARAMS, "ROMWRIGHT_INFERRED_TYPES", "ROMWRIGHT_JOIN_PAIRS"}


@dataclasses.dataclass(frozen=True)
class Config:
    """One measured configuration.

    `env` is applied to every stage; the stage split above decides which
    variables key an import or a prototype copy. The component verdict
    compares this configuration to `reference`: sign +1 when this
    configuration turns the component on relative to it, -1 when it turns
    it off (the component's effect is then reference minus this)."""
    name: str
    env: dict
    component: str
    reference: str | None
    sign: int = 1
    infer_prototypes: bool = False

    def import_env(self) -> dict:
        return {k: v for k, v in self.env.items() if k in IMPORT_VARS}

    def prototype_env(self) -> dict:
        return {k: v for k, v in self.env.items() if k in PROTOTYPE_VARS}

    def transforms(self) -> str | None:
        return self.env.get(IR)


# Adding a configuration is one line. A new toggle read at import or by the
# prototype job also needs its variable in IMPORT_VARS / PROTOTYPE_VARS.
CONFIGS = [
    Config("default", {}, "all research (default vs baseline-off)", "baseline-off"),
    Config("baseline-off", {IR: "", NO_VSA: "1", NO_SWITCH_DECOMPILER: "1", STRUCTURING: "none"}, "reference", None),
    Config("ir-none", {IR: ""}, "IR passes (all three)", "default", -1),
    Config("ir-only-structure", {IR: "structure"}, "IR pass structure alone", "ir-none"),
    Config("ir-only-canonical_helpers", {IR: "canonical_helpers"}, "IR pass canonical_helpers alone", "ir-none"),
    Config("ir-only-additive_inverse", {IR: "additive_inverse"}, "IR pass additive_inverse alone", "ir-none"),
    Config("rust-structuring-none", {STRUCTURING: "none"}, "Rust structuring (SAILR-style models)", "default", -1),
    Config("switch-vsa-off", {NO_VSA: "1"}, "switch VSA", "default", -1),
    Config("switch-decompiler-off", {NO_SWITCH_DECOMPILER: "1"}, "switch decompiler", "default", -1),
    Config("register-params", {REGISTER_PARAMS: "1"}, "register params (decompile-time)", "default"),
    Config("promote-tailcalls", {TAILCALLS: "1"}, "promote tailcalls", "default"),
    Config("infer-prototypes", {}, "persisted prototypes (infer_prototypes job)", "default",
           infer_prototypes=True),
    Config("infer-prototypes+register-params", {REGISTER_PARAMS: "1"}, "register params (persisted)",
           "infer-prototypes", infer_prototypes=True),
    Config("inferred-types-off", {"ROMWRIGHT_INFERRED_TYPES": "0"}, "inferred types -> prototypes",
           "infer-prototypes", -1, infer_prototypes=True),
    Config("join-pairs-off", {"ROMWRIGHT_JOIN_PAIRS": "0"}, "joined register pairs -> prototypes",
           "infer-prototypes", -1, infer_prototypes=True),
    Config("structs-off", {"ROMWRIGHT_STRUCTS": "off"}, "struct layer (printed C)", "default", -1),
]
BY_NAME = {config.name: config for config in CONFIGS}

# m21-001's images, the GameCube DOL (no truth: printed-C metrics only), and
# Puzzle Bobble Pocket (PSP, linked at 0 as the importer loads it). Its symtab
# names the functions and its DWARF 2 the types; both are section-relative (an
# offset into `.text`, which sits at 0x40), so `M21.section_relative_bases`
# adds the section address in the function truth and in `dwarf_truth`. Two
# research inputs:
#   psp-puzzle-bobble-pocket         `strip: True`  llvm-strip --strip-all: no
#       symbols, no DWARF; discovery is scored against the symtab's functions.
#   psp-puzzle-bobble-pocket-symtab  `strip: "debug"`  --strip-debug: the symtab
#       stays, so the functions are named and found; only the DWARF is removed.
#       It isolates type/arity recovery from discovery; its discovery numbers
#       are the symtab's and say nothing about discovery.
PSP_BOOT = "psp-puzzle-bobble-pocket/[PSP] Puzzle Bobble Pocket (Korea) (En,Ja)/SYSDIR/BOOT.BIN"
IMAGES = [dict(spec) for spec in M21.IMAGES] + [
    {"id": "gc-animal-crossing", "image": "gc-animal-crossing/main.dol", "program": "gc",
     "truth": None, "ranges": None},
    {"id": "psp-puzzle-bobble-pocket", "image": PSP_BOOT, "strip": True, "program": "psp",
     "truth": ("elf", PSP_BOOT), "ranges": None},
    {"id": "psp-puzzle-bobble-pocket-symtab", "image": PSP_BOOT, "strip": "debug", "program": "psp",
     "truth": ("elf", PSP_BOOT), "ranges": None},
]
# Unstripped twins whose DWARF is the type/arity oracle; addresses equal the
# image's (GBA ROM/ELF share 0x08xxxxxx, the NDS arm9 static image is
# scored inside m21's ranges, the PS2 image is the stripped ELF itself).
DWARF = {
    "gba-pokeemerald": "gba-pokeemerald/pokeemerald.elf",
    "nds-pokeheartgold-arm9": "nds-pokeheartgold/pokeheartgold.elf",
    "ps2-dungeon-game": "ps2-dungeon-game/dungeon_game.elf",
    # Metrowerks DWARF 1, read by benchmarks/dwarf1_types.py; the research
    # input is the llvm-strip'd twin (`strip`), which has no `.debug`.
    "ps2-capcom-fighting-evolution": "ps2-capcom-fighting-evolution/SLUS_209.50",
    "psp-puzzle-bobble-pocket": PSP_BOOT,
    "psp-puzzle-bobble-pocket-symtab": PSP_BOOT,
}
M22_IMAGE = "gba-pokeemerald"

RATE_THRESHOLD = 0.005
COUNT_THRESHOLD = 0.01
# (metric, better direction, kind). Direction 0: reported, never judged.
METRICS = [
    ("recall", 1, "rate"), ("precision", 1, "rate"),
    ("success_rate", 1, "rate"), ("gotos", -1, "count"), ("labels", -1, "count"),
    ("irregular_functions", -1, "count"), ("native_warnings", -1, "count"),
    ("text_warnings", -1, "count"), ("lines", 0, "count"),
    ("arity_accuracy", 1, "rate"), ("type_exact_rate", 1, "rate"),
    ("m22_mean_similarity", 1, "rate"), ("m22_exact", 1, "count"),
    ("m22_standalone_similarity", 1, "rate"), ("m22_standalone_exact", 1, "count"),
    # Supplement (docs/console-research.md): discovery over verified=1 truth rows only. Reported, never judged.
    ("recall_verified", 0, "rate"), ("precision_verified", 0, "rate"),
]


def log(message: str) -> None:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}", file=sys.stderr, flush=True)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def env_key(env: dict) -> str:
    return hashlib.sha256(json.dumps(sorted(env.items())).encode()).hexdigest()[:12]


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=1) + "\n")
    temporary.replace(path)


def read_json(path: Path):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def reflink_copy(source: Path, destination: Path) -> None:
    shutil.rmtree(destination, ignore_errors=True)
    subprocess.run(["cp", "-a", "--reflink=auto", str(source), str(destination)], check=True)


class Tools:
    def __init__(self, target: Path):
        self.cli = target / "release" / "romwright-cli"
        self.worker = target / "release" / "romwright-worker"
        self.api = target / "release" / "romwright-api"
        for path in (self.cli, self.worker, GHIDRA_OPT):
            if not path.is_file():
                raise SystemExit(f"missing {path}: build with CARGO_TARGET_DIR={target} "
                                 "cargo build --release -p romwright-cli -p romwright-worker -p romwright-api")
        self.fingerprint = hashlib.sha256("".join(
            sha256_file(path) for path in (self.cli, self.worker, GHIDRA_OPT)).encode()).hexdigest()[:16]

    def env(self, extra: dict) -> dict:
        env = {k: v for k, v in os.environ.items()
               if not k.startswith("ROMWRIGHT_") or k in ("ROMWRIGHT_GHIDRA",)}
        env.update(ROMWRIGHT_GHIDRA_OPT=str(GHIDRA_OPT),
                   ROMWRIGHT_WORKER=str(self.worker), ROMWRIGHT_NO_IMPORT_CACHE="1",
                   ROMWRIGHT_NO_FACT_PACK="1")
        env.update(extra)
        # `CONSOLE_RESEARCH_ENV` (a JSON object) is applied to every tool process of the run and is not part of any
        # project key: use it with a cache of its own (a rule switched off for a whole run, e.g.
        # {"ROMWRIGHT_COMPILER_RULES_DISABLE": "literal-pool-extent"}).
        env.update(json.loads(os.environ.get("CONSOLE_RESEARCH_ENV") or "{}"))
        return env


# ---------------------------------------------------------------------------
# Truth
# ---------------------------------------------------------------------------

def function_truth(spec: dict, corpus: Path) -> dict[int, tuple[int, str]] | None:
    if not spec.get("truth"):
        return None
    kind, path = spec["truth"]
    return M21.LOADERS[kind](corpus / path)


def readelf_nodes(elf: Path):
    """dwarf_types' DIE graph from readelf, or None when readelf refuses.

    mwcc (NDS) writes DW_AT_low_pc with a form readelf prints as
    `(ref_addr) <0x...>`; it is an address, rewritten so dwarf_types reads
    it as one."""
    result = subprocess.run(["readelf", "--debug-dump=info", "--wide", str(elf)], capture_output=True,
                            text=True, env=dict(os.environ, LC_ALL="C", DEBUGINFOD_URLS=""))
    if result.returncode or result.stderr.strip():
        return None
    text = re.sub(r"(DW_AT_(?:low_pc|entry_pc)\s*:\s*)\(ref_addr\)\s*<(0x[0-9a-fA-F]+)>",
                  r"\1(addr) \2", result.stdout)
    return dwarf_types.parse(text)


def pyelftools_nodes(elf: Path):
    """The same DIE graph from pyelftools, for agbcc (GBA) DWARF.

    agbcc's per-unit abbreviation tables are not zero-terminated, which makes
    readelf, llvm-dwarfdump and stock pyelftools refuse the whole section.
    Codes restart at 1 in the next unit's table, so reading each table until
    a repeated code (or the section end) recovers it exactly. Attributes are
    rendered the way readelf prints them so dwarf_types' readers apply."""
    from elftools.common.exceptions import ELFParseError
    from elftools.common.utils import struct_parse
    from elftools.dwarf import abbrevtable
    from elftools.elf.elffile import ELFFile

    def tolerant(self):
        table = {}
        self.stream.seek(self.offset)
        while True:
            try:
                code = struct_parse(self.structs.the_Dwarf_uleb128, self.stream)
                if code == 0 or code in table:
                    break
                declaration = struct_parse(self.structs.Dwarf_abbrev_declaration, self.stream)
            except ELFParseError:
                break
            table[code] = abbrevtable.AbbrevDecl(code, declaration)
        return table

    original = abbrevtable.AbbrevTable._parse_abbrev_table
    abbrevtable.AbbrevTable._parse_abbrev_table = tolerant
    keep = {"DW_AT_type", "DW_AT_abstract_origin", "DW_AT_specification", "DW_AT_byte_size",
            "DW_AT_encoding", "DW_AT_name", "DW_AT_low_pc", "DW_AT_entry_pc", "DW_AT_location"}
    nodes = {}
    try:
        with open(elf, "rb") as handle:
            dwarf = ELFFile(handle).get_dwarf_info()
            for unit in dwarf.iter_CUs():
                for die in unit.iter_DIEs():
                    if die.is_null():
                        continue
                    attributes = {}
                    for name, attribute in die.attributes.items():
                        if name not in keep:
                            continue
                        value = attribute.value
                        if attribute.form.startswith("DW_FORM_ref") and attribute.form != "DW_FORM_ref_addr":
                            attributes[name] = f"<0x{value + unit.cu_offset:x}>"
                        elif attribute.form == "DW_FORM_ref_addr" and name in (
                                "DW_AT_type", "DW_AT_abstract_origin", "DW_AT_specification"):
                            attributes[name] = f"<0x{value:x}>"
                        elif name == "DW_AT_location":
                            # An expression is a byte list; anything else is a location list.
                            attributes[name] = ("(exprloc) bytes: " + " ".join(f"{b:x}" for b in value)
                                                if isinstance(value, list) else "(loclist)")
                        elif isinstance(value, bytes):
                            attributes[name] = f"(string) {value.decode('latin-1')}"
                        elif isinstance(value, int):
                            attributes[name] = f"(data) {value}" if name == "DW_AT_encoding" else f"(addr) {value:#x}"
                    nodes[die.offset] = {"tag": die.tag, "attributes": attributes,
                                         "children": [child.offset for child in die.iter_children()]}
    finally:
        abbrevtable.AbbrevTable._parse_abbrev_table = original
    return nodes


def dwarf_truth(elf: Path) -> dict[int, dict]:
    """Per entry: arity and dwarf_types classes. dwarf_types.extract's rule
    (abstract-origin parameter inheritance included); entries whose
    definitions disagree (NDS overlays share addresses) are dropped."""
    found = dwarf1_types.read(elf)
    if found:
        nodes, reader = found[0], "dwarf1-python"
    else:
        nodes = readelf_nodes(elf)
        reader = "readelf"
        if nodes is None:
            nodes, reader = pyelftools_nodes(elf), "pyelftools-tolerant"
    truth = truth_from_nodes(nodes, reader)
    # A PSP image's unrelocated DW_AT_low_pc is an offset into `.text`.
    bases = M21.section_relative_bases(elf)
    if bases is not None:
        text = next(addr for name, addr in bases.values() if name == ".text")
        truth["functions"] = {entry + text: row for entry, row in truth["functions"].items()}
    return truth


def truth_from_nodes(nodes: dict, reader: str) -> dict:
    rows: dict[int, dict] = {}
    conflicts = set()

    def classify(offset):
        # mwcc (NDS) spells `void` as a zero-size base type with encoding 0,
        # which dwarf_types reads as `unknown`.
        node = nodes.get(offset)
        if (node and node["tag"] == "DW_TAG_base_type"
                and dwarf_types.integer(node["attributes"].get("DW_AT_byte_size", "0")) == 0):
            return "void"
        return dwarf_types.classify(nodes, offset)

    for offset, node in nodes.items():
        if node["tag"] != "DW_TAG_subprogram":
            continue
        attributes = node["attributes"]
        entry = attributes.get("DW_AT_entry_pc", attributes.get("DW_AT_low_pc"))
        if entry is None:
            continue
        entry = dwarf_types.integer(entry) & ~1
        if not entry:
            continue

        def classes(part):
            return [classify(dwarf_types.reference(dwarf_types.inherited(nodes, child, "DW_AT_type")))
                    for child in nodes[part]["children"] if nodes[child]["tag"] == "DW_TAG_formal_parameter"]

        parameters = classes(offset)
        if not parameters:
            for part in dwarf_types.lineage(nodes, offset)[1:]:
                if parameters := classes(part):
                    break
        name = dwarf_types.inherited(nodes, offset, "DW_AT_name")
        row = {"name": dwarf_types.payload(name) if name else None, "arity": len(parameters),
               "returns": classify(dwarf_types.reference(dwarf_types.inherited(nodes, offset, "DW_AT_type"))),
               "parameters": parameters}
        previous = rows.get(entry)
        if previous and (previous["arity"], previous["parameters"]) != (row["arity"], row["parameters"]):
            conflicts.add(entry)
        rows[entry] = row
    for entry in conflicts:
        rows.pop(entry)
    return {"reader": reader, "conflicts_dropped": len(conflicts), "functions": rows}


# ---------------------------------------------------------------------------
# Printed C
# ---------------------------------------------------------------------------

LABEL = re.compile(r"^\s*([A-Za-z_]\w*):\s*$", re.M)
C_SCALARS = {
    "void": ("void", None), "bool": ("bool", 8), "_Bool": ("bool", 8),
    "char": ("int", 8), "signed char": ("int", 8), "schar": ("int", 8), "sbyte": ("int", 8), "s8": ("int", 8),
    "unsigned char": ("uint", 8), "uchar": ("uint", 8), "byte": ("uint", 8), "u8": ("uint", 8),
    "short": ("int", 16), "signed short": ("int", 16), "s16": ("int", 16),
    "unsigned short": ("uint", 16), "ushort": ("uint", 16), "u16": ("uint", 16),
    "int": ("int", 32), "signed int": ("int", 32), "s32": ("int", 32),
    "unsigned int": ("uint", 32), "uint": ("uint", 32), "unsigned": ("uint", 32), "u32": ("uint", 32),
    # Every m21 console target is ILP32: `long` is 32 bits (type_headtohead's
    # table assumes LP64 and would score every console `long` as wrong).
    "long": ("int", 32), "unsigned long": ("uint", 32), "ulong": ("uint", 32),
    "long long": ("int", 64), "longlong": ("int", 64), "s64": ("int", 64),
    "unsigned long long": ("uint", 64), "ulonglong": ("uint", 64), "u64": ("uint", 64),
    "float": ("float", 32), "double": ("float", 64), "f32": ("float", 32), "f64": ("float", 64),
}


def classify_c(text: str):
    text = " ".join(word for word in text.replace("*", " * ").split()
                    if word not in ("const", "volatile", "struct", "union", "enum"))
    if "(" in text and "*" in text:
        return ("code", None)
    if "*" in text:
        return ("ptr", None)
    if match := re.fullmatch(r"undefined(\d+)", text):
        return ("num", int(match[1]) * 8)
    return C_SCALARS.get(text, ("unknown", None))


def split_parameters(text: str) -> list[str]:
    parts, depth, current = [], 0, ""
    for char in text:
        if char == "," and depth == 0:
            parts.append(current)
            current = ""
            continue
        depth += char in "(["
        depth -= char in ")]"
        current += char
    if current.strip():
        parts.append(current)
    return [part.strip() for part in parts]


def signature(text: str, name: str):
    """(return type, [parameter types]) of `name`'s definition, or None.

    The definition is the occurrence whose closing parenthesis is followed
    by `{`; its return type is the text back to the previous statement,
    block or comment boundary."""
    for match in re.finditer(r"\b" + re.escape(name) + r"\s*\(", text):
        depth, at = 1, match.end()
        while at < len(text) and depth:
            depth += {"(": 1, ")": -1}.get(text[at], 0)
            at += 1
        if not text[at:].lstrip().startswith("{"):
            continue
        head = re.split(r";|\}|\*/|\n\s*\n", text[:match.start()])[-1]
        returns = " ".join(head.split())
        parameters = text[match.end():at - 1].strip()
        if parameters in ("", "void"):
            return returns, []
        types = []
        for parameter in split_parameters(parameters):
            if parameter == "...":
                continue
            if "(" in parameter:  # function pointer: `int (*name)(int)`
                types.append(re.sub(r"\(\s*\*\s*\w+\s*\)", "(*)", parameter))
            else:
                types.append(re.sub(r"\b[A-Za-z_]\w*\s*(\[[^\]]*\])?\s*$", "", parameter).strip() or "int")
        return returns, types
    return None


def decompile_one(tools: Tools, project: Path, binary: Path, program: str, address: int,
                  config: Config, keep_dir: Path) -> dict:
    with tempfile.TemporaryDirectory(prefix="research-c-") as temporary:
        outdir = Path(temporary) / "out"
        argv = [str(tools.cli), "export-c", str(binary), program, str(outdir), "--address", f"{address:x}",
                "--project", str(project)]
        if config.transforms() is not None:
            argv += ["--transforms", config.transforms()]
        started = time.monotonic()
        try:
            result = subprocess.run(argv, capture_output=True, text=True, timeout=600, env=tools.env(config.env))
            code, stdout, stderr = result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            code, stdout, stderr = -9, "", "timeout after 600s"
        seconds = time.monotonic() - started
        files = sorted(outdir.glob("*.c")) if outdir.exists() else []
        row = {"address": f"{address:08x}", "exit": code, "seconds": round(seconds, 3)}
        if code != 0 or not files:
            row.update(success=False, error=(stderr or stdout)[-600:])
            return row
        text = "\n".join(path.read_text(errors="replace") for path in files)
    try:
        report = json.loads(stdout)
    except ValueError:
        report = {}
    keep_dir.mkdir(parents=True, exist_ok=True)
    (keep_dir / f"{address:08x}.c").write_text(text)
    name = files[0].stem
    found = signature(text, name)
    row.update(
        success=True, name=name, sha256=hashlib.sha256(text.encode()).hexdigest()[:16],
        gotos=len(re.findall(r"\bgoto\b", text)),
        labels=sum(1 for label in LABEL.findall(text) if label != "default"),
        irregular=int("/* irregular" in text),
        native_warnings=len(report.get("warnings") or []),
        text_warnings=text.count("WARNING"),
        lines=sum(1 for line in text.splitlines() if line.strip()),
        semantic_rewrites=report.get("semantic_rewrites"),
        returns=found[0] if found else None,
        parameters=found[1] if found else None,
    )
    return row


# ---------------------------------------------------------------------------
# Stages
# ---------------------------------------------------------------------------

def prepared_binary(spec: dict, corpus: Path, cache: Path) -> Path:
    image = corpus / spec["image"]
    if not spec.get("strip"):
        return image
    out = cache / "binaries" / spec["id"] / f"{image.name}.stripped"
    if not out.is_file():
        out.parent.mkdir(parents=True, exist_ok=True)
        if spec["strip"] == "debug":
            # Keep the symbol table; remove only the DWARF (`.debug_*`).
            subprocess.run(["llvm-objcopy", "--strip-debug", str(image), str(out)], check=True)
        else:
            M21.strip(image, out.parent)
    return out


def program_name(project: Path, wanted: str, probe: list[int] | None = None) -> str:
    """The program `--name wanted` made. A container the importer splits names its programs
    `<name>.<part>`: failing an exact match, the one program sharing `wanted`'s first component; with
    several (or none), the program that holds most of `probe` (truth addresses) as function entries."""
    db = sqlite3.connect(f"file:{project}/project.sqlite?mode=ro", uri=True)
    names = {row[0]: row[1] for row in db.execute("SELECT name, id FROM programs")}
    try:
        if wanted in names:
            return wanted
        if len(names) == 1:
            return next(iter(names))
        stem = wanted.split(".")[0]
        near = [name for name in names if name.split(".")[0] == stem]
        if len(near) == 1:
            return near[0]
        if probe:
            wanted_set = set(probe)
            best, best_hits = None, 0
            for name in near or names:
                hits = 0
                for (entry,) in db.execute("SELECT entry FROM functions WHERE program_id = ?", (names[name],)):
                    try:
                        hits += int(entry, 16) in wanted_set
                    except ValueError:
                        continue
                if hits > best_hits:
                    best, best_hits = name, hits
            if best:
                return best
    finally:
        db.close()
    raise RuntimeError(f"program {wanted!r} not among {sorted(names)}")


def import_project(tools: Tools, spec: dict, binary: Path, image_sha: str, config: Config,
                   truth, cache: Path) -> tuple[Path, dict]:
    return import_env_project(tools, spec, binary, image_sha, config.import_env(), truth, cache)


def import_env_project(tools: Tools, spec: dict, binary: Path, image_sha: str, env: dict,
                       truth, cache: Path) -> tuple[Path, dict]:
    # Switching value-set analysis off cannot change an import in which it
    # resolved nothing: with no table added, every round asks the decompiler
    # the same branches and leaves the import untouched (native.rs
    # `discover`, switch stage), so the rounds that follow see the same
    # state. The same import with VSA on answers whether that held, and its
    # project stands in for this one instead of a second full import.
    if NO_VSA in env:
        with_vsa = {k: v for k, v in env.items() if k != NO_VSA}
        base, base_marker = import_env_project(tools, spec, binary, image_sha, with_vsa, truth, cache)
        stats = base_marker.get("switch_stats") or {}
        if stats.get("vsa_resolved") == 0:
            log(f"{spec['id']}: VSA resolved nothing with {with_vsa or 'default import env'}; "
                f"{env} reuses {base.name}")
            return base, dict(base_marker, env=env, aliased_to=base.name)
    raw_tag = f"-raw{spec['raw'][0]:x}" if spec.get("raw") else ""
    project = cache / "projects" / f"{spec['id']}-{image_sha[:12]}-{env_key(env)}{raw_tag}-{tools.fingerprint}"
    marker = read_json(project / "done.json")
    if marker:
        return project, marker
    shutil.rmtree(project, ignore_errors=True)
    project.mkdir(parents=True)
    log(f"{spec['id']}: importing with {env or 'default import env'} -> {project.name}")
    argv = [str(tools.cli), "import", str(binary), "--name", spec["program"].split(".")[0],
            "--project", str(project), "--timings"]
    if spec.get("raw"):
        argv += ["--raw", f"{spec['raw'][0]:x}", "--language", spec["raw"][1]]
    started = time.monotonic()
    result = subprocess.run(argv, capture_output=True, text=True, env=tools.env(env),
                            timeout=spec.get("limit_s", M21.DEFAULT_LIMIT_S))
    seconds = round(time.monotonic() - started, 1)
    if result.returncode:
        shutil.rmtree(project, ignore_errors=True)
        raise RuntimeError(f"import failed: {result.stderr.strip()[-600:]}")
    timings = {}
    for line in result.stdout.splitlines():
        if line.startswith("TIMINGS "):
            timings = json.loads(line[len("TIMINGS "):])
    program = program_name(project, spec["program"], spec.get("probe"))
    marker = {"env": env, "program": program, "seconds": seconds, "binary": str(binary),
              "image_sha256": image_sha, "tools": tools.fingerprint,
              "diagnostics": timings.get("diagnostics", []), "switch_stats": timings.get("switch_stats"),
              "phases": timings.get("phases")}
    if truth is not None:
        marker["discovery"] = M21.score(project, program, truth, spec["ranges"])
    write_json(project / "done.json", marker)
    log(f"{spec['id']}: imported in {seconds}s"
        + (f", recall {marker['discovery']['recall']} precision {marker['discovery']['precision']}"
           if "discovery" in marker else ""))
    return project, marker


def run_api(api: Path, project: Path, requests: list, env: dict, timeout: int) -> list:
    """prototype_gate.run_api against this harness's API binary."""
    process = subprocess.Popen([str(api), "--project", str(project)], cwd=ROOT, env=env,
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, start_new_session=True)
    payload = "".join(json.dumps(dict(api=2, id=index, method=method, params=params)) + "\n"
                      for index, (method, params) in enumerate(requests))
    try:
        stdout, stderr = process.communicate(payload, timeout=timeout)
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.communicate()
        raise
    if process.returncode:
        raise RuntimeError(f"romwright-api exited {process.returncode}: {stderr[-2000:]}")
    replies = [json.loads(line) for line in stdout.splitlines()]
    errors = [reply["error"] for reply in replies if reply.get("error")]
    if errors or len(replies) != len(requests):
        raise RuntimeError(f"romwright-api errors: {json.dumps(errors)[:2000]}")
    return [reply["result"] for reply in replies]


def prototype_project(tools: Tools, base: Path, marker: dict, binary: Path, config: Config,
                      budget_ms: int) -> tuple[Path, dict]:
    env = config.prototype_env()
    project = base.with_name(f"{base.name}-proto-{env_key(env)}")
    done = read_json(project / "done.json")
    if done and done.get("prototypes"):
        return project, done
    if not tools.api.is_file():
        raise RuntimeError(f"missing {tools.api} (needed by infer_prototypes configurations)")
    reflink_copy(base, project)
    (project / "done.json").unlink(missing_ok=True)
    log(f"{base.name}: infer_prototypes with {env or 'default env'}")
    started = time.monotonic()
    report, = run_api(tools.api, project, [("infer_prototypes", dict(
        binary=str(binary), program=marker["program"], budget_ms=budget_ms))],
        tools.env(env), timeout=budget_ms // 1000 + 600)
    done = dict(marker, prototypes={"env": env, "seconds": round(time.monotonic() - started, 1),
                                    "report": {k: v for k, v in report.items() if k != "analyzed_addresses"}})
    write_json(project / "done.json", done)
    return project, done


def stratified(candidates: list[tuple[int, int]], n: int, rng: random.Random) -> list[int]:
    """n of (size, address), n/4 from each equal-count size quartile."""
    candidates = sorted(candidates)
    if len(candidates) <= n:
        return [address for _, address in candidates]
    chosen = []
    for index in range(4):
        bucket = candidates[index * len(candidates) // 4:(index + 1) * len(candidates) // 4]
        take = n // 4 + (1 if index < n % 4 else 0)
        chosen += [address for _, address in rng.sample(bucket, min(take, len(bucket)))]
    return chosen


def choose_sample(spec: dict, project: Path, program: str, truth, dwarf, n: int, seed: int) -> list[int]:
    """Deterministic, size-stratified: functions of the default import (that
    the truth also names, when it exists) inside the scored ranges. Where a
    DWARF oracle exists, DWARF-covered functions are drawn first (the PS2
    DWARF covers only libgcc), and the rest of n from the others."""
    db = sqlite3.connect(f"file:{project}/project.sqlite?mode=ro", uri=True)
    pid = db.execute("SELECT id FROM programs WHERE name = ?", (program,)).fetchone()[0]
    ranges = spec["ranges"]
    if ranges is None:
        ranges = [(int(start, 16), int(start, 16) + size) for start, size, permissions in db.execute(
            "SELECT start, size, permissions FROM memory_regions WHERE program_id = ?", (pid,))
            if "x" in permissions]
    candidates = []
    for entry, size in db.execute("SELECT entry, size FROM functions WHERE program_id = ?", (pid,)):
        try:
            address = int(entry, 16)
        except ValueError:
            continue
        if any(lo <= address < hi for lo, hi in ranges) and (truth is None or address in truth):
            candidates.append((size, address))
    db.close()
    rng = random.Random(f"{seed}:{spec['id']}")
    covered = [item for item in candidates if dwarf and item[1] in dwarf]
    chosen = stratified(covered, n, rng)
    rest = [item for item in candidates if not (dwarf and item[1] in dwarf)]
    chosen += stratified(rest, n - len(chosen), rng)
    return sorted(chosen)


def run_decompile(tools: Tools, spec: dict, project: Path, marker: dict, binary: Path, config: Config,
                  sample: list, result_path: Path, jobs: int, units: list[dict] | None = None) -> dict:
    """Decompile every sampled item. An item is an address (the image's one program) or, when the
    image has several scored units (wave images), `[unit index, address]`; a unit that is a program of
    this project runs against `project` (so a prototype copy applies), a separately imported one against
    its own project."""
    key = {"tools": tools.fingerprint, "env": config.env, "infer_prototypes": config.infer_prototypes,
           "sample": hashlib.sha256(json.dumps(sample).encode()).hexdigest()[:16], "project": project.name}
    if units is not None and len(units) > 1:
        key["units"] = [[unit["module"], Path(unit["project"]).name if unit["project"] else None] for unit in units]
    cached = read_json(result_path)
    if cached and cached.get("key") == key:
        return cached
    log(f"{spec['id']}/{config.name}: decompiling {len(sample)} functions ({jobs} jobs)")
    keep = result_path.with_suffix("")
    shutil.rmtree(keep, ignore_errors=True)
    started = time.monotonic()

    def one(item) -> dict:
        if isinstance(item, int):
            return decompile_one(tools, project, binary, marker["program"], item, config, keep)
        index, address = item
        unit = units[index]
        row = decompile_one(tools, unit_project(unit, project), Path(unit["binary"]) if unit["binary"] else binary,
                            unit["program"], address, config,
                            keep if index == 0 else keep / re.sub(r"[^\w.-]", "_", unit["module"]))
        if index:
            row.update(unit=index, module=unit["module"])
        return row

    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        rows = list(pool.map(one, sample))
    result = {"key": key, "image": spec["id"], "config": config.name, "project": str(project),
              "wall_seconds": round(time.monotonic() - started, 1), "functions": rows}
    write_json(result_path, result)
    return result


# ---------------------------------------------------------------------------
# pokeemerald end to end (m22-001)
# ---------------------------------------------------------------------------

class M22Runner:
    """Imports m22-001 and drives its own extraction, context and scoring.

    m22 imports the ROM itself; here its `project-romwright` is a reflink
    copy of this harness's default GBA import (same binary, same tools), so
    the names/prototypes it asserts never leak into the printed-C sample."""

    def __init__(self, tools: Tools, cache: Path):
        self.module = load_module("m22_c_output", ROOT / "tests" / "m22-001_c_output.py")
        self.module.CLI = tools.cli
        self.tools = tools
        self.work = cache / "m22" / tools.fingerprint
        self.prepared = None

    def prerequisites(self) -> list[str]:
        m = self.module
        return [str(path) for path in (m.ROM, m.ELF, m.DRIVER, m.AGBCC, m.AS, m.OBJDUMP, m.OBJDIFF)
                if not Path(path).exists()]

    def prepare(self, project: Path, program: str):
        if self.prepared:
            return self.prepared
        m = self.module
        m.PROGRAM = program
        self.work.mkdir(parents=True, exist_ok=True)
        elf_functions, elf_objects = m.load_elf_symbols()
        extracted, functions = [], {}
        for name, unit in m.FUNCTIONS:
            target_object = m.OBJ_ROOT / f"{unit}.o"
            fdir = self.work / "functions" / name
            fdir.mkdir(parents=True, exist_ok=True)
            asm, refs = m.extract_asm(target_object, name)
            (fdir / "target.s").write_text(asm)
            addresses = {a for a, _ in elf_functions.get(name, [])}
            if len(addresses) != 1:
                raise RuntimeError(f"m22 {name}: ELF address missing or ambiguous")
            extracted.append((name, unit, refs))
            functions[name] = (addresses.pop(), target_object)
        context_text, prototypes, _notes = m.build_context(extracted, m.Declarations(), elf_objects, elf_functions)
        (self.work / "context.h").write_text(context_text)
        copy = self.work / "project-romwright"
        marker = read_json(self.work / "asserted.json")
        if not marker or marker.get("source") != project.name:
            reflink_copy(project, copy)
            (copy / "done.json").unlink(missing_ok=True)
            _, record = m.romwright_project(self.work, "romwright", m.ROM, elf_functions, prototypes,
                                            False, log)
            write_json(self.work / "asserted.json", {"source": project.name, "record": record})
        self.prepared = (copy, context_text, functions)
        return self.prepared

    def run(self, config: Config, result_path: Path) -> dict:
        m = self.module
        project, context_text, functions = self.prepared
        key = {"tools": self.tools.fingerprint, "env": config.env, "functions": sorted(functions)}
        cached = read_json(result_path)
        if cached and cached.get("key") == key:
            return cached
        log(f"m22/{config.name}: exporting and scoring {len(functions)} functions")
        rows = {}
        for name, (address, target_object) in functions.items():
            ldir = self.work / "layers" / config.name / name
            shutil.rmtree(ldir, ignore_errors=True)
            ldir.mkdir(parents=True)
            argv = [m.CLI, "export-c", m.ROM, m.PROGRAM, ldir / "export", "--address", f"{address:x}",
                    "--project", project]
            if config.transforms() is not None:
                argv += ["--transforms", config.transforms()]
            produced = m.run(argv, env=self.tools.env(config.env), timeout=600)
            files = sorted((ldir / "export").glob("*.c"))
            text = "\n".join(f.read_text(errors="replace") for f in files) if files else None
            variants = m.score(ldir, name, text, context_text, target_object)
            rows[name] = {"export_exit": produced["exit"], "compile_exit": variants["context"]["compile_exit"],
                          "similarity": variants["context"]["similarity"],
                          "similarity_standalone": variants["standalone"]["similarity"]}
        values = [row["similarity"] for row in rows.values()]
        result = {"key": key, "config": config.name, "functions": rows,
                  "mean_similarity": round(sum(values) / len(values), 3),
                  "compiled": sum(row["compile_exit"] == 0 for row in rows.values()),
                  "exact": sum(value >= 100.0 for value in values)}
        write_json(result_path, result)
        return result


# ---------------------------------------------------------------------------
# Wave images: modules placed into units, the sample, discovery scoring
# ---------------------------------------------------------------------------

def row_id(row: dict) -> tuple:
    """A decompiled row's identity: (module or None for the main/only unit, address text)."""
    return (row.get("module"), row["address"])


def dwarf_key(row: dict):
    """Key of a row in the types truth: the address, or (module, address) for a non-main unit."""
    address = int(row["address"], 16)
    return address if not row.get("module") else (row["module"], address)


def project_programs(project: Path):
    """({program: id}, {id: [(lo, hi)] executable regions}, [(program id, name, file_id, load, size)] modules)."""
    db = sqlite3.connect(f"file:{project}/project.sqlite?mode=ro", uri=True)
    try:
        programs = {name: pid for pid, name in db.execute("SELECT id, name FROM programs")}
        regions: dict[int, list] = {}
        for pid, start, size, permissions in db.execute(
                "SELECT program_id, start, size, permissions FROM memory_regions"):
            if "x" in permissions:
                regions.setdefault(pid, []).append((int(start, 16), int(start, 16) + size))
        try:
            # Only the importer's REL/overlay modules: an executable's own sections are `code`/`data` rows
            # (`dol:0`, `prx:1`), and its own image row `dol`/`rom`; none is a module of the truth.
            modules = [(pid, name, file_id, int(load, 16), size) for pid, name, file_id, load, size in db.execute(
                "SELECT program_id, name, file_id, load_vaddr, size FROM modules WHERE kind IN ('rel', 'overlay')")]
        except sqlite3.OperationalError:
            modules = []
    finally:
        db.close()
    return programs, regions, modules


def project_found(project: Path, program: str) -> dict[int, int]:
    db = sqlite3.connect(f"file:{project}/project.sqlite?mode=ro", uri=True)
    pid = db.execute("SELECT id FROM programs WHERE name = ?", (program,)).fetchone()[0]
    found = {}
    for entry, size in db.execute("SELECT entry, size FROM functions WHERE program_id = ?", (pid,)):
        try:
            found[int(entry, 16)] = size
        except ValueError:
            continue
    db.close()
    return found


def separate_import(tools: Tools, spec: dict, corpus: Path, cache: Path, name: str, env: dict) -> dict:
    """Import a module that meta.json stages as its own file, the way its importer would take it alone.
    A recognised executable (a REL: section i at 0x80000000 + i * 0x10000000) is handed over as is; a
    headerless overlay of a platform in wave.RAW_LANGUAGE (PSX) is a flat dump at its `load_address`
    (`import --raw BASE --language ID`). Returns the unit fields, or {"error": reason}."""
    info = spec["wave"]
    declared = next(module for module in info["modules"] if module["name"] == name)
    relative = f"{info['label']}/{declared['image']}"
    sub_spec = {"id": f"{spec['id']}@{wave.alias(name)}", "image": relative, "program": wave.alias(name),
                "truth": None, "ranges": None, "limit_s": spec.get("limit_s", M21.DEFAULT_LIMIT_S),
                "strip": wave.elf_has_symtab(corpus / relative)}
    if wave.headerless(info["platform"], corpus / relative):
        if declared.get("load_address") is None:
            return {"error": "headerless module without a load_address"}
        sub_spec["raw"] = (wave.hex_int(declared["load_address"]), wave.RAW_LANGUAGE[info["platform"]])
    try:
        binary = prepared_binary(sub_spec, corpus, cache)
        project, marker = import_env_project(tools, sub_spec, binary, sha256_file(corpus / relative), env, None, cache)
        programs, regions, _ = project_programs(project)
    except (RuntimeError, OSError, subprocess.SubprocessError) as error:
        return {"error": f"separate import failed: {str(error)[-200:]}"}
    program = marker["program"]
    return {"program": program, "ranges": list(regions.get(programs[program], [])),
            "placement": "separate import" + (" (flat dump)" if "raw" in sub_spec else ""), "span": None,
            "project": str(project), "binary": str(binary)}


def wave_units(tools: Tools, spec: dict, modules: dict, project: Path, marker: dict, binary: Path, env: dict,
               cache: Path, corpus: Path, jobs: int = 4) -> tuple[list[dict], list[dict]]:
    """Where each truth module of a wave image lives in an import: (units, unresolved).

    A unit is `{module, program, project, binary, ranges, placement}`; `project`/`binary` are None
    when the unit is a program of the project that was passed in. The module is placed the way the
    importer placed it, never by the truth's own addresses:

      main      the program the import named for the image (`marker["program"]`), over meta.json
                `ranges` or its executable regions, less the span of every other module placed in it;
      modules   a row of the project's `modules` table whose name (or file id) equals the module name
                under `wave.alias` (a REL merged into the DOL's program by `rel::attach`; an NDS
                overlay's one-row program): the executable regions of that program within the row's
                [load, load + size); else a program whose last name component equals it (`nds.ov5`):
                all of its executable regions;
      separate  a module meta.json stages as its own file (`modules[].image`) that the import did not
                already hold, or whose `placement` there begins with `standalone` (the truth lists its
                addresses as the standalone import places them, though a disc import also holds it
                merged): `separate_import` (concurrently, `jobs` at a time). The span such a module has
                in the main program is still taken out of the main module's ranges;

    A module none of these places (an N64 overlay inside the ROM: the ROM import maps the boot view, or
    a catalogued segment layout, and nothing else) is `unresolved` with the reason and its truth count,
    not scored and not guessed from the truth's own addresses.

    A unit whose ranges hold under half of its module's truth addresses is flagged `warning`: the
    truth's address space is not the importer's for that module."""
    programs, regions, rows = project_programs(project)
    main_pid = programs[marker["program"]]
    info = spec["wave"]
    declared = {module["name"]: module for module in info["modules"]}
    placed: dict[str, dict] = {}
    reasons: dict[str, str] = {}
    separate = []
    holes: list[tuple[int, int]] = []  # spans, in the main program, of modules it holds (merged RELs)
    for name in modules:
        if name == wave.MAIN:
            continue
        key = wave.alias(name)
        # An exact name first (a GBA RAM image's rows `gba:ram.02000000` / `gba:ram.02000b96` share one alias).
        row = (next((r for r in rows if name in (r[1], r[2])), None)
               or next((r for r in rows if key in (wave.alias(r[1]), wave.alias(r[2]))), None))
        module_image = declared.get(name, {}).get("image")
        has_file = bool(module_image and module_image != info["meta"]["image"]
                        and (corpus / info["label"] / module_image).is_file())
        if has_file and str(declared[name].get("placement", "")).startswith("standalone"):
            separate.append(name)
            continue
        explicit = declared.get(name, {}).get("program")
        if explicit in programs and explicit != marker["program"]:
            # The builder names the importer's program for this module (a GBA `gba.ov<N>`): take it.
            placed[name] = {"program": explicit, "ranges": list(regions.get(programs[explicit], [])),
                            "placement": f"program {explicit} (meta.json)", "span": None}
            continue
        if row is not None:
            placed[name] = {"program": next(p for p, pid in programs.items() if pid == row[0]),
                            "ranges": wave.intersect(regions.get(row[0], []), row[3], row[3] + row[4]),
                            "placement": f"modules table row {row[1]!r}", "span": (row[0], row[3], row[3] + row[4])}
            continue
        by_program = next((p for p, pid in programs.items() if "." in p and wave.alias(p.split(".")[-1]) == key), None)
        if by_program is not None:
            placed[name] = {"program": by_program, "ranges": list(regions.get(programs[by_program], [])),
                            "placement": f"program {by_program}", "span": None}
            continue
        if has_file:
            separate.append(name)
        else:
            reasons[name] = "the importer does not place this module (not in the import's modules table or programs)"
    # Every REL/overlay the main program holds (a disc import's merged RELs, truth or not) is out of the main
    # module's ranges.
    holes = [(r[3], r[3] + r[4]) for r in rows if r[0] == main_pid]
    if separate:
        with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
            for name, result in zip(separate, pool.map(
                    lambda module: separate_import(tools, spec, corpus, cache, module, env), separate)):
                if "error" in result:
                    reasons[name] = result["error"]
                else:
                    placed[name] = result
    unresolved = [{"module": name, "reason": reasons[name], "functions": len(modules[name]["truth"])}
                  for name in modules if name in reasons]
    units = []
    if wave.MAIN in modules:
        ranges = spec["ranges"] or wave.subtract(regions.get(main_pid, []), holes)
        units.append({"module": wave.MAIN, "program": marker["program"], "project": None, "binary": None,
                      "ranges": [list(r) for r in ranges], "placement": "import program"})
    for name in modules:
        if name in placed:
            p = placed[name]
            declared_ranges = wave.parse_ranges(declared.get(name, {}).get("ranges"))
            units.append({"module": name, "program": p["program"], "project": p.get("project"),
                          "binary": p.get("binary"),
                          "ranges": [list(r) for r in (declared_ranges or p["ranges"])], "placement": p["placement"]})
    for unit in units:
        truth = modules[unit["module"]]["truth"]
        inside = sum(1 for a in truth if any(lo <= a < hi for lo, hi in unit["ranges"]))
        if truth and inside < len(truth) / 2:
            unit["warning"] = (f"{inside} of {len(truth)} truth addresses lie in the unit's ranges "
                               f"({unit['placement']}): the truth's address space is not the importer's")
    return units, unresolved


def unit_project(unit: dict, project: Path) -> Path:
    return Path(unit["project"]) if unit["project"] else project


def score_units(units: list[dict], modules: dict, project: Path) -> dict:
    """Discovery over the units: the frozen recall/precision pooled over every placed module, the
    verified-only supplement, and `*_main` = the main module alone (the scope stock is run on)."""
    rows = []
    for unit in units:
        entry = modules[unit["module"]]
        row = wave.score_found(project_found(unit_project(unit, project), unit["program"]), entry["truth"],
                               entry["verified"], unit["ranges"])
        row["module"] = unit["module"]
        rows.append(row)
    total = wave.aggregate(rows)
    total["units"] = rows
    if units and units[0]["module"] == wave.MAIN:
        for key in ("recall", "precision", "recall_verified", "precision_verified"):
            total[f"{key}_main"] = rows[0][key]
    return total


def choose_wave_sample(spec: dict, units: list[dict], modules: dict, project: Path, dwarf, n: int, seed: int,
                       verified_only: bool) -> list:
    """choose_sample over every unit: the functions of the default import, inside the unit's ranges, that the
    module's truth names (verified=1 only with `verified_only`), size-stratified over all units together.
    One unit: plain addresses, so the draw and the sample file are choose_sample's; several: [unit, address]."""
    candidates = []
    for index, unit in enumerate(units):
        entry = modules[unit["module"]]
        for address, size in project_found(unit_project(unit, project), unit["program"]).items():
            if (any(lo <= address < hi for lo, hi in unit["ranges"]) and address in entry["truth"]
                    and (not verified_only or address in entry["verified"])):
                candidates.append((size, (index, address)))
    rng = random.Random(f"{seed}:{spec['id']}")
    key = lambda item: dwarf_key_of(item[1], units)  # noqa: E731
    covered = [item for item in candidates if dwarf and key(item) in dwarf]
    chosen = stratified(covered, n, rng)
    chosen += stratified([item for item in candidates if not (dwarf and key(item) in dwarf)], n - len(chosen), rng)
    chosen = sorted(chosen)
    return [address for _, address in chosen] if len(units) == 1 else [list(item) for item in chosen]


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

def dwarf_scores(rows: list[dict], truth: dict | None) -> dict:
    if not truth:
        return {}
    arity_total = arity_correct = 0
    slots = {"exact": 0, "partial": 0, "wrong": 0}
    for row in rows:
        expected = truth.get(dwarf_key(row))
        if expected is None:
            continue
        arity_total += 1
        if not row.get("success") or row.get("parameters") is None:
            slots["wrong"] += sum(1 for c in expected["parameters"] + [expected["returns"]] if c != "unknown")
            continue
        arity_correct += len(row["parameters"]) == expected["arity"]
        pairs = list(zip(expected["parameters"], row["parameters"])) + [(expected["returns"], row["returns"])]
        for want, got in pairs:
            exact, partial, wrong = type_headtohead.score(type_headtohead.norm_truth(want), classify_c(got or ""))
            slots["exact"] += exact
            slots["partial"] += partial
            slots["wrong"] += wrong
    scored = sum(slots.values())
    return {"dwarf_functions": arity_total,
            "arity_accuracy": round(arity_correct / arity_total, 4) if arity_total else None,
            "type_slots": scored, **{f"type_{k}": v for k, v in slots.items()},
            "type_exact_rate": round(slots["exact"] / scored, 4) if scored else None}


def summarize(result: dict, discovery: dict | None, truth_dwarf: dict | None, m22: dict | None) -> dict:
    rows = result["functions"]
    ok = [row for row in rows if row.get("success")]
    times = [row["seconds"] for row in ok]
    summary = {
        "sampled": len(rows), "decompiled": len(ok),
        "success_rate": round(len(ok) / len(rows), 4) if rows else None,
        "gotos": sum(row["gotos"] for row in ok), "labels": sum(row["labels"] for row in ok),
        "irregular_functions": sum(row["irregular"] for row in ok),
        "native_warnings": sum(row["native_warnings"] for row in ok),
        "text_warnings": sum(row["text_warnings"] for row in ok),
        "lines": sum(row["lines"] for row in ok),
        "median_seconds": round(statistics.median(times), 3) if times else None,
        "max_seconds": round(max(times), 3) if times else None,
        "wall_seconds": result["wall_seconds"],
    }
    if discovery:
        summary.update(recall=discovery["recall"], precision=discovery["precision"],
                       discovered=discovery["found"])
        # Wave images: the supplement over verified=1 rows and the main module alone (the module stock is run on).
        summary.update({k: discovery[k] for k in ("recall_verified", "precision_verified", "recall_main",
                                                  "precision_main", "recall_verified_main", "precision_verified_main",
                                                  "verified_truth") if k in discovery})
    summary.update(dwarf_scores(rows, truth_dwarf))
    if m22:
        # The context wrapping compiles m22's generated context.h, which agbcc
        # can refuse for every candidate alike (-Werror on a built-in
        # redeclaration); the standalone wrapping still measures the C.
        standalone = [row["similarity_standalone"] for row in m22["functions"].values()]
        summary.update(m22_mean_similarity=round(m22["mean_similarity"] / 100, 5), m22_exact=m22["exact"],
                       m22_compiled=m22["compiled"],
                       m22_standalone_similarity=round(sum(standalone) / len(standalone) / 100, 5),
                       m22_standalone_exact=sum(value >= 100.0 for value in standalone))
    return summary


def compare(a: dict, b: dict, a_rows: list[dict], b_rows: list[dict]) -> dict:
    """b - a per metric. Count metrics only over functions both decompiled."""
    both = ({row_id(row) for row in a_rows if row.get("success")}
            & {row_id(row) for row in b_rows if row.get("success")})
    count = lambda rows, key: sum(row[key] for row in rows if row_id(row) in both)  # noqa: E731
    field = {"irregular_functions": "irregular"}
    deltas = {}
    for metric, direction, kind in METRICS:
        if kind == "count" and not metric.startswith("m22"):
            base, other = count(a_rows, field.get(metric, metric)), count(b_rows, field.get(metric, metric))
        else:
            base, other = a.get(metric), b.get(metric)
        if base is None or other is None:
            continue
        delta = other - base
        material = (abs(delta) >= RATE_THRESHOLD if kind == "rate"
                    else abs(delta) >= max(1, COUNT_THRESHOLD * abs(base)))
        deltas[metric] = {"from": base, "to": other, "delta": round(delta, 5), "material": material,
                          "direction": direction}
    deltas["common_functions"] = len(both)
    return deltas


def verdict(deltas: dict, sign: int) -> str:
    better = worse = False
    for metric, delta in deltas.items():
        if not isinstance(delta, dict) or not delta["material"] or not delta["direction"]:
            continue
        if delta["delta"] * delta["direction"] * sign > 0:
            better = True
        else:
            worse = True
    return {(True, False): "helps", (False, True): "hurts", (True, True): "mixed"}.get((better, worse), "neutral")


def describe(deltas: dict) -> str:
    parts = []
    for metric, _, kind in METRICS:
        delta = deltas.get(metric)
        if not delta or not delta["delta"]:
            continue
        value = f"{delta['delta'] * 100:+.1f}pp" if kind == "rate" else f"{delta['delta']:+d}"
        parts.append(f"{metric} {value}" + ("" if delta["material"] or not delta["direction"] else "~"))
    return ", ".join(parts) or "no change"


def markdown(report: dict) -> str:
    out = [f"# Console research components ({report['generated']})", "",
           f"Tools fingerprint `{report['tools']}`; sample n={report['n']} seeds={report['seeds']}. "
           f"Thresholds: rates {RATE_THRESHOLD * 100:.1f} pp, counts {COUNT_THRESHOLD:.0%} of the reference "
           "(min 1), counts over functions both configurations decompiled. Output is deterministic: deltas are "
           "exact. `~` marks a change below the threshold.", ""]
    images = [image for image in report["images"] if report["images"][image].get("configs")]
    out += ["## Verdict matrix (component effect vs its reference)", "",
            "| component | config | reference | " + " | ".join(images) + " |",
            "|---|---|---|" + "---|" * len(images)]
    for config in CONFIGS:
        if config.reference is None:
            continue
        cells = [report["images"][image]["configs"].get(config.name, {}).get("verdict", "–") for image in images]
        if all(cell == "–" for cell in cells):
            continue
        out.append(f"| {config.component} | {config.name} | {config.reference} | " + " | ".join(cells) + " |")
    out += ["", "## Deltas", "",
            "| component | image | verdict | vs reference | vs default | vs baseline-off |", "|---|---|---|---|---|---|"]
    for config in CONFIGS:
        if config.reference is None:
            continue
        for image in images:
            row = report["images"][image]["configs"].get(config.name)
            if not row:
                continue
            if "error" in row:
                out.append(f"| {config.component} | {image} | error | {row['error'][-200:].replace('|', '/')} | | |")
                continue
            out.append(f"| {config.component} | {image} | {row.get('verdict', '–')} | "
                       f"{describe(row.get('vs_reference', {}))} | {describe(row.get('vs_default', {}))} | "
                       f"{describe(row.get('vs_baseline_off', {}))} |")
    out += ["", "## Absolute values", "",
            "| image | config | success | gotos | labels | irregular | warnings | lines | recall | precision | "
            "arity | type exact | m22 sim | m22 standalone | median s |",
            "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for image in images:
        for name, row in report["images"][image]["configs"].items():
            if "summary" not in row:
                continue
            s = row["summary"]
            fmt = lambda v: "–" if v is None else (f"{v:.4f}" if isinstance(v, float) else str(v))  # noqa: E731
            out.append(f"| {image} | {name} | {fmt(s.get('success_rate'))} | {s['gotos']} | {s['labels']} | "
                       f"{s['irregular_functions']} | {s['native_warnings']} | {s['lines']} | "
                       f"{fmt(s.get('recall'))} | {fmt(s.get('precision'))} | {fmt(s.get('arity_accuracy'))} | "
                       f"{fmt(s.get('type_exact_rate'))} | {fmt(s.get('m22_mean_similarity'))} | "
                       f"{fmt(s.get('m22_standalone_similarity'))} | "
                       f"{fmt(s.get('median_seconds'))} |")
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Stock Ghidra (the existing comparator: benchmarks/import_speed.py's analyzeHeadless
# configuration per image, ghidra/ExportFunctionEntries.java for discovery and
# scripts/ExportDecompiledSignatures.java for printed signatures, as psp_stock_compare.py)
# ---------------------------------------------------------------------------

# (language, loader, loader options) by platform prefix, for images import_speed.GHIDRA_CONFIG
# (keyed by image id) does not name. Same choices as there; None = the loader/opinion picks.
STOCK_PLATFORM = {
    "gba": ("ARM:LE:32:v4t", "GBALoader", []),
    "nds": ("ARM:LE:32:v5t", "NTRGhidraLoader", ["-loader-cpu", "ARM9", "-loader-overlays", "true"]),
    "gc": ("PowerPC:BE:32:Gekko_Broadway", None, []),
    "wii": ("PowerPC:BE:32:Gekko_Broadway", None, []),
    "n64": (None, None, []),
    "psx": ("MIPS:LE:32:default", None, []),
    "ps1": ("MIPS:LE:32:default", None, []),
    "ps2": ("r5900:LE:32:default", None, []),
    "psp": ("Allegrex:LE:32:default", None, []),
    "psv": ("ARM:LE:32:v8", None, []),
    "x360": ("PowerPC:BE:64:A2ALT-32addr", None, []),
    # Windows PE (x86 and x86-64): the PE loader reads the machine and picks the compiler spec, as it does for a user.
    "pc": (None, None, []),
}
STOCK_SCRIPTS = f"{ROOT / 'benchmarks' / 'ghidra'};{ROOT / 'scripts'}"


def stock_config(spec: dict) -> dict:
    speed = load_module("import_speed", ROOT / "benchmarks" / "import_speed.py")
    if spec["id"] in speed.GHIDRA_CONFIG:
        return dict(speed.GHIDRA_CONFIG[spec["id"]], source="import_speed.GHIDRA_CONFIG")
    language, loader, options = STOCK_PLATFORM.get(spec["id"].split("-")[0], (None, None, []))
    return {"language": language, "loader": loader, "options": options,
            "why": "STOCK_PLATFORM[" + spec["id"].split("-")[0] + "] (console_research.py)",
            "source": "console_research.STOCK_PLATFORM"}


class StockFailure(RuntimeError):
    """Stock Ghidra itself did not produce a result: `kind` "dnf" (over the time limit) or "crash"
    (its analyzer aborted). Either is a result about stock, cached like a success and labelled in the
    tables; neither is a timing, and the vs-stock sign tests leave such a game out (counted neither way).
    A failure of our own export scripts is not a StockFailure (a harness bug, never cached)."""

    def __init__(self, record: dict):
        super().__init__(record["label"])
        self.record = record


def stock_crash(output: str) -> dict | None:
    """Stock's own failure to analyse the image (`Import failed for file`, or the analyzer's `Abort due to
    Headless analyzer error`) as a crash record: the first error the run reported (the abort's exception
    class, else the first `ERROR REPORT:` message) and the analysis command classes in that stack trace
    (for a stack overflow, the commands that recurse), in order of first appearance. The same crash can
    surface as different errors in different runs (KH Chain of Memories: a StackOverflowError once, the
    transaction's locked-buffer assertion it leaves behind another time), so the label is per run."""
    lines = output.splitlines()
    if not any("Import failed for file" in line or "Abort due to Headless analyzer error" in line for line in lines):
        return None
    at = next((i for i, line in enumerate(lines) if "Abort due to Headless analyzer error" in line), None)
    if at is not None:
        exception = re.search(r"([\w.$]+(?:Error|Exception))", lines[at])
        name = exception.group(1).rsplit(".", 1)[-1] if exception else "unknown error"
    else:
        at = next(i for i, line in enumerate(lines) if line.startswith("ERROR REPORT:"))
        message = lines[at].removeprefix("ERROR REPORT:").split("(HeadlessAnalyzer)")[0].strip()
        exception = re.search(r"\(HeadlessAnalyzer\)\s+([\w.$]+)", lines[at])
        name = (exception.group(1).rsplit(".", 1)[-1] + ": " if exception else "") + message
    commands: list[str] = []
    for line in lines[at + 1:]:
        frame = re.match(r"\s+at ghidra\.app\.cmd\.[\w.]*?\.(\w+Cmd)\.", line)
        if frame and frame.group(1) not in commands:
            commands.append(frame.group(1))
        elif not line.startswith(("\t", " ")):
            break
    where = f" in {' / '.join(commands)}" if commands else ""
    return {"kind": "crash", "label": f"stock crashed ({name}{where})", "exception": name, "commands": commands}


def run_stock_headless(ghidra: Path, binary: Path, config: dict, addresses: list[int], work: Path,
                       platform: str, timeout: int) -> tuple[dict, list[dict]]:
    shutil.rmtree(work, ignore_errors=True)
    project = work / "project"
    project.mkdir(parents=True)
    listing, entries, signatures = work / "addresses.txt", work / "entries.json", work / "signatures.json"
    listing.write_text("".join(f"{address:x}\n" for address in addresses))
    argv = [str(ghidra / "support" / "analyzeHeadless"), str(project), "proj", "-import", str(binary)]
    if config.get("loader"):
        argv += ["-loader", config["loader"], *config.get("options", [])]
    if config.get("language"):
        argv += ["-processor", config["language"]]
    argv += ["-scriptPath", STOCK_SCRIPTS, "-postScript", "ExportFunctionEntries.java", str(entries),
             "-postScript", "ExportDecompiledSignatures.java", str(listing), str(signatures), "120",
             *(["thumb"] if platform == "gba" else []), "-deleteProject"]
    env = {k: v for k, v in os.environ.items() if not k.startswith("ROMWRIGHT_")}
    env.update(GHIDRA_HEADLESS_MAXMEM=os.environ.get("GHIDRA_HEADLESS_MAXMEM", "8G"), DEBUGINFOD_URLS="")
    # analyzeHeadless is a shell script that forks the JVM; run it in its own session so a timeout
    # kills the JVM too (subprocess.run's timeout kills only the shell, and the orphaned JVM went on
    # analysing into the next run's work directory).
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env,
                               start_new_session=True)
    started = time.monotonic()
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate()
        (work / "headless.log").write_text(stdout + stderr)
        phase = "signature export" if entries.is_file() else "auto-analysis"
        raise StockFailure({"kind": "dnf", "label": f"stock DNF (>{timeout / 3600:g} h {phase})",
                            "phase": phase, "limit_s": timeout, "log": str(work / "headless.log")})
    finally:
        shutil.rmtree(project, ignore_errors=True)
    output = stdout + stderr
    (work / "headless.log").write_text(output)
    if not entries.is_file() or not signatures.is_file():
        crash = stock_crash(output)
        if crash is None:
            raise RuntimeError(f"stock run failed (full log {work / 'headless.log'}):\n" + output[-1200:])
        crash.update(wall_seconds=round(time.monotonic() - started, 1), log=str(work / "headless.log"))
        raise StockFailure(crash)
    rows = []
    for line, row in json.loads(signatures.read_text())["functions"].items():
        parsed = None
        if row.get("signature"):
            text = row["signature"].rstrip().rstrip(";")
            parsed = signature(text + "\n{", text.split("(")[0].split()[-1].lstrip("*"))
        rows.append({"address": f"{int(line, 16):08x}", "success": parsed is not None,
                     "parameters": parsed[1] if parsed else None, "returns": parsed[0] if parsed else None,
                     "existed": bool(row.get("existed", False))})
    return json.loads(entries.read_text()), rows


def stock_summary(found: dict[int, int] | None, entry: dict | None, ranges, rows: list[dict], dwarf) -> dict:
    ok = [row for row in rows if row["success"]]
    summary = {"sampled": len(rows), "decompiled": len(ok),
               "success_rate": round(len(ok) / len(rows), 4) if rows else None,
               "stock_functions_existing": sum(1 for row in rows if row["existed"])}
    if found is not None and entry is not None:
        score = wave.score_found(found, entry["truth"], entry["verified"], ranges)
        summary.update({k: score[k] for k in ("recall", "precision", "recall_verified", "precision_verified")},
                       discovered=score["found"])
    summary.update(dwarf_scores(rows, dwarf))
    return summary


def stock_for_image(args, spec: dict, binary: Path, image_sha: str, entry: dict | None, ranges,
                    dwarf, samples: dict, union: list, cache: Path) -> dict:
    """Stock Ghidra on the main module (the program its loader makes of the staged image), over the
    union of the seeds' sampled main-module addresses; per-seed and combined summaries."""
    def main_address(item):
        return item if isinstance(item, int) else (item[1] if item[0] == 0 else None)

    addresses = sorted({a for item in union if (a := main_address(item)) is not None})
    config = stock_config(spec)
    key = hashlib.sha256(json.dumps([addresses, config.get("language"), config.get("loader")]).encode()).hexdigest()[:12]
    cached = cache / "stock" / f"{spec['id']}-{image_sha[:12]}-{key}.json"
    data = read_json(cached)
    if data is not None and "failure" in data:
        failure = data["failure"]
        retry = args.stock_retry_failed or (failure["kind"] == "dnf" and failure.get("limit_s", 0) < args.stock_timeout)
        if not retry:
            raise StockFailure(failure)
        data = None
    if data is None and spec["id"] in args.stock_known_failure:
        # A DNF observed by an earlier run of this harness that predates failure caching, recorded with
        # its evidence instead of re-running a multi-hour stock analysis to the same limit.
        limit_s, evidence = args.stock_known_failure[spec["id"]]
        failure = {"kind": "dnf", "label": f"stock DNF (>{limit_s / 3600:g} h auto-analysis)",
                   "phase": "auto-analysis", "limit_s": limit_s, "source": evidence}
        write_json(cached, {"failure": failure})
        raise StockFailure(failure)
    if data is None:
        log(f"{spec['id']}: stock Ghidra ({config.get('language')}, loader {config.get('loader')}) on "
            f"{len(addresses)} sampled addresses")
        started = time.monotonic()
        try:
            exported, rows = run_stock_headless(args.ghidra, binary, config, addresses, args.stock_work / spec["id"],
                                                spec["id"].split("-")[0], args.stock_timeout)
        except StockFailure as failure:
            write_json(cached, {"failure": failure.record})
            raise
        data = {"language": exported.get("language"), "compiler": exported.get("compiler"),
                "format": exported.get("format"), "wall_seconds": round(time.monotonic() - started, 1),
                "functions": [[f["entry"], f["size"]] for f in exported["functions"] if not f["overlay"]],
                "rows": rows}
        write_json(cached, data)
    found = {entry_address: size for entry_address, size in data["functions"]}
    rows = {row["address"]: row for row in data["rows"]}
    view = lambda keep: [row for address, row in rows.items() if keep(int(address, 16))]  # noqa: E731
    out = {"config": {k: config.get(k) for k in ("language", "loader", "options", "why", "source")},
           "ghidra_language": data["language"], "ghidra_compiler": data["compiler"],
           "wall_seconds": data["wall_seconds"], "functions": len(found),
           "scope": "main module only (the program stock's loader makes of the staged image)",
           "combined": {"summary": stock_summary(found, entry, ranges, view(lambda a: True), dwarf)}}
    if len(samples) > 1:
        out["per_seed"] = {}
        for seed, sample in samples.items():
            wanted = {a for item in sample if (a := main_address(item)) is not None}
            out["per_seed"][str(seed)] = {"summary": stock_summary(found, entry, ranges, view(wanted.__contains__), dwarf)}
    return out


# ---------------------------------------------------------------------------
# One image
# ---------------------------------------------------------------------------

def run_no_truth(args, tools: Tools, cache: Path, name: str, path: Path) -> dict:
    """An image that has no truth (a retail game): success and time only (`--no-truth NAME=PATH`).

    Our import (default environment, fresh project), the export-c success of up to 20 functions it found, spread
    over the address range, and with `--stock` stock Ghidra's wall time and function count on the same file. No
    recall, precision or sample is computed: nothing here says which functions exist. The two tools' entry sets
    are compared with each other (agreement, not accuracy)."""
    spec = {"id": f"pc-{name}", "image": str(path), "program": "pc"}
    image_sha = sha256_file(path)
    row = {"id": spec["id"], "image": str(path), "sha256": image_sha, "size": path.stat().st_size}
    project, marker = import_env_project(tools, spec, path, image_sha, {}, None, cache)
    found = project_found(project, marker["program"])
    row["import"] = {"seconds": marker["seconds"], "functions": len(found),
                     "degraded": [d for d in marker.get("diagnostics", []) if d.get("severity") == "degraded"],
                     "compiler": next((d["message"] for d in marker.get("diagnostics", [])
                                       if d.get("stage") == "compiler"), None)}
    addresses = sorted(found)
    step = max(1, len(addresses) // 20)
    sampled = addresses[::step][:20]
    config = BY_NAME["default"]
    rows = [decompile_one(tools, project, path, marker["program"], address, config,
                          cache / "decompiled" / spec["id"]) for address in sampled]
    row["decompile"] = {"sampled": len(rows), "success": sum(1 for r in rows if r.get("success")),
                        "seconds": round(sum(r["seconds"] for r in rows), 1),
                        "errors": sorted({(r.get("error") or "")[-120:] for r in rows if not r.get("success")})[:3]}
    if args.stock:
        cached = cache / "stock" / f"{spec['id']}-{image_sha[:12]}-notruth.json"
        data = read_json(cached)
        if data is None:
            config_stock = stock_config(spec)
            started = time.monotonic()
            try:
                exported, _rows = run_stock_headless(args.ghidra, path, config_stock, [], args.stock_work / spec["id"],
                                                     "pc", args.stock_timeout)
                data = {"language": exported.get("language"), "compiler": exported.get("compiler"),
                        "wall_seconds": round(time.monotonic() - started, 1),
                        "functions": [f["entry"] for f in exported["functions"] if not f["overlay"]]}
            except StockFailure as failure:
                data = {"failure": failure.record}
            write_json(cached, data)
        if "failure" in data:
            row["stock"] = {"failure": data["failure"]["label"]}
        else:
            theirs = set(data["functions"])
            ours = set(found)
            row["stock"] = {"seconds": data["wall_seconds"], "functions": len(theirs),
                            "language": data["language"], "compiler": data["compiler"],
                            "agreement": {"both": len(ours & theirs), "ours_only": len(ours - theirs),
                                          "stock_only": len(theirs - ours)}}
    return row


def no_truth_markdown(rows: list[dict]) -> str:
    out = ["", "## Images without truth (success and time only)", "",
           "| image | size | import s | functions | export-c ok | stock s | stock functions | both / ours only / stock only | compiler |",
           "|---|---|---|---|---|---|---|---|---|"]
    for row in rows:
        stock = row.get("stock") or {}
        agree = stock.get("agreement") or {}
        out.append(f"| {row['id']} | {row['size']:,} | {row['import']['seconds']} | {row['import']['functions']} | "
                   f"{row['decompile']['success']}/{row['decompile']['sampled']} | "
                   f"{stock.get('seconds', stock.get('failure', ''))} | {stock.get('functions', '')} | "
                   f"{agree.get('both', '')} / {agree.get('ours_only', '')} / {agree.get('stock_only', '')} | "
                   f"{(row['import'].get('compiler') or '').split(': ', 1)[-1][:70]} |")
    return "\n".join(out) + "\n"


def item_id(item, units) -> tuple:
    """The row identity (module or None, address text) of a sample item (an address, or [unit, address])."""
    if isinstance(item, int):
        return (None, f"{item:08x}")
    index, address = item
    return (None if index == 0 else units[index]["module"], f"{address:08x}")


def sample_label(item, units) -> str:
    module, address = item_id(item, units)
    return address if module is None else f"{module}:{address}"


def dwarf_key_of(item, units):
    if isinstance(item, int):
        return item
    index, address = item
    return address if index == 0 else (units[index]["module"], address)


def subset(result: dict, sample: list, units) -> dict:
    wanted = {item_id(item, units) for item in sample}
    return dict(result, wall_seconds=None, functions=[row for row in result["functions"] if row_id(row) in wanted])


def legacy_dwarf(spec: dict, corpus: Path, cache: Path, image_sha: str):
    if spec["id"] not in DWARF:
        return None, None
    dwarf_path = cache / "dwarf" / f"{spec['id']}-{image_sha[:12]}.json"
    dwarf_report = read_json(dwarf_path)
    if dwarf_report is None:
        log(f"{spec['id']}: reading DWARF truth")
        extracted = dwarf_truth(corpus / DWARF[spec["id"]])
        dwarf_report = dict(extracted, functions={f"{k:08x}": v for k, v in extracted["functions"].items()})
        write_json(dwarf_path, dwarf_report)
    dwarf = {int(k, 16): v for k, v in dwarf_report["functions"].items()}
    return dwarf, {"reader": dwarf_report["reader"], "functions": len(dwarf),
                   "conflicts_dropped": dwarf_report["conflicts_dropped"]}


def wave_dwarf(spec: dict, corpus: Path, cache: Path, image_sha: str):
    """Prototype truth of a wave image: `truth/types/` when the builder wrote it (shape of the dwarf
    cache: {reader, conflicts_dropped, functions: {"%08x" | "<module>:%08x": row}}); otherwise, for a
    `dwarf` truth whose staged image still carries `.debug_info`, `dwarf_truth` of that image."""
    info = spec["wave"]
    path = wave.types_file(corpus / info["label"])
    if path:
        payload = read_json(path)
        dwarf = wave.parse_types(payload["functions"])
        return dwarf, {"reader": payload.get("reader"), "functions": len(dwarf), "source": f"{path.name}",
                       "conflicts_dropped": payload.get("conflicts_dropped", 0)}
    source = corpus / spec["image"]
    if info["meta"].get("truth_kind") == "dwarf" and ".debug_info" in subprocess.run(
            ["llvm-readelf", "-S", "--wide", str(source)], capture_output=True, text=True).stdout:
        dwarf_path = cache / "dwarf" / f"{spec['id']}-{image_sha[:12]}.json"
        payload = read_json(dwarf_path)
        if payload is None:
            log(f"{spec['id']}: reading DWARF truth from the staged image")
            try:
                extracted = dwarf_truth(source)
            except ValueError as error:
                # No silent default: dwarf1_types refuses to guess `long`'s width (e.g. a PSP image whose
                # structs do not fix it). The image runs without type truth and the report says why;
                # a builder who knows the ABI supplies truth/types/functions.json instead.
                return None, {"error": f"DWARF truth unreadable: {error}", "functions": 0}
            payload = dict(extracted, functions={f"{k:08x}": v for k, v in extracted["functions"].items()})
            write_json(dwarf_path, payload)
        dwarf = wave.parse_types(payload["functions"])
        return dwarf, {"reader": payload["reader"], "functions": len(dwarf), "source": "staged image DWARF",
                       "conflicts_dropped": payload["conflicts_dropped"]}
    return None, None


def wave_summary(meta: dict, modules: dict, variant: str | None = None) -> dict:
    out = {key: meta.get(key) for key in ("game", "platform", "region_version", "source_archive", "sha1_expected",
                                           "sha1_actual", "version_match", "truth_kind", "repo", "commit", "compiler",
                                           "linked_percent", "notes", "program_hint")}
    out["variant"] = variant
    out["truth_functions"] = sum(len(m["truth"]) for m in modules.values())
    out["verified_functions"] = sum(len(m["verified"]) for m in modules.values())
    nesting = {name: wave.nesting(m["truth"]) for name, m in modules.items()}
    out["nested_rows"] = sum(n["nested"] for n in nesting.values())
    out["nested_size0_rows"] = sum(n["nested_size0"] for n in nesting.values())
    out["straddling_rows"] = sum(n["straddling"] for n in nesting.values())
    out["truth_by_module"] = {name: {"functions": len(m["truth"]), "verified": len(m["verified"]), **nesting[name]}
                              for name, m in modules.items()}
    return out


def build_configs(results: dict, imports: dict, discoveries: dict, dwarf, m22_results: dict, files: dict) -> dict:
    """summary / comparisons / verdict of every configuration over `results` (name -> result)."""
    out = {}
    for name, result in results.items():
        marker = imports[name]
        out[name] = {"summary": summarize(result, discoveries.get(name), dwarf, m22_results.get(name)),
                     "import": {k: marker.get(k) for k in ("seconds", "switch_stats")},
                     "prototypes": marker.get("prototypes"), "results_file": files[name]}
    for name, row in out.items():
        config = BY_NAME[name]
        for label, other in (("vs_default", "default"), ("vs_baseline_off", "baseline-off"),
                             ("vs_reference", config.reference)):
            if other and other != name and other in results:
                row[label] = compare(out[other]["summary"], row["summary"],
                                     results[other]["functions"], results[name]["functions"])
        if "vs_reference" in row:
            row["verdict"] = verdict(row["vs_reference"], config.sign)
    return out


def process_image(args, tools: Tools, cache: Path, configs: list, spec: dict, image: dict, seeds: list[int],
                  n: int, m22_box: dict) -> None:
    corpus = args.corpus
    wave_info = spec.get("wave")
    binary = prepared_binary(spec, corpus, cache)
    image_sha = sha256_file(corpus / spec["image"])
    modules = truth = None
    sample_tag = ""
    if wave_info:
        truth_path = corpus / spec["truth"][1]
        modules = wave.load_modules(truth_path, wave_info["modules"])
        spec["probe"] = sorted(modules.get(wave.MAIN, {"truth": {}})["truth"])[:5000]
        sample_tag = "-w" + sha256_file(truth_path)[:8] + ("-v" if args.sample_verified else "")
        image["wave"] = wave_summary(wave_info["meta"], modules, wave_info.get("variant"))
        dwarf, dwarf_info = wave_dwarf(spec, corpus, cache, image_sha)
    else:
        truth = function_truth(spec, corpus)
        dwarf, dwarf_info = legacy_dwarf(spec, corpus, cache, image_sha)
    if dwarf_info:
        image["dwarf"] = dwarf_info
    default_project, default_marker = import_project(tools, spec, binary, image_sha, BY_NAME["default"], truth, cache)
    program = default_marker["program"]
    default_units = None
    if wave_info:
        default_units, unresolved = wave_units(tools, spec, modules, default_project, default_marker, binary,
                                               {}, cache, corpus, args.jobs)
        image["wave"]["scored_modules"] = [unit["module"] for unit in default_units]
        image["wave"]["unresolved_modules"] = unresolved
        image["wave"]["unplaced_functions"] = sum(row["functions"] for row in unresolved)
        image["units"] = [{k: unit.get(k) for k in ("module", "program", "placement", "warning", "ranges")}
                          for unit in default_units]
        if not default_units:
            raise RuntimeError(f"no truth module could be placed in the import (unresolved: {unresolved})")
        # The sample depends on where the modules were placed, not only on the truth: a stale placement must
        # not be reused.
        sample_tag += "-u" + hashlib.sha256(json.dumps(
            [[u["module"], u["program"], u["project"], u["ranges"]] for u in default_units]).encode()).hexdigest()[:8]
    samples: dict[int, list] = {}
    for seed in seeds:
        sample_path = cache / "samples" / f"{spec['id']}-{tools.fingerprint}-{n}-{seed}{sample_tag}.json"
        raw = read_json(sample_path)
        if raw is None:
            raw = (choose_wave_sample(spec, default_units, modules, default_project, dwarf, n, seed,
                                      args.sample_verified)
                   if wave_info else choose_sample(spec, default_project, program, truth, dwarf, n, seed))
            write_json(sample_path, raw)
        samples[seed] = [tuple(item) if isinstance(item, list) else item for item in raw]
    union = samples[seeds[0]] if len(seeds) == 1 else sorted({item for sample in samples.values() for item in sample})
    image["stripped"] = spec.get("strip") or False
    image.update(status="ran", program=program, sample=[sample_label(item, default_units) for item in union],
                 samples={str(seed): [sample_label(item, default_units) for item in sample]
                          for seed, sample in samples.items()},
                 sample_in_dwarf=sum(1 for item in union if dwarf and dwarf_key_of(item, default_units) in dwarf))
    seed_tag = "-".join(str(seed) for seed in seeds)
    results, imports, discoveries, files, errors = {}, {}, {}, {}, {}
    for config in configs:
        try:
            base, marker = import_project(tools, spec, binary, image_sha, config, truth, cache)
            project, units = base, None
            if wave_info:
                units, _ = wave_units(tools, spec, modules, base, marker, binary, config.import_env(), cache, corpus,
                                      args.jobs)
                if [u["module"] for u in units] != [u["module"] for u in default_units]:
                    raise RuntimeError("the scored modules differ from the default import's")
            if config.infer_prototypes:
                project, marker = prototype_project(tools, base, marker, binary, config, args.prototype_budget_ms)
            imports[config.name] = marker
            if config.import_env() or config.name == "default":
                discoveries[config.name] = score_units(units, modules, base) if wave_info else marker.get("discovery")
            result_path = cache / "results" / tools.fingerprint / spec["id"] / f"{config.name}-{n}-{seed_tag}.json"
            files[config.name] = str(result_path)
            results[config.name] = run_decompile(tools, spec, project, marker, binary, config, union, result_path,
                                                 args.jobs, units)
        except (RuntimeError, OSError, subprocess.SubprocessError) as error:
            errors[config.name] = {"error": str(error)[-1000:]}
            log(f"{spec['id']}/{config.name}: ERROR {str(error)[-300:]}")
    m22_results = {}
    if spec["id"] == M22_IMAGE and not args.no_m22 and "default" in results:
        m22 = m22_box.get("runner") or m22_box.setdefault("runner", M22Runner(tools, cache))
        missing = m22.prerequisites()
        if missing:
            image["m22"] = {"status": "skipped", "missing": missing}
        else:
            m22.prepare(default_project, program)
            for config in configs:
                # Decompile-time configurations: same import, no prototype job.
                if config.import_env() or config.infer_prototypes or config.name not in results:
                    continue
                m22_results[config.name] = m22.run(
                    config, cache / "results" / tools.fingerprint / "m22" / f"{config.name}.json")
    degraded = {name: [d.get("message", "") for d in marker.get("diagnostics") or [] if d.get("severity") == "degraded"]
                for name, marker in imports.items()}
    image["degraded_imports"] = {name: messages[:5] for name, messages in degraded.items() if messages}
    if image["degraded_imports"]:
        log(f"{spec['id']}: DEGRADED import(s) {sorted(image['degraded_imports'])}: not a valid measurement; "
            f"{next(iter(image['degraded_imports'].values()))[0][:200]}")
    image["configs"] = {**errors, **build_configs(results, imports, discoveries, dwarf, m22_results, files)}
    if len(seeds) > 1:
        image["per_seed"] = {}
        for seed in seeds:
            views = {name: subset(result, samples[seed], default_units) for name, result in results.items()}
            image["per_seed"][str(seed)] = {
                "sample": [sample_label(item, default_units) for item in samples[seed]],
                "configs": {**errors, **build_configs(views, imports, discoveries, dwarf, m22_results, files)}}
    if args.stock:
        if wave_info:
            entry = modules.get(wave.MAIN)
            ranges = default_units[0]["ranges"] if default_units and default_units[0]["module"] == wave.MAIN else None
        else:
            entry = {"truth": truth, "verified": set()} if truth else None
            ranges = (spec["ranges"] or project_ranges(default_project, program)) if truth else None
        stock_binary, stock_sha = binary, image_sha
        main_module = next((m for m in (wave_info or {}).get("modules", []) if m["name"] == wave.MAIN), None)
        if main_module and main_module.get("image") and main_module["image"] != wave_info["meta"]["image"]:
            # The staged image is a container (a disc) no stock loader reads: stock runs on the main
            # module's own file (the DOL), the scope it is compared on.
            relative = f"{wave_info['label']}/{main_module['image']}"
            stock_spec = {"id": f"{spec['id']}@main", "image": relative, "strip": wave.elf_has_symtab(corpus / relative)}
            stock_binary, stock_sha = prepared_binary(stock_spec, corpus, cache), sha256_file(corpus / relative)
        try:
            image["stock"] = stock_for_image(args, spec, stock_binary, stock_sha, entry if ranges else None, ranges,
                                             dwarf, samples, union, cache)
        except StockFailure as failure:
            image["stock"] = {"error": failure.record["label"], "failure": failure.record}
            log(f"{spec['id']}/stock: {failure.record['label']}")
        except (RuntimeError, OSError, subprocess.SubprocessError) as error:
            image["stock"] = {"error": str(error)[-1000:]}
            log(f"{spec['id']}/stock: ERROR {str(error)[-300:]}")


def project_ranges(project: Path, program: str) -> list[tuple[int, int]]:
    programs, regions, _modules = project_programs(project)
    return regions.get(programs[program], [])


# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--corpus", type=Path, default=M21.CORPUS)
    parser.add_argument("--cache", type=Path, default=CACHE)
    parser.add_argument("--target-dir", type=Path, default=TARGET)
    parser.add_argument("--out", type=Path, default=None,
                        help="JSON report; the markdown summary is written next to it (.md). Default: "
                             "benchmarks/reports/console_research.json, or console_research_wave_<date>.json "
                             "with --corpus-wave")
    parser.add_argument("--images", default="", help="comma-separated image ids (default: all present)")
    parser.add_argument("--configs", default="",
                        help="comma-separated configurations (default: all; with --corpus-wave: default,baseline-off)")
    parser.add_argument("-n", type=int, default=None,
                        help="sampled functions per image and seed (default 200; 500 with --corpus-wave)")
    parser.add_argument("--seed", type=int, default=None, help="one sample seed (default 20261006)")
    parser.add_argument("--seeds", default="",
                        help="comma-separated sample seeds; results per seed plus the combined (union) result "
                             "(default 1,2 with --corpus-wave)")
    parser.add_argument("--jobs", type=int, default=4, help="concurrent export-c processes")
    parser.add_argument("--prototype-budget-ms", type=int, default=3_600_000)
    parser.add_argument("--no-m22", action="store_true", help="skip the pokeemerald objdiff measurement")
    wave_group = parser.add_argument_group("truth-contract images (docs/console-research.md)")
    wave_group.add_argument("--corpus-wave", action="store_true",
                            help="run the images described by <corpus>/<id>/truth/{meta.json,functions.tsv} "
                                 "instead of the built-in list")
    wave_group.add_argument("--min-age-s", type=float, default=60.0,
                            help="skip a truth directory whose meta/tsv/image changed more recently than this")
    wave_group.add_argument("--sample-verified", action="store_true",
                            help="draw the sample from verified=1 functions only")
    wave_group.add_argument("--import-limit-s", type=int, default=7200, help="per-import timeout")
    wave_group.add_argument("--symtab-variants", action="store_true",
                            help="also run each stripped ELF image as <id>-symtab (symbols kept, DWARF removed): "
                                 "a supplement table, not part of the headline")
    wave_group.add_argument("--sign-include-mismatch", action="store_true",
                            help="treat version_match=false games as headline games (platform tables, sign tests) "
                                 "instead of the supplement table")
    stock_group = parser.add_argument_group("stock Ghidra comparison")
    stock_group.add_argument("--stock", action="store_true",
                             help="also run stock Ghidra headless on each image (main module) and report it "
                                  "beside default / baseline-off")
    stock_group.add_argument("--ghidra", type=Path,
                             default=Path(os.environ.get("ROMWRIGHT_GHIDRA") or Path.home() / "ghidra_12.1.3_PUBLIC"))
    stock_group.add_argument("--stock-work", type=Path, default=Path.home() / "romwright-research-stock",
                             help="scratch for Ghidra projects (not under a dot directory)")
    stock_group.add_argument("--stock-timeout", type=int, default=None,
                             help="seconds per stock run; over it the game is a stock DNF (default 3600 with "
                                  "--corpus-wave, 14400 otherwise)")
    stock_group.add_argument("--stock-retry-failed", action="store_true",
                             help="re-run stock on games whose cached stock result is a DNF or crash (a DNF is "
                                  "re-run anyway when --stock-timeout exceeds the limit it was recorded at)")
    parser.add_argument("--no-truth", action="append", default=[], metavar="NAME=PATH",
                        help="an image with no truth (a retail game), run for success and time only: import, "
                             "export-c of up to 20 functions, and with --stock stock Ghidra's time and entry set; "
                             "reported as `pc-NAME` in the \"Images without truth\" table")
    stock_group.add_argument("--stock-known-failure", action="append", default=[], metavar="ID=SECONDS:EVIDENCE",
                             help="record a stock DNF observed by an earlier run at SECONDS, with EVIDENCE (where "
                                  "it is logged), for a game with no cached stock result instead of running stock")
    args = parser.parse_args()
    if args.stock_timeout is None:
        args.stock_timeout = 3600 if args.corpus_wave else 14400
    known: dict[str, tuple[int, str]] = {}
    for item in args.stock_known_failure:
        image_id, _, rest = item.partition("=")
        seconds, _, evidence = rest.partition(":")
        if not image_id or not seconds.isdigit() or not evidence:
            parser.error(f"--stock-known-failure needs ID=SECONDS:EVIDENCE, got {item!r}")
        known[image_id] = (int(seconds), evidence)
    args.stock_known_failure = known

    n = args.n if args.n is not None else (500 if args.corpus_wave else 200)
    seeds_text = args.seeds or (str(args.seed) if args.seed is not None else ("1,2" if args.corpus_wave else "20261006"))
    seeds = [int(item) for item in seeds_text.split(",") if item]
    if not seeds or len(set(seeds)) != len(seeds):
        parser.error("--seeds needs distinct integers")
    if args.out is None:
        args.out = ROOT / "benchmarks" / "reports" / (
            f"console_research_wave_{datetime.now().strftime('%Y%m%d')}.json" if args.corpus_wave
            else "console_research.json")

    tools = Tools(args.target_dir)
    cache = args.cache
    wanted_images = {item for item in args.images.split(",") if item}
    skipped_dirs: list[dict] = []
    if args.corpus_wave:
        specs, skipped_dirs = wave.discover(args.corpus, wanted_images, args.min_age_s, symtab_variants=args.symtab_variants)
        for spec in specs:
            spec["limit_s"] = args.import_limit_s
        for row in skipped_dirs:
            log(f"wave: skipped {row['dir']}: {row['reason']}")
    else:
        specs = IMAGES
    unknown = wanted_images - {spec["id"] for spec in specs} if not args.corpus_wave else set()
    default_configs = "default,baseline-off" if args.corpus_wave else ""
    wanted_configs = [item for item in (args.configs or default_configs).split(",") if item] or [c.name for c in CONFIGS]
    unknown |= set(wanted_configs) - set(BY_NAME)
    if unknown:
        parser.error(f"unknown image/config: {sorted(unknown)}")
    # The sample comes from the default import; comparisons need their references.
    needed = set(wanted_configs) | {"default"}
    needed |= {BY_NAME[name].reference for name in wanted_configs if BY_NAME[name].reference}
    configs = [config for config in CONFIGS if config.name in needed]
    log(f"tools {tools.fingerprint}; configs {[c.name for c in configs]}; n={n} seeds={seeds}")

    report = {"schema": "console-research/2", "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
              "tools": tools.fingerprint, "cli": str(tools.cli), "n": n,
              "seed": seeds[0] if len(seeds) == 1 else seeds, "seeds": seeds,
              "mode": "corpus-wave" if args.corpus_wave else "builtin",
              "thresholds": {"rate": RATE_THRESHOLD, "count_relative": COUNT_THRESHOLD},
              "configs": {c.name: dataclasses.asdict(c) for c in configs}, "images": {}}
    if args.corpus_wave:
        report["wave_skipped"] = skipped_dirs
        report["sample_verified_only"] = args.sample_verified

    def write_report() -> None:
        text = markdown(report)
        if args.corpus_wave:
            report["rollup"] = wave.rollup(report, args.sign_include_mismatch)
            text = wave.markdown(report, report["rollup"]) + "\n" + text
        if report.get("no_truth"):
            text += no_truth_markdown(list(report["no_truth"].values()))
        write_json(args.out, report)
        args.out.with_suffix(".md").write_text(text)

    m22_box: dict = {}
    for spec in specs:
        base_id = spec["id"].removesuffix("-symtab") if (spec.get("wave") or {}).get("variant") else spec["id"]
        if wanted_images and base_id not in wanted_images and spec["id"] not in wanted_images:
            continue
        image = report["images"].setdefault(spec["id"], {"configs": {}})
        source = args.corpus / spec["image"]
        if not source.is_file() or (spec.get("truth") and not (args.corpus / spec["truth"][1]).is_file()):
            image.update(status="skipped", reason="image or truth absent")
            log(f"{spec['id']}: skipped (absent)")
            continue
        try:
            process_image(args, tools, cache, configs, spec, image, seeds, n, m22_box)
        except (RuntimeError, OSError, subprocess.SubprocessError, ValueError, KeyError) as error:
            image.update(status="error", reason=str(error)[-1000:])
            log(f"{spec['id']}: ERROR {str(error)[-300:]}")
        write_report()
    for item in args.no_truth:
        name, _, path = item.partition("=")
        if not name or not path:
            parser.error(f"--no-truth needs NAME=PATH, got {item!r}")
        try:
            report.setdefault("no_truth", {})[f"pc-{name}"] = run_no_truth(args, tools, cache, name, Path(path).expanduser())
        except (RuntimeError, OSError, subprocess.SubprocessError, ValueError, KeyError) as error:
            report.setdefault("no_truth", {})[f"pc-{name}"] = {
                "id": f"pc-{name}", "image": path, "sha256": "", "size": 0, "error": str(error)[-600:],
                "import": {"seconds": "", "functions": "", "compiler": None},
                "decompile": {"success": 0, "sampled": 0}}
            log(f"pc-{name}: ERROR {str(error)[-300:]}")
        write_report()
    write_report()
    log(f"report {args.out} / {args.out.with_suffix('.md')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
