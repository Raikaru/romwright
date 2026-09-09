#!/usr/bin/env python3
"""m4-003: token identity against the oracle, for every language it can reach.

`tests/differential.sh` proves the native decompiler emits the same token
stream as the JVM oracle -- for one x86-64 fixture. The support matrix
therefore still reads "decompile parity pending" for AArch64 and "not
parity-gated" for the other languages whose spec bundles `native/specs` ships.

This gate closes that by measurement rather than by prose. For every language
bundle it enumerates from `native/specs`, it either measures parity or names
a blocker it verifies:

  * **measured**: the language has an ELF row in the committed corpus lock, or
    a committed fixture builds an image both stores load, so the same image is
    imported natively and through the bridge, every function both stores hold
    is decompiled both ways, and the token streams must be identical;
  * **attributed**: where the two stores disagree about a function's name or
    signature, the decompilations may differ -- that is the point of recovering
    facts -- but the gate must be able to name the differing fact, and any
    difference it cannot attribute fails;
  * **blocked**: the language has no corpus row and no fixture that reaches it,
    which II.1 reserves adding. The gate verifies the absence rather than
    trusting the note.

Usage:
    python3 tests/m4-003_language_parity.py --corpus-dir DIR [--report OUT.json]
"""
from __future__ import annotations

import argparse
import concurrent.futures
import difflib
import hashlib
import importlib.util
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "benchmarks"))
import gate_cache  # noqa: E402
SPECS = ROOT / "native/specs"
LOCK = ROOT / "tests/corpus.lock.json"
GHIDRA = Path(os.environ.get("VENTRIS_GHIDRA", str(Path.home() / "ghidra_12.1.3_PUBLIC")))
CLI = ROOT / "target/release/lre-cli"
# Pinned once, compared against afterwards, like the memory envelopes.
BASELINE = ROOT / "benchmarks/reports/parity-baseline.json"
# The variants to compare: every ELF variant the corpus lock already holds
# for a measured language, and every function in each of them. `plain_pie`
# is excluded because its load bias makes the two stores name different
# addresses for the same function, which is a comparison of loaders rather
# than of decompilers.
VARIANTS = ("plain_o0", "plain_o2", "cpp_o2", "many_o2")
# A language reached only by a container image is measured from a committed
# fixture: the builder writes the image from `tests/fixtures-src`, both stores
# import that image, and the row is compared like any corpus row. Ghidra's GBA
# loader identifies a cartridge by the first eight logo bytes and the 0x96 at
# 0xB2 (`GBALoader.findSupportedLoadSpecs`), which the fixture header carries.
CONTAINERS = {
    "ARM:LE:32:v4t": {"module": "m5_001", "path": ROOT / "tests/m5-001_gba.py",
                      "variant": "cartridge"},
}
# A language both stores can load, whose token parity is not reached yet. The
# row is still measured on every run, against floors the last run proved: the
# imports must keep working, the shared function set must not shrink, and the
# identical count can only go up. That makes an open gap a ratchet rather than
# a note. The image is a retail cartridge that cannot be committed, so it is
# pinned by hash and its absence is reported rather than passed over silently.
UNREACHED = {
    "ARM:LE:32:v5t": {
        "image": Path.home() / "ventris-corpus/extracted/nds-pokeheartgold/pokeheartgold.us.nds",
        "sha256": "65f02a56842b75aa92d775d56d657a56fe3fa993550b04dc20704ab82d760105",
        "variant": "cartridge",
        "native_program": "pokeheartgold.us.nds.arm9",
        "sample": 512,
        "shared_floor": 7168,
        "identical_floor": 394,
        "reason": "both stores load the cartridge -- the install now carries an "
                  "NDS loader and ours unpacks the ARM9 module as crt0 does -- "
                  "and the ARM9 program shares 7168 functions with the oracle, "
                  "394 of the first 512 token-identical now that the decompile "
                  "worker replays the instruction set discovery settled at "
                  "each point and discovery walks the switch tables the "
                  "decompiler recovers; the rest differ where the oracle's "
                  "callee prototypes and stack frames name what ours does not "
                  "yet",
    },
    "MIPS:BE:64:64-32addr": {
        "image": Path.home() / "ventris-corpus/perfect_dark_ntsc_final.z64",
        "sha256": "4e51142acac686d96861cecc58cf7cb7c3b06b21733b7f8ed609a709dc039a21",
        "variant": "cartridge",
        "shared_floor": 116,
        "identical_floor": 58,
        "reason": "both stores load the ROM -- the install now carries an N64 "
                  "loader and ours maps the boot segment at the header's boot "
                  "address -- and 58 of the 116 shared functions are "
                  "token-identical now that the raw-SLEIGH worker truncates "
                  "the ram space as the language declares, answers LAB_ code "
                  "labels, and sign-extended lui addresses wrap into the "
                  "space; the rest differ where the oracle's callee "
                  "prototypes, global-overlap warnings and thunk names differ "
                  "from ours",
    },
}
# A language neither the corpus, a fixture, nor an image reaches cannot be
# measured; each needs a reason, and every reason names what was tried.
BLOCKED = {
    "PowerPC:BE:32:e500": {"reason": "no image selects e500: the GameCube DOLs "
                                     "the corpus holds load as Gekko_Broadway "
                                     "through the oracle and BE32 default "
                                     "natively, and the corpus PowerPC ELF row "
                                     "is BE32 default too"},
}
# Ghidra's dynamic label prefixes, from the pinned tree
# (`SymbolUtilities.DYNAMIC_PREFIX_ARRAY`, SymbolUtilities.java:84-86) plus the
# built-in data-type prefixes it appends (`getDynamicDataTypePrefixes`, :105).
DYNAMIC = re.compile(r"\b_?(?:UNK|DAT|LAB|SUB|EXT|OFF|PTR|s)_[0-9A-Za-z_]+")
# The C++ decompiler's own fallback when the program holds no symbol at an
# address: a type letter, the space name and the offset, e.g.
# `cRam00000000002038f8` (`Scope::buildDefaultName`, decompiler database.cc).
FALLBACK = re.compile(r"\b[a-z]{1,4}Ram([0-9a-f]{8,16})\b")
WARNING = re.compile(r"/\* WARNING:.*?\*/", re.S)
# The comments Ghidra's exception analyzer writes into the listing from
# `.gcc_except_table`, which its decompiler then prints. Nothing else in a
# comment is matched: only try/catch bracketing.
EH_COMMENT = re.compile(r"/\*\s*(?:try \{|\} // end try|catch\(|\} // end catch)"
                        r".*?\*/", re.S)
# An Itanium-mangled name, as the image spells it (`_ZTIi`).
MANGLED = re.compile(r"^_Z[A-Za-z0-9_]+$")
# A name the decompiler derives from a register: stock's language variant may
# spell the same register `_r2` where ours spells it `r2`.
REGISTER_DERIVED = re.compile(r"\b((?:unaff|in|extraout)_)_+")
# A C cast to a pointer of a core type, e.g. `(code *)`.
CAST = re.compile(r"\(\s*(?:code|undefined[0-9]?|byte|char|u?int|u?long|u?short)"
                  r"\s*\*+\s*\)")
# What each class of fact licenses in the token stream, and nothing else.
# A name the decompiler derives from storage rather than from a symbol: these
# change when a prototype, a type or a convention changes, and never otherwise
# (`Funcdata::nameRecommendation`, `ActionNameVars`).
DERIVED = re.compile(
    r"^(?:param_\d+|[a-z]{1,3}Var\d+|[a-z]{1,3}Stack_[0-9a-fx]+|local_[0-9a-fx]+"
    r"|in_stack_[0-9a-fx]+|unaff_\w+|extraout_\w+|stack0x[0-9a-f]+"
    r"|in_[A-Z]\w*|[a-z]{1,4}Ram[0-9a-f]+|uRam[0-9a-f]+)$")
# The core type names a prototype or a type fact can supply.
TYPE_NAME = re.compile(
    r"^(?:void|undefined[0-9]?|byte|u?char|u?short|u?int|u?long|u?longlong"
    r"|float[0-9]?|double|bool|code|size_t|ssize_t|wchar[0-9]?|undefined)$")
# The punctuation a differing argument list or a differing structure moves.
SHAPE = set("(),*&;{}")
# Keywords whose presence follows from a flow disagreement, not from text.
CONTROL = {"do", "while", "if", "else", "goto", "switch", "case", "break",
           "return", "default", "continue"}
TOKEN = re.compile(
    r"""/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[A-Za-z_]\w*"""
    r"""|0[xX][0-9a-fA-F]+|\d+|[^\s]""", re.S)


def tokens(text: str) -> list[str]:
    """The C text as tokens, so layout differences are not divergences."""
    stream = []
    for token in TOKEN.findall(text):
        stream.append(re.sub(r"\s+", " ", token).strip()
                      if token.startswith(("/*", "//")) else token)
    return stream


def environment() -> dict[str, str]:
    """A plain install: per-language resolution, no spec or language overrides."""
    values = dict(os.environ)
    for name in ("VENTRIS_SLA", "VENTRIS_LANGUAGE", "VENTRIS_LANGUAGE_DIR",
                 "VENTRIS_SPECS", "VENTRIS_REGISTER_PARAMS",
                 "VENTRIS_PROMOTE_TAILCALLS"):
        values.pop(name, None)
    values["VENTRIS_SERVICE_JAR"] = str(ROOT / "service/build/ventris-service.jar")
    return values


def cli(*arguments: str, timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run([str(CLI), *arguments], cwd=ROOT, capture_output=True,
                          text=True, timeout=timeout, env=environment())


def bundled_languages() -> list[str]:
    """Languages `native/specs` ships a bundle for, plus the root x86-64 one."""
    languages = ["x86:LE:64:default"]
    for entry in sorted(SPECS.iterdir()):
        if entry.is_dir():
            languages.append(entry.name.replace("-", ":", 1).replace(
                "-", ":", 1).replace("-", ":", 1))
    return languages


def facts(store: Path, program: str) -> dict[int, dict]:
    """Per-function name and signature, as one store holds them."""
    connection = sqlite3.connect(store)
    try:
        identifier = connection.execute(
            "SELECT id FROM programs WHERE name = ?", (program,)).fetchone()
        assert identifier, f"{program} is missing from {store}"
        rows = {}
        for entry, name, signature in connection.execute(
                "SELECT entry, name, signature FROM functions WHERE program_id = ?",
                (identifier[0],)):
            offset = ram_offset(entry)
            if offset is not None:
                rows[offset] = {"name": name, "signature": signature}
        for function, return_type in connection.execute(
                "SELECT function, return_type FROM prototypes WHERE program_id = ?",
                (identifier[0],)):
            offset = ram_offset(function)
            if offset in rows:
                rows[offset]["return_type"] = return_type
        return rows
    finally:
        connection.close()



def ram_offset(cell: str) -> int | None:
    """The RAM offset a stored address cell names, or None for other spaces.

    The store keeps RAM addresses as bare hex and everything else as a typed
    JSON cell, so a section-relative address must be skipped rather than
    parsed.
    """
    try:
        return int(cell, 16)
    except ValueError:
        pass
    try:
        decoded = json.loads(cell)
    except json.JSONDecodeError:
        return None
    return decoded.get("offset") if decoded.get("space") == "Ram" else None


def store_context(store: Path, program: str) -> dict:
    """The facts the native store holds that a decompilation can show."""
    connection = sqlite3.connect(store)
    try:
        (identifier,) = connection.execute(
            "SELECT id FROM programs WHERE name = ?", (program,)).fetchone()
        symbols = {offset for (address,) in connection.execute(
            "SELECT address FROM symbols WHERE program_id = ?", (identifier,))
            if (offset := ram_offset(address)) is not None}
        prototypes = {offset for (address,) in connection.execute(
            "SELECT function FROM prototypes WHERE program_id = ?", (identifier,))
            if (offset := ram_offset(address)) is not None}
        externals = {offset: name for address, name in connection.execute(
            "SELECT address, name FROM symbols WHERE program_id = ? AND external = 1",
            (identifier,)) if (offset := ram_offset(address)) is not None}
        strings = {offset: value for address, value in connection.execute(
            "SELECT address, value FROM strings WHERE program_id = ?", (identifier,))
            if (offset := ram_offset(address)) is not None}
        # Addresses the store holds a type for. An import slot and an
        # ABI-reserved GOT word are both typed facts, and either explains why
        # our text needs no cast where the oracle's does.
        definitions = {offset for (address,) in connection.execute(
            "SELECT address FROM data_definitions WHERE program_id = ?", (identifier,))
            if (offset := ram_offset(address)) is not None}
        names = {offset: name for address, name in connection.execute(
            "SELECT address, name FROM symbols WHERE program_id = ?", (identifier,))
            if (offset := ram_offset(address)) is not None}
        # Function name -> entry: which function a called name resolves to, so
        # a missing prototype is looked for where a prototype can live.
        entries = {name: offset for address, name in connection.execute(
            "SELECT entry, name FROM functions WHERE program_id = ?", (identifier,))
            if (offset := ram_offset(address)) is not None}
        # Every name a store holds at an address, not just the last row read:
        # stock keeps the mangled import name *and* the demangled one its
        # analyzer derived, and which of the two a query returns last is not a
        # fact about either image.
        aliases: dict[int, list[str]] = {}
        for address, name in connection.execute(
                "SELECT address, name FROM symbols WHERE program_id = ?", (identifier,)):
            if (offset := ram_offset(address)) is not None:
                aliases.setdefault(offset, []).append(name)
        (language,) = connection.execute(
            "SELECT language FROM programs WHERE id = ?", (identifier,)).fetchone()
        # The stack frame each store declares. Ghidra's analysis recovers one
        # and names its slots `local_<offset>`; a store without it leaves the
        # decompiler to name the same slots itself.
        frames: dict[int, list[str]] = {}
        for address, name in connection.execute(
                "SELECT function, name FROM stack_variables WHERE program_id = ?",
                (identifier,)):
            if (offset := ram_offset(address)) is not None:
                frames.setdefault(offset, []).append(name)
        return {"symbols": symbols, "prototypes": prototypes,
                "externals": externals, "strings": strings,
                "definitions": definitions, "names": names, "functions": entries,
                "aliases": {offset: sorted(set(held)) for offset, held in aliases.items()},
                "frames": {offset: sorted(set(held)) for offset, held in frames.items()},
                "language": language}
    finally:
        connection.close()


def strip_annotations(text: str, wanted: list[str]) -> str:
    """Removes only the exception comments a class actually claimed."""
    for match in EH_COMMENT.findall(text):
        if re.sub(r"\s+", " ", match) in wanted:
            text = text.replace(match, "")
    return text


def demangled_pairs(native_text: str, oracle_text: str, store: dict,
                    oracle_store: dict) -> list[dict]:
    """An object the image names in its mangled form, at an address stock's
    demangler names again.

    Both stores hold `_ZTIi` at the slot the COPY relocation names; stock's
    demangler adds a qualified symbol (`int::typeinfo`) at the same address
    and prints that in place of the address of the slot. Ours keeps the name
    the image declared, which is what the relocation carries.
    """
    pairs = []
    for address, ours in store["names"].items():
        if not MANGLED.match(ours) or ours not in native_text:
            continue
        for theirs in oracle_store["aliases"].get(address, []):
            if theirs == ours:
                continue
            if not re.search(rf"&?\b(?:\w+::)*{re.escape(theirs)}\b", oracle_text):
                continue
            pairs.append({
                "address": f"{address:08x}", "oracle": theirs, "native": ours,
                "substituted": f"&{ours}" if f"&{ours}" in native_text else ours})
    return pairs


def apply_demangled(oracle_text: str, pairs: list[dict]) -> str:
    """Rewrite stock's demangled, qualified spelling into ours."""
    for pair in pairs:
        oracle_text = re.sub(rf"&?\b(?:\w+::)*{re.escape(pair['oracle'])}\b",
                             lambda _, pair=pair: pair["substituted"], oracle_text)
    return oracle_text


def classify(native_text: str, oracle_text: str, native_row: dict, oracle_row: dict,
             entry: int, store: dict, oracle_store: dict) -> dict:
    """Name the fact each divergence comes from, with the evidence for it."""
    classes: dict[str, object] = {}
    # A signature is content, not spelling: `int f(char *name)` and
    # `int f(char *)` say the same thing about the return type and the arity,
    # and neither decompiler's parameter naming is a fact about the image.
    differing = {key: [oracle_row.get(key), native_row.get(key)]
                 for key in ("name", "return_type")
                 if oracle_row.get(key) != native_row.get(key)}
    counts = (arity(oracle_row.get("signature")), arity(native_row.get("signature")))
    if None not in counts and counts[0] != counts[1]:
        differing["parameters"] = list(counts)

    # A name is a choice, not a gap: the loader-derived names differ on
    # purpose (`_plt` says which section proved the start; Ghidra's
    # `FUN_00201710` says nothing). Substituting one for the other decides
    # whether the name is the *only* difference, so a deliberate convention is
    # never counted as a missing fact.
    native_name, oracle_name = native_row.get("name"), oracle_row.get("name")
    named: dict[str, object] = {}
    substituted = oracle_text
    if native_name and oracle_name and native_name != oracle_name:
        substituted = re.sub(rf"\b{re.escape(oracle_name)}\b", native_name, oracle_text)
        # Only a name we chose is a convention. If ours is the decompiler's
        # own default and the oracle has a real name, the name is missing,
        # not different.
        default = re.match(r"(?:FUN|SUB|UNK)_[0-9a-f]+$", native_name)
        named = {"missing-name" if default else "name-convention":
                 [oracle_name, native_name]}
        if tokens(substituted) == tokens(native_text):
            return named

    # A name C cannot spell is rendered as a C identifier (m4-011) while the
    # store keeps what the image declared; stock prints the raw name into its
    # own C, including inside its warnings. Comparing text means applying the
    # same rendering to stock's names first.
    rendered = []
    for held in sorted(set(oracle_store["functions"])
                       | set(oracle_store["names"].values()), key=len, reverse=True):
        identifier = c_identifier(held)
        if identifier == held or held not in substituted:
            continue
        substituted = substituted.replace(held, identifier)
        rendered.append([held, identifier])
    if rendered:
        named["name-rendering"] = rendered
        if tokens(substituted) == tokens(native_text):
            return named

    # A mangled name both stores hold, which stock's demangler names again.
    demangled = demangled_pairs(native_text, substituted, store, oracle_store)
    if demangled:
        substituted = apply_demangled(substituted, demangled)
        named["mangled-name"] = demangled
        if tokens(substituted) == tokens(native_text):
            return named

    # Comments the exception analyzer writes from `.gcc_except_table`. Both
    # sides read that table now (m4-024), so the class has a direction: only
    # an annotation stock prints and we do not is a difference, and a matching
    # pair cancels in the token streams without a class.
    ours = {re.sub(r"\s+", " ", item) for item in EH_COMMENT.findall(native_text)}
    annotations = sorted({re.sub(r"\s+", " ", item) for item in EH_COMMENT.findall(substituted)}
                         - ours)
    if annotations:
        substituted = strip_annotations(substituted, annotations)
        named["exception-annotation"] = annotations
        if tokens(substituted) == tokens(native_text):
            return named

    # The two sides disassembled with different language variants: stock's
    # opinion files pick `PowerPC:BE:32:e500` where our loader picks
    # `PowerPC:BE:32:default`, and the e500 variant names the four-byte view
    # of `r2` as `_r2`. Only the register spelling is rewritten, and only
    # where the recorded languages actually differ.
    if store.get("language") != oracle_store.get("language"):
        respelled = REGISTER_DERIVED.sub(lambda match: match.group(1), substituted)
        names = sorted({item for item in re.findall(r"\b(?:unaff|in|extraout)__\w+",
                                                   substituted)})
        if names and respelled != substituted:
            substituted = respelled
            named["language-variant"] = {
                "oracle": oracle_store.get("language"),
                "native": store.get("language"), "registers": names}
            if tokens(substituted) == tokens(native_text):
                return named

    # A cast the two sides place differently because they type the same slot
    # differently: the store holds the import slot's own type, so our text
    # casts at the comparison and not at the call, while the oracle types the
    # slot `undefined` and casts at the call. Dropping every core-type pointer
    # cast from *both* sides decides it, and the claim is only made when the
    # slot is one the store holds as an import. The two normalisations
    # compose: naming one fact never excuses the other.
    oracle_casts = {cast.strip() for cast in re.findall(CAST, substituted)}
    native_casts = {cast.strip() for cast in re.findall(CAST, native_text)}
    typed = store["externals"].keys() | store["definitions"]
    typed_slot = any(int(match.group(1), 16) in typed
                     for match in re.finditer(r"\b(?:PTR|DAT)_\w*?_?([0-9a-f]{6,16})\b",
                                              native_text))
    if (oracle_casts != native_casts and typed_slot
            and tokens(re.sub(CAST, "", substituted))
            == tokens(re.sub(CAST, "", native_text))):
        return {**named, "type-stronger": sorted(oracle_casts ^ native_casts)}

    # A name we substituted or rendered is a difference in its own right, and
    # the rest of the classification compares the text after those rewrites --
    # otherwise the same warning is counted once in each direction.
    classes.update(named)
    oracle_text = substituted
    if differing:
        classes["function-facts"] = differing

    # The cast difference can be one contribution among several -- a row may
    # differ by a typed slot *and* by a warning stock emits. The claim is the
    # same one the early return makes, and needs the same evidence.
    if oracle_casts != native_casts and typed_slot:
        classes["type-stronger"] = sorted(oracle_casts ^ native_casts)

    # A memory location the native store holds no symbol for: the decompiler
    # falls back to its own name while the oracle prints a dynamic label.
    unnamed = sorted({f"{int(match, 16):08x}" for match in FALLBACK.findall(native_text)
                      if int(match, 16) not in store["symbols"]})
    if unnamed and DYNAMIC.search(oracle_text):
        classes["missing-data-symbol"] = unnamed

    # A string the store already holds, printed as a bare address because the
    # decompiler was never told about it while the oracle renders the literal.
    unrendered = []
    for address, value in store["strings"].items():
        if f"{address:#x}" in native_text and json.dumps(value)[1:-1] in oracle_text:
            unrendered.append({"address": f"{address:08x}", "value": value})
    if unrendered:
        classes["string-not-rendered"] = unrendered

    # An import the oracle *calls* by name, whose signature stock holds and we
    # do not. Three narrowings, each measured: a name in the decompiled
    # function's own signature is not a call (m4-016); the signature that
    # would answer it belongs to the stub the name resolves to, never to the
    # import slot; and a name **nobody** declares -- `__gmon_start__` is in no
    # pinned archive and stock records no signature for it either -- is not a
    # gap of ours (m4-019). A gap is a difference, and a difference has a
    # direction.
    without = []
    body = oracle_text[oracle_text.index("{"):] if "{" in oracle_text else ""
    for name in set(store["externals"].values()):
        if not re.search(rf"\b{re.escape(name)}\s*\(", body):
            continue
        if held_signature(store, name):
            continue
        if not held_signature(oracle_store, name):
            continue
        without.append(name)
    if entry in store["externals"] and entry not in store["prototypes"] \
            and entry in oracle_store["prototypes"]:
        without.append(native_row.get("name"))
    if without:
        classes["missing-external-prototype"] = sorted(set(filter(None, without)))

    # Both sides name the location, and disagree about what is there: the
    # store holds a reference, the oracle holds defined data with a type.
    typed = []
    for match in DYNAMIC.finditer(oracle_text):
        address = re.search(r"([0-9a-f]{6,16})$", match.group(0))
        if address is None:
            continue
        native_names = {item.group(0) for item in DYNAMIC.finditer(native_text)
                        if item.group(0).endswith(address.group(1))}
        if native_names and match.group(0) not in native_names:
            typed.append({"oracle": match.group(0), "native": sorted(native_names)})
    if typed:
        classes["data-type-unknown"] = typed

    # A data label both stores name, and name differently on purpose.
    labels = label_substitutions(native_text, oracle_text, store, oracle_store)
    if labels:
        classes["data-name-convention"] = labels

    # A stack frame the oracle store declares and ours does not. Ghidra's
    # analysis names each slot it recovers (`SymbolUtilities.getDefaultLocalName`
    # spells it `local_<offset>`) and hands those names to its decompiler; a
    # store with no frame leaves the same slots to the decompiler, which names
    # them from the storage instead (`ScopeLocal::buildVariableName`, varmap.cc,
    # spells them `uStack_<offset>`). The claim is evidence-backed and has a
    # direction: the oracle store must hold slots for this function, ours must
    # hold none, and the oracle text must actually print those names.
    # Only the analyzer's own default names: a stack *parameter* the frame
    # also lists (`__format`) is named by a prototype, which is another class's
    # fact, and a name both texts print is not a difference at all.
    declared = [name for name in oracle_store.get("frames", {}).get(entry, [])
                if name.startswith("local_")]
    printed = [name for name in declared
               if re.search(rf"\b{re.escape(name)}\b", oracle_text)
               and not re.search(rf"\b{re.escape(name)}\b", native_text)]
    if printed and not store.get("frames", {}).get(entry):
        classes["missing-stack-frame"] = printed

    # Flow the two sides disagree about, on the same bytes -- and which side
    # says so. A warning we emit and stock does not is a gap of ours; the
    # reverse is stock warning about its own recovery (its locked-storage
    # prototype, say), which is not ours to close.
    native_warnings = {re.sub(r"\s+", " ", item) for item in WARNING.findall(native_text)}
    oracle_warnings = {re.sub(r"\s+", " ", item) for item in WARNING.findall(oracle_text)}
    if native_warnings - oracle_warnings:
        classes["flow"] = sorted(native_warnings - oracle_warnings)[:3]
    if oracle_warnings - native_warnings:
        classes["oracle-warning"] = sorted(oracle_warnings - native_warnings)[:3]
    return classes


def label_substitutions(native_text: str, oracle_text: str, store: dict,
                        oracle_store: dict) -> list[dict]:
    """Addresses both stores name, deliberately and differently.

    Ours names the slot after the import it holds (the relocation proves it);
    Ghidra names it after the dynamic tag that reserves it. Our text prints
    the address inside its label, so the pair can be matched by address
    rather than by guessing.
    """
    pairs = []
    for address, oracle_name in oracle_store["names"].items():
        if store["names"].get(address) == oracle_name:
            continue
        if not re.search(rf"\b{re.escape(oracle_name)}\b", oracle_text):
            continue
        ours = [item for item in DYNAMIC.findall(native_text)
                if item.endswith(f"{address:08x}")]
        if len(ours) == 1 and ours[0] != oracle_name:
            pairs.append({"address": f"{address:08x}", "oracle": oracle_name,
                          "native": ours[0]})
    return pairs


def c_identifier(name: str) -> str:
    """The name as C can spell it: the rendering `lre_worker::c_identifier`
    applies, so a label like `__i686.get_pc_thunk.bx` is comparable."""
    return re.sub(r"[^A-Za-z0-9_]", "_", name)


def held_signature(store: dict, name: str) -> bool:
    """Whether a store holds a signature for the function that name resolves
    to, or -- for a name it knows only as an import slot -- for the slot."""
    stub = store["functions"].get(name)
    if stub is not None:
        return stub in store["prototypes"]
    return any(address in store["prototypes"]
               for address, held in store["externals"].items() if held == name)


def arity(signature: str | None) -> int | None:
    """How many parameters a signature declares, or None when there is none to
    read. `(void)` declares zero; `...` is one, spelled the same either way."""
    if not signature or "(" not in signature or ")" not in signature:
        return None
    inner = signature[signature.index("(") + 1:signature.rindex(")")].strip()
    if inner in ("", "void"):
        return 0
    return len([part for part in inner.split(",") if part.strip()])


def numeric(token: str) -> str:
    """An integer literal as its value, so notation is never a divergence."""
    try:
        return str(int(token, 0))
    except ValueError:
        return token


def licensed(classes: dict, native_text: str, oracle_text: str,
             store: dict, native_row: dict, oracle_row: dict
             ) -> tuple[set[str], set[re.Pattern]]:
    """The tokens each named class accounts for -- literal, then by shape."""
    words: set[str] = set()
    shapes: set[re.Pattern] = set()
    for name, evidence in classes.items():
        if name == "function-facts":
            # A signature or a return type the two stores disagree about: the
            # values themselves, the types they name, and the names the
            # decompiler derives from them.
            for pair in evidence.values():
                for value in pair:
                    words.update(tokens(value or ""))
            shapes.update({DERIVED, TYPE_NAME})
        elif name == "missing-external-prototype":
            # A declared prototype changes the argument list: its types, its
            # length, and the locals the decompiler derives without it.
            words.update(evidence)
            words.update(SHAPE)
            shapes.update({DERIVED, TYPE_NAME})
            # Where the prototype missing is *this* function's own, the
            # declaration is what stock prints: the parameter names it
            # declares, and the assignment a non-void return introduces. A
            # prototype missing for a function it merely calls licenses
            # neither (m4-019 narrowed the class in that direction).
            if native_row.get("name") in set(evidence):
                words.update(tokens(oracle_row.get("signature") or ""))
                words.add("=")
        elif name == "type-stronger":
            # The casts either side carries: where the store holds the slot's
            # type, the cast moves rather than disappearing, so the tokens of
            # a shared cast move with it.
            for cast in set(evidence) | set(re.findall(CAST, native_text)) \
                    | set(re.findall(CAST, oracle_text)):
                words.update(tokens(cast))
        elif name == "missing-data-symbol":
            words.update(DYNAMIC.findall(oracle_text))
            words.update(item.group(0) for item in
                         re.finditer(r"\b[a-z]{1,4}Ram[0-9a-f]{8,16}\b", native_text))
            words.update(f"0x{int(address, 16):x}" for address in evidence)
        elif name == "data-type-unknown":
            for item in evidence:
                words.add(item["oracle"])
                words.update(item["native"])
        elif name == "string-not-rendered":
            for item in evidence:
                words.add(f'"{item["value"]}"')
                words.update(tokens(json.dumps(item["value"])))
                words.add(f"0x{int(item['address'], 16):x}")
                words.update(DYNAMIC.findall(oracle_text))
        elif name == "mangled-name":
            for pair in evidence:
                words.update({pair["oracle"], pair["native"], pair["substituted"]})
            words.update(SHAPE)
        elif name == "exception-annotation":
            words.update(evidence)
            words.update(tokens(" ".join(evidence)))
        elif name == "language-variant":
            # The register the variant spells differently, and the name the
            # decompiler derives from it -- nothing else.
            words.update(evidence["registers"])
            shapes.update({DERIVED})
        elif name == "missing-stack-frame":
            # The names the oracle's declared frame supplies, and the names
            # our decompiler derives for the same slots because no frame was
            # declared. Only names: a frame does not license code or types.
            words.update(evidence)
            words.update(item.group(0) for item in
                         re.finditer(r"\b[a-z]{1,3}Stack[XY]?_[0-9a-fx]+\b", native_text))
        elif name == "oracle-warning":
            # Stock warned about its own recovery: the tokens of that comment,
            # and nothing else. A warning does not license code.
            words.update(evidence)
            words.update(tokens(" ".join(evidence)))
        elif name == "flow":
            # Where the two sides disagree about flow they disagree about the
            # structure that follows from it: its warnings, its keywords, its
            # labels and the punctuation that carries them.
            words.update(re.sub(r"\s+", " ", item)
                         for item in WARNING.findall(native_text) + WARNING.findall(oracle_text))
            words.update(CONTROL)
            words.update(SHAPE)
            words.update(DYNAMIC.findall(native_text))
            words.update(DYNAMIC.findall(oracle_text))
            shapes.update({DERIVED})
    return words, shapes


def residue(native_text: str, oracle_text: str, native_row: dict, oracle_row: dict,
            classes: dict, store: dict) -> list[str]:
    """Every differing token no named class accounts for.

    A class that names one fact does not excuse the rest of a function: the
    gate subtracts what the class licenses and fails on what is left, which
    is how `processEntry` -- a convention no fact recorded -- stayed hidden
    behind a name that did differ.
    """
    native_name, oracle_name = native_row.get("name"), oracle_row.get("name")
    if native_name and oracle_name and native_name != oracle_name:
        oracle_text = re.sub(rf"\b{re.escape(oracle_name)}\b", native_name, oracle_text)
    for pair in classes.get("data-name-convention", []):
        oracle_text = re.sub(rf"\b{re.escape(pair['oracle'])}\b", pair["native"],
                             oracle_text)
    for held, identifier in classes.get("name-rendering", []):
        oracle_text = oracle_text.replace(held, identifier)
    oracle_text = apply_demangled(oracle_text, classes.get("mangled-name", []))
    if "exception-annotation" in classes:
        oracle_text = strip_annotations(oracle_text, classes["exception-annotation"])
    if "language-variant" in classes:
        oracle_text = REGISTER_DERIVED.sub(lambda match: match.group(1), oracle_text)
    words, shapes = licensed(classes, native_text, oracle_text, store,
                             native_row, oracle_row)
    words.update(filter(None, (native_name, oracle_name)))
    left = []
    # An integer's notation is not a fact: `0x0` and `0` are the same number,
    # and which one the decompiler prints follows from the operand's type.
    # A differing *value* still differs after this.
    matcher = difflib.SequenceMatcher(a=[numeric(item) for item in tokens(oracle_text)],
                                      b=[numeric(item) for item in tokens(native_text)],
                                      autojunk=False)
    for operation, i1, i2, j1, j2 in matcher.get_opcodes():
        if operation == "equal":
            continue
        for token in matcher.a[i1:i2] + matcher.b[j1:j2]:
            if token in words or any(shape.match(token) for shape in shapes):
                continue
            left.append(token)
    return sorted(set(left))


def batch(*arguments: str, timeout: int) -> dict[str, str]:
    """One decompiler launch for a whole list of addresses.

    Both backends load their language (and, for the oracle, a JVM and a
    project) once per launch, so a per-function launch is what used to make a
    corpus-wide comparison unaffordable: 400 functions cost minutes instead
    of an hour.
    """
    result = cli(*arguments, timeout=timeout)
    assert result.returncode == 0, (
        f"decompile-batch failed: {result.stderr.strip()[-400:]}")
    return json.loads(result.stdout)


def import_native(binary: Path, timeout: int) -> Path:
    """A store for `binary`, reused while the binary and the build are the same.

    Re-analysing bytes that never changed with executables that never changed
    is the whole of this gate's old wall time. The key is the provenance:
    the binary's digest and the digests of the `lre-cli` and `lre-worker` that
    read it, so a rebuilt worker is a miss (`benchmarks/gate_cache.py`).
    """
    def build(directory: Path) -> None:
        result = cli("import", str(binary), "--project", str(directory), timeout=timeout)
        assert result.returncode == 0, (
            f"{binary.name}: native import failed: {result.stderr.strip()}")

    return gate_cache.store(gate_cache.native_key(binary), build)


def import_oracle(binary: Path, timeout: int) -> Path:
    """The same, for the JVM oracle: keyed by the binary, the bridge sources
    and the pinned install's revision -- the digests every committed oracle
    reference is already pinned by."""
    def build(directory: Path) -> None:
        result = cli("import", str(binary), "--oracle", "--project", str(directory),
                     "--ghidra", str(GHIDRA), timeout=timeout)
        assert result.returncode == 0, (
            f"{binary.name}: oracle import failed: {result.stderr.strip()}")

    return gate_cache.store(gate_cache.oracle_key(binary, GHIDRA), build)


def compare_row(language: str, variant: str, binary: Path, work: Path,
                timeout: int, native_program: str | None = None,
                sample: int | None = None) -> dict:
    """Import both ways, then compare every function both stores hold.

    A container yields one native program per processor, named by suffix;
    the oracle loads the one the console boots under the file's own name.
    `native_program` names ours where the two differ."""
    program = binary.name
    native_name = native_program or program
    native_project = import_native(binary, timeout)
    oracle_project = import_oracle(binary, timeout)
    native_facts = facts(native_project / "project.sqlite", native_name)
    oracle_facts = facts(oracle_project / "project.sqlite", program)
    store = store_context(native_project / "project.sqlite", native_name)
    oracle_store = store_context(oracle_project / "project.sqlite", program)
    # The language is read from the store, not from an import message: a
    # reused store has no message, and the recorded fact is the claim anyway.
    assert store["language"] == language, (
        f"{language}: the native store recorded {store['language']!r}")
    shared = sorted(set(native_facts) & set(oracle_facts))
    assert shared, f"{language}: the two stores share no function"
    # A retail module shares thousands of functions, and the oracle
    # decompiles one at a time through the JVM. A ratcheted row compares a
    # fixed prefix of the shared set: deterministic, so the floor means the
    # same thing every run, and stated in the report.
    shared_total = len(shared)
    if sample is not None:
        shared = shared[:sample]

    addresses = [f"{entry:08x}" for entry in shared]
    joined = ",".join(addresses)
    digest = hashlib.sha256(joined.encode()).hexdigest()
    native_texts = gate_cache.document(
        gate_cache.native_key(binary, artifact="decompile-batch",
                              addresses=f"{native_name}:{digest}"),
        lambda: batch("decompile-batch", str(binary), joined, "--name", native_name,
                      "--project", str(native_project), timeout=timeout))
    oracle_texts = gate_cache.document(
        gate_cache.oracle_key(binary, GHIDRA, artifact="decompile-batch",
                              addresses=digest),
        lambda: batch("decompile-batch", program, joined, "--oracle",
                      "--project", str(oracle_project), "--ghidra", str(GHIDRA),
                      timeout=timeout))

    identical, attributed, unattributed, skipped = [], [], [], []
    for entry in shared:
        address = f"{entry:08x}"
        native_text = native_texts.get(address)
        oracle_text = oracle_texts.get(address)
        if native_text is None or oracle_text is None:
            skipped.append({"address": address,
                            "native_answered": native_text is not None,
                            "oracle_answered": oracle_text is not None})
            continue
        native_stream, oracle_stream = tokens(native_text), tokens(oracle_text)
        if native_stream == oracle_stream:
            identical.append({"address": address, "tokens": len(native_stream)})
            continue
        classes = classify(native_text, oracle_text,
                           native_facts[entry], oracle_facts[entry], entry, store,
                           oracle_store)
        left = residue(native_text, oracle_text, native_facts[entry],
                       oracle_facts[entry], classes, store) if classes else []
        if classes and not left:
            attributed.append({"address": address, "classes": classes,
                               "oracle_tokens": len(oracle_stream),
                               "native_tokens": len(native_stream)})
        else:
            unattributed.append({
                "address": address, "classes": sorted(classes), "residue": left[:12],
                "oracle": " ".join(oracle_stream)[:400],
                "native": " ".join(native_stream)[:400]})
    return {"language": language, "variant": variant, "program": program,
            "shared": shared_total, "compared": len(shared), "identical": identical,
            "attributed": attributed, "unattributed": unattributed, "skipped": skipped}


def container_image(entry: dict, work: Path) -> Path:
    """Build a container image from its committed fixture sources.

    The container, not its ELF twin: the twin is an ordinary ELF the oracle
    loads as ARM:LE:32:v8, which would prove nothing about the cartridge
    language. The builder is the m5-001 gate's, so one set of sources feeds
    both gates and neither can drift from the other."""
    specification = importlib.util.spec_from_file_location(entry["module"],
                                                           entry["path"])
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    work.mkdir(parents=True, exist_ok=True)
    _, image = module.build(work)
    return image


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--record", action="store_true",
                        help="write the parity baseline instead of checking it")
    parser.add_argument("--timeout", type=int, default=1200)
    parser.add_argument("--jobs", type=int, default=4,
                        help="rows compared concurrently; an uncached row runs a JVM")
    arguments = parser.parse_args()

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-cli",
                    "-p", "lre-worker"],
                   cwd=ROOT, check=True, env=environment())
    assert (ROOT / "service/build/ventris-service.jar").is_file(), (
        "the oracle bridge jar is missing; build service/ before this gate")

    lock = json.loads(LOCK.read_text())
    rows = {(row["expected_language"], row["variant"]): row
            for row in lock["entries"]
            if row["format"] == "elf" and row["variant"] in VARIANTS}
    measurable = {language for language, _ in rows} | set(CONTAINERS) | set(UNREACHED)
    languages = bundled_languages()
    unclassified = [language for language in languages
                    if language not in measurable and language not in BLOCKED]
    assert not unclassified, (
        f"these bundled languages are neither measured nor blocked: {unclassified}")
    stale = [language for language in BLOCKED if language in measurable]
    assert not stale, (
        f"these languages are blocked for want of an image that now exists: "
        f"{stale}")
    overlap = [language for language in CONTAINERS if (language, "plain_o0") in rows]
    assert not overlap, (
        f"these languages have both a corpus row and a container fixture, so the "
        f"corpus row is the measurement: {overlap}")

    measured, blocked, pending, unreached = [], {}, [], {}
    with tempfile.TemporaryDirectory(prefix="m4-003-") as directory:
        work = Path(directory)
        for language in languages:
            if language in BLOCKED:
                blocked[language] = dict(BLOCKED[language])
                continue
            if language in CONTAINERS:
                entry = CONTAINERS[language]
                row_work = work / f"{language.replace(':', '-')}-{entry['variant']}"
                image = container_image(entry, row_work / "image")
                pending.append((language, entry["variant"], image, row_work))
                continue
            if language in UNREACHED:
                entry = UNREACHED[language]
                image = Path(entry["image"])
                if not image.is_file():
                    unreached[language] = {"reason": entry["reason"],
                                           "image_absent": str(image)}
                    continue
                digest = hashlib.sha256(image.read_bytes()).hexdigest()
                assert digest == entry["sha256"], (
                    f"{language}: {image} hashes to {digest}, not the pinned "
                    f"{entry['sha256']}")
                row_work = work / f"{language.replace(':', '-')}-{entry['variant']}"
                row_work.mkdir(parents=True)
                row = compare_row(language, entry["variant"], image, row_work,
                                  arguments.timeout, entry.get("native_program"),
                                  entry.get("sample"))
                assert len(row["identical"]) >= entry["identical_floor"], (
                    f"{language}: {len(row['identical'])} token-identical "
                    f"function(s), below the {entry['identical_floor']} the "
                    f"floor records")
                assert row["shared"] >= entry["shared_floor"], (
                    f"{language}: the two stores share {row['shared']} "
                    f"function(s), below the {entry['shared_floor']} the floor "
                    f"records")
                unreached[language] = {
                    "reason": entry["reason"], "program": row["program"],
                    "shared": row["shared"], "compared": row["compared"],
                    "identical": len(row["identical"]),
                    "attributed": len(row["attributed"]),
                    "unattributed": len(row["unattributed"]),
                    "floors": {"shared": entry["shared_floor"],
                               "identical": entry["identical_floor"]},
                }
                continue
            # Every variant the lock holds for this language, so an
            # optimized or C++ row cannot hide behind the smallest one.
            present = [variant for variant in VARIANTS if (language, variant) in rows]
            assert present == list(VARIANTS), (
                f"{language}: the lock holds {present} of {list(VARIANTS)}; a "
                f"measured language is measured on every variant it has")
            for variant in present:
                binary = (arguments.corpus_dir
                          / rows[(language, variant)]["binary"]).resolve()
                assert binary.is_file(), f"{language}/{variant}: {binary} is missing"
                row_work = work / f"{language.replace(':', '-')}-{variant}"
                row_work.mkdir(parents=True)
                pending.append((language, variant, binary, row_work))
        # The rows are independent: each one imports its own binary and
        # compares its own functions. They run concurrently, bounded because
        # an uncached row still spawns a JVM whose analysis wants memory --
        # and the results are re-ordered afterwards, so the report and the
        # baseline do not depend on which row finished first.
        order = {(language, variant): index
                 for index, (language, variant, _, _) in enumerate(pending)}
        with concurrent.futures.ThreadPoolExecutor(max_workers=arguments.jobs) as pool:
            futures = {
                pool.submit(compare_row, language, variant, binary, row_work,
                            arguments.timeout): (language, variant)
                for language, variant, binary, row_work in pending
            }
            for future in concurrent.futures.as_completed(futures):
                measured.append(future.result())
        measured.sort(key=lambda row: order[(row["language"], row["variant"])])

    for row in measured:
        assert not row["unattributed"], (
            f"{row['language']}/{row['variant']}: {len(row['unattributed'])} "
            f"function(s) differ from "
            f"the oracle by tokens no fact explains: "
            f"{[(item['address'], item['classes'], item['residue']) for item in row['unattributed']][:4]}")
        assert not row["skipped"], (
            f"{row['language']}/{row['variant']}: {len(row['skipped'])} "
            f"function(s) could not be "
            f"compared: {row['skipped'][:2]}")
        assert row["identical"], (
            f"{row['language']}/{row['variant']}: no function was token-identical, "
            f"so nothing is "
            f"proven for it")

    identical = sum(len(row["identical"]) for row in measured)
    attributed = sum(len(row["attributed"]) for row in measured)
    per_class: dict[str, int] = {}
    for row in measured:
        for item in row["attributed"]:
            for name in item["classes"]:
                per_class[name] = per_class.get(name, 0) + 1
    metrics = {
        "parity.languages_bundled": len(languages),
        "parity.languages_measured": len({row["language"] for row in measured}),
        "parity.languages_unreached": len(unreached),
        "parity.languages_blocked": len(blocked),
        "parity.rows_measured": len(measured),
        "parity.functions_compared": identical + attributed,
        "parity.functions_token_identical": identical,
        "parity.functions_fact_attributed": attributed,
        "parity.functions_unattributed": 0,
    }
    metrics.update({f"parity.class.{name}": count
                    for name, count in sorted(per_class.items())})
    reached = ", ".join(
        f"{language} {note.get('identical', 0)}/{note.get('compared', 0)} identical "
        f"of {note.get('shared', 0)} shared"
        if "shared" in note else f"{language} image absent"
        for language, note in sorted(unreached.items()))
    summary = (
        f"{len({row['language'] for row in measured})} of {len(languages)} bundled "
        f"languages measured against the JVM oracle on {len(measured)} committed "
        f"corpus rows ({', '.join(VARIANTS)}): {identical} of "
        f"{identical + attributed} functions token-identical, {attributed} differing "
        f"only where a named fact differs "
        f"({', '.join(f'{name} {count}' for name, count in sorted(per_class.items()))}"
        f"), 0 unexplained; {len(unreached)} measured but not yet at parity "
        f"({reached}); {len(blocked)} languages blocked for want of an image "
        f"II.1 reserves adding, each verified absent")

    # Every count is pinned: an improvement and a regression both have to be
    # re-recorded deliberately, which is what keeps a divergence class from
    # being quietly widened into an excuse.
    counts = {"rows": {f"{row['language']}/{row['variant']}":
                       {"identical": len(row["identical"]),
                        "attributed": len(row["attributed"])}
                       for row in measured},
              "classes": dict(sorted(per_class.items()))}
    if arguments.record:
        BASELINE.write_text(json.dumps({
            "id": "parity-baseline",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "note": "token identity against the JVM oracle per language, and the "
                    "fact class each divergence comes from; recorded once and "
                    "compared against afterwards",
            "counts": counts}, indent=1) + "\n")
        print(f"m4-003: recorded {BASELINE.relative_to(ROOT)}")
        return 0
    assert BASELINE.is_file(), (
        f"{BASELINE.relative_to(ROOT)} is missing; record it with --record first")
    recorded = json.loads(BASELINE.read_text())["counts"]
    assert counts["rows"] == recorded["rows"], (
        f"per-row parity moved: recorded "
        f"{ {k: v for k, v in recorded['rows'].items() if counts['rows'].get(k) != v} }, "
        f"measured "
        f"{ {k: v for k, v in counts['rows'].items() if recorded['rows'].get(k) != v} }")
    assert counts["classes"] == recorded["classes"], (
        f"the divergence classes moved: recorded {recorded['classes']}, measured "
        f"{counts['classes']}")

    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        # Complete evidence, without an oversized aggregate commit: the same
        # split `prototype_gate.write_arity_report` uses for mismatches.
        rows = []
        for row in measured:
            detail = arguments.report.parent / (arguments.report.stem + "-divergences")
            detail.mkdir(parents=True, exist_ok=True)
            payload = "".join(json.dumps(item) + "\n"
                              for item in row["attributed"]).encode()
            path = detail / (f"{row['language'].replace(':', '-')}"
                             f"-{row['variant']}.jsonl")
            path.write_bytes(payload)
            rows.append({
                "language": row["language"], "variant": row["variant"],
                "program": row["program"],
                "shared": row["shared"],
                "identical": len(row["identical"]),
                "identical_tokens": sum(item["tokens"] for item in row["identical"]),
                "attributed": len(row["attributed"]),
                "classes": sorted({name for item in row["attributed"]
                                   for name in item["classes"]}),
                "evidence": {"path": path.relative_to(arguments.report.parent).as_posix(),
                             "sha256": hashlib.sha256(payload).hexdigest()},
            })
        arguments.report.write_text(json.dumps({
            "id": "m4-003",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "status": "pass",
            "passed": True,
            "summary": summary,
            "metrics": metrics,
            "measured": rows,
            "unreached": unreached,
        }, indent=1) + "\n")
    print(f"m4-003: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
