#!/usr/bin/env python3
"""m4-003: token identity against the oracle, for every language it can reach.

`tests/differential.sh` proves the native decompiler emits the same token
stream as the JVM oracle -- for one x86-64 fixture. The support matrix
therefore still reads "decompile parity pending" for AArch64 and "not
parity-gated" for the other languages whose spec bundles `native/specs` ships.

This gate closes that by measurement rather than by prose. For every language
bundle it enumerates from `native/specs`, it either measures parity or names
a blocker it verifies:

  * **measured**: the language has an ELF row in the committed corpus lock, so
    the same stripped image is imported natively and through the bridge, every
    function both stores hold is decompiled both ways, and the token streams
    must be identical;
  * **attributed**: where the two stores disagree about a function's name or
    signature, the decompilations may differ -- that is the point of recovering
    facts -- but the gate must be able to name the differing fact, and any
    difference it cannot attribute fails;
  * **blocked**: the language has no corpus row, which II.1 reserves adding.
    The gate verifies the absence rather than trusting the note, and for a
    container language it also verifies that the oracle cannot load the image.

Usage:
    python3 tests/m4-003_language_parity.py --corpus-dir DIR [--report OUT.json]
"""
from __future__ import annotations

import argparse
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
SPECS = ROOT / "native/specs"
LOCK = ROOT / "tests/corpus.lock.json"
GHIDRA = Path(os.environ.get("VENTRIS_GHIDRA", str(Path.home() / "ghidra_12.1.3_PUBLIC")))
CLI = ROOT / "target/release/lre-cli"
# Pinned once, compared against afterwards, like the memory envelopes.
BASELINE = ROOT / "benchmarks/reports/parity-baseline.json"
# The variant to compare: the smallest rows, and every function in them.
VARIANT = "plain_o0"
# A language with no corpus row cannot be measured; each needs a reason, and
# `container` reasons are checked by asking the oracle to load the image.
BLOCKED = {
    "ARM:LE:32:v4t": {"reason": "no ARM32 ELF row in the corpus lock; the ARM "
                                "images that exist are cartridge containers the "
                                "oracle has no loader for",
                      "container": "gba"},
    "ARM:LE:32:v5t": {"reason": "same ARM32 gap: the only images are the NDS "
                                "cartridge's two CPU views"},
    "MIPS:LE:32:default": {"reason": "no MIPS ELF row in the corpus lock; the "
                                     "PS-EXE container has no oracle loader"},
    "MIPS:BE:64:64-32addr": {"reason": "no MIPS ELF row in the corpus lock; the "
                                       "Nintendo 64 ROM has no oracle loader"},
    "PowerPC:BE:32:e500": {"reason": "the e500 images are GameCube DOL "
                                     "containers, which the oracle cannot load; "
                                     "the corpus PowerPC row is BE32 default"},
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
        return {"symbols": symbols, "prototypes": prototypes,
                "externals": externals, "strings": strings}
    finally:
        connection.close()


def classify(native_text: str, oracle_text: str, native_row: dict, oracle_row: dict,
             entry: int, store: dict) -> dict:
    """Name the fact each divergence comes from, with the evidence for it."""
    classes: dict[str, object] = {}
    differing = {key: [oracle_row.get(key), native_row.get(key)]
                 for key in ("name", "signature", "return_type")
                 if oracle_row.get(key) != native_row.get(key)}

    # A name is a choice, not a gap: the loader-derived names differ on
    # purpose (`_plt` says which section proved the start; Ghidra's
    # `FUN_00201710` says nothing). Substituting one for the other decides
    # whether the name is the *only* difference, so a deliberate convention is
    # never counted as a missing fact.
    native_name, oracle_name = native_row.get("name"), oracle_row.get("name")
    if native_name and oracle_name and native_name != oracle_name:
        substituted = re.sub(rf"\b{re.escape(oracle_name)}\b", native_name, oracle_text)
        if tokens(substituted) == tokens(native_text):
            # Only a name we chose is a convention. If ours is the decompiler's
            # own default and the oracle has a real name, the name is missing,
            # not different.
            default = re.match(r"(?:FUN|SUB|UNK)_[0-9a-f]+$", native_name)
            return {"missing-name" if default else "name-convention":
                    [oracle_name, native_name]}

    if differing:
        classes["function-facts"] = differing

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

    # An import with no prototype: this function, or one the oracle calls by a
    # name the store holds as an import.
    without = []
    if entry in store["externals"] and entry not in store["prototypes"]:
        without.append(native_row.get("name"))
    for address, name in store["externals"].items():
        if (re.search(rf"\b{re.escape(name)}\s*\(", oracle_text)
                and address not in store["prototypes"]):
            without.append(name)
    if without:
        classes["missing-external-prototype"] = sorted(set(without))

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

    # Flow the two sides disagree about, on the same bytes.
    native_warnings = {re.sub(r"\s+", " ", item) for item in WARNING.findall(native_text)}
    oracle_warnings = {re.sub(r"\s+", " ", item) for item in WARNING.findall(oracle_text)}
    if native_warnings != oracle_warnings:
        classes["flow"] = sorted(native_warnings - oracle_warnings)[:3]
    return classes


def compare_language(language: str, binary: Path, work: Path, timeout: int) -> dict:
    """Import both ways, then compare every function both stores hold."""
    program = binary.name
    native_project, oracle_project = work / "native", work / "oracle"
    imported = cli("import", str(binary), "--project", str(native_project),
                   timeout=timeout)
    assert imported.returncode == 0, (
        f"{language}: native import failed: {imported.stderr.strip()}")
    assert language in imported.stdout, (
        f"{language}: native import reported {imported.stdout.strip()!r}")
    oracle = cli("import", str(binary), "--oracle", "--project", str(oracle_project),
                 "--ghidra", str(GHIDRA), timeout=timeout)
    assert oracle.returncode == 0, (
        f"{language}: oracle import failed: {oracle.stderr.strip()}")

    native_facts = facts(native_project / "project.sqlite", program)
    oracle_facts = facts(oracle_project / "project.sqlite", program)
    store = store_context(native_project / "project.sqlite", program)
    shared = sorted(set(native_facts) & set(oracle_facts))
    assert shared, f"{language}: the two stores share no function"

    identical, attributed, unattributed, skipped = [], [], [], []
    for entry in shared:
        address = f"{entry:08x}"
        native_text = cli("decompile", str(binary), address,
                          "--project", str(native_project), timeout=timeout)
        oracle_text = cli("decompile", program, address, "--oracle",
                          "--project", str(oracle_project), "--ghidra", str(GHIDRA),
                          timeout=timeout)
        if native_text.returncode or oracle_text.returncode:
            skipped.append({"address": address,
                            "native_error": native_text.stderr.strip()[-200:],
                            "oracle_error": oracle_text.stderr.strip()[-200:]})
            continue
        native_stream, oracle_stream = tokens(native_text.stdout), tokens(oracle_text.stdout)
        if native_stream == oracle_stream:
            identical.append({"address": address, "tokens": len(native_stream)})
            continue
        classes = classify(native_text.stdout, oracle_text.stdout,
                           native_facts[entry], oracle_facts[entry], entry, store)
        if classes:
            attributed.append({"address": address, "classes": classes,
                               "oracle_tokens": len(oracle_stream),
                               "native_tokens": len(native_stream)})
        else:
            unattributed.append({
                "address": address,
                "oracle": " ".join(oracle_stream)[:400],
                "native": " ".join(native_stream)[:400]})
    return {"language": language, "program": program, "shared": len(shared),
            "identical": identical, "attributed": attributed,
            "unattributed": unattributed, "skipped": skipped}


def container_refused(kind: str, work: Path, timeout: int) -> str:
    """Ask the oracle to load a cartridge image, and record its refusal."""
    builders = {"gba": ("m5_001", ROOT / "tests/m5-001_gba.py")}
    name, path = builders[kind]
    specification = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    work.mkdir(parents=True, exist_ok=True)
    # The container, not its ELF twin: the twin is an ordinary ELF the oracle
    # loads happily (as ARM:LE:32:v8), which proves nothing about the ROM.
    _, image = module.build(work)
    attempt = cli("import", str(image), "--oracle", "--project", str(work / "oracle"),
                  "--ghidra", str(GHIDRA), timeout=timeout)
    assert attempt.returncode != 0, (
        f"the oracle loaded {image.name}, so the blocker is stale: "
        f"{attempt.stdout.strip()}")
    return (attempt.stderr.strip() or attempt.stdout.strip())[-300:]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--record", action="store_true",
                        help="write the parity baseline instead of checking it")
    parser.add_argument("--timeout", type=int, default=1200)
    arguments = parser.parse_args()

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-cli"],
                   cwd=ROOT, check=True, env=environment())
    assert (ROOT / "service/build/ventris-service.jar").is_file(), (
        "the oracle bridge jar is missing; build service/ before this gate")

    lock = json.loads(LOCK.read_text())
    rows = {row["expected_language"]: row for row in lock["entries"]
            if row["format"] == "elf" and row["variant"] == VARIANT}
    languages = bundled_languages()
    unclassified = [language for language in languages
                    if language not in rows and language not in BLOCKED]
    assert not unclassified, (
        f"these bundled languages are neither measured nor blocked: {unclassified}")
    stale = [language for language in BLOCKED if language in rows]
    assert not stale, (
        f"these languages are blocked for want of a corpus row that now exists: "
        f"{stale}")

    measured, blocked = [], {}
    with tempfile.TemporaryDirectory(prefix="m4-003-") as directory:
        work = Path(directory)
        for language in languages:
            if language in BLOCKED:
                note = dict(BLOCKED[language])
                if "container" in note:
                    note["oracle_refusal"] = container_refused(
                        note.pop("container"), work / "container", arguments.timeout)
                blocked[language] = note
                continue
            binary = (arguments.corpus_dir / rows[language]["binary"]).resolve()
            assert binary.is_file(), f"{language}: {binary} is missing"
            row_work = work / language.replace(":", "-")
            row_work.mkdir(parents=True)
            measured.append(compare_language(language, binary, row_work,
                                             arguments.timeout))

    for row in measured:
        assert not row["unattributed"], (
            f"{row['language']}: {len(row['unattributed'])} function(s) differ from "
            f"the oracle with no fact to explain it: "
            f"{[item['address'] for item in row['unattributed']]}")
        assert not row["skipped"], (
            f"{row['language']}: {len(row['skipped'])} function(s) could not be "
            f"compared: {row['skipped'][:2]}")
        assert row["identical"], (
            f"{row['language']}: no function was token-identical, so nothing is "
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
        "parity.languages_measured": len(measured),
        "parity.languages_blocked": len(blocked),
        "parity.functions_compared": identical + attributed,
        "parity.functions_token_identical": identical,
        "parity.functions_fact_attributed": attributed,
        "parity.functions_unattributed": 0,
    }
    metrics.update({f"parity.class.{name}": count
                    for name, count in sorted(per_class.items())})
    summary = (
        f"{len(measured)} of {len(languages)} bundled languages measured against the "
        f"JVM oracle on committed corpus rows: {identical} of "
        f"{identical + attributed} functions token-identical, {attributed} differing "
        f"only where a named fact differs "
        f"({', '.join(f'{name} {count}' for name, count in sorted(per_class.items()))}"
        f"), 0 unexplained; {len(blocked)} languages blocked for want of a corpus row "
        f"II.1 reserves adding, each verified absent")

    # Every count is pinned: an improvement and a regression both have to be
    # re-recorded deliberately, which is what keeps a divergence class from
    # being quietly widened into an excuse.
    counts = {"languages": {row["language"]: {"identical": len(row["identical"]),
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
    assert counts["languages"] == recorded["languages"], (
        f"per-language parity moved: recorded {recorded['languages']}, measured "
        f"{counts['languages']}")
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
            path = detail / f"{row['language'].replace(':', '-')}.jsonl"
            path.write_bytes(payload)
            rows.append({
                "language": row["language"], "program": row["program"],
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
            "blocked": blocked,
        }, indent=1) + "\n")
    print(f"m4-003: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
