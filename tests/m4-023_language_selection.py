#!/usr/bin/env python3
"""m4-023: the install's own opinion data selects the language, not a table.

Ghidra decides an ELF's language from `<processor>.opinion` -- the loader
queries it with `e_machine` as the primary key and `e_flags` as the secondary
one (`ElfLoader.findSupportedLoadSpecs`) -- and the constraint that matches
names the processor, and sometimes the variant. Our loader answered from a
hand-written table instead, which is how an ARM ELF was decoded as `v7` where
the pinned install's own opinion file pins `v8`.

This gate recomputes the selection from the install for every row, compares it
with what `lre-cli import` selected, and compares both with what stock chose
for the same bytes. A disagreement with stock passes only when it is *proven
unconstrained*: no ELF constraint for that machine pins a variant, none has a
secondary matching the image's flags, both languages are declared for the same
processor/endian/size, and ours is the neutral `default` variant. That is the
PowerPC case -- stock takes the first element of a `HashSet<QueryResult>`
iteration among equally preferred candidates, which is not a fact about the
image.

    python3 tests/m4-023_language_selection.py --corpus-dir DIR [--report OUT.json]
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "target/release/lre-cli"
LOCK = ROOT / "tests/corpus.lock.json"
ELF_LOADER = "Executable and Linking Format (ELF)"
# The neutral decoder: the variant to take when the opinion data leaves the
# choice open. The PowerPC ELF constraint names no variant, and the RISCV one
# says so in a comment ("must choose between 'default' and 'AndeStar'").
NEUTRAL = "default"
# Cross-compiled probes; ARM is the only machine whose opinion file selects a
# variant from `e_flags`, so it is the only one that can prove the secondary
# key is read. These are temporary probes, not corpus entries.
PROBES = [
    ("arm_le", "arm-none-eabi", ["-march=armv7-a"]),
    ("arm_be32", "armeb-none-eabi", ["-march=armv5t"]),
    ("arm_be8", "armeb-none-eabi", ["-march=armv7-a"]),
]


def elf_header(data: bytes) -> dict:
    """`e_machine`, `e_flags`, endianness and pointer size, read directly."""
    assert data[:4] == b"\x7fELF", "not an ELF"
    bits = 64 if data[4] == 2 else 32
    order = ">" if data[5] == 2 else "<"
    machine = struct.unpack_from(order + "H", data, 18)[0]
    flags = struct.unpack_from(order + "I", data, 48 if bits == 64 else 36)[0]
    return {"machine": machine, "flags": flags, "bits": bits,
            "endian": "big" if data[5] == 2 else "little"}


def constraints(install: Path) -> list[dict]:
    """Every ELF constraint the install declares, with inherited attributes.

    A constraint element inherits `loader` and `compilerSpecID` from its
    ancestors (`QueryOpinionServiceHandler` pushes them down), and the leaf
    rows carry `primary`, `secondary`, `processor`, `endian`, `size` and
    `variant`.
    """
    rows = []
    for opinion in sorted((install / "Ghidra/Processors").glob("*/data/languages/*.opinion")):
        root = ET.parse(opinion).getroot()

        def walk(node: ET.Element, inherited: dict) -> None:
            merged = dict(inherited)
            merged.update({key: value for key, value in node.attrib.items()})
            children = [child for child in node if child.tag == "constraint"]
            if children:
                for child in children:
                    walk(child, merged)
                return
            if merged.get("loader") != ELF_LOADER or "primary" not in merged:
                return
            rows.append(merged)

        for child in root:
            if child.tag == "constraint":
                walk(child, {})
    return rows


def primary_matches(constraint: dict, machine: int) -> bool:
    """`primary="8,10"` lists several `e_machine` values (MIPS)."""
    for value in constraint["primary"].split(","):
        text = value.strip()
        try:
            if int(text, 0) == machine:
                return True
        except ValueError:
            continue
    return False


def secondary_matches(constraint: dict, flags: int) -> bool | None:
    """Whether a secondary key matches these flags.

    `None` means the constraint carries no secondary key, which Ghidra falls
    back to when nothing matched (`QueryOpinionService.getSpecs`). A `0b`
    pattern masks don't-care bits with `.`; a decimal or `0x` key compares
    equal (`getQueryResultWithSecondaryMasking`).
    """
    key = constraint.get("secondary")
    if key is None:
        return None
    text = key.strip()
    if text.startswith("0b"):
        bits = text[2:].replace(" ", "").replace("_", "")
        if len(bits) != 32:
            return False
        for index, symbol in enumerate(bits):
            if symbol == ".":
                continue
            if symbol not in "01":
                return False
            if (flags >> (31 - index)) & 1 != int(symbol):
                return False
        return True
    try:
        return int(text, 0) == flags
    except ValueError:
        # A compiler-name secondary ("golang", "swift"); we do not detect
        # those, so such a constraint never matches.
        return False


def languages(install: Path) -> list[dict]:
    """Every language the install declares, in declaration order."""
    rows = []
    for ldefs in sorted((install / "Ghidra/Processors").glob("*/data/languages/*.ldefs")):
        for language in ET.parse(ldefs).getroot().findall("language"):
            rows.append({
                "id": language.get("id"),
                "processor": language.get("processor"),
                "endian": language.get("endian"),
                "size": language.get("size"),
                "variant": language.get("variant"),
                "compilers": [item.get("id") for item in language.findall("compiler")],
                "ldefs": ldefs.name,
            })
    return rows


def expected_selection(install: Path, header: dict) -> tuple[str, str, list[str]]:
    """The language, compiler spec, and the candidates the data allowed."""
    matching = [row for row in constraints(install) if primary_matches(row, header["machine"])]
    assert matching, f"no ELF constraint for machine {header['machine']}"
    keyed = [row for row in matching if secondary_matches(row, header["flags"]) is True]
    chosen = keyed or [row for row in matching if row.get("secondary") is None]
    assert chosen, f"no constraint matches flags {header['flags']:#x}"
    declared = languages(install)
    candidates = []
    for constraint in chosen:
        for language in declared:
            if language["processor"] != constraint["processor"]:
                continue
            if language["endian"] != constraint.get("endian", header["endian"]):
                continue
            if language["size"] != constraint.get("size", str(header["bits"])):
                continue
            variant = constraint.get("variant")
            if variant is not None and language["variant"] != variant:
                continue
            compiler = constraint.get("compilerSpecID", NEUTRAL)
            if compiler not in language["compilers"]:
                continue
            candidates.append((language, compiler))
    assert candidates, "the opinion data allows no installed language"
    neutral = [item for item in candidates if item[0]["variant"] == NEUTRAL]
    language, compiler = (neutral or candidates)[0]
    return language["id"], compiler, [item[0]["id"] for item in candidates]


def unconstrained(install: Path, header: dict, ours: str, theirs: str) -> dict:
    """Proof that the data does not choose between two variants.

    A mismatch with stock is only excusable when the install declares no rule
    that separates them: no constraint for this machine pins a variant, none
    matches these flags, both languages sit at the same processor, endian and
    size, and ours is the neutral one.
    """
    matching = [row for row in constraints(install) if primary_matches(row, header["machine"])]
    pinned = [row.get("variant") for row in matching if row.get("variant")]
    keyed = [row for row in matching if secondary_matches(row, header["flags"]) is True]
    declared = {row["id"]: row for row in languages(install)}
    assert not pinned, f"the data pins {pinned}: a mismatch is ours, not stock's"
    assert not keyed, f"a secondary key matches {header['flags']:#x}: {keyed}"
    for identifier in (ours, theirs):
        assert identifier in declared, f"{identifier} is not declared by the install"
    mine, stock = declared[ours], declared[theirs]
    for field in ("processor", "endian", "size"):
        assert mine[field] == stock[field], (
            f"{ours} and {theirs} differ in {field}: that is a real disagreement")
    assert mine["variant"] == NEUTRAL, (
        f"ours is {mine['variant']}, not the neutral {NEUTRAL}: unexplained")
    siblings = sorted(row["id"] for row in languages(install)
                      if (row["processor"], row["endian"], row["size"])
                      == (mine["processor"], mine["endian"], mine["size"]))
    return {"pinned_variants": [], "flags": f"{header['flags']:#x}",
            "ours": ours, "stock": theirs, "siblings": siblings}


def stock_language(install: Path, binary: Path, work: Path, name: str) -> str:
    """What stock selects for the same bytes, with no analysis."""
    project = work / f"stock-{name}"
    project.mkdir(parents=True, exist_ok=True)
    environment = dict(os.environ, DEBUGINFOD_URLS="")
    result = subprocess.run(
        [str(install / "support/analyzeHeadless"), str(project), name,
         "-import", str(binary), "-noanalysis"],
        capture_output=True, text=True, env=environment, timeout=900)
    match = re.search(r"Using Language/Compiler: (\S+)", result.stdout)
    assert match, f"{name}: stock printed no language: {result.stdout[-400:]}"
    return match.group(1)


def our_language(binary: Path, work: Path, name: str) -> str:
    """What our loader selects, read from the import summary."""
    project = work / f"native-{name}"
    result = subprocess.run(
        [str(CLI), "import", str(binary), "--name", name, "--project", str(project)],
        capture_output=True, text=True, timeout=900)
    assert result.returncode == 0, f"{name}: import failed: {result.stderr[-400:]}"
    match = re.search(r"\(\d+ functions, ([^)]+)\)", result.stdout)
    assert match, f"{name}: no import summary: {result.stdout[-200:]}"
    return match.group(1)


def corpus_rows(corpus: Path) -> list[tuple[str, Path]]:
    """One ELF per language the lock holds, at its unoptimised variant."""
    lock = json.loads(LOCK.read_text())
    rows = []
    for entry in lock["entries"]:
        if entry.get("format") != "elf" or entry.get("variant") != "plain_o0":
            continue
        binary = corpus / entry["binary"]
        rows.append((Path(entry["binary"]).stem, binary))
    return sorted(rows)


def probe_rows(work: Path) -> list[tuple[str, Path, str | None]]:
    """ARM probes: the machine whose opinion file reads `e_flags`."""
    source = work / "entry.c"
    source.write_text("volatile unsigned int word = 0x12345678;\n"
                      "int entry(void) { return word + 42; }\n")
    rows = []
    for name, target, flags in PROBES:
        binary = work / f"{name}.elf"
        attempt = subprocess.run(
            ["clang", f"--target={target}", *flags, "-fuse-ld=lld", "-nostdlib",
             "-Wl,-e,entry", str(source), "-o", str(binary)],
            capture_output=True, text=True)
        if attempt.returncode != 0 or not binary.is_file():
            rows.append((name, binary, (attempt.stderr.strip() or "clang failed")[-200:]))
            continue
        rows.append((name, binary, None))
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--ghidra", type=Path,
                        default=Path(os.environ.get("VENTRIS_GHIDRA",
                                                    Path.home() / "ghidra_12.1.3_PUBLIC")))
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()
    install = arguments.ghidra
    assert (install / "support/analyzeHeadless").is_file(), f"no install at {install}"
    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-cli", "-p", "lre-worker"],
                   cwd=ROOT, check=True)

    measured, skipped = [], []
    with tempfile.TemporaryDirectory(prefix="m4-023-") as temporary:
        work = Path(temporary)
        rows = [(name, binary, None) for name, binary in corpus_rows(arguments.corpus_dir)]
        rows += probe_rows(work)
        for name, binary, reason in rows:
            if reason is not None or not binary.is_file():
                skipped.append({"id": name, "reason": reason or f"missing {binary}"})
                continue
            header = elf_header(binary.read_bytes())
            language, compiler, candidates = expected_selection(install, header)
            ours = our_language(binary, work, name)
            theirs = stock_language(install, binary, work, name)
            row = {"id": name, "machine": header["machine"],
                   "flags": f"{header['flags']:#x}", "endian": header["endian"],
                   "bits": header["bits"], "expected": language,
                   "compiler": compiler, "candidates": candidates,
                   "ours": ours, "stock": theirs}
            assert ours == language, (
                f"{name}: the install's opinion data selects {language}, we selected {ours}")
            stock_language_id = theirs.rsplit(":", 1)[0]
            if ours == stock_language_id:
                row["agreement"] = "identical"
            else:
                row["agreement"] = "stock-unconstrained"
                row["evidence"] = unconstrained(install, header, ours, stock_language_id)
            measured.append(row)
            print(f"{row['agreement']:>20} {name}: ours {ours}, stock {theirs}", flush=True)

    assert measured, "no row was measured"
    identical = [row for row in measured if row["agreement"] == "identical"]
    unexplained = [row for row in measured if row["agreement"] not in
                   ("identical", "stock-unconstrained")]
    assert not unexplained, f"unexplained selections: {unexplained}"
    metrics = {
        "language.rows_measured": len(measured),
        "language.rows_identical_to_stock": len(identical),
        "language.rows_stock_unconstrained": len(measured) - len(identical),
        "language.rows_unexplained": 0,
    }
    summary = (f"{len(measured)} ELF rows selected from the install's opinion data, "
               f"{len(identical)} identical to stock's own choice, "
               f"{len(measured) - len(identical)} differing only where the data "
               f"pins no variant and stock takes the first of its equally "
               f"preferred candidates; {len(skipped)} skipped")
    print(f"m4-023: PASS ({summary})")
    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps({
            "id": "m4-023",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "status": "pass",
            "passed": True,
            "summary": summary,
            "metrics": metrics,
            "measured": measured,
            "skipped": skipped,
        }, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
