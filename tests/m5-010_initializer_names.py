#!/usr/bin/env python3
"""m5-010: initializer-array entries carry the name their array gives them.

`_INIT_0` is stock Ghidra's name for the function `DT_INIT_ARRAY[0]` points
at (`ElfProgramBuilder.createDynamicEntryPoints:690-750`, base names `_INIT_`,
`_PREINIT_` and `_FINI_`). Ventris referenced the same function from the same
array slot and still called it `FUN_00201670`, which is the last
name-difference class left on the corpus after m5-009.

The name is derived, never copied: the array's base and size come from the
dynamic table, the target from the slot's own word or its relocation, and the
index from the slot's position. The gate reads all three out of the ELF file
itself and requires the store to agree:

  * every array slot that points into executable memory names its target
    `_INIT_<i>` / `_PREINIT_<i>` / `_FINI_<i>`, unless a symbol already names
    that address -- Ghidra keeps a symbol-based name too, and so must we;
  * every such name is backed by a data reference from that slot in our own
    store, so the label cannot exist without the fact;
  * stock Ghidra's name at the same address must agree, and every remaining
    difference must be a *proven-equivalent label*: the same address named
    from a different source (before m4-017: our `_entry` for `e_entry`, our `_init` for
    `DT_INIT`), asserted by reading the header and the dynamic table.

Usage:
    python3 tests/m5-010_initializer_names.py --corpus-dir DIR [--report OUT.json]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import struct
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXPORTER = ROOT / "scripts" / "ExportFunctionScoring.java"

THRESHOLDS = {
    "initializer.name.missing": 0,
    "initializer.name.unbacked": 0,
    "initializer.name.unexplained": 0,
}

DERIVED = re.compile(r"^_(INIT|PREINIT|FINI)_\d+$")
# Names stock Ghidra takes from a `<funcstart label=...>` pattern in the pinned
# install. Empty since m5-011: Ventris applies those labels itself, so such a
# row would now be a real disagreement. A new row fails here.
PATTERN_LABELS: dict[str, dict[str, str]] = {}

# The loader's own entry names agree with stock since m4-017, so no
# equivalence is needed for them.
EQUIVALENT: set[tuple[str, str]] = set()

DT = {"INIT_ARRAY": 25, "FINI_ARRAY": 26, "INIT_ARRAYSZ": 27, "FINI_ARRAYSZ": 28,
      "PREINIT_ARRAY": 32, "PREINIT_ARRAYSZ": 33, "INIT": 12, "FINI": 13}
ARRAYS = (("INIT_ARRAY", "INIT_ARRAYSZ", "_INIT_"),
          ("PREINIT_ARRAY", "PREINIT_ARRAYSZ", "_PREINIT_"),
          ("FINI_ARRAY", "FINI_ARRAYSZ", "_FINI_"))


def elf_facts(binary: Path) -> dict:
    """Header, dynamic table, section words and relative relocations."""
    data = binary.read_bytes()
    assert data[:4] == b"\x7fELF", f"{binary.name} is not an ELF"
    width = 8 if data[4] == 2 else 4
    big = data[5] == 2
    order = ">" if big else "<"
    entry = struct.unpack_from(f"{order}{'Q' if width == 8 else 'I'}",
                               data, 24)[0]

    # Program headers locate PT_DYNAMIC and the lowest PT_LOAD.
    if width == 8:
        phoff, phentsize, phnum = (struct.unpack_from(f"{order}Q", data, 32)[0],
                                   struct.unpack_from(f"{order}H", data, 54)[0],
                                   struct.unpack_from(f"{order}H", data, 56)[0])
    else:
        phoff, phentsize, phnum = (struct.unpack_from(f"{order}I", data, 28)[0],
                                   struct.unpack_from(f"{order}H", data, 42)[0],
                                   struct.unpack_from(f"{order}H", data, 44)[0])
    dynamic, loads = None, []
    for index in range(phnum):
        header = phoff + index * phentsize
        kind = struct.unpack_from(f"{order}I", data, header)[0]
        if width == 8:
            offset = struct.unpack_from(f"{order}Q", data, header + 8)[0]
            vaddr = struct.unpack_from(f"{order}Q", data, header + 16)[0]
            size = struct.unpack_from(f"{order}Q", data, header + 32)[0]
        else:
            offset = struct.unpack_from(f"{order}I", data, header + 4)[0]
            vaddr = struct.unpack_from(f"{order}I", data, header + 8)[0]
            size = struct.unpack_from(f"{order}I", data, header + 20)[0]
        if kind == 2:
            dynamic = (offset, size)
        elif kind == 1:
            loads.append((vaddr, offset, size))
    assert dynamic, f"{binary.name} has no PT_DYNAMIC"

    tags: dict[int, int] = {}
    step = width * 2
    offset, size = dynamic
    for position in range(offset, offset + size, step):
        pack = "Q" if width == 8 else "I"
        tag = struct.unpack_from(f"{order}{pack}", data, position)[0]
        value = struct.unpack_from(f"{order}{pack}", data, position + width)[0]
        if tag == 0:
            break
        tags.setdefault(tag, value)

    def file_offset(vaddr: int) -> int | None:
        for start, offset, size in loads:
            if start <= vaddr < start + size:
                return offset + (vaddr - start)
        return None

    def word(vaddr: int) -> int | None:
        position = file_offset(vaddr)
        if position is None:
            return None
        pack = "Q" if width == 8 else "I"
        return struct.unpack_from(f"{order}{pack}", data, position)[0]

    # R_*_RELATIVE relocations: a PIE's array slots hold zero, and the target
    # is the relocation's addend.
    relative: dict[int, int] = {}
    relocations = subprocess.run(["readelf", "-rW", str(binary)],
                                 capture_output=True, text=True,
                                 env=dict(os.environ, LC_ALL="C")).stdout
    for line in relocations.splitlines():
        parts = line.split()
        if len(parts) >= 4 and "RELATIVE" in parts[2]:
            try:
                relative[int(parts[0], 16)] = int(parts[-1], 16)
            except ValueError:
                continue
    # Section starts, so a section-derived label can be proven.
    if width == 8:
        shoff = struct.unpack_from(f"{order}Q", data, 40)[0]
        shentsize = struct.unpack_from(f"{order}H", data, 58)[0]
        shnum = struct.unpack_from(f"{order}H", data, 60)[0]
        shstrndx = struct.unpack_from(f"{order}H", data, 62)[0]
    else:
        shoff = struct.unpack_from(f"{order}I", data, 32)[0]
        shentsize = struct.unpack_from(f"{order}H", data, 46)[0]
        shnum = struct.unpack_from(f"{order}H", data, 48)[0]
        shstrndx = struct.unpack_from(f"{order}H", data, 50)[0]
    sections: dict[int, str] = {}
    if shoff and shnum and shstrndx < shnum:
        strtab_header = shoff + shstrndx * shentsize
        strtab_offset = struct.unpack_from(
            f"{order}{'Q' if width == 8 else 'I'}", data,
            strtab_header + (24 if width == 8 else 16))[0]
        for index in range(shnum):
            header = shoff + index * shentsize
            name_offset = struct.unpack_from(f"{order}I", data, header)[0]
            address = struct.unpack_from(
                f"{order}{'Q' if width == 8 else 'I'}", data,
                header + (16 if width == 8 else 12))[0]
            end = data.index(b"\0", strtab_offset + name_offset)
            name = data[strtab_offset + name_offset:end].decode("utf-8", "replace")
            if address:
                sections[address] = name
    return {"entry": entry, "tags": tags, "word": word, "relative": relative,
            "width": width, "sections": sections}


def native_facts(cli: Path, binary: Path, work: Path, timeout: int) -> dict:
    project = work / "project"
    imported = subprocess.run(
        [str(cli), "import", str(binary), "--name", "scored", "--project", str(project)],
        cwd=ROOT, capture_output=True, text=True, timeout=timeout)
    assert imported.returncode == 0, (
        f"{binary.name}: native import failed: {imported.stderr.strip()}")
    store = sqlite3.connect(project / "project.sqlite")
    functions = {int(entry, 16): name for entry, name in store.execute(
        "SELECT entry, name FROM functions")}
    symbols: dict[int, set[str]] = {}
    for address, name in store.execute("SELECT address, name FROM symbols"):
        symbols.setdefault(int(address, 16), set()).add(name)
    references: set[tuple[int, int]] = {
        (int(source, 16), int(destination, 16)) for source, destination in store.execute(
            "SELECT src, dst FROM xrefs WHERE kind = 'DATA'")}
    executable = [(int(start, 16), size) for start, size, permissions in store.execute(
        "SELECT start, size, permissions FROM memory_regions") if "x" in permissions]
    return {"functions": functions, "symbols": symbols, "references": references,
            "executable": executable}


def stock_names(install: Path, binary: Path, work: Path, timeout: int) -> dict[int, str]:
    output = work / "names.json"
    result = subprocess.run(
        [str(install / "support/analyzeHeadless"), str(work), "names",
         "-import", str(binary), "-scriptPath", str(EXPORTER.parent),
         "-postScript", EXPORTER.name, str(output), "-deleteProject"],
        capture_output=True, text=True, timeout=timeout,
        env=dict(os.environ, DEBUGINFOD_URLS=""))
    assert output.is_file(), (
        f"{binary.name}: stock name export produced nothing: "
        f"{result.stdout[-400:]}")
    return {int(row["entry"], 16): row["name"] for row in json.loads(output.read_text())
            if row.get("block_execute")}


def scored_row(identifier: str, elf: dict, native: dict, stock: dict[int, str]) -> dict:
    bias = None
    for address, name in native["functions"].items():
        if name == "entry":
            bias = address - elf["entry"]
            break
    assert bias is not None, f"{identifier}: no entry function to anchor the bias"

    def executable(address: int) -> bool:
        return any(start <= address < start + size
                   for start, size in native["executable"])

    slots, missing, unbacked = [], [], []
    for array, size_tag, prefix in ARRAYS:
        base = elf["tags"].get(DT[array])
        size = elf["tags"].get(DT[size_tag])
        if base is None or not size:
            continue
        width = elf["width"]
        for index in range(size // width):
            slot = base + index * width
            target = elf["word"](slot) or elf["relative"].get(slot, 0)
            if not target or not executable(target + bias):
                continue
            address = target + bias
            expected = f"{prefix}{index}"
            ours = native["functions"].get(address)
            slots.append({"slot": f"{slot + bias:08x}", "target": f"{address:08x}",
                          "expected": expected, "ours": ours})
            if ours is None:
                continue
            symbol_named = ours in native["symbols"].get(address, set())
            if ours != expected and not symbol_named:
                missing.append({"target": f"{address:08x}", "expected": expected,
                                "ours": ours})
            if ours == expected and (slot + bias, address) not in native["references"]:
                unbacked.append({"target": f"{address:08x}", "slot": f"{slot + bias:08x}"})

    equal, equivalent, unexplained, pattern_labels = 0, [], [], []
    for address, theirs in sorted(stock.items()):
        ours = native["functions"].get(address)
        if ours is None:
            continue
        if ours == theirs:
            equal += 1
            continue
        # A section-derived label where stock leaves a generated name: same
        # address, and the section table proves the label.
        if theirs.startswith("FUN_") and ours.startswith("_"):
            section = elf["sections"].get(address - bias)
            if section and section.lstrip(".") == ours.lstrip("_"):
                equivalent.append({"address": f"{address:08x}", "ours": ours,
                                   "stock": theirs, "section": section})
                continue
        if (ours, theirs) in EQUIVALENT:
            # Same address, different source for the label. Prove the source.
            proven = (
                (ours == "_entry" and address == elf["entry"] + bias)
                or (ours == "_init" and address == elf["tags"].get(DT["INIT"], -1) + bias)
                or (ours == "_fini" and address == elf["tags"].get(DT["FINI"], -1) + bias)
            )
            if proven:
                equivalent.append({"address": f"{address:08x}", "ours": ours,
                                   "stock": theirs})
                continue
        if PATTERN_LABELS.get(identifier, {}).get(f"{address:08x}") == theirs:
            pattern_labels.append({"address": f"{address:08x}", "stock": theirs})
            continue
        unexplained.append({"address": f"{address:08x}", "ours": ours, "stock": theirs})

    pinned = PATTERN_LABELS.get(identifier, {})
    seen = {row["address"] for row in pattern_labels}
    assert seen == set(pinned), (
        f"{identifier}: pattern-label rows are {sorted(seen)} but the pinned set "
        f"is {sorted(pinned)}")
    return {"id": identifier, "slots": slots, "missing": missing,
            "unbacked": unbacked, "equal": equal, "equivalent": equivalent,
            "unexplained": unexplained, "pattern_labels": pattern_labels,
            "compared": equal + len(equivalent) + len(unexplained)
            + len(pattern_labels)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--ghidra", type=Path, default=Path(os.environ.get(
        "VENTRIS_GHIDRA", str(Path.home() / "ghidra_12.1.3_PUBLIC"))))
    parser.add_argument("--timeout", type=int, default=900)
    arguments = parser.parse_args()

    report = {"id": "m5-010", "recorded_at": datetime.now(timezone.utc).isoformat(),
              "thresholds": THRESHOLDS, "status": "skipped"}
    if not (arguments.ghidra / "support/analyzeHeadless").is_file():
        report["reason"] = f"no pinned Ghidra install at {arguments.ghidra}"
        print(f"SKIP: {report['reason']}")
        if arguments.report:
            arguments.report.write_text(json.dumps(report, indent=2) + "\n")
        return 0

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-cli"],
                   cwd=ROOT, check=True)
    cli = ROOT / "target/release/lre-cli"
    manifest = json.loads((arguments.corpus_dir / "manifest.json").read_text())

    rows, totals = [], {"slots": 0, "missing": 0, "unbacked": 0, "equal": 0,
                        "equivalent": 0, "unexplained": 0, "compared": 0,
                        "pattern_labels": 0}
    for entry in manifest["entries"]:
        if entry.get("status") != "ok":
            continue
        identifier = f"{entry['architecture']}_{entry['variant']}"
        binary = arguments.corpus_dir / entry["binary"]
        with tempfile.TemporaryDirectory(prefix="m5-010-") as temporary:
            work = Path(temporary)
            elf = elf_facts(binary)
            native = native_facts(cli, binary, work, arguments.timeout)
            stock = stock_names(arguments.ghidra, binary, work, arguments.timeout)
        row = scored_row(identifier, elf, native, stock)
        rows.append(row)
        totals["slots"] += len(row["slots"])
        totals["compared"] += row["compared"]
        totals["equal"] += row["equal"]
        for key in ("missing", "unbacked", "equivalent", "unexplained",
                    "pattern_labels"):
            totals[key] += len(row[key])

        assert not row["missing"], (
            f"{identifier}: initializer-array targets without the name their array "
            f"gives them: {row['missing']}")
        assert not row["unbacked"], (
            f"{identifier}: derived names with no reference from their own slot: "
            f"{row['unbacked']}")
        assert not row["unexplained"], (
            f"{identifier}: names differ from stock with no proven equivalence: "
            f"{row['unexplained']}")

    assert len(rows) >= 20, f"only {len(rows)} corpus entries were scored"
    assert totals["slots"] >= 20, (
        f"only {totals['slots']} initializer slots were found; the corpus should "
        f"carry an init and a fini array per input")
    assert totals["equivalent"], "the proven-equivalent label class is untested"
    metrics = {
        "initializer.name.agreement": totals["equal"] / max(totals["compared"], 1),
        "initializer.name.missing": totals["missing"],
        "initializer.name.unbacked": totals["unbacked"],
        "initializer.name.unexplained": totals["unexplained"],
        "initializer.slots": totals["slots"],
        "initializer.name.equivalent": totals["equivalent"],
        "initializer.name.pattern_labels": totals["pattern_labels"],
    }
    for name, threshold in THRESHOLDS.items():
        assert metrics[name] <= threshold, f"{name} is {metrics[name]}"

    summary = (f"{len(rows)} corpus entries: {totals['slots']} initializer slots named "
               f"from their arrays, {totals['equal']}/{totals['compared']} names equal "
               f"to stock with {totals['equivalent']} proven-equivalent labels, "
               f"{totals['pattern_labels']} pinned pattern labels, "
               f"0 missing, 0 unbacked, 0 unexplained")
    if arguments.report:
        report.update(status="pass", passed=True, summary=summary, metrics=metrics,
                      totals=totals, corpus=rows)
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps(report, indent=2) + "\n")
    print(f"m5-010: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
