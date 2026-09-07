#!/usr/bin/env python3
"""m8-001: PE32+ function recovery scored against the compiler's own truth.

The support matrix reads "in progress" for PE32+ because nothing scores it.
`tests/m1-005_pe_relocs.sh` prints a recall number for one fixture and gates
neither it nor anything derived from it, and `m3-001` -- which does gate
recall -- reads DWARF through `readelf`, which refuses a PE file outright.

Truth here is the same definition `m3-001` uses for ELF, read from the PE
container instead: concrete `DW_TAG_subprogram` entries with a low PC,
restricted to executable sections. The committed fixtures are MinGW-built, so
they carry DWARF in a PE; the scored input is a stripped copy of each, made
here rather than committed.

The gate requires, per x86-64 fixture:

  * `pe.dwarf.fn.recall >= 0.98`, the bar `m3-001` sets for ELF;
  * `pe.dwarf.fn.unattributed == 0`: every recovered entry is described by
    DWARF, named by a symbol in the unstripped fixture, proved a thunk by the
    store, or bounded by a `RUNTIME_FUNCTION` in the exception directory. An
    entry with none of those is invented;
  * at least one `native-import:pe-unwind` reference, so recall is credited to
    the exception directory rather than to luck.

`tiny_pe32.exe` is measured and recorded, not gated: PE32 x86 carries no
exception directory (`IMAGE_DIRECTORY_ENTRY_EXCEPTION` is empty), so its
recall has no unwind evidence behind it yet.

Usage:
    python3 tests/m8-001_pe_unwind.py [--report OUT.json]
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from gen_corpus import parse_pe_info  # noqa: E402

RECALL_THRESHOLD = 0.98
GATED = ["tiny_pe.exe", "dispatch.exe"]
RECORDED = ["tiny_pe32.exe"]
TAG = re.compile(r"DW_TAG_\w+")
NAME = re.compile(r'DW_AT_name\s*\("(.*?)"\)')
LOW_PC = re.compile(r"DW_AT_low_pc\s*\((0x[0-9a-f]+)\)")


def image_base(data: bytes) -> int:
    """The linker's chosen base; DWARF in a PE records absolute addresses."""
    header = struct.unpack_from("<I", data, 0x3C)[0]
    optional = header + 24
    magic = struct.unpack_from("<H", data, optional)[0]
    if magic == 0x20B:
        return struct.unpack_from("<Q", data, optional + 24)[0]
    return struct.unpack_from("<I", data, optional + 28)[0]


def data_directory(data: bytes, index: int) -> tuple[int, int]:
    header = struct.unpack_from("<I", data, 0x3C)[0]
    optional = header + 24
    magic = struct.unpack_from("<H", data, optional)[0]
    start, count_at = ((optional + 112, optional + 108) if magic == 0x20B
                       else (optional + 96, optional + 92))
    count = struct.unpack_from("<I", data, count_at)[0]
    if index >= count:
        return 0, 0
    return struct.unpack_from("<II", data, start + index * 8)


def runtime_functions(data: bytes) -> list[tuple[int, int]]:
    """(begin, end) image addresses from IMAGE_DIRECTORY_ENTRY_EXCEPTION."""
    rva, size = data_directory(data, 3)
    if not rva or not size:
        return []
    base = image_base(data)
    sections = parse_pe_info(data)["sections"]
    holder = next((section for section in sections
                   if section["vaddr"] <= rva < section["vaddr"] + section["vsize"]), None)
    if holder is None:
        return []
    offset = holder["raw_off"] + (rva - holder["vaddr"])
    bounds = []
    for index in range(size // 12):
        begin, end, _ = struct.unpack_from("<III", data, offset + index * 12)
        if begin:
            bounds.append((base + begin, base + end))
    return bounds


def dwarf_truth(binary: Path) -> tuple[dict[int, str | None], int]:
    """Concrete subprograms inside executable sections, and how many were not."""
    text = subprocess.run(["llvm-dwarfdump", "--debug-info", str(binary)],
                          capture_output=True, text=True, check=True).stdout
    found: dict[int, str | None] = {}
    tag = name = low = None
    for line in text.splitlines():
        if "DW_TAG_" in line:
            if tag == "DW_TAG_subprogram" and low is not None:
                found[low] = name
            match = TAG.search(line)
            tag, name, low = (match.group(0) if match else None), None, None
        elif "DW_AT_name" in line:
            match = NAME.search(line)
            name = match.group(1) if match else name
        elif "DW_AT_low_pc" in line:
            match = LOW_PC.search(line)
            low = int(match.group(1), 16) if match else low
    if tag == "DW_TAG_subprogram" and low is not None:
        found[low] = name
    data = binary.read_bytes()
    base = image_base(data)
    ranges = [(base + section["vaddr"], section["vsize"])
              for section in parse_pe_info(data)["sections"] if section["exec"]]
    mapped = {address: symbol for address, symbol in found.items()
              if any(start <= address < start + size for start, size in ranges)}
    return mapped, len(found) - len(mapped)


def symbol_addresses(binary: Path) -> set[int]:
    output = subprocess.run(["llvm-nm", "--defined-only", str(binary)],
                            capture_output=True, text=True).stdout
    addresses = set()
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 3:
            try:
                addresses.add(int(fields[0], 16))
            except ValueError:
                continue
    return addresses


def native_import(binary: Path, work: Path) -> tuple[set[int], set[int], set[str]]:
    project = work / f"{binary.stem}-project"
    result = subprocess.run(
        [str(ROOT / "target/release/lre-cli"), "import", str(binary),
         "--name", "scored", "--project", str(project)],
        cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 0, f"native import failed: {result.stderr.strip()}"
    store = sqlite3.connect(project / "project.sqlite")
    entries = {int(row[0], 16) for row in store.execute("SELECT entry FROM functions")}
    thunks = {int(row[0], 16) for row in store.execute("SELECT function FROM thunks")}
    provenance = {row[0] for row in store.execute("SELECT DISTINCT provenance FROM xrefs")}
    return entries, thunks, provenance


def score(fixture: Path, work: Path) -> dict:
    stripped = work / f"{fixture.stem}.stripped{fixture.suffix}"
    shutil.copy2(fixture, stripped)
    subprocess.run(["llvm-strip", "--strip-all", str(stripped)], check=True)
    assert not symbol_addresses(stripped), f"{fixture.name}: the scored copy kept symbols"

    truth, unmapped = dwarf_truth(fixture)
    assert truth, f"{fixture.name}: no DWARF subprograms in an executable section"
    observed, thunks, provenance = native_import(stripped, work)
    symbols = symbol_addresses(fixture)
    bounds = runtime_functions(fixture.read_bytes())

    matched = set(truth) & observed
    missing = sorted(set(truth) - observed)
    undescribed = observed - set(truth)
    unattributed = sorted(
        address for address in undescribed
        if address not in symbols and address not in thunks
        and not any(begin <= address < end for begin, end in bounds))
    row = {
        "id": fixture.name,
        "truth": len(truth),
        "truth_outside_code": unmapped,
        "observed": len(observed),
        "runtime_functions": len(bounds),
        "metrics": {
            "pe.dwarf.fn.recall": len(matched) / len(truth),
            "pe.dwarf.fn.unattributed": len(unattributed),
            "pe.functions": len(observed),
            "pe.undescribed": len(undescribed),
        },
        "unwind_provenance": "native-import:pe-unwind" in provenance,
    }
    if missing:
        row["missing"] = [f"{address:08x} {truth[address] or '?'}" for address in missing[:12]]
    if unattributed:
        row["unattributed"] = [f"{address:08x}" for address in unattributed[:12]]
    return row


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-cli"],
                   cwd=ROOT, check=True)
    rows, recorded = [], []
    with tempfile.TemporaryDirectory(prefix="m8-001-") as directory:
        work = Path(directory)
        for name in GATED:
            fixture = ROOT / "tests/fixtures-src" / name
            assert fixture.is_file(), f"missing committed fixture {name}"
            rows.append(score(fixture, work))
        for name in RECORDED:
            fixture = ROOT / "tests/fixtures-src" / name
            if fixture.is_file():
                recorded.append(score(fixture, work))

    for row in rows:
        recall = row["metrics"]["pe.dwarf.fn.recall"]
        assert recall >= RECALL_THRESHOLD, (
            f"{row['id']}: pe.dwarf.fn.recall {recall:.4f} < {RECALL_THRESHOLD}, "
            f"{len(row.get('missing', []))} shown of "
            f"{row['truth'] - int(recall * row['truth'])} missing: "
            f"{row.get('missing', [])[:6]}")
        assert row["metrics"]["pe.dwarf.fn.unattributed"] == 0, (
            f"{row['id']}: {row['metrics']['pe.dwarf.fn.unattributed']} recovered "
            f"entries have no evidence: {row.get('unattributed', [])[:6]}")
        assert row["unwind_provenance"], (
            f"{row['id']}: no native-import:pe-unwind reference, so the "
            f"exception directory is not what recovered these functions")

    totals = {
        "pe.dwarf.fn.recall": (sum(row["metrics"]["pe.dwarf.fn.recall"] * row["truth"]
                                   for row in rows)
                               / sum(row["truth"] for row in rows)),
        "pe.dwarf.fn.unattributed": sum(row["metrics"]["pe.dwarf.fn.unattributed"]
                                        for row in rows),
        "pe.runtime_functions": sum(row["runtime_functions"] for row in rows),
    }
    summary = (f"{len(rows)} gated PE32+ fixtures: recall "
               f"{totals['pe.dwarf.fn.recall']:.4f} over "
               f"{sum(row['truth'] for row in rows)} DWARF functions, "
               f"{totals['pe.dwarf.fn.unattributed']} unattributed, "
               f"{totals['pe.runtime_functions']} runtime-function records")
    if recorded:
        summary += ("; recorded without a gate: " + ", ".join(
            f"{row['id']} recall {row['metrics']['pe.dwarf.fn.recall']:.4f}"
            for row in recorded))

    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps({
            "id": "m8-001",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "status": "pass",
            "passed": True,
            "summary": summary,
            "thresholds": {"pe.dwarf.fn.recall": RECALL_THRESHOLD,
                           "pe.dwarf.fn.unattributed": 0},
            "totals": totals,
            "gated": rows,
            "recorded": recorded,
        }, indent=1) + "\n")
    print(f"m8-001: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
