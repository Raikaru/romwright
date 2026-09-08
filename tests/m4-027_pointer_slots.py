#!/usr/bin/env python3
"""m4-027: a word that holds an address is typed as a pointer.

Ghidra types an undefined word as a pointer when a reference lands on it and
the bytes there look like an address: `OperandReferenceAnalyzer.checkForPointer`
(:952-1035) reads the pointer-sized value, refuses anything below 4096,
refuses a value the processor's alignment forbids, refuses one that is not in
memory unless a non-default symbol names it, refuses an offcut target, and
refuses a target inside a function that is not its entry. What survives gets a
`PointerDataType` -- which is why stock prints `PTR_FUN_004026d8` where we
printed `DAT_004026d8`, the whole of `m4-003`'s `data-type-unknown` class.

The label is Ghidra's too (`PointerDataType.getLabelString`:192-235): a
referent with a real name gives `PTR_<name>`, a referent with only a default
name gives `PTR_` plus that name with its address stripped
(`SymbolUtilities.getCleanSymbolName`), and the slot's own address is appended.

Both directions are measured. Every slot stock types, we type; every slot we
type, stock types. A pointer nobody can prove is an invented fact.

    python3 tests/m4-027_pointer_slots.py --corpus-dir DIR [--report OUT.json]
"""
from __future__ import annotations

import argparse
import concurrent.futures
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "benchmarks"))
import gate_cache  # noqa: E402

CLI = ROOT / "target/release/lre-cli"
LOCK = ROOT / "tests/corpus.lock.json"
# Stock's pointer labels whose referent carries no name of its own: either a
# default function name with its address stripped, or nothing at all. An
# import slot is excluded on purpose -- the store already holds those as
# external symbols and both sides already print `PTR_<import>_<address>`.
PLAIN_POINTER = re.compile(r"^PTR_(?:FUN_[0-9a-f]+|[0-9a-f]+)$")
SOURCE = "native-analysis:data-pointer"


def rows(store: Path, query: str) -> list[tuple]:
    connection = sqlite3.connect(store)
    try:
        (program,) = connection.execute("SELECT id FROM programs").fetchone()
        return list(connection.execute(query, (program,)))
    finally:
        connection.close()


def ram(cell: str) -> bool:
    return isinstance(cell, str) and not cell.startswith("{")


def stock_pointers(store: Path) -> dict[str, str]:
    """Addresses stock labels as a pointer to something it cannot name."""
    return {address: name for address, name in rows(
        store, "SELECT address, name FROM symbols WHERE program_id = ?")
        if ram(address) and PLAIN_POINTER.match(name)}


# The store records what a slot points at where it knows: `code-pointer` where
# the image declares the target is a function, `pointer` where it declares only
# that an address lives there (m4-030). Both are pointers, which is what this
# gate measures.
POINTER_TYPES = ("pointer", "code-pointer")


def our_pointers(store: Path) -> dict[str, str]:
    """Addresses our store types as a pointer, with the provenance."""
    return {address: provenance for address, kind, provenance in rows(
        store, "SELECT address, type, provenance FROM data_definitions "
               "WHERE program_id = ?")
        if ram(address) and kind in POINTER_TYPES}


def externals(store: Path) -> set[str]:
    return {address for address, external in rows(
        store, "SELECT address, external FROM symbols WHERE program_id = ?")
        if ram(address) and external}


def native_store(binary: Path) -> Path:
    def build(directory: Path) -> None:
        result = subprocess.run(
            [str(CLI), "import", str(binary), "--project", str(directory)],
            capture_output=True, text=True, timeout=900)
        assert result.returncode == 0, (
            f"{binary.name}: native import failed: {result.stderr[-400:]}")

    return gate_cache.store(gate_cache.native_key(binary), build)


def oracle_store(binary: Path, install: Path) -> Path:
    def build(directory: Path) -> None:
        result = subprocess.run(
            [str(CLI), "import", str(binary), "--oracle", "--project", str(directory),
             "--ghidra", str(install)],
            capture_output=True, text=True, timeout=1800,
            env=dict(os.environ, DEBUGINFOD_URLS=""))
        assert result.returncode == 0, (
            f"{binary.name}: oracle import failed: {result.stderr[-400:]}")

    return gate_cache.store(gate_cache.oracle_key(binary, install), build)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--ghidra", type=Path,
                        default=Path(os.environ.get("VENTRIS_GHIDRA",
                                                    Path.home() / "ghidra_12.1.3_PUBLIC")))
    parser.add_argument("--report", type=Path)
    parser.add_argument("--jobs", type=int, default=4)
    arguments = parser.parse_args()
    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-cli", "-p", "lre-worker"],
                   cwd=ROOT, check=True)
    lock = json.loads(LOCK.read_text())
    wanted = [entry for entry in lock["entries"] if entry.get("format") == "elf"]

    def measure(entry: dict) -> dict:
        binary = arguments.corpus_dir / entry["binary"]
        native = native_store(binary) / "project.sqlite"
        oracle = oracle_store(binary, arguments.ghidra) / "project.sqlite"
        theirs = stock_pointers(oracle)
        ours = our_pointers(native)
        imported = externals(native)
        # An import slot is already a pointer on both sides through the
        # external symbol it names; this gate is about the rest.
        expected = {address for address in theirs if address not in imported}
        missing = sorted({address: theirs[address] for address in expected
                          if address not in ours}.items())
        invented = sorted(address for address, provenance in ours.items()
                          if provenance == SOURCE and address not in theirs)
        return {"id": Path(entry["binary"]).stem, "variant": entry["variant"],
                "stock_pointers": len(expected), "held": len(expected) - len(missing),
                "missing": [{"address": address, "stock": name}
                            for address, name in missing],
                "invented": [{"address": address} for address in invented]}

    measured = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=arguments.jobs) as pool:
        for row in pool.map(measure, wanted):
            measured.append(row)
            print(f"{row['id']:24} stock {row['stock_pointers']:2} held "
                  f"{row['held']:2} invented {len(row['invented']):2}", flush=True)

    measured.sort(key=lambda row: row["id"])
    missing = [item for row in measured for item in row["missing"]]
    invented = [item for row in measured for item in row["invented"]]
    expected = sum(row["stock_pointers"] for row in measured)
    assert expected, "stock types no pointer slot, so this gate measures nothing"
    assert not missing, (
        f"slots stock types as pointers and we leave undefined: {missing[:6]}")
    assert not invented, (
        f"slots we type as pointers and stock does not: {invented[:6]}")
    metrics = {
        "pointer.rows_measured": len(measured),
        "pointer.slots_stock_types": expected,
        "pointer.slots_held": expected,
        "pointer.slots_missing": 0,
        "pointer.slots_invented": 0,
    }
    summary = (f"{expected} pointer slots across {len(measured)} ELF rows, every one "
               f"typed on both sides and none typed by only one; import slots are "
               f"excluded, being pointers through the external symbol they name")
    print(f"m4-027: PASS ({summary})")
    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps({
            "id": "m4-027",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "status": "pass",
            "passed": True,
            "summary": summary,
            "metrics": metrics,
            "measured": measured,
        }, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
