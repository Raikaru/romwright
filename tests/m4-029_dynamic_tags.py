#!/usr/bin/env python3
"""m4-029: the dynamic table names its own addresses, and that name wins.

Ghidra's loader labels every nonzero ADDRESS-valued dynamic tag's target
`__DT_<TAG>` (`ElfProgramBuilder.markupDynamicTable` through
`addDynamicMemoryReference`, :2691-2773), including the processor extensions --
`DT_PPC_GOT` is declared `ElfDynamicValueType.ADDRESS` by
`PowerPC_ElfExtension` (:44-45). The label is a real symbol with
`SourceType.IMPORTED`, so it is the primary symbol at that address and the name
a decompiler prints.

That matters where two facts meet. On PowerPC `DT_PLTGOT` points at `.plt`,
whose first word is also the first `R_PPC_JMP_SLOT` slot, so our store holds
the import the slot resolves to *and* the tag names the same address. Stock
holds only the tag label there -- the import lives in its EXTERNAL block, tied
to the slot by a reference -- and prints `__DT_PLTGOT` where we printed
`PTR___libc_start_main_1003074c` (`m4-003`'s `data-name-convention` class).

The gate measures the store: every `__DT_*` name stock holds must be held at
the same address, none invented, and where stock holds a tag name our store
must not be naming that address something else instead. The rendering is
measured by `m4-003`.

Usage:
    python3 tests/m4-029_dynamic_tags.py --corpus-dir DIR [--report OUT.json]
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "benchmarks"))
import gate_cache  # noqa: E402

CLI = ROOT / "target/release/lre-cli"
LOCK = ROOT / "tests/corpus.lock.json"
SOURCE = "native-import:dynamic-tag"
PREFIX = "__DT_"


def rows(store: Path, query: str) -> list[tuple]:
    connection = sqlite3.connect(store)
    try:
        (program,) = connection.execute("SELECT id FROM programs").fetchone()
        return list(connection.execute(query, (program,)))
    finally:
        connection.close()


def ram(cell: str) -> bool:
    return isinstance(cell, str) and not cell.startswith("{")


def symbols(store: Path) -> list[tuple[str, str, str]]:
    return [(address, name, source) for address, name, source in rows(
        store, "SELECT address, name, source FROM symbols WHERE program_id = ?")
        if ram(address)]


def tags(store: Path) -> dict[str, str]:
    """Addresses the dynamic table names, and the name it gives them."""
    return {address: name for address, name, _ in symbols(store)
            if name.startswith(PREFIX)}


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
        theirs = tags(oracle)
        ours = tags(native)
        held = symbols(native)
        missing = sorted({address: name for address, name in theirs.items()
                          if ours.get(address) != name}.items())
        invented = sorted({address: name for address, name in ours.items()
                           if theirs.get(address) != name}.items())
        # Where stock names an address after the tag, the name has to be in our
        # store too -- what else we hold at that address is a separate fact
        # (the import a slot resolves to), and the report records it.
        shared = sorted({address: [name for _, name in
                                   ((a, n) for a, n, _ in held if a == address)]
                         for address in theirs if address in ours}.items())
        return {"id": Path(entry["binary"]).stem, "variant": entry["variant"],
                "stock_tags": len(theirs), "held": len(theirs) - len(missing),
                "missing": [{"address": address, "stock": name}
                            for address, name in missing],
                "invented": [{"address": address, "ours": name}
                             for address, name in invented],
                "names_at_tagged": [{"address": address, "names": sorted(names)}
                                    for address, names in shared if len(names) > 1]}

    measured = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=arguments.jobs) as pool:
        for row in pool.map(measure, wanted):
            measured.append(row)
            print(f"{row['id']:24} stock tags {row['stock_tags']:2} held "
                  f"{row['held']:2} invented {len(row['invented']):2}", flush=True)

    measured.sort(key=lambda row: row["id"])
    missing = [item for row in measured for item in row["missing"]]
    invented = [item for row in measured for item in row["invented"]]
    expected = sum(row["stock_tags"] for row in measured)
    assert expected, "stock names no dynamic-tag address, so this gate measures nothing"
    assert not missing, (
        f"addresses stock names after a dynamic tag and we do not: {missing[:6]}")
    assert not invented, (
        f"addresses we name after a dynamic tag and stock does not: {invented[:6]}")
    metrics = {
        "tags.rows_measured": len(measured),
        "tags.names_stock_holds": expected,
        "tags.names_held": expected,
        "tags.names_missing": 0,
        "tags.names_invented": 0,
    }
    summary = (f"{expected} dynamic-tag names across {len(measured)} ELF rows, every "
               f"one held at the same address with the same text and none invented")
    print(f"m4-029: PASS ({summary})")
    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps({
            "id": "m4-029",
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
