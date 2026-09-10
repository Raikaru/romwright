#!/usr/bin/env python3
"""m4-028: a mangled name also carries the name it was mangled from.

The image names a slot `_ZTIi` -- a COPY relocation carries that name from
libstdc++ -- and both stores record it. Stock then demangles it and applies a
second symbol at the same address: `GnuDemanglerParser.getSpecialPrefixHandler`
(:502-522) routes `typeinfo for int` to its `AddressTableHandler`, which takes
the prefix up to its last space as the name (`typeinfo`) and the demangled type
as the namespace (`int`, :1877-1913), and `DemangledAddressTable.applyTo`
(:74-90) applies it with `setPrimary` true and `SourceType.ANALYSIS`. The
primary symbol is what the decompiler prints, which is why stock's text reads
`&typeinfo` where ours reads `&_ZTIi`.

Every symbol that is not `DEFAULT` and is parented globally is attempted
(`AbstractDemanglerAnalyzer.demangleSymbols` :124-171, `skipSymbol` :205-233),
after `SymbolUtilities.getCleanSymbolName` strips any address suffix
(:333-335).

The gate measures the store, not the text: for every address where stock holds
both a mangled name and an `ANALYSIS` name it derived from it, our store must
hold the same derived name at the same address with its own provenance, and we
must invent none. The rendering is measured by `m4-003`, whose `mangled-name`
class exists for exactly these rows.

Usage:
    python3 tests/m4-028_demangled_names.py --corpus-dir DIR [--report OUT.json]
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
SOURCE = "native-analysis:demangle"
# Itanium C++ ABI mangled names start `_Z`; nothing else in these images does.
MANGLED_PREFIX = "_Z"


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


def stock_derived(store: Path) -> dict[str, str]:
    """Names stock derived from a mangled name at the same address."""
    held = symbols(store)
    mangled = {address for address, name, _ in held if name.startswith(MANGLED_PREFIX)}
    return {address: name for address, name, source in held
            if address in mangled and source == "ANALYSIS"
            and not name.startswith(MANGLED_PREFIX)}


def our_derived(store: Path) -> dict[str, str]:
    return {address: name for address, name, source in symbols(store)
            if source == SOURCE}


def our_mangled(store: Path) -> set[str]:
    return {address for address, name, _ in symbols(store)
            if name.startswith(MANGLED_PREFIX)}


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
    matrix = set(lock["oracle_matrix"]["architectures"])
    wanted = [entry for entry in lock["entries"]
              if entry.get("format") == "elf" and entry["architecture"] in matrix]

    def measure(entry: dict) -> dict:
        binary = arguments.corpus_dir / entry["binary"]
        native = native_store(binary) / "project.sqlite"
        oracle = oracle_store(binary, arguments.ghidra) / "project.sqlite"
        theirs = stock_derived(oracle)
        ours = our_derived(native)
        kept = our_mangled(native)
        missing = sorted({address: name for address, name in theirs.items()
                          if ours.get(address) != name}.items())
        invented = sorted({address: name for address, name in ours.items()
                           if theirs.get(address) != name}.items())
        # The mangled name is evidence, not a casualty: closing this class must
        # not cost the name the relocation carries.
        dropped = sorted(address for address in theirs if address not in kept)
        return {"id": Path(entry["binary"]).stem, "variant": entry["variant"],
                "stock_derives": len(theirs), "held": len(theirs) - len(missing),
                "missing": [{"address": address, "stock": name}
                            for address, name in missing],
                "invented": [{"address": address, "ours": name}
                             for address, name in invented],
                "dropped_mangled": dropped}

    measured = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=arguments.jobs) as pool:
        for row in pool.map(measure, wanted):
            measured.append(row)
            print(f"{row['id']:24} stock derives {row['stock_derives']:2} held "
                  f"{row['held']:2} invented {len(row['invented']):2}", flush=True)

    measured.sort(key=lambda row: row["id"])
    missing = [item for row in measured for item in row["missing"]]
    invented = [item for row in measured for item in row["invented"]]
    dropped = [address for row in measured for address in row["dropped_mangled"]]
    expected = sum(row["stock_derives"] for row in measured)
    assert expected, "stock derives no name from a mangled one, so this gate measures nothing"
    assert not missing, (
        f"names stock derives from a mangled name and we do not hold: {missing[:6]}")
    assert not invented, (
        f"names we derive and stock does not: {invented[:6]}")
    assert not dropped, (
        f"addresses where the mangled name itself was lost: {dropped[:6]}")
    metrics = {
        "demangle.rows_measured": len(measured),
        "demangle.names_stock_derives": expected,
        "demangle.names_held": expected,
        "demangle.names_missing": 0,
        "demangle.names_invented": 0,
        "demangle.mangled_names_kept": expected,
    }
    summary = (f"{expected} names stock derives from a mangled name across "
               f"{len(measured)} ELF rows, every one held at the same address with "
               f"the same text, none invented, and every mangled name kept beside "
               f"the name derived from it")
    print(f"m4-028: PASS ({summary})")
    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps({
            "id": "m4-028",
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
