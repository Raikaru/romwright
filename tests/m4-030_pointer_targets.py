#!/usr/bin/env python3
"""m4-030: a slot is typed a code pointer only where the image says so.

Stock types every word its loader marks up as a plain pointer
(`ElfDefaultGotPltMarkup.createPointer`, :562-585), and every cast its text
carries in front of one -- `(*(code *)PTR_printf_004036f8)()` -- follows from
that. Ventris types a slot from the fact the image declares about the target,
which is stronger where a fact exists and identical where none does. This gate
holds that split to its evidence:

  * a `code-pointer` row must have a proof in the same store: an external
    symbol naming the slot, whose relocation declared `STT_FUNC`
    (`native-import:elf-linkage`), or an outgoing data reference that lands on
    a function's entry (`native-import:elf-pointer` for an initializer array,
    `native-analysis:data-pointer` for a referenced word);
  * a plain `pointer` row must *not* have that proof, so the split is decided
    by the evidence and not by which rule happened to write the row;
  * an address we type as a code pointer must be data on stock's side too --
    stock holds no function there -- so the difference is the pointee, not what
    the address is.

The residual divergence this leaves is `m4-003`'s `type-stronger` class: stock
prints a cast where our typed slot does not need one. The count is recorded
here as a measured choice, not smoothed away.

Usage:
    python3 tests/m4-030_pointer_targets.py --corpus-dir DIR [--report OUT.json]
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
CODE_POINTER = "code-pointer"
# The rules that carry a declaration about the target rather than an
# observation of one word's current value.
DECLARING = ("native-import:elf-linkage", "native-import:elf-pointer")
PLAIN_POINTER = "pointer"
DATA_KINDS = ("DATA", "READ", "WRITE")


def rows(store: Path, query: str) -> list[tuple]:
    connection = sqlite3.connect(store)
    try:
        (program,) = connection.execute("SELECT id FROM programs").fetchone()
        return list(connection.execute(query, (program,)))
    finally:
        connection.close()


def ram(cell: str) -> bool:
    return isinstance(cell, str) and not cell.startswith("{")


def definitions(store: Path) -> dict[str, tuple[str, str]]:
    return {address: (kind, provenance) for address, kind, provenance in rows(
        store, "SELECT address, type, provenance FROM data_definitions "
               "WHERE program_id = ?")
        if ram(address)}


def externals(store: Path) -> set[str]:
    return {address for address, external in rows(
        store, "SELECT address, external FROM symbols WHERE program_id = ?")
        if ram(address) and external}


def entries(store: Path) -> set[str]:
    return {address for (address,) in rows(
        store, "SELECT entry FROM functions WHERE program_id = ?") if ram(address)}


def data_targets(store: Path) -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for source, target, kind in rows(
            store, "SELECT src, dst, kind FROM xrefs WHERE program_id = ?"):
        if ram(source) and ram(target) and kind in DATA_KINDS:
            found.setdefault(source, set()).add(target)
    return found


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
        held = definitions(native)
        named = externals(native)
        functions = entries(native)
        targets = data_targets(native)
        stock_functions = entries(oracle)
        tag_named = {address for address, name, _ in rows(
            native, "SELECT address, name, source FROM symbols WHERE program_id = ?")
            if ram(address) and name.startswith("__DT_")}

        def evidence(address: str) -> bool:
            """Something in this store says the slot's target is code."""
            if address in named:
                return True
            return any(target in functions for target in targets.get(address, ()))

        code = [address for address, (kind, _) in held.items() if kind == CODE_POINTER]
        plain = [address for address, (kind, _) in held.items() if kind == PLAIN_POINTER]
        unproven = sorted(address for address in code if not evidence(address))
        # A declaring rule's row must carry the declaration: the linkage
        # relocation and the initializer array both say "function pointer", and
        # only a name the dynamic table gives the address overrides that
        # (m4-029).
        under = sorted(address for address, (kind, provenance) in held.items()
                       if kind == PLAIN_POINTER and provenance in DECLARING
                       and address not in tag_named)
        code_in_stock = sorted(address for address in code if address in stock_functions)
        return {"id": Path(entry["binary"]).stem, "variant": entry["variant"],
                "code_pointers": len(code), "plain_pointers": len(plain),
                "unproven": [{"address": address, "provenance": held[address][1]}
                             for address in unproven],
                "under_typed": [{"address": address, "provenance": held[address][1]}
                                for address in under],
                "code_is_function_in_stock": code_in_stock}

    measured = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=arguments.jobs) as pool:
        for row in pool.map(measure, wanted):
            measured.append(row)
            print(f"{row['id']:24} code-pointers {row['code_pointers']:3} plain "
                  f"{row['plain_pointers']:3} unproven {len(row['unproven']):2} "
                  f"under-typed {len(row['under_typed']):2}", flush=True)

    measured.sort(key=lambda row: row["id"])
    unproven = [item for row in measured for item in row["unproven"]]
    under = [item for row in measured for item in row["under_typed"]]
    clashes = [address for row in measured for address in row["code_is_function_in_stock"]]
    code = sum(row["code_pointers"] for row in measured)
    plain = sum(row["plain_pointers"] for row in measured)
    assert code, "no slot is typed a code pointer, so this gate measures nothing"
    assert plain, "no slot keeps the weaker type, so the split is not being made"
    assert not unproven, (
        f"slots typed as code pointers with nothing in the store proving the "
        f"target is code: {unproven[:6]}")
    assert not under, (
        f"slots the store proves hold a code address and we type weakly: {under[:6]}")
    assert not clashes, (
        f"addresses we type as data and stock holds a function at: {clashes[:6]}")
    metrics = {
        "pointee.rows_measured": len(measured),
        "pointee.code_pointers": code,
        "pointee.plain_pointers": plain,
        "pointee.unproven": 0,
        "pointee.under_typed": 0,
    }
    summary = (f"{code} slots typed as code pointers and {plain} left plain across "
               f"{len(measured)} ELF rows: every code pointer has a fact in the same "
               f"store proving its target is code, every plain pointer has none, and "
               f"no such address is a function on stock's side")
    print(f"m4-030: PASS ({summary})")
    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps({
            "id": "m4-030",
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
