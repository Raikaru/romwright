#!/usr/bin/env python3
"""m4-026: a name is printed as the image declared it.

The store keeps what the image declared -- Ghidra's own x86 pattern file and
the ELF symbol table both call a stub `__i686.get_pc_thunk.bx` -- and m4-011
rendered such a name as a C identifier before handing it to the decompiler, on
the theory that a `.` printed into C is a member access. Stock does no such
thing: it prints the declared name verbatim, dots and all, and the only
difference on fifteen `m4-003` rows was our substitution.

A name still has to be an identifier where the decompiler *parses* it: the
patched `setFunctionSignature` runs a C declaration through
`parse_protopieces`, and the name inside that declaration is parsed. The name
handed alongside it is not (`native/ghidra-opt-sleigh.patch`:224-263), and
neither is a symbol name in the shell document or in a comment.

This gate measures both halves: every declared name a store holds is printed
as declared wherever stock prints it, and every function whose prototype the
decompiler parses still decompiles.

    python3 tests/m4-026_declared_names.py --corpus-dir DIR [--report OUT.json]
"""
from __future__ import annotations

import argparse
import concurrent.futures
from datetime import datetime, timezone
import hashlib
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


def identifier(name: str) -> str:
    """The rendering m4-011 applied: every character C cannot carry."""
    return re.sub(r"[^A-Za-z0-9_]", "_", name)


def rows(store: Path, query: str) -> list[tuple]:
    connection = sqlite3.connect(store)
    try:
        (program,) = connection.execute("SELECT id FROM programs").fetchone()
        return list(connection.execute(query, (program,)))
    finally:
        connection.close()


def declared_names(store: Path) -> dict[str, str]:
    """`address -> name` for every function and symbol name a store holds."""
    held = {}
    for entry, name in rows(
            store, "SELECT entry, name FROM functions WHERE program_id = ?"):
        held[entry] = name
    for address, name in rows(
            store, "SELECT address, name FROM symbols WHERE program_id = ?"):
        held.setdefault(address, name)
    return held


def prototype_functions(store: Path) -> list[str]:
    return [function for (function,) in rows(
        store, "SELECT function FROM prototypes WHERE program_id = ?")]


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


def texts(binary: Path, project: Path, addresses: list[str], oracle: bool,
          install: Path) -> dict[str, str]:
    joined = ",".join(addresses)
    digest = hashlib.sha256(joined.encode()).hexdigest()

    def build() -> dict:
        arguments = [str(CLI), "decompile-batch",
                     binary.name if oracle else str(binary), joined,
                     "--project", str(project)]
        if oracle:
            arguments += ["--oracle", "--ghidra", str(install)]
        result = subprocess.run(arguments, capture_output=True, text=True, timeout=1800,
                                env=dict(os.environ, DEBUGINFOD_URLS=""))
        assert result.returncode == 0, (
            f"{binary.name}: decompile failed: {result.stderr[-400:]}")
        return json.loads(result.stdout)

    key = (gate_cache.oracle_key(binary, install, artifact="decompile-batch",
                                 addresses=digest)
           if oracle else
           gate_cache.native_key(binary, artifact="decompile-batch", addresses=digest))
    return gate_cache.document(key, build)


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
        native = native_store(binary)
        oracle = oracle_store(binary, arguments.ghidra)
        held = declared_names(native / "project.sqlite")
        # Only the names C cannot spell can be rendered away, so they are the
        # measurement; every other name is compared by `m4-003` already.
        unspellable = sorted({name for name in held.values()
                              if identifier(name) != name})
        addresses = sorted(set(held) & set(declared_names(oracle / "project.sqlite")))
        substituted, absent = [], []
        parsed = prototype_functions(native / "project.sqlite")
        empty = []
        if addresses:
            mine = texts(binary, native, addresses, False, arguments.ghidra)
            stock = texts(binary, oracle, addresses, True, arguments.ghidra)
            for address in addresses:
                ours_text, stock_text = mine.get(address, ""), stock.get(address, "")
                for name in unspellable:
                    if name not in stock_text:
                        continue
                    if name not in ours_text:
                        absent.append({"address": address, "name": name})
                    if identifier(name) in ours_text:
                        substituted.append({"address": address, "name": name,
                                            "printed": identifier(name)})
            # A prototype the decompiler parses must still produce a body:
            # the parser reads the name inside the declaration.
            for function in parsed:
                if function in mine and not mine[function].strip():
                    empty.append({"address": function})
        return {"id": Path(entry["binary"]).stem, "variant": entry["variant"],
                "unspellable": unspellable, "compared": len(addresses),
                "prototypes_parsed": len(parsed), "absent": absent,
                "substituted": substituted, "empty": empty}

    measured = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=arguments.jobs) as pool:
        for row in pool.map(measure, wanted):
            measured.append(row)
            print(f"{row['id']:24} declared-only names {len(row['unspellable'])} "
                  f"functions {row['compared']:3} prototypes "
                  f"{row['prototypes_parsed']}", flush=True)

    measured.sort(key=lambda row: row["id"])
    absent = [item for row in measured for item in row["absent"]]
    substituted = [item for row in measured for item in row["substituted"]]
    empty = [item for row in measured for item in row["empty"]]
    carriers = [row for row in measured if row["unspellable"]]
    assert carriers, (
        "no corpus row holds a name C cannot spell, so this gate measures nothing")
    assert not substituted, (
        f"a declared name was printed with its characters replaced: {substituted[:4]}")
    assert not absent, (
        f"stock printed a declared name we did not: {absent[:4]}")
    assert not empty, (
        f"a function whose prototype the decompiler parses produced no body: {empty[:4]}")
    names = sorted({name for row in measured for name in row["unspellable"]})
    metrics = {
        "names.rows_measured": len(measured),
        "names.rows_holding_unspellable": len(carriers),
        "names.unspellable_declared": len(names),
        "names.printed_with_substitution": 0,
        "names.printed_by_stock_and_not_by_us": 0,
        "names.prototypes_parsed": sum(row["prototypes_parsed"] for row in measured),
    }
    summary = (f"{len(names)} declared names C cannot spell ({', '.join(names)}) are "
               f"printed as declared on {len(carriers)} of {len(measured)} ELF rows, "
               f"with {sum(row['prototypes_parsed'] for row in measured)} parsed "
               f"prototypes still producing bodies")
    print(f"m4-026: PASS ({summary})")
    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps({
            "id": "m4-026",
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
