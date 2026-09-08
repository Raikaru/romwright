#!/usr/bin/env python3
"""m4-025: a declaration is applied in the language's own type names.

The pinned C library archive declares `long strtol(char **, ...)`. Stock
applies it on every language: its Java side resolves the declaration against
the program's *data organization*, so `long` is four bytes on a 32-bit target
and eight on a 64-bit one, and the decompiler is handed a type rather than a
sentence. We hand the decompiler C text, and its parser resolves a type name
through `TypeFactoryGhidra::findById`, which asks the client for any name it
does not already hold (`typegrp_ghidra.cc`:20-36). Answering that question
from the compiler spec's `<data_organization>` is what this gate measures: a
32-bit language's `coretypes.xml` names `longlong` and no `long`, and until
the client could answer for `long`, `strtol` was refused on every 32-bit row
while stock applied it.

Three claims, per corpus row:

* every prototype stock recorded for a function we know is recorded by us,
  with the same declared types -- the archive's spelling, not a substitution;
* the stub's decompiled text is token-identical to stock's, which is the only
  proof the applied type reached the decompiler;
* a declaration whose types the language cannot express (`FILE *`) is still
  refused rather than guessed.

    python3 tests/m4-025_declaration_types.py --corpus-dir DIR [--report OUT.json]
"""
from __future__ import annotations

import argparse
import concurrent.futures
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "benchmarks"))
import gate_cache  # noqa: E402

CLI = ROOT / "target/release/lre-cli"
LOCK = ROOT / "tests/corpus.lock.json"
ARCHIVE = ROOT / "oracle/library-prototypes-v1/generic_clib_64.json"
# A declaration nothing can express: `FILE` is an opaque struct no language
# declares a size for, so applying it would be a guess.
UNEXPRESSIBLE = "FILE"


def parity_module():
    """`m4-003`'s tokenizer, so "identical" means the same thing here."""
    specification = importlib.util.spec_from_file_location(
        "m4_003", ROOT / "tests/m4-003_language_parity.py")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def rows(store: Path, query: str) -> list[tuple]:
    connection = sqlite3.connect(store)
    try:
        (identifier,) = connection.execute("SELECT id FROM programs").fetchone()
        return list(connection.execute(query, (identifier,)))
    finally:
        connection.close()


def prototypes(store: Path) -> dict[str, str]:
    return {address: signature for address, signature in rows(
        store, "SELECT function, signature FROM prototypes WHERE program_id = ?")}


def functions(store: Path) -> set[str]:
    return {entry for (entry,) in rows(
        store, "SELECT entry FROM functions WHERE program_id = ?")}


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


def declared(signature: str) -> tuple[str, tuple[str, ...]]:
    """A signature as content: the return type and the parameter types."""
    head, _, rest = signature.partition("(")
    return_type = head.rsplit(" ", 1)[0].strip()
    inner = rest.rsplit(")", 1)[0].strip()
    if inner in ("", "void"):
        return return_type, ()
    parameters = []
    for part in inner.split(","):
        part = part.strip()
        if part == "...":
            parameters.append(part)
            continue
        parameters.append(part.rsplit(" ", 1)[0].strip())
    return return_type, tuple(parameters)


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
    assert ARCHIVE.is_file(), f"the pinned declaration archive is missing: {ARCHIVE}"
    archive = json.loads(ARCHIVE.read_text())["functions"]
    unexpressible = sorted(
        name for name, declaration in archive.items()
        if UNEXPRESSIBLE in declaration["return_type"]
        or any(UNEXPRESSIBLE in parameter["type"]
               for parameter in declaration["parameters"]))
    assert unexpressible, (
        f"the archive declares nothing with {UNEXPRESSIBLE}, so the control proves nothing")

    parity = parity_module()
    lock = json.loads(LOCK.read_text())
    wanted = [entry for entry in lock["entries"] if entry.get("format") == "elf"]

    def measure(entry: dict) -> dict:
        binary = arguments.corpus_dir / entry["binary"]
        native = native_store(binary)
        oracle = oracle_store(binary, arguments.ghidra)
        ours = prototypes(native / "project.sqlite")
        theirs = prototypes(oracle / "project.sqlite")
        known = functions(native / "project.sqlite")
        # Stock records a declaration on the import slot as well as on the
        # stub; a slot is not a function in our model, so the comparison is
        # over the functions both stores know.
        expected = {address: signature for address, signature in theirs.items()
                    if address in known}
        differing, missing = [], []
        for address, signature in sorted(expected.items()):
            held = ours.get(address)
            if held is None:
                missing.append({"address": address, "stock": signature})
            elif declared(held) != declared(signature):
                differing.append({"address": address, "stock": signature, "ours": held})
        guessed = sorted(address for address, signature in ours.items()
                         if UNEXPRESSIBLE in signature)
        # Every declared prototype has to reach the decompiler, or the type
        # was recorded and never used.
        divergent = []
        if expected:
            addresses = sorted(expected)
            mine = texts(binary, native, addresses, False, arguments.ghidra)
            stock = texts(binary, oracle, addresses, True, arguments.ghidra)
            for address in addresses:
                if parity.tokens(mine.get(address, "")) != parity.tokens(
                        stock.get(address, "")):
                    divergent.append({
                        "address": address,
                        "ours": " ".join(parity.tokens(mine.get(address, "")))[:200],
                        "stock": " ".join(parity.tokens(stock.get(address, "")))[:200]})
        return {"id": Path(entry["binary"]).stem, "variant": entry["variant"],
                "declared_by_stock": len(expected), "held": len(expected) - len(missing),
                "missing": missing, "differing": differing, "guessed": guessed,
                "divergent": divergent}

    measured = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=arguments.jobs) as pool:
        for row in pool.map(measure, wanted):
            measured.append(row)
            print(f"{row['id']:24} declared {row['declared_by_stock']:2} held "
                  f"{row['held']:2} identical "
                  f"{row['declared_by_stock'] - len(row['divergent']):2}", flush=True)

    measured.sort(key=lambda row: row["id"])
    missing = [item for row in measured for item in row["missing"]]
    differing = [item for row in measured for item in row["differing"]]
    guessed = [item for row in measured for item in row["guessed"]]
    divergent = [item for row in measured for item in row["divergent"]]
    assert not missing, f"declarations stock applied and we did not: {missing[:4]}"
    assert not differing, f"declarations we applied with other types: {differing[:4]}"
    assert not guessed, (
        f"a declaration whose types the language cannot express was applied: {guessed[:4]}")
    assert not divergent, (
        f"a declared prototype did not reach the decompiler: {divergent[:2]}")
    declarations = sum(row["declared_by_stock"] for row in measured)
    assert declarations, "no row carries a declared prototype, so nothing is measured"
    metrics = {
        "declaration.rows_measured": len(measured),
        "declaration.declared_by_stock": declarations,
        "declaration.held": declarations,
        "declaration.token_identical_stubs": declarations,
        "declaration.applied_with_other_types": 0,
        "declaration.unexpressible_declarations_refused": len(unexpressible),
    }
    summary = (f"{declarations} declared prototypes across {len(measured)} ELF rows, "
               f"each recorded with the archive's own types and each stub "
               f"token-identical to stock's; {len(unexpressible)} declarations the "
               f"language cannot express stay refused")
    print(f"m4-025: PASS ({summary})")
    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps({
            "id": "m4-025",
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
