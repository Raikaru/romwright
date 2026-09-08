#!/usr/bin/env python3
"""m4-009: an import the C library declares gets its declared prototype.

`missing-external-prototype` is the largest divergence class `m4-003` measures
(18 of 56 functions). The cause is one missing fact: the store names imports
and holds no signature for them, so a call decompiles as

    printf(s_sum___d__002004d0, uVar1)

where the oracle prints `printf("sum: %d\\n",(ulong)uVar1)` -- with a `char *`
first parameter the same string renders as a literal.

The declarations come from the pinned install's own C library type archive
(`typeinfo/generic_clib*.gdt`, vendored under `third_party/ghidra/typeinfo`).
Reading that packed database at runtime would put a Ghidra format parser in
the JVM-free path for one table of names; instead the table is exported once
by an oracle-only script, committed with the archive's hash, and read
natively -- the same shape `oracle/prototypes-v1` already uses for reference
data.

Assertions
  1. The committed table exists, records the archive it came from and its
     hash, and declares a function the corpus actually imports.
  2. Importing that image stores the declared prototype for the import, with
     provenance naming the archive and the symbol.
  3. The call site decompiles with the declared parameter types: the string
     renders as a literal instead of a label.
  4. Nothing is invented: no prototype is stored for an import the table does
     not declare, and a made-up name is never matched.

Usage:
    python3 tests/m4-009_library_prototypes.py --corpus-dir DIR [--report OUT.json]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "target/release/lre-cli"
LOCK = ROOT / "tests/corpus.lock.json"
TABLE = ROOT / "oracle/library-prototypes-v1/generic_clib_64.json"
INSTALL = Path(os.environ.get(
    "VENTRIS_GHIDRA", str(Path.home() / "ghidra_12.1.3_PUBLIC")))
ROW = "x86_64_plain_o0"
SOURCE = "native-import:type-archive"


def environment() -> dict[str, str]:
    values = dict(os.environ)
    for name in ("VENTRIS_SLA", "VENTRIS_LANGUAGE", "VENTRIS_LANGUAGE_DIR",
                 "VENTRIS_SPECS", "VENTRIS_REGISTER_PARAMS",
                 "VENTRIS_PROMOTE_TAILCALLS"):
        values.pop(name, None)
    return values


def cli(*arguments: str, timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run([str(CLI), *arguments], cwd=ROOT, capture_output=True,
                          text=True, timeout=timeout, env=environment())


def ram(cell: str) -> int | None:
    try:
        return int(cell, 16)
    except ValueError:
        pass
    try:
        decoded = json.loads(cell)
    except json.JSONDecodeError:
        return None
    return decoded.get("offset") if decoded.get("space") == "Ram" else None


def store(project: Path, program: str) -> dict:
    connection = sqlite3.connect(project / "project.sqlite")
    try:
        (identifier,) = connection.execute(
            "SELECT id FROM programs WHERE name = ?", (program,)).fetchone()
        prototypes = {}
        for function, return_type, signature, provenance in connection.execute(
                "SELECT function, return_type, signature, provenance FROM prototypes "
                "WHERE program_id = ?", (identifier,)):
            offset = ram(function)
            if offset is not None:
                prototypes[offset] = {"return_type": return_type,
                                      "signature": signature,
                                      "provenance": provenance}
        externals = {}
        for address, name, external in connection.execute(
                "SELECT address, name, external FROM symbols WHERE program_id = ?",
                (identifier,)):
            offset = ram(address)
            if offset is not None and external:
                externals[offset] = name
        functions = {}
        for entry, name in connection.execute(
                "SELECT entry, name FROM functions WHERE program_id = ?", (identifier,)):
            offset = ram(entry)
            if offset is not None:
                functions[offset] = name
        return {"prototypes": prototypes, "externals": externals,
                "functions": functions}
    finally:
        connection.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--timeout", type=int, default=900)
    arguments = parser.parse_args()

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-cli"],
                   cwd=ROOT, check=True, env=environment())
    # The release CLI drives the worker beside it, so the gate builds the pair
    # it measures (m4-014).
    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-worker"],
                   cwd=ROOT, check=True, env=environment())

    # 1. The committed table, with the archive it came from.
    assert TABLE.is_file(), (
        f"{TABLE.relative_to(ROOT)} is missing; export it from the pinned "
        f"archive first")
    table = json.loads(TABLE.read_text())
    for key in ("archive", "archive_sha256", "generator", "functions"):
        assert key in table, f"the table records no {key}"
    archive = Path(table["archive"])
    if not archive.is_absolute():
        archive = INSTALL / archive
    assert archive.is_file(), f"the table names an archive that is not here: {archive}"
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    assert digest == table["archive_sha256"], (
        f"{archive.name} has changed since the table was exported: {digest} "
        f"against {table['archive_sha256']}")
    assert "printf" in table["functions"], (
        "the table declares no printf, so nothing here can be proven")
    declared = table["functions"]["printf"]
    assert declared["return_type"] and declared["parameters"], (
        f"printf's declaration is empty: {declared}")

    lock = json.loads(LOCK.read_text())
    recipe = next(row for row in lock["entries"]
                  if f"{row['architecture']}_{row['variant']}" == ROW)
    binary = (arguments.corpus_dir / recipe["binary"]).resolve()
    assert binary.is_file(), f"{binary} is missing"

    findings: dict[str, object] = {}
    with tempfile.TemporaryDirectory(prefix="m4-009-") as directory:
        project = Path(directory) / "project"
        imported = cli("import", str(binary), "--project", str(project),
                       timeout=arguments.timeout)
        assert imported.returncode == 0, f"import failed: {imported.stderr.strip()}"
        facts = store(project, binary.name)

        # 2. The prototype reached the store, for the import that carries it.
        stubs = sorted(address for address, name in facts["functions"].items()
                       if name == "printf")
        assert stubs, "the store holds no function named printf to type"
        typed = [address for address in stubs
                 if address in facts["prototypes"]
                 and SOURCE in facts["prototypes"][address]["provenance"]]
        assert typed, (
            f"no printf stub carries an archive prototype; the store holds "
            f"{[(f'{a:08x}', facts['prototypes'].get(a)) for a in stubs]}")
        row = facts["prototypes"][typed[0]]
        assert declared["return_type"] in row["signature"], (
            f"the stored signature does not carry the declared return type "
            f"{declared['return_type']!r}: {row['signature']!r}")
        assert declared["parameters"][0]["type"].replace(" ", "") in \
            row["signature"].replace(" ", ""), (
            f"the stored signature does not carry the declared first parameter "
            f"{declared['parameters'][0]['type']!r}: {row['signature']!r}")
        findings["prototype"] = {"stub": f"{typed[0]:08x}", **row}

        # 3. The call site shows it: a `char *` renders the string.
        callers = sorted(entry for entry, name in facts["functions"].items()
                         if name.startswith("FUN_"))
        rendered = None
        for entry in callers:
            text = cli("decompile", str(binary), f"{entry:08x}",
                       "--project", str(project), timeout=arguments.timeout)
            if text.returncode == 0 and "printf(" in text.stdout:
                rendered = text.stdout
                break
        assert rendered is not None, "no decompilation calls printf"
        assert '"sum: %d\\n"' in rendered, (
            f"the string is still passed as a label rather than a literal: "
            f"{rendered.strip()[:300]}")
        findings["call"] = rendered.strip()[:200]

        # 4. Nothing invented: every archive prototype names a declared symbol.
        invented = []
        for address, prototype in facts["prototypes"].items():
            if SOURCE not in prototype["provenance"]:
                continue
            name = facts["functions"].get(address) or facts["externals"].get(address)
            if name not in table["functions"]:
                invented.append((f"{address:08x}", name))
        assert not invented, (
            f"these prototypes claim a declaration the table does not hold: "
            f"{invented}")
        findings["typed"] = len(typed)

    metrics = {"library.declared_functions": len(table["functions"]),
               "library.typed_imports": findings["typed"],
               "library.invented_prototypes": 0}
    summary = (f"the pinned C library archive declares "
               f"{len(table['functions'])} functions; the import at "
               f"{findings['prototype']['stub']} carries its declared prototype "
               f"({findings['prototype']['signature']}) with provenance "
               f"{findings['prototype']['provenance']}, the call site renders "
               f"\"sum: %d\\n\" as a literal, and no prototype names a symbol the "
               f"archive does not declare")

    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps({
            "id": "m4-009",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "status": "pass",
            "passed": True,
            "summary": summary,
            "metrics": metrics,
            "prototype": findings["prototype"],
            "call": findings["call"],
        }, indent=1) + "\n")
    print(f"m4-009: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
