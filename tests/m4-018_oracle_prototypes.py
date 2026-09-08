#!/usr/bin/env python3
"""m4-018: make the instrument record what it knows.

The last five `function-facts` rows all read `[None, ours]` on `return_type`:
the oracle store holds **zero** prototype rows, because the bridge's batched
export sends only name, entry and size per function
(`Dispatcher.exportFacts`). So the gate was comparing a type we recovered
against the instrument's silence and calling it a divergence -- on rows whose
*text* already agrees, `int printf(char *__format,...)` both ways.

Ghidra distinguishes a recovered signature from its own placeholder:
`Function.getSignatureSource()` is `SourceType.DEFAULT` when the signature is
`undefined FUN_x(void)`, and `ANALYSIS`/`IMPORTED`/`USER_DEFINED` when
something recovered it. Only the latter is a fact.

And a signature is content, not spelling: `int f(char *name)` and
`int f(char *)` say the same thing about the return type and the arity, which
is what the two stores can be compared on without pinning either
decompiler's parameter-naming.

Assertions
  1. An oracle import records prototypes: the `printf` stub, whose text shows
     `int printf(char *__format,...)`, has a row with return type `int`.
  2. A function whose signature Ghidra calls DEFAULT gets no row -- the
     control, without which assertion 1 would just be recording placeholders.
  3. The classifier compares content: two spellings of the same signature are
     not a divergence, a differing return type is, and a differing arity is.
  4. Both stores now record return types for the same stubs, so the field
     stops firing on rows whose text agrees.

Usage:
    python3 tests/m4-018_oracle_prototypes.py --corpus-dir DIR [--report OUT.json]
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "target/release/lre-cli"
LOCK = ROOT / "tests/corpus.lock.json"
GHIDRA = Path(os.environ.get("VENTRIS_GHIDRA", str(Path.home() / "ghidra_12.1.3_PUBLIC")))
DEFAULT_NAME = re.compile(r"^(?:FUN|SUB|UNK)_[0-9a-f]+$")


def environment() -> dict[str, str]:
    values = dict(os.environ)
    for name in ("VENTRIS_SLA", "VENTRIS_LANGUAGE", "VENTRIS_LANGUAGE_DIR",
                 "VENTRIS_SPECS", "VENTRIS_REGISTER_PARAMS",
                 "VENTRIS_PROMOTE_TAILCALLS"):
        values.pop(name, None)
    values["VENTRIS_SERVICE_JAR"] = str(ROOT / "service/build/ventris-service.jar")
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
        functions = {offset: name for entry, name in connection.execute(
            "SELECT entry, name FROM functions WHERE program_id = ?", (identifier,))
            if (offset := ram(entry)) is not None}
        prototypes = {}
        for function, signature, return_type in connection.execute(
                "SELECT function, signature, return_type FROM prototypes "
                "WHERE program_id = ?", (identifier,)):
            offset = ram(function)
            if offset is not None:
                prototypes[offset] = {"signature": signature, "return_type": return_type}
        return {"functions": functions, "prototypes": prototypes}
    finally:
        connection.close()


def gate():
    specification = importlib.util.spec_from_file_location(
        "m4_003", ROOT / "tests/m4-003_language_parity.py")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def context() -> dict:
    return {"symbols": set(), "prototypes": set(), "externals": {}, "strings": {},
            "definitions": set(), "names": {}, "functions": {}}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--timeout", type=int, default=900)
    arguments = parser.parse_args()

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-cli", "-p", "lre-worker"],
                   cwd=ROOT, check=True, env=environment())
    assert (ROOT / "service/build/ventris-service.jar").is_file(), (
        "the oracle bridge jar is missing; build service/ before this gate")

    lock = json.loads(LOCK.read_text())
    recipes = {f"{row['architecture']}_{row['variant']}": row for row in lock["entries"]}
    binary = (arguments.corpus_dir / recipes["x86_64_plain_o0"]["binary"]).resolve()
    assert binary.is_file(), f"{binary} is missing"
    findings: dict[str, object] = {}

    with tempfile.TemporaryDirectory(prefix="m4-018-") as directory:
        work = Path(directory)
        native_project, oracle_project = work / "native", work / "oracle"
        imported = cli("import", str(binary), "--project", str(native_project),
                       timeout=arguments.timeout)
        assert imported.returncode == 0, imported.stderr.strip()
        oracle = cli("import", str(binary), "--oracle", "--project", str(oracle_project),
                     "--ghidra", str(GHIDRA), timeout=arguments.timeout)
        assert oracle.returncode == 0, oracle.stderr.strip()

        ours = store(native_project, binary.name)
        theirs = store(oracle_project, binary.name)

        # 1. The instrument records a recovered signature.
        assert theirs["prototypes"], (
            "the oracle store still holds no prototype rows, so a return-type "
            "comparison measures its silence")
        stub = next((entry for entry, name in theirs["functions"].items()
                     if name == "printf"), None)
        assert stub is not None, (
            f"the oracle records no printf stub: {sorted(set(theirs['functions'].values()))[:12]}")
        held = theirs["prototypes"].get(stub)
        assert held is not None, (
            f"the oracle's printf stub at {stub:08x} has no prototype row, and its "
            f"own text prints one")
        assert held["return_type"] == "int", held
        findings["oracle_printf"] = held

        # 2. The control: a default signature is not a recovered one.
        placeholders = sorted(entry for entry, name in theirs["functions"].items()
                              if DEFAULT_NAME.match(name)
                              and entry in theirs["prototypes"])
        assert not placeholders, (
            f"these functions carry Ghidra's placeholder signature as a recovered "
            f"prototype: {[f'{a:08x}' for a in placeholders]}")
        findings["oracle_prototypes"] = len(theirs["prototypes"])

        # 4. Both stores hold a type for the same stub, so the field agrees.
        mine = ours["prototypes"].get(
            next(entry for entry, name in ours["functions"].items() if name == "printf"))
        assert mine is not None, "our own store holds no printf prototype"
        assert mine["return_type"] == held["return_type"], (mine, held)
        findings["agreed_return_type"] = mine["return_type"]

    # 3. The classifier compares content, not spelling.
    module = gate()
    empty = context()
    spellings = module.classify(
        "int f(char *a){return 1;}", "int f(char *a){return 1;}",
        {"name": "f", "signature": "int f(char *)", "return_type": "int"},
        {"name": "f", "signature": "int f(char *__format)", "return_type": "int"},
        0x1000, empty, empty)
    assert "function-facts" not in spellings, (
        f"two spellings of one signature were counted as a divergence: {spellings}")
    types = module.classify(
        "int f(void){return 1;}", "void f(void){return;}",
        {"name": "f", "signature": "void f(void)", "return_type": "void"},
        {"name": "f", "signature": "int f(void)", "return_type": "int"},
        0x1000, empty, empty)
    assert "return_type" in types.get("function-facts", {}), (
        f"a differing return type stopped counting: {types}")
    arity = module.classify(
        "int f(char *a){return 1;}", "int f(char *a,int b){return 1;}",
        {"name": "f", "signature": "int f(char *, int)", "return_type": "int"},
        {"name": "f", "signature": "int f(char *)", "return_type": "int"},
        0x1000, empty, empty)
    assert "parameters" in arity.get("function-facts", {}), (
        f"a differing parameter count stopped counting: {arity}")
    findings["content_comparison"] = {"spelling": sorted(spellings),
                                      "return_type": sorted(types),
                                      "arity": sorted(arity)}

    summary = (f"the oracle records {findings['oracle_prototypes']} recovered "
               f"prototypes and no placeholders, both stores agree on the stub's "
               f"return type, and signatures compare by content")
    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps({
            "task": "m4-018",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "scope": "instrument acceptance plus classifier controls",
            "metrics": findings,
            "passed": True,
        }, indent=2) + "\n")
    print(f"m4-018: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
