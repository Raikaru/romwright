#!/usr/bin/env python3
"""m4-019: a prototype is missing from us only when stock has one.

The five remaining `missing-external-prototype` rows name exactly two imports,
`__libc_start_main` (3 rows) and `__gmon_start__` (2). Measured, offline:

  * the pinned type archive this tree already applies declares
    **6627** functions including `abort`, `printf` and `exit` -- and neither
    of those two, because both are glibc-internal (`__gmon_start__` is the
    profiling hook, declared nowhere at all);
  * **stock holds no signature for them either**: after m4-018 the oracle
    store records every signature Ghidra says it recovered, and for these two
    names -- at the stub and in its EXTERNAL block alike -- it records none.

So there is nothing to supply, and nothing missing on our side. The class was
firing on the same over-broad shape m4-016 fixed for warnings: it asked only
whether *our* store had a signature, so a name nobody has a declaration for
counted against us. A gap is a difference, and a difference has a direction.

Assertions
  1. Both stores lack a signature for a called import: no class.
  2. Stock has one and we do not: the class fires -- the control that keeps
     assertion 1 from being an excuse.
  3. We have one and stock does not: no class (we are ahead, not behind).
  4. On the corpus, neither store holds a signature for `__libc_start_main`
     or `__gmon_start__`, which is why they stop being counted.
  5. The recorded PowerPC pair -- the row that carried the class -- is still
     accounted for token by token with no residue.

Usage:
    python3 tests/m4-019_prototype_direction.py --corpus-dir DIR [--report OUT.json]
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "benchmarks"))
import gate_cache  # noqa: E402
CLI = ROOT / "target/release/romwright-cli"
LOCK = ROOT / "tests/corpus.lock.json"
GHIDRA = Path(os.environ.get("ROMWRIGHT_GHIDRA", str(Path.home() / "ghidra_12.1.3_PUBLIC")))
ARCHIVE = ROOT / "oracle/library-prototypes-v1/generic_clib_64.json"
UNDECLARED = ("__libc_start_main", "__gmon_start__")

# Recorded from both decompilers for the PowerPC stub at 10010568, the row
# whose only classes were this one plus a label and a cast.
NATIVE_PAIR = "void __libc_start_main(void){(*PTR___libc_start_main_1003074c)();return;}"
ORACLE_PAIR = "void __libc_start_main(void)\n{\n  (*(code *)__DT_PLTGOT)();\n  return;\n}\n"


def environment() -> dict[str, str]:
    values = dict(os.environ)
    for name in ("ROMWRIGHT_SLA", "ROMWRIGHT_LANGUAGE", "ROMWRIGHT_LANGUAGE_DIR",
                 "ROMWRIGHT_SPECS", "ROMWRIGHT_REGISTER_PARAMS",
                 "ROMWRIGHT_PROMOTE_TAILCALLS"):
        values.pop(name, None)
    values["ROMWRIGHT_SERVICE_JAR"] = str(ROOT / "service/build/romwright-service.jar")
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


def signatures(project: Path, program: str) -> dict[str, str | None]:
    """Signature per function name, for the names this task is about."""
    connection = sqlite3.connect(project / "project.sqlite")
    try:
        (identifier,) = connection.execute(
            "SELECT id FROM programs WHERE name = ?", (program,)).fetchone()
        prototypes = {}
        for function, signature in connection.execute(
                "SELECT function, signature FROM prototypes WHERE program_id = ?",
                (identifier,)):
            offset = ram(function)
            if offset is not None:
                prototypes[offset] = signature
        held: dict[str, str | None] = {}
        for entry, name in connection.execute(
                "SELECT entry, name FROM functions WHERE program_id = ?", (identifier,)):
            offset = ram(entry)
            if offset is None or name not in UNDECLARED:
                continue
            held[name] = prototypes.get(offset) or held.get(name)
        return held
    finally:
        connection.close()


def gate():
    specification = importlib.util.spec_from_file_location(
        "m4_003", ROOT / "tests/m4-003_language_parity.py")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def context(**overrides) -> dict:
    empty = {"symbols": set(), "prototypes": set(), "externals": {}, "strings": {},
             "definitions": set(), "names": {}, "functions": {}}
    empty.update(overrides)
    return empty


def cached_stores(binary: Path, timeout: int) -> tuple[Path, Path]:
    """The native and oracle stores for `binary`, reused across gate runs.

    Both are keyed by the provenance that produced them -- the binary and the
    build for ours, the binary, the bridge sources and the install revision
    for stock's -- so a rebuilt worker or an edited bridge is a miss
    (`benchmarks/gate_cache.py`). Nothing here writes to a store.
    """
    def build_native(directory: Path) -> None:
        result = cli("import", str(binary), "--project", str(directory), timeout=timeout)
        assert result.returncode == 0, result.stderr.strip()

    def build_oracle(directory: Path) -> None:
        result = cli("import", str(binary), "--oracle", "--project", str(directory),
                     "--ghidra", str(GHIDRA), timeout=timeout)
        assert result.returncode == 0, result.stderr.strip()

    return (gate_cache.store(gate_cache.native_key(binary), build_native),
            gate_cache.store(gate_cache.oracle_key(binary, GHIDRA), build_oracle))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--timeout", type=int, default=900)
    arguments = parser.parse_args()

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "romwright-cli", "-p", "romwright-worker"],
                   cwd=ROOT, check=True, env=environment())
    module = gate()
    findings: dict[str, object] = {}
    rows = ({"name": "f"}, {"name": "f"})
    native_text = "void f(void){(*PTR_x_00002000)();return;}"
    oracle_text = "void f(void){__gmon_start__();return;}"

    # 1. Neither store holds a signature for the called import.
    neither = context(externals={0x2000: "__gmon_start__"},
                      functions={"__gmon_start__": 0x1500})
    classes = module.classify(native_text, oracle_text, rows[0], rows[1], 0x1000,
                              neither, neither)
    assert "missing-external-prototype" not in classes, (
        f"a name neither store declares was counted against us: {classes}")
    findings["neither"] = sorted(classes)

    # 2. The control: stock has one, we do not.
    theirs = context(externals={0x2000: "__gmon_start__"},
                     functions={"__gmon_start__": 0x1500},
                     prototypes={0x1500})
    ours = context(externals={0x2000: "__gmon_start__"},
                   functions={"__gmon_start__": 0x1500})
    classes = module.classify(native_text, oracle_text, rows[0], rows[1], 0x1000,
                              ours, theirs)
    assert classes.get("missing-external-prototype") == ["__gmon_start__"], (
        f"stock has a signature we lack and it stopped counting: {classes}")
    findings["theirs_only"] = sorted(classes)

    # 3. We have one and stock does not: not a gap.
    classes = module.classify(native_text, oracle_text, rows[0], rows[1], 0x1000,
                              theirs, ours)
    assert "missing-external-prototype" not in classes, (
        f"holding a signature stock lacks was counted as a gap: {classes}")
    findings["ours_only"] = sorted(classes)

    # 4. On the corpus: nobody declares those two names.
    archive = json.loads(ARCHIVE.read_text())["functions"]
    for name in UNDECLARED:
        assert name not in archive, (
            f"{name} is in the pinned archive after all, so it should be applied "
            f"rather than excused")
    lock = json.loads(LOCK.read_text())
    recipes = {f"{row['architecture']}_{row['variant']}": row for row in lock["entries"]}
    binary = (arguments.corpus_dir / recipes["aarch64_plain_o0"]["binary"]).resolve()
    with tempfile.TemporaryDirectory(prefix="m4-019-") as directory:
        work = Path(directory)
        native_project, oracle_project = cached_stores(binary, arguments.timeout)
        mine = signatures(native_project, binary.name)
        stock = signatures(oracle_project, binary.name)
        for name in UNDECLARED:
            assert name in mine and name in stock, (
                f"{name} is not a function in both stores: {mine}, {stock}")
            assert mine[name] is None and stock[name] is None, (
                f"{name} now has a signature somewhere -- ours {mine[name]!r}, "
                f"stock {stock[name]!r} -- so this row is a real comparison again")
        findings["corpus"] = {"ours": mine, "stock": stock}

    # 5. The recorded pair still accounts for every token.
    pair_store = context(externals={0x1003074c: "__libc_start_main"},
                         definitions={0x1003074c},
                         names={0x1003074c: "PTR___libc_start_main_1003074c"},
                         functions={"__libc_start_main": 0x10010568})
    oracle_store = context(names={0x1003074c: "__DT_PLTGOT"})
    classes = module.classify(NATIVE_PAIR, ORACLE_PAIR, {"name": "__libc_start_main"},
                              {"name": "__libc_start_main"}, 0x10010568,
                              pair_store, oracle_store)
    assert "missing-external-prototype" not in classes, classes
    left = module.residue(NATIVE_PAIR, ORACLE_PAIR, {"name": "__libc_start_main"},
                          {"name": "__libc_start_main"}, classes, pair_store)
    assert left == [], (
        f"the recorded pair left {left} unexplained once the prototype class "
        f"stopped covering it: classes {sorted(classes)}")
    findings["recorded_pair"] = sorted(classes)

    summary = ("a called import nobody declares is nobody's gap, stock having a "
               "signature we lack still is, and the row that carried the class is "
               "still accounted for")
    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps({
            "task": "m4-019",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "scope": "classifier acceptance plus a measured corpus check",
            "metrics": findings,
            "passed": True,
        }, indent=2) + "\n")
    print(f"m4-019: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
