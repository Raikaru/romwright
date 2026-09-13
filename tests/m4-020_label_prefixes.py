#!/usr/bin/env python3
"""m4-020: a label says whether the address is code, and a rendered name is a
rendering.

Two gaps are left in the parity account, and both are small and specific.

**`data-type-unknown` 2.** The AArch64 entry passes `&DAT_002106f4` where
stock passes `&LAB_002106f4`. The address is code -- stock disassembled it --
and our provider prefixes every unnamed location `DAT_`. Ghidra's own
constants are explicit: `SymbolUtilities.DEFAULT_SYMBOL_PREFIX = "LAB_"` and
`DEFAULT_DATA_PREFIX = "DAT_"` (:49-53), and the store already records which
mappings are executable.

**`flow` 3.** All three rows carry the same warning, and both sides emit it:

    ours:  Function: __i686_get_pc_thunk_bx replaced with injection: ...
    stock: Function: __i686.get_pc_thunk.bx replaced with injection: ...

The difference is the name inside it. m4-011 renders a name C cannot spell as
a C identifier -- `.` is a member access -- while the store keeps what the
image declared; stock prints the dotted name into its own C. That is a
deliberate rendering of ours, so comparing text means applying the same
rendering to stock's names first, and naming the choice when it happens.

Assertions
  1. An unnamed address in an executable mapping is labelled `LAB_<addr>`, and
     the AArch64 entry passes `&LAB_002106f4` as stock does.
  2. An unnamed address in a non-executable mapping keeps `DAT_<addr>` -- the
     control, without which assertion 1 would just be a rename.
  3. A warning that differs only by a name we render as a C identifier is
     classified `name-rendering`, not `flow`.
  4. A warning that differs by anything else is still `flow`.

Usage:
    python3 tests/m4-020_label_prefixes.py --corpus-dir DIR [--report OUT.json]
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
CLI = ROOT / "target/release/romwright-cli"
LOCK = ROOT / "tests/corpus.lock.json"
LABEL = re.compile(r"\b(LAB|DAT)_([0-9a-f]{6,16})\b")


def environment() -> dict[str, str]:
    values = dict(os.environ)
    for name in ("ROMWRIGHT_SLA", "ROMWRIGHT_LANGUAGE", "ROMWRIGHT_LANGUAGE_DIR",
                 "ROMWRIGHT_SPECS", "ROMWRIGHT_REGISTER_PARAMS",
                 "ROMWRIGHT_PROMOTE_TAILCALLS"):
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
        functions = {}
        for entry, name, size in connection.execute(
                "SELECT entry, name, size FROM functions WHERE program_id = ?",
                (identifier,)):
            offset = ram(entry)
            if offset is not None:
                functions[offset] = (name, size or 1)
        regions = []
        for start, size, permissions in connection.execute(
                "SELECT start, size, permissions FROM memory_regions "
                "WHERE program_id = ?", (identifier,)):
            offset = ram(start)
            if offset is not None and size:
                regions.append((offset, offset + size, permissions))
        return {"functions": functions, "regions": regions}
    finally:
        connection.close()


def executable(regions: list[tuple[int, int, str]], address: int) -> bool | None:
    for start, end, permissions in regions:
        if start <= address < end:
            return "x" in permissions
    return None


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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--timeout", type=int, default=900)
    arguments = parser.parse_args()

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "romwright-cli", "-p", "romwright-worker"],
                   cwd=ROOT, check=True, env=environment())

    lock = json.loads(LOCK.read_text())
    recipes = {f"{row['architecture']}_{row['variant']}": row for row in lock["entries"]}
    findings: dict[str, object] = {}
    with tempfile.TemporaryDirectory(prefix="m4-020-") as directory:
        work = Path(directory)
        code_labels, data_labels, misplaced = [], [], []
        for name in ("aarch64_plain_o0", "x86_64_plain_o0", "i386_plain_o0",
                     "powerpc_plain_o0"):
            binary = (arguments.corpus_dir / recipes[name]["binary"]).resolve()
            project = work / name
            imported = cli("import", str(binary), "--project", str(project),
                           timeout=arguments.timeout)
            assert imported.returncode == 0, imported.stderr.strip()
            held = store(project, binary.name)
            for entry, _ in sorted(held["functions"].items()):
                text = cli("decompile", str(binary), f"{entry:08x}", "--project",
                           str(project), timeout=arguments.timeout)
                assert text.returncode == 0, \
                    f"decompile failed for {name}:{entry:08x}: {text.stderr.strip()}"
                for prefix, address in LABEL.findall(text.stdout):
                    where = executable(held["regions"], int(address, 16))
                    if where is None:
                        continue
                    if where and prefix == "LAB":
                        code_labels.append(f"{name}:{address}")
                    elif not where and prefix == "DAT":
                        data_labels.append(f"{name}:{address}")
                    else:
                        misplaced.append(f"{name}:{prefix}_{address} "
                                         f"(executable={where})")
        assert not misplaced, (
            f"these labels contradict their own mapping's permissions: {misplaced}")
        assert code_labels, (
            "no unnamed code address was labelled LAB_, so nothing is proven")
        assert data_labels, "no data address kept DAT_, so the control is missing"
        findings["code_labels"] = sorted(set(code_labels))[:6]
        findings["data_labels"] = len(set(data_labels))

    # 3. and 4. A rendered name is a rendering; anything else is flow.
    module = gate()
    rows = ({"name": "f"}, {"name": "f"})
    ours = context(functions={"__i686_get_pc_thunk_bx": 0x401469})
    theirs = context(functions={"__i686.get_pc_thunk.bx": 0x401469},
                     names={0x401469: "__i686.get_pc_thunk.bx"})
    native_text = ("/* WARNING: Function: __i686_get_pc_thunk_bx replaced with "
                   "injection: get_pc_thunk_bx */void f(void){return;}")
    oracle_text = ("/* WARNING: Function: __i686.get_pc_thunk.bx replaced with "
                   "injection: get_pc_thunk_bx */void f(void){return;}")
    classes = module.classify(native_text, oracle_text, rows[0], rows[1], 0x1000,
                              ours, theirs)
    assert "name-rendering" in classes, (
        f"a warning differing only by a name we render was classified "
        f"{sorted(classes)}")
    assert "flow" not in classes, (
        f"a rendering difference was counted as flow: {classes}")
    left = module.residue(native_text, oracle_text, rows[0], rows[1], classes, ours)
    assert left == [], f"the rendered name left {left} unexplained"
    findings["rendering"] = sorted(classes)

    other = ("/* WARNING: Could not recover jumptable at 0x401469 */"
             "void f(void){return;}")
    classes = module.classify(other, oracle_text, rows[0], rows[1], 0x1000, ours, theirs)
    assert "flow" in classes, (
        f"a warning that differs by more than a name stopped counting as flow: "
        f"{sorted(classes)}")
    findings["still_flow"] = sorted(classes)

    summary = (f"{len(findings['code_labels'])} code addresses labelled LAB_ and "
               f"{findings['data_labels']} data addresses kept DAT_, no label "
               f"contradicts its mapping, and a rendered name is named a rendering")
    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps({
            "task": "m4-020",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "scope": "label acceptance on four corpus rows plus classifier controls",
            "metrics": findings,
            "passed": True,
        }, indent=2) + "\n")
    print(f"m4-020: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
