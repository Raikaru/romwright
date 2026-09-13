#!/usr/bin/env python3
"""m4-021: the last gap row -- a slot that holds code, and a name that stays named.

One row still carries gap classes, x86-32 `00401440`, and it carries two
independent defects:

  * **the slot.** Stock calls `004026d8` `PTR_FUN_004026d8` -- a pointer whose
    target is a function -- and we call it `DAT_004026d8`. The slot is an
    `.init_array` entry: the array proves it holds a code address, which is
    the same evidence m5-010 uses to name the *target* `_INIT_0` while leaving
    the slot that holds it untyped.
  * **the name.** Both decompilers emit the injection warning, differing only
    by the callee's spelling (`__i686.get_pc_thunk.bx` vs our C identifier).
    m4-020 named that `name-rendering` -- but only when it was the *whole*
    difference: `classify` dropped its name classes when it fell through to
    the general path, so this row filed the same warning twice, once as `flow`
    (ours) and once as `oracle-warning` (stock's).

Assertions
  1. An `.init_array` slot is typed as a pointer with provenance, and its
     label in decompiled text starts `PTR_`, not `DAT_`.
  2. A word with no array behind it keeps `DAT_` and gains no pointer type --
     the control.
  3. A row that differs by a rendered name *and* by something else still names
     `name-rendering`, and the warning that differs only by that name is
     counted in neither direction.
  4. A warning that genuinely differs is still counted in its own direction.

Usage:
    python3 tests/m4-021_initializer_slots.py --corpus-dir DIR [--report OUT.json]
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
SOURCE = "native-import:elf-pointer"
DT = {"INIT_ARRAY": 25, "INIT_ARRAYSZ": 27, "FINI_ARRAY": 26, "FINI_ARRAYSZ": 28,
      "PREINIT_ARRAY": 32, "PREINIT_ARRAYSZ": 33}
ROWS = ("i386_plain_o0", "x86_64_plain_o0", "aarch64_plain_o0", "powerpc_plain_o0")


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


def dynamic(binary: Path) -> dict[int, int]:
    """The dynamic tags, read the way the loader reads them."""
    data = binary.read_bytes()
    wide = data[4] == 2
    order = "big" if data[5] == 2 else "little"

    def field(at: int, size: int) -> int:
        return int.from_bytes(data[at:at + size], order)

    width = 8 if wide else 4
    phoff = field(32, 8) if wide else field(28, 4)
    phentsize = field(54, 2) if wide else field(42, 2)
    phnum = field(56, 2) if wide else field(44, 2)
    tags: dict[int, int] = {}
    for index in range(phnum):
        at = phoff + index * phentsize
        if field(at, 4) != 2:
            continue
        offset = field(at + 8, 8) if wide else field(at + 4, 4)
        while True:
            tag, value = field(offset, width), field(offset + width, width)
            if tag == 0:
                break
            tags.setdefault(tag, value)
            offset += 2 * width
    return tags


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
        definitions = {}
        for address, kind, size, provenance in connection.execute(
                "SELECT address, type, size, provenance FROM data_definitions "
                "WHERE program_id = ?", (identifier,)):
            offset = ram(address)
            if offset is not None:
                definitions[offset] = {"type": kind, "size": size,
                                       "provenance": provenance}
        return {"functions": functions, "definitions": definitions}
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
    with tempfile.TemporaryDirectory(prefix="m4-021-") as directory:
        work = Path(directory)
        typed, labelled, untyped = [], [], []
        for name in ROWS:
            binary = (arguments.corpus_dir / recipes[name]["binary"]).resolve()
            project = work / name
            imported = cli("import", str(binary), "--project", str(project),
                           timeout=arguments.timeout)
            assert imported.returncode == 0, imported.stderr.strip()
            held = store(project, binary.name)
            tags = dynamic(binary)
            width = 8 if binary.read_bytes()[4] == 2 else 4
            slots = []
            for array, size in (("INIT_ARRAY", "INIT_ARRAYSZ"),
                                ("PREINIT_ARRAY", "PREINIT_ARRAYSZ"),
                                ("FINI_ARRAY", "FINI_ARRAYSZ")):
                base, length = tags.get(DT[array]), tags.get(DT[size])
                if not base or not length:
                    continue
                slots.extend(base + index * width for index in range(length // width))
            assert slots, f"{name}: the image declares no initializer array"
            for slot in slots:
                definition = held["definitions"].get(slot)
                # `code-pointer` is the same claim with the target named: the
                # ABI defines an initializer array as function pointers, and
                # m4-030 records that declaration in the type.
                assert definition is not None and definition["type"] in (
                    "pointer", "code-pointer"), (
                    f"{name}: the initializer slot at {slot:08x} holds a code "
                    f"address and the store types it {definition}")
                assert definition["provenance"] == SOURCE, definition
                assert definition["size"] == width, definition
                typed.append(f"{name}:{slot:08x}")

            # 1. The label follows the type.
            for entry, _ in sorted(held["functions"].items()):
                text = cli("decompile", str(binary), f"{entry:08x}", "--project",
                           str(project), timeout=arguments.timeout)
                if text.returncode != 0:
                    continue
                for slot in slots:
                    if f"DAT_{slot:08x}" in text.stdout:
                        untyped.append(f"{name}:{entry:08x}->DAT_{slot:08x}")
                    if f"_{slot:08x}" in text.stdout and f"PTR_" in text.stdout:
                        labelled.append(f"{name}:{slot:08x}")

            # 2. The control: a word with no array behind it keeps DAT_.
            plain = [address for address, definition in held["definitions"].items()
                     if definition["provenance"] != SOURCE and address not in slots]
            assert plain, f"{name}: no non-array definition to control against"
        assert not untyped, (
            f"these initializer slots are still rendered as untyped data: {untyped}")
        assert typed, "no initializer slot was typed, so nothing is proven"
        findings["typed_slots"] = sorted(set(typed))
        findings["labelled"] = sorted(set(labelled))[:6]

    # 3. and 4. A rendered name survives the general path.
    module = gate()
    rows = ({"name": "entry"}, {"name": "entry"})
    ours = context(functions={"__i686_get_pc_thunk_bx": 0x401469})
    theirs = context(functions={"__i686.get_pc_thunk.bx": 0x401469},
                     names={0x401469: "__i686.get_pc_thunk.bx"})
    native_text = ("/* WARNING: Function: __i686_get_pc_thunk_bx replaced with "
                   "injection: get_pc_thunk_bx */void entry(void)"
                   "{undefined1 auStack_4 [4];return;}")
    oracle_text = ("/* WARNING: Function: __i686.get_pc_thunk.bx replaced with "
                   "injection: get_pc_thunk_bx */void entry(void)"
                   "{undefined1 auStack_4 [4];int extra;return;}")
    classes = module.classify(native_text, oracle_text, rows[0], rows[1], 0x401440,
                              ours, theirs)
    assert "name-rendering" in classes, (
        f"a rendered name was dropped when the row differed elsewhere too: "
        f"{sorted(classes)}")
    assert "flow" not in classes and "oracle-warning" not in classes, (
        f"the same warning was counted in both directions after rendering: "
        f"{ {k: v for k, v in classes.items() if k in ('flow', 'oracle-warning')} }")
    findings["rendering_survives"] = sorted(classes)

    real = native_text.replace("injection: get_pc_thunk_bx",
                               "injection: get_pc_thunk_ax")
    classes = module.classify(real, oracle_text, rows[0], rows[1], 0x401440,
                              ours, theirs)
    assert "flow" in classes and "oracle-warning" in classes, (
        f"a warning that genuinely differs stopped being counted: {sorted(classes)}")
    findings["real_difference"] = sorted(classes)

    summary = (f"{len(findings['typed_slots'])} initializer slots typed as code "
               f"pointers and rendered as such, and a rendered name survives a row "
               f"that differs elsewhere too")
    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps({
            "task": "m4-021",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "scope": "slot-typing acceptance on four rows plus classifier controls",
            "metrics": findings,
            "passed": True,
        }, indent=2) + "\n")
    print(f"m4-021: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
