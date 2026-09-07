#!/usr/bin/env python3
"""m4-004: the decompiler must be told the data facts the store already holds.

`m4-003` measured two divergence classes that are not gaps in analysis at all
-- the facts exist, the decompiler is simply never told:

  * `string-not-rendered` (4): the store holds `sum: %d\\n` at `002004d0`, and
    the decompilation prints `printf(0x2004d0, ...)` where the oracle prints
    the literal. `lre-worker` answers `getStringData` from
    `ProgramProvider::strings`, and nothing fills it.
  * `missing-data-symbol` (8): the store holds a data reference to `002038f8`,
    and the decompilation prints `cRam00000000002038f8` -- the C++
    decompiler's own fallback -- where the oracle prints `DAT_002038f8`.

Ghidra does not store those labels either; it composes them on demand, and
this gate holds the native side to the same documented rules from the pinned
tree: `SymbolUtilities.getDynamicName` (prefix per reference level, then the
address string, SymbolUtilities.java:478-484), `getDynamicDataName` (a data
type's own label prefix, then the address, :541-544) and
`PointerDataType.getLabelString` (`PTR_` + the target's name, :212-238).

Assertions
  1. A data reference the store holds is named, not addressed: the function
     that references it decompiles with the dynamic label.
  2. A string the store holds is rendered as a literal, and its address no
     longer appears as a bare constant.
  3. A linkage slot the store names is rendered as a pointer to that name.
  4. Nothing is invented: every dynamic label in the output belongs to an
     address the store holds a reference or a symbol for.
  5. No fallback name survives in any of the compared functions.

Usage:
    python3 tests/m4-004_data_names.py --corpus-dir DIR [--report OUT.json]
"""
from __future__ import annotations

import argparse
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
ROW = "x86_64_plain_o0"
FALLBACK = re.compile(r"\b[a-z]{1,4}Ram[0-9a-f]{8,16}\b")
LABEL = re.compile(r"\b(?:DAT|PTR|LAB|UNK|OFF|s)_[0-9A-Za-z_]*?([0-9a-f]{6,16})\b")


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
        functions = {}
        for entry, name, size in connection.execute(
                "SELECT entry, name, size FROM functions WHERE program_id = ?",
                (identifier,)):
            offset = ram(entry)
            if offset is not None:
                functions[offset] = {"name": name, "size": size or 0}
        strings, symbols, references = {}, {}, []
        for address, value in connection.execute(
                "SELECT address, value FROM strings WHERE program_id = ?", (identifier,)):
            offset = ram(address)
            if offset is not None:
                strings[offset] = value
        for address, name, external in connection.execute(
                "SELECT address, name, external FROM symbols WHERE program_id = ?",
                (identifier,)):
            offset = ram(address)
            if offset is not None:
                symbols[offset] = {"name": name, "external": bool(external)}
        for source, destination, kind in connection.execute(
                "SELECT src, dst, kind FROM xrefs WHERE program_id = ?", (identifier,)):
            from_offset, to_offset = ram(source), ram(destination)
            if from_offset is not None and to_offset is not None:
                references.append((from_offset, to_offset, kind))
        return {"functions": functions, "strings": strings, "symbols": symbols,
                "references": references}
    finally:
        connection.close()


def containing(facts: dict, address: int) -> int | None:
    for entry, row in facts["functions"].items():
        if entry <= address < entry + max(row["size"], 1):
            return entry
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--timeout", type=int, default=900)
    arguments = parser.parse_args()

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-cli",
                    "-p", "lre-worker"], cwd=ROOT, check=True, env=environment())
    lock = json.loads(LOCK.read_text())
    recipe = next(row for row in lock["entries"]
                  if f"{row['architecture']}_{row['variant']}" == ROW)
    binary = (arguments.corpus_dir / recipe["binary"]).resolve()
    assert binary.is_file(), f"{binary} is missing"

    findings: dict[str, object] = {}
    with tempfile.TemporaryDirectory(prefix="m4-004-") as directory:
        project = Path(directory) / "project"
        imported = cli("import", str(binary), "--project", str(project),
                       timeout=arguments.timeout)
        assert imported.returncode == 0, f"import failed: {imported.stderr.strip()}"
        facts = store(project, binary.name)

        # 1. A data reference whose target the store holds no name for.
        unnamed = [(source, target) for source, target, kind in facts["references"]
                   if kind == "DATA" and target not in facts["symbols"]
                   and target not in facts["functions"]
                   and containing(facts, source) is not None
                   and target not in facts["strings"]]
        assert unnamed, "the corpus row holds no unnamed data reference to name"
        source, target = unnamed[0]
        owner = containing(facts, source)

        # 2. A string the store holds, referenced from a function.
        strings = [(src, dst) for src, dst, _ in facts["references"]
                   if dst in facts["strings"] and containing(facts, src) is not None]
        assert strings, "no function references a string the store holds"
        string_source, string_target = strings[0]
        string_owner = containing(facts, string_source)

        # 3. A linkage slot the store names as an import, outside any function.
        slots = sorted(address for address, row in facts["symbols"].items()
                       if row["external"] and address not in facts["functions"]
                       and containing(facts, address) is None)
        assert slots, "the store holds no import slot outside a function"
        slot = slots[0]
        slot_users = [src for src, dst, _ in facts["references"] if dst == slot
                      and containing(facts, src) is not None]
        assert slot_users, f"nothing references the import slot {slot:08x}"
        slot_owner = containing(facts, slot_users[0])

        texts = {}
        for label, entry in (("data", owner), ("string", string_owner),
                             ("slot", slot_owner)):
            result = cli("decompile", str(binary), f"{entry:08x}",
                         "--project", str(project), timeout=arguments.timeout)
            assert result.returncode == 0, (
                f"{label}: decompile of {entry:08x} failed: {result.stderr.strip()}")
            texts[label] = result.stdout

        expected_label = f"DAT_{target:08x}"
        assert expected_label in texts["data"], (
            f"{owner:08x} references {target:08x} and the store holds the "
            f"reference, but the decompilation names no {expected_label}: "
            f"{texts['data'].strip()[:300]}")

        literal = json.dumps(facts["strings"][string_target])[1:-1]
        assert literal in texts["string"], (
            f"{string_owner:08x} references the string at {string_target:08x} "
            f"({literal!r}) and the decompilation does not render it: "
            f"{texts['string'].strip()[:300]}")
        assert f"{string_target:#x}" not in texts["string"], (
            f"the string address is still printed as a bare constant: "
            f"{texts['string'].strip()[:300]}")

        slot_name = facts["symbols"][slot]["name"]
        assert f"PTR_{slot_name}_{slot:08x}" in texts["slot"], (
            f"the import slot {slot:08x} is named {slot_name} in the store and "
            f"the decompilation does not render it as a pointer to it: "
            f"{texts['slot'].strip()[:300]}")

        # 4. Nothing invented, and 5. no fallback survives.
        invented, fallbacks = [], []
        for label, text in texts.items():
            for match in LABEL.finditer(text):
                address = int(match.group(1), 16)
                if (address not in facts["symbols"] and address not in facts["strings"]
                        and not any(destination == address
                                    for _, destination, _ in facts["references"])):
                    invented.append(f"{label}:{match.group(0)}")
            fallbacks += [f"{label}:{name}" for name in FALLBACK.findall(text)]
        assert not invented, (
            f"these labels name addresses the store holds no fact for: {invented}")
        assert not fallbacks, (
            f"the decompiler still falls back to its own naming: {fallbacks}")
        findings = {"data_label": expected_label, "string": literal,
                    "slot_label": f"PTR_{slot_name}_{slot:08x}",
                    "functions": [f"{owner:08x}", f"{string_owner:08x}",
                                  f"{slot_owner:08x}"]}

    metrics = {"data.labels_rendered": 1, "data.strings_rendered": 1,
               "data.slots_rendered": 1, "data.fallback_names": 0,
               "data.invented_labels": 0}
    summary = (f"the store's data facts reach the decompiler: {findings['data_label']} "
               f"for a held reference, {findings['string']!r} for a held string, and "
               f"{findings['slot_label']} for a named import slot, with no fallback "
               f"name and nothing invented across {len(findings['functions'])} functions")

    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps({
            "id": "m4-004",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "status": "pass",
            "passed": True,
            "summary": summary,
            "metrics": metrics,
            "rendered": findings,
        }, indent=1) + "\n")
    print(f"m4-004: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
