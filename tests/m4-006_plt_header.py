#!/usr/bin/env python3
"""m4-006: the PLT header's indirect jump is a call the ABI names.

`m4-005` closed the thunk shapes the store already recorded. One shape is
left in the same fixture: the PLT header at the start of `.plt` jumps through
`.got.plt[2]`, and with no fact behind it the decompilation reports "Could not
recover jumptable at 0x00201716" while the oracle prints the call and says
nothing.

That slot is not a guess. The System V x86-64 psABI reserves the first three
`DT_PLTGOT` entries: `[0]` is the address of `.dynamic`, `[1]` the link-map
and `[2]` the resolver the header jumps to. So an indirect transfer that reads
`DT_PLTGOT + 2 * pointer size` behaves like a call.

The fact is *not* a thunk: stock Ghidra's own thunk table is empty for this
image, and recording one broke set-level thunk parity (`m5-008`). What stock
holds is a per-instruction flow override (`Instruction.getFlowOverride`), so
that is what the store now holds too, in `flow_overrides`.

Assertions
  1. The store records a `callreturn` flow override at an instruction inside
     the PLT that reads exactly `DT_PLTGOT + 2 * pointer size`, recomputed
     here from the ELF.
  2. Its provenance names the rule, not a generic import.
  3. The header decompiles with no jumptable warning, and the slot is named
     the way Ghidra names a code pointer with no named target.
  4. An image with no `DT_PLTGOT` gets no such row: a PE fixture is imported
     and must hold none.
  5. Thunk facts are untouched, so thunk parity with stock is unaffected.

Usage:
    python3 tests/m4-006_plt_header.py --corpus-dir DIR [--report OUT.json]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
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
PE = ROOT / "tests/fixtures-src/tiny_pe32.exe"
JUMPTABLE = re.compile(r"Could not recover jumptable")


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


def overrides(project: Path, program: str) -> list[dict]:
    connection = sqlite3.connect(project / "project.sqlite")
    try:
        (identifier,) = connection.execute(
            "SELECT id FROM programs WHERE name = ?", (program,)).fetchone()
        rows = []
        for address, kind, provenance in connection.execute(
                "SELECT address, kind, provenance FROM flow_overrides "
                "WHERE program_id = ?", (identifier,)):
            offset = ram(address)
            if offset is not None:
                rows.append({"address": offset, "kind": kind,
                             "provenance": provenance})
        return rows
    finally:
        connection.close()


def data_targets(project: Path, program: str, source: int) -> list[int]:
    connection = sqlite3.connect(project / "project.sqlite")
    try:
        (identifier,) = connection.execute(
            "SELECT id FROM programs WHERE name = ?", (program,)).fetchone()
        found = []
        for src, dst, kind in connection.execute(
                "SELECT src, dst, kind FROM xrefs WHERE program_id = ?", (identifier,)):
            if kind == "DATA" and ram(src) == source and ram(dst) is not None:
                found.append(ram(dst))
        return found
    finally:
        connection.close()


def thunks(project: Path, program: str) -> list[dict]:
    connection = sqlite3.connect(project / "project.sqlite")
    try:
        (identifier,) = connection.execute(
            "SELECT id FROM programs WHERE name = ?", (program,)).fetchone()
        rows = []
        for function, thunked, kind, provenance in connection.execute(
                "SELECT function, thunked, kind, provenance FROM thunks "
                "WHERE program_id = ?", (identifier,)):
            entry, destination = ram(function), ram(thunked)
            if entry is not None and destination is not None:
                rows.append({"entry": entry, "destination": destination,
                             "kind": kind, "provenance": provenance})
        return rows
    finally:
        connection.close()


def elf_facts(binary: Path) -> dict:
    """`DT_PLTGOT`, the pointer width and the PLT range, read independently."""
    dynamic = subprocess.run(["readelf", "-d", str(binary)], capture_output=True,
                             text=True, check=True).stdout
    match = re.search(r"\(PLTGOT\)\s+(0x[0-9a-f]+)", dynamic)
    assert match, f"{binary.name} declares no DT_PLTGOT"
    header = subprocess.run(["readelf", "-hW", str(binary)], capture_output=True,
                            text=True, check=True).stdout
    width = 8 if "ELF64" in header else 4
    sections = subprocess.run(["readelf", "-SW", str(binary)], capture_output=True,
                              text=True, check=True).stdout
    plt = re.search(r"\.plt\s+PROGBITS\s+([0-9a-f]+)\s+\S+\s+([0-9a-f]+)", sections)
    assert plt, f"{binary.name} has no .plt section"
    return {"pltgot": int(match.group(1), 16), "width": width,
            "plt": int(plt.group(1), 16), "plt_size": int(plt.group(2), 16)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--timeout", type=int, default=900)
    arguments = parser.parse_args()

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-cli"],
                   cwd=ROOT, check=True, env=environment())
    subprocess.run(["cargo", "build", "-q", "-p", "lre-worker"],
                   cwd=ROOT, check=True, env=environment())

    lock = json.loads(LOCK.read_text())
    recipe = next(row for row in lock["entries"]
                  if f"{row['architecture']}_{row['variant']}" == ROW)
    binary = (arguments.corpus_dir / recipe["binary"]).resolve()
    assert binary.is_file(), f"{binary} is missing"
    elf = elf_facts(binary)
    resolver = elf["pltgot"] + 2 * elf["width"]

    findings: dict[str, object] = {}
    with tempfile.TemporaryDirectory(prefix="m4-006-") as directory:
        work = Path(directory)
        project = work / "project"
        imported = cli("import", str(binary), "--project", str(project),
                       timeout=arguments.timeout)
        assert imported.returncode == 0, f"import failed: {imported.stderr.strip()}"
        rows = thunks(project, binary.name)
        corrections = overrides(project, binary.name)

        # 1 and 2. The override, at an instruction reading the reserved slot.
        reading = [row for row in corrections
                   if resolver in data_targets(project, binary.name, row["address"])]
        assert reading, (
            f"the store records no flow override at an instruction reading the "
            f"resolver slot {resolver:08x} (DT_PLTGOT {elf['pltgot']:08x} + 2 * "
            f"{elf['width']}); it holds {corrections}")
        assert len(reading) == 1, f"more than one override claims the slot: {reading}"
        # Nothing else is corrected: every override the store holds must read
        # the reserved slot, or the rule is firing on ordinary data reads.
        stray = [item for item in corrections if item not in reading]
        assert not stray, (
            f"these instructions were corrected without reading the reserved "
            f"slot: {[(f'{i["address"]:08x}', i['provenance']) for i in stray]}")
        row = reading[0]
        assert row["kind"] == "callreturn", (
            f"the resolver transfer is recorded as {row['kind']}, not callreturn")
        assert "plt-header" in row["provenance"], (
            f"the row's provenance does not name the rule: {row['provenance']!r}")
        assert elf["plt"] <= row["address"] < elf["plt"] + elf["plt_size"], (
            f"the corrected instruction {row['address']:08x} is outside .plt "
            f"({elf['plt']:08x}+{elf['plt_size']:x})")

        # 3. The header decompiles as a call, with the slot named as a pointer.
        owner = max(entry for entry in
                    [item["entry"] for item in rows] + [elf["plt"]]
                    if entry <= row["address"])
        text = cli("decompile", str(binary), f"{owner:08x}",
                   "--project", str(project), timeout=arguments.timeout)
        assert text.returncode == 0, f"decompile failed: {text.stderr.strip()}"
        assert not JUMPTABLE.search(text.stdout), (
            f"the PLT header still asks for a jumptable: "
            f"{text.stdout.strip()[:300]}")
        assert f"PTR_{resolver:08x}" in text.stdout, (
            f"the resolver slot is not rendered as a pointer: "
            f"{text.stdout.strip()[:300]}")
        findings["header"] = {"instruction": f"{row['address']:08x}",
                              "function": f"{owner:08x}",
                              "resolver": f"{resolver:08x}",
                              "provenance": row["provenance"]}

        # 4. No DT_PLTGOT, no row: a PE image has neither.
        pe = work / PE.name
        shutil.copy2(PE, pe)
        pe_project = work / "pe"
        pe_import = cli("import", str(pe), "--project", str(pe_project),
                        timeout=arguments.timeout)
        assert pe_import.returncode == 0, (
            f"PE import failed: {pe_import.stderr.strip()}")
        invented = overrides(pe_project, pe.name)
        assert not invented, (
            f"a PE image with no DT_PLTGOT got PLT-header rows: {invented}")
        findings["pe_rows"] = len(overrides(pe_project, pe.name))

        # 5. Thunk facts are untouched, so thunk parity is unaffected.
        assert rows, "the row's thunk facts disappeared"
        assert all("plt-header" not in item["provenance"] for item in rows), (
            f"the PLT header was recorded as a thunk after all: {rows}")
        findings["other_thunks"] = len(rows)

    metrics = {"plt.overrides": 1, "plt.resolver_slot": resolver,
               "plt.thunks_unchanged": findings["other_thunks"],
               "plt.pe_overrides": 0}
    summary = (f"the PLT header's jump at {findings['header']['instruction']} is a "
               f"`callreturn` override reading the ABI-reserved resolver slot "
               f"{findings['header']['resolver']} (DT_PLTGOT + 2 words), recorded as "
               f"{findings['header']['provenance']}; the function decompiles with no "
               f"jumptable warning and names the slot PTR_"
               f"{findings['header']['resolver']}, "
               f"{findings['other_thunks']} thunk facts are unchanged, and a PE image "
               f"gets none")

    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps({
            "id": "m4-006",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "status": "pass",
            "passed": True,
            "summary": summary,
            "metrics": metrics,
            "header": findings["header"],
        }, indent=1) + "\n")
    print(f"m4-006: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
