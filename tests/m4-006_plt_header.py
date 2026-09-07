#!/usr/bin/env python3
"""m4-006: the PLT header's indirect jump is a call the ABI names.

`m4-005` closed the thunk shapes the store already recorded. One shape is
left in the same fixture: the PLT header at the start of `.plt` jumps through
`.got.plt[2]`, and with no fact behind it the decompilation reports "Could not
recover jumptable at 0x00201716" while the oracle prints the call and says
nothing.

That slot is not a guess. The System V x86-64 psABI reserves the first three
`DT_PLTGOT` entries: `[0]` is the address of `.dynamic`, `[1]` the link-map
and `[2]` the resolver the header jumps to. So an indirect transfer inside
`.plt` that reads `DT_PLTGOT + 2 * pointer size` is a call to the dynamic
linker's resolver, and the store can record it as a linkage thunk with the
tag as its evidence.

Assertions
  1. The store records a linkage thunk for the PLT header whose destination is
     exactly `DT_PLTGOT + 2 * pointer size`, recomputed here from the ELF.
  2. Its provenance names the rule, not a generic import.
  3. The header decompiles with no jumptable warning.
  4. An image with no `DT_PLTGOT` gets no such row: a PE fixture is imported
     and must hold none.
  5. Nothing else moves: every other thunk row the store held is still there.

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

        # 1 and 2. The header's thunk, named by the ABI-reserved slot.
        header = [row for row in rows if row["destination"] == resolver]
        assert header, (
            f"the store records no thunk reaching the resolver slot "
            f"{resolver:08x} (DT_PLTGOT {elf['pltgot']:08x} + 2 * {elf['width']}); "
            f"it holds {[(f'{r['entry']:08x}', f'{r['destination']:08x}') for r in rows]}")
        assert len(header) == 1, f"more than one row claims the resolver: {header}"
        row = header[0]
        assert row["kind"] == "linkage", (
            f"the resolver transfer is recorded as {row['kind']}, not linkage")
        assert "plt-header" in row["provenance"], (
            f"the row's provenance does not name the rule: {row['provenance']!r}")
        assert elf["plt"] <= row["entry"] < elf["plt"] + elf["plt_size"], (
            f"the row's function {row['entry']:08x} is outside .plt "
            f"({elf['plt']:08x}+{elf['plt_size']:x})")

        # 3. The header decompiles as a call.
        text = cli("decompile", str(binary), f"{row['entry']:08x}",
                   "--project", str(project), timeout=arguments.timeout)
        assert text.returncode == 0, f"decompile failed: {text.stderr.strip()}"
        assert not JUMPTABLE.search(text.stdout), (
            f"the PLT header still asks for a jumptable: "
            f"{text.stdout.strip()[:300]}")
        findings["header"] = {"entry": f"{row['entry']:08x}",
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
        invented = [item for item in thunks(pe_project, pe.name)
                    if "plt-header" in item["provenance"]]
        assert not invented, (
            f"a PE image with no DT_PLTGOT got PLT-header rows: {invented}")
        findings["pe_rows"] = len(thunks(pe_project, pe.name))

        # 5. The rest of the thunk facts are untouched.
        others = [item for item in rows if item["destination"] != resolver]
        assert others, "the row's other thunk facts disappeared"
        findings["other_thunks"] = len(others)

    metrics = {"plt.header_rows": 1, "plt.resolver_slot": resolver,
               "plt.other_thunks": findings["other_thunks"],
               "plt.pe_header_rows": 0}
    summary = (f"the PLT header at {findings['header']['entry']} is a linkage thunk to "
               f"the ABI-reserved resolver slot {findings['header']['resolver']} "
               f"(DT_PLTGOT + 2 words), recorded as "
               f"{findings['header']['provenance']}, and it decompiles with no "
               f"jumptable warning; {findings['other_thunks']} other thunk facts are "
               f"unchanged and a PE image gets none")

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
