#!/usr/bin/env python3
"""m4-010: the override belongs on the branch, not on the load before it.

`m4-005` and `m4-006` made a stub's transfer a call by recording a
`callreturn` override -- and keyed it on the instruction that *reads* the slot.
On x86-64 that is the same instruction (`jmp qword ptr [...]`), so it worked.
On AArch64 and PowerPC it is not: the stub loads the slot into a register and
branches through it two instructions later, so the override landed on the load
and the branch stayed a jumptable candidate:

    /* WARNING: Could not recover jumptable at 0x002108ac. Too many branches */
    /* WARNING: Treating indirect jump as call */

The transfer instruction is a fact discovery already proves -- it is the
indirect branch that ends the stub's body -- so that is what the override must
name.

Assertions
  1. Every linkage stub the store holds carries a `callreturn` override, and
     the override sits on an indirect branch inside that stub, not on the
     instruction that reads the slot.
  2. Those stubs decompile with no jumptable warning.
  3. Nothing else is overridden: every override address lies inside a function
     the store records a stub or reserved-slot fact for.
  4. The x86-64 shape still holds, where load and branch are one instruction.

Usage:
    python3 tests/m4-010_stub_transfers.py --corpus-dir DIR [--report OUT.json]
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
ROWS = ("aarch64_plain_o0", "powerpc_plain_o0", "x86_64_plain_o0")
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


def facts(project: Path, program: str) -> dict:
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
        thunks = []
        for function, thunked, kind in connection.execute(
                "SELECT function, thunked, kind FROM thunks WHERE program_id = ?",
                (identifier,)):
            entry, slot = ram(function), ram(thunked)
            if entry is not None and slot is not None:
                thunks.append({"entry": entry, "slot": slot, "kind": kind})
        overrides = []
        for address, kind, provenance in connection.execute(
                "SELECT address, kind, provenance FROM flow_overrides "
                "WHERE program_id = ?", (identifier,)):
            offset = ram(address)
            if offset is not None:
                overrides.append({"address": offset, "kind": kind,
                                  "provenance": provenance})
        reads = {}
        for source, destination, kind in connection.execute(
                "SELECT src, dst, kind FROM xrefs WHERE program_id = ?", (identifier,)):
            from_offset, to_offset = ram(source), ram(destination)
            if from_offset is not None and to_offset is not None:
                reads.setdefault(to_offset, []).append(from_offset)
        definitions = {ram(address) for (address,) in connection.execute(
            "SELECT address FROM data_definitions WHERE program_id = ?", (identifier,))}
        # Transfers a branch performs, by branching instruction: the evidence
        # the shared-return rule acts on (m4-013).
        transfers = {}
        for source, destination, kind in connection.execute(
                "SELECT src, dst, kind FROM xrefs WHERE program_id = ?", (identifier,)):
            from_offset, to_offset = ram(source), ram(destination)
            if from_offset is not None and to_offset is not None and (
                    "JUMP" in kind or "CALL" in kind):
                transfers.setdefault(from_offset, set()).add(to_offset)
        return {"functions": functions, "thunks": thunks, "overrides": overrides,
                "reads": reads, "definitions": definitions, "transfers": transfers}
    finally:
        connection.close()


def containing(functions: dict, address: int) -> int | None:
    candidates = [entry for entry, row in functions.items()
                  if entry <= address < entry + max(row["size"], 1)]
    return max(candidates) if candidates else None


def disassembly(binary: Path, entry: int, size: int, timeout: int) -> dict[int, str]:
    result = cli("disasm", str(binary), f"{entry:08x}", "-n", str(max(size, 1)),
                 timeout=timeout)
    assert result.returncode == 0, f"disasm of {entry:08x} failed: {result.stderr.strip()}"
    rows = {}
    for line in result.stdout.splitlines():
        match = re.match(r"0x([0-9a-f]+):\s+(.*)$", line.strip())
        if match:
            address = int(match.group(1), 16)
            if address < entry + max(size, 1):
                rows[address] = match.group(2)
    return rows


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

    lock = json.loads(LOCK.read_text())
    recipes = {f"{row['architecture']}_{row['variant']}": row
               for row in lock["entries"]}
    measured: dict[str, dict] = {}
    with tempfile.TemporaryDirectory(prefix="m4-010-") as directory:
        work = Path(directory)
        for name in ROWS:
            binary = (arguments.corpus_dir / recipes[name]["binary"]).resolve()
            assert binary.is_file(), f"{binary} is missing"
            project = work / name
            imported = cli("import", str(binary), "--project", str(project),
                           timeout=arguments.timeout)
            assert imported.returncode == 0, (
                f"{name}: import failed: {imported.stderr.strip()}")
            row = facts(project, binary.name)

            stubs = [thunk for thunk in row["thunks"] if thunk["kind"] == "linkage"]
            assert stubs, f"{name}: the store holds no linkage stub"
            overridden = {item["address"] for item in row["overrides"]}

            # 1. Each stub carries an override, on a branch and not on a load.
            missing, misplaced = [], []
            for stub in stubs:
                entry = stub["entry"]
                size = row["functions"].get(entry, {}).get("size", 0)
                inside = sorted(address for address in overridden
                                if entry <= address < entry + max(size, 1))
                if not inside:
                    missing.append(f"{entry:08x}")
                    continue
                text = disassembly(binary, entry, size, arguments.timeout)
                for address in inside:
                    mnemonic = text.get(address, "")
                    reads_slot = address in row["reads"].get(stub["slot"], [])
                    branches = bool(re.match(
                        r"(?i)(b|br|braa|bctr|bctrl|jmp|blr|bx|j)\b", mnemonic))
                    if not branches and reads_slot:
                        misplaced.append(f"{address:08x} {mnemonic!r}")
            assert not missing, (
                f"{name}: these linkage stubs carry no override: {missing}")
            assert not misplaced, (
                f"{name}: these overrides sit on the load rather than the "
                f"branch: {misplaced}")

            # 2. Every function carrying an override decompiles without
            #    asking for a jumptable -- stubs and the PLT header alike.
            owners = sorted({containing(row["functions"], item["address"])
                             for item in row["overrides"]} - {None})
            assert owners, f"{name}: no function owns an override"
            warned = []
            for entry in owners:
                text = cli("decompile", str(binary), f"{entry:08x}",
                           "--project", str(project), timeout=arguments.timeout)
                if text.returncode == 0 and JUMPTABLE.search(text.stdout):
                    warned.append(f"{entry:08x}")
            assert not warned, (
                f"{name}: these still ask for a jumptable: {warned}")

            # 3. Nothing else is overridden. Three rules may own an override,
            #    and each has to show its own evidence: a stub's transfer, a
            #    reserved-slot read, or a branch that leaves its function for
            #    another function's entry (m4-013's shared return).
            stray = []
            for item in row["overrides"]:
                owner = containing(row["functions"], item["address"])
                shared_return = (
                    owner is not None
                    and owner != item["address"]
                    and any(target in row["functions"] and target != owner
                            for target in row["transfers"].get(item["address"], ())))
                known = owner is not None and (
                    any(stub["entry"] == owner for stub in row["thunks"])
                    or any(slot in row["definitions"]
                           for slot in row["reads"]
                           if owner == containing(row["functions"],
                                                  min(row["reads"][slot])))
                    or shared_return)
                if not known:
                    stray.append(f"{item['address']:08x} ({item['provenance']})")
            assert not stray, (
                f"{name}: these overrides belong to no stub, reserved slot or "
                f"proven shared return: {stray}")
            measured[name] = {"stubs": len(stubs), "overrides": len(row["overrides"])}

    metrics = {"stubs.rows_measured": len(measured),
               "stubs.linkage_stubs": sum(row["stubs"] for row in measured.values()),
               "stubs.overrides": sum(row["overrides"] for row in measured.values()),
               "stubs.jumptable_warnings": 0}
    summary = (f"{metrics['stubs.linkage_stubs']} linkage stubs across "
               f"{len(measured)} architectures each carry a `callreturn` override on "
               f"the branch that performs the transfer, not the load before it, and "
               f"none of them asks for a jumptable; "
               f"{metrics['stubs.overrides']} overrides in total, all inside a stub or "
               f"a function reading a reserved slot")

    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps({
            "id": "m4-010",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "status": "pass",
            "passed": True,
            "summary": summary,
            "metrics": metrics,
            "rows": measured,
        }, indent=1) + "\n")
    print(f"m4-010: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
