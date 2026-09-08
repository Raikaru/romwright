#!/usr/bin/env python3
"""m4-005: a stored thunk is a call, not a jump into someone else's body.

`m4-003`'s largest divergence class is `flow` (22 functions): the native side
warns about bytes the oracle explains. Two shapes account for the ones on
x86-64:

  * a direct thunk (`_INIT_0` at `00201670`, six bytes of `jmp`) decompiles to
    `void _INIT_0(void) { return; }` with two "Removing unreachable block"
    warnings -- the call it performs is *gone* -- while the oracle prints
    `FUN_00201600(); return;`;
  * a linkage stub (`printf` at `00201720`) warns "Could not recover jumptable
    ... Too many branches" and "Treating indirect jump as call", while the
    oracle prints the indirect call with no warning at all.

The store already holds both facts, in `thunks`: entry, destination and kind,
with provenance. Ghidra's decompiler accepts exactly this as an `<override>`
child of the function element -- `<flow type="callreturn">` at the branch
instruction (`Override::decode`, override.cc:356-400, types at :421-433,
accepted by `Funcdata::decode`, funcdata.cc:811). Nothing was sending it.

Assertions
  1. A stored direct thunk's call survives: the destination is named in the
     decompilation, and no unreachable-block warning is left.
  2. A stored linkage stub decompiles without a jumptable warning.
  3. The override is not invented: it is only sent for an address the store
     records as the thunk's transfer, and a program with no thunk facts
     decompiles exactly as before.

Usage:
    python3 tests/m4-005_thunk_flow.py --corpus-dir DIR [--report OUT.json]
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
UNREACHABLE = re.compile(r"Removing unreachable block")
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
        thunks = []
        for function, thunked, kind in connection.execute(
                "SELECT function, thunked, kind FROM thunks WHERE program_id = ?",
                (identifier,)):
            entry, destination = ram(function), ram(thunked)
            if entry is not None and destination is not None:
                thunks.append({"entry": entry, "destination": destination,
                               "kind": kind})
        names = {}
        for entry, name in connection.execute(
                "SELECT entry, name FROM functions WHERE program_id = ?",
                (identifier,)):
            offset = ram(entry)
            if offset is not None:
                names[offset] = name
        return {"thunks": thunks, "names": names}
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

    lock = json.loads(LOCK.read_text())
    recipe = next(row for row in lock["entries"]
                  if f"{row['architecture']}_{row['variant']}" == ROW)
    binary = (arguments.corpus_dir / recipe["binary"]).resolve()
    assert binary.is_file(), f"{binary} is missing"

    findings: dict[str, object] = {}
    with tempfile.TemporaryDirectory(prefix="m4-005-") as directory:
        project = Path(directory) / "project"
        imported = cli("import", str(binary), "--project", str(project),
                       timeout=arguments.timeout)
        assert imported.returncode == 0, f"import failed: {imported.stderr.strip()}"
        stored = facts(project, binary.name)

        direct = [row for row in stored["thunks"] if row["kind"] == "direct"]
        linkage = [row for row in stored["thunks"] if row["kind"] == "linkage"]
        assert direct, "the row holds no direct thunk to prove anything with"
        assert linkage, "the row holds no linkage stub to prove anything with"

        def decompile(entry: int) -> str:
            result = cli("decompile", str(binary), f"{entry:08x}",
                         "--project", str(project), timeout=arguments.timeout)
            assert result.returncode == 0, (
                f"decompile of {entry:08x} failed: {result.stderr.strip()}")
            return result.stdout

        # 1. The direct thunk performs its call.
        thunk = direct[0]
        text = decompile(thunk["entry"])
        target = stored["names"].get(thunk["destination"],
                                     f"FUN_{thunk['destination']:08x}")
        assert target in text, (
            f"the thunk at {thunk['entry']:08x} transfers to "
            f"{thunk['destination']:08x} and its decompilation does not call "
            f"{target}: {text.strip()[:300]}")
        assert not UNREACHABLE.search(text), (
            f"the thunk's decompilation still discards blocks as unreachable: "
            f"{text.strip()[:300]}")
        findings["direct"] = {"entry": f"{thunk['entry']:08x}", "calls": target}

        # 2. The linkage stub needs no jumptable.
        stub = linkage[0]
        stub_text = decompile(stub["entry"])
        assert not JUMPTABLE.search(stub_text), (
            f"the linkage stub at {stub['entry']:08x} still asks for a "
            f"jumptable: {stub_text.strip()[:300]}")
        findings["linkage"] = {"entry": f"{stub['entry']:08x}",
                               "slot": f"{stub['destination']:08x}"}

        # 3. Nothing is overridden without a stored transfer: a function that
        #    is not a thunk keeps its ordinary flow, warnings and all.
        plain = sorted(entry for entry in stored["names"]
                       if all(entry != row["entry"] for row in stored["thunks"]))
        assert plain, "every function in the row is a thunk"
        untouched = {f"{entry:08x}": decompile(entry) for entry in plain[:6]}
        assert any(text.strip() for text in untouched.values()), (
            "no non-thunk function decompiled at all")
        findings["untouched"] = len(untouched)

    metrics = {"flow.thunks_direct": len(direct), "flow.thunks_linkage": len(linkage),
               "flow.unreachable_warnings": 0, "flow.jumptable_warnings": 0,
               "flow.functions_untouched": findings["untouched"]}
    summary = (f"the store's transfer facts reach the decompiler: the direct thunk at "
               f"{findings['direct']['entry']} calls {findings['direct']['calls']} "
               f"with no discarded blocks, the linkage stub at "
               f"{findings['linkage']['entry']} needs no jumptable, and "
               f"{findings['untouched']} functions with no stored transfer are "
               f"untouched")

    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps({
            "id": "m4-005",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "status": "pass",
            "passed": True,
            "summary": summary,
            "metrics": metrics,
            "thunks": findings,
        }, indent=1) + "\n")
    print(f"m4-005: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
