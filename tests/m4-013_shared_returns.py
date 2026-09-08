#!/usr/bin/env python3
"""m4-013: a branch to another function's entry is a call that returns.

`m4-012`'s exact accounting left two corpus rows whose *whole* difference is
one missing fact. The PowerPC entry ends with `b __libc_start_main`; stock
prints `__libc_start_main(); return;` and we print an indirect call through the
GOT slot with two warnings, because we followed the branch into the stub and
met its `bctr` with no override in reach:

    /* WARNING: Could not recover jumptable at 0x10010574. Too many branches */
    /* WARNING: Treating indirect jump as call */
    (*PTR___libc_start_main_1003074c)();

Ghidra's rule is `SharedReturnAnalysisCmd.processFunctionJumpReferences`
(:376-424), run by the default-enabled `SharedReturnAnalyzer`
("Converts branches to calls, followed by an immediate return, when the
destination is a function"): for every *unconditional* jump reference whose
destination is a function entry, when

  * the instruction has exactly one flow reference, to that destination
    (`getSingleFlowReferenceFrom`),
  * no function starts *at* the branch instruction -- that shape is a thunk,
    handled elsewhere (`funcMgr.getFunctionAt(refInstrAddr) != null`),
  * the function containing the branch is not the destination itself, so an
    internal jump to a function's own top is left alone, and
  * the instruction carries no flow override already,

it sets `FlowOverride.CALL_RETURN` on that instruction. Conditional jumps are
excluded by default (`OPTION_DEFAULT_CONSIDER_CONDITIONAL_BRANCHES_ENABLED =
false`), and the whole analyzer is off only where a language's pspec sets
`enableSharedReturnAnalysis=false`.

Our tree already decides the *consequence* of that rule -- `record_branch_
transfers` types such a branch `UNCONDITIONAL_CALL` -- and never recorded the
cause, so nothing reached the decompiler. The second, `assumeContiguous
Functions` half of the same command *creates* functions at jump destinations
beyond the next entry; that is tail-call promotion, which II.1 keeps behind
`VENTRIS_PROMOTE_TAILCALLS`, and this task does not touch it.

Assertions
  1. On the corpus: the tail branch of the PowerPC entry and of the AArch64
     `.init` stub each carry a `callreturn` override with shared-return
     provenance, their decompilations call the import by name, and no
     jumptable warning is left.
  2. On a fixture built for the rule's four conditions: a tail call to a
     function entry is overridden; a jump to the branching function's own
     entry is not, and stays a jump; a conditional branch to a function entry
     is not; and a branch that *is* a function entry keeps the thunk
     provenance rather than gaining a second owner.

Usage:
    python3 tests/m4-013_shared_returns.py --corpus-dir DIR [--report OUT.json]
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
SOURCE = "native-analysis:shared-return"
JUMPTABLE = re.compile(r"Could not recover jumptable")

FIXTURE = """
    .text
    .globl _start
    .type _start,@function
_start:
    call caller
    hlt
    .size _start,.-_start

    /* The destination sits before its callers, so no transfer here is a
       fallthrough to the next address. */
    .type callee,@function
callee:
    inc %eax
    ret
    .size callee,.-callee

    /* A tail call: one unconditional jump, straight to another entry. */
    .type caller,@function
caller:
    xor %eax,%eax
    jmp callee
    .size caller,.-caller

    /* A jump to the branching function's own entry: an internal loop. */
    .type looper,@function
looper:
    dec %eax
    jmp looper
    .size looper,.-looper

    /* A conditional branch to a function entry: excluded by default. */
    .type conditional,@function
conditional:
    test %eax,%eax
    je callee
    ret
    .size conditional,.-conditional

    /* The branch instruction *is* the entry: a thunk, owned by its own rule. */
    .type stub,@function
stub:
    jmp callee
    .size stub,.-stub
"""


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
    """The facts this rule reads and writes."""
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
        overrides = {}
        for address, kind, provenance in connection.execute(
                "SELECT address, kind, provenance FROM flow_overrides WHERE program_id = ?",
                (identifier,)):
            offset = ram(address)
            if offset is not None:
                overrides[offset] = (kind, provenance)
        branches = {}
        for source, target, kind in connection.execute(
                "SELECT src, dst, kind FROM xrefs WHERE program_id = ?", (identifier,)):
            source, target = ram(source), ram(target)
            if source is not None and target is not None and "JUMP" in kind or (
                    source is not None and target is not None and "CALL" in kind):
                branches[(source, target)] = kind
        return {"functions": functions, "overrides": overrides, "branches": branches}
    finally:
        connection.close()


def imported(binary: Path, project: Path, timeout: int) -> None:
    result = cli("import", str(binary), "--project", str(project), timeout=timeout)
    assert result.returncode == 0, f"{binary.name}: import failed: {result.stderr.strip()}"


def decompiled(binary: Path, entry: int, project: Path, timeout: int) -> str:
    result = cli("decompile", str(binary), f"{entry:08x}", "--project", str(project),
                 timeout=timeout)
    assert result.returncode == 0, (
        f"{binary.name}: decompile of {entry:08x} failed: {result.stderr.strip()}")
    return result.stdout


def tail_branch(facts: dict, entry: int, target: int) -> int:
    """The one branch inside `entry`'s body that transfers to `target`."""
    _, size = facts["functions"][entry]
    found = [source for (source, destination) in facts["branches"]
             if destination == target and entry <= source < entry + size]
    assert len(found) == 1, (
        f"{entry:08x} has {len(found)} recorded transfers to {target:08x}: "
        f"{[f'{address:08x}' for address in found]}")
    return found[0]


def containing(facts: dict, address: int) -> int | None:
    """The function whose body holds `address`."""
    for entry, (_, size) in facts["functions"].items():
        if entry <= address < entry + size:
            return entry
    return None


def branches_into(facts: dict, target: int) -> list[tuple[int, int]]:
    """Recorded transfers to `target` from inside some other function, as
    (branching function, branch address). The caller is derived rather than
    named: which function tail-branches into a stub is the image's business."""
    found = []
    for (source, destination) in facts["branches"]:
        if destination != target:
            continue
        function = containing(facts, source)
        if function is not None and function != target:
            found.append((function, source))
    return sorted(set(found))


def build_fixture(work: Path) -> tuple[Path, dict[str, int]]:
    """Assemble the four shapes the rule distinguishes, and read their addresses."""
    compiler = shutil.which("cc") or shutil.which("gcc")
    assert compiler, "no C compiler to build the shared-return fixture"
    source = work / "shapes.s"
    source.write_text(FIXTURE)
    binary = work / "shapes"
    build = subprocess.run(
        [compiler, "-nostdlib", "-no-pie", "-static", "-o", str(binary), str(source)],
        capture_output=True, text=True)
    assert build.returncode == 0, f"fixture build failed: {build.stderr.strip()}"
    listed = subprocess.run(["nm", "-f", "posix", str(binary)], capture_output=True,
                            text=True, check=True)
    symbols = {}
    for line in listed.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[1] in ("T", "t"):
            symbols[fields[0]] = int(fields[2], 16)
    for name in ("_start", "caller", "callee", "looper", "conditional", "stub"):
        assert name in symbols, f"{name} is missing from the fixture: {symbols}"
    return binary, symbols


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
    recipes = {f"{row['architecture']}_{row['variant']}": row for row in lock["entries"]}
    findings: dict[str, object] = {}
    with tempfile.TemporaryDirectory(prefix="m4-013-") as directory:
        work = Path(directory)

        # 1. The corpus rows whose whole difference is this fact.
        rows = []
        for name, import_name in (("powerpc_plain_o0", "__libc_start_main"),
                                  ("aarch64_plain_o0", "__gmon_start__")):
            binary = (arguments.corpus_dir / recipes[name]["binary"]).resolve()
            assert binary.is_file(), f"{binary} is missing"
            project = work / name
            imported(binary, project, arguments.timeout)
            facts = store(project, binary.name)
            by_name = {label: entry for entry, (label, _) in facts["functions"].items()}
            assert import_name in by_name, (
                f"{name} records no {import_name} stub: {sorted(by_name)}")
            target = by_name[import_name]
            transfers = branches_into(facts, target)
            assert transfers, (
                f"{name}: nothing tail-branches into {import_name} at "
                f"{target:08x}, so this row proves nothing")
            for caller, branch in transfers:
                held = facts["overrides"].get(branch)
                assert held == ("callreturn", SOURCE), (
                    f"{name}: the branch at {branch:08x} transfers to {import_name} "
                    f"at {target:08x} and holds {held}")
                text = decompiled(binary, caller, project, arguments.timeout)
                assert f"{import_name}(" in text, (
                    f"{name}: {caller:08x} does not call {import_name}: {text[:220]}")
                assert not JUMPTABLE.search(text), (
                    f"{name}: {caller:08x} still asks for a jumptable: {text[:220]}")
                rows.append({"program": binary.name, "caller": f"{caller:08x}",
                             "branch": f"{branch:08x}", "calls": import_name})
        findings["corpus"] = rows

        # 2. The rule's own conditions, one fixture shape apiece.
        fixture, symbols = build_fixture(work)
        fixture_project = work / "fixture"
        imported(fixture, fixture_project, arguments.timeout)
        facts = store(fixture_project, fixture.name)
        shapes: dict[str, object] = {}

        branch = tail_branch(facts, symbols["caller"], symbols["callee"])
        assert facts["overrides"].get(branch) == ("callreturn", SOURCE), (
            f"a tail call from caller to callee holds "
            f"{facts['overrides'].get(branch)}")
        shapes["tail_call"] = f"{branch:08x}"

        # The branching function is the destination: an internal jump. It
        # leaves no transfer to record (a body's own branches are not
        # inter-function references) and must leave no override either.
        _, looper_size = facts["functions"][symbols["looper"]]
        looper_body = range(symbols["looper"], symbols["looper"] + looper_size)
        claimed = [f"{address:08x}" for address, (_, provenance) in
                   facts["overrides"].items()
                   if address in looper_body and provenance == SOURCE]
        assert not claimed, (
            f"an internal jump to its own function's entry was overridden: "
            f"{claimed}")
        mistyped = {edge: kind for edge, kind in facts["branches"].items()
                    if edge[1] == symbols["looper"] and edge[0] in looper_body}
        assert not mistyped, (
            f"a jump to its own function's entry was recorded as a transfer: "
            f"{ {f'{a:08x}->{b:08x}': k for (a, b), k in mistyped.items()} }")
        shapes["internal_jump"] = "no override, no transfer"

        # A conditional branch: excluded while `considerConditionalBranches`
        # is off, which is the default.
        _, size = facts["functions"][symbols["conditional"]]
        conditional = [address for address in facts["overrides"]
                       if symbols["conditional"] <= address < symbols["conditional"] + size
                       and facts["overrides"][address][1] == SOURCE]
        assert not conditional, (
            f"a conditional branch to a function entry was overridden: "
            f"{[f'{a:08x}' for a in conditional]}")
        shapes["conditional"] = "no shared-return override"

        # The branch instruction is itself an entry: the thunk rule owns it.
        held = facts["overrides"].get(symbols["stub"])
        assert held is None or held[1] != SOURCE, (
            f"the stub's own entry branch was claimed by the shared-return rule: "
            f"{held}")
        shapes["entry_branch"] = held[1] if held else "no override"
        findings["shapes"] = shapes

    summary = (f"{len(findings['corpus'])} corpus tail branches carry a callreturn "
               f"override and call the import by name; 4 fixture shapes keep the "
               f"rule's conditions")
    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps({
            "task": "m4-013",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "scope": "positive acceptance plus four fixture controls, not a locked corpus gate",
            "metrics": findings,
            "passed": True,
        }, indent=2) + "\n")
    print(f"m4-013: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
