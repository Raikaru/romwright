#!/usr/bin/env python3
"""m5-006: a tail call is recorded as a jump reference.

`nds.arm7`'s `mix` is entered only by an unconditional branch, and the m5-002
gate records it as an unrecovered function. Before deciding whether a
function may be created from such a transfer, the transfer itself has to be
a fact in the store: today no reference is written for it at all, so nothing
in the program model says the branch leaves its function.

The rule this gate pins: an unconditional single-target branch whose target
lies outside the branching function's own extent is recorded as
`UNCONDITIONAL_JUMP` (Ghidra's name for that flow type -- see
`.ghidra-java/ghidra/program/model/symbol/RefType.java:128`), and a branch
inside its own function -- a loop -- is not recorded. Both directions are
checked against the fixture's disassembly, and both classes must occur, so
the check cannot pass by recording everything or nothing.

Recording the fact must not invent the function: the discovered function set
is asserted unchanged.

Usage:
    python3 tests/m5-006_tailcall.py [--report OUT.json]
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
JUMP = "UNCONDITIONAL_JUMP"

# The fixture's discovered function set, from tests/m5-002_nds.py. Recording a
# transfer is not the same as creating a function, so these must not move.
EXPECTED_FUNCTIONS = {
    "nds.arm9": {0x0200_0000, 0x0200_000C, 0x0200_001C, 0x0200_002C, 0x0200_0060},
    "nds.arm7": {0x037F_8008, 0x037F_8010, 0x037F_8030},
}
# The tail call itself: `b mix` in the middle of the ARM7 image.
TAIL_CALL = (0x037F_802C, 0x037F_8000)

BRANCH = re.compile(r"^\s*([0-9a-f]+):\s+[0-9a-f ]+\s+b\s+0x([0-9a-f]+)")


def load_fixture():
    """Reuse the m5-002 container builder: one fixture, two gates."""
    spec = importlib.util.spec_from_file_location(
        "m5_002", ROOT / "tests" / "m5-002_nds.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def unconditional_branches(elf: Path) -> list[tuple[int, int]]:
    """Every unconditional direct branch in an image, from its own bytes."""
    output = subprocess.run(
        ["llvm-objdump", "-d", "--triple=armv4t", str(elf)],
        capture_output=True, text=True, check=True).stdout
    found = []
    for line in output.splitlines():
        match = BRANCH.match(line)
        if match:
            found.append((int(match.group(1), 16), int(match.group(2), 16)))
    return found


def containing(functions: dict[int, int], address: int) -> int | None:
    for entry, size in functions.items():
        if entry <= address < entry + size:
            return entry
    return None


THRESHOLDS = {
    "flow_xref.jump.precision": 1.0,
    "flow_xref.jump.cross_recall": 1.0,
    "flow_xref.call.precision": 1.0,
    "flow_xref.call.recall": 0.98,
}


def score_against_ghidra(cli: Path, corpus: Path, oracle_dir: Path,
                         timeout: int) -> dict[str, object]:
    """Score branch-derived references against the stock-Ghidra oracle.

    Ghidra records a reference for every flow, so its own export is the only
    honest judge of a reference this project invents. The comparison is
    kind-exact: a transfer recorded under the wrong kind counts as a miss on
    one side and a false positive on the other.
    """
    manifest = json.loads((corpus / "manifest.json").read_text())
    oracle = {}
    for path in sorted(oracle_dir.rglob("*.json")):
        exported = json.loads(path.read_text())
        if "xrefs" in exported:
            oracle[exported["sha256"]] = exported

    totals = dict(jump=0, jump_hit=0, cross=0, cross_hit=0, call=0, call_hit=0,
                  ghidra_call=0, scored=0)
    rows = []
    for entry in manifest["entries"]:
        exported = oracle.get(entry["binary_sha256"])
        if exported is None:
            continue
        binary = corpus / entry["binary"]
        ghidra_jump = {(x["from"].lower(), x["to"].lower())
                       for x in exported["xrefs"] if x["kind"] == "UNCONDITIONAL_JUMP"}
        ghidra_call = {(x["from"].lower(), x["to"].lower())
                       for x in exported["xrefs"] if x["kind"] == "UNCONDITIONAL_CALL"}
        with tempfile.TemporaryDirectory(prefix="m5-006-corpus-") as temporary:
            project = Path(temporary) / "project"
            imported = subprocess.run(
                [str(cli), "import", str(binary), "--name", "t",
                 "--project", str(project)],
                cwd=ROOT, capture_output=True, text=True, timeout=timeout)
            assert imported.returncode == 0, (
                f"{entry['binary']}: import failed: {imported.stderr.strip()}")
            store = sqlite3.connect(project / "project.sqlite")
            native_jump = {(a.lower(), b.lower()) for a, b in store.execute(
                "SELECT src, dst FROM xrefs WHERE kind = 'UNCONDITIONAL_JUMP'")}
            native_call = {(a.lower(), b.lower()) for a, b in store.execute(
                "SELECT src, dst FROM xrefs WHERE kind = 'UNCONDITIONAL_CALL'")}
            extents = sorted((int(a, 16), size) for a, size in store.execute(
                "SELECT entry, size FROM functions"))

        def leaves_its_function(source: str, target: str) -> bool:
            owner = None
            for start, size in extents:
                if start <= int(source, 16) < start + size:
                    owner = (start, size)
            if owner is None:
                return False
            return not owner[0] <= int(target, 16) < owner[0] + owner[1]

        cross = {edge for edge in ghidra_jump if leaves_its_function(*edge)}
        totals["scored"] += 1
        totals["jump"] += len(native_jump)
        totals["jump_hit"] += len(native_jump & ghidra_jump)
        totals["cross"] += len(cross)
        totals["cross_hit"] += len(native_jump & cross)
        totals["call"] += len(native_call)
        totals["call_hit"] += len(native_call & ghidra_call)
        totals["ghidra_call"] += len(ghidra_call)
        rows.append({
            "id": f"{entry['architecture']}_{entry['variant']}",
            "native_jumps": len(native_jump),
            "ghidra_jumps": len(ghidra_jump),
            "cross_function_jumps": len(cross),
            "cross_recorded": len(native_jump & cross),
            "native_calls": len(native_call),
            "ghidra_calls": len(ghidra_call),
        })

    assert totals["scored"] >= 20, (
        f"only {totals['scored']} corpus entries had an oracle to score against")
    assert totals["cross"], "no cross-function jump existed in any oracle"
    metrics = {
        "flow_xref.jump.precision": totals["jump_hit"] / max(totals["jump"], 1),
        "flow_xref.jump.cross_recall": totals["cross_hit"] / max(totals["cross"], 1),
        "flow_xref.call.precision": totals["call_hit"] / max(totals["call"], 1),
        "flow_xref.call.recall": totals["call_hit"] / max(totals["ghidra_call"], 1),
    }
    for name, threshold in THRESHOLDS.items():
        assert metrics[name] >= threshold, (
            f"{name} is {metrics[name]:.4f}, below {threshold}")
    return {"metrics": metrics, "corpus": rows, "totals": totals}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--corpus-dir", type=Path,
                        help="score branch references against the Ghidra oracle")
    parser.add_argument("--oracle-dir", type=Path, default=ROOT / "oracle" / "xrefs-v1")
    parser.add_argument("--timeout", type=int, default=900)
    arguments = parser.parse_args()

    report = {"id": "m5-006", "recorded_at": datetime.now(timezone.utc).isoformat(),
              "status": "skipped"}
    for tool in ("clang", "ld.lld", "llvm-objcopy", "llvm-objdump"):
        if shutil.which(tool) is None:
            report["reason"] = f"no freestanding ARM toolchain: {tool} not found"
            print(f"SKIP: {report['reason']}")
            if arguments.report:
                arguments.report.write_text(json.dumps(report, indent=2) + "\n")
            return 0

    fixture = load_fixture()
    subprocess.run(["cargo", "build", "-q", "--release", "-p", "romwright-cli"],
                   cwd=ROOT, check=True)
    cli = ROOT / "target/release/romwright-cli"

    with tempfile.TemporaryDirectory(prefix="m5-006-") as temporary:
        work = Path(temporary)
        container, images = fixture.build_container(work)
        project = work / "project"
        imported = subprocess.run(
            [str(cli), "import", str(container), "--name", "nds", "--project", str(project)],
            cwd=ROOT, capture_output=True, text=True, timeout=arguments.timeout)
        if imported.returncode != 0:
            raise AssertionError(f"import failed: {imported.stderr.strip()}")

        branches = {}
        for name, image in images.items():
            branches[f"nds.{name}"] = unconditional_branches(image["elf"])
        assert any(branches.values()), "the fixture has no unconditional branches"

        store = sqlite3.connect(project / "project.sqlite")
        crossing_checked = 0
        internal_checked = 0
        rows_by_program = {}
        for program_id, program in store.execute("SELECT id, name FROM programs"):
            functions = {int(entry, 16): size for entry, size in store.execute(
                "SELECT entry, size FROM functions WHERE program_id = ?", (program_id,))}
            assert set(functions) == EXPECTED_FUNCTIONS[program], (
                f"{program}: discovered functions changed to "
                f"{sorted(hex(a) for a in functions)}; recording a transfer "
                f"must not create a function"
            )
            recorded = {
                (int(src, 16), int(dst, 16)): provenance
                for src, dst, provenance in store.execute(
                    "SELECT src, dst, provenance FROM xrefs "
                    "WHERE program_id = ? AND kind = ?", (program_id, JUMP))
            }
            rows_by_program[program] = sorted(
                (f"{src:08x}", f"{dst:08x}") for src, dst in recorded)

            expected = set()
            for source, target in branches[program]:
                owner = containing(functions, source)
                if owner is None:
                    continue  # a branch outside every discovered function
                if functions[owner] and owner <= target < owner + functions[owner]:
                    internal_checked += 1
                    assert (source, target) not in recorded, (
                        f"{program}: a branch inside {owner:#x} was recorded as a "
                        f"jump reference ({source:#x} -> {target:#x}); loops are "
                        f"not transfers out of a function"
                    )
                    continue
                crossing_checked += 1
                expected.add((source, target))

            assert set(recorded) == expected, (
                f"{program}: recorded jump references "
                f"{sorted((hex(a), hex(b)) for a, b in recorded)} do not match the "
                f"transfers its own disassembly proves "
                f"{sorted((hex(a), hex(b)) for a, b in expected)}"
            )
            for edge, provenance in recorded.items():
                assert provenance, f"{program}: jump reference {edge} has no provenance"

        assert crossing_checked, "no cross-function branch was checked"
        assert internal_checked, "no intra-function branch was checked"

        # The specific deficit m5-002 recorded: the transfer into `mix`.
        arm7 = store.execute(
            "SELECT id FROM programs WHERE name = 'nds.arm7'").fetchone()
        assert arm7, "the ARM7 program is missing"
        into_mix = store.execute(
            "SELECT src, kind FROM xrefs WHERE program_id = ? AND dst = ?",
            (arm7[0], f"{TAIL_CALL[1]:08x}")).fetchall()
        assert (f"{TAIL_CALL[0]:08x}", JUMP) in into_mix, (
            f"the tail call into {TAIL_CALL[1]:#x} is still unrecorded; "
            f"references to it are {into_mix}"
        )

    scored = None
    if arguments.corpus_dir:
        scored = score_against_ghidra(cli, arguments.corpus_dir,
                                      arguments.oracle_dir, arguments.timeout)

    summary = (f"{crossing_checked} cross-function transfer(s) recorded, "
               f"{internal_checked} loop branch(es) correctly not recorded, "
               f"function set unchanged")
    if scored:
        summary += (
            f"; scored {scored['totals']['scored']} corpus entries against "
            f"Ghidra: jump precision "
            f"{scored['metrics']['flow_xref.jump.precision']:.4f}, "
            f"cross-function recall "
            f"{scored['metrics']['flow_xref.jump.cross_recall']:.4f}, "
            f"call precision {scored['metrics']['flow_xref.call.precision']:.4f}, "
            f"call recall {scored['metrics']['flow_xref.call.recall']:.4f}"
        )
    if arguments.report:
        metrics = {"transfers_recorded": crossing_checked,
                   "loops_excluded": internal_checked}
        if scored:
            metrics.update(scored["metrics"])
            report["thresholds"] = THRESHOLDS
            report["corpus"] = scored["corpus"]
        report.update(status="pass", passed=True, summary=summary,
                      metrics=metrics, rows=rows_by_program)
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps(report, indent=2) + "\n")
    print(f"m5-006: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
