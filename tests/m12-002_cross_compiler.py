#!/usr/bin/env python3
"""m12-002: name transfer across compilers, scored on a real pair.

m12-001 scores the diff on same-compiler builds and on ELF twins, where
truth comes for free. It passed while the matcher placed half its
structural rows on a GCC-Mac / MSVC-Windows pair of one game at chance,
and while the Mach-O import it depended on was wrong. This gate runs that
pair: the Mac build of KOTOR II (`kotor2sub`, i386 slice, symbols) as the
reference and the unpacked Windows `swkotor2.exe` (stripped) as the
target.

Two truths, neither of them the matcher's own:

* **Named addresses** -- a hand-verified map of Windows entries to Mac
  symbols. A name the diff places is right when it lands on any Windows
  entry the map gives that name (constructor variants share one).
* **Mac-only names** -- SDL, `*_Mac`, ASL and the like cannot name
  Windows code, so every row carrying one is wrong. It sees only a slice
  of the errors, but a slice that does not depend on what else is
  labelled, and per evidence class.

Both programs are indexed after import (`index-semantics`): the literal
operands the index keeps are the one content term measured to carry
identity across the compiler change, so the gate scores the diff as it
should be run. The inputs are private, so a runner skips with a reason,
as the modules rows of m12-001 do.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import struct
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "target" / "release" / "romwright-cli"
NIHILUS = Path.home() / "Nihilus"
FAT = NIHILUS / "KOTOR2sub"
TARGET = Path.home() / "nihilus-lab" / "unpack" / "swkotor2.exe.unpacked.exe"
TRUTH = NIHILUS / ".private" / "research" / "SYM-0001" / "symbol-map-extended.json"

# Measured 2026-09-23 with both programs indexed: named 245 right / 3
# wrong (0.9879; all three are call-graph pairs of content 0.11-0.24);
# Mac-only Alignment 0.12%, CallGraph 0.0%, Context 0.69%; 487 anchors,
# 6,010 rows. Before that day's fixes this pair read 8 anchors and
# Mac-only 4.5% / 5.4%, failing every ceiling below by a wide margin.
THRESHOLDS = {
    "named.precision": 0.98,
    "named.right": 235,
    "maconly.alignment": 0.01,
    "maconly.call-graph": 0.01,
    "maconly.context": 0.02,
    "anchors": 400,
}
# The wrong named rows as measured, each with its cause. The two C1
# constructors are GCC's complete-object stubs (`push ebp; mov ebp,esp;
# pop ebp; jmp C2`): MSVC emits one constructor, so a stub has no Windows
# counterpart, and the call-graph extension placed each on its C2 body's
# real caller on one vote. The C2 bodies themselves land right on string
# anchors.
EXPECTED_WRONG = {
    ("CSWTrackFollower::Load(CResGFF*, CResStruct*)", "0x4f8a70"),
    ("CExoInputInternal::CExoInputInternal(HINSTANCE__*, HWND__*)", "0x62b6f0"),
    ("CSWGuiInGameOptKeyMappings::CSWGuiInGameOptKeyMappings(CSWGuiManager*)", "0x759480"),
}
MAC_ONLY = re.compile(r"SDL|_Mac\b|Mac[A-Z_]|\bMac\b|\bASL|Cocoa|NSApp|Carbon|objc_|_mac\b")
# Names with no identity of their own: generated labels, compiler tables
# and runtime-library code both builds carry under different names.
UNSCORED = re.compile(
    r"^(FUN_|GCC_except_table|typeinfo|vtable|std::|__cxx|__gnu|operator new"
    r"|operator delete|__cxa|__Unwind|_Unwind)"
)


def i386_slice(fat: Path, out: Path) -> Path:
    data = fat.read_bytes()
    for index in range(struct.unpack(">I", data[4:8])[0]):
        cpu, _, offset, size, _ = struct.unpack(">5I", data[8 + index * 20:28 + index * 20])
        if cpu == 7:
            out.write_bytes(data[offset:offset + size])
            return out
    raise ValueError("no i386 slice")


def import_program(binary: Path, project: Path, name: str) -> None:
    if project.exists():
        shutil.rmtree(project)
    project.mkdir(parents=True)
    result = subprocess.run(
        [str(CLI), "import", str(binary), "--project", str(project), "--name", name],
        capture_output=True, text=True)
    if result.returncode:
        raise ValueError(f"import {binary.name} failed: {result.stderr[-800:]}")
    result = subprocess.run(
        [str(CLI), "index-semantics", str(binary), name, "--project", str(project)],
        capture_output=True, text=True)
    if result.returncode:
        raise ValueError(f"index {binary.name} failed: {result.stderr[-800:]}")


def demangle(names: list[str]) -> list[str]:
    out = subprocess.run(["c++filt"], input="\n".join(names), capture_output=True,
                         text=True, check=True).stdout.split("\n")
    return out[:len(names)]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--reference", type=Path, default=FAT)
    parser.add_argument("--target", type=Path, default=TARGET)
    parser.add_argument("--truth", type=Path, default=TRUTH)
    arguments = parser.parse_args()
    missing = [str(path) for path in (arguments.reference, arguments.target, arguments.truth)
               if not path.is_file()]
    report = {
        "id": "m12-002",
        "milestone": "M12",
        "criterion": "cross-compiler name transfer, scored against named addresses"
                     " and Mac-only names",
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "thresholds": THRESHOLDS,
    }
    if missing:
        report.update(status="skipped", reason=f"inputs absent: {missing}")
        if arguments.report:
            arguments.report.parent.mkdir(parents=True, exist_ok=True)
            arguments.report.write_text(json.dumps(report, indent=2) + "\n")
        print(f"m12-002: SKIPPED (inputs absent: {', '.join(missing)})")
        return 0
    arguments.work.mkdir(parents=True, exist_ok=True)
    subprocess.run(["cargo", "build", "-q", "--release", "-p", "romwright-cli",
                    "-p", "romwright-worker"], cwd=ROOT, check=True)

    reference_binary = i386_slice(arguments.reference, arguments.work / "kotor2sub-i386.bin")
    reference_project = arguments.work / "mac"
    target_project = arguments.work / "win"
    import_program(reference_binary, reference_project, "kotor2sub_i386")
    import_program(arguments.target, target_project, "swkotor2")
    result = subprocess.run(
        [str(CLI), "diff", "swkotor2", "--project", str(target_project),
         "--reference", str(reference_project), "--reference-name", "kotor2sub_i386",
         "--matcher", "nap", "--no-semantic", "--json"],
        capture_output=True, text=True)
    if result.returncode:
        raise ValueError(f"diff failed: {result.stderr[-800:]}")
    diff = json.loads(result.stdout)
    rows = diff["matches"]
    names = demangle([row["reference_name"] for row in rows])

    # Named addresses: every Windows entry the map gives a name.
    entries_by_name: dict[str, set[int]] = {}
    for record in json.loads(arguments.truth.read_text())["names"]:
        entries_by_name.setdefault(record["mac_symbol"], set()).add(int(record["entry"], 16))
    named = {"right": 0, "wrong": 0, "wrong_rows": []}
    maconly: dict[str, dict[str, int]] = {}
    for row, name in zip(rows, names):
        target = row["target"]["offset"]
        evidence = row["evidence"]
        if name in entries_by_name:
            if target in entries_by_name[name]:
                named["right"] += 1
            else:
                named["wrong"] += 1
                named["wrong_rows"].append(
                    {"name": name, "target": f"{target:#x}", "evidence": evidence,
                     "score": row["score"]})
        if UNSCORED.match(name):
            continue
        bucket = maconly.setdefault(evidence, {"rows": 0, "mac_only": 0})
        bucket["rows"] += 1
        bucket["mac_only"] += bool(MAC_ONLY.search(name))
    judged = named["right"] + named["wrong"]
    named["precision"] = round(named["right"] / max(judged, 1), 4)
    for bucket in maconly.values():
        bucket["rate"] = round(bucket["mac_only"] / max(bucket["rows"], 1), 4)

    measured = {"named": named, "maconly": maconly, "anchors": diff.get("anchors", 0),
                "rows": len(rows)}
    failures = []
    if named["precision"] < THRESHOLDS["named.precision"]:
        failures.append(f"named.precision {named['precision']} < {THRESHOLDS['named.precision']}")
    if named["right"] < THRESHOLDS["named.right"]:
        failures.append(f"named.right {named['right']} < {THRESHOLDS['named.right']}")
    for evidence in ("alignment", "call-graph", "context"):
        rate = maconly.get(evidence, {}).get("rate", 0.0)
        ceiling = THRESHOLDS[f"maconly.{evidence}"]
        if rate > ceiling:
            failures.append(f"maconly.{evidence} {rate} > {ceiling}")
    if measured["anchors"] < THRESHOLDS["anchors"]:
        failures.append(f"anchors {measured['anchors']} < {THRESHOLDS['anchors']}")
    # Every wrong named row must be a known one, and a known one that no
    # longer occurs is stale: the record tracks the matcher, not a floor.
    seen_wrong = {(row["name"], row["target"]) for row in named["wrong_rows"]}
    for name, target in sorted(seen_wrong - EXPECTED_WRONG):
        failures.append(f"new wrong placement: {name} at {target}")
    for name, target in sorted(EXPECTED_WRONG - seen_wrong):
        failures.append(f"expected miss {name} at {target} no longer occurs"
                        " -- remove it from EXPECTED_WRONG")
    report.update(measured=measured, status="pass" if not failures else "fail",
                  failures=failures)
    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps(report, indent=2) + "\n")
    if failures:
        print(f"FAIL: {'; '.join(failures)}", file=sys.stderr)
        return 1
    rates = ", ".join(f"{k} {v['rate']}" for k, v in sorted(maconly.items()))
    print(f"m12-002: PASS (named {named['right']}/{judged}; Mac-only {rates};"
          f" anchors {measured['anchors']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
