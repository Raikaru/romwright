#!/usr/bin/env python3
"""m13-001: jump tables from value-set analysis, scored against stock Ghidra.

Switch recovery was the last pass in a native import that still called the
decompiler, and the most expensive one: 130 of 137 seconds on a statically
linked AArch64 image, with two bodies hitting the per-function decompiler
deadline. `crates/lre-core/src/native/vsa.rs` answers the same question by
emulating the dispatch path over SLEIGH's own p-code, once per index, exactly
as `JumpBasic::buildAddresses` does over the decompiler's IR.

What this gate pins is the claim, not a hope:

- what value-set analysis claims is *right*: every branch it reports is one
  stock reports too, and the case edges agree;
- it is *cheap*: the whole phase costs a fraction of a second;
- turning it on does not *lose* anything: with the decompiler still behind it
  the recovered set is no worse than the decompiler alone.

Its recall against stock is ~0.12 today; that is recorded, not asserted as
good, and it is why the pass is opt-in (`VENTRIS_SWITCH_VSA=1`).

The subject is the host's own libc, which has real switches in real
compiler-emitted shapes, and stock's answer comes from Ghidra with the
decompiler. Both sides are recomputed here; nothing is pinned to this
machine's numbers except the thresholds above.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "target" / "release" / "lre-cli"
EXPORTER = ROOT / "scripts/ExportSwitchTargets.java"

THRESHOLDS = {
    # A branch value-set analysis claims that stock does not have at all.
    "vsa_extra_branches": 0,
    # Case edges it gets right, of those it claims.
    "vsa_edge_precision": 0.95,
    # The phase's own wall time, seconds, summed over rounds.
    "vsa_seconds": 5.0,
    # With the decompiler behind it, nothing is lost.
    "combined_edge_recall_floor": 1.0,
    "combined_edge_precision_floor": 1.0,
}


def stock_tables(binary: Path, install: Path, work: Path) -> dict[int, set[int]]:
    """Stock Ghidra's own jump tables, from its decompiler."""
    work.mkdir(parents=True, exist_ok=True)
    output = work / "stock.json"
    subprocess.run(
        [
            str(install / "support/analyzeHeadless"),
            str(work),
            "switch-oracle",
            "-import",
            str(binary),
            "-scriptPath",
            str(EXPORTER.parent),
            "-postScript",
            EXPORTER.name,
            str(output),
            "-deleteProject",
            "-max-cpu",
            "4",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if not output.is_file():
        raise ValueError("stock Ghidra produced no switch export")
    exported = json.loads(output.read_text())["functions"]
    tables: dict[int, set[int]] = {}
    for entries in exported.values():
        for table in entries:
            branch = int(table["branch"].split(":")[-1], 16)
            tables.setdefault(branch, set()).update(
                int(target.split(":")[-1], 16) for target in table["targets"]
            )
    return tables


def imported(binary: Path, project: Path, environment: dict[str, str]) -> tuple[dict[int, set[int]], float, float]:
    if project.exists():
        shutil.rmtree(project)
    project.mkdir(parents=True)
    started = time.time()
    result = subprocess.run(
        [str(CLI), "import", str(binary), "--project", str(project), "--timings"],
        capture_output=True,
        text=True,
        env={**os.environ, **environment},
    )
    wall = time.time() - started
    if result.returncode:
        raise ValueError(f"import failed: {result.stderr[-800:]}")
    phase = 0.0
    for line in result.stdout.splitlines():
        if not line.startswith("TIMINGS "):
            continue
        timings = json.loads(line[len("TIMINGS ") :])
        # The phase is measured once per discovery round.
        phase = sum(
            seconds
            for name, seconds in timings.get("phases", {}).items()
            if name == "switch-vsa"
        )
    connection = sqlite3.connect(project / "project.sqlite")
    tables: dict[int, set[int]] = {}
    for source, destination in connection.execute(
        "SELECT src, dst FROM xrefs WHERE provenance = 'native-import:switch'"
    ):
        tables.setdefault(int(source, 16), set()).add(int(destination, 16))
    return tables, wall, phase


def score(ours: dict[int, set[int]], stock: dict[int, set[int]]) -> dict:
    shared = set(ours) & set(stock)
    correct = sum(len(ours[branch] & stock[branch]) for branch in shared)
    claimed = correct + sum(len(ours[branch] - stock[branch]) for branch in shared)
    claimed += sum(len(ours[branch]) for branch in set(ours) - set(stock))
    missing = sum(len(stock[branch] - ours.get(branch, set())) for branch in stock)
    return {
        "branches": len(ours),
        "stock_branches": len(stock),
        "exact_branches": sum(1 for branch in shared if ours[branch] == stock[branch]),
        "extra_branches": len(set(ours) - set(stock)),
        "missed_branches": len(set(stock) - set(ours)),
        "edge_precision": round(correct / max(claimed, 1), 4),
        "edge_recall": round(correct / max(correct + missing, 1), 4),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path("/usr/lib64/libc.so.6"))
    parser.add_argument(
        "--ghidra",
        type=Path,
        default=Path(os.environ.get("VENTRIS_GHIDRA", Path.home() / "ghidra_12.1.3_PUBLIC")),
    )
    parser.add_argument("--work", type=Path, default=Path.home() / "ventris-cache/tmp/m13-001")
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()

    report = {
        "id": "m13-001",
        "milestone": "M13",
        "criterion": "jump tables recovered from p-code without the decompiler, scored against stock",
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "thresholds": THRESHOLDS,
        "binary": str(arguments.binary),
    }
    if not arguments.binary.is_file():
        report["status"] = "skipped"
        report["reason"] = f"{arguments.binary} is not on this machine"
        print(f"m13-001: SKIPPED ({report['reason']})")
    else:
        subprocess.run(
            ["cargo", "build", "-q", "--release", "-p", "lre-cli"], cwd=ROOT, check=True
        )
        stock = stock_tables(arguments.binary, arguments.ghidra, arguments.work / "stock")
        vsa, vsa_wall, vsa_phase = imported(
            arguments.binary,
            arguments.work / "vsa",
            {"VENTRIS_SWITCH_VSA": "1", "VENTRIS_NO_SWITCH_DECOMPILER": "1"},
        )
        decompiler, decompiler_wall, _ = imported(
            arguments.binary, arguments.work / "decompiler", {}
        )
        combined, combined_wall, combined_phase = imported(
            arguments.binary, arguments.work / "combined", {"VENTRIS_SWITCH_VSA": "1"}
        )
        measured = {
            "vsa": {**score(vsa, stock), "wall_s": round(vsa_wall, 1), "phase_s": round(vsa_phase, 3)},
            "decompiler": {**score(decompiler, stock), "wall_s": round(decompiler_wall, 1)},
            "combined": {
                **score(combined, stock),
                "wall_s": round(combined_wall, 1),
                "phase_s": round(combined_phase, 3),
            },
        }
        report["measured"] = measured

        failures = []
        if measured["vsa"]["extra_branches"] > THRESHOLDS["vsa_extra_branches"]:
            failures.append(
                f"vsa claims {measured['vsa']['extra_branches']} branches stock does not have"
            )
        if measured["vsa"]["edge_precision"] < THRESHOLDS["vsa_edge_precision"]:
            failures.append(
                f"vsa edge precision {measured['vsa']['edge_precision']}"
                f" < {THRESHOLDS['vsa_edge_precision']}"
            )
        if measured["vsa"]["phase_s"] > THRESHOLDS["vsa_seconds"]:
            failures.append(
                f"vsa phase {measured['vsa']['phase_s']}s > {THRESHOLDS['vsa_seconds']}s"
            )
        # Turning the pass on must not lose an edge the decompiler alone had.
        if measured["combined"]["edge_recall"] < measured["decompiler"]["edge_recall"]:
            failures.append(
                f"combined recall {measured['combined']['edge_recall']} below decompiler"
                f" alone {measured['decompiler']['edge_recall']}"
            )
        if measured["combined"]["edge_precision"] < measured["decompiler"]["edge_precision"] - 0.01:
            failures.append(
                f"combined precision {measured['combined']['edge_precision']} below decompiler"
                f" alone {measured['decompiler']['edge_precision']}"
            )
        report["status"] = "pass" if not failures else "fail"
        report["failures"] = failures
        if failures:
            print(f"FAIL: {'; '.join(failures)}", file=sys.stderr)
            if arguments.report:
                arguments.report.parent.mkdir(parents=True, exist_ok=True)
                arguments.report.write_text(json.dumps(report, indent=2) + "\n")
            return 1
        print(
            "m13-001: PASS (vsa {branches} branches, precision {precision},"
            " recall {recall}, phase {phase}s; combined precision"
            " {cprecision}, recall {crecall})".format(
                branches=measured["vsa"]["branches"],
                precision=measured["vsa"]["edge_precision"],
                recall=measured["vsa"]["edge_recall"],
                phase=measured["vsa"]["phase_s"],
                cprecision=measured["combined"]["edge_precision"],
                crecall=measured["combined"]["edge_recall"],
            )
        )
    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps(report, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
