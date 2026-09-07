#!/usr/bin/env python3
"""m3-003: hold native at or above the frozen stock-Ghidra ground truth.

m3-001 scores native against DWARF; m3-002 froze what stock Ghidra scores on
the same truth. This gate joins them per corpus row so that

  * a native regression fails instead of being noticed later, and
  * a row where *both* producers are below truth stays named, instead of
    passing because the two agree with each other.

Evidence is re-measured by default -- the native prototype pass costs about a
minute -- because the failure this gate is most likely to hit is stale
evidence. Supplied artifacts are accepted only when the source hashes they
record still match the tree.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from gen_oracle import digest

BASELINE = ROOT / "benchmarks/reports/baseline-ghidra-truth.json"
TRUTH_THRESHOLD = 0.98
PINS = {
    "dwarf_gate_sha256": ROOT / "benchmarks/dwarf_gate.py",
    "dwarf_reader_sha256": ROOT / "benchmarks/dwarf_arity.py",
    "native_patch_sha256": ROOT / "native/ghidra-opt-sleigh.patch",
    "native_linkage_sha256": ROOT / "native/ventris_linkage.hh",
}


def freshness(name: str, document: dict, pins: dict) -> dict:
    """Compare an artifact's recorded source hashes against this tree."""
    stale = []
    for pin, recorded in pins.items():
        current = digest(PINS[pin])
        if current != recorded:
            stale.append({"pin": pin, "recorded": recorded, "current": current})
    return {"artifact": name, "fresh": not stale,
            "pin": stale[0]["pin"] if stale else None,
            "recorded": stale[0]["recorded"] if stale else None,
            "current": stale[0]["current"] if stale else None,
            "stale": stale}


def run_gate(script: str, arguments: list[str], report: Path) -> dict:
    environment = dict(os.environ)
    result = subprocess.run(
        [sys.executable, str(ROOT / script), *arguments, "--report", str(report)],
        cwd=ROOT, env=environment, capture_output=True, text=True)
    if result.returncode != 0 or not report.is_file():
        raise ValueError(f"{script} failed: {result.stderr.strip() or result.stdout.strip()}")
    return json.loads(report.read_text())


def native_arity_scores(report: dict, report_path: Path) -> dict:
    """Exact matched/correct counts from the per-architecture detail files."""
    scores = {}
    for row in report["corpus"]:
        if row["status"] != "pass":
            continue
        evidence = row["evidence"]
        detail_path = report_path.parent / evidence["path"]
        if digest(detail_path) != evidence["sha256"]:
            raise ValueError(f"{row['id']}: arity detail evidence changed after the run")
        detail = json.loads(detail_path.read_text())
        entry = next(item for item in detail["corpus"] if item["id"] == row["id"])
        scores[row["id"]] = {
            "native": entry["scores"]["native"], "ghidra": entry["scores"]["ghidra"]}
    return scores


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--native-entries", type=Path,
                        help="reuse an m3-001 report instead of re-measuring")
    parser.add_argument("--native-arity", type=Path,
                        help="reuse a prototype-gate report instead of re-measuring")
    parser.add_argument("--budget-ms", type=int, default=60000)
    arguments = parser.parse_args()

    baseline = json.loads(BASELINE.read_text())
    baseline_rows = {row["id"]: row for row in baseline["rows"] if row["status"] == "recorded"}

    with tempfile.TemporaryDirectory(prefix="m3-003-") as temporary:
        work = Path(temporary)
        if arguments.native_entries:
            entries_path = arguments.native_entries
            entries = json.loads(entries_path.read_text())
        else:
            entries_path = work / "dwarf-truth.json"
            entries = run_gate("benchmarks/dwarf_gate.py",
                               ["--corpus-dir", str(arguments.corpus_dir)], entries_path)
        if arguments.native_arity:
            arity_path = arguments.native_arity
            arity = json.loads(arity_path.read_text())
        else:
            arity_path = work / "native-arity.json"
            arity = run_gate("benchmarks/prototype_gate.py",
                             ["--corpus-dir", str(arguments.corpus_dir),
                              "--budget-ms", str(arguments.budget_ms)], arity_path)
        arity_scores = native_arity_scores(arity, arity_path)

        checks = {
            "native_entries": freshness("native_entries", entries, entries["sources"]),
            "native_arity": freshness("native_arity", arity, {
                key: arity[key] for key in
                ("dwarf_reader_sha256", "native_patch_sha256", "native_linkage_sha256")}),
        }

        rows, deficits = [], []
        totals = {"truth_functions": 0, "native_entries_matched": 0,
                  "baseline_entries_matched": 0, "arity_matched": 0,
                  "native_arity_correct": 0, "baseline_arity_correct": 0}
        for identifier, recorded in baseline_rows.items():
            entry_row = next((row for row in entries["rows"]
                              if row["id"] == identifier and row["status"] == "pass"), None)
            if entry_row is None:
                raise ValueError(f"{identifier}: no native entry evidence")
            if identifier not in arity_scores:
                raise ValueError(f"{identifier}: no native arity evidence")
            native_arity = arity_scores[identifier]["native"]
            reference_arity = arity_scores[identifier]["ghidra"]
            frozen = recorded["metrics"]
            # The two artifacts must project the same truth, or the comparison
            # is between different questions.
            if abs(reference_arity["value"] - frozen["ghidra.dwarf.proto.arity"]) > 1e-9:
                raise ValueError(
                    f"{identifier}: arity reference {reference_arity['value']} disagrees "
                    f"with the frozen baseline {frozen['ghidra.dwarf.proto.arity']}")
            if abs(entry_row["metrics"]["ghidra.dwarf.fn.recall"]
                   - frozen["ghidra.dwarf.fn.recall"]) > 1e-9:
                raise ValueError(
                    f"{identifier}: entry reference disagrees with the frozen baseline")

            native = {"dwarf.fn.recall": entry_row["metrics"]["native.dwarf.fn.recall"],
                      "proto.arity": native_arity["value"]}
            frozen_pair = {"dwarf.fn.recall": frozen["ghidra.dwarf.fn.recall"],
                           "proto.arity": frozen["ghidra.dwarf.proto.arity"]}
            row = {"id": identifier, "native": native, "baseline": frozen_pair,
                   "delta": {family: native[family] - frozen_pair[family]
                             for family in native},
                   "counts": {"dwarf_functions": frozen["dwarf.functions"],
                              "arity_matched": native_arity["matched"],
                              "native_arity_correct": native_arity["correct"],
                              "baseline_arity_matched": frozen["dwarf.arity_matched"],
                              "baseline_arity_correct": frozen["ghidra.arity_correct"]}}
            row["status"] = "pass" if all(
                native[family] + 1e-9 >= frozen_pair[family] for family in native) else "fail"
            for family in native:
                if min(native[family], frozen_pair[family]) < TRUTH_THRESHOLD:
                    deficits.append(f"{identifier}:{family}")
            rows.append(row)
            totals["truth_functions"] += frozen["dwarf.functions"]
            totals["native_entries_matched"] += round(
                native["dwarf.fn.recall"] * frozen["dwarf.functions"])
            totals["baseline_entries_matched"] += round(
                frozen_pair["dwarf.fn.recall"] * frozen["dwarf.functions"])
            totals["arity_matched"] += native_arity["matched"]
            totals["native_arity_correct"] += native_arity["correct"]
            totals["baseline_arity_correct"] += frozen["ghidra.arity_correct"]
            print(f"{row['status'].upper()} {identifier}: entries "
                  f"{native['dwarf.fn.recall']:.4f} vs {frozen_pair['dwarf.fn.recall']:.4f}, "
                  f"arity {native['proto.arity']:.4f} vs "
                  f"{frozen_pair['proto.arity']:.4f}", flush=True)

    report = {
        "id": "m3-003", "recorded_at": datetime.now(timezone.utc).isoformat(),
        "thresholds": {"native.vs.baseline": "native >= baseline per row",
                       "truth_threshold": TRUTH_THRESHOLD},
        "freshness": checks, "rows": rows, "deficits": sorted(set(deficits)),
        "totals": dict(
            totals,
            **{"native.dwarf.fn.recall": totals["native_entries_matched"] / totals["truth_functions"],
               "baseline.dwarf.fn.recall": totals["baseline_entries_matched"] / totals["truth_functions"],
               "native.proto.arity": totals["native_arity_correct"] / totals["arity_matched"],
               "baseline.proto.arity": totals["baseline_arity_correct"] / totals["arity_matched"]}),
        "summary": {"pass": sum(1 for row in rows if row["status"] == "pass"),
                    "fail": sum(1 for row in rows if row["status"] == "fail")},
    }
    report["passed"] = (report["summary"]["fail"] == 0
                        and all(check["fresh"] for check in checks.values())
                        and len(rows) == len(baseline_rows))
    arguments.report.parent.mkdir(parents=True, exist_ok=True)
    arguments.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"summary": report["summary"], "deficits": report["deficits"],
                      "totals": report["totals"], "passed": report["passed"]}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
