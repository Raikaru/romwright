#!/usr/bin/env python3
"""m3-002: the stock-Ghidra ground-truth baseline is frozen and reproducible.

M4 claims improvement over stock Ghidra. A claim like that is worth nothing
against a remembered number, so this milestone freezes one: what stock
Ghidra 12.1.3 scores against the compiler's own debug information on the
locked corpus, with the provenance to reproduce it.

Assertions
  1. `benchmarks/ground_truth_baseline.py` recomputes the committed baseline
     **byte for byte** from the pinned install, the locked corpus and the
     immutable stock references. A changed number fails here rather than
     being quietly re-baselined.
  2. Every locked ELF entry is present; a skipped row is never a pass.
  3. Each row carries the digests that make it reproducible: binary, twin,
     function-entry oracle, arity reference, and the bridge sources hash.
  4. The baseline agrees with the m3-001 gate on stock Ghidra's
     `dwarf.fn.recall`, so the two artifacts cannot drift apart.
  5. Recorded scores are real: truth counts positive, values in [0, 1].
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "benchmarks/reports/baseline-ghidra-truth.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()

    if not BASELINE.is_file():
        raise AssertionError(f"no committed baseline at {BASELINE.relative_to(ROOT)}")
    committed = BASELINE.read_bytes()

    with tempfile.TemporaryDirectory(prefix="m3-002-") as temporary:
        recomputed = Path(temporary) / "baseline.json"
        run = subprocess.run(
            [sys.executable, str(ROOT / "benchmarks/ground_truth_baseline.py"),
             "--corpus-dir", str(arguments.corpus_dir),
             "--baseline", str(recomputed), "--write"],
            cwd=ROOT, capture_output=True, text=True)
        print(run.stdout.strip())
        if run.returncode != 0:
            raise AssertionError(
                f"baseline recompute failed: {run.stderr.strip() or run.stdout.strip()}")
        produced = recomputed.read_bytes()

    if produced != committed:
        baseline = json.loads(committed)
        fresh = json.loads(produced)
        changed = [row["id"] for row, other in zip(baseline["rows"], fresh["rows"])
                   if row.get("metrics") != other.get("metrics")]
        raise AssertionError(
            "the committed baseline is not reproducible; "
            f"metrics changed on {changed or 'no row (provenance or shape differs)'}")

    baseline = json.loads(committed)
    manifest = json.loads((arguments.corpus_dir / "manifest.json").read_text())
    expected = {f"{row['architecture']}_{row['variant']}"
                for row in manifest["entries"] if row.get("status") == "ok"}
    scored = {row["id"] for row in baseline["rows"] if row["status"] == "recorded"}
    if scored != expected:
        raise AssertionError(f"baseline rows missing: {sorted(expected - scored)}, "
                             f"unexpected: {sorted(scored - expected)}")

    for row in baseline["rows"]:
        for digest in ("binary_sha256", "twin_sha256", "oracle_sha256",
                       "arity_reference_sha256", "bridge_sources_sha256"):
            if len(row["provenance"].get(digest, "")) != 64:
                raise AssertionError(f"{row['id']}: missing {digest} provenance")
        metrics = row["metrics"]
        if metrics["dwarf.functions"] <= 0 or metrics["dwarf.arity_matched"] <= 0:
            raise AssertionError(f"{row['id']}: baseline recorded an empty truth set")
        for key in ("ghidra.dwarf.fn.recall", "ghidra.dwarf.proto.arity"):
            if not 0.0 <= metrics[key] <= 1.0:
                raise AssertionError(f"{row['id']}: {key} = {metrics[key]} is not a ratio")

    # 4. Cross-artifact consistency with the m3-001 gate.
    gate_report = ROOT / "benchmarks/reports/m3-001.json"
    if not gate_report.is_file():
        raise AssertionError("m3-001 gate evidence is missing")
    gate = json.loads(gate_report.read_text())
    gate_recall = {row["id"]: row["metrics"]["ghidra.dwarf.fn.recall"]
                   for row in gate["rows"] if row["status"] == "pass"}
    for row in baseline["rows"]:
        if row["status"] != "recorded":
            continue
        recorded = row["metrics"]["ghidra.dwarf.fn.recall"]
        if row["id"] not in gate_recall:
            raise AssertionError(f"{row['id']}: absent from the m3-001 gate evidence")
        if abs(gate_recall[row["id"]] - recorded) > 1e-9:
            raise AssertionError(
                f"{row['id']}: baseline recall {recorded} disagrees with the "
                f"m3-001 gate's {gate_recall[row['id']]}")

    totals = baseline["totals"]
    if arguments.report:
        arguments.report.write_text(json.dumps(
            {"id": "m3-002", "status": "pass", "totals": totals}, indent=2) + "\n")
    print(f"m3-002: PASS (baseline reproduced byte-for-byte; stock Ghidra "
          f"{totals['ghidra.dwarf.fn.recall']:.4f} entry recall and "
          f"{totals['ghidra.dwarf.proto.arity']:.4f} arity over "
          f"{totals['dwarf.functions']} DWARF functions)")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
