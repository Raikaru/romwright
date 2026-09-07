#!/usr/bin/env python3
"""m3-001: function recovery scored against DWARF truth, not against Ghidra.

Every `fn.*` number so far measures parity with Ghidra's own analysis. That
says the two tools agree; it does not say either is right. M3 scores against
the compiler's own debug information on the locked corpus, and records what
stock Ghidra scores on the same truth so later milestones have a baseline
rather than an anecdote.

Assertions
  1. `benchmarks/dwarf_gate.py` scores every locked corpus entry -- a
     skipped row is a skipped row, never a pass.
  2. Truth is the compiler's: concrete `DW_TAG_subprogram` entries inside
     executable segments, biased to the store's own image base for ET_DYN.
     Every row carries a non-empty truth set and its provenance digests.
  3. `dwarf.fn.recall >= 0.98` per row and in aggregate, for the native
     importer and for the pinned stock-Ghidra oracle.
  4. `dwarf.fn.unattributed == 0`: a recovered entry that DWARF does not
     describe must still be explained -- a symbol in the unstripped twin, a
     store thunk row, a linker stub inside a `.plt*` section, or a function
     stock Ghidra also created. Anything else is an invented function.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
RECALL_THRESHOLD = 0.98


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()

    report_path = arguments.report or Path(
        subprocess.check_output(["mktemp", "-t", "m3-001-XXXXXX.json"], text=True).strip())
    result = subprocess.run(
        [sys.executable, str(ROOT / "benchmarks/dwarf_gate.py"),
         "--corpus-dir", str(arguments.corpus_dir), "--report", str(report_path)],
        cwd=ROOT, capture_output=True, text=True)
    print(result.stdout.strip())
    if result.returncode != 0:
        raise AssertionError(f"dwarf gate failed: {result.stderr.strip() or result.stdout.strip()}")

    report = json.loads(report_path.read_text())
    manifest = json.loads((arguments.corpus_dir / "manifest.json").read_text())
    expected = {f"{row['architecture']}_{row['variant']}"
                for row in manifest["entries"] if row.get("status") == "ok"}
    scored = {row["id"] for row in report["rows"]}
    if scored != expected:
        raise AssertionError(f"unscored corpus entries: {sorted(expected - scored)}, "
                             f"unexpected rows: {sorted(scored - expected)}")

    skipped = [row["id"] for row in report["rows"] if row["status"] != "pass"]
    if skipped:
        raise AssertionError(f"rows did not pass: {skipped}")

    for row in report["rows"]:
        if not row["truth"]["functions"]:
            raise AssertionError(f"{row['id']}: empty DWARF truth set")
        for digest in ("binary_sha256", "twin_sha256", "oracle_sha256"):
            if len(row["provenance"].get(digest, "")) != 64:
                raise AssertionError(f"{row['id']}: missing {digest} provenance")
        for producer in ("native", "ghidra"):
            recall = row["metrics"][f"{producer}.dwarf.fn.recall"]
            if recall < RECALL_THRESHOLD:
                raise AssertionError(
                    f"{row['id']}: {producer} dwarf.fn.recall {recall:.4f} < {RECALL_THRESHOLD}")
        if row["metrics"]["native.dwarf.fn.unattributed"] != 0:
            raise AssertionError(
                f"{row['id']}: {row['metrics']['native.dwarf.fn.unattributed']} recovered "
                f"entries are neither DWARF, symbol, thunk, stub nor Ghidra: "
                f"{row['unattributed']}")

    totals = report["totals"]
    for producer in ("native", "ghidra"):
        recall = totals[f"{producer}.dwarf.fn.recall"]
        if recall < RECALL_THRESHOLD:
            raise AssertionError(
                f"aggregate {producer} dwarf.fn.recall {recall:.4f} < {RECALL_THRESHOLD}")
    if not report["passed"]:
        raise AssertionError("gate reported failure")

    print(f"m3-001: PASS ({totals['truth_functions']} DWARF functions over "
          f"{len(report['rows'])} corpus entries; native recall "
          f"{totals['native.dwarf.fn.recall']:.4f}, stock Ghidra "
          f"{totals['ghidra.dwarf.fn.recall']:.4f}, "
          f"{totals['native.dwarf.fn.unattributed']} unattributed)")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
