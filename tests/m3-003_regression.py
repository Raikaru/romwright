#!/usr/bin/env python3
"""m3-003: native may not fall below the frozen stock-Ghidra baseline.

m3-001 measures native against DWARF truth; m3-002 freezes what stock Ghidra
scores on the same truth. This gate joins them so a native regression is a
failure rather than a footnote, and so the places where *both* producers are
below truth stay visible instead of passing because they match each other.

Assertions
  1. Every artifact the comparison consumes is fresh: the native evidence
     records the source hashes it was produced from, and they must equal the
     current tree. Stale evidence fails here; it never scores.
  2. Every locked ELF row is compared -- entries and prototype arity, native
     against the frozen baseline.
  3. `native >= baseline` per row for both families. Falling behind stock
     Ghidra is a regression even when the absolute number looks respectable.
  4. The known-deficit set is pinned: rows where either producer scores below
     0.98 against truth must be exactly the recorded ones, so a new deficit
     fails and a fixed one has to be recorded rather than silently absorbed.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "benchmarks/reports/m3-003.json"
# Recorded deficits: i386 `many_o2` prototype arity is 0.0000 for stock Ghidra
# and for native (`DecompilerParameterIdCmd` commits no parameters for 413 of
# 415 functions). M4 owns closing it; until then it is named, not hidden.
KNOWN_DEFICITS = {"i386_many_o2:proto.arity"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path, default=REPORT)
    arguments = parser.parse_args()

    command = [sys.executable, str(ROOT / "benchmarks/regression_gate.py"),
               "--corpus-dir", str(arguments.corpus_dir),
               "--report", str(arguments.report)]
    run = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
    print(run.stdout.strip())
    if run.returncode != 0:
        raise AssertionError(f"regression gate failed: {run.stderr.strip() or run.stdout.strip()}")

    report = json.loads(arguments.report.read_text())
    manifest = json.loads((arguments.corpus_dir / "manifest.json").read_text())
    lock = json.loads((ROOT / "tests/corpus.lock.json").read_text())
    matrix = set(lock["oracle_matrix"]["architectures"])
    expected = {f"{row['architecture']}_{row['variant']}"
                for row in manifest["entries"]
                if row.get("status") == "ok" and row["format"] == "elf"
                and row["architecture"] in matrix}
    compared = {row["id"] for row in report["rows"]}
    if compared != expected:
        raise AssertionError(f"rows not compared: {sorted(expected - compared)}, "
                             f"unexpected: {sorted(compared - expected)}")

    for artifact, freshness in report["freshness"].items():
        if not freshness["fresh"]:
            raise AssertionError(
                f"{artifact} is stale: {freshness['pin']} recorded "
                f"{freshness['recorded']}, tree has {freshness['current']}")

    for row in report["rows"]:
        for family in ("dwarf.fn.recall", "proto.arity"):
            native = row["native"][family]
            baseline = row["baseline"][family]
            if native + 1e-9 < baseline:
                raise AssertionError(
                    f"{row['id']}: native {family} {native:.4f} fell below the "
                    f"frozen baseline {baseline:.4f}")

    deficits = set(report["deficits"])
    if deficits != KNOWN_DEFICITS:
        raise AssertionError(
            f"deficit set changed: new {sorted(deficits - KNOWN_DEFICITS)}, "
            f"resolved {sorted(KNOWN_DEFICITS - deficits)}")

    if not report["passed"]:
        raise AssertionError("regression gate reported failure")

    totals = report["totals"]
    print(f"m3-003: PASS ({len(report['rows'])} rows; native entries "
          f"{totals['native.dwarf.fn.recall']:.4f} vs baseline "
          f"{totals['baseline.dwarf.fn.recall']:.4f}, native arity "
          f"{totals['native.proto.arity']:.4f} vs baseline "
          f"{totals['baseline.proto.arity']:.4f}, "
          f"{len(deficits)} recorded deficit(s))")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
