#!/usr/bin/env python3
"""m7-001: what an import costs, measured against stock Ghidra per entry.

`benchmarks/gate.sh` measures peak RSS and wall time for one tiny fixture, and
`baseline-stock.json` records a stock number for that same fixture. Nothing
compared the two producers on the locked corpus, so "JVM-free is cheaper" was
a claim without per-entry evidence.

This gate imports every locked corpus entry with both producers on the same
inputs, in the same way, and measures each with `os.wait4`, whose `ru_maxrss`
covers the process and the children it waited for -- the same accounting the
stock baseline documents. It then requires, per entry:

  * the native import to peak lower than stock analysis;
  * the native import to finish sooner than stock analysis;
  * the native peak to stay inside the frozen envelope in
    `benchmarks/reports/cost-envelope.json`, with 25% headroom for host noise.

The envelope is recorded once with `--write` and never edited afterwards: a
regression has to show up as a failure, not as a new number.

Usage:
    python3 tests/m7-001_cost_envelope.py --corpus-dir DIR [--write] [--report OUT.json]
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "benchmarks"))
from cost import (HEADROOM, build_shipped, check_envelope, measure,  # noqa: E402
                  record_envelope, shipped_binary)

ENVELOPE = ROOT / "benchmarks" / "reports" / "cost-envelope.json"


def native(binary: Path) -> tuple[float, int]:
    with tempfile.TemporaryDirectory(prefix="m7-001-native-") as temporary:
        elapsed, peak, code = measure(
            [str(shipped_binary(ROOT, "romwright-cli")), "import", str(binary),
             "--name", "cost", "--project", str(Path(temporary) / "project")],
            cwd=ROOT,
            # A cached import is a file copy (docs/environment.md): the gate
            # measures the analysis, cold, every time.
            environment=dict(os.environ, ROMWRIGHT_NO_IMPORT_CACHE="1"))
    assert code == 0, f"native import of {binary.name} exited {code}"
    return elapsed, peak


def stock(install: Path, binary: Path) -> tuple[float, int]:
    with tempfile.TemporaryDirectory(prefix="m7-001-stock-") as temporary:
        elapsed, peak, code = measure(
            [str(install / "support/analyzeHeadless"), temporary, "cost",
             "-import", str(binary), "-deleteProject"], cwd=ROOT,
            environment=dict(os.environ, DEBUGINFOD_URLS=""))
    assert code == 0, f"stock analysis of {binary.name} exited {code}"
    return elapsed, peak


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--write", action="store_true",
                        help="record the envelope; refuses to overwrite one")
    parser.add_argument("--ghidra", type=Path, default=Path(os.environ.get(
        "ROMWRIGHT_GHIDRA", str(Path.home() / "ghidra_12.1.3_PUBLIC"))))
    arguments = parser.parse_args()

    build_shipped(ROOT, "romwright-cli")
    manifest = json.loads((arguments.corpus_dir / "manifest.json").read_text())
    entries = [entry for entry in manifest["entries"] if entry.get("status") == "ok"]
    assert len(entries) >= 20, f"only {len(entries)} corpus entries are usable"

    stock_available = (arguments.ghidra / "support/analyzeHeadless").is_file()
    skipped = [] if stock_available else [
        f"stock comparison: no pinned Ghidra install at {arguments.ghidra}"]

    rows = []
    for entry in entries:
        identifier = f"{entry['architecture']}_{entry['variant']}"
        binary = arguments.corpus_dir / entry["binary"]
        wall, peak = native(binary)
        row = {"id": identifier, "native.wall_s": round(wall, 3),
               "native.peak_kb": peak}
        if stock_available:
            stock_wall, stock_peak = stock(arguments.ghidra, binary)
            row["stock.wall_s"] = round(stock_wall, 3)
            row["stock.peak_kb"] = stock_peak
            row["peak_ratio"] = round(stock_peak / max(peak, 1), 2)
            row["wall_ratio"] = round(stock_wall / max(wall, 1e-6), 2)
            assert peak < stock_peak, (
                f"{identifier}: native peaked at {peak} KiB, stock at "
                f"{stock_peak} KiB")
            assert wall < stock_wall, (
                f"{identifier}: native took {wall:.3f}s, stock {stock_wall:.3f}s")
        rows.append(row)

    peaks = {row["id"]: row["native.peak_kb"] for row in rows}
    if arguments.write:
        record_envelope(ENVELOPE, peaks,
                        "native import peak RSS per locked corpus entry; "
                        "recorded once, compared against afterwards")
        print(f"recorded {ENVELOPE.relative_to(ROOT)} for {len(rows)} entries")
    check_envelope(ENVELOPE, peaks)

    metrics = {
        "cost.native.peak_kb.median":
            statistics.median(row["native.peak_kb"] for row in rows),
        "cost.native.wall_s.median":
            round(statistics.median(row["native.wall_s"] for row in rows), 3),
    }
    if stock_available:
        metrics.update({
            "cost.stock.peak_kb.median":
                statistics.median(row["stock.peak_kb"] for row in rows),
            "cost.stock.wall_s.median":
                round(statistics.median(row["stock.wall_s"] for row in rows), 3),
            "cost.peak_ratio.median":
                round(statistics.median(row["peak_ratio"] for row in rows), 2),
            "cost.wall_ratio.median":
                round(statistics.median(row["wall_ratio"] for row in rows), 2),
        })

    summary = (f"{len(rows)} locked entries: native median "
               f"{metrics['cost.native.peak_kb.median']} KiB peak and "
               f"{metrics['cost.native.wall_s.median']}s")
    if stock_available:
        summary += (f", stock median {metrics['cost.stock.peak_kb.median']} KiB "
                    f"and {metrics['cost.stock.wall_s.median']}s -- "
                    f"{metrics['cost.peak_ratio.median']}x less memory and "
                    f"{metrics['cost.wall_ratio.median']}x faster, every entry "
                    f"inside the recorded envelope")
    else:
        summary += ", inside the recorded envelope; stock comparison skipped"

    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps({
            "id": "m7-001",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "status": "pass",
            "passed": True,
            "summary": summary,
            "host": {"system": platform.system(), "machine": platform.machine()},
            "headroom": HEADROOM,
            "metrics": metrics,
            "corpus": rows,
            "skipped": skipped,
        }, indent=1) + "\n")
    print(f"m7-001: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
