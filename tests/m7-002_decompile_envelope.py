#!/usr/bin/env python3
"""m7-002: what one decompiled function costs, per corpus entry.

`m7-001` measures an import. The next question a user asks is what a single
decompiled function costs, and `benchmarks/gate.sh` answers that for one tiny
fixture only.

Both producers decompile the *same function by name* -- `main` in each locked
entry's unstripped twin, so neither producer needs an address guessed for it
and PIE image bases cannot make the two disagree about what was decompiled.
Import and analysis happen first and are **not** timed: for the native path an
`lre-cli import`, for stock an `analyzeHeadless -import` that analyses and
saves. Each timed run then opens the stored program and decompiles one
function -- native `lre-cli decompile`, stock `analyzeHeadless -process
-noanalysis -postScript scripts/DecompileOne.java` -- so both numbers include
their own process startup and neither includes analysis.

Per entry the gate requires:

  * the native decompile to peak lower than the stock decompile;
  * the native decompile to finish sooner;
  * both producers to emit a real function body (asserted, not assumed);
  * the native peak to stay inside `benchmarks/reports/decompile-envelope.json`,
    recorded once with `--write` and never edited afterwards.

Usage:
    python3 tests/m7-002_decompile_envelope.py --corpus-dir DIR [--write] [--report OUT.json]
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
from cost import HEADROOM, check_envelope, measure, record_envelope  # noqa: E402

ENVELOPE = ROOT / "benchmarks" / "reports" / "decompile-envelope.json"
FUNCTION = "main"


def native_address(program: str, project: Path) -> str:
    """The address the native store gave the wanted function."""
    listing = subprocess.run(
        [str(ROOT / "target/release/lre-cli"), "functions", program,
         "--project", str(project)],
        cwd=ROOT, capture_output=True, text=True, check=True).stdout
    for line in listing.splitlines():
        fields = line.split()
        if fields and fields[-1] == FUNCTION:
            return fields[0]
    raise AssertionError(f"the native store has no function named {FUNCTION}")


def native_decompile(binary: Path, identifier: str, temporary: Path
                     ) -> tuple[float, int, str, int]:
    project = temporary / "native"
    setup = subprocess.run(
        [str(ROOT / "target/release/lre-cli"), "import", str(binary),
         "--name", "cost", "--project", str(project)],
        cwd=ROOT, capture_output=True, text=True)
    assert setup.returncode == 0, f"{identifier}: native import failed: {setup.stderr}"
    address = native_address("cost", project)
    output = temporary / "native.c"
    wall, peak, code = measure(
        [str(ROOT / "target/release/lre-cli"), "decompile", str(binary), address,
         "--name", "cost", "--project", str(project)], cwd=ROOT, output=output)
    assert code == 0, f"{identifier}: native decompile exited {code}"
    body = output.read_text()
    assert f"{FUNCTION}(" in body and "{" in body, (
        f"{identifier}: native decompile produced no function body: {body[:120]!r}")
    return wall, peak, address, len(body)


def stock_decompile(install: Path, binary: Path, identifier: str, temporary: Path
                    ) -> tuple[float, int, str, int]:
    project = temporary / "stock"
    project.mkdir()
    environment = dict(os.environ, DEBUGINFOD_URLS="")
    setup = subprocess.run(
        [str(install / "support/analyzeHeadless"), str(project), "cost",
         "-import", str(binary)],
        capture_output=True, text=True, env=environment)
    assert setup.returncode == 0, (
        f"{identifier}: stock import failed: {setup.stdout[-400:]}")
    log = temporary / "stock.log"
    wall, peak, code = measure(
        [str(install / "support/analyzeHeadless"), str(project), "cost",
         "-process", binary.name, "-noanalysis",
         "-scriptPath", str(ROOT / "scripts"),
         "-postScript", "DecompileOne.java", FUNCTION],
        environment=environment, output=log)
    assert code == 0, f"{identifier}: stock decompile exited {code}"
    reported = [line for line in log.read_text().splitlines() if "DECOMPILED" in line]
    assert reported, f"{identifier}: stock decompile printed nothing: {log.read_text()[-400:]}"
    fields = reported[0].split()
    address, characters = fields[fields.index("DECOMPILED") + 2], int(fields[-1])
    assert characters > 0, f"{identifier}: stock decompile produced no C"
    return wall, peak, address, characters


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--write", action="store_true",
                        help="record the envelope; refuses to overwrite one")
    parser.add_argument("--ghidra", type=Path, default=Path(os.environ.get(
        "VENTRIS_GHIDRA", str(Path.home() / "ghidra_12.1.3_PUBLIC"))))
    arguments = parser.parse_args()

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-cli"],
                   cwd=ROOT, check=True)
    manifest = json.loads((arguments.corpus_dir / "manifest.json").read_text())
    entries = [entry for entry in manifest["entries"]
               if entry.get("status") == "ok" and entry.get("unstripped_twin")]
    assert len(entries) >= 20, f"only {len(entries)} corpus entries are usable"

    stock_available = (arguments.ghidra / "support/analyzeHeadless").is_file()
    skipped = [] if stock_available else [
        f"stock comparison: no pinned Ghidra install at {arguments.ghidra}"]

    rows = []
    for entry in entries:
        identifier = f"{entry['architecture']}_{entry['variant']}"
        binary = arguments.corpus_dir / entry["unstripped_twin"]
        with tempfile.TemporaryDirectory(prefix="m7-002-") as directory:
            temporary = Path(directory)
            wall, peak, address, characters = native_decompile(
                binary, identifier, temporary)
            row = {"id": identifier, "function": FUNCTION,
                   "native.address": address, "native.chars": characters,
                   "native.wall_s": round(wall, 3), "native.peak_kb": peak}
            if stock_available:
                stock_wall, stock_peak, stock_address, stock_characters = \
                    stock_decompile(arguments.ghidra, binary, identifier, temporary)
                row.update({
                    "stock.address": stock_address,
                    "stock.chars": stock_characters,
                    "stock.wall_s": round(stock_wall, 3),
                    "stock.peak_kb": stock_peak,
                    "peak_ratio": round(stock_peak / max(peak, 1), 2),
                    "wall_ratio": round(stock_wall / max(wall, 1e-6), 2),
                })
                assert peak < stock_peak, (
                    f"{identifier}: native decompile peaked at {peak} KiB, "
                    f"stock at {stock_peak} KiB")
                assert wall < stock_wall, (
                    f"{identifier}: native decompile took {wall:.3f}s, stock "
                    f"{stock_wall:.3f}s")
        rows.append(row)

    peaks = {row["id"]: row["native.peak_kb"] for row in rows}
    if arguments.write:
        record_envelope(ENVELOPE, peaks,
                        f"native peak RSS for decompiling {FUNCTION} in each "
                        f"locked corpus entry; recorded once, compared against "
                        f"afterwards")
        print(f"recorded {ENVELOPE.relative_to(ROOT)} for {len(rows)} entries")
    check_envelope(ENVELOPE, peaks)

    metrics = {
        "decompile.native.peak_kb.median":
            statistics.median(row["native.peak_kb"] for row in rows),
        "decompile.native.wall_s.median":
            round(statistics.median(row["native.wall_s"] for row in rows), 3),
    }
    if stock_available:
        metrics.update({
            "decompile.stock.peak_kb.median":
                statistics.median(row["stock.peak_kb"] for row in rows),
            "decompile.stock.wall_s.median":
                round(statistics.median(row["stock.wall_s"] for row in rows), 3),
            "decompile.peak_ratio.median":
                round(statistics.median(row["peak_ratio"] for row in rows), 2),
            "decompile.wall_ratio.median":
                round(statistics.median(row["wall_ratio"] for row in rows), 2),
        })

    summary = (f"{len(rows)} locked entries decompiling {FUNCTION}: native "
               f"median {metrics['decompile.native.peak_kb.median']} KiB peak "
               f"and {metrics['decompile.native.wall_s.median']}s")
    if stock_available:
        summary += (f", stock median {metrics['decompile.stock.peak_kb.median']} "
                    f"KiB and {metrics['decompile.stock.wall_s.median']}s -- "
                    f"{metrics['decompile.peak_ratio.median']}x less memory and "
                    f"{metrics['decompile.wall_ratio.median']}x faster, every "
                    f"entry inside the recorded envelope")
    else:
        summary += ", inside the recorded envelope; stock comparison skipped"

    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps({
            "id": "m7-002",
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
    print(f"m7-002: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
