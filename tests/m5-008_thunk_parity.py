#!/usr/bin/env python3
"""m5-008: thunk parity compared as sets, not counts.

`benchmarks/thunk_gate.py` compares thunk *counts* on one host libc, and on
this machine that comparison reads 107 against 107 while the two sets differ
by thirteen entries in each direction. Counts agreeing is not parity, so this
gate compares the facts themselves over the locked corpus:

  * every thunk Ventris records must be a thunk stock Ghidra records
    (`thunk.entry.precision` = 1.0 -- no invented thunk);
  * every stock thunk whose *entry* is inside the image must be recorded
    (`thunk.entry.recall`), with the known misses pinned by address and
    symbol so a new one fails and a fixed one demands an update;
  * every destination must either match stock exactly or be *explained*:
    Ghidra hops PLT stub -> EXTERNAL-block stub -> external symbol, while
    Ventris hops PLT stub -> the GOT slot the stub reads. A row is explained
    only when the stock destination lies outside every image mapping and the
    Ventris destination is an in-image address carrying the same import name.
    Anything else is an unexplained disagreement and fails.

Stock thunks whose entry lies in Ghidra's synthetic EXTERNAL block are
excluded, because Ventris has no such block; the exclusion is asserted rather
than assumed -- every excluded entry must be outside every image mapping.

Usage:
    python3 tests/m5-008_thunk_parity.py --corpus-dir DIR [--report OUT.json]
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "benchmarks"))
sys.path.insert(0, str(ROOT / "scripts"))

THRESHOLDS = {
    "thunk.entry.precision": 1.0,
    "thunk.entry.recall": 0.96,
    "thunk.destination.unexplained": 0,
}

# Stock thunks Ventris does not record, pinned with the symbol each one binds.
# i386 PIE PLT stubs jump through `%ebx`, which holds the GOT base the caller
# established: the slot is not derivable from the stub's own instructions, and
# Ventris records a linkage thunk only from a resolved slot.
DEFICITS = {
    "i386_plain_pie": {
        "00011650": "__libc_start_main",
        "00011660": "__cxa_finalize",
        "00011670": "printf",
    },
}


def native_facts(cli: Path, binary: Path, work: Path, timeout: int) -> dict:
    project = work / "project"
    imported = subprocess.run(
        [str(cli), "import", str(binary), "--name", "scored", "--project", str(project)],
        cwd=ROOT, capture_output=True, text=True, timeout=timeout)
    assert imported.returncode == 0, (
        f"{binary.name}: native import failed: {imported.stderr.strip()}")
    store = sqlite3.connect(project / "project.sqlite")
    thunks = {entry.lower(): {"thunked": (thunked or "").lower() or None, "kind": kind}
              for entry, thunked, kind in store.execute(
                  "SELECT function, thunked, kind FROM thunks")}
    symbols = {}
    for address, name in store.execute("SELECT address, name FROM symbols"):
        symbols.setdefault(address.lower(), set()).add(name)
    regions = [(int(start, 16), size) for start, size in store.execute(
        "SELECT start, size FROM memory_regions")]
    return {"thunks": thunks, "symbols": symbols, "regions": regions}


def mapped(regions: list[tuple[int, int]], address: str) -> bool:
    value = int(address, 16)
    return any(start <= value < start + size for start, size in regions)


def compare(identifier: str, stock: dict, native: dict) -> dict:
    """Classify every stock and native thunk fact for one binary."""
    excluded, comparable = {}, {}
    for entry, fact in stock.items():
        if mapped(native["regions"], entry):
            comparable[entry] = fact
        else:
            excluded[entry] = fact

    for entry, fact in excluded.items():
        # The only reason to skip a stock thunk is that its entry is not in
        # the image at all: Ghidra's EXTERNAL block. Assert that, so the
        # exclusion cannot quietly grow to cover real misses.
        assert not fact["external"] or fact["thunked"] is None, (
            f"{identifier}: {entry} was excluded but looks like image code")

    recorded = set(native["thunks"])
    agree = set(comparable) & recorded
    invented = recorded - set(stock)
    missing = {entry: comparable[entry]["name"] for entry in set(comparable) - recorded}

    equal, explained, unexplained = 0, [], []
    for entry in sorted(agree):
        stock_target = (comparable[entry]["thunked"] or "").lower() or None
        ours = native["thunks"][entry]["thunked"]
        if stock_target and ours and stock_target == ours:
            equal += 1
            continue
        # Explained: Ghidra's destination is its EXTERNAL-block stub, ours is
        # the in-image slot, and both carry the same import name.
        name = comparable[entry]["name"]
        stock_outside = stock_target is None or not mapped(native["regions"], stock_target)
        ours_named = bool(ours) and name in native["symbols"].get(ours, set())
        if stock_outside and ours and mapped(native["regions"], ours) and ours_named:
            explained.append({"entry": entry, "stock": stock_target, "native": ours,
                              "name": name})
            continue
        unexplained.append({"entry": entry, "stock": stock_target, "native": ours,
                            "name": name})

    return {"id": identifier, "stock": len(stock), "excluded": len(excluded),
            "comparable": len(comparable), "native": len(recorded),
            "agree": len(agree), "equal": equal, "explained": len(explained),
            "unexplained": unexplained, "invented": sorted(invented),
            "missing": missing}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--ghidra", type=Path, default=Path(os.environ.get(
        "VENTRIS_GHIDRA", str(Path.home() / "ghidra_12.1.3_PUBLIC"))))
    parser.add_argument("--timeout", type=int, default=900)
    arguments = parser.parse_args()

    report = {"id": "m5-008", "recorded_at": datetime.now(timezone.utc).isoformat(),
              "thresholds": THRESHOLDS, "status": "skipped"}
    if not (arguments.ghidra / "support/analyzeHeadless").is_file():
        report["reason"] = f"no pinned Ghidra install at {arguments.ghidra}"
        print(f"SKIP: {report['reason']}")
        if arguments.report:
            arguments.report.write_text(json.dumps(report, indent=2) + "\n")
        return 0

    from thunk_gate import stock_thunks

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-cli"],
                   cwd=ROOT, check=True)
    cli = ROOT / "target/release/lre-cli"
    manifest = json.loads((arguments.corpus_dir / "manifest.json").read_text())

    rows, totals = [], {"comparable": 0, "native": 0, "agree": 0, "equal": 0,
                        "explained": 0, "unexplained": 0, "invented": 0}
    for entry in manifest["entries"]:
        if entry.get("status") != "ok":
            continue
        identifier = f"{entry['architecture']}_{entry['variant']}"
        binary = arguments.corpus_dir / entry["binary"]
        with tempfile.TemporaryDirectory(prefix="m5-008-") as temporary:
            work = Path(temporary)
            exported = stock_thunks(arguments.ghidra, binary, work, arguments.timeout)
            stock = {key.lower(): {"thunked": value["thunked"],
                                   "external": value["external"],
                                   "name": value["name"]}
                     for key, value in exported["thunks"].items()}
            native = native_facts(cli, binary, work, arguments.timeout)
        row = compare(identifier, stock, native)
        rows.append(row)
        for key in ("comparable", "native", "agree", "equal", "explained"):
            totals[key] += row[key]
        totals["unexplained"] += len(row["unexplained"])
        totals["invented"] += len(row["invented"])

        assert not row["invented"], (
            f"{identifier}: recorded thunks stock Ghidra does not: {row['invented']}")
        assert not row["unexplained"], (
            f"{identifier}: destinations disagree with no explanation: "
            f"{row['unexplained']}")
        pinned = DEFICITS.get(identifier, {})
        assert row["missing"] == pinned, (
            f"{identifier}: stock thunks not recorded are {row['missing']}, "
            f"but the pinned deficit is {pinned}")

    assert len(rows) >= 20, f"only {len(rows)} corpus entries were scored"
    metrics = {
        "thunk.entry.precision": totals["agree"] / max(totals["native"], 1),
        "thunk.entry.recall": totals["agree"] / max(totals["comparable"], 1),
        "thunk.destination.unexplained": totals["unexplained"],
        "thunk.destination.equal": totals["equal"],
        "thunk.destination.explained": totals["explained"],
    }
    for name, threshold in THRESHOLDS.items():
        if name.endswith("unexplained"):
            assert metrics[name] <= threshold, f"{name} is {metrics[name]}"
        else:
            assert metrics[name] >= threshold, (
                f"{name} is {metrics[name]:.4f}, below {threshold}")

    summary = (f"{len(rows)} corpus entries: {totals['agree']}/{totals['comparable']} "
               f"stock thunks recorded, precision "
               f"{metrics['thunk.entry.precision']:.4f}, recall "
               f"{metrics['thunk.entry.recall']:.4f}, "
               f"{totals['equal']} destinations equal, {totals['explained']} explained "
               f"by the EXTERNAL-block model, 0 unexplained")
    if arguments.report:
        report.update(status="pass", passed=True, summary=summary, metrics=metrics,
                      totals=totals, deficits=DEFICITS, corpus=rows)
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps(report, indent=2) + "\n")
    print(f"m5-008: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
