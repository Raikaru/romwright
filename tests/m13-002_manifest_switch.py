#!/usr/bin/env python3
"""m13-002: comparative re-run on a recorded 8-function manifest.

m13-001 scores whole-corpus tiers; this gate names eight functions and
re-runs the comparison fresh every time -- stock is re-exported,
romwright re-imported, nothing is pinned to a checked-in golden file
(an old export cannot pass this gate: there is nothing to replay).

Manifest (mechanical, no cherry-picking): the 8 functions holding the
most stock-reported branches on the subject binary, tie-broken by
address, taken from the fresh export. The manifest -- symbols,
branches, both sides' sets -- is embedded in the report.

Tiers: combined (the product default) and interpreted (SJA). What is
asserted is soundness: every target either tier claims on the 8 must
decode as an instruction and lie inside the branching function's own
extent. Agreement with stock is recorded per function, not
thresholded: stock's own tables carry unsound targets (m13-001
measures 0.981), so exact-equality would enshrine stock's errors.
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
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "target" / "release" / "romwright-cli"
EXPORTER = ROOT / "scripts/ExportSwitchTargets.java"
MANIFEST_SIZE = 8


def run(command, **kwargs):
    return subprocess.run(command, cwd=ROOT, capture_output=True, text=True, **kwargs)


def stock_tables(binary: Path, install: Path, work: Path) -> dict[int, set[int]]:
    """Stock Ghidra's own jump tables, exported fresh -- never replayed."""
    work.mkdir(parents=True, exist_ok=True)
    output = work / "stock.json"
    if output.is_file():
        output.unlink()
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


def symbol_extents(binary: Path, base: int) -> tuple[list[tuple[int, int]], dict[int, int], dict[str, list[tuple[int, int]]]]:
    out = run(["readelf", "-sW", str(binary)]).stdout
    spans: dict[str, list[tuple[int, int]]] = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 8 or parts[3] != "FUNC":
            continue
        try:
            value, size = int(parts[1], 16), int(parts[2], 0)
        except ValueError:
            continue
        if size:
            spans.setdefault(parts[7], []).append((base + value, base + value + size))
    by_name: dict[str, list[tuple[int, int]]] = dict(spans)
    merged: list[tuple[int, int]] = []
    groups: dict[int, int] = {}
    for index, (name, own) in enumerate(spans.items()):
        if name.endswith(".cold"):
            parent_index = next((i for i, n in enumerate(spans) if n == name[: -len(".cold")]), None)
            group = parent_index if parent_index is not None else index
        else:
            group = index
        for start, _ in own:
            groups[start] = group
        merged.extend(own)
    merged.sort()
    return merged, groups, by_name


def owner(spans: list[tuple[int, int]], address: int) -> tuple[int, int] | None:
    low, high = 0, len(spans)
    while low < high:
        middle = (low + high) // 2
        if spans[middle][0] <= address:
            low = middle + 1
        else:
            high = middle
    if low == 0:
        return None
    start, end = spans[low - 1]
    return (start, end) if address < end else None


def decodes(binary: Path, base: int, addresses: set[int], ghidra: Path) -> set[int]:
    if not addresses:
        return set()
    cli = CLI
    ordered = sorted(addresses)
    good: set[int] = set()
    for start in range(0, len(ordered), 400):
        chunk = ordered[start : start + 400]
        # `ir-dump` lifts in process under the image's own language, at the
        # addresses the import stored (the bias an import adds to a shared
        # object included); an instruction SLEIGH cannot decode is marked
        # `error=BAD` or `error=UNIMPL`.
        result = subprocess.run(
            [str(cli), "ir-dump", str(binary), ",".join(f"{address:x}" for address in chunk)],
            capture_output=True,
            text=True,
            env={**os.environ, "ROMWRIGHT_GHIDRA": str(ghidra)},
        )
        answers = [
            line for line in result.stdout.splitlines() if line.startswith("0x") and " (len " in line
        ]
        for line, address in zip(answers, chunk):
            if " error=" not in line:
                good.add(address)
    return good


def imported(binary: Path, project: Path, environment: dict[str, str]) -> dict[int, set[int]]:
    if project.exists():
        shutil.rmtree(project)
    project.mkdir(parents=True)
    result = subprocess.run(
        [str(CLI), "import", str(binary), "--project", str(project)],
        capture_output=True,
        text=True,
        env={**os.environ, "ROMWRIGHT_NO_IMPORT_CACHE": "1", **environment},
        timeout=1200,
    )
    if result.returncode:
        raise ValueError(f"import failed: {result.stderr[-800:]}")
    connection = sqlite3.connect(project / "project.sqlite")
    try:
        rows = connection.execute(
            "SELECT src, dst FROM xrefs WHERE provenance = 'native-import:switch'"
        ).fetchall()
    finally:
        connection.close()
    tables: dict[int, set[int]] = {}
    for source, destination in rows:
        tables.setdefault(int(source, 16), set()).add(int(destination, 16))
    return tables


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=Path("/usr/lib64/libc.so.6"))
    parser.add_argument(
        "--ghidra",
        type=Path,
        default=Path(os.environ.get("ROMWRIGHT_GHIDRA", Path.home() / "ghidra_12.1.3_PUBLIC")),
    )
    parser.add_argument("--work", type=Path, default=Path.home() / "romwright-cache/tmp/m13-002")
    parser.add_argument("--report", type=Path, default=None)
    arguments = parser.parse_args()
    for place in (arguments.work, Path(tempfile.gettempdir())):
        anchor = place if place.exists() else place.parent
        free = os.statvfs(anchor).f_bavail * os.statvfs(anchor).f_frsize
        if free < 2 << 30:
            raise SystemExit(f"m13-002 refuses: {anchor} filesystem has {free >> 20}MB free (<2GB)")

    report: dict = {
        "id": "m13-002",
        "milestone": "M13",
        "criterion": "comparative re-run on a recorded 8-function manifest, fresh stock export",
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "binary": str(arguments.binary),
    }
    if not arguments.binary.is_file():
        report["status"] = "skipped"
        print(f"m13-002: SKIPPED ({arguments.binary} is not on this machine)")
    else:
        subprocess.run(
            ["cargo", "build", "-q", "--release", "-p", "romwright-cli", "-p", "romwright-worker"],
            cwd=ROOT,
            check=True,
        )
        stock = stock_tables(arguments.binary, arguments.ghidra, arguments.work / "stock")
        base = min(min(targets) for targets in stock.values()) if stock else 0
        base = 0x100000 if base >= 0x100000 else 0
        spans, groups, by_name = symbol_extents(arguments.binary, base)
        by_group: dict[int, list[tuple[int, int]]] = {}
        for start, end in spans:
            by_group.setdefault(groups.get(start, start), []).append((start, end))
        # Manifest: the 8 functions holding the most stock branches.
        per_function: dict[str, set[int]] = {}
        for branch, targets in stock.items():
            extent = owner(spans, branch)
            if extent is None:
                continue
            name = next(n for n, own in by_name.items() if extent in own)
            per_function.setdefault(name, set()).add(branch)
        ranked = sorted(per_function.items(), key=lambda item: (-len(item[1]), min(item[1])))
        manifest = [name for name, _ in ranked[:MANIFEST_SIZE]]
        assert len(manifest) == MANIFEST_SIZE, (len(manifest), len(stock))
        manifest_branches = {branch for name in manifest for branch in per_function[name]}

        started = time.time()
        combined = imported(arguments.binary, arguments.work / "combined", {})
        interpreted = imported(
            arguments.binary,
            arguments.work / "interpreted",
            {"ROMWRIGHT_NO_SWITCH_DECOMPILER": "1", "ROMWRIGHT_SJA": "1"},
        )
        import_wall = time.time() - started

        claimed = set()
        for tables in (combined, interpreted):
            for branch in manifest_branches:
                claimed.update(tables.get(branch, set()))
        good = decodes(arguments.binary, base, claimed, arguments.ghidra)

        rows = []
        for name in manifest:
            branches = sorted(per_function[name])
            extent = owner(spans, branches[0])
            group = by_group.get(groups.get(extent[0], extent[0])) if extent else None
            row = {"function": name, "extent": [f"{extent[0]:x}", f"{extent[1]:x}"], "branches": {}}
            for branch in branches:
                want = sorted(stock.get(branch, set()))
                for tier_name, tables in (("combined", combined), ("interpreted", interpreted)):
                    got = sorted(tables.get(branch, set()))
                    sound = all(
                        t in good and extent and any(s <= t < e for s, e in (group or [extent]))
                        for t in got
                    )
                    row["branches"][f"{branch:x}"] = row["branches"].get(f"{branch:x}", {}) | {
                        tier_name: {"stock": want, "recovered": got, "agree": got == want, "sound": sound}
                    }
            rows.append(row)
        unsound = [
            (row["function"], branch, tier)
            for row in rows
            for branch, tiers in row["branches"].items()
            for tier, scored in tiers.items()
            if not scored["sound"]
        ]
        agree = sum(
            scored["agree"] for row in rows for tiers in row["branches"].values() for scored in tiers.values()
        )
        total = sum(len(tiers) for row in rows for tiers in row["branches"].values())
        report["manifest"] = manifest
        report["functions"] = rows
        report["import_wall_s"] = round(import_wall, 1)
        report["agreement"] = f"{agree}/{total}"
        report["unsound"] = unsound
        report["status"] = "pass" if not unsound else "fail"
        print(f"m13-002: {report['status']} (agreement {report['agreement']}, unsound {len(unsound)})")
    if arguments.report is not None:
        arguments.report.write_text(json.dumps(report, indent=2) + "\n")
    return 0 if report["status"] in ("pass", "skipped") else 1


if __name__ == "__main__":
    sys.exit(main())
