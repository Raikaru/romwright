#!/usr/bin/env python3
"""m20-002: PsyQ/SN linker MAP ingestion on a retail PS-X EXE.

VS.MAP is the build's own linker output for Darkstalkers 3 (1998): an
extent table plus `ADDR NAME` lists with no types. The gate imports
VS.EXE with `--map` and scores the store against the map's own names
inside the `.text` extent -- the same 818-address set the m4-036 census
recorded at 751 matched by other means.

Usage:
    python3 tests/m20-002_psyq_map.py [--images-dir DIR] [--report OUT.json]
"""
from __future__ import annotations

import argparse
import json
import re
import sqlite3
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IMAGES = Path.home() / "romwright-corpus/extracted/psx-darkstalkers-3"
EXE = "VS.EXE"
MAP = "VS.MAP"
RECALL_FLOOR = 0.95

EXTENT = re.compile(r"^ ([0-9A-F]{8}) ([0-9A-F]{8}) [0-9A-F]{8} [0-9A-F]{8} \S+\s+(\.\S+)")
NAME_ROW = re.compile(r"^ ([0-9A-F]{8})  +(\S+)")


def map_code_names(map_path: Path) -> dict[int, str]:
    """Names inside `.text` extents, deduped across both name lists."""
    extents: list[tuple[int, int]] = []
    names: dict[int, str] = {}
    in_names = False
    for line in map_path.read_text(errors="replace").splitlines():
        stripped = line.strip()
        if stripped.startswith("Address") and "Names" in stripped:
            in_names = True
            continue
        extent = EXTENT.match(line)
        if extent and not in_names:
            if extent.group(3).endswith(".text"):
                extents.append((int(extent.group(1), 16), int(extent.group(2), 16) + 1))
            continue
        row = NAME_ROW.match(line)
        if in_names and row:
            address = int(row.group(1), 16)
            if any(lo <= address < hi for lo, hi in extents):
                names[address] = row.group(2)
    return names


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--images-dir", type=Path, default=IMAGES)
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()

    report = {"id": "m20-002",
              "recorded_at": datetime.now(timezone.utc).isoformat(),
              "thresholds": {"named_recall": RECALL_FLOOR},
              "status": "skipped"}
    exe = arguments.images_dir / EXE
    map_file = arguments.images_dir / MAP
    if not exe.is_file() or not map_file.is_file():
        report["reason"] = "images absent"
        print(f"SKIP: {report['reason']}")
        if arguments.report:
            arguments.report.write_text(json.dumps(report, indent=2) + "\n")
        return 0

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "romwright-cli"],
                   cwd=ROOT, check=True)
    cli = ROOT / "target/release/romwright-cli"
    with tempfile.TemporaryDirectory(prefix="m20-002-", dir=Path.home() / "tmp") as temporary:
        project = Path(temporary) / "project"
        imported = subprocess.run(
            [str(cli), "import", str(exe), "--map", str(map_file),
             "--name", "vs", "--project", str(project), "--no-analysis"],
            cwd=ROOT, capture_output=True, text=True, timeout=1800)
        assert imported.returncode == 0, f"import failed: {imported.stderr.strip()}"

        store = sqlite3.connect(project / "project.sqlite")
        functions = {int(entry, 16): name for entry, name in store.execute(
            "SELECT entry, name FROM functions")}

        truth = map_code_names(map_file)
        hits = sum(1 for address, name in truth.items()
                   if functions.get(address) == name)
        recall = hits / len(truth)
        assert recall >= RECALL_FLOOR, (
            f"named recall {recall:.4f} < {RECALL_FLOOR}: {hits} of {len(truth)}")

        summary = (f"{len(functions)} functions, named recall {recall:.4f} "
                   f"over {len(truth)} map names in .text extents")
        report.update(status="pass", passed=True, summary=summary,
                      metrics={"named_recall": recall, "map_names": len(truth)})
        print(f"m20-002: PASS ({summary})")
    if arguments.report:
        arguments.report.write_text(json.dumps(report, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
