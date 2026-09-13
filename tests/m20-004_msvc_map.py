#!/usr/bin/env python3
"""m20-004: MSVC /MAP ingestion on a 91 MB game executable.

ffxv_s.map is MSVC `/MAP` output: `seg:off name rva+base flag obj` rows
under `Publics by Value`, flag `f` marking functions. The gate imports
ffxv_s.exe with `--map` and scores stored names against the map's own
`f` rows -- the linker is the truth on its own output.

Usage:
    python3 tests/m20-004_msvc_map.py [--images-dir DIR] [--report OUT.json]
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
IMAGES = Path.home() / "romwright-corpus/extracted/win-ffxv"
EXE = "ffxv_s.exe"
MAP = "ffxv_s.map"
RECALL_FLOOR = 0.95

PUB_ROW = re.compile(
    r"^\s*[0-9A-Fa-f]+:[0-9A-Fa-f]+\s+(\S+)\s+([0-9A-Fa-f]+)\s+(\S+)")


def map_functions(map_path: Path) -> dict[int, str]:
    """`f`-flagged publics, keyed by Rva+Base."""
    functions: dict[int, str] = {}
    in_publics = False
    for line in map_path.read_text(errors="replace").splitlines():
        if "Publics by Value" in line:
            in_publics = True
            continue
        if not in_publics:
            continue
        if line.strip().startswith("entry point"):
            break
        row = PUB_ROW.match(line)
        if row and row.group(3) == "f":
            functions[int(row.group(2), 16)] = row.group(1)
    return functions


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--images-dir", type=Path, default=IMAGES)
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()

    report = {"id": "m20-004",
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
    with tempfile.TemporaryDirectory(prefix="m20-004-", dir=Path.home() / "tmp") as temporary:
        project = Path(temporary) / "project"
        imported = subprocess.run(
            [str(cli), "import", str(exe), "--map", str(map_file),
             "--name", "ffxv", "--project", str(project), "--no-analysis"],
            cwd=ROOT, capture_output=True, text=True, timeout=1800)
        assert imported.returncode == 0, f"import failed: {imported.stderr.strip()}"

        store = sqlite3.connect(project / "project.sqlite")
        functions = {int(entry, 16): name for entry, name in store.execute(
            "SELECT entry, name FROM functions")}

        truth = map_functions(map_file)
        hits = sum(1 for address, name in truth.items()
                   if functions.get(address) == name)
        recall = hits / len(truth)
        assert recall >= RECALL_FLOOR, (
            f"named recall {recall:.4f} < {RECALL_FLOOR}: {hits} of {len(truth)}")

        summary = (f"{len(functions)} functions, named recall {recall:.4f} "
                   f"over {len(truth)} MSVC publics")
        report.update(status="pass", passed=True, summary=summary,
                      metrics={"named_recall": recall, "map_functions": len(truth)})
        print(f"m20-004: PASS ({summary})")
    if arguments.report:
        arguments.report.write_text(json.dumps(report, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
