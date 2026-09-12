#!/usr/bin/env python3
"""m20-005: flat `ADDR NAME` MAP on a raw 3DS code dump.

Fire Emblem Fates ships `romfs/debug/symbols.map`: bare `ADDR NAME`
lines, base 0x00100000, matching `exefs/code-decompressed.bin`. There
is no container to sniff, so the gate exercises `--raw` + `--language`
+ `--map` together: the flat parser types every row code and the
executable-mapping gate keeps only what the image maps.

Usage:
    python3 tests/m20-005_flat_map.py [--images-dir DIR] [--report OUT.json]
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
IMAGES = Path.home() / "ventris-corpus/extracted/3ds-fire-emblem-fates"
CODE = "exefs/code-decompressed.bin"
MAP = "romfs/debug/symbols.map"
BASE = 0x00100000
LANGUAGE = "ARM:LE:32:v6"
RECALL_FLOOR = 0.95

ROW = re.compile(r"^([0-9a-f]{8})\s+(\S+)")


def map_names(map_path: Path, code_len: int) -> dict[int, str]:
    """Rows inside the loaded image's address range."""
    names: dict[int, str] = {}
    for line in map_path.read_text(errors="replace").splitlines():
        row = ROW.match(line.strip())
        if row:
            address = int(row.group(1), 16)
            if BASE <= address < BASE + code_len:
                names[address] = row.group(2)
    return names


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--images-dir", type=Path, default=IMAGES)
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()

    report = {"id": "m20-005",
              "recorded_at": datetime.now(timezone.utc).isoformat(),
              "thresholds": {"named_recall": RECALL_FLOOR},
              "status": "skipped"}
    code = arguments.images_dir / CODE
    map_file = arguments.images_dir / MAP
    if not code.is_file() or not map_file.is_file():
        report["reason"] = "images absent"
        print(f"SKIP: {report['reason']}")
        if arguments.report:
            arguments.report.write_text(json.dumps(report, indent=2) + "\n")
        return 0

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-cli"],
                   cwd=ROOT, check=True)
    cli = ROOT / "target/release/lre-cli"
    with tempfile.TemporaryDirectory(prefix="m20-005-", dir=Path.home() / "tmp") as temporary:
        project = Path(temporary) / "project"
        imported = subprocess.run(
            [str(cli), "import", str(code),
             "--raw", hex(BASE), "--language", LANGUAGE,
             "--map", str(map_file),
             "--name", "fates", "--project", str(project), "--no-analysis"],
            cwd=ROOT, capture_output=True, text=True, timeout=1800)
        assert imported.returncode == 0, f"import failed: {imported.stderr.strip()}"

        store = sqlite3.connect(project / "project.sqlite")
        functions = {int(entry, 16): name for entry, name in store.execute(
            "SELECT entry, name FROM functions")}

        truth = map_names(map_file, code.stat().st_size)
        hits = sum(1 for address, name in truth.items()
                   if functions.get(address) == name)
        recall = hits / len(truth)
        assert recall >= RECALL_FLOOR, (
            f"named recall {recall:.4f} < {RECALL_FLOOR}: {hits} of {len(truth)}")

        summary = (f"{len(functions)} functions, named recall {recall:.4f} "
                   f"over {len(truth)} flat map rows")
        report.update(status="pass", passed=True, summary=summary,
                      metrics={"named_recall": recall, "map_names": len(truth)})
        print(f"m20-005: PASS ({summary})")
    if arguments.report:
        arguments.report.write_text(json.dumps(report, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
