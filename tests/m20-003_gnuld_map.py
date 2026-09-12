#!/usr/bin/env python3
"""m20-003: GNU ld MAP ingestion on a GBA cartridge.

pokeemerald.map is agbcc/GNU-ld output: `file.o(input)` context lines
and `ADDR NAME` rows, no types. The map is a different build than the
bundled ELF (3 of 15853 FUNC addresses coincide), so the truth is the
map's own `.text`-input-section rows -- the linker is the truth on its
own output.

Usage:
    python3 tests/m20-003_gnuld_map.py [--images-dir DIR] [--report OUT.json]
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
IMAGES = Path.home() / "ventris-corpus/extracted/gba-pokeemerald"
ROM = "pokeemerald.gba"
MAP = "pokeemerald.map"
AGB_MAIN = 0x080003A4
RECALL_FLOOR = 0.95

CONTEXT = re.compile(r"^ \S.*\(([^)]*)\)\s*$")
SYMBOL = re.compile(r"^\s+0x([0-9a-f]+)\s+(\S+)\s*$")


def map_code_names(map_path: Path) -> dict[int, str]:
    """`ADDR NAME` rows under a code input section, in ROM space."""
    names: dict[int, str] = {}
    input_section = ""
    for raw in map_path.read_text(errors="replace").splitlines():
        line = raw.rstrip("\r\n")
        if not line.strip():
            continue
        context = CONTEXT.match(line)
        if context and not line.startswith("  "):
            input_section = context.group(1)
            continue
        if not line.startswith((" ", "\t")):
            continue
        stripped = line.strip()
        if stripped.startswith("*fill*") or " = " in stripped:
            continue
        row = SYMBOL.match(line)
        if not row:
            continue
        name = row.group(2)
        if name.startswith((".", "$")):
            continue
        if input_section in (".text", ".init") or input_section.startswith(".text."):
            address = int(row.group(1), 16)
            if 0x08000000 <= address < 0x0A000000:
                names[address] = name
    return names


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--images-dir", type=Path, default=IMAGES)
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()

    report = {"id": "m20-003",
              "recorded_at": datetime.now(timezone.utc).isoformat(),
              "thresholds": {"named_recall": RECALL_FLOOR},
              "status": "skipped"}
    rom = arguments.images_dir / ROM
    map_file = arguments.images_dir / MAP
    if not rom.is_file() or not map_file.is_file():
        report["reason"] = "images absent"
        print(f"SKIP: {report['reason']}")
        if arguments.report:
            arguments.report.write_text(json.dumps(report, indent=2) + "\n")
        return 0

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-cli"],
                   cwd=ROOT, check=True)
    cli = ROOT / "target/release/lre-cli"
    with tempfile.TemporaryDirectory(prefix="m20-003-", dir=Path.home() / "tmp") as temporary:
        project = Path(temporary) / "project"
        imported = subprocess.run(
            [str(cli), "import", str(rom), "--map", str(map_file),
             "--name", "gba", "--project", str(project), "--no-analysis"],
            cwd=ROOT, capture_output=True, text=True, timeout=1800)
        assert imported.returncode == 0, f"import failed: {imported.stderr.strip()}"

        store = sqlite3.connect(project / "project.sqlite")
        functions = {int(entry, 16): name for entry, name in store.execute(
            "SELECT entry, name FROM functions")}

        assert functions.get(AGB_MAIN) == "AgbMain", (
            f"AgbMain at {AGB_MAIN:#x}: {functions.get(AGB_MAIN)}")

        truth = map_code_names(map_file)
        hits = sum(1 for address, name in truth.items()
                   if functions.get(address) == name)
        recall = hits / len(truth)
        assert recall >= RECALL_FLOOR, (
            f"named recall {recall:.4f} < {RECALL_FLOOR}: {hits} of {len(truth)}")

        summary = (f"{len(functions)} functions, named recall {recall:.4f} "
                   f"over {len(truth)} map .text rows")
        report.update(status="pass", passed=True, summary=summary,
                      metrics={"named_recall": recall, "map_names": len(truth)})
        print(f"m20-003: PASS ({summary})")
    if arguments.report:
        arguments.report.write_text(json.dumps(report, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
