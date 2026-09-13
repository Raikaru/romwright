#!/usr/bin/env python3
"""m20-001: CodeWarrior MAP ingestion names what discovery cannot.

The HeartGold corpus holds the linker ground truth beside the ROM: an
11 MB mwldarm MAP, a full-symtab ELF, and a retail ROM the build
reproduces byte-for-byte. Stock Ghidra has no DS MAP importer (R7
baseline: documented absence), so the gate is differential against the
ELF symtab rather than stock: MAP FUNC rows must agree with ELF FUNC
symbols at the same addresses, and a ROM import with `--map` must
carry those names into the store.

Usage:
    python3 tests/m20-001_cw_map.py [--images-dir DIR] [--report OUT.json]
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
IMAGES = Path.home() / "romwright-corpus/extracted/nds-pokeheartgold"
ROM = "pokeheartgold.us.nds"
MAP = "pokeheartgold.map"
ELF = "pokeheartgold.elf"
NITRO_MAIN = 0x02000CA4
RECALL_FLOOR = 0.95

# mwldarm layout row: `  ADDR SIZE SECTION NAME<tab>(TU)`. Independent
# oracle for the Rust reader: address + name only, no type join.
LAYOUT_ROW = re.compile(r"^  ([0-9A-F]{8}) [0-9A-F]+ \.\S+\s+(\S+)")


def elf_functions(elf: Path, low: int, high: int) -> dict[int, str]:
    """Sized FUNC symbols inside [low, high), by aligned address."""
    output = subprocess.run(["readelf", "-sW", str(elf)], capture_output=True,
                            text=True, check=True).stdout
    functions: dict[int, str] = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 8 or parts[3] != "FUNC" or int(parts[2]) == 0:
            continue
        address = int(parts[1], 16) & ~1
        if low <= address < high:
            functions.setdefault(address, parts[7])
    return functions


def map_names(map_path: Path, low: int, high: int) -> dict[int, str]:
    """Named, sized, non-marker layout rows inside [low, high)."""
    names: dict[int, str] = {}
    for line in map_path.read_text(errors="replace").splitlines():
        match = LAYOUT_ROW.match(line)
        if not match:
            continue
        address = int(match.group(1), 16)
        name = match.group(2)
        if name.startswith("$") or name.startswith("."):
            continue
        if low <= address < high:
            names.setdefault(address, name)
    return names


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--images-dir", type=Path, default=IMAGES)
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()

    report = {"id": "m20-001",
              "recorded_at": datetime.now(timezone.utc).isoformat(),
              "thresholds": {"named_recall": RECALL_FLOOR},
              "status": "skipped"}
    rom = arguments.images_dir / ROM
    map_file = arguments.images_dir / MAP
    elf = arguments.images_dir / ELF
    if not rom.is_file() or not map_file.is_file() or not elf.is_file():
        report["reason"] = "images absent"
        print(f"SKIP: {report['reason']}")
        if arguments.report:
            arguments.report.write_text(json.dumps(report, indent=2) + "\n")
        return 0

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "romwright-cli"],
                   cwd=ROOT, check=True)
    cli = ROOT / "target/release/romwright-cli"
    with tempfile.TemporaryDirectory(prefix="m20-001-") as temporary:
        project = Path(temporary) / "project"
        imported = subprocess.run(
            [str(cli), "import", str(rom), "--map", str(map_file),
             "--name", "nds", "--project", str(project)],
            cwd=ROOT, capture_output=True, text=True, timeout=1800)
        assert imported.returncode == 0, f"import failed: {imported.stderr.strip()}"

        store = sqlite3.connect(project / "project.sqlite")
        identifier = store.execute(
            "SELECT id FROM programs WHERE name = 'nds.arm9'").fetchone()[0]
        module_size = store.execute(
            "SELECT size FROM memory_regions WHERE program_id = ? AND name = 'nds:arm9'",
            (identifier,)).fetchone()[0]
        functions = {int(entry, 16): name for entry, name in store.execute(
            "SELECT entry, name FROM functions WHERE program_id = ?", (identifier,))}

        # 1. The linker's own word for the entry reached through crt0's bx r1.
        assert functions.get(NITRO_MAIN) == "NitroMain", (
            f"NitroMain at {NITRO_MAIN:#x}: {functions.get(NITRO_MAIN)}")

        # 2. MAP names land on ELF truth: named recall far above the 0.61
        # discovery floor.
        truth = elf_functions(elf, 0x02000000, 0x02000000 + module_size)
        hits = sum(1 for address, name in truth.items()
                   if functions.get(address) == name)
        recall = hits / len(truth)
        assert recall >= RECALL_FLOOR, (
            f"named recall {recall:.4f} < {RECALL_FLOOR}: {hits} of {len(truth)}")

        # 3. MAP and ELF agree with each other through the store: MAP rows
        # the linker types as functions carry ELF's names.
        rows = map_names(map_file, 0x02000000, 0x02000000 + module_size)
        both = [address for address in rows if address in truth]
        agree = sum(1 for address in both
                    if rows[address] == truth[address]
                    and functions.get(address) == truth[address])
        agreement = agree / len(both)
        assert agreement >= 0.99, (
            f"MAP/ELF agreement {agreement:.4f}: {agree} of {len(both)}")

        summary = (f"{len(functions)} functions, named recall {recall:.4f} "
                   f"over {len(truth)} ELF symbols, MAP/ELF agreement "
                   f"{agreement:.4f} over {len(both)} shared rows")
        report.update(status="pass", passed=True, summary=summary,
                      metrics={"named_recall": recall, "elf_symbols": len(truth),
                               "map_rows": len(rows), "agreement": agreement})
        print(f"m20-001: PASS ({summary})")
    if arguments.report:
        arguments.report.write_text(json.dumps(report, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
