#!/usr/bin/env python3
"""m20-006: PS Vita SCE ELF loading and NID symbol resolution.

The NFS Most Wanted corpus ships a sectionless SCE ELF (e_type 0xfe00,
program headers only) beside a binary symbol map. Stock Ghidra has no
Vita loader (R7 baseline: documented absence), so the gate asserts the
format's own ground truth: PT_LOAD mappings, the module export table's
module_start, NID-named import stubs, and — through --map — the BINMAP's
linked names and NID resolutions.

Usage:
    python3 tests/m20-006_vita_elf.py [--images-dir DIR] [--report OUT.json]
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IMAGES = Path.home() / "ventris-corpus/extracted/psv-need-for-speed-most-wanted"
ELF = "eboot.elf"
BINMAP = "EBOOT.BINMAP"

# sce_module_info sits at e_entry's segment offset; module_start is the
# export table's NID 0x935cd196 entry (vita-toolchain sce-elf.h).
MODULE_START = 0x8146DF24
# A plain BINMAP record: vaddr (Thumb bit set in the file) + size + name.
KNOWN_FUNCTION = 0x8100B7AE
KNOWN_NAME = "Game::GameLogic::AchievementManagerVITA::UpdateTrophies"
# NID 0x0056061b resolves to ldexp through the BINMAP's _NID_/_INID_ rows.
LDEXP_STUB = 0x8167BD8C
FUNCTION_FLOOR = 20000


def functions(store: sqlite3.Connection, program: str) -> dict[int, str]:
    identifier = store.execute(
        "SELECT id FROM programs WHERE name = ?", (program,)).fetchone()[0]
    return {int(entry, 16): name for entry, name in store.execute(
        "SELECT entry, name FROM functions WHERE program_id = ?", (identifier,))}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--images-dir", type=Path, default=IMAGES)
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()

    report = {"id": "m20-006",
              "recorded_at": datetime.now(timezone.utc).isoformat(),
              "thresholds": {"functions": FUNCTION_FLOOR},
              "status": "skipped"}
    elf = arguments.images_dir / ELF
    binmap = arguments.images_dir / BINMAP
    if not elf.is_file() or not binmap.is_file():
        report["reason"] = "images absent"
        print(f"SKIP: {report['reason']}")
        if arguments.report:
            arguments.report.write_text(json.dumps(report, indent=2) + "\n")
        return 0

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-cli"],
                   cwd=ROOT, check=True)
    cli = ROOT / "target/release/lre-cli"
    with tempfile.TemporaryDirectory(prefix="m20-006-") as temporary:
        # 1. The sectionless SCE ELF imports through its program headers:
        #    module_start from the export table, NID-named import stubs.
        project = Path(temporary) / "bare"
        imported = subprocess.run(
            [str(cli), "import", str(elf), "--no-analysis",
             "--name", "eboot", "--project", str(project)],
            cwd=ROOT, capture_output=True, text=True, timeout=1800)
        assert imported.returncode == 0, f"import failed: {imported.stderr.strip()}"
        store = sqlite3.connect(project / "project.sqlite")
        bare = functions(store, "eboot")
        assert bare, "no functions from SCE export/import tables"
        assert bare.get(MODULE_START) == "module_start", (
            f"module_start at {MODULE_START:#x}: {bare.get(MODULE_START)}")
        assert bare.get(LDEXP_STUB) == "sce_import_SceLibm_0056061b", (
            f"import stub at {LDEXP_STUB:#x}: {bare.get(LDEXP_STUB)}")
        regions = store.execute(
            "SELECT start, permissions FROM memory_regions").fetchall()
        assert any(start == "81000000" and "x" in perms
                   for start, perms in regions), f"no exec region: {regions}"
        store.close()

        # 2. --map EBOOT.BINMAP: linked names land on addresses, and the
        #    NID table renames the SCE placeholders.
        project = Path(temporary) / "mapped"
        imported = subprocess.run(
            [str(cli), "import", str(elf), "--no-analysis", "--map", str(binmap),
             "--name", "eboot", "--project", str(project)],
            cwd=ROOT, capture_output=True, text=True, timeout=1800)
        assert imported.returncode == 0, f"import failed: {imported.stderr.strip()}"
        store = sqlite3.connect(project / "project.sqlite")
        mapped = functions(store, "eboot")
        assert len(mapped) >= FUNCTION_FLOOR, (
            f"{len(mapped)} functions < {FUNCTION_FLOOR}")
        # The _MNID_ row renames module_start to the linked symbol.
        assert mapped.get(MODULE_START) == "_start", (
            f"module_start at {MODULE_START:#x}: {mapped.get(MODULE_START)}")
        assert mapped.get(KNOWN_FUNCTION) == KNOWN_NAME, (
            f"{KNOWN_FUNCTION:#x}: {mapped.get(KNOWN_FUNCTION)}")
        assert mapped.get(LDEXP_STUB) == "ldexp", (
            f"import stub at {LDEXP_STUB:#x}: {mapped.get(LDEXP_STUB)}")
        leftovers = sum(1 for name in mapped.values()
                        if name.startswith("sce_import_"))
        assert leftovers == 0, f"{leftovers} unresolved NID names"
        store.close()

        summary = (f"{len(bare)} SCE-seeded functions, {len(mapped)} "
                   f"BINMAP-named, NID imports resolved")
        report.update(status="pass", passed=True, summary=summary,
                      metrics={"bare_functions": len(bare),
                               "mapped_functions": len(mapped)})
        print(f"m20-006: PASS ({summary})")
    if arguments.report:
        arguments.report.write_text(json.dumps(report, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
