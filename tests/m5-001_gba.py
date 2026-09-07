#!/usr/bin/env python3
"""m5-001: Game Boy Advance cartridge ROMs, scored against DWARF.

The first console platform, chosen because every piece needed to *prove* it
already exists: `ARM:LE:32:v4t` ships in the pinned Ghidra install, the
container is publicly documented (gbatek "Cartridge Header" and "Memory
Map"), and the fixture is built from committed source, so the same DWARF
scoring the M3 gates use applies unchanged.

A raw ROM carries no section table, no symbols and no entry field. What it
does carry is a branch at offset 0 and the fixed 0x96 at 0xB2. The loader
must map the image at 0x08000000, resolve that branch as the entry seed, and
declare the console's memory map -- and then discovery has to find the
functions with nothing but flow.

Assertions
  1. The ROM is recognised as its own format with the ARMv4T language; a raw
     image must not be guessed at as an ELF or a PE.
  2. The store's regions are the documented map: ROM at 0x08000000 holding
     the image bytes, plus the RAM/IO regions the console defines.
  3. The entry seed is the branch target at ROM offset 0, not offset 0
     itself.
  4. `dwarf.fn.recall >= 0.98` against the ELF twin's DWARF, with every
     recovered entry attributed: DWARF, a twin symbol, or the entry stub.
  5. Decompilation works on a recovered function, so the platform is not
     claimed from a successful import alone.
"""
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

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "benchmarks"))
sys.path.insert(0, str(ROOT / "scripts"))
from dwarf_arity import extract

SOURCE = ROOT / "tests/fixtures-src/gba_rom.c"
HEADER = ROOT / "tests/fixtures-src/gba_header.S"
SCRIPT = ROOT / "tests/fixtures-src/gba_rom.ld"
ROM_BASE = 0x08000000
RECALL_THRESHOLD = 0.98
# gbatek "Memory Map": the regions a cartridge image implies but does not
# contain. Names are the console's, not the loader's invention.
EXPECTED_REGIONS = {"gba:rom", "gba:ewram", "gba:iwram", "gba:io", "gba:palette",
                    "gba:vram", "gba:oam"}


def build(work: Path) -> tuple[Path, Path]:
    """Builds the ELF twin (with DWARF) and the raw ROM from committed source."""
    for tool in ("clang", "ld.lld", "llvm-objcopy"):
        if shutil.which(tool) is None:
            raise FileNotFoundError(tool)
    objects = []
    for source, extra in ((SOURCE, ["-O2", "-g", "-ffreestanding", "-fno-pic"]), (HEADER, [])):
        obj = work / (source.stem + ".o")
        subprocess.run(["clang", "--target=armv4t-none-eabi", "-march=armv4t", "-marm",
                        *extra, "-c", str(source), "-o", str(obj)],
                       cwd=ROOT, check=True, capture_output=True, text=True)
        objects.append(obj)
    elf = work / "gba_rom.elf"
    subprocess.run(["ld.lld", "-T", str(SCRIPT), "--nostdlib", "-o", str(elf),
                    str(objects[1]), str(objects[0])],
                   cwd=ROOT, check=True, capture_output=True, text=True)
    rom = work / "gba_rom.gba"
    subprocess.run(["llvm-objcopy", "-O", "binary", str(elf), str(rom)],
                   cwd=ROOT, check=True, capture_output=True, text=True)
    return elf, rom


def twin_symbols(elf: Path) -> dict[int, str]:
    output = subprocess.run(["readelf", "-sW", str(elf)], text=True,
                            capture_output=True, check=True).stdout
    symbols = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 8 and parts[3] in ("FUNC", "NOTYPE"):
            try:
                symbols[int(parts[1], 16)] = parts[7]
            except ValueError:
                continue
    return symbols


def entry_target(rom: Path) -> int:
    """The ARM branch at ROM offset 0, per the ARM architecture reference:
    target = pc + 8 + (signed imm24 << 2)."""
    word = int.from_bytes(rom.read_bytes()[:4], "little")
    if word >> 24 != 0xEA:
        raise AssertionError(f"ROM offset 0 is not an unconditional branch: {word:#010x}")
    offset = word & 0x00FFFFFF
    if offset & 0x00800000:
        offset -= 0x01000000
    return ROM_BASE + 8 + (offset << 2)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--timeout", type=int, default=900)
    arguments = parser.parse_args()

    report = {"id": "m5-001", "recorded_at": datetime.now(timezone.utc).isoformat(),
              "thresholds": {"dwarf.fn.recall": RECALL_THRESHOLD}, "status": "skipped"}
    with tempfile.TemporaryDirectory(prefix="m5-001-") as temporary:
        work = Path(temporary)
        try:
            elf, rom = build(work)
        except FileNotFoundError as missing:
            report["reason"] = f"no freestanding ARM toolchain: {missing} not found"
            print(f"SKIP: {report['reason']}")
            if arguments.report:
                arguments.report.write_text(json.dumps(report, indent=2) + "\n")
            return 0

        subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-cli"],
                       cwd=ROOT, check=True)
        cli = ROOT / "target/release/lre-cli"
        project = work / "project"
        imported = subprocess.run(
            [str(cli), "import", str(rom), "--name", "gba", "--project", str(project)],
            cwd=ROOT, capture_output=True, text=True, timeout=arguments.timeout)
        if imported.returncode != 0:
            raise AssertionError(f"import failed: {imported.stderr.strip()}")
        summary = imported.stdout.strip()

        store = sqlite3.connect(project / "project.sqlite")
        language = store.execute("SELECT language FROM programs WHERE name = 'gba'").fetchone()
        if language is None or language[0] != "ARM:LE:32:v4t":
            raise AssertionError(f"language is {language} , expected ARM:LE:32:v4t")
        regions = {name: (int(start, 16), size, permissions) for name, start, size, permissions
                   in store.execute("SELECT name, start, size, permissions FROM memory_regions")}
        missing = EXPECTED_REGIONS - set(regions)
        if missing:
            raise AssertionError(f"undeclared console regions: {sorted(missing)}")
        rom_region = regions["gba:rom"]
        if rom_region[0] != ROM_BASE or rom_region[1] != rom.stat().st_size:
            raise AssertionError(f"ROM region is {rom_region}, expected {ROM_BASE:#x} "
                                 f"and {rom.stat().st_size} bytes")

        observed = {int(row[0], 16) for row in store.execute("SELECT entry FROM functions")}
        truth = {int(address, 16) for address in extract(elf)["functions"]}
        seed = entry_target(rom)
        if seed not in observed:
            raise AssertionError(f"entry branch target {seed:#010x} was not seeded")

        matched = truth & observed
        recall = len(matched) / len(truth)
        symbols = twin_symbols(elf)
        unattributed = sorted(f"{address:08x}" for address in observed - truth
                              if address not in symbols and address != ROM_BASE)
        if recall < RECALL_THRESHOLD:
            raise AssertionError(
                f"dwarf.fn.recall {recall:.4f} < {RECALL_THRESHOLD} "
                f"(missing {sorted(f'{a:08x}' for a in truth - observed)})")
        if unattributed:
            raise AssertionError(f"invented functions: {unattributed}")

        # The bundle must carry real injection bodies. `CompilerSpec.encode`
        # cannot reproduce them, and a raw-SLEIGH worker compiles what the
        # bundle says: a placeholder would silently make ARM `bx` a no-op.
        cspec = (ROOT / "native/specs/ARM-LE-32-v4t/cspec.xml").read_text()
        if "setISAMode" not in cspec:
            raise AssertionError("the ARM bundle declares no setISAMode injection")
        if "local tmp:1 = 0;" in cspec:
            raise AssertionError(
                "the ARM bundle carries placeholder injection bodies; re-export it "
                "with scripts/gen_native_specs.py")

        # A platform is not supported because an import succeeded.
        target = min(matched)
        decompiled = subprocess.run(
            [str(cli), "decompile", str(rom), f"{target:08x}", "--name", "gba",
             "--project", str(project)],
            cwd=ROOT, capture_output=True, text=True, timeout=arguments.timeout)
        if decompiled.returncode != 0 or "(" not in decompiled.stdout:
            raise AssertionError(
                f"native decompilation failed at {target:#x}: "
                f"{decompiled.stderr.strip() or decompiled.stdout.strip()}")

    report.update(status="pass", passed=True, summary=summary,
                  metrics={"dwarf.fn.recall": recall, "dwarf.functions": len(truth),
                           "functions": len(observed), "unattributed": len(unattributed)},
                  entry=f"{seed:08x}", regions={name: f"{start:08x}"
                                                for name, (start, _, _) in regions.items()},
                  decompiled={"address": f"{target:08x}",
                              "text": decompiled.stdout.strip()[:400]})
    if arguments.report:
        arguments.report.write_text(json.dumps(report, indent=2) + "\n")
    print(f"m5-001: PASS ({summary}; entry {seed:#010x}, "
          f"dwarf.fn.recall {recall:.4f} over {len(truth)} functions, "
          f"{len(unattributed)} unattributed, decompiled {target:#010x})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
