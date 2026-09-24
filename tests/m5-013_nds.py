#!/usr/bin/env python3
"""m5-013: a retail Nintendo DS cartridge, scored against its own symbols.

The DS container holds two processors' images (m5-002 loads both). What that
loader had never been scored against is a real cartridge: the corpus now
holds Pokemon HeartGold (USA) beside a byte-matching build of
`pret/pokeheartgold`, whose ARM9 ELF carries every function the game links
into its static module, and whose ARM7 ELF carries the subsystem's.

A retail ARM9 module is stored compressed. The SDK's crt0 unpacks it before
anything else runs (`MIi_UncompressBackward`, NitroSDK `crt0.c`), and the
loader must do the same or it scores the compressed bytes as code. The game
then enters Thumb code through `bx r1` from ARM crt0, so the interworking
mode must travel with every computed target, or half the module stays
unreached.

Assertions
  1. The cartridge yields a program per processor with the documented
     languages, `ARM:LE:32:v5t` for the ARM9 and `ARM:LE:32:v4t` for the
     ARM7, and one per ARM9 overlay, whose unpacked RAM image it maps.
  2. The ARM9 module is unpacked: its mapping spans the decompressed size,
     which is larger than the header's stored size.
  3. `NitroMain`, reached only through crt0's `bx r1`, is a function with a
     body, not a one-byte seed.
  4. Recall and precision of the ARM9 function set against the ELF's sized
     `FUNC` symbols inside the static module stay at or above the floors this
     gate records; the floors are what the last run proved and only move up.
  5. Decompilation works on a recovered Thumb function.

The images cannot be committed, so they are pinned by hash and their absence
is reported as a skip, never passed over silently.

Usage:
    python3 tests/m5-013_nds.py [--images-dir DIR] [--report OUT.json]
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
IMAGES = Path.home() / "romwright-corpus/extracted/nds-pokeheartgold"
ROM = "pokeheartgold.us.nds"
ROM_SHA256 = "65f02a56842b75aa92d775d56d657a56fe3fa993550b04dc20704ab82d760105"
ARM9_ELF = "pokeheartgold.elf"
ARM9_ELF_SHA256 = "9078d5d5ed64393a31d20e66b360d6cb05dd72b29de49f0e11b3ec54c866f9ba"
# NitroSDK `crt0.c`: NitroMain is what crt0 transfers to; the build's map
# places it here, and the ELF agrees.
NITRO_MAIN = 0x02000CA4
# The floors the last run proved (recall 0.9057, precision 0.9927, 10053
# functions), less 0.01. Stock Ghidra with its own NDS loader reaches recall
# 0.7698 on the same module. 731 of the functions only overlays call, found
# through the overlay programs' calls into the module.
RECALL_FLOOR = 0.895
PRECISION_FLOOR = 0.982


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--images-dir", type=Path, default=IMAGES)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--timeout", type=int, default=1800)
    arguments = parser.parse_args()

    report = {"id": "m5-013", "recorded_at": datetime.now(timezone.utc).isoformat(),
              "thresholds": {"fn.recall": RECALL_FLOOR, "fn.precision": PRECISION_FLOOR},
              "status": "skipped"}
    rom = arguments.images_dir / ROM
    elf = arguments.images_dir / ARM9_ELF
    if not rom.is_file() or not elf.is_file():
        report["reason"] = f"images absent under {arguments.images_dir}"
        print(f"SKIP: {report['reason']}")
        if arguments.report:
            arguments.report.write_text(json.dumps(report, indent=2) + "\n")
        return 0
    assert sha256(rom) == ROM_SHA256, f"{rom} is not the pinned cartridge"
    assert sha256(elf) == ARM9_ELF_SHA256, f"{elf} is not the pinned build"

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "romwright-cli", "-p", "romwright-worker"],
                   cwd=ROOT, check=True)
    cli = ROOT / "target/release/romwright-cli"
    with tempfile.TemporaryDirectory(prefix="m5-013-") as temporary:
        project = Path(temporary) / "project"
        imported = subprocess.run([str(cli), "import", str(rom), "--project", str(project)],
                                  cwd=ROOT, capture_output=True, text=True,
                                  timeout=arguments.timeout)
        assert imported.returncode == 0, f"import failed: {imported.stderr.strip()}"

        store = sqlite3.connect(project / "project.sqlite")
        programs = {name: (identifier, language) for identifier, name, language in
                    store.execute("SELECT id, name, language FROM programs")}
        arm9, arm7 = f"{ROM}.arm9", f"{ROM}.arm7"
        # Overlays share RAM, so each is a program of its own beside the two
        # static modules: one per OVT entry, `{id, ram, ram_size, bss, ...}`.
        data = rom.read_bytes()
        ovt_off, ovt_size = (int.from_bytes(data[at:at + 4], "little") for at in (0x50, 0x54))
        overlays = {}
        for at in range(ovt_off, ovt_off + ovt_size, 32):
            words = [int.from_bytes(data[at + i:at + i + 4], "little") for i in range(0, 32, 4)]
            overlays[f"{ROM}.ov{words[0]}"] = words[2] + words[3]
        assert set(programs) == {arm9, arm7} | set(overlays), (
            f"programs: {sorted(set(programs) ^ ({arm9, arm7} | set(overlays)))}")
        assert programs[arm9][1] == "ARM:LE:32:v5t", programs[arm9]
        assert programs[arm7][1] == "ARM:LE:32:v4t", programs[arm7]
        identifier = programs[arm9][0]
        # Overlay files are packed like the static module; each maps its
        # unpacked RAM image plus BSS, never the packed bytes.
        ov0 = programs[f"{ROM}.ov0"][0]
        (ov0_size,) = store.execute(
            "SELECT size FROM memory_regions WHERE program_id = ?", (ov0,)).fetchone()
        assert ov0_size == overlays[f"{ROM}.ov0"], (ov0_size, overlays[f"{ROM}.ov0"])

        # 2. The module is unpacked: the header stores the compressed size.
        stored = int.from_bytes(rom.read_bytes()[0x2C:0x30], "little")
        (module_start, module_size) = store.execute(
            "SELECT start, size FROM memory_regions WHERE program_id = ? AND name = 'nds:arm9'",
            (identifier,)).fetchone()
        assert int(module_start, 16) == 0x02000000, module_start
        assert module_size > stored, (
            f"ARM9 module is {module_size} bytes, the header stores {stored}: not unpacked")

        functions = {int(entry, 16): (name, size) for entry, name, size in store.execute(
            "SELECT entry, name, size FROM functions WHERE program_id = ?", (identifier,))}
        # 3. NitroMain, entered through crt0's `bx r1`.
        assert NITRO_MAIN in functions and functions[NITRO_MAIN][1] > 1, (
            f"NitroMain at {NITRO_MAIN:#x}: {functions.get(NITRO_MAIN)}")

        # 4. Score against the build's symbols inside the static module.
        truth = elf_functions(elf, 0x02000000, 0x02000000 + module_size)
        assert truth, "the ELF names no function inside the static module"
        hits = set(functions) & set(truth)
        recall = len(hits) / len(truth)
        precision = len(hits) / len(functions)
        assert recall >= RECALL_FLOOR, (
            f"fn.recall {recall:.4f} < {RECALL_FLOOR}: {len(hits)} of {len(truth)} "
            f"symbols recovered")
        assert precision >= PRECISION_FLOOR, (
            f"fn.precision {precision:.4f} < {PRECISION_FLOOR}: "
            f"{len(functions) - len(hits)} of {len(functions)} entries name no symbol")

        # 5. A Thumb function decompiles.
        decompiled = subprocess.run(
            [str(cli), "decompile-batch", str(rom), f"{NITRO_MAIN:08x}",
             "--name", arm9, "--project", str(project)],
            cwd=ROOT, capture_output=True, text=True, timeout=arguments.timeout)
        text = json.loads(decompiled.stdout).get(f"{NITRO_MAIN:08x}", "") \
            if decompiled.returncode == 0 else ""
        assert "{" in text and "}" in text, (
            f"decompilation of NitroMain failed: "
            f"{decompiled.stderr.strip() or decompiled.stdout.strip()[:200]}")

        summary = (f"ARM9 unpacked to {module_size} bytes (stored {stored}); "
                   f"{len(functions)} functions, fn.recall {recall:.4f} and "
                   f"fn.precision {precision:.4f} over {len(truth)} symbols; "
                   f"NitroMain {functions[NITRO_MAIN][1]} bytes, decompiled")
        report.update(status="pass", passed=True, summary=summary,
                      metrics={"fn.recall": recall, "fn.precision": precision,
                               "fn.symbols": len(truth), "fn.recovered": len(functions),
                               "arm9.module_bytes": module_size,
                               "arm9.stored_bytes": stored})
        if arguments.report:
            arguments.report.parent.mkdir(parents=True, exist_ok=True)
            arguments.report.write_text(json.dumps(report, indent=2) + "\n")
    print(f"m5-013: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
