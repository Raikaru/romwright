#!/usr/bin/env python3
"""m5-002: Nintendo DS cartridges -- one container, two CPUs, two programs.

A DS cartridge carries an ARM9 image and an ARM7 image with different
architectures (ARMv5TE and ARMv4T), different load addresses and different
entry points. A program in the store has one language, so a container must
yield **two** programs; collapsing them would attach one CPU's code to the
other's decoder.

The header fields this reads are the documented ones (gbatek "DS Cartridge
Header"): ROM offset, entry address, RAM address and size for each CPU at
0x20 and 0x30. The fixture is built from committed source, so the same DWARF
scoring the M3 gates use applies to each CPU separately.

Assertions
  1. One import yields two programs, named per CPU, with `ARM:LE:32:v5t` for
     ARM9 and `ARM:LE:32:v4t` for ARM7.
  2. Each program maps its own image at the RAM address the header gives,
     and declares that CPU's memory map.
  3. Each program's entry seed is the header's entry address for that CPU.
  4. `dwarf.fn.recall >= 0.98` per CPU against that CPU's ELF twin, with
     every recovered entry attributed.
  5. A recovered function from each CPU decompiles natively, so neither
     language is claimed from a successful import alone.
  6. The loader refuses a container whose declared regions do not fit the
     file: a size or offset past the end is not a cartridge.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "benchmarks"))
sys.path.insert(0, str(ROOT / "scripts"))
from dwarf_arity import extract

HEADER_LEN = 0x200
RECALL_THRESHOLD = 0.98
CPUS = {
    "arm9": {"source": "nds_arm9.c", "script": "nds_arm9.ld", "triple": "armv5te-none-eabi",
             "arch": "armv5te", "language": "ARM:LE:32:v5t", "ram": 0x02000000,
             "regions": {"nds:arm9", "nds:main-ram", "nds:io", "nds:vram-a"}},
    "arm7": {"source": "nds_arm7.c", "script": "nds_arm7.ld", "triple": "armv4t-none-eabi",
             "arch": "armv4t", "language": "ARM:LE:32:v4t", "ram": 0x037F8000,
             "regions": {"nds:arm7", "nds:arm7-wram", "nds:io"}},
}


def build_cpu(cpu: dict, work: Path, name: str) -> tuple[Path, Path, int]:
    """Builds one CPU's ELF twin (with DWARF) and its raw image."""
    obj = work / f"{name}.o"
    subprocess.run(["clang", f"--target={cpu['triple']}", f"-march={cpu['arch']}", "-marm",
                    "-ffreestanding", "-fno-pic", "-O2", "-g", "-c",
                    str(ROOT / "tests/fixtures-src" / cpu["source"]), "-o", str(obj)],
                   cwd=ROOT, check=True, capture_output=True, text=True)
    elf = work / f"{name}.elf"
    subprocess.run(["ld.lld", "-T", str(ROOT / "tests/fixtures-src" / cpu["script"]),
                    "--nostdlib", "-o", str(elf), str(obj)],
                   cwd=ROOT, check=True, capture_output=True, text=True)
    raw = work / f"{name}.bin"
    subprocess.run(["llvm-objcopy", "-O", "binary", str(elf), str(raw)],
                   cwd=ROOT, check=True, capture_output=True, text=True)
    entry = int(subprocess.run(["llvm-readelf", "-h", str(elf)], text=True, check=True,
                               capture_output=True).stdout.split("Entry point address:")[1]
                .split()[0], 16)
    return elf, raw, entry


def build_container(work: Path) -> tuple[Path, dict]:
    """Assembles a cartridge from the documented header fields only."""
    images = {}
    for name, cpu in CPUS.items():
        elf, raw, entry = build_cpu(cpu, work, name)
        images[name] = {"elf": elf, "bytes": raw.read_bytes(), "entry": entry}

    arm9_offset = 0x4000
    arm7_offset = arm9_offset + len(images["arm9"]["bytes"])
    arm7_offset += -arm7_offset % 4
    total = arm7_offset + len(images["arm7"]["bytes"])

    rom = bytearray(total)
    # gbatek "DS Cartridge Header": title, game code, maker code, then the
    # two CPU descriptors at 0x20 and 0x30.
    rom[0x00:0x0C] = b"VENTRISGATE\x00"
    rom[0x0C:0x10] = b"VNDS"
    rom[0x10:0x12] = b"VT"
    struct.pack_into("<IIII", rom, 0x20, arm9_offset, images["arm9"]["entry"],
                     CPUS["arm9"]["ram"], len(images["arm9"]["bytes"]))
    struct.pack_into("<IIII", rom, 0x30, arm7_offset, images["arm7"]["entry"],
                     CPUS["arm7"]["ram"], len(images["arm7"]["bytes"]))
    struct.pack_into("<I", rom, 0x80, total)          # total used ROM size
    struct.pack_into("<I", rom, 0x84, HEADER_LEN)     # header size
    rom[arm9_offset:arm9_offset + len(images["arm9"]["bytes"])] = images["arm9"]["bytes"]
    rom[arm7_offset:arm7_offset + len(images["arm7"]["bytes"])] = images["arm7"]["bytes"]

    container = work / "fixture.nds"
    container.write_bytes(bytes(rom))
    return container, images


def twin_symbols(elf: Path) -> set[int]:
    output = subprocess.run(["readelf", "-sW", str(elf)], text=True,
                            capture_output=True, check=True).stdout
    addresses = set()
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 8 and parts[3] in ("FUNC", "NOTYPE"):
            try:
                addresses.add(int(parts[1], 16))
            except ValueError:
                continue
    return addresses


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--timeout", type=int, default=900)
    arguments = parser.parse_args()

    report = {"id": "m5-002", "recorded_at": datetime.now(timezone.utc).isoformat(),
              "thresholds": {"dwarf.fn.recall": RECALL_THRESHOLD}, "status": "skipped"}
    for tool in ("clang", "ld.lld", "llvm-objcopy"):
        if shutil.which(tool) is None:
            report["reason"] = f"no freestanding ARM toolchain: {tool} not found"
            print(f"SKIP: {report['reason']}")
            if arguments.report:
                arguments.report.write_text(json.dumps(report, indent=2) + "\n")
            return 0

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-cli"], cwd=ROOT, check=True)
    cli = ROOT / "target/release/lre-cli"
    with tempfile.TemporaryDirectory(prefix="m5-002-") as temporary:
        work = Path(temporary)
        container, images = build_container(work)
        project = work / "project"
        imported = subprocess.run(
            [str(cli), "import", str(container), "--name", "nds", "--project", str(project)],
            cwd=ROOT, capture_output=True, text=True, timeout=arguments.timeout)
        if imported.returncode != 0:
            raise AssertionError(f"import failed: {imported.stderr.strip()}")
        summary = imported.stdout.strip()

        store = sqlite3.connect(project / "project.sqlite")
        programs = {name: language for name, language
                    in store.execute("SELECT name, language FROM programs")}
        expected = {"nds.arm9": "ARM:LE:32:v5t", "nds.arm7": "ARM:LE:32:v4t"}
        if programs != expected:
            raise AssertionError(f"programs are {programs}, expected {expected}")

        rows = {}
        for name, cpu in CPUS.items():
            program = f"nds.{name}"
            identifier = store.execute(
                "SELECT id FROM programs WHERE name = ?", (program,)).fetchone()[0]
            regions = {region: (int(start, 16), size) for region, start, size in store.execute(
                "SELECT name, start, size FROM memory_regions WHERE program_id = ?",
                (identifier,))}
            missing = cpu["regions"] - set(regions)
            if missing:
                raise AssertionError(f"{program}: undeclared regions {sorted(missing)}")
            image_region = regions[f"nds:{name}"]
            if image_region != (cpu["ram"], len(images[name]["bytes"])):
                raise AssertionError(
                    f"{program}: image region {image_region} does not match the header's "
                    f"{cpu['ram']:#x} and {len(images[name]['bytes'])} bytes")

            observed = {int(entry, 16) for (entry,) in store.execute(
                "SELECT entry FROM functions WHERE program_id = ?", (identifier,))}
            if images[name]["entry"] not in observed:
                raise AssertionError(
                    f"{program}: header entry {images[name]['entry']:#010x} was not seeded")
            truth = {int(address, 16) for address in extract(images[name]["elf"])["functions"]}
            matched = truth & observed
            recall = len(matched) / len(truth)
            symbols = twin_symbols(images[name]["elf"])
            unattributed = sorted(f"{address:08x}" for address in observed - truth
                                  if address not in symbols)
            if recall < RECALL_THRESHOLD:
                raise AssertionError(
                    f"{program}: dwarf.fn.recall {recall:.4f} < {RECALL_THRESHOLD} "
                    f"(missing {sorted(f'{a:08x}' for a in truth - observed)})")
            if unattributed:
                raise AssertionError(f"{program}: invented functions {unattributed}")

            target = min(matched)
            decompiled = subprocess.run(
                [str(cli), "decompile", str(container), f"{target:08x}", "--name", program,
                 "--project", str(project)],
                cwd=ROOT, capture_output=True, text=True, timeout=arguments.timeout)
            if decompiled.returncode != 0 or "(" not in decompiled.stdout:
                raise AssertionError(
                    f"{program}: native decompilation failed at {target:#x}: "
                    f"{decompiled.stderr.strip() or decompiled.stdout.strip()}")
            rows[program] = {"language": programs[program], "dwarf.fn.recall": recall,
                             "dwarf.functions": len(truth), "functions": len(observed),
                             "unattributed": len(unattributed),
                             "entry": f"{images[name]['entry']:08x}",
                             "decompiled": {"address": f"{target:08x}",
                                            "text": decompiled.stdout.strip()[:300]}}

        # 6. A container that does not fit its own file is not a cartridge.
        truncated = work / "truncated.nds"
        data = bytearray(container.read_bytes())
        struct.pack_into("<I", data, 0x2C, len(data) * 4)
        truncated.write_bytes(bytes(data))
        refused = subprocess.run(
            [str(cli), "import", str(truncated), "--name", "bad",
             "--project", str(work / "refused")],
            cwd=ROOT, capture_output=True, text=True, timeout=arguments.timeout)
        if refused.returncode == 0 and "nds" in refused.stdout:
            raise AssertionError(
                f"a container claiming more than its file was accepted: {refused.stdout.strip()}")

    report.update(status="pass", passed=True, summary=summary, rows=rows)
    if arguments.report:
        arguments.report.write_text(json.dumps(report, indent=2) + "\n")
    print("m5-002: PASS (" + "; ".join(
        f"{program} {row['language']} recall {row['dwarf.fn.recall']:.4f} over "
        f"{row['dwarf.functions']} functions, {row['unattributed']} unattributed"
        for program, row in rows.items()) + ")")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
