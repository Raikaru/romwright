#!/usr/bin/env python3
"""m5-004: Nintendo 64 cartridge ROMs, scored against DWARF.

A ROM's first 0x1000 bytes are its header and boot code; the game code
follows, and the boot code copies it to the address the header names
(n64brew "ROM header": the PI configuration word at 0x00 and the boot address
at 0x08, both big-endian). The fixture carries no boot code -- IPL3 is
Nintendo's -- so the ROM here is the documented header fields plus one image
built from committed source, scored with the same DWARF machinery as the M3
gates.

Assertions
  1. The ROM is recognised as its own format on `MIPS:BE:64:64-32addr`; a
     big-endian image must not be guessed at as an ELF or another cartridge.
  2. The store maps the game code at the header's boot address and declares
     the console's memory map.
  3. The entry seed is that boot address.
  4. `dwarf.fn.recall >= 0.98` against the ELF twin, every recovered entry
     attributed.
  5. A recovered function decompiles natively, on a big-endian 64-bit
     language.
  6. A byte-swapped dump is refused *with its reason*, rather than mapped
     with bytes the decompiler would read in the wrong order.
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

SOURCE = ROOT / "tests/fixtures-src/n64_rom.c"
SCRIPT = ROOT / "tests/fixtures-src/n64_rom.ld"
CODE_OFFSET = 0x1000
BOOT_ADDRESS = 0x80000400
NATIVE_CONFIGURATION = 0x80371240
BYTESWAPPED_CONFIGURATION = 0x37804012
RECALL_THRESHOLD = 0.98
EXPECTED_REGIONS = {"n64:code", "n64:rdram", "n64:sp-dmem", "n64:sp-imem", "n64:mmio"}


def build(work: Path) -> tuple[Path, Path, int]:
    """Builds the ELF twin (with DWARF) and a native-order ROM."""
    obj = work / "n64.o"
    subprocess.run(["clang", "--target=mips-none-elf", "-march=mips3", "-mabi=32",
                    "-ffreestanding", "-fno-pic", "-fno-builtin", "-O2", "-g", "-c",
                    str(SOURCE), "-o", str(obj)],
                   cwd=ROOT, check=True, capture_output=True, text=True)
    elf = work / "n64.elf"
    subprocess.run(["ld.lld", "-T", str(SCRIPT), "--nostdlib", "-o", str(elf), str(obj)],
                   cwd=ROOT, check=True, capture_output=True, text=True)
    raw = work / "n64.bin"
    subprocess.run(["llvm-objcopy", "-O", "binary", str(elf), str(raw)],
                   cwd=ROOT, check=True, capture_output=True, text=True)
    entry = int(subprocess.run(["llvm-readelf", "-h", str(elf)], text=True, check=True,
                               capture_output=True).stdout.split("Entry point address:")[1]
                .split()[0], 16)

    # The header states where the boot code puts this image. IPL3 itself is
    # not reproduced: those 4032 bytes are Nintendo's.
    header = bytearray(CODE_OFFSET)
    struct.pack_into(">I", header, 0x00, NATIVE_CONFIGURATION)
    struct.pack_into(">I", header, 0x08, BOOT_ADDRESS)
    header[0x20:0x2C] = b"VENTRISGATE\x00"
    rom = work / "fixture.z64"
    rom.write_bytes(bytes(header) + raw.read_bytes())
    return elf, rom, entry


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

    report = {"id": "m5-004", "recorded_at": datetime.now(timezone.utc).isoformat(),
              "thresholds": {"dwarf.fn.recall": RECALL_THRESHOLD}, "status": "skipped"}
    for tool in ("clang", "ld.lld", "llvm-objcopy"):
        if shutil.which(tool) is None:
            report["reason"] = f"no freestanding MIPS toolchain: {tool} not found"
            print(f"SKIP: {report['reason']}")
            if arguments.report:
                arguments.report.write_text(json.dumps(report, indent=2) + "\n")
            return 0

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-cli"], cwd=ROOT, check=True)
    cli = ROOT / "target/release/lre-cli"
    with tempfile.TemporaryDirectory(prefix="m5-004-") as temporary:
        work = Path(temporary)
        elf, rom, entry = build(work)
        project = work / "project"
        imported = subprocess.run(
            [str(cli), "import", str(rom), "--name", "n64", "--project", str(project)],
            cwd=ROOT, capture_output=True, text=True, timeout=arguments.timeout)
        if imported.returncode != 0:
            raise AssertionError(f"import failed: {imported.stderr.strip()}")
        summary = imported.stdout.strip()

        store = sqlite3.connect(project / "project.sqlite")
        language = store.execute("SELECT language FROM programs WHERE name = 'n64'").fetchone()
        if language is None or language[0] != "MIPS:BE:64:64-32addr":
            raise AssertionError(f"language is {language}, expected MIPS:BE:64:64-32addr")
        regions = {name: (int(start, 16), size) for name, start, size in store.execute(
            "SELECT name, start, size FROM memory_regions")}
        missing_regions = EXPECTED_REGIONS - set(regions)
        if missing_regions:
            raise AssertionError(f"undeclared console regions: {sorted(missing_regions)}")
        code_size = rom.stat().st_size - CODE_OFFSET
        if regions["n64:code"] != (BOOT_ADDRESS, code_size):
            raise AssertionError(
                f"code region {regions['n64:code']} does not match the header's "
                f"{BOOT_ADDRESS:#x} and {code_size} bytes")

        observed = {int(row[0], 16) for row in store.execute("SELECT entry FROM functions")}
        if BOOT_ADDRESS not in observed:
            raise AssertionError(f"boot address {BOOT_ADDRESS:#010x} was not seeded")
        truth = {int(address, 16) for address in extract(elf)["functions"]}
        matched = truth & observed
        recall = len(matched) / len(truth)
        symbols = twin_symbols(elf)
        unattributed = sorted(f"{address:08x}" for address in observed - truth
                              if address not in symbols and address != BOOT_ADDRESS)
        if recall < RECALL_THRESHOLD:
            raise AssertionError(
                f"dwarf.fn.recall {recall:.4f} < {RECALL_THRESHOLD} "
                f"(missing {sorted(f'{a:08x}' for a in truth - observed)})")
        if unattributed:
            raise AssertionError(f"invented functions: {unattributed}")

        target = min(matched)
        decompiled = subprocess.run(
            [str(cli), "decompile", str(rom), f"{target:08x}", "--name", "n64",
             "--project", str(project)],
            cwd=ROOT, capture_output=True, text=True, timeout=arguments.timeout)
        if decompiled.returncode != 0 or "(" not in decompiled.stdout:
            raise AssertionError(
                f"native decompilation failed at {target:#x}: "
                f"{decompiled.stderr.strip() or decompiled.stdout.strip()}")

        # 6. A byte-swapped dump must be refused, and say why.
        swapped = bytearray(rom.read_bytes())
        struct.pack_into(">I", swapped, 0x00, BYTESWAPPED_CONFIGURATION)
        swapped_rom = work / "swapped.v64"
        swapped_rom.write_bytes(bytes(swapped))
        refused = subprocess.run(
            [str(cli), "import", str(swapped_rom), "--name", "swapped",
             "--project", str(work / "refused")],
            cwd=ROOT, capture_output=True, text=True, timeout=arguments.timeout)
        if refused.returncode == 0:
            raise AssertionError(
                f"a byte-swapped dump was accepted: {refused.stdout.strip()}")
        if "native order" not in refused.stderr:
            raise AssertionError(
                f"the refusal does not name the reason: {refused.stderr.strip()}")

    report.update(status="pass", passed=True, summary=summary,
                  metrics={"dwarf.fn.recall": recall, "dwarf.functions": len(truth),
                           "functions": len(observed), "unattributed": len(unattributed)},
                  entry=f"{entry:08x}", boot=f"{BOOT_ADDRESS:08x}",
                  regions={name: f"{start:08x}" for name, (start, _) in regions.items()},
                  decompiled={"address": f"{target:08x}",
                              "text": decompiled.stdout.strip()[:300]})
    if arguments.report:
        arguments.report.write_text(json.dumps(report, indent=2) + "\n")
    print(f"m5-004: PASS ({summary}; boot {BOOT_ADDRESS:#010x}, dwarf.fn.recall {recall:.4f} "
          f"over {len(truth)} functions, {len(unattributed)} unattributed, "
          f"decompiled {target:#010x}; byte-swapped dump refused)")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
