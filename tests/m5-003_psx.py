#!/usr/bin/env python3
"""m5-003: PlayStation executables, scored against DWARF.

A PS-EXE is a 2 KiB header followed by one flat image. The header states
where the image loads, where execution starts and how long the image is
(psx-spx "Executables": magic at 0x00, initial PC at 0x10, destination
address at 0x18, size at 0x1C). Nothing else in the file says anything about
functions, so discovery has to close the rest from flow.

The fixture is built from committed source with clang/lld for MIPS R3000A,
so the same DWARF scoring the M3 gates use applies here too. The header this
test writes contains only documented fields -- no licence string is
reproduced, because that text is Sony's, not a loader requirement.

Assertions
  1. The image is recognised as its own format on `MIPS:LE:32:default`; a
     PS-EXE must not be guessed at as an ELF, a PE or a cartridge.
  2. The store maps the image at the header's destination address, with the
     header's size, and declares the console's memory map.
  3. The entry seed is the header's initial PC.
  4. `dwarf.fn.recall >= 0.98` against the ELF twin, every recovered entry
     attributed.
  5. A recovered function decompiles natively.
  6. A header whose size field does not match the file is refused.
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

SOURCE = ROOT / "tests/fixtures-src/psx_exe.c"
SCRIPT = ROOT / "tests/fixtures-src/psx_exe.ld"
HEADER_LEN = 0x800
LOAD_ADDRESS = 0x80010000
RECALL_THRESHOLD = 0.98
# psx-spx "Memory Map": what a PlayStation program sees but the file does
# not contain.
EXPECTED_REGIONS = {"psx:text", "psx:main-ram", "psx:scratchpad", "psx:io"}


def build(work: Path) -> tuple[Path, Path, int]:
    """Builds the ELF twin (with DWARF) and the PS-EXE image."""
    obj = work / "psx.o"
    subprocess.run(["clang", "--target=mipsel-none-elf", "-march=mips1", "-ffreestanding",
                    "-fno-pic", "-fno-builtin", "-O2", "-g", "-c", str(SOURCE), "-o", str(obj)],
                   cwd=ROOT, check=True, capture_output=True, text=True)
    elf = work / "psx.elf"
    subprocess.run(["ld.lld", "-T", str(SCRIPT), "--nostdlib", "-o", str(elf), str(obj)],
                   cwd=ROOT, check=True, capture_output=True, text=True)
    raw = work / "psx.bin"
    subprocess.run(["llvm-objcopy", "-O", "binary", str(elf), str(raw)],
                   cwd=ROOT, check=True, capture_output=True, text=True)
    entry = int(subprocess.run(["llvm-readelf", "-h", str(elf)], text=True, check=True,
                               capture_output=True).stdout.split("Entry point address:")[1]
                .split()[0], 16)

    image = raw.read_bytes()
    header = bytearray(HEADER_LEN)
    header[0x00:0x08] = b"PS-X EXE"
    struct.pack_into("<I", header, 0x10, entry)            # initial PC
    struct.pack_into("<I", header, 0x14, 0)                # initial GP
    struct.pack_into("<I", header, 0x18, LOAD_ADDRESS)     # destination
    struct.pack_into("<I", header, 0x1C, len(image))       # image size
    struct.pack_into("<I", header, 0x30, 0x801FFF00)       # stack base
    executable = work / "fixture.exe"
    executable.write_bytes(bytes(header) + image)
    return elf, executable, entry


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

    report = {"id": "m5-003", "recorded_at": datetime.now(timezone.utc).isoformat(),
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
    with tempfile.TemporaryDirectory(prefix="m5-003-") as temporary:
        work = Path(temporary)
        elf, executable, entry = build(work)
        project = work / "project"
        imported = subprocess.run(
            [str(cli), "import", str(executable), "--name", "psx", "--project", str(project)],
            cwd=ROOT, capture_output=True, text=True, timeout=arguments.timeout)
        if imported.returncode != 0:
            raise AssertionError(f"import failed: {imported.stderr.strip()}")
        summary = imported.stdout.strip()

        store = sqlite3.connect(project / "project.sqlite")
        language = store.execute("SELECT language FROM programs WHERE name = 'psx'").fetchone()
        if language is None or language[0] != "MIPS:LE:32:default":
            raise AssertionError(f"language is {language}, expected MIPS:LE:32:default")
        regions = {name: (int(start, 16), size) for name, start, size in store.execute(
            "SELECT name, start, size FROM memory_regions")}
        missing_regions = EXPECTED_REGIONS - set(regions)
        if missing_regions:
            raise AssertionError(f"undeclared console regions: {sorted(missing_regions)}")
        image_size = executable.stat().st_size - HEADER_LEN
        if regions["psx:text"] != (LOAD_ADDRESS, image_size):
            raise AssertionError(
                f"image region {regions['psx:text']} does not match the header's "
                f"{LOAD_ADDRESS:#x} and {image_size} bytes")

        observed = {int(row[0], 16) for row in store.execute("SELECT entry FROM functions")}
        if entry not in observed:
            raise AssertionError(f"header entry {entry:#010x} was not seeded")
        truth = {int(address, 16) for address in extract(elf)["functions"]}
        matched = truth & observed
        recall = len(matched) / len(truth)
        symbols = twin_symbols(elf)
        unattributed = sorted(f"{address:08x}" for address in observed - truth
                              if address not in symbols)
        if recall < RECALL_THRESHOLD:
            raise AssertionError(
                f"dwarf.fn.recall {recall:.4f} < {RECALL_THRESHOLD} "
                f"(missing {sorted(f'{a:08x}' for a in truth - observed)})")
        if unattributed:
            raise AssertionError(f"invented functions: {unattributed}")

        target = min(matched)
        decompiled = subprocess.run(
            [str(cli), "decompile", str(executable), f"{target:08x}", "--name", "psx",
             "--project", str(project)],
            cwd=ROOT, capture_output=True, text=True, timeout=arguments.timeout)
        if decompiled.returncode != 0 or "(" not in decompiled.stdout:
            raise AssertionError(
                f"native decompilation failed at {target:#x}: "
                f"{decompiled.stderr.strip() or decompiled.stdout.strip()}")

        # 6. A header that disagrees with its own file is not a PS-EXE.
        data = bytearray(executable.read_bytes())
        struct.pack_into("<I", data, 0x1C, len(data) * 4)
        broken = work / "broken.exe"
        broken.write_bytes(bytes(data))
        refused = subprocess.run(
            [str(cli), "import", str(broken), "--name", "bad",
             "--project", str(work / "refused")],
            cwd=ROOT, capture_output=True, text=True, timeout=arguments.timeout)
        if refused.returncode == 0 and "MIPS" in refused.stdout:
            raise AssertionError(
                f"a header claiming more than its file was accepted: {refused.stdout.strip()}")

    report.update(status="pass", passed=True, summary=summary,
                  metrics={"dwarf.fn.recall": recall, "dwarf.functions": len(truth),
                           "functions": len(observed), "unattributed": len(unattributed)},
                  entry=f"{entry:08x}",
                  regions={name: f"{start:08x}" for name, (start, _) in regions.items()},
                  decompiled={"address": f"{target:08x}",
                              "text": decompiled.stdout.strip()[:300]})
    if arguments.report:
        arguments.report.write_text(json.dumps(report, indent=2) + "\n")
    print(f"m5-003: PASS ({summary}; entry {entry:#010x}, dwarf.fn.recall {recall:.4f} "
          f"over {len(truth)} functions, {len(unattributed)} unattributed, "
          f"decompiled {target:#010x})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
