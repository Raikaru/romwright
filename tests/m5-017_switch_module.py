#!/usr/bin/env python3
"""m5-017: a Nintendo Switch module, loaded and scored with no JVM.

The image is an NSO0: three LZ4-compressed segments and a `MOD0` header
pointing at an ELF64 dynamic table. The loader is `crates/lre-core/src/
native/nso.rs`; this gate proves it against the module's own symbol table,
which it parses here independently -- a different LZ4 implementation, a
different dynamic-table reader -- so the measurement does not rest on the
code under test.

The target is a retail dump and is not in the repository. Without it the gate
skips and says so, the way the other console gates do.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import sqlite3
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "target" / "release" / "lre-cli"
DEFAULT_TARGET = Path.home() / "ventris-corpus/extracted/nx-xenoblade-de/main"

# Where a 64-bit module is mapped (`SwitchLoader.load` in the Ghidra
# extension, and `nso.rs`).
BASE = 0x71_0000_0000

THRESHOLDS = {
    # Every function the module names must be recovered: the loader reads
    # that table, so anything less is a loader defect, not an analysis gap.
    "symbol_recall": 1.0,
    # Functions beyond the symbol table are static functions flow reached;
    # they are not scored as wrong, but a flood of them would be.
    "symbol_precision": 0.95,
    # Stock Ghidra with the Switch loader extension recovered 45259
    # functions on this module (analyzeHeadless, `SwitchLoader`,
    # AARCH64:LE:64:v8A, base 0x7100000000).
    "stock_ratio": 0.95,
    # Re-baselined when the switch round started answering this module. At
    # 420 s (commit 7a14e1e) the round resolved *zero* dispatches here: the
    # value-set pass found none on AArch64 and the decompiler path was not
    # yet behind it. It now resolves 690, each one a decompile of a real
    # body, and the import measures 1452 s on this host -- so the old budget
    # was pricing an import that did less. The ceiling is what this host
    # measures plus room for a slower runner; bringing it back down is the
    # jump-table milestone's job (sound analysis instead of the decompiler),
    # not a number to relax again.
    "wall_seconds": 1800.0,
    # And the extra time has to keep buying those dispatches: a faster
    # import that stops answering them fails here rather than looking like
    # an improvement.
    "switch_dispatches": 690,
}
STOCK_FUNCTIONS = 45259


def segments(data: bytes) -> list[tuple[int, int, int, int, bool]]:
    flags = struct.unpack_from("<I", data, 0x0C)[0]
    out = []
    for index, at in enumerate((0x10, 0x20, 0x30)):
        file_offset, memory_offset, size = struct.unpack_from("<III", data, at)
        compressed_size = struct.unpack_from("<I", data, 0x60 + index * 4)[0]
        out.append(
            (
                file_offset,
                memory_offset,
                size,
                compressed_size,
                bool(flags & (1 << index)),
            )
        )
    return out


def assemble(data: bytes) -> bytes:
    import lz4.block

    parts = segments(data)
    end = parts[2][1] + parts[2][2]
    image = bytearray(end)
    for file_offset, memory_offset, size, compressed_size, compressed in parts:
        stored = data[file_offset : file_offset + (compressed_size if compressed else size)]
        out = (
            lz4.block.decompress(stored, uncompressed_size=size) if compressed else stored
        )
        image[memory_offset : memory_offset + size] = out
    return bytes(image)


def module_functions(data: bytes) -> dict[int, str]:
    """Every `STT_FUNC` symbol the module declares, by mapped address."""
    image = assemble(data)
    text_offset = segments(data)[0][1]
    mod0 = struct.unpack_from("<I", image, text_offset + 4)[0]
    if image[mod0 : mod0 + 4] != b"MOD0":
        raise ValueError("module has no MOD0 header")
    cursor = mod0 + struct.unpack_from("<I", image, mod0 + 4)[0]
    tags: dict[int, int] = {}
    while True:
        tag, value = struct.unpack_from("<QQ", image, cursor)
        cursor += 16
        if tag == 0:
            break
        tags.setdefault(tag, value)
    symtab, strtab = tags[6], tags[5]
    entry_size = tags.get(11, 24)
    count = struct.unpack_from("<I", image, tags[4] + 4)[0]
    out = {}
    for index in range(count):
        at = symtab + index * entry_size
        name_offset, info = struct.unpack_from("<IB", image, at)
        value = struct.unpack_from("<Q", image, at + 8)[0]
        if info & 0xF != 2 or value == 0:
            continue
        end = image.index(b"\0", strtab + name_offset)
        out[BASE + value] = image[strtab + name_offset : end].decode("utf8", "replace")
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, default=DEFAULT_TARGET)
    parser.add_argument("--work", type=Path, default=Path.home() / "ventris-cache/tmp/m5-017")
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()

    report = {
        "id": "m5-017",
        "milestone": "M5",
        "criterion": "a Switch NSO0 module imported with no JVM and scored against its own symbols",
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "thresholds": THRESHOLDS,
        "stock_functions": STOCK_FUNCTIONS,
    }
    if not arguments.target.is_file():
        report["status"] = "skipped"
        report["reason"] = f"{arguments.target} is not on this machine (retail dump)"
        print(f"m5-017: SKIPPED ({report['reason']})")
        if arguments.report:
            arguments.report.parent.mkdir(parents=True, exist_ok=True)
            arguments.report.write_text(json.dumps(report, indent=2) + "\n")
        return 0

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-cli"], cwd=ROOT, check=True)
    data = arguments.target.read_bytes()
    truth = module_functions(data)

    if arguments.work.exists():
        shutil.rmtree(arguments.work)
    arguments.work.mkdir(parents=True)
    started = time.time()
    result = subprocess.run(
        [
            str(CLI),
            "import",
            str(arguments.target),
            "--project",
            str(arguments.work),
            "--name",
            "module",
        ],
        capture_output=True,
        text=True,
    )
    wall = time.time() - started
    if result.returncode:
        raise ValueError(f"import failed: {result.stderr[-800:]}")

    connection = sqlite3.connect(arguments.work / "project.sqlite")
    ours = {
        int(entry, 16)
        for (entry,) in connection.execute("SELECT entry FROM functions")
    }
    language = connection.execute("SELECT language FROM programs").fetchone()[0]
    recovered = len(ours & set(truth))
    dispatches = connection.execute(
        "SELECT COUNT(DISTINCT src) FROM xrefs WHERE provenance = 'native-import:switch'"
    ).fetchone()[0]
    metrics = {
        "functions": len(ours),
        "symbols": len(truth),
        "symbol_recall": round(recovered / len(truth), 4) if truth else 0.0,
        "symbol_precision": round(recovered / len(ours), 4) if ours else 0.0,
        "stock_ratio": round(len(ours) / STOCK_FUNCTIONS, 4),
        "switch_dispatches": dispatches,
        "wall_seconds": round(wall, 1),
        "language": language,
    }
    report["metrics"] = metrics

    failures = []
    for key, threshold in THRESHOLDS.items():
        value = metrics[key]
        # Wall time is a ceiling; everything else is a floor.
        if key == "wall_seconds":
            if value > threshold:
                failures.append(f"{key} {value} > {threshold}")
        elif value < threshold:
            failures.append(f"{key} {value} < {threshold}")
    if language != "AARCH64:LE:64:v8A":
        failures.append(f"language {language} is not AARCH64:LE:64:v8A")

    report["status"] = "pass" if not failures else "fail"
    report["failures"] = failures
    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps(report, indent=2) + "\n")
    if failures:
        print(f"FAIL: {'; '.join(failures)}", file=sys.stderr)
        return 1
    print(
        f"m5-017: PASS ({metrics['functions']} functions in {metrics['wall_seconds']}s,"
        f" recall {metrics['symbol_recall']} over {metrics['symbols']} module symbols,"
        f" precision {metrics['symbol_precision']}, {metrics['stock_ratio']} of stock's"
        f" {STOCK_FUNCTIONS}, {metrics['switch_dispatches']} switch dispatches)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
