#!/usr/bin/env python3
"""m8-003: a function body may not swallow the next function.

`m8-002` found `FUN_00401c80` claiming `00401c80..00408796` in
`tiny_pe32.exe` -- 27 KB across dozens of functions -- because a proven body
is the maximum end over every instruction attributed to an origin, and one
fallthrough chain across inter-function padding stretches it over everything
that follows. That number is what the store reports as `size`, what
`function_extents` resolves a containing function with, and what a listing
renders.

Truth is the compiler's own range: `DW_AT_low_pc` to `DW_AT_high_pc` of each
concrete subprogram, read from the unstripped twin. Per image the gate
requires:

  * `body.crossing == 0` -- no recovered body strictly contains another
    recovered entry. Two functions cannot overlap, so a body that spans one is
    wrong regardless of what truth says;
  * every matched body to end inside its truth range, or to overshoot it by
    less than one alignment slot (16 bytes) into bytes no other entry owns.
    A larger overshoot is unexplained and fails.

Usage:
    python3 tests/m8-003_body_extents.py --corpus-dir DIR [--report OUT.json]
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from gen_corpus import get_load_segments, parse_pe_info  # noqa: E402

ALIGNMENT = 16
TAG = re.compile(r"DW_TAG_\w+")
LOW_PC = re.compile(r"DW_AT_low_pc\s*\((0x[0-9a-f]+)\)")
HIGH_PC = re.compile(r"DW_AT_high_pc\s*\((0x[0-9a-f]+)\)")


def load_m8_001():
    spec = importlib.util.spec_from_file_location(
        "m8_001", ROOT / "tests/m8-001_pe_unwind.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["m8_001"] = module
    spec.loader.exec_module(module)
    return module


def dwarf_ranges(binary: Path) -> dict[int, int]:
    """low_pc -> high_pc for every concrete subprogram, as llvm prints them."""
    text = subprocess.run(["llvm-dwarfdump", "--debug-info", str(binary)],
                          capture_output=True, text=True, errors="replace",
                          check=True).stdout
    ranges: dict[int, int] = {}
    tag = low = high = None
    for line in text.splitlines():
        if "DW_TAG_" in line:
            if tag == "DW_TAG_subprogram" and low is not None and high is not None:
                ranges[low] = high
            match = TAG.search(line)
            tag, low, high = (match.group(0) if match else None), None, None
        elif "DW_AT_low_pc" in line:
            match = LOW_PC.search(line)
            low = int(match.group(1), 16) if match else low
        elif "DW_AT_high_pc" in line:
            match = HIGH_PC.search(line)
            high = int(match.group(1), 16) if match else high
    if tag == "DW_TAG_subprogram" and low is not None and high is not None:
        ranges[low] = high
    return {low: high for low, high in ranges.items() if high > low}


def executable_ranges(binary: Path) -> list[tuple[int, int]]:
    data = binary.read_bytes()
    if data[:4] == b"\x7fELF":
        return [(address, size)
                for address, size, flags, _, _ in get_load_segments(data)
                if flags & 1]
    base = image_base(data)
    return [(base + section["vaddr"], section["vsize"])
            for section in parse_pe_info(data)["sections"] if section["exec"]]


def image_base(data: bytes) -> int:
    header = struct.unpack_from("<I", data, 0x3C)[0]
    optional = header + 24
    magic = struct.unpack_from("<H", data, optional)[0]
    if magic == 0x20B:
        return struct.unpack_from("<Q", data, optional + 24)[0]
    return struct.unpack_from("<I", data, optional + 28)[0]


def is_shared_object(binary: Path, big_endian: bool) -> bool:
    header = binary.read_bytes()[16:18]
    return int.from_bytes(header, "big" if big_endian else "little") == 3


def store_bodies(binary: Path, work: Path) -> tuple[dict[int, int], int]:
    """entry -> size from a fresh import, with the store's image base."""
    project = work / f"{binary.stem}-extents"
    result = subprocess.run(
        [str(ROOT / "target/release/lre-cli"), "import", str(binary),
         "--name", "extents", "--project", str(project)],
        cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 0, f"native import failed: {result.stderr.strip()}"
    store = sqlite3.connect(project / "project.sqlite")
    bodies = {int(entry, 16): size
              for entry, size in store.execute("SELECT entry, size FROM functions")}
    base = min(int(row[0], 16)
               for row in store.execute("SELECT start FROM memory_regions"))
    return bodies, base


def score(image: Path, twin: Path, identifier: str, work: Path,
          big_endian: bool) -> dict:
    bodies, base = store_bodies(image, work)
    bias = base if twin.read_bytes()[:4] == b"\x7fELF" and is_shared_object(
        twin, big_endian) else 0
    executable = executable_ranges(twin)
    truth = {low + bias: high + bias
             for low, high in dwarf_ranges(twin).items()
             if any(start <= low < start + size for start, size in executable)}

    entries = sorted(bodies)
    crossing = []
    for entry in entries:
        end = entry + bodies[entry]
        inside = [other for other in entries if entry < other < end]
        if inside:
            crossing.append({"entry": f"{entry:08x}", "size": bodies[entry],
                             "swallows": len(inside),
                             "first": f"{inside[0]:08x}"})

    padding, unexplained = [], []
    for entry, high in sorted(truth.items()):
        if entry not in bodies:
            continue
        end = entry + bodies[entry]
        if end <= high:
            continue
        overshoot = end - high
        row = {"entry": f"{entry:08x}", "truth_end": f"{high:08x}",
               "body_end": f"{end:08x}", "overshoot": overshoot}
        (padding if overshoot < ALIGNMENT else unexplained).append(row)

    matched = [entry for entry in truth if entry in bodies]
    exact = sum(1 for entry in matched if entry + bodies[entry] == truth[entry])
    return {
        "id": identifier,
        "functions": len(bodies),
        "truth_ranges": len(truth),
        "matched": len(matched),
        "metrics": {
            "body.crossing": len(crossing),
            "body.exact": exact / len(matched) if matched else 0.0,
            "body.padding_overshoot": len(padding),
            "body.unexplained_overshoot": len(unexplained),
            "body.overshoot_bytes.max": max(
                (row["overshoot"] for row in padding + unexplained), default=0),
        },
        "crossing": crossing[:6],
        "unexplained": unexplained[:6],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-cli"],
                   cwd=ROOT, check=True)
    m8_001 = load_m8_001()
    manifest = json.loads((arguments.corpus_dir / "manifest.json").read_text())
    entries = [entry for entry in manifest["entries"]
               if entry.get("status") == "ok" and entry.get("unstripped_twin")]
    assert len(entries) >= 20, f"only {len(entries)} corpus entries are usable"

    rows = []
    with tempfile.TemporaryDirectory(prefix="m8-003-") as directory:
        work = Path(directory)
        for entry in entries:
            rows.append(score(
                arguments.corpus_dir / entry["binary"],
                arguments.corpus_dir / entry["unstripped_twin"],
                f"{entry['architecture']}_{entry['variant']}", work,
                entry["endian"] == "big"))
        # The defect was found in a PE, so the PE fixtures are gated too; the
        # scored copy is stripped here rather than committed.
        for name in ("tiny_pe.exe", "dispatch.exe", "tiny_pe32.exe"):
            fixture = ROOT / "tests/fixtures-src" / name
            stripped = work / name
            shutil.copy2(fixture, stripped)
            subprocess.run(["llvm-strip", "--strip-all", str(stripped)], check=True)
            rows.append(score(stripped, fixture, name, work, False))
    del m8_001

    crossing = {row["id"]: row["crossing"] for row in rows
                if row["metrics"]["body.crossing"]}
    assert not crossing, (
        "recovered bodies swallow other entries: "
        + "; ".join(f"{identifier}: {rows_[0]['entry']} size {rows_[0]['size']} "
                    f"swallows {rows_[0]['swallows']}"
                    for identifier, rows_ in list(crossing.items())[:4]))
    unexplained = {row["id"]: row["unexplained"] for row in rows
                   if row["metrics"]["body.unexplained_overshoot"]}
    assert not unexplained, (
        "bodies run past their truth range by more than one alignment slot: "
        + "; ".join(f"{identifier}: {rows_[0]['entry']} to {rows_[0]['body_end']} "
                    f"(+{rows_[0]['overshoot']})"
                    for identifier, rows_ in list(unexplained.items())[:4]))

    totals = {
        "body.crossing": sum(row["metrics"]["body.crossing"] for row in rows),
        "body.matched": sum(row["matched"] for row in rows),
        "body.exact": (sum(row["metrics"]["body.exact"] * row["matched"] for row in rows)
                       / max(sum(row["matched"] for row in rows), 1)),
        "body.padding_overshoot": sum(row["metrics"]["body.padding_overshoot"]
                                      for row in rows),
        "body.overshoot_bytes.max": max(row["metrics"]["body.overshoot_bytes.max"]
                                        for row in rows),
    }
    summary = (f"{len(rows)} images, {totals['body.matched']} bodies matched to a "
               f"DWARF range: 0 crossing another entry, "
               f"{totals['body.exact']:.4f} ending exactly where the compiler "
               f"says, {totals['body.padding_overshoot']} ending inside one "
               f"alignment slot past it (worst "
               f"{totals['body.overshoot_bytes.max']} bytes)")

    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps({
            "id": "m8-003",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "status": "pass",
            "passed": True,
            "summary": summary,
            "thresholds": {"body.crossing": 0, "body.unexplained_overshoot": 0,
                           "alignment_bytes": ALIGNMENT},
            "totals": totals,
            "images": rows,
        }, indent=1) + "\n")
    print(f"m8-003: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
