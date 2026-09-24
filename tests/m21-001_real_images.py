#!/usr/bin/env python3
"""m21-001: function recovery on real game images, scored against their truth.

The corpus gates (m3-001, m17-002, m8-*) score small compiler-built samples.
They passed while real images failed in ways they could not see: a Mach-O
loader counting data labels as functions, junk constant seeds cutting real
functions short, a Windows import splitting functions in two. This gate
imports real retail or stripped game images and scores the functions
RomWright finds against truth each image ships with:

* **symbols** -- the unstripped ELF of the same build (GBA, NDS and PS2
  decomp or debug builds): every defined `FUNC` symbol;
* **maps** -- a linker map (PSX `VS.MAP`: names inside the main `.text`;
  Xbox 360 MSVC map: publics flagged `f`).

Per image it records recall (truth entries found), precision (found
entries the truth names; the rest are invented), how many sizes match,
wall time and peak memory, and every diagnostic. An image whose analysis
is degraded fails, whatever it scores. Floors are the measured values with
a small margin: this gate catches regressions and shows the gap, it does
not certify a target.

The images are private, so a runner skips each one that is absent.
"""
from __future__ import annotations

import argparse
import json
import re
import resource
import shutil
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "target" / "release" / "romwright-cli"
CORPUS = Path.home() / "ventris-corpus" / "extracted"


def elf_functions(elf: Path) -> dict[int, tuple[int, str]]:
    out = subprocess.run(["llvm-readelf", "-sW", str(elf)], capture_output=True,
                         text=True, check=True).stdout
    truth: dict[int, tuple[int, str]] = {}
    for line in out.splitlines():
        parts = line.split()
        # `$a`/`$t`/`$d`/`$b` are AAELF mapping symbols and local labels,
        # typed FUNC by the pokeheartgold toolchain; they name no function.
        if (len(parts) >= 8 and parts[3] == "FUNC" and parts[6] != "UND"
                and not parts[7].startswith("$")):
            address = int(parts[1], 16) & ~1  # Thumb bit
            size = int(parts[2], 0)
            if address and (address not in truth or truth[address][0] < size):
                truth[address] = (size, parts[7])
    return truth


def psx_map_functions(path: Path) -> dict[int, tuple[int, str]]:
    """Names inside the main `.text` section of a Psy-Q map."""
    text = path.read_text(errors="replace")
    section = re.search(r"^\s*([0-9A-F]{8})\s+([0-9A-F]{8})\s+[0-9A-F]{8}\s+[0-9A-F]{8}\s+text\s+\.text\s*$",
                        text, re.M)
    lo, hi = int(section.group(1), 16), int(section.group(2), 16)
    truth = {}
    for address, name in re.findall(r"^\s*([0-9A-F]{8})\s+(\S+)\s*$", text, re.M):
        value = int(address, 16)
        if lo <= value <= hi:
            truth[value] = (0, name)
    return truth


def msvc_map_functions(path: Path) -> dict[int, tuple[int, str]]:
    """Publics an MSVC map flags as functions (`f` after Rva+Base)."""
    truth = {}
    for name, address in re.findall(r"^\s*[0-9a-f]{4}:[0-9a-f]{8}\s+(\S+)\s+([0-9a-f]{8})\s+f\s", 
                                    path.read_text(errors="replace"), re.M):
        truth[int(address, 16)] = (0, name)
    return truth


def binmap_functions(path: Path) -> dict[int, tuple[int, str]]:
    """Thumb records of an EA Vita EBOOT.BINMAP (layout: native/binmap.rs).

    A record is `{name[152], address, size}`; the low address bit marks
    Thumb code, as in ELF `st_value`. The even records all sit past the last
    Thumb function (import stubs, vtables, constants), so the odd ones are
    the image's functions."""
    data = path.read_bytes()
    truth = {}
    for index in range(int.from_bytes(data[:4], "little")):
        at = 16 + 160 * index
        name = data[at:at + 152].split(b"\0")[0].decode("latin-1")
        address, size = (int.from_bytes(data[at + 152 + i:at + 156 + i], "little") for i in (0, 4))
        if address & 1 and not name.startswith(("_NID_", "_INID_", "_MNID_")):
            truth[address & ~1] = (size, name)
    return truth


def strip(source: Path, work: Path) -> Path:
    out = work / f"{source.name}.stripped"
    subprocess.run(["llvm-strip", "--strip-all", "-o", str(out), str(source)], check=True)
    return out


# name, image (relative to the corpus), program, truth, ranges the truth is
# scored over (None: every executable region), floors.
IMAGES = [
    {"id": "gba-pokeemerald", "image": "gba-pokeemerald/pokeemerald.gba", "program": "gba",
     "truth": ("elf", "gba-pokeemerald/pokeemerald.elf"), "ranges": [(0x08000000, 0x0A000000)]},
    {"id": "nds-pokeheartgold-arm9", "image": "nds-pokeheartgold/pokeheartgold.us.nds",
     "program": "nds.arm9", "truth": ("elf", "nds-pokeheartgold/pokeheartgold.elf"),
     # The static arm9 image and ITCM; overlays share addresses above it.
     "ranges": [(0x01FF8000, 0x02000000), (0x02000000, 0x021E5900)]},
    {"id": "ps2-capcom-fighting-evolution", "image": "ps2-capcom-fighting-evolution/SLUS_209.50",
     "strip": True, "program": "capcom", "truth": ("elf", "ps2-capcom-fighting-evolution/SLUS_209.50"),
     "ranges": None},
    {"id": "ps2-dungeon-game", "image": "ps2-dungeon-game/dungeon_game.elf", "strip": True,
     "program": "dungeon", "truth": ("elf", "ps2-dungeon-game/dungeon_game.elf"), "ranges": None},
    {"id": "psx-darkstalkers-3", "image": "psx-darkstalkers-3/VS.EXE", "program": "psx",
     # The map names `.text` only; `.rdata` shares the executable segment.
     "truth": ("psx-map", "psx-darkstalkers-3/VS.MAP"), "ranges": [(0x801395F0, 0x8018ED2C)]},
    {"id": "psv-need-for-speed-most-wanted", "image": "psv-need-for-speed-most-wanted/eboot.elf",
     "program": "vita", "truth": ("binmap", "psv-need-for-speed-most-wanted/EBOOT.BINMAP"),
     # The one executable segment also holds rodata; code ends where the
     # map's first stub or data record begins.
     "ranges": [(0x81000000, 0x8167A1BC)]},
    {"id": "x360-black-ops-2", "image": "x360-call-of-duty-black-ops-2/default_mp_script.exe",
     "program": "x360.xex", "truth": ("msvc-map", "x360-call-of-duty-black-ops-2/default_mp_script.map"),
     "ranges": None},
]

# Images whose import is known not to finish within its limit. Reported,
# not failed; one that finishes fails as stale so the record tracks the
# defect.
EXPECTED_TIMEOUT: set[str] = set()
DEFAULT_LIMIT_S = 1800

# Degraded analyses known today, by the text of the diagnostic. As above:
# reported, and stale once they no longer occur.
EXPECTED_DEGRADED: dict[str, str] = {}

# Measured 2026-09-23 (recall, precision), with a 0.01 margin. Raise them as
# recovery improves; a drop below is a regression.
FLOORS: dict[str, tuple[float, float]] = {
    "gba-pokeemerald": (0.859, 0.830),          # 0.869 / 0.840, 522 s idle (smt-cloud), 2.0 GB
    "nds-pokeheartgold-arm9": (0.894, 0.987),   # 0.905 / 0.997, 504 s
    "ps2-capcom-fighting-evolution": (0.887, 0.874),  # 0.897 / 0.884
    "ps2-dungeon-game": (0.780, 0.814),         # 0.791 / 0.824
    # 0.919 / 0.376. The map lists globals only: of the 1,246 "invented"
    # entries, 534 are jal targets and 678 open a stack frame; 34 have
    # neither. Precision here is a floor on accuracy, not a measure of it.
    "psv-need-for-speed-most-wanted": (0.794, 0.938),  # 0.804 / 0.948, 522 s
    "psx-darkstalkers-3": (0.909, 0.366),
    "x360-black-ops-2": (0.929, 0.985),         # 0.940 / 0.995, 153 s
}


def score(project: Path, program: str, truth: dict[int, tuple[int, str]],
          ranges: list[tuple[int, int]] | None) -> dict:
    db = sqlite3.connect(f"file:{project}/project.sqlite?mode=ro", uri=True)
    pid = db.execute("SELECT id FROM programs WHERE name = ?", (program,)).fetchone()[0]
    if ranges is None:
        ranges = [(int(start, 16), int(start, 16) + size) for start, size, permissions in
                  db.execute("SELECT start, size, permissions FROM memory_regions WHERE program_id = ?",
                             (pid,)) if "x" in permissions]
    inside = lambda address: any(lo <= address < hi for lo, hi in ranges)
    found: dict[int, int] = {}
    for entry, size in db.execute("SELECT entry, size FROM functions WHERE program_id = ?", (pid,)):
        try:
            found[int(entry, 16)] = size
        except ValueError:
            continue
    scored = {address: value for address, value in truth.items() if inside(address)}
    hits = [address for address in scored if address in found]
    invented = [address for address in found if address not in scored and inside(address)]
    sized = [address for address in hits if scored[address][0]]
    return {
        "truth": len(scored),
        "found": sum(1 for address in found if inside(address)),
        "recall": round(len(hits) / max(len(scored), 1), 4),
        "precision": round(len(hits) / max(len(hits) + len(invented), 1), 4),
        "invented": len(invented),
        "sizes_compared": len(sized),
        "size_exact": sum(1 for a in sized if found[a] == scored[a][0]),
        "size_short": sum(1 for a in sized if found[a] < scored[a][0]),
        "size_long": sum(1 for a in sized if found[a] > scored[a][0]),
        "missed_sample": [f"{a:#x} {scored[a][1]}" for a in sorted(set(scored) - set(found))[:10]],
        "invented_sample": [f"{a:#x}" for a in sorted(invented)[:10]],
    }


def run_image(spec: dict, corpus: Path, work: Path) -> dict:
    image = corpus / spec["image"]
    kind, truth_path = spec["truth"]
    truth_file = corpus / truth_path
    if not image.is_file() or not truth_file.is_file():
        return {"status": "skipped", "reason": "image or truth absent"}
    if spec.get("strip"):
        image = strip(image, work)
    project = work / spec["id"]
    shutil.rmtree(project, ignore_errors=True)
    project.mkdir(parents=True)
    started = time.monotonic()
    before = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    limit = spec.get("limit_s", DEFAULT_LIMIT_S)
    try:
        result = subprocess.run(
            [str(CLI), "import", str(image), "--name", spec["program"].split(".")[0],
             "--project", str(project), "--timings"],
            capture_output=True, text=True, timeout=limit,
            env={**__import__("os").environ, "ROMWRIGHT_NO_IMPORT_CACHE": "1"})
    except subprocess.TimeoutExpired:
        shutil.rmtree(project, ignore_errors=True)
        if spec["id"] in EXPECTED_TIMEOUT:
            return {"status": "known-timeout", "reason": f"import over {limit}s (known)"}
        return {"status": "fail", "reason": f"import over {limit}s"}
    seconds = time.monotonic() - started
    if spec["id"] in EXPECTED_TIMEOUT:
        shutil.rmtree(project, ignore_errors=True)
        return {"status": "fail", "reason": f"expected timeout no longer occurs ({seconds:.0f}s)"
                " -- remove it from EXPECTED_TIMEOUT and set its floors"}
    peak_kb = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    if result.returncode:
        return {"status": "fail", "reason": f"import failed: {result.stderr.strip()[-400:]}",
                "seconds": round(seconds, 1)}
    diagnostics = []
    for line in result.stdout.splitlines():
        if line.startswith("TIMINGS "):
            diagnostics = json.loads(line[len("TIMINGS "):]).get("diagnostics", [])
    truth = {"elf": elf_functions, "psx-map": psx_map_functions,
             "msvc-map": msvc_map_functions, "binmap": binmap_functions}[kind](truth_file)
    row = score(project, spec["program"], truth, spec["ranges"])
    row.update(seconds=round(seconds, 1),
               peak_rss_mb=round(max(peak_kb, before) / 1024) if peak_kb > before else None,
               diagnostics=diagnostics)
    failures = []
    degraded = [d["message"] for d in diagnostics if d.get("severity") == "degraded"]
    expected = EXPECTED_DEGRADED.get(spec["id"])
    if expected:
        if not any(expected in message for message in degraded):
            failures.append(f"expected degradation '{expected}' no longer occurs"
                            " -- remove it from EXPECTED_DEGRADED")
        degraded = [message for message in degraded if expected not in message]
    if degraded:
        failures.append("analysis degraded: " + "; ".join(degraded)[:300])
    floor = FLOORS.get(spec["id"])
    if floor:
        if row["recall"] < floor[0]:
            failures.append(f"recall {row['recall']} < {floor[0]}")
        if row["precision"] < floor[1]:
            failures.append(f"precision {row['precision']} < {floor[1]}")
    row["status"] = "fail" if failures else "pass"
    row["failures"] = failures
    shutil.rmtree(project, ignore_errors=True)
    return row


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=CORPUS)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--only", nargs="*", help="image ids to run")
    arguments = parser.parse_args()
    arguments.work.mkdir(parents=True, exist_ok=True)
    subprocess.run(["cargo", "build", "-q", "--release", "-p", "romwright-cli",
                    "-p", "romwright-worker"], cwd=ROOT, check=True)
    rows = {}
    for spec in IMAGES:
        if arguments.only and spec["id"] not in arguments.only:
            continue
        rows[spec["id"]] = run_image(spec, arguments.corpus, arguments.work)
        row = rows[spec["id"]]
        print(f"{spec['id']}: {row['status']} "
              + (f"recall {row['recall']} precision {row['precision']} in {row['seconds']}s"
                 if "recall" in row else row.get("reason", "")), flush=True)
    failures = [f"{name}: {'; '.join(row.get('failures') or [row.get('reason', '')])}"
                for name, row in rows.items() if row["status"] == "fail"]
    report = {"id": "m21-001", "recorded_at": datetime.now(timezone.utc).isoformat(),
              "floors": FLOORS, "rows": rows, "status": "fail" if failures else "pass",
              "failures": failures}
    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps(report, indent=2) + "\n")
    if failures:
        print("FAIL: " + "; ".join(failures), file=sys.stderr)
        return 1
    scored = [row for row in rows.values() if row["status"] == "pass"]
    skipped = sum(1 for row in rows.values() if row["status"] == "skipped")
    known = sum(1 for row in rows.values() if row["status"] == "known-timeout")
    print(f"m21-001: PASS ({len(scored)} images scored, {known} known timeouts, {skipped} skipped)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
