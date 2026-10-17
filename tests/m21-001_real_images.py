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

A Psy-Q map lists globals only, so a PSX tool that finds the file-local
statics is charged for them in `precision`. For PSX the row therefore also
carries `precision_corroborated` (`psx_corroborated`): the same ratio, where
an invented entry counts when the image's own bytes show a function there
(a `jal` callee, a function-pointer-table entry, an address-taken frame
opener). It is reported beside `precision`, never in its place, and has its
own floor (PSX_CORROBORATED_FLOORS).

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
CORPUS = Path.home() / "romwright-corpus" / "extracted"


ET_SCE_PSPRELEXEC = 0xFFA0


def section_relative_bases(elf: Path) -> dict[int, tuple[str, int]] | None:
    """Section index -> (name, `sh_addr`) for an ELF whose symbol values are section-relative.

    A PSP image (`e_type` 0xffa0) linked at base 0 keeps the object-file
    convention in `.symtab` and in unrelocated DWARF `DW_AT_low_pc`: a value is
    an offset into its section, whose own `sh_addr` (0x40 for Puzzle Bobble
    Pocket's `.text`, which follows the 0x24-byte `.init` at 64-byte
    alignment) is not in it. The loaded address is `sh_addr + value`; code
    bytes and `jal` targets are already final (verified on that image: every
    `jal` target minus 0x40 is a `.symtab` value). None for any other ELF."""
    data = elf.read_bytes()
    if (len(data) < 52 or data[:4] != b"\x7fELF" or data[4] != 1 or data[5] != 1
            or int.from_bytes(data[16:18], "little") != ET_SCE_PSPRELEXEC):
        return None
    shoff = int.from_bytes(data[32:36], "little")
    count = int.from_bytes(data[48:50], "little")
    def field(index: int, at: int) -> int:
        return int.from_bytes(data[shoff + 40 * index + at:shoff + 40 * index + at + 4], "little")

    strings = field(int.from_bytes(data[50:52], "little"), 16)
    return {index: (data[strings + field(index, 0):].split(b"\0", 1)[0].decode("latin-1"), field(index, 12))
            for index in range(count)}


def elf_functions(elf: Path) -> dict[int, tuple[int, str]]:
    out = subprocess.run(["llvm-readelf", "-sW", str(elf)], capture_output=True,
                         text=True, check=True).stdout
    bases = section_relative_bases(elf)
    truth: dict[int, tuple[int, str]] = {}
    for line in out.splitlines():
        parts = line.split()
        # `$a`/`$t`/`$d`/`$b` are AAELF mapping symbols and local labels,
        # typed FUNC by the pokeheartgold toolchain; they name no function.
        if (len(parts) >= 8 and parts[3] == "FUNC" and parts[6] != "UND"
                and not parts[7].startswith("$")):
            address = int(parts[1], 16) & ~1  # Thumb bit
            if bases is not None and parts[6].isdigit():
                address += bases[int(parts[6])][1]
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


def psx_corroborated(exe: Path, ranges: list[tuple[int, int]]) -> dict[int, str]:
    """Addresses in `ranges` the PS-X EXE's own bytes corroborate as function entries.

    Supplementary to `score()`'s precision, which counts only what the map
    names. A Psy-Q map lists globals; the `static` functions of the same
    translation units (state handlers in function-pointer tables, file-local
    helpers) are absent, so the map-only precision charges every tool for
    finding them. This answers "is that entry a real function?" from the
    image alone, whatever tool proposed it. An address qualifies when

      * it is word-aligned and the code before it ends in a return (`jr $ra`
        in one of the two preceding non-zero words): it starts after a
        function, not mid-body; and
      * no branch or `j` in the ranges targets it (the map's own entries
        are never branch targets either); and
      * one of
          jal    a `jal` in the ranges calls it (a callee is a function);
          table  a data word outside the ranges points at it, in a run of two
                 or more consecutive words that all point at addresses
                 meeting the first two rules: a function-pointer table (case
                 labels of a jump table rarely follow a return);
          frame+address-taken
                 its first six instructions open a stack frame
                 (`addiu $sp, $sp, -N`) and its address is formed by
                 `lui` + `addiu`/`ori`, or sits in a lone data word.

    It is a floor on real functions, not a proof: a leaf function that is
    only reached through a lone pointer qualifies by none of the three.
    Returns {address: evidence} over every qualifying address, so an
    entry no tool proposed is listed too."""
    data = exe.read_bytes()
    base = int.from_bytes(data[0x18:0x1C], "little")
    size = int.from_bytes(data[0x1C:0x20], "little")
    count = min(size, len(data) - 0x800) // 4
    words = [int.from_bytes(data[0x800 + 4 * i:0x804 + 4 * i], "little") for i in range(count)]
    word = lambda address: (words[(address - base) >> 2]
                            if base <= address < base + 4 * count and not address & 3 else None)
    in_ranges = lambda address: any(lo <= address < hi for lo, hi in ranges)
    signed = lambda value: value - 0x10000 if value & 0x8000 else value
    jal, branched, formed, pointed = set(), set(), set(), {}
    for index, w in enumerate(words):
        address = base + 4 * index
        op = w >> 26
        if not in_ranges(address):
            if in_ranges(w) and not w & 3:
                pointed[address] = w
            continue
        if op == 3:
            jal.add((address & 0xF0000000) | ((w & 0x3FFFFFF) << 2))
        elif op == 2:
            branched.add((address & 0xF0000000) | ((w & 0x3FFFFFF) << 2))
        elif op in (1, 4, 5, 6, 7):
            branched.add(address + 4 + 4 * signed(w & 0xFFFF))
        elif op == 0xF:  # lui rt; a nearby addiu/ori on rt completes the address
            for ahead in range(1, 5):
                follower = word(address + 4 * ahead)
                if follower is not None and follower >> 26 in (9, 13) \
                        and (follower >> 21) & 31 == (w >> 16) & 31:
                    low = signed(follower & 0xFFFF) if follower >> 26 == 9 else follower & 0xFFFF
                    formed.add(((w & 0xFFFF) << 16) + low & 0xFFFFFFFF)
                    break

    def starts_function(address: int) -> bool:
        if not in_ranges(address) or address & 3 or address in branched:
            return False
        previous = address - 4
        while word(previous) == 0 and in_ranges(previous):
            previous -= 4
        return 0x03E00008 in (word(previous), word(previous - 4))

    def opens_frame(address: int) -> bool:
        opcodes = [word(address + 4 * i) or 0 for i in range(6)]
        return any(w >> 16 == 0x27BD and w & 0xFFFF >= 0x8000 for w in opcodes)

    tabled = {target for slot, target in pointed.items() if starts_function(target)
              and any(neighbour in pointed and starts_function(pointed[neighbour])
                      for neighbour in (slot - 4, slot + 4))}
    taken = set(pointed.values()) | formed
    out: dict[int, str] = {}
    for lo, hi in ranges:
        for address in range(lo, hi, 4):
            if not starts_function(address):
                continue
            if address in jal:
                out[address] = "jal"
            elif address in tabled:
                out[address] = "table"
            elif address in taken and opens_frame(address):
                out[address] = "frame+address-taken"
    return out


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


TSV_HEADER = ["start", "size", "name", "module", "verified"]


def tsv_rows(path: Path) -> list[dict]:
    """Rows of a truth contract `functions.tsv` (benchmarks/console_research.py,
    docs/console-research.md "Truth contract"): `start` hex in the executable's
    load address space, `size` decimal (0 unknown), `name`, `module` (`main` or
    an overlay/REL name) and `verified` (1: the function lies in a unit the
    decomp matched/linked, so its boundary is compiler truth). The header line
    must be exactly `start\tsize\tname\tmodule\tverified`."""
    lines = path.read_text(errors="replace").splitlines()
    if not lines or lines[0].split("\t") != TSV_HEADER:
        raise ValueError(f"{path}: header is not {'<TAB>'.join(TSV_HEADER)}")
    rows = []
    for number, line in enumerate(lines[1:], 2):
        if not line.strip():
            continue
        fields = line.split("\t")
        if len(fields) != len(TSV_HEADER):
            raise ValueError(f"{path}:{number}: {len(fields)} fields, expected {len(TSV_HEADER)}")
        start, size, name, module, verified = fields
        if verified not in ("0", "1"):
            raise ValueError(f"{path}:{number}: verified must be 0 or 1, got {verified!r}")
        rows.append({"start": int(start, 16), "size": int(size), "name": name, "module": module,
                     "verified": int(verified)})
    return rows


def tsv_functions(path: Path) -> dict[int, tuple[int, str]]:
    """Every row of a `functions.tsv` as `{address: (size, name)}`, the loader
    shape of the other truth kinds. Modules that share an address (NDS/N64
    overlays) collapse onto the larger size here; console_research scores a
    TSV truth per module and does not use this flattening."""
    truth: dict[int, tuple[int, str]] = {}
    for row in tsv_rows(path):
        address = row["start"]
        if address not in truth or truth[address][0] < row["size"]:
            truth[address] = (row["size"], row["name"])
    return truth


# Truth kinds an image spec can name: `spec["truth"] = (kind, path)`.
LOADERS = {"elf": elf_functions, "psx-map": psx_map_functions, "msvc-map": msvc_map_functions,
           "binmap": binmap_functions, "tsv": tsv_functions}


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

# Measured 2026-09-24 (recall, precision), with a 0.01 margin. Raise them as
# recovery improves; a drop below is a regression.
FLOORS: dict[str, tuple[float, float]] = {
    # 0.9737 / 0.9904 since 2026-10-07 (junk entries refused: repeated-byte
    # runs, calls into fill, undecodable Thumb-1 entries, interior entries);
    # 0.9736 / 0.9689 before, 558 s idle (smt-cloud), 1.6 GB.
    # 0.9737 / 0.9971 since 2026-10-08 (odd-word table seeds need a loaded
    # literal pool, frame-releasing `bl` labels refused); 0.9737 / 0.9910 on
    # the same tree without those rules.
    "gba-pokeemerald": (0.963, 0.987),
    "nds-pokeheartgold-arm9": (0.962, 0.988),   # 0.9729 / 0.9984 (0.9981 before 2026-10-08)
    # 0.9762 / 0.9924 since 2026-10-10 (stripped MIPS executables: alignment fill
    # is no start, the boundary sweep and the data words that name code seed
    # entries, a frame opener after a `nop` starts a function); 0.9418 / 0.9964 before.
    "ps2-capcom-fighting-evolution": (0.966, 0.986),
    # 0.9885 / 0.9785 since 2026-10-10 (same); 0.9438 / 0.9880 before.
    "ps2-dungeon-game": (0.978, 0.978),
    # 0.9878 / 0.3663. The map lists globals only (the file-local `static`
    # functions are absent): of the 1,398 "invented" entries, 545 are jal
    # targets, 803 sit in function-pointer tables and 43 open a stack frame
    # at an address the code takes; 7 have no corroboration. Precision here
    # is a floor on accuracy, not a measure of it; PSX_CORROBORATED_FLOORS
    # gates the supplementary precision that counts the corroborated ones.
    "psx-darkstalkers-3": (0.976, 0.356),
    # 0.9731 / 0.9713 since 2026-10-08 (an ARM pattern no longer walks a
    # vtable-named Thumb function as ARM); 0.9720 / 0.9712 before.
    "psv-need-for-speed-most-wanted": (0.963, 0.961),
    "x360-black-ops-2": (0.973, 0.986),         # 0.9833 / 0.9964 (0.9956 before)
}

# Supplementary precision (`psx_corroborated`), measured 0.9968 on 2026-10-08
# with a 0.01 margin. Stock Ghidra measures 1.0000 under the same rule.
PSX_CORROBORATED_FLOORS: dict[str, float] = {"psx-darkstalkers-3": 0.986}


def score(project: Path, program: str, truth: dict[int, tuple[int, str]],
          ranges: list[tuple[int, int]] | None, corroborated: dict[int, str] | None = None) -> dict:
    """Recall and precision against `truth`; with `corroborated` (PSX), also the supplementary
    `precision_corroborated`: precision where an entry counts when the truth names it or the
    image's bytes corroborate it (`psx_corroborated`). `precision` is unchanged."""
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
    row = {
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
    if corroborated is not None:
        evidence = [corroborated[a] for a in invented if a in corroborated]
        unproven = sorted(a for a in invented if a not in corroborated)
        row.update({
            "precision_corroborated": round((len(hits) + len(evidence)) / max(len(hits) + len(invented), 1), 4),
            "invented_corroborated": len(evidence),
            "invented_corroborated_by": {kind: evidence.count(kind) for kind in sorted(set(evidence))},
            "invented_uncorroborated": len(unproven),
            "uncorroborated_sample": [f"{a:#x}" for a in unproven[:10]],
            # Image-corroborated entries no tool proposed (truth entries excluded).
            "corroborated_unfound": sum(1 for a in corroborated
                                        if a not in found and a not in scored and inside(a)),
        })
    return row


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
            env={**__import__("os").environ, "ROMWRIGHT_NO_IMPORT_CACHE": "1", "ROMWRIGHT_NO_FACT_PACK": "1"})
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
    truth = LOADERS[kind](truth_file)
    corroborated = psx_corroborated(image, spec["ranges"]) if kind == "psx-map" else None
    row = score(project, spec["program"], truth, spec["ranges"], corroborated)
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
    corroborated_floor = PSX_CORROBORATED_FLOORS.get(spec["id"])
    if corroborated_floor and row["precision_corroborated"] < corroborated_floor:
        failures.append(f"precision_corroborated {row['precision_corroborated']} < {corroborated_floor}")
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
