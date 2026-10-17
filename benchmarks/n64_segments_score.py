#!/usr/bin/env python3
"""P3.3: Perfect Dark NTSC-final imported through its real segments, scored
against the public decomp's truth and against stock Ghidra.

Inputs (all on the host, none committed):

* the retail ROM (`~/romwright-corpus/perfect_dark_ntsc_final.z64`);
* the truth JSON from `benchmarks/pd_ido_truth.py truth` (names and
  addresses derived from n64decomp/perfect_dark, MIT; see that file for how
  an address is derived and checked);
* an import of the ROM (`romwright-cli import ROM --name pd --project P`);
* optionally stock Ghidra's `ExportFunctionEntries` JSON for the same ROM
  (N64LoaderWV) and for the decompressed game segment handed to it as a raw
  binary, and our own import of that raw segment.

It reports, over the game text `[0x7f000000, 0x7f1a78c0)` (the only segment
the truth covers):

* recall against the named truth functions, and precision twice: the m21
  definition (a found entry the truth names is right) and the corroborated
  one (also right: an entry the segment's own bytes prove, a `jal` target or
  a function the chain walk of `pd_ido_truth.walk_chain` starts -- the 490
  functions the source-order mapping could not name);
* the spot check: ten truth functions whose bytes, read through
  `romwright-cli mem` (the loader's own mapping), equal the same range of the
  segment inflated here with Python's zlib, and the SHA-256 of every
  unpacked segment against the same independent inflate;
* module rows (`modules`), so cross-segment references are accounted for.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sqlite3
import subprocess
import sys
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = 0x7F000000
TEXT_END = 0x7F1A78C0


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


M21 = load("m21_real_images", ROOT / "tests" / "m21-001_real_images.py")
PD = load("pd_ido_truth", ROOT / "benchmarks" / "pd_ido_truth.py")


def rare(rom: bytes, at: int) -> bytes:
    assert int.from_bytes(rom[at:at + 2], "big") == 0x1173
    return zlib.decompressobj(wbits=-15).decompress(rom[at + 5:])


def segments(rom: bytes) -> dict[str, tuple[int, bytes]]:
    """The layout's segments inflated with zlib alone (an independent decoder)."""
    lib = rom[0x1050:0x3050] + rare(rom, 0x3050)
    return {
        "preamble": (0x80001000, rom[0x1000:0x1050]),
        "lib-boot": (0x80001050, rom[0x1050:0x3050]),  # the raw head, run before the TLB maps the lib
        "lib": (0x70001050, lib),
        "data": (0x70001050 + len(lib) + 0x10000000, rare(rom, 0x39850)),
        "inflate": (0x70200000, rom[0x4E850:0x4FC40]),
        "game": (BASE, PD.extract_game(rom)),
    }


def mem(cli: Path, rom: Path, address: int, size: int) -> bytes:
    out = subprocess.run([str(cli), "mem", str(rom), f"{address:x}", str(size)],
                         capture_output=True, text=True, check=True).stdout
    return bytes.fromhex(out.replace(" ", "").strip())


def entries_of(path: Path) -> dict[int, int]:
    return {row["entry"]: row["size"] for row in json.loads(path.read_text())["functions"]}


def score_entries(found: dict[int, int], truth: dict[int, tuple[int, str]], corroborated: set[int]) -> dict:
    inside = lambda a: BASE <= a < TEXT_END
    scored = {a: v for a, v in truth.items() if inside(a)}
    mine = {a: s for a, s in found.items() if inside(a)}
    hits = [a for a in scored if a in mine]
    invented = [a for a in mine if a not in scored]
    proven = [a for a in invented if a in corroborated]
    sized = [a for a in hits if scored[a][0]]
    return {
        "truth": len(scored), "found_in_game_text": len(mine), "found_total": len(found),
        "recall": round(len(hits) / len(scored), 4),
        "precision": round(len(hits) / max(len(mine), 1), 4),
        "precision_corroborated": round((len(hits) + len(proven)) / max(len(mine), 1), 4),
        "invented": len(invented), "invented_corroborated": len(proven),
        "size_exact": sum(1 for a in sized if mine[a] == scored[a][0]),
        "sizes_compared": len(sized),
        "missed_sample": [f"{a:#x} {scored[a][1]}" for a in sorted(set(scored) - set(mine))[:8]],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rom", type=Path, required=True)
    parser.add_argument("--truth", type=Path, required=True)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--project", type=Path, required=True, help="import of --rom, program `pd`")
    parser.add_argument("--raw-project", type=Path, help="import of the raw game segment, program `pdraw`")
    parser.add_argument("--stock-rom", type=Path)
    parser.add_argument("--stock-raw", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    rom = args.rom.read_bytes()
    rows = json.loads(args.truth.read_text())["functions"]
    truth = {r["address"]: (r["end"] - r["address"], r["name"]) for r in rows}
    game = segments(rom)["game"][1]
    image = PD.Image(game, BASE)
    bounds = PD.jal_targets(image, BASE, TEXT_END + 0x40, 0x70000000)
    corroborated = set(bounds) | {e["address"] for e in PD.walk_chain(image, BASE, TEXT_END, bounds)}

    report: dict = {"rom": args.rom.name, "truth_named": len(truth), "corroborating_entries": len(corroborated)}

    def ours(project: Path, program: str) -> dict:
        db = sqlite3.connect(f"file:{project}/project.sqlite?mode=ro", uri=True)
        pid = db.execute("SELECT id FROM programs WHERE name = ?", (program,)).fetchone()[0]
        found = {int(e, 16): s for e, s in db.execute("SELECT entry, size FROM functions WHERE program_id = ?", (pid,))}
        row = score_entries(found, truth, corroborated)
        row["m21_score"] = M21.score(project, program, truth, [(BASE, TEXT_END)])
        return row, db, pid

    row, db, pid = ours(args.project, "pd")
    report["ours_rom"] = row
    report["modules"] = [list(m) for m in db.execute(
        "SELECT name, kind, load_vaddr, size FROM modules WHERE program_id = ? ORDER BY load_vaddr", (pid,))]
    report["regions"] = [list(r) for r in db.execute(
        "SELECT name, start, size, permissions FROM memory_regions WHERE program_id = ? ORDER BY start", (pid,))]
    by_segment: dict[str, int] = {}
    for entry, in db.execute("SELECT entry FROM functions WHERE program_id = ?", (pid,)):
        address = int(entry, 16)
        for name, (start, data) in segments(rom).items():
            if start <= address < start + len(data):
                by_segment[name] = by_segment.get(name, 0) + 1
                break
        else:
            by_segment["(outside every segment)"] = by_segment.get("(outside every segment)", 0) + 1
    report["functions_by_segment"] = by_segment
    if args.raw_project:
        report["ours_raw_game_segment"] = ours(args.raw_project, "pdraw")[0]
    if args.stock_rom:
        report["stock_rom_n64loaderwv"] = score_entries(entries_of(args.stock_rom), truth, corroborated)
    if args.stock_raw:
        report["stock_raw_game_segment"] = score_entries(entries_of(args.stock_raw), truth, corroborated)

    # Spot check: ten truth functions spread over the segment, bytes read
    # through the loader against the independent inflate.
    ordered = sorted(truth)
    picks = [ordered[i * (len(ordered) - 1) // 9] for i in range(10)]
    spot = []
    for address in picks:
        size = min(truth[address][0], 64)
        expected = game[address - BASE:address - BASE + size]
        got = mem(args.cli, args.rom, address, size)
        spot.append({"address": f"{address:#x}", "name": truth[address][1], "bytes": size, "equal": got == expected})
    report["spot_check"] = spot
    segment_hashes = {}
    for name, (start, data) in segments(rom).items():
        got = mem(args.cli, args.rom, start, len(data))
        segment_hashes[name] = {"vaddr": f"{start:#x}", "size": len(data),
                                "sha256": hashlib.sha256(data).hexdigest(), "loader_equal": got == data}
    report["segments"] = segment_hashes
    args.out.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k not in ("regions", "segments", "spot_check")}, indent=1)[:6000])
    ok = all(s["equal"] for s in spot) and all(v["loader_equal"] for v in segment_hashes.values())
    print("spot check:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
