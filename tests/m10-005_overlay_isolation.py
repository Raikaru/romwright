#!/usr/bin/env python3
"""m10-005: modules that share an address are separate namespaces (P3.12).

Pokemon HeartGold loads 129 overlays into a few RAM windows, so one address
is a different function in every overlay that covers it. A program's facts
are keyed by address, so overlays that overlap cannot share a program: each
is a program of its own (`<rom>.ov<N>`) beside the resident `arm9`, with one
`modules` row, and `locate` is the cross-program question. The gate checks the
consequences on the real cartridge:

  * **isolation**: for 5 addresses where two or more overlays each hold a
    function, `rename` through the API in overlay A changes A and nothing
    else: every other holder answers `function_at`, `functions`, incoming
    `xrefs` and its store revision exactly as before, and `undo` in A puts the
    name back;
  * **locate is module-aware**: it names every overlay mapping the address,
    with the module name and the id of that overlay's `modules` row (distinct
    per overlay), and the function each one holds there, before and after the
    rename; `romwright-cli locate --follow` prints the same per-program facts;
  * **follow resolves into the caller's overlay**: a call out of a caller in A
    lands, through A's own xrefs, on A's renamed function, and the callers
    recorded at that address are A's;
  * **modules carry real file offsets**, for NDS overlays, a GameCube disc
    and an N64 ROM: each row's `file_off` equals what the container's own
    tables say (FAT entry, FST entry / boot header, layout segment ROM
    range), and the container's bytes there look like what the row is (the
    overlay's own bytes, a `Yaz0` stream or the REL header, a Rare packed
    stream).

Images are not committed: an absent image skips that part, loudly.

Usage:
    python3 tests/m10-005_overlay_isolation.py [--images-dir DIR] [--project P]
        [--gc-disc FILE] [--n64-rom FILE] [--pairs 5] [--report OUT.json]

`--project` names an existing full-analysis import of the HeartGold cartridge
(it is copied, never written); without it the gate imports the ROM, which
takes minutes.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CLI = ROOT / "target/release/romwright-cli"
API = ROOT / "target/release/romwright-api"
CORPUS = next((p for p in (Path.home() / "ventris-corpus", Path.home() / "romwright-corpus")
               if p.is_dir()), Path.home() / "ventris-corpus")
NDS_DIR = CORPUS / "extracted/nds-pokeheartgold"
ROM = "pokeheartgold.us.nds"
GC_DIR = CORPUS / "extracted/gc-animal-crossing"
N64_ROM = CORPUS / "perfect_dark_ntsc_final.z64"
# The retail layout's segment ROM ranges (STATUS.md, N64 segments; re-measured
# there on this ROM): name -> (first ROM offset, codec magic of its stream).
PD_SEGMENTS = {"preamble": 0x1000, "lib-boot": 0x1050, "lib": 0x1050, "data": 0x39850,
               "inflate": 0x4E850, "game": 0x4FC40}


class Api:
    def __init__(self, project: Path) -> None:
        self.process = subprocess.Popen(
            [str(API), "--project", str(project)], cwd=ROOT, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
        self.identity = 0

    def call(self, method: str, **params):
        self.identity += 1
        self.process.stdin.write(json.dumps(
            {"api": 2, "id": self.identity, "method": method, "params": params}) + "\n")
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        assert line, f"the service closed on {method}"
        return json.loads(line)

    def result(self, method: str, **params):
        answer = self.call(method, **params)
        assert "result" in answer, f"{method} failed: {answer}"
        return answer["result"]

    def close(self) -> None:
        self.process.stdin.close()
        self.process.wait(timeout=60)


def run(command, timeout=7200):
    done = subprocess.run([str(c) for c in command], cwd=ROOT, capture_output=True,
                          text=True, timeout=timeout)
    assert done.returncode == 0, f"{command[:3]} failed: {done.stderr.strip()[-400:]}"
    return done


def u32(data: bytes, at: int, order: str = "little") -> int:
    return int.from_bytes(data[at:at + 4], order)


# ----- NDS ------------------------------------------------------------------

def nds_tables(rom: bytes):
    """Overlays from the cartridge's own OVT and FAT (gbatek), no loader code."""
    fat_off, ovt_off, ovt_size = u32(rom, 0x48), u32(rom, 0x50), u32(rom, 0x54)
    overlays = []
    for at in range(ovt_off, ovt_off + ovt_size, 32):
        words = [u32(rom, at + i) for i in range(0, 32, 4)]
        file_id = words[6]
        start, end = u32(rom, fat_off + file_id * 8), u32(rom, fat_off + file_id * 8 + 4)
        overlays.append({"id": words[0], "ram": words[1], "ram_size": words[2],
                         "bss": words[3], "file_id": file_id, "start": start,
                         "packed": bool(words[7] >> 24 & 1), "end": end})
    return overlays


def module_rows(store: sqlite3.Connection, program: str):
    return store.execute(
        "SELECT m.module_id, m.name, m.kind, m.file_id, m.load_vaddr, m.size, m.file_off "
        "FROM modules m JOIN programs p ON p.id = m.program_id WHERE p.name = ? "
        "ORDER BY m.module_id", (program,)).fetchall()


def nds_offsets(rom_path: Path, work: Path) -> dict:
    rom = rom_path.read_bytes()
    overlays = nds_tables(rom)
    project = work / "nds-offsets"
    run([CLI, "import", rom_path, "--no-analysis", "--project", project])
    store = sqlite3.connect(project / "project.sqlite")
    try:
        # Every overlay, not only three: the FAT is the truth.
        for overlay in overlays:
            rows = module_rows(store, f"{ROM}.ov{overlay['id']}")
            assert len(rows) == 1, f"ov{overlay['id']}: {len(rows)} module rows"
            _, name, kind, file_id, load, size, file_off = rows[0]
            assert (name, kind, file_id) == (f"ov{overlay['id']}", "overlay",
                                             str(overlay["file_id"])), rows[0]
            assert int(load, 16) == overlay["ram"], rows[0]
            assert size == overlay["ram_size"] + overlay["bss"], rows[0]
            assert file_off == overlay["start"] > 0, (
                f"ov{overlay['id']}: file_off {file_off:#x}, FAT says {overlay['start']:#x}")
        # The static module's row names its own cartridge offset too.
        (arm9_off,) = store.execute(
            "SELECT m.file_off FROM modules m JOIN programs p ON p.id = m.program_id "
            "WHERE p.name = ?", (f"{ROM}.arm9",)).fetchone()
        assert arm9_off == u32(rom, 0x20), (arm9_off, u32(rom, 0x20))
    finally:
        store.close()
    # Three distinct overlays, recorded with the cartridge's bytes at the
    # offset: an unpacked overlay's stored file is its RAM image; a packed one
    # (127 of HeartGold's 129) starts at its packed stream.
    unpacked = [o for o in overlays if not o["packed"] and o["end"] - o["start"] >= 64]
    packed_ones = [o for o in overlays if o["packed"]]
    chosen = list(dict.fromkeys(
        [o["id"] for o in unpacked[:2] + packed_ones[len(packed_ones) // 2:][:1]]))
    spots = []
    for overlay in (o for o in overlays if o["id"] in chosen):
        spots.append({"overlay": overlay["id"], "packed": overlay["packed"],
                      "file_off": overlay["start"],
                      "bytes": rom[overlay["start"]:overlay["start"] + 8].hex()})
    assert len(spots) == 3, spots
    packed = sum(1 for o in overlays if o["packed"])
    return {"overlays": len(overlays), "packed": packed, "spot_checks": spots}


# ----- GameCube -------------------------------------------------------------

def ciso_reader(path: Path):
    data = path.read_bytes()
    if data[:4] != b"CISO":
        return lambda off, size: data[off:off + size]
    block = u32(data, 4)
    slots, count = [], 0
    for flag in data[8:0x8000]:
        slots.append(count if flag else None)
        count += 1 if flag else 0

    def read(off: int, size: int) -> bytes:
        out = bytearray()
        while size:
            index, inner = divmod(off, block)
            take = min(block - inner, size)
            slot = slots[index] if index < len(slots) else None
            if slot is None:
                out += bytes(take)
            else:
                start = 0x8000 + slot * block + inner
                out += data[start:start + take].ljust(take, b"\0")
            off, size = off + take, size - take
        return bytes(out)
    return read


def fst_files(read) -> dict[str, tuple[int, int]]:
    fst_off, fst_size = u32(read(0x424, 4) + b"", 0, "big"), u32(read(0x428, 4), 0, "big")
    fst = read(fst_off, fst_size)
    count = u32(fst, 8, "big")
    names = fst[count * 12:]
    files, dirs = {}, []
    for index in range(1, count):
        while dirs and index >= dirs[-1][1]:
            dirs.pop()
        kind = fst[index * 12]
        name_at = int.from_bytes(fst[index * 12 + 1:index * 12 + 4], "big")
        name = names[name_at:names.index(0, name_at)].decode("latin-1")
        a, b = u32(fst, index * 12 + 4, "big"), u32(fst, index * 12 + 8, "big")
        if kind == 1:
            dirs.append((name, b))
        else:
            files["/".join([d for d, _ in dirs] + [name])] = (a, b)
    return files


def gc_offsets(disc: Path, work: Path) -> dict:
    read = ciso_reader(disc)
    files = fst_files(read)
    dol_at = u32(read(0x420, 4), 0, "big")
    project = work / "gc-offsets"
    run([CLI, "import", disc, "--name", "gc", "--no-analysis", "--project", project])
    store = sqlite3.connect(project / "project.sqlite")
    try:
        rows = module_rows(store, "gc")
    finally:
        store.close()
    by_name = {row[1]: row for row in rows}
    assert "main.dol" in by_name, [row[1] for row in rows]
    spots = []
    dol = by_name["main.dol"]
    assert dol[6] == dol_at > 0, (dol, dol_at)
    # A DOL header's first text-section offset is its own 0x100.
    assert u32(read(dol_at, 4), 0, "big") == 0x100, "the boot header does not point at a DOL"
    spots.append({"module": "main.dol", "file_off": dol_at})
    rels = [row for row in rows if row[2] == "rel"]
    assert rels, "the disc imported no REL module"
    for row in rels[:2]:
        file_id = row[3]
        assert file_id in files, (file_id, sorted(files)[:5])
        want = files[file_id][0]
        assert row[6] == want > 0, f"{row[1]}: file_off {row[6]:#x}, the FST says {want:#x}"
        head = read(row[6], 4)
        if file_id.endswith(".szs"):
            assert head == b"Yaz0", head
        else:
            # A REL header: the format version is the word at 0x1c.
            assert u32(read(row[6] + 0x1C, 4), 0, "big") in (1, 2, 3), read(row[6], 0x20).hex()
        spots.append({"module": row[1], "file_id": file_id, "file_off": row[6], "magic": head.hex()})
    return {"modules": len(rows), "spot_checks": spots}


# ----- N64 ------------------------------------------------------------------

def n64_offsets(rom_path: Path, work: Path) -> dict:
    rom = rom_path.read_bytes()
    project = work / "n64-offsets"
    run([CLI, "import", rom_path, "--name", "pd", "--no-analysis", "--project", project])
    store = sqlite3.connect(project / "project.sqlite")
    try:
        rows = {row[1]: row for row in module_rows(store, "pd")}
    finally:
        store.close()
    spots = []
    for name, first in PD_SEGMENTS.items():
        assert name in rows, (name, sorted(rows))
        _, _, kind, file_id, load, size, file_off = rows[name]
        assert file_off == first, f"{name}: file_off {file_off:#x}, expected {first:#x}"
        assert file_id.startswith(f"rom:{first:#x}-"), (name, file_id)
        spots.append({"segment": name, "file_off": file_off, "file_id": file_id,
                      "bytes": rom[first:first + 4].hex()})
    # The packed streams the modules name: `data` is one Rare 0x1173 stream
    # from its first byte, `lib` is 0x2000 raw bytes and then one at 0x3050,
    # and `game` is paged (a page length word, not a codec magic, leads it).
    assert rom[0x39850:0x39852] == b"\x11\x73", rom[0x39850:0x39854].hex()
    assert rom[0x3050:0x3052] == b"\x11\x73", rom[0x3050:0x3054].hex()
    assert u32(rom, 0x4FC40, "big") < 0x10000, rom[0x4FC40:0x4FC44].hex()
    assert rows["cartridge"][6] == 0
    return {"modules": len(rows), "spot_checks": spots}


# ----- isolation --------------------------------------------------------------

def overlay_pairs(store: sqlite3.Connection, count: int):
    """`count` addresses held by two overlays each, spread over the address
    space and over different overlay pairs. (entry, [(program, program_id)])."""
    rows = store.execute(
        "SELECT f.entry, p.name, p.id FROM functions f JOIN programs p ON p.id = f.program_id "
        "WHERE p.name LIKE '%.ov%' ORDER BY f.entry, p.id").fetchall()
    holders: dict[str, list[tuple[str, int]]] = {}
    for entry, name, identifier in rows:
        holders.setdefault(entry, []).append((name, identifier))
    shared = [(entry, who) for entry, who in holders.items() if len(who) >= 2]
    assert len(shared) >= count, f"only {len(shared)} addresses are held by two overlays"
    picked, used = [], set()
    step = max(1, len(shared) // count)
    for entry, who in shared[::step] + shared:
        pair = (who[0][0], who[-1][0])
        if entry in {e for e, _ in picked} or pair in used and len(picked) < count - 1:
            continue
        picked.append((entry, who))
        used.add(pair)
        if len(picked) == count:
            break
    assert len(picked) == count
    return picked


def snapshot(api: Api, program: str, entry: int) -> dict:
    address = f"{entry:08x}"
    function = api.result("function_at", program=program, address=entry)
    return {
        "function": function and (function["name"], function["size"]),
        "incoming": sorted(x["from"]["offset"] for x in
                           api.result("xrefs", program=program, address=address, incoming=True)),
        "revision": next(p["revision"] for p in api.result("programs") if p["program"] == program),
    }


def isolation(project_source: Path, work: Path, pairs: int) -> dict:
    project = work / "project"
    shutil.copytree(project_source, project, ignore=shutil.ignore_patterns("project.sqlite-*"))
    store = sqlite3.connect(project / "project.sqlite")
    picked = overlay_pairs(store, pairs)
    module_ids = {name: (rows[0][0], rows[0][1]) for name, rows in
                  ((n, module_rows(store, n)) for _, who in picked for n, _ in who)}
    store.close()
    api = Api(project)
    report = []
    try:
        for entry_hex, who in picked:
            entry = int(entry_hex, 16)
            a_name, b_name = who[0][0], who[-1][0]
            holders = [name for name, _ in who]
            address = f"{entry:08x}"

            # locate: every holder is named with its own module and id.
            before_rows = api.result("locate", address=address)
            located = {row["program"]: row for row in before_rows}
            for name in holders:
                row = located.get(name)
                assert row, f"locate {address} does not name {name}"
                want_id, want_name = module_ids[name]
                assert row["module"] == name.rsplit(".", 1)[1] == want_name, (name, row["module"])
                assert row["module_id"] == want_id, (name, row["module_id"], want_id)
            assert len({located[n]["module_id"] for n in holders}) == len(holders), (
                "two overlays answer with one module id")

            sample = holders[:1] + holders[-1:] + holders[1:3]
            sample = list(dict.fromkeys(sample))
            baseline = {name: snapshot(api, name, entry) for name in holders}
            listings = {name: json.dumps(api.result("functions", program=name), sort_keys=True)
                        for name in sample}
            symbols = {name: json.dumps(api.result("symbols", program=name), sort_keys=True)
                       for name in sample}
            resident = json.dumps(api.result("functions", program=f"{ROM}.arm9"), sort_keys=True)
            old_name = baseline[a_name]["function"][0]

            new_name = f"iso_{a_name.rsplit('.', 1)[1]}_{address}"
            api.result("rename", program=a_name, address=address, name=new_name)

            assert api.result("function_at", program=a_name, address=entry)["name"] == new_name
            for name in holders:
                if name == a_name:
                    continue
                assert snapshot(api, name, entry) == baseline[name], (
                    f"renaming in {a_name} moved {name} at {address}")
            for name in sample:
                if name == a_name:
                    continue
                assert json.dumps(api.result("functions", program=name),
                                  sort_keys=True) == listings[name], f"{name}: functions moved"
                assert json.dumps(api.result("symbols", program=name),
                                  sort_keys=True) == symbols[name], f"{name}: symbols moved"
            assert json.dumps(api.result("functions", program=f"{ROM}.arm9"),
                              sort_keys=True) == resident, "the resident image moved"

            # locate after: A's row holds the new name, every other row its old.
            after = {row["program"]: row for row in api.result("locate", address=address)}
            assert after[a_name]["function"] == new_name, after[a_name]
            for name in holders:
                if name != a_name:
                    assert after[name]["function"] == before_rows_function(before_rows, name), name
                assert after[name]["module_id"] == located[name]["module_id"]

            # follow: a caller in A reaches A's function; B's callers are B's.
            callers = baseline[a_name]["incoming"]
            followed = None
            if callers:
                caller = callers[0]
                targets = {x["to"]["offset"] for x in api.result(
                    "xrefs", program=a_name, address=f"{caller:08x}", incoming=False)}
                assert entry in targets, f"{a_name}: caller {caller:#x} does not reach {address}"
                landed = api.result("function_at", program=a_name, address=entry)
                assert landed["name"] == new_name, "the call resolved to another overlay's name"
                now = sorted(x["from"]["offset"] for x in api.result(
                    "xrefs", program=a_name, address=address, incoming=True))
                assert now == callers, f"{a_name}: callers moved"
                followed = caller
            terminal = run([CLI, "locate", address, "--follow", "--project", project]).stdout
            for name, expected in ((a_name, new_name), (b_name, old_name)):
                line = next(l for l in terminal.splitlines() if l.startswith(name + "  "))
                assert line.split("  ")[-2 if "module=" in line else -1].strip() in {expected}, (
                    f"cli locate: {line!r}, expected function {expected}")
                assert f"module={name.rsplit('.', 1)[1]}#{located[name]['module_id']}" in line, line

            # undo puts A back; nothing else was touched.
            api.result("undo", program=a_name)
            assert api.result("function_at", program=a_name, address=entry)["name"] == old_name
            for name in holders:
                assert snapshot(api, name, entry)["function"] == baseline[name]["function"], name
            report.append({"address": address, "renamed_in": a_name, "checked_unchanged": b_name,
                           "holders": len(holders), "listings_compared": len(sample) + 1,
                           "follow_caller": followed and f"{followed:08x}",
                           "module_ids": {n: located[n]["module_id"] for n in (a_name, b_name)}})
    finally:
        api.close()
    return {"pairs": report}


def before_rows_function(rows, name):
    return next(row["function"] for row in rows if row["program"] == name)


# ----- main ------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--images-dir", type=Path, default=NDS_DIR)
    parser.add_argument("--project", type=Path)
    parser.add_argument("--gc-disc", type=Path)
    parser.add_argument("--n64-rom", type=Path, default=N64_ROM)
    parser.add_argument("--pairs", type=int, default=5)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--skip-build", action="store_true")
    arguments = parser.parse_args()
    if not arguments.skip_build:
        subprocess.run(["cargo", "build", "-q", "--release", "-p", "romwright-cli",
                        "-p", "romwright-api", "-p", "romwright-worker"], cwd=ROOT, check=True)
    report = {"id": "m10-005", "recorded_at": datetime.now(timezone.utc).isoformat(), "parts": {}}
    nds_rom = arguments.images_dir / ROM
    gc_disc = arguments.gc_disc or next(iter(sorted(GC_DIR.glob("*.ciso"))), None)
    with tempfile.TemporaryDirectory(prefix="m10-005-") as directory:
        work = Path(directory)
        if nds_rom.is_file():
            source = arguments.project
            if source is None:
                source = work / "imported"
                run([CLI, "import", nds_rom, "--project", source])
            report["parts"]["isolation"] = isolation(source, work, arguments.pairs)
            report["parts"]["nds_offsets"] = nds_offsets(nds_rom, work)
        else:
            report["parts"]["nds"] = f"SKIP: {nds_rom} absent"
            print(f"SKIP: {nds_rom} absent")
        if gc_disc and gc_disc.is_file():
            report["parts"]["gc_offsets"] = gc_offsets(gc_disc, work)
        else:
            report["parts"]["gc"] = "SKIP: no GameCube disc"
            print("SKIP: no GameCube disc")
        if arguments.n64_rom.is_file():
            report["parts"]["n64_offsets"] = n64_offsets(arguments.n64_rom, work)
        else:
            report["parts"]["n64"] = f"SKIP: {arguments.n64_rom} absent"
            print(f"SKIP: {arguments.n64_rom} absent")
    ran = [k for k, v in report["parts"].items() if isinstance(v, dict)]
    report["status"] = "pass" if ran else "skipped"
    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    print(f"m10-005: {report['status'].upper()} ({', '.join(ran)})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        import traceback
        traceback.print_exc()
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
