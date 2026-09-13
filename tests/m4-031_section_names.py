#!/usr/bin/env python3
"""m4-031: the one name we coin, and the rule that bounds it.

`m4-003`'s `name-convention` class is a single decision, repeated: the function
at the start of `.plt` is `_plt` in our store and `FUN_<address>` in stock's.
Ghidra's loader names the PLT entries after the imports they resolve -- which
we match, gated by `m5-008` and `m5-009` -- and leaves the resolver stub at the
head of the table with a default name. We name it after the section the image
declares, because a reader who sees `_plt` knows what the stub is and a reader
who sees `FUN_00201710` does not.

The decision is kept; this gate bounds it, so the coinage cannot spread:

  1. every function we name `_plt` is at the loaded start of a `.plt` section,
     computed from the image's own section headers and the store's own image
     bias (the entry point it recorded against `e_entry`);
  2. stock holds a function at each of those addresses, so the coinage names a
     function rather than inventing one;
  3. stock's name there is a default `FUN_<address>`, which is the direction the
     class records -- we name what stock leaves unnamed;
  4. the image's own symbol tables name none of those addresses, so a real
     symbol is never overridden by the coinage.

Usage:
    python3 tests/m4-031_section_names.py --corpus-dir DIR [--report OUT.json]
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import sqlite3
import struct
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "benchmarks"))
import gate_cache  # noqa: E402

CLI = ROOT / "target/release/romwright-cli"
LOCK = ROOT / "tests/corpus.lock.json"
COINED = {"_plt": ".plt", "_init": ".init", "_fini": ".fini"}
DEFAULT_NAME = re.compile(r"^FUN_[0-9a-f]+$")


def rows(store: Path, query: str) -> list[tuple]:
    connection = sqlite3.connect(store)
    try:
        (program,) = connection.execute("SELECT id FROM programs").fetchone()
        return list(connection.execute(query, (program,)))
    finally:
        connection.close()


def ram(cell: str) -> bool:
    return isinstance(cell, str) and not cell.startswith("{")


def functions(store: Path) -> dict[str, str]:
    return {address: name for address, name in rows(
        store, "SELECT entry, name FROM functions WHERE program_id = ?") if ram(address)}


def elf_facts(binary: Path) -> tuple[int, dict[str, int], set[int]]:
    """The image's entry, its section starts by name, and its named addresses.

    Parsed here rather than shelled out, so the gate needs nothing but the
    file: `readelf` is a convenience, not a dependency of the claim."""
    data = binary.read_bytes()
    assert data[:4] == b"\x7fELF", f"{binary.name}: not an ELF"
    wide = data[4] == 2
    little = data[5] == 1
    order = "<" if little else ">"
    if wide:
        # e_entry, e_phoff, e_shoff; then e_shentsize, e_shnum, e_shstrndx.
        entry, _phoff, shoff = struct.unpack_from(f"{order}QQQ", data, 24)
        shentsize, shnum, shstrndx = struct.unpack_from(f"{order}HHH", data, 58)
    else:
        entry, _phoff, shoff = struct.unpack_from(f"{order}III", data, 24)
        shentsize, shnum, shstrndx = struct.unpack_from(f"{order}HHH", data, 46)
    headers = []
    for index in range(shnum):
        base = shoff + index * shentsize
        if wide:
            name_off, kind, _flags, addr, offset, size, link, _info, _align, entsize = \
                struct.unpack_from(f"{order}IIQQQQIIQQ", data, base)
        else:
            name_off, kind, _flags, addr, offset, size, link, _info, _align, entsize = \
                struct.unpack_from(f"{order}IIIIIIIIII", data, base)
        headers.append({"name_off": name_off, "kind": kind, "addr": addr,
                        "off": offset, "size": size, "link": link, "entsize": entsize})
    strtab = headers[shstrndx]
    names = data[strtab["off"]:strtab["off"] + strtab["size"]]

    def read_name(table: bytes, offset: int) -> str:
        end = table.find(b"\0", offset)
        return table[offset:end if end >= 0 else None].decode("utf-8", "replace")

    starts: dict[str, int] = {}
    named: set[int] = set()
    for header in headers:
        header["name"] = read_name(names, header["name_off"])
        if header["name"] in COINED.values() and header["addr"]:
            starts[header["name"]] = header["addr"]
    for header in headers:
        # SHT_SYMTAB and SHT_DYNSYM: every address the image itself names.
        if header["kind"] not in (2, 11) or not header["entsize"]:
            continue
        if header["link"] >= len(headers):
            continue
        table = headers[header["link"]]
        text = data[table["off"]:table["off"] + table["size"]]
        count = header["size"] // header["entsize"]
        for index in range(count):
            base = header["off"] + index * header["entsize"]
            if wide:
                sym_name, _info, _other, shndx, value, _size = \
                    struct.unpack_from(f"{order}IBBHQQ", data, base)
            else:
                sym_name, value, _size, _info, _other, shndx = \
                    struct.unpack_from(f"{order}IIIBBH", data, base)
            if value and shndx and read_name(text, sym_name):
                named.add(value)
    return entry, starts, named


def native_store(binary: Path) -> Path:
    def build(directory: Path) -> None:
        result = subprocess.run(
            [str(CLI), "import", str(binary), "--project", str(directory)],
            capture_output=True, text=True, timeout=900)
        assert result.returncode == 0, (
            f"{binary.name}: native import failed: {result.stderr[-400:]}")

    return gate_cache.store(gate_cache.native_key(binary), build)


def oracle_store(binary: Path, install: Path) -> Path:
    def build(directory: Path) -> None:
        result = subprocess.run(
            [str(CLI), "import", str(binary), "--oracle", "--project", str(directory),
             "--ghidra", str(install)],
            capture_output=True, text=True, timeout=1800,
            env=dict(os.environ, DEBUGINFOD_URLS=""))
        assert result.returncode == 0, (
            f"{binary.name}: oracle import failed: {result.stderr[-400:]}")

    return gate_cache.store(gate_cache.oracle_key(binary, install), build)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--ghidra", type=Path,
                        default=Path(os.environ.get("ROMWRIGHT_GHIDRA",
                                                    Path.home() / "ghidra_12.1.3_PUBLIC")))
    parser.add_argument("--report", type=Path)
    parser.add_argument("--jobs", type=int, default=4)
    arguments = parser.parse_args()
    subprocess.run(["cargo", "build", "-q", "--release", "-p", "romwright-cli", "-p", "romwright-worker"],
                   cwd=ROOT, check=True)
    lock = json.loads(LOCK.read_text())
    matrix = set(lock["oracle_matrix"]["architectures"])
    wanted = [entry for entry in lock["entries"]
              if entry.get("format") == "elf" and entry["architecture"] in matrix]

    def measure(entry: dict) -> dict:
        binary = arguments.corpus_dir / entry["binary"]
        ours = functions(native_store(binary) / "project.sqlite")
        theirs = functions(oracle_store(binary, arguments.ghidra) / "project.sqlite")
        image_entry, starts, named = elf_facts(binary)
        # The bias the store loaded the image at, from its own entry fact.
        loaded = [address for address, name in ours.items() if name == "entry"]
        assert loaded, f"{binary.name}: the store recorded no entry point"
        bias = int(loaded[0], 16) - image_entry
        coined = sorted((address, name) for address, name in ours.items() if name in COINED)
        misplaced, invented, shadowed, renamed = [], [], [], []
        for address, name in coined:
            offset = int(address, 16)
            section = COINED[name]
            if starts.get(section, 0) + bias != offset:
                misplaced.append({"address": address, "name": name,
                                  "section_start": f"{starts.get(section, 0) + bias:08x}"})
            if address not in theirs:
                invented.append({"address": address, "name": name})
            elif not DEFAULT_NAME.match(theirs[address]):
                renamed.append({"address": address, "ours": name, "stock": theirs[address]})
            if offset - bias in named:
                shadowed.append({"address": address, "name": name})
        return {"id": Path(entry["binary"]).stem, "variant": entry["variant"],
                "coined": [{"address": address, "name": name} for address, name in coined],
                "misplaced": misplaced, "invented": invented,
                "shadowed": shadowed, "stock_named": renamed}

    measured = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=arguments.jobs) as pool:
        for row in pool.map(measure, wanted):
            measured.append(row)
            print(f"{row['id']:24} coined {len(row['coined']):2} misplaced "
                  f"{len(row['misplaced']):2} invented {len(row['invented']):2} "
                  f"shadowed {len(row['shadowed']):2}", flush=True)

    measured.sort(key=lambda row: row["id"])
    coined = [item for row in measured for item in row["coined"]]
    misplaced = [item for row in measured for item in row["misplaced"]]
    invented = [item for row in measured for item in row["invented"]]
    shadowed = [item for row in measured for item in row["shadowed"]]
    stock_named = [item for row in measured for item in row["stock_named"]]
    assert coined, "no name is coined, so this gate measures nothing"
    assert not misplaced, (
        f"names coined somewhere other than the section's loaded start: {misplaced[:6]}")
    assert not invented, (
        f"coined names on functions stock does not hold: {invented[:6]}")
    assert not shadowed, (
        f"coined names over addresses the image itself names: {shadowed[:6]}")
    assert not stock_named, (
        f"coined names where stock has a name of its own, so the class is not a "
        f"free choice: {stock_named[:6]}")
    metrics = {
        "coined.rows_measured": len(measured),
        "coined.names": len(coined),
        "coined.misplaced": 0,
        "coined.invented": 0,
        "coined.shadowed": 0,
    }
    summary = (f"{len(coined)} coined names across {len(measured)} ELF rows, every one "
               f"at its section's loaded start, on a function stock also holds, where "
               f"stock's name is its own default and the image names nothing")
    print(f"m4-031: PASS ({summary})")
    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps({
            "id": "m4-031",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "status": "pass",
            "passed": True,
            "summary": summary,
            "metrics": metrics,
            "measured": measured,
        }, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
