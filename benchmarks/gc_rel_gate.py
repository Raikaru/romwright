#!/usr/bin/env python3
"""P3.1 measurement: Animal Crossing's game code (foresta.rel) against truth.

Animal Crossing's game code is `foresta.rel.szs` on the disc, not the boot
DOL. This script measures three things, none of which edits a report by hand
(it writes `--out` JSON only):

  ours    Import the .ciso with romwright-cli (one program: main.dol and
          foresta.rel), then score function recall/precision on the REL's
          text and on the DOL's text against the ac-decomp project's dtk
          symbols (`config/GAFE01_00/foresta/symbols.txt`, `.../symbols.txt`),
          with m21-001's `score()` (the same policy as every real-image row),
          and count the cross-module references the store holds.
  stock   The same score for a stock Ghidra + GameCubeLoader run, read from
          the JSON `benchmarks/ghidra/ExportFunctionEntries.java` and
          `ExportModuleReferences.java` wrote (the headless run itself is a
          command in the STATUS.md section; it takes the REL placed beside
          main.dol, which is how the loader finds the DOL).
  bytes   Relocation correctness: every byte of the REL's loaded sections as
          romwright-cli maps them (`mem`) against `dtk rel merge`'s ELF for
          the same DOL + REL (an independent producer: it applies the relocation
          table itself, placing the REL at align32(__ArenaLo + 0x2000)), and
          the share of module-0 `bl` relocations whose patched target is a
          function the ac-decomp symbols name.

Scoring: truth is {address: (size, name)} of `type:function` symbols; an entry
counts as found when our/Ghidra's function table has that address; precision
is hits / (hits + functions found inside the scored range the truth does not
name). Same code path as tests/m21-001_real_images.py::score.

Usage:
  gc_rel_gate.py ours  --image DISC.ciso --foresta-symbols S --dol-symbols S --work DIR --out J
  gc_rel_gate.py stock --functions F.json [--references R.json] --foresta-symbols S --dol-symbols S --out J
  gc_rel_gate.py bytes --image DISC.ciso --elf MERGED.elf --dol-symbols S --relocs RELOCS.txt --out J
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import shutil
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLI = Path(__import__("os").environ.get("ROMWRIGHT_CLI", ROOT / "target" / "release" / "romwright-cli"))


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


M21 = load_module("m21_real_images", ROOT / "tests" / "m21-001_real_images.py")
SPEED = load_module("import_speed", ROOT / "benchmarks" / "import_speed.py")

SYMBOL = re.compile(r"^(?P<name>.+?) = \.(?P<section>[\w.]+):0x(?P<offset>[0-9A-Fa-f]+);"
                    r"(?: //(?P<attrs>.*))?$")


def dtk_functions(path: Path, sections: tuple[str, ...], functions_only: bool = True
                  ) -> dict[int, tuple[int, str]]:
    """`type:function` symbols (every symbol when not `functions_only`) of a dtk
    symbols.txt in `sections`, keyed by the section-relative offset (a REL's) or
    the absolute address (the DOL's)."""
    out: dict[int, tuple[int, str]] = {}
    for line in path.read_text(errors="replace").splitlines():
        match = SYMBOL.match(line.strip())
        if not match or "." + match["section"] not in sections:
            continue
        attrs = match["attrs"] or ""
        if functions_only and "type:function" not in attrs:
            continue
        size = re.search(r"size:0x([0-9A-Fa-f]+)", attrs)
        out[int(match["offset"], 16)] = (int(size.group(1), 16) if size else 0, match["name"])
    return out


def rebased(truth: dict[int, tuple[int, str]], base: int) -> dict[int, tuple[int, str]]:
    return {base + offset: value for offset, value in truth.items()}


def ours(args) -> dict:
    work = Path(args.work)
    project = work / "project"
    shutil.rmtree(project, ignore_errors=True)
    project.mkdir(parents=True)
    started = time.monotonic()
    proc = subprocess.run(
        [str(CLI), "import", str(args.image), "--name", "gc", "--project", str(project), "--timings"],
        capture_output=True, text=True, timeout=args.limit,
        env={**__import__("os").environ, "ROMWRIGHT_NO_IMPORT_CACHE": "1"})
    seconds = time.monotonic() - started
    if proc.returncode:
        raise SystemExit(f"import failed: {proc.stderr[-600:]}")
    timings = {}
    for line in proc.stdout.splitlines():
        if line.startswith("TIMINGS "):
            timings = json.loads(line[len("TIMINGS "):])
    db = sqlite3.connect(f"file:{project}/project.sqlite?mode=ro", uri=True)
    pid = db.execute("SELECT id FROM programs WHERE name = 'gc'").fetchone()[0]
    modules = db.execute("SELECT module_id, name, kind, load_vaddr, size FROM modules "
                         "WHERE program_id = ? ORDER BY module_id", (pid,)).fetchall()
    regions = db.execute("SELECT name, start, size, permissions FROM memory_regions "
                         "WHERE program_id = ? ORDER BY start", (pid,)).fetchall()
    rel_text = next((int(s, 16), size) for name, s, size, perm in regions
                    if name.endswith("rel1.sec1") and "x" in perm)
    dol_exec = [(int(s, 16), int(s, 16) + size) for name, s, size, perm in regions
                if "x" in perm and not name.split(":")[-1].startswith("rel")]
    functions = db.execute("SELECT COUNT(*) FROM functions WHERE program_id = ?", (pid,)).fetchone()[0]
    xrefs = db.execute("SELECT x.from_addr, x.to_addr, x.kind, m.name FROM module_xrefs x "
                       "JOIN modules m ON m.module_id = x.module_id WHERE m.program_id = ?",
                       (pid,)).fetchall()
    diagnostics = [dict(severity=s, stage=st, message=m[:300]) for s, st, m in db.execute(
        "SELECT severity, stage, message FROM import_diagnostics WHERE program_id = ?", (pid,))]
    db.close()
    foresta = rebased(dtk_functions(Path(args.foresta_symbols), (".text",)), rel_text[0])
    dol = dtk_functions(Path(args.dol_symbols), (".init", ".text"))
    rel_row = M21.score(project, "gc", foresta, [(rel_text[0], rel_text[0] + rel_text[1])])
    dol_row = M21.score(project, "gc", dol, dol_exec)
    by_pair: dict[str, int] = {}
    for _, _, _, module in xrefs:
        by_pair[module] = by_pair.get(module, 0) + 1
    return {
        "tool": "romwright", "image": Path(args.image).name, "import_seconds": round(seconds, 1),
        "phases": timings.get("phases"), "functions_total": functions,
        "rel_text_base": f"{rel_text[0]:#x}", "rel_text_size": rel_text[1],
        "modules": [dict(id=i, name=n, kind=k, load=l, size=s) for i, n, k, l, s in modules],
        "foresta": quality(rel_row), "main_dol": quality(dol_row),
        "cross_module_xrefs": {
            "rows": len(xrefs),
            "distinct_pairs": len({(a, b) for a, b, _, _ in xrefs}),
            "rows_by_source_module": by_pair,
        },
        "diagnostics": diagnostics,
        "dtk_parity": parity(regions, diagnostics, args) if args.rel_info else None,
    }


KIND_NUMBER = {"Absolute": 1, "PpcAddr16Lo": 4, "PpcAddr16Hi": 5, "PpcAddr16Ha": 6,
               "PpcRel24": 10, "PpcRel14": 11}


def parity(regions, diagnostics, args) -> dict:
    """`dtk rel info` against our loader: the section table (size and kind per
    index) and the relocation count per type (module 0 and self together)."""
    info = Path(args.rel_info).read_text().splitlines()
    theirs = {}
    for line in info:
        match = re.match(r"^\s*(\S+) \| (code|rodata|data|bss)\s+\| 0x([0-9A-F]+)\s+\| 0x([0-9A-F]+)\s+\| (\d+)\s*$", line)
        if match:
            theirs[int(match[5])] = (match[2], int(match[3], 16))
    mine = {}
    for name, start, size, perm in regions:
        match = re.search(r"rel1\.sec(\d+)$", name)
        if match:
            mine[int(match[1])] = size
    sections_equal = {i: v[1] for i, v in theirs.items()} == mine
    counts = {}
    for line in Path(args.relocs).read_text().splitlines():
        match = re.match(r"^\s+\d+:0x[0-9A-F]+ (\w+) -> ", line)
        if match:
            counts[KIND_NUMBER[match[1]]] = counts.get(KIND_NUMBER[match[1]], 0) + 1
    message = next(d["message"] for d in diagnostics if d["stage"] == "rel")
    ours_counts = {int(k): int(v) for k, v in re.findall(r"(\d+):(\d+)", message.split("by type")[1])}
    return {"sections_equal": sections_equal, "sections": len(theirs),
            "relocation_counts_equal": counts == ours_counts,
            "relocations_dtk": sum(counts.values()), "relocations_ours": sum(ours_counts.values()),
            "by_type_dtk": counts, "by_type_ours": ours_counts}


def quality(row: dict) -> dict:
    keys = ("truth", "found", "recall", "precision", "invented", "sizes_compared",
            "size_exact", "size_short", "size_long", "missed_sample", "invented_sample")
    return {key: row[key] for key in keys if key in row}


def stock(args) -> dict:
    exported = json.loads(Path(args.functions).read_text())
    blocks = exported["blocks"]
    # GameCubeLoader names the DOL's blocks `MAIN_.text0` ... and a REL's
    # `<file>_.text0`; system blocks (OSGlobals, registers) carry no prefix.
    is_rel = lambda b: "_." in b["name"] and not b["name"].startswith("MAIN_")
    rel_blocks = [b for b in blocks if is_rel(b) and ".text" in b["name"]]
    if not rel_blocks:
        raise SystemExit("stock program has no `<module>_.text` block: the REL was not loaded")
    rel_text = rel_blocks[0]
    functions = {f["entry"]: f["size"] for f in exported["functions"] if not f["overlay"]}
    foresta = rebased(dtk_functions(Path(args.foresta_symbols), (".text",)), rel_text["start"])
    dol = dtk_functions(Path(args.dol_symbols), (".init", ".text"))
    dol_exec = [(b["start"], b["start"] + b["size"]) for b in blocks
                if b["execute"] and b["initialized"] and not is_rel(b)]
    scratch = Path(args.out).with_suffix(".score")
    rel_row = SPEED.score_entries(functions, foresta,
                                  [(rel_text["start"], rel_text["start"] + rel_text["size"])],
                                  scratch / "rel")
    dol_row = SPEED.score_entries(functions, dol, dol_exec, scratch / "dol")
    shutil.rmtree(scratch, ignore_errors=True)
    row = {
        "tool": "ghidra+GameCubeLoader", "language": exported["language"],
        "format": exported["format"], "functions_total": len(exported["functions"]),
        "rel_text_base": f"{rel_text['start']:#x}", "rel_text_size": rel_text["size"],
        "blocks": [dict(name=b["name"], start=f"{b['start']:#x}", size=b["size"]) for b in blocks],
        "foresta": quality(rel_row), "main_dol": quality(dol_row),
    }
    if args.references:
        row["cross_module"] = json.loads(Path(args.references).read_text())
    return row


def elf_sections(path: Path) -> list[dict]:
    """Section headers of a 32-bit big-endian ELF: name, address, offset, size, type."""
    data = path.read_bytes()
    assert data[:4] == b"\x7fELF" and data[4] == 1 and data[5] == 2, "expected ELF32 big-endian"
    shoff = int.from_bytes(data[0x20:0x24], "big")
    entsize = int.from_bytes(data[0x2E:0x30], "big")
    count = int.from_bytes(data[0x30:0x32], "big")
    names = int.from_bytes(data[0x32:0x34], "big")
    headers = [data[shoff + i * entsize: shoff + (i + 1) * entsize] for i in range(count)]
    field = lambda h, o: int.from_bytes(h[o:o + 4], "big")
    string_table = field(headers[names], 0x10)
    out = []
    for header in headers:
        start = string_table + field(header, 0)
        name = data[start:data.index(b"\0", start)].decode()
        out.append(dict(name=name, type=field(header, 4), address=field(header, 0x0C),
                        offset=field(header, 0x10), size=field(header, 0x14), data=data))
    return out


def mem(image: Path, address: int, size: int) -> bytes:
    out = subprocess.run([str(CLI), "mem", str(image), f"{address:x}", str(size)],
                         capture_output=True, text=True, check=True, timeout=1800).stdout
    return bytes.fromhex(out.replace(" ", "").strip())


def bytes_check(args) -> dict:
    sections = [s for s in elf_sections(Path(args.elf))
                if s["name"].endswith(":1") and s["type"] == 1 and s["size"]]
    dol_functions = {a for a in dtk_functions(Path(args.dol_symbols), (".init", ".text"))}
    dol_symbols = {a for a in dtk_functions(Path(args.dol_symbols), (".init", ".text"), functions_only=False)}
    rows = []
    total = same = 0
    first_difference = None
    for section in sections:
        theirs = section["data"][section["offset"]: section["offset"] + section["size"]]
        ours_bytes = mem(Path(args.image), section["address"], section["size"])
        agree = sum(1 for a, b in zip(ours_bytes, theirs) if a == b)
        if agree != len(theirs) and first_difference is None:
            at = next(i for i, (a, b) in enumerate(zip(ours_bytes, theirs)) if a != b)
            first_difference = f"{section['name']}+{at:#x}: ours {ours_bytes[at]:02x} dtk {theirs[at]:02x}"
        rows.append(dict(section=section["name"], address=f"{section['address']:#x}",
                         size=section["size"], bytes_equal=agree))
        total += len(theirs)
        same += agree
        if section["name"] == ".text:1":
            text = ours_bytes
            text_base = section["address"]
    # The patched `bl` of every module-0 REL24 relocation: decoded from our
    # bytes, it must name a function the ac-decomp symbols name.
    pattern = re.compile(r"^\s+(\d+):0x([0-9A-F]+) PpcRel24 -> 0:(\d+):0x([0-9A-F]+)$")
    calls = on_function = on_symbol = decoded_equals_table = 0
    for line in Path(args.relocs).read_text().splitlines():
        match = pattern.match(line)
        if not match or int(match[3]) != 1:
            continue
        place, addend = int(match[2], 16), int(match[4], 16)
        word = int.from_bytes(text[place:place + 4], "big")
        displacement = (word & 0x03FF_FFFC) - ((word & 0x0200_0000) << 1)
        target = (text_base + place + displacement) & 0xFFFF_FFFF
        calls += 1
        decoded_equals_table += target == addend
        on_function += target in dol_functions
        on_symbol += target in dol_symbols
    return {
        "tool": "romwright", "image": Path(args.image).name, "reference": "dtk rel merge (ELF)",
        "sections": rows, "bytes_compared": total, "bytes_equal": same,
        "byte_agreement": round(same / total, 8) if total else None,
        "first_difference": first_difference,
        "rel24_to_dol": {"relocations": calls, "patched_target_equals_table": decoded_equals_table,
                         "target_is_named_dol_function": on_function,
                         "named_function_rate": round(on_function / calls, 4) if calls else None,
                         # `_savegpr_N`/`_restgpr_N` sled entries are `type:label`, not functions.
                         "target_is_any_named_dol_text_symbol": on_symbol,
                         "named_symbol_rate": round(on_symbol / calls, 4) if calls else None},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("ours", "stock", "bytes"):
        p = sub.add_parser(name)
        p.add_argument("--out", required=True)
        p.add_argument("--dol-symbols", required=True)
        if name != "stock":
            p.add_argument("--image", required=True)
        if name != "bytes":
            p.add_argument("--foresta-symbols", required=True)
        if name == "ours":
            p.add_argument("--work", required=True)
            p.add_argument("--limit", type=int, default=3 * 3600)
            p.add_argument("--rel-info", help="`dtk rel info` output for the REL (parity)")
            p.add_argument("--relocs", help="`dtk rel info -r` output (parity)")
        if name == "stock":
            p.add_argument("--functions", required=True)
            p.add_argument("--references")
        if name == "bytes":
            p.add_argument("--elf", required=True)
            p.add_argument("--relocs", required=True)
    args = parser.parse_args()
    result = {"ours": ours, "stock": stock, "bytes": bytes_check}[args.command](args)
    Path(args.out).write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
