#!/usr/bin/env python3
"""GC/Wii discovery supplement: DOL function recovery against truth.

A documented supplement to tests/m21-001_real_images.py, not a change to its
frozen image set. Same `score()` policy (recall, precision, size agreement);
each image's truth is the FUNC symbols of the ELF the DOL was linked into, or
a dtk `symbols.txt` (`type:function`).

  gc_discovery.py --cli CLI --work DIR --bond bond.dol bond.elf --base base.dol base.elf
                  [--ac main.dol symbols.txt]

Prints one JSON row per image with the counts and the invented / missed /
wrong-size entries (the rows `dtk dol diff` complains about). Nothing is
written outside --work.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("m21", ROOT / "tests" / "m21-001_real_images.py")
M21 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M21)

SYMBOL = re.compile(r"^(?P<name>.+?) = \.(?P<section>[\w.]+):0x(?P<offset>[0-9A-Fa-f]+);(?: //(?P<attrs>.*))?$")


def dtk_functions(path: Path) -> dict[int, tuple[int, str]]:
    """`type:function` symbols of `.init`/`.text` in a dtk symbols.txt (absolute DOL addresses)."""
    out: dict[int, tuple[int, str]] = {}
    for line in path.read_text(errors="replace").splitlines():
        match = SYMBOL.match(line.strip())
        if not match or "." + match["section"] not in (".init", ".text"):
            continue
        attrs = match["attrs"] or ""
        if "type:function" not in attrs:
            continue
        size = re.search(r"size:0x([0-9A-Fa-f]+)", attrs)
        out[int(match["offset"], 16)] = (int(size.group(1), 16) if size else 0, match["name"])
    return out


def run(cli: Path, image: Path, name: str, work: Path, truth: dict[int, tuple[int, str]]) -> dict:
    project = work / name
    shutil.rmtree(project, ignore_errors=True)
    project.mkdir(parents=True)
    started = time.monotonic()
    proc = subprocess.run([str(cli), "import", str(image), "--name", name, "--project", str(project)],
                          capture_output=True, text=True, env={**os.environ, "ROMWRIGHT_NO_IMPORT_CACHE": "1"})
    seconds = time.monotonic() - started
    if proc.returncode:
        raise SystemExit(f"import of {image} failed: {proc.stderr[-500:]}")
    (work / f"{name}.err").write_text(proc.stderr)
    row = M21.score(project, name, truth, None)
    db = sqlite3.connect(f"file:{project}/project.sqlite?mode=ro", uri=True)
    pid = db.execute("SELECT id FROM programs WHERE name = ?", (name,)).fetchone()[0]
    found = {int(entry, 16): size for entry, size in
             db.execute("SELECT entry, size FROM functions WHERE program_id = ?", (pid,)) if not entry.startswith("ext")}
    ranges = [(int(start, 16), int(start, 16) + size) for start, size, perm in
              db.execute("SELECT start, size, permissions FROM memory_regions WHERE program_id = ?", (pid,))
              if "x" in perm]
    inside = lambda a: any(lo <= a < hi for lo, hi in ranges)
    scored = {a: v for a, v in truth.items() if inside(a)}
    invented = sorted(a for a in found if a not in scored and inside(a))
    row.pop("missed_sample"), row.pop("invented_sample")
    row.update(
        image=image.name, seconds=round(seconds, 1),
        invented_addresses=[f"{a:#x}" for a in invented],
        missed_addresses=[f"{a:#x}" for a in sorted(set(scored) - set(found))],
        unaligned_invented=[f"{a:#x}" for a in invented if a & 3],
        wrong_size=[f"{a:#x} {found[a]} vs {scored[a][0]}" for a in sorted(scored)
                    if a in found and scored[a][0] and found[a] != scored[a][0]],
    )
    return row


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--bond", nargs=2, type=Path, metavar=("DOL", "ELF"))
    parser.add_argument("--base", nargs=2, type=Path, metavar=("DOL", "ELF"))
    parser.add_argument("--ac", nargs=2, type=Path, metavar=("DOL", "SYMBOLS"))
    parser.add_argument("--tag", default="")
    args = parser.parse_args()
    args.work.mkdir(parents=True, exist_ok=True)
    for name, pair in (("bond", args.bond), ("base", args.base)):
        if pair:
            row = run(args.cli, pair[0], name, args.work, M21.elf_functions(pair[1]))
            print(json.dumps({"id": name, "tag": args.tag, **row}), flush=True)
    if args.ac:
        row = run(args.cli, args.ac[0], "ac", args.work, dtk_functions(args.ac[1]))
        print(json.dumps({"id": "ac-main", "tag": args.tag, **row}), flush=True)


if __name__ == "__main__":
    main()
