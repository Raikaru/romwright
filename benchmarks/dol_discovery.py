#!/usr/bin/env python3
"""Paired before/after function discovery on GameCube/Wii images, against truth.

Each image is a corpus directory `<corpus>/<slug>/` holding `main.dol` (or the
disc named with --disc) and `truth/functions.tsv` (start, size, name, module,
verified). For every image the CLIs are run in turn, interleaved, so a shared
host's load affects both alike; each run records the 1/5/15-minute load average
read just before it. Nothing is written outside --work and --out.

  dol_discovery.py --work DIR --out J \
      --cli before=BIN_BEFORE/romwright-cli --cli after=BIN_AFTER/romwright-cli \
      [--corpus ~/ventris-corpus/extracted] [--reps 2] [slug ...]

Scoring: truth is the rows of module `main` (`--module all` scores every module,
for a disc import whose RELs are linked into the program); an entry is a hit
when the program has a function at that address; precision is hits over the
functions found inside executable regions. The invented functions are broken
down by producer and by whether they sit inside a truth function (an interior
entry) or outside every one. A run whose import is `degraded` is reported as
such and is not a valid measurement.

The CLI and worker of one label must sit in one directory.
"""
from __future__ import annotations

import argparse
import bisect
import collections
import json
import os
import shutil
import sqlite3
import subprocess
import time
from pathlib import Path

DEFAULT_IMAGES = [
    "wii-skyward-sword", "wii-npc-pikmin-2", "wii-super-mario-galaxy",
    "wii-rock-band-3", "wii-mario-strikers-charged",
    "gc-melee", "gc-pikmin-2", "gc-tiger-woods-2004",
]


def load_truth(path: Path, module: str) -> dict[int, tuple[int, str, str]]:
    truth: dict[int, tuple[int, str, str]] = {}
    with path.open() as handle:
        next(handle)
        for line in handle:
            row = line.rstrip("\n").split("\t")
            if module == "all" or row[3] == module:
                truth[int(row[0], 16)] = (int(row[1]), row[2], row[3])
    return truth


def score(project: Path, program: str | None, truth: dict[int, tuple[int, str, str]]) -> dict:
    db = sqlite3.connect(f"file:{project}/project.sqlite?mode=ro", uri=True)
    ids = [row[0] for row in db.execute(
        "SELECT id FROM programs WHERE name = ?" if program else "SELECT id FROM programs",
        (program,) if program else ())]
    found: dict[int, str] = {}
    ranges: list[tuple[int, int]] = []
    for pid in ids:
        for entry, producer in db.execute("SELECT entry, producer FROM functions WHERE program_id = ?", (pid,)):
            if not entry.startswith("ext"):
                found[int(entry, 16)] = producer
        ranges += [(int(start, 16), int(start, 16) + size) for start, size, perm in db.execute(
            "SELECT start, size, permissions FROM memory_regions WHERE program_id = ?", (pid,)) if "x" in perm]
    inside = lambda a: any(lo <= a < hi for lo, hi in ranges)
    scored = {a for a in truth if inside(a)}
    found = {a: p for a, p in found.items() if inside(a)}
    hits = scored & found.keys()
    starts = sorted(truth)
    invented = collections.Counter()
    for address, producer in found.items():
        if address in truth:
            continue
        i = bisect.bisect_right(starts, address) - 1
        interior = i >= 0 and starts[i] <= address < starts[i] + max(truth[starts[i]][0], 1)
        invented[f"{producer}/{'inside-truth-function' if interior else 'outside-truth'}"] += 1
    main_rows = {a for a in scored if truth[a][2] == "main"}
    rel_rows = scored - main_rows
    split = {}
    if main_rows and rel_rows:
        split = {"main_recall": round(len(main_rows & found.keys()) / len(main_rows), 5),
                 "rel_recall": round(len(rel_rows & found.keys()) / len(rel_rows), 5),
                 "main_rows": len(main_rows), "rel_rows": len(rel_rows)}
    return {
        **split,
        "truth": len(scored), "found": len(found), "hits": len(hits),
        "recall": round(len(hits) / len(scored), 5) if scored else None,
        "precision": round(len(hits) / len(found), 5) if found else None,
        "missed": len(scored) - len(hits), "invented": len(found) - len(hits),
        "invented_breakdown": dict(invented.most_common()),
    }


def one_run(cli: Path, image: Path, name: str, work: Path) -> tuple[Path, float, list[float], list[str]]:
    project = work / name
    shutil.rmtree(project, ignore_errors=True)
    load = list(os.getloadavg())
    started = time.monotonic()
    proc = subprocess.run(
        [str(cli), "import", str(image), "--name", name, "--project", str(project), "--timings"],
        capture_output=True, text=True, env={**os.environ, "ROMWRIGHT_NO_IMPORT_CACHE": "1"})
    seconds = time.monotonic() - started
    if proc.returncode:
        raise SystemExit(f"import of {image} failed: {proc.stderr[-400:]}")
    degraded: list[str] = []
    for line in proc.stdout.splitlines():
        if line.startswith("TIMINGS "):
            degraded = [d["message"] for d in json.loads(line[8:]).get("diagnostics", [])
                        if d.get("severity") == "degraded"]
    return project, seconds, load, degraded


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cli", action="append", required=True, metavar="LABEL=PATH")
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, default=Path.home() / "ventris-corpus" / "extracted")
    parser.add_argument("--reps", type=int, default=1)
    parser.add_argument("--module", default="main", help="truth module to score, or 'all'")
    parser.add_argument("--disc", help="image file inside the slug directory (default main.dol)")
    parser.add_argument("images", nargs="*")
    args = parser.parse_args()
    clis = [(label, Path(path)) for label, path in (item.split("=", 1) for item in args.cli)]
    args.work.mkdir(parents=True, exist_ok=True)
    rows = []
    for slug in args.images or DEFAULT_IMAGES:
        image = args.corpus / slug / (args.disc or "main.dol")
        truth = load_truth(args.corpus / slug / "truth" / "functions.tsv", args.module)
        program = None if args.module == "all" else slug
        for rep in range(args.reps):
            # Alternate the order between repetitions so neither label always runs second.
            for label, cli in (clis if rep % 2 == 0 else clis[::-1]):
                project, seconds, load, degraded = one_run(cli, image, slug if program else "disc", args.work / label)
                row = {"image": slug, "label": label, "rep": rep, "seconds": round(seconds, 1),
                       "load_1_5_15": [round(value, 2) for value in load],
                       "valid": not degraded, "degraded": degraded,
                       **score(project, slug if program else None, truth)}
                rows.append(row)
                print(json.dumps(row), flush=True)
                shutil.rmtree(project, ignore_errors=True)
    args.out.write_text(json.dumps(rows, indent=1))


if __name__ == "__main__":
    main()
