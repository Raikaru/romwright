#!/usr/bin/env python3
"""Build the universal fact pack from the corpus's decomp games.

For every donor in donors.json (all 48 decomp games, whatever their license: the pack holds facts only,
each carrying its donor's repo, commit and license; dropping a donor is a rebuild without it) this
driver

  1. finds the game's default cached import (benchmarks/fact_pack/units.py: the research harness's
     cache, read through a work cache of symlinks, never written),
  2. maps each truth module to the program wave_units placed it in (console_research.wave_units),
  3. copies the project (`facts add-donor` opens it read-write), writes the per-program truth TSV,
  4. calls `romwright facts add-donor --pack P --project <copy> --program <p> --truth <tsv>
     --donor <json> [--prototypes ~/romwright-scratch/factpack/prototypes/<game>.tsv]`.

It then writes `<pack>.manifest.json`: tools fingerprint, per-donor counts (truth rows, programs,
unplaced modules, bodies and prototypes the pack ended up holding) and the pack's own meta.
The pack is a build product (default ~/runs/FactEval/fact-pack.sqlite); it is never committed.

  python3 benchmarks/fact_pack/build_pack.py --cli <romwright-cli> [--games a,b] [--pack P]

A full build starts from an empty pack. With --games the donors are added to the existing pack (a
game already in it is skipped, so a half-finished build resumes).
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import units  # noqa: E402

RUNS = Path.home() / "runs" / "FactEval"
PROTOTYPES = Path.home() / "romwright-scratch" / "factpack" / "prototypes"


def log(message: str) -> None:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}", file=sys.stderr, flush=True)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def load_donors(path: Path) -> list[dict]:
    return json.loads(path.read_text())["donors"]


def pack_counts(pack: Path) -> dict:
    """What the pack holds per donor and overall (read directly; tables are the contract's)."""
    db = sqlite3.connect(f"file:{pack}?mode=ro", uri=True)
    try:
        games = dict(db.execute("SELECT id, game FROM donors"))
        per = {game: {"bodies": 0, "named_bodies": 0, "prototypes": 0} for game in games.values()}
        for donor, bodies, named in db.execute("SELECT donor, COUNT(*), COUNT(name) FROM bodies GROUP BY donor"):
            per[games[donor]].update(bodies=bodies, named_bodies=named)
        try:
            for donor, count in db.execute("SELECT donor, COUNT(*) FROM prototypes GROUP BY donor"):
                per[games[donor]]["prototypes"] = count
        except sqlite3.OperationalError:
            pass
        return {"meta": dict(db.execute("SELECT key, value FROM meta")),
                "user_version": db.execute("PRAGMA user_version").fetchone()[0], "donors": per}
    finally:
        db.close()


def parse_json_line(text: str):
    """`facts add-donor --json` prints one JSON object; anything else is kept as text."""
    try:
        return json.loads(text.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return text.strip()[-400:]


def add_game(donor: dict, args, lock: threading.Lock) -> dict:
    game = donor["game"]
    row = {"game": game, "license": donor["license"], "repo": donor["repo"], "commit": donor["commit"]}
    work = args.work / game
    started = time.monotonic()
    resolved = units.game_units(game, args.corpus, args.cache, work, args.fingerprint, jobs=1)
    if "error" in resolved:
        row.update(status="skipped", reason=resolved["error"])
        return row
    row.update(project=resolved["project"], project_fingerprint=resolved["fingerprint"],
               unresolved=resolved["unresolved"], warnings=resolved["warnings"],
               modules=resolved["modules"], programs=[])
    prototypes = args.prototypes / f"{game}.tsv"
    donor_file = work / "donor.json"
    donor_file.parent.mkdir(parents=True, exist_ok=True)
    donor_file.write_text(json.dumps(donor))
    copies: dict[str, Path] = {}
    added = 0
    try:
        for index, unit in enumerate(resolved["units"]):
            copy = copies.get(unit["project"])
            if copy is None:
                copy = copies[unit["project"]] = units.copy_project(
                    unit["project"], work / f"p{len(copies)}-{Path(unit['project']).name[:60]}")
            tsv = work / f"truth-{index}.tsv"
            rows = units.write_truth_tsv(tsv, unit)
            argv = [str(args.cli), "facts", "add-donor", "--pack", str(args.pack), "--project", str(copy),
                    "--program", unit["program"], "--truth", str(tsv), "--donor", str(donor_file), "--json"]
            if index == 0 and prototypes.is_file():
                argv += ["--prototypes", str(prototypes)]
            with lock:  # one writer on the pack
                result = subprocess.run(argv, capture_output=True, text=True, timeout=args.timeout, env=args.env)
            program = {"program": unit["program"], "modules": unit["modules"], "truth_rows": rows,
                       "prototypes_file": str(prototypes) if index == 0 and prototypes.is_file() else None}
            if result.returncode:
                program.update(status="error", reason=result.stderr.strip()[-600:])
            else:
                program.update(status="ok", result=parse_json_line(result.stdout))
                added += 1
            row["programs"].append(program)
    except (subprocess.SubprocessError, OSError) as error:
        row.update(status="error", reason=str(error)[-400:])
        return row
    finally:
        shutil.rmtree(work, ignore_errors=True)
    row["seconds"] = round(time.monotonic() - started, 1)
    row["status"] = "ok" if added and all(p["status"] == "ok" for p in row["programs"]) else "error"
    if row["status"] != "ok":
        row["reason"] = "; ".join(p.get("reason", "") for p in row["programs"] if p["status"] != "ok") or "no program unit"
    return row


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cli", type=Path, required=True, help="romwright-cli with `facts add-donor`")
    parser.add_argument("--pack", type=Path, default=RUNS / "fact-pack.sqlite")
    parser.add_argument("--donors", type=Path, default=HERE / "donors.json")
    parser.add_argument("--games", default="", help="comma-separated donor games (default: all)")
    parser.add_argument("--corpus", type=Path, default=units.CORPUS)
    parser.add_argument("--cache", type=Path, default=units.CACHE)
    parser.add_argument("--prototypes", type=Path, default=PROTOTYPES, help="directory of <game>.tsv prototype tables")
    parser.add_argument("--work", type=Path, default=RUNS / "build-work")
    parser.add_argument("--fingerprint", default=None, help="prefer the cached projects of this tool fingerprint")
    parser.add_argument("--ghidra", type=Path, default=Path.home() / "ghidra_12.1.3_PUBLIC")
    parser.add_argument("--ghidra-opt", type=Path, default=HERE.parents[1] / "native" / "build" / "ghidra_opt")
    parser.add_argument("--worker", type=Path, default=None, help="romwright-worker (default: beside --cli)")
    parser.add_argument("--jobs", type=int, default=3, help="donors prepared concurrently (pack writes are serial)")
    parser.add_argument("--timeout", type=int, default=3600, help="seconds per `facts add-donor`")
    args = parser.parse_args()

    args.env = units.tool_env(args.cli, args.ghidra, args.ghidra_opt, args.worker)
    donors = load_donors(args.donors)
    wanted = [g for g in args.games.split(",") if g]
    unknown = set(wanted) - {d["game"] for d in donors}
    if unknown:
        parser.error(f"not in {args.donors.name}: {sorted(unknown)}")
    selected = [d for d in donors if not wanted or d["game"] in wanted]
    args.pack.parent.mkdir(parents=True, exist_ok=True)
    if not wanted:
        for suffix in ("", "-wal", "-shm", "-journal"):
            Path(str(args.pack) + suffix).unlink(missing_ok=True)
    elif args.pack.exists():
        present = set(pack_counts(args.pack)["donors"])
        for d in selected:
            if d["game"] in present:
                log(f"{d['game']}: already in the pack, skipped")
        selected = [d for d in selected if d["game"] not in present]
    log(f"cli {sha256_file(args.cli)[:16]}: {len(selected)} donors -> {args.pack}")

    lock = threading.Lock()
    rows = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        for row in pool.map(lambda d: add_game(d, args, lock), selected):
            log(f"{row['game']}: {row['status']}" + (f" ({row.get('reason', '')[:160]})" if row["status"] != "ok" else
                                                      f" in {row['seconds']}s"))
            rows.append(row)

    counts = pack_counts(args.pack) if args.pack.exists() else {"meta": {}, "user_version": None, "donors": {}}
    for row in rows:
        row["pack"] = counts["donors"].get(row["game"])
    manifest = {"built": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "cli": str(args.cli), "cli_sha256_16": sha256_file(args.cli)[:16],
                "pack": str(args.pack), "pack_bytes": args.pack.stat().st_size if args.pack.exists() else None,
                "pack_sha256_16": sha256_file(args.pack)[:16] if args.pack.exists() else None,
                "format": counts["user_version"], "meta": counts["meta"],
                "licenses": {license_: sum(1 for d in selected if d["license"] == license_)
                             for license_ in sorted({d["license"] for d in selected})},
                "donors": rows}
    manifest_path = args.pack.with_suffix(".manifest.json")
    manifest_path.write_text(json.dumps(manifest, indent=1) + "\n")
    failed = [r["game"] for r in rows if r["status"] != "ok"]
    log(f"manifest {manifest_path}; {len(rows) - len(failed)} ok, failed/skipped: {failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
