#!/usr/bin/env python3
"""PS2 decompile success on the wave's own samples, for one build of the tools.

Takes the sampled function addresses of every PS2 row in a console-research
wave report (`images.<game>.configs.default.results_file`), copies the cached
project the wave decompiled against (the cache itself is never written to),
runs `export-c --address` for each address with the given binaries, and writes
per-game success and the failure classes. Run it once per build (before,
after) and compare the two reports with `--compare`.

    python3 benchmarks/ps2_decompile_success.py --wave REPORT.json \
        --bin DIR --work DIR --out OUT.json [--games a,b] [--jobs 4]
    python3 benchmarks/ps2_decompile_success.py --compare BEFORE.json AFTER.json

`--bin` holds romwright-cli, romwright-worker and ghidra_opt. Nothing here
decides what is sampled: the addresses are the wave's.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

CACHE = Path(os.environ.get("ROMWRIGHT_RESEARCH_CACHE") or Path.home() / ".cache" / "romwright" / "research-eval")


def failure_class(message: str) -> str:
    message = message.strip().splitlines()[-1] if message.strip() else "no output"
    message = re.sub(r"^error:\s*(native:\s*)?", "", message)
    message = re.sub(r"\b(DAT|LAB|FUN|PTR|s)_[0-9a-fA-F]+\b", r"\1_X", message)
    message = re.sub(r"partial access to \S+", "partial access to X", message)
    message = re.sub(r"0x[0-9a-fA-F]+|\b\d+\b", "N", message)
    return message[:120]


def decompile(cli: Path, env: dict, project: Path, binary: str, program: str, address: int, timeout: int):
    with tempfile.TemporaryDirectory(prefix="ps2-success-") as temporary:
        out = Path(temporary) / "out"
        argv = [str(cli), "export-c", binary, program, str(out), "--address", f"{address:x}", "--project", str(project)]
        started = time.monotonic()
        try:
            result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env=env)
            code, stdout, stderr = result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            code, stdout, stderr = -9, "", f"timeout after {timeout}s"
        seconds = round(time.monotonic() - started, 2)
        files = sorted(out.glob("*.c")) if out.exists() else []
        if code != 0 or not files:
            return {"address": f"{address:08x}", "success": False, "seconds": seconds,
                    "error": (stderr or stdout)[-400:], "class": failure_class(stderr or stdout)}
        return {"address": f"{address:08x}", "success": True, "seconds": seconds}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--wave", type=Path)
    parser.add_argument("--bin", type=Path)
    parser.add_argument("--work", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--games", default="")
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument("--compare", nargs=2, type=Path, metavar=("BEFORE", "AFTER"))
    args = parser.parse_args()
    if args.compare:
        return compare(*args.compare)
    if not (args.wave and args.bin and args.work and args.out):
        parser.error("--wave, --bin, --work and --out are required")
    wave = json.loads(args.wave.read_text())
    wanted = set(filter(None, args.games.split(",")))
    cli = args.bin / "romwright-cli"
    # ROMWRIGHT_STRUCTS is the one setting a run may carry in: it selects the struct layer under test.
    env = {k: v for k, v in os.environ.items() if not k.startswith("ROMWRIGHT_") or k == "ROMWRIGHT_STRUCTS"}
    env.update(ROMWRIGHT_WORKER=str(args.bin / "romwright-worker"), ROMWRIGHT_GHIDRA_OPT=str(args.bin / "ghidra_opt"),
               ROMWRIGHT_NO_IMPORT_CACHE="1", ROMWRIGHT_NO_FACT_PACK="1")
    args.work.mkdir(parents=True, exist_ok=True)
    report = {"wave": str(args.wave), "bin": str(args.bin), "games": {}}
    for game, image in wave["images"].items():
        if not game.startswith("ps2-") or (wanted and game not in wanted):
            continue
        config = image["configs"]["default"]
        rows = json.loads(Path(config["results_file"]).read_text())
        # A wave row of an overlay module names its unit; that unit is a project of its own.
        projects = {None: Path(rows["project"])}
        for module, name in rows["key"].get("units", []):
            if name:
                projects[module] = CACHE / "projects" / name
        work = []
        for row in rows["functions"]:
            source = projects[row.get("module")]
            done = json.loads((source / "done.json").read_text())
            project = args.work / source.name
            if not project.exists():
                shutil.copytree(source, project)
            work.append((project, done["binary"], done["program"], int(row["address"], 16)))
        print(f"{game}: {len(work)} functions", file=sys.stderr, flush=True)
        started = time.monotonic()
        with ThreadPoolExecutor(max_workers=args.jobs) as pool:
            results = list(pool.map(lambda item: decompile(cli, env, item[0], item[1], item[2], item[3], args.timeout), work))
        failures = [r for r in results if not r["success"]]
        classes: dict[str, int] = {}
        for failure in failures:
            classes[failure["class"]] = classes.get(failure["class"], 0) + 1
        report["games"][game] = {
            "sampled": len(results), "decompiled": len(results) - len(failures),
            "success_rate": round((len(results) - len(failures)) / max(1, len(results)), 4),
            "wave_success_rate": config["summary"]["success_rate"], "classes": classes,
            "failures": failures, "wall_seconds": round(time.monotonic() - started, 1)}
        print(f"  {report['games'][game]['decompiled']}/{len(results)} {classes}", file=sys.stderr, flush=True)
    args.out.write_text(json.dumps(report, indent=1))
    return 0


def compare(before: Path, after: Path) -> int:
    b, a = json.loads(before.read_text())["games"], json.loads(after.read_text())["games"]
    print("| game | sampled | before | after | failures before -> after |\n|---|---|---|---|---|")
    totals = [0, 0, 0]
    for game in sorted(set(b) & set(a)):
        x, y = b[game], a[game]
        totals[0] += y["sampled"]
        totals[1] += x["decompiled"]
        totals[2] += y["decompiled"]
        print(f"| {game} | {y['sampled']} | {x['success_rate']:.4f} ({x['decompiled']}) | {y['success_rate']:.4f} ({y['decompiled']}) "
              f"| {x['sampled'] - x['decompiled']} -> {y['sampled'] - y['decompiled']} |")
    print(f"| all | {totals[0]} | {totals[1] / totals[0]:.4f} ({totals[1]}) | {totals[2] / totals[0]:.4f} ({totals[2]}) "
          f"| {totals[0] - totals[1]} -> {totals[0] - totals[2]} |")
    return 0


if __name__ == "__main__":
    sys.exit(main())
