#!/usr/bin/env python3
"""PC (Windows PE / x86) function discovery against stock Ghidra, per fixture.

Discovery only (no decompilation): our `romwright-cli import` and stock `analyzeHeadless`
(`benchmarks/ghidra/ExportFunctionEntries.java`) on the staged image of every `pc-*` truth fixture
(docs/console-research.md "The truth contract"), both scored by `console_research_wave.score_found`
over the image's executable sections: the numbers `console_research.py --corpus-wave` reports for the
headline discovery columns, without its sample/export-c phases. `benchmarks/console_research.py
--corpus-wave --images pc-... --stock` is the full harness run (same truth, same stock config); this
driver is the fast loop and the source of the per-function miss/invented lists.

A no-truth image (`--no-truth NAME=PATH`, e.g. a retail game) goes through `console_research.run_no_truth`:
success, wall time, function counts, agreement of the two tools.

    CARGO_TARGET_DIR=~/runs/X/ventris/target benchmarks/pc_import.py --corpus ~/ventris-corpus/extracted \\
        --work ~/runs/X/pc-work --out benchmarks/reports/pc_import_discovery_<tag>.json [--stock] [--images ids]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import resource
import shutil
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "benchmarks"))
import console_research as CR  # noqa: E402

wave = CR.wave
log = CR.log


def cpu_seconds() -> float:
    """User + system CPU seconds of every child process that has finished so far."""
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    return usage.ru_utime + usage.ru_stime


def our_import(tools, spec: dict, binary: Path, work: Path, extra_env: dict, limit_s: int) -> dict:
    project = work / "ours" / spec["id"]
    shutil.rmtree(project, ignore_errors=True)
    project.mkdir(parents=True)
    argv = [str(tools.cli), "import", str(binary), "--name", spec["program"].split(".")[0],
            "--project", str(project), "--timings"]
    started, cpu = time.monotonic(), cpu_seconds()
    load = os.getloadavg()[0]
    result = subprocess.run(argv, capture_output=True, text=True, env=tools.env(extra_env), timeout=limit_s)
    seconds = round(time.monotonic() - started, 2)
    cpu = round(cpu_seconds() - cpu, 2)
    if result.returncode:
        return {"error": result.stderr.strip()[-800:], "seconds": seconds}
    timings = {}
    for line in result.stdout.splitlines():
        if line.startswith("TIMINGS "):
            timings = json.loads(line[len("TIMINGS "):])
    program = CR.program_name(project, spec["program"])
    db = sqlite3.connect(f"file:{project}/project.sqlite?mode=ro", uri=True)
    pid = db.execute("SELECT id FROM programs WHERE name = ?", (program,)).fetchone()[0]
    found = {}
    producers = {}
    for entry, size, producer in db.execute("SELECT entry, size, producer FROM functions WHERE program_id = ?", (pid,)):
        try:
            found[int(entry, 16)] = size
            producers[int(entry, 16)] = producer
        except ValueError:
            pass
    regions = [(int(start, 16), int(start, 16) + size) for start, size, perms in
               db.execute("SELECT start, size, permissions FROM memory_regions WHERE program_id = ?", (pid,))
               if "x" in perms]
    return {"seconds": seconds, "cpu_seconds": cpu, "load_at_start": round(load, 1), "found": found,
            "producers": producers, "executable": regions, "phases": timings.get("phases"),
            "diagnostics": timings.get("diagnostics", []), "project": str(project)}


def stock_run(args, spec: dict, binary: Path, image_sha: str, cache: Path) -> dict:
    cached = cache / "stock-discovery" / f"{spec['id']}-{image_sha[:12]}.json"
    data = CR.read_json(cached)
    if data is not None and "failure" not in data:
        return data
    config = CR.stock_config(spec)
    log(f"{spec['id']}: stock Ghidra ({config.get('language')}, loader {config.get('loader')})")
    started, cpu = time.monotonic(), cpu_seconds()
    load = os.getloadavg()[0]
    try:
        exported, _rows = CR.run_stock_headless(args.ghidra, binary, config, [], args.work / "stock" / spec["id"],
                                                spec["id"].split("-")[0], args.stock_timeout)
    except CR.StockFailure as failure:
        data = {"failure": failure.record}
        CR.write_json(cached, data)
        return data
    data = {"language": exported.get("language"), "compiler": exported.get("compiler"),
            "format": exported.get("format"), "wall_seconds": round(time.monotonic() - started, 1),
            "cpu_seconds": round(cpu_seconds() - cpu, 1), "load_at_start": round(load, 1),
            "functions": [[f["entry"], f["size"], bool(f.get("thunk"))] for f in exported["functions"]
                          if not f["overlay"]]}
    CR.write_json(cached, data)
    return data


def names_of(truth: dict, addresses) -> list[str]:
    return [f"{a:#x} {truth[a][1]}" if a in truth else f"{a:#x}" for a in addresses]


def measure(args, tools, spec: dict, corpus: Path, cache: Path) -> dict:
    binary = corpus / spec["image"]
    image_sha = CR.sha256_file(binary)
    kind, rel = spec["truth"]
    modules = wave.load_modules(corpus / rel)
    main = modules[wave.MAIN]
    row = {"id": spec["id"], "image": spec["image"], "sha256": image_sha, "truth_functions": len(main["truth"])}
    ranges = spec["ranges"]
    arms = {}
    if "ours" in args.arms:
        log(f"{spec['id']}: our import")
        ours = our_import(tools, spec, binary, args.work, json.loads(args.env or "{}"), args.import_limit_s)
        if "error" in ours:
            arms["ours"] = ours
        else:
            rng = ranges or ours["executable"]
            score = wave.score_found(ours["found"], main["truth"], main["verified"], rng)
            prod = ours["producers"]
            inside = lambda a: any(lo <= a < hi for lo, hi in rng)  # noqa: E731
            by_producer = {}
            for a, name in prod.items():
                if inside(a):
                    cell = by_producer.setdefault(name, {"hits": 0, "invented": 0})
                    cell["hits" if a in main["truth"] else "invented"] += 1
            arms["ours"] = {"seconds": ours["seconds"], "cpu_seconds": ours["cpu_seconds"],
                            "load_at_start": ours["load_at_start"], "score": score, "phases": ours["phases"],
                            "by_producer": by_producer, "project": ours["project"],
                            "invented_producers": {f"{a:#x}": prod[a] for a in sorted(prod)
                                                   if inside(a) and a not in main["truth"]},
                            "diagnostics": ours["diagnostics"],
                            "missed": names_of(main["truth"], sorted(set(a for a in main["truth"] if any(
                                lo <= a < hi for lo, hi in rng)) - set(ours["found"]))),
                            "invented": names_of(main["truth"], sorted(a for a in ours["found"]
                                                                       if a not in main["truth"]
                                                                       and any(lo <= a < hi for lo, hi in rng)))}
    if "stock" in args.arms:
        stock = stock_run(args, spec, binary, image_sha, cache)
        if "failure" in stock:
            arms["stock"] = stock
        else:
            found = {entry: size for entry, size, _thunk in stock["functions"]}
            rng = ranges
            score = wave.score_found(found, main["truth"], main["verified"], rng)
            arms["stock"] = {"seconds": stock["wall_seconds"], "cpu_seconds": stock.get("cpu_seconds"),
                             "load_at_start": stock.get("load_at_start"), "score": score,
                             "ghidra_language": stock["language"], "ghidra_compiler": stock["compiler"],
                             "missed": names_of(main["truth"], sorted(set(a for a in main["truth"] if any(
                                 lo <= a < hi for lo, hi in rng)) - set(found))),
                             "invented": names_of(main["truth"], sorted(a for a in found if a not in main["truth"]
                                                                        and any(lo <= a < hi for lo, hi in rng)))}
    row["arms"] = arms
    return row


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--corpus", type=Path, default=Path.home() / "ventris-corpus" / "extracted")
    p.add_argument("--work", type=Path, required=True)
    p.add_argument("--cache", type=Path, default=Path.home() / ".cache" / "romwright" / "pc-import")
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--images", default="", help="comma-separated fixture ids (default: every pc-*)")
    p.add_argument("--arms", default="ours,stock")
    p.add_argument("--env", default="", help="JSON object: extra ROMWRIGHT_* for our import (a leave-one-out arm)")
    p.add_argument("--no-truth", action="append", default=[], metavar="NAME=PATH")
    p.add_argument("--ghidra", type=Path, default=Path.home() / "ghidra_12.1.3_PUBLIC")
    p.add_argument("--stock-timeout", type=int, default=3600)
    p.add_argument("--import-limit-s", type=int, default=3600)
    args = p.parse_args()
    args.arms = set(args.arms.split(","))
    args.work.mkdir(parents=True, exist_ok=True)
    tools = CR.Tools(CR.TARGET)
    wanted = {w for w in args.images.split(",") if w}
    specs, skipped = wave.discover(args.corpus, wanted, 0.0)
    specs = [s for s in specs if s["id"].startswith("pc-")]
    rows = [measure(args, tools, spec, args.corpus, args.cache) for spec in specs]
    for item in args.no_truth:
        name, path = item.split("=", 1)
        args.stock = "stock" in args.arms
        args.stock_work = args.work / "stock"
        rows.append(CR.run_no_truth(args, tools, args.cache, name, Path(path).expanduser()))
    report = {"tools": tools.fingerprint, "env": json.loads(args.env or "{}"), "rows": rows, "skipped": skipped}
    CR.write_json(args.out, report)
    for row in rows:
        if "arms" not in row:
            print(json.dumps({k: row[k] for k in ("id", "import", "decompile", "stock") if k in row}))
            continue
        line = [row["id"]]
        for arm, value in row["arms"].items():
            score = value.get("score")
            if score:
                line.append(f"{arm}: recall {score['recall']} precision {score['precision']} "
                            f"(verified {score['recall_verified']}/{score['precision_verified']}) {value['seconds']}s")
            else:
                line.append(f"{arm}: {value.get('error') or value.get('failure') or value}")
        print(" | ".join(str(x) for x in line))
    return 0


if __name__ == "__main__":
    sys.exit(main())
