#!/usr/bin/env python3
"""Printed gotos and labels per structuring model (crates/romwright-worker/src/printc/structure.rs).

Decompiles the structuring gate set (benchmarks/structuring_baseline.py: the
console-research samples plus the m15 libc functions) through
`romwright-worker` batch mode (the Rust printer, docs/printer-ir.md) once
per configuration:

  baseline           ROMWRIGHT_RUST_STRUCTURING=none: Ghidra's structure,
                     printed byte-identically to PrintC
  <model>            that model alone
  all                every model, in the order structure.rs runs them
  NAME=VALUE         `--config`: any other ROMWRIGHT_RUST_STRUCTURING value,
                     e.g. `b8=all,budget=8` (repeatable)

and counts, from the printed DecompDoc tokens, `goto` keywords (the count the
StructureGotos guard uses), label definitions (a Label token followed by
`:`), non-blank printed lines and lines ending in `;` (statements; copies
grow both). A function regresses when a configuration prints more gotos
than the baseline; the models' own guard means there should be none. The
`remaining.<cause>/<tail>` stats classify the gotos a configuration still
prints (structure.rs `classify`), from the worker's structuring log line
for the printed render. With `--dump DIR` the C text of every function is
written per configuration for the compile check
(benchmarks/structuring_compile.py).

Usage (from the repository root):
  native/build_ghidra_opt.sh /tmp/rw-structmodels-build
  CARGO_TARGET_DIR=target/structmodels cargo build --release -p romwright-worker -p romwright-cli
  benchmarks/structuring_models.py --ghidra-opt /tmp/rw-structmodels-build/ghidra_opt \\
      --target target/structmodels --report benchmarks/reports/structuring_models.json
"""
from __future__ import annotations

import argparse
import collections
import concurrent.futures
import importlib.util
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("printer_diff", ROOT / "benchmarks/printer_diff.py")
DIFF = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(DIFF)

MODELS = ["break_continue", "collapsed_edges", "else_join", "switch_tails", "loop_exits",
          "irreducible_entry", "sink_join"]
CONFIGS = {"baseline": "none", **{model: model for model in MODELS}, "all": "all"}


def count(tokens: list[dict]) -> tuple[int, int]:
    gotos = sum(1 for token in tokens if token["kind"] in ("Syntax", "Op") and token["text"] == "goto")
    labels = 0
    for position, token in enumerate(tokens):
        if token["kind"] != "Label":
            continue
        following = next((t["text"] for t in tokens[position + 1:] if t["text"]), "")
        if following == ":":
            labels += 1
    return gotos, labels


def text(tokens: list[dict]) -> str:
    return "".join("\n" + " " * (token["indent"] or 0) if token["kind"] == "Break" else token["text"]
                   for token in tokens)


def run_chunk(worker: Path, ghidra_opt: Path, target: dict, chunk: list[str], models: str,
              passes: str | None, dump: bool) -> tuple[dict, collections.Counter]:
    env = dict(os.environ, WORKER_STRUCTURED="1", WORKER_DECOMPILE_TIMEOUT_SECS="0",
               ROMWRIGHT_RUST_STRUCTURING=models, ROMWRIGHT_RUST_STRUCTURING_LOG="1")
    env.pop("ROMWRIGHT_IR_PASSES", None)
    if passes is not None:
        env["ROMWRIGHT_IR_PASSES"] = passes
    argv = [str(worker), str(ghidra_opt), "auto", target["program"], *chunk,
            "--project", str(target["project"])]
    result = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, env=env, timeout=7200)
    if result.returncode:
        raise RuntimeError(f"{target['image']}: {result.stderr[-600:]}")
    answers = json.loads(result.stdout)
    if len(chunk) == 1 and "tokens" in answers:
        answers = {chunk[0]: answers}
    stats = collections.Counter()
    renders = collections.defaultdict(list)
    for line in result.stderr.splitlines():
        if line.startswith('{"structuring"'):
            entry = json.loads(line)["structuring"]
            renders[entry.get("function")].append(entry)
            stats["functions"] += 1
            if entry.get("refused"):
                stats["refused"] += 1
            for model, applied in entry.get("applied", {}).items():
                stats[f"applied.{model}"] += applied
    rows = {}
    for address, doc in answers.items():
        gotos, labels = count(doc["tokens"])
        body = text(doc["tokens"])
        lines = [line.strip() for line in body.splitlines() if line.strip()]
        rows[address] = {"gotos": gotos, "labels": labels, "lines": len(lines),
                         "statements": sum(line.endswith(";") for line in lines)}
        # The worker can render a function more than once (with and without
        # the IR passes' forced cuts); the printed one is the last render of
        # that name with the printed goto count.
        name = next((token["text"] for token in doc["tokens"] if token["kind"] == "FuncName"), None)
        final = next((entry for entry in reversed(renders.get(name, []))
                      if entry["after"][0] == gotos), None)
        remaining = (final or {}).get("remaining", {})
        for cause, left in remaining.items():
            stats[f"remaining.{cause}"] += left
        if remaining:
            rows[address]["remaining"] = remaining
        if final and final.get("attempts", 0) >= 4000:
            stats["exhausted"] += 1
            rows[address].setdefault("remaining", {})["exhausted"] = 1
        if dump:
            rows[address]["text"] = body
    return rows, stats


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cache", type=Path, default=DIFF.CACHE)
    parser.add_argument("--images", help="comma-separated image ids (default: all)")
    parser.add_argument("--configs", help="comma-separated configurations (default: all)")
    parser.add_argument("--config", action="append", default=[], metavar="NAME=MODELS",
                        help="an extra configuration: ROMWRIGHT_RUST_STRUCTURING=MODELS (repeatable)")
    parser.add_argument("--target", type=Path, default=Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target")))
    parser.add_argument("--ghidra-opt", type=Path, required=True)
    parser.add_argument("--ir-passes", help="ROMWRIGHT_IR_PASSES for every run (default: unset)")
    parser.add_argument("--libc", type=Path,
                        default=Path(next((c for c in DIFF.LIBC_CANDIDATES if Path(c).is_file()),
                                          DIFF.LIBC_CANDIDATES[0])))
    parser.add_argument("--libc-limit", type=int, default=200)
    parser.add_argument("--no-libc", action="store_true")
    parser.add_argument("--chunk", type=int, default=25)
    parser.add_argument("--jobs", type=int, default=6)
    parser.add_argument("--dump", type=Path, help="write each function's C text per configuration here")
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    target_dir = args.target if args.target.is_absolute() else ROOT / args.target
    worker = target_dir / "release/romwright-worker"
    extra = dict(spec.split("=", 1) for spec in args.config)
    known = {**CONFIGS, **extra}
    names = args.configs.split(",") if args.configs else list(CONFIGS)
    configs = {name: known[name] for name in names}
    configs.update(extra)
    if "baseline" not in configs:
        configs = {"baseline": CONFIGS["baseline"], **configs}
    wanted = set(args.images.split(",")) if args.images else None
    targets = DIFF.console_targets(args.cache, wanted)
    if not args.no_libc and (wanted is None or "x86-libc" in wanted):
        libc = DIFF.libc_target(target_dir / "release/romwright-cli", args.libc, args.libc_limit,
                                Path.home() / ".cache/romwright/printer-diff")
        if libc:
            targets.append(libc)

    images = []
    totals = {config: collections.Counter() for config in configs}
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        jobs = {(target["image"], config): [
            pool.submit(run_chunk, worker, args.ghidra_opt, target, target["addresses"][i:i + args.chunk],
                        models, args.ir_passes, args.dump is not None)
            for i in range(0, len(target["addresses"]), args.chunk)]
            for target in targets for config, models in configs.items()}
        for target in targets:
            per, stats = {}, {}
            for config in configs:
                rows, counter = {}, collections.Counter()
                for future in jobs[(target["image"], config)]:
                    chunk_rows, chunk_stats = future.result()
                    rows.update(chunk_rows)
                    counter.update(chunk_stats)
                per[config], stats[config] = rows, counter
            common = sorted(set.intersection(*(set(rows) for rows in per.values())))
            row = {"image": target["image"], "decompiled": len(common), "configs": {}}
            for config in configs:
                gotos = sum(per[config][a]["gotos"] for a in common)
                labels = sum(per[config][a]["labels"] for a in common)
                lines = sum(per[config][a]["lines"] for a in common)
                statements = sum(per[config][a]["statements"] for a in common)
                worse = [a for a in common if per[config][a]["gotos"] > per["baseline"][a]["gotos"]]
                better = [a for a in common if per[config][a]["gotos"] < per["baseline"][a]["gotos"]]
                row["configs"][config] = {"gotos": gotos, "labels": labels, "lines": lines,
                                          "statements": statements,
                                          "functions_better": len(better), "functions_worse": len(worse),
                                          "worse": worse, "stats": dict(stats[config])}
                totals[config].update({"gotos": gotos, "labels": labels, "lines": lines,
                                       "statements": statements, "better": len(better),
                                       "worse": len(worse), "functions": len(common)})
                totals[config].update({key: value for key, value in stats[config].items()
                                       if key.startswith(("remaining.", "applied.", "refused", "exhausted"))})
            row["per_function"] = {a: {config: [per[config][a]["gotos"], per[config][a]["labels"],
                                                per[config][a]["lines"], per[config][a].get("remaining", {})]
                                       for config in configs} for a in common}
            images.append(row)
            print(f"{row['image']:32} " + "  ".join(
                f"{config} {c['gotos']}/{c['labels']}/{c['lines']}" for config, c in row["configs"].items()),
                flush=True)
            if args.dump:
                for config in configs:
                    out = args.dump / config
                    out.mkdir(parents=True, exist_ok=True)
                    (out / f"{target['image']}.json").write_text(json.dumps(
                        {a: per[config][a]["text"] for a in common}))
    for config, total in totals.items():
        print(f"total {config:18} gotos {total['gotos']:5} labels {total['labels']:5} "
              f"lines {total['lines']:6} statements {total['statements']:6} "
              f"better {total['better']:4} worse {total['worse']}")

    report = {
        "benchmark": "structuring_models",
        "date": datetime.now(timezone.utc).date().isoformat(),
        "commit": subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True,
                                 text=True).stdout.strip(),
        "ghidra_opt": str(args.ghidra_opt),
        "ir_passes": args.ir_passes,
        "configs": configs,
        "totals": {config: dict(total) for config, total in totals.items()},
        "images": images,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
