#!/usr/bin/env python3
"""Printed `goto`s per image: the structuring baseline every structuring pass is gated on.

Decompiles the printer-differential gate set (benchmarks/printer_diff.py: the
console-research samples plus the m15 libc functions) through
`romwright-worker` batch mode, once per IR-pass configuration, and counts the
`goto` keywords in the printed DecompDoc tokens -- the same count
`finalize_document`'s StructureGotos guard uses (`printed_gotos`, syntax or op
tokens whose text is `goto`). Configurations:

  default   ROMWRIGHT_IR_PASSES unset: additive_inverse, canonical_helpers,
            structure (cuts kept only when printed gotos strictly drop)
  ir-none   ROMWRIGHT_IR_PASSES="" (stock structuring and printing)

`--structuring MODELS` sets ROMWRIGHT_RUST_STRUCTURING (default `none`:
Ghidra's structure, printed byte-identically to PrintC; `all` is the
production default).

Usage (from the repository root):
  benchmarks/structuring_baseline.py --ghidra-opt native/build/ghidra_opt \\
      --target target/printer --report benchmarks/reports/structuring_baseline.json
"""
from __future__ import annotations

import argparse
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

CONFIGS = {"default": None, "ir-none": ""}


def run_chunk(worker: Path, ghidra_opt: Path, target: dict, chunk: list[str], passes: str | None,
              structuring: str) -> dict:
    env = dict(os.environ, WORKER_STRUCTURED="1", WORKER_DECOMPILE_TIMEOUT_SECS="0",
               ROMWRIGHT_RUST_STRUCTURING=structuring)
    env.pop("ROMWRIGHT_IR_PASSES", None)
    if passes is not None:
        env["ROMWRIGHT_IR_PASSES"] = passes
    argv = [str(worker), str(ghidra_opt), "auto", target["program"], *chunk,
            "--project", str(target["project"])]
    result = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, env=env, timeout=7200)
    if result.returncode:
        raise RuntimeError(f"{target['image']}: {result.stderr[-600:]}")
    answers = json.loads(result.stdout)
    return {address: sum(1 for token in doc["tokens"]
                         if token["kind"] in ("Syntax", "Op") and token["text"] == "goto")
            for address, doc in answers.items()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cache", type=Path, default=DIFF.CACHE)
    parser.add_argument("--images", help="comma-separated image ids (default: all)")
    parser.add_argument("--target", type=Path, default=Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target")))
    parser.add_argument("--ghidra-opt", type=Path, default=ROOT / "native/build/ghidra_opt")
    parser.add_argument("--libc", type=Path,
                        default=Path(next((c for c in DIFF.LIBC_CANDIDATES if Path(c).is_file()),
                                          DIFF.LIBC_CANDIDATES[0])))
    parser.add_argument("--libc-limit", type=int, default=200)
    parser.add_argument("--no-libc", action="store_true")
    parser.add_argument("--structuring", default="none",
                        help="ROMWRIGHT_RUST_STRUCTURING for every configuration (default: none)")
    parser.add_argument("--chunk", type=int, default=25)
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    target_dir = args.target if args.target.is_absolute() else ROOT / args.target
    worker = target_dir / "release/romwright-worker"
    wanted = set(args.images.split(",")) if args.images else None
    targets = DIFF.console_targets(args.cache, wanted)
    if not args.no_libc and (wanted is None or "x86-libc" in wanted):
        libc = DIFF.libc_target(target_dir / "release/romwright-cli", args.libc, args.libc_limit,
                                Path.home() / ".cache/romwright/printer-diff")
        if libc:
            targets.append(libc)

    images = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        jobs = {(target["image"], config): [
            pool.submit(run_chunk, worker, args.ghidra_opt, target, target["addresses"][i:i + args.chunk],
                        passes, args.structuring)
            for i in range(0, len(target["addresses"]), args.chunk)]
            for target in targets for config, passes in CONFIGS.items()}
        for target in targets:
            row = {"image": target["image"], "project": str(target["project"]),
                   "sampled": len(target["addresses"])}
            per = {}
            for config in CONFIGS:
                answers = {}
                for future in jobs[(target["image"], config)]:
                    answers.update(future.result())
                per[config] = answers
            # Count only functions every configuration decompiled.
            common = set.intersection(*(set(answers) for answers in per.values()))
            row["decompiled"] = len(common)
            row["gotos"] = {config: sum(per[config][a] for a in common) for config in CONFIGS}
            row["functions_with_gotos"] = {config: sum(1 for a in common if per[config][a])
                                           for config in CONFIGS}
            row["per_function"] = {a: {config: per[config][a] for config in CONFIGS} for a in sorted(common)}
            images.append(row)
            print(f"{row['image']:32} decompiled {row['decompiled']:4}  gotos "
                  + "  ".join(f"{config} {count}" for config, count in row["gotos"].items()))

    report = {
        "benchmark": "structuring_baseline",
        "date": datetime.now(timezone.utc).date().isoformat(),
        "commit": subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True,
                                 text=True).stdout.strip(),
        "ghidra_opt": str(args.ghidra_opt),
        "structuring": args.structuring,
        "configs": {name: passes for name, passes in CONFIGS.items()},
        "images": images,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
