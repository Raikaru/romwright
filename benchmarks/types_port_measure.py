#!/usr/bin/env python3
"""Stage 2 measurements on the printer-differential samples (docs/types-port.md): who decided the casts, and
what `ActionInferTypes` costs.

One default-build decompile of every sampled function of every image, with two logs on:

* `ROMWRIGHT_OWNERSHIP_LOG` (worker): per function `print.expressions`: `cast_functions` [functions the worker
  cast, functions the decompiler cast], what the worker's pass did (`casts` and the rest), and `native_cast_ops`,
  the `CAST` operators in the statements of the functions the decompiler cast.
* `ROMWRIGHT_INFER_LOG` (`ghidra_opt`): per function how often the mainloop ran `ActionInferTypes`, its time, and
  the size of the data-flow graph at each call (alive ops, varnodes): what a type query to the worker per
  mainloop iteration would have to carry.

  types_port_measure.py --cache CACHE --report OUT.json [--images a,b] [--chunk 25] [--jobs 4]
"""
from __future__ import annotations

import argparse
import collections
import concurrent.futures
import json
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from printer_diff import console_targets  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def run_chunk(worker: Path, ghidra_opt: Path, target: dict, chunk: list[str], work: Path, tag: str):
    own, infer = work / f"{tag}.own.jsonl", work / f"{tag}.infer.jsonl"
    env = dict(os.environ, ROMWRIGHT_OWNERSHIP_LOG=str(own), ROMWRIGHT_INFER_LOG=str(infer))
    addresses = chunk if len(chunk) > 1 else chunk * 2
    argv = [str(worker), str(ghidra_opt), "auto", target["program"], *addresses, "--project", str(target["project"])]
    started = time.monotonic()
    subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, timeout=7200, env=env)
    seconds = time.monotonic() - started
    own_rows = [json.loads(line) for line in own.read_text().splitlines()] if own.is_file() else []
    infer_rows = [json.loads(line)["infer"] for line in infer.read_text().splitlines()] if infer.is_file() else []
    return own_rows, infer_rows, seconds


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--images")
    parser.add_argument("--target", type=Path, default=Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target")))
    parser.add_argument("--ghidra-opt", type=Path, default=ROOT / "native/build/ghidra_opt")
    parser.add_argument("--chunk", type=int, default=25)
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    worker = (args.target if args.target.is_absolute() else ROOT / args.target) / "release/romwright-worker"
    targets = console_targets(args.cache, set(args.images.split(",")) if args.images else None)
    work = Path(tempfile.mkdtemp(prefix="types-measure-", dir=os.environ.get("TMPDIR")))
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = {}
        for target in targets:
            chunks = [target["addresses"][i:i + args.chunk] for i in range(0, len(target["addresses"]), args.chunk)]
            futures[target["image"]] = [pool.submit(run_chunk, worker, args.ghidra_opt, target, chunk, work,
                                                    f"{target['image']}-{i}") for i, chunk in enumerate(chunks)]
        for target in targets:
            own_rows, infer_rows, seconds = [], [], 0.0
            for future in futures[target["image"]]:
                own, infer, secs = future.result()
                own_rows += own
                infer_rows += infer
                seconds += secs
            casts = collections.Counter()
            functions = [0, 0]
            native_ops = 0
            for row in own_rows:
                expr = (row.get("print") or {}).get("expressions") or {}
                for index in (0, 1):
                    functions[index] += (expr.get("cast_functions") or [0, 0])[index]
                for key, value in (expr.get("casts") or {}).items():
                    casts[key] += value
                native_ops += expr.get("native_cast_ops") or 0
            calls = sum(r["calls"] for r in infer_rows)
            micros = sum(r["micros"] for r in infer_rows)
            summary = {
                "image": target["image"],
                "functions_logged": len(own_rows),
                "cast_functions": {"worker": functions[0], "decompiler": functions[1]},
                "worker_cast_operators": dict(casts),
                "decompiler_cast_ops_in_declined_functions": native_ops,
                "infer": {
                    "functions": len(infer_rows),
                    "calls_total": calls,
                    "calls_per_function_mean": round(calls / len(infer_rows), 2) if infer_rows else None,
                    "calls_per_function_max": max((r["calls"] for r in infer_rows), default=None),
                    "ops_per_call_mean": round(sum(r["sum_ops"] for r in infer_rows) / calls, 1) if calls else None,
                    "varnodes_per_call_mean": round(sum(r["sum_varnodes"] for r in infer_rows) / calls, 1) if calls else None,
                    "microseconds_total": micros,
                    "microseconds_per_function_mean": round(micros / len(infer_rows), 1) if infer_rows else None,
                    "decompile_wall_seconds": round(seconds, 1),
                    "infer_share_of_wall": round(micros / 1e6 / seconds, 4) if seconds else None,
                },
            }
            results.append(summary)
            print(json.dumps(summary))
    report = {"benchmark": "types_port_measure", "date": datetime.now(timezone.utc).date().isoformat(),
              "ghidra_opt": str(args.ghidra_opt), "images": results}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
