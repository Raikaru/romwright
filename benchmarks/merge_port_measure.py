#!/usr/bin/env python3
"""Stage 3 ownership measurement on the printer-differential samples (docs/merge-port.md): who decided the variables.

One default-build decompile of every sampled function of every image, with two logs on:

* `ROMWRIGHT_OWNERSHIP_LOG` (worker): per function `print.expressions.merge_functions` [functions whose merge the
  worker decided, functions the decompiler's own actions merged].
* `ROMWRIGHT_RUST_MERGE_LOG` (worker): per function `merge_ok` (what the worker's decisions were: merges, speculative
  merges, variables marked explicit and implied, inserted COPY ops, log entries, microseconds), `merge_declined` (why
  not) and `names_ok` (variables the worker named).

  merge_port_measure.py --cache CACHE --report OUT.json [--images a,b] [--chunk 25] [--jobs 4]
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


def read_lines(path: Path) -> list[dict]:
    rows = []
    if path.is_file():
        for line in path.read_text().splitlines():
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return rows


def run_chunk(worker: Path, ghidra_opt: Path, target: dict, chunk: list[str], work: Path, tag: str):
    own, merge = work / f"{tag}.own.jsonl", work / f"{tag}.merge.jsonl"
    env = dict(os.environ, ROMWRIGHT_OWNERSHIP_LOG=str(own), ROMWRIGHT_RUST_MERGE_LOG=str(merge))
    addresses = chunk if len(chunk) > 1 else chunk * 2
    argv = [str(worker), str(ghidra_opt), "auto", target["program"], *addresses, "--project", str(target["project"])]
    started = time.monotonic()
    subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, timeout=7200, env=env)
    return read_lines(own), read_lines(merge), time.monotonic() - started


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
    work = Path(tempfile.mkdtemp(prefix="merge-measure-", dir=os.environ.get("TMPDIR")))
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = {}
        for target in targets:
            chunks = [target["addresses"][i:i + args.chunk] for i in range(0, len(target["addresses"]), args.chunk)]
            futures[target["image"]] = [pool.submit(run_chunk, worker, args.ghidra_opt, target, chunk, work,
                                                    f"{target['image']}-{i}") for i, chunk in enumerate(chunks)]
        for target in targets:
            functions = [0, 0]
            did: collections.Counter = collections.Counter()
            declined: collections.Counter = collections.Counter()
            decided = 0
            names = 0
            seconds = 0.0
            micros = 0
            for future in futures[target["image"]]:
                own_rows, merge_rows, secs = future.result()
                seconds += secs
                for row in own_rows:
                    merged = ((row.get("print") or {}).get("expressions") or {}).get("merge_functions") or [0, 0]
                    functions[0] += merged[0]
                    functions[1] += merged[1]
                for row in merge_rows:
                    if "merge_ok" in row:
                        decided += 1
                        for key in ("merges", "speculative", "explicit", "implied", "new_ops", "entries"):
                            did[key] += row["merge_ok"].get(key, 0)
                        micros += row["merge_ok"].get("micros", 0)
                    elif "merge_declined" in row:
                        declined[row["merge_declined"]] += 1
                    elif "names_ok" in row:
                        names += row["names_ok"]["names"]
            summary = {
                "image": target["image"],
                "functions_logged": functions[0] + functions[1],
                "merge_functions": {"worker": functions[0], "decompiler": functions[1]},
                "decided_by_worker": decided,
                "declined": dict(declined),
                "worker_did": dict(did),
                "variables_named_by_worker": names,
                "worker_decide_microseconds": micros,
                "decompile_wall_seconds": round(seconds, 1),
                "decide_share_of_wall": round(micros / 1e6 / seconds, 4) if seconds else None,
            }
            results.append(summary)
            print(json.dumps(summary))
    totals = collections.Counter()
    for r in results:
        totals["functions"] += r["functions_logged"]
        totals["worker"] += r["merge_functions"]["worker"]
        totals["decompiler"] += r["merge_functions"]["decompiler"]
        for key, value in r["worker_did"].items():
            totals[key] += value
        totals["named"] += r["variables_named_by_worker"]
    report = {"benchmark": "merge_port_measure", "date": datetime.now(timezone.utc).date().isoformat(),
              "ghidra_opt": str(args.ghidra_opt), "totals": dict(totals), "images": results}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print("totals", dict(totals))
    return 0


if __name__ == "__main__":
    sys.exit(main())
