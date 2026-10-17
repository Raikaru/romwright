#!/usr/bin/env python3
"""Merge verify over imported projects (docs/merge-port.md, stage 3).

For every address of a wave (`benchmarks/ps2_decompile_success.py` format: `{"images": {name: {"configs":
{"default": {"results_file": rows.json}}}}}`, each rows file `{"project": dir, "functions": [{"address": "0x..."}]}`)
the worker decompiles the function with `ROMWRIGHT_RUST_MERGE=verify`: `ghidra_opt` runs the decompiler's own
merge actions, the worker decides the same function from the same p-code, and the two final states are
compared (the variable partition, explicit/implied marks, inserted COPY ops, non-printing ops, for-loop
records). `ROMWRIGHT_RUST_MERGE_LOG` gives per function `merge_verified`, `merge_mismatch` (with the first
differences) or `merge_declined` (with the reason).

Usage (on nih-vps-u, in a tree whose release build and `ghidra_opt` are current):
  benchmarks/merge_verify.py --wave ~/runs/Stage3/succ-t2/wave.json --bin ~/runs/Stage3/bin-final \
      --report benchmarks/reports/merge_verify_stage3_<date>.json
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
from datetime import datetime, timezone
from pathlib import Path


def run_chunk(binary: Path, project: Path, program: str, chunk: list[str], work: Path, tag: str):
    log = work / f"{tag}.log"
    log.unlink(missing_ok=True)
    env = dict(os.environ, ROMWRIGHT_RUST_MERGE="verify", ROMWRIGHT_RUST_MERGE_LOG=str(log))
    argv = [str(binary / "romwright-worker"), str(binary / "ghidra_opt"), "auto", program, *chunk,
            "--project", str(project)]
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=1800, env=env)
        failed = result.returncode != 0
        err = result.stderr[-300:]
    except subprocess.TimeoutExpired:
        failed, err = True, "timeout"
    rows = []
    if log.is_file():
        for line in log.read_text().splitlines():
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return rows, failed, err


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--wave", type=Path, required=True)
    parser.add_argument("--bin", type=Path, required=True)
    parser.add_argument("--chunk", type=int, default=40)
    parser.add_argument("--jobs", type=int, default=6)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    wave = json.loads(args.wave.read_text())
    work = Path(tempfile.mkdtemp(prefix="merge-verify-", dir=os.environ.get("TMPDIR")))
    summary = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = {}
        for image, entry in wave["images"].items():
            rows = json.loads(Path(entry["configs"]["default"]["results_file"]).read_text())
            project = Path(rows["project"])
            program = json.loads((project / "done.json").read_text())["program"]
            addresses = [row["address"] for row in rows["functions"]]
            futures[image] = [
                pool.submit(run_chunk, args.bin, project, program, addresses[i:i + args.chunk], work, f"{image}-{i}")
                for i in range(0, len(addresses), args.chunk)
            ]
        for image, jobs in futures.items():
            counts: collections.Counter = collections.Counter()
            examples, failures = [], []
            for job in jobs:
                rows, failed, err = job.result()
                if failed:
                    failures.append(err)
                for row in rows:
                    if "merge_verified" in row:
                        counts["verified"] += 1
                    elif "merge_mismatch" in row:
                        counts["mismatch"] += 1
                        if len(examples) < 10:
                            examples.append(row["merge_mismatch"])
                    elif "merge_declined" in row:
                        counts["declined"] += 1
                        counts["reason:" + row["merge_declined"].split(":")[0] + ":" + row["merge_declined"].split(":")[1]] += 1
                    elif "merge_ok" in row:
                        counts["worker_decided"] += 1
                    elif "names_ok" in row:
                        counts["names_functions"] += 1
                        counts["names"] += row["names_ok"]["names"]
            summary[image] = {
                "decided": counts["worker_decided"],
                "verified": counts["verified"],
                "mismatch": counts["mismatch"],
                "declined": counts["declined"],
                "decline_reasons": {k[7:]: v for k, v in counts.items() if k.startswith("reason:")},
                "chunk_failures": failures[:3],
                "examples": examples,
            }
            print(f"{image:32} decided {counts['worker_decided']:5} verified {counts['verified']:5} "
                  f"mismatch {counts['mismatch']:3} declined {counts['declined']:3} chunk-failures {len(failures)}")
    totals = {key: sum(row[key] for row in summary.values()) for key in ("decided", "verified", "mismatch", "declined")}
    report = {"benchmark": "merge_verify", "date": datetime.now(timezone.utc).date().isoformat(),
              "bin": str(args.bin), "totals": totals, "images": summary}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print("totals", totals, "->", args.report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
