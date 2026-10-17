#!/usr/bin/env python3
"""Merge differential (docs/merge-port.md, stage 3): the worker's merge decisions against the decompiler's merge actions.

For every function of the printer-differential samples (the console-research projects and addresses,
`benchmarks/printer_diff.py`), the same worker decompiles the function twice: default (the worker decides the
merge of the functions it accepts, `ghidra_opt` runs its own merge actions for the others) and with
`ROMWRIGHT_NATIVE_MERGE=1` (the decompiler's merge actions for every function: the previous default). The printed
C is compared function by function; a third run in `ROMWRIGHT_RUST_MERGE=verify` mode (the decompiler merges,
the worker decides the same function and compares its decisions with the decompiler's final state: the variable
partition, explicit/implied marks, inserted ops, non-printing ops, for-loop records) lists the functions whose
decisions differ.

Per function: `identical` (same C text), or `different` (first differing line). `ROMWRIGHT_RUST_MERGE_LOG` of
the default run lists, per function, whether the worker decided it (`merge_ok`, with what it did) or why it
declined (`merge_declined`).

Usage (on nih-vps-u, in a source tree whose release build and `ghidra_opt` are current):
  source ~/runs/Stage3/env.sh
  benchmarks/merge_diff.py --cache ~/runs/Stage3/cache --report benchmarks/reports/merge_diff_stage3_<date>.json
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

sys.path.insert(0, str(Path(__file__).resolve().parent))
from printer_diff import console_targets  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def run_arm(worker: Path, ghidra_opt: Path, target: dict, chunk: list[str], env_extra: dict, log: Path | None):
    env = dict(os.environ, **env_extra)
    if log is not None:
        env["ROMWRIGHT_RUST_MERGE_LOG"] = str(log)
    # A single address answers as plain text, several as one JSON object.
    argv = [str(worker), str(ghidra_opt), "auto", target["program"], *chunk,
            "--project", str(target["project"])]
    result = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, timeout=7200, env=env)
    if len(chunk) == 1:
        key = chunk[0].lower().removeprefix("0x").zfill(8)
        return ({key: result.stdout} if result.stdout.strip() else {}), result.stderr[-400:]
    try:
        answers = json.loads(result.stdout) if result.stdout.strip().startswith("{") else {}
    except json.JSONDecodeError:
        answers = {}
    return answers, result.stderr[-400:]


def first_difference(a: str, b: str) -> dict:
    la, lb = a.splitlines(), b.splitlines()
    for index in range(max(len(la), len(lb))):
        x = la[index] if index < len(la) else "<end>"
        y = lb[index] if index < len(lb) else "<end>"
        if x != y:
            return {"line": index + 1, "worker": x.strip()[:200], "decompiler": y.strip()[:200]}
    return {}


def read_log(path: Path) -> collections.Counter:
    counts: collections.Counter = collections.Counter()
    if not path.is_file():
        return counts
    for line in path.read_text().splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "merge_ok" in row:
            counts["worker"] += 1
            for key in ("merges", "speculative", "explicit", "implied", "new_ops", "entries"):
                counts["did:" + key] += row["merge_ok"].get(key, 0)
        elif "merge_declined" in row:
            counts["declined"] += 1
            counts["reason:" + row["merge_declined"]] += 1
        elif "merge_mismatch" in row:
            counts["mismatch"] += 1
        elif "merge_verified" in row:
            counts["verified"] += 1
    return counts


def one_chunk(worker, ghidra_opt, target, chunk, verify: bool, work: Path):
    tag = f"{target['image']}-{chunk[0]}"
    log_default = work / f"{tag}.default.log"
    log_verify = work / f"{tag}.verify.log"
    for path in (log_default, log_verify):
        path.unlink(missing_ok=True)
    new, new_err = run_arm(worker, ghidra_opt, target, chunk, {}, log_default)
    old, old_err = run_arm(worker, ghidra_opt, target, chunk, {"ROMWRIGHT_NATIVE_MERGE": "1"}, None)
    rows = []
    for address in chunk:
        key = address.lower().removeprefix("0x").zfill(8)
        a, b = new.get(key), old.get(key)
        if a is None and b is None:
            rows.append({"address": key, "status": "decompile-error"})
        elif a is None or b is None:
            rows.append({"address": key, "status": "one-arm-failed", "worker_failed": a is None})
        elif a == b:
            rows.append({"address": key, "status": "identical"})
        else:
            rows.append({"address": key, "status": "different", **first_difference(a, b)})
    verify_counts: collections.Counter = collections.Counter()
    mismatches = []
    if verify:
        run_arm(worker, ghidra_opt, target, chunk, {"ROMWRIGHT_RUST_MERGE": "verify"}, log_verify)
        if log_verify.is_file():
            for line in log_verify.read_text().splitlines():
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if "merge_mismatch" in row:
                    mismatches.append(row["merge_mismatch"])
        verify_counts = read_log(log_verify)
    return rows, read_log(log_default), verify_counts, mismatches


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--images")
    parser.add_argument("--target", type=Path, default=Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target")))
    parser.add_argument("--ghidra-opt", type=Path, default=ROOT / "native/build/ghidra_opt")
    parser.add_argument("--chunk", type=int, default=25)
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--verify", action="store_true", help="also run the statement-level verify arm")
    parser.add_argument("--no-ir-passes", action="store_true",
                        help="run every arm with ROMWRIGHT_IR_PASSES= (the semantic IR passes' edits reprint "
                             "statements the verify arm compares before they are edited)")
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    if args.no_ir_passes:
        os.environ["ROMWRIGHT_IR_PASSES"] = ""
    worker = (args.target if args.target.is_absolute() else ROOT / args.target) / "release/romwright-worker"
    wanted = set(args.images.split(",")) if args.images else None
    targets = console_targets(args.cache, wanted)
    work = Path(tempfile.mkdtemp(prefix="merge-diff-", dir=os.environ.get("TMPDIR")))
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = {}
        for target in targets:
            chunks = [target["addresses"][i:i + args.chunk]
                      for i in range(0, len(target["addresses"]), args.chunk)]
            futures[target["image"]] = [pool.submit(one_chunk, worker, args.ghidra_opt, target, chunk,
                                                    args.verify, work) for chunk in chunks]
        for target in targets:
            rows, default_counts, verify_counts, mismatches = [], collections.Counter(), collections.Counter(), []
            for future in futures[target["image"]]:
                chunk_rows, dc, vc, mm = future.result()
                rows += chunk_rows
                default_counts += dc
                verify_counts += vc
                mismatches += mm
            decompiled = [r for r in rows if r["status"] not in ("decompile-error", "one-arm-failed")]
            identical = [r for r in decompiled if r["status"] == "identical"]
            summary = {
                "image": target["image"],
                "sampled": len(rows),
                "decompiled": len(decompiled),
                "identical": len(identical),
                "different": len(decompiled) - len(identical),
                "worker_merge_functions": default_counts["worker"],
                "declined_functions": default_counts["declined"],
                "decline_reasons": {k[7:]: v for k, v in default_counts.most_common() if k.startswith("reason:")},
                "worker_did": {k[4:]: v for k, v in default_counts.items() if k.startswith("did:")},
                "one_arm_failed": [r for r in rows if r["status"] == "one-arm-failed"],
                "differences": [r for r in rows if r["status"] == "different"],
            }
            if args.verify:
                summary["verify_mismatches"] = len(mismatches)
                summary["verify_verified"] = verify_counts["verified"]
                summary["verify_examples"] = mismatches[:20]
            results.append(summary)
            print(f"{summary['image']:36} identical {summary['identical']:4}/{summary['decompiled']:<4}"
                  f" worker-merge {summary['worker_merge_functions']:4} declined {summary['declined_functions']:4}"
                  + (f" verify-mismatch {summary.get('verify_mismatches', 0)}" if args.verify else ""))
    report = {
        "benchmark": "merge_diff",
        "date": datetime.now(timezone.utc).date().isoformat(),
        "ghidra_opt": str(args.ghidra_opt),
        "decompiled": sum(r["decompiled"] for r in results),
        "identical": sum(r["identical"] for r in results),
        "images": results,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(f"total identical {report['identical']}/{report['decompiled']} -> {args.report}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
