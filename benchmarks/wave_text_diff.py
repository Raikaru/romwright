#!/usr/bin/env python3
"""C-text differential of two worker arms over imported projects (a `ps2_decompile_success.py` wave).

Decompiles every address of the wave twice with the same worker and `ghidra_opt`, once per environment (default: the
default build against `ROMWRIGHT_NATIVE_MERGE=1`, docs/merge-port.md), and compares the printed C function by function.

  wave_text_diff.py --wave WAVE.json --bin BINDIR --report OUT.json [--b-env KEY=VALUE ...] [--a-env KEY=VALUE ...]
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def run(binary: Path, project: Path, program: str, chunk: list[str], env_extra: dict):
    argv = [str(binary / "romwright-worker"), str(binary / "ghidra_opt"), "auto", program, *chunk, "--project", str(project)]
    if len(chunk) == 1:
        argv.append(chunk[0])  # a single address answers as plain text; repeat it so the answer is a JSON object
    result = subprocess.run(argv, capture_output=True, text=True, timeout=3600, env=dict(os.environ, **env_extra))
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {}


def first_difference(a: str, b: str) -> dict:
    la, lb = a.splitlines(), b.splitlines()
    for index in range(max(len(la), len(lb))):
        x = la[index] if index < len(la) else "<end>"
        y = lb[index] if index < len(lb) else "<end>"
        if x != y:
            return {"line": index + 1, "a": x.strip()[:200], "b": y.strip()[:200]}
    return {}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--wave", type=Path, required=True)
    parser.add_argument("--bin", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--a-env", action="append", default=[])
    parser.add_argument("--b-env", action="append", default=["ROMWRIGHT_NATIVE_MERGE=1"])
    parser.add_argument("--chunk", type=int, default=40)
    parser.add_argument("--jobs", type=int, default=6)
    args = parser.parse_args()
    a_env = dict(item.split("=", 1) for item in args.a_env)
    b_env = dict(item.split("=", 1) for item in args.b_env)
    wave = json.loads(args.wave.read_text())
    summary = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = {}
        for image, entry in wave["images"].items():
            rows = json.loads(Path(entry["configs"]["default"]["results_file"]).read_text())
            project = Path(rows["project"])
            program = json.loads((project / "done.json").read_text())["program"]
            addresses = sorted({row["address"].lower().removeprefix("0x").zfill(8) for row in rows["functions"]})
            for i in range(0, len(addresses), args.chunk):
                chunk = addresses[i:i + args.chunk]
                futures.setdefault(image, []).append(
                    (chunk, pool.submit(run, args.bin, project, program, chunk, a_env),
                     pool.submit(run, args.bin, project, program, chunk, b_env)))
        total = {"compared": 0, "identical": 0, "different": 0, "missing": 0, "missing_a": 0, "missing_b": 0}
        for image, jobs in futures.items():
            counts = {"compared": 0, "identical": 0, "different": 0, "missing": 0, "missing_a": 0, "missing_b": 0}
            differences = []
            for chunk, fa, fb in jobs:
                answers_a, answers_b = fa.result(), fb.result()
                for address in chunk:
                    a, b = answers_a.get(address), answers_b.get(address)
                    if a is None or b is None:
                        counts["missing"] += 1
                        counts["missing_a"] += a is None
                        counts["missing_b"] += b is None
                    elif a == b:
                        counts["compared"] += 1
                        counts["identical"] += 1
                    else:
                        counts["compared"] += 1
                        counts["different"] += 1
                        if len(differences) < 10:
                            differences.append({"address": address, **first_difference(a, b)})
            summary[image] = {**counts, "differences": differences}
            for key in total:
                total[key] += counts[key]
            print(f"{image:30} compared {counts['compared']:5} identical {counts['identical']:5} different {counts['different']:3} missing {counts['missing']:3} (a {counts['missing_a']}, b {counts['missing_b']})")
    report = {"benchmark": "wave_text_diff", "date": datetime.now(timezone.utc).date().isoformat(), "bin": str(args.bin),
              "a_env": a_env, "b_env": b_env, "totals": total, "images": summary}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print("totals", total)
    return 0


if __name__ == "__main__":
    sys.exit(main())
