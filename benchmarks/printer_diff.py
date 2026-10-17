#!/usr/bin/env python3
"""Printer differential: the Rust C printer against PrintC, function by function.

`ghidra_opt` built from native/ghidra-opt-sleigh.patch exports a printer IR
after PrintC's own markup in every decompile response
(native/romwright_printir.hh); the worker prints C from the IR, and PrintC's
markup survives only as this differential's reference. `romwright-worker
--printer-diff` prints each function from that IR with the Rust printer
without structuring models (crates/romwright-worker/src/printc `reference`)
and compares the result against PrintC's markup from the same Funcdata. A
function is *identical* when the packed markup bytes are equal -- tokens,
links, line breaks, indents, parenthesis ids and every grouping element.

Gate set: the console-research samples (benchmarks/console_research.py,
~/.cache/romwright/research-eval/samples/*-23c94218619e781c-200-20261006.json,
on the default-configuration projects *-4f53cda18c2b-23c94218619e781c) plus
the first multi-block functions of the x86 libc m15-001 scores.

Categories of a difference (first one wins):
  markup-only   DecompDoc tokens equal, packed bytes differ
  token-links   same text and breaks, a token's links/colour differ
  line-breaks   same text, different line breaks or indents
  text          different text (first differing line reported)
  render        the IR did not decode or print
  missing-output / document   response lacked PrintC markup or IR
Decompile failures are reported separately and excluded from the rate.

Usage (from the repository root):
  native/build_ghidra_opt.sh /tmp/rw-printer-build
  CARGO_TARGET_DIR=target/printer cargo build --release -p romwright-worker -p romwright-cli
  benchmarks/printer_diff.py --ghidra-opt /tmp/rw-printer-build/ghidra_opt \\
      --target target/printer --report benchmarks/reports/printer_diff.json
"""
from __future__ import annotations

import argparse
import collections
import concurrent.futures
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CACHE = Path.home() / ".cache/romwright/research-eval"
SAMPLE_SUFFIX = "-23c94218619e781c-200-20261006.json"
PROJECT_PATTERN = "{image}-*-4f53cda18c2b-23c94218619e781c"
LIBC_CANDIDATES = ("/usr/lib64/libc.so.6", "/usr/lib/x86_64-linux-gnu/libc.so.6")


def marked_program(project: Path) -> str:
    """The program console_research.py imported (its done.json marker)."""
    return json.loads((project / "done.json").read_text())["program"]


def console_targets(cache: Path, wanted: set[str] | None) -> list[dict]:
    targets = []
    for sample in sorted((cache / "samples").glob("*" + SAMPLE_SUFFIX)):
        image = sample.name[: -len(SAMPLE_SUFFIX)]
        if wanted and image not in wanted:
            continue
        projects = sorted((cache / "projects").glob(PROJECT_PATTERN.format(image=image)))
        projects = [p for p in projects if (p / "done.json").is_file()]
        if len(projects) != 1:
            print(f"skip {image}: {len(projects)} default projects", file=sys.stderr)
            continue
        addresses = [f"{address:08x}" for address in json.loads(sample.read_text())]
        targets.append({"image": image, "project": projects[0],
                        "program": marked_program(projects[0]), "addresses": addresses})
    return targets


def libc_target(cli: Path, binary: Path, limit: int, cache: Path) -> dict | None:
    if not binary.is_file():
        print(f"skip libc: {binary} not present", file=sys.stderr)
        return None
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()[:16]
    project = cache / f"libc-{digest}"
    marker = project / "done.json"
    if not marker.is_file():
        project.mkdir(parents=True, exist_ok=True)
        subprocess.run([str(cli), "import", str(binary), "--project", str(project),
                        "--name", binary.name], cwd=ROOT, check=True, capture_output=True,
                       timeout=3600)
        marker.write_text(json.dumps({"binary": str(binary)}) + "\n")
    with sqlite3.connect(f"file:{project}/project.sqlite?mode=ro", uri=True) as db:
        # The functions m15-001 scores: the first multi-block ones.
        rows = db.execute("SELECT function FROM function_features WHERE blocks > 1"
                          " ORDER BY function LIMIT ?", (limit,)).fetchall()
    return {"image": "x86-libc", "project": project, "program": binary.name,
            "addresses": [row[0] for row in rows]}


def run_chunk(worker: Path, ghidra_opt: Path, target: dict, chunk: list[str]) -> list[dict]:
    argv = [str(worker), str(ghidra_opt), "auto", target["program"], *chunk,
            "--project", str(target["project"]), "--printer-diff"]
    # PrintC's markup, the reference, exists only when Ghidra structures the function
    # (the worker's structurer is the default; docs/printer-ir.md, "Unstructured handoff").
    env = dict(os.environ, ROMWRIGHT_NATIVE_STRUCTURE="1")
    result = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, timeout=7200, env=env)
    rows = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
    answered = {row["address"] for row in rows}
    for address in chunk:
        if address.lower().removeprefix("0x").zfill(8) not in answered:
            rows.append({"address": address, "status": "decompile-error",
                         "detail": (result.stderr or "no answer")[-400:]})
    return rows


def summarize(image: str, rows: list[dict]) -> dict:
    decompiled = [row for row in rows if row["status"] != "decompile-error"]
    identical = [row for row in decompiled if row["status"] == "identical"]
    categories = collections.Counter(row.get("category", row["status"]) for row in decompiled
                                     if row["status"] != "identical")
    examples = collections.defaultdict(list)
    for row in decompiled:
        if row["status"] != "identical" and len(examples[row["category"]]) < 5:
            examples[row["category"]].append({"address": row["address"],
                                              "detail": row.get("detail", "")[:400]})
    return {
        "image": image,
        "sampled": len(rows),
        "decompiled": len(decompiled),
        "decompile_errors": len(rows) - len(decompiled),
        "identical": len(identical),
        "identical_rate": round(len(identical) / len(decompiled), 4) if decompiled else None,
        "categories": dict(categories.most_common()),
        "examples": dict(examples),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cache", type=Path, default=CACHE)
    parser.add_argument("--images", help="comma-separated console image ids (default: all)")
    parser.add_argument("--target", type=Path, default=Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target")),
                        help="cargo target dir holding release romwright-worker/romwright-cli")
    parser.add_argument("--ghidra-opt", type=Path, default=ROOT / "native/build/ghidra_opt")
    parser.add_argument("--libc", type=Path,
                        default=Path(next((c for c in LIBC_CANDIDATES if Path(c).is_file()), LIBC_CANDIDATES[0])))
    parser.add_argument("--libc-limit", type=int, default=200)
    parser.add_argument("--no-libc", action="store_true")
    parser.add_argument("--chunk", type=int, default=25)
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--report", type=Path, default=ROOT / "benchmarks/reports/printer_diff.json")
    args = parser.parse_args()
    target_dir = args.target if args.target.is_absolute() else ROOT / args.target
    worker = target_dir / "release/romwright-worker"
    cli = target_dir / "release/romwright-cli"
    wanted = set(args.images.split(",")) if args.images else None
    targets = console_targets(args.cache, wanted)
    if not args.no_libc and (wanted is None or "x86-libc" in wanted):
        libc = libc_target(cli, args.libc, args.libc_limit, Path.home() / ".cache/romwright/printer-diff")
        if libc:
            targets.append(libc)

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = {}
        for target in targets:
            chunks = [target["addresses"][i:i + args.chunk]
                      for i in range(0, len(target["addresses"]), args.chunk)]
            futures[target["image"]] = [pool.submit(run_chunk, worker, args.ghidra_opt, target, chunk)
                                        for chunk in chunks]
        for target in targets:
            rows = [row for future in futures[target["image"]] for row in future.result()]
            summary = summarize(target["image"], rows)
            summary["project"] = str(target["project"])
            # Identical functions are counted, not listed.
            summary["differences"] = [row for row in rows if row["status"] != "identical"]
            results.append(summary)
            print(f"{summary['image']:32} identical {summary['identical']:4}/{summary['decompiled']:<4}"
                  f" ({(summary['identical_rate'] or 0) * 100:6.2f}%)  errors {summary['decompile_errors']:3}"
                  f"  {summary['categories']}")

    decompiled = sum(r["decompiled"] for r in results)
    identical = sum(r["identical"] for r in results)
    report = {
        "benchmark": "printer_diff",
        "date": datetime.now(timezone.utc).date().isoformat(),
        "commit": subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True,
                                 text=True).stdout.strip(),
        "ghidra_opt": str(args.ghidra_opt),
        "decompiled": decompiled,
        "identical": identical,
        "identical_rate": round(identical / decompiled, 4) if decompiled else None,
        "images": results,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(f"{'total':32} identical {identical:4}/{decompiled:<4}"
          f" ({(report['identical_rate'] or 0) * 100:6.2f}%)  -> {args.report}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
