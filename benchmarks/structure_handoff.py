#!/usr/bin/env python3
"""Structuring handoff differential: the worker's structurer against Ghidra's.

Stage 1 of the back-to-front port (docs/printer-ir.md, "Unstructured
handoff"): `ghidra_opt` exports the unstructured control-flow graph and the
worker builds the printed block tree. `ROMWRIGHT_NATIVE_STRUCTURE=1` keeps the
stock path (Ghidra's ActionBlockStructure, ActionPreferComplement and
ActionFinalStructure build the tree), which is this script's reference.

For each sampled function of the console-research images (the ownership run's
sample, ~/runs/OwnershipMetric/cache) it runs `export-c --address` once per
mode and compares the C text:

  identical   byte-equal
  better      the Rust-structured output prints fewer gotos (then fewer labels)
  neutral     different text, same gotos and labels (arm order, nesting)
  worse       more gotos (or, at equal gotos, more labels)
  failed      a mode did not produce C (counted per mode)

The totals also give the printed gotos, labels and `if` forms per mode.
`--verify` additionally runs the worker's tree-comparison mode
(ROMWRIGHT_NATIVE_STRUCTURE=2 ROMWRIGHT_STRUCTURE=verify) and counts functions
whose Rust tree differs from the decompiler's.

Usage (on the build host; see docs/ownership.md for the cache):
  benchmarks/structure_handoff.py --target ~/runs/RustStructure/target \\
      --ghidra-opt ~/runs/RustStructure/ventris/native/build/ghidra_opt \\
      --cache ~/runs/OwnershipMetric/cache --limit 100 --jobs 3 --out /tmp/handoff.json
"""
from __future__ import annotations

import argparse
import concurrent.futures
import importlib.util
import json
import re
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GOTO = re.compile(r"\bgoto\b")
LABEL = re.compile(r"^\s*[A-Za-z_]\w*:\s*$", re.M)
ELSE_IF = re.compile(r"\belse\b")


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def export(tools, binary: Path, program: str, project: Path, address: int, env: dict) -> tuple[str | None, str]:
    with tempfile.TemporaryDirectory(prefix="handoff-") as temporary:
        outdir = Path(temporary) / "out"
        argv = [str(tools.cli), "export-c", str(binary), program, str(outdir), "--address", f"{address:x}",
                "--project", str(project)]
        try:
            result = subprocess.run(argv, capture_output=True, text=True, timeout=900, env=tools.env(env))
        except subprocess.TimeoutExpired:
            return None, "timeout"
        files = sorted(outdir.glob("*.c")) if outdir.exists() else []
        if result.returncode != 0 or not files:
            return None, (result.stderr or result.stdout)[-300:]
        return "\n".join(path.read_text(errors="replace") for path in files), result.stderr


def shape(text: str) -> tuple[int, int, int]:
    return len(GOTO.findall(text)), len(LABEL.findall(text)), len(ELSE_IF.findall(text))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", type=Path, required=True, help="cargo target dir with release/romwright-cli")
    parser.add_argument("--ghidra-opt", type=Path, required=True)
    parser.add_argument("--cache", type=Path, default=Path.home() / "runs/OwnershipMetric/cache")
    parser.add_argument("--corpus", type=Path, default=Path.home() / "ventris-corpus" / "extracted")
    parser.add_argument("--images", default="", help="comma list of image ids (default: all)")
    parser.add_argument("--limit", type=int, default=0, help="functions per image (0: the whole sample)")
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    CR = load("console_research", ROOT / "benchmarks" / "console_research.py")
    CR.GHIDRA_OPT = args.ghidra_opt
    tools = CR.Tools(args.target)
    wanted = {item for item in args.images.split(",") if item}
    summary: dict = {"ghidra_opt": CR.sha256_file(args.ghidra_opt), "images": {}}
    totals = Counter()
    for spec in CR.IMAGES:
        if wanted and spec["id"] not in wanted:
            continue
        source = args.corpus / spec["image"]
        results = sorted(args.cache.glob(f"results/*/{spec['id']}-200-*.json"))
        projects = sorted(args.cache.glob(f"projects/{spec['id']}-*-4f53cda18c2b-*"))
        if not source.is_file() or not results or not projects:
            print(f"skip {spec['id']}: image, sample or project absent", file=sys.stderr)
            continue
        sample = [int(a, 16) for a in json.loads(results[-1].read_text())["image"]["sample"]]
        if args.limit:
            sample = sample[: args.limit]
        project = projects[-1]
        program = json.loads((project / "done.json").read_text())["program"]
        binary = CR.prepared_binary(spec, args.corpus, args.cache)

        def one(address: int) -> dict:
            row = {"address": f"{address:08x}"}
            stock, stock_err = export(tools, binary, program, project, address, {"ROMWRIGHT_NATIVE_STRUCTURE": "1"})
            ours, ours_err = export(tools, binary, program, project, address, {})
            row["stock_failed"] = stock is None
            row["rust_failed"] = ours is None
            if stock is None or ours is None:
                row["error"] = {"stock": stock_err[-120:], "rust": ours_err[-120:]}
                return row
            row["stock"], row["rust"] = shape(stock), shape(ours)
            row["identical"] = stock == ours
            if args.verify:
                with tempfile.NamedTemporaryFile("r", suffix=".jsonl") as log:
                    export(tools, binary, program, project, address,
                           {"ROMWRIGHT_NATIVE_STRUCTURE": "2", "ROMWRIGHT_STRUCTURE": "verify",
                            "ROMWRIGHT_STRUCTURE_VERIFY_FILE": log.name})
                    lines = [json.loads(line)["structure_verify"] for line in log.read().splitlines() if line]
                row["verify_checked"] = len(lines)
                row["verify_mismatches"] = sum(1 for line in lines if not line["equal"])
                row["verify_detail"] = [line for line in lines if not line["equal"]][:1]
            return row

        with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
            rows = list(pool.map(one, sample))
        image = Counter()
        for row in rows:
            image["functions"] += 1
            image["stock_failed"] += row["stock_failed"]
            image["rust_failed"] += row["rust_failed"]
            if row["stock_failed"] or row["rust_failed"]:
                continue
            image["compared"] += 1
            for key, mode in (("stock", "stock"), ("rust", "rust")):
                goto, label, else_count = row[key]
                image[f"{mode}_gotos"] += goto
                image[f"{mode}_labels"] += label
                image[f"{mode}_else"] += else_count
            if row["identical"]:
                image["identical"] += 1
            else:
                a, b = (row["rust"][0], row["rust"][1]), (row["stock"][0], row["stock"][1])
                image["better" if a < b else "worse" if a > b else "neutral"] += 1
            image["verify_checked"] += row.get("verify_checked", 0)
            image["verify_mismatched"] += 1 if row.get("verify_mismatches") else 0
        summary["images"][spec["id"]] = {"counts": dict(image), "rows": rows}
        totals.update(image)
        print(spec["id"], dict(image), flush=True)
    summary["totals"] = dict(totals)
    print("TOTAL", dict(totals))
    if args.out:
        args.out.write_text(json.dumps(summary, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
