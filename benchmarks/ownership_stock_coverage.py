#!/usr/bin/env python3
"""Coverage of the stock structuring path (or, with `--default-path`, the default one) on the
sample an ownership run used.

`benchmarks/ownership.py` measures which lines of the vendored C++ and of the
Rust crates a run executes. Since the structuring handoff
(docs/printer-ir.md, "Unstructured handoff") the default path structures in
Rust; `ROMWRIGHT_NATIVE_STRUCTURE=1` is the stock path. This script decompiles
the *same sampled functions* an ownership run decompiled, on the stock path,
with the same instrumented binaries and projects, and reports the same
`coverage` block for them, so the two are comparable function for function
(an earlier tree's report samples different functions).

    benchmarks/ownership_stock_coverage.py --target-dir T --cov-build C --cache CACHE \\
        --source-root S --report REPORT.json [--jobs 3] --out stock_coverage.json

`--report` is the ownership report of the default run (it names the sample);
`CACHE` is that run's `--cache`. Nothing is imported or re-sampled.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target-dir", type=Path, required=True)
    parser.add_argument("--cov-build", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--corpus", type=Path, default=Path.home() / "ventris-corpus" / "extracted")
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--default-path", action="store_true",
                        help="run the default path instead of the stock one (the same decompiles, for totals "
                             "comparable with the stock run: an ownership report's totals include its imports)")
    args = parser.parse_args()
    own = load("ownership", ROOT / "benchmarks" / "ownership.py")
    CR = load("console_research", ROOT / "benchmarks" / "console_research.py")
    CR.GHIDRA_OPT = args.cov_build / "ghidra_opt"
    tools = CR.Tools(args.target_dir)
    report = json.loads(args.report.read_text())
    profraw = args.cache / ("profraw-default" if args.default_path else "profraw-stock")
    profraw.mkdir(exist_ok=True)
    for old in profraw.glob("*.profraw"):
        old.unlink()
    import os
    os.environ["LLVM_PROFILE_FILE"] = str(profraw / "own-%m%c.profraw")
    ran = 0
    for spec in CR.IMAGES:
        image = report["images"].get(spec["id"])
        if not image or image.get("status") != "ran":
            continue
        sample = [int(a, 16) for a in image["sample"]]
        projects = sorted(args.cache.glob(f"projects/{spec['id']}-*-4f53cda18c2b-*"))
        project = projects[-1]
        program = json.loads((project / "done.json").read_text())["program"]
        binary = CR.prepared_binary(spec, args.corpus, args.cache)

        def one(address: int):
            return own.export_one(tools, project, binary, program, address,
                                  {} if args.default_path else {"ROMWRIGHT_NATIVE_STRUCTURE": "1"},
                                  None, None, profraw)

        with ThreadPoolExecutor(max_workers=args.jobs) as pool:
            rows = list(pool.map(one, sample))
        ran += len(rows)
        print(spec["id"], sum(1 for row in rows if row.get("success")), "of", len(rows), flush=True)
    patch = own.parse_patch(ROOT / "native" / "ghidra-opt-sleigh.patch")
    shim = SimpleNamespace(profraw=profraw, target_dir=args.target_dir, cov_build=args.cov_build,
                           source_root=args.source_root)
    out = {"functions": ran, "coverage": own.coverage(shim, patch)}
    args.out.write_text(json.dumps(out, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
