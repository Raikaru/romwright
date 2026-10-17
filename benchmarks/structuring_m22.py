#!/usr/bin/env python3
"""m22 standalone match per structuring model (crates/romwright-worker/src/printc/structure.rs).

Drives tests/m22-001_c_output.py's extraction, context and agbcc/objdiff
scoring through benchmarks/console_research.py's M22Runner, on the default
GBA research project, once per configuration of benchmarks/structuring_models.py
(baseline = `ROMWRIGHT_RUST_STRUCTURING=none`, byte-identical to PrintC). The
`ghidra_opt` under test is passed explicitly, since the Rust printer needs one
built with native/romwright_printir.hh. The headline is the *standalone*
similarity: the context variant does not compile (docs/structuring-baseline.md).

Usage (from the repository root):
  CARGO_TARGET_DIR=target/structmodels cargo build --release -p romwright-worker -p romwright-cli
  benchmarks/structuring_m22.py --ghidra-opt /tmp/rw-structmodels-build/ghidra_opt \\
      --target target/structmodels --report benchmarks/reports/structuring_m22.json
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def main() -> int:
    research = load("console_research", ROOT / "benchmarks/console_research.py")
    models = load("structuring_models", ROOT / "benchmarks/structuring_models.py")
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--ghidra-opt", type=Path, required=True)
    parser.add_argument("--configs", help="comma-separated configurations (default: all)")
    parser.add_argument("--config", action="append", default=[], metavar="NAME=MODELS",
                        help="an extra configuration: ROMWRIGHT_RUST_STRUCTURING=MODELS (repeatable)")
    parser.add_argument("--cache", type=Path, default=Path.home() / ".cache/romwright/structuring-m22")
    parser.add_argument("--ir-passes", help="ROMWRIGHT_IR_PASSES for every run (default: unset)")
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    target = args.target if args.target.is_absolute() else ROOT / args.target
    known = {**models.CONFIGS, **dict(spec.split("=", 1) for spec in args.config)}
    names = args.configs.split(",") if args.configs else list(models.CONFIGS)

    tools = research.Tools(target)
    runner = research.M22Runner(tools, args.cache)
    missing = runner.prerequisites()
    if missing:
        raise SystemExit(f"m22 prerequisites missing: {missing}")
    projects = sorted(research.CACHE.glob("projects/gba-pokeemerald-*-4f53cda18c2b-23c94218619e781c"))
    if len(projects) != 1:
        raise SystemExit(f"expected one default GBA project, found {projects}")
    program = json.loads((projects[0] / "done.json").read_text())["program"]
    runner.prepare(projects[0], program)

    rows = {}
    for name in names:
        env = {"ROMWRIGHT_GHIDRA_OPT": str(args.ghidra_opt.resolve()),
               "ROMWRIGHT_RUST_STRUCTURING": known[name]}
        if args.ir_passes is not None:
            env["ROMWRIGHT_IR_PASSES"] = args.ir_passes
        config = research.Config(f"structuring-{name}", env, f"structuring model {name}", None)
        result = runner.run(config, args.cache / "results" / tools.fingerprint / f"{name}.json")
        functions = result["functions"]
        standalone = [row["similarity_standalone"] for row in functions.values()]
        rows[name] = {
            "standalone_mean": round(sum(standalone) / len(standalone), 2),
            "standalone_exact": sum(value >= 100.0 for value in standalone),
            "functions": len(standalone),
            "per_function": {fn: row["similarity_standalone"] for fn, row in functions.items()},
        }
        print(f"{name:18} standalone mean {rows[name]['standalone_mean']:6.2f}  "
              f"exact {rows[name]['standalone_exact']}/{len(standalone)}", flush=True)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps({"benchmark": "structuring_m22", "ghidra_opt": str(args.ghidra_opt),
                                       "configs": rows}, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
