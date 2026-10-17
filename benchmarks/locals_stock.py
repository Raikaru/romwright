#!/usr/bin/env python3
"""Stock Ghidra's printed C for the functions a harness run sampled.

Runs `analyzeHeadless` once per image on the same stripped twin our import
reads, with the language and loader `import_speed.py` documents for it and
default analyzers, then `ghidra/ExportDecompiledC.java` decompiles the sample.
The output feeds `locals_truth.py --stock`.

    locals_stock.py IMAGE --report console_research_dwarf1.json --out stock.json \\
        [--binary STRIPPED] [--work DIR]
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import import_speed  # noqa: E402

SCRIPT = Path(__file__).resolve().parent / "ghidra" / "ExportDecompiledC.java"
GHIDRA = Path(os.environ.get("GHIDRA_INSTALL_DIR", Path.home() / "ghidra_12.1.3_PUBLIC"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("image")
    parser.add_argument("--report", type=Path, required=True, help="console_research JSON with the sample")
    parser.add_argument("--binary", type=Path, required=True, help="the stripped twin the harness imports")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--work", type=Path)
    parser.add_argument("--timeout", type=int, default=7200)
    parser.add_argument("--create", action="store_true",
                        help="disassemble and create a function at a sampled address stock analysis did not make one")
    args = parser.parse_args()
    sample = json.loads(args.report.read_text())["images"][args.image]["sample"]
    config = import_speed.GHIDRA_CONFIG[args.image]
    work = args.work or Path(tempfile.mkdtemp(prefix="locals-stock-"))
    work.mkdir(parents=True, exist_ok=True)
    listing = work / "addresses.txt"
    listing.write_text("\n".join(sample) + "\n")
    argv = [str(GHIDRA / "support" / "analyzeHeadless"), str(work / "project"), "proj", "-import", str(args.binary)]
    if config["loader"]:
        argv += ["-loader", config["loader"], *config["options"]]
    argv += ["-processor", config["language"], "-scriptPath", str(SCRIPT.parent),
             "-postScript", SCRIPT.name, str(args.out), str(listing), *(["create"] if args.create else []),
             "-deleteProject"]
    (work / "project").mkdir(exist_ok=True)
    env = dict(os.environ, GHIDRA_HEADLESS_MAXMEM=os.environ.get("GHIDRA_HEADLESS_MAXMEM", "8G"), DEBUGINFOD_URLS="")
    result = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=args.timeout)
    (work / "headless.log").write_text(result.stdout + result.stderr)
    if result.returncode or not args.out.is_file():
        print(result.stdout[-1500:], result.stderr[-500:], file=sys.stderr)
        return 1
    rows = json.loads(args.out.read_text())["functions"]
    print(f"{args.image}: {sum(1 for r in rows.values() if 'c' in r)} of {len(rows)} decompiled, "
          f"{sum(1 for r in rows.values() if r.get('error') == 'no function at address')} not functions in stock")
    return 0


if __name__ == "__main__":
    sys.exit(main())
