#!/usr/bin/env python3
"""Compile check for the structuring models: no new C errors against Ghidra's structure.

Reads the per-configuration C text `benchmarks/structuring_models.py --dump
DIR` wrote and runs every function through `gcc -fsyntax-only` with a prelude
of Ghidra's type names. Decompiled functions do not compile on their own
(undeclared globals, unknown callees), so the check is differential: for each
function, the set of diagnostics (message text, line numbers dropped) a
configuration produces is compared with the baseline's. A structuring
rewrite only moves, copies and drops existing statements, so any diagnostic
the baseline does not have -- a label used but not defined, `break` outside
a loop, a jump into a scope, a syntax error -- is a regression.
`undeclared` errors are left out: gcc reports an undeclared global once per
function, at whichever use it reaches first, so moving or copying a
statement changes which of them it names without changing the code.
Functions whose baseline is diagnostic-free are also reported, to show how
many compile cleanly in both.

Usage (from the repository root):
  benchmarks/structuring_compile.py --dump /tmp/structuring-dump --report benchmarks/reports/structuring_compile.json
"""
from __future__ import annotations

import argparse
import collections
import concurrent.futures
import json
import re
import subprocess
import sys
from pathlib import Path

PRELUDE = """
typedef unsigned char byte, undefined, undefined1, uchar, bool;
typedef unsigned short ushort, undefined2, word;
typedef unsigned int uint, undefined4, dword, uint3;
typedef unsigned long long ulonglong, undefined8, qword, ulong, undefined6, undefined5, undefined7;
typedef long long longlong;
typedef void code;
typedef float float10;
typedef long double float16;
typedef unsigned int undefined3;
typedef struct { unsigned long long lo, hi; } undefined16;
#define true 1
#define false 0
"""
DIAGNOSTIC = re.compile(r"^<stdin>:\d+:\d+: (error|warning): (.*)$")


def diagnostics(source: str, compiler: str) -> collections.Counter:
    result = subprocess.run([compiler, "-fsyntax-only", "-std=gnu89", "-fmax-errors=0", "-x", "c", "-"],
                            input=PRELUDE + source, capture_output=True, text=True, timeout=120)
    found = collections.Counter()
    for line in result.stderr.splitlines():
        match = DIAGNOSTIC.match(line)
        if match and match.group(1) == "error" and "undeclared" not in match.group(2):
            found[match.group(2)] += 1
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dump", type=Path, required=True)
    parser.add_argument("--compiler", default="gcc")
    parser.add_argument("--jobs", type=int, default=8)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    configs = sorted(path.name for path in args.dump.iterdir() if path.is_dir() and path.name != "baseline")
    images = sorted(path.stem for path in (args.dump / "baseline").glob("*.json"))
    report = {"benchmark": "structuring_compile", "compiler": args.compiler, "configs": {}}
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        baseline = {}
        for image in images:
            texts = json.loads((args.dump / "baseline" / f"{image}.json").read_text())
            for address, found in zip(texts, pool.map(lambda t: diagnostics(t, args.compiler), texts.values())):
                baseline[(image, address)] = found
        for config in configs:
            compared = clean = changed = 0
            regressions = []
            for image in images:
                path = args.dump / config / f"{image}.json"
                if not path.is_file():
                    continue
                texts = json.loads(path.read_text())
                base_texts = json.loads((args.dump / "baseline" / f"{image}.json").read_text())
                todo = [a for a in texts if texts[a] != base_texts.get(a)]
                compared += len(texts)
                changed += len(todo)
                results = dict(zip(todo, pool.map(lambda a: diagnostics(texts[a], args.compiler), todo)))
                for address in texts:
                    before = baseline[(image, address)]
                    after = results.get(address, before)
                    if not after:
                        clean += 1
                    new = sorted(set(after) - set(before))
                    if new:
                        regressions.append({"image": image, "address": address, "new": new[:5]})
            report["configs"][config] = {"functions": compared, "rewritten": changed,
                                         "error_free": clean, "regressions": regressions}
            print(f"{config:18} functions {compared:5} rewritten {changed:4} error-free {clean:5} "
                  f"new-diagnostic regressions {len(regressions)}")
            for regression in regressions[:10]:
                print("   ", regression)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
