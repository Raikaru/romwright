#!/usr/bin/env python3
"""The stack slots the native decompiler itself names, for a sampled function list.

The printed C of `export-c` renames Ghidra's `local_<hex>` and `auStack_<hex>`
symbols to `temp_*` (`emit_m2c::is_generated_name`), so a stack slot the
decompiler created can be invisible in it. `decompile-doc` carries the
decompiler's own names. This writes, per sampled function, `<address>.stack`
(a JSON list of entry-relative offsets) next to a copy of the printed C, so
`locals_truth.py --ours LABEL=DIR` scores the slots the decompiler found.

    locals_doc.py --cli CLI --binary BIN --project DIR --name N \\
        --sample ADDR[,ADDR..]|FILE.json --from-dir RESULTS --out DIR
Tool paths come from the ROMWRIGHT_GHIDRA_OPT /
ROMWRIGHT_WORKER environment, as the harness sets them.
"""
import argparse
import concurrent.futures as futures
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

STACK = re.compile(r"\b(?:local|[a-z]*Stack)_([0-9a-fA-F]+)\b")


def stack_offsets(document: dict) -> list[int]:
    """Entry-relative offsets of every stack-named symbol in the token stream."""
    text = json.dumps(document.get("tokens", []))
    return sorted({-int(match[1], 16) for match in STACK.finditer(text)})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--project", type=Path, required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--sample", required=True, help="comma-separated hex addresses, or a harness JSON `images.<id>.sample` via --image")
    parser.add_argument("--image")
    parser.add_argument("--from-dir", type=Path, required=True, help="directory of the printed `<address>.c` files")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=2)
    args = parser.parse_args()
    if args.image:
        sample = json.loads(Path(args.sample).read_text())["images"][args.image]["sample"]
    else:
        sample = args.sample.split(",")
    args.out.mkdir(parents=True, exist_ok=True)

    def one(address: str) -> bool:
        source = args.from_dir / f"{address}.c"
        if not source.is_file():
            return False
        result = subprocess.run(
            [str(args.cli), "decompile-doc", str(args.binary), address.lstrip("0") or "0", "--project",
             str(args.project), "--name", args.name], capture_output=True, text=True, timeout=600)
        if result.returncode:
            return False
        shutil.copy(source, args.out / source.name)
        (args.out / f"{address}.stack").write_text(json.dumps(stack_offsets(json.loads(result.stdout))))
        return True

    with futures.ThreadPoolExecutor(args.jobs) as pool:
        done = sum(pool.map(one, sample))
    print(f"{done} of {len(sample)} functions")
    return 0


if __name__ == "__main__":
    sys.exit(main())
