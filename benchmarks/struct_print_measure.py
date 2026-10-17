#!/usr/bin/env python3
"""What the struct layer does to printed C: decompile success and the share of field access printed as members.

For every address of a list, `romwright-cli export-c --address` is run once per `ROMWRIGHT_STRUCTS` mode on its own
copy of the project (the struct pass writes layouts to the store, and a copy per worker keeps parallel runs off each
other's database). Per mode it reports

  success           addresses that produced a file / addresses (and which ones failed)
  member accesses   `x->name` and `x.name` in the printed bodies (struct definitions excluded)
  offset accesses   `*(T *)(x + 0xN)` and `*(T *)((char *)x + 0xN)`: field access printed as pointer arithmetic
  member share      member / (member + offset); the printed field-access share
  functions with a member access, and the functions that succeed in `off` but fail in another mode

    python3 benchmarks/struct_print_measure.py --cli CLI --binary IMAGE --program NAME --project DIR \
        --addresses FILE --modes off,debug,inferred,all --jobs 4 --out OUT.json

`FILE` holds one hex address per line. The project must have been imported by a build that stores debug-info
layouts for `debug` mode to differ from `off`.
"""
import argparse
import concurrent.futures
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

MEMBER = re.compile(r"[A-Za-z_]\w*\s*(?:->|\.)\s*[A-Za-z_]\w*")
OFFSET = re.compile(
    r"\*\s*\(\s*[A-Za-z_][\w\s\*]*\*\s*\)\s*\(\s*(?:\(\s*[A-Za-z_][\w\s\*]*\)\s*)?[A-Za-z_]\w*\s*\+\s*(?:0x[0-9a-fA-F]+|\d+)\s*\)")
DEFINITIONS = re.compile(r"^(?:typedef struct \w+ \w+;|struct \w+ \{.*?^\};)\n?", re.S | re.M)


def bodies(text):
    """The printed functions: the text without the struct definitions it carries."""
    return DEFINITIONS.sub("", text)


def counts(text):
    body = bodies(text)
    # a `.` between digits is a float literal; `->` / `.` in a comment or a string is not an access
    body = re.sub(r"/\*.*?\*/", "", body, flags=re.S)
    body = re.sub(r'"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'', '""', body)
    return {"members": len(MEMBER.findall(body)), "offsets": len(OFFSET.findall(body))}


def run_one(cli, binary, program, project, address, mode, env, timeout):
    with tempfile.TemporaryDirectory(prefix="struct-measure-") as tmp:
        out = Path(tmp) / "out"
        started = time.monotonic()
        argv = [cli, "export-c", binary, program, str(out), "--address", address, "--project", str(project)]
        try:
            result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env=dict(env, ROMWRIGHT_STRUCTS=mode))
        except subprocess.TimeoutExpired:
            return {"address": address, "ok": False, "error": f"timeout after {timeout}s"}
        files = sorted(out.glob("*.c")) if out.exists() else []
        row = {"address": address, "seconds": round(time.monotonic() - started, 2)}
        if result.returncode != 0 or not files:
            row.update(ok=False, error=(result.stderr or result.stdout)[-300:])
            return row
        text = "\n".join(f.read_text(errors="replace") for f in files)
        row.update(ok=True, structs="typedef struct" in text, **counts(text))
        return row


def run_mode(args, mode, addresses, env):
    root = Path(tempfile.mkdtemp(prefix=f"struct-measure-{mode}-"))
    chunks = [addresses[index::args.jobs] for index in range(args.jobs)]
    try:
        copies = []
        for index in range(len(chunks)):
            copy = root / f"project{index}"
            shutil.copytree(args.project, copy)
            copies.append(copy)

        def thread(index):
            return [run_one(args.cli, args.binary, args.program, copies[index], a, mode, env, args.timeout)
                    for a in chunks[index]]

        with concurrent.futures.ThreadPoolExecutor(len(chunks)) as pool:
            results = [row for part in pool.map(thread, range(len(chunks))) for row in part]
    finally:
        shutil.rmtree(root, ignore_errors=True)
    return sorted(results, key=lambda row: row["address"])


def summarise(rows):
    ok = [r for r in rows if r["ok"]]
    members = sum(r["members"] for r in ok)
    offsets = sum(r["offsets"] for r in ok)
    return {
        "functions": len(rows), "ok": len(ok), "failed": [r["address"] for r in rows if not r["ok"]],
        "member_accesses": members, "offset_accesses": offsets,
        "member_share": round(members / (members + offsets), 4) if members + offsets else None,
        "functions_with_members": sum(1 for r in ok if r["members"]),
        "functions_with_structs": sum(1 for r in ok if r["structs"]),
        "seconds": round(sum(r.get("seconds", 0) for r in rows), 1),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--cli", required=True)
    ap.add_argument("--binary", required=True)
    ap.add_argument("--program", required=True)
    ap.add_argument("--project", type=Path, required=True)
    ap.add_argument("--addresses", type=Path, required=True)
    ap.add_argument("--modes", default="off,debug,inferred,all")
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    addresses = [a.strip().lower().removeprefix("0x") for a in args.addresses.read_text().split() if a.strip()]
    env = {k: v for k, v in os.environ.items() if not k.startswith("ROMWRIGHT_") or k in ("ROMWRIGHT_WORKER", "ROMWRIGHT_GHIDRA_OPT", "ROMWRIGHT_GHIDRA")}
    env.update(ROMWRIGHT_NO_IMPORT_CACHE="1", ROMWRIGHT_NO_FACT_PACK="1")
    result = {"binary": args.binary, "program": args.program, "addresses": len(addresses), "modes": {}}
    per_mode = {}
    for mode in args.modes.split(","):
        rows = run_mode(args, mode, addresses, env)
        per_mode[mode] = rows
        result["modes"][mode] = summarise(rows)
        print(mode, json.dumps(result["modes"][mode]))
    if "off" in per_mode:
        base = {r["address"] for r in per_mode["off"] if r["ok"]}
        for mode, rows in per_mode.items():
            result["modes"][mode]["fail_where_off_succeeds"] = sorted(base - {r["address"] for r in rows if r["ok"]})
            result["modes"][mode]["succeed_where_off_fails"] = sorted({r["address"] for r in rows if r["ok"]} - base)
    result["functions"] = {mode: rows for mode, rows in per_mode.items()}
    args.out.write_text(json.dumps(result, indent=1))


if __name__ == "__main__":
    main()
