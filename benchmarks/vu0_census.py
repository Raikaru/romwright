#!/usr/bin/env python3
"""How much VU0 macro-mode code a PS2 image holds, and what it prints as (P4.3).

Three questions, one subcommand each:

  words       the COP2-family words (arithmetic and lower ops, lqc2, sqc2, qmfc2, qmtc2, cfc2,
              ctc2, bc2*) inside the discovered function ranges of an imported project, and
              the functions that hold one. A raw word scan of the executable segment would also
              count VU microcode that sits in .text/data, so ranges come from the project.
  mnemonics   the same by mnemonic, from a `native/sleigh_diff.cc ... pcode ELF` dump, with how
              many of them lift to a CALLOTHER.
  printed     `export-c` on every function that holds one of those words plus a sample, and the
              unknown VU calls (`_v*`, `_lqc2`, `_sqc2`, `_cfc2`, `_ctc2`, `_qmfc2`, `_qmtc2`)
              left in the printed C, gotos and warnings. Run it once per language and compare.

usage:
  vu0_census.py words      PROJECT_DIR BINARY [--out ranges.json]
  vu0_census.py mnemonics  PROJECT_DIR PCODE_DUMP
  vu0_census.py printed    PROJECT_DIR BINARY ranges.json OUT.json [--sample sample.json]
                           [--cli romwright-cli] [--jobs 2]
  (environment: ROMWRIGHT_GHIDRA selects the language install, as for the CLI;
   ROMWRIGHT_GHIDRA_OPT and ROMWRIGHT_WORKER are passed through)
"""
from __future__ import annotations

import argparse
import bisect
import collections
import concurrent.futures
import json
import os
import re
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def exec_segments(path):
    data = Path(path).read_bytes()
    phoff = struct.unpack_from("<I", data, 0x1C)[0]
    entsize, count = struct.unpack_from("<HH", data, 0x2A)
    for i in range(count):
        kind, off, va, _pa, filesz, _memsz, flags, _align = struct.unpack_from("<8I", data, phoff + i * entsize)
        if kind == 1 and flags & 1:
            yield va, data[off:off + filesz]


def classify(word):
    """COP2-family class of one instruction word, or None."""
    prime = word >> 26
    if prime == 54: return "lqc2"
    if prime == 62: return "sqc2"
    if prime != 18: return None
    rs = word >> 21 & 31
    if rs & 16: return "vu"
    return {1: "qmfc2", 2: "cfc2", 5: "qmtc2", 6: "ctc2", 8: "bc2"}.get(rs)


def project_functions(project):
    db = sqlite3.connect(f"file:{project}/project.sqlite?mode=ro", uri=True)
    rows = [(int(entry, 16), size, name) for entry, name, size in db.execute("SELECT entry, name, size FROM functions")]
    db.close()
    return rows


def words(project, binary):
    segments = list(exec_segments(binary))
    def word(addr):
        for va, blob in segments:
            if va <= addr < va + len(blob) - 3:
                return struct.unpack_from("<I", blob, addr - va)[0]
    per_function, total = {}, collections.Counter()
    for entry, size, name in project_functions(project):
        counts = collections.Counter()
        for addr in range(entry, entry + size, 4):
            w = word(addr)
            kind = classify(w) if w is not None else None
            if kind: counts[kind] += 1
        if counts:
            per_function[hex(entry)] = [name, size, dict(counts)]
            total.update(counts)
    return per_function, total


VU = re.compile(r"^(v[a-z0-9]+|lqc2|sqc2|qmfc2|qmtc2|cfc2|ctc2|bc2[ft]l?)(\.[xyzw]+|\.I)?$")


def mnemonics(project, dump):
    ranges = sorted((entry, entry + size) for entry, size, _ in project_functions(project))
    starts = [a for a, _ in ranges]
    def in_function(addr):
        i = bisect.bisect_right(starts, addr) - 1
        return i >= 0 and addr < ranges[i][1]
    whole, inside, opaque = collections.Counter(), collections.Counter(), collections.Counter()
    current = None
    for line in Path(dump).read_text().splitlines():
        if not line.startswith("    "):
            parts = line.split(" ", 3)
            current = None
            if len(parts) >= 3 and (VU.match(parts[2]) or parts[2].split(".")[0] in ("vcallms", "vcallmsr")):
                addr, name = int(parts[0], 16), parts[2].split(".")[0]
                whole[name] += 1
                if in_function(addr): inside[name] += 1
                current = (name, in_function(addr))
        elif current and "CALLOTHER" in line:
            opaque[current[0], current[1]] += 1
            current = None
    return whole, inside, opaque


OPAQUE = re.compile(r"\b(_(?:v[a-z0-9]+|lqc2|sqc2|cfc2|ctc2|qmfc2|qmtc2|bc2[a-z]*))\s*\(")


def printed(project, binary, ranges, out, sample, cli, jobs):
    env = {k: v for k, v in os.environ.items()}
    env["ROMWRIGHT_NO_IMPORT_CACHE"] = "1"
    vu = {int(a, 16) for a in json.loads(Path(ranges).read_text())}
    addrs = sorted(vu | set(json.loads(Path(sample).read_text()) if sample else []))
    program = sqlite3.connect(f"file:{project}/project.sqlite?mode=ro", uri=True).execute("SELECT name FROM programs").fetchone()[0]
    work = Path(tempfile.mkdtemp(prefix="vu0-census-"))
    copy = work / "project"
    subprocess.run(["cp", "-a", "--reflink=auto", str(project), str(copy)], check=True)

    def one(addr):
        with tempfile.TemporaryDirectory(prefix="vu0-c-") as tmp:
            outdir = Path(tmp) / "out"
            started = time.time()
            try:
                run = subprocess.run([str(cli), "export-c", str(binary), program, str(outdir), "--address", f"{addr:x}",
                                      "--project", str(copy)], capture_output=True, text=True, timeout=600, env=env)
            except subprocess.TimeoutExpired:
                return addr, {"success": False, "error": "timeout"}
            files = sorted(outdir.glob("*.c")) if outdir.is_dir() else []
            if run.returncode or not files:
                return addr, {"success": False, "error": (run.stderr or run.stdout)[-300:]}
            text = "\n".join(p.read_text(errors="replace") for p in files)
            ops = collections.Counter(m.group(1) for m in OPAQUE.finditer(text))
            return addr, {"success": True, "ops": dict(ops), "gotos": len(re.findall(r"\bgoto\b", text)),
                          "warn": text.count("WARNING"), "lines": sum(1 for l in text.splitlines() if l.strip()),
                          "in_vu": addr in vu, "seconds": round(time.time() - started, 2), "text": text}
    with concurrent.futures.ThreadPoolExecutor(jobs) as pool:
        rows = dict(pool.map(one, addrs))
    shutil.rmtree(work, ignore_errors=True)
    Path(out).write_text(json.dumps({hex(a): r for a, r in rows.items()}))
    ok = [r for r in rows.values() if r["success"]]
    calls = collections.Counter()
    for r in ok:
        calls.update(r["ops"])
    print(f"functions {len(rows)} ok {len(ok)} (VU0 functions {len(vu)}); unknown VU calls {sum(calls.values())} "
          f"in {sum(1 for r in ok if r['ops'])} functions; gotos {sum(r['gotos'] for r in ok)}; "
          f"warnings {sum(r['warn'] for r in ok)}; lines {sum(r['lines'] for r in ok)}")
    print("  ", sorted(calls.items(), key=lambda kv: -kv[1]))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    w = sub.add_parser("words"); w.add_argument("project"); w.add_argument("binary"); w.add_argument("--out")
    m = sub.add_parser("mnemonics"); m.add_argument("project"); m.add_argument("dump")
    p = sub.add_parser("printed")
    p.add_argument("project"); p.add_argument("binary"); p.add_argument("ranges"); p.add_argument("out")
    p.add_argument("--sample"); p.add_argument("--cli", default="target/release/romwright-cli"); p.add_argument("--jobs", type=int, default=2)
    args = parser.parse_args()
    if args.cmd == "words":
        per_function, total = words(args.project, args.binary)
        print(f"{len(per_function)} functions hold {sum(total.values())} COP2-family words: {dict(total)}")
        if args.out: Path(args.out).write_text(json.dumps(per_function))
    elif args.cmd == "mnemonics":
        whole, inside, opaque = mnemonics(args.project, args.dump)
        print(f"VU0 instructions: whole image {sum(whole.values())}, in functions {sum(inside.values())}, "
              f"with a CALLOTHER in functions {sum(n for (name, fn), n in opaque.items() if fn)}")
        for name, n in whole.most_common():
            print(f"  {name:10s} whole {n:6d} in-function {inside[name]:6d} "
                  f"opaque-in-function {opaque[name, True]:6d}")
    else:
        printed(args.project, args.binary, args.ranges, args.out, args.sample, args.cli, args.jobs)


if __name__ == "__main__":
    sys.exit(main())
