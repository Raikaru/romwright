#!/usr/bin/env python3
"""Head-to-head pilot: native vs stock on one real binary, four axes.

Not a gate (no thresholds): a measurement instrument. Scores the same
medium real binary on both tools, cold, side by side -- function
recovery, prototype agreement, goto count, wall time -- and reports
better/worse per axis instead of parity-on-fixtures.

 Pilot binary is /usr/lib64/libc.so.6 (precedent: m13-001's committed
default). No DWARF is available (no debuginfo on this host, and the
helpers pin DEBUGINFOD_URLS=""), so the function axis is symtab truth
plus stock parity, labeled as such -- not recall against DWARF.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import random
import re
import shutil
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "target" / "release" / "lre-cli"
SAMPLE = 30
DECOMPILE_TIMEOUT = 180

SIG = re.compile(
    r"^\s*(.+?)\s+([A-Za-z_]\w*)\s*\(([^;{}]*)\)\s*\{?\s*$", re.MULTILINE)


def run(arguments: list[str], environment: dict[str, str], timeout: int) -> str:
    result = subprocess.run(
        [str(CLI)] + arguments, cwd=ROOT, env=environment,
        capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"{' '.join(arguments)} failed: {result.stderr[-800:]}")
    return result.stdout


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def symtab_funcs(binary: Path) -> dict[int, str]:
    """All defined FUNC symbols: the only compiler truth on a stripped lib."""
    result = subprocess.run(
        ["readelf", "-sW", str(binary)], capture_output=True,
        text=True, timeout=120)
    if result.returncode:
        raise SystemExit("readelf -sW failed")
    symbols = {}
    for line in result.stdout.splitlines():
        parts = line.split()
        if (len(parts) >= 8 and parts[0][:-1].isdigit()
                and parts[3] == "FUNC" and parts[6] != "UND"):
            try:
                symbols[int(parts[1], 16)] = parts[7]
            except ValueError:
                continue
    return symbols


SIG = re.compile(r"([A-Za-z_][\w\s\*]*?)\s+([A-Za-z_]\w*)\s*\(([^;{}]*)\)")


def signature(text: str) -> tuple[str, int] | None:
    """(normalized return type, arity) of the first C function signature."""
    match = SIG.search(text)
    if not match:
        return None
    ret = re.sub(r"\s+", " ", match.group(1)).strip()
    params = match.group(3).strip()
    if params in ("", "void"):
        return ret, 0
    return ret, len([p for p in params.split(",") if p.strip()])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path("/usr/lib64/libc.so.6"))
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--twin", type=Path, default=None,
                        help="unstripped twin for symbol truth (defaults to --binary itself)")
    parser.add_argument("--ghidra", type=Path, default=Path(
        os.environ.get("VENTRIS_GHIDRA", Path.home() / "ghidra_12.1.3_PUBLIC")))
    parser.add_argument("--sample", type=int, default=SAMPLE)
    parser.add_argument("--reuse", action="store_true",
                        help="reuse existing projects and C artifacts instead of re-running")
    arguments = parser.parse_args()
    work = arguments.work
    binary = arguments.binary
    work.mkdir(parents=True, exist_ok=True)
    environment = dict(os.environ)
    environment["TMPDIR"] = str(work / "tmp")
    # Honest cold numbers: the import cache would time a restore, not an analysis.
    environment["VENTRIS_NO_IMPORT_CACHE"] = "1"
    (work / "tmp").mkdir(exist_ok=True)
    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-cli"],
                   cwd=ROOT, check=True)
    package = subprocess.run(
        ["rpm", "-qf", str(binary), "--queryformat", "%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}"],
        capture_output=True, text=True).stdout.strip() or "unknown"
    info = {"path": str(binary), "sha256": sha256_file(binary),
            "package": package, "os": platform.platform()}
    print(json.dumps({"inputs": info}), flush=True)

    # Mirror the corpus twin shape: strip a copy, import that, score it
    # against the unstripped original's symbols. Scoring an import that
    # still carries its symtab measures nothing (both tools ingest it).
    target = work / "stripped.bin"
    if not arguments.reuse or not target.is_file():
        shutil.copy2(binary, target)
        subprocess.run(["strip", "-s", str(target)], check=True, timeout=300)
    info["stripped_sha256"] = sha256_file(target)
    native_project = work / "native"
    stock_project = work / "stock"
    native_wall_s = stock_wall_s = None
    if not arguments.reuse or not (native_project / "project.sqlite").is_file():
        started = time.monotonic()
        run(["import", str(target), "--project", str(native_project),
             "--name", "h2h"], environment, 1200)
        native_wall_s = round(time.monotonic() - started, 1)
    store = sqlite3.connect(native_project / "project.sqlite")
    native = {int(row[0], 16) for row in store.execute("SELECT entry FROM functions")}
    if not arguments.reuse or not (stock_project / "project.sqlite").is_file():
        started = time.monotonic()
        run(["import", str(target), "--project", str(stock_project),
             "--name", "h2h", "--oracle", "--ghidra", str(arguments.ghidra)],
            environment, 1200)
        stock_wall_s = round(time.monotonic() - started, 1)
    stock_store = sqlite3.connect(stock_project / "project.sqlite")
    stock = {int(row[0], 16) for row in stock_store.execute("SELECT entry FROM functions")}
    # Both tools store image-based addresses; readelf prints link VAs.
    # Mirror dwarf_gate: shared objects bias truth by the mapping base.
    e_type = int.from_bytes(binary.read_bytes()[16:18], "little")
    base = min(int(row[0], 16) for row in store.execute("SELECT start FROM memory_regions"))
    bias = base if e_type == 3 else 0
    truth_set = {address + bias for address in symtab_funcs(arguments.twin or binary)}
    # Symbols surviving the strip: recall against these is ingestion, the
    # rest is discovery. Reported beside truth every run.
    exposed = {address + bias for address in symtab_funcs(target)}
    hidden = truth_set - exposed
    axis_functions = {
        "truth_functions": len(truth_set),
        "exposed_symbols": len(exposed),
        "must_discover": len(hidden),
        "load_bias": f"{bias:08x}",
        "native": {"recovered": len(native),
                   "recall": round(len(native & truth_set) / len(truth_set), 4),
                   "discovered_recall": (round(len(native & hidden) / len(hidden), 4) if hidden else None),
                   "unexplained": sorted(f"{a:#x}" for a in native - truth_set)[:20],
                   "unexplained_count": len(native - truth_set),
                   "wall_s": native_wall_s},
        "stock": {"recovered": len(stock),
                  "recall": round(len(stock & truth_set) / len(truth_set), 4),
                  "discovered_recall": (round(len(stock & hidden) / len(hidden), 4) if hidden else None),
                  "unexplained": sorted(f"{a:#x}" for a in stock - truth_set)[:20],
                  "unexplained_count": len(stock - truth_set),
                  "wall_s": stock_wall_s},
    }
    print(json.dumps({"functions": {k: (v if not isinstance(v, dict) else
        {kk: vv for kk, vv in v.items() if kk != "unexplained"})
        for k, v in axis_functions.items()}}), flush=True)

    # Axes 2+3: same sampled functions decompiled both ways. C artifacts
    # persist per address so metric iterations re-read files in seconds.
    cdir = work / "c"
    cdir.mkdir(exist_ok=True)
    both = sorted(native & stock & truth_set)
    sample = sorted(random.Random(0xC10C).sample(both, min(arguments.sample, len(both))))
    proto_agree = proto_total = 0
    arity_agree = arity_total = 0
    details = []
    goto_native = goto_stock = 0
    decompiled = failed = 0
    failures = []
    stock_program = target.name
    for address in sample:
        arg = f"{address:x}"
        native_c_path = cdir / f"{arg}.native.c"
        stock_c_path = cdir / f"{arg}.stock.c"
        try:
            if arguments.reuse and native_c_path.is_file() and stock_c_path.is_file():
                native_c = native_c_path.read_text()
                stock_c = stock_c_path.read_text()
            else:
                native_c = run(["decompile", str(target), arg, "--project",
                                str(native_project), "--name", "h2h"],
                               environment, DECOMPILE_TIMEOUT)
                stock_c = run(["decompile", stock_program, arg, "--project",
                               str(stock_project), "--oracle",
                               "--ghidra", str(arguments.ghidra)],
                              environment, DECOMPILE_TIMEOUT)
                native_c_path.write_text(native_c)
                stock_c_path.write_text(stock_c)
        except (RuntimeError, subprocess.TimeoutExpired) as error:
            failed += 1
            failures.append(f"{address:#x}: {str(error)[:100]}")
            continue
        decompiled += 1
        native_sig, stock_sig = signature(native_c), signature(stock_c)
        if native_sig is not None and stock_sig is not None:
            proto_total += 1
            proto_agree += native_sig == stock_sig
            arity_agree_here = native_sig[1] == stock_sig[1]
            arity_total_here = 1
            details.append({"address": f"{address:#x}", "native": list(native_sig),
                            "stock": list(stock_sig)})
        else:
            arity_agree_here = arity_total_here = 0
        arity_agree += arity_agree_here
        arity_total += arity_total_here
        goto_native += len(re.findall(r"\bgoto\b", native_c))
        goto_stock += len(re.findall(r"\bgoto\b", stock_c))
    axes = {
        # Arity is structural (both sides read the code); return types pit
        # our inference against stock's signature DB, so the headline is
        # arity and return-type pairs are recorded, not headlined.
        "prototypes": {"sampled": len(sample), "decompiled": decompiled,
                       "compared": proto_total,
                       "arity_agreement": round(arity_agree / arity_total, 4) if arity_total else 0.0,
                       "full_agreement": round(proto_agree / proto_total, 4) if proto_total else 0.0,
                       "details": details,
                       "failures": failures[:10], "failed": failed},
        "gotos": {"functions": decompiled, "native": goto_native, "stock": goto_stock},
    }
    print(json.dumps(axes), flush=True)

    report = {"id": "head-to-head-libc", "recorded_at": datetime.now(timezone.utc).isoformat(),
              "inputs": info, "axis_functions": axis_functions,
              "axis_prototypes": axes["prototypes"], "axis_gotos": axes["gotos"],
              "note": "no DWARF on this host: function axis is symtab truth, "
                      "not DWARF recall. exposed_symbols (surviving the strip) "
                      "is ingestion on both sides; recall over the rest is "
                      "discovery. Prototype headline is arity agreement "
                      "(structural on both sides), return-type pairs recorded "
                      "per function, never parameter names"}
    arguments.report.parent.mkdir(parents=True, exist_ok=True)
    arguments.report.write_text(json.dumps(report, indent=2) + "\n")
    print(f"head-to-head: report at {arguments.report}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
