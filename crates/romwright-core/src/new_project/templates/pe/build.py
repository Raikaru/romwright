#!/usr/bin/env python3
"""Compile the decompiled C of this project with the pinned compiler and score each function against the retail bytes.

There is no whole-executable build here (docs/new-project.md, "Windows PE"): the retail image's linker, C runtime and object
order are not recovered. `src/` holds one function per unit; this script compiles each with the compiler of the era
(config/project.json, build/config.json), then objdiff compares each compiled function with the retail bytes in
`orig/target/` (an i386 COFF object per function, relocations kept).

    python3 configure.py                      # once: fetch the pinned compiler, wibo, objdiff-cli
    python3 build.py [-j N] [--only SUBSTR]   # compile every unit -> build/obj/**, build/compile_report.json
    python3 build.py build/obj/main/0040/FUN_00401000.obj   # one unit (what objdiff runs)
    python3 build.py report                   # objdiff-cli report -> build/report.json, build/progress.json, build/progress.tsv
    python3 build.py status                   # the summary of the last report

A function is *matched* when objdiff reports 100%: remove its `NON_MATCHING` marker. Compiled objects get the compiler's name
decoration (`_f`, `_f@8`, `@f@8`) stripped from their symbols so they pair with the target objects by function name.

Standard library only.
"""
import argparse
import concurrent.futures
import glob
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BUILD = ROOT / "build"
PROJECT = json.loads((ROOT / "config" / "project.json").read_text())


def config():
    path = BUILD / "config.json"
    if not path.exists():
        raise SystemExit("build/config.json is missing: run `python3 configure.py` first")
    return json.loads(path.read_text())


def winpath(path):
    """wibo maps `Z:` to `/`."""
    return "Z:" + str(Path(path).resolve()).replace("/", "\\")


def headers_mtime():
    newest = 0.0
    for path in (ROOT / "include").rglob("*.h"):
        newest = max(newest, path.stat().st_mtime)
    return newest


# ---------------------------------------------------------------------------
# COFF: strip the compiler's name decoration
# ---------------------------------------------------------------------------

DECORATED = re.compile(r"^(?:@|_)(?P<name>.+?)(?:@\d+)?$")


def undecorate(name):
    if name.startswith("@"):
        found = re.match(r"^@(?P<name>.+)@\d+$", name)
        return found.group("name") if found else name
    if name.startswith("_"):
        found = DECORATED.match(name)
        return found.group("name") if found else name
    return name


def normalise_object(path):
    """Rewrite the symbol table of an i386 COFF object so `_f@12` is `f`, `@f@8` is `f`, `_g` is `g`. The symbol table and
    its string table are the end of the file in every object cl.exe and clang write."""
    data = bytearray(Path(path).read_bytes())
    if len(data) < 20 or struct.unpack_from("<H", data, 0)[0] != 0x14C:
        return False
    symptr, nsyms = struct.unpack_from("<II", data, 8)
    if nsyms == 0 or symptr + 18 * nsyms > len(data):
        return False
    old_strings = bytes(data[symptr + 18 * nsyms:])
    old_size = struct.unpack_from("<I", old_strings, 0)[0] if len(old_strings) >= 4 else 4

    def read_name(entry):
        if entry[:4] == b"\0\0\0\0":
            offset = struct.unpack_from("<I", entry, 4)[0]
            end = old_strings.index(b"\0", offset)
            return old_strings[offset:end].decode("latin1")
        return entry[:8].rstrip(b"\0").decode("latin1")

    symbols = bytearray()
    strings = bytearray()
    index = 0
    while index < nsyms:
        entry = bytes(data[symptr + 18 * index: symptr + 18 * (index + 1)])
        aux = entry[17]
        name, storage = read_name(entry), entry[16]
        if storage == 2:  # external
            name = undecorate(name)
        raw = name.encode("latin1")
        if len(raw) <= 8:
            head = raw.ljust(8, b"\0")
        else:
            head = b"\0\0\0\0" + struct.pack("<I", 4 + len(strings))
            strings += raw + b"\0"
        symbols += head + entry[8:18]
        for extra in range(aux):
            symbols += data[symptr + 18 * (index + 1 + extra): symptr + 18 * (index + 2 + extra)]
        index += 1 + aux
    out = bytes(data[:symptr]) + bytes(symbols) + struct.pack("<I", 4 + len(strings)) + bytes(strings)
    Path(path).write_bytes(out)
    return True


def text_size(path):
    """Bytes of code in an i386 COFF object, 0 when there is none or the file is missing."""
    try:
        data = Path(path).read_bytes()
    except OSError:
        return 0
    if len(data) < 20 or struct.unpack_from("<H", data, 0)[0] != 0x14C:
        return 0
    nsec, = struct.unpack_from("<H", data, 2)
    opt, = struct.unpack_from("<H", data, 16)
    total = 0
    for index in range(nsec):
        name, _vs, _va, size, _raw, _rel, _ln, _nr, _nl, chars = struct.unpack_from("<8sIIIIIIHHI", data, 20 + opt + 40 * index)
        if chars & 0x20:  # IMAGE_SCN_CNT_CODE
            total += size
    return total


# ---------------------------------------------------------------------------
# Compile
# ---------------------------------------------------------------------------

def find_clang(cfg):
    for candidate in (cfg.get("clang"), os.environ.get("CLANG"), *sorted(glob.glob(str(BUILD / "tools" / cfg["tool"] / "*" / "bin" / "clang"))), shutil.which("clang")):
        if candidate and (Path(candidate).exists() or shutil.which(candidate)):
            return candidate
    raise SystemExit(f"no clang found for {cfg['tool']}: run `python3 configure.py`, or set $CLANG / config/toolchain.local.json")


def command(cfg, unit, source, obj):
    inc = ROOT / "include"
    if cfg["family"] == "msvc":
        includes = []
        for directory in cfg["include"]:
            includes += ["/I", winpath(directory)]
        return ([cfg["wibo"], cfg["cl"], "/nologo", "/c", *cfg["flags"], "/I", winpath(inc), *includes, f"/Fo{winpath(obj)}", winpath(source)],
                dict(os.environ, INCLUDE=";".join(winpath(d) for d in cfg["include"])))
    return ([find_clang(cfg), "--target=i686-pc-windows-msvc", *cfg["flags"], "-I", str(inc), "-c", str(source), "-o", str(obj)], dict(os.environ))


def compile_unit(cfg, unit, newest_header, force):
    source = ROOT / unit["source"]
    obj = ROOT / unit["object"]
    if not force and obj.exists() and obj.stat().st_mtime >= max(source.stat().st_mtime, newest_header):
        return unit, "cached", ""
    obj.parent.mkdir(parents=True, exist_ok=True)
    if obj.exists():
        obj.unlink()
    argv, env = command(cfg, unit, source, obj)
    done = subprocess.run(argv, capture_output=True, text=True, cwd=ROOT, env=env, errors="replace")
    if done.returncode == 0 and obj.exists():
        normalise_object(obj)
        return unit, "ok", ""
    if obj.exists():
        obj.unlink()
    text = done.stdout + done.stderr
    first = next((line for line in text.splitlines() if re.search(r"error|fatal", line, re.I)), text.strip()[:200])
    return unit, "failed", first.strip()[:300]


def units_present():
    return [unit for unit in PROJECT["units"] if (ROOT / unit["source"]).exists()]


def build(args):
    cfg = config()
    units = units_present()
    if args.paths:
        by_object = {unit["object"]: unit for unit in units}
        units = [by_object[w] for w in (os.path.relpath(Path(p).resolve(), ROOT) for p in args.paths) if w in by_object]
    if args.only:
        units = [unit for unit in units if args.only in unit["source"]]
    if not units:
        raise SystemExit("no units to build (src/ is empty or nothing matched)")
    newest = headers_mtime()
    started = time.time()
    results = {"ok": 0, "cached": 0, "failed": 0}
    failures = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = [pool.submit(compile_unit, cfg, unit, newest, args.force) for unit in units]
        for index, future in enumerate(concurrent.futures.as_completed(futures), 1):
            unit, status, message = future.result()
            results[status] += 1
            if status == "failed":
                failures.append({"function": unit["function"], "source": unit["source"], "first_error": message})
            if len(units) > 200 and index % 500 == 0:
                print(f"  {index}/{len(units)}", flush=True)
    compiled = results["ok"] + results["cached"]
    summary = {"compiler": cfg["tool"], "family": cfg["family"], "flags": cfg["flags"], "units": len(units), "compiled": compiled,
               "failed": results["failed"], "seconds": round(time.time() - started, 1), "failures": sorted(failures, key=lambda f: f["source"])}
    if not args.paths:
        BUILD.mkdir(exist_ok=True)
        (BUILD / "compile_report.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(f"compiled {compiled}/{len(units)} units with {cfg['tool']} ({results['failed']} failed{', see build/compile_report.json' if not args.paths else ''})")
    for failure in failures[:10]:
        print(f"  FAIL {failure['source']}: {failure['first_error']}")
    if len(failures) > 10:
        print(f"  ... {len(failures) - 10} more in build/compile_report.json")
    return 1 if args.paths and failures else (1 if args.strict and failures else 0)


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def report(args):
    cfg = config()
    exe = cfg.get("objdiff") or shutil.which("objdiff-cli")
    if not exe or not (Path(exe).exists() or shutil.which(exe)):
        raise SystemExit("objdiff-cli not found: run `python3 configure.py`")
    document_path = ROOT / "objdiff.json"
    original = document_path.read_text()
    document = json.loads(original)
    # objdiff-cli 3.6.1 fails on a unit whose compiled object is missing or has no code (a decompilation that failed to
    # compile, or compiled to nothing): such a unit is reported target-only (0%) for this run
    for unit in document["units"]:
        if "base_path" in unit and text_size(ROOT / unit["base_path"]) == 0:
            del unit["base_path"]
    BUILD.mkdir(exist_ok=True)
    document_path.write_text(json.dumps(document, indent=2) + "\n")
    try:
        done = subprocess.run([exe, "report", "generate", "-p", str(ROOT), "-o", str(BUILD / "report.json")], capture_output=True, text=True, errors="replace")
    finally:
        document_path.write_text(original)
    if done.returncode != 0:
        sys.stderr.write(done.stdout + done.stderr)
        return done.returncode
    return status(args)


def status(args):
    path = BUILD / "report.json"
    if not path.exists():
        raise SystemExit("no build/report.json: run `python3 build.py report`")
    data = json.loads(path.read_text())
    by_name = {unit["function"]: unit for unit in PROJECT["units"]}
    rows = []
    for unit in data.get("units", []):
        for function in unit.get("functions", []):
            name = function["name"]
            percent = float(function.get("fuzzy_match_percent", 0.0))
            meta = by_name.get(name, {})
            rows.append({"function": name, "address": meta.get("address"), "size": function.get("size") and int(function["size"]), "percent": round(percent, 3),
                         "status": "matched" if percent >= 100.0 else ("near" if percent >= 90.0 else "non-matching"),
                         "source": meta.get("source")})
    compiled = {u["function"] for u in PROJECT["units"] if (ROOT / u["object"]).exists()}
    for row in rows:
        row["compiled"] = row["function"] in compiled
    rows.sort(key=lambda r: (-r["percent"], r["function"]))
    total = len(PROJECT["units"])
    matched = sum(r["status"] == "matched" for r in rows)
    near = sum(r["status"] == "near" for r in rows)
    mean = round(sum(r["percent"] for r in rows) / len(rows), 3) if rows else 0.0
    summary = {"functions": total, "scored": len(rows), "compiled": len(compiled), "matched": matched, "near_90": near, "mean_percent": mean,
               "compiler": config()["tool"], "whole_image_rebuild": False}
    (BUILD / "progress.json").write_text(json.dumps({"summary": summary, "functions": rows}, indent=1) + "\n")
    with open(BUILD / "progress.tsv", "w") as out:
        out.write("function\taddress\tsize\tpercent\tstatus\tcompiled\tsource\n")
        for r in rows:
            out.write(f"{r['function']}\t{r['address']}\t{r['size']}\t{r['percent']}\t{r['status']}\t{int(r['compiled'])}\t{r['source']}\n")
    print(f"{total} functions: {len(compiled)} compile, {matched} match exactly, {near} at >= 90%, mean {mean}% (build/progress.json, build/progress.tsv)")
    if matched:
        print("matched, ready to drop their NON_MATCHING marker: " + ", ".join(r["function"] for r in rows if r["status"] == "matched")[:300])
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("paths", nargs="*", help="`report`, `status`, or object files to build")
    parser.add_argument("-j", "--jobs", type=int, default=os.cpu_count() or 2)
    parser.add_argument("--strict", action="store_true", help="exit 1 when any unit fails to compile")
    parser.add_argument("--force", action="store_true", help="rebuild up-to-date objects")
    parser.add_argument("--only", help="build only units whose source path contains this")
    args = parser.parse_args()
    if args.paths == ["report"]:
        sys.exit(report(args))
    if args.paths == ["status"]:
        sys.exit(status(args))
    sys.exit(build(args))


if __name__ == "__main__":
    main()
