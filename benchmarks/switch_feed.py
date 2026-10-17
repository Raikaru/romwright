#!/usr/bin/env python3
"""Stored switch tables fed to the decompiler: who supplied each printed switch,
and where the import's table and `jumptable.cc` disagree.

Since the stored dispatch tables (Rust VSA, or the import's own decompile) are
handed to the decompiler as the authority for their branch
(`ROMWRIGHT_STORED_SWITCHES`, docs/ownership.md "Stored tables fed to the
decompiler"), every printed `<jumptable>` carries how its stored table related to
what `jumptable.cc` recovers for the same branch:

  confirmed  jumptable.cc recovered exactly the stored addresses
  applied    it recovered something else (or failed): the stored table was
             installed through Ghidra's manual-override model
  observed   (mode `observe` only) it differed, the stored table was compared
             and not used
  none       no stored table for the branch: jumptable.cc is the only source

Per image of the 8 research images this runs, on the 200-function sample of
benchmarks/console_research.py (same rule, seed 20261006) and, with
`--extended`, on every function that holds a stored table:

  apply   the default: the worker's ownership log (`switch_sources`) gives each
          printed switch's state; this is the census and the supplied share.
  off     `ROMWRIGHT_STORED_SWITCHES=off` (jumptable.cc alone, the tree before the
          cutover), on the functions that hold a stored table: the text the
          cutover may change.
  observe the same functions again with the comparison only: its text must equal
          `off` (the comparison is inert).

and writes benchmarks/reports/switch_feed.json: the census by disagreement class
with every disagreeing branch listed (stored size, jumptable.cc size, common),
the printed-switch counts per state, the functions whose text differs between
`off` and `apply`, and lines/gotos in both.

  benchmarks/switch_feed.py --target-dir ~/runs/SwitchFeed/target \\
      --cache ~/runs/SwitchFeed/cache --jobs 2 --extended
"""
from __future__ import annotations

import argparse
import bisect
import concurrent.futures
import hashlib
import importlib.util
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "benchmarks"))

SCHEMA = "switch_feed/1"
MODE = "ROMWRIGHT_STORED_SWITCHES"
SWITCH_PROVENANCE = "native-import:switch"


def log(message: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {message}", file=sys.stderr, flush=True)


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def stored_tables(project: Path, program: str) -> tuple[dict[int, set[int]], dict[int, int]]:
    """branch -> targets for the import's switch tables, and entry -> size."""
    db = sqlite3.connect(f"file:{project}/project.sqlite?mode=ro", uri=True)
    pid = db.execute("SELECT id FROM programs WHERE name = ?", (program,)).fetchone()[0]
    # A branch the switch stage gave edges to, and every COMPUTED_JUMP edge it has (an edge another
    # pass laid first keeps that pass's provenance).
    switch_branches = {row[0] for row in db.execute(
        "SELECT DISTINCT src FROM xrefs WHERE program_id=? AND kind='COMPUTED_JUMP' AND provenance=?",
        (pid, SWITCH_PROVENANCE))}
    tables: dict[int, set[int]] = defaultdict(set)
    for src, dst in db.execute(
            "SELECT src, dst FROM xrefs WHERE program_id=? AND kind='COMPUTED_JUMP'", (pid,)):
        if src in switch_branches:
            tables[int(src, 16)].add(int(dst, 16))
    sizes = {}
    for entry, size in db.execute("SELECT entry, size FROM functions WHERE program_id=?", (pid,)):
        try:
            sizes[int(entry, 16)] = size
        except ValueError:
            continue
    db.close()
    return dict(tables), sizes


def owners(tables: dict[int, set[int]], sizes: dict[int, int]) -> dict[int, list[int]]:
    """function entry -> its stored branches."""
    entries = sorted(sizes)
    out: dict[int, list[int]] = defaultdict(list)
    for branch in sorted(tables):
        index = bisect.bisect_right(entries, branch) - 1
        if index >= 0 and branch < entries[index] + max(sizes[entries[index]], 1):
            out[entries[index]].append(branch)
    return dict(out)


IDENT_GOTO = re.compile(r"\bgoto\b")


def export_one(tools, project: Path, binary: Path, program: str, address: int, mode: str,
               work: Path) -> dict:
    """One `export-c --address` with the ownership log; saves the text."""
    import tempfile
    log_path = work / f"{mode}-{address:08x}.jsonl"
    log_path.unlink(missing_ok=True)
    with tempfile.TemporaryDirectory(prefix="sf-c-") as temporary:
        outdir = Path(temporary) / "out"
        argv = [str(tools.cli), "export-c", str(binary), program, str(outdir), "--address", f"{address:x}",
                "--project", str(project)]
        env = tools.env({MODE: mode, "ROMWRIGHT_OWNERSHIP_LOG": str(log_path)})
        started = time.monotonic()
        try:
            result = subprocess.run(argv, capture_output=True, text=True, timeout=600, env=env)
            code, stdout, stderr = result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            code, stdout, stderr = -9, "", "timeout after 600s"
        row = {"address": address, "exit": code, "seconds": round(time.monotonic() - started, 2)}
        files = sorted(outdir.glob("*.c")) if outdir.exists() else []
        if code != 0 or not files:
            row.update(success=False, error=(stderr or stdout)[-300:])
            return row
        text = "\n".join(path.read_text(errors="replace") for path in files)
    (work / mode).mkdir(parents=True, exist_ok=True)
    (work / mode / f"{address:08x}.c").write_text(text)
    row.update(success=True, sha256=hashlib.sha256(text.encode()).hexdigest()[:16],
               lines=sum(1 for line in text.splitlines() if line.strip()),
               gotos=len(IDENT_GOTO.findall(text)), switches=len(re.findall(r"\bswitch\s*\(", text)))
    sources = []
    if log_path.is_file():
        wanted = f"{address:x}"
        records = []
        for line in log_path.read_text().splitlines():
            try:
                records.append(json.loads(line))
            except ValueError:
                pass
        match = [r for r in records if r.get("address") == wanted] or records
        if match:
            row["jump_tables"] = [t["branch"] for t in (match[-1].get("jump_tables") or [])]
            sources = match[-1].get("switch_sources") or []
        log_path.unlink(missing_ok=True)
    row["sources"] = sources
    return row


def run_pass(tools, project, binary, program, addresses, mode, jobs, work) -> dict[int, dict]:
    work.mkdir(parents=True, exist_ok=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        rows = list(pool.map(lambda a: export_one(tools, project, binary, program, a, mode, work), addresses))
    # A failure under a loaded host (the 600 s limit) is not a result: each is run once more, alone.
    rows = [row if row.get("success") or "timeout" not in row.get("error", "")
            else dict(export_one(tools, project, binary, program, row["address"], mode, work), retried=True)
            for row in rows]
    return {row["address"]: row for row in rows}


def classify(source: dict) -> str:
    """The disagreement class of one printed switch."""
    state = source["state"]
    if state in ("none", "confirmed"):
        return state
    stock, stored, common = source["stock"], source["stored"], source["common"]
    if stock is None:
        return f"{state}:stock-failed"
    if common == stock and stock < stored:
        return f"{state}:stock-subset"
    if common == stored and stored < stock:
        return f"{state}:stock-superset"
    if common == 0:
        return f"{state}:disjoint"
    return f"{state}:overlap"


def run_image(args, CR, tools, spec, cache: Path) -> dict:
    corpus = args.corpus
    source = corpus / spec["image"]
    if not source.is_file() or (spec.get("truth") and not (corpus / spec["truth"][1]).is_file()):
        return {"status": "skipped", "reason": "image or truth absent"}
    binary = CR.prepared_binary(spec, corpus, cache)
    image_sha = CR.sha256_file(source)
    truth = CR.function_truth(spec, corpus)
    dwarf = None
    if spec["id"] in CR.DWARF:
        dwarf_path = cache / "dwarf" / f"{spec['id']}-{image_sha[:12]}.json"
        dwarf_report = CR.read_json(dwarf_path)
        if dwarf_report is None:
            extracted = CR.dwarf_truth(corpus / CR.DWARF[spec["id"]])
            dwarf_report = dict(extracted, functions={f"{k:08x}": v for k, v in extracted["functions"].items()})
            CR.write_json(dwarf_path, dwarf_report)
        dwarf = {int(k, 16): v for k, v in dwarf_report["functions"].items()}
    project, marker = CR.import_env_project(tools, spec, binary, image_sha, {}, truth, cache)
    program = marker["program"]
    sample = CR.choose_sample(spec, project, program, truth, dwarf, args.n, args.seed)
    tables, sizes = stored_tables(project, program)
    holders = owners(tables, sizes)
    work = cache / "work" / spec["id"]
    sample_set = set(sample)
    extended = sorted(set(holders) - sample_set) if args.extended else []
    log(f"{spec['id']}: {len(sample)} sampled, {len(tables)} stored tables in {len(holders)} functions "
        f"({len([e for e in holders if e in sample_set])} sampled), {len(extended)} extended")

    apply_rows = run_pass(tools, project, binary, program, sample + extended, "apply", args.jobs, work)
    holder_functions = sorted(e for e in holders if e in apply_rows)
    off_rows = run_pass(tools, project, binary, program, holder_functions, "off", args.jobs, work)
    observe_rows = run_pass(tools, project, binary, program,
                            [e for e in holder_functions if e in sample_set], "observe", args.jobs, work)

    def census(scope: set[int]) -> dict:
        classes: Counter = Counter()
        listed = []
        unstored = []
        printed_branches = set()
        for address in sorted(scope):
            row = apply_rows.get(address)
            if not row or not row.get("success"):
                continue
            for item in row["sources"]:
                cls = classify(item)
                classes[cls] += 1
                printed_branches.add(item["branch"])
                if cls == "none":
                    unstored.append({"function": f"{address:08x}", "branch": f"{item['branch']:08x}"})
                if cls not in ("none", "confirmed"):
                    listed.append({"function": f"{address:08x}", "branch": f"{item['branch']:08x}",
                                   "class": cls, "stored": item["stored"], "stock": item["stock"],
                                   "common": item["common"]})
        not_printed = []
        for address in sorted(scope):
            for branch in holders.get(address, []):
                if branch not in printed_branches:
                    not_printed.append({"function": f"{address:08x}", "branch": f"{branch:08x}",
                                        "stored": len(tables[branch])})
        printed = sum(classes.values())
        supplied = classes["confirmed"] + sum(v for k, v in classes.items() if k.startswith("applied"))
        return {"functions": len(scope), "decompiled": sum(1 for a in scope if apply_rows.get(a, {}).get("success")),
                "printed_switches": printed, "by_class": dict(classes), "supplied_by_stored": supplied,
                "supplied_share": round(supplied / printed, 4) if printed else None,
                "disagreements": listed, "printed_without_stored_table": unstored,
                "stored_not_printed": not_printed}

    differing = []
    for address in holder_functions:
        a, o = apply_rows.get(address), off_rows.get(address)
        if a and o and a.get("success") and o.get("success") and a["sha256"] != o["sha256"]:
            differing.append({"function": f"{address:08x}", "off_lines": o["lines"], "apply_lines": a["lines"],
                              "off_gotos": o["gotos"], "apply_gotos": a["gotos"],
                              "off_switches": o["switches"], "apply_switches": a["switches"]})
    observe_mismatch = [f"{a:08x}" for a, r in observe_rows.items()
                        if r.get("success") and off_rows.get(a, {}).get("success")
                        and r["sha256"] != off_rows[a]["sha256"]]
    failures = {mode: sorted(f"{a:08x}" for a, r in rows.items() if not r.get("success"))
                for mode, rows in (("apply", apply_rows), ("off", off_rows), ("observe", observe_rows))}

    def totals(rows, scope):
        picked = [rows[a] for a in scope if a in rows and rows[a].get("success")]
        return {"functions": len(picked), "lines": sum(r["lines"] for r in picked),
                "gotos": sum(r["gotos"] for r in picked), "switches": sum(r["switches"] for r in picked)}

    return {
        "status": "ran", "program": program, "import_seconds": marker.get("seconds"),
        "stored": {"tables": len(tables), "functions": len(holders),
                   "targets": sum(len(t) for t in tables.values())},
        "sample": census(sample_set),
        "extended": census(set(extended) | sample_set) if args.extended else None,
        "off_vs_apply_on_holders": {"functions": len(holder_functions), "text_differs": differing,
                                     "off": totals(off_rows, holder_functions),
                                     "apply": totals(apply_rows, holder_functions)},
        "observe_differs_from_off": observe_mismatch,
        "sample_totals_apply": totals(apply_rows, sample),
        "failures": failures,
    }


def observe_census(args, CR, tools, spec, cache: Path) -> dict:
    """The census before the cutover: `observe` over every function holding a stored table. The stored
    table is compared and never used, so every printed switch is jumptable.cc's own; `confirmed` and
    `observed:*` are exactly how the import's table and jumptable.cc relate. A stored table jumptable.cc
    gives no switch for at all is listed in `stored_not_printed`."""
    corpus = args.corpus
    if not (corpus / spec["image"]).is_file():
        return {"status": "skipped"}
    binary = CR.prepared_binary(spec, corpus, cache)
    image_sha = CR.sha256_file(corpus / spec["image"])
    truth = CR.function_truth(spec, corpus)
    project, marker = CR.import_env_project(tools, spec, binary, image_sha, {}, truth, cache)
    program = marker["program"]
    tables, sizes = stored_tables(project, program)
    holders = owners(tables, sizes)
    work = cache / "work" / spec["id"]
    rows = run_pass(tools, project, binary, program, sorted(holders), "observe", args.jobs, work)
    classes: Counter = Counter()
    listed, printed = [], set()
    for address in sorted(holders):
        row = rows.get(address)
        if not row or not row.get("success"):
            continue
        for item in row["sources"]:
            cls = classify(item)
            classes[cls] += 1
            printed.add(item["branch"])
            if cls not in ("none", "confirmed"):
                listed.append({"function": f"{address:08x}", "branch": f"{item['branch']:08x}", "class": cls,
                               "stored": item["stored"], "stock": item["stock"], "common": item["common"]})
    not_printed = [{"function": f"{a:08x}", "branch": f"{b:08x}", "stored": len(tables[b]),
                    "function_failed": not rows.get(a, {}).get("success", False)}
                   for a in sorted(holders) for b in holders[a] if b not in printed]
    return {"functions": len(holders), "printed_switches": sum(classes.values()), "by_class": dict(classes),
            "disagreements": listed, "stored_not_printed": not_printed}


def merge(images: dict, key: str) -> dict:
    classes: Counter = Counter()
    printed = supplied = 0
    for image in images.values():
        if image.get("status") != "ran" or not image.get(key):
            continue
        part = image[key]
        classes.update(part["by_class"])
        printed += part["printed_switches"]
        supplied += part.get("supplied_by_stored", 0)
    total = {"printed_switches": printed, "by_class": dict(classes)}
    if key != "before_cutover":
        total.update(supplied_by_stored=supplied, supplied_share=round(supplied / printed, 4) if printed else None)
    return total


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--corpus", type=Path, default=Path.home() / "ventris-corpus" / "extracted")
    parser.add_argument("--cache", type=Path, default=Path.home() / ".cache" / "romwright" / "switch-feed")
    parser.add_argument("--target-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, default=ROOT / "benchmarks" / "reports" / "switch_feed.json")
    parser.add_argument("--images", default="")
    parser.add_argument("-n", type=int, default=200)
    parser.add_argument("--seed", type=int, default=20261006)
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--observe-census", action="store_true",
                        help="only add the before-the-cutover census (`observe` over every function holding a "
                             "stored table) to an existing report")
    parser.add_argument("--extended", action="store_true",
                        help="also run every function holding a stored table, not only the sampled ones")
    args = parser.parse_args()
    os.environ["CARGO_TARGET_DIR"] = str(args.target_dir)
    CR = load_module("console_research", ROOT / "benchmarks" / "console_research.py")
    tools = CR.Tools(args.target_dir)
    args.cache.mkdir(parents=True, exist_ok=True)
    wanted = {item for item in args.images.split(",") if item}
    report = {"schema": SCHEMA, "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
              "tools": tools.fingerprint, "n": args.n, "seed": args.seed, "images": {}}
    if args.out.is_file():
        try:
            previous = json.loads(args.out.read_text())
            if wanted or args.observe_census:
                report = dict(previous)
                report["images"] = previous.get("images", {})
        except ValueError:
            pass
    for spec in CR.IMAGES:
        if wanted and spec["id"] not in wanted:
            continue
        if args.observe_census:
            image = report["images"].setdefault(spec["id"], {"status": "ran"})
            image["before_cutover"] = observe_census(args, CR, tools, spec, args.cache)
            CR.write_json(args.out, report)
            continue
        try:
            report["images"][spec["id"]] = run_image(args, CR, tools, spec, args.cache)
        except (RuntimeError, OSError, subprocess.SubprocessError, ValueError) as error:
            report["images"][spec["id"]] = {"status": "error", "reason": str(error)[-1000:]}
            log(f"{spec['id']}: ERROR {str(error)[-300:]}")
        report["total_sample"] = merge(report["images"], "sample")
        report["total_before_cutover"] = merge(report["images"], "before_cutover")
        report["total_extended"] = merge(report["images"], "extended")
        CR.write_json(args.out, report)
    log(f"report {args.out}")
    if args.observe_census:
        CR.write_json(args.out, dict(report, total_before_cutover=merge(report["images"], "before_cutover")))
    print(json.dumps({"sample": report.get("total_sample"), "extended": report.get("total_extended"),
                      "before_cutover": report.get("total_before_cutover")}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
