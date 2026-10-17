#!/usr/bin/env python3
"""Import precision against stock Ghidra on the corpus-wave images, with the false positives classified.

Discovery only (nothing is decompiled): every image gets a brand-new import (no import cache, no fact
pack) into `--cache`, scored by the wave scorer (`console_research.wave_units` / `score_units`,
`console_research_wave.score_found`) over the main module, the scope stock is run on. Stock's function
list is read from the research-eval stock cache (read-only, reused as is: stock does not depend on our
tree). For every image the report carries both tools' frozen and verified metrics and, for each tool,
its invented entries (found, inside the ranges, named by no truth row) classified from the truth's
geometry and, for ours, the producer the import recorded:

  verified    strictly inside a verified truth function's extent (a false split of compiler truth)
  unverified  strictly inside an unverified truth row's extent
  between     inside no truth extent; `tail` when 4..16 bytes after the end of the nearest extent below
  also_other  the other tool found the same entry (a truth gap candidate, not a tool-specific error)

  import_precision.py run  --cache DIR --out J --tools-target TARGET [--jobs 2] [--redo] [image ...]
  import_precision.py report J [J ...] [--before J ...] [--md OUT.md] [--json OUT.json]
                                                        (sign tests against stock, per-image table, classes)
  import_precision.py compare A.json B.json [--show N]   (truth and invented entries B gained or lost)
  import_precision.py features J --tools-target T --out F.json [image ...]   (MIPS: how entries are reached)

`--tools-target` is a cargo target directory holding `release/romwright-cli` and `release/romwright-worker`.
"""
from __future__ import annotations

import argparse
import bisect
import collections
import json
import os
import re
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "benchmarks"))
import console_research as C  # noqa: E402
import console_research_wave as wave  # noqa: E402

STOCK_CACHE = C.CACHE / "stock"
METRICS = ("recall", "precision", "recall_verified", "precision_verified")


def stock_found(image_id: str) -> tuple[dict[int, int] | None, str | None]:
    """(stock's {entry: size}, None), or (None, label) for a stock DNF/crash/absent result."""
    pattern = re.compile(re.escape(image_id) + r"-[0-9a-f]{12}-[0-9a-f]{12}\.json")
    files = sorted((p for p in STOCK_CACHE.iterdir() if pattern.fullmatch(p.name)), key=lambda p: p.stat().st_mtime)
    failure = None
    for path in reversed(files):
        data = wave.read_json(path)
        if data and "functions" in data:
            return {int(entry): size for entry, size in data["functions"]}, None
        if data and "failure" in data:
            failure = data["failure"]["label"]
    return None, failure or "no stock result cached"


def project_producers(project: Path, program: str) -> dict[int, tuple[int, str]]:
    db = sqlite3.connect(f"file:{project}/project.sqlite?mode=ro", uri=True)
    pid = db.execute("SELECT id FROM programs WHERE name = ?", (program,)).fetchone()[0]
    out = {}
    for entry, size, producer in db.execute("SELECT entry, size, producer FROM functions WHERE program_id = ?", (pid,)):
        try:
            out[int(entry, 16)] = (size, producer)
        except ValueError:
            continue
    db.close()
    return out


def classify(found: dict[int, int], truth: dict[int, tuple[int, str]], verified: set[int], ranges,
             other: dict[int, int] | None, producers: dict[int, tuple[int, str]] | None) -> list[dict]:
    """The invented entries of `found` (entry in ranges, no truth row) with their class."""
    inside = lambda a: any(lo <= a < hi for lo, hi in ranges)  # noqa: E731
    starts = sorted(a for a in truth if inside(a))
    # Extents in address order: (start, end, verified); `outer_end[i]` = max end over rows 0..i.
    outer_end, hi = [], 0
    for a in starts:
        hi = max(hi, a + truth[a][0])
        outer_end.append(hi)
    rows = []
    for entry in sorted(found):
        if entry in truth or not inside(entry):
            continue
        i = bisect.bisect_right(starts, entry) - 1
        where, host, gap = "between", None, None
        if i >= 0:
            # The outermost row covering `entry`: scan back while some earlier row may reach it.
            j = i
            while j >= 0 and outer_end[j] > entry:
                a = starts[j]
                if a < entry < a + truth[a][0]:
                    host = a
                    if a in verified:
                        break
                j -= 1
            if host is not None:
                where = "verified" if host in verified else "unverified"
            else:
                gap = entry - outer_end[i]
        row = {"entry": f"{entry:#x}", "size": found[entry], "where": where}
        if host is not None:
            row["host"] = f"{host:#x}"
            row["offset"] = entry - host
        elif gap is not None:
            row["gap_after_previous_truth_end"] = gap
            if 4 <= gap <= 16:
                row["where"] = "between_tail"
        if other is not None:
            row["also_other"] = entry in other
        if producers is not None:
            row["producer"] = producers.get(entry, (0, "?"))[1]
        rows.append(row)
    return rows


def summarise(rows: list[dict]) -> dict:
    by_where = collections.Counter(r["where"] for r in rows)
    by_producer = collections.Counter(r.get("producer") for r in rows if "producer" in r)
    return {"count": len(rows), "by_where": dict(by_where), "by_producer": dict(by_producer),
            "also_other": sum(1 for r in rows if r.get("also_other"))}


def measure(tools, spec: dict, corpus: Path, cache: Path, jobs: int) -> dict:
    binary = C.prepared_binary(spec, corpus, cache)
    image_sha = C.sha256_file(corpus / spec["image"])
    truth_path = corpus / spec["truth"][1]
    modules = wave.load_modules(truth_path, spec["wave"]["modules"])
    spec["probe"] = sorted(modules.get(wave.MAIN, {"truth": {}})["truth"])[:5000]
    project, marker = C.import_project(tools, spec, binary, image_sha, C.BY_NAME["default"], None, cache)
    units, unresolved = C.wave_units(tools, spec, modules, project, marker, binary, {}, cache, corpus, jobs)
    score = C.score_units(units, modules, project)
    degraded = [d.get("message", "") for d in marker.get("diagnostics") or [] if d.get("severity") == "degraded"]
    main = units[0]
    entry = modules[wave.MAIN]
    ranges = [tuple(r) for r in main["ranges"]]
    ours = C.project_found(C.unit_project(main, project), main["program"])
    producers = project_producers(C.unit_project(main, project), main["program"])
    ours_row = wave.score_found(ours, entry["truth"], entry["verified"], ranges)
    stock, stock_label = stock_found(spec["id"])
    stock_row = wave.score_found(stock, entry["truth"], entry["verified"], ranges) if stock is not None else None
    ours_inv = classify(ours, entry["truth"], entry["verified"], ranges, stock, producers)
    stock_inv = classify(stock, entry["truth"], entry["verified"], ranges, ours, None) if stock is not None else None
    missed_only_ours = sorted(a for a in entry["truth"] if any(lo <= a < hi for lo, hi in ranges)
                              and a not in ours and stock is not None and a in stock)
    return {"id": spec["id"], "project": str(project), "program": marker["program"], "seconds": marker["seconds"],
            "load_before": [round(x, 2) for x in os.getloadavg()], "degraded": degraded[:3],
            "phases": marker.get("phases"),
            "ranges": [list(r) for r in ranges], "stock_label": stock_label,
            "ours": {k: ours_row[k] for k in ("truth", "found", "hits", "invented", *METRICS, "verified_split")},
            "stock": None if stock_row is None else
            {k: stock_row[k] for k in ("truth", "found", "hits", "invented", *METRICS, "verified_split")},
            "ours_invented": ours_inv, "stock_invented": stock_inv,
            "ours_summary": summarise(ours_inv), "stock_summary": None if stock_inv is None else summarise(stock_inv),
            "recall_losses_vs_stock": [f"{a:#x}" for a in missed_only_ours][:200],
            "recall_losses_vs_stock_count": len(missed_only_ours),
            "unresolved": unresolved}


def run(args) -> int:
    tools = C.Tools(Path(args.tools_target))
    specs, _ = wave.discover(args.corpus, set(args.images), 0.0)
    if args.images:
        specs = [s for s in specs if s["id"] in set(args.images)]
    else:
        specs = [s for s in specs if s["wave"]["meta"].get("version_match", True)]
    out = json.loads(args.out.read_text()) if args.out.exists() else {"images": {}}
    out["tools"] = tools.fingerprint
    for spec in specs:
        if spec["id"] in out["images"] and not args.redo:
            continue
        try:
            row = measure(tools, dict(spec), args.corpus, args.cache, args.jobs)
        except Exception as error:  # a failing image is reported, not fatal
            row = {"id": spec["id"], "error": str(error)[-800:]}
        out["images"][spec["id"]] = row
        if "error" in row:
            print(f"{spec['id']}: ERROR {row['error']}", flush=True)
        else:
            o, s = row["ours"], row["stock"] or {}
            print(f"{spec['id']}: recall {o['recall']}/{s.get('recall')} precision {o['precision']}/{s.get('precision')} "
                  f"rv {o['recall_verified']}/{s.get('recall_verified')} pv {o['precision_verified']}/{s.get('precision_verified')} "
                  f"inv {o['invented']}/{s.get('invented')} {row['seconds']}s load {row['load_before'][0]}"
                  + (f" DEGRADED {row['degraded']}" if row["degraded"] else ""), flush=True)
        args.out.write_text(json.dumps(out, indent=1))
    return 0


def report(args) -> int:
    """Sign tests against stock, per-image tables, invented-entry classes and the change against `--before`."""
    def load(paths):
        out = {}
        for path in paths:
            out.update(json.loads(Path(path).read_text())["images"])
        return out
    images = load(args.reports)
    before = load(args.before) if args.before else {}
    specs, _ = wave.discover(args.corpus, set(), 0.0)
    mismatch = {s["id"] for s in specs if not s["wave"]["meta"].get("version_match", True)}
    lines = ["# Import precision against stock Ghidra", ""]
    if args.title:
        lines += [args.title, ""]
    by_platform = collections.defaultdict(list)
    for image_id, row in sorted(images.items()):
        if "error" in row or row.get("stock") is None or image_id in mismatch:
            continue
        by_platform[image_id.split("-")[0]].append(row)
    tests = {}
    for metric in METRICS:
        pairs = {"all": []}
        for platform, rows in by_platform.items():
            pairs[platform] = [(r["ours"][metric], r["stock"][metric]) for r in rows
                               if r["ours"][metric] is not None and r["stock"][metric] is not None]
            pairs["all"] += pairs[platform]
        tests[metric] = {k: wave.sign_test(v) for k, v in pairs.items()}
    lines += ["Wins/losses/ties of ours against stock (a win or loss is a difference of 0.5 pp or more); games with a",
              "stock DNF/crash and version-mismatch images (" + ", ".join(sorted(mismatch & set(images))) + ") are in no test.", "",
              "| platform | games | " + " | ".join(METRICS) + " |", "|---|---|" + "---|" * len(METRICS)]
    for platform in ["all", *sorted(by_platform)]:
        games = tests[METRICS[0]][platform]["games"]
        cells = []
        for metric in METRICS:
            t = tests[metric][platform]
            p = "" if t["p_value"] is None or not t["wins"] else f" (p={t['p_value']:.3g})"
            cells.append(f"{t['wins']}/{t['losses']}/{t['ties']}{p}")
        lines.append(f"| {platform} | {games} | " + " | ".join(cells) + " |")
    lines += ["", "## Per image (ours / stock; `was` = the same metric before the change)", "",
              "| image | recall | precision | precision was | recall_v | precision_v | precision_v was | invented ours / stock | import s | was |",
              "|---|---|---|---|---|---|---|---|---|---|"]
    for image_id, row in sorted(images.items()):
        if "error" in row:
            lines.append(f"| {image_id} | ERROR | | | | | | | | |")
            continue
        o, s_ = row["ours"], row["stock"]
        was = before.get(image_id, {}).get("ours", {}) if "error" not in before.get(image_id, {}) else {}
        was_s = before.get(image_id, {}).get("seconds")
        sv = (lambda m: s_[m] if s_ else row["stock_label"])
        lines.append(f"| {image_id}{' (version mismatch)' if image_id in mismatch else ''} | {o['recall']} / {sv('recall')} | "
                     f"{o['precision']} / {sv('precision')} | {was.get('precision', '')} | "
                     f"{o['recall_verified']} / {sv('recall_verified')} | {o['precision_verified']} / {sv('precision_verified')} | "
                     f"{was.get('precision_verified', '')} | {o['invented']} / {s_['invented'] if s_ else '-'} | {row['seconds']} | {was_s or ''} |")
    lines += ["", "## Invented entries by class (`shared` = the other tool found the same entry; a shared entry in no truth row is a truth-gap candidate)", "",
              "| image | ours | in a verified function | in an unverified row | between rows | shared with stock | by producer | stock | stock in verified | stock between rows | stock shared |",
              "|---|---|---|---|---|---|---|---|---|---|---|"]
    for image_id, row in sorted(images.items()):
        if "error" in row:
            continue
        sm = row["ours_summary"]
        w = sm["by_where"]
        lines.append(f"| {image_id} | {sm['count']} | {w.get('verified', 0)} | {w.get('unverified', 0)} | "
                     f"{w.get('between', 0) + w.get('between_tail', 0)} | {sm['also_other']} | "
                     + ", ".join(f"{k} {v}" for k, v in sorted(sm['by_producer'].items(), key=lambda kv: -kv[1])[:4]) + " | "
                     + (f"{row['stock_summary']['count']} | {row['stock_summary']['by_where'].get('verified', 0)} | "
                        f"{row['stock_summary']['by_where'].get('between', 0) + row['stock_summary']['by_where'].get('between_tail', 0)} | "
                        f"{row['stock_summary']['also_other']} |" if row.get("stock_summary") else "- | - | - | - |"))
    text = "\n".join(lines) + "\n"
    if args.md:
        Path(args.md).write_text(text)
    if args.json:
        args.json.write_text(json.dumps({"images": images, "before": before, "sign_tests_vs_stock": tests,
                                         "version_mismatch": sorted(mismatch)}, indent=1))
    print(text)
    return 0


def compare(args) -> int:
    """Per image, what B changed against A: truth entries gained or lost, invented entries gained or lost,
    both read off the two projects (the function tables), scored over A's main-module ranges."""
    a_rows = json.loads(args.a.read_text())["images"]
    b_rows = json.loads(args.b.read_text())["images"]
    specs, _ = wave.discover(args.corpus, set(), 0.0)
    by_id = {s["id"]: s for s in specs}
    total = collections.Counter()
    for image_id in sorted(set(a_rows) & set(b_rows)):
        a, b = a_rows[image_id], b_rows[image_id]
        if "error" in a or "error" in b:
            continue
        spec = by_id[image_id]
        entry = wave.load_modules(args.corpus / spec["truth"][1], spec["wave"]["modules"])[wave.MAIN]
        ranges = [tuple(r) for r in a["ranges"]]
        inside = lambda x: any(lo <= x < hi for lo, hi in ranges)  # noqa: E731
        fa = C.project_found(Path(a["project"]), a["program"])
        fb = C.project_found(Path(b["project"]), b["program"])
        truth = {x for x in entry["truth"] if inside(x)}
        lost = sorted((set(fa) - set(fb)) & truth)
        gained = sorted((set(fb) - set(fa)) & truth)
        inv_a = {x for x in fa if inside(x) and x not in truth}
        inv_b = {x for x in fb if inside(x) and x not in truth}
        removed_inv = len(inv_a - inv_b)
        added_inv = len(inv_b - inv_a)
        oa, ob = a["ours"], b["ours"]
        flag = " RECALL LOSS" if lost else ""
        print(f"{image_id}: hits {oa['hits']}->{ob['hits']} (lost {len(lost)} gained {len(gained)}); "
              f"invented {oa['invented']}->{ob['invented']} (-{removed_inv} +{added_inv}); "
              f"precision {oa['precision']}->{ob['precision']} pv {oa['precision_verified']}->{ob['precision_verified']}; "
              f"seconds {a['seconds']}->{b['seconds']}{flag}")
        if lost:
            print("   lost:", " ".join(f"{x:#x}" for x in lost[:args.show]))
        total.update(lost=len(lost), gained=len(gained), removed=removed_inv, added=added_inv)
    print("total", dict(total))
    return 0


def features(args) -> int:
    """Byte features of the entries on the MIPS images of a `run` report (import_precision_features.py)."""
    import import_precision_features as F
    report = json.loads(args.report.read_text())["images"]
    cli = str(Path(args.tools_target) / "release" / "romwright-cli")
    env = C.Tools(Path(args.tools_target)).env({})
    corpus = args.corpus
    specs, _ = wave.discover(corpus, set(), 0.0)
    by_id = {s["id"]: s for s in specs}
    pooled = collections.defaultdict(lambda: collections.Counter())
    samples = collections.defaultdict(list)
    for image_id, row in sorted(report.items()):
        if "error" in row or (args.images and image_id not in args.images):
            continue
        project = Path(row["project"])
        db = sqlite3.connect(f"file:{project}/project.sqlite?mode=ro", uri=True)
        language = db.execute("SELECT language FROM programs WHERE name = ?", (row["program"],)).fetchone()[0]
        db.close()
        if not any(language.startswith(f) for f in ("MIPS", "r5900", "PSX", "Allegrex")):
            continue
        done = json.loads((project / "done.json").read_text())
        spans = F.regions(project, row["program"])
        words = F.read_words(cli, Path(done["binary"]), spans, ":BE:" in language, env)
        index = F.Index(words)
        db = sqlite3.connect(f"file:{project}/project.sqlite?mode=ro", uri=True)
        pid = db.execute("SELECT id FROM programs WHERE name = ?", (row["program"],)).fetchone()[0]
        data_words = {int(d, 16) for (d,) in db.execute("SELECT dst FROM xrefs WHERE program_id = ? AND kind = 'DATA'", (pid,))}
        db.close()
        ours = C.project_found(project, row["program"])
        starts = sorted(ours)
        spec = by_id[image_id]
        entry = wave.load_modules(corpus / spec["truth"][1], spec["wave"]["modules"])[wave.MAIN]
        ranges = [tuple(r) for r in row["ranges"]]
        inside = lambda a: any(lo <= a < hi for lo, hi in ranges)  # noqa: E731
        previous = lambda a: starts[bisect.bisect_left(starts, a) - 1] if bisect.bisect_left(starts, a) else None  # noqa: E731
        invented = {int(r["entry"], 16): r for r in row["ours_invented"]}
        counters = {"truth_found": collections.Counter(), "truth_missed": collections.Counter(),
                    "invented": collections.Counter()}
        for a in entry["truth"]:
            if not inside(a):
                continue
            size = ours.get(a, entry["truth"][a][0])
            kind = "truth_found" if a in ours else "truth_missed"
            counters[kind][index.describe(a, size, previous(a), data_words)] += 1
        for a, r in invented.items():
            described = index.describe(a, ours[a], previous(a), data_words)
            counters["invented"][described + (r["where"],)] += 1
            samples[described].append((image_id, f"{a:#x}", ours[a], r["where"], r.get("host"), r.get("also_other")))
        for kind, c in counters.items():
            pooled[kind].update(c)
        print(image_id, {k: sum(v.values()) for k, v in counters.items()}, flush=True)
    out = {kind: [[list(k), v] for k, v in c.most_common()] for kind, c in pooled.items()}
    out["samples"] = [[list(k), v[:12]] for k, v in samples.items()]
    args.out.write_text(json.dumps(out, indent=1))
    inv = collections.Counter()
    for k, v in pooled["invented"].items():
        inv[k[:4]] += v
    print("\nfeature (first, before/gap, inbound, size) | invented | truth found | truth missed")
    for k, v in inv.most_common(args.top):
        print(k, v, pooled["truth_found"].get(k, 0), pooled["truth_missed"].get(k, 0))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("run")
    p.add_argument("images", nargs="*")
    p.add_argument("--corpus", type=Path, default=C.M21.CORPUS)
    p.add_argument("--cache", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--tools-target", required=True)
    p.add_argument("--jobs", type=int, default=2)
    p.add_argument("--redo", action="store_true")
    p.set_defaults(fn=run)
    p = sub.add_parser("report")
    p.add_argument("reports", nargs="+")
    p.add_argument("--before", nargs="*", default=[])
    p.add_argument("--corpus", type=Path, default=C.M21.CORPUS)
    p.add_argument("--title", default="")
    p.add_argument("--md")
    p.add_argument("--json", type=Path, help="write the merged rows and the tests here")
    p.set_defaults(fn=report)
    p = sub.add_parser("compare")
    p.add_argument("a", type=Path)
    p.add_argument("b", type=Path)
    p.add_argument("--corpus", type=Path, default=C.M21.CORPUS)
    p.add_argument("--show", type=int, default=12)
    p.set_defaults(fn=compare)
    p = sub.add_parser("features")
    p.add_argument("report", type=Path)
    p.add_argument("images", nargs="*")
    p.add_argument("--corpus", type=Path, default=C.M21.CORPUS)
    p.add_argument("--tools-target", required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--top", type=int, default=40)
    p.set_defaults(fn=features)
    args = parser.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
