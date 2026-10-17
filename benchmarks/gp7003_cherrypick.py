#!/usr/bin/env python3
"""GP-7003 cherry-pick: switch recovery of several `ghidra_opt` builds on the console images.

`benchmarks/ghidra_master_trial.py` found that upstream's GP-7003 (non-zero mask and
remainder bounds in jump-table recovery) recovers two jump tables of Fatal Frame
`FActExecOccur` that 12.1.3 misses, and drops the last case of the God Hand table at
0x274828 (`switch (irand() % 5)` with six table entries, the sixth a case the program
holds). This harness measures builds of the pinned decompiler with GP-7003 applied,
as a patch, against the pinned build, on every switch the console images store.

  recover   decompiler-only switch recovery. For every function of a project that has a
            stored computed jump, the project's stored jump tables are removed and each
            build's `romwright-worker --switches` is asked for the tables of the
            function. Per branch the builds are compared: same targets, gained, lost,
            changed. The stored tables are the base import's, so a build is never
            handed its own answer.
  printed   the same functions printed as C (`romwright-cli export-c`) by each build on
            the stripped project: `switch (`, `case`, gotos, jump-table warnings, lines.
  stored    the tables each build's own import stored (two console-research wave
            reports, `ghidra_master_trial.py switchdiff`) are compared there, not here.
  report    merge the recover and printed results into
            benchmarks/reports/ghidra_master_trial/gp7003_cherrypick.{json,md}.

    benchmarks/gp7003_cherrypick.py recover --wave WAVE.json --work DIR --out recover.json \\
        --bin base=DIR --bin cp=DIR [--jobs 3]
    benchmarks/gp7003_cherrypick.py printed --wave WAVE.json --work DIR --recover recover.json \\
        --out printed.json --bin base=DIR --bin cp=DIR
    benchmarks/gp7003_cherrypick.py report --inputs INPUTS.json

A `--bin` directory holds `ghidra_opt`, `romwright-worker` and `romwright-cli`; the first
`--bin` is the reference the others are compared with.
"""
from __future__ import annotations

import argparse
import collections
import concurrent.futures
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "benchmarks" / "reports" / "ghidra_master_trial"


def projects_of(wave: dict) -> dict[str, Path]:
    """game -> default project directory of the wave's main module."""
    result = {}
    for game, image in wave["images"].items():
        config = image.get("configs", {}).get("default")
        if config:
            rows = json.loads(Path(config["results_file"]).read_text())
            result[game] = Path(rows["project"])
    return result


def functions_with_switches(project: Path) -> list[tuple[str, int]]:
    """(entry, size) of every function containing a stored computed jump."""
    with sqlite3.connect(f"file:{project}/project.sqlite?mode=ro", uri=True) as db:
        entries = [(row[0], row[1]) for row in db.execute("SELECT entry, size FROM functions ORDER BY entry")]
        sources = [row[0] for row in db.execute(
            "SELECT DISTINCT src FROM xrefs WHERE kind = 'COMPUTED_JUMP' AND provenance = 'native-import:switch' ORDER BY src")]
    found, index = {}, 0
    for source in sources:
        while index + 1 < len(entries) and entries[index + 1][0] <= source:
            index += 1
        entry, size = entries[index]
        if entry <= source < "%08x" % (int(entry, 16) + max(size, 1)):
            found[entry] = size
    return sorted(found.items())


def stripped_copy(project: Path, target: Path) -> None:
    if target.exists():
        shutil.rmtree(target)
    subprocess.run(["cp", "-a", "--reflink=auto", str(project), str(target)], check=True)
    with sqlite3.connect(target / "project.sqlite") as db:
        db.execute("DELETE FROM xrefs WHERE kind = 'COMPUTED_JUMP'")


def run_switches(binary: Path, project: Path, program: str, addresses: list[str]) -> dict[str, list | None]:
    env = dict(os.environ, ROMWRIGHT_GHIDRA_OPT=str(binary / "ghidra_opt"), ROMWRIGHT_WORKER=str(binary / "romwright-worker"),
               ROMWRIGHT_NO_IMPORT_CACHE="1", ROMWRIGHT_NO_FACT_PACK="1")
    argv = [str(binary / "romwright-worker"), str(binary / "ghidra_opt"), "auto", program,
            *[a.lstrip("0") or "0" for a in addresses], "--project", str(project), "--switches"]
    result = subprocess.run(argv, capture_output=True, text=True, env=env, timeout=7200)
    answers: dict[str, list | None] = {a: None for a in addresses}
    for line in result.stdout.splitlines():
        if line.startswith("{"):
            row = json.loads(line)
            outcome = row["result"].get("Ok")
            key = "%08x" % row["address"]
            answers[key] = None if outcome is None else [
                [t["branch"]["offset"], sorted({target["offset"] for target in t["targets"]})] for t in outcome]
    return answers


def cmd_recover(args) -> int:
    wave = json.loads(Path(args.wave).read_text())
    bins = [item.split("=", 1) for item in args.bin]
    work = Path(args.work)
    work.mkdir(parents=True, exist_ok=True)
    out = {"bins": [name for name, _ in bins], "games": {}}
    for game, project in sorted(projects_of(wave).items()):
        if args.games and game not in args.games.split(","):
            continue
        done = json.loads((project / "done.json").read_text())
        functions = functions_with_switches(project)
        clean = work / f"{game}-stripped"
        stripped_copy(project, clean)
        addresses = [entry for entry, _ in functions]
        chunks = [addresses[i:i + args.chunk] for i in range(0, len(addresses), args.chunk)]
        per_bin: dict[str, dict] = {}
        for name, directory in bins:
            merged: dict[str, list | None] = {}
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
                for part in pool.map(lambda chunk: run_switches(Path(directory), clean, done["program"], chunk), chunks):
                    merged.update(part)
            per_bin[name] = merged
        reference = bins[0][0]
        summary = {"functions": len(functions), "stored_branches": None, "per_bin": {}}
        tables_ref = {fn: {b: t for b, t in (answers or [])} for fn, answers in per_bin[reference].items()}
        summary["per_bin"][reference] = {
            "tables": sum(len(v) for v in tables_ref.values()), "targets": sum(len(t) for v in tables_ref.values() for t in v.values()),
            "failed_functions": sum(1 for v in per_bin[reference].values() if v is None)}
        for name, _ in bins[1:]:
            tables = {fn: {b: t for b, t in (answers or [])} for fn, answers in per_bin[name].items()}
            counts = collections.Counter()
            examples = collections.defaultdict(list)
            for fn in addresses:
                ref, got = tables_ref.get(fn, {}), tables.get(fn, {})
                for branch in sorted(set(ref) | set(got)):
                    if branch not in got:
                        kind = "lost"
                    elif branch not in ref:
                        kind = "gained"
                    elif ref[branch] == got[branch]:
                        kind = "same"
                    else:
                        lost = len(set(ref[branch]) - set(got[branch]))
                        gained = len(set(got[branch]) - set(ref[branch]))
                        kind = "fewer_targets" if lost and not gained else "more_targets" if gained and not lost else "different_targets"
                    counts[kind] += 1
                    if kind != "same" and len(examples[kind]) < 8:
                        detail = {"function": fn, "branch": "%08x" % branch}
                        if kind in ("fewer_targets", "more_targets", "different_targets"):
                            detail["lost"] = ["%08x" % t for t in sorted(set(ref[branch]) - set(got[branch]))]
                            detail["gained"] = ["%08x" % t for t in sorted(set(got[branch]) - set(ref[branch]))]
                        examples[kind].append(detail)
            summary["per_bin"][name] = {
                "tables": sum(len(v) for v in tables.values()), "targets": sum(len(t) for v in tables.values() for t in v.values()),
                "failed_functions": sum(1 for v in per_bin[name].values() if v is None),
                "against_reference": dict(counts), "examples": dict(examples)}
        out["games"][game] = summary
        print(f"{game}: {summary}", file=sys.stderr, flush=True)
    Path(args.out).write_text(json.dumps(out, indent=1))
    print(f"wrote {args.out}")
    return 0


def printed_one(binary: Path, project: Path, binary_path: str, program: str, address: str) -> str | None:
    env = dict(os.environ, ROMWRIGHT_GHIDRA_OPT=str(binary / "ghidra_opt"), ROMWRIGHT_WORKER=str(binary / "romwright-worker"),
               ROMWRIGHT_NO_IMPORT_CACHE="1", ROMWRIGHT_NO_FACT_PACK="1")
    with tempfile.TemporaryDirectory(prefix="gp7003-") as temporary:
        out = Path(temporary) / "out"
        result = subprocess.run([str(binary / "romwright-cli"), "export-c", binary_path, program, str(out), "--address",
                                 address.lstrip("0") or "0", "--project", str(project)],
                                capture_output=True, text=True, env=env, timeout=900)
        files = sorted(out.glob("*.c")) if out.exists() else []
        if result.returncode != 0 or not files:
            return None
        return "\n".join(path.read_text(errors="replace") for path in files)


def body_metrics(text: str | None) -> dict:
    if text is None:
        return {"printed": False}
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if line.strip() == "{" and i > 0), 0)
    body = "\n".join(lines[start:])
    return {"printed": True, "switch": len(re.findall(r"\bswitch\s*\(", body)), "case": len(re.findall(r"^\s*case\b", body, re.M)),
            "goto": len(re.findall(r"\bgoto\b", body)), "jumptable_warning": body.count("Could not recover jumptable"),
            "indirect_jump": body.count("indirect jump"), "lines": len([l for l in body.splitlines() if l.strip()])}


def cmd_printed(args) -> int:
    wave = json.loads(Path(args.wave).read_text())
    recover = json.loads(Path(args.recover).read_text())
    bins = [item.split("=", 1) for item in args.bin]
    work = Path(args.work)
    out = {"bins": [name for name, _ in bins], "games": {}}
    for game, project in sorted(projects_of(wave).items()):
        if game not in recover["games"]:
            continue
        done = json.loads((project / "done.json").read_text())
        clean = work / f"{game}-stripped"
        if not clean.exists():
            stripped_copy(project, clean)
        # every function a build disagrees on, plus the first few hundred that all agree on
        differing = {example["function"] for name in recover["games"][game]["per_bin"]
                     for kinds in (recover["games"][game]["per_bin"][name].get("examples") or {}).values() for example in kinds}
        functions = [entry for entry, _ in functions_with_switches(project)]
        chosen = sorted(differing) + [f for f in functions if f not in differing][:args.control]
        rows = []

        def one(address):
            texts = {name: printed_one(Path(directory), clean, done["binary"], done["program"], address) for name, directory in bins}
            return {"function": address, **{name: body_metrics(text) for name, text in texts.items()},
                    "identical": len({re.sub(r"\s+", " ", t) if t else None for t in texts.values()}) == 1}

        with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
            rows = list(pool.map(one, chosen))
        out["games"][game] = {"functions": len(rows), "identical": sum(1 for r in rows if r["identical"]),
                              "differing": [r for r in rows if not r["identical"]][:60]}
        print(f"{game}: {len(rows)} printed, {out['games'][game]['identical']} identical", file=sys.stderr, flush=True)
    Path(args.out).write_text(json.dumps(out, indent=1))
    print(f"wrote {args.out}")
    return 0


def table(header, rows):
    out = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    out += ["| " + " | ".join("-" if c is None else str(c) for c in row) + " |" for row in rows]
    return out


def cmd_report(args) -> int:
    inputs_path = Path(args.inputs).resolve()
    os.chdir(inputs_path.parent)
    inputs = json.loads(inputs_path.read_text())
    result = {"generated": datetime.now(timezone.utc).isoformat(timespec="seconds"), "notes": inputs.get("notes", {})}
    md = [f"# GP-7003 cherry-pick ({datetime.now(timezone.utc).strftime('%Y-%m-%d')})", ""]
    md += [inputs["notes"]["summary_md"], ""]
    paths = inputs["recover"] if isinstance(inputs["recover"], list) else [inputs["recover"]]
    recover = json.loads(Path(paths[0]).read_text())
    for extra in paths[1:]:		# further runs against the same reference build add their builds
        more = json.loads(Path(extra).read_text())
        for name in more["bins"][1:]:
            recover["bins"].append(name)
            for game, g in more["games"].items():
                recover["games"][game]["per_bin"][name] = g["per_bin"][name]
    result["recover"] = recover
    bins = recover["bins"]
    md += ["## Decompiler-only switch recovery (stored tables removed), per game", "",
           f"Reference build: `{bins[0]}`. For every function with a stored computed jump the stored tables were removed; each build recovered them itself.", ""]
    header = ["game", "functions", f"{bins[0]} tables / targets"]
    for name in bins[1:]:
        header += [f"{name} tables / targets", f"{name}: same", "gained", "lost", "fewer targets", "more targets", "different targets", "failed fns"]
    rows = []
    totals = collections.defaultdict(collections.Counter)
    for game, g in recover["games"].items():
        ref = g["per_bin"][bins[0]]
        row = [game, g["functions"], f"{ref['tables']} / {ref['targets']}"]
        for name in bins[1:]:
            b = g["per_bin"][name]
            c = b.get("against_reference", {})
            row += [f"{b['tables']} / {b['targets']}", c.get("same", 0), c.get("gained", 0), c.get("lost", 0), c.get("fewer_targets", 0),
                    c.get("more_targets", 0), c.get("different_targets", 0), f"{ref['failed_functions']} -> {b['failed_functions']}"]
            for kind in ("same", "gained", "lost", "fewer_targets", "more_targets", "different_targets"):
                totals[name][kind] += c.get(kind, 0)
            totals[name]["tables"] += b["tables"]
            totals[name]["targets"] += b["targets"]
        totals[bins[0]]["tables"] += ref["tables"]
        totals[bins[0]]["targets"] += ref["targets"]
        totals[bins[0]]["functions"] += g["functions"]
        rows.append(row)
    total_row = ["all", totals[bins[0]]["functions"], f"{totals[bins[0]]['tables']} / {totals[bins[0]]['targets']}"]
    for name in bins[1:]:
        t = totals[name]
        total_row += [f"{t['tables']} / {t['targets']}", t["same"], t["gained"], t["lost"], t["fewer_targets"], t["more_targets"], t["different_targets"], ""]
    rows.append(total_row)
    md += table(header, rows) + [""]
    for name in bins[1:]:
        md += [f"### Differing branches, `{name}` against `{bins[0]}`", ""]
        shown = 0
        for game, g in recover["games"].items():
            for kind, items in (g["per_bin"][name].get("examples") or {}).items():
                for item in items:
                    md.append(f"- {game} {kind}: function {item['function']} branch {item['branch']}"
                              + (f", lost {item.get('lost')}, gained {item.get('gained')}" if "lost" in item else ""))
                    shown += 1
        if not shown:
            md.append("- none")
        md.append("")
    if inputs.get("printed"):
        printed = json.loads(Path(inputs["printed"]).read_text())
        result["printed"] = printed
        md += ["## Printed C of the functions the builds disagree on, plus a control of functions they agree on", ""]
        rows = [[game, g["functions"], g["identical"], len(g["differing"])] for game, g in printed["games"].items()]
        md += table(["game", "functions printed", "identical text in every build", "differing (first 60 in the JSON)"], rows) + [""]
    if inputs.get("gates"):
        gates = json.loads(Path(inputs["gates"]).read_text())
        result["gates"] = {key: value for key, value in gates.items() if key != "md"}
        md += [gates["md"], ""]
    for key in ("stored_md", "gates_md", "findings_md"):
        if inputs["notes"].get(key):
            md += [inputs["notes"][key], ""]
    Path(inputs["out_json"]).write_text(json.dumps(result, indent=1, default=str) + "\n")
    Path(inputs["out_md"]).write_text("\n".join(md) + "\n")
    print(f"wrote {inputs['out_json']} and {inputs['out_md']}")
    return 0


def pair_name(arms: list[str]) -> str:
    return ", ".join(arms)


def cmd_gates(args) -> int:
    """Collect the stored-table, m21 and m22 gates and the upstream datatests into one JSON plus markdown."""
    spec = json.loads(Path(args.spec).read_text())
    base = spec["base"]
    out: dict = {"base": base}
    md: list[str] = []

    stored = {arm: json.loads(Path(path).read_text()) for arm, path in spec["stored"].items()}
    out["stored"] = {}
    md += ["## Stored switch tables, whole games (each build imported the game itself)", "",
           f"Reference: `{base}`. Tables and edges are counted in the stored computed-jump xrefs.", ""]
    header = ["build", "tables (ref -> build)", "edges (ref -> build)", "tables only in ref", "tables only in build", "different targets"]
    rows = []
    for arm, games in stored.items():
        tables = [sum(g["tables"]["base"] for g in games.values()), sum(g["tables"]["master"] for g in games.values())]
        edges = [sum(g["edges"]["base"] for g in games.values()), sum(g["edges"]["master"] for g in games.values())]
        lost = {game: g["only_base"] for game, g in games.items() if g["only_base"]}
        gained = {game: g["only_master"] for game, g in games.items() if g["only_master"]}
        diff = {game: g["different_targets"] for game, g in games.items() if g["different_targets"]}
        out["stored"][arm] = {"tables": tables, "edges": edges, "lost": lost, "gained": gained, "different": diff, "games": len(games)}
        rows.append([arm, f"{tables[0]} -> {tables[1]}", f"{edges[0]} -> {edges[1]}",
                     "; ".join(f"{g}: {' '.join(a)}" for g, a in lost.items()) or "none",
                     "; ".join(f"{g}: {' '.join(a)}" for g, a in gained.items()) or "none",
                     "; ".join(f"{g}: {' '.join(a)}" for g, a in diff.items()) or "none"])
    md += table(header, rows) + [""]

    keys = ["truth", "found", "recall", "precision", "invented", "sizes_compared", "size_exact", "size_short", "size_long"]
    m21 = {arm: json.loads(Path(path).read_text()) for arm, path in spec["m21"].items()}
    games = list(next(iter(m21.values()))["rows"])
    out["m21"] = {}
    rows = []
    for game in games:
        values = {arm: tuple(m21[arm]["rows"][game].get(k) for k in keys) for arm in m21}
        same = len(set(values.values())) == 1
        out["m21"][game] = {"identical": same, "values": {arm: dict(zip(keys, v)) for arm, v in values.items()}}
        first = next(iter(values.values()))
        rows.append([game, f"{first[2]:.4f}", f"{first[3]:.4f}", first[6], "identical in every build" if same else json.dumps(out["m21"][game]["values"])])
    md += ["## m21 function discovery (7 images)", "",
           f"Builds: {pair_name(list(m21))}. Status: " + ", ".join(f"{arm} {m21[arm]['status']}" for arm in m21) + ".", ""]
    md += table(["image", "recall", "precision", "size exact", "across builds"], rows) + [""]

    out["m22"] = {}
    md += ["## m22-002 (PS2 C match, 200 functions per run, context variant)", ""]
    header = ["run", "build", "exact", "compiled", "mean percent", "best exact", "paired vs ref: better / worse / same", "exact gained / lost"]
    rows = []
    for tag, arms in spec["m22"].items():
        reports = {arm: json.loads(Path(path).read_text()) for arm, path in arms.items()}
        ref_fn = reports[base]["functions"]
        out["m22"][tag] = {}
        for arm, rep in reports.items():
            s = rep["summary"]["overall"]["all"]["romwright"]
            ctx, best = s["context"], s["best"]
            better = worse = same = 0
            gained, lost = [], []
            for addr, fn in rep["functions"].items():
                a = ref_fn[addr]["layers"]["romwright"]["variants"]["context"]
                b = fn["layers"]["romwright"]["variants"]["context"]
                if b["percent"] > a["percent"] + 1e-9:
                    better += 1
                elif b["percent"] < a["percent"] - 1e-9:
                    worse += 1
                else:
                    same += 1
                if b["exact"] and not a["exact"]:
                    gained.append(addr)
                if a["exact"] and not b["exact"]:
                    lost.append(addr)
            out["m22"][tag][arm] = {"exact": ctx["exact"], "compiled": ctx["compiled"], "mean_percent": ctx["mean_percent"], "best_exact": best["exact"],
                                    "better": better, "worse": worse, "same": same, "exact_gained": gained, "exact_lost": lost,
                                    "compiler": rep["lane"] if isinstance(rep.get("lane"), str) else None}
            rows.append([tag, arm, f"{ctx['exact']}/{ctx['functions']}", ctx["compiled"], ctx["mean_percent"], best["exact"],
                         "-" if arm == base else f"{better} / {worse} / {same}",
                         "-" if arm == base else f"{len(gained)} / {len(lost)}"])
    md += table(header, rows) + [""]

    if spec.get("datatests"):
        dt = json.loads(Path(spec["datatests"]).read_text())
        builds = list(next(iter(dt.values()))["sha"])
        # builds with identical printed text share one sha
        differing = {}
        for name, row in dt.items():
            groups = collections.defaultdict(list)
            for build, sha in row["sha"].items():
                groups[sha].append(build)
            if len(groups) > 1:
                differing[name] = [sorted(g) for g in groups.values()]
        out["datatests"] = {"files": len(dt), "builds": builds, "identical_in_every_build": len(dt) - len(differing), "differing": differing}
        md += ["## Upstream decompiler datatests (decomp_opt `load test file` + `execute test command`)", "",
               f"{len(dt)} XML tests (12.1.3's `datatests` directory plus master's `switchmask.xml`), each decompiled by {pair_name(builds)}; "
               f"the printed C was compared. {len(dt) - len(differing)} tests print identical text in every build.", ""]
        for name, groups in differing.items():
            md.append(f"- `{name}`: " + " | ".join("+".join(g) for g in groups))
        md.append("")
    out["md"] = "\n".join(md)
    Path(args.out).write_text(json.dumps(out, indent=1, default=str) + "\n")
    print(f"wrote {args.out}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("recover", "printed"):
        p = sub.add_parser(name)
        p.add_argument("--wave", required=True)
        p.add_argument("--work", required=True)
        p.add_argument("--out", required=True)
        p.add_argument("--bin", action="append", required=True, metavar="NAME=DIR")
        p.add_argument("--jobs", type=int, default=3)
        if name == "recover":
            p.add_argument("--chunk", type=int, default=60)
            p.add_argument("--games", default="")
        else:
            p.add_argument("--recover", required=True)
            p.add_argument("--control", type=int, default=60)
    r = sub.add_parser("report")
    r.add_argument("--inputs", required=True)
    g = sub.add_parser("gates")
    g.add_argument("--spec", required=True)
    g.add_argument("--out", required=True)
    args = parser.parse_args()
    return {"recover": cmd_recover, "printed": cmd_printed, "gates": cmd_gates, "report": cmd_report}[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
