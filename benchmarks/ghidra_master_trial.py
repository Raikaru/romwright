#!/usr/bin/env python3
"""Ghidra master trial: the pinned decompiler against upstream master, same Rust.

docs/upstream-ghidra.md ("Master trial") has the question and the method. The
two arms are two `ghidra_opt` builds driven by one `romwright-cli` /
`romwright-worker` pair:

  base    third_party/ghidra/decompiler (Ghidra 12.1.3) + native/ghidra-opt-sleigh.patch
  master  upstream master 918d44e (2026-10-08) + the same patch, rebased

Subcommands (each prints what it wrote):

  sample    pick the paired-export sample from a console-research wave report
  export    decompile every sampled function with both arms, same project, one
            process per function and arm, alternating which arm goes first;
            keeps the C text, the seconds and the host load of every pair
  switchdiff  the switch tables each arm's own import stored, per game (gained,
            lost, changed), from the two wave reports
  attribute re-decompile the changed functions with `master minus one commit
            group` builds; which group restores the 12.1.3 text
  classify  compare the two texts of every pair: changed / better / worse /
            neutral, with the reason, and the paired timing
  report    merge the gate results (paths below) into
            benchmarks/reports/ghidra_master_trial.{json,md}

    benchmarks/ghidra_master_trial.py sample --wave REPORT.json --out SAMPLE.json
    benchmarks/ghidra_master_trial.py export --sample SAMPLE.json \\
        --base-bin DIR --master-bin DIR --work DIR [--jobs 3]
    benchmarks/ghidra_master_trial.py classify --work DIR --out CLASSIFIED.json
    benchmarks/ghidra_master_trial.py report --inputs INPUTS.json

A `--bin` directory holds `romwright-cli`, `romwright-worker` and `ghidra_opt`.

Classification (classify). A pair is *changed* when the two printed C texts
differ after whitespace normalisation. A changed pair is scored on measurable
things in the text, each of which moves the verdict by its sign:

  failure / timeout   one arm printed nothing: the arm that did wins outright
  gotos + labels      fewer is better (weight 3)
  `/* irregular`      the function's irregular-flow marker, fewer is better (3)
  halt_baddata        calls the decompiler gave up on, fewer is better (3)
  casts               explicit C casts, fewer is better (1)
  address literals    hex constants of 6 or more digits printed as numbers
                      where the other arm names a symbol (DAT_/PTR_/FUN_ or a
                      project name): fewer is better (1)
  statements          fewer is NOT better by itself and carries no weight

The verdict is the sign of the weighted sum: better, worse, or neutral (the
text changed and the sum is zero: renames, reordering, an `else` that is not
needed, a trade of one gotos for one cast). It is a measure of the printed
text, not of correctness; the gates that compile the output (m22-002) are the
correctness evidence and the report keeps them apart.
"""
from __future__ import annotations

import argparse
import collections
import concurrent.futures
import hashlib
import json
import os
import random
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "benchmarks" / "reports"
ARMS = ("base", "master")

CAST = re.compile(r"\(\s*(?:const\s+|volatile\s+|struct\s+|union\s+|enum\s+)?"
                  r"(?:unsigned\s+|signed\s+)?(?:u?int\d*_t|char|short|int|long(?:\s+long)?|float|double|"
                  r"undefined\d*|bool|code|void|[A-Za-z_]\w*)\s*\**\s*\)\s*(?=[\w(&*~!\-])")
ADDRESS_LITERAL = re.compile(r"\b0x[0-9a-fA-F]{6,16}\b")
SYMBOL_NAME = re.compile(r"\b(?:DAT|PTR|FUN|LAB|SUB|s|u)_[0-9a-fA-F]{6,16}\b")


def sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def normalise(text: str) -> str:
    return "\n".join(" ".join(line.split()) for line in text.splitlines() if line.strip())


def function_body(text: str) -> str:
    """The function itself: from its `{` line on. What precedes it is the file's preamble (storage-view unions,
    extern declarations, typedef checks), whose casts and constants are not the decompiler's decisions."""
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.strip() == "{" and index > 0:
            return "\n".join(lines[index:])
    return text


def text_metrics(text: str) -> dict:
    body = function_body(text)
    code = "\n".join(line for line in body.splitlines() if not line.lstrip().startswith(("//", "/*")) or "irregular" in line)
    return {
        "gotos": len(re.findall(r"\bgoto\b", body)),
        "labels": len([m for m in re.findall(r"^\s*(\w+):\s*$", body, re.M) if m not in ("default",)]),
        "irregular": int("/* irregular" in body),
        "halt_baddata": len(re.findall(r"halt_baddata|halt_unimplemented", body)),
        "casts": len(CAST.findall(code)),
        "address_literals": len(ADDRESS_LITERAL.findall(code)),
        "symbol_names": len(SYMBOL_NAME.findall(code)),
        "lines": len([line for line in body.splitlines() if line.strip()]),
    }


WEIGHTS = {"gotos_labels": 3, "irregular": 3, "halt_baddata": 3, "casts": 1, "address_literals": 1}


def verdict(base: dict | None, master: dict | None) -> tuple[str, list[str]]:
    """(better|worse|neutral, reasons) for master relative to base."""
    if base is None and master is None:
        return "neutral", ["both failed"]
    if base is None:
        return "better", ["base failed, master printed"]
    if master is None:
        return "worse", ["master failed, base printed"]
    reasons, score = [], 0
    pairs = {"gotos_labels": (base["gotos"] + base["labels"], master["gotos"] + master["labels"]),
             "irregular": (base["irregular"], master["irregular"]),
             "halt_baddata": (base["halt_baddata"], master["halt_baddata"]),
             "casts": (base["casts"], master["casts"]),
             "address_literals": (base["address_literals"], master["address_literals"])}
    for name, (before, after) in pairs.items():
        if after < before:
            score += WEIGHTS[name]
            reasons.append(f"{name} {before}->{after}")
        elif after > before:
            score -= WEIGHTS[name]
            reasons.append(f"{name} {before}->{after}")
    return ("better" if score > 0 else "worse" if score < 0 else "neutral"), reasons


# ---------------------------------------------------------------------------
# sample
# ---------------------------------------------------------------------------

def cmd_sample(args) -> int:
    wave = json.loads(Path(args.wave).read_text())
    cache = Path(args.cache) if args.cache else None
    rows = []
    quotas = dict(item.split("=") for item in args.quota.split(",") if item)
    for game, image in wave["images"].items():
        config = image.get("configs", {}).get("default")
        if not config:
            continue
        platform = game.split("-")[0]
        quota = int(quotas.get(platform, quotas.get("*", 200)))
        results = json.loads(Path(config["results_file"]).read_text())
        projects = {None: Path(results["project"])}
        for module, name in results["key"].get("units", []):
            if name:
                projects[module] = Path(results["project"]).parent / name
        # An overlay unit whose project is the image's own project has its own program and binary, which the
        # wave report does not keep: only the main module and units that are projects of their own are paired.
        functions = sorted((row for row in results["functions"] if row.get("module") in projects),
                           key=lambda row: (str(row.get("module")), row["address"]))
        rng = random.Random(f"{args.seed}:{game}")
        chosen = functions if len(functions) <= quota else rng.sample(functions, quota)
        for row in sorted(chosen, key=lambda r: (str(r.get("module")), r["address"])):
            project = projects[row.get("module")]
            done = json.loads((project / "done.json").read_text())
            rows.append({"game": game, "project": str(project), "binary": done["binary"],
                         "program": done["program"], "address": row["address"],
                         "wave_success": bool(row.get("success"))})
        print(f"{game}: {len(chosen)} of {len(functions)}", file=sys.stderr)
    Path(args.out).write_text(json.dumps({"seed": args.seed, "wave": str(args.wave), "rows": rows}, indent=1))
    print(f"wrote {args.out}: {len(rows)} functions")
    return 0


# ---------------------------------------------------------------------------
# export
# ---------------------------------------------------------------------------

def arm_env(binary: Path) -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith("ROMWRIGHT_") or k == "ROMWRIGHT_GHIDRA"}
    env.update(ROMWRIGHT_WORKER=str(binary / "romwright-worker"), ROMWRIGHT_GHIDRA_OPT=str(binary / "ghidra_opt"),
               ROMWRIGHT_NO_IMPORT_CACHE="1", ROMWRIGHT_NO_FACT_PACK="1")
    return env


def run_one(binary: Path, project: Path, row: dict, timeout: int) -> dict:
    cli = binary / "romwright-cli"
    with tempfile.TemporaryDirectory(prefix="gmt-") as temporary:
        out = Path(temporary) / "out"
        argv = [str(cli), "export-c", row["binary"], row["program"], str(out), "--address", row["address"].lstrip("0") or "0",
                "--project", str(project)]
        started = time.monotonic()
        try:
            result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env=arm_env(binary))
            code, stdout, stderr = result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            code, stdout, stderr = -9, "", f"timeout after {timeout}s"
        seconds = round(time.monotonic() - started, 3)
        files = sorted(out.glob("*.c")) if out.exists() else []
        if code != 0 or not files:
            return {"ok": False, "seconds": seconds, "timeout": code == -9,
                    "error": (stderr or stdout)[-300:]}
        text = "\n".join(path.read_text(errors="replace") for path in files)
    try:
        report = json.loads(stdout)
    except ValueError:
        report = {}
    return {"ok": True, "seconds": seconds, "text": text,
            "warnings": [w.get("message", "") for w in report.get("warnings") or []]}


def cmd_export(args) -> int:
    sample = json.loads(Path(args.sample).read_text())["rows"]
    work = Path(args.work)
    (work / "projects").mkdir(parents=True, exist_ok=True)
    bins = {"base": Path(args.base_bin), "master": Path(args.master_bin)}
    projects: dict[str, Path] = {}
    for row in sample:
        source = Path(row["project"])
        if source.name not in projects:
            target = work / "projects" / source.name
            if not target.exists():
                subprocess.run(["cp", "-a", "--reflink=auto", str(source), str(target)], check=True)
            projects[source.name] = target
    done_path = work / "pairs.jsonl"
    finished = set()
    if done_path.exists():
        for line in done_path.read_text().splitlines():
            record = json.loads(line)
            finished.add((record["game"], record["address"]))
    todo = [(index, row) for index, row in enumerate(sample) if (row["game"], row["address"]) not in finished]
    print(f"{len(todo)} to do, {len(finished)} done", file=sys.stderr, flush=True)

    def pair(item):
        index, row = item
        project = projects[Path(row["project"]).name]
        order = ARMS if index % 2 == 0 else ARMS[::-1]
        load = os.getloadavg()[0]
        results = {}
        for arm in order:
            results[arm] = run_one(bins[arm], project, row, args.timeout)
        record = {"game": row["game"], "address": row["address"], "order": list(order), "load1": round(load, 2)}
        for arm in ARMS:
            outcome = results[arm]
            entry = {k: v for k, v in outcome.items() if k != "text"}
            if outcome["ok"]:
                directory = work / "c" / arm / row["game"]
                directory.mkdir(parents=True, exist_ok=True)
                (directory / f"{row['address']}.c").write_text(outcome["text"])
                entry["sha"] = sha(outcome["text"])
            record[arm] = entry
        return record

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool, open(done_path, "a") as sink:
        for count, record in enumerate(pool.map(pair, todo), 1):
            sink.write(json.dumps(record) + "\n")
            sink.flush()
            if count % 200 == 0:
                print(f"  {count}/{len(todo)}", file=sys.stderr, flush=True)
    print(f"wrote {done_path}")
    return 0


# ---------------------------------------------------------------------------
# classify
# ---------------------------------------------------------------------------

def read_c(work: Path, arm: str, game: str, address: str) -> str | None:
    path = work / "c" / arm / game / f"{address}.c"
    return path.read_text(errors="replace") if path.is_file() else None


def cmd_classify(args) -> int:
    work = Path(args.work)
    records = [json.loads(line) for line in (work / "pairs.jsonl").read_text().splitlines()]
    games: dict[str, dict] = {}
    changed_rows = []
    totals = collections.Counter()
    for record in records:
        game = games.setdefault(record["game"], {"functions": 0, "base_ok": 0, "master_ok": 0, "identical": 0,
                                                 "changed": 0, "better": 0, "worse": 0, "neutral": 0,
                                                 "base_seconds": [], "master_seconds": [], "ratios": [],
                                                 "base_timeouts": 0, "master_timeouts": 0, "reasons": collections.Counter(),
                                                 "failure_classes": collections.Counter()})
        game["functions"] += 1
        base_text = read_c(work, "base", record["game"], record["address"]) if record["base"]["ok"] else None
        master_text = read_c(work, "master", record["game"], record["address"]) if record["master"]["ok"] else None
        game["base_ok"] += base_text is not None
        game["master_ok"] += master_text is not None
        game["base_timeouts"] += bool(record["base"].get("timeout"))
        game["master_timeouts"] += bool(record["master"].get("timeout"))
        if record["base"]["ok"] and record["master"]["ok"]:
            game["base_seconds"].append(record["base"]["seconds"])
            game["master_seconds"].append(record["master"]["seconds"])
            if record["base"]["seconds"] > 0:
                game["ratios"].append(record["master"]["seconds"] / record["base"]["seconds"])
        for arm in ARMS:
            if not record[arm]["ok"]:
                message = record[arm].get("error", "")
                message = re.sub(r"0x[0-9a-fA-F]+|\b\d+\b", "N", message.strip().splitlines()[-1] if message.strip() else "no output")
                game["failure_classes"][f"{arm}: {message[:100]}"] += 1
        if base_text is None and master_text is None:
            game["identical"] += 1
            continue
        if base_text is not None and master_text is not None and normalise(base_text) == normalise(master_text):
            game["identical"] += 1
            continue
        base_metrics = text_metrics(base_text) if base_text is not None else None
        master_metrics = text_metrics(master_text) if master_text is not None else None
        label, reasons = verdict(base_metrics, master_metrics)
        game["changed"] += 1
        game[label] += 1
        for reason in reasons:
            game["reasons"][(label, reason.split(" ")[0])] += 1
        changed_rows.append({"game": record["game"], "address": record["address"], "verdict": label, "reasons": reasons,
                             "base": base_metrics, "master": master_metrics,
                             "base_ok": base_text is not None, "master_ok": master_text is not None})
    out_games = {}
    for name, game in games.items():
        base_s, master_s = game.pop("base_seconds"), game.pop("master_seconds")
        ratios = game.pop("ratios")
        reasons = game.pop("reasons")
        failures = game.pop("failure_classes")
        game["reasons"] = {f"{label}:{metric}": count for (label, metric), count in sorted(reasons.items())}
        game["failure_classes"] = dict(failures.most_common(8))
        game["median_seconds"] = {"base": round(statistics.median(base_s), 3) if base_s else None,
                                  "master": round(statistics.median(master_s), 3) if master_s else None}
        game["total_seconds"] = {"base": round(sum(base_s), 1), "master": round(sum(master_s), 1)}
        game["median_pair_ratio"] = round(statistics.median(ratios), 3) if ratios else None
        out_games[name] = game
        for key in ("functions", "base_ok", "master_ok", "identical", "changed", "better", "worse", "neutral",
                    "base_timeouts", "master_timeouts"):
            totals[key] += game[key]
    all_ratios = [r for record in records if record["base"]["ok"] and record["master"]["ok"] and record["base"]["seconds"] > 0
                  for r in [record["master"]["seconds"] / record["base"]["seconds"]]]
    loads = [record["load1"] for record in records]
    result = {
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "totals": dict(totals), "games": out_games,
        "timing": {"pairs": len(all_ratios),
                   "median_pair_ratio": round(statistics.median(all_ratios), 3) if all_ratios else None,
                   "master_slower_pairs": sum(1 for r in all_ratios if r > 1.0),
                   "load1_median": round(statistics.median(loads), 2) if loads else None,
                   "load1_max": max(loads) if loads else None,
                   "note": "one process per function and arm; the arm order alternates; seconds include process "
                           "start, project open and the decompile"},
        "changed": changed_rows,
    }
    Path(args.out).write_text(json.dumps(result, indent=1))
    print(f"wrote {args.out}: {dict(totals)}")
    return 0


# ---------------------------------------------------------------------------
# switchdiff
# ---------------------------------------------------------------------------

def switch_edges(project: Path) -> dict[str, set[str]]:
    """Stored computed jumps of a project: branch address -> target addresses."""
    import sqlite3
    with sqlite3.connect(f"file:{project}/project.sqlite?mode=ro", uri=True) as db:
        rows = db.execute("SELECT src, dst FROM xrefs WHERE kind = 'COMPUTED_JUMP' AND provenance = 'native-import:switch'").fetchall()
    tables: dict[str, set[str]] = collections.defaultdict(set)
    for src, dst in rows:
        tables[src].add(dst)
    return tables


def cmd_switchdiff(args) -> int:
    """The tables each arm's own import stored (the import's switch stage runs the decompiler)."""
    waves = {arm: json.loads(Path(path).read_text()) for arm, path in (("base", args.base_wave), ("master", args.master_wave))}
    result = {}
    for game in sorted(set(waves["base"]["images"]) & set(waves["master"]["images"])):
        projects = {}
        stats = {}
        for arm in ARMS:
            config = waves[arm]["images"][game].get("configs", {}).get("default")
            if not config:
                break
            results = json.loads(Path(config["results_file"]).read_text())
            projects[arm] = Path(results["project"])
            marker = json.loads((projects[arm] / "done.json").read_text())
            stats[arm] = marker.get("switch_stats")
        if len(projects) != 2:
            continue
        base, master = switch_edges(projects["base"]), switch_edges(projects["master"])
        only_base = sorted(set(base) - set(master))
        only_master = sorted(set(master) - set(base))
        differ = sorted(src for src in set(base) & set(master) if base[src] != master[src])
        result[game] = {
            "tables": {"base": len(base), "master": len(master)},
            "edges": {"base": sum(len(v) for v in base.values()), "master": sum(len(v) for v in master.values())},
            "only_base": only_base[:40], "only_master": only_master[:40],
            "only_base_count": len(only_base), "only_master_count": len(only_master),
            "different_targets": differ[:40], "different_targets_count": len(differ),
            "switch_stats": stats,
        }
    Path(args.out).write_text(json.dumps(result, indent=1))
    print(f"wrote {args.out}")
    return 0


# ---------------------------------------------------------------------------
# attribute
# ---------------------------------------------------------------------------

def cmd_attribute(args) -> int:
    """Re-decompile every changed function with `master minus one commit group` builds.

    A variant is the master `ghidra_opt` with the listed upstream commits reverted
    (`--variant NAME=DIR`, DIR holding `ghidra_opt` and the shared cli/worker). For a
    changed function:
      restores   the variant prints what the base arm printed (that group alone explains it)
      moves      the variant prints something else than master did (the group contributes)
      none       the variant prints what master printed (the group is not involved)
    """
    work = Path(args.work)
    sample = {(row["game"], row["address"]): row for row in json.loads(Path(args.sample).read_text())["rows"]}
    classified = json.loads(Path(args.classified).read_text())
    changed = [row for row in classified["changed"] if row["base_ok"] and row["master_ok"]]
    if args.only:
        wanted = set(args.only.split(","))
        changed = [row for row in changed if row["game"] in wanted]
    variants = dict(item.split("=", 1) for item in args.variant)
    projects = {}
    for row in changed:
        name = Path(sample[(row["game"], row["address"])]["project"]).name
        projects[name] = work / "projects" / name
    out = {"variants": {}, "functions": len(changed)}
    detail = collections.defaultdict(dict)

    def one(item):
        name, directory, row = item
        source = sample[(row["game"], row["address"])]
        project = projects[Path(source["project"]).name]
        result = run_one(Path(directory), project, source, args.timeout)
        base = read_c(work, "base", row["game"], row["address"])
        master = read_c(work, "master", row["game"], row["address"])
        if not result["ok"]:
            return name, row, "failed", None
        text = normalise(result["text"])
        if text == normalise(base):
            return name, row, "restores", text
        if text != normalise(master):
            return name, row, "moves", text
        return name, row, "none", text

    jobs = [(name, directory, row) for name, directory in variants.items() for row in changed]
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        for name, row, label, _ in pool.map(one, jobs):
            entry = out["variants"].setdefault(name, {"restores": 0, "moves": 0, "none": 0, "failed": 0, "by_game": {}})
            entry[label] += 1
            game = entry["by_game"].setdefault(row["game"], {"restores": 0, "moves": 0, "none": 0, "failed": 0})
            game[label] += 1
            detail[(row["game"], row["address"])][name] = label
    # functions no single variant restores
    unexplained = [key for key, labels in detail.items() if "restores" not in labels.values()]
    out["unexplained_by_single_group"] = len(unexplained)
    out["examples"] = {name: [f"{g}:{a}" for (g, a), labels in detail.items() if labels.get(name) == "restores"][:12]
                       for name in variants}
    out["by_function"] = {f"{g}:{a}": labels for (g, a), labels in detail.items()}
    Path(args.out).write_text(json.dumps(out, indent=1))
    print(f"wrote {args.out}")
    return 0


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------

def load(path) -> dict | None:
    if not path:
        return None
    path = Path(path)
    return json.loads(path.read_text()) if path.is_file() else None


def delta(before, after, digits=4) -> str:
    if before is None or after is None:
        return "-"
    if before == after:
        return f"{before}"
    return f"{before} -> {after}"


def table(header: list[str], rows: list[list]) -> list[str]:
    out = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    for row in rows:
        out.append("| " + " | ".join("-" if cell is None else str(cell) for cell in row) + " |")
    return out


def wave_rows(base: dict, master: dict, prior: dict | None) -> tuple[list[dict], list[list]]:
    rows, cells = [], []
    games = [g for g in base["images"] if g in master["images"]]
    for game in games:
        b = base["images"][game]["configs"]["default"]
        m = master["images"][game]["configs"]["default"]
        bs, ms = b["summary"], m["summary"]
        row = {"game": game}
        for key in ("sampled", "decompiled", "success_rate", "recall", "precision", "discovered", "gotos", "labels",
                    "irregular_functions", "native_warnings", "lines", "median_seconds", "recall_verified",
                    "precision_verified"):
            row[key] = {"base": bs.get(key), "master": ms.get(key)}
        row["import_seconds"] = {"base": (b.get("import") or {}).get("seconds"), "master": (m.get("import") or {}).get("seconds")}
        row["switch_stats"] = {"base": (b.get("import") or {}).get("switch_stats"), "master": (m.get("import") or {}).get("switch_stats")}
        stock = ((prior or {}).get("images", {}).get(game, {}).get("stock") or {}).get("combined", {}).get("summary")
        row["stock_reference"] = stock
        rows.append(row)
        cells.append([game, delta(bs.get("discovered"), ms.get("discovered")),
                      delta(bs.get("recall"), ms.get("recall")), delta(bs.get("precision"), ms.get("precision")),
                      delta(bs.get("success_rate"), ms.get("success_rate")),
                      delta(bs.get("gotos"), ms.get("gotos")), delta(bs.get("labels"), ms.get("labels")),
                      delta(bs.get("irregular_functions"), ms.get("irregular_functions")),
                      delta(bs.get("lines"), ms.get("lines")),
                      (f"{stock['recall']} / {stock['precision']}" if stock else "-")])
    # the totals the verdict rests on, without the one image GP-7310 breaks
    keep = [r for r in rows if r["game"] != "n64-super-mario-64"]
    def total(key, arm):
        return sum((r[key][arm] or 0) for r in keep)
    cells.append(["all but n64-super-mario-64", delta(total("discovered", "base"), total("discovered", "master")),
                  "identical in every game" if all(r["recall"]["base"] == r["recall"]["master"] for r in keep) else "differs",
                  "identical in every game" if all(r["precision"]["base"] == r["precision"]["master"] for r in keep) else "differs",
                  delta(total("decompiled", "base"), total("decompiled", "master")) + " decompiled of " + str(total("sampled", "base")),
                  delta(total("gotos", "base"), total("gotos", "master")), delta(total("labels", "base"), total("labels", "master")),
                  delta(total("irregular_functions", "base"), total("irregular_functions", "master")),
                  delta(total("lines", "base"), total("lines", "master")), "-"])
    return rows, cells


def cmd_report(args) -> int:
    inputs_path = Path(args.inputs).resolve()
    out_json, out_md = Path(args.out_json).resolve(), Path(args.out_md).resolve()
    os.chdir(inputs_path.parent)  # the inputs name their files relative to themselves
    inputs = json.loads(inputs_path.read_text())
    notes = json.loads(Path(inputs["notes"]).read_text())
    result: dict = {"schema": 1, "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "environment": load(inputs.get("environment")), "notes": notes}
    md = [f"# Ghidra master trial ({datetime.now(timezone.utc).strftime('%Y-%m-%d')})", ""]
    md += [notes["summary_md"], ""]

    environment = result["environment"] or {}
    md += ["## Arms and environment", ""]
    md += table(["", "base", "master"], [
        ["decompiler C++", environment.get("base", {}).get("upstream"), environment.get("master", {}).get("upstream")],
        ["ghidra_opt sha256", environment.get("base", {}).get("ghidra_opt"), environment.get("master", {}).get("ghidra_opt")],
        ["native/ghidra-opt-sleigh.patch", environment.get("base", {}).get("patch"), environment.get("master", {}).get("patch")],
        ["romwright-cli / worker sha256", environment.get("cli"), environment.get("worker")],
        ["host", environment.get("host"), environment.get("host")],
        ["load while measuring", environment.get("load"), environment.get("load")]])
    md += [""]

    md += ["## Rebase of `native/ghidra-opt-sleigh.patch` and `native/romwright_*.hh` onto master", ""]
    rebase = notes["rebase"]
    md += [rebase["intro_md"], ""]
    md += ["### Textual conflicts (git three-way merge of the patch onto master)", ""]
    md += table(["file", "upstream commit", "what collided", "resolution", "behaviour"],
                [[c["file"], c["commit"], c["collision"], c["resolution"], c["behaviour"]] for c in rebase["conflicts"]])
    md += ["", "### Hunks that merged cleanly but no longer compiled or no longer matched the wire", ""]
    md += table(["where", "upstream commit", "break", "fix"],
                [[c["where"], c["commit"], c["break"], c["fix"]] for c in rebase["breaks"]])
    md += ["", "### Hooks added so the unchanged Rust keeps working (compat)", ""]
    md += table(["hook", "upstream commit", "why", "what it does"],
                [[c["hook"], c["commit"], c["why"], c["does"]] for c in rebase["compat"]])
    md += ["", rebase["tail_md"], ""]

    # --- wave
    wave_b, wave_m = load(inputs["wave"]["base"]), load(inputs["wave"]["master"])
    if wave_b and wave_m:
        rows, cells = wave_rows(wave_b, wave_m, load(inputs.get("prior_wave")))
        result["wave"] = rows
        md += ["## Console-research wave (each arm imports and decompiles on its own)", "",
               notes["wave_intro_md"], ""]
        md += table(["game", "functions found", "recall", "precision", "decompile success", "gotos", "labels",
                     "irregular fns", "printed lines", "stock Ghidra 12.1.3 recall / precision (prior wave, same either arm)"], cells)
        md += [""]
        sw = []
        for row in rows:
            b, m = row["switch_stats"]["base"] or {}, row["switch_stats"]["master"] or {}
            sw.append([row["game"], delta(b.get("vsa_resolved"), m.get("vsa_resolved")), delta(b.get("vsa_refused"), m.get("vsa_refused")),
                       delta(b.get("decompiler_skipped"), m.get("decompiler_skipped")),
                       delta(row["import_seconds"]["base"], row["import_seconds"]["master"])])
        fix = load(inputs.get("wave_fix"))
        if fix:
            for game, image in fix["images"].items():
                f = image["configs"]["default"]["summary"]
                b = base_row = next(r for r in rows if r["game"] == game)
                result.setdefault("wave_master_without_gp7310", {})[game] = f
                md += [f"`{game}` with master and the check GP-7310 added to `Varnode::setDef` removed (the commit's other changes stay): "
                       f"decompile success {f['success_rate']} ({f['decompiled']}/{f['sampled']}), gotos {f['gotos']}, labels {f['labels']}, "
                       f"irregular functions {f['irregular_functions']}, printed lines {f['lines']}, recall {f['recall']}, precision {f['precision']} "
                       f"(base: {b['success_rate']['base']}, {b['gotos']['base']}, {b['labels']['base']}, {b['irregular_functions']['base']}, {b['lines']['base']}).", ""]
        md += ["### Import switch stage", ""] + table(["game", "VSA resolved", "VSA refused", "decompiler skipped", "import seconds (load unrecorded)"], sw) + [""]
    switchdiff = load(inputs.get("switchdiff"))
    if switchdiff:
        result["switchdiff"] = switchdiff
        cells = [[g, delta(v["tables"]["base"], v["tables"]["master"]), delta(v["edges"]["base"], v["edges"]["master"]),
                  v["only_base_count"], v["only_master_count"], v["different_targets_count"]] for g, v in switchdiff.items()]
        md += ["### Stored switch tables per arm (COMPUTED_JUMP edges the import stored)", ""]
        md += table(["game", "tables", "edges", "only in base", "only in master", "same branch, other targets"], cells) + [""]

    # --- ps2 success
    success_b, success_m = load(inputs["ps2_success"]["base"]), load(inputs["ps2_success"]["master"])
    if success_b and success_m:
        cells, result["ps2_success"] = [], {}
        total = [0, 0, 0]
        for game in sorted(set(success_b["games"]) & set(success_m["games"])):
            b, m = success_b["games"][game], success_m["games"][game]
            cells.append([game, b["sampled"], f"{b['decompiled']} ({b['success_rate']})", f"{m['decompiled']} ({m['success_rate']})",
                          json.dumps(b["classes"]) if b["classes"] else "-", json.dumps(m["classes"]) if m["classes"] else "-",
                          f"{b['wall_seconds']} / {m['wall_seconds']}"])
            result["ps2_success"][game] = {"sampled": b["sampled"], "base": b["decompiled"], "master": m["decompiled"],
                                           "base_classes": b["classes"], "master_classes": m["classes"],
                                           "base_wall": b["wall_seconds"], "master_wall": m["wall_seconds"]}
            total[0] += b["sampled"]; total[1] += b["decompiled"]; total[2] += m["decompiled"]
        cells.append(["all", total[0], total[1], total[2], "", "",
                      f"{round(sum(v['base_wall'] for v in result['ps2_success'].values()), 1)} / {round(sum(v['master_wall'] for v in result['ps2_success'].values()), 1)}"])
        md += ["## PS2 decompile success on the wave samples (same projects, both decompilers)", "",
               "The two arms ran at the same time (3 jobs each), so the wall seconds are paired under one load; one `export-c` process per function.", ""]
        md += table(["game", "sampled", "base decompiled", "master decompiled", "base failure classes", "master failure classes",
                     "wall seconds base / master"], cells) + [""]

    # --- m21
    m21_b, m21_m = load(inputs["m21"]["base"]), load(inputs["m21"]["master"])
    if m21_b and m21_m:
        cells, result["m21"] = [], {}
        for image in m21_b["rows"]:
            b, m = m21_b["rows"][image], (m21_m["rows"].get(image) or {})
            cells.append([image, b.get("status"), m.get("status"), delta(b.get("recall"), m.get("recall")),
                          delta(b.get("precision"), m.get("precision")), delta(b.get("seconds"), m.get("seconds"))])
            result["m21"][image] = {"base": {k: b.get(k) for k in ("status", "recall", "precision", "seconds", "failures")},
                                    "master": {k: m.get(k) for k in ("status", "recall", "precision", "seconds", "failures")}}
        md += ["## m21-001 real images (function recovery; the import's switch stage runs the decompiler)", ""]
        md += table(["image", "base", "master", "recall", "precision", "seconds (load unrecorded)"], cells)
        md += ["", f"Overall: base {m21_b.get('status')}, master {m21_m.get('status')}.", ""]

    # --- m22
    m22 = inputs.get("m22") or {}
    if m22:
        result["m22"] = {}
        md += ["## m22-002 compiled C against the retail bytes (romwright layer only; Persona 4, 200 functions per lane)", "",
               notes["m22_intro_md"], ""]
        cells = []
        for lane, paths in m22.items():
            b, m = load(paths.get("base")), load(paths.get("master"))
            if not (b and m):
                continue
            result["m22"][lane] = {}
            pair = {}
            for arm, report in (("base", b), ("master", m)):
                for variant in ("context", "standalone", "best"):
                    summary = report["summary"]["overall"]["all"]["romwright"][variant]
                    result["m22"][lane].setdefault(variant, {})[arm] = summary
            for variant in ("context", "standalone"):
                bs, ms = result["m22"][lane][variant]["base"], result["m22"][lane][variant]["master"]
                cells.append([lane, variant, delta(bs["compiled"], ms["compiled"]), delta(bs["exact"], ms["exact"]),
                              delta(bs["mean_percent"], ms["mean_percent"]), delta(bs["percent_ge_90"], ms["percent_ge_90"])])
            # paired per function
            wins = losses = ties = 0
            for key, entry in b["functions"].items():
                other = m["functions"].get(key)
                if not other:
                    continue
                x = entry["layers"]["romwright"]["variants"]["context"]["percent"] if entry["layers"]["romwright"]["variants"]["context"]["compiled"] else 0.0
                y = other["layers"]["romwright"]["variants"]["context"]["percent"] if other["layers"]["romwright"]["variants"]["context"]["compiled"] else 0.0
                x, y = x or 0.0, y or 0.0
                if y > x + 1e-9: wins += 1
                elif y < x - 1e-9: losses += 1
                else: ties += 1
            result["m22"][lane]["paired_context"] = {"master_better": wins, "master_worse": losses, "same": ties}
            cells.append([lane, "paired (context percent)", f"master better {wins}", f"worse {losses}", f"same {ties}", ""])
        md += table(["lane", "variant", "compiled", "exact", "mean percent", "percent >= 90"], cells) + [""]

    # --- function diff
    classified = load(inputs.get("classified"))
    if classified:
        result["function_diff"] = {k: v for k, v in classified.items() if k != "changed"}
        result["function_diff"]["changed_examples"] = classified["changed"][:60]
        t = classified["totals"]
        md += ["## Function-level output diff (same project, both decompilers)", "",
               f"{t['functions']} functions. Identical text: {t['identical']}. Changed: {t['changed']} "
               f"(better {t['better']}, worse {t['worse']}, neutral {t['neutral']}). Printed by base / master: {t['base_ok']} / {t['master_ok']}. "
               f"Timeouts base / master: {t['base_timeouts']} / {t['master_timeouts']}.", ""]
        cells = []
        for game, g in classified["games"].items():
            cells.append([game, g["functions"], g["identical"], g["changed"], g["better"], g["worse"], g["neutral"],
                          f"{g['base_ok']} / {g['master_ok']}", f"{g['median_seconds']['base']} / {g['median_seconds']['master']}", g["median_pair_ratio"]])
        md += table(["game", "functions", "identical", "changed", "better", "worse", "neutral", "printed base / master",
                     "median seconds base / master", "median paired ratio"], cells) + [""]
        reasons = collections.Counter()
        for game in classified["games"].values():
            for key, count in game["reasons"].items():
                reasons[key] += count
        md += ["Reasons behind the verdicts (a function can carry several):", ""]
        md += table(["verdict:metric", "functions"], [[k, v] for k, v in sorted(reasons.items())]) + [""]
        timing = classified["timing"]
        md += [f"Paired timing: {timing['pairs']} pairs, median master/base ratio {timing['median_pair_ratio']}, master slower in "
               f"{timing['master_slower_pairs']} pairs; host load1 median {timing['load1_median']}, max {timing['load1_max']}. "
               f"{timing['note']}.", ""]

    fixed = load(inputs.get("classified_n64_fixed"))
    if fixed:
        result["function_diff_n64_without_gp7310"] = {k: v for k, v in fixed.items() if k != "changed"}
        g = fixed["games"].get("n64-super-mario-64")
        if g:
            md += [f"Nintendo 64 against master with GP-7310's added check removed: {g['functions']} functions, identical {g['identical']}, changed {g['changed']} "
                   f"(better {g['better']}, worse {g['worse']}, neutral {g['neutral']}), printed base / master {g['base_ok']} / {g['master_ok']}.", ""]

    # --- printer diff
    pd_b, pd_m = load((inputs.get("printer_diff") or {}).get("base")), load((inputs.get("printer_diff") or {}).get("master"))
    if pd_b and pd_m:
        cells = []
        result["printer_diff"] = {}
        for image_b in pd_b["images"]:
            image_m = next((i for i in pd_m["images"] if i["image"] == image_b["image"]), None)
            if not image_m:
                continue
            cells.append([image_b["image"], f"{image_b['identical']}/{image_b['decompiled']}", f"{image_m['identical']}/{image_m['decompiled']}",
                          json.dumps(image_b["categories"]), json.dumps(image_m["categories"]), image_m["decompile_errors"]])
            result["printer_diff"][image_b["image"]] = {"base": {k: image_b[k] for k in ("decompiled", "identical", "categories", "decompile_errors")},
                                                         "master": {k: image_m[k] for k in ("decompiled", "identical", "categories", "decompile_errors")}}
        md += ["## Printer differential (Rust printer from the exported IR against each decompiler's own PrintC)", "",
               notes["printer_intro_md"], ""]
        md += table(["image", "base identical", "master identical", "base differences", "master differences", "master decompile errors"], cells) + [""]

    # --- attribution
    attribution = load(inputs.get("attribution"))
    result["attribution_groups"] = notes["attribution_groups"]
    if attribution:
        result["attribution"] = {k: v for k, v in attribution.items() if k != "by_function"}
        md += ["## Attribution: master minus one commit group, on the changed functions", "",
               f"{attribution['functions']} changed functions that both arms printed. `restores` = the variant prints the 12.1.3 text "
               f"(that group alone explains the change); `moves` = the variant prints something else than master (the group contributes); "
               f"`none` = the group is not involved. {attribution['unexplained_by_single_group']} functions are restored by no single group.", ""]
        cells = []
        for name, v in attribution["variants"].items():
            cells.append([name, notes["attribution_groups"].get(name, {}).get("commits", ""), v["restores"], v["moves"], v["none"], v["failed"]])
        md += table(["group", "reverted commits", "restores 12.1.3 text", "moves the text", "not involved", "failed"], cells) + [""]
    md += ["## Individual findings", ""]
    for finding in notes["findings"]:
        md += [f"### {finding['title']}", "", finding["body_md"], ""]

    md += ["## Port reference list: upstream commits since 12.1.3 the Rust port should take as its reference", "",
           notes["port_intro_md"], ""]
    for stage in notes["port_reference"]:
        md += [f"### {stage['stage']}", "", stage["scope_md"], ""]
        md += table(["commit", "title", "why the port needs it"], [[f"`{c['commit']}`", c["title"], c["reason"]] for c in stage["commits"]]) + [""]
    md += ["## Recommendation", "", notes["recommendation_md"], "", "## Limits", ""]
    md += [f"- {item}" for item in notes["limits"]]
    result["recommendation"] = notes["recommendation_md"]
    out_json.write_text(json.dumps(result, indent=1, default=str) + "\n")
    out_md.write_text("\n".join(md) + "\n")
    print(f"wrote {out_json} and {out_md}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    s = sub.add_parser("sample")
    s.add_argument("--wave", required=True)
    s.add_argument("--out", required=True)
    s.add_argument("--seed", type=int, default=20261012)
    s.add_argument("--quota", default="ps2=150,*=200", help="functions per game by platform prefix")
    s.add_argument("--cache", default="")
    e = sub.add_parser("export")
    e.add_argument("--sample", required=True)
    e.add_argument("--base-bin", required=True)
    e.add_argument("--master-bin", required=True)
    e.add_argument("--work", required=True)
    e.add_argument("--jobs", type=int, default=3)
    e.add_argument("--timeout", type=int, default=600)
    c = sub.add_parser("classify")
    c.add_argument("--work", required=True)
    c.add_argument("--out", required=True)
    a = sub.add_parser("attribute")
    a.add_argument("--work", required=True)
    a.add_argument("--sample", required=True)
    a.add_argument("--classified", required=True)
    a.add_argument("--variant", action="append", default=[], metavar="NAME=BINDIR")
    a.add_argument("--only", default="", help="comma-separated games")
    a.add_argument("--jobs", type=int, default=3)
    a.add_argument("--timeout", type=int, default=600)
    a.add_argument("--out", required=True)
    r = sub.add_parser("report")
    r.add_argument("--inputs", required=True)
    r.add_argument("--out-json", default=str(REPORTS / "ghidra_master_trial.json"))
    r.add_argument("--out-md", default=str(REPORTS / "ghidra_master_trial.md"))
    w = sub.add_parser("switchdiff")
    w.add_argument("--base-wave", required=True)
    w.add_argument("--master-wave", required=True)
    w.add_argument("--out", required=True)
    args = parser.parse_args()
    return {"sample": cmd_sample, "export": cmd_export, "classify": cmd_classify,
            "switchdiff": cmd_switchdiff, "attribute": cmd_attribute,
            "report": cmd_report}[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
