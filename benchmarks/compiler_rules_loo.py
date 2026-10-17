#!/usr/bin/env python3
"""Leave-one-out evaluation of the compiler rules (docs/compiler-rules.md).

For every rule in `crates/romwright-core/compiler_rules/` (read through
`romwright-cli compiler-rules --json`, so the harness measures what the
binary ships) and every corpus game the rule covers and that is NOT in the
rule's `derived_from`, the rule is compared **on against off** on the same
build:

  import      the game is imported twice, rule on and rule off (the off arm
              sets ROMWRIGHT_COMPILER_RULES_DISABLE=<id>; a `candidate` or
              `off` rule's on arm sets ROMWRIGHT_COMPILER_RULES_ENABLE=<id>).
              Stored facts are digested (functions, thunks, return behaviours,
              flow overrides, xrefs, symbols); an import-level rule whose two
              digests are equal has no effect on this game.
  discovery   recall and precision against the game's truth, scored by the
              wave's own metric (tests/m21-001 `score`) on both imports.
  decompile   `export-c --address` of the functions the rule can reach (the
              functions whose stored rows differ between the arms, the
              callers of the helpers the rule names) plus a fixed stratified
              sample, on both arms: success, gotos, labels, irregular
              functions, native warnings, `unaff_` locals, and how many
              printed functions differ. Counts are compared over the
              functions both arms decompiled.

Outputs are deterministic, so any difference is real: there is no noise
floor. A rule `helps` a game when some judged metric improves and none
worsens, `hurts` it in the reverse case, `mixed` when both happen, and is
`neutral` when none moves. An arm that did not finish (import deadline) loses
to one that did.

Policy (the bar a rule must clear to ship `on`):

  learned     helps at least one held-out game and hurts none;
  migrated    behaviour that shipped before the rule layer existed, moved to
              data unchanged: hurts no held-out game. Whether it also helps is
              reported, and a migrated rule with no held-out game to measure on
              is reported as `unmeasured`, not as proven.

A rule that cannot be measured with the metrics above (`c-canonical`: its only
judge is the objdiff match of a C-output lane, and the one lane that exists, m22-002
on Persona 4, is where the rules were derived) is reported `pending lanes`: the
per-game lanes `tests/m22-003_ps2_multigame_c.py` (Ps2Lanes) are the held-out
C-output source, and until they exist nothing is inferred from Persona 4.

    python3 benchmarks/compiler_rules_loo.py --target-dir DIR --cache DIR --out OUT.json \
        [--rules id,id] [--games game,game] [--sample 40] [--jobs 3]
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


CR = load_module("console_research_loo", ROOT / "benchmarks" / "console_research.py")
WAVE = CR.wave
M21 = CR.M21

DISABLE = "ROMWRIGHT_COMPILER_RULES_DISABLE"
ENABLE = "ROMWRIGHT_COMPILER_RULES_ENABLE"
UNKNOWN = "unknown"

# The loader `format` of each platform's image (the rule `formats` key).
FORMAT = {"ps2": "elf32", "psp": "PRX", "gc": "dol", "wii": "dol", "gba": "gba", "nds": "nds", "n64": "n64",
          "psx": "psx", "x360": "xex"}

# Judged metrics (higher is better) for every rule: the wave's discovery metrics and decompile success.
RATES = ("recall", "precision", "success")
# Counts reported for every rule and never judged (structure statistics, like the wave's lines and time).
COUNTS = ("gotos", "labels", "irregular", "native_warnings", "unaff", "sled_calls")
# Counts judged (lower is better) because they are what the rule kind is for: a register-save helper that is not
# expanded stays in the printed C as a call (`FUN_<sled entry>(...)`) and leaves the callee-saved registers as
# `unaff_rN` locals.
JUDGED_COUNTS = {"register-sled": ("unaff", "sled_calls"), "literal-pool-extent": ("size_long",)}
# Rates judged (higher is better) because they are what the rule kind is for: a function extent that runs through
# its literal pool makes the stored size equal the truth size (the wave's `size_exact`).
JUDGED_RATES = {"literal-pool-extent": ("size_exact",)}


def covers(pattern: str, identifier: str) -> bool:
    if pattern == "*":
        return identifier not in (UNKNOWN, "")
    return identifier == pattern or identifier.startswith(pattern + "-")


def rule_covers(rule: dict, compiler: str, language: str, fmt: str) -> bool:
    """Mirror of `compiler::rules::covers_program`."""
    if rule["languages"] and not any(language.startswith(p) for p in rule["languages"]):
        return False
    if rule["formats"] and fmt not in rule["formats"]:
        return False
    if compiler in (UNKNOWN, ""):
        return rule["unknown"]
    return any(covers(p, compiler) for p in rule["compilers"])


def digest(project: Path, program: str) -> dict:
    db = sqlite3.connect(f"file:{project}/project.sqlite?mode=ro", uri=True)
    try:
        pid = db.execute("SELECT id FROM programs WHERE name=?", (program,)).fetchone()[0]
        queries = {
            "functions": "SELECT entry,name,size FROM functions WHERE program_id=? ORDER BY entry",
            "thunks": "SELECT function,thunked,kind FROM thunks WHERE program_id=? ORDER BY 1,2,3",
            "return_behaviors": "SELECT function,no_return,provenance FROM return_behaviors WHERE program_id=? ORDER BY 1",
            "flow_overrides": "SELECT address,kind,provenance FROM flow_overrides WHERE program_id=? ORDER BY 1,2",
            "xrefs": "SELECT src,dst,kind FROM xrefs WHERE program_id=? ORDER BY 1,2,3",
            "symbols": "SELECT address,name,source FROM symbols WHERE program_id=? ORDER BY 1,2,3",
        }
        rows = {name: db.execute(sql, (pid,)).fetchall() for name, sql in queries.items()}
        compiler, language = db.execute("SELECT compiler,language FROM programs WHERE id=?", (pid,)).fetchone()
    finally:
        db.close()
    return {"rows": rows, "compiler": compiler, "language": language,
            "digest": {name: [len(r), hashlib.sha256(repr(r).encode()).hexdigest()[:12]] for name, r in rows.items()}}


def changed_entries(a: dict, b: dict) -> list[int]:
    """Entries of functions present in both arms whose stored row differs, plus the sides of changed
    thunks and return behaviours, in address order."""
    fa = {r[0]: r for r in a["rows"]["functions"]}
    fb = {r[0]: r for r in b["rows"]["functions"]}
    out = {int(e, 16) for e in fa.keys() & fb.keys() if fa[e] != fb[e]}
    for table, columns in (("thunks", (0, 1)), ("return_behaviors", (0,)), ("flow_overrides", (0,))):
        sa, sb = set(map(tuple, a["rows"][table])), set(map(tuple, b["rows"][table]))
        for row in sa ^ sb:
            for column in columns:
                try:
                    entry = int(row[column], 16)
                except (ValueError, TypeError):
                    continue
                out.add(entry)
    present = {int(e, 16) for e in fa.keys() & fb.keys()}
    return sorted(out & present)


def function_of(entries: list[int], address: int) -> int | None:
    import bisect
    index = bisect.bisect_right(entries, address) - 1
    return entries[index] if index >= 0 else None


def callers_of_helpers(project: Path, program: str, patterns: tuple[str, ...]) -> list[int]:
    """Entries of the functions that call a function whose name matches one of the GLOB `patterns`."""
    db = sqlite3.connect(f"file:{project}/project.sqlite?mode=ro", uri=True)
    try:
        pid = db.execute("SELECT id FROM programs WHERE name=?", (program,)).fetchone()[0]
        where = " OR ".join("name GLOB ?" for _ in patterns)
        helpers = {row[0] for row in db.execute(f"SELECT entry FROM functions WHERE program_id=? AND ({where})",
                                                (pid, *patterns))}
        entries = sorted(int(row[0], 16) for row in db.execute("SELECT entry FROM functions WHERE program_id=?", (pid,)))
        sources = {int(row[0], 16) for row in db.execute(
            "SELECT src,dst FROM xrefs WHERE program_id=? AND kind LIKE '%CALL'", (pid,)) if row[1] in helpers}
    finally:
        db.close()
    callers = {function_of(entries, src) for src in sources}
    return sorted(c for c in callers if c is not None and f"{c:08x}" not in helpers)


def stratified(entries: list[int], sizes: dict[int, int], count: int) -> list[int]:
    """`count` entries spread evenly over the size-sorted functions: a fixed, truth-free sample."""
    ordered = sorted(entries, key=lambda e: (sizes.get(e, 0), e))
    if len(ordered) <= count:
        return sorted(ordered)
    step = len(ordered) / count
    return sorted({ordered[int(i * step)] for i in range(count)})


def unaff(text: str) -> int:
    return len(re.findall(r"\bunaff_\w+", text))


class Arm:
    """One configuration of one game: its import, its stored facts and its printed functions."""

    def __init__(self, label: str, env: dict):
        self.label, self.env = label, env
        self.project: Path | None = None
        self.marker: dict | None = None
        self.facts: dict | None = None
        self.error: str | None = None
        self.printed: dict[int, dict] = {}


def import_arm(tools, spec, binary, sha, truth, cache, arm: Arm) -> None:
    try:
        arm.project, arm.marker = CR.import_env_project(tools, spec, binary, sha, arm.env, truth, cache)
        arm.facts = digest(arm.project, arm.marker["program"])
    except subprocess.TimeoutExpired:
        arm.error = f"import did not finish in {spec.get('limit_s')} s"
    except (RuntimeError, OSError, subprocess.SubprocessError, KeyError, TypeError) as error:
        arm.error = str(error)[-300:]


def decompile_arm(tools, binary, arm: Arm, addresses: list[int], jobs: int, work: Path,
                  helper_call: re.Pattern | None = None) -> None:
    config = CR.Config(arm.label, arm.env, "loo", None)
    program = arm.marker["program"]

    def one(address: int):
        row = CR.decompile_one(tools, arm.project, binary, program, address, config, work / arm.label)
        if row.get("success"):
            text = (work / arm.label / f"{address:08x}.c").read_text(errors="replace")
            row["unaff"] = unaff(text)
            row["sled_calls"] = len(helper_call.findall(text)) if helper_call else 0
        return address, row

    with ThreadPoolExecutor(max_workers=jobs) as pool:
        arm.printed = dict(pool.map(one, addresses))


def summarize(on: Arm, off: Arm, addresses: list[int]) -> dict:
    """Paired metrics of the on and off arms over `addresses`."""
    both = [a for a in addresses if on.printed.get(a, {}).get("success") and off.printed.get(a, {}).get("success")]
    out = {"decompiled": len(addresses), "paired_success": len(both)}
    for arm, tag in ((on, "on"), (off, "off")):
        ok = [a for a in addresses if arm.printed.get(a, {}).get("success")]
        out[f"success_{tag}"] = round(len(ok) / max(len(addresses), 1), 4)
        for metric in COUNTS:
            out[f"{metric}_{tag}"] = sum(arm.printed[a].get(metric, 0) for a in both)
        out[f"lines_{tag}"] = sum(arm.printed[a].get("lines", 0) for a in both)
    differing = [a for a in both if on.printed[a]["sha256"] != off.printed[a]["sha256"]]
    out["differ"] = len(differing)
    out["differ_sample"] = [f"{a:08x}" for a in differing[:8]]
    failed_on = [f"{a:08x}" for a in addresses if not on.printed.get(a, {}).get("success")]
    failed_off = [f"{a:08x}" for a in addresses if not off.printed.get(a, {}).get("success")]
    out["failed_on"], out["failed_off"] = failed_on[:6], failed_off[:6]
    return out


def verdict_of(metrics: dict, kind: str = "") -> tuple[str, list[str]]:
    """helps / hurts / mixed / neutral of the rule (on against off) from `metrics`."""
    better, worse = [], []
    for name in RATES + JUDGED_RATES.get(kind, ()):
        on, off = metrics.get(f"{name}_on"), metrics.get(f"{name}_off")
        if on is None or off is None:
            continue
        (better if on > off else worse if on < off else []).append(f"{name} {off} -> {on}")
    for name in JUDGED_COUNTS.get(kind, ()):
        on, off = metrics.get(f"{name}_on"), metrics.get(f"{name}_off")
        if on is None or off is None:
            continue
        (better if on < off else worse if on > off else []).append(f"{name} {off} -> {on}")
    if metrics.get("off_dnf") and not metrics.get("on_dnf"):
        better.append("the off arm did not finish")
    if metrics.get("on_dnf") and not metrics.get("off_dnf"):
        worse.append("the on arm did not finish")
    if better and worse:
        return "mixed", better + ["but"] + worse
    if better:
        return "helps", better
    if worse:
        return "hurts", worse
    return "neutral", []


def c_lane_functions(args, tools, lane: str, tag: str, env: dict) -> dict:
    """One romwright-layer run of a C-output lane (`tests/m22-003_ps2_multigame_c.py`, Ps2Lanes) under `env`:
    {address: {"compiled": bool, "exact": bool, "percent": float}} of its fixed sample, `context` variant."""
    work = args.c_lane_work
    work.mkdir(parents=True, exist_ok=True)
    out, report = work / f"{lane}-{tag}.functions.json", work / f"{lane}-{tag}.report.json"
    if not out.is_file():
        argv = [str(args.c_lane_python), str(args.c_lane_script), lane, "--work", str(work), "--tools-cache", str(args.c_lane_tools),
                "--repo", str(args.c_lane_repos / lane), "--layers", "romwright", "--tag", tag, "--cli", str(tools.cli),
                "--worker", str(tools.worker), "--ghidra-opt", str(CR.GHIDRA_OPT), "--functions-out", str(out), "--report", str(report)]
        for key, value in sorted(env.items()):
            argv += ["--env", f"{key}={value}"]
        # Every arm starts from a fresh import by the tools under test (so the project records their compiler id):
        # the lane's romwright layer asserts names and prototypes into its project as it goes, and a project reused
        # across arms carries one arm's assertions into the next (measured: the same arm compiled 125 and then 133
        # of ff's 200 functions).
        argv.append("--fresh-import")
        CR.log(f"C lane {lane} [{tag}] {env or 'default'}")
        run = subprocess.run(argv, cwd=args.c_lane_script.parents[1], capture_output=True, text=True,
                             env=dict(os.environ, ROMWRIGHT_NO_IMPORT_CACHE="1", ROMWRIGHT_NO_FACT_PACK="1"))
        if run.returncode or not out.is_file():
            raise RuntimeError(f"C lane {lane} failed: {(run.stderr or run.stdout)[-400:]}")
    functions = json.loads(out.read_text())["functions"]
    rows = {}
    for address, row in functions.items():
        cell = (row.get("layers", {}).get("romwright", {}) or {}).get("context") or {}
        rows[address] = {"compiled": bool(cell.get("compiled")), "exact": bool(cell.get("exact")),
                         "percent": float(cell.get("percent") or 0.0)}
    return rows


def c_lane_verdict(on: dict, off: dict) -> dict:
    """Paired m22 metrics of a rule on against off over one lane's fixed sample."""
    keys = sorted(set(on) & set(off))
    better = [k for k in keys if on[k]["percent"] > off[k]["percent"] + 1e-9]
    worse = [k for k in keys if on[k]["percent"] < off[k]["percent"] - 1e-9]
    row = {"lane_functions": len(keys),
           "m22_exact_on": sum(on[k]["exact"] for k in keys), "m22_exact_off": sum(off[k]["exact"] for k in keys),
           "m22_compiled_on": sum(on[k]["compiled"] for k in keys), "m22_compiled_off": sum(off[k]["compiled"] for k in keys),
           "m22_mean_on": round(sum(on[k]["percent"] for k in keys) / max(len(keys), 1), 3),
           "m22_mean_off": round(sum(off[k]["percent"] for k in keys) / max(len(keys), 1), 3),
           "m22_better": len(better), "m22_worse": len(worse), "m22_same": len(keys) - len(better) - len(worse),
           "m22_better_sample": better[:6], "m22_worse_sample": worse[:6]}
    good, bad = [], []
    for name in ("exact", "compiled", "mean"):
        a, b = row[f"m22_{name}_on"], row[f"m22_{name}_off"]
        (good if a > b else bad if a < b else []).append(f"m22 {name} {b} -> {a}")
    row["verdict"] = "mixed" if good and bad else "helps" if good else "hurts" if bad else "neutral"
    row["reasons"] = good + (["but"] + bad if good and bad else bad)
    return row


def evaluate(tools, spec, binary, sha, truth, cache, rule: dict, base: Arm, args, work: Path) -> dict:
    """Rule on against off for one game; `base` is the default (shipped) arm."""
    if rule["kind"] == "c-canonical":
        # A print-time rewrite: judged by the objdiff match of a C-output lane (m22 exact / compiled / mean over the
        # lane's fixed sample), run with the rule on and off. A game with no lane is `pending lanes`: nothing is
        # inferred from Persona 4, where the rewrites were derived.
        lane = args.c_lane_of.get(spec["id"])
        if lane is None:
            return {"verdict": "unmeasured", "reasons": ["pending lanes: no C-output lane for this game"]}
        try:
            on_rows = c_lane_functions(args, tools, lane, "on", {})
            off_rows = c_lane_functions(args, tools, lane, "off-" + rule["id"], {DISABLE: rule["id"]})
        except RuntimeError as error:
            return {"verdict": "unmeasured", "reasons": [f"C lane {lane} did not run: {error}"[:200]]}
        row = c_lane_verdict(on_rows, off_rows)
        row["lane"] = lane
        return row
    shipped_on = rule["status"] == "on"
    if shipped_on:
        on = base
        off = Arm(f"{rule['id']}-off", {DISABLE: rule["id"]})
        import_arm(tools, spec, binary, sha, truth, cache, off)
    else:
        on = Arm(f"{rule['id']}-on", {ENABLE: rule["id"]})
        off = base
        import_arm(tools, spec, binary, sha, truth, cache, on)
    row: dict = {"on_dnf": on.error is not None, "off_dnf": off.error is not None}
    for arm, tag in ((on, "on"), (off, "off")):
        row[f"import_seconds_{tag}"] = arm.marker.get("seconds") if arm.marker else None
        row[f"error_{tag}"] = arm.error
        if arm.marker and "discovery" in arm.marker:
            d = arm.marker["discovery"]
            row[f"recall_{tag}"], row[f"precision_{tag}"] = d["recall"], d["precision"]
            if d.get("sizes_compared"):
                row[f"size_exact_{tag}"] = round(d["size_exact"] / d["sizes_compared"], 4)
                row[f"size_long_{tag}"] = d["size_long"]
            row[f"found_{tag}"] = d.get("found")
    if on.error or off.error:
        row["verdict"], row["reasons"] = verdict_of(row, rule["kind"])
        return row
    row["compiler"] = on.facts["compiler"]
    row["facts_identical"] = on.facts["digest"] == off.facts["digest"]
    row["facts_diff"] = {name: [on.facts["digest"][name][0], off.facts["digest"][name][0]]
                         for name in on.facts["digest"] if on.facts["digest"][name] != off.facts["digest"][name]}
    kind = rule["kind"]
    if kind == "c-canonical":
        row["verdict"], row["reasons"] = "unmeasured", ["pending lanes"]
        return row
    sizes = {int(r[0], 16): r[2] for r in on.facts["rows"]["functions"]}
    entries = sorted(sizes)
    reach = changed_entries(on.facts, off.facts)
    if kind == "register-sled":
        reach = sorted(set(reach) | set(callers_of_helpers(
            on.project, on.marker["program"], ("_savegpr_*", "_restgpr_*", "_savefpr_*", "_restfpr_*"))))
    needs_decompile = bool(reach) if kind in ("flag", "nonreturn-names", "literal-pool-extent") else True
    row["reach"] = len(reach)
    if not needs_decompile and row["facts_identical"]:
        row["verdict"], row["reasons"] = "neutral", ["stored facts identical; nothing to decompile differently"]
        return row
    stride = max(1, len(reach) // max(args.reach, 1))
    reach = reach[::stride][: args.reach]
    sample = stratified(entries, sizes, args.sample)
    addresses = sorted(set(reach) | set(sample))
    helper_call = None
    if kind == "register-sled":
        # Calls to the helpers, by name (naming pass on) or by the generated name of the entry (off).
        entries = [r[0] for r in on.facts["rows"]["functions"] if re.fullmatch(r"_(?:save|rest)[gf]pr_\d+", r[1])]
        alternatives = [f"FUN_{e}" for e in entries] + [r"_(?:save|rest)[gf]pr_\d+"]
        helper_call = re.compile(r"\b(?:" + "|".join(alternatives) + r")\s*\(")
    decompile_arm(tools, binary, on, addresses, args.jobs, work / "text", helper_call)
    decompile_arm(tools, binary, off, addresses, args.jobs, work / "text", helper_call)
    row.update(summarize(on, off, addresses))
    row["verdict"], row["reasons"] = verdict_of(row, rule["kind"])
    return row


def policy(rule: dict, games: dict[str, dict]) -> dict:
    """The bar `rule` has to clear to hold its status, from its per-game verdicts."""
    held = {g: r for g, r in games.items() if g not in rule["derived_from"]}
    verdicts = {g: r["verdict"] for g, r in held.items()}
    helps = [g for g, v in verdicts.items() if v in ("helps",)]
    hurts = [g for g, v in verdicts.items() if v in ("hurts", "mixed")]
    measured = [g for g, v in verdicts.items() if v not in ("unmeasured",)]
    learned = rule["origin"] == "learned"
    if not measured:
        status = "pending lanes" if rule["kind"] == "c-canonical" else "no held-out game"
        met = not learned  # a learned rule needs evidence; a migrated one keeps its inherited behaviour
        return {"held_out": sorted(held), "helps": [], "hurts": [], "outcome": status, "met": met,
                "bar": "learned: helps >= 1 held-out game, hurts none" if learned else "migrated: hurts no held-out game"}
    if learned:
        met = bool(helps) and not hurts
        bar = "helps >= 1 held-out game and hurts none"
    else:
        met = not hurts
        bar = "hurts no held-out game (migrated)"
    outcome = "hurts" if hurts else ("helps" if helps else "neutral")
    return {"held_out": sorted(held), "helps": helps, "hurts": hurts, "outcome": outcome, "met": met, "bar": bar}


def render(report: dict) -> str:
    lines = ["# Compiler rules: leave-one-out", "",
             f"Generated {report['generated']} by `benchmarks/compiler_rules_loo.py`; tools `{report['tools']}` "
             f"(`romwright-cli`, `romwright-worker`, `ghidra_opt`), decompile sample {report['sample']} stratified "
             f"functions + up to {report['reach']} the rule can reach per game. {report['note']}", "",
             "Each cell compares the rule **on** against **off** on one build, per game the rule covers and that is not in its "
             "`derived_from`. Outputs are deterministic: any difference is real. `helps`: a judged metric improves, none "
             "worsens; `hurts`: the reverse; `mixed`: both; `neutral`: none moves (for an import-level rule with identical "
             "stored facts nothing is decompiled). Judged: recall, precision and decompile success (and, for `register-sled`, the helper calls left visible and "
             "the `unaff_` locals; for `literal-pool-extent`, the share of exact stored sizes and the number of too-long ones); gotos, labels, irregular functions, native warnings and the number of printed functions "
             "that differ are reported, not judged (counts over functions both arms decompiled).", "",
             "## Rules", "", "| rule | kind | status | origin | covered games | held out | helps | hurts | neutral | outcome | bar met |",
             "|---|---|---|---|---|---|---|---|---|---|---|"]
    for rule in report["rules"]:
        games = rule["games"]
        held = rule["policy"]["held_out"]
        neutral = [g for g in held if games[g]["verdict"] == "neutral"]
        lines.append(f"| `{rule['id']}` | {rule['kind']} | {rule['status']} | {rule['origin']} | {len(games)} | {len(held)} | "
                     f"{len(rule['policy']['helps'])} | {len(rule['policy']['hurts'])} | {len(neutral)} | "
                     f"{rule['policy']['outcome']} | {'yes' if rule['policy']['met'] else '**NO**'} |")
    lines += [""]
    for rule in report["rules"]:
        if rule.get("excluded"):
            lines_excluded = ", ".join(f"{g} ({row['verdict']})" for g, row in sorted(rule["excluded"].items())
                                       if row["verdict"] not in ("unmeasured", "derived"))
        else:
            lines_excluded = ""
        lines += [f"### `{rule['id']}`", "",
                  f"{rule['note']}", "",
                  f"kind `{rule['kind']}`, status `{rule['status']}`, origin `{rule['origin']}`, compilers "
                  f"`{', '.join(rule['compilers'])}`{' (and unknown)' if rule['unknown'] else ''}; derived from: "
                  f"{', '.join(rule['derived_from']) or '-'}. Bar: {rule['policy']['bar']}; outcome **{rule['policy']['outcome']}**.", ""]
        if lines_excluded:
            lines += [f"Measured, then excluded by narrowing the rule's compilers (no longer covered; their rows are in the JSON "
                      f"under `excluded`): {lines_excluded}.", ""]
        if not rule["games"]:
            lines += ["No corpus game in the loaded set is covered by this rule.", ""]
            continue
        if all(row["verdict"] in ("unmeasured", "derived") for row in rule["games"].values()):
            covered = sorted(rule["games"])
            lines += [f"Covers {len(covered)} corpus games ({', '.join(covered[:6])}{', ...' if len(covered) > 6 else ''}); "
                      f"none can be measured with the metrics above, so no on/off run was made. "
                      f"{rule['games'][covered[0]].get('reasons', [''])[0]}.", ""]
            continue
        lines += ["| game | compiler | held out | verdict | facts | recall on / off | precision on / off | success on / off | "
                  "size exact on / off | gotos | labels | unaff | warnings | printed differ | reach | import s on / off | "
                  "m22 exact on / off | m22 mean on / off | m22 better / worse |",
                  "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
        pending = sorted(g for g, row in rule["games"].items() if row["verdict"] == "unmeasured")
        if pending and len(pending) < len(rule["games"]):
            lines.insert(len(lines) - 2, f"Games covered with no C-output lane, so not measured (pending lanes): {len(pending)} "
                                         f"({', '.join(pending[:5])}{', ...' if len(pending) > 5 else ''}).")
            lines.insert(len(lines) - 2, "")
        for game, row in sorted(rule["games"].items()):
            if row["verdict"] == "unmeasured" and len(pending) < len(rule["games"]):
                continue
            held = "no" if game in rule["derived_from"] else "yes"
            facts = "identical" if row.get("facts_identical") else ("differ " + json.dumps(row.get("facts_diff", {}))[:60])
            pair = lambda k: (f"{row.get(k + '_on', '-')} / {row.get(k + '_off', '-')}")  # noqa: E731
            lines.append(f"| {game} | {row.get('compiler', '-')} | {held} | {row['verdict']} | {facts} | {pair('recall')} | "
                         f"{pair('precision')} | {pair('success')} | {pair('size_exact')} | {pair('gotos')} | {pair('labels')} | {pair('unaff')} | "
                         f"{pair('native_warnings')} | {row.get('differ', '-')} | {row.get('reach', '-')} | {pair('import_seconds')} | {pair('m22_exact')} | {pair('m22_mean')} | "
                         f"{row.get('m22_better', '-')} / {row.get('m22_worse', '-')} |")
            if row.get("reasons"):
                lines.append(f"|  | | | {'; '.join(row['reasons'])[:220]} | | | | | | | | | | | | | | | |")
        lines.append("")
    if report.get("neutrality"):
        same = [g for g, n in report["neutrality"].items() if n.get("identical")]
        diff = {g: n for g, n in report["neutrality"].items() if n.get("identical") is False}
        bad = {g: n for g, n in report["neutrality"].items() if n.get("identical") is None}
        lines += ["## Behaviour neutrality of the migration", "",
                  f"Every game imported with a build of the tree before the rule layer (tools `{report['baseline_tools']}`) and with "
                  f"this one with every shipped rule on except the learned ones (the migrated rules only): stored facts (functions, "
                  f"thunks, return behaviours, flow overrides, xrefs, symbols) identical on **{len(same)} of {len(report['neutrality'])}** games.", ""]
        changed = {g: n["with_learned_rules"] for g, n in report["neutrality"].items() if n.get("with_learned_rules")}
        if changed:
            lines += [f"With the shipped learned rules on as well, the stored facts of {len(changed)} games differ from the "
                      f"baseline, as those rules intend: " + "; ".join(f"{g} {json.dumps(v)}" for g, v in sorted(changed.items())[:8])
                      + ("; ..." if len(changed) > 8 else ""), ""]
        for game, n in sorted(diff.items()):
            lines.append(f"* {game}: differs in {n['differing']} (baseline, rules)")
        for game, n in sorted(bad.items()):
            lines.append(f"* {game}: baseline import failed: {n['error'][:120]}")
        lines.append("")
    lines += ["## Games and their compilers", "", "| game | platform | compiler | language |", "|---|---|---|---|"]
    for game, info in sorted(report["games"].items()):
        lines.append(f"| {game} | {info['platform']} | {info['compiler']} | {info['language']} |")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--corpus", type=Path, default=M21.CORPUS)
    parser.add_argument("--target-dir", type=Path, default=ROOT / "target")
    parser.add_argument("--cache", type=Path, default=None, help="harness cache (projects, stripped binaries); not the research-eval cache")
    parser.add_argument("--work", type=Path, default=None)
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--rules", default="", help="comma-separated rule ids (default: all)")
    parser.add_argument("--games", default="", help="comma-separated game ids (default: every wave game)")
    parser.add_argument("--platforms", default="", help="restrict to platforms (ps2,gba,...)")
    parser.add_argument("--sample", type=int, default=40, help="stratified functions decompiled per game and arm")
    parser.add_argument("--reach", type=int, default=60, help="at most this many functions the rule can reach")
    parser.add_argument("--jobs", type=int, default=3)
    parser.add_argument("--import-limit-s", type=int, default=3600)
    parser.add_argument("--baseline-target-dir", type=Path, default=None,
                        help="a build of the tree before the rule layer: every game is also imported with it and the "
                             "stored facts compared with the default arm (behaviour neutrality of the migration)")
    parser.add_argument("--c-lanes", default="", help="C-output lanes for the printed-C rules: lane=game,lane=game "
                                                      "(e.g. dds=ps2-digital-devil-saga,ff=ps2-fatal-frame)")
    parser.add_argument("--c-lane-script", type=Path, default=ROOT / "tests" / "m22-003_ps2_multigame_c.py")
    parser.add_argument("--c-lane-python", type=Path, default=Path(sys.executable))
    parser.add_argument("--c-lane-work", type=Path, default=None)
    parser.add_argument("--c-lane-tools", type=Path, default=None, help="the lanes' --tools-cache")
    parser.add_argument("--c-lane-repos", type=Path, default=None, help="directory holding one checkout per lane")
    parser.add_argument("--merge", type=Path, default=None, metavar="REPORT_JSON",
                        help="start from this report and replace the rules this run measured (a later run for a subset of "
                             "rules, e.g. the printed-C rules once their lanes exist)")
    parser.add_argument("--merge-games", action="store_true",
                        help="with --merge: add this run's games to the rule entries instead of replacing them")
    parser.add_argument("--merge-reports", nargs="+", type=Path, default=None, metavar="REPORT_JSON",
                        help="with --out and --base: fold these reports' per-game rows into the base report's rules and exit")
    parser.add_argument("--refresh-rules", action="store_true",
                        help="with --merge-reports: take every rule's definition from `romwright-cli compiler-rules` of "
                             "--target-dir and move the games a rule no longer covers to its `excluded` list "
                             "(a narrowing chosen from these measurements)")
    parser.add_argument("--detected-from", type=Path, default=None, metavar="ACCURACY_JSON",
                        help="with --refresh-rules: take each game's compiler id from this detection report (the ids of the "
                             "build the rules are refreshed against)")
    parser.add_argument("--base", type=Path, default=None, help="the report --merge-reports starts from")
    parser.add_argument("--render-only", type=Path, default=None, metavar="REPORT_JSON",
                        help="rewrite the Markdown beside REPORT_JSON from the report and exit")
    parser.add_argument("--note", default="")
    args = parser.parse_args()
    if args.merge_reports:
        base = json.loads(args.base.read_text())
        by_id = {r["id"]: r for r in base["rules"]}
        for path in args.merge_reports:
            other = json.loads(path.read_text())
            base["games"].update(other["games"])
            for rule in other["rules"]:
                mine = by_id.get(rule["id"])
                if mine is None:
                    continue
                for game, row in rule["games"].items():
                    if row["verdict"] != "unmeasured" or game not in mine["games"] or mine["games"][game]["verdict"] == "unmeasured":
                        mine["games"][game] = row
        if args.refresh_rules:
            if args.detected_from:
                detected = {row["game"]: row["detected"] for row in json.loads(args.detected_from.read_text())["games"]
                            if row.get("status") == "ran"}
                for game, info in base["games"].items():
                    info["compiler"] = detected.get(game.removesuffix("-symtab"), info["compiler"])
            tools = CR.Tools(args.target_dir)
            current = {r["id"]: r for r in json.loads(subprocess.run([str(tools.cli), "compiler-rules", "--json"], capture_output=True,
                                                                      text=True, check=True, env=tools.env({})).stdout)}
            for rid, rule in by_id.items():
                new = current[rid]
                changed = [k for k in ("compilers", "unknown", "languages", "formats", "status", "derived_from") if rule[k] != new[k]]
                rule.update({k: new[k] for k in ("compilers", "unknown", "languages", "formats", "status", "origin", "note", "derived_from")})
                rule["definition_changed_since_measured"] = changed
                excluded = {}
                for game in list(rule["games"]):
                    info = base["games"][game]
                    if not rule_covers(rule, info["compiler"], info["language"], FORMAT.get(info["platform"], "")):
                        excluded[game] = rule["games"].pop(game)
                rule["excluded"] = excluded
        for rule in by_id.values():
            held = {g: row for g, row in rule["games"].items() if row["verdict"] != "derived"}
            rule["policy"] = policy(rule, held)
        base["merged_from"] = [str(p.name) for p in args.merge_reports]
        if args.note:
            base["note"] = (base.get("note", "") + " " + args.note).strip()
        args.out.write_text(json.dumps(base, indent=2, default=str) + "\n")
        args.out.with_suffix(".md").write_text(render(base))
        return 0
    if args.render_only:
        report = json.loads(args.render_only.read_text())
        args.render_only.with_suffix(".md").write_text(render(report))
        return 0
    if args.cache is None or args.out is None:
        parser.error("--cache and --out are required")
    args.work = args.work or args.cache / "work"
    args.c_lane_of = {}
    for item in [i for i in args.c_lanes.split(",") if i]:
        lane, _, game = item.partition("=")
        args.c_lane_of[game] = lane
    args.c_lane_work = args.c_lane_work or args.cache / "c-lanes"

    tools = CR.Tools(args.target_dir)
    rules = json.loads(subprocess.run([str(tools.cli), "compiler-rules", "--json"], capture_output=True, text=True,
                                      check=True, env=tools.env({})).stdout)
    learned_on = [r["id"] for r in rules if r["origin"] == "learned" and r["status"] == "on"]
    wanted_rules = {r for r in args.rules.split(",") if r}
    unknown = wanted_rules - {r["id"] for r in rules}
    if unknown:
        parser.error(f"unknown rules {sorted(unknown)}")
    rules = [r for r in rules if not wanted_rules or r["id"] in wanted_rules]
    wanted_games = {g for g in args.games.split(",") if g}
    platforms = {p for p in args.platforms.split(",") if p}
    specs, skipped = WAVE.discover(args.corpus, wanted_games, 0.0, symtab_variants=True)
    specs = [s for s in specs if not platforms or s["wave"]["platform"] in platforms]
    for spec in specs:
        spec["limit_s"] = args.import_limit_s

    games: dict[str, dict] = {}
    base_arms: dict[str, tuple] = {}
    CR.log(f"tools {tools.fingerprint}; {len(specs)} games, {len(rules)} rules")
    for spec in specs:
        gid = spec["id"]
        source = args.corpus / spec["image"]
        if not source.is_file():
            continue
        binary = CR.prepared_binary(spec, args.corpus, args.cache)
        sha = CR.sha256_file(source)
        truth = CR.function_truth(spec, args.corpus)
        base = Arm("default", {})
        import_arm(tools, spec, binary, sha, truth, args.cache, base)
        if base.error:
            CR.log(f"{gid}: default import failed: {base.error}")
            continue
        platform = spec["wave"]["platform"]
        games[gid] = {"platform": platform, "compiler": base.facts["compiler"], "language": base.facts["language"],
                      "default_seconds": base.marker.get("seconds")}
        base_arms[gid] = (spec, binary, sha, truth, base)
        CR.log(f"{gid}: compiler {base.facts['compiler'] or '(none)'} language {base.facts['language']}")

    neutrality: dict[str, dict] = {}
    if args.baseline_target_dir:
        baseline = CR.Tools(args.baseline_target_dir)
        CR.log(f"baseline tools {baseline.fingerprint}")
        for gid, (spec, binary, sha, truth, base) in base_arms.items():
            arm = Arm("baseline", {})
            import_arm(baseline, spec, binary, sha, truth, args.cache, arm)
            if arm.error:
                neutrality[gid] = {"identical": None, "error": arm.error}
                continue
            # The migrated rules reproduce the baseline; a learned rule shipped `on` changes it on purpose, so the
            # comparison switches the learned rules off (and the rows that differ with them on are listed apart).
            migrated = base
            if learned_on:
                migrated = Arm("migrated-only", {DISABLE: ",".join(learned_on)})
                import_arm(tools, spec, binary, sha, truth, args.cache, migrated)
                if migrated.error:
                    neutrality[gid] = {"identical": None, "error": migrated.error}
                    continue
            differing = {name: [arm.facts["digest"][name][0], migrated.facts["digest"][name][0]]
                         for name in arm.facts["digest"] if arm.facts["digest"][name] != migrated.facts["digest"][name]}
            with_learned = {name: [arm.facts["digest"][name][0], base.facts["digest"][name][0]]
                            for name in arm.facts["digest"] if arm.facts["digest"][name] != base.facts["digest"][name]}
            neutrality[gid] = {"identical": not differing, "differing": differing, "functions": arm.facts["digest"]["functions"][0],
                               "with_learned_rules": with_learned if learned_on else None,
                               "seconds_baseline": arm.marker.get("seconds"), "seconds_rules": base.marker.get("seconds")}
            CR.log(f"neutrality {gid}: {'identical' if not differing else differing}")

    report_rules = []
    for rule in rules:
        per_game: dict[str, dict] = {}
        for gid, (spec, binary, sha, truth, base) in base_arms.items():
            info = games[gid]
            if not rule_covers(rule, info["compiler"], info["language"], FORMAT.get(info["platform"], "")):
                continue
            # `-symtab` variants carry the base game's derivation.
            root = gid.removesuffix("-symtab")
            if root in rule["derived_from"]:
                per_game[gid] = {"verdict": "derived", "reasons": ["the rule was derived on this game"]}
                continue
            CR.log(f"{rule['id']} x {gid}")
            started = time.monotonic()
            work = args.work / rule["id"] / gid
            per_game[gid] = evaluate(tools, spec, binary, sha, truth, args.cache, rule, base, args, work)
            per_game[gid]["seconds"] = round(time.monotonic() - started, 1)
            CR.log(f"  -> {per_game[gid]['verdict']} {per_game[gid].get('reasons', '')}")
        derived = {g.removesuffix("-symtab") for g in rule["derived_from"]}
        view = dict(rule, derived_from=sorted(derived))
        held = {g: r for g, r in per_game.items() if r["verdict"] != "derived"}
        report_rules.append({**view, "games": {g: r for g, r in per_game.items()},
                             "policy": policy(view, {g: r for g, r in held.items()})})
    report = {"generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"), "tools": tools.fingerprint,
              "sample": args.sample, "reach": args.reach, "note": args.note, "games": games, "rules": report_rules,
              "wave_skipped": skipped, "baseline_tools": baseline.fingerprint if args.baseline_target_dir else None,
              "neutrality": neutrality}
    if args.merge:
        base = json.loads(args.merge.read_text())
        by_id = {r["id"]: r for r in base["rules"]}
        for r in report_rules:
            if r["id"] in by_id and args.merge_games:
                # Games measured by this run join the ones the base report already holds for the rule.
                merged_games = {**by_id[r["id"]]["games"], **{g: row for g, row in r["games"].items()
                                                              if row["verdict"] != "unmeasured" or g not in by_id[r["id"]]["games"]}}
                held = {g: row for g, row in merged_games.items() if row["verdict"] != "derived"}
                r = {**r, "games": merged_games, "policy": policy(r, held)}
            by_id[r["id"]] = r
        order = [r["id"] for r in base["rules"]] + [r["id"] for r in report_rules if r["id"] not in {b["id"] for b in base["rules"]}]
        report = {**base, "rules": [by_id[i] for i in order], "games": {**base["games"], **games},
                  "note": (base.get("note", "") + " " + args.note).strip(),
                  "merged": [r["id"] for r in report_rules]}
    args.out.write_text(json.dumps(report, indent=2, default=str) + "\n")
    args.out.with_suffix(".md").write_text(render(report))
    failing = [r["id"] for r in report["rules"] if r["status"] == "on" and not r["policy"]["met"]]
    CR.log(f"report {args.out}; rules below their bar: {failing or 'none'}")
    return 1 if failing else 0


if __name__ == "__main__":
    sys.exit(main())
