#!/usr/bin/env python3
"""What a gate buys: wrong-name rate against renames kept, for the fact pack's auto-applied `FUN_` renames.

benchmarks/fact_pack_eval.py's leave-one-out report says 4.5% of scoreable renames are wrong. A wrong name
costs a user more than a missing one, so this study keeps every rename of the 48 donor games' leave-one-out
run with the facts a gate could use, scores each against truth with the eval's classifier, and replays
candidate gates over the rows. Nothing here changes the pack, the CLI or the LOO report.

Stage 1 (collect, per donor game, on the host): `romwright facts apply --exclude <game>` on a private
copy of the game's default cached import (no --scan: scan rows never rename). Each rename becomes a row:
address, pack length, the agreeing donors (and their compiler families), platform, the target's compiler
family (truth meta.json: `oracle`) and the family detected from the run itself (the family of the apply
report's `implied_compiler`, the donors' compiler vote: what a user's import can know), and the verdict:

  correct       equal after normalizing, or after reducing to the base name (eval's `judge`)
  spelling / affix / collision / different
                a wrong name, by eval's `pair_kind`; `collision` is split into `name_in_target` (the pack's
                name is also the truth name of another function of the target: rule A) and `mangled` (both
                names are different mangled / qualified methods)
  unscoreable   no truth row at the address, or a generic truth name

Alias or wrong function, inside `different`:
  rule A  the pack's name is also the truth name of another function of the target -> wrong function
          (already how `collision` is assigned, so it settles no `different` row by construction).
  rule B  the truth name at this address is a name some other donor gives to a body whose masked digest
          equals this one -> alias. "Other": every donor except the excluded game and its twin group
          (the excluded game's own row has the same digest and the truth name by construction, so it
          would settle every row). Donors dropped from the consensus as stubs count here, since they still
          name the body. The pack is read directly (bodies.digest, never bytes).
  The rows neither rule settles are sampled for eyeballing.

Two definitions of wrong: strict = every scoreable non-correct rename; function-wrong = `collision` rows
(rule A, or both names mangled methods): the rename put the name of one function on another.

Stage 2 replays gates over the rows: minimum body length, at least two agreeing donors below a length, the
donor compiler family equal to the target's (detected or oracle; any agreeing donor, or all), and
combinations; overall and per platform.

  python3 benchmarks/fact_pack_gating.py --cli <romwright-cli> --pack <pack>
"""
from __future__ import annotations

import argparse
import collections
import concurrent.futures
import json
import random
import shutil
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "benchmarks"))
sys.path.insert(0, str(ROOT / "benchmarks" / "fact_pack"))
import fact_pack_eval as ev  # noqa: E402

RUNS = Path.home() / "runs" / "FactEval"
MIN_LENGTHS = (32, 48, 64, 96, 128)
ALWAYS = 1 << 30  # "below N" with N beyond every body: at least two donors, whatever the length
TWO_DONOR_BELOW = (None, 64, 128, ALWAYS)
FAMILY_MODES = ("none", "detected_any", "detected_all", "oracle_any")
SAMPLE = 20


# ---------------------------------------------------------------------------
# Row classification (pure)
# ---------------------------------------------------------------------------

def classify(name: str, truth_name: str | None, truth_names) -> dict:
    """Verdict fields of one rename. `truth_names`: normalized names and base names of the target's truth."""
    if truth_name is None:
        return {"verdict": "unscoreable", "why": "no_truth"}
    verdict = ev.judge(name, truth_name)
    if verdict == "generic":
        return {"verdict": "unscoreable", "why": "generic_truth"}
    if verdict != "wrong":
        return {"verdict": "correct", "why": verdict}
    kind = ev.pair_kind(name, truth_name, truth_names)
    row = {"verdict": kind}
    # Rule A holds for any wrong name the target also uses for another function, whatever pair_kind said first.
    row["name_in_target"] = ev.normalize(name) in truth_names or ev.normalize(ev.base_name(name)) in truth_names
    if kind == "collision":
        row["collision_source"] = "name_in_target" if row["name_in_target"] else "mangled"
    return row


def is_scoreable(row: dict) -> bool:
    return row["verdict"] != "unscoreable"


def is_correct(row: dict) -> bool:
    return row["verdict"] == "correct"


def strict_wrong(row: dict) -> bool:
    return is_scoreable(row) and not is_correct(row)


def function_wrong(row: dict) -> bool:
    """A collision (the name of one function put on another): rule A or two different mangled methods. A
    name that is also another function's truth name is a collision even when pair_kind first called it affix."""
    return row["verdict"] == "collision" or (strict_wrong(row) and bool(row.get("name_in_target")))


# ---------------------------------------------------------------------------
# Gates (pure)
# ---------------------------------------------------------------------------

def gate_name(min_len: int, two_below: int | None, family: str, by_source: bool = False) -> str:
    parts = [f"len>={min_len}" if min_len != MIN_LENGTHS[0] else "len>=32 (any)"]
    noun = "independent donors (twin groups merged)" if by_source else "donors"
    if two_below == ALWAYS:
        parts.append(f">=2 {noun}")
    elif two_below:
        parts.append(f">=2 {noun} if len<{two_below}")
    if family != "none":
        parts.append({"detected_any": "family = detected (any donor)", "detected_all": "family = detected (all donors)",
                      "oracle_any": "family = truth (any donor)"}[family])
    return ", ".join(parts)


def keeps(row: dict, min_len: int, two_below: int | None, family: str, by_source: bool = False) -> bool:
    if row["length"] < min_len:
        return False
    if two_below and row["length"] < two_below and row["n_sources" if by_source else "n_donors"] < 2:
        return False
    if family == "none":
        return True
    target = row["detected_family"] if family.startswith("detected") else row["target_family"]
    families = row["donor_families"]
    if family.endswith("_all"):
        return bool(families) and all(f == target for f in families)
    return target in families


def all_gates() -> list[tuple[int, int | None, str, bool]]:
    """(min length, two-donor limit, family mode, count independent sources instead of games)."""
    return [(m, t, f, source) for f in FAMILY_MODES for m in MIN_LENGTHS for t in TWO_DONOR_BELOW
            for source in ((False, True) if t else (False,))]


def tally(rows: list[dict]) -> dict:
    """Counts and rates of a set of kept renames."""
    scoreable = sum(is_scoreable(r) for r in rows)
    correct = sum(is_correct(r) for r in rows)
    wrong = sum(strict_wrong(r) for r in rows)
    fwrong = sum(function_wrong(r) for r in rows)
    return {"kept": len(rows), "scoreable": scoreable, "correct": correct, "strict_wrong": wrong,
            "function_wrong": fwrong, "strict_rate": ev.rate(wrong, scoreable), "function_rate": ev.rate(fwrong, scoreable)}


def evaluate_gates(rows: list[dict]) -> list[dict]:
    """Every gate of the grid over `rows` (duplicates of an earlier gate's kept set dropped)."""
    out, seen = [], set()
    total = len(rows)
    for min_len, two_below, family, by_source in all_gates():
        kept = [i for i, r in enumerate(rows) if keeps(r, min_len, two_below, family, by_source)]
        key = tuple(kept)
        if key in seen:
            continue
        seen.add(key)
        result = tally([rows[i] for i in kept])
        result.update(gate=gate_name(min_len, two_below, family, by_source), min_len=min_len, two_donors_below=two_below,
                      family=family, by_source=by_source, kept_fraction=ev.rate(len(kept), total))
        out.append(result)
    return out


def best_gates(gates: list[dict], cap: float, key: str = "strict_rate") -> dict | None:
    """The gate keeping the most correct renames with `key` (a rate) at or under `cap`."""
    fits = [g for g in gates if g[key] is not None and g[key] <= cap]
    return max(fits, key=lambda g: (g["correct"], -g["strict_wrong"]), default=None)


# ---------------------------------------------------------------------------
# Alias evidence (pack side)
# ---------------------------------------------------------------------------

class PackIndex:
    """The named bodies of the pack by (family, length, digest) and (family, length, name), read once."""

    def __init__(self, pack: Path):
        db = sqlite3.connect(f"file:{pack}?mode=ro", uri=True)
        self.by_digest: dict[tuple, list[tuple[str, str]]] = collections.defaultdict(list)
        self.by_name: dict[tuple, set[bytes]] = collections.defaultdict(set)
        # bodies of one digest a donor holds (named or not): two or more make it a stub for that donor
        self.copies: dict[tuple, int] = {}
        for family, length, digest, game, count in db.execute(
                "SELECT b.family, b.length, b.digest, d.game, COUNT(*) FROM bodies b JOIN donors d ON d.id = b.donor "
                "GROUP BY b.family, b.length, b.digest, d.game HAVING COUNT(*) > 1"):
            self.copies[(family, length, digest, game)] = count
        for family, length, digest, name, game in db.execute(
                "SELECT b.family, b.length, b.digest, b.name, d.game FROM bodies b JOIN donors d ON d.id = b.donor "
                "WHERE b.name IS NOT NULL"):
            self.by_digest[(family, length, digest)].append((name, game))
            self.by_name[(family, length, name)].add(digest)
        db.close()

    def alias_donors(self, family: str, length: int, pack_name: str, donors: list[str], truth_name: str,
                     excluded: set[str]) -> list[tuple[str, bool]]:
        """(donor game, is a stub there) for donors outside `excluded` that name a body of the pack name's digest
        with the truth name (equal after normalizing, or base name). The digest is the one the agreeing donors
        gave `pack_name`. A donor holding the body twice is a stub there and is dropped from the consensus,
        which is the only way such a donor can disagree with the pack's name without making the match ambiguous."""
        found = []
        for digest in self.by_name.get((family, length, pack_name), ()):
            rows = self.by_digest[(family, length, digest)]
            if not any(game in donors for name, game in rows if name == pack_name):
                continue
            for name, game in rows:
                if game not in excluded and ev.judge(name, truth_name) in ("correct_strict", "correct", "correct_scope"):
                    found.append((game, self.copies.get((family, length, digest, game), 1) > 1))
        return sorted(set(found))

    def target_row(self, family: str, length: int, pack_name: str, donors: list[str], truth_name: str,
                   target: set[str]) -> bool:
        """The excluded game's own row of that digest carries the truth name (true whenever our body is the
        truth function's: it cannot separate an alias from a collision)."""
        for digest in self.by_name.get((family, length, pack_name), ()):
            rows = self.by_digest[(family, length, digest)]
            if any(game in donors for name, game in rows if name == pack_name) and any(
                    game in target and ev.judge(name, truth_name) != "wrong" for name, game in rows):
                return True
        return False


# ---------------------------------------------------------------------------
# Collection
# ---------------------------------------------------------------------------

def compiler_family_of_string(text: str | None, by_compiler: dict[str, str]) -> str | None:
    if not text:
        return None
    return by_compiler.get(text) or ev.compiler_family(text)


def collect_game(game: str, args, pack_info: dict, index: PackIndex, by_compiler: dict) -> dict:
    import units as unit_lib
    work = args.work / game
    resolved = unit_lib.game_units(game, args.corpus, args.cache, work, args.fingerprint, jobs=1)
    if "error" in resolved:
        return {"game": game, "status": "no_run", "reason": resolved["error"], "rows": []}
    donors = pack_info["donor_rows"]
    excluded = ev.twin_games(game, donors)
    target_family = ev.compiler_family(resolved["compiler"], resolved["platform"])
    copies: dict[str, Path] = {}
    rows, units = [], []
    try:
        for unit in resolved["units"]:
            copy = copies.get(unit["project"])
            if copy is None:
                copy = copies[unit["project"]] = unit_lib.copy_project(
                    unit["project"], work / f"p{len(copies)}-{Path(unit['project']).name[:60]}")
            try:
                report = ev.run_apply(args.cli, copy, unit["program"], args.pack, [game], False, args.timeout, args.env)
            except (RuntimeError, ValueError, subprocess.SubprocessError) as error:
                units.append({"program": unit["program"], "status": "error", "reason": str(error)[-300:]})
                continue
            implied = report.get("implied_compiler")
            detected = compiler_family_of_string(implied, by_compiler)
            truth = unit["truth"]
            names = frozenset(ev.normalize(n) for _, n in truth.values()) | frozenset(
                ev.normalize(ev.base_name(n)) for _, n in truth.values())
            inside = lambda a: not unit["ranges"] or any(lo <= a < hi for lo, hi in unit["ranges"])  # noqa: E731
            for m in report.get("matches") or []:
                address = ev.to_int(m["address"])
                if m.get("action") != "renamed" or not m.get("name") or not inside(address):
                    continue
                entry = truth.get(address)
                row = classify(m["name"], entry[1] if entry else None, names)
                row.update(game=game, platform=resolved["platform"], target_family=target_family,
                           detected_family=detected, implied_compiler=implied, program=unit["program"],
                           address=address, length=int(m["length"]), name=m["name"],
                           truth_name=entry[1] if entry else None, truth_size=entry[0] if entry else None,
                           our_size=m.get("our_size"), donors=m["donors"], n_donors=len(m["donors"]),
                           n_sources=len({(donors[d].get("twin_group") or d) if d in donors else d for d in m["donors"]}),
                           donor_families=sorted({pack_info["families"].get(d, "unknown") for d in m["donors"]}),
                           family=m.get("family"))
                if row["verdict"] == "different" and entry:
                    row["alias_donors"] = index.alias_donors(m.get("family"), row["length"], m["name"], m["donors"],
                                                             entry[1], excluded)
                    row["target_row_has_truth_name"] = index.target_row(
                        m.get("family"), row["length"], m["name"], m["donors"], entry[1], {game} | excluded)
                rows.append(row)
            units.append({"program": unit["program"], "status": "ok", "implied_compiler": implied,
                          "detected_family": detected, "renamed": report.get("renamed")})
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return {"game": game, "status": "ok" if units and all(u["status"] == "ok" for u in units) else "partial",
            "platform": resolved["platform"], "target_family": target_family, "units": units, "rows": rows}


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def classes(rows: list[dict]) -> dict:
    counts = collections.Counter()
    for r in rows:
        if r["verdict"] == "unscoreable":
            counts[f"unscoreable.{r['why']}"] += 1
        elif r["verdict"] == "correct":
            counts["correct"] += 1
            counts[f"correct.{r['why']}"] += 1
        else:
            counts[r["verdict"]] += 1
            if r.get("collision_source"):
                counts[f"collision.{r['collision_source']}"] += 1
            if r.get("name_in_target") and r["verdict"] != "collision":
                counts[f"{r['verdict']}.name_in_target"] += 1
    counts["total"] = len(rows)
    return dict(counts)


def settle_different(rows: list[dict], seed: int) -> dict:
    different = [r for r in rows if r["verdict"] == "different"]
    rule_a = [r for r in different if r.get("name_in_target")]
    alias = [r for r in different if r.get("alias_donors")]
    unsettled = [r for r in different if not r.get("name_in_target") and not r.get("alias_donors")]
    rng = random.Random(seed)
    picked = rng.sample(unsettled, min(SAMPLE, len(unsettled)))
    show = lambda r: {  # noqa: E731
        "game": r["game"], "address": f"{r['address']:#x}", "truth": r["truth_name"], "pack": r["name"],
        "length": r["length"], "donors": r["n_donors"], "donor_games": r["donors"][:4],
        "target_row_has_truth_name": r.get("target_row_has_truth_name")}
    return {"different": len(different), "rule_a_wrong_function": len(rule_a), "rule_b_alias": len(alias),
            "unsettled": len(unsettled),
            "target_row_has_truth_name": sum(bool(r.get("target_row_has_truth_name")) for r in different),
            "rule_b_alias_via_stub_only": sum(all(stub for _, stub in r["alias_donors"]) for r in alias),
            "alias_examples": [{"truth": r["truth_name"], "pack": r["name"], "length": r["length"],
                                "other_donors": [f"{g}{' (stub there)' if stub else ''}" for g, stub in r["alias_donors"]]}
                               for r in alias[:10]],
            "unsettled_sample": [show(r) for r in picked]}


def breakdowns(rows: list[dict]) -> dict:
    """Wrong rates by the number of agreeing donors and by body length, ungated."""
    def bucket(label, subset):
        t = tally(subset)
        t["bucket"] = label
        return t
    donors = [("1 donor", lambda r: r["n_donors"] == 1), ("2 donors", lambda r: r["n_donors"] == 2),
              ("3-4 donors", lambda r: 3 <= r["n_donors"] <= 4), ("5+ donors", lambda r: r["n_donors"] >= 5)]
    lengths = [("32-47 B", lambda r: r["length"] < 48), ("48-63 B", lambda r: 48 <= r["length"] < 64),
               ("64-95 B", lambda r: 64 <= r["length"] < 96), ("96-127 B", lambda r: 96 <= r["length"] < 128),
               ("128+ B", lambda r: r["length"] >= 128)]
    return {"by_donors": [bucket(label, [r for r in rows if f(r)]) for label, f in donors],
            "by_length": [bucket(label, [r for r in rows if f(r)]) for label, f in lengths]}


def pct(value) -> str:
    return "-" if value is None else f"{value * 100:.2f}%"


def gate_table(gates: list[dict]) -> list[str]:
    lines = ["| gate | renames kept | % kept | scoreable | correct | strict wrong | strict rate | function-wrong | function rate |",
             "|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for g in gates:
        lines.append(f"| {g['gate']} | {g['kept']:,} | {pct(g['kept_fraction'])} | {g['scoreable']:,} | {g['correct']:,} "
                     f"| {g['strict_wrong']:,} | {pct(g['strict_rate'])} | {g['function_wrong']:,} | {pct(g['function_rate'])} |")
    return lines


def markdown(report: dict) -> str:
    c = report["classes"]
    s = report["settle"]
    lines = ["# Fact pack gating study", "",
             f"Generated {report['generated']} by `benchmarks/fact_pack_gating.py`; pack `{Path(report['pack']['path']).name}` "
             f"({report['pack']['bytes'] / 1e6:.1f} MB, {report['pack']['donors']} donors), `romwright-cli` {report['cli_sha']}. "
             "Leave-one-out over the 48 donor games (twin groups excluded); every `FUN_` rename the pack made, scored "
             "against truth with the LOO report's classifier. Definitions: see the script's docstring.", "",
             "## The renames", "",
             f"- renames: {c['total']:,}; scoreable {report['overall']['scoreable']:,}; correct {c.get('correct', 0):,} "
             f"(strict equal {c.get('correct.correct_strict', 0):,}, base name {c.get('correct.correct', 0):,}, "
             f"base name but another class {c.get('correct.correct_scope', 0):,}); unscoreable "
             f"{c.get('unscoreable.generic_truth', 0) + c.get('unscoreable.no_truth', 0):,}",
             f"- strict wrong (every scoreable non-correct): {report['overall']['strict_wrong']:,} "
             f"({pct(report['overall']['strict_rate'])}): spelling {c.get('spelling', 0):,}, affix {c.get('affix', 0):,}, "
             f"collision {c.get('collision', 0):,}, different {c.get('different', 0):,}",
             f"- function-wrong (collision: another function of the target has this name, or both are different mangled "
             f"methods): {report['overall']['function_wrong']:,} ({pct(report['overall']['function_rate'])}); of the "
             f"{c.get('collision', 0):,} collision rows {c.get('collision.name_in_target', 0):,} are rule A (name in target), "
             f"{c.get('collision.mangled', 0):,} mangled-vs-mangled", ""]
    lines += ["## Aliases and wrong functions inside `different`", "",
              f"- `different` rows: {s['different']:,}",
              f"- rule A (the pack's name is the truth name of another function of the target): settles "
              f"{s['rule_a_wrong_function']:,}. It is already how `collision` is assigned, so it cannot settle a row "
              f"left in `different`.",
              f"- rule B (another donor, outside the excluded game and its twins, names the same digest with the truth "
              f"name): settles {s['rule_b_alias']:,} as alias; {s['rule_b_alias_via_stub_only']:,} of them only through a donor "
              f"that holds the body twice (a stub there: a shared tiny body, which is evidence of a collision more than of an alias)",
              f"- unsettled: {s['unsettled']:,} of {s['different']:,}",
              f"- not a usable rule: the excluded game's own row of the same digest carries the truth name in "
              f"{s['target_row_has_truth_name']:,} of {s['different']:,} `different` rows (it holds whenever our body is "
              f"the truth function's, alias or not).", ""]
    if s["alias_examples"]:
        lines += ["Rule B aliases (examples):", ""] + [
            f"- truth `{a['truth']}` = pack `{a['pack']}` ({a['length']} B; truth name also given by {', '.join(a['other_donors'])})" for a in s["alias_examples"]] + [""]
    lines += [f"### {len(s['unsettled_sample'])} random unsettled pairs", "",
              "| game | address | truth name | pack name | length | agreeing donors | donor games |",
              "|---|---|---|---|---:|---:|---|"]
    lines += [f"| {x['game']} | {x['address']} | `{x['truth']}` | `{x['pack']}` | {x['length']} | {x['donors']} "
              f"| {', '.join(x['donor_games'])} |" for x in s["unsettled_sample"]]
    for title, key in (("Ungated, by the number of agreeing donors", "by_donors"), ("Ungated, by pack body length", "by_length")):
        lines += ["", f"## {title}", "", "| bucket | renames | scoreable | correct | strict wrong | strict rate | function-wrong | function rate |",
                  "|---|---:|---:|---:|---:|---:|---:|---:|"]
        lines += [f"| {b['bucket']} | {b['kept']:,} | {b['scoreable']:,} | {b['correct']:,} | {b['strict_wrong']:,} "
                  f"| {pct(b['strict_rate'])} | {b['function_wrong']:,} | {pct(b['function_rate'])} |" for b in report[key]]
    lines += ["", "## Gates, overall", ""]
    lines += gate_table(report["gates"]["overall"])
    lines += ["", "Gate columns: `len>=N` keeps renames whose pack body length is at least N bytes; `>=2 donors if len<N` "
              "drops a rename of fewer than N bytes that fewer than two donor games agree on (`independent donors` counts a twin "
              "group, e.g. both Pikmin 2 discs, once); `family = detected` keeps "
              "a rename when an agreeing donor (or every agreeing donor, `all`) has the compiler family the import's "
              "own donor vote implies (`implied_compiler` of the apply report), `family = truth` the same against the "
              "game's meta.json compiler (not available to a user). Identical kept sets are listed once.", ""]
    for rec in report["recommendation"]:
        lines.append(f"- {rec}")
    lines.append("")
    for platform, gates in report["gates"]["platforms"].items():
        lines += [f"## Gates, {platform}", ""] + gate_table(gates) + [""]
    lines += ["## Detected against true compiler family", "",
              "The family of the apply report's `implied_compiler` (the donors' compiler vote of the run) against the game's "
              "meta.json compiler family, per program unit that made at least one rename.", "",
              "| platform | program units with renames | detected = truth | detected differs | no detection |", "|---|---:|---:|---:|---:|"]
    for platform, d in report["detection"].items():
        lines.append(f"| {platform} | {d['games']} | {d['same']} | {d['differs']} | {d['none']} |")
    lines.append("")
    return "\n".join(lines) + "\n"


def recommend(overall: list[dict]) -> list[str]:
    base = overall[0]
    out = [f"Baseline (no gate): {base['kept']:,} renames, strict rate {pct(base['strict_rate'])}, function-wrong "
           f"{pct(base['function_rate'])}."]
    for cap in (0.03, 0.02, 0.01):
        g = best_gates(overall, cap)
        out.append(f"Most correct renames kept with strict rate <= {cap * 100:.0f}%: " + (
            f"**{g['gate']}**: keeps {g['kept']:,} renames ({pct(g['kept_fraction'])}), {g['correct']:,} correct, "
            f"{g['strict_wrong']:,} wrong strict ({pct(g['strict_rate'])}), {g['function_wrong']:,} function-wrong "
            f"({pct(g['function_rate'])})" if g else "none"))
    for cap in (0.005, 0.002):
        g = best_gates(overall, cap, "function_rate")
        out.append(f"Most correct renames kept with function-wrong rate <= {cap * 100:.1f}%: " + (
            f"**{g['gate']}**: keeps {g['kept']:,} ({pct(g['kept_fraction'])}), {g['correct']:,} correct, strict "
            f"{pct(g['strict_rate'])}, function-wrong {g['function_wrong']:,} ({pct(g['function_rate'])})" if g else "none"))
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pack", type=Path, default=RUNS / "fact-pack.sqlite")
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, default=Path.home() / "romwright-corpus" / "extracted")
    parser.add_argument("--cache", type=Path, default=Path.home() / ".cache" / "romwright" / "research-eval")
    parser.add_argument("--work", type=Path, default=RUNS / "gating-work")
    parser.add_argument("--games", default="")
    parser.add_argument("--fingerprint", default=None)
    parser.add_argument("--ghidra", type=Path, default=Path.home() / "ghidra_12.1.3_PUBLIC")
    parser.add_argument("--ghidra-opt", type=Path, default=ROOT / "native" / "build" / "ghidra_opt")
    parser.add_argument("--worker", type=Path, default=None)
    parser.add_argument("--jobs", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=3600)
    parser.add_argument("--seed", type=int, default=20261011)
    parser.add_argument("--rows", type=Path, default=RUNS / "gating-renames.jsonl",
                        help="every rename with its details, one JSON object per line (host-side, not committed)")
    parser.add_argument("--out", type=Path, default=ROOT / "benchmarks" / "reports" / "fact_pack_gating.json")
    args = parser.parse_args()

    import units as unit_lib
    args.env = unit_lib.tool_env(args.cli, args.ghidra, args.ghidra_opt, args.worker)
    pack_info = ev.read_pack(args.pack)
    wanted = [g for g in args.games.split(",") if g]
    games = [g for g in sorted(pack_info["donor_rows"]) if not wanted or g in wanted]
    by_compiler = {row["compiler"]: pack_info["families"][game] for game, row in pack_info["donor_rows"].items()
                   if row.get("compiler")}
    index = PackIndex(args.pack)
    print(f"{len(games)} donor games, pack {ev.sha256_file(args.pack)[:16]}", file=sys.stderr)

    def task(game: str) -> dict:
        result = collect_game(game, args, pack_info, index, by_compiler)
        print(f"{game}: {result['status']}, {len(result['rows'])} renames", file=sys.stderr, flush=True)
        return result

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        results = list(pool.map(task, games))
    rows = [r for result in results for r in result["rows"]]
    args.rows.parent.mkdir(parents=True, exist_ok=True)
    with open(args.rows, "w") as handle:
        for row in rows:
            handle.write(json.dumps(row) + "\n")

    overall = evaluate_gates(rows)
    per_platform = {p: evaluate_gates([r for r in rows if r["platform"] == p]) for p in sorted({r["platform"] for r in rows})}
    detection = {}
    for result in results:
        for unit in result["units"]:
            if not unit.get("renamed"):
                continue
            d = detection.setdefault(result["platform"], {"games": 0, "same": 0, "differs": 0, "none": 0})
            d["games"] += 1
            if unit.get("detected_family") is None:
                d["none"] += 1
            elif unit["detected_family"] == result["target_family"]:
                d["same"] += 1
            else:
                d["differs"] += 1
    report = {
        "schema": "fact-pack-gating/1", "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "cli": str(args.cli), "cli_sha": ev.sha256_file(args.cli)[:16],
        "pack": {"path": str(args.pack), "bytes": pack_info["bytes"], "donors": len(pack_info["donor_rows"]),
                 "sha256_16": ev.sha256_file(args.pack)[:16]},
        "games": {r["game"]: {"status": r["status"], "renames": len(r["rows"]), "target_family": r.get("target_family"),
                              "units": [{k: u.get(k) for k in ("program", "status", "implied_compiler", "detected_family", "renamed")}
                                        for u in r["units"][:3]], "unit_count": len(r["units"])} for r in results},
        "classes": classes(rows), "overall": tally(rows), "settle": settle_different(rows, args.seed),
        "gates": {"overall": overall, "platforms": per_platform}, "recommendation": recommend(overall),
        "detection": detection, "rows_file": str(args.rows), **breakdowns(rows),
        "per_platform_classes": {p: classes([r for r in rows if r["platform"] == p]) for p in per_platform},
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=1) + "\n")
    args.out.with_suffix(".md").write_text(markdown(report))
    print(f"report {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
