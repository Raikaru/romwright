#!/usr/bin/env python3
"""Leave-one-out evaluation of the universal fact pack on the corpus's truth games.

The pack (crates/romwright-facts `pack`, built by benchmarks/fact_pack/build_pack.py) names a function
whose relocation-masked body matches one a decomp already named. This harness measures how often that
name, size and prototype are right, on the games whose truth we hold:

  loo     for each of the 58 truth games, `romwright facts apply --scan --json --exclude <game>` on a
          private copy of the game's default cached import (apply writes; the research cache is never
          touched). The pack removes the game and its twin group (same source tree: both Pikmin 2
          discs, both Ratchet & Clank regions) from every consensus, so one pack serves every run.
  self    the same without the exclusion, on a few games: what a user gets for a game that has a decomp.

The 10 dwarf/pdb games (psp, x360) are not donors; they are the out-of-corpus case and are reported
apart from the 48 donor games.

Scored against each program unit's truth (the truth modules console_research.wave_units placed in that
program, over the ranges it scores):

  names     per match with a pack name: truth at that address names the function (correct: equal after
            stripping leading underscores and case, or equal after reducing a mangled / qualified name
            to its base name; wrong otherwise) or cannot judge it (no truth row at the address, or the
            truth name is generic: `func_80123456`, `FUN_…`, `sub_…`, `fn_…`, `lbl_…`, address-suffixed).
            Three populations: `renamed` (the rename apply made on a `FUN_` function; the headline),
            `proposed_found` (every name proposed at a function the import found) and `scan`.
  scan      matches at aligned offsets that are no function of the import: start in truth (hit / miss; a
            miss is a body the truth does not list as a function start, which includes truth gaps) and
            length equal to the truth size.
  found     matches at functions the import found: our size equals the pack length; and against truth,
            whether the pack length fixes a size the import got wrong (or breaks one it had right).
  abstain   matches with no usable name (ambiguous donors, or a body that only generic / stub donors hold).

Usage (on the host, after build_pack.py):
  python3 benchmarks/fact_pack_eval.py --pack ~/runs/FactEval/fact-pack.sqlite --cli <romwright-cli> [--games A,B]
"""
from __future__ import annotations

import argparse
import collections
import concurrent.futures
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "benchmarks" / "fact_pack"))

RUNS = Path.home() / "runs" / "FactEval"
SELF_GAMES = ["gba-kh-chain-of-memories", "n64-super-mario-64", "gc-pikmin"]

# ---------------------------------------------------------------------------
# Names (pure)
# ---------------------------------------------------------------------------

GENERIC = re.compile(
    r"^(?:fun|sub)_"
    r"|^(?:func|fun|fn|sub|lbl|loc|unk|fcn|proc|zz|jtbl|text|code)_(?:[a-z0-9]+_)*(?:0x)?(?=[0-9a-f]*\d)[0-9a-f]{4,}$"
    r"|^(?:func|fun|fn|sub|lbl|text|code)(?=[0-9a-f]*\d)[0-9a-f]{6,8}$"
    r"|_(?:0x)?[0-9a-f]{8}$", re.IGNORECASE)
MWCC_MEMBER = re.compile(r"^(_{0,2}[A-Za-z0-9]\w*?)__(?:F|Q\d|C[FQ\d]|\d+[A-Za-z_])")
ITANIUM_PART = re.compile(r"(\d+)")
MSVC = re.compile(r"^\?+\d?([^@?]+)@")


def is_generic(name: str) -> bool:
    """A placeholder, not a name: `func_80123456`, `FUN_00123456`, `sub_…`, `fn_…`, `lbl_…`, or any name
    ending in an eight-digit address."""
    return bool(GENERIC.search(name))


def normalize(name: str) -> str:
    """Name equality of the pack's consensus: leading underscores stripped, case-insensitive."""
    return name.lstrip("_").lower()


def _drop_templates(text: str) -> str:
    depth, out = 0, []
    for ch in text:
        if ch == "<":
            depth += 1
        elif ch == ">" and depth:
            depth -= 1
        elif not depth:
            out.append(ch)
    return "".join(out)


def _itanium_base(name: str) -> str | None:
    """Last identifier of `_ZN3foo3barEv` / `_Z3bazv`."""
    if not name.startswith("_Z"):
        return None
    text = name[2:]
    if text.startswith("N"):
        text = text[1:]
    last, position = None, 0
    while position < len(text):
        match = ITANIUM_PART.match(text, position)
        if not match:
            if text[position] in "KVrRO":  # qualifiers
                position += 1
                continue
            break
        end = match.end() + int(match[1])
        last = text[match.end():end]
        position = end
    return last


def base_name(name: str) -> str:
    """The function's own name with scope, parameters and mangling removed: MWCC `Update__8UberBondFv` and
    `UberBond::Update(float)` -> `Update`; Itanium `_ZN3foo3barEv` -> `bar`; MSVC `?bar@foo@@YAXXZ` -> `bar`.
    A name that is none of these is returned as is."""
    mangled = _itanium_base(name)
    if mangled:
        return mangled
    match = MSVC.match(name)
    if match:
        return match[1]
    match = MWCC_MEMBER.match(name)
    if match:
        return match[1]
    text = _drop_templates(name)
    if "(" in text:
        text = text[:text.index("(")]
    return text.rsplit("::", 1)[-1].strip() or name


def scope_of(name: str) -> str | None:
    """The class / namespace a mangled or qualified name belongs to (`Update__8UberBondFv` -> `UberBond`,
    `_ZN3foo3barEv` -> `foo`, `?bar@foo@@YAXXZ` -> `foo`, `A::B::f` -> `A::B`); None when it has none."""
    if name.startswith("_Z"):
        text = name[2:]
        if not text.startswith("N"):
            return None
        text, parts, position = text[1:], [], 0
        while (match := ITANIUM_PART.match(text, position)):
            end = match.end() + int(match[1])
            parts.append(text[match.end():end])
            position = end
        return "::".join(parts[:-1]) or None
    if name.startswith("?"):
        head = name[1:].split("@@", 1)[0]
        parts = head.split("@")[1:]
        return "::".join(reversed(parts)) or None
    match = MWCC_MEMBER.match(name)
    if match:
        rest = name[match.end(1) + 2:]
        count = int(rest[1]) if len(rest) > 1 and rest[0] == "Q" and rest[1].isdigit() else 1
        position = 2 if count != 1 or rest.startswith("Q") else 0
        parts = []
        for _ in range(count):
            digits = re.match(r"\d+", rest[position:])
            if not digits:
                return None
            start = position + digits.end()
            parts.append(rest[start:start + int(digits[0])])
            position = start + int(digits[0])
        return "::".join(parts)
    text = _drop_templates(name)
    if "(" in text:
        text = text[:text.index("(")]
    return text.rsplit("::", 1)[0] if "::" in text else None


def judge(proposed: str, truth_name: str) -> str:
    """`correct_strict` (equal after normalize), `correct` (equal base names, the scopes agree or one has none),
    `correct_scope` (equal base names but different classes: counted correct, as the rule says, and flagged),
    `wrong`, or `generic` (the truth cannot judge)."""
    if is_generic(truth_name):
        return "generic"
    if normalize(proposed) == normalize(truth_name):
        return "correct_strict"
    if normalize(base_name(proposed)) == normalize(base_name(truth_name)):
        a, b = scope_of(proposed), scope_of(truth_name)
        return "correct_scope" if a and b and normalize(a) != normalize(b) else "correct"
    return "wrong"


def pair_kind(proposed: str, truth_name: str, truth_names: set[str] | frozenset[str] = frozenset()) -> str:
    """Why a wrong name is wrong, as far as the names show: `spelling` (equal once `_` and case are dropped),
    `affix` (one base name holds the other: a prefix or suffix convention), `collision` (two different
    functions share a masked body: the pack's name is also a name of another function of the target, or both
    names are mangled / qualified methods with different names, which a naming convention cannot explain),
    else `different` (unrelated plain names: another convention for the same function, or a collision with
    a function the truth leaves unnamed; the names do not say which)."""
    squash = lambda text: re.sub(r"_", "", text).lower()  # noqa: E731
    a, b = squash(base_name(proposed)), squash(base_name(truth_name))
    if a == b or squash(proposed) == squash(truth_name):
        return "spelling"
    if min(len(a), len(b)) >= 4 and (a in b or b in a):
        return "affix"
    if normalize(proposed) in truth_names or normalize(base_name(proposed)) in truth_names:
        return "collision"
    if scope_of(proposed) and scope_of(truth_name):
        return "collision"
    return "different"


FAMILIES = ("MWCC", "IDO", "agbcc", "psyq", "ee-gcc", "gcc", "other")


def compiler_family(compiler: str | None, platform: str | None = None) -> str:
    """The compiler family of a truth `compiler` field (meta.json), by its first-named toolchain:
    MWCC (every Metrowerks/CodeWarrior: mwcc, mwccarm, MWCC PS2, CodeWarrior for PlayStation/PSP), IDO (SGI),
    agbcc (agbcc, old_agbcc, agscc), ee-gcc (PS2's EE GCC / SN ProDG ee-gcc), psyq (PSX GCC and SN/Psy-Q),
    gcc (any other GCC, KMC, the PSP's allegrex GNU C), other (Microsoft)."""
    text = (compiler or "").strip().lower()
    if re.match(r"(mwcc|metrowerks|codewarrior)", text):
        return "MWCC"
    if text.startswith("ido"):
        return "IDO"
    if re.match(r"(agbcc|agscc|old_agbcc)", text):
        return "agbcc"
    head = re.split(r"[;+]", text)[0]
    if "ee-gcc" in head or text.startswith("ee gcc"):
        return "ee-gcc"
    if platform in ("psx", "ps1") and re.search(r"gcc|psy-?q", text):
        return "psyq"
    if "gcc" in text or text.startswith("gnu c"):
        return "gcc"
    return "other"


# ---------------------------------------------------------------------------
# Scoring (pure)
# ---------------------------------------------------------------------------

POPULATIONS = ("renamed", "proposed_found", "scan")


def to_int(value) -> int:
    return int(value, 16) if isinstance(value, str) else int(value)


def twin_games(game: str, donors: dict[str, dict]) -> set[str]:
    """`game` and every donor of its twin group (the games the pack must exclude when `game` is the query)."""
    group = (donors.get(game) or {}).get("twin_group")
    return {game} | ({g for g, row in donors.items() if group and row.get("twin_group") == group})


def score_unit(matches: list[dict], truth: dict[int, tuple[int, str]], ranges, excluded: set[str],
               donor_families: dict[str, str] | None = None) -> dict:
    """Counters and wrong pairs of one program unit's matches. `matches` are the apply report's records
    (`address`, `length`, `name`, `donors`, `ambiguous`, `found`, `our_size`, `action`); the records of one
    address (a body that fits several lengths yields one each) are one match. A match is *abstained* when
    none of its records names the function (`action` abstained, ambiguous donors, or no name); only records
    that do are scored. Matches outside `ranges` (code the truth does not cover) are only counted as
    `out_of_scope`. `excluded` are the games the run removed: a donor of one in a match is a `leak` (must be 0).
    `donor_families` maps a donor game to its compiler family: each scored rename also counts under
    `renamed.correct_from.<family>` / `renamed.wrong_from.<family>` once per distinct family among the donors."""
    inside = lambda a: not ranges or any(lo <= a < hi for lo, hi in ranges)  # noqa: E731
    c = collections.Counter()
    pairs = {name: collections.Counter() for name in POPULATIONS}
    truth_names = frozenset(normalize(name) for _, name in truth.values()) | frozenset(
        normalize(base_name(name)) for _, name in truth.values())
    by_address: dict[int, list[dict]] = {}
    for m in matches:
        by_address.setdefault(to_int(m["address"]), []).append(m)
    for address, records in by_address.items():
        if not inside(address):
            c["out_of_scope"] += 1
            continue
        found = bool(records[0].get("found", True))
        entry = truth.get(address)
        usable = [m for m in records if m.get("name") and not m.get("ambiguous")
                  and m.get("action") not in ("abstained", "gated")]
        gated = not usable and any(m.get("action") == "gated" for m in records)
        c["matched"] += 1
        c["matched_found" if found else "matched_scan"] += 1
        c["leaks"] += any(d in excluded for m in records for d in m.get("donors") or [])
        if gated:
            c["gated"] += 1  # held back by the rename gate: no rename, no size row, no prototype
        elif not usable:
            c["abstained_ambiguous" if any(m.get("ambiguous") for m in records) else "abstained_nameless"] += 1
        our = records[0].get("our_size")
        # The record the match stands for: a named one, else the one that fits our size, else the first.
        chosen = (usable or [m for m in records if our is not None and int(m["length"]) == our] or records)[0]
        length = int(chosen["length"])
        if any(m.get("action") == "renamed" for m in records):
            c["renamed"] += 1
        for m in usable:
            populations = (["renamed"] if m.get("action") == "renamed" else []) + ["proposed_found" if found else "scan"]
            for population in populations:
                if entry is None:
                    c[f"{population}.no_truth"] += 1
                    continue
                verdict = judge(m["name"], entry[1])
                if verdict == "generic":
                    c[f"{population}.generic_truth"] += 1
                    continue
                outcome = "wrong" if verdict == "wrong" else "correct"
                c[f"{population}.{outcome}"] += 1
                if outcome == "wrong":
                    kind = pair_kind(m["name"], entry[1], truth_names)
                    pairs[population][(entry[1], m["name"], kind)] += 1
                    # function-wrong: the name of another function of the target (or of a different method) put here
                    if kind == "collision" or normalize(m["name"]) in truth_names or normalize(base_name(m["name"])) in truth_names:
                        c[f"{population}.function_wrong"] += 1
                elif verdict in ("correct_strict", "correct_scope"):
                    c[f"{population}.{verdict}"] += 1
                if donor_families and population == "renamed":
                    for family in {donor_families.get(d, "unknown") for d in m.get("donors") or []}:
                        c[f"renamed.{outcome}_from.{family}"] += 1
        if found and not gated:
            if our is not None:
                c["found_size_compared"] += 1
                c["found_size_equals_pack"] += our == length
                if entry and entry[0]:
                    c["found_vs_truth"] += 1
                    ours_right, pack_right = our == entry[0], length == entry[0]
                    c["found_ours_short"] += our < entry[0]
                    c["found_ours_long"] += our > entry[0]
                    c["found_ours_right"] += ours_right
                    c["found_pack_right"] += pack_right
                    c["found_pack_fixes"] += pack_right and not ours_right
                    c["found_pack_breaks"] += ours_right and not pack_right
        elif not found and entry is not None:
            c["scan_start_hit"] += 1
            if entry[0]:
                c["scan_hit_sized"] += 1
                c["scan_length_equals_truth"] += any(int(m["length"]) == entry[0] for m in records)
        elif not found:
            c["scan_start_miss"] += 1
    return {"counts": dict(c), "pairs": {k: [[t, p, kind, n] for (t, p, kind), n in v.items()] for k, v in pairs.items()}}


def merge_scores(parts: list[dict]) -> dict:
    counts, pairs = collections.Counter(), {name: collections.Counter() for name in POPULATIONS}
    for part in parts:
        counts.update(part.get("counts", {}))
        for name, rows in part.get("pairs", {}).items():
            for truth_name, proposed, kind, n in rows:
                pairs[name][(truth_name, proposed, kind)] += n
    return {"counts": dict(counts),
            "pairs": {k: [[t, p, kind, n] for (t, p, kind), n in v.items()] for k, v in pairs.items()}}


def rate(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


def metrics(counts: dict) -> dict:
    """Derived rates of a counter set (one game, one platform, or a whole mode)."""
    g = counts.get
    out = dict(counts)
    for population in POPULATIONS:
        correct, wrong = g(f"{population}.correct", 0), g(f"{population}.wrong", 0)
        out[f"{population}.scoreable"] = correct + wrong
        out[f"{population}.wrong_rate"] = rate(wrong, correct + wrong)
        out[f"{population}.function_wrong_rate"] = rate(g(f"{population}.function_wrong", 0), correct + wrong)
    out["scan_start_precision"] = rate(g("scan_start_hit", 0), g("matched_scan", 0))
    out["scan_length_given_start"] = rate(g("scan_length_equals_truth", 0), g("scan_hit_sized", 0))
    out["scan_length_exact_of_matches"] = rate(g("scan_length_equals_truth", 0), g("matched_scan", 0))
    out["found_size_equals_pack_rate"] = rate(g("found_size_equals_pack", 0), g("found_size_compared", 0))
    return out


def top_pairs(parts: list[dict], population: str, limit: int = 20) -> list[dict]:
    """The wrong (truth name, pack name) pairs that recur most, with the pair's kind."""
    total = collections.Counter()
    for part in parts:
        for truth_name, proposed, kind, n in part.get("pairs", {}).get(population, []):
            total[(truth_name, proposed, kind)] += n
    return [{"truth": t, "pack": p, "count": n, "kind": kind}
            for (t, p, kind), n in sorted(total.items(), key=lambda item: (-item[1], item[0]))[:limit]]


def wrong_kinds(parts: list[dict], population: str) -> dict:
    """How many wrong names of each kind (see `pair_kind`)."""
    total = collections.Counter()
    for part in parts:
        for _, _, kind, n in part.get("pairs", {}).get(population, []):
            total[kind] += n
    return dict(total)


def top_pack_names(parts: list[dict], population: str, limit: int = 20) -> list[dict]:
    """The pack names that were wrong most often: one donor name stamped on many different functions is a
    collision (a shared stub body), not a convention."""
    total, examples = collections.Counter(), collections.defaultdict(list)
    for part in parts:
        for truth_name, proposed, _, n in part.get("pairs", {}).get(population, []):
            total[proposed] += n
            if len(examples[proposed]) < 3:
                examples[proposed].append(truth_name)
    return [{"pack": p, "count": n, "truth_examples": examples[p]}
            for p, n in sorted(total.items(), key=lambda item: (-item[1], item[0]))[:limit]]


# ---------------------------------------------------------------------------
# Pack and apply
# ---------------------------------------------------------------------------

def read_pack(pack: Path) -> dict:
    """Facts about the pack file, read directly: size, format, meta, donors and body counts."""
    db = sqlite3.connect(f"file:{pack}?mode=ro", uri=True)
    try:
        info = {"path": str(pack), "bytes": pack.stat().st_size, "user_version": db.execute("PRAGMA user_version").fetchone()[0],
                "meta": dict(db.execute("SELECT key, value FROM meta")),
                "bodies": db.execute("SELECT COUNT(*) FROM bodies").fetchone()[0],
                "named_bodies": db.execute("SELECT COUNT(*) FROM bodies WHERE name IS NOT NULL").fetchone()[0]}
        try:
            info["prototypes"] = db.execute("SELECT COUNT(*) FROM prototypes").fetchone()[0]
        except sqlite3.OperationalError:
            info["prototypes"] = None
        columns = [row[1] for row in db.execute("PRAGMA table_info(donors)")]
        rows = [dict(zip(columns, row)) for row in db.execute("SELECT * FROM donors")]
        info["donor_rows"] = {row["game"]: row for row in rows}
        info["families"] = {game: compiler_family(row.get("compiler"), row.get("platform"))
                            for game, row in info["donor_rows"].items()}
    finally:
        db.close()
    return info


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def run_apply(cli: Path, project: Path, program: str, pack: Path, exclude: list[str], scan: bool,
              timeout: int, env: dict) -> dict:
    argv = [str(cli), "facts", "apply", "--project", str(project), "--program", program, "--pack", str(pack), "--json"]
    if scan:
        argv.append("--scan")
    for game in exclude:
        argv += ["--exclude", game]
    started = time.monotonic()
    result = subprocess.run(argv, capture_output=True, text=True, env=env, timeout=timeout)
    seconds = round(time.monotonic() - started, 1)
    if result.returncode:
        raise RuntimeError(f"facts apply exit {result.returncode}: {result.stderr.strip()[-600:]}")
    report = json.loads(result.stdout)
    report["_seconds"] = seconds
    return report


def apply_matches(report: dict) -> list[dict]:
    return report.get("matches") or []


def summarize_unresolved(unresolved: list[dict]) -> dict:
    """Truth modules no import program holds (not scored): how many, how many truth functions, why, which."""
    reasons = collections.Counter(u["reason"] for u in unresolved)
    return {"modules": len(unresolved), "functions": sum(u["functions"] for u in unresolved),
            "reasons": dict(reasons), "names": [u["module"] for u in unresolved][:12]}


def run_game(game: str, args, pack_info: dict, mode: str, work_root: Path) -> dict:
    import units as unit_lib
    donors = pack_info["donor_rows"]
    donor = game in donors
    row = {"game": game, "mode": mode, "donor": donor}
    work = work_root / game
    resolved = unit_lib.game_units(game, args.corpus, args.cache, work, args.fingerprint, jobs=args.unit_jobs)
    if "error" in resolved:
        row.update(status="no_run", reason=resolved["error"])
        return row
    row.update(platform=resolved["platform"], truth_kind=resolved["truth_kind"], compiler=resolved["compiler"],
               compiler_family=compiler_family(resolved["compiler"], resolved["platform"]),
               project=resolved["project"],
               fingerprint=resolved["fingerprint"], unresolved=summarize_unresolved(resolved["unresolved"]),
               warnings=resolved["warnings"][:3], warning_count=len(resolved["warnings"]))
    exclude = []
    excluded = set()
    if mode == "loo":
        excluded = twin_games(game, donors) if donor else set()
        exclude = [game] if donor else []
    copies: dict[str, Path] = {}
    parts, unit_rows, probed_functions, probed_scan, prototypes = [], [], 0, 0, 0
    try:
        for unit in resolved["units"]:
            copy = copies.get(unit["project"])
            if copy is None:
                copy = copies[unit["project"]] = unit_lib.copy_project(
                    unit["project"], work / f"p{len(copies)}-{Path(unit['project']).name[:60]}")
            unit_row = {"program": unit["program"], "modules": unit["modules"], "truth": len(unit["truth"])}
            try:
                report = run_apply(args.cli, copy, unit["program"], args.pack, exclude, not args.no_scan, args.timeout, args.env)
            except subprocess.TimeoutExpired:
                unit_row.update(status="timeout", reason=f"facts apply over {args.timeout}s")
                unit_rows.append(unit_row)
                continue
            except (RuntimeError, ValueError) as error:
                unit_row.update(status="error", reason=str(error)[-600:])
                unit_rows.append(unit_row)
                continue
            score = score_unit(apply_matches(report), unit["truth"], unit["ranges"], excluded, pack_info["families"])
            parts.append(score)
            unit_row.update(status="ok", seconds=report.get("_seconds"),
                            probed_functions=report.get("probed_functions"), probed_scan=report.get("probed_scan"),
                            matched=score["counts"].get("matched", 0), renamed=score["counts"].get("renamed", 0),
                            gated=report.get("gated"), gate=report.get("gate"))
            prototypes += report.get("prototypes") or 0
            probed_functions += report.get("probed_functions") or 0
            probed_scan += report.get("probed_scan") or 0
            unit_rows.append(unit_row)
    finally:
        if not args.keep:
            shutil.rmtree(work / "cache", ignore_errors=True)
            for copy in copies.values():
                shutil.rmtree(copy, ignore_errors=True)
    merged = merge_scores(parts)
    merged["counts"]["probed_functions"] = probed_functions
    merged["counts"]["probed_scan"] = probed_scan
    merged["counts"]["prototypes_applied"] = prototypes
    merged["counts"]["truth_functions"] = sum(u["truth"] for u in unit_rows)
    row.update(units=unit_rows, score=merged, metrics=metrics(merged["counts"]),
               status="ok" if parts and all(u["status"] == "ok" for u in unit_rows) else
               ("partial" if parts else "failed"))
    if row["status"] != "ok":
        row["reason"] = "; ".join(f"{u['program']}: {u.get('reason')}" for u in unit_rows if u["status"] != "ok")
    return row


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def rollup(rows: list[dict]) -> dict:
    """Totals per platform, per kind (donor / non-donor) and overall over the runs that produced scores."""
    ok = [r for r in rows if r.get("score")]
    def total(subset):
        merged = merge_scores([r["score"] for r in subset])
        return {"games": len(subset), "metrics": metrics(merged["counts"]),
                "wrong_pairs_renamed": top_pairs([r["score"] for r in subset], "renamed"),
                "wrong_pairs_proposed": top_pairs([r["score"] for r in subset], "proposed_found"),
                "wrong_kinds_renamed": wrong_kinds([r["score"] for r in subset], "renamed"),
                "wrong_pack_names_renamed": top_pack_names([r["score"] for r in subset], "renamed")}
    out = {"all": total(ok), "platforms": {}, "kinds": {}}
    for platform in sorted({r["platform"] for r in ok}):
        out["platforms"][platform] = total([r for r in ok if r["platform"] == platform])
    for kind, flag in (("donor", True), ("non_donor", False)):
        subset = [r for r in ok if r["donor"] is flag]
        if subset:
            out["kinds"][kind] = total(subset)
    # By the target game's compiler family, per kind; the donor families behind its correct renames are
    # in each total's `renamed.correct_from.<family>` counters.
    out["compilers"] = {kind: {family: total(subset) for family in FAMILIES
                               if (subset := [r for r in ok if r["donor"] is flag and r.get("compiler_family") == family])}
                        for kind, flag in (("donor", True), ("non_donor", False))}
    return out


def pct(value) -> str:
    """A rate in percent: one decimal, two below 1% (the function-wrong rates are tenths of a percent)."""
    if value is None:
        return "-"
    return f"{value * 100:.2f}%" if value < 0.01 else f"{value * 100:.1f}%"


def head(label: str) -> str:
    return HEAD.format(label).rstrip("\n")


def table_row(label: str, m: dict) -> str:
    g = lambda key: m.get(key, 0)  # noqa: E731
    return (f"| {label} | {g('probed_functions')} | {g('matched')} | {g('abstained_ambiguous') + g('abstained_nameless')} "
            f"| {g('gated')} | {g('renamed')} | {g('renamed.correct')} | {g('renamed.wrong')} "
            f"| {g('renamed.generic_truth') + g('renamed.no_truth')} "
            f"| {pct(m.get('renamed.wrong_rate'))} | {g('renamed.function_wrong')} ({pct(m.get('renamed.function_wrong_rate'))}) "
            f"| {g('matched_scan')} | {g('scan_start_hit')} | {g('scan_start_miss')} "
            f"| {g('scan_length_equals_truth')} | {pct(m.get('found_size_equals_pack_rate'))} |")


HEAD = ("| {} | probed fns | matched | abstained | gated | renamed | correct | wrong | unscoreable | wrong rate (strict) "
        "| function-wrong | scan matches | start hit | start miss | length = truth | our size = pack length |\n"
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n")


def compiler_sections(loo: dict) -> list[str]:
    """Per compiler family of the target game (donor games, then non-donors), and which donor families
    its correct renames come from."""
    lines = []
    for title, key in (("Per compiler family of the target game, donor games (leave-one-out)", "donor"),
                       ("Per compiler family of the target game, non-donor games", "non_donor")):
        groups = loo["rollup"].get("compilers", {}).get(key) or {}
        if not groups:
            continue
        lines += [f"## {title}", "", head("compiler family")]
        lines += [table_row(f"{family} ({total['games']})", total["metrics"]) for family, total in groups.items()]
        lines.append("")
        columns = [f for f in (*FAMILIES, "unknown") if any(t["metrics"].get(f"renamed.correct_from.{f}")
                                                           or t["metrics"].get(f"renamed.wrong_from.{f}")
                                                           for t in groups.values())]
        lines += [f"Renames by the donors' compiler family (correct / wrong; a rename counts once per distinct donor family "
                  f"among its donors), rows = the target's family:", "",
                  "| target \\ donor | " + " | ".join(columns) + " |", "|---|" + "---:|" * len(columns)]
        for family, total in groups.items():
            m = total["metrics"]
            lines.append(f"| {family} | " + " | ".join(
                f"{m.get(f'renamed.correct_from.{c}', 0)} / {m.get(f'renamed.wrong_from.{c}', 0)}" for c in columns) + " |")
        lines.append("")
    games = [(g, r) for g, r in sorted(loo["games"].items()) if r.get("metrics")]
    columns = [f for f in (*FAMILIES, "unknown") if any(r["metrics"].get(f"renamed.correct_from.{f}") for _, r in games)]
    if columns:
        lines += ["Correct renames per target game by the donors' compiler family:", "",
                  "| game | target family | " + " | ".join(columns) + " |", "|---|---|" + "---:|" * len(columns)]
        for game, row in games:
            lines.append(f"| {game} | {row.get('compiler_family')} | " + " | ".join(
                str(row["metrics"].get(f"renamed.correct_from.{c}", 0)) for c in columns) + " |")
        lines.append("")
    return lines


def load_ungated(path: Path | None) -> dict | None:
    """The ungated reference (benchmarks/fact_pack_gating.json: the same leave-one-out renames before the
    rename gate), overall and per platform, as its ungated gate row."""
    if not path or not path.is_file():
        return None
    report = json.loads(path.read_text())
    row = lambda gates: next(g for g in gates if g["gate"] == "len>=32 (any)")  # noqa: E731
    return {"source": path.name, "generated": report["generated"], "cli_sha": report["cli_sha"],
            "overall": row(report["gates"]["overall"]),
            "platforms": {p: row(g) for p, g in report["gates"]["platforms"].items()}}


def platform_metrics(loo: dict, donor: bool) -> dict:
    """{platform: metrics} over the donor (or non-donor) games that produced a score."""
    out = {}
    for platform in sorted({r["platform"] for r in loo["games"].values() if r.get("score")}):
        subset = [r for r in loo["games"].values() if r.get("score") and r["platform"] == platform and r["donor"] is donor]
        if subset:
            out[platform] = metrics(merge_scores([r["score"] for r in subset])["counts"])
    return out


def gate_comparison(report: dict) -> list[str]:
    ungated = report.get("ungated_reference")
    loo = report["loo"]
    kind = loo["rollup"]["kinds"].get("donor")
    if not ungated or not kind:
        return []
    lines = ["## The rename gate: gated against ungated (leave-one-out, donor games)", "",
             f"Gate: {report['gate_text']}. The **ungated** rows are the same leave-one-out renames before the gate, taken from "
             f"`{ungated['source']}` (generated {ungated['generated'][:10]}, `romwright-cli` {ungated['cli_sha']}), not re-measured here. "
             "Strict wrong = every scoreable rename whose name is not correct; function-wrong = the name of another function "
             "of the target (or of a different method) put on this one.", "",
             "| platform | state | renames | gated (withheld) | scoreable | strict wrong | strict rate | function-wrong | function rate |",
             "|---|---|---:|---:|---:|---:|---:|---:|---:|"]
    gated_by = platform_metrics(loo, True)
    gated_by["all"] = kind["metrics"]
    ungated_by = dict(ungated["platforms"])
    ungated_by["all"] = ungated["overall"]
    for platform in [*gated_by.keys()][:-1] + ["all"]:
        u, m = ungated_by.get(platform), gated_by[platform]
        if u:
            lines.append(f"| {platform} | ungated, {ungated['generated'][:10]} | {u['kept']:,} | 0 | {u['scoreable']:,} | {u['strict_wrong']:,} "
                         f"| {pct(u['strict_rate'])} | {u['function_wrong']:,} | {pct(u['function_rate'])} |")
        lines.append(f"| {platform} | gated | {m.get('renamed', 0):,} | {m.get('gated', 0):,} | {m.get('renamed.scoreable', 0):,} "
                     f"| {m.get('renamed.wrong', 0):,} | {pct(m.get('renamed.wrong_rate'))} | {m.get('renamed.function_wrong', 0):,} "
                     f"| {pct(m.get('renamed.function_wrong_rate'))} |")
    lines.append("")
    return lines


def markdown(report: dict) -> str:
    pack = report["pack"]
    lines = ["# Universal fact pack: leave-one-out evaluation", "",
             f"Generated {report['generated']} by `benchmarks/fact_pack_eval.py`. Tools `{report['tools']}`.", "",
             "## Pack", "",
             f"- file: `{Path(pack['path']).name}`, **{pack['bytes'] / 1e6:.1f} MB** on disk ({pack['bytes']:,} bytes), "
             f"format {pack['user_version']}, mask version {pack['meta'].get('mask_version')}",
             f"- {pack['donors']} donor games, {pack['bodies']:,} masked bodies ({pack['named_bodies']:,} named), "
             + (f"{pack['prototypes']:,} prototypes" if pack["prototypes"] is not None else "no prototypes"),
             "- donor licenses, recorded verbatim, none filtered (NONE = no license file): "
             + ", ".join(f"{name} {n}" for name, n in sorted(pack["donor_licenses"].items())), ""]
    loo = report["loo"]
    don = loo["rollup"]["kinds"].get("donor", {}).get("metrics", {})
    lines += ["## Headline (leave-one-out, donor games)", ""]
    if don:
        lines += [
            f"- games evaluated: {loo['rollup']['kinds']['donor']['games']} of {loo['expected_donor_games']} donor games "
            f"(failures listed below)",
            f"- functions probed {don.get('probed_functions', 0):,}; matched {don.get('matched', 0):,}; "
            f"abstained {don.get('abstained_ambiguous', 0) + don.get('abstained_nameless', 0):,}; "
            f"**gated {don.get('gated', 0):,}** (held back by the rename gate: {report['gate_text']}); "
            f"renamed (`FUN_` -> donor name) **{don.get('renamed', 0):,}**",
            f"- **function-wrong renames (the name of another function put on this one): {don.get('renamed.function_wrong', 0):,} "
            f"of {don.get('renamed.scoreable', 0):,} scoreable = {pct(don.get('renamed.function_wrong_rate'))}**",
            f"- **wrong-name rate on scoreable renames: {pct(don.get('renamed.wrong_rate'))} "
            f"({don.get('renamed.wrong', 0):,} wrong of {don.get('renamed.scoreable', 0):,} scoreable; "
            f"{don.get('renamed.correct', 0):,} correct, of which {don.get('renamed.correct_strict', 0):,} equal after "
            f"normalizing and the rest after demangling to the base name ({don.get('renamed.correct_scope', 0):,} of those "
            f"name a different class than the truth's); "
            f"{don.get('renamed.generic_truth', 0) + don.get('renamed.no_truth', 0):,} unscoreable)**",
            f"- prototypes applied as inferences: {don.get('prototypes_applied', 0):,}",
            f"- wrong-name rate over every name proposed at a found function: {pct(don.get('proposed_found.wrong_rate'))} "
            f"({don.get('proposed_found.wrong', 0):,} of {don.get('proposed_found.scoreable', 0):,})",
            f"- **scan boundary precision: {pct(don.get('scan_start_precision'))} of {don.get('matched_scan', 0):,} scan matches "
            f"start at a truth function ({don.get('scan_start_hit', 0):,} hits, {don.get('scan_start_miss', 0):,} misses); "
            f"of the hits with a known size, {pct(don.get('scan_length_given_start'))} "
            f"({don.get('scan_length_equals_truth', 0):,} of {don.get('scan_hit_sized', 0):,}) have the exact truth length "
            f"({pct(don.get('scan_length_exact_of_matches'))} of all scan matches have a correct start and length)**",
            f"- scan-found names: {pct(don.get('scan.wrong_rate'))} wrong "
            f"({don.get('scan.wrong', 0):,} of {don.get('scan.scoreable', 0):,} scoreable)",
            f"- matches on found functions: our size = pack length for {pct(don.get('found_size_equals_pack_rate'))} "
            f"({don.get('found_size_equals_pack', 0):,} of {don.get('found_size_compared', 0):,}); against truth the pack "
            f"length fixes {don.get('found_pack_fixes', 0):,} sizes the import had wrong and breaks "
            f"{don.get('found_pack_breaks', 0):,} it had right (of {don.get('found_vs_truth', 0):,} compared; where ours "
            f"differs from truth it is shorter {don.get('found_ours_short', 0):,} times, longer {don.get('found_ours_long', 0):,})",
            f"- twin-group leaks (a donor of the excluded game or its twin in a match): {don.get('leaks', 0)}", ""]
    else:
        lines += ["No donor game produced a score.", ""]
    lines += gate_comparison(report)
    for title, key in (("Per platform, donor games (leave-one-out)", "donor"), ("Out of corpus: non-donor games (psp, x360; dwarf / pdb truth)", "non_donor")):
        lines += [f"## {title}", ""]
        kind = loo["rollup"]["kinds"].get(key)
        if not kind:
            lines += ["No games.", ""]
            continue
        lines += [head("platform")]
        for platform, total in loo["rollup"]["platforms"].items():
            subset = [r for r in loo["games"].values() if r.get("score") and r["platform"] == platform
                      and r["donor"] is (key == "donor")]
            if subset:
                lines.append(table_row(f"{platform} ({len(subset)})", metrics(merge_scores([r["score"] for r in subset])["counts"])))
        lines.append(table_row(f"**all ({kind['games']})**", kind["metrics"]))
        lines.append("")
    lines += compiler_sections(loo)
    if report.get("self", {}).get("games"):
        lines += ["## Self mode: no exclusion (a game that has a decomp)", "", head("game")]
        for game, row in report["self"]["games"].items():
            lines.append(table_row(game, row["metrics"]) if row.get("metrics") else f"| {game} | {row.get('reason')} |")
        lines.append("")
    lines += ["## Per game (leave-one-out)", "", head("game")]
    for game, row in sorted(loo["games"].items()):
        tag = "" if row["donor"] else " (non-donor)"
        lines.append(table_row(f"{game}{tag}", row["metrics"]) if row.get("metrics")
                     else f"| {game}{tag} | {row.get('status')}: {str(row.get('reason'))[:160]} |")
    lines.append("")
    donor_total = loo["rollup"].get("kinds", {}).get("donor") or {}
    kinds = donor_total.get("wrong_kinds_renamed") or {}
    lines += ["## Wrong names on renames: conventions against collisions", "",
              "Donor games, `FUN_` renames the truth names differently. `kind`, as far as the names show: "
              "**spelling** = equal once `_` and case are dropped; **affix** = one base name holds the other "
              "(a prefix/suffix convention); **collision** = two different functions share a masked body (the pack's "
              "name is also the name of another function of the target, or both names are mangled / qualified "
              "methods with different names); **different** = unrelated plain names: another naming convention for "
              "the same function, or a collision with a function the truth leaves unnamed; the names cannot tell "
              "these apart.", "",
              "Wrong names by kind: " + (", ".join(f"{kind} {kinds.get(kind, 0):,}"
                                                  for kind in ("spelling", "affix", "collision", "different")) or "none"), ""]
    lines += ["### Most frequent wrong (truth, pack) pairs (top 20)", "", "| truth | pack | count | kind |", "|---|---|---:|---|"]
    lines += [f"| `{p['truth']}` | `{p['pack']}` | {p['count']} | {p['kind']} |"
              for p in donor_total.get("wrong_pairs_renamed") or []]
    lines += ["", "### Pack names that were wrong most often (top 20)", "",
              "One donor name on many different functions is a shared body, not a convention.", "",
              "| pack name | wrong | truth names (examples) |", "|---|---:|---|"]
    lines += [f"| `{p['pack']}` | {p['count']} | " + ", ".join(f"`{t}`" for t in p["truth_examples"]) + " |"
              for p in donor_total.get("wrong_pack_names_renamed") or []]
    lines.append("")
    problems = [(g, r) for g, r in sorted(loo["games"].items()) if r.get("status") != "ok" or (r.get("unresolved") or {}).get("modules") or r.get("warning_count")]
    if problems:
        lines += ["## Games that did not run in full", ""]
        for game, row in problems:
            notes = [f"status {row.get('status')}"] if row.get("status") != "ok" else []
            if row.get("reason"):
                notes.append(str(row["reason"])[:300])
            lost = row.get("unresolved") or {}
            if lost.get("modules"):
                notes.append(f"{lost['modules']} truth modules ({lost['functions']:,} functions) not placed in any import program, "
                             f"not scored: " + "; ".join(f"{n} x {why}" for why, n in lost["reasons"].items())
                             + f" (e.g. {', '.join(lost['names'][:4])})")
            if row.get("warning_count"):
                notes.append(f"{row['warning_count']} placement warnings, e.g. {row['warnings'][0]}")
            lines.append(f"- `{game}`: " + "; ".join(notes))
        lines.append("")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pack", type=Path, default=RUNS / "fact-pack.sqlite")
    parser.add_argument("--cli", type=Path, required=True, help="romwright-cli with `facts apply`")
    parser.add_argument("--corpus", type=Path, default=Path.home() / "romwright-corpus" / "extracted")
    parser.add_argument("--cache", type=Path, default=Path.home() / ".cache" / "romwright" / "research-eval")
    parser.add_argument("--work", type=Path, default=RUNS / "eval-work")
    parser.add_argument("--games", default="", help="comma-separated games (default: every truth game)")
    parser.add_argument("--self-games", default=",".join(SELF_GAMES), help="games of the no-exclusion mode ('' = skip)")
    parser.add_argument("--fingerprint", default=None, help="prefer the cached projects of this tool fingerprint")
    parser.add_argument("--ghidra", type=Path, default=Path.home() / "ghidra_12.1.3_PUBLIC")
    parser.add_argument("--ghidra-opt", type=Path, default=ROOT / "native" / "build" / "ghidra_opt")
    parser.add_argument("--worker", type=Path, default=None, help="romwright-worker (default: beside --cli)")
    parser.add_argument("--no-scan", action="store_true")
    parser.add_argument("--jobs", type=int, default=3)
    parser.add_argument("--unit-jobs", type=int, default=1)
    parser.add_argument("--timeout", type=int, default=3600, help="seconds per `facts apply`")
    parser.add_argument("--keep", action="store_true", help="keep the project copies")
    parser.add_argument("--force", action="store_true", help="ignore stored per-game results")
    parser.add_argument("--ungated-report", type=Path, default=ROOT / "benchmarks" / "reports" / "fact_pack_gating.json",
                        help="the pre-gate renames (fact_pack_gating.json), shown as the ungated comparison")
    parser.add_argument("--out", type=Path, default=ROOT / "benchmarks" / "reports" / "fact_pack_loo.json")
    args = parser.parse_args()

    import units as unit_lib  # noqa: F401  (fails early when the harness imports are missing)
    args.env = unit_lib.tool_env(args.cli, args.ghidra, args.ghidra_opt, args.worker)
    pack_info = read_pack(args.pack)
    cli_sha = sha256_file(args.cli)[:16]
    pack_sha = sha256_file(args.pack)[:16]
    wanted = [g for g in args.games.split(",") if g]
    truth_games = sorted(p.parent.parent.name for p in args.corpus.glob("*/truth/meta.json"))
    games = [g for g in truth_games if not wanted or g in wanted]
    unknown = set(wanted) - set(truth_games)
    if unknown:
        parser.error(f"no truth for {sorted(unknown)}")
    self_games = [g for g in args.self_games.split(",") if g and (not wanted or g in games)]
    print(f"pack {pack_sha} cli {cli_sha}: {len(games)} loo games, {len(self_games)} self games", file=sys.stderr)
    store = args.work / "results" / f"{pack_sha}-{cli_sha}"
    store.mkdir(parents=True, exist_ok=True)

    def task(mode: str, game: str) -> dict:
        path = store / f"{mode}-{game}.json"
        if path.is_file() and not args.force:
            return json.loads(path.read_text())
        try:
            row = run_game(game, args, pack_info, mode, args.work)
        except Exception as error:  # a game must not stop the run; the report says why  # noqa: BLE001
            row = {"game": game, "mode": mode, "donor": game in pack_info["donor_rows"], "status": "no_run",
                   "reason": f"{type(error).__name__}: {str(error)[-400:]}"}
        if row.get("status") in ("ok", "partial"):
            path.write_text(json.dumps(row))
        print(f"{mode} {game}: {row['status']}" + (f" {row.get('reason', '')[:120]}" if row["status"] != "ok" else ""),
              file=sys.stderr, flush=True)
        return row

    jobs = [("loo", g) for g in games] + [("self", g) for g in self_games]
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        results = list(pool.map(lambda job: task(*job), jobs))
    loo_rows = {r["game"]: r for r in results if r["mode"] == "loo"}
    self_rows = {r["game"]: r for r in results if r["mode"] == "self"}
    for rows in (loo_rows, self_rows):
        for row in rows.values():
            if row.get("platform") is None:
                row["platform"] = row["game"].split("-")[0]
    donor_games = [g for g in pack_info["donor_rows"]]
    gates = [u["gate"] for rows in (loo_rows, self_rows) for row in rows.values() for u in row.get("units", []) if u.get("gate")]
    gate = gates[0] if gates else None
    gate_text = (f">={gate['min_donors']} independent donors (twin group counted once) when the body is < {gate['short_body']} B"
                 if gate else "no gate reported by the CLI")
    report = {
        "schema": "fact-pack-loo/1", "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "tools": f"cli {cli_sha}", "cli": str(args.cli),
        "pack": {"path": str(args.pack), "bytes": pack_info["bytes"], "sha256_16": pack_sha,
                 "user_version": pack_info["user_version"], "meta": pack_info["meta"],
                 "donors": len(donor_games), "bodies": pack_info["bodies"], "named_bodies": pack_info["named_bodies"],
                 "prototypes": pack_info["prototypes"],
                 "donor_licenses": dict(collections.Counter(r["license"] for r in pack_info["donor_rows"].values()))},
        "method": {"scan": not args.no_scan, "exclude": "the game under test (twin group excluded by the pack)",
                   "import": "default cached import (default environment key), private copy per run",
                   "name_correct": "equal after stripping leading underscores and case, or equal after reducing "
                                   "mangled/qualified names to the base name; generic truth names unscoreable"},
        "loo": {"expected_donor_games": len(donor_games), "games": loo_rows, "rollup": rollup(list(loo_rows.values()))},
        "self": {"games": self_rows},
        "gate": gate, "gate_text": gate_text, "ungated_reference": load_ungated(args.ungated_report),
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=1) + "\n")
    args.out.with_suffix(".md").write_text(markdown(report))
    print(f"report {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
