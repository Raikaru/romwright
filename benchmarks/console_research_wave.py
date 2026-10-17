#!/usr/bin/env python3
"""Truth-contract helpers of benchmarks/console_research.py's `--corpus-wave` mode.

Pure functions, no romwright tools: they read the truth directories the
corpus builders write (`<corpus>/<id>/truth/{meta.json,functions.tsv}` plus
optional `types/`), score a set of found function entries against them, and
turn the per-image results into the per-platform rollup and the sign tests.
The contract is documented in docs/console-research.md ("Truth contract").

  discover()      image specs from meta.json files
  load_modules()  functions.tsv -> per-module truth tables
  score_found()   recall/precision (the frozen metric) and the verified-only
                  supplement over one module's address ranges
  aggregate()     the same over several modules
  sign_test()     one-sided sign test over games
  rollup()        per-platform tables and sign tests from a harness report
"""
from __future__ import annotations

import bisect
import json
import math
import re
import subprocess
import time
from pathlib import Path

MAIN = "main"

# `--name` for an image whose meta.json has no `program_hint`. A container
# the importer splits is found by prefix (console_research.program_name).
PLATFORM_PROGRAM = {
    "gba": "gba", "nds": "nds.arm9", "gc": "gc", "wii": "gc", "n64": "n64", "psx": "psx", "ps1": "psx",
    "ps2": "ps2", "psp": "psp", "psv": "vita", "x360": "x360.xex", "pc": "pc",
}

# Platforms whose overlay files are flat dumps without an executable header: the module is imported
# `--raw <load_address> --language <id>` (the language the platform's importer declares). A file that
# starts with the platform's executable magic is handed over as is.
RAW_LANGUAGE = {"psx": "PSX:LE:32:default", "ps1": "PSX:LE:32:default", "ps2": "r5900:LE:32:default"}
EXECUTABLE_MAGIC = {"psx": b"PS-X EXE", "ps1": b"PS-X EXE", "ps2": b"\x7fELF"}


def headerless(platform: str, path: Path) -> bool:
    """A module file of a RAW_LANGUAGE platform that does not start with the executable magic."""
    if platform not in RAW_LANGUAGE:
        return False
    with open(path, "rb") as handle:
        return handle.read(len(EXECUTABLE_MAGIC[platform])) != EXECUTABLE_MAGIC[platform]


# Headline metrics (frozen definitions: tests/m21-001_real_images.py `score`,
# console_research `dwarf_scores`) and the documented supplement.
HEADLINE = ["recall", "precision", "success_rate", "arity_accuracy", "type_exact_rate"]
SUPPLEMENT = ["recall_verified", "precision_verified"]
# Metrics stock Ghidra can be compared on (it has no export-c success rate).
STOCK_METRICS = ["recall", "precision", "arity_accuracy", "type_exact_rate", "recall_verified",
                 "precision_verified"]
RATE_THRESHOLD = 0.005


def read_json(path: Path):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def hex_int(value) -> int:
    return int(value, 16) if isinstance(value, str) else int(value)


def parse_ranges(value) -> list[tuple[int, int]] | None:
    """meta.json `ranges`: [[lo, hi], ...] as integers or hex strings; null/empty = every executable region."""
    if not value:
        return None
    return [(hex_int(lo), hex_int(hi)) for lo, hi in value]


def elf_has_symtab(path: Path) -> bool:
    with open(path, "rb") as handle:
        if handle.read(4) != b"\x7fELF":
            return False
    out = subprocess.run(["llvm-readelf", "-S", "--wide", str(path)], capture_output=True, text=True)
    return ".symtab" in out.stdout


# ---------------------------------------------------------------------------
# Specs from meta.json
# ---------------------------------------------------------------------------

REQUIRED_META = ("id", "image", "truth_kind")


def discover(corpus: Path, wanted: set[str], min_age_s: float, now: float | None = None,
             symtab_variants: bool = False) -> tuple[list[dict], list[dict]]:
    """(specs, skipped) for every `<corpus>/<dir>/truth/meta.json`.

    A directory is skipped, with the reason recorded, when its meta.json is
    unreadable or lacks a required field, its functions.tsv or staged image is
    missing, or any of the three changed less than `min_age_s` ago (the corpus
    is still being written). An ELF carrying a `.symtab` is run stripped
    (llvm-strip --strip-all) as the m21 specs do, so the importer cannot read
    the truth from the symbols; `"strip": false` in meta.json opts out. With
    `symtab_variants`, each such image also yields `<id>-symtab` (symbols kept,
    only DWARF removed: llvm-objcopy --strip-debug), a supplement that isolates
    types from discovery as the PSP `-symtab` input does; its discovery is the
    symtab's and says nothing about discovery."""
    now = time.time() if now is None else now
    specs, skipped = [], []
    for meta_path in sorted(corpus.glob("*/truth/meta.json")):
        label = meta_path.parent.parent.name
        meta = read_json(meta_path)
        if not isinstance(meta, dict):
            skipped.append({"dir": label, "reason": "meta.json unreadable"})
            continue
        if wanted and label not in wanted and meta.get("id") not in wanted:
            continue
        missing = [field for field in REQUIRED_META if not meta.get(field)]
        tsv = meta_path.parent / "functions.tsv"
        image = corpus / label / str(meta.get("image", ""))
        if missing:
            reason = f"meta.json lacks {missing}"
        elif not tsv.is_file():
            reason = "truth/functions.tsv absent"
        elif not image.is_file():
            reason = f"staged image {meta['image']} absent"
        elif sum(1 for line in tsv.read_text(errors="replace").splitlines()[1:] if line.strip()) == 0:
            reason = "functions.tsv has a header and no rows (header-only truth)"
        elif (age := now - max(path.stat().st_mtime for path in (meta_path, tsv, image))) < min_age_s:
            reason = f"written {age:.0f}s ago (< {min_age_s:.0f}s): still being staged"
        else:
            reason = None
        if reason:
            skipped.append({"dir": label, "id": meta.get("id"), "reason": reason})
            continue
        platform = meta["id"].split("-")[0]
        strip = bool(meta.get("strip", True)) and elf_has_symtab(image)
        specs.append({
            "id": meta["id"], "image": f"{label}/{meta['image']}",
            "program": meta.get("program_hint") or PLATFORM_PROGRAM.get(platform, platform),
            "truth": ("tsv", f"{label}/truth/functions.tsv"), "ranges": parse_ranges(meta.get("ranges")),
            "strip": True if strip else False,
            "wave": {"meta": meta, "label": label, "platform": platform,
                     "modules": [dict(module) for module in meta.get("modules") or []]},
        })
        if symtab_variants and strip:
            twin = json.loads(json.dumps(specs[-1], default=list))
            twin["truth"] = tuple(twin["truth"])
            twin["ranges"] = parse_ranges(meta.get("ranges"))
            twin.update(id=f"{meta['id']}-symtab", strip="debug")
            twin["wave"]["variant"] = "symtab"
            specs.append(twin)
    return specs, skipped


def load_modules(path: Path, declared: list[dict] | None = None) -> dict[str, dict]:
    """functions.tsv -> {module: {"truth": {addr: (size, name)}, "verified": {addr}}}, `main` first.

    A duplicate address inside a module keeps the larger size and is verified
    when any of its rows is (the m21 loaders' rule). Modules not in the
    tsv but declared in meta.json are absent: nothing to score."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("m21_for_wave", Path(__file__).resolve().parents[1]
                                                   / "tests" / "m21-001_real_images.py")
    m21 = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m21)
    modules: dict[str, dict] = {}
    for row in m21.tsv_rows(path):
        entry = modules.setdefault(row["module"], {"truth": {}, "verified": set()})
        address = row["start"]
        old = entry["truth"].get(address)
        if old is None or old[0] < row["size"]:
            entry["truth"][address] = (row["size"], row["name"])
        if row["verified"]:
            entry["verified"].add(address)
    order = [MAIN] + [module["name"] for module in declared or []]
    ordered = {name: modules[name] for name in order if name in modules}
    ordered.update({name: modules[name] for name in modules if name not in ordered})
    return ordered


def parse_types(functions: dict) -> dict:
    """Types-file `functions`: key `%08x` (main module) or `<module>:%08x`; value the dwarf_truth row."""
    out = {}
    for key, row in functions.items():
        if ":" in key:
            module, address = key.rsplit(":", 1)
            out[(module, int(address, 16))] = row
        else:
            out[int(key, 16)] = row
    return out


def types_file(directory: Path) -> Path | None:
    """`truth/types/functions.json`, else the one `*.json` there holding a `functions` object."""
    base = directory / "truth" / "types"
    if (base / "functions.json").is_file():
        return base / "functions.json"
    found = [path for path in sorted(base.glob("*.json"))
             if isinstance((read_json(path) or {}).get("functions"), dict)] if base.is_dir() else []
    return found[0] if found else None


# ---------------------------------------------------------------------------
# Module placement
# ---------------------------------------------------------------------------

def alias(text: str) -> str:
    """The comparison key of a module name: `foresta.rel.szs` -> `foresta`, `overlay_0005` -> `ov5`."""
    stem = re.split(r"[\\/]", text.strip())[-1].lower().split(".")[0]
    key = re.sub(r"[^a-z0-9]", "", stem)
    match = re.fullmatch(r"(?:overlay|ovl|ov)0*(\d+)", key)
    return f"ov{int(match[1])}" if match else key


def intersect(ranges, lo: int, hi: int) -> list[tuple[int, int]]:
    return [(max(a, lo), min(b, hi)) for a, b in ranges if max(a, lo) < min(b, hi)]


def subtract(ranges, holes) -> list[tuple[int, int]]:
    out = []
    for lo, hi in ranges:
        parts = [(lo, hi)]
        for hole_lo, hole_hi in holes:
            kept = []
            for a, b in parts:
                if hole_hi <= a or hole_lo >= b:
                    kept.append((a, b))
                    continue
                if a < hole_lo:
                    kept.append((a, hole_lo))
                if hole_hi < b:
                    kept.append((hole_hi, b))
            parts = kept
        out += parts
    return out


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def score_found(found: dict[int, int], truth: dict[int, tuple[int, str]], verified: set[int],
                ranges: list[tuple[int, int]]) -> dict:
    """Recall/precision of `found` ({entry: size}) against one module's truth over `ranges`.

    The frozen metric is tests/m21-001_real_images.py `score` unchanged: truth
    entries inside the ranges, hits = those found, invented = found entries
    inside the ranges the truth does not name. The supplement restricts the
    truth to `verified` rows (units the decomp matched, so the boundary is
    compiler truth). Recall: verified entries found / verified entries in the
    ranges. Precision: verified hits / (verified hits + found entries strictly
    inside a verified function's extent [start, start+size) that no truth row
    names): such an entry is a split of a function whose boundary is known.
    Entries elsewhere (padding, data, unverified code) are not judged, as the
    truth cannot say whether they are functions; a verified row of size 0 has
    no extent and judges nothing but its own entry."""
    inside = lambda address: any(lo <= address < hi for lo, hi in ranges)  # noqa: E731
    scored = {address: value for address, value in truth.items() if inside(address)}
    hits = [address for address in scored if address in found]
    invented = [address for address in found if address not in scored and inside(address)]
    sized = [address for address in hits if scored[address][0]]
    in_ranges = sorted(address for address in found if inside(address))
    vscored = sorted(address for address in scored if address in verified)
    vhits = [address for address in vscored if address in found]
    split = set()
    for address in vscored:
        size = scored[address][0]
        if size > 0:
            split.update(entry for entry in in_ranges[bisect.bisect_right(in_ranges, address):
                                                      bisect.bisect_left(in_ranges, address + size)]
                         if entry not in scored)
    return {
        "truth": len(scored), "found": len(in_ranges), "hits": len(hits), "invented": len(invented),
        "recall": round(len(hits) / max(len(scored), 1), 4),
        "precision": round(len(hits) / max(len(hits) + len(invented), 1), 4),
        "sizes_compared": len(sized),
        "size_exact": sum(1 for a in sized if found[a] == scored[a][0]),
        "size_short": sum(1 for a in sized if found[a] < scored[a][0]),
        "size_long": sum(1 for a in sized if found[a] > scored[a][0]),
        "verified_truth": len(vscored), "verified_hits": len(vhits), "verified_split": len(split),
        "recall_verified": round(len(vhits) / len(vscored), 4) if vscored else None,
        "precision_verified": round(len(vhits) / (len(vhits) + len(split)), 4) if vhits or split else None,
        "missed_sample": [f"{a:#x} {scored[a][1]}" for a in sorted(set(scored) - set(found))[:10]],
        "invented_sample": [f"{a:#x}" for a in sorted(invented)[:10]],
    }


def nesting(truth: dict[int, tuple[int, str]]) -> dict:
    """Rows whose start lies strictly inside the extent of an earlier sized row.

    The walk is in address order against the outermost extent seen so far, so a row nested in a nested row
    is counted once, against the same outermost function. Nested truth rows are legitimate discovery starts
    (X360 `__unwind$N` SEH funclets, `__savegprlr_N` alternate entries: size 0; a DWARF size that straddles
    the next function's start): `score_found` keeps every row as a start and, wherever it asks "which
    function contains this address" (the verified supplement's extents), the extents are the union of the
    sized rows, i.e. the outermost one. `nested_size0` are the size-0 ones, `straddling` the nested rows
    whose own extent ends past the outermost function's."""
    outer_end = 0
    nested = nested_size0 = straddling = 0
    for start in sorted(truth):
        size = truth[start][0]
        if start < outer_end:
            nested += 1
            nested_size0 += size == 0
            straddling += size > 0 and start + size > outer_end
        outer_end = max(outer_end, start + size)
    return {"nested": nested, "nested_size0": nested_size0, "straddling": straddling}


def aggregate(rows: list[dict]) -> dict:
    """Pool per-module `score_found` rows (counts add; ratios recomputed). One row pools to itself."""
    total = {key: sum(row[key] for row in rows) for key in (
        "truth", "found", "hits", "invented", "sizes_compared", "size_exact", "size_short", "size_long",
        "verified_truth", "verified_hits", "verified_split")}
    total.update(
        recall=round(total["hits"] / max(total["truth"], 1), 4),
        precision=round(total["hits"] / max(total["hits"] + total["invented"], 1), 4),
        recall_verified=(round(total["verified_hits"] / total["verified_truth"], 4)
                         if total["verified_truth"] else None),
        precision_verified=(round(total["verified_hits"] / (total["verified_hits"] + total["verified_split"]), 4)
                            if total["verified_hits"] or total["verified_split"] else None),
        missed_sample=[s for row in rows for s in row["missed_sample"]][:10],
        invented_sample=[s for row in rows for s in row["invented_sample"]][:10])
    return total


# ---------------------------------------------------------------------------
# Rollup and sign tests
# ---------------------------------------------------------------------------

def sign_test(pairs: list[tuple[float, float]], threshold: float = RATE_THRESHOLD) -> dict:
    """One-sided sign test that the first value of each pair beats the second.

    A pair is a win when first - second >= threshold, a loss when <= -threshold,
    else a tie (dropped, as in any sign test). p = P(X >= wins), X ~
    Binomial(wins + losses, 1/2); None when nothing is left to test."""
    wins = sum(1 for a, b in pairs if a - b >= threshold)
    losses = sum(1 for a, b in pairs if b - a >= threshold)
    n = wins + losses
    p = sum(math.comb(n, k) for k in range(wins, n + 1)) / 2 ** n if n else None
    return {"games": len(pairs), "wins": wins, "losses": losses, "ties": len(pairs) - n,
            "p_value": None if p is None else round(p, 5)}


def metric_of(summary: dict | None, metric: str, main: bool = False):
    if not summary:
        return None
    if main and summary.get(f"{metric}_main") is not None:
        return summary[f"{metric}_main"]
    return summary.get(metric)


def game_values(image: dict) -> dict:
    """{tool: summary} of one image's combined results: default, baseline-off, stock."""
    out = {}
    for name in ("default", "baseline-off"):
        summary = (image.get("configs", {}).get(name) or {}).get("summary")
        if summary:
            out[name] = summary
    stock = ((image.get("stock") or {}).get("combined") or {}).get("summary")
    if stock:
        out["stock"] = stock
    return out


def stock_failure_of(image: dict) -> str | None:
    """The label of a stock run that gave no result: a DNF or crash record's label (stock's own
    failure), else the harness error, marked as such."""
    stock = image.get("stock") or {}
    if "error" not in stock:
        return None
    failure = stock.get("failure")
    return failure["label"] if failure else "stock error (harness): " + stock["error"].splitlines()[0][:100]


def rollup(report: dict, include_mismatch: bool = False) -> dict:
    """Per-platform game tables and the sign tests over games.

    A game is an image id that ran. A game whose meta.json says
    `version_match: false` is not in its platform's headline table or in any
    sign test: the decomp targets another build, so its truth is not (exactly)
    this image's. Such games go to `mismatch`, the supplement table, unless
    `include_mismatch` puts them back. Sign tests compare `default` with
    `baseline-off` (every metric) and with stock Ghidra (STOCK_METRICS,
    discovery on the main module only, where both tools were run), per
    platform and over all games."""
    platforms: dict[str, dict] = {}
    mismatch: dict[str, dict] = {}
    variants: dict[str, dict] = {}
    for image_id, image in report["images"].items():
        platform = image_id.split("-")[0]
        entry = platforms.setdefault(platform, {"games": {}, "failures": {}})
        if image.get("status") in ("error", "skipped"):
            # An image that did not run stays visible in its platform's table: a failure is a result.
            entry["failures"][image_id] = f"{image['status']}: {image.get('reason', '')}"
            continue
        if image.get("status") != "ran":
            continue
        values = game_values(image)
        if "default" not in values:
            continue
        meta = image.get("wave") or {}
        game = {"game": meta.get("game") or image_id, "version_match": meta.get("version_match", True),
                "truth_kind": meta.get("truth_kind"), "tools": values}
        if "stock" not in values and (failure := stock_failure_of(image)):
            game["stock_failure"] = failure
        if meta.get("variant"):
            variants[image_id] = game
        elif game["version_match"] is False and not include_mismatch:
            mismatch[image_id] = game
        else:
            entry["games"][image_id] = game
    for entry in platforms.values():
        entry["tests"] = tests_over(entry["games"])
        # Games without a stock result are in no vs-stock test: a stock DNF or crash counts neither way.
        entry["stock_excluded"] = {image_id: game["stock_failure"] for image_id, game in entry["games"].items()
                                   if game.get("stock_failure")}
    pooled = {image_id: game for entry in platforms.values() for image_id, game in entry["games"].items()}
    return {"platforms": platforms, "mismatch": mismatch, "variants": variants,
            "all": {"games": sorted(pooled), "tests": tests_over(pooled)},
            "sign_test": {"rate_threshold": RATE_THRESHOLD, "include_version_mismatch": include_mismatch}}


def tests_over(games: dict) -> dict:
    tests: dict[str, dict] = {}
    for other, metrics in (("baseline-off", HEADLINE + SUPPLEMENT), ("stock", STOCK_METRICS)):
        for metric in metrics:
            pairs = []
            for game in games.values():
                tools = game["tools"]
                a = metric_of(tools.get("default"), metric, main=other == "stock")
                b = metric_of(tools.get(other), metric, main=other == "stock")
                if a is not None and b is not None:
                    pairs.append((a, b))
            if pairs:
                tests[f"{metric} vs {other}"] = sign_test(pairs)
    return tests


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------

def fmt(value) -> str:
    return "–" if value is None else (f"{value:.4f}" if isinstance(value, float) else str(value))


COLUMNS = ["recall", "precision", "success_rate", "arity_accuracy", "type_exact_rate",
           "recall_verified", "precision_verified"]


def tool_row(label: str, tool: str, summary: dict, main: bool = False) -> str:
    cells = [fmt(metric_of(summary, metric, main)) for metric in COLUMNS]
    return f"| {label} | {tool} | " + " | ".join(cells) + f" | {summary.get('sampled', '–')} |"


def tool_rows(label: str, game: dict, main_too: bool = False) -> list[str]:
    """default, baseline-off and stock rows of one game; a stock run without a result is a labelled row
    (not a timing, not a zero)."""
    tools = game["tools"]
    rows = [tool_row(label, tool if tool != "stock" else "stock Ghidra", tools[tool])
            for tool in ("default", "baseline-off", "stock") if tool in tools]
    if "stock" not in tools and game.get("stock_failure"):
        rows.append(f"| {label} | stock Ghidra | **{game['stock_failure']}** | "
                    + " | ".join(["–"] * (len(COLUMNS) - 1)) + " | – |")
    if main_too and "stock" in tools:
        rows.append(tool_row(label, "default (main module only)", tools["default"], main=True))
    return rows


def markdown(report: dict, roll: dict) -> str:
    out = [f"# Console research wave ({report['generated']})", "",
           f"Tools fingerprint `{report['tools']}`; sample n={report['n']} per seed, seeds "
           f"{report['seeds']}; combined = the union of the seeds' samples (rows deduplicated). Truth: "
           f"`<corpus>/<id>/truth/{{meta.json,functions.tsv}}`. Headline metrics are the frozen ones "
           f"(recall, precision, success rate, arity, type exact); `recall_verified` / `precision_verified` "
           f"are the supplement over `verified=1` rows (docs/console-research.md).", ""]
    if report.get("wave_skipped"):
        out += ["## Skipped truth directories", "", "| dir | reason |", "|---|---|"]
        out += [f"| {row['dir']} | {row['reason']} |" for row in report["wave_skipped"]]
        out.append("")
    out += ["## Images", "",
            "| id | game | version | match | truth | compiler | linked % | truth fns | verified | nested (size 0) | "
            "scored modules | unplaced fns | stripped | status |",
            "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for image_id, image in report["images"].items():
        meta = image.get("wave") or {}
        out.append(f"| {image_id} | {meta.get('game', '')} | {meta.get('region_version', '')} | "
                   f"{meta.get('version_match', '')} | {meta.get('truth_kind', '')} | {meta.get('compiler', '')} | "
                   f"{meta.get('linked_percent', '')} | {meta.get('truth_functions', '')} | "
                   f"{meta.get('verified_functions', '')} | {meta.get('nested_rows', '')} ({meta.get('nested_size0_rows', '')}) | "
                   f"{modules_cell(meta.get('scored_modules') or [])} | "
                   f"{meta.get('unplaced_functions', '')} | {image.get('stripped', '')} | "
                   f"{image.get('status', '')}"
                   + (f": {image['reason'][:120]}" if image.get("reason") else "")
                   + (f" **DEGRADED import ({', '.join(image['degraded_imports'])}): not a valid measurement**"
                      if image.get("degraded_imports") else "") + " |")
    out.append("")
    header = ("| game | tool | recall | precision | success | arity | type exact | recall (verified) | "
              "precision (verified) | sampled |")
    rule = "|---|---|---|---|---|---|---|---|---|---|"
    for platform, entry in sorted(roll["platforms"].items()):
        out += [f"## {platform}", "", header, rule]
        for image_id, game in entry["games"].items():
            default = game["tools"]["default"]
            multi = default.get("recall_main") is not None and default.get("recall_main") != default.get("recall")
            out += tool_rows(image_id, game, main_too=multi)
        for image_id, reason in (entry.get("failures") or {}).items():
            out.append(f"| {image_id} | **did not run** | " + " | ".join(["–"] * 7) + f" | {reason[:160]} |")
        out += ["", sign_table(f"Sign tests, {platform}", entry["tests"]), ""]
    out += ["## All games", "", sign_table("Sign tests over all games", roll["all"]["tests"]), ""]
    if roll.get("variants"):
        out += ["## Supplement: symtab variants", "",
                "The staged ELF with its symbol table kept and only DWARF removed (`<id>-symtab`). It isolates "
                "type/arity recovery from discovery: its discovery numbers are the symtab's and say nothing "
                "about discovery. Not in the per-platform tables or the sign tests.", "", header, rule]
        for image_id, game in roll["variants"].items():
            out += tool_rows(image_id, game)
        out.append("")
    if roll.get("mismatch"):
        out += ["## Supplement: version-mismatch images", "",
                "meta.json says `version_match: false` (the decomp targets another build of the game; the truth "
                "is usable but not exact for this image). Not in the per-platform tables above or in any sign test.",
                "", header, rule]
        for image_id, game in roll["mismatch"].items():
            out += tool_rows(image_id, game)
        out.append("")
    out += ["The sign tests are a supplement. A game is a win when `default` beats the other tool by at least "
            f"{RATE_THRESHOLD * 100:.1f} pp (the harness's materiality floor), a loss when it trails by as much, "
            "else a tie (dropped). One-sided p = P(X >= wins), X ~ Binomial(wins + losses, 1/2). Games whose "
            "meta.json says `version_match: false` are in the supplement table only"
            + (" (here included: `--sign-include-mismatch`)." if roll["sign_test"]["include_version_mismatch"] else ".")
            + " vs stock uses discovery on the main module only (the module stock was run on). A game whose "
            "stock run did not finish within the limit (DNF) or crashed has a labelled stock row and is in no "
            "vs-stock test: it counts neither as a win nor as a loss.", ""]
    seeds = [image for image in report["images"].values() if image.get("per_seed")]
    if seeds:
        out += ["## Per seed (default vs baseline-off)", "",
                "| game | seed | config | recall | precision | success | arity | type exact | sampled |",
                "|---|---|---|---|---|---|---|---|---|"]
        for image_id, image in report["images"].items():
            for seed, view in (image.get("per_seed") or {}).items():
                for name in ("default", "baseline-off"):
                    summary = (view["configs"].get(name) or {}).get("summary")
                    if summary:
                        out.append(f"| {image_id} | {seed} | {name} | " + " | ".join(
                            fmt(summary.get(m)) for m in HEADLINE) + f" | {summary['sampled']} |")
        out.append("")
    return "\n".join(out) + "\n"


def modules_cell(names: list[str], limit: int = 4) -> str:
    return ", ".join(names[:limit]) + (f" (+{len(names) - limit})" if len(names) > limit else "")


def sign_table(title: str, tests: dict) -> str:
    if not tests:
        return f"**{title}**: no game has both sides measured."
    lines = [f"**{title}**", "", "| comparison | games | wins | losses | ties | one-sided p |", "|---|---|---|---|---|---|"]
    for name, test in tests.items():
        lines.append(f"| {name} | {test['games']} | {test['wins']} | {test['losses']} | {test['ties']} | "
                     f"{fmt(test['p_value'])} |")
    return "\n".join(lines)
