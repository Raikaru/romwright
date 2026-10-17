#!/usr/bin/env python3
"""Compiler detection accuracy: what `romwright-cli import` records in
`programs.compiler`, scored against each game's truth.

For every corpus game with a truth `compiler` (`<corpus>/<game>/truth/meta.json`)
and the supplementary games whose truth lives in their manifests, the image is
imported with `--no-analysis` (the detector runs in the loader phase, before
discovery, so nothing else is needed), the stored id is read back from the
project database, and it is compared with the id the truth text names.

Verdicts per game:

  exact       the detected id is the truth id or one built on it
              (`ee-gcc-2.9x` is an `ee-gcc`);
  lineage     right toolchain lineage (GNU, MWCC, IDO, MSVC) when the family
              is not: `ee-gcc-2.9x` for SN ProDG, which is a gcc 2.95 derivative;
  abstained   `unknown` (the honest answer; a detector that does not exist for
              the platform lands here);
  wrong       a different lineage.

The truth text is free prose; `expected_id` is the one place it is turned into
a canonical id, and it names the rule for every platform. A game whose truth
names no compiler is not scored.

    python3 benchmarks/compiler_detection_accuracy.py --cli target/release/romwright-cli \
        --out benchmarks/reports/compiler_detection_accuracy.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORPUS = Path.home() / "romwright-corpus" / "extracted"

# Truth for games whose `truth/meta.json` does not exist: (relative image, truth id, source).
SUPPLEMENT = {
    "gba-pokeemerald": ("gba-pokeemerald/pokeemerald.gba", "agbcc", "manifest.json: matching agbcc build (pret/agbcc)"),
    "gc-animal-crossing": ("gc-animal-crossing/main.dol", "mwcc-gc", "ac-decomp (CodeWarrior GC), mwcc_runtime.rs"),
    "nds-pokeheartgold": ("nds-pokeheartgold/pokeheartgold.us.nds", "mwcc-arm", "manifest.json: mwccarm 2.0/sp2p2"),
    "ps2-capcom-fighting-evolution": ("ps2-capcom-fighting-evolution/SLUS_209.50", "mwcc-ps2",
                                      "manifest.json: Metrowerks CodeWarrior DWARF 1 sections"),
    "ps2-dungeon-game": ("ps2-dungeon-game/dungeon_game.elf", "ee-gcc", "DWARF producer `GNU C 3.2.2` (m23-001 supplementary)"),
    "psp-puzzle-bobble-pocket": ("psp-puzzle-bobble-pocket/[PSP] Puzzle Bobble Pocket (Korea) (En,Ja)/SYSDIR/BOOT.BIN",
                                 "allegrex-gcc", "libgcc/libm GCC 3.3.3 allegrex (STATUS.md, Puzzle Bobble Pocket)"),
}

# Which toolchain lineage an id belongs to, for the `lineage` verdict.
LINEAGE = {"mwcc": "mwcc", "mingw-gcc": "gnu", "ee-gcc": "gnu", "sn-prodg": "gnu", "allegrex-gcc": "gnu", "agbcc": "gnu", "n64-gcc": "gnu",
           "gcc": "gnu", "psyq-gcc": "gnu", "devkitarm-gcc": "gnu", "devkitppc-gcc": "gnu", "devkita64-gcc": "gnu",
           "ido": "ido", "msvc": "msvc", "clang": "llvm"}


def family_of(identifier: str) -> str:
    for family in sorted(LINEAGE, key=len, reverse=True):
        if identifier == family or identifier.startswith(family + "-"):
            return family
    return identifier


def covers(pattern: str, identifier: str) -> bool:
    return identifier == pattern or identifier.startswith(pattern + "-")


def expected_id(platform: str, text: str) -> str | None:
    """The canonical id a truth `compiler` text names; None when it names no id we model."""
    t = text.lower()
    if platform == "ps2":
        if t.startswith("mwcc ps2"):
            return "mwcc-ps2"
        if "sn prodg" in t[:24]:
            return "sn-prodg"
        if t.startswith("ee gcc"):
            return "ee-gcc"
    elif platform == "psp":
        if "metrowerks" in t[:40]:
            return "mwcc-psp"
        if t.startswith("gnu c"):
            return "allegrex-gcc"
    elif platform in ("gc", "wii"):
        if t.startswith("mwcc"):
            return "mwcc-gc" if platform == "gc" else "mwcc-wii"
    elif platform == "nds":
        if t.startswith("mwccarm"):
            return "mwcc-arm"
    elif platform == "gba":
        if re.match(r"(old_)?agbcc|agscc", t):
            return "agbcc"
    elif platform == "n64":
        if t.startswith("ido"):
            return "ido"
        if t.startswith("kmc gcc") or t.startswith("gcc "):
            return "n64-gcc"
    elif platform == "psx":
        if "codewarrior" in t[:30]:
            return "mwcc-psx"
        return "psyq-gcc"
    elif platform == "x360":
        m = re.search(r"optimizing compiler (\d+)\.", t)
        if m:
            return f"msvc-{m.group(1)}"
    elif platform == "pc":
        # the fixtures' meta.json names the toolchain: `MSVC 14.00.50727.42 (...)`, `GCC 16.2.1 MinGW-w64 ...`
        m = re.match(r"msvc (\d+)\.(\d+)", t)
        if m:
            return f"msvc-13.1" if (m.group(1), m.group(2)) == ("13", "10") else f"msvc-{m.group(1)}"
        m = re.match(r"gcc (\d+)\.", t)
        if m and "mingw" in t:
            return f"mingw-gcc-{m.group(1)}"
    return None


def verdict(truth: str, found: str) -> str:
    if found == "unknown":
        return "abstained"
    if covers(truth, found) or covers(found, truth):
        return "exact"
    if LINEAGE.get(family_of(truth)) and LINEAGE.get(family_of(truth)) == LINEAGE.get(family_of(found)):
        return "lineage"
    return "wrong"


def games(corpus: Path) -> list[dict]:
    rows = []
    for meta_path in sorted(corpus.glob("*/truth/meta.json")):
        game = meta_path.parent.parent.name
        meta = json.loads(meta_path.read_text())
        platform = meta.get("platform") or game.split("-")[0]
        truth = expected_id(platform, meta.get("compiler", ""))
        rows.append({"game": game, "platform": platform, "image": f"{game}/{meta.get('image', '')}", "truth": truth,
                     "truth_text": meta.get("compiler", ""), "source": "truth/meta.json"})
    seen = {row["game"] for row in rows}
    for game, (image, truth, source) in SUPPLEMENT.items():
        if game not in seen and (corpus / image).exists():
            rows.append({"game": game, "platform": game.split("-")[0], "image": image, "truth": truth,
                         "truth_text": source, "source": "supplement"})
    return rows


def detect(cli: Path, image: Path, work: Path, timeout: int) -> dict:
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    started = time.monotonic()
    try:
        run = subprocess.run([str(cli), "import", str(image), "--no-analysis", "--name", "x", "--project", str(work)],
                             capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"error": f"timeout after {timeout}s"}
    seconds = round(time.monotonic() - started, 1)
    db = work / "project.sqlite"
    if run.returncode != 0 or not db.exists():
        return {"error": (run.stderr or run.stdout).strip()[-300:], "seconds": seconds}
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        programs = con.execute("SELECT id, name, language, compiler FROM programs ORDER BY id").fetchall()
        out = []
        for pid, name, language, compiler in programs:
            evidence = con.execute(
                "SELECT message FROM import_diagnostics WHERE program_id=? AND stage='compiler' ORDER BY ordinal",
                (pid,)).fetchall()
            out.append({"program": name, "language": language, "compiler": compiler,
                        "evidence": evidence[0][0] if evidence else ""})
    finally:
        con.close()
    return {"programs": out, "seconds": seconds}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cli", type=Path, default=ROOT / "target" / "release" / "romwright-cli")
    parser.add_argument("--corpus", type=Path, default=CORPUS)
    parser.add_argument("--games", default="", help="comma-separated game ids (default: all)")
    parser.add_argument("--work", type=Path, default=Path(tempfile.gettempdir()) / "compiler-detection-accuracy")
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--out", type=Path, required=True, help="JSON report; a Markdown report is written beside it")
    parser.add_argument("--control", action="append", default=[], metavar="NAME=PATH=ID",
                        help="a synthetic control image (not a corpus game) and the id it should detect as; "
                             "reported apart from the corpus totals")
    parser.add_argument("--note", default="")
    args = parser.parse_args()

    wanted = {g for g in args.games.split(",") if g}
    rows = []
    for spec in games(args.corpus):
        if wanted and spec["game"] not in wanted:
            continue
        image = args.corpus / spec["image"]
        if not image.exists():
            rows.append({**spec, "status": "image missing"})
            continue
        print(f"{spec['game']} ...", file=sys.stderr, flush=True)
        found = detect(args.cli, image, args.work / spec["game"], args.timeout)
        if "error" in found:
            rows.append({**spec, "status": "import failed", "error": found["error"]})
            continue
        # The main program: the first one a container stores (NDS: arm9).
        program = found["programs"][0]
        detected = program["compiler"] or "(not recorded)"
        score = verdict(spec["truth"], detected) if spec["truth"] else "unscored"
        rows.append({**spec, "status": "ran", "detected": detected, "language": program["language"],
                     "evidence": program["evidence"], "verdict": score, "seconds": found["seconds"],
                     "programs": [p["compiler"] for p in found["programs"]]})
        shutil.rmtree(args.work / spec["game"], ignore_errors=True)

    controls = []
    for item in args.control:
        name, path, truth = item.split("=", 2)
        found = detect(args.cli, Path(path), args.work / f"control-{name}", args.timeout)
        if "error" in found:
            controls.append({"name": name, "image": path, "truth": truth, "status": "import failed", "error": found["error"]})
            continue
        program = found["programs"][0]
        controls.append({"name": name, "image": path, "truth": truth, "status": "ran", "detected": program["compiler"],
                         "evidence": program["evidence"], "verdict": verdict(truth, program["compiler"] or "(not recorded)")})
        shutil.rmtree(args.work / f"control-{name}", ignore_errors=True)

    scored = [r for r in rows if r.get("verdict") in ("exact", "lineage", "abstained", "wrong")]
    by_platform: dict[str, dict] = {}
    for row in scored:
        cell = by_platform.setdefault(row["platform"], {"games": 0, "exact": 0, "lineage": 0, "abstained": 0, "wrong": 0})
        cell["games"] += 1
        cell[row["verdict"]] += 1
    report = {
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "cli_sha256": hashlib.sha256(args.cli.read_bytes()).hexdigest(),
        "note": args.note,
        "games": rows,
        "controls": controls,
        "by_platform": by_platform,
        "totals": {k: sum(c[k] for c in by_platform.values()) for k in ("games", "exact", "lineage", "abstained", "wrong")},
    }
    args.out.write_text(json.dumps(report, indent=2) + "\n")
    args.out.with_suffix(".md").write_text(render(report))
    print(json.dumps(report["totals"]))
    return 0


def render(report: dict) -> str:
    lines = ["# Compiler detection accuracy", "",
             f"Generated {report['generated']} by `benchmarks/compiler_detection_accuracy.py` "
             f"(`romwright-cli` sha256 `{report['cli_sha256'][:16]}...`). {report['note']}", "",
             "`programs.compiler` after `import --no-analysis`, against the id the game's truth text names "
             "(`expected_id` in the script). `exact`: the truth id or one built on it; `lineage`: right toolchain "
             "lineage, different family; `abstained`: `unknown`; `wrong`: a different lineage.", "",
             "## By platform", "", "| platform | scored | exact | lineage only | abstained | wrong |", "|---|---|---|---|---|---|"]
    for platform, cell in sorted(report["by_platform"].items()):
        lines.append(f"| {platform} | {cell['games']} | {cell['exact']} | {cell['lineage']} | {cell['abstained']} | {cell['wrong']} |")
    t = report["totals"]
    lines += [f"| **all** | {t['games']} | {t['exact']} | {t['lineage']} | {t['abstained']} | {t['wrong']} |", "",
              "## By game", "", "| game | truth | detected | verdict | evidence |", "|---|---|---|---|---|"]
    for row in report["games"]:
        if row.get("status") != "ran":
            lines.append(f"| {row['game']} | {row.get('truth') or '-'} | - | {row.get('status')} | {row.get('error', '')[:80]} |")
            continue
        evidence = row["evidence"].split("): ", 1)[-1][:110].replace("|", "\\|")
        lines.append(f"| {row['game']} | {row['truth'] or '-'} | {row['detected']} | {row['verdict']} | {evidence} |")
    lines.append("")
    if report.get("controls"):
        lines += ["## Controls", "",
                  "Synthetic images, not corpus games and not in the totals: what the detector says about a toolchain the "
                  "corpus has no game for.", "", "| control | expected | detected | verdict | evidence |", "|---|---|---|---|---|"]
        for row in report["controls"]:
            if row.get("status") != "ran":
                lines.append(f"| {row['name']} | {row['truth']} | - | {row['status']} | {row.get('error', '')[:80]} |")
                continue
            evidence = row["evidence"].split("): ", 1)[-1][:120].replace("|", "\\|")
            lines.append(f"| {row['name']} | {row['truth']} | {row['detected']} | {row['verdict']} | {evidence} |")
        lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
