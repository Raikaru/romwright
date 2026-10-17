#!/usr/bin/env python3
"""Paired before/after function discovery on the corpus-wave images, scored by the wave scorer.

The scoring is `console_research.py`'s own (`wave_units` + `score_units`, which call
`console_research_wave.score_found`): the frozen `recall`/`precision` and the verified supplement
`recall_verified`/`precision_verified`, pooled over the image's placed modules. Nothing is
decompiled; each image is imported once per tools label and repetition with the default import
environment and `ROMWRIGHT_NO_IMPORT_CACHE=1`, and the labels alternate inside one repetition so
a shared host's load affects both alike. The 1/5/15-minute load average is read just before
each import.

  ps2_discovery.py --cache DIR --out J \
      --tools before=TARGET_BEFORE --tools after=TARGET_AFTER [--reps 1] [--corpus DIR] [image ...]

`TARGET_*` is a cargo target directory holding `release/romwright-cli` and
`release/romwright-worker` (the same layout `console_research.py --target-dir` takes). Images
default to the eight PS2 games of the wave. Writes only to --cache and --out; a run whose
import is `degraded` is reported as such and is not a valid measurement.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "benchmarks"))
import console_research as C  # noqa: E402
import console_research_wave as wave  # noqa: E402

PS2 = ["ps2-dark-chronicle", "ps2-dark-cloud", "ps2-digital-devil-saga", "ps2-fatal-frame", "ps2-god-hand",
       "ps2-persona-4", "ps2-ratchet-clank", "ps2-ratchet-clank-pal"]
KEYS = ("truth", "found", "hits", "invented", "recall", "precision", "verified_truth", "verified_hits",
        "verified_split", "recall_verified", "precision_verified")


def measure(tools, spec: dict, corpus: Path, cache: Path, jobs: int) -> dict:
    binary = C.prepared_binary(spec, corpus, cache)
    image_sha = C.sha256_file(corpus / spec["image"])
    truth_path = corpus / spec["truth"][1]
    modules = wave.load_modules(truth_path, spec["wave"]["modules"])
    spec["probe"] = sorted(modules.get(wave.MAIN, {"truth": {}})["truth"])[:5000]
    load = os.getloadavg()
    project, marker = C.import_project(tools, spec, binary, image_sha, C.BY_NAME["default"], None, cache)
    units, unresolved = C.wave_units(tools, spec, modules, project, marker, binary, {}, cache, corpus, jobs)
    score = C.score_units(units, modules, project)
    degraded = [d.get("message", "") for d in marker.get("diagnostics") or [] if d.get("severity") == "degraded"]
    return {"project": str(project), "program": marker["program"], "seconds": marker["seconds"],
            "load_before": [round(x, 2) for x in load], "degraded": degraded[:3],
            "units": [{"module": unit["module"], "ranges": unit["ranges"], **{k: row[k] for k in KEYS}}
                      for unit, row in zip(units, score["units"])],
            "unresolved": unresolved, **{k: score[k] for k in KEYS}}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("images", nargs="*")
    parser.add_argument("--corpus", type=Path, default=C.M21.CORPUS)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--tools", action="append", default=[], metavar="LABEL=TARGET_DIR")
    parser.add_argument("--reps", type=int, default=1)
    parser.add_argument("--jobs", type=int, default=2)
    args = parser.parse_args()
    labelled = [item.partition("=")[::2] for item in args.tools]
    if not labelled or any(not label or not target for label, target in labelled):
        parser.error("--tools LABEL=TARGET_DIR is required (at least once)")
    tools = {label: C.Tools(Path(target)) for label, target in labelled}
    wanted = set(args.images) or set(PS2)
    specs, _ = wave.discover(args.corpus, wanted, 0.0)
    specs = [spec for spec in specs if spec["id"] in wanted]
    report = {"tools": {label: t.fingerprint for label, t in tools.items()}, "images": {}}
    for spec in specs:
        rows = report["images"].setdefault(spec["id"], {label: [] for label in tools})
        for rep in range(args.reps):
            for label, t in tools.items():
                cache = args.cache / f"{label}-rep{rep}"
                row = measure(t, dict(spec), args.corpus, cache, args.jobs)
                rows[label].append(row)
                print(f"{spec['id']} {label} rep{rep}: recall {row['recall']} precision {row['precision']} "
                      f"verified {row['recall_verified']}/{row['precision_verified']} "
                      f"{row['seconds']}s load {row['load_before'][0]}"
                      + (f" DEGRADED {row['degraded']}" if row["degraded"] else ""), flush=True)
                args.out.write_text(json.dumps(report, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
