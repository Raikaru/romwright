#!/usr/bin/env python3
"""Imports staged N64 ROMs one at a time and records, beside each project, what `n64_layout_score.py`
needs for its timing columns: `<out>/<slug>.json` with the wall time and the load average read before
and after, and whether the import printed `degraded` (an import that did is not a valid measurement).

    n64_layout_run.py --cli-dir DIR --corpus ~/romwright-corpus/extracted --out OUT slug [slug ...]

`--cli-dir` holds `romwright-cli` and the `romwright-worker` it spawns from beside its own executable
(build both: a missing worker makes every import `degraded`). The import cache is switched off so a
rerun is a measurement. Run the baseline and the new binary back to back per game for a paired
comparison, each into its own `--out`.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import time
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cli-dir", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("slugs", nargs="+")
    args = parser.parse_args()
    env = dict(os.environ, ROMWRIGHT_NO_IMPORT_CACHE="1")
    args.out.mkdir(parents=True, exist_ok=True)
    for slug in args.slugs:
        rom = args.corpus / f"n64-{slug}" / f"n64-{slug}.z64"
        project = args.out / slug
        shutil.rmtree(project, ignore_errors=True)
        load_before = os.getloadavg()[0]
        started = time.time()
        proc = subprocess.run(
            [str(args.cli_dir / "romwright-cli"), "import", str(rom), "--name", "n64", "--timings", "--project", str(project)],
            capture_output=True, text=True, env=env)
        wall = time.time() - started
        text = proc.stdout + proc.stderr
        (args.out / f"{slug}.log").write_text(text)
        row = {"game": slug, "rc": proc.returncode, "wall_s": round(wall, 2), "load_before": load_before,
               "load_after": os.getloadavg()[0], "degraded": "degraded" in text.lower()}
        (args.out / f"{slug}.json").write_text(json.dumps(row))
        print(json.dumps(row), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
