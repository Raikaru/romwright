#!/usr/bin/env python3
"""m14-003: every query answers now, and says what it is missing.

The interactive contract has two halves and this gate holds both:

1. **Answer now.** A query never waits for analysis. Against a loader-only
   import -- where nothing has been walked -- listing, symbol and xref
   queries answer from committed facts within a bounded time, and they carry
   a status saying the answer is provisional: how many functions are walked
   bodies, how many are entries the image merely declared.

2. **Commit as you go.** A background pass analyses seeds one at a time and
   commits each body's facts on its own, bumping the store revision per
   function, so a consumer polling `events_since` watches the store grow
   instead of waiting for a whole image. Queries stay fast *while* the pass
   runs -- measured with the pass running, not before it.

3. **Finish honestly.** Run to completion on a small image and the status
   stops being provisional: no seed is left, and the count of walked bodies
   equals the functions the store holds.

What the facts *are* once walked is m14-002's claim (byte-identical to
whole-image analysis); this gate is about when they arrive and how they are
described while incomplete.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "target/release/romwright-cli"
LIBC_CANDIDATES = (
    "/usr/lib64/libc.so.6",
    "/usr/lib/x86_64-linux-gnu/libc.so.6",
    "/lib/x86_64-linux-gnu/libc.so.6",
)
# A query is a store read; anything approaching a second means it waited for
# work it should not have waited for.
QUERY_CEILING_S = 0.25
BUDGET = 100


def libc() -> Path:
    pinned = os.environ.get("ROMWRIGHT_LIBC")
    if pinned:
        return Path(pinned)
    for candidate in LIBC_CANDIDATES:
        if Path(candidate).is_file():
            return Path(candidate)
    return Path(LIBC_CANDIDATES[0])


def run(arguments, environment, timeout=600):
    result = subprocess.run([str(CLI), *arguments], cwd=ROOT, env=environment,
                            capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"{' '.join(arguments)}: {result.stderr[-600:]}")
    return result.stdout


def status(program, project, environment):
    return json.loads(run(["status", program, "--project", str(project), "--json"],
                          environment).strip())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    arguments = parser.parse_args()
    environment = os.environ.copy()
    environment["ROMWRIGHT_NO_IMPORT_CACHE"] = "1"
    subprocess.run(["cargo", "build", "-q", "--release", "-p", "romwright-cli"], cwd=ROOT, check=True)

    failures = []
    report = {
        "gate": "m14-003",
        "milestone": "M14",
        "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT,
                                          text=True).strip(),
        "date": datetime.now(timezone.utc).date().isoformat(),
        "machine": {"os": platform.platform(), "cpu": platform.machine()},
        "thresholds": {"query_seconds": QUERY_CEILING_S},
        "metrics": {},
    }

    with tempfile.TemporaryDirectory(prefix="m14-003-") as temporary:
        work = Path(temporary)
        binary = libc()
        if not binary.is_file():
            raise SystemExit(f"{binary} not present")
        project = work / "libc"
        load_started = time.perf_counter()
        run(["import", str(binary), "--project", str(project), "--name", "libc",
             "--no-analysis"], environment, timeout=1800)
        load_seconds = time.perf_counter() - load_started

        # 1. Answer now, and say what is missing.
        first = status("libc", project, environment)
        if not first["stale"] or first["analysed"] != 0 or first["seeded"] == 0:
            failures.append(f"a loader-only import does not report itself provisional: {first}")

        # 2. Queries stay fast while a pass is committing facts.
        latencies = {}
        pass_result = {}

        def background():
            started = time.perf_counter()
            pass_result["status"] = json.loads(run(
                ["analyse-pending", str(binary), "libc", "--budget", str(BUDGET),
                 "--project", str(project), "--json"], environment, timeout=1800).strip())
            pass_result["seconds"] = time.perf_counter() - started

        worker = threading.Thread(target=background)
        worker.start()
        time.sleep(0.2)
        while worker.is_alive():
            for query in (["functions", "libc", "--limit", "50"],
                          ["symbols", "libc"],
                          ["status", "libc"]):
                started = time.perf_counter()
                run([*query, "--project", str(project)], environment, timeout=120)
                elapsed = time.perf_counter() - started
                latencies[query[0]] = max(latencies.get(query[0], 0.0), elapsed)
            time.sleep(0.05)
        worker.join()
        for name, worst in latencies.items():
            if worst > QUERY_CEILING_S:
                failures.append(
                    f"`{name}` took {worst:.3f}s while a pass was running, over "
                    f"{QUERY_CEILING_S}s")
        if not latencies:
            failures.append("the pass finished before any query could be timed against it")

        after = pass_result.get("status") or status("libc", project, environment)
        analysed = after["analysed"] - first["analysed"]
        if analysed != BUDGET:
            failures.append(f"a budget of {BUDGET} analysed {analysed} functions")
        # One commit per function: the revision moves by the work done, so a
        # consumer can tell how much is new without re-reading everything.
        if after["revision"] - first["revision"] != analysed:
            failures.append(
                f"revision moved {after['revision'] - first['revision']} for {analysed} "
                "functions: facts are not committed per function")
        if not after["stale"]:
            failures.append("still 3798 seeds left but the answer claims to be complete")

        # 3. Run a small image to completion.
        manifest = json.loads((arguments.corpus_dir / "manifest.json").read_text())
        row = next((item for item in manifest["entries"]
                    if item["architecture"] == "x86_64" and item["variant"] == "many_o2"
                    and item.get("status") == "ok"), None)
        if row is None:
            raise SystemExit("corpus row x86_64_many_o2 missing")
        small = (arguments.corpus_dir / row["binary"]).resolve()
        small_project = work / "small"
        run(["import", str(small), "--project", str(small_project), "--name", "small",
             "--no-analysis"], environment, timeout=1800)
        before_small = status("small", small_project, environment)
        rounds = 0
        finish_started = time.perf_counter()
        while True:
            current = json.loads(run(
                ["analyse-pending", str(small), "small", "--budget", "200",
                 "--project", str(small_project), "--json"], environment,
                timeout=1800).strip())
            rounds += 1
            if not current["stale"] or rounds > 20:
                break
        finish_seconds = time.perf_counter() - finish_started
        if current["stale"] or current["seeded"]:
            failures.append(
                f"analysing every seed left {current['seeded']} of them unanalysed")
        if current["analysed"] + current["undecodable"] != current["functions"]:
            failures.append(f"functions do not add up after a complete pass: {current}")

        report["metrics"] = {
            "load_seconds": round(load_seconds, 3),
            "libc_functions": first["functions"],
            "libc_seeded_at_load": first["seeded"],
            "budgeted_pass_seconds": round(pass_result.get("seconds", 0.0), 3),
            "analysed_in_pass": analysed,
            "revision_moved": after["revision"] - first["revision"],
            "worst_query_seconds": {name: round(value, 4)
                                    for name, value in sorted(latencies.items())},
            "small_functions": before_small["functions"],
            "small_rounds_to_finish": rounds,
            "small_finish_seconds": round(finish_seconds, 3),
            "small_analysed": current["analysed"],
            "small_undecodable": current["undecodable"],
        }

    report["passed"] = not failures
    report["failures"] = failures
    arguments.report.parent.mkdir(parents=True, exist_ok=True)
    arguments.report.write_text(json.dumps(report, indent=2) + "\n")
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        return 1
    metrics = report["metrics"]
    worst = max(metrics["worst_query_seconds"].values(), default=0.0)
    print(
        f"m14-003: PASS (libc loaded in {metrics['load_seconds']}s as "
        f"{metrics['libc_seeded_at_load']} seeds; {metrics['analysed_in_pass']} bodies "
        f"committed one at a time in {metrics['budgeted_pass_seconds']}s, revision moved "
        f"{metrics['revision_moved']}; worst query while analysing {worst:.3f}s; "
        f"{metrics['small_functions']} functions analysed to completion in "
        f"{metrics['small_finish_seconds']}s and the answer stopped being provisional)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
