#!/usr/bin/env python3
"""m14-004: the window shows facts so far, then fills them in.

`m14-003` holds the contract at the Core: answer now, say what is missing,
commit facts per function. This holds the half an analyst actually sees.

The desktop opens a project the way a large image forces you to -- map it,
show the loader's answer, analyse in the background -- and the gate reads
what the window displayed, not what the store believed:

1. **It shows something immediately, and admits it is incomplete.** The
   first completeness the window renders after opening is `provisional`,
   with no body analysed and every declared entry still to go.
2. **It fills in while you watch.** The window's own timer runs bounded
   passes; the gate polls the same status the window shows and requires it
   to reach "nothing left" without the window being touched again.
3. **It stops claiming to be provisional when it is not.** At the end,
   `stale` is false and every function is either walked or recorded as
   undecodable -- no seed silently left behind a finished-looking listing.

The gate uses the offscreen UI harness, so it exercises the real window,
its real bridge, and the real store.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "benchmarks"))
import ui_gate  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=300.0)
    arguments = parser.parse_args()

    report = {
        "gate": "m14-004",
        "milestone": "M14",
        "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT,
                                          text=True).strip(),
        "date": datetime.now(timezone.utc).date().isoformat(),
        "machine": {"os": platform.platform(), "cpu": platform.machine()},
    }
    failures = []
    try:
        app = ui_gate.default_app(ROOT)
    except ui_gate.GateError as error:
        report.update(status="skipped", reason=str(error))
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps(report, indent=2) + "\n")
        print(f"SKIP: {error}")
        return 0

    manifest = json.loads((arguments.corpus_dir / "manifest.json").read_text())
    row = next((item for item in manifest["entries"]
                if item["architecture"] == "x86_64" and item["variant"] == "many_o2"
                and item.get("status") == "ok"), None)
    if row is None:
        raise SystemExit("corpus row x86_64_many_o2 missing")
    binary = (arguments.corpus_dir / row["binary"]).resolve()

    import tempfile
    with tempfile.TemporaryDirectory(prefix="m14-004-") as temporary:
        project = Path(temporary) / "project"
        project.mkdir()
        environment_key = "VENTRIS_UI_LOAD_ONLY"
        previous = os.environ.get(environment_key)
        os.environ[environment_key] = "1"
        started = time.perf_counter()
        try:
            metrics = ui_gate.run_app(app, project, binary, "small", "00201000",
                                      arguments.timeout)
        finally:
            if previous is None:
                os.environ.pop(environment_key, None)
            else:
                os.environ[environment_key] = previous
        seconds = time.perf_counter() - started

    first = metrics.get("ui.analysis.first", "")
    report["metrics"] = {
        "first_shown": first,
        "final_shown": metrics.get("ui.analysis", ""),
        "analysed": metrics.get("ui.analysis.analysed"),
        "seeded": metrics.get("ui.analysis.seeded"),
        "stale": metrics.get("ui.analysis.stale"),
        "polls_while_filling": metrics.get("ui.analysis.polls"),
        "seconds": round(seconds, 3),
    }
    metrics_row = report["metrics"]
    if "provisional" not in first or "0 analysed" not in first:
        failures.append(
            f"the window's first answer did not admit to being provisional: {first!r}")
    if metrics_row["stale"] is not False:
        failures.append("the window never stopped calling its answer provisional")
    if not metrics_row["analysed"]:
        failures.append("no function was analysed by the window's own background pass")
    if metrics_row["seeded"]:
        failures.append(f"{metrics_row['seeded']} seeds left behind a finished listing")
    if not metrics_row["polls_while_filling"]:
        failures.append(
            "the pass finished before the window ever showed a provisional answer, "
            "so the filling-in was never observed")

    report["passed"] = not failures
    report["failures"] = failures
    arguments.report.parent.mkdir(parents=True, exist_ok=True)
    arguments.report.write_text(json.dumps(report, indent=2) + "\n")
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        return 1
    print(
        f"m14-004: PASS (window opened showing {first!r}, filled in over "
        f"{metrics_row['polls_while_filling']} polls, ended with "
        f"{metrics_row['analysed']} analysed and no seed left, in "
        f"{metrics_row['seconds']}s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
