#!/usr/bin/env python3
"""m7-003: what a long-lived session costs, and whether it leaks.

`m7-001` and `m7-002` each measure one process that starts, answers once and
exits. The desktop and every script hold a project open through a single
`lre-api` process and ask it many questions, and nothing measured what that
costs after N requests -- or whether the Nth answer costs more than the
second.

Per locked corpus entry this drives one long-lived `lre-api` process through
the same request sequence for several identical rounds, sampling the *process
tree*'s resident size (the service plus the SLEIGH console child it spawns for
`decompile_doc`) every 25 ms. It then requires:

  * the peak tree RSS to stay inside `benchmarks/reports/session-envelope.json`,
    recorded once with `--write` and never edited afterwards;
  * resident size to plateau: growth across the measured rounds within
    `max(4 MiB, 5%)`, and not strictly increasing every round unless total
    growth stays under 512 KiB. A warm cache is not a leak, but a cache that
    never stops filling is, so four warm-up rounds run first and are excluded
    from both the plateau baseline and the drift comparison -- measured on the
    PowerPC entries, `decompile_doc` settles from 33 ms to 7 ms to 3.3 ms over
    the first four rounds;
  * latency not to drift: for each method the second half of the measured
    rounds within twice the first half plus 2 ms, that floor being what
    separates a regression from jitter on reads that answer in 0.2 ms.
    Absolute latency is recorded rather than gated, because it tracks the
    host's CPU while drift does not.

Usage:
    python3 tests/m7-003_session_envelope.py --corpus-dir DIR [--write] [--report OUT.json]
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "benchmarks"))
from cost import HEADROOM, check_envelope, record_envelope  # noqa: E402

ENVELOPE = ROOT / "benchmarks" / "reports" / "session-envelope.json"
# Warm-up is measured but excluded: the console child settles over the first
# few requests, and that descent is not what this gate is looking for.
WARMUP = 4
ROUNDS = 8
SAMPLE_SECONDS = 0.025
# Allocator arenas and page rounding move a settled process by a few hundred
# KiB; a leak shows up as growth that never stops.
PLATEAU_FLOOR_KB = 4096
PLATEAU_FRACTION = 0.05
MONOTONIC_FLOOR_KB = 512
DRIFT_FACTOR = 2.0
DRIFT_FLOOR_MS = 2.0


def descendants(pid: int) -> list[int]:
    """The pid and every process below it, from /proc children lists."""
    found, frontier = [], [pid]
    while frontier:
        current = frontier.pop()
        found.append(current)
        task = Path(f"/proc/{current}/task")
        try:
            for thread in task.iterdir():
                children = (thread / "children").read_text().split()
                frontier.extend(int(child) for child in children)
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
    return found


def tree_rss_kb(pid: int) -> int:
    total = 0
    for process in descendants(pid):
        try:
            for line in Path(f"/proc/{process}/status").read_text().splitlines():
                if line.startswith("VmRSS:"):
                    total += int(line.split()[1])
                    break
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
    return total


class Sampler(threading.Thread):
    """Peak of the process tree's resident size, sampled while it runs."""

    def __init__(self, pid: int) -> None:
        super().__init__(daemon=True)
        self.pid = pid
        self.peak = 0
        self.stop = threading.Event()

    def run(self) -> None:
        while not self.stop.is_set():
            self.peak = max(self.peak, tree_rss_kb(self.pid))
            self.stop.wait(SAMPLE_SECONDS)


def sequence(program: str, binary: Path, address: str, console: bool
             ) -> list[tuple[str, dict]]:
    requests: list[tuple[str, dict]] = [
        ("functions", {"program": program}),
        ("symbols", {"program": program}),
        ("strings", {"program": program}),
        ("memory_regions", {"program": program}),
        ("search", {"program": program, "term": "main"}),
        ("xrefs", {"program": program, "address": address}),
    ]
    if console:
        requests.append(("decompile_doc", {"program": program,
                                           "binary": str(binary),
                                           "address": address}))
    return requests


def native_address(program: str, project: Path) -> str:
    listing = subprocess.run(
        [str(ROOT / "target/release/lre-cli"), "functions", program,
         "--project", str(project)],
        cwd=ROOT, capture_output=True, text=True, check=True).stdout
    for line in listing.splitlines():
        fields = line.split()
        if fields and fields[-1] == "main":
            return fields[0]
    raise AssertionError("the native store has no function named main")


def drive(identifier: str, binary: Path, temporary: Path, console: bool) -> dict:
    project = temporary / "project"
    imported = subprocess.run(
        [str(ROOT / "target/release/lre-cli"), "import", str(binary),
         "--name", "session", "--project", str(project)],
        cwd=ROOT, capture_output=True, text=True)
    assert imported.returncode == 0, (
        f"{identifier}: import failed: {imported.stderr}")
    address = native_address("session", project)
    requests = sequence("session", binary, address, console)

    service = subprocess.Popen(
        [str(ROOT / "target/release/lre-api"), "--project", str(project)],
        cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, text=True, bufsize=1)
    sampler = Sampler(service.pid)
    sampler.start()
    latencies: dict[str, list[float]] = {method: [] for method, _ in requests}
    warmup: dict[str, list[float]] = {method: [] for method, _ in requests}
    rounds: list[int] = []
    identity = 0
    try:
        for index in range(WARMUP + ROUNDS):
            warming = index < WARMUP
            for method, parameters in requests:
                identity += 1
                envelope = {"api": 2, "id": identity, "method": method,
                            "params": parameters}
                started = time.monotonic()
                service.stdin.write(json.dumps(envelope) + "\n")
                service.stdin.flush()
                line = service.stdout.readline()
                elapsed = (time.monotonic() - started) * 1000.0
                (warmup if warming else latencies)[method].append(elapsed)
                assert line, f"{identifier}: the service closed on {method}"
                answer = json.loads(line)
                assert answer.get("id") == identity, (
                    f"{identifier}: {method} answered out of order: {line[:120]}")
                assert "result" in answer, (
                    f"{identifier}: {method} failed: {line[:200]}")
            if not warming:
                rounds.append(tree_rss_kb(service.pid))
        service.stdin.close()
        assert service.wait(timeout=30) == 0, (
            f"{identifier}: the service exited {service.returncode}")
    finally:
        sampler.stop.set()
        sampler.join(timeout=2)
        if service.poll() is None:
            service.kill()

    assert all(rounds), f"{identifier}: sampled no resident size: {rounds}"
    baseline = rounds[0]
    growth = rounds[-1] - baseline
    tolerance = max(PLATEAU_FLOOR_KB, int(baseline * PLATEAU_FRACTION))
    assert growth <= tolerance, (
        f"{identifier}: resident size grew {growth} KiB across {ROUNDS} "
        f"measured rounds (tolerance {tolerance} KiB): {rounds}")
    climbing = all(rounds[index] < rounds[index + 1]
                   for index in range(len(rounds) - 1))
    assert not (climbing and growth > MONOTONIC_FLOOR_KB), (
        f"{identifier}: resident size grew every round, {growth} KiB in total: "
        f"{rounds}")

    early = slice(0, ROUNDS // 2)
    late = slice(ROUNDS // 2, ROUNDS)
    drift = {}
    for method, samples in latencies.items():
        before = statistics.median(samples[early])
        after = statistics.median(samples[late])
        drift[method] = round(after / before, 2) if before else 0.0
        assert after <= before * DRIFT_FACTOR + DRIFT_FLOOR_MS, (
            f"{identifier}: {method} slowed from {before:.2f}ms to "
            f"{after:.2f}ms over the session")

    return {
        "id": identifier,
        "requests_per_round": len(requests),
        "warmup_rounds": WARMUP,
        "rounds": rounds,
        "warmup_latency_ms": {method: round(statistics.median(samples), 3)
                              for method, samples in warmup.items()},
        "peak_kb": sampler.peak,
        "growth_kb": growth,
        "growth_tolerance_kb": tolerance,
        "drift_ratio_max": max(drift.values()),
        "latency_ms": {method: round(statistics.median(samples), 3)
                       for method, samples in latencies.items()},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--write", action="store_true",
                        help="record the envelope; refuses to overwrite one")
    arguments = parser.parse_args()

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-api",
                    "-p", "lre-cli"], cwd=ROOT, check=True)
    manifest = json.loads((arguments.corpus_dir / "manifest.json").read_text())
    entries = [entry for entry in manifest["entries"]
               if entry.get("status") == "ok" and entry.get("unstripped_twin")]
    assert len(entries) >= 20, f"only {len(entries)} corpus entries are usable"

    console = bool(os.environ.get("VENTRIS_CONSOLE")) or (
        ROOT / "native/build/decomp_native").is_file()
    skipped = [] if console else [
        "decompile_doc: no SLEIGH console, so the session holds no console child"]

    rows = [drive(f"{entry['architecture']}_{entry['variant']}",
                  arguments.corpus_dir / entry["unstripped_twin"],
                  Path(directory), console)
            for entry in entries
            for directory in [tempfile.mkdtemp(prefix="m7-003-")]]

    peaks = {row["id"]: row["peak_kb"] for row in rows}
    if arguments.write:
        record_envelope(
            ENVELOPE, peaks,
            f"peak process-tree RSS of one lre-api session answering "
            f"{rows[0]['requests_per_round']} requests for {WARMUP} warm-up "
            f"and {ROUNDS} measured rounds per locked corpus entry; recorded "
            f"once, compared against afterwards",
            extra={"rounds": ROUNDS, "warmup_rounds": WARMUP,
                   "latency_ms": {row["id"]: row["latency_ms"] for row in rows},
                   "latency_note": "recorded for reference, not gated: absolute "
                                   "latency tracks the host's CPU, while the "
                                   "drift between early and late rounds does not"})
        print(f"recorded {ENVELOPE.relative_to(ROOT)} for {len(rows)} entries")
    check_envelope(ENVELOPE, peaks)

    methods = sorted(rows[0]["latency_ms"])
    metrics = {
        "session.peak_kb.median": statistics.median(peaks.values()),
        "session.growth_kb.max": max(row["growth_kb"] for row in rows),
        "session.growth_kb.median":
            statistics.median(row["growth_kb"] for row in rows),
        "session.drift_ratio.max": max(row["drift_ratio_max"] for row in rows),
    }
    for method in methods:
        metrics[f"session.latency_ms.{method}.median"] = round(
            statistics.median(row["latency_ms"][method] for row in rows), 3)

    summary = (f"{len(rows)} locked entries, one session each answering "
               f"{rows[0]['requests_per_round']} requests x {WARMUP} warm-up + "
               f"{ROUNDS} measured rounds: "
               f"peak {metrics['session.peak_kb.median']} KiB median, resident "
               f"growth {metrics['session.growth_kb.max']} KiB worst case after "
               f"round 2, latency drift {metrics['session.drift_ratio.max']}x "
               f"worst case, every entry inside the recorded envelope")
    if not console:
        summary += "; decompile_doc skipped without a console"

    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps({
            "id": "m7-003",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "status": "pass",
            "passed": True,
            "summary": summary,
            "host": {"system": platform.system(), "machine": platform.machine()},
            "headroom": HEADROOM,
            "rounds": ROUNDS,
            "warmup_rounds": WARMUP,
            "metrics": metrics,
            "corpus": rows,
            "skipped": skipped,
        }, indent=1) + "\n")
    print(f"m7-003: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
