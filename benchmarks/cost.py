#!/usr/bin/env python3
"""Shared cost measurement for the M7 envelope gates.

One definition of "what it cost", used by every producer in every M7 gate:
`os.wait4`, whose `ru_maxrss` covers the process and the children it waited
for. That is the accounting `benchmarks/reports/baseline-stock.json` documents
for the stock launcher, so the JVM's decompiler child and `lre-cli`'s SLEIGH
console child are both inside their own producer's number rather than escaping
it.

An envelope is recorded once and compared against afterwards: a regression has
to appear as a failure, not as a new number.
"""
from __future__ import annotations

import json
import os
import platform
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

# Host noise moves peak RSS by a few percent; a quarter is generous without
# hiding a real regression, which shows up as a multiple.
HEADROOM = 1.25


def measure(command: list[str], cwd: Path | str | None = None,
            environment: dict[str, str] | None = None,
            output: Path | None = None) -> tuple[float, int, int]:
    """Wall seconds, peak RSS in KiB, exit code for one process tree.

    `output`, when given, receives stdout and stderr; a file rather than a
    pipe, so a chatty producer cannot deadlock on a full pipe buffer and
    inflate its own wall time.
    """
    stream = open(output, "wb") if output is not None else subprocess.DEVNULL
    try:
        started = time.monotonic()
        process = subprocess.Popen(command, cwd=cwd, env=environment,
                                   stdout=stream, stderr=subprocess.STDOUT
                                   if output is not None else subprocess.DEVNULL)
        _, status, usage = os.wait4(process.pid, 0)
        elapsed = time.monotonic() - started
    finally:
        if stream is not subprocess.DEVNULL:
            stream.close()
    peak = usage.ru_maxrss
    if platform.system() == "Darwin":  # ru_maxrss is bytes there, KiB on Linux
        peak //= 1024
    return elapsed, peak, os.waitstatus_to_exitcode(status)


def record_envelope(path: Path, peaks: dict[str, int], note: str,
                    extra: dict | None = None) -> None:
    """Write the envelope once; never overwrite a recorded one."""
    assert not path.is_file(), (
        f"{path} already exists; a recorded envelope is never overwritten")
    path.parent.mkdir(parents=True, exist_ok=True)
    document = {
        "id": path.stem,
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "host": {"system": platform.system(), "machine": platform.machine()},
        "headroom": HEADROOM,
        "note": note,
        "entries": peaks,
    }
    document.update(extra or {})
    path.write_text(json.dumps(document, indent=1) + "\n")


def check_envelope(path: Path, peaks: dict[str, int]) -> dict:
    """Fail when any entry is missing from, or grew past, the envelope."""
    assert path.is_file(), (
        f"{path} does not exist; record it once with --write")
    envelope = json.loads(path.read_text())
    recorded = envelope["entries"]
    missing = sorted(identifier for identifier in peaks if identifier not in recorded)
    assert not missing, f"the envelope has no entry for: {missing}"
    headroom = envelope.get("headroom", HEADROOM)
    over = {identifier: (peak, round(recorded[identifier] * headroom))
            for identifier, peak in peaks.items()
            if peak > recorded[identifier] * headroom}
    assert not over, f"native peak RSS grew past the recorded envelope: {over}"
    return envelope
