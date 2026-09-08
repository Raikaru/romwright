#!/usr/bin/env python3
"""m4-024: the try ranges `.gcc_except_table` declares are facts we record.

Ghidra's `GccExceptionAnalyzer` walks each function's LSDA call-site table and
writes one PRE comment per call site that has a landing pad:

    try { // try from <first> to <last> has its CatchHandler @ <pad>

(`GccExceptionAnalyzer.markStartOfTry`, :292-303). Its decompiler then prints
that comment, which is the whole of the `exception-annotation` divergence
class in `m4-003`: four C++ rows differed by a comment we did not have,
because we read neither `.eh_frame`'s augmentation data nor the LSDA it points
at.

This gate reads the ranges from our own store, renders the comment Ghidra
renders, and compares it with what **stock recorded for the same bytes** --
address, owning function and text -- in both directions. It then decompiles
the owning function through the native worker and requires the comment in the
text, since a fact the decompiler never sees closes nothing.

    python3 tests/m4-024_exception_annotations.py --corpus-dir DIR [--report OUT.json]
"""
from __future__ import annotations

import argparse
import concurrent.futures
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "benchmarks"))
import gate_cache  # noqa: E402
CLI = ROOT / "target/release/lre-cli"
LOCK = ROOT / "tests/corpus.lock.json"
# The shapes Ghidra's exception analyzer writes; nothing else in a comment is
# this gate's business.
SHAPES = ("try { // try from", "} // end try from", "catch(")
SOURCE = "native-import:elf-exception"


def rows(store: Path, query: str, *arguments) -> list[tuple]:
    connection = sqlite3.connect(store)
    try:
        (identifier,) = connection.execute("SELECT id FROM programs").fetchone()
        return list(connection.execute(query, (identifier, *arguments)))
    finally:
        connection.close()


def exception_comments(store: Path) -> dict[tuple[str, str], str]:
    """`(address, function) -> text` for every exception comment a store holds."""
    held = {}
    for address, function, text in rows(
            store, "SELECT address, function, text FROM comments "
                   "WHERE program_id = ? AND type = 'pre'"):
        if any(text.startswith(shape) for shape in SHAPES):
            held[(address, function)] = text
    return held


def rendered_sites(store: Path) -> dict[tuple[str, str], str]:
    """The same mapping, rendered from the ranges our store records.

    The rendering is Ghidra's: the call site's first and last address, and the
    landing pad, each printed as an address.
    """
    rendered = {}
    for function, start, end, pad, provenance in rows(
            store, "SELECT function, start, end, landing_pad, provenance "
                   "FROM exception_sites WHERE program_id = ?"):
        assert provenance == SOURCE, f"unexpected provenance {provenance}"
        rendered[(start, function)] = (
            f"try {{ // try from {start} to {end} has its CatchHandler @ {pad}")
    return rendered


def native_import(binary: Path, name: str) -> Path:
    """A native store, reused while the binary and the build are unchanged."""
    def build(directory: Path) -> None:
        result = subprocess.run(
            [str(CLI), "import", str(binary), "--name", name,
             "--project", str(directory)],
            capture_output=True, text=True, timeout=900)
        assert result.returncode == 0, (
            f"{name}: native import failed: {result.stderr[-400:]}")

    return gate_cache.store(gate_cache.native_key(binary, program=name), build)


def oracle_import(binary: Path, name: str, install: Path) -> Path:
    """The oracle's store for the same bytes, keyed by its own provenance."""
    def build(directory: Path) -> None:
        result = subprocess.run(
            [str(CLI), "import", str(binary), "--name", name, "--oracle",
             "--project", str(directory), "--ghidra", str(install)],
            capture_output=True, text=True, timeout=1800,
            env=dict(os.environ, DEBUGINFOD_URLS=""))
        assert result.returncode == 0, (
            f"{name}: oracle import failed: {result.stderr[-400:]}")

    return gate_cache.store(gate_cache.oracle_key(binary, install, program=name), build)


def decompiled(binary: Path, project: Path, name: str, addresses: list[str]) -> dict:
    """One launch for every function this row needs, not one launch each."""
    joined = ",".join(addresses)
    def build() -> dict:
        result = subprocess.run(
            [str(CLI), "decompile-batch", str(binary), joined, "--name", name,
             "--project", str(project)],
            capture_output=True, text=True, timeout=900)
        assert result.returncode == 0, (
            f"{name}: decompile failed: {result.stderr[-400:]}")
        return json.loads(result.stdout)

    return gate_cache.document(
        gate_cache.native_key(binary, program=name, artifact="decompile-batch",
                              addresses=hashlib.sha256(joined.encode()).hexdigest()),
        build)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--ghidra", type=Path,
                        default=Path(os.environ.get("VENTRIS_GHIDRA",
                                                    Path.home() / "ghidra_12.1.3_PUBLIC")))
    parser.add_argument("--report", type=Path)
    parser.add_argument("--jobs", type=int, default=4,
                        help="rows measured concurrently; an uncached row runs a JVM")
    arguments = parser.parse_args()
    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-cli", "-p", "lre-worker"],
                   cwd=ROOT, check=True)
    lock = json.loads(LOCK.read_text())
    # The C++ rows are the ones with exception tables; the others are the
    # control: a row with no landing pad must gain no comment.
    wanted = [entry for entry in lock["entries"]
              if entry.get("format") == "elf"
              and entry.get("variant") in ("cpp_o2", "plain_o0")]
    assert wanted, "the lock holds no ELF rows to measure"

    def measure(entry: dict) -> tuple[dict, list, list]:
        binary = arguments.corpus_dir / entry["binary"]
        name = Path(entry["binary"]).stem
        native = native_import(binary, name)
        oracle = oracle_import(binary, name, arguments.ghidra)
        ours = rendered_sites(native / "project.sqlite")
        theirs = exception_comments(oracle / "project.sqlite")
        held = exception_comments(native / "project.sqlite")
        assert not held, (
            f"{name}: derived ranges must not be written into the analyst's "
            f"comments: {held}")
        absent, extra = [], []
        for key, text in theirs.items():
            if ours.get(key) != text:
                absent.append({"row": name, "address": key[0], "function": key[1],
                               "stock": text, "ours": ours.get(key)})
        for key, text in ours.items():
            if theirs.get(key) != text:
                extra.append({"row": name, "address": key[0], "function": key[1],
                              "ours": text, "stock": theirs.get(key)})
        row = {"id": name, "variant": entry["variant"], "sites": len(ours),
               "stock_comments": len(theirs)}
        # A recorded range has to reach the decompiler, or the parity class it
        # was recorded for stays open. One launch answers every function this
        # row records a range for.
        if ours:
            functions = sorted({function for _, function in ours})
            bodies = decompiled(binary, native, name, functions)
            for (address, function), text in sorted(ours.items()):
                body = bodies.get(function, "")
                assert text in body, (
                    f"{name}: the comment at {address} is not in the text of "
                    f"{function}: {body[:200]!r}")
            row["rendered"] = sorted(ours.values())[0]
        return row, absent, extra

    measured, missing, invented = [], [], []
    rows = [entry for entry in sorted(wanted, key=lambda item: item["binary"])
            if (arguments.corpus_dir / entry["binary"]).is_file()]
    with concurrent.futures.ThreadPoolExecutor(max_workers=arguments.jobs) as pool:
        for row, absent, extra in pool.map(measure, rows):
            measured.append(row)
            missing.extend(absent)
            invented.extend(extra)
            print(f"{row['id']:24} sites {row['sites']} stock {row['stock_comments']}",
                  flush=True)

    assert measured, "no row was measured"
    assert not missing, f"exception ranges stock recorded and we did not: {missing}"
    assert not invented, f"exception ranges we recorded and stock did not: {invented}"
    with_sites = [row for row in measured if row["sites"]]
    assert with_sites, "no row recorded a single try range"
    metrics = {
        "exception.rows_measured": len(measured),
        "exception.rows_with_ranges": len(with_sites),
        "exception.ranges_recorded": sum(row["sites"] for row in measured),
        "exception.ranges_missing": 0,
        "exception.ranges_invented": 0,
    }
    summary = (f"{sum(row['sites'] for row in measured)} try ranges recorded from "
               f"`.gcc_except_table` across {len(with_sites)} of {len(measured)} ELF "
               f"rows, each identical to the comment stock recorded for the same "
               f"bytes and present in the text our worker prints; 0 missing, "
               f"0 invented")
    print(f"m4-024: PASS ({summary})")
    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps({
            "id": "m4-024",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "status": "pass",
            "passed": True,
            "summary": summary,
            "metrics": metrics,
            "measured": measured,
        }, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
