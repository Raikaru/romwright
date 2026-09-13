#!/usr/bin/env python3
"""m11-001: one measured game-first session on the approved target.

`GOAL.md`'s last open criterion is C3: measured game-first sessions on the
approved targets. The target is 007 Agent Under Fire (GameCube GQFE78), whose
main game module is `files/Bond.elf` -- ELF32 big-endian PowerPC, shipped with
its own symbol table. This gate runs the session an analyst would run, on that
image, with no JVM anywhere in it, and records the numbers:

  1. **Blind recovery.** The module is stripped into the work directory (the
     copy is asserted to carry no symbol table) and imported. Recall and
     precision are scored against the *unstripped* module's own `STT_FUNC`
     symbols, which never reach the importer.
  2. **Navigation.** `functions_page` unfiltered and filtered, `xrefs_page`
     into a recovered callee, and a `listing` window, each through a real
     `romwright-api` process bound to the session project.
  3. **Decompilation.** `decompile_doc` on recovered functions: tokens and a
     prototype for every one, JVM-free, with the language resolved from the
     program's stored language id.
  4. **Recovery passes.** `infer_prototypes` over the whole module under a
     budget -- the pass that a game module of this size is the first real test
     of -- and `recover_classes`, whose counts are recorded rather than
     asserted: a CodeWarrior image carries no Itanium type_info.
  5. **An analyst edit that survives.** A rename, then a second import of the
     same image, then the name read back.
  5a. **A bounded worker.** The same inference again in a second service whose
     worker cap is set low enough that a module this size grows past it, so the
     pass has to recycle its worker and carry on: the report records the
     recycles, and a pass that failed at the cap instead would fail here.
  6. **The live target.** `memory_live` against a GDB stub when
     `ROMWRIGHT_LIVE_ENDPOINT` names one, recorded as skipped with its reason
     when it does not, so the session never claims a running console it did
     not talk to. Dolphin's stub accepts one client per boot and stops
     listening when it disconnects, so the run needs a freshly booted target.

The image is private (a retail disc): with the target absent the gate records
`skipped` with the reason and passes, which is why it is not wired into CI.

Usage:
    python3 tests/m11-001_game_session.py [--target ELF] [--report OUT.json]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import sqlite3
import statistics
import struct
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "target/release/romwright-cli"
API = ROOT / "target/release/romwright-api"
TARGET = Path.home() / "Projects/agent-under-fire/orig/GQFE78/files/Bond.elf"
TARGET_SHA = "424880792a74f6220f6534f4c99e3b43d71abdfca50f78d070df901e9730a1e2"
PROGRAM = "bond"
# Measured on this machine before the thresholds were written: import 6.9 s at
# 65.6 MB peak, recall 0.9799, precision 0.9384, decompile 107 ms, pages under
# 15 ms. The thresholds leave room for a slower host, not for a regression in
# kind.
THRESHOLDS = {
    "session.import_wall_s": 60.0,
    "session.import_peak_kb": 300000,
    "session.functions_recovered": 8000,
    "session.fn_recall": 0.95,
    "session.fn_precision": 0.90,
    "session.page_ms": 500.0,
    "session.decompile_ms": 2000.0,
    "session.inference_analyzed": 1,
    "session.bounded_analyzed": 1,
    "session.worker_recycles": 1,
}


class Api:
    """One `romwright-api` process bound to the session project."""

    def __init__(self, project: Path, environment: dict[str, str] | None = None) -> None:
        self.process = subprocess.Popen(
            [str(API), "--project", str(project)], cwd=ROOT,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, bufsize=1,
            env=dict(os.environ, **(environment or {})))
        self.identity = 0

    def call(self, method: str, **params) -> tuple[dict, float]:
        self.identity += 1
        self.process.stdin.write(json.dumps(
            {"api": 2, "id": self.identity, "method": method, "params": params}) + "\n")
        self.process.stdin.flush()
        started = time.perf_counter()
        line = self.process.stdout.readline()
        elapsed = (time.perf_counter() - started) * 1000.0
        assert line, f"the service closed on {method}"
        return json.loads(line), elapsed

    def result(self, method: str, **params):
        answer, elapsed = self.call(method, **params)
        assert "result" in answer, f"{method} failed: {json.dumps(answer)[:400]}"
        return answer["result"], elapsed

    def close(self) -> None:
        self.process.stdin.close()
        self.process.wait(timeout=120)


def strip_symbols(source: Path, destination: Path) -> None:
    """A blind copy: recovery must not read the module's own symbols."""
    for tool in ("llvm-objcopy", "objcopy"):
        binary = shutil.which(tool)
        if not binary:
            continue
        result = subprocess.run([binary, "--strip-all", str(source), str(destination)],
                                capture_output=True, text=True, timeout=300)
        if result.returncode == 0:
            return
    raise FileNotFoundError("no llvm-objcopy or objcopy to strip the target with")


def function_symbols(image: bytes) -> dict[int, str]:
    """Every `STT_FUNC` symbol the unstripped module defines, by address."""
    assert image[:6] == b"\x7fELF\x01\x02", "the target must be ELF32 big endian"
    shoff = struct.unpack_from(">I", image, 32)[0]
    entsize, count = struct.unpack_from(">HH", image, 46)
    sections = [struct.unpack_from(">10I", image, shoff + index * entsize)
                for index in range(count)]
    found: dict[int, str] = {}
    for section in sections:
        if section[1] != 2 or not section[9]:      # SHT_SYMTAB
            continue
        strings = sections[section[6]]
        names = image[strings[4]:strings[4] + strings[5]]
        for offset in range(section[4], section[4] + section[5], section[9]):
            name_off, address, _size, info, _other, shndx = \
                struct.unpack_from(">IIIBBH", image, offset)
            if info & 15 == 2 and shndx and address:
                end = names.find(b"\0", name_off)
                found[address] = names[name_off:end].decode("utf-8", "replace")
    assert found, "the target carries no function symbols to score against"
    return found


def has_symbol_table(image: bytes) -> bool:
    shoff = struct.unpack_from(">I", image, 32)[0]
    entsize, count = struct.unpack_from(">HH", image, 46)
    return any(struct.unpack_from(">10I", image, shoff + index * entsize)[1] == 2
               for index in range(count))


def imported(binary: Path, project: Path) -> dict:
    """Import the stripped module, measuring wall time and peak RSS."""
    measured = subprocess.run(
        ["/usr/bin/time", "-f", "%e %M", str(CLI), "import", str(binary),
         "--name", PROGRAM, "--project", str(project)],
        capture_output=True, text=True, timeout=1800)
    assert measured.returncode == 0, (
        f"import failed: {(measured.stdout + measured.stderr)[-400:]}")
    wall, peak = measured.stderr.strip().splitlines()[-1].split()
    return {"wall_s": float(wall), "peak_kb": int(peak),
            "message": measured.stdout.strip()}


def recovered_functions(project: Path) -> list[tuple[int, str, int]]:
    with sqlite3.connect(project / "project.sqlite") as store:
        (identity,) = store.execute(
            "SELECT id FROM programs WHERE name = ?", (PROGRAM,)).fetchone()
        return [(int(entry, 16), name, size) for entry, name, size in store.execute(
            "SELECT entry, name, size FROM functions WHERE program_id = ?", (identity,))
            if not entry.startswith("{")]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, default=TARGET)
    parser.add_argument("--work", type=Path,
                        default=Path(os.environ.get("ROMWRIGHT_SESSION_WORK",
                                                    Path.home() / "romwright-cache/session")))
    parser.add_argument("--budget-ms", type=int, default=20000)
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()

    report = {
        "id": "m11-001",
        "milestone": "M11",
        "criterion": "GOAL.md C3: measured game-first sessions on the approved targets",
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "machine": {"os": platform.platform(), "cpu": platform.machine()},
        "target": {"path": str(arguments.target), "sha256": None},
        "thresholds": THRESHOLDS,
        "metrics": {},
        "steps": {},
        "status": "skipped",
        "passed": True,
    }
    if not arguments.target.is_file():
        report["reason"] = (f"the approved target is absent: {arguments.target} "
                            f"(007 Agent Under Fire, GameCube GQFE78, a private disc image)")
        print(f"m11-001: SKIP ({report['reason']})")
    else:
        subprocess.run(["cargo", "build", "-q", "--release", "-p", "romwright-cli",
                        "-p", "romwright-api", "-p", "romwright-worker"], cwd=ROOT, check=True)
        image = arguments.target.read_bytes()
        digest = hashlib.sha256(image).hexdigest()
        report["target"]["sha256"] = digest
        assert digest == TARGET_SHA, (
            f"the target's hash moved: {digest} (pinned {TARGET_SHA})")
        oracle = function_symbols(image)
        report["metrics"]["session.oracle_functions"] = len(oracle)

        work = arguments.work
        if work.exists():
            shutil.rmtree(work)
        work.mkdir(parents=True)
        stripped = work / "Bond.stripped.elf"
        strip_symbols(arguments.target, stripped)
        assert not has_symbol_table(stripped.read_bytes()), (
            "the stripped copy still carries a symbol table, so recovery is not blind")

        project = work / "project"
        cost = imported(stripped, project)
        report["steps"]["import"] = cost
        functions = recovered_functions(project)
        entries = {entry for entry, _, _ in functions}
        matched = entries & set(oracle)
        report["metrics"].update({
            "session.import_wall_s": cost["wall_s"],
            "session.import_peak_kb": cost["peak_kb"],
            "session.functions_recovered": len(functions),
            "session.functions_matched": len(matched),
            "session.fn_recall": len(matched) / len(oracle),
            "session.fn_precision": len(matched) / len(functions),
        })

        api = Api(project)
        try:
            programs, _ = api.result("programs")
            row = next(entry for entry in programs if entry["program"] == PROGRAM)
            report["steps"]["language"] = row["language"]
            report["metrics"]["session.language_is_powerpc_be32"] = float(
                row["language"] == "PowerPC:BE:32:default")

            _, unfiltered_ms = api.result(
                "functions_page", program=PROGRAM, offset=0, limit=50)
            filtered, filtered_ms = api.result(
                "functions_page", program=PROGRAM, offset=0, limit=50, filter="8001")
            assert filtered["rows"], "a filter that matches recovered names returned nothing"

            # A callee with callers: the session's xref step needs a real edge.
            sample = sorted(entry for entry, _, size in functions if 100 <= size <= 600)
            assert len(sample) >= 5, f"too few mid-sized functions to walk: {len(sample)}"
            callee = f"{sample[1]:08x}"
            xrefs, xrefs_ms = api.result(
                "xrefs_page", program=PROGRAM, address=callee, offset=0, limit=10)
            listing, listing_ms = api.result(
                "listing", program=PROGRAM, binary=str(stripped),
                start=f"{sample[0]:08x}", count=16)
            rows = listing["rows"] if isinstance(listing, dict) else listing
            assert rows, "the listing window came back empty"
            report["metrics"].update({
                "session.page_ms": max(unfiltered_ms, filtered_ms, xrefs_ms, listing_ms),
                "session.xrefs_rows": len(xrefs["rows"]),
                "session.listing_rows": len(rows),
            })

            decompiled = []
            for entry in sample[:5]:
                document, elapsed = api.result(
                    "decompile_doc", program=PROGRAM, binary=str(stripped),
                    address=f"{entry:08x}")
                assert document["tokens"], f"{entry:08x} decompiled to nothing"
                assert document["prototype"], f"{entry:08x} came back without a prototype"
                decompiled.append(elapsed)
            report["metrics"]["session.decompile_ms"] = statistics.median(decompiled)
            report["metrics"]["session.decompiled"] = len(decompiled)

            classes, classes_ms = api.result(
                "recover_classes", program=PROGRAM, binary=str(stripped))
            report["steps"]["recover_classes"] = dict(classes, ms=round(classes_ms, 1))

            inference, inference_ms = api.result(
                "infer_prototypes", program=PROGRAM, binary=str(stripped),
                budget_ms=arguments.budget_ms)
            report["steps"]["infer_prototypes"] = dict(
                inference, ms=round(inference_ms, 1))
            report["metrics"]["session.inference_analyzed"] = inference["analyzed"]

            held = api.result("memory", program=PROGRAM, binary=str(stripped),
                              address=f"{sample[0]:08x}", size=8)[0]
            report["metrics"]["session.memory_bytes"] = held["size"]

            endpoint = os.environ.get("ROMWRIGHT_LIVE_ENDPOINT")
            if endpoint:
                live, live_ms = api.result("memory_live", program=PROGRAM,
                                           endpoint=endpoint, address="80000000", size=16)
                assert live["source"] == "live" and live["size"] == 16, (
                    f"the live read did not answer from the target: {live}")
                # The console's own disc header, read out of the running
                # machine rather than out of the file.
                report["steps"]["memory_live"] = {
                    "endpoint": endpoint, "bytes": live["bytes"],
                    "disc_id": bytes(live["bytes"][:6]).decode("ascii", "replace"),
                    "ms": round(live_ms, 1)}
                report["metrics"]["session.live_bytes"] = live["size"]
            else:
                report["steps"]["memory_live"] = {
                    "status": "skipped",
                    "reason": "no ROMWRIGHT_LIVE_ENDPOINT: no GDB stub was serving the "
                              "running console, so no live read is claimed"}

            renamed = f"auf_session_{sample[2]:08x}"
            api.result("rename", program=PROGRAM, address=f"{sample[2]:08x}", name=renamed)
        finally:
            api.close()

        # The edit survives a second import of the same image (m10-003's rule,
        # here on the game target).
        again = imported(stripped, project)
        report["steps"]["reimport"] = again
        surviving = {entry: name for entry, name, _ in recovered_functions(project)}
        assert surviving.get(sample[2]) == renamed, (
            f"the rename did not survive the second import: "
            f"{surviving.get(sample[2])!r} != {renamed!r}")
        report["metrics"]["session.edit_survived_reimport"] = 1.0

        # The cap bounds a long session's memory rather than failing the
        # request that discovers the growth: with the cap set below what this
        # module's inference reaches, the pass recycles workers and completes.
        bounded = Api(project, {"ROMWRIGHT_WORKER_MEMORY_CAP": str(120 * 1024 * 1024)})
        try:
            recycled, recycled_ms = bounded.result(
                "infer_prototypes", program=PROGRAM, binary=str(stripped),
                budget_ms=arguments.budget_ms)
        finally:
            bounded.close()
        report["steps"]["infer_prototypes_bounded"] = dict(
            recycled, ms=round(recycled_ms, 1), cap_bytes=120 * 1024 * 1024)
        assert recycled["analyzed"] >= 1, (
            f"a bounded worker analysed nothing: {recycled}")
        assert recycled["worker_recycles"] >= 1, (
            f"the bounded cap never recycled a worker, so the path a large "
            f"module needs is untested here: {recycled}")
        report["metrics"]["session.worker_recycles"] = recycled["worker_recycles"]
        report["metrics"]["session.bounded_analyzed"] = recycled["analyzed"]

        failures = []
        for key, limit in THRESHOLDS.items():
            value = report["metrics"].get(key)
            assert value is not None, f"{key} was never measured"
            worse = value > limit if key.endswith(("_s", "_kb", "_ms")) else value < limit
            if worse:
                failures.append({"metric": key, "value": value, "threshold": limit})
        assert not failures, f"session metrics outside their thresholds: {failures}"
        report["status"] = "pass"
        summary = (
            f"a JVM-free session on the approved target: {len(functions)} functions "
            f"recovered from the stripped module in {cost['wall_s']:.1f} s at "
            f"{cost['peak_kb'] / 1000:.0f} MB, recall "
            f"{report['metrics']['session.fn_recall']:.4f} and precision "
            f"{report['metrics']['session.fn_precision']:.4f} against the module's own "
            f"{len(oracle)} function symbols, {len(decompiled)} functions decompiled "
            f"(median {report['metrics']['session.decompile_ms']:.0f} ms), "
            f"{inference['analyzed']} analysed by prototype inference, and one rename "
            f"read back after a second import")
        report["summary"] = summary
        print(f"m11-001: PASS ({summary})")

    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps(report, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
