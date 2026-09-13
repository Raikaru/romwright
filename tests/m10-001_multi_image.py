#!/usr/bin/env python3
"""m10-001: several images in one project, and one question across them.

A project has held more than one program since the Nintendo DS loader landed
(two CPU images), but every read takes a single `program` and nothing lists
what a project holds, so two questions had no answer: *what is in this
project*, and *which image maps this address*. The second one matters because
images overlap -- a stripped `tiny_pe32.exe` and `tiny_bin` both start at
`0x400000`, so an address alone does not say which program you are looking at.

The gate imports both images into one project and requires:

  * **separation**: every read for one program returns exactly what it returns
    from a project holding only that image -- no leakage, nothing lost;
  * **a project inventory**: `programs` lists both, with the language each was
    imported as and a revision that has moved;
  * **a cross-program answer**: `locate` names every program mapping an
    address, with the region that maps it and the function containing it when
    one does; an address inside only one image names only that one, and an
    address in neither names nothing;
  * **refusal**: an address that is not an address is `invalid_params`.

Usage:
    python3 tests/m10-001_multi_image.py [--report OUT.json]
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ELF = ROOT / "tests/fixtures-src/tiny_bin"
PE = ROOT / "tests/fixtures-src/tiny_pe32.exe"
# Reads that answer for one program and nothing else.
PER_PROGRAM = ("functions", "symbols", "strings", "memory_regions", "thunks",
               "return_behaviors", "prototypes")


class Api:
    def __init__(self, project: Path) -> None:
        self.process = subprocess.Popen(
            [str(ROOT / "target/release/romwright-api"), "--project", str(project)],
            cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, bufsize=1)
        self.identity = 0

    def call(self, method: str, **params):
        self.identity += 1
        self.process.stdin.write(json.dumps(
            {"api": 2, "id": self.identity, "method": method, "params": params}) + "\n")
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        assert line, f"the service closed on {method}"
        return json.loads(line)

    def result(self, method: str, **params):
        answer = self.call(method, **params)
        assert "result" in answer, f"{method} failed: {answer}"
        return answer["result"]

    def close(self) -> None:
        self.process.stdin.close()
        self.process.wait(timeout=30)


def imported(binary: Path, name: str, project: Path) -> None:
    result = subprocess.run(
        [str(ROOT / "target/release/romwright-cli"), "import", str(binary),
         "--name", name, "--project", str(project)],
        cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 0, (
        f"import of {binary.name} as {name} failed: {result.stderr.strip()}")


def stripped_pe(work: Path) -> Path:
    copy = work / PE.name
    shutil.copy2(PE, copy)
    subprocess.run(["llvm-strip", "--strip-all", str(copy)], check=True)
    return copy


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "romwright-cli",
                    "-p", "romwright-api"], cwd=ROOT, check=True)
    assert ELF.is_file() and PE.is_file(), "a committed fixture is missing"

    checks: dict[str, int] = {}
    with tempfile.TemporaryDirectory(prefix="m10-001-") as directory:
        work = Path(directory)
        pe = stripped_pe(work)

        shared = work / "shared"
        imported(ELF, "elf", shared)
        imported(pe, "win", shared)
        alone = {}
        for name, binary in (("elf", ELF), ("win", pe)):
            project = work / f"alone-{name}"
            imported(binary, name, project)
            alone[name] = project

        api = Api(shared)
        singles = {name: Api(project) for name, project in alone.items()}
        try:
            for name in ("elf", "win"):
                for method in PER_PROGRAM:
                    together = api.result(method, program=name)
                    apart = singles[name].result(method, program=name)
                    assert together == apart, (
                        f"{name}.{method}: sharing a project changed the answer "
                        f"({len(together)} rows against {len(apart)})")
                    checks[method] = checks.get(method, 0) + len(together)
                page = api.result("symbols_page", program=name, offset=0, limit=4096)
                apart_page = singles[name].result("symbols_page", program=name,
                                                  offset=0, limit=4096)
                assert page["rows"] == apart_page["rows"], (
                    f"{name}.symbols_page: sharing a project changed the window")
                assert page["total"] == apart_page["total"], (
                    f"{name}.symbols_page: total is {page['total']} shared against "
                    f"{apart_page['total']} alone")

            inventory = api.result("programs")
            held = {row["program"]: row for row in inventory}
            assert set(held) == {"elf", "win"}, f"programs lists {sorted(held)}"
            assert held["elf"]["language"].startswith("x86:LE:64"), held["elf"]
            assert held["win"]["language"].startswith("x86:LE:32"), held["win"]
            for row in inventory:
                assert row["functions"] > 0, f"{row['program']} holds no function"
                assert row["revision"] > 0, f"{row['program']} has no revision"

            # An address both images map, one only the ELF maps, and one neither.
            regions = {name: api.result("memory_regions", program=name)
                       for name in ("elf", "win")}

            def span(name: str) -> tuple[int, int]:
                starts = [row["start"]["offset"] for row in regions[name]]
                ends = [row["start"]["offset"] + row["size"] for row in regions[name]]
                return min(starts), max(ends)

            shared_address = None
            elf_start, elf_end = span("elf")
            win_start, win_end = span("win")
            for candidate in range(max(elf_start, win_start),
                                   min(elf_end, win_end), 4):
                if (any(row["start"]["offset"] <= candidate
                        < row["start"]["offset"] + row["size"]
                        for row in regions["elf"])
                        and any(row["start"]["offset"] <= candidate
                                < row["start"]["offset"] + row["size"]
                                for row in regions["win"])):
                    shared_address = candidate
                    break
            assert shared_address is not None, (
                "the two fixtures do not overlap, so the cross-program question "
                "has no interesting case")

            both = api.result("locate", address=f"{shared_address:08x}")
            assert {row["program"] for row in both} == {"elf", "win"}, (
                f"locate at {shared_address:08x} named "
                f"{[row['program'] for row in both]}")
            for row in both:
                region = row["region"]
                start = region["start"]["offset"]
                assert start <= shared_address < start + region["size"], (
                    f"{row['program']}: the named region does not hold the address")
                assert region["name"] and region["source"], (
                    f"{row['program']}: the region names neither itself nor its source")
                if row.get("function"):
                    functions = {entry["name"]: entry
                                 for entry in api.result("functions",
                                                         program=row["program"])}
                    held_function = functions.get(row["function"])
                    assert held_function is not None, (
                        f"{row['program']}: locate named a function the program "
                        f"does not hold: {row['function']}")
                    entry = held_function["entry"]["offset"]
                    assert entry <= shared_address < entry + held_function["size"], (
                        f"{row['program']}: {row['function']} does not contain the "
                        f"address")

            only_elf = None
            for candidate in range(elf_start, elf_end, 4):
                inside_elf = any(row["start"]["offset"] <= candidate
                                 < row["start"]["offset"] + row["size"]
                                 for row in regions["elf"])
                inside_win = any(row["start"]["offset"] <= candidate
                                 < row["start"]["offset"] + row["size"]
                                 for row in regions["win"])
                if inside_elf and not inside_win:
                    only_elf = candidate
                    break
            assert only_elf is not None, "no address belongs to one image alone"
            single = api.result("locate", address=f"{only_elf:08x}")
            assert [row["program"] for row in single] == ["elf"], (
                f"locate at {only_elf:08x} named "
                f"{[row['program'] for row in single]}")

            unmapped = max(elf_end, win_end) + 0x10_0000
            assert api.result("locate", address=f"{unmapped:08x}") == [], (
                f"locate claimed a program maps {unmapped:08x}")

            refused = api.call("locate", address="not-an-address")
            assert refused.get("error", {}).get("code") == "invalid_params", (
                f"a malformed address was answered: {refused}")

            # The terminal answers the same question.
            listing = subprocess.run(
                [str(ROOT / "target/release/romwright-cli"), "locate",
                 f"{shared_address:08x}", "--project", str(shared)],
                cwd=ROOT, capture_output=True, text=True)
            assert listing.returncode == 0, (
                f"cli locate failed: {listing.stderr.strip()}")
            for name in ("elf", "win"):
                assert name in listing.stdout, (
                    f"the terminal did not name {name}: {listing.stdout!r}")
        finally:
            api.close()
            for single_api in singles.values():
                single_api.close()

    metrics = {
        "images.programs": 2,
        "images.reads_compared": len(PER_PROGRAM) * 2 + 2,
        "images.rows_compared": sum(checks.values()),
        "images.overlapping_address": shared_address,
    }
    summary = (f"two images in one project: {metrics['images.reads_compared']} reads "
               f"per-program identical to single-image projects over "
               f"{metrics['images.rows_compared']} rows, both listed by `programs`, "
               f"and `locate` naming both at the overlapping address "
               f"{shared_address:08x}, one at an address only the ELF maps, none "
               f"outside either")

    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps({
            "id": "m10-001",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "status": "pass",
            "passed": True,
            "summary": summary,
            "metrics": metrics,
            "rows_per_read": dict(sorted(checks.items())),
        }, indent=1) + "\n")
    print(f"m10-001: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
