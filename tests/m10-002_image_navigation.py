#!/usr/bin/env python3
"""m10-002: moving between the images a project holds.

`m10-001` answers *what is in this project* and *which image maps this
address*. Nothing used those answers: the desktop opened the one program named
on its command line with no way to switch, and the terminal could name the
programs mapping an address but not look at what is there.

Both surfaces now move:

  * `lre-cli locate <hex> --follow` prints, under each program that maps the
    address, the facts that program holds there -- the containing function,
    the symbols at that address, and the references in each direction. Every
    number is compared with the API's answer for that program, so a `--follow`
    that prints the first program's facts under the second one fails;
  * the desktop has a program selector filled from `programs`. Switching
    reloads the docks, and the UI gate records how many programs it listed and
    how many functions the list held **after** switching. On a project holding
    `tiny` (12 functions) and `win` (112), a selector that does not switch
    cannot report the second program's count.

Usage:
    python3 tests/m10-002_image_navigation.py [--report OUT.json]
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "benchmarks"))
import ui_gate  # noqa: E402

ELF = ROOT / "tests/fixtures-src/tiny_bin"
PE = ROOT / "tests/fixtures-src/tiny_pe32.exe"
FOLLOW = re.compile(
    r"^\s*follow (\S+) function=(\S+) symbols=(\d+) xrefs_to=(\d+) xrefs_from=(\d+)")


class Api:
    def __init__(self, project: Path) -> None:
        self.process = subprocess.Popen(
            [str(ROOT / "target/release/lre-api"), "--project", str(project)],
            cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, bufsize=1)
        self.identity = 0

    def result(self, method: str, **params):
        self.identity += 1
        self.process.stdin.write(json.dumps(
            {"api": 2, "id": self.identity, "method": method, "params": params}) + "\n")
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        assert line, f"the service closed on {method}"
        answer = json.loads(line)
        assert "result" in answer, f"{method} failed: {answer}"
        return answer["result"]

    def close(self) -> None:
        self.process.stdin.close()
        self.process.wait(timeout=30)


def cli(*arguments: str) -> subprocess.CompletedProcess:
    return subprocess.run([str(ROOT / "target/release/lre-cli"), *arguments],
                          cwd=ROOT, capture_output=True, text=True)


def imported(binary: Path, name: str, project: Path) -> None:
    result = cli("import", str(binary), "--name", name, "--project", str(project))
    assert result.returncode == 0, (
        f"import of {binary.name} as {name} failed: {result.stderr.strip()}")


def expected_facts(api: Api, program: str, address: int) -> tuple[str, int, int, int]:
    functions = api.result("functions", program=program)
    holder = next((row["name"] for row in functions
                   if row["entry"]["offset"] <= address
                   < row["entry"]["offset"] + row["size"]), "-")
    symbols = [row for row in api.result("symbols_page", program=program,
                                         offset=0, limit=4096)["rows"]
               if row["address"]["offset"] == address]
    to_page = api.result("xrefs_page", program=program, address=f"{address:08x}",
                         incoming=True, offset=0, limit=4096)
    from_page = api.result("xrefs_page", program=program, address=f"{address:08x}",
                           incoming=False, offset=0, limit=4096)
    return holder, len(symbols), to_page["total"], from_page["total"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-cli",
                    "-p", "lre-api"], cwd=ROOT, check=True)

    followed, desktop = {}, {}
    with tempfile.TemporaryDirectory(prefix="m10-002-") as directory:
        work = Path(directory)
        pe = work / PE.name
        shutil.copy2(PE, pe)
        subprocess.run(["llvm-strip", "--strip-all", str(pe)], check=True)
        project = work / "project"
        imported(ELF, "tiny", project)
        imported(pe, "win", project)

        api = Api(project)
        try:
            programs = {row["program"]: row for row in api.result("programs")}
            assert set(programs) == {"tiny", "win"}, f"programs lists {sorted(programs)}"

            address = 0x401000
            mapped = [row["program"] for row in
                      api.result("locate", address=f"{address:08x}")]
            assert set(mapped) == {"tiny", "win"}, (
                f"the fixtures no longer overlap at {address:08x}: {mapped}")

            result = cli("locate", f"{address:08x}", "--follow",
                         "--project", str(project))
            assert result.returncode == 0, f"locate --follow failed: {result.stderr.strip()}"
            printed = {match.group(1): match.groups()[1:]
                       for match in (FOLLOW.match(line)
                                     for line in result.stdout.splitlines())
                       if match}
            assert set(printed) == set(mapped), (
                f"--follow printed facts for {sorted(printed)} where the address is "
                f"mapped by {sorted(mapped)}")
            for program in mapped:
                holder, symbols, to_count, from_count = expected_facts(
                    api, program, address)
                shown = printed[program]
                assert shown == (holder, str(symbols), str(to_count), str(from_count)), (
                    f"{program}: --follow printed {shown} where the service says "
                    f"{(holder, symbols, to_count, from_count)}")
                followed[program] = {"function": holder, "symbols": symbols,
                                     "xrefs_to": to_count, "xrefs_from": from_count}
            # The two images must disagree somewhere, or the comparison above
            # would pass on a --follow that ignores which program it is in.
            assert followed["tiny"] != followed["win"], (
                "both images hold the same facts at this address, so the check "
                "cannot tell them apart")

            without = cli("locate", f"{address:08x}", "--project", str(project))
            assert not FOLLOW.search(without.stdout), (
                "locate printed followed facts without --follow")

            try:
                app = ui_gate.default_app(ROOT).resolve()
            except ui_gate.GateError as failure:
                desktop = {"skipped": str(failure)}
                app = None
            if app is not None:
                metrics = ui_gate.run_app(app, project, ELF, "tiny",
                                          f"{0x400466:08x}", timeout=240.0)
                assert metrics["ui.programs"] == 2, (
                    f"the window listed {metrics['ui.programs']} programs where the "
                    f"project holds 2")
                switched = int(metrics["ui.programs_switch_functions"])
                assert switched == programs["win"]["functions"], (
                    f"after switching the list held {switched} functions where "
                    f"`win` has {programs['win']['functions']}")
                assert switched != programs["tiny"]["functions"], (
                    "the two programs have the same function count, so switching "
                    "cannot be observed")
                desktop = {"programs": metrics["ui.programs"],
                           "switch_functions": switched,
                           "first_program_functions": programs["tiny"]["functions"]}
        finally:
            api.close()

    metrics = {
        "images.followed_programs": len(followed),
        "images.follow_facts_compared": len(followed) * 4,
        "images.ui_programs": desktop.get("programs", -1),
        "images.ui_switch_functions": desktop.get("switch_functions", -1),
    }
    summary = (f"`locate --follow` printed the facts each of {len(followed)} images "
               f"holds at 00401000 and every number matched the service; ")
    if "skipped" in desktop:
        summary += f"desktop run skipped ({desktop['skipped']})"
    else:
        summary += (f"the window listed {desktop['programs']} programs and held "
                    f"{desktop['switch_functions']} functions after switching, "
                    f"against {desktop['first_program_functions']} before")

    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps({
            "id": "m10-002",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "status": "pass",
            "passed": True,
            "summary": summary,
            "metrics": metrics,
            "followed": followed,
            "desktop": desktop,
        }, indent=1) + "\n")
    print(f"m10-002: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
