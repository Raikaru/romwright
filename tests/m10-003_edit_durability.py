#!/usr/bin/env python3
"""m10-003: a second import must not disturb the first image's work.

`m10-001` reads a multi-image project and `m10-002` moves through it. Neither
touches the case a user actually hits: analysing one image, then importing
another into the same project. An import replaces a program's facts, and the
question is whether it replaces only *that* program's -- and whether the
journal an analyst built survives it.

The gate makes the edits, imports the second image, and requires:

  * **the edits survive**: the renamed function keeps its name and the comment
    stays, byte for byte;
  * **the untouched program stays untouched**: every read for the first image
    answers exactly as it did before the second import, and its store revision
    does not move;
  * **undo stays per program**: `undo` on the second image, which has no
    journal, reverses nothing and says so; `undo` on the first reverses its
    own last edit, and again the one before it;
  * **the new program is complete**: importing beside an existing program
    yields the same facts as importing alone.

Usage:
    python3 tests/m10-003_edit_durability.py [--report OUT.json]
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
RENAMED = "analyst_named_this"
COMMENT = "an analyst wrote this before the second import"
# Reads that must be identical before and after the second import.
READS = ("functions", "symbols", "strings", "memory_regions", "comments",
         "thunks", "prototypes", "return_behaviors")


class Api:
    def __init__(self, project: Path) -> None:
        self.process = subprocess.Popen(
            [str(ROOT / "target/release/lre-api"), "--project", str(project)],
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


def cli(*arguments: str) -> subprocess.CompletedProcess:
    return subprocess.run([str(ROOT / "target/release/lre-cli"), *arguments],
                          cwd=ROOT, capture_output=True, text=True)


def imported(binary: Path, name: str, project: Path) -> None:
    result = cli("import", str(binary), "--name", name, "--project", str(project))
    assert result.returncode == 0, (
        f"import of {binary.name} as {name} failed: {result.stderr.strip()}")


def snapshot(api: Api, program: str) -> dict:
    return {method: api.result(method, program=program) for method in READS}


def revision(api: Api, program: str) -> int:
    return next(row["revision"] for row in api.result("programs")
                if row["program"] == program)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-cli",
                    "-p", "lre-api"], cwd=ROOT, check=True)

    findings: dict[str, object] = {}
    with tempfile.TemporaryDirectory(prefix="m10-003-") as directory:
        work = Path(directory)
        pe = work / PE.name
        shutil.copy2(PE, pe)
        subprocess.run(["llvm-strip", "--strip-all", str(pe)], check=True)

        project = work / "project"
        imported(ELF, "tiny", project)

        api = Api(project)
        try:
            functions = api.result("functions", program="tiny")
            target = next(row for row in functions if row["name"] == "add")
            address = f"{target['entry']['offset']:08x}"

            renamed = cli("rename", "tiny", address, RENAMED,
                          "--project", str(project))
            assert renamed.returncode == 0, f"rename failed: {renamed.stderr.strip()}"
            commented = cli("comment", "tiny", address, COMMENT,
                            "--project", str(project))
            assert commented.returncode == 0, (
                f"comment failed: {commented.stderr.strip()}")

            before = snapshot(api, "tiny")
            before_revision = revision(api, "tiny")
            assert any(row["name"] == RENAMED for row in before["functions"]), (
                "the rename did not reach the store")
            assert any(row["text"] == COMMENT for row in before["comments"]), (
                "the comment did not reach the store")

            # A second image lands in the same project.
            imported(pe, "win", project)
            after = snapshot(api, "tiny")
            after_revision = revision(api, "tiny")

            differing = sorted(method for method in READS
                               if before[method] != after[method])
            assert not differing, (
                f"importing a second image changed the first image's "
                f"{differing}")
            assert after_revision == before_revision, (
                f"the first image's revision moved from {before_revision} to "
                f"{after_revision} because another image was imported")
            findings["revision"] = after_revision

            alone_project = work / "alone"
            imported(pe, "win", alone_project)
            alone = Api(alone_project)
            try:
                for method in READS:
                    beside = api.result(method, program="win")
                    solo = alone.result(method, program="win")
                    assert beside == solo, (
                        f"win.{method}: importing beside another program changed "
                        f"the answer ({len(beside)} rows against {len(solo)})")
            finally:
                alone.close()

            # Undo belongs to a program, not to the project.
            empty = cli("undo", "win", "--project", str(project))
            assert "nothing" in (empty.stdout + empty.stderr).lower(), (
                f"undo on an unedited image said {empty.stdout.strip()!r} "
                f"{empty.stderr.strip()!r}")
            assert any(row["name"] == RENAMED
                       for row in api.result("functions", program="tiny")), (
                "undo on the second image reversed the first image's rename")

            first_undo = cli("undo", "tiny", "--project", str(project))
            assert first_undo.returncode == 0, (
                f"undo failed: {first_undo.stderr.strip()}")
            findings["first_undo"] = first_undo.stdout.strip()
            assert not any(row["text"] == COMMENT
                           for row in api.result("comments", program="tiny")), (
                f"the comment survived its own undo: {first_undo.stdout.strip()!r}")
            assert any(row["name"] == RENAMED
                       for row in api.result("functions", program="tiny")), (
                "undoing the comment also reversed the rename")

            second_undo = cli("undo", "tiny", "--project", str(project))
            assert second_undo.returncode == 0, (
                f"second undo failed: {second_undo.stderr.strip()}")
            findings["second_undo"] = second_undo.stdout.strip()
            assert any(row["name"] == "add"
                       for row in api.result("functions", program="tiny")), (
                f"the rename survived its own undo: {second_undo.stdout.strip()!r}")
            findings["win_functions"] = len(api.result("functions", program="win"))
            assert findings["win_functions"] > 0, "the second image lost its functions"
        finally:
            api.close()

    metrics = {
        "edits.reads_compared": len(READS) * 2,
        "edits.revision_after_second_import": findings["revision"],
        "edits.win_functions": findings["win_functions"],
    }
    summary = (f"analyst edits survived a second import: {len(READS)} reads "
               f"identical for the first image and {len(READS)} identical for the "
               f"second whether imported beside or alone, its revision unchanged at "
               f"{findings['revision']}, undo on the unedited image reversing "
               f"nothing, and two undos reversing the comment then the rename")

    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps({
            "id": "m10-003",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "status": "pass",
            "passed": True,
            "summary": summary,
            "metrics": metrics,
            "undo": {"first": findings["first_undo"],
                     "second": findings["second_undo"]},
        }, indent=1) + "\n")
    print(f"m10-003: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
