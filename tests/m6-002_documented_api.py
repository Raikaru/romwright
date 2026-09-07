#!/usr/bin/env python3
"""m6-002: the documented Core API is driven through the real process.

`docs/core-api.md` documents the stdio interface every consumer speaks -- the
Qt desktop, scripts, agents. Each documented exchange is sent to a real
`lre-api` process here, and the documented response must be a subset of what
comes back: every documented key must be present with the documented value.
Extra fields are allowed, missing or different ones fail.

Contract for the document:

  * a fenced ```json block holds alternating request and response lines; a
    request is a line containing `"method"`, and the line after it is the
    documented response;
  * `$PROGRAM` is the program name and `$BINARY` the fixture path, replaced
    here so the gate is hermetic;
  * a block preceded by `<!-- requires: sleigh -->` needs the pinned Ghidra
    install for SLEIGH language data and is skipped, with the skip recorded,
    when that install is absent.

Usage:
    python3 tests/m6-002_documented_api.py [--report OUT.json]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "docs" / "core-api.md"
FIXTURE = ROOT / "tests" / "fixtures-src" / "tiny_bin"
PROGRAM = "tiny"
REQUIRES = re.compile(r"<!--\s*requires:\s*(\w+)\s*-->")
BLOCK = re.compile(r"```json\n(.*?)```", re.DOTALL)


def exchanges(text: str) -> list[tuple[str | None, list[tuple[dict, dict]]]]:
    parsed = []
    for match in BLOCK.finditer(text):
        preceding = text[:match.start()].rstrip().splitlines()[-3:]
        requirement = None
        for line in preceding:
            found = REQUIRES.search(line)
            if found:
                requirement = found.group(1)
        pairs, pending = [], None
        for line in match.group(1).splitlines():
            if not line.strip():
                continue
            document = json.loads(line)
            if "method" in document:
                assert pending is None, (
                    f"request with no documented response: {pending}")
                pending = document
            else:
                assert pending is not None, f"response with no request: {line}"
                pairs.append((pending, document))
                pending = None
        assert pending is None, f"request with no documented response: {pending}"
        assert pairs, "empty json block"
        parsed.append((requirement, pairs))
    return parsed


def substitute(value, program: str, binary: str):
    if isinstance(value, str):
        return value.replace("$PROGRAM", program).replace("$BINARY", binary)
    if isinstance(value, dict):
        return {key: substitute(item, program, binary) for key, item in value.items()}
    if isinstance(value, list):
        return [substitute(item, program, binary) for item in value]
    return value


def contains(documented, actual, path: str) -> str | None:
    """Deep-subset check; returns the first path that does not hold."""
    if isinstance(documented, dict):
        if not isinstance(actual, dict):
            return f"{path}: expected an object, got {type(actual).__name__}"
        for key, value in documented.items():
            if key not in actual:
                return f"{path}.{key}: missing"
            failure = contains(value, actual[key], f"{path}.{key}")
            if failure:
                return failure
        return None
    if isinstance(documented, list):
        if not isinstance(actual, list):
            return f"{path}: expected a list, got {type(actual).__name__}"
        if len(actual) < len(documented):
            return f"{path}: {len(actual)} entries, documented {len(documented)}"
        for index, value in enumerate(documented):
            failure = contains(value, actual[index], f"{path}[{index}]")
            if failure:
                return failure
        return None
    if documented != actual:
        return f"{path}: documented {documented!r}, got {actual!r}"
    return None


def sleigh_available() -> bool:
    install = Path(os.environ.get("VENTRIS_GHIDRA",
                                  str(Path.home() / "ghidra_12.1.3_PUBLIC")))
    console = Path(os.environ.get("VENTRIS_CONSOLE",
                                  str(ROOT / "native/build/decomp_native")))
    return install.is_dir() and console.is_file()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--timeout", type=int, default=900)
    arguments = parser.parse_args()

    assert DOC.is_file(), f"{DOC.relative_to(ROOT)} does not exist"
    parsed = exchanges(DOC.read_text(encoding="utf-8"))
    assert parsed, "the document contains no documented exchange"

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-api",
                    "-p", "lre-cli"], cwd=ROOT, check=True)
    api = ROOT / "target/release/lre-api"
    cli = ROOT / "target/release/lre-cli"

    checked, skipped = 0, []
    with tempfile.TemporaryDirectory(prefix="m6-002-") as temporary:
        project = Path(temporary) / "project"
        imported = subprocess.run(
            [str(cli), "import", str(FIXTURE), "--name", PROGRAM,
             "--project", str(project)],
            cwd=ROOT, capture_output=True, text=True, timeout=arguments.timeout)
        assert imported.returncode == 0, f"import failed: {imported.stderr.strip()}"

        for requirement, pairs in parsed:
            if requirement == "sleigh" and not sleigh_available():
                skipped.append("sleigh: no pinned Ghidra install or SLEIGH console")
                continue
            assert requirement in (None, "sleigh"), (
                f"unknown block requirement {requirement!r}")
            requests = [substitute(request, PROGRAM, str(FIXTURE))
                        for request, _ in pairs]
            payload = "".join(json.dumps(request) + "\n" for request in requests)
            result = subprocess.run(
                [str(api), "--project", str(project)], cwd=ROOT, input=payload,
                capture_output=True, text=True, timeout=arguments.timeout)
            lines = [line for line in result.stdout.splitlines() if line.strip()]
            assert len(lines) == len(requests), (
                f"{len(requests)} requests produced {len(lines)} responses; "
                f"stderr: {result.stderr.strip()[:200]}")
            for (request, documented), line in zip(pairs, lines):
                actual = json.loads(line)
                expected = substitute(documented, PROGRAM, str(FIXTURE))
                failure = contains(expected, actual, "response")
                assert failure is None, (
                    f"documented response does not hold for "
                    f"{request.get('method')}: {failure}\n"
                    f"  actual: {json.dumps(actual)[:400]}")
                checked += 1

    assert checked >= 8, f"only {checked} documented exchanges were checked"
    summary = (f"{checked} documented API exchanges driven through lre-api, "
               f"{len(skipped)} block(s) skipped")
    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps({
            "id": "m6-002",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "status": "pass",
            "passed": True,
            "summary": summary,
            "metrics": {"exchanges": checked, "skipped_blocks": len(skipped)},
            "skipped": skipped,
        }, indent=1) + "\n")
    print(f"m6-002: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
