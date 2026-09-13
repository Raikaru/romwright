#!/usr/bin/env python3
"""m6-005: the documented script runs, and the documented client exists.

`docs/scripting.md` shows `examples/facts_report.py` driving a project through
`python/romwright_sdk.py`. This gate runs the documented command exactly as
written, matches every output line under it, and checks the page against the
client itself: every helper the page names must exist on `Client`, and every
`Client` helper must be named by the page. A client that grows a method the
page never mentions, or a page that promises one the client lost, fails here.

The script is run twice -- with the SLEIGH console and with every `ROMWRIGHT_*`
variable stripped -- because the page claims it works either way.

Usage:
    python3 tests/m6-005_scripting.py [--report OUT.json]
"""
from __future__ import annotations

import argparse
import importlib.util
import inspect
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "docs" / "scripting.md"
SDK = ROOT / "python" / "romwright_sdk.py"
BLOCK = re.compile(r"```console\n(.*?)```", re.DOTALL)


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    # `dataclasses` resolves annotations through `sys.modules[cls.__module__]`,
    # so a module executed outside it cannot define one.
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def documented_commands(text: str) -> list[tuple[str, list[str]]]:
    pairs = []
    for match in BLOCK.finditer(text):
        for line in match.group(1).splitlines():
            if line.startswith("$ "):
                pairs.append((line[2:].strip(), []))
            elif line.strip():
                assert pairs, f"output line before any command: {line!r}"
                pairs[-1][1].append(line.rstrip())
    return pairs


def check_helpers(text: str) -> list[str]:
    """The page and the client name the same helpers."""
    client = load("romwright_sdk", SDK).Client
    helpers = sorted(
        name for name, value in inspect.getmembers(client, inspect.isfunction)
        if not name.startswith("_")
        and name not in {"request", "close", "stdio", "http"})
    documented = {name for name in re.findall(r"`(\w+)`", text)}
    documented |= {name for name in re.findall(r"`client\.(\w+)", text)}
    missing = [name for name in helpers if name not in documented]
    assert not missing, (
        f"docs/scripting.md does not mention these Client helpers: {missing}")
    promised = {name for name in re.findall(r"`client\.(\w+)\(", text)}
    absent = sorted(name for name in promised
                    if not hasattr(client, name))
    assert not absent, f"the page promises helpers the client lacks: {absent}"
    return helpers


def run_documented(commands: list[tuple[str, list[str]]], project: Path,
                   environment: dict[str, str], timeout: int) -> int:
    checked = 0
    for command, expected in commands:
        argv = shlex.split(command.replace("$PROJECT", str(project)))
        result = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True,
                                timeout=timeout, env=environment)
        assert result.returncode == 0, (
            f"documented command failed: {command}\n"
            f"{(result.stderr.strip() or result.stdout.strip())[-600:]}")
        position = 0
        for line in expected:
            index = result.stdout.find(line.strip(), position)
            assert index >= 0, (
                f"documented output missing from `{command}`:\n"
                f"  expected: {line.strip()!r}\n"
                f"  actual:   {result.stdout.strip()[:400]!r}")
            position = index + len(line.strip())
            checked += 1
    return checked


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--timeout", type=int, default=900)
    arguments = parser.parse_args()

    assert DOC.is_file(), f"{DOC.relative_to(ROOT)} does not exist"
    assert SDK.is_file(), f"{SDK.relative_to(ROOT)} does not exist"
    text = DOC.read_text(encoding="utf-8")
    commands = documented_commands(text)
    assert commands, "the page contains no runnable command"
    helpers = check_helpers(text)

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "romwright-api",
                    "-p", "romwright-cli"], cwd=ROOT, check=True)

    checked = 0
    with tempfile.TemporaryDirectory(prefix="m6-005-") as temporary:
        # With whatever this environment offers.
        checked += run_documented(commands, Path(temporary) / "configured",
                                  dict(os.environ), arguments.timeout)
        # And with nothing: the page claims the script runs either way.
        bare = {key: value for key, value in os.environ.items()
                if not key.startswith("ROMWRIGHT_")}
        bare["ROMWRIGHT_GHIDRA"] = "/nonexistent"
        bare["ROMWRIGHT_CONSOLE"] = "/nonexistent"
        checked += run_documented(commands, Path(temporary) / "bare", bare,
                                  arguments.timeout)

    summary = (f"{len(commands)} documented commands run in two environments, "
               f"{checked} output lines checked, {len(helpers)} client helpers "
               f"all documented")
    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps({
            "id": "m6-005",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "status": "pass",
            "passed": True,
            "summary": summary,
            "metrics": {"commands": len(commands), "output_lines": checked,
                        "client_helpers": len(helpers)},
        }, indent=1) + "\n")
    print(f"m6-005: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
