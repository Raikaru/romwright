#!/usr/bin/env python3
"""m6-001: the documented workflow is executed, not described.

`docs/getting-started.md` walks a user from a build to an imported binary,
its functions, its references, a rename and a decompilation. Every command in
that document is run here exactly as written, and every output line printed
beneath a command must appear in what the command actually prints. A document
that drifts from the tool fails this gate.

Contract for the document, so it stays runnable:

  * a fenced ```console block holds `$ ` command lines; the lines beneath a
    command are expected output, matched as ordered substrings;
  * `$PROJECT` in a command is the walkthrough's project directory, replaced
    here with a temporary one so the gate is hermetic;
  * a block preceded by `<!-- requires: sleigh -->` needs the pinned Ghidra
    install for SLEIGH language data, and is skipped -- with the skip
    recorded -- when that install is absent.

Usage:
    python3 tests/m6-001_documented_workflow.py [--report OUT.json]
"""
from __future__ import annotations

import argparse
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
DOC = ROOT / "docs" / "getting-started.md"
REQUIRES = re.compile(r"<!--\s*requires:\s*(\w+)\s*-->")
BLOCK = re.compile(r"```console\n(.*?)```", re.DOTALL)


def blocks(text: str) -> list[tuple[str | None, list[tuple[str, list[str]]]]]:
    """Every console block with its requirement and its command/output pairs."""
    parsed = []
    for match in BLOCK.finditer(text):
        preceding = text[:match.start()]
        marker = REQUIRES.search(preceding[preceding.rfind("```") + 3:]
                                 if "```" in preceding else preceding)
        # Only a marker in the paragraph immediately above counts.
        tail = preceding.rstrip().splitlines()[-3:] if preceding.strip() else []
        requirement = None
        for line in tail:
            found = REQUIRES.search(line)
            if found:
                requirement = found.group(1)
        del marker
        commands: list[tuple[str, list[str]]] = []
        for line in match.group(1).splitlines():
            if line.startswith("$ "):
                commands.append((line[2:].strip(), []))
            elif line.strip() and commands:
                commands[-1][1].append(line.rstrip())
            elif line.strip():
                raise AssertionError(f"output line before any command: {line!r}")
        parsed.append((requirement, commands))
    return parsed


def usage_text() -> str:
    result = subprocess.run([str(ROOT / "target/release/romwright-cli")],
                            cwd=ROOT, capture_output=True, text=True)
    text = result.stdout + result.stderr
    assert "usage:" in text, f"the CLI prints no usage: {text[:200]!r}"
    return text


def implemented_verbs() -> set[str]:
    """Verbs the CLI dispatches.

    Read from the dispatch arms in `crates/romwright-cli/src/main.rs`, which couples
    this check to our own source on purpose: the invariant is that the tool
    lists everything it does, and `xrefs`, `undo`, `open`, `comment`,
    `comments` and `types` were all missing from the usage text when this gate
    was written.
    """
    source = (ROOT / "crates/romwright-cli/src/main.rs").read_text(encoding="utf-8")
    return set(re.findall(r'^\s{8}"([a-z][a-z-]*)"(?:\s+if [^=]*)?\s*=>',
                          source, re.MULTILINE))


def sleigh_available() -> bool:
    install = Path(os.environ.get("ROMWRIGHT_GHIDRA",
                                  str(Path.home() / "ghidra_12.1.3_PUBLIC")))
    console = Path(os.environ.get("ROMWRIGHT_CONSOLE",
                                  str(ROOT / "native/build/decomp_native")))
    return install.is_dir() and console.is_file()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--timeout", type=int, default=900)
    arguments = parser.parse_args()

    assert DOC.is_file(), f"{DOC.relative_to(ROOT)} does not exist"
    text = DOC.read_text(encoding="utf-8")
    parsed = blocks(text)
    assert parsed, "the document contains no runnable console block"

    # The walkthrough must name exactly one project directory, so the reader
    # follows one thread and the gate can redirect it.
    projects = set(re.findall(r"\$PROJECT", text))
    assert projects, "no $PROJECT placeholder: the walkthrough must name its project"

    usage = usage_text()
    verbs = implemented_verbs()
    undocumented = sorted(verb for verb in verbs if f"romwright-cli {verb} " not in usage
                          and f"romwright-cli {verb}\n" not in usage)
    assert not undocumented, (
        f"the CLI dispatches these verbs and does not list them in its usage: "
        f"{undocumented}")
    documented_here = {shlex.split(command)[1] for _, commands in parsed
                       for command, _ in commands
                       if shlex.split(command)[0].endswith("romwright-cli")}
    unknown = sorted(documented_here - verbs)
    assert not unknown, (
        f"the walkthrough uses commands the CLI does not dispatch: {unknown}")

    executed, skipped, checked = 0, [], 0
    with tempfile.TemporaryDirectory(prefix="m6-001-") as temporary:
        project = Path(temporary) / "project"
        for requirement, commands in parsed:
            if requirement == "sleigh" and not sleigh_available():
                skipped.append("sleigh: no pinned Ghidra install or SLEIGH console")
                continue
            assert requirement in (None, "sleigh"), (
                f"unknown block requirement {requirement!r}")
            for command, expected in commands:
                argv = shlex.split(command.replace("$PROJECT", str(project)))
                result = subprocess.run(argv, cwd=ROOT, capture_output=True,
                                        text=True, timeout=arguments.timeout)
                assert result.returncode == 0, (
                    f"documented command failed: {command}\n"
                    f"{result.stderr.strip() or result.stdout.strip()}")
                executed += 1
                output = result.stdout
                position = 0
                for line in expected:
                    index = output.find(line.strip(), position)
                    assert index >= 0, (
                        f"documented output missing from `{command}`:\n"
                        f"  expected: {line.strip()!r}\n"
                        f"  actual:   {output.strip()[:400]!r}")
                    position = index + len(line.strip())
                    checked += 1

    assert executed >= 6, f"only {executed} documented commands ran"
    assert checked >= 10, f"only {checked} documented output lines were checked"

    summary = (f"{executed} documented commands run, {checked} documented output "
               f"lines checked, {len(verbs)} verbs all listed in usage, "
               f"{len(skipped)} block(s) skipped")
    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps({
            "id": "m6-001",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "status": "pass",
            "passed": True,
            "summary": summary,
            "metrics": {"commands": executed, "output_lines": checked,
                        "verbs": len(verbs), "skipped_blocks": len(skipped)},
            "skipped": skipped,
        }, indent=1) + "\n")
    print(f"m6-001: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
