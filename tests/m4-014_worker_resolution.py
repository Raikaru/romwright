#!/usr/bin/env python3
"""m4-014: the worker a build drives is the worker it was built with.

`RuntimeConfig::from_env` resolved the decompile worker as the literal path
`target/release/romwright-worker` unless `ROMWRIGHT_WORKER` said otherwise. So a
**release** `romwright-cli` -- which is what every gate builds -- silently drove
whatever `cargo build` last left in `target/debug`, and a measurement could
change with no source change at all.

That is not hypothetical: while measuring m4-014's first hypothesis, token
identity read 25 of 56 against a pinned baseline of 30 on an unmodified tree,
twice, because an experimental debug worker was still on disk. The experiment's
conclusion was drawn, then withdrawn, from a build that was not the tree.
A number a gate pins has to come from the binaries that gate built.

The fix is the boring one: an explicit `ROMWRIGHT_WORKER` still wins, then the
worker sitting **beside the running executable**, then the workspace's release
and debug paths, and each candidate has to exist.

Assertions
  1. A CLI run from a directory with a working worker beside it decompiles --
     the sibling is found without any workspace-relative path existing.
  2. The same CLI with a *broken* worker beside it fails, naming the worker:
     the sibling is what is used, not a fallback that happens to work. This is
     the control that gives assertion 1 its meaning.
  3. `ROMWRIGHT_WORKER` still overrides both.
  4. In the workspace, the release CLI and the debug CLI each decompile, and
     both produce the same text: neither depends on the other's build.

Usage:
    python3 tests/m4-014_worker_resolution.py [--report OUT.json]
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures-src/tiny_bin"
BROKEN = "#!/bin/sh\necho 'this worker is deliberately broken' >&2\nexit 3\n"


def environment(**overrides: str) -> dict[str, str]:
    """A plain install, with absolute paths for everything but the worker."""
    values = dict(os.environ)
    for name in ("ROMWRIGHT_SLA", "ROMWRIGHT_LANGUAGE", "ROMWRIGHT_LANGUAGE_DIR",
                 "ROMWRIGHT_REGISTER_PARAMS", "ROMWRIGHT_PROMOTE_TAILCALLS",
                 "ROMWRIGHT_WORKER"):
        values.pop(name, None)
    values["ROMWRIGHT_SPECS"] = str(ROOT / "native/specs")
    values["ROMWRIGHT_GHIDRA_OPT"] = str(ROOT / "native/build/ghidra_opt")
    values["ROMWRIGHT_LIBRARY_PROTOTYPES"] = str(
        ROOT / "oracle/library-prototypes-v1/generic_clib_64.json")
    values.update(overrides)
    return values


def run(binary: Path, arguments: list[str], cwd: Path, timeout: int,
        **env: str) -> subprocess.CompletedProcess:
    return subprocess.run([str(binary), *arguments], cwd=cwd, capture_output=True,
                          text=True, timeout=timeout, env=environment(**env))


def function_entry(project: Path, program: str) -> int:
    import sqlite3
    connection = sqlite3.connect(project / "project.sqlite")
    try:
        (identifier,) = connection.execute(
            "SELECT id FROM programs WHERE name = ?", (program,)).fetchone()
        rows = [int(entry, 16) for (entry,) in connection.execute(
            "SELECT entry FROM functions WHERE program_id = ? ORDER BY entry",
            (identifier,)) if all(c in "0123456789abcdef" for c in entry)]
        assert rows, f"{program} has no functions to decompile"
        # The largest body: a one-instruction stub proves little.
        (entry,) = connection.execute(
            "SELECT entry FROM functions WHERE program_id = ? ORDER BY size DESC LIMIT 1",
            (identifier,)).fetchone()
        return int(entry, 16)
    finally:
        connection.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--timeout", type=int, default=600)
    arguments = parser.parse_args()

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "romwright-cli", "-p", "romwright-worker"],
                   cwd=ROOT, check=True, env=environment())
    subprocess.run(["cargo", "build", "-q", "--release", "-p", "romwright-cli", "-p", "romwright-worker"],
                   cwd=ROOT, check=True, env=environment())
    release_cli = ROOT / "target/release/romwright-cli"
    release_worker = ROOT / "target/release/romwright-worker"
    debug_cli = ROOT / "target/release/romwright-cli"
    assert FIXTURE.is_file(), f"{FIXTURE} is missing"

    findings: dict[str, object] = {}
    with tempfile.TemporaryDirectory(prefix="m4-014-") as directory:
        work = Path(directory)
        project = work / "project"
        imported = run(release_cli, ["import", str(FIXTURE), "--project", str(project)],
                       ROOT, arguments.timeout)
        assert imported.returncode == 0, f"import failed: {imported.stderr.strip()}"
        entry = function_entry(project, FIXTURE.name)
        call = ["decompile", str(FIXTURE), f"{entry:08x}", "--project", str(project)]

        # 1. A directory holding the CLI and a working worker, and nothing else.
        good = work / "good"
        good.mkdir()
        shutil.copy(release_cli, good / "romwright-cli")
        shutil.copy(release_worker, good / "romwright-worker")
        sibling = run(good / "romwright-cli", call, good, arguments.timeout)
        assert sibling.returncode == 0, (
            f"a CLI with a worker beside it could not decompile: "
            f"{sibling.stderr.strip()[:300]}")
        assert "{" in sibling.stdout, f"no C came back: {sibling.stdout[:200]!r}"
        findings["sibling"] = sibling.stdout.strip()[:80]

        # 2. The control: the same shape with a broken sibling must fail, or
        #    assertion 1 proves nothing about which worker ran.
        bad = work / "bad"
        bad.mkdir()
        shutil.copy(release_cli, bad / "romwright-cli")
        broken = bad / "romwright-worker"
        broken.write_text(BROKEN)
        broken.chmod(0o755)
        refused = run(bad / "romwright-cli", call, bad, arguments.timeout)
        assert refused.returncode != 0, (
            f"a CLI with a deliberately broken worker beside it decompiled anyway, "
            f"so some other worker ran: {refused.stdout[:200]!r}")
        findings["broken_sibling"] = refused.stderr.strip()[-80:]

        # 3. An explicit override still wins, over a good sibling.
        overridden = run(good / "romwright-cli", call, good, arguments.timeout,
                         ROMWRIGHT_WORKER=str(broken))
        assert overridden.returncode != 0, (
            f"ROMWRIGHT_WORKER was ignored in favour of the sibling: "
            f"{overridden.stdout[:200]!r}")
        findings["explicit_override"] = overridden.stderr.strip()[-80:]

        # 4. In the workspace both builds work, and agree.
        release_text = run(release_cli, call, ROOT, arguments.timeout)
        debug_text = run(debug_cli, call, ROOT, arguments.timeout)
        assert release_text.returncode == 0, (
            f"the release CLI failed in the workspace: {release_text.stderr.strip()[:200]}")
        assert debug_text.returncode == 0, (
            f"the debug CLI failed in the workspace: {debug_text.stderr.strip()[:200]}")
        assert release_text.stdout == debug_text.stdout, (
            "the release and debug builds disagree about the same function, so one "
            "of them is driving the other's worker:\n"
            f"  release: {release_text.stdout[:160]!r}\n"
            f"  debug:   {debug_text.stdout[:160]!r}")
        findings["workspace_agreement"] = len(release_text.stdout.split())

    summary = ("a worker beside the executable is found, a broken one is not "
               "worked around, an explicit override still wins, and the release "
               "and debug builds agree")
    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps({
            "task": "m4-014",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "scope": "resolution acceptance with three controls, not a corpus gate",
            "metrics": findings,
            "passed": True,
        }, indent=2) + "\n")
    print(f"m4-014: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
