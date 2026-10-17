#!/usr/bin/env python3
"""m6-003: the packaged desktop is built, installed and launched.

`tests/package_install_smoke.sh` already builds the release archive, extracts
it and runs the offscreen gate -- but it passes `ROMWRIGHT_UI_INSTALL_OK=1` to
the app, and the app reports that variable back as `ui.install.ok`. The gate
asserts a value the harness supplied, so nothing about the installation is
measured.

This gate measures it instead. It builds the archive with the command
`docs/desktop.md` documents (`packaging/package_desktop.py`), extracts it to a
clean prefix, and launches the *extracted* `romwright-desktop` headless with
**every `ROMWRIGHT_*` variable removed**, so the run has no configuration to
lean on. The app renders offscreen through wgpu -- a GPU when there is one,
otherwise the platform's software adapter -- and reports two facts it can see
for itself:

  * `ui.install.prefix_ok` -- the executable is running from an installed
    layout, not from a cargo build tree;
  * `ui.install.store_only_ok` -- it completed the store-facing workflow
    (import, function list, filter) with no `ROMWRIGHT_*` variable set.

`ui.install.ok` is left alone: it is a metric in a committed gate, and
AGENTS.md II.1 reserves metric-definition changes. STATUS.md records the
proposal to retire it.

The report names the platform and the wgpu adapter it ran on, so a reader can
see which platforms the evidence actually covers rather than assuming three.

Usage:
    python3 tests/m6-003_desktop_package.py [--report OUT.json]
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKAGER = ROOT / "packaging" / "package_desktop.py"
DOC = ROOT / "docs" / "desktop.md"
FIXTURE = ROOT / "tests" / "fixtures-src" / "tiny_bin"
EXECUTABLE = "romwright-desktop.exe" if os.name == "nt" else "romwright-desktop"
# The same list thresholds the M0 UI gate uses; unchanged.
THRESHOLDS = {"ui.list.load_ms": 500.0, "ui.list.filter_ms": 100.0}
MEASURED = ("ui.install.prefix_ok", "ui.install.store_only_ok")
ADAPTER_PREFIX = "ui gate: rendering offscreen on "


def documented_commands() -> list[str]:
    """The build commands `docs/desktop.md` tells a reader to run."""
    assert DOC.is_file(), f"{DOC.relative_to(ROOT)} does not exist"
    commands = []
    for line in DOC.read_text(encoding="utf-8").splitlines():
        if line.startswith("$ "):
            commands.append(line[2:].strip())
    return commands


def build_package(output: Path, timeout: int) -> Path:
    # The page and the gate must run the same packager; a page that drifts
    # from the build it documents is the failure this checks for.
    documented = documented_commands()
    assert any("packaging/package_desktop.py" in command for command in documented), (
        f"docs/desktop.md documents no packaging/package_desktop.py command: {documented}")
    result = subprocess.run([sys.executable, str(PACKAGER), "--output", str(output)],
                            cwd=ROOT, timeout=timeout, capture_output=True, text=True)
    assert result.returncode == 0, (
        f"packaging failed: {(result.stderr.strip() or result.stdout.strip())[-600:]}")
    archive = Path(result.stdout.strip().splitlines()[-1])
    assert archive.is_file(), f"the packager wrote no archive: {result.stdout[-400:]}"
    suffix = f"-{platform.system()}-{platform.machine()}.tar.gz"
    assert archive.name.startswith("romwright-") and archive.name.endswith(suffix), (
        f"{archive.name} is not romwright-<version>-<system>-<machine>.tar.gz")
    return archive


def extract(archive: Path, prefix: Path) -> Path:
    with tarfile.open(archive) as bundle:
        for member in bundle.getmembers():
            assert not member.name.startswith("/") and ".." not in member.name, (
                f"archive member escapes the prefix: {member.name}")
        bundle.extractall(prefix)
    installed = [path for path in prefix.rglob(EXECUTABLE)
                 if path.is_file() and os.access(path, os.X_OK)]
    assert installed, f"no executable {EXECUTABLE} inside {archive.name}"
    return installed[0]


def run_gate(app: Path, project: Path, extra: dict[str, str],
             store_only: bool, timeout: int) -> tuple[dict, str | None]:
    # Nothing from this shell leaks in: a packaged run must stand on its own.
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith("ROMWRIGHT_")}
    environment.update(extra)
    command = [str(app), "--gate", "--project", str(project), "--program", "tiny",
               "--binary", str(FIXTURE), "--address", "00400466"]
    if store_only:
        command.append("--store-only")
    result = subprocess.run(command, cwd=app.parent, env=environment,
                            capture_output=True, text=True, timeout=timeout)
    assert result.returncode == 0, (
        f"packaged gate exited {result.returncode}: "
        f"{(result.stderr.strip() or result.stdout.strip())[-600:]}")
    adapter = next((line[len(ADAPTER_PREFIX):].strip()
                    for line in result.stderr.splitlines()
                    if line.startswith(ADAPTER_PREFIX)), None)
    for line in reversed(result.stdout.splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        metrics = payload.get("metrics", payload)
        if isinstance(metrics, dict):
            return metrics, adapter
    raise AssertionError(f"gate printed no metrics: {result.stdout[-400:]}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--package-dir", type=Path, default=ROOT / "build" / "desktop-package",
                        help="directory the archive is written to")
    parser.add_argument("--timeout", type=int, default=2400)
    arguments = parser.parse_args()

    report = {"id": "m6-003", "recorded_at": datetime.now(timezone.utc).isoformat(),
              "thresholds": THRESHOLDS, "status": "skipped",
              "platform": {"system": platform.system(),
                           "machine": platform.machine()}}
    if shutil.which("cargo") is None:
        report["reason"] = "no cargo available"
        print(f"SKIP: {report['reason']}")
        if arguments.report:
            arguments.report.write_text(json.dumps(report, indent=1) + "\n")
        return 0

    archive = build_package(arguments.package_dir.resolve(), arguments.timeout)
    with tempfile.TemporaryDirectory(prefix="m6-003-") as temporary:
        prefix = Path(temporary) / "prefix"
        prefix.mkdir()
        app = extract(archive, prefix)
        assert prefix in app.parents, "the extracted app is outside the prefix"
        for marker in (".fingerprint", "deps", "CACHEDIR.TAG"):
            assert not (app.parent / marker).exists(), (
                f"the extracted tree contains cargo's {marker}, so it is a build tree")

        store, adapter = run_gate(app, Path(temporary) / "store", {}, True,
                                  arguments.timeout)
        for metric in MEASURED:
            assert store.get(metric) is True, (
                f"{metric} is {store.get(metric)!r} on a packaged store-only run")
        for metric, threshold in THRESHOLDS.items():
            value = store.get(metric)
            assert isinstance(value, (int, float)) and not isinstance(value, bool), (
                f"{metric} is {value!r}")
            assert value <= threshold, f"{metric} {value} exceeds {threshold}"
    report["platform"]["adapter"] = adapter

    summary = (f"packaged {archive.name} on {platform.system()}/"
               f"{platform.machine()} rendering on {adapter}: store-only run from a "
               f"clean prefix with no ROMWRIGHT_* configuration, "
               f"ui.list.load_ms {store['ui.list.load_ms']:.2f}")
    if arguments.report:
        report.update(status="pass", passed=True, summary=summary,
                      metrics={**{key: store[key] for key in MEASURED},
                               **{key: store[key] for key in THRESHOLDS},
                               **{key: value for key, value in store.items()
                                  if key.startswith("ui.source.")}},
                      package=archive.name)
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps(report, indent=1) + "\n")
    print(f"m6-003: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
