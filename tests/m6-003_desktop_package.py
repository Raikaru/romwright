#!/usr/bin/env python3
"""m6-003: the packaged desktop is built, installed and launched.

`tests/package_install_smoke.sh` already builds the CPack archive, extracts it
and runs the offscreen gate -- but it passes `ROMWRIGHT_UI_INSTALL_OK=1` to the
app, and the app reports that variable back as `ui.install.ok`. The gate
asserts a value the harness supplied, so nothing about the installation is
measured.

This gate measures it instead. It builds the archive, extracts it to a clean
prefix, and launches the *extracted* binary with **every `ROMWRIGHT_*` variable
removed**, so the run has no configuration to lean on. The app reports two
facts it can see for itself:

  * `ui.install.prefix_ok` -- the executable is running from an installed
    layout, not from a build tree;
  * `ui.install.store_only_ok` -- it completed the store-facing workflow
    (import, function list, filter) with no `ROMWRIGHT_*` variable set.

`ui.install.ok` is left alone: it is a metric in a committed gate, and
AGENTS.md II.1 reserves metric-definition changes. STATUS.md records the
proposal to retire it.

The report names the platform it ran on, so a reader can see which platforms
the evidence actually covers rather than assuming three.

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
SOURCE = ROOT / "desktop" / "romwright-qt"
DOC = ROOT / "docs" / "desktop.md"
FIXTURE = ROOT / "tests" / "fixtures-src" / "tiny_bin"
# The same list thresholds the M0 UI gate uses; unchanged.
THRESHOLDS = {"ui.list.load_ms": 500.0, "ui.list.filter_ms": 100.0}
MEASURED = ("ui.install.prefix_ok", "ui.install.store_only_ok")


def qt_available() -> str | None:
    if shutil.which("cmake") is None:
        return None
    for tool in ("qmake6", "qmake"):
        found = shutil.which(tool)
        if found is None:
            continue
        result = subprocess.run([found, "-query", "QT_VERSION"],
                                capture_output=True, text=True)
        version = result.stdout.strip()
        if result.returncode == 0 and version.startswith("6."):
            return version
    return None


def documented_commands() -> list[str]:
    """The build commands `docs/desktop.md` tells a reader to run."""
    assert DOC.is_file(), f"{DOC.relative_to(ROOT)} does not exist"
    commands = []
    for line in DOC.read_text(encoding="utf-8").splitlines():
        stripped = line[2:].strip() if line.startswith("$ ") else line.strip()
        if stripped.startswith("cmake "):
            commands.append(stripped)
    return commands


def build_package(build: Path, timeout: int) -> Path:
    generator = ["-G", "Ninja"] if shutil.which("ninja") else []
    # The page and the gate must run the same targets; a page that drifts from
    # the build it documents is the failure this checks for.
    documented = documented_commands()
    for target in ("-S desktop/romwright-qt", "--target romwright-qt", "--target package"):
        assert any(target in command for command in documented), (
            f"docs/desktop.md documents no command with {target!r}: {documented}")
    subprocess.run(["cmake", "-S", str(SOURCE), "-B", str(build),
                    "-DCMAKE_BUILD_TYPE=Release", *generator],
                   cwd=ROOT, check=True, timeout=timeout,
                   stdout=subprocess.DEVNULL)
    subprocess.run(["cmake", "--build", str(build), "--config", "Release",
                    "--target", "romwright-qt"],
                   cwd=ROOT, check=True, timeout=timeout,
                   stdout=subprocess.DEVNULL)
    subprocess.run(["cmake", "--build", str(build), "--config", "Release",
                    "--target", "package"],
                   cwd=ROOT, check=True, timeout=timeout,
                   stdout=subprocess.DEVNULL)
    archives = sorted(build.glob("romwright-*.tar.gz"),
                      key=lambda path: path.stat().st_mtime, reverse=True)
    assert archives, f"no CPack archive under {build}"
    return archives[0]


def extract(archive: Path, prefix: Path) -> Path:
    with tarfile.open(archive) as bundle:
        for member in bundle.getmembers():
            assert not member.name.startswith("/") and ".." not in member.name, (
                f"archive member escapes the prefix: {member.name}")
        bundle.extractall(prefix)
    installed = [path for path in prefix.rglob("romwright-qt")
                 if path.is_file() and os.access(path, os.X_OK)]
    assert installed, f"no executable romwright-qt inside {archive.name}"
    return installed[0]


def run_gate(app: Path, project: Path, extra: dict[str, str],
             store_only: bool, timeout: int) -> dict:
    # Nothing from this shell leaks in: a packaged run must stand on its own.
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith("ROMWRIGHT_")}
    environment["QT_QPA_PLATFORM"] = "offscreen"
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
            return metrics
    raise AssertionError(f"gate printed no metrics: {result.stdout[-400:]}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--build-dir", type=Path,
                        default=Path(os.environ.get("ROMWRIGHT_BUILD_DIR",
                                                    "/tmp/romwright-qt-m6-003")))
    parser.add_argument("--timeout", type=int, default=2400)
    arguments = parser.parse_args()

    report = {"id": "m6-003", "recorded_at": datetime.now(timezone.utc).isoformat(),
              "thresholds": THRESHOLDS, "status": "skipped",
              "platform": {"system": platform.system(),
                           "machine": platform.machine()}}
    version = qt_available()
    if version is None:
        report["reason"] = "no cmake with Qt 6 available"
        print(f"SKIP: {report['reason']}")
        if arguments.report:
            arguments.report.write_text(json.dumps(report, indent=1) + "\n")
        return 0
    report["platform"]["qt"] = version

    archive = build_package(arguments.build_dir, arguments.timeout)
    with tempfile.TemporaryDirectory(prefix="m6-003-") as temporary:
        prefix = Path(temporary) / "prefix"
        prefix.mkdir()
        app = extract(archive, prefix)
        assert prefix in app.parents, "the extracted app is outside the prefix"
        assert not (app.parent / "CMakeCache.txt").is_file(), (
            "the extracted tree contains a CMake cache, so it is a build tree")

        store = run_gate(app, Path(temporary) / "store", {}, True, arguments.timeout)
        for metric in MEASURED:
            assert store.get(metric) is True, (
                f"{metric} is {store.get(metric)!r} on a packaged store-only run")
        for metric, threshold in THRESHOLDS.items():
            value = store.get(metric)
            assert isinstance(value, (int, float)) and not isinstance(value, bool), (
                f"{metric} is {value!r}")
            assert value <= threshold, f"{metric} {value} exceeds {threshold}"

    summary = (f"packaged {archive.name} on {platform.system()}/"
               f"{platform.machine()} with Qt {version}: store-only run from a "
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
