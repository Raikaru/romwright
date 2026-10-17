#!/usr/bin/env python3
"""m6-007: the desktop creates a project from the open image and runs match.

`docs/desktop.md` documents Program setup's **Create project** (`new-project`)
and the **Match** panel (`match`), and says the packaged archive carries the
CLI the first one runs. This builds the archive with the documented packager,
extracts it to a clean prefix and drives the *extracted* `romwright-desktop`
through `--gate --project-image tests/fixtures-src/tiny_pe32.exe`: the gate
imports the PE32 as a second program, clicks Create project on it, checks the
repository the panel reports, gives the repository the host's clang as its
compile check and runs Match on the largest function, then reads the variant
table back after painting it (docs/desktop.md "The project gate").

The run keeps its environment (the pinned Ghidra install and the built
decompiler are found through it) except `ROMWRIGHT_CLI`, so the CLI the panel
runs is the one beside the extracted app. Needs `cargo`, `python3`, `clang`
(`$CLANG` or `PATH`) and the Ghidra install; without one the gate is skipped,
and says which.

Usage:
    python3 tests/m6-007_desktop_projects.py [--report OUT.json]
"""
from __future__ import annotations

import argparse
import importlib.util
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
FIXTURE = ROOT / "tests" / "fixtures-src" / "tiny_bin"
IMAGE = ROOT / "tests" / "fixtures-src" / "tiny_pe32.exe"
SIBLINGS = ("romwright-worker", "romwright-cli")


def package_helpers():
    """The packaging and extraction m6-003 gates, so both gate one archive layout."""
    path = ROOT / "tests" / "m6-003_desktop_package.py"
    spec = importlib.util.spec_from_file_location("m6_003_desktop_package", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def missing_prerequisites() -> list[str]:
    missing = []
    if shutil.which("cargo") is None:
        missing.append("cargo")
    if shutil.which("python3") is None:
        missing.append("python3")
    clang = os.environ.get("CLANG")
    if not (clang and Path(clang).is_file()) and shutil.which("clang") is None:
        missing.append("clang ($CLANG or PATH)")
    ghidra = Path(os.environ.get("ROMWRIGHT_GHIDRA", str(Path.home() / "ghidra_12.1.3_PUBLIC")))
    if not ghidra.is_dir():
        missing.append(f"the Ghidra install ({ghidra})")
    return missing


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--package-dir", type=Path, default=ROOT / "build" / "desktop-package")
    parser.add_argument("--timeout", type=int, default=2400)
    arguments = parser.parse_args()

    report = {"id": "m6-007", "recorded_at": datetime.now(timezone.utc).isoformat(),
              "status": "skipped",
              "platform": {"system": platform.system(), "machine": platform.machine()}}
    missing = missing_prerequisites()
    if missing:
        report["reason"] = "missing " + ", ".join(missing)
        print(f"SKIP: {report['reason']}")
        if arguments.report:
            arguments.report.write_text(json.dumps(report, indent=1) + "\n")
        return 0

    helpers = package_helpers()
    archive = helpers.build_package(arguments.package_dir.resolve(), arguments.timeout)
    suffix = ".exe" if os.name == "nt" else ""
    with tarfile.open(archive) as bundle:
        members = {Path(member.name).name for member in bundle.getmembers() if "/bin/" in member.name}
    for sibling in SIBLINGS:
        assert f"{sibling}{suffix}" in members, f"{archive.name} carries no bin/{sibling}{suffix}"

    with tempfile.TemporaryDirectory(prefix="m6-007-") as temporary:
        prefix = Path(temporary) / "prefix"
        prefix.mkdir()
        app = helpers.extract(archive, prefix)
        for sibling in SIBLINGS:
            assert (app.parent / f"{sibling}{suffix}").is_file(), f"{sibling} is not beside the extracted app"
        environment = {key: value for key, value in os.environ.items() if key != "ROMWRIGHT_CLI"}
        command = [str(app), "--gate", "--project", str(Path(temporary) / "store"),
                   "--program", "tiny", "--binary", str(FIXTURE), "--address", "00400466",
                   "--project-image", str(IMAGE)]
        result = subprocess.run(command, cwd=app.parent, env=environment, capture_output=True,
                                text=True, timeout=arguments.timeout)
        assert result.returncode == 0, (
            f"packaged project gate exited {result.returncode}: "
            f"{(result.stderr.strip() or result.stdout.strip())[-800:]}")
        metrics = None
        for line in reversed(result.stdout.splitlines()):
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            metrics = payload.get("metrics")
            if isinstance(metrics, dict):
                break
        assert metrics, f"the gate printed no metrics: {result.stdout[-400:]}"
        adapter = next((line.split("rendering offscreen on ", 1)[1].strip()
                        for line in result.stderr.splitlines() if "rendering offscreen on " in line), None)

    for key in ("ui.new_project.readme", "ui.new_project.config", "ui.new_project.job_logged",
                "ui.match.root_follows_project"):
        assert metrics.get(key) is True, f"{key} is {metrics.get(key)!r}"
    assert metrics.get("ui.new_project.files", 0) > 0, "the repository has no files"
    assert metrics.get("ui.new_project.image") == "project_image", (
        f"the repository names its image {metrics.get('ui.new_project.image')!r}, not the program")
    rows = metrics.get("ui.match.rows", 0)
    assert rows >= 2, f"the match table has {rows} rows"
    assert metrics.get("ui.match.rendered_rows") == rows, "the table painted other rows than the report holds"
    assert metrics.get("ui.match.compiled_rows", 0) >= 1, "no variant compiled"
    assert metrics["ui.match.best_percent"] >= metrics["ui.match.default_percent"], "the best row scores below the stock print"
    assert metrics.get("ui.match.decompiles", 0) >= 1 and metrics.get("ui.match.compiles", 0) >= 1

    summary = (f"packaged {archive.name} on {platform.system()}/{platform.machine()} rendering on {adapter}: "
               f"Create project wrote {metrics['ui.new_project.files']} files in "
               f"{metrics['ui.new_project.ms']:.0f} ms; Match on {metrics['ui.match.function']} "
               f"showed {rows} variants, {metrics['ui.match.compiled_rows']} compiled, best "
               f"{metrics['ui.match.best_percent']:.3f}% against stock {metrics['ui.match.default_percent']:.3f}%")
    if arguments.report:
        report.update(status="pass", passed=True, summary=summary, package=archive.name,
                      metrics={key: value for key, value in metrics.items()
                               if key.startswith(("ui.new_project.", "ui.match."))})
        report["platform"]["adapter"] = adapter
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps(report, indent=1) + "\n")
    print(f"m6-007: PASS ({summary})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        sys.exit(1)
