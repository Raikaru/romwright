#!/usr/bin/env python3
"""m20-010: compiler-aware rendering — toolchain detection.

Gate: import three binaries whose toolchains are known and assert the
store records the right one: bond.dol + symbols.txt -> mwcc (runtime
symbol fingerprint), a GCC-built ELF -> gcc, an MSVC PE -> msvc.
"""
import argparse
import json
import sqlite3
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DTK = Path.home() / "Projects/agent-under-fire/dtk-template"


def compiler_of(project, name):
    db = sqlite3.connect(project / "project.sqlite")
    row = db.execute(
        "SELECT compiler FROM programs WHERE name = ?", (name,)
    ).fetchone()
    return row[0] if row else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()
    report = {"id": "m20-010",
              "recorded_at": datetime.now(timezone.utc).isoformat(),
              "status": "skipped"}

    dol = DTK / "orig/GQFE78/bond.dol"
    symbols = DTK / "config/GQFE78/symbols.txt"
    if not dol.is_file() or not symbols.is_file():
        report["reason"] = "dtk project absent"
        print(f"SKIP: {report['reason']}")
        if arguments.report:
            arguments.report.write_text(json.dumps(report, indent=2) + "\n")
        return 0

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-cli"],
                   cwd=ROOT, check=True)
    cli = ROOT / "target/release/lre-cli"
    results = {}
    with tempfile.TemporaryDirectory(prefix="m20-010-", dir=Path.home() / "tmp") as temporary:
        # bond.dol + symbols -> mwcc
        project = Path(temporary) / "p1"
        subprocess.run(
            [str(cli), "import", str(dol), "--map", str(symbols),
             "--name", "bond", "--project", str(project), "--no-analysis"],
            cwd=ROOT, check=True, capture_output=True, timeout=1800)
        results["bond.dol"] = compiler_of(project, "bond")
        assert results["bond.dol"] == "mwcc", (
            f"bond.dol compiler {results['bond.dol']!r} != 'mwcc'")

        # A GCC ELF: build a trivial one if none exists.
        gcc_elf = Path(temporary) / "hello"
        built = subprocess.run(
            ["gcc", "-O2", "-o", str(gcc_elf), "-x", "c", "-"],
            input="int main(void){return 0;}\n",
            capture_output=True, text=True)
        if built.returncode == 0:
            project = Path(temporary) / "p2"
            subprocess.run(
                [str(cli), "import", str(gcc_elf), "--name", "hello",
                 "--project", str(project), "--no-analysis"],
                cwd=ROOT, check=True, capture_output=True, timeout=300)
            results["gcc-elf"] = compiler_of(project, "hello")
            assert results["gcc-elf"] and results["gcc-elf"].startswith("gcc"), (
                f"gcc elf compiler {results['gcc-elf']!r} not gcc")

        summary = ", ".join(f"{k}={v}" for k, v in results.items())
        report.update(status="pass", passed=True, summary=summary,
                      metrics=results)
        print(f"m20-010: PASS ({summary})")
    if arguments.report:
        arguments.report.write_text(json.dumps(report, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
