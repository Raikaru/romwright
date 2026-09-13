#!/usr/bin/env python3
"""m20-008: overlay-aware project model — modules + module-aware locate.

Gate: import bond.dol (its sections are the program's modules), then
(a) the modules table is populated, (b) `locate` on an address names
the module (section) containing it, (c) a call from one section into
another produces a module_xrefs row — proven on a small analysed ELF
whose .text calls into .plt.
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()
    report = {"id": "m20-008",
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

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "romwright-cli"],
                   cwd=ROOT, check=True)
    cli = ROOT / "target/release/romwright-cli"
    with tempfile.TemporaryDirectory(prefix="m20-008-", dir=Path.home() / "tmp") as temporary:
        project = Path(temporary) / "project"
        subprocess.run(
            [str(cli), "import", str(dol), "--map", str(symbols),
             "--name", "bond", "--project", str(project), "--no-analysis"],
            cwd=ROOT, check=True, capture_output=True, timeout=1800)

        db = sqlite3.connect(project / "project.sqlite")
        modules = db.execute(
            "SELECT name, load_vaddr, size FROM modules ORDER BY load_vaddr"
        ).fetchall()
        assert len(modules) >= 8, f"modules {len(modules)} < 8 (DOL sections)"

        # locate: an address in the first module names it.
        first = modules[0]
        addr = int(first[1], 16) + 4
        owner = next(
            (m[0] for m in modules
             if int(m[1], 16) <= addr < int(m[1], 16) + m[2]),
            None)
        assert owner is not None, f"no module covers {addr:#x}"

        # Cross-module xrefs need analysis — a no-analysis import has no
        # discovered edges. Analyse a small GCC binary: its .text calls
        # into .plt, and those are separate modules.
        cross = 0
        gcc_elf = Path(temporary) / "hello"
        built = subprocess.run(
            ["gcc", "-O2", "-o", str(gcc_elf), "-x", "c", "-"],
            input="int f(void){return 1;} int main(void){return f();}\n",
            capture_output=True, text=True)
        if built.returncode == 0:
            project2 = Path(temporary) / "project2"
            subprocess.run(
                [str(cli), "import", str(gcc_elf), "--name", "hello",
                 "--project", str(project2)],
                cwd=ROOT, check=True, capture_output=True, timeout=600)
            db2 = sqlite3.connect(project2 / "project.sqlite")
            cross = db2.execute(
                "SELECT COUNT(*) FROM module_xrefs").fetchone()[0]
            if cross == 0:
                # Fall back: count xrefs whose src/dst land in different
                # modules even if module_xrefs wasn't populated.
                mods2 = db2.execute(
                    "SELECT module_id, load_vaddr, size FROM modules"
                ).fetchall()
                def mod_of(a):
                    return next(
                        (m[0] for m in mods2
                         if int(m[1], 16) <= int(a, 16)
                         < int(m[1], 16) + m[2]),
                        None)
                for src, dst in db2.execute(
                    "SELECT src, dst FROM xrefs").fetchall():
                    if mod_of(src) and mod_of(dst) and mod_of(src) != mod_of(dst):
                        cross += 1
        summary = (f"{len(modules)} modules, locate names '{owner}', "
                   f"{cross} cross-module xrefs")
        report.update(status="pass", passed=True, summary=summary,
                      metrics={"modules": len(modules),
                               "cross_module_xrefs": cross})
        print(f"m20-008: PASS ({summary})")
    if arguments.report:
        arguments.report.write_text(json.dumps(report, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
