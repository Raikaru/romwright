#!/usr/bin/env python3
"""m20-006: dtk symbols.txt round-trip on a GameCube DOL.

The Agent Under Fire decomp project (dtk-template, config/GQFE78) is the
interop target: its symbols.txt names 17k addresses the linker placed.
The gate imports bond.dol with `--symbols` (dtk grammar), exports the
store's names back to dtk format, re-imports the export onto a fresh
project, and requires the names to survive the round-trip -- the
contract a decomp project actually needs.

Usage:
    python3 tests/m20-006_dtk_roundtrip.py [--project-dir DIR] [--report OUT.json]
"""
from __future__ import annotations

import argparse
import json
import re
import sqlite3
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DTK = Path.home() / "Projects/agent-under-fire/dtk-template"
DOL = DTK / "orig/GQFE78/bond.dol"
RECALL_FLOOR = 0.95

DTK_ROW = re.compile(
    r"^(\S+)\s*=\s*(?:([\w.]+):)?(0x[0-9a-fA-F]+);"
    r"(?:\s*//\s*(.*))?$")


def dtk_functions(symbols: Path) -> dict[int, str]:
    """`type:function` rows, by address."""
    functions: dict[int, str] = {}
    for line in symbols.read_text(errors="replace").splitlines():
        row = DTK_ROW.match(line.strip())
        if not row:
            continue
        comment = row.group(4) or ""
        if "type:function" in comment:
            functions[int(row.group(3), 16)] = row.group(1)
    return functions


def store_names(project: Path) -> dict[int, str]:
    store = sqlite3.connect(project / "project.sqlite")
    return {int(entry, 16): name for entry, name in store.execute(
        "SELECT entry, name FROM functions")}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-dir", type=Path, default=DTK)
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()

    report = {"id": "m20-006",
              "recorded_at": datetime.now(timezone.utc).isoformat(),
              "thresholds": {"named_recall": RECALL_FLOOR},
              "status": "skipped"}
    dol = arguments.project_dir / "orig/GQFE78/bond.dol"
    symbols = arguments.project_dir / "config/GQFE78/symbols.txt"
    if not dol.is_file() or not symbols.is_file():
        report["reason"] = "dtk project absent"
        print(f"SKIP: {report['reason']}")
        if arguments.report:
            arguments.report.write_text(json.dumps(report, indent=2) + "\n")
        return 0

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "romwright-cli"],
                   cwd=ROOT, check=True)
    cli = ROOT / "target/release/romwright-cli"
    with tempfile.TemporaryDirectory(prefix="m20-006-", dir=Path.home() / "tmp") as temporary:
        project = Path(temporary) / "project"
        imported = subprocess.run(
            [str(cli), "import", str(dol), "--map", str(symbols),
             "--name", "bond", "--project", str(project), "--no-analysis"],
            cwd=ROOT, capture_output=True, text=True, timeout=1800)
        assert imported.returncode == 0, f"import failed: {imported.stderr.strip()}"

        truth = dtk_functions(symbols)
        first = store_names(project)
        hits = sum(1 for address, name in truth.items()
                   if first.get(address) == name)
        recall = hits / len(truth)
        assert recall >= RECALL_FLOOR, (
            f"symbols.txt recall {recall:.4f} < {RECALL_FLOOR}: "
            f"{hits} of {len(truth)}")

        # Round-trip: export the store's names with real section names
        # from the project's splits.txt, re-import onto a fresh project,
        # require the same names back.
        exported = subprocess.run(
            [str(cli), "export-symbols", "bond",
             "--project", str(project), "--format", "dtk",
             "--splits", str(arguments.project_dir / "config/GQFE78/splits.txt")],
            cwd=ROOT, capture_output=True, text=True, timeout=300)
        assert exported.returncode == 0, f"export failed: {exported.stderr.strip()}"
        export_file = Path(temporary) / "exported.txt"
        export_file.write_text(exported.stdout)

        project2 = Path(temporary) / "project2"
        reimported = subprocess.run(
            [str(cli), "import", str(dol), "--map", str(export_file),
             "--name", "bond", "--project", str(project2), "--no-analysis"],
            cwd=ROOT, capture_output=True, text=True, timeout=1800)
        assert reimported.returncode == 0, (
            f"re-import failed: {reimported.stderr.strip()}")
        second = store_names(project2)
        roundtrip = sum(1 for address, name in first.items()
                        if second.get(address) == name)
        assert roundtrip == len(first), (
            f"round-trip lost names: {roundtrip} of {len(first)}")

        # The dtk contract: our emitted config + symbols must satisfy
        # `dtk dol diff` no worse than the project's own symbols.txt —
        # the rebuilt ELF is mid-decomp, so even the original file diffs
        # with errors; ours must not add any.
        dtk = Path.home() / "Projects/agent-under-fire/tools/dtk"
        bond_elf = arguments.project_dir / "build/GQFE78/bond.elf"
        if dtk.is_file() and bond_elf.is_file():
            work = Path(temporary) / "dtkproj"
            work.mkdir()
            (work / "bond.dol").write_bytes(dol.read_bytes())
            (work / "splits.txt").write_text(
                (arguments.project_dir / "config/GQFE78/splits.txt")
                .read_text(errors="replace"))
            (work / "config.yml").write_text(
                "name: bond\nobject: bond.dol\n"
                "symbols: symbols.txt\nsplits: splits.txt\n")

            def dol_diff(symbols_text):
                (work / "symbols.txt").write_text(symbols_text)
                run = subprocess.run(
                    [str(dtk), "dol", "diff", "config.yml", str(bond_elf)],
                    cwd=work, capture_output=True, text=True, timeout=300)
                return [line for line in run.stdout.splitlines()
                        if line.startswith("ERROR")]

            ours = dol_diff(exported.stdout)
            baseline = dol_diff(symbols.read_text(errors="replace"))
            assert len(ours) <= len(baseline), (
                f"dtk dol diff: ours {len(ours)} errors vs "
                f"baseline {len(baseline)}: {ours[:4]}")

        summary = (f"{len(first)} functions, symbols.txt recall {recall:.4f} "
                   f"over {len(truth)} dtk rows, round-trip {roundtrip}/{len(first)}")
        report.update(status="pass", passed=True, summary=summary,
                      metrics={"named_recall": recall, "dtk_rows": len(truth),
                               "roundtrip": roundtrip})
        print(f"m20-006: PASS ({summary})")
    if arguments.report:
        arguments.report.write_text(json.dumps(report, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
