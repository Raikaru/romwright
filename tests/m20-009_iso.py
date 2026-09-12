#!/usr/bin/env python3
"""m20-009: container-direct import — ISO9660 disc image.

Gate: import the nightfire-ps2 ISO directly (no manual extraction).
Asserts (a) the ISO is detected and every root ELF becomes a program,
(b) the SYSTEM.CNF boot executable (SLUS_205.79) is the first image,
(c) the symtab-bearing ELF (ACTION) imports its real function count.
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
ISO = Path.home() / "Projects/nightfire-ps2/007 - Nightfire (USA).iso"
# ACTION.ELF carries a symtab; the others are stripped (names live in
# the .SYM, gated separately by m20-007).
ACTION_FLOOR = 3000


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iso", type=Path, default=ISO)
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()

    report = {"id": "m20-009",
              "recorded_at": datetime.now(timezone.utc).isoformat(),
              "thresholds": {"action_functions": ACTION_FLOOR},
              "status": "skipped"}
    if not arguments.iso.is_file():
        report["reason"] = "nightfire ISO absent"
        print(f"SKIP: {report['reason']}")
        if arguments.report:
            arguments.report.write_text(json.dumps(report, indent=2) + "\n")
        return 0

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-cli"],
                   cwd=ROOT, check=True)
    cli = ROOT / "target/release/lre-cli"
    with tempfile.TemporaryDirectory(prefix="m20-009-", dir=Path.home() / "tmp") as temporary:
        project = Path(temporary) / "project"
        imported = subprocess.run(
            [str(cli), "import", str(arguments.iso),
             "--name", "nightfire", "--project", str(project),
             "--no-analysis"],
            cwd=ROOT, capture_output=True, text=True, timeout=1800)
        assert imported.returncode == 0, f"import failed: {imported.stderr.strip()}"
        lines = [l for l in imported.stdout.splitlines() if l.startswith("imported")]
        assert len(lines) >= 4, f"expected 4 programs, got {len(lines)}: {lines}"
        # Boot executable first (SYSTEM.CNF BOOT2 = SLUS_205.79).
        assert "SLUS_205.79" in lines[0], (
            f"boot image not first: {lines[0]}")
        db = sqlite3.connect(project / "project.sqlite")
        programs = {r[0]: r[1] for r in db.execute(
            "SELECT p.name, COUNT(f.entry) FROM programs p "
            "LEFT JOIN functions f ON f.program_id = p.id "
            "GROUP BY p.name")}
        action = next((v for k, v in programs.items() if "ACTION" in k), 0)
        assert action >= ACTION_FLOOR, (
            f"ACTION.ELF functions {action} < {ACTION_FLOOR}")
        summary = (f"{len(lines)} programs from ISO, boot={lines[0].split()[1]}, "
                   f"ACTION={action} functions")
        report.update(status="pass", passed=True, summary=summary,
                      metrics={"programs": len(lines), "action_functions": action})
        print(f"m20-009: PASS ({summary})")
    if arguments.report:
        arguments.report.write_text(json.dumps(report, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
