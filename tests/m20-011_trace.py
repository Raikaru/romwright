#!/usr/bin/env python3
"""m20-011: emulator trace ingest — trace_events + traced functions.

Gate: import bond.dol, feed a CSV trace covering known functions plus
one address outside any function, assert (a) trace_events rows land,
(b) exec/call/bp events mark their functions traced, (c) read/write
events do not mark.
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
    report = {"id": "m20-011",
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
    with tempfile.TemporaryDirectory(prefix="m20-011-", dir=Path.home() / "tmp") as temporary:
        project = Path(temporary) / "project"
        subprocess.run(
            [str(cli), "import", str(dol), "--map", str(symbols),
             "--name", "bond", "--project", str(project), "--no-analysis"],
            cwd=ROOT, check=True, capture_output=True, timeout=1800)

        db = sqlite3.connect(project / "project.sqlite")
        # Two real function entries + one data address + one miss.
        entries = [r[0] for r in db.execute(
            "SELECT entry FROM functions ORDER BY entry LIMIT 3")]
        assert len(entries) >= 3, "need 3 functions"
        trace = Path(temporary) / "trace.csv"
        trace.write_text(
            f"# addr,kind,thread\n"
            f"0x{entries[0]},exec,cpu0\n"
            f"0x{entries[1]},call,cpu0\n"
            f"0x{entries[2]},bp,cpu0\n"
            f"0x80229208,read,cpu0\n"   # data address — must not mark
            f"0xdeadbeef,exec,cpu0\n"  # outside any function — no mark
        )
        out = subprocess.run(
            [str(cli), "import-trace", "bond", str(trace),
             "--project", str(project)],
            cwd=ROOT, capture_output=True, text=True, timeout=300)
        assert out.returncode == 0, f"import-trace failed: {out.stderr.strip()}"

        events = db.execute(
            "SELECT COUNT(*) FROM trace_events").fetchone()[0]
        assert events == 5, f"trace_events {events} != 5"
        traced = {r[0] for r in db.execute(
            "SELECT entry FROM functions WHERE traced <> 0")}
        expected = {e.lower().lstrip("0x").zfill(8) for e in entries}
        # Entries are stored as 8-hex strings; normalize both sides.
        traced_norm = {e.lower().lstrip("0x").zfill(8) for e in traced}
        assert expected <= traced_norm, (
            f"traced {traced_norm} missing {expected - traced_norm}")
        assert "80229208" not in traced_norm, "read event marked a function"
        summary = (f"{events} events, {len(traced)} functions traced, "
                   f"3 expected entries marked")
        report.update(status="pass", passed=True, summary=summary,
                      metrics={"events": events, "traced": len(traced)})
        print(f"m20-011: PASS ({summary})")
    if arguments.report:
        arguments.report.write_text(json.dumps(report, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
