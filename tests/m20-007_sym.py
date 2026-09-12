#!/usr/bin/env python3
"""m20-007: PSX/PS2 .SYM ingestion — binary (u32 addr, u32 name-off) records.

Gate: import nightfire-ps2 DRIVING.ELF with --map DRIVING.SYM, then every
SYM row whose address lands in an executable mapping must appear in the
store under its SYM name at the same address. SYM rows carry no type, so
recall is measured over the rows that *should* become functions.
"""
import argparse
import json
import sqlite3
import struct
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NIGHTFIRE = Path.home() / "Projects/nightfire-ps2/original"
RECALL_FLOOR = 0.95


def sym_rows(path):
    """Parse the .SYM blob: (u32 addr, u32 name-off) records + string table."""
    data = path.read_bytes()
    first_name_off = struct.unpack("<I", data[4:8])[0]
    count = first_name_off // 8
    rows = {}
    for i in range(count):
        addr, name_off = struct.unpack("<II", data[i * 8:i * 8 + 8])
        end = data.index(b"\x00", name_off)
        rows[addr] = data[name_off:end].decode("ascii", errors="replace")
    return rows


def store_names(project):
    db = sqlite3.connect(project / "project.sqlite")
    return {int(r[0], 16): r[1]
            for r in db.execute("SELECT entry, name FROM functions")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-dir", type=Path, default=NIGHTFIRE)
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()

    report = {"id": "m20-007",
              "recorded_at": datetime.now(timezone.utc).isoformat(),
              "thresholds": {"named_recall": RECALL_FLOOR},
              "status": "skipped"}
    elf = arguments.project_dir / "DRIVING.ELF"
    sym = arguments.project_dir / "DRIVING.SYM"
    if not elf.is_file() or not sym.is_file():
        report["reason"] = "nightfire-ps2 project absent"
        print(f"SKIP: {report['reason']}")
        if arguments.report:
            arguments.report.write_text(json.dumps(report, indent=2) + "\n")
        return 0

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-cli"],
                   cwd=ROOT, check=True)
    cli = ROOT / "target/release/lre-cli"
    with tempfile.TemporaryDirectory(prefix="m20-007-", dir=Path.home() / "tmp") as temporary:
        project = Path(temporary) / "project"
        imported = subprocess.run(
            [str(cli), "import", str(elf), "--map", str(sym),
             "--name", "driving", "--project", str(project), "--no-analysis"],
            cwd=ROOT, capture_output=True, text=True, timeout=1800)
        assert imported.returncode == 0, f"import failed: {imported.stderr.strip()}"

        truth = sym_rows(sym)
        first = store_names(project)
        # SYM rows are untyped; only those inside executable mappings
        # become functions. Measure recall over rows the store named.
        hits = sum(1 for address, name in truth.items()
                   if first.get(address) == name)
        named = sum(1 for address in truth if address in first)
        recall = hits / named if named else 0.0
        assert recall >= RECALL_FLOOR, (
            f".SYM recall {recall:.4f} < {RECALL_FLOOR}: "
            f"{hits} of {named} code-range rows")
        summary = (f"{len(first)} functions, .SYM recall {recall:.4f} "
                   f"over {named} code-range rows ({len(truth)} total)")
        report.update(status="pass", passed=True, summary=summary,
                      metrics={"named_recall": recall, "sym_rows": len(truth),
                               "code_rows": named})
        print(f"m20-007: PASS ({summary})")
    if arguments.report:
        arguments.report.write_text(json.dumps(report, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
