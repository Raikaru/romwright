#!/usr/bin/env python3
"""Drive a Romwright project from a script: read facts, write one, undo it.

Everything here goes through the same Core API the desktop uses, over the
stdio transport in `python/romwright_sdk.py`. The script computes over the
facts it is given -- the containing function is worked out from the function
extents rather than asked for, because the store answers with what it proved
and leaves the interpretation to its consumer.

    python3 examples/facts_report.py --project DIR --binary PATH [--name NAME]
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "python"))

from romwright_sdk import Client  # noqa: E402


def offset(address: object) -> int:
    """Addresses come back typed: an object naming its space and offset."""
    if isinstance(address, dict):
        return int(address["offset"])
    return int(str(address), 16)


def containing(rows: list[dict], address: int) -> str | None:
    """The function whose proven body holds `address`, computed here."""
    best = None
    for row in rows:
        entry = offset(row["entry"])
        if entry <= address < entry + int(row["size"]):
            if best is None or entry > offset(best["entry"]):
                best = row
    return None if best is None else str(best["name"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--name", default="tiny")
    parser.add_argument("--address", default="00400466")
    parser.add_argument("--inside", default="00400488")
    parser.add_argument("--executable",
                        default=str(ROOT / "target/release/romwright-api"))
    arguments = parser.parse_args()

    with Client.stdio(arguments.project, arguments.executable) as client:
        client.import_native(arguments.binary, arguments.name)
        rows = client.functions(arguments.name)

        wanted = offset(arguments.address)
        match = next((row for row in rows if offset(row["entry"]) == wanted), None)
        if match is None:
            print(f"no function at {arguments.address}", file=sys.stderr)
            return 1
        print(f"{match['name']} at {arguments.address} ({match['size']} bytes)")

        inside = offset(arguments.inside)
        owner = containing(rows, inside)
        print(f"{arguments.inside} is inside {owner}")

        renamed = client.request("rename", program=arguments.name,
                                 address=arguments.address, name="demo_add")
        print(f"renamed {arguments.address} -> {renamed['name']}")

        undone = client.request("undo", program=arguments.name)
        print(undone["message"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
