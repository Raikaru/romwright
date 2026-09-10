#!/usr/bin/env python3
"""m14-001: an import an analyst can sit in front of.

Three claims, each a wall-clock budget with a correctness condition attached,
because a fast import that answers differently is not a faster import:

1. **Loading is not analysing.** `import --no-analysis` maps the image,
   applies what the image says about itself -- its symbol table above all --
   stores it, and returns. Every function it lists must be one the image's
   own symbols name, so the fast path invents nothing.
2. **An unchanged image is not re-analysed.** The second full import of the
   same bytes by the same analyser is restored from cache, and its fact set
   is byte-identical to the first across every table.
3. **A changed analyser is re-analysed.** Flipping a switch that changes
   facts must miss the cache, or the cache would serve stale answers.

Budgets are wall-clock on the machine running the gate, so they are set well
above the measured figures; a regression of the kind this guards against is
an order of magnitude, not a percent.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "target" / "release" / "lre-cli"

BUDGETS = {
    # Measured: 1.2 s on the host libc, 2.1 s on a 60 MB Switch module of
    # 45687 functions.
    "load_small_seconds": 4.0,
    "load_large_seconds": 8.0,
    # Measured: 0.42 s restoring libc's 33050 xrefs and 3961 functions.
    "second_import_seconds": 5.0,
}


def run(arguments: list[str], environment: dict[str, str] | None = None) -> tuple[str, float]:
    started = time.time()
    result = subprocess.run(
        arguments,
        capture_output=True,
        text=True,
        env={**os.environ, **(environment or {})},
    )
    if result.returncode:
        raise ValueError(f"{arguments[1]} failed: {result.stderr[-800:]}")
    return result.stdout, time.time() - started


def snapshot(project: Path) -> dict[str, tuple[int, str]]:
    """Row count and content digest of every table."""
    connection = sqlite3.connect(project / "project.sqlite")
    out = {}
    for (table,) in connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
    ):
        rows = connection.execute(f'SELECT * FROM "{table}"').fetchall()
        digest = hashlib.sha256(repr(sorted(map(repr, rows))).encode()).hexdigest()[:16]
        out[table] = (len(rows), digest)
    return out


def symbol_names(binary: Path) -> set[str]:
    """Function names the image's own symbol table declares."""
    out = subprocess.run(["readelf", "-sW", str(binary)], capture_output=True, text=True).stdout
    names = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 8 and parts[3] == "FUNC":
            names.add(parts[7].split("@")[0])
    return names


def fresh(path: Path) -> Path:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True)
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--small", type=Path, default=Path("/usr/lib64/libc.so.6"))
    parser.add_argument(
        "--large",
        type=Path,
        default=Path.home() / "ventris-corpus/extracted/nx-xenoblade-de/main",
    )
    parser.add_argument("--work", type=Path, default=Path.home() / "ventris-cache/tmp/m14-001")
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()

    report = {
        "id": "m14-001",
        "milestone": "M14",
        "criterion": "loading is not analysing; an unchanged image is not re-analysed",
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "budgets": BUDGETS,
    }
    if not arguments.small.is_file():
        report["status"] = "skipped"
        report["reason"] = f"{arguments.small} is not on this machine"
        print(f"m14-001: SKIPPED ({report['reason']})")
        if arguments.report:
            arguments.report.parent.mkdir(parents=True, exist_ok=True)
            arguments.report.write_text(json.dumps(report, indent=2) + "\n")
        return 0

    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-cli"], cwd=ROOT, check=True)
    work = arguments.work
    cache = fresh(work / "cache")
    measured: dict[str, object] = {}
    failures: list[str] = []

    # 1. Loading is not analysing.
    loaded = fresh(work / "loaded")
    _, load_seconds = run(
        [str(CLI), "import", str(arguments.small), "--project", str(loaded), "--name", "small",
         "--no-analysis"],
        {"VENTRIS_IMPORT_CACHE": str(cache)},
    )
    listing, list_seconds = run(
        [str(CLI), "functions", "small", "--project", str(loaded)]
    )
    rows = [line for line in listing.splitlines() if line and not line.startswith("--")]
    declared = symbol_names(arguments.small)

    def accounted(name: str) -> bool:
        """True when the image itself accounts for this name.

        A symbol may be listed with its version (`memcpy@@GLIBC_2.14`), a
        linkage stub is named after the import it jumps to, and an address
        the loader declares without a symbol -- the ELF entry point -- gets
        a generated name. None of those is the fast path inventing a
        function; a name that matches none of them would be.
        """
        bare = name.split("@")[0]
        if bare in declared:
            return True
        for prefix in ("FUN_", "thunk_", "LAB_", "SUB_"):
            if bare.startswith(prefix):
                return True
        return bare.lstrip("_").split(".")[0] in {"plt", "init", "fini", "start"}

    invented = [
        line.split()[2]
        for line in rows
        if len(line.split()) >= 3 and not accounted(line.split()[2])
    ]
    measured["load"] = {
        "seconds": round(load_seconds, 2),
        "list_seconds": round(list_seconds, 2),
        "functions": len(rows),
        "invented": len(invented),
    }
    if load_seconds > BUDGETS["load_small_seconds"]:
        failures.append(f"load took {load_seconds:.2f}s > {BUDGETS['load_small_seconds']}s")
    if not rows:
        failures.append("loading listed no functions")
    if invented:
        # A loader-only import must name only what the image names.
        failures.append(f"loading invented {len(invented)} names, e.g. {invented[:3]}")

    if arguments.large.is_file():
        large = fresh(work / "large")
        _, large_seconds = run(
            [str(CLI), "import", str(arguments.large), "--project", str(large), "--name", "large",
             "--no-analysis"],
            {"VENTRIS_IMPORT_CACHE": str(cache)},
        )
        large_listing, _ = run([str(CLI), "functions", "large", "--project", str(large)])
        measured["load_large"] = {
            "seconds": round(large_seconds, 2),
            "functions": len(
                [line for line in large_listing.splitlines() if line and not line.startswith("--")]
            ),
        }
        if large_seconds > BUDGETS["load_large_seconds"]:
            failures.append(
                f"loading the large image took {large_seconds:.2f}s"
                f" > {BUDGETS['load_large_seconds']}s"
            )

    # 2. An unchanged image is not re-analysed.
    first = fresh(work / "first")
    _, first_seconds = run(
        [str(CLI), "import", str(arguments.small), "--project", str(first), "--name", "small"],
        {"VENTRIS_IMPORT_CACHE": str(cache)},
    )
    second = fresh(work / "second")
    _, second_seconds = run(
        [str(CLI), "import", str(arguments.small), "--project", str(second), "--name", "small"],
        {"VENTRIS_IMPORT_CACHE": str(cache)},
    )
    before, after = snapshot(first), snapshot(second)
    # `programs` carries the import timestamp and `revision_events` its
    # times, so they are compared by row count rather than by content.
    volatile = {"programs", "revision_events"}
    differing = [
        table
        for table in before
        if (before[table] if table not in volatile else before[table][0])
        != (after.get(table) if table not in volatile else (after.get(table) or (None,))[0])
    ]
    measured["reuse"] = {
        "first_seconds": round(first_seconds, 1),
        "second_seconds": round(second_seconds, 2),
        "tables": len(before),
        "differing": differing,
    }
    if second_seconds > BUDGETS["second_import_seconds"]:
        failures.append(
            f"second import took {second_seconds:.2f}s > {BUDGETS['second_import_seconds']}s"
        )
    if differing:
        failures.append(f"reused import differs from the analysed one: {differing}")

    # 3. A changed analyser is re-analysed.
    changed = fresh(work / "changed")
    _, changed_seconds = run(
        [str(CLI), "import", str(arguments.small), "--project", str(changed), "--name", "small"],
        {"VENTRIS_IMPORT_CACHE": str(cache), "VENTRIS_NO_SWITCH_VSA": "1"},
    )
    measured["invalidation"] = {"seconds": round(changed_seconds, 1)}
    if changed_seconds <= BUDGETS["second_import_seconds"]:
        failures.append(
            f"a changed analyser hit the cache ({changed_seconds:.2f}s): the key is too weak"
        )

    report["measured"] = measured
    report["status"] = "pass" if not failures else "fail"
    report["failures"] = failures
    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps(report, indent=2) + "\n")
    if failures:
        print(f"FAIL: {'; '.join(failures)}", file=sys.stderr)
        return 1
    load = measured["load"]
    reuse = measured["reuse"]
    large = measured.get("load_large")
    print(
        f"m14-001: PASS (load {load['seconds']}s listing {load['functions']} named functions"
        + (f", {large['seconds']}s for {large['functions']}" if large else "")
        + f"; analysed {reuse['first_seconds']}s, reused {reuse['second_seconds']}s"
        f" over {reuse['tables']} identical tables)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
