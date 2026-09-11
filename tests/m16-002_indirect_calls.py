#!/usr/bin/env python3
"""m16-002: type-guided pruning of indirect-call candidates.

Manta's observation is that a `call *reg` whose argument registers are
already set constrains the callee's signature: a function that takes a
float where the site passes an integer, or two parameters where the site
sets one, cannot be the callee. The candidate pool is every address-taken
function -- an initializer slot or a code-immediate reference that names
a function entry -- and the pruned set is the pool minus the functions
whose recovered signature is incompatible with the site's.

The fixture is `indirect_calls.c`: a global table of five functions with
different signatures, called through `ops[index % 5]` at two sites that
set different argument counts. The true callee at `call_one` is any of
the one-parameter functions; at `call_two` it is `two_ints`. The gate
scores the pruned set two ways:

* **Recall** -- every signature-compatible pool member survives. A
  pruning that drops a compatible callee is wrong, whatever else it
  removed.
* **Precision** -- the pruned set is smaller than the pool. A pruning
  that keeps everything is not wrong, but it is not the task either.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "benchmarks"))
from dwarf_types import extract  # noqa: E402

CLI = ROOT / "target/release/lre-cli"
FIXTURE = ROOT / "tests/fixtures-src/indirect_calls.c"
LEVELS = ("O0", "O2")

# The pool is the table's five entries. At `call_one` the site sets one
# integer argument and reads an integer result: `one_int`, `one_int_void`
# (void is compatible -- the site may ignore a result), and `no_args`
# (fewer parameters is compatible -- extra arguments are ignored) survive;
# `two_ints` (needs a second argument the site does not set) and
# `one_double` (float where the site passes an integer) do not.
COMPATIBLE_ONE = {"one_int", "one_int_void", "no_args"}
# At `call_two` the site sets two integer arguments: only `two_ints`
# survives.
COMPATIBLE_TWO = {"two_ints"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    arguments = parser.parse_args()
    environment = os.environ.copy()
    environment.setdefault("VENTRIS_CONSOLE", str(ROOT / "native/build/decomp_native"))
    environment["VENTRIS_NO_IMPORT_CACHE"] = "1"
    subprocess.run(["cargo", "build", "-q", "--release", "-p", "lre-cli"], cwd=ROOT, check=True)

    report = {
        "gate": "m16-002",
        "milestone": "M16",
        "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT,
                                          text=True).strip(),
        "date": datetime.now(timezone.utc).date().isoformat(),
        "machine": {"os": platform.platform(), "cpu": platform.machine()},
        "levels": [],
    }
    failures = []

    with tempfile.TemporaryDirectory(prefix="m16-002-") as temporary:
        work = Path(temporary)
        for level in LEVELS:
            unstripped = work / f"indirect.{level}"
            stripped = work / f"indirect.{level}.stripped"
            build = subprocess.run(
                ["gcc", f"-{level}", "-g", "-fno-inline", "-o", str(unstripped), str(FIXTURE)],
                capture_output=True, text=True, timeout=300)
            if build.returncode:
                raise SystemExit(f"fixture build failed: {build.stderr[-500:]}")
            subprocess.run(["objcopy", "--strip-debug", str(unstripped), str(stripped)],
                           check=True, timeout=120)
            truth = extract(unstripped)["functions"]
            by_name = {row["name"]: entry for entry, row in truth.items() if row["name"]}
            # The pool and kept sets are hex strings; the truth's entries
            # are zero-padded. Normalize both to bare hex.
            def norm(address):
                return format(int(address, 16), "x")

            for name in ("call_one", "call_two", "one_int", "two_ints",
                         "one_int_void", "one_double", "no_args"):
                if name not in by_name:
                    raise SystemExit(f"{level}: fixture truth missing {name}")

            project = work / f"project-{level}"
            subprocess.run([str(CLI), "import", str(stripped), "--project", str(project),
                            "--name", "indirect", "--no-analysis"],
                           cwd=ROOT, env=environment, check=True, capture_output=True,
                           timeout=600)

            for caller, compatible in (("call_one", COMPATIBLE_ONE),
                                       ("call_two", COMPATIBLE_TWO)):
                result = subprocess.run(
                    [str(CLI), "prune-indirect-calls", str(stripped), "indirect",
                     by_name[caller], "--project", str(project), "--json"],
                    cwd=ROOT, env=environment, capture_output=True, text=True, timeout=600)
                if result.returncode:
                    raise SystemExit(f"prune failed: {result.stderr[-500:]}")
                rows = [json.loads(line) for line in result.stdout.splitlines()
                        if line.startswith("{")]
                if not rows:
                    failures.append(f"{level} {caller}: no call site answered")
                    continue
                site = rows[0]
                pool = {norm(a) for a in site.get("candidates", [])}
                kept = {norm(a) for a in site.get("kept", [])}
                # The pool must name the five table entries.
                expected_pool = {norm(by_name[name]) for name in
                                 ("one_int", "two_ints", "one_int_void",
                                  "one_double", "no_args")}
                missing_pool = expected_pool - pool
                if missing_pool:
                    failures.append(
                        f"{level} {caller}: pool missing {sorted(missing_pool)}")
                # Every compatible member must survive.
                expected_kept = {norm(by_name[name]) for name in compatible}
                dropped = expected_kept - kept
                if dropped:
                    failures.append(
                        f"{level} {caller}: compatible callees pruned: {sorted(dropped)}")
                # And the incompatible members must be gone: at `call_one`
                # the site sets one integer argument, so `two_ints` (needs
                # two) and `one_double` (float) are out; at `call_two` the
                # site sets two, so `one_double` is out.
                incompatible = expected_pool - expected_kept
                still_kept = incompatible & kept
                if still_kept:
                    failures.append(
                        f"{level} {caller}: incompatible callees kept: {sorted(still_kept)}")
                if len(kept) >= len(pool):
                    failures.append(
                        f"{level} {caller}: nothing pruned ({len(kept)} of {len(pool)})")
                report["levels"].append({
                    "level": level,
                    "caller": caller,
                    "site": site.get("site"),
                    "pool": len(pool),
                    "kept": len(kept),
                    "dropped_compatible": sorted(dropped),
                })

    report["failures"] = failures
    arguments.report.parent.mkdir(parents=True, exist_ok=True)
    arguments.report.write_text(json.dumps(report, indent=2) + "\n")
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}", file=sys.stderr)
        raise SystemExit(1)
    for level in report["levels"]:
        print(f"{level['level']} {level['caller']}: site {level['site']} "
              f"kept {level['kept']} of {level['pool']}")


if __name__ == "__main__":
    main()
