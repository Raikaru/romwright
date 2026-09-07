#!/usr/bin/env bash
# m1-003-e acceptance: flow must stay batched, and closing libc's flow must
# stay inside 5.0 seconds.
#
# Rescoped at m2-016 (user-authorised). The budget was written when import
# was parse plus flow discovery and measured total wall time as a proxy for
# batching. Import has since gained reference inference, string sweeping,
# prototypes, switches, non-returning functions, thunks and RTTI, so total
# time stopped describing batched flow. The 5.0 s number is unchanged; it now
# reads the `flow` phase that `import --timings` measures, best of two runs so
# a busy host cannot fail it. The claim batching actually makes -- many
# instructions per console request -- is asserted directly and is independent
# of machine speed. The total pipeline is bounded by
# `tests/m2-016_import_budget.py`.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ ! -f /usr/lib64/libc.so.6 ]]; then
    echo "SKIP: /usr/lib64/libc.so.6 not present"
    exit 77
fi

BIN=/usr/lib64/libc.so.6
CONSOLE_PROJECT=/tmp/m1-003-batched-console
cargo build -q --release -p lre-cli --no-default-features
CONSOLE=target/release/lre-cli

# The build immediately above leaves the machine hot and busy, which is not
# what this gate measures: discard one run, then keep the best of three.
RUNS=()
for _ in 0 1 2 3; do
    rm -rf "$CONSOLE_PROJECT"
    LINE=$($CONSOLE import "$BIN" --name libc --project "$CONSOLE_PROJECT" --timings 2>/dev/null \
        | sed -n 's/^TIMINGS //p')
    if [[ -z "$LINE" ]]; then
        echo "FAIL: import --timings reported no phases" >&2
        exit 1
    fi
    RUNS+=("$LINE")
done
RUNS=("${RUNS[@]:1}")

python3 - "${RUNS[@]}" <<'PY'
import json
import sys

runs = [json.loads(argument) for argument in sys.argv[1:]]
flow = min(run["phases"]["flow"] for run in runs)
stats = runs[0]["flow"]
if not stats or not stats["requests"]:
    sys.exit("FAIL: the flow phase reported no console requests")

ratio = stats["instructions"] / stats["requests"]
print(f"console-path libc flow phase: {flow}s (best of {len(runs)}), "
      f"{stats['instructions']} instructions over {stats['requests']} console "
      f"requests = {ratio:.1f} per request")

# One request per instruction is the regression this gate exists to catch.
if ratio < 20.0:
    sys.exit(f"FAIL: flow issued one request per {ratio:.1f} instructions; batching is gone")
if flow >= 5.0:
    sys.exit(f"FAIL: batched flow took {flow}s >= 5.0s")
print(f"m1-003-e: PASS ({flow}s < 5.0s, {ratio:.1f} instructions per request)")
PY
