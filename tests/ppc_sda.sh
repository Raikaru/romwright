#!/usr/bin/env bash
# PPC r13 SDA regression: a synthetic PowerPC32 binary whose only function
# loads a word through r13 must decompile to the OBJECT name, not a raw
# r13-relative dereference. Covers the #325 slice: OBJECT symbols through
# the store, `_SDA_BASE_` into tracked r13, one tracked_set per range --
# and the console path: the import must report no degraded stage, proving
# the reference console loaded the image (r13 rows are not console
# context variables).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROJECT="${1:-$(mktemp -d /tmp/romwright-ppc-sda.XXXXXX)}"
CLI="${CLI:-$ROOT/target/release/romwright-cli}"

[ -x "$CLI" ] || { echo "missing $CLI — cargo build --release -p romwright-cli" >&2; exit 1; }
[ -x "${ROMWRIGHT_GHIDRA_OPT:-$ROOT/native/build/ghidra_opt}" ] || {
    echo "missing native decompiler — build native/build_ghidra_opt.sh" >&2
    exit 1
}
[ -x "${ROMWRIGHT_CONSOLE:-$ROOT/native/build/decomp_native}" ] || {
    echo "missing reference console — build native/build_console.sh" >&2
    exit 1
}
[ -x "${ROMWRIGHT_WORKER:-$ROOT/target/release/romwright-worker}" ] || {
    echo "missing romwright-worker — cargo build --release -p romwright-worker" >&2
    exit 1
}

export ROMWRIGHT_GHIDRA_OPT="${ROMWRIGHT_GHIDRA_OPT:-$ROOT/native/build/ghidra_opt}"
export ROMWRIGHT_WORKER="${ROMWRIGHT_WORKER:-$ROOT/target/release/romwright-worker}"
export ROMWRIGHT_SPECS="${ROMWRIGHT_SPECS:-$ROOT/native/specs}"

rm -rf "$PROJECT"
mkdir -p "$PROJECT"

python3 "$ROOT/tests/fixtures-src/ppc_sda.py" "$PROJECT/ppc_sda_bin" > /dev/null
"$CLI" import "$PROJECT/ppc_sda_bin" --name sda --project "$PROJECT" --timings > "$PROJECT/import.out"
"$CLI" decompile "$PROJECT/ppc_sda_bin" 10000 --name sda --project "$PROJECT" \
    > "$PROJECT/decompile.out"

python3 - "$PROJECT/import.out" "$PROJECT/decompile.out" <<'PY'
import pathlib
import sys

import_out = pathlib.Path(sys.argv[1]).read_text()
assert "\"degraded\"" not in import_out, import_out
out = pathlib.Path(sys.argv[2]).read_text()
assert "HadError" in out, out
assert "unaff_r13" not in out, out
assert "r13 +" not in out, out
PY

echo "ppc sda gate passed: $PROJECT"
