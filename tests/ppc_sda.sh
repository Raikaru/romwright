#!/usr/bin/env bash
# PPC r13 SDA regression: a synthetic PowerPC32 binary whose only function
# loads a word through r13 must decompile to the OBJECT name, not a raw
# r13-relative dereference. Covers the #325 slice: OBJECT symbols through
# the store, `_SDA_BASE_` into tracked r13, one tracked_set per range.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROJECT="${1:-$(mktemp -d /tmp/ventris-ppc-sda.XXXXXX)}"
CLI="${CLI:-$ROOT/target/release/lre-cli}"

[ -x "$CLI" ] || { echo "missing $CLI — cargo build --release -p lre-cli" >&2; exit 1; }
[ -x "${VENTRIS_GHIDRA_OPT:-$ROOT/native/build/ghidra_opt}" ] || {
    echo "missing native decompiler — build native/build_ghidra_opt.sh" >&2
    exit 1
}
[ -x "${VENTRIS_WORKER:-$ROOT/target/release/lre-worker}" ] || {
    echo "missing lre-worker — cargo build --release -p lre-worker" >&2
    exit 1
}

export VENTRIS_GHIDRA_OPT="${VENTRIS_GHIDRA_OPT:-$ROOT/native/build/ghidra_opt}"
export VENTRIS_WORKER="${VENTRIS_WORKER:-$ROOT/target/release/lre-worker}"
export VENTRIS_SPECS="${VENTRIS_SPECS:-$ROOT/native/specs}"

rm -rf "$PROJECT"
mkdir -p "$PROJECT"

python3 "$ROOT/tests/fixtures-src/ppc_sda.py" "$PROJECT/ppc_sda_bin" > /dev/null
"$CLI" import "$PROJECT/ppc_sda_bin" --name sda --project "$PROJECT" > "$PROJECT/import.out"
"$CLI" decompile "$PROJECT/ppc_sda_bin" 10000 --name sda --project "$PROJECT" \
    > "$PROJECT/decompile.out"

python3 - "$PROJECT/decompile.out" <<'PY'
import pathlib
import sys

out = pathlib.Path(sys.argv[1]).read_text()
assert "HadError" in out, out
assert "unaff_r13" not in out, out
assert "r13 +" not in out, out
PY

echo "ppc sda gate passed: $PROJECT"
