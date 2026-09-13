#!/usr/bin/env bash
# Required JVM-free consumer workflow: open -> browse -> follow ->
# decompile -> xref -> rename -> undo -> reopen.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${1:-$ROOT/tests/fixtures-src/tiny_bin}"
PROJECT="${2:-$(mktemp -d /tmp/romwright-workflow.XXXXXX)}"
CLI="${CLI:-$ROOT/target/release/romwright-cli}"
ADDR="${ADDR:-00400466}"

[ -x "$CLI" ] || { echo "missing $CLI — cargo build --release -p romwright-cli" >&2; exit 1; }
[ -x "${ROMWRIGHT_GHIDRA_OPT:-$ROOT/native/build/ghidra_opt}" ] || {
    echo "missing native decompiler — build native/build_ghidra_opt.sh" >&2
    exit 1
}
[ -x "${ROMWRIGHT_WORKER:-$ROOT/target/release/romwright-worker}" ] || {
    echo "missing romwright-worker — cargo build --release -p romwright-worker" >&2
    exit 1
}
[ -n "${ROMWRIGHT_SLA:-}" ] || { echo "set ROMWRIGHT_SLA to x86-64.sla" >&2; exit 1; }

export ROMWRIGHT_GHIDRA_OPT="${ROMWRIGHT_GHIDRA_OPT:-$ROOT/native/build/ghidra_opt}"
export ROMWRIGHT_WORKER="${ROMWRIGHT_WORKER:-$ROOT/target/release/romwright-worker}"
export ROMWRIGHT_SPECS="${ROMWRIGHT_SPECS:-$ROOT/native/specs}"

rm -rf "$PROJECT"
mkdir -p "$PROJECT"

"$CLI" import "$BIN" --name workflow --project "$PROJECT" > "$PROJECT/import.out"
"$CLI" functions workflow --project "$PROJECT" > "$PROJECT/functions.out"
"$CLI" xrefs workflow --to "$ADDR" --project "$PROJECT" > "$PROJECT/xrefs.out"
"$CLI" decompile-doc "$BIN" "$ADDR" --name workflow --project "$PROJECT" \
    > "$PROJECT/decompile.json"

python3 - "$PROJECT/decompile.json" "$PROJECT/functions.out" <<'PY'
import json
import pathlib
import sys

doc = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert doc["address"]["offset"] == int("400466", 16)
assert doc["tokens"], "structured decompiler document was empty"
functions = pathlib.Path(sys.argv[2]).read_text()
assert "add" in functions or "main" in functions, functions
PY

"$CLI" rename workflow "$ADDR" workflow_renamed --project "$PROJECT" > "$PROJECT/rename.out"
"$CLI" functions workflow --project "$PROJECT" > "$PROJECT/functions_renamed.out"
python3 - "$PROJECT/functions_renamed.out" <<'PY'
import pathlib
import sys
assert "workflow_renamed" in pathlib.Path(sys.argv[1]).read_text()
PY
"$CLI" undo workflow --project "$PROJECT" > "$PROJECT/undo_rename.out"
"$CLI" functions workflow --project "$PROJECT" > "$PROJECT/functions_undo.out"
python3 - "$PROJECT/functions_undo.out" <<'PY'
import pathlib
import sys
assert "workflow_renamed" not in pathlib.Path(sys.argv[1]).read_text()
PY

"$CLI" comment workflow "$ADDR" "workflow comment" --project "$PROJECT" > "$PROJECT/comment.out"
"$CLI" undo workflow --project "$PROJECT" > "$PROJECT/undo_comment.out"
"$CLI" open workflow --project "$PROJECT" > "$PROJECT/open.out"
"$CLI" open workflow --project "$PROJECT" > "$PROJECT/reopen.out"

echo "workflow gate passed: $PROJECT"
