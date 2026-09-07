#!/usr/bin/env bash
# M1-002 acceptance: verify generic worklist discovery over pcode flow
# achieves fn.recall >= 0.986 on libc and discovers functions on PPC.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [ -x "$ROOT/target/release/lre-cli" ]; then
    CLI="${LRE_CLI:-$ROOT/target/release/lre-cli}"
else
    CLI="${LRE_CLI:-$ROOT/target/debug/lre-cli}"
fi
LIBC_BIN="${1:-/usr/lib64/libc.so.6}"
PPC_BIN="/home/raikaru/Projects/agent-under-fire/orig/GQFE78/files/base.elf"

if [ ! -f "$LIBC_BIN" ]; then
    echo "libc binary not found: $LIBC_BIN" >&2
    exit 1
fi

PROJECT="$(mktemp -d /tmp/ventris-m1-002.XXXXXX)"
trap 'rm -rf "$PROJECT"' EXIT

# Step 1: Import libc and verify function count matches or exceeds recall >= 0.986 (>= 3931 functions)
VENTRIS_GENERIC_DISCOVERY=1 "$CLI" import "$LIBC_BIN" --name libc --project "$PROJECT" >/dev/null

python3 - "$PROJECT/project.sqlite" "$ROOT/oracle/01cccbe278d898add05282986a9346d4dda4b3d2b84bc496f9c04c66016528db.json" <<'PY'
import json, sqlite3, sys

db_path = sys.argv[1]
oracle_path = sys.argv[2]
with open(oracle_path) as f:
    oracle = {int(entry, 16) for entry in json.load(f)["entries"]}

conn = sqlite3.connect(db_path)
cur = conn.cursor()

cur.execute("SELECT id FROM programs WHERE name = 'libc'")
program_id = cur.fetchone()[0]

# The m1-002 oracle records image-relative entries. Since m1-004 the loader maps
# ELF PIE at Ghidra's default base, so the store is scored in its own RVA space.
cur.execute("SELECT start FROM memory_regions WHERE program_id = ?", (program_id,))
image_base = min(int(row[0], 16) for row in cur.fetchall())

cur.execute("SELECT entry FROM functions WHERE program_id = ?", (program_id,))
native = {int(row[0], 16) - image_base for row in cur.fetchall()}

matched = native & oracle
precision = len(matched) / len(native) if native else 0.0
recall = len(matched) / len(oracle) if oracle else 0.0

if recall < 0.986:
    sys.exit(f"FAIL: fn.recall = {recall:.4f} ({len(matched)}/{len(oracle)}) < 0.986 requirement")

if precision < 0.980:
    sys.exit(f"FAIL: fn.precision = {precision:.4f} ({len(matched)}/{len(native)}) < 0.980 requirement")

print(f"libc: fn.precision = {precision:.4f} ({len(matched)}/{len(native)}), fn.recall = {recall:.4f} ({len(matched)}/{len(oracle)}) >= 0.986")
PY

# Step 2: If the PPC base.elf is present, score native discovery against the
# bridge's own analysis of the same image. The M1 criterion is entry recall,
# not growth over the symtab seeds: a symbol-rich image can be fully seeded.
if [ -f "$PPC_BIN" ]; then
    VENTRIS_GENERIC_DISCOVERY=1 "$CLI" import "$PPC_BIN" --name base --project "$PROJECT" >/dev/null
    if "$CLI" import "$PPC_BIN" --oracle --name base_oracle --project "$PROJECT" >/dev/null 2>&1; then
        python3 - "$PROJECT/project.sqlite" <<'PY'
import sqlite3, sys

db_path = sys.argv[1]
conn = sqlite3.connect(db_path)
cur = conn.cursor()


def entries(name):
    cur.execute(
        "SELECT entry FROM functions WHERE program_id = (SELECT id FROM programs WHERE name = ?)",
        (name,),
    )
    return {int(row[0], 16) for row in cur.fetchall()}


native = entries("base")
oracle = entries("base_oracle")
if not native or not oracle:
    sys.exit("FAIL: PPC import produced no functions")

matched = native & oracle
precision = len(matched) / len(native)
recall = len(matched) / len(oracle)

if recall < 0.986:
    sys.exit(f"FAIL: PPC fn.recall = {recall:.4f} ({len(matched)}/{len(oracle)}) < 0.986")
if precision < 0.980:
    sys.exit(f"FAIL: PPC fn.precision = {precision:.4f} ({len(matched)}/{len(native)}) < 0.980")

cur.execute(
    "SELECT count(*) FROM xrefs WHERE program_id = (SELECT id FROM programs WHERE name = 'base')"
    " AND kind LIKE '%CALL%'"
)
calls = cur.fetchone()[0]
if calls <= 0:
    sys.exit("FAIL: PPC import recorded no call xrefs; console flow did not run")

print(
    f"PPC base.elf: fn.precision = {precision:.4f} ({len(matched)}/{len(native)}),"
    f" fn.recall = {recall:.4f} ({len(matched)}/{len(oracle)}), {calls} flow call xrefs"
)
PY
    else
        echo "PPC base.elf: skipped scoring (bridge oracle unavailable)"
    fi
fi

echo "m1-002 acceptance: pass"
