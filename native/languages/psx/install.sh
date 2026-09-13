#!/usr/bin/env bash
# Builds and installs the romwright PSX language — the PsxLoader MIPS spec
# plus a GTE command fallback that lifts every known cop2 command to a
# named pcodeop (gte_rtps, gte_mvmva, ...) regardless of flag bits.
#
# Compiles native/languages/psx/mips32le.slaspec -> mips32le.sla with the
# pinned sleigh compiler, then copies the extension files into
#   $GHIDRA/Ghidra/Extensions/PsxLoader/data/languages/
# replacing the stock sla so PSX:LE:32:default resolves to the patched one.
#
# Usage: native/languages/psx/install.sh [GHIDRA_INSTALL_DIR]
#   default: $ROMWRIGHT_GHIDRA or ~/ghidra_12.1.3_PUBLIC
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
SRC="$ROOT/native/languages/psx"
GHIDRA="${1:-${ROMWRIGHT_GHIDRA:-$HOME/ghidra_12.1.3_PUBLIC}}"
SLEIGH="$GHIDRA/Ghidra/Features/Decompiler/os/linux_x86_64/sleigh"
DEST="$GHIDRA/Ghidra/Extensions/PsxLoader/data/languages"

[ -x "$SLEIGH" ] || { echo "no sleigh compiler at $SLEIGH" >&2; exit 1; }

"$SLEIGH" "$SRC/mips32le.slaspec" "$SRC/mips32le.sla"
mkdir -p "$DEST"
cp "$SRC/mips32le.sla" "$DEST/"
echo "installed PSX:LE:32:default (GTE-named) -> $DEST"
