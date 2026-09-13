#!/usr/bin/env bash
# Builds and installs the PS2 VU micro-mode language.
#
# Compiles native/languages/vu/vu.slaspec -> vu.sla with the pinned
# sleigh compiler, then copies the extension files into
#   $GHIDRA/Ghidra/Extensions/VU/data/languages/
# so `architecture::discover` resolves VU:LE:64:micro.
#
# Usage: native/languages/vu/install.sh [GHIDRA_INSTALL_DIR]
#   default: $ROMWRIGHT_GHIDRA or ~/ghidra_12.1.3_PUBLIC
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
SRC="$ROOT/native/languages/vu"
GHIDRA="${1:-${ROMWRIGHT_GHIDRA:-$HOME/ghidra_12.1.3_PUBLIC}}"
SLEIGH="$GHIDRA/Ghidra/Features/Decompiler/os/linux_x86_64/sleigh"
DEST="$GHIDRA/Ghidra/Extensions/VU/data/languages"

[ -x "$SLEIGH" ] || { echo "no sleigh compiler at $SLEIGH" >&2; exit 1; }

"$SLEIGH" "$SRC/vu.slaspec" "$SRC/vu.sla"
mkdir -p "$DEST"
cp "$SRC/vu.sla" "$SRC/vu.ldefs" "$SRC/vu.pspec" "$SRC/vu.cspec" "$DEST/"
echo "installed VU:LE:64:micro -> $DEST"
