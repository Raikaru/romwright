#!/usr/bin/env bash
# Builds and installs the RSP (N64 Reality Signal Processor) language.
#
# Compiles native/languages/rsp/rsp.slaspec -> rsp.sla with the pinned
# sleigh compiler, then copies the extension files into
#   $GHIDRA/Ghidra/Extensions/RSP/data/languages/
# so `architecture::discover` resolves RSP:BE:32:default like the other
# extension languages (GameCubeLoader, PsxLoader).
#
# Usage: native/languages/rsp/install.sh [GHIDRA_INSTALL_DIR]
#   default: $VENTRIS_GHIDRA or ~/ghidra_12.1.3_PUBLIC
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
SRC="$ROOT/native/languages/rsp"
GHIDRA="${1:-${VENTRIS_GHIDRA:-$HOME/ghidra_12.1.3_PUBLIC}}"
SLEIGH="$GHIDRA/Ghidra/Features/Decompiler/os/linux_x86_64/sleigh"
DEST="$GHIDRA/Ghidra/Extensions/RSP/data/languages"

[ -x "$SLEIGH" ] || { echo "no sleigh compiler at $SLEIGH" >&2; exit 1; }

"$SLEIGH" "$SRC/rsp.slaspec" "$SRC/rsp.sla"
mkdir -p "$DEST"
cp "$SRC/rsp.sla" "$SRC/rsp.ldefs" "$SRC/rsp.pspec" "$SRC/rsp.cspec" "$DEST/"
echo "installed RSP:BE:32:default -> $DEST"
