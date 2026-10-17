#!/usr/bin/env bash
# Builds and installs the romwright PSX language, PSX:LE:32:default.
#
# The language is Ghidra's pinned MIPS32 little-endian specification
# (third_party/ghidra/languages/mips, Apache-2.0) with stock-cop2.patch
# applied and gte.sinc, our own GTE/COP2 definitions written from psx-spx,
# added. Nothing here derives from a third-party PlayStation language
# module. The script stages the pinned stock files in a scratch directory,
# compiles psx.slaspec -> psx.sla with the pinned sleigh compiler, and
# installs the language as a Ghidra extension module
#   $GHIDRA/Ghidra/Extensions/RomwrightPsx/data/languages/
# (psx.ldefs psx.pspec psx.cspec psx.sla and its sources) where `architecture::discover`
# and the Ghidra JVM both find it.
#
# A PsxLoader extension from an older setup also registers
# PSX:LE:32:default; a duplicate id is ambiguous (Ghidra scans every .ldefs
# below the install), so its data/languages directory is moved to
# $GHIDRA/.romwright-replaced/PsxLoader-languages (kept, outside the scanned
# tree). Its loader jar is untouched and resolves our language by id.
#
# Usage: native/languages/psx/install.sh [GHIDRA_INSTALL_DIR]
#   default: $ROMWRIGHT_GHIDRA or ~/ghidra_12.1.3_PUBLIC
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
SRC="$ROOT/native/languages/psx"
STOCK="$ROOT/third_party/ghidra/languages/mips"
GHIDRA="${1:-${ROMWRIGHT_GHIDRA:-$HOME/ghidra_12.1.3_PUBLIC}}"
SLEIGH="$GHIDRA/Ghidra/Features/Decompiler/os/linux_x86_64/sleigh"
EXT="$GHIDRA/Ghidra/Extensions"
DEST="$EXT/RomwrightPsx/data/languages"

[ -x "$SLEIGH" ] || { echo "no sleigh compiler at $SLEIGH" >&2; exit 1; }

STAGE=$(mktemp -d "${TMPDIR:-/tmp}/romwright-psx.XXXXXX")
trap 'rm -rf "$STAGE"' EXIT
cp "$STOCK/mips.sinc" "$STOCK/mips32Instructions.sinc" "$STOCK/mipsfloat.sinc" "$STAGE/"
(cd "$STAGE" && git apply -p1 "$SRC/stock-cop2.patch")
cp "$SRC/gte.sinc" "$SRC/psx.slaspec" "$STAGE/"
"$SLEIGH" "$STAGE/psx.slaspec" "$STAGE/psx.sla"

PSXLOADER="$EXT/PsxLoader/data"
if [ -d "$PSXLOADER/languages" ]; then
    mkdir -p "$GHIDRA/.romwright-replaced"
    rm -rf "$GHIDRA/.romwright-replaced/PsxLoader-languages"
    mv "$PSXLOADER/languages" "$GHIDRA/.romwright-replaced/PsxLoader-languages"
fi
mkdir -p "$DEST"
# Ghidra's JVM only reads languages from a module: Module.manifest marks one
# and extension.properties names it.
: > "$EXT/RomwrightPsx/Module.manifest"
cat > "$EXT/RomwrightPsx/extension.properties" <<PROPS
name=RomwrightPsx
description=PlayStation R3000A language with GTE (COP2) definitions, built from Ghidra's MIPS32 spec and psx-spx
author=romwright
version=12.1.3
PROPS
# The JVM checks psx.sla against psx.slaspec and its includes (and would
# recompile it itself), so the staged sources install beside the sla.
cp "$STAGE/psx.sla" "$STAGE/psx.slaspec" "$STAGE/mips.sinc" "$STAGE/mips32Instructions.sinc" \
   "$STAGE/mipsfloat.sinc" "$STAGE/gte.sinc" "$SRC/psx.ldefs" "$SRC/psx.pspec" "$SRC/psx.cspec" "$DEST/"
echo "installed PSX:LE:32:default -> $DEST"
