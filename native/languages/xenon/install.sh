#!/usr/bin/env bash
# Builds and installs the Xbox 360 Xenon language (PowerPC A2 + VMX128).
#
# xenon.slaspec includes the stock PowerPC sincs; those live in the Ghidra
# install, so this script symlinks them into the source dir before compiling
# (they are not committed — absolute paths differ per machine). The two
# xenon-local copies (ppc_common_vmx.sinc, altivec_xenon.sinc) carry the
# VMX128 token fields and drop the ISA-3.0 ops that collide with VMX128.
#
# Usage: native/languages/xenon/install.sh [GHIDRA_INSTALL_DIR]
#   default: $ROMWRIGHT_GHIDRA or ~/ghidra_12.1.3_PUBLIC
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
SRC="$ROOT/native/languages/xenon"
GHIDRA="${1:-${ROMWRIGHT_GHIDRA:-$HOME/ghidra_12.1.3_PUBLIC}}"
PPC="$GHIDRA/Ghidra/Processors/PowerPC/data/languages"
SLEIGH="$GHIDRA/Ghidra/Features/Decompiler/os/linux_x86_64/sleigh"
DEST="$GHIDRA/Ghidra/Extensions/Xenon/data/languages"

[ -x "$SLEIGH" ] || { echo "no sleigh compiler at $SLEIGH" >&2; exit 1; }
[ -d "$PPC" ] || { echo "no PowerPC languages at $PPC" >&2; exit 1; }

# Symlink the stock sincs xenon.slaspec includes (idempotent).
for f in ppc_isa.sinc ppc_a2.sinc quicciii.sinc FPRC.sinc \
         ppc_instructions.sinc ppc_common.sinc ppc_embedded.sinc \
         4xx.sinc evx.sinc g2.sinc lmwInstructions.sinc lswInstructions.sinc \
         mulhwInstructions.sinc ppc_vle.sinc SPE_APU.sinc SPE_EFSD.sinc \
         SPE_EFV.sinc SPE_FloatMulAdd.sinc SPEF_SCR.sinc Scalar_SPFP.sinc \
         stmwInstructions.sinc stswiInstructions.sinc vsx.sinc altivec.sinc; do
  [ -e "$SRC/$f" ] || ln -s "$PPC/$f" "$SRC/$f"
done

"$SLEIGH" "$SRC/xenon.slaspec" "$SRC/xenon.sla"
mkdir -p "$DEST"
cp "$SRC/xenon.sla" "$SRC/xenon.ldefs" "$SRC/ppc_64.pspec" "$SRC/ppc_64_be.cspec" "$DEST/"
echo "installed PowerPC:BE:64:Xenon-32addr -> $DEST"
