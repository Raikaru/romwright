#!/usr/bin/env bash
# Builds the pinned SLEIGH console (`decomp_opt` in the decompiler Makefile;
# EXECS line): the interactive console behind `disasm` and
# `import --discover`.
#
# The pinned third_party/ghidra tree is NEVER modified in place; this script
# copies the decompiler sources aside and applies ghidra-opt-sleigh.patch.
# The console loads languages via `-s DIR` + SLEIGHHOME.
#
# Prerequisite: binutils-devel (bfd.h) — the console links the BFD load
# image, matching the pinned decompiler Makefile's requirement.
#
# Usage: native/build_console.sh [--jobs N] [OUTDIR]
#   OUTDIR default: native/build; produces OUTDIR/decomp_native
#   runtime: ROMWRIGHT_CONSOLE=$OUTDIR/decomp_native
#   TMPDIR controls scratch directories and the build log (default: /tmp).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PATCH="$ROOT/native/ghidra-opt-sleigh.patch"
if [ ! -r /usr/include/bfd.h ]; then
    echo "missing bfd.h — the console links the BFD load image." >&2
    echo "install binutils-devel (dnf: 'sudo dnf install binutils-devel';" >&2
    echo "apt: 'sudo apt install binutils-dev'), then re-run." >&2
    exit 1
fi

JOBS=1
OUT="$ROOT/native/build"
while [ "${1:-}" != "" ]; do
    case "$1" in
        --jobs) JOBS="$2"; shift 2 ;;
        *) OUT="$1"; shift ;;
    esac
done

BUILD=$(mktemp -d "${TMPDIR:-/tmp}/ghidra-console-build.XXXXXX")
trap 'rm -rf "$BUILD"' EXIT
cp -r "$ROOT/third_party/ghidra/decompiler" "$BUILD/decompiler"
cp "$ROOT/native/romwright_linkage.hh" "$ROOT/native/romwright_patterns.hh" \
   "$ROOT/native/romwright_flow.hh" "$ROOT/native/romwright_pcode.hh" "$ROOT/native/romwright_constant_state.hh" \
   "$ROOT/native/romwright_operand_refs.hh" \
   "$ROOT/native/romwright_x86_references.hh" \
   "$ROOT/native/romwright_callfixups.hh" \
   "$ROOT/native/romwright_ir_state.hh" "$ROOT/native/romwright_parent.hh" \
   "$ROOT/native/romwright_constants.hh" "$BUILD/decompiler/"
cp "$PATCH" "$BUILD/apply.patch"
git -C "$BUILD" init -q
git -C "$BUILD" add -A
git -C "$BUILD" apply --whitespace=nowarn --ignore-space-change "$BUILD/apply.patch"

cd "$BUILD/decompiler"
# Fedora's libbfd (binutils 2.4x) pulls in zstd for compressed sections;
# the pinned Makefile's LNK only carries -lz. Command-line override appends
# it without touching the pinned tree.
make decomp_opt -j"$JOBS" LNK="-lz -lzstd" > "${TMPDIR:-/tmp}/ghidra-console-build.log" 2>&1
mkdir -p "$OUT"
TEMP_BINARY=$(mktemp "$OUT/.decomp_native.XXXXXX")
trap 'rm -rf "$BUILD"; rm -f "$TEMP_BINARY"' EXIT
cp -p decomp_opt "$TEMP_BINARY"
mv -f "$TEMP_BINARY" "$OUT/decomp_native"
echo "built: $OUT/decomp_native"
echo "runtime: ROMWRIGHT_CONSOLE=$OUT/decomp_native"
