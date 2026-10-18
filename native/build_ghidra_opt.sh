#!/usr/bin/env bash
# Builds the out-of-tree `ghidra_opt` with the raw-SLEIGH translator hook.
#
# The pinned third_party/ghidra tree is NEVER modified in place; this script
# copies the decompiler sources aside, applies native/ghidra-opt-sleigh.patch,
# and builds. At runtime, when the worker sets ROMWRIGHT_SLA to a compiled
# .sla, the binary self-disassembles (Sleigh translator) instead of asking
# the client for per-instruction pcode — closing the getPcode gap for the
# JVM-free worker path (see STATUS.md, stages/notes).
#
# Usage: native/build_ghidra_opt.sh [--jobs N] [OUTDIR]
#   OUTDIR default: native/build; produces OUTDIR/ghidra_opt
#   TMPDIR controls scratch directories and the build log (default: /tmp).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PATCH="$ROOT/native/ghidra-opt-sleigh.patch"
JOBS=1
OUT="$ROOT/native/build"
while [ "${1:-}" != "" ]; do
    case "$1" in
        --jobs) JOBS="$2"; shift 2 ;;
        *) OUT="$1"; shift ;;
    esac
done

BUILD=$(mktemp -d "${TMPDIR:-/tmp}/ghidra-opt-build.XXXXXX")
trap 'rm -rf "$BUILD"' EXIT
cp -r "$ROOT/third_party/ghidra/decompiler" "$BUILD/decompiler"
cp "$ROOT"/native/romwright_*.hh "$BUILD/decompiler/"

cp "$PATCH" "$BUILD/apply.patch"
git -C "$BUILD" init -q
git -C "$BUILD" add -A
git -C "$BUILD" apply --whitespace=nowarn --ignore-space-change "$BUILD/apply.patch"

cd "$BUILD/decompiler"
# Windows (MSYS2 MinGW-w64): Ghidra's sources select their Windows paths
# (binary-mode stdio, Win32 directory listing) on _WINDOWS, and a static link
# keeps the binary free of the MinGW runtime DLLs. The product is ghidra_opt.exe.
MAKE_ARGS=()
EXE=""
WINDOWS=""
case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*)
        MAKE_ARGS=(ADDITIONAL_FLAGS=-D_WINDOWS MAKE_STATIC=-static)
        EXE=".exe"
        WINDOWS=1
        ;;
esac
MAKE_BIN="${MAKE:-make}"
if ! command -v "$MAKE_BIN" > /dev/null 2>&1 && command -v mingw32-make > /dev/null 2>&1; then
    MAKE_BIN=mingw32-make
fi
"$MAKE_BIN" ghidra_opt -j"$JOBS" ${MAKE_ARGS[@]+"${MAKE_ARGS[@]}"} > "${TMPDIR:-/tmp}/ghidra-opt-build.log" 2>&1
# Exercise the shipped hash codec, including legacy and SIMD-sized collision sets.
if [ -n "$WINDOWS" ]; then
    # PE/COFF section GC does not drop dynamic.cc's unreferenced functions
    # before symbol resolution, so resolve them from an archive of the
    # decompiler's own objects: the linker pulls only the members it needs.
    HASH_LINK=()
    for object in ghi_opt/*.o; do
        [ "$object" = ghi_opt/dynamic.o ] || HASH_LINK+=("$object")
    done
    ar rcs "$BUILD/libghidra_opt.a" "${HASH_LINK[@]}"
    c++ -std=c++11 -O2 -D_WINDOWS -static -I. \
        dynamic.cc "$ROOT/native/dynamic_hash_test.cc" "$BUILD/libghidra_opt.a" -lz -o "$BUILD/hash-test$EXE"
else
    GC_SECTIONS="-Wl,--gc-sections"
    if [ "$(uname -s)" = Darwin ]; then GC_SECTIONS="-Wl,-dead_strip"; fi
    c++ -std=c++11 -O2 -ffunction-sections -fdata-sections -I. \
        dynamic.cc "$ROOT/native/dynamic_hash_test.cc" "$GC_SECTIONS" -o "$BUILD/hash-test$EXE"
fi
"$BUILD/hash-test$EXE"
mkdir -p "$OUT"
TEMP_BINARY=$(mktemp "$OUT/.ghidra_opt.XXXXXX")
trap 'rm -rf "$BUILD"; rm -f "$TEMP_BINARY"' EXIT
cp -p "ghidra_opt$EXE" "$TEMP_BINARY"
mv -f "$TEMP_BINARY" "$OUT/ghidra_opt$EXE"
echo "built: $OUT/ghidra_opt$EXE"
echo "runtime: ROMWRIGHT_SLA=/path/to/x86-64.sla $OUT/ghidra_opt$EXE"
