#!/usr/bin/env bash
# Builds `ghidra_opt` with clang
# source-based coverage in continuous mode, for benchmarks/ownership.py.
#
# Same sources as native/build_ghidra_opt.sh: the
# pinned third_party/ghidra/decompiler tree, our headers, and
# native/ghidra-opt-sleigh.patch applied to a copy. Only the compiler and
# its flags differ. Continuous mode (`%c`) maps the counters onto the profile
# file, so a process the worker kills with SIGKILL still leaves its counts.
#
# The binaries record absolute source paths, so the build tree is persistent
# and llvm-cov must run with it at the same path. Build it where it will be
# read, or copy the whole OUT
# directory to the same absolute path on the machine that runs the images.
#
# Usage: benchmarks/ownership_build_coverage.sh [--jobs N] OUTDIR
#   produces OUTDIR/ghidra_opt and OUTDIR/src/decompiler
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PATCH="$ROOT/native/ghidra-opt-sleigh.patch"
JOBS=1
OUT=""
while [ "${1:-}" != "" ]; do
    case "$1" in
        --jobs) JOBS="$2"; shift 2 ;;
        *) OUT="$1"; shift ;;
    esac
done
[ -n "$OUT" ] || { echo "usage: $0 [--jobs N] OUTDIR" >&2; exit 2; }
OUT="$(mkdir -p "$OUT" && cd "$OUT" && pwd)"

SRC="$OUT/src"
rm -rf "$SRC"
mkdir -p "$SRC"
cp -r "$ROOT/third_party/ghidra/decompiler" "$SRC/decompiler"
# What build_ghidra_opt.sh copies; the patch includes only what the target needs.
cp "$ROOT"/native/romwright_*.hh "$SRC/decompiler/"
cp "$PATCH" "$SRC/apply.patch"
git -C "$SRC" init -q
git -C "$SRC" add -A
git -C "$SRC" apply --whitespace=nowarn --ignore-space-change "$SRC/apply.patch"

cd "$SRC/decompiler"
FLAGS="-O2 -Wall -Wno-sign-compare -Wno-c++11-narrowing -fprofile-instr-generate -fcoverage-mapping -mllvm -runtime-counter-relocation"
make ghidra_opt -j"$JOBS" CXX=clang++ OPT_CXXFLAGS="$FLAGS" > "$OUT/build-ghidra_opt.log" 2>&1
cp -p ghidra_opt "$OUT/ghidra_opt"
echo "built: $OUT/ghidra_opt (sources: $SRC/decompiler)"
