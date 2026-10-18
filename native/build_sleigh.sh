#!/usr/bin/env bash
# Builds the SLEIGH language compiler (`sleigh_opt`) from the pinned, unmodified
# Ghidra 12.1.3 decompiler sources in third_party/ghidra/decompiler.
#
# packaging/languages.py compiles romwright's own languages (native/languages/*)
# with the `sleigh` binary the Ghidra release ships, which exists only for
# linux_x86_64 and win_x86_64. On any other host (macOS, Linux on ARM) it runs
# this script instead; the .sla it produces is the one the shipped compiler does
# (the grammar sources are the same release, and the generated parsers are
# committed with them: no bison or flex is needed).
#
# Usage: native/build_sleigh.sh [--jobs N] [OUTDIR]
#   OUTDIR default: native/build; produces OUTDIR/sleigh_opt
#   TMPDIR controls the scratch directory and the build log (default: /tmp).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
JOBS=1
OUT="$ROOT/native/build"
while [ "${1:-}" != "" ]; do
    case "$1" in
        --jobs) JOBS="$2"; shift 2 ;;
        *) OUT="$1"; shift ;;
    esac
done

BUILD=$(mktemp -d "${TMPDIR:-/tmp}/sleigh-opt-build.XXXXXX")
trap 'rm -rf "$BUILD"' EXIT
cp -r "$ROOT/third_party/ghidra/decompiler" "$BUILD/decompiler"
cd "$BUILD/decompiler"
# The generated parsers are committed with their grammars. A fresh checkout or a
# copy gives the files timestamps in arbitrary order, and make then runs bison
# or flex (not required, often absent) for a parser that looks older than its
# grammar. Touch the generated files, in dependency order, so they never do.
touch slghparse.cc slghparse.hh slghscan.cc grammar.cc xml.cc pcodeparse.cc


MAKE_BIN="${MAKE:-make}"
if ! command -v "$MAKE_BIN" > /dev/null 2>&1 && command -v mingw32-make > /dev/null 2>&1; then
    MAKE_BIN=mingw32-make
fi
MAKE_ARGS=()
EXE=""
case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*)
        MAKE_ARGS=(ADDITIONAL_FLAGS=-D_WINDOWS MAKE_STATIC=-static)
        EXE=".exe"
        ;;
esac
LOG="${TMPDIR:-/tmp}/sleigh-opt-build.log"
if ! "$MAKE_BIN" sleigh_opt -j"$JOBS" ${MAKE_ARGS[@]+"${MAKE_ARGS[@]}"} > "$LOG" 2>&1; then
    tail -40 "$LOG" >&2
    echo "sleigh_opt build failed; full log: $LOG" >&2
    exit 1
fi
mkdir -p "$OUT"
TEMP_BINARY=$(mktemp "$OUT/.sleigh_opt.XXXXXX")
trap 'rm -rf "$BUILD"; rm -f "$TEMP_BINARY"' EXIT
cp -p "sleigh_opt$EXE" "$TEMP_BINARY"
mv -f "$TEMP_BINARY" "$OUT/sleigh_opt$EXE"
echo "built: $OUT/sleigh_opt$EXE"
