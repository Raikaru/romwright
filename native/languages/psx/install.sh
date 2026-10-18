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

# The build itself is packaging/languages.py (Python, so the same code runs on
# Windows, Linux and macOS; `python setup.py` and the release workflow call it
# for all languages at once). This script installs PSX:LE:32:default alone, always
# recompiling, into GHIDRA_INSTALL_DIR (a full Ghidra install, whose own sleigh
# compiler is used, or the data directory `setup.py` made).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
GHIDRA="${1:-${ROMWRIGHT_GHIDRA:-$HOME/ghidra_12.1.3_PUBLIC}}"
exec "${PYTHON:-python3}" "$ROOT/packaging/languages.py" --ghidra "$GHIDRA" --only psx --force
