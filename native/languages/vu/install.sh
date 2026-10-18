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

# The build itself is packaging/languages.py (Python, so the same code runs on
# Windows, Linux and macOS; `python setup.py` and the release workflow call it
# for all languages at once). This script installs VU:LE:64:micro alone, always
# recompiling, into GHIDRA_INSTALL_DIR (a full Ghidra install, whose own sleigh
# compiler is used, or the data directory `setup.py` made).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
GHIDRA="${1:-${ROMWRIGHT_GHIDRA:-$HOME/ghidra_12.1.3_PUBLIC}}"
exec "${PYTHON:-python3}" "$ROOT/packaging/languages.py" --ghidra "$GHIDRA" --only vu --force
