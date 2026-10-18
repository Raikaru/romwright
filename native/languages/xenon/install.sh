#!/usr/bin/env bash
# Builds and installs the Xbox 360 Xenon language (PowerPC A2 + VMX128).
#
# xenon.slaspec includes the stock PowerPC sincs; those live in the Ghidra
# install, so the build copies them next to it before compiling. The two
# xenon-local copies (ppc_common_vmx.sinc, altivec_xenon.sinc) carry the
# VMX128 token fields and drop the ISA-3.0 ops that collide with VMX128.
#
# Usage: native/languages/xenon/install.sh [GHIDRA_INSTALL_DIR]
#   default: $ROMWRIGHT_GHIDRA or ~/ghidra_12.1.3_PUBLIC

# The build itself is packaging/languages.py (Python, so the same code runs on
# Windows, Linux and macOS; `python setup.py` and the release workflow call it
# for all languages at once). This script installs PowerPC:BE:64:Xenon-32addr alone, always
# recompiling, into GHIDRA_INSTALL_DIR (a full Ghidra install, whose own sleigh
# compiler is used, or the data directory `setup.py` made).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
GHIDRA="${1:-${ROMWRIGHT_GHIDRA:-$HOME/ghidra_12.1.3_PUBLIC}}"
exec "${PYTHON:-python3}" "$ROOT/packaging/languages.py" --ghidra "$GHIDRA" --only xenon --force
