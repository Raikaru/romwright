# Sourced by native/build_ghidra_opt.sh and native/build_sleigh.sh on macOS.
#
# third_party/ghidra/decompiler/Makefile hard-codes `-arch x86_64` and
# `-mmacosx-version-min=10.6` for Darwin. That tree is pinned and must not be
# edited (tools/vendor_ghidra.py --verify), so the build overrides those two make
# variables on the command line for the architecture of the host instead: an
# Apple-silicon runner gets an arm64 binary, an Intel one an x86_64 binary.
#
# Sets DARWIN_MAKE_ARGS (an array). arm64 needs macOS 11.0 as its deployment
# target; the Makefile's 10.6 is not a target it supports.
host_darwin_make_args() {
    local machine
    machine="$(uname -m)"
    case "$machine" in
        arm64|aarch64)
            DARWIN_MAKE_ARGS=("ARCH_TYPE=-arch arm64" "ADDITIONAL_FLAGS=-mmacosx-version-min=11.0 -w")
            ;;
        x86_64)
            DARWIN_MAKE_ARGS=("ARCH_TYPE=-arch x86_64")
            ;;
        *)
            echo "error: unsupported macOS architecture '$machine' (expected arm64 or x86_64)" >&2
            return 1
            ;;
    esac
}
