# Cross-Compilation Toolchains

Pinned toolchain configuration for multi-architecture corpus generation (`m1-006`).

## Tool policy: what romwright ships, what generated projects fetch

romwright ships no compiler, assembler, linker or wrapper, and the romwright
binary never downloads one. Two separate mechanisms put tools in front of a
build:

* **Matching workspaces** (this section, `matching-run`, `match-source`) use
  installed, user-owned toolchain profiles. They are not a compiler-download
  service. Supply source/header inputs and target objects that you are entitled
  to use. Inputs default to private; mark them redistributable only when
  authorized. Compiler and declared tool bytes are never included in workspace
  exports. Bundles retain recipe paths, arguments and environment, so review
  metadata before sharing.
* **Generated projects** (`romwright-cli new-project`, see
  [new-project.md](new-project.md)) behave like decomp-toolkit's dtk-template: the
  project's own `configure.py` downloads its build tools by default, from a pinned
  manifest (`config/toolchain.json`: URL, sha256, version, license and provenance per
  tool; the table lives in `crates/romwright-core/src/new_project/toolchains.json` and is
  updated by editing data, not code). The sha256 is checked before anything is
  extracted or run, and a mismatch stops the build. Compilers named there (MWCC,
  ee-gcc) are proprietary third-party archives that romwright neither hosts nor
  licenses; the manifest records where each came from. A toolchain profile
  (`--toolchain FILE` or `config/toolchain.local.json`, the format below) overrides
  any tool, one by one, so a machine that already has its tools never downloads.

## User-owned matching profiles

A profile records the launcher hash, declared tool hashes, version command,
compiler flags and environment. `compile_arguments` are appended to
`recipe.arguments`; `version_arguments` are the complete version-query argv.
`{source}`, `{output}`, `{root}` and `{tool:NAME}` expand as argv operands,
not shell code. Declare required headers, wrappers and support files explicitly:
implicit external dependencies are not discovered automatically. A generated
project reads the same file: tools `compiler`, `as`, `ld`, `objcopy`, `objdump`,
`wibo` and `objdiff-cli` replace the manifest's; `recipe.compiler` and
`recipe.arguments` are the compiler launcher; `recipe.environment` is applied to
compiles; a `compile_arguments` template that has `{source}` replaces the
project's default compile command.

For MWCC with wibo and sjiswrap, the profile template is:

```text
{
  "name": "configured-MWCC",
  "recipe": {"compiler": "/local/wibo", "arguments": [], "environment": {}},
  "tools": {
    "compiler": {"path": "/local/mwcceppc.exe", "digest": ""},
    "sjiswrap": {"path": "/local/sjiswrap.exe", "digest": ""}
  },
  "compile_arguments": [
    "{tool:sjiswrap}", "{tool:compiler}", "-nodefaults", "-proc", "gekko",
    "-O4,p", "-enum", "int", "-nosyspath", "-c", "{source}", "-o", "{output}"
  ],
  "version_arguments": ["{tool:compiler}", "-version"]
}
```

Setup fills the empty hashes from local files. Use the project's actual flags
and include inputs, not this illustrative profile, when reproducing a game
build. Profiles may name different compiler versions or flag combinations;
calibration ranks their measured reference results and preserves ties.
Portable import permits local path remaps but requires matching tool hashes.
Replay provides fresh local evidence rather than trusting imported history.

Instruction, relocation and whole-object equality are separate results.
For big-endian 32-bit PowerPC `R_PPC_EMB_SDA21`, MWCC can record the low-halfword
offset while a split target records the containing instruction's offset.
The comparator normalizes these equivalent patch sites only; relocation type,
symbol identity/binding, addends, order and other offsets remain checked.
This follows [decomp-toolkit's ELF relocation convention](https://github.com/encounter/decomp-toolkit/blob/main/src/obj/relocations.rs).
A real MWCC GC/1.2.5n `PADClamp` trial is instruction- and relocation-exact
after that normalization, but not whole-object-byte-exact: split metadata,
section flags and symbol/string-table ordering still differ. A 100 similarity
score does not override the separate exactness fields.

Standalone matching execution uses the Unix process runner; real-project
verification additionally requires Linux bubblewrap. This isolates writable
build state but is not a hermetic toolchain or hostile-code sandbox.
See [core-api.md](core-api.md#matching-workspaces) for the shared contracts.

### i386 compiler binaries on a host without a 32-bit glibc

The ee-gcc 2.96 compilers and Sony's EE assembler that PS2 decompilation projects use are i386 ELFs
whose interpreter is the fixed path `/lib/ld-linux.so.2`. A host that has no 32-bit glibc can still run
them from a user-owned 32-bit glibc tree (a Debian `libc6:i386` extraction, for instance) without
root and without touching the host: run the command inside a bubblewrap mount namespace in which a
tmpfs overlay on the directory `/lib` resolves to puts the tree's `ld-linux.so.2` at that name.

<!-- not gated: host-specific recipe -->
```bash
LIB=$(realpath /lib)
bwrap --dev-bind / / --overlay-src "$LIB" --tmp-overlay "$LIB" \
      --bind ~/opt/glibc32/usr/lib/ld-linux.so.2 "$LIB/ld-linux.so.2" \
      env LD_LIBRARY_PATH=~/opt/glibc32/usr/lib ee-gcc -O2 -G0 -S unit.c
```

`tests/m22-002_ps2_c_output.py --compiler eegcc` does this for itself (it re-executes under
`bwrap` when `/lib/ld-linux.so.2` is absent; `--glibc32` names the tree). The toolchain stays the
user's: romwright neither downloads nor ships it, and no tool bytes enter an export.

## Host Toolchains (Fedora 44 baseline)

- **LLVM / Clang**: 22.1.8 (`clang`, `clang++`)
- **LLD Linker**: 22.1.8 (`ld.lld`, invoked via `-fuse-ld=lld`)
- **GNU C/C++ (Host x86-64)**: 16.2.1 (`gcc`, `g++`)
- **MinGW-w64 (PE32/PE32+)**: 16.1.1 (`x86_64-w64-mingw32-gcc`, `i686-w64-mingw32-gcc`)

## Target Sysroots

Non-x86 targets need per-target glibc and libgcc runtime objects. `clang --target=<triple>`
compiles without a sysroot, but the linker needs the target `crt*.o` and `libc.so`.

Install the pinned Debian bookworm sysroots:

<!-- not gated: prepares a host environment or a cross toolchain that a gate cannot install for itself -->
```bash
python3 tools/fetch_cross_sysroots.py
```

This downloads the exact package versions below into `third_party/sysroots/` and runs a
PIE link smoke test for every architecture. The directory is `.gitignore`d; only the
script and this document are tracked.

| Target | Pinned packages |
|---|---|
| **aarch64** | `libc6-dev-arm64-cross 2.36-8cross1`, `libc6-arm64-cross 2.36-8cross1`, `linux-libc-dev-arm64-cross 6.1.4-1cross1`, `libgcc-12-dev-arm64-cross 12.2.0-14cross1`, `libgcc-s1-arm64-cross 12.2.0-14cross1` |
| **i386** | `libc6-dev-i386-cross 2.36-8cross1`, `libc6-i386-cross 2.36-8cross1`, `linux-libc-dev-i386-cross 6.1.4-1cross1`, `libgcc-12-dev-i386-cross 12.2.0-14cross1`, `libgcc-s1-i386-cross 12.2.0-14cross1` |
| **PowerPC 32-bit BE** | `libc6-dev-powerpc-cross 2.36-8cross1`, `libc6-powerpc-cross 2.36-8cross1`, `linux-libc-dev-powerpc-cross 6.1.4-1cross1`, `libgcc-12-dev-powerpc-cross 12.2.0-13cross1`, `libgcc-s1-powerpc-cross 12.2.0-13cross1` |

The C++ fixtures additionally use `libstdc++-12-dev-{arm64,i386}-cross` and
`libstdc++6-{arm64,i386}-cross` at `12.2.0-14cross1`, and the corresponding
PowerPC packages at `12.2.0-13cross1`. All six archive SHA-256 values are pinned
in `tools/fetch_cross_sysroots.py`. These are corpus toolchain dependencies,
not Rust crate runtime dependencies. Exception stubs and `-nostdlib++` are
not used.

The Linux gate requires `qemu-i386`, `qemu-aarch64` and `qemu-ppc` (Debian:
`qemu-user`). It executes positive TLS arithmetic and negative throw/catch
inputs on all four ELF targets, using `-L SYSROOT/usr/TARGET` for the cross
loaders and `LD_LIBRARY_PATH=SYSROOT/usr/TARGET/lib` for the target libraries
(preventing host loader-cache paths from selecting a host libc). Windows
executes the same checks natively for MSVC.

`cpp_o2` explicitly uses `-fno-pie -no-pie` on ELF targets. This avoids
host-dependent default PIE selection: Ubuntu 24.04 LLVM 18 PPC C++ PIE output
faulted on both runtime inputs, while its non-PIE output passed both.
The independent `plain_pie` variant remains `-fPIE -pie`.

## Target Architectures for Corpus (`m1-006`)

Each architecture builds the 5 corpus variants:
`{C -O0, C -O2, C++ exceptions+TLS, stripped, PIE}`.

| Architecture | Target Triple | Sysroot Path | C Compiler | C++ Compiler |
|---|---|---|---|---|
| **x86-64** | `x86_64-linux-gnu` | (host) | `clang --target=x86_64-linux-gnu` | `clang++ --target=x86_64-linux-gnu` |
| **x86-32** | `i686-linux-gnu` | `third_party/sysroots/i386` | `clang --target=i686-linux-gnu` | `clang++ --target=i686-linux-gnu` |
| **AArch64** | `aarch64-linux-gnu` | `third_party/sysroots/aarch64` | `clang --target=aarch64-linux-gnu` | `clang++ --target=aarch64-linux-gnu` |
| **PPC32-BE** | `powerpc-linux-gnu` | `third_party/sysroots/powerpc` | `clang --target=powerpc-linux-gnu` | `clang++ --target=powerpc-linux-gnu` |

## Example Invocations

### x86-64
<!-- not gated: prepares a host environment or a cross toolchain that a gate cannot install for itself -->
```bash
clang --target=x86_64-linux-gnu -fuse-ld=lld -O2 -s src.c -o x86_64_o2.bin
clang --target=x86_64-linux-gnu -fuse-ld=lld -O2 -fPIE -pie src.c -o x86_64_pie.bin
```

### x86-32
<!-- not gated: prepares a host environment or a cross toolchain that a gate cannot install for itself -->
```bash
clang --target=i686-linux-gnu \
  --sysroot=third_party/sysroots/i386 \
  -B third_party/sysroots/i386/usr/lib/gcc-cross/i686-linux-gnu/12 \
  -L third_party/sysroots/i386/usr/lib/gcc-cross/i686-linux-gnu/12 \
  -fuse-ld=lld -O2 -s src.c -o x86_32_o2.bin

clang --target=i686-linux-gnu \
  --sysroot=third_party/sysroots/i386 \
  -B third_party/sysroots/i386/usr/lib/gcc-cross/i686-linux-gnu/12 \
  -L third_party/sysroots/i386/usr/lib/gcc-cross/i686-linux-gnu/12 \
  -fuse-ld=lld -O2 -fPIE -pie src.c -o x86_32_pie.bin
```

### AArch64
<!-- not gated: prepares a host environment or a cross toolchain that a gate cannot install for itself -->
```bash
clang --target=aarch64-linux-gnu \
  --sysroot=third_party/sysroots/aarch64 \
  -B third_party/sysroots/aarch64/usr/lib/gcc-cross/aarch64-linux-gnu/12 \
  -L third_party/sysroots/aarch64/usr/lib/gcc-cross/aarch64-linux-gnu/12 \
  -fuse-ld=lld -O2 -s src.c -o aarch64_o2.bin

clang --target=aarch64-linux-gnu \
  --sysroot=third_party/sysroots/aarch64 \
  -B third_party/sysroots/aarch64/usr/lib/gcc-cross/aarch64-linux-gnu/12 \
  -L third_party/sysroots/aarch64/usr/lib/gcc-cross/aarch64-linux-gnu/12 \
  -fuse-ld=lld -O2 -fPIE -pie src.c -o aarch64_pie.bin
```

### PowerPC 32-bit Big-Endian
<!-- not gated: prepares a host environment or a cross toolchain that a gate cannot install for itself -->
```bash
clang --target=powerpc-linux-gnu \
  --sysroot=third_party/sysroots/powerpc \
  -B third_party/sysroots/powerpc/usr/lib/gcc-cross/powerpc-linux-gnu/12 \
  -L third_party/sysroots/powerpc/usr/lib/gcc-cross/powerpc-linux-gnu/12 \
  -fuse-ld=lld -O2 -s src.c -o ppc32_o2.bin

clang --target=powerpc-linux-gnu \
  --sysroot=third_party/sysroots/powerpc \
  -B third_party/sysroots/powerpc/usr/lib/gcc-cross/powerpc-linux-gnu/12 \
  -L third_party/sysroots/powerpc/usr/lib/gcc-cross/powerpc-linux-gnu/12 \
  -fuse-ld=lld -O2 -fPIE -pie src.c -o ppc32_pie.bin
```

## Corpus verification and lock maintenance

`bash tests/m1-006_corpus.sh` checks the full 25-entry matrix; only the five
MSVC entries may be skipped on a non-Windows host. `--msvc-only` requires all
five MSVC entries to build. The gate rebuilds the CLI and keeps its manifest,
report, binaries and import database in a temporary directory.

`--update-report` explicitly replaces `benchmarks/reports/m1-006.json`.
`python3 scripts/gen_corpus.py --update-lock` refreshes source digests only;
it preserves every recipe and matrix entry and does not build binaries.
Recipe changes are reviewed edits to `tests/corpus.lock.json`. Per-run binary
hashes belong in the generated manifest, not the cross-host recipe lock.

MSVC builds put `/Fo` objects and `/Fd` compiler state under the temporary
output directory. `/DEBUG:FULL /PDB:...` produces the separate linker PDB.
Validation checks MSF block/stream bounds, PDB Info and DBI ages, exact RSDS
GUID/age and filename association, and complete public function symbol records.
The primary has no debug-directory reference; every executable section retains
the twin's name, RVA, virtual/raw sizes and bytes.

## Ghidra corpus references (`m1-007`)

On Linux, install JDK 25 and the pinned Ghidra 12.1.3 release, then run:

<!-- not gated: prepares a host environment or a cross toolchain that a gate cannot install for itself -->
```bash
python3 scripts/gen_corpus.py --architectures x86_64,i386,aarch64,powerpc --out-dir /tmp/romwright-corpus
python3 scripts/gen_oracle.py --corpus-dir /tmp/romwright-corpus --report /tmp/romwright-oracle-report.json
python3 tests/m1-007_oracle_test.py
```

`ROMWRIGHT_GHIDRA` or `--ghidra` selects the installation; the default is
`~/ghidra_12.1.3_PUBLIC`. CI verifies the official release archive's SHA-256.
The generator rebuilds the existing Java bridge once when analysis is needed,
imports each stripped primary into an isolated temporary project, runs default
Ghidra analysis, and exports all non-external function entries. It never uses
the unstripped twins as analysis inputs.

References are `oracle/<binary-sha256>.json`; `--output-dir` selects another cache.
Each records the upstream version/revision, bridge source digest, selected
language, image base and sorted unique entries. Addresses remain **Ghidra
virtual addresses**, not RVAs or native-loader addresses. Automatic language
selection is preserved: Ghidra selects `PowerPC:BE:32:e500` for the local PPC
fixtures; the native corpus lock's `default` language is not an oracle override.
This task does not change discovery scoring or the existing libc reference.

Valid cache hits do not launch Java or rewrite references. `--check` validates
without generating; missing primaries and missing/invalid references are
reported as skipped with reasons and make the gate fail. Validation still
requires the pinned installation metadata and current bridge sources.
The m1-007 gate requires all **20 ELF entries**, with zero allowed skips; the
separate five MSVC entries are outside the original m1-007 acceptance scope.
The committed generation report is `benchmarks/reports/m1-007.json`.

## Native language selection (`m1-008`)

`python3 tests/m1-008_languages.py` checks six native imports against the pinned
Ghidra `.ldefs` entries and compiled SLA files: ELF32 i386, ARM little-endian,
ARM BE32, ARM BE8, the existing PE32 fixture, and an ELF64 x86-64 control.
It requires Clang/LLD, Rust and the Ghidra installation metadata; it does not
launch the Java bridge. Compiler probes and import databases are temporary;
the committed corpus matrix is unchanged.

Selection is the install's decision, not ours (`m4-023`): the pinned
`*.opinion` files are queried with `e_machine` as the primary key and
`e_flags` as the secondary one, exactly as `ElfLoader.findSupportedLoadSpecs`
queries them, and the constraint that matches names the processor, the
compiler spec, and often the variant. `ARM.opinion` pins `variant="v8"` and,
behind the `EF_ARM_BE8` bit (`0x00800000`: big-endian data, little-endian
instructions), `variant="v8LEInstruction"` -- so ARM little-endian is
`ARM:LE:32:v8`, ordinary big-endian ARM is `ARM:BE:32:v8`, and BE8 is
`ARM:LEBE:32:v8LEInstruction`, whose `.ldefs` entry carries
`instructionEndian="little"`. ELF32 i386 and PE32 remain `x86:LE:32:default`.
This verifies language selection, not ARM decompile parity.

Where the data pins no variant -- PowerPC, MIPS, 32-bit RISC-V -- the choice is
open. Ghidra's importer then takes the first element of a
`HashSet<QueryResult>` iteration over candidates that are all equally
preferred, which for a flags-0 32-bit big-endian PowerPC ELF is
`PowerPC:BE:32:e500` (`PowerPC:BE:32:default` is twelfth in the same set).
Hash order is not a fact about the image, so Romwright takes the neutral
`default` variant and `m4-023` records the disagreement with the proof that
nothing in the data separates the two.

`--update-report` explicitly writes `benchmarks/reports/m1-008.json`; normal
runs leave the working tree unchanged. All six cases must pass, with zero
allowed skips.

The x86 probes use Linux GNU targets and explicit `-fno-pie -no-pie`.
Ubuntu LLVM 18 routes generic `*-none-elf` x86 links through GCC, whose
default PIE mode rejects the probes' absolute relocations. The explicit
targets/model avoid that host-dependent driver behavior.

## Reusable gate stores (`ROMWRIGHT_GATE_CACHE`)

A gate run spent most of its wall time re-analysing bytes that never changed
with analysers that never changed: `m4-003` imported sixteen corpus rows
through the JVM bridge on every invocation, and four M5 gates asked stock the
same questions about the same rows. `benchmarks/gate_cache.py` reuses those
answers, keyed by the provenance that produced them and nothing else:

| Artifact | Key |
|---|---|
| oracle store, oracle decompile texts | binary digest + `bridge_sources_sha256` + install `upstream_version`/`upstream_revision` |
| stock headless export (thunks, names, selected language) | binary digest + exporter-script digest + install version/revision |
| native store, native decompile texts | binary digest + `romwright-cli` digest + `romwright-worker` digest |

The native key carries the executables on purpose: m4-014 recorded three
measurement rounds driven by a stale worker, and a key that omitted the build
would reintroduce that failure as a cache hit. A miss, a changed input, a
corrupt marker or a crashed build all fall through to real work, and
`tests/gate_cache_test.py` pins each of those properties.

Set `ROMWRIGHT_GATE_CACHE=/some/path` to relocate the store (default:
`$TMPDIR/romwright-gate-cache`), or `ROMWRIGHT_GATE_CACHE=` to switch reuse off.
The cost gates (`m7-001`..`m7-003`) never use it: they measure the work it
skips. Measured on the corpus: `m4-003` 690-1300 s -> **250 s** cold and
**3 s** reused, `m5-008` 172 s -> 14 s, `m5-011` 177 s -> 6 s, `m4-023` 65 s
-> 0.6 s, `m4-024` 54 s -> 0.3 s.

Rows inside a gate run concurrently (`--jobs`, default 4). The bound is
memory, not CPU: an uncached row still starts a JVM whose analysis wants a
few hundred megabytes. Results are re-ordered by row before anything is
recorded, so a report never depends on which row finished first.
