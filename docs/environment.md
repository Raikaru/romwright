# Environment variables

Every `ROMWRIGHT_*` variable the Rust crates read, grouped by what it is
for. An unset variable takes the default shown. The Python gates set a few
of these for themselves; this list covers only what the programs read.

## Build profiles

Not an environment variable, but what the gates below depend on: `cargo build
--release` is the fast-to-build development profile, and what ships is built
with `--profile dist` (`Cargo.toml`: it inherits `release`, adds `lto = "fat"`
and `codegen-units = 1`, and builds into `target/dist`) and, for the long-lived
`romwright-api`, `--profile dist-service` (the same, optimised for size except
the importer's crates; `target/dist-service`). `packaging/` builds them, and
the memory gates (`tests/m7-001`, `m7-002`, `m7-003`) build and measure them,
because a resident-size envelope is about the binaries a user runs. For a quick
test run on a `--release` build, the cheap profile is
`CARGO_PROFILE_RELEASE_LTO=false CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16`
(`docs/releasing.md`); it changes no behaviour.

## Where things are

| Variable | Default | What it names |
|---|---|---|
| `ROMWRIGHT_GHIDRA` | first existing of `<exe dir>/../share/romwright/ghidra`, `<repo>/build/ghidra`, `~/ghidra_12.1.3_PUBLIC` (`%USERPROFILE%\ghidra_12.1.3_PUBLIC` on Windows) (see "Default resolution order") | The pinned Ghidra install whose `Ghidra/Processors/*/data` (processor specs and `.sla` files) the in-process SLEIGH decoder and the worker load. Without it, discovery reports a degraded import. |
| `ROMWRIGHT_GHIDRA_OPT` | `<exe dir>/ghidra_opt`, then `native/build/ghidra_opt` (`ghidra_opt.exe` on Windows) | The decompiler binary the worker drives. |
| `ROMWRIGHT_SPECS` | `<exe dir>/../share/romwright/specs`, then `native/specs` | Compiled language specs for the worker. |
| `ROMWRIGHT_WORKER` | `romwright-worker` beside the running executable (so a `target/dist` build finds its own), then `target/release`, `target/debug` | The decompiler worker process. |
| `ROMWRIGHT_CLI` | `romwright-cli` beside the desktop app, then `target/release`, `target/debug` | The CLI the desktop's Program setup runs for **Create project** (`new-project`). |
| `ROMWRIGHT_LIBRARY_PROTOTYPES` | `<exe dir>/../share/romwright/library-prototypes-v1/generic_clib_64.json`, then `oracle/library-prototypes-v1/generic_clib_64.json` | Library prototypes applied to known imports; `runtime_helpers.json` and `ctr_sdk.json` are read from the same directory. |
| `ROMWRIGHT_OBJDIFF` | `objdiff-cli` on `PATH` | objdiff, for matching reports. |
| `ROMWRIGHT_SERVICE_JAR` | next to the CLI's build | The Java bridge, used only to produce oracles. |
| `ROMWRIGHT_IMPORT_CACHE` | `~/.cache/romwright/imports` | Where imports are cached for reuse. |
| `ROMWRIGHT_SCRATCH` | `~/.cache/romwright/scratch` | Scratch stores for switch recovery. |

## Default resolution order

With no variable set, romwright finds its own files the same way from a source
checkout and from a release archive (`crates/romwright-core/src/runtime_paths.rs`).
For each file the first existing candidate wins, and an environment variable
above beats all of them:

1. **beside the running executable**, the layout of a release archive
   (`romwright-<version>-<os>-<arch>/`): `bin/ghidra_opt[.exe]` next to
   `bin/romwright-cli`, and `share/romwright/` one level up
   (`specs/`, `library-prototypes-v1/`, `ghidra/`, holding
   `Ghidra/Processors/*/data`). The worker is looked for beside the executable
   too (`ROMWRIGHT_WORKER`'s default);
2. **inside the source checkout the binary was built from**:
   `native/build/ghidra_opt[.exe]`, `native/specs`,
   `oracle/library-prototypes-v1/`, and `build/ghidra`, where `setup.py`
   extracts the Ghidra language data (gitignored with the rest of `build/`);
3. **the home directory**, for Ghidra only: `~/ghidra_12.1.3_PUBLIC`
   (`%USERPROFILE%\ghidra_12.1.3_PUBLIC`), the location before `setup.py`
   existed, so an existing install keeps working.

A Ghidra candidate counts only when its `Ghidra/` directory exists. When no
candidate exists, the last one is used so the error names a path, and the
message for a missing decompiler or language file says to run `setup.py`.
Nothing is resolved against the working directory. `romwright-cli paths` prints
the five resolved locations (worker, decompiler, specs, library prototypes,
Ghidra data) and whether each exists.

romwright reads only `Ghidra/Processors/<processor>/data/**` of the Ghidra
release (`.sla`, `.ldefs`, `.opinion`, `.pspec`, `.cspec`, patterns, and the
`.slaspec`/`.sinc` sources the language installers in `native/languages/`
link against), never its Java code or jars; only the `--oracle` bridge needs a
full install. `packaging/ghidra_data.py` extracts exactly that subset (26 MB,
967 files, without `data/manuals`) from the pinned release zip, which it keeps
in a per-user cache (`%LOCALAPPDATA%\romwright\cache`,
`~/Library/Caches/romwright`, `$XDG_CACHE_HOME/romwright` or
`~/.cache/romwright`) after verifying its SHA-256.

## How much of the machine

| Variable | Default | Effect |
|---|---|---|
| `ROMWRIGHT_CONSOLE_SHARDS` | 4 | In-process SLEIGH decoder lanes one discovery flow batch is split across, and in-process propagation lanes one reference round is split across. Fixed, not per core: each lane keeps the mode switches its own decodes committed, so the count changes what a mixed ARM/Thumb image yields (a Vita import differs by ~60 rows between 1, 4 and 8 lanes) and an import must not depend on the host's cores or a `taskset`. Another value is yours to own. The lane count is kept for a small image too (under 256 KiB mapped: a program walked in milliseconds), but its discovery lanes share one decoder, each with its own committed modes swapped in for the slice it answers, so the result is the one four decoders give and the memory is one; the reference lanes claim ranges as they finish them, so a small image opens one per 256 KiB (never more than the count) instead of four. A language's tables are megabytes per decoder, which is what a tiny import's peak is made of (`benchmarks/reports/memory_fix_*.md`). |
| `ROMWRIGHT_PROGRAM_JOBS` | half the cores, 1 to 4 | Programs of one container (overlays, RELs, processors) analysed at once. Speed only: each program's analysis depends on its own image and the configuration, and results are stored in container order, so the count changes no row. The switch stage's decompiler workers stay bounded process-wide (as many as one program's lanes would use alone), so more programs in flight do not multiply their memory. |
| `ROMWRIGHT_WORKER_MEMORY_CAP` | 268435456 (256 MiB) | Memory cap in bytes for each decompiler worker; values under 16 MiB are ignored. |
| `ROMWRIGHT_SWITCH_MAX_OWNERS` | 1024 | Functions the decompiler switch round may ask about; the rest are recorded as skipped, never dropped silently. |
| `ROMWRIGHT_SWITCH_WORK_BUDGET` | 75000000 | Work units one switch decompile may spend before the decompiler refuses it (`WorkBudgetExceeded`, a partial note naming the function); `0` is unlimited. A count of the decompiler's own work, so a function is finished or refused the same way on every host, and part of the import-cache key. The wall-clock guard per function (`ROMWRIGHT_SWITCH_WALL_SECS`, 900) is only a backstop: a function it kills makes the import degraded and uncached. |
| `ROMWRIGHT_BRIDGE_MAXMEM` | the bridge's raised heap | Java heap for the oracle bridge. |

## Switching behaviour on or off

| Variable | Default | Effect |
|---|---|---|
| `ROMWRIGHT_NO_DECODER_POOL` | unset | Build every SLEIGH decoder from its `.sla`, as before decoders were pooled: the pooled path hands a finished decoder (reset to the state its spec left, given the next image) to the next program that decodes the same language. For measuring and as a switch if a result is ever suspected to depend on it; the two paths give the same rows. |
| `ROMWRIGHT_EAGER_SLA` | unset | Decode every decoder's whole `.sla` into its own tables, as before the shared image: by default a language's `.sla` is inflated once per process and each decoder decodes a constructor, a template or a decision node the first time an instruction reaches it (`third_party/kuna-sleigh/src/slaimage.rs`, `docs/third-party.md`). A decoder of a tiny ELF is 2-3 MB instead of 10-35, and the first one builds in a few milliseconds. For measuring and as a switch if a result is ever suspected to depend on it; the two paths give the same p-code (`a_lazily_decoded_language_lifts_what_the_eager_decode_does`). |
| `ROMWRIGHT_NO_IMPORT_CACHE` | cache on | Set: every import analyses from scratch. Gates that measure analysis set it. |
| `ROMWRIGHT_NO_SWITCH_VSA` | on | Set: jump tables are recovered by the decompiler alone, so the value-set path can be measured against it. |
| `ROMWRIGHT_NO_SWITCH_DECOMPILER` | on | Set: jump tables are recovered by value-set analysis alone. |
| `ROMWRIGHT_STORED_SWITCHES` | `apply` | `off`: the decompiler recovers every printed switch itself. `observe`: the stored dispatch tables are sent and only compared with `jumptable.cc`'s (the worker's ownership log reports the relation). `apply`: a stored table is the authority for its branch (docs/ownership.md, "Stored switch tables fed to the decompiler"). The import's own switch worker is never fed. |
| `ROMWRIGHT_SJA` | off | Set: run the abstract-interpretation switch pass where the pattern pass refused. Opt-in until measured to help. |
| `ROMWRIGHT_REGISTER_PARAMS` | off | Set: infer register parameters for prototypes. |
| `ROMWRIGHT_INFERRED_TYPES` | on | `0`: the `infer_prototypes` job keeps the decompiler's parameter types. Otherwise it upgrades `undefined`/register-width integer parameters to pointers (structural evidence) or signed integers (signed evidence) from the p-code type inference; never on asserted or import-supplied prototypes, never changing arity. For ablation only. |
| `ROMWRIGHT_STRUCTS` | `all` | `off\|debug\|inferred\|all`: which struct layouts reach the decompiler and the printed C. `debug`: the image's debug stream's layouts (`native-import:debug-info`); `inferred`: layouts synthesized from function bodies, gated (`native-inferred:struct-layout`); `all`: both. Asserted layouts are used in every mode but `off`. Read when a layout is used, never when it is stored (docs/structs.md). |
| `ROMWRIGHT_PROMOTE_TAILCALLS` | off | Set: promote proven tail-call targets to functions. |
| `ROMWRIGHT_IR_PASSES` | the default pipeline | Comma list of IR passes the worker runs. |
| `ROMWRIGHT_RUST_STRUCTURING` | `all` | Structuring models the worker's Rust C printer (always on; docs/printer-ir.md) runs before printing: `all`, `none` (Ghidra's structure, byte-identical to PrintC -- for ablation and oracle parity) or a comma list of models (`break_continue`, `collapsed_edges`, `else_join`, `thread_test`, `switch_tails`, `loop_exits`, `irreducible_entry`, `sink_join`, `cond_merge`), optionally with `budget=N` (printed lines a rewrite may add per goto it removes, default 5). The models rewrite Ghidra's structured tree to print fewer gotos; a rewrite is kept only when the printed control flow still matches the block graph, the goto count drops and the copy fits the budget. An unknown name is an error. |
| `ROMWRIGHT_RUST_STRUCTURING_LOG` | off | Set: every structured function writes one `{"structuring": ...}` JSON line (function name, gotos/labels before and after, rewrites per model, remaining gotos by cause, rewrite attempts, why a tree was refused) to the worker's stderr; `benchmarks/structuring_models.py` aggregates it. |

## Set by romwright for its own children

Not for users: the CLI sets these when it starts a worker.
`ROMWRIGHT_LANGUAGE`, `ROMWRIGHT_LANGUAGE_DIR`, `ROMWRIGHT_SLA` (the
program's language and its compiled spec), `ROMWRIGHT_PROGRAM_INPUT` (the
captured input the worker came from) and `ROMWRIGHT_IMAGE_SNAPSHOT`
(`<input identity>:<digest>`, the program's mapped image, written once by the
importing process as a project artifact: the worker maps that file for its
bytes instead of opening the input, which for a disc is gigabytes; a snapshot
made for a different input is ignored).

## Build prerequisites

### One command: `setup.py`

`python setup.py` (`python3` on Linux and macOS; standard library only) at the
repository root does the following, then smoke-tests it:

1. checks the prerequisites and, for each one missing, says how to get it:
   Rust via rustup (and on Windows the Visual Studio C++ build tools the MSVC
   toolchain links with); a C++11 compiler, `make`, zlib and `git` on Linux
   and macOS (the message carries the `apt`, `dnf`, `pacman` or
   `xcode-select` line); on Windows MSYS2 with its MinGW64 packages
   `mingw-w64-x86_64-gcc mingw-w64-x86_64-make mingw-w64-x86_64-zlib` and
   Git for Windows. `--check` stops after this step, and
   `--install-msys2-packages` runs `pacman` for the missing MinGW64 packages;
2. downloads the pinned Ghidra 12.1.3 release, verifies its SHA-256, and
   extracts the language data (see above) into `build/ghidra`, where romwright
   finds it with no variable set (`--ghidra-dir` chooses another place, which
   then needs `ROMWRIGHT_GHIDRA`; `--ghidra-zip` uses a zip you already have, and
   its SHA-256 is checked against the pinned digest before anything is read from
   it, whether or not the data is already extracted),
   then compiles the languages this repository carries (below) and installs them
   beside it (`--skip-languages` skips that);
3. builds `native/build/ghidra_opt` (on Windows by driving MSYS2's MINGW64
   bash, found at `C:\msys64`, `%MSYS2_ROOT%` or `--msys2`);
4. runs `cargo build --release -p romwright-cli -p romwright-worker`;
5. imports `tests/fixtures-src/tiny_bin` into a temporary project and
   decompiles `00400466` with every `ROMWRIGHT_*` variable removed from the
   environment, expecting `return param_2 + param_1;`, then imports and
   decompiles a generated PlayStation 2 ELF (`packaging/smoke_fixtures.py`),
   which needs the `r5900` language compiled in step 2.

### romwright's own languages

Six languages are not in the Ghidra release and come from sources in this
repository; without them a PS1, PS2, N64 or Xbox 360 import fails
(`No sleigh specification for r5900:LE:32:default`):

| Language | Sources | Console |
|---|---|---|
| `PSX:LE:32:default` | `native/languages/psx` + stock MIPS in `third_party/ghidra/languages/mips` | PlayStation |
| `r5900:LE:32:default` | `native/languages/r5900` | PlayStation 2 |
| `VU:LE:64:micro` | `native/languages/vu` | PlayStation 2 vector units |
| `RSP:BE:32:default` | `native/languages/rsp` | Nintendo 64 |
| `PowerPC:BE:64:Xenon-32addr` | `native/languages/xenon` + the stock PowerPC sources in the Ghidra data | Xbox 360 |
| `PowerPC:BE:32:Gekko_Broadway` | `third_party/ghidra/languages/gamecube` | GameCube, Wii |

`packaging/languages.py` compiles each to a `.sla` and installs it as an
extension module of the Ghidra data directory
(`Ghidra/Extensions/<Module>/data/languages/`, where `architecture::discover`
finds it), recording the sources' hash in `.romwright-languages.json` so that a
rerun recompiles only what changed. It is the logic of the
`native/languages/*/install.sh` scripts, which now call it, so it runs on
Windows too. The compiler is, in order: `--sleigh`; the `sleigh` of a full Ghidra
install; the one in the pinned release zip (`Ghidra/Features/Decompiler/os/
win_x86_64` or `linux_x86_64`, extracted into the cache, not into the shipped
data); else `sleigh_opt` built from the pinned, unmodified decompiler sources by
`native/build_sleigh.sh` (macOS, Linux on ARM; the release ships no compiler
for them; on macOS it builds for the host's architecture, arm64 or x86_64,
`native/darwin_arch.sh`). The `.sla` files are byte-identical from the Windows release
compiler and the source-built one. Languages of other third-party Ghidra
extensions (Allegrex/PSP, SPU/PS3, Game Boy, 65816, M16C, the RISC-V
`RV32G`/`RV64G` variants) have no vendored source and are not produced: install
those extensions' own `data/languages` under `ROMWRIGHT_GHIDRA` if you need them.

A test that needs one of these languages (the `native::vsa` and `native::discovery`
tests for r5900 and Gekko, the Xenon lookup in `architecture.rs`) prints `SKIP:` and
passes when the language is not installed, so a contributor who has not run
`python setup.py` is not told the code is broken. CI provisions the languages
first and sets `ROMWRIGHT_REQUIRE_LANGUAGES=1`, which turns that skip into a
failure: the coverage cannot silently disappear.

A rerun skips what is done: the extraction when `build/ghidra` carries the
matching marker, the download when the cache holds the verified zip,
`ghidra_opt` when it is newer than its sources (`--rebuild-native` forces
it), and cargo when nothing changed. `--skip-ghidra`, `--skip-native`,
`--skip-cargo` and `--skip-smoke` skip a step outright.

### By hand

Rust stable, and for the one C++ product, the patched decompiler
`native/build/ghidra_opt` (`native/build_ghidra_opt.sh`): a C++11 compiler,
`make`, `git` and zlib. No `binutils-devel` (`bfd.h`) and no `libzstd` are
needed: those belonged to the SLEIGH console, which no longer
exists. Disassembly, flow and lifting run in process (`kuna-sleigh`), so the
only native process the product starts is `ghidra_opt`, through the worker.

`cargo build` also needs a C compiler (`cc`): the disc reader `nod`
(GameCube/Wii RVZ, WIA, WBFS, Wii partitions) builds the zstd, bzip2, LZMA and
zlib decoders it carries (`zstd-sys`, `bzip2-sys`, `liblzma-sys`, `libz-sys`,
their vendored C sources). No system library and no environment variable is
involved: the disc reader is configured by the file it is given. It holds no
key; the Wii common keys it embeds are `nod`'s, used only to unwrap the
title key stored in the disc's own ticket.

### Windows

The CLI, worker and desktop build natively with the MSVC Rust toolchain
(`x86_64-pc-windows-msvc`; Visual Studio Build Tools supply `cc`). The
decompiler builds with MSYS2's MinGW-w64 toolchain (packages
`mingw-w64-x86_64-gcc`, `mingw-w64-x86_64-make`, `mingw-w64-x86_64-zlib`) and
Git for Windows on `PATH`, from an MSYS2 MINGW64 shell:

```sh
export PATH="$PATH:/c/Program Files/Git/cmd"
native/build_ghidra_opt.sh --jobs 8
```

The script defines `_WINDOWS` (Ghidra's binary-mode stdio and Win32 paths) and
links statically, so `native/build/ghidra_opt.exe` needs no MinGW DLLs and runs
from any shell. Tools romwright runs under a deadline (`exec::run_command`) are
supervised by a kill-on-close job object instead of a Unix process group.

## Tracing

Each prints diagnostic lines to stderr and changes no result.

| Variable | Prints |
|---|---|
| `ROMWRIGHT_TRACE_CACHE` | Import-cache keys, hits and restore failures. |
| `ROMWRIGHT_TRACE_SWITCH` | Per-round switch-decompiler owners, lanes, tables and time. |
| `ROMWRIGHT_WORK_TRACE` | Read by `ghidra_opt` itself: each decompile's address, outcome (`ok`/`exceeded`), work units and milliseconds (`work-trace ...`), which is how `ROMWRIGHT_SWITCH_WORK_BUDGET` is calibrated. Reaches the terminal only when the worker's stderr does (`ghidra_opt` run directly, or `romwright-worker --switches`). |
| `ROMWRIGHT_TRACE_VSA` | Switch candidates per round and why value-set analysis refused a branch: `no_guard` (nothing before it tests anything), `no_live_in`, `no_strided_load` (nothing moves with an index), `too_few_targets`, `unguarded` (a table no guard ends), `unmodelled`; `narrowed`, tables cut to the slots the index can take given the register bits every way into the dispatch fixes, and `renarrowed`, earlier tables cut once their cases are decoded (`VSA renarrowed <branch> to [...]`). `VSA left final/outside/nested` counts answered tables handed to the decompiler, and `VSA nested dispatch <addr>` / `budget` names why. |
| `ROMWRIGHT_TRACE_VSA_AT=<addr>` | Value-set analysis state at one branch, and (`VSA facts at`) the flow facts that narrowed it or why none did. |
| `ROMWRIGHT_TRACE_SLICE` | Backward slices the table matcher tried. |
| `ROMWRIGHT_TRACE_SJA_AT`, `_CFG`, `_EDGE`, `_OPS`, `_STATE`, `_CBRANCH` `=<addr>` | The abstract-interpretation switch pass at one function or branch. |
| `ROMWRIGHT_TRACE_ADDR` | Worker address-decoding misses. |
| `ROMWRIGHT_DEBUG_PRUNE` | Indirect-call pruning decisions. |
