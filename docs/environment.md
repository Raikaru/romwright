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
| `ROMWRIGHT_GHIDRA` | `~/ghidra_12.1.3_PUBLIC` (`%USERPROFILE%\ghidra_12.1.3_PUBLIC` on Windows) | The pinned Ghidra install whose processor specs and `.sla` files the in-process SLEIGH decoder and the worker load. Without it, discovery reports a degraded import. |
| `ROMWRIGHT_GHIDRA_OPT` | `native/build/ghidra_opt` (`ghidra_opt.exe` on Windows) | The decompiler binary the worker drives. |
| `ROMWRIGHT_SPECS` | `native/specs` | Compiled language specs for the worker. |
| `ROMWRIGHT_WORKER` | `romwright-worker` beside the running executable (so a `target/dist` build finds its own), then `target/release`, `target/debug` | The decompiler worker process. |
| `ROMWRIGHT_CLI` | `romwright-cli` beside the desktop app, then `target/release`, `target/debug` | The CLI the desktop's Program setup runs for **Create project** (`new-project`). |
| `ROMWRIGHT_LIBRARY_PROTOTYPES` | `oracle/library-prototypes-v1/generic_clib_64.json` | Library prototypes applied to known imports. |
| `ROMWRIGHT_OBJDIFF` | `objdiff-cli` on `PATH` | objdiff, for matching reports. |
| `ROMWRIGHT_SERVICE_JAR` | next to the CLI's build | The Java bridge, used only to produce oracles. |
| `ROMWRIGHT_IMPORT_CACHE` | `~/.cache/romwright/imports` | Where imports are cached for reuse. |
| `ROMWRIGHT_SCRATCH` | `~/.cache/romwright/scratch` | Scratch stores for switch recovery. |

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
