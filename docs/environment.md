# Environment variables

Every `ROMWRIGHT_*` variable the Rust crates read, grouped by what it is
for. An unset variable takes the default shown. The Python gates set a few
of these for themselves; this list covers only what the programs read.

## Where things are

| Variable | Default | What it names |
|---|---|---|
| `ROMWRIGHT_CONSOLE` | `native/build/decomp_native` in the repository, if built | The SLEIGH console (`native/build_console.sh`). Without one, discovery reports a degraded import. |
| `ROMWRIGHT_GHIDRA` | `~/ghidra_12.1.3_PUBLIC` | The pinned Ghidra install whose processor specs the console loads. |
| `ROMWRIGHT_GHIDRA_OPT` | `native/build/ghidra_opt` | The decompiler binary the worker drives. |
| `ROMWRIGHT_SPECS` | `native/specs` | Compiled language specs for the worker. |
| `ROMWRIGHT_WORKER` | `target/release/romwright-worker` beside the CLI | The decompiler worker process. |
| `ROMWRIGHT_LIBRARY_PROTOTYPES` | `oracle/library-prototypes-v1/generic_clib_64.json` | Library prototypes applied to known imports. |
| `ROMWRIGHT_OBJDIFF` | `objdiff-cli` on `PATH` | objdiff, for matching reports. |
| `ROMWRIGHT_SERVICE_JAR` | next to the CLI's build | The Java bridge, used only to produce oracles. |
| `ROMWRIGHT_IMPORT_CACHE` | `~/.cache/romwright/imports` | Where imports are cached for reuse. |
| `ROMWRIGHT_SCRATCH` | `~/.cache/romwright/scratch` | Scratch stores for switch recovery. |

## How much of the machine

| Variable | Default | Effect |
|---|---|---|
| `ROMWRIGHT_CONSOLE_SHARDS` | one per physical core, at most eight | Consoles one flow or reference batch is split across. |
| `ROMWRIGHT_WORKER_MEMORY_CAP` | 268435456 (256 MiB) | Memory cap in bytes for each decompiler worker; values under 16 MiB are ignored. |
| `ROMWRIGHT_SWITCH_MAX_OWNERS` | 1024 | Functions the decompiler switch round may ask about; the rest are recorded as skipped, never dropped silently. |
| `ROMWRIGHT_BRIDGE_MAXMEM` | the bridge's raised heap | Java heap for the oracle bridge. |

## Switching behaviour on or off

| Variable | Default | Effect |
|---|---|---|
| `ROMWRIGHT_NO_IMPORT_CACHE` | cache on | Set: every import analyses from scratch. Gates that measure analysis set it. |
| `ROMWRIGHT_NO_SWITCH_VSA` | on | Set: jump tables are recovered by the decompiler alone, so the value-set path can be measured against it. |
| `ROMWRIGHT_NO_SWITCH_DECOMPILER` | on | Set: jump tables are recovered by value-set analysis alone. |
| `ROMWRIGHT_SJA` | off | Set: run the abstract-interpretation switch pass where the pattern pass refused. Opt-in until measured to help. |
| `ROMWRIGHT_REGISTER_PARAMS` | off | Set: infer register parameters for prototypes. |
| `ROMWRIGHT_PROMOTE_TAILCALLS` | off | Set: promote proven tail-call targets to functions. |
| `ROMWRIGHT_IR_PASSES` | the default pipeline | Comma list of IR passes the worker runs. |

## Set by romwright for its own children

Not for users: the CLI sets these when it starts a console or worker.
`ROMWRIGHT_LANGUAGE`, `ROMWRIGHT_LANGUAGE_DIR`, `ROMWRIGHT_SLA` (the
program's language and its compiled spec), `ROMWRIGHT_PROGRAM_INPUT` (the
captured input the worker reads bytes from), `ROMWRIGHT_PARENT_PID` (so a
console exits with the process that started it).

## Tracing

Each prints diagnostic lines to stderr and changes no result.

| Variable | Prints |
|---|---|
| `ROMWRIGHT_TRACE_CACHE` | Import-cache keys, hits and restore failures. |
| `ROMWRIGHT_TRACE_SWITCH` | Per-round switch-decompiler owners, lanes, tables and time. |
| `ROMWRIGHT_TRACE_VSA` | Switch candidates per round and why value-set analysis refused a branch. |
| `ROMWRIGHT_TRACE_VSA_AT=<addr>` | Value-set analysis state at one branch. |
| `ROMWRIGHT_TRACE_SLICE` | Backward slices the table matcher tried. |
| `ROMWRIGHT_TRACE_SJA_AT`, `_CFG`, `_EDGE`, `_OPS`, `_STATE`, `_CBRANCH` `=<addr>` | The abstract-interpretation switch pass at one function or branch. |
| `ROMWRIGHT_TRACE_ADDR` | Worker address-decoding misses. |
| `ROMWRIGHT_DEBUG_PRUNE` | Indirect-call pruning decisions. |
