# Overview: architecture, build and surfaces

How Romwright is put together, how to build it, and the surfaces it exposes (CLI, API, SDK, debugger). Moved from the README; the short version is there.

## Matching decompilation workflow

The desktop **Matching** workspace (`Ctrl+Shift+M`), CLI and API share the same Core
workspace and execution contracts:

- Evidence-backed mismatch diagnosis, without invented source/ROM links.
- Bounded candidate search, immutable history and source pins; no LLM required.
- Portable per-function inputs and reproducible tool profiles, with private
  files and proprietary tools excluded from export.
- Measured compiler/profile calibration that preserves ties.
- Isolated shared-context trials reporting both improvements and regressions.
- Reviewable source patches verified by the real project's build before
  explicit application, with unexpected object/symbol/data changes refused.

Similarity, instruction bytes, relocation metadata, object bytes and final
project output equality are separate results. A 100% score is not a claim
that the object or game matches.

Start with [the desktop workflow](desktop.md#matching-workstation),
[API/CLI contracts](core-api.md#matching-workspaces) and
[user-owned toolchains](toolchains.md#user-owned-matching-profiles).
Local Clang, MWCC, desktop and actual AUF Ninja verification evidence is recorded in
`benchmarks/reports/matching-workflow.json`; broader milestone gates are
tracked separately in `STATUS.md`.

## Architecture: staged migration to JVM-free

| Stage | Architecture | Status |
|---|---|---|
| 0 | Stock Ghidra + pinned reference | pinned: 12.1.3 |
| 1 | Rust core + SQLite store + tiny Java JSON-RPC bridge | done |
| 2 | Rust core owns all state; Java only on-demand compatibility | done |
| 3 | Native SLEIGH/decompiler C++ worker replaces the bridge | done (x86-64) |
| 4 | Fully native, JVM-free supported workflow | **done — gated** |

The bridge is an implementation aid, not the final architecture. The Rust
core owns durable facts (functions, symbols, xrefs, renames) in SQLite with
provenance. Every user path is native and runs with **no JVM in the process
tree**: `romwright-cli import <binary>`, `decompile`, `decompile-doc`, `disasm` and
store browsing. The Stage-1 Java bridge is reachable only through `--oracle`,
which exists to produce comparison oracles — `import --oracle`,
`decompile --oracle`, `disasm --oracle` and `dump-specs --oracle` — and needs
`--ghidra DIR` or the service jar. Continuous integration takes that path only
in oracle-generating steps. Native decompilation still reads SLEIGH language
data from the Ghidra install; that is data, not a JVM.

## Layout

```text
service/           Java JSON-RPC stdio bridge over pinned Ghidra APIs
crates/romwright-model   IDs, address-space+offset Address, API rows
crates/romwright-db      SQLite durable store (WAL, FKs, schema versioning)
crates/romwright-core    CoreService facade: store + native import/worker API,
                         `new_project/` (project plugins), `match_search/`
crates/romwright-worker  no-JVM decompiler worker (pinned ghidra_opt protocol)
crates/romwright-worker-client  worker pool the CLI, API and desktop drive
crates/romwright-api     versioned stdio/HTTP Core API
crates/romwright-diff    whole-program structural diff, name porting across builds
crates/romwright-facts   fact packs: names and prototypes carried between images
crates/romwright-sig     signature databases (vsig)
crates/romwright-debug isolated GDB/LLDB read-only debugger backend
crates/romwright-cli     scriptable CLI over the facade (`new-project`, `match`, ...)
crates/romwright-desktop pure-Rust egui/wgpu workstation
python/            SDK, console, permissioned plugins, AI tool adapter
tests/             differential test (native vs Ghidra oracle)
benchmarks/        gold baseline, Stage-4 gate, reports
native/            build scripts, specs, SLEIGH patch (see support matrix)
packaging/         SPDX SBOM and release update metadata tools
third_party/ghidra pinned Ghidra 12.1.3 decompiler C++ + language sources
```

## Prerequisites

- Rust stable (tested 1.98)
- A Ghidra 12.1.3 installation; default lookup is `$ROMWRIGHT_GHIDRA`, then
  `~/ghidra_12.1.3_PUBLIC`. The JVM and JDK are needed only for the bridge
  (Java service) and oracle-side tests.
- Native C++ build (`ghidra_opt`): a C++ toolchain and zlib; JDK 25 for the
  Java side.
- Python 3.10+ for the SDK, console, plugin host, and packaging scripts.
- Rust 1.95+ for the desktop (`romwright-desktop`); headless runs need a GPU
  or a software adapter (Mesa lavapipe on Linux, WARP on Windows).

## Build

<!-- not gated: builds native components whose toolchains are host-specific; the workflow they enable is gated by tests/m6-001_documented_workflow.py -->
```sh
cargo build --workspace
# Native decompiler worker (patched ghidra_opt; raw-SLEIGH, no JVM)
./native/build_ghidra_opt.sh
# Versioned Core API (stdio by default, HTTP with --listen)
cargo build -p romwright-api
# Java service (only for bridge compatibility paths; Ghidra install jars)
./service/build.sh
# Desktop workstation and its relocatable release archive
cargo build --profile dist -p romwright-desktop -p romwright-worker -p romwright-cli
python3 packaging/package_desktop.py --output build/desktop-package
```

## API, scripting, and extensions

The versioned Core API uses newline-delimited JSON over stdio or `POST /v2`
over HTTP. It is the same `romwright-core` service used by the CLI and the
desktop:

<!-- not gated: illustrates the surfaces documented and executed by docs/core-api.md and docs/scripting.md -->
```sh
./target/debug/romwright-api --project ./proj
./target/debug/romwright-api --project ./proj --listen 127.0.0.1:8787
python3 python/romwright_console.py --project ./proj \
  --api-executable ./target/debug/romwright-api \
  -c 'print(client.ping())'
python3 python/romwright_plugin_host.py plugin.py --project ./proj --permission read
```

API envelopes use `"api": 2`. Xref `provenance` is an object containing
`kind` (`inferred` or `asserted`), `source`, and `confidence` (a value in
`[0, 1]`, or `null` when unknown). Version-1 envelopes and `/v1` are rejected.
Opening a project migrates xref storage to schema 5; analysis replacement
preserves asserted references, including legacy rows of unknown ownership.
Native imports retain loader references and persist SLEIGH-inferred READ,
WRITE, and DATA references separately as inferred facts. The
[`xref_gate.py`](../benchmarks/xref_gate.py) acceptance compares all 20 ELF corpus
entries with explicitly matched Ghidra language/compiler contexts, requiring
data-reference precision >= 0.98 and recall >= 0.95. Full xref metrics remain
reported separately; this is not a claim of complete M2 program-model parity.

`python/romwright_sdk.py` is dependency-free and supports both transports.
`romwright_plugin_host.py` runs each plugin in a child process and gates API
methods by `read`, `write`, `types`, and `native` permissions. The optional
`romwright_ai.py` adapter exposes the same read tools and requires an explicit
mutation opt-in.

`romwright-debug` provides isolated GDB/LLDB read commands (backtrace, registers,
and bounded memory reads) through fresh child processes with deadlines. Its
read-only `DolphinGdb` client speaks acknowledged GDB RSP for live target
memory; the Core/API/desktop `memory_live` surface reuses that connection.
`trace_events` stores an ordered timeline; `collab_ops` stores idempotent
Lamport/actor-ordered operations and explicit apply state, so API clients can
share durable analysis changes without sharing SQLite connections.

## End-to-end (supported workflow, no JVM)

<!-- not gated: prepares a host environment or a cross toolchain that a gate cannot install for itself -->
```sh
export ROMWRIGHT_SLA=$HOME/ghidra_12.1.3_PUBLIC/Ghidra/Processors/x86/data/languages/x86-64.sla
export ROMWRIGHT_GHIDRA=$HOME/ghidra_12.1.3_PUBLIC          # console defaults

./target/debug/romwright-cli import ./smoke_bin --name smoke --project ./proj
./target/debug/romwright-cli functions smoke --project ./proj   # store only
./target/debug/romwright-cli xrefs smoke --to 00400466 --project ./proj
./target/debug/romwright-cli rename smoke 00400466 my_add --project ./proj
./target/debug/romwright-cli open smoke --project ./proj        # reopen, no reanalysis
./target/debug/romwright-cli disasm ./smoke_bin 00400466 -n 8
./target/debug/romwright-cli decompile ./smoke_bin 00400466 --name smoke --project ./proj
```

Import measures itself. `--timings` prints one machine-readable line: the
total, the phases (`parse`, `patterns`, `flow`, `discovery`, `references`,
`store`), the decoder lane count, and what the flow phase asked (in-process
decoder batches, and instructions decoded).
Batch-parallel work runs four lanes on every host: flow
batches split across in-process SLEIGH decoders, reference rounds across
in-process propagation lanes; `ROMWRIGHT_CONSOLE_SHARDS` pins
that count. `ROMWRIGHT_WORKER_MEMORY_CAP` bounds one decompiler worker's
resident size in bytes (256 MiB by default, values under 16 MiB refused): a
worker that grows past it is recycled mid-pass rather than failing the request
that discovered the growth, and `benchmarks/reports/m11-001.json` records eight
such recycles inside one bounded inference pass over a game module. On an image with one instruction set,
shards change wall time and nothing else -- `tests/m2-016_import_budget.py`
asserts that a one-console import and an N-console import write identical
function, xref, string, symbol and thunk sets. A lane keeps the mode switches
its own decodes committed, so on an image that mixes ARM and Thumb the count
shapes the result (a Vita import differs by about 60 rows between one, four and
eight lanes), which is why it is fixed and not taken from the host. A range that kills its console costs
that range alone: the console is replaced with the round's context, so the
rest of its lane is still answered. Every variable the programs read is listed
in [docs/environment.md](environment.md).

Native import staging and mapped-image XML use `ROMWRIGHT_SCRATCH`, defaulting
to `$HOME/.cache/romwright/scratch`, rather than the system temporary directory.
Choose a filesystem with enough space for the imported image and switch-recovery
store. Without either `ROMWRIGHT_SCRATCH` or `HOME`, scratch creation fails.

<!-- not gated: illustrates the surfaces documented and executed by docs/core-api.md and docs/scripting.md -->
```sh
./target/debug/romwright-cli import /usr/lib64/libc.so.6 --name libc \
    --project ./proj --timings
# TIMINGS {"total":9.30,"functions":3961,"shards":6,
#          "flow":{"requests":3146,"instructions":297390},
#          "phases":{"parse":0.02,"patterns":0.12,"flow":2.86,
#                    "discovery":3.60,"references":5.32,"store":0.19}}
```

Only `--oracle` starts the JVM: `import --oracle`, `decompile --oracle`,
`disasm --oracle` and `dump-specs --oracle --out DIR` accept `--ghidra DIR`
or the service jar, and exist for oracle generation, not for daily use.

<!-- not gated: illustrates the surfaces documented and executed by docs/core-api.md and docs/scripting.md -->
```sh
./target/debug/romwright-cli import ./smoke_bin --oracle --project ./oracle-proj
python3 tests/m2-015_native_default.py
```

GameCube DOL import maps the section table and preserves initialized data
inside BSS bounds. Discovery runs on the in-process SLEIGH decoder with the
installed `PowerPC:BE:32:default` language (the native console is retired). No
symbol ELF is supplied to the importer. A disc image (ISO, CISO, RVZ, WIA,
WBFS) imports its boot DOL and merges its RELs (`native/disc.rs`,
`native/rel.rs`; `docs/console-research.md`).

<!-- not gated: illustrates the surfaces documented and executed by docs/core-api.md and docs/scripting.md -->
```sh
./target/debug/romwright-cli import /path/to/sys/main.dol --name dol --project ./proj
python3 tests/m1-009_dol.py --dol /path/to/sys/main.dol --oracle /path/to/files/boot.elf
```

The real-input gate requires the hash-pinned GQFE78 pair; missing private
inputs produce a skipped, non-passing report. It is a local gate, not a claim
that CI possesses or tests the game binary.

## Verification

<!-- not gated: builds native components whose toolchains are host-specific; the workflow they enable is gated by tests/m6-001_documented_workflow.py -->
```sh
cargo test --workspace
ROMWRIGHT_SLA=... ./tests/differential.sh     # native vs Ghidra oracle
RUNS=3 ROMWRIGHT_SLA=... ./benchmarks/gate.sh # memory/perf gates
```

## Packaging and desktop status

`crates/romwright-desktop` is the pure-Rust workstation (egui shell, wgpu
renderer); `packaging/package_desktop.py` builds it with `cargo` and writes the
relocatable `romwright-<version>-<system>-<machine>.tar.gz` archive.
`packaging/sbom.py` emits an SPDX 2.3 dependency inventory;
`packaging/update_manifest.py` creates release artifact size/SHA-256 metadata;
`packaging/verify_update.py` verifies downloaded artifacts before use.
The desktop's `--gate`, `--matching-gate` and `--screenshot` modes render
offscreen with no display server, on Mesa lavapipe when the machine has no
GPU. CI remains authoritative for the cross-platform package.

Known limits remain: the all-input discovery gate is incomplete and PE
function-set parity is not claimed. The x86-64 worker needs `ROMWRIGHT_SLA`
and a patched `ghidra_opt`; the API HTTP listener is localhost-oriented and
does not provide authentication; the Python plugin host is the capability
boundary for untrusted scripts. The live overlay was also smoke-tested against
Dolphin 2606a's real GDB stub using the Agent Under Fire RVZ. A live read at
0x80000000 returned the game ID bytes `GW7E69`.
