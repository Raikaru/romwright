# Romwright

Romwright is a lightweight reverse-engineering platform that reuses Ghidra's
proven components (SLEIGH, p-code, the native decompiler) as compiler
technology rather than reimplementing them. It is **not** a Ghidra fork and
claims no drop-in compatibility.

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

Start with [the desktop workflow](docs/desktop.md#matching-workstation),
[API/CLI contracts](docs/core-api.md#matching-workspaces) and
[user-owned toolchains](docs/toolchains.md#user-owned-matching-profiles).
Local Clang, MWCC, desktop and actual AUF Ninja verification evidence is recorded in
`benchmarks/reports/matching-workflow.json`; broader milestone gates are
tracked separately in `STATUS.md`.

## Projects: `new-project` and `match`

`romwright-cli new-project <image> <outdir>` imports a retail image and writes
a repository to decompile it in; `romwright-cli match <name|0xADDR>` then runs
inside that repository and searches the ways the decompiler can print one
function for the C that the repository's own compiler turns into the retail
bytes (`docs/match.md`). The platform is read from the image (or given with
`--platform`); every platform romwright imports is covered, in one of three
shapes:

| Platform | Image | What `new-project` writes | Where it is described |
|---|---|---|---|
| PlayStation 2 | boot ELF, or an ISO9660 disc whose `SYSTEM.CNF` names it | splat repository; `ninja` rebuilds the retail ELF byte for byte from assembly, `configure.py swap` turns one function into C | [new-project.md](docs/new-project.md#what-ps2-new-project-writes) |
| GameCube, Wii | DOL, or a disc (ISO, CISO, RVZ, WIA, WBFS) | decomp-toolkit repository (DOL and RELs), byte-identical rebuild | [new-project.md](docs/new-project.md#gamecube-and-wii) |
| Nintendo 64, PlayStation, PSP | ROM in any byte order, PS-X EXE, PSP ELF (EBOOT/PRX or `ET_EXEC`) | splat repository, byte-identical rebuild | [new-project.md](docs/new-project.md#nintendo-64-playstation-and-psp) |
| Game Boy Advance, Nintendo DS | cartridge image | romwright's own ARM/Thumb units (GBA) or a ds-decomp project (NDS), byte-identical rebuild | [new-project.md](docs/new-project.md#game-boy-advance-and-nintendo-ds) |
| 3DS, Switch, PS3, PS4, Vita, Xbox 360 | the container (your keys with `--keys` where it is encrypted) | **non-matching scaffold**: decompiled C one function per file, target objects of the retail bytes, an objdiff project where objdiff has a backend. No byte-identical build exists for these platforms and none is claimed | [new-project.md](docs/new-project.md#3ds-switch-ps3-ps4-vita-and-xbox-360-the-non-matching-scaffold) |
| Windows PE (i386 EXE or DLL) | PE32 executable | **per-function** repository: romwright's C, the era's Visual C++ (or clang as a compile check), the retail bytes of each function as an i386 COFF object. There is no whole-executable rebuild and no sha1 to hit | [new-project.md](docs/new-project.md#windows-pe-x86-per-function-projects), [pc-project.md](docs/pc-project.md) |

`romwright-cli new-project --list-platforms` prints the same data, and
`romwright-cli detect-compiler <image>` prints the compiler the image was
built with and why. The byte-matching repositories fetch their pinned tools
(some proprietary, none shipped by romwright) with `python3 configure.py`,
which checks every sha256; `match` needs those tools installed. This is the
whole path on the repository's PE32 fixture, with clang as the compile check
so no proprietary compiler is involved (the same commands are run by
`docs/getting-started.md`, "Start a matching project"):

<!-- not gated: the same commands are executed on this fixture by docs/getting-started.md through tests/m6-001_documented_workflow.py -->
```sh
cargo build --release -p romwright-cli -p romwright-worker
./target/release/romwright-cli new-project tests/fixtures-src/tiny_pe32.exe repo \
    --toolchain tests/fixtures-src/pe_clang_profile.json --decompile none
python3 repo/configure.py
./target/release/romwright-cli match 0x00401420 --project repo --budget 4
```

The desktop does both from the open image (Program setup > Create project, and
the Match panel; [docs/desktop.md](docs/desktop.md#new-project-and-match)).
What `match` achieved on real images, per platform and per compiler, is in
[docs/match.md](docs/match.md); it is a search for near misses, not a claim
that a function matches.

## Documentation

| Page | Covers |
|---|---|
| [getting-started.md](docs/getting-started.md) | build, import, read, annotate, decompile, start a matching project (executed by `tests/m6-001_documented_workflow.py`) |
| [new-project.md](docs/new-project.md) | `new-project` and `detect-compiler` for every platform; the platform matrix and limits |
| [match.md](docs/match.md) | the near-miss search, what it varies and what it measured |
| [pc-project.md](docs/pc-project.md) | Windows PE / x86: fixtures, C-output lane, `new-project` and `match` for PC games |
| [desktop.md](docs/desktop.md) | the desktop workstation, its panels, the UI gate and the project gate |
| [core-api.md](docs/core-api.md), [scripting.md](docs/scripting.md) | the stdio/HTTP API and the Python SDK (executed by `tests/m6-002`, `m6-005`) |
| [releasing.md](docs/releasing.md) | build, package, SBOM, manifest, verify (executed by `tests/m6-004_release_artifacts.py`) |
| [environment.md](docs/environment.md), [toolchains.md](docs/toolchains.md), [third-party.md](docs/third-party.md) | every `ROMWRIGHT_*` variable, user-owned toolchains, vendored sources and licences |
| [types-port.md](docs/types-port.md), [printer-ir.md](docs/printer-ir.md), [merge-port.md](docs/merge-port.md), [structs.md](docs/structs.md) | the decompiler's stage ports: types and symbol layout, the print tree, merge, struct recovery |
| [compiler-rules.md](docs/compiler-rules.md), [console-research.md](docs/console-research.md), [c-output-lanes.md](docs/c-output-lanes.md) | import precision rules, the measurements behind the console and PC work, the C-output lanes |
| [import-speed.md](docs/import-speed.md), [ownership.md](docs/ownership.md), [fact-pack.md](docs/fact-pack.md), [vsig.md](docs/vsig.md), [n64-segments.md](docs/n64-segments.md) | import speed, ownership measurement, fact packs, signature databases, N64 segment layouts |
| [structuring-baseline.md](docs/structuring-baseline.md), [upstream-ghidra.md](docs/upstream-ghidra.md), [assumptions.md](docs/assumptions.md), [game-decomp-plan.md](docs/game-decomp-plan.md) | structuring baseline, the pinned Ghidra, standing assumptions, the decomp plan |

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
[`xref_gate.py`](benchmarks/xref_gate.py) acceptance compares all 20 ELF corpus
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
in [docs/environment.md](docs/environment.md).

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

## Honest status

- **Previously gated workflow**: x86-64 ELF + PE (PE32/PE32+) native import
  (section maps, symbols, PLT/GOT naming, unwind and pointer/init seeds);
  current discovery cutover limits are recorded below. Store
  browsing/reopen/rename; SLEIGH disassembly via the pinned console;
  decompilation via the raw-SLEIGH worker — token-identical to the Ghidra
  bridge oracle on the pinned fixtures (differential test).
- **Targeted GameCube sample (`Agent Under Fire`, GQFE78 `base.elf`)**:
  native ELF32 big-endian PowerPC import and JVM-free e500 decompilation
  are verified with the matching vendored SLEIGH bundle. Prototype edits
  are applied through the worker and appear in decompiler tokens.
- **Gate numbers (tiny ELF fixture, this machine)**: Stage-4 workflow peak
  RSS 39.9 MB (3-run median) vs the 375 MiB stock-Ghidra baseline; median
  end-to-end wall 0.32 s vs 10.83 s stock. See
  `benchmarks/reports/stage4-gate.json`. **Out of date for imports (2026-10-15):**
  that report predates the in-process SLEIGH decoder lanes. A tiny ELF import
  now peaks at about 290 MB with the four fixed lanes (152 MB with one, 197 MB
  with two; `ROMWRIGHT_CONSOLE_SHARDS`), still below the stock baseline but
  well above the 50 MB envelope `tests/m7-001_cost_envelope.py` froze, which
  therefore fails (STATUS.md, "Release readiness 2026-10-15").
  **Honest comparison caveat**: this is not an apples-to-apples throughput
  benchmark. The native pipeline performs **no auto-analysis** (import is
  structural discovery; analysis facts come from symbols, flow walking, and
  the in-process SLEIGH decoder) while the stock baseline runs Ghidra's full analyzer.
  Speed/memory win is real but is *at the price of analysis depth* — a trade
  against Ghidra, not a replacement.
- **Historical real-binary measurement (`/usr/lib64/libc.so.6`, 2.48 MB,
  stripped, this machine)**: native import recovered 3,999 functions in 0.54 s (exported
  symbols, init/fini arrays, two-path flow closure); a real 192-byte varargs
  function (`__GI___asprintf`) decompiles natively in 0.9 s. Against the
  Ghidra oracle (3,987): intersection 3,930 — **precision 0.983, recall
  0.986** (69 native-only / 57 oracle-only entries, mostly boundary and
  alias differences). Function-set agreement, not just count proximity.
- **Gate semantics**: `benchmarks/gate.sh` runs every phase (import, functions,
  xrefs, rename, open, disasm, decompile) and passes (exit 0) only when all of
  them run within the bounds; nothing is skipped for a missing optional tool.

## Code-function scoring

Raw SHA-keyed `oracle/*.json` references remain unchanged. The separately
versioned `oracle/scoring-v1/` views exclude only Ghidra synthetic external
placeholders with positive loader evidence: an artificial `EXTERNAL` block,
source `Elf Loader`, and a thunk to an external function. Each exclusion
records its reason and evidence; each view hashes its raw reference and exporter.
Permissions or address-range membership alone never exclude a function.
Executable PLT stubs, thunks and unreferenced code remain scored.

<!-- not gated: reproduces a gate that needs the locked corpus and the pinned Ghidra install; CI runs it in the corpus job -->
```sh
python3 scripts/gen_function_scoring.py --corpus-dir CORPUS \
  --check --report /tmp/function-scoring.json
python3 tests/m1-008b_pointer_seeds.py --corpus-dir CORPUS
```

Omit `--check` to regenerate evidence with pinned Ghidra. `--oracle-dir` and
`--output-dir` support isolated toolchain-specific references without replacing
the committed raw corpus. The policy covers all 20 ELF inputs; the m1-008b
discovery gate covers x86-64 `plain_o0` and `cpp_o2`, with recall >=0.98.
The CI M1 job installs the pinned Ghidra release and separately generates a matching
corpus, raw oracles and scoring views before running `benchmarks/discovery_gate.py`
over all 20 inputs. Its reports and corpus manifest are retained in the
`m1-discovery-reports` artifact even when a step fails.

### DWARF ground truth (M3)

Every `fn.*` number above measures parity with Ghidra: it says the two tools
agree, not that either is right. `benchmarks/dwarf_gate.py` scores against
the compiler instead — concrete `DW_TAG_subprogram` entries from each
unstripped twin, restricted to executable segments and biased to the store's
own image base for ET_DYN (DWARF records link-time addresses; the loader
picks the base; without that bias the PIE rows score 0).

DWARF is silent about CRT stubs, PLT slots and linker-generated code that
both tools legitimately recover, so recall is the metric and the rest is
*attributed*: a symbol in the unstripped twin, a thunk the store proved, a
linker stub inside a `.plt*` section, or a function stock Ghidra also
created. An entry with none of those is an invented function and fails the
gate. Stock Ghidra is scored on the same truth, so later milestones claim
improvement against a recorded number.

| Producer | DWARF functions | Recovered | `dwarf.fn.recall` | Unattributed |
|---|---|---|---|---|
| native import | 1 640 | 1 640 | **1.0000** | **0** of 263 undescribed |
| stock Ghidra 12.1.3 | 1 640 | 1 640 | **1.0000** | baseline column |

<!-- not gated: reproduces a gate that needs the locked corpus and the pinned Ghidra install; CI runs it in the corpus job -->
```sh
python3 tests/m3-001_dwarf_truth.py --corpus-dir CORPUS
```

Thresholds: `dwarf.fn.recall >= 0.98` per row and in aggregate for both
producers, `dwarf.fn.unattributed == 0`. Evidence:
`benchmarks/reports/m3-001.json` (20 rows, per-row provenance digests for the
binary, its twin and the pinned oracle).

### Transfers out of a function

An unconditional branch that leaves its function is recorded as a reference,
because that is how a tail call reaches its target; a branch that lands inside
its own function is a loop and is not recorded. The reference kind follows
Ghidra: `SharedReturnAnalysisCmd.processFunctionJumpReferences` gives a jump
that leaves its function for **another function's entry** a `CALL_RETURN`
override, which makes the reference a call, so Romwright records those as
`UNCONDITIONAL_CALL`. A jump to an address that is *not* a function entry
keeps its `UNCONDITIONAL_JUMP` reference: that is a tail call into code
nobody recovered, and the only record that the code is reached.

Scored against the stock-Ghidra oracle over the 20 locked ELF inputs
(`tests/m5-006_tailcall.py --corpus-dir`, evidence in
`benchmarks/reports/m5-006.json`):

| Metric | Value |
|---|---|
| `flow_xref.jump.precision` | **1.0000** |
| `flow_xref.jump.cross_recall` | **1.0000** |
| `flow_xref.call.precision` | **1.0000** |
| `flow_xref.call.recall` | **0.9830** (1735 / 1765) |

The comparison is kind-exact, so a transfer recorded under the wrong kind
counts against both precision and recall. Recording the transfer does not
create the function: `close_call_targets` acts on call references only, and
the gate asserts the discovered function set is unchanged.

### Thunk parity, compared as sets

`benchmarks/thunk_gate.py` compares thunk *counts* on one host libc. On this
machine that reads **107 against 107 while the two sets differ by thirteen
entries in each direction**, so `tests/m5-008_thunk_parity.py` compares the
facts instead, over the 20 locked ELF inputs plus the host libc when it is the
image the committed baseline was recorded from
(`benchmarks/reports/m5-008.json`):

| Metric | Value |
|---|---|
| `thunk.entry.recall` | **1.0000** (185 / 185) |
| `thunk.entry.precision` | **1.0000** |
| `thunk.entry.unexplained` | **0** |
| `thunk.destination.unexplained` | **0** |

Two model differences are named and asserted rather than averaged away:

* **Destination.** Ghidra hops PLT stub → EXTERNAL-block stub → external
  symbol; Romwright hops PLT stub → the GOT slot the stub's own instructions
  read. A row counts as explained only when the stock destination lies outside
  every image mapping *and* the Romwright destination is an in-image address
  carrying the same import name. 71 rows are explained this way; 114 match
  exactly.
* **Entry.** For thirteen libc stubs Ghidra records the thunk on the slot
  inside its EXTERNAL block instead of on the stub. Those are accepted only
  because the slot symbol names match one-for-one -- the same thirteen symbols
  on both sides, which is what the count comparison was accidentally counting.

A thunk with neither explanation fails the gate, as does a stock thunk whose
entry is in the image and which Romwright does not record.

### Function names against stock Ghidra

Every function name in the store is compared with stock Ghidra's name for the
same address over the 20 locked ELF inputs
(`tests/m5-010_initializer_names.py`, `benchmarks/reports/m5-010.json`):

| Class | Rows |
|---|---|
| names equal | 1818 |
| proven-equivalent label (same address, different source) | 74 |
| pattern label applied from the pattern that matched | 11 |
| unexplained | **0** |

Initializer-array targets take the name their array gives them: the base and
size come from `DT_INIT_ARRAY` / `DT_PREINIT_ARRAY` / `DT_FINI_ARRAY`, the
target from the slot's own word or the relocation applied to it, and the index
from the slot's position -- the same construction as
`ElfProgramBuilder.createDynamicEntryPoints`. Only a generated `FUN_` name is
replaced; a symbol keeps its name, as it does in Ghidra.

A *proven-equivalent* label is the same address named from a different source:
Romwright says `_entry`, `_init`, `_fini` and `_plt` from the ELF header and the
section table where Ghidra says `entry`, `_DT_INIT`, `_DT_FINI` and nothing.
The gate proves each one by reading the header, the dynamic table or the
section table, so "equivalent" is never a shrug.

The 11 pattern-label rows are `__i686.get_pc_thunk.*`, named from the
`<funcstart label=...>` attribute of the pattern that matched at that address
in `Ghidra/Processors/x86/data/patterns/x86gcc_patterns.xml` -- the same label
the console already uses to install a call fixup there.
`tests/m5-011_pattern_labels.py` checks both directions against the bytes:
bytes matching a labelled pattern must carry its name, and a function carrying
a pattern label must have the matching bytes at its entry. A label applied to
the wrong function fails the gate (verified by mutation).

### Names at linkage stubs

A stub whose slot the store resolves takes that slot's import name, from the
same evidence that recorded its linkage thunk. Only a generated `FUN_` name is
replaced: a name from a symbol or from the section table stands. Scored
against stock Ghidra's own name at every thunk entry it records inside the
image (`tests/m5-009_linkage_names.py`,
`benchmarks/reports/m5-009.json`, 20 locked ELF inputs):

| Class | Rows |
|---|---|
| names equal | 71 |
| synthetic `_INIT_n` label not copied, fact held as a reference | 20 |
| import name proven but not applied | **0** |
| names with no symbol at their own address | **0** |

`_INIT_0` is Ghidra's label for an entry of `.init_array`. Romwright does not
copy it: the fact is the reference from the initializer array, which the store
holds (`native-import:elf-pointer`, or `native-import:elf-reloc` for a PIE),
and the gate accepts that class only when the reference really is there. A
name with no symbol at its own address fails the gate even when it agrees with
Ghidra, so agreement can never be manufactured.

### Promoting a tail-call target (off by default)

`ROMWRIGHT_PROMOTE_TAILCALLS=1` lets a recorded transfer create the function it
reaches. Stock Ghidra creates none of these, so the pass moves output past the
frozen baseline and stays off unless asked -- AGENTS.md II.1 reserves enabling
it. The evidence a candidate must supply is the evidence a relocation
candidate supplies (m1-005):

* the address is executable, image-backed code;
* it does not sit inside a body another entry already proved;
* its own flow decodes from that address to a terminator, and does not run
  into another function's entry -- code reached without a prologue belongs to
  that function.

Measured (`benchmarks/reports/m5-007.json`): on the NDS fixture the pass
recovers `mix`, a leaf entered only by `b`, taking `nds.arm7` from
**0.7500 to 1.0000** DWARF recall with zero invented functions; over the 20
locked ELF inputs it promotes **nothing** -- every transfer there already
lands on a known function -- and adds **0 unattributed functions**, with no
row below the committed m3-001 recall.

### The frozen stock-Ghidra baseline (M3)

M4 exists to improve on stock Ghidra, and that claim is worthless against a
remembered number. `benchmarks/ground_truth_baseline.py` records one:
`benchmarks/reports/baseline-ghidra-truth.json`, what stock Ghidra 12.1.3
scores against DWARF on the locked corpus. Without `--write` the script
recomputes and compares; a moved metric fails the gate instead of being
re-baselined, and the recorded `readelf` version travels with the numbers so
a different DWARF reader is reported rather than mistaken for a regression.

| Stock Ghidra 12.1.3 vs DWARF | Value |
|---|---|
| `ghidra.dwarf.fn.recall` (1 640 functions) | **1.0000** |
| `ghidra.dwarf.proto.arity` (1 640 matched) | **0.7537** (1 236 correct) |
| functions created | 2 008 |

The arity number is uneven, not uniformly good: 0.9975–1.0000 on x86-64,
AArch64 and PowerPC, and **0.0000 on i386 `many_o2`** — Ghidra's
`DecompilerParameterIdCmd` commits zero parameters for 413 of that image's
415 functions. Reproduced from a fresh `analyzeHeadless` run, so it is a
stock result, not an export artifact, and it is the clearest M4 target on
record.

<!-- not gated: reproduces a gate that needs the locked corpus and the pinned Ghidra install; CI runs it in the corpus job -->
```sh
python3 tests/m3-002_baseline.py --corpus-dir CORPUS
```

### Console platforms (M5)

The first console target is the Game Boy Advance, chosen because it can be
*proved* with the machinery that already exists: `ARM:LE:32:v4t` ships in the
pinned install, the container is publicly documented (gbatek "Cartridge
Header" and "Memory Map"), and the fixture is built from committed source, so
DWARF scoring applies unchanged.

A raw ROM has no sections, no symbols and no entry field. The loader
recognises it only when the fixed 0x96 at 0xB2 is in place **and** offset 0
is an unconditional ARM branch whose target lands inside the image; then it
maps ROM at 0x08000000, resolves that branch as the entry seed, and declares
the console's RAM and IO windows without giving them invented bytes.
Discovery finds the rest from flow.

| GBA fixture | Value |
|---|---|
| DWARF functions | 6 |
| `dwarf.fn.recall` | **1.0000** |
| entries with no attribution | **0** |
| native decompilation | verified on a recovered function |

<!-- not gated: reproduces a gate that needs the locked corpus and the pinned Ghidra install; CI runs it in the corpus job -->
```sh
python3 tests/m5-001_gba.py
```

Two defects had to be fixed to get there, both of which affected every
non-x86 language:

- **Injections were unreachable without a JVM.** In raw-SLEIGH mode the
  decompiler asked the *client* for every p-code injection
  (`inject_ghidra.cc:56`), which a JVM-free worker cannot answer, so any
  language whose semantics use one could not be decompiled at all -- ARM `bx`
  emits `CALLOTHER setISAMode`. The patched worker now compiles injections
  from the loaded compiler spec (`PcodeInjectLibrarySleigh`).
- **Exported compiler specs lost those bodies.** `CompilerSpec.encode` cannot
  reproduce a compiled `InjectPayload`, so it wrote placeholders. The bridge
  now copies the language's compiler spec file verbatim, and the platform
  gate fails if a bundle still carries a placeholder body.

#### Nintendo DS: one container, two programs

A DS cartridge carries an ARM9 image and an ARM7 image with different
architectures, load addresses and entry points (gbatek "DS Cartridge
Header", fields at 0x20 and 0x30). A program in the store holds one
language, so `import` stores **two** programs -- `<name>.arm9` and
`<name>.arm7` -- and prints a line for each. `import_container` returns them
all; the API keeps the booted program at the top level and lists the rest
under `programs`.

Detection is arithmetic, not a magic number: every declared region must fit
the file, the two images must not overlap, each entry must land inside its
own image, and each load address must be where gbatek says that CPU's code
runs. Seven unit tests pin the refusals.

| Program | Language | DWARF functions | recall | Unattributed |
|---|---|---|---|---|
| `nds.arm9` | `ARM:LE:32:v5t` | 5 | **1.0000** | 0 |
| `nds.arm7` | `ARM:LE:32:v4t` | 4 | 0.7500 | 0 |

The ARM7 miss is recorded, not rounded away: `mix` is entered only by a tail
call (`b`), so nothing references its entry, and **stock Ghidra misses it on
the same stripped bytes too** -- it absorbs the range into the caller's
extent. The gate pins that one address; a new miss fails, and recovering it
requires updating the record.

<!-- not gated: reproduces a gate that needs the locked corpus and the pinned Ghidra install; CI runs it in the corpus job -->
```sh
python3 tests/m5-002_nds.py
```

#### PlayStation and Nintendo 64

Both are a header plus one flat image, and both are accepted only when the
header agrees with the file it sits in.

| Platform | Header fields read | Language | recall |
|---|---|---|---|
| PS-EXE | magic, initial PC (0x10), destination (0x18), size (0x1C) | `MIPS:LE:32:default` | **1.0000** over 5 |
| N64 `.z64` | PI configuration word (0x00), boot address (0x08) | `MIPS:BE:64:64-32addr` | **1.0000** over 5 |

A PS-EXE is refused when its declared size is not in the file, when the
destination is not main RAM (through any of the three MIPS segment windows),
or when the initial PC falls outside the image it describes.

**Byte-swapped N64 dumps (`.v64`, `.n64`) are refused with their reason**
rather than mapped: the JVM-free worker reads the file's own bytes, so a
swapped dump would decompile reordered instructions. Converting to native
order is the user's step, not a silent guess by the loader.

#### Nintendo Switch

An NSO0 module is three LZ4-block-compressed segments and a header that says
where each goes in memory; the module carries ELF machinery inside it, reached
through the `MOD0` header that the word at text offset 4 names. The loader
assembles the image, maps it at `0x71_0000_0000` -- where a 64-bit module goes
-- applies `DT_RELA` and `DT_JMPREL` before mapping, and reads the module's own
`.dynsym`, whose length comes from `nchain` in `DT_HASH`. The LZ4 decoder is
60 lines against the block-format specification; no dependency was added.

| Xenoblade Chronicles: Definitive Edition `main` | Value |
|---|---|
| functions recovered, no JVM | 43465 in 420 s |
| `symbol.recall` over the module's 42423 `STT_FUNC` symbols | **1.0000** |
| `symbol.precision` (1042 found that no symbol names) | 0.9760 |
| share of stock Ghidra's 45259 (Adubbz `SwitchLoader` in the pinned install) | 0.9604 |

The gate parses the module's symbols itself, with a different LZ4
implementation and a different dynamic-table reader, so the score does not
rest on the loader it scores. The image is a retail dump: absent it, the gate
skips and says why.

<!-- not gated: needs a retail dump that is not in the repository -->
```sh
python3 tests/m5-017_switch_module.py
```

### Loading is not analysing

An import used to answer nothing until the whole image had been walked: 849 s
on a 60 MB Switch module, 92 s on the host libc. Loading is a parse -- mapped
bytes, declared regions, relocations, and the image's own symbol table -- and
that is what an analyst needs before anything else can be shown.

`romwright-cli import <binary> --no-analysis` does exactly that, and analysis is a
separate pass over the same store. Measured (`tests/m14-001_interactive_import.py`,
`benchmarks/reports/m14-001.json`):

| | Loaded | Analysed | Reused from cache |
|---|---|---|---|
| host libc (3898 named functions) | **1.01 s** | 130.8 s | **0.41 s** |
| Switch module (42423 named functions) | **3.96 s** | 849 s | -- |

Every function the fast path lists is one the image itself names: the gate
fails if a single name is not a symbol, a linkage stub named after its
import, or a generated name at an address the loader declared.

Reuse is keyed on the image's bytes together with the digests of the analyser
that reads them -- this executable (which carries the SLEIGH lifter), the decompiler worker
-- the configuration that changes facts, and the store schema. A second
import of an unchanged image restores 32 byte-identical tables in 0.41 s;
changing any fact-affecting switch misses the key and re-analyses, which the
gate also checks. `ROMWRIGHT_NO_IMPORT_CACHE=1` switches it off, as a gate that
measures import cost must.

Later rounds re-walk from every seed, but the instructions an earlier round
decoded are kept (`NativeImport::flow_cache`) rather than decoded
again; a mode context new to the image or to the walk drops what it could
re-mode. GBA 808 to 604 s, fact digests identical. An opt-in walk that resumed
from the previous round's state was removed: its facts never matched the
batch walk's.

### Jump tables without the decompiler, and better than stock

Switch recovery was the last pass in a native import that called the
decompiler, and the most expensive: 130 of 137 s on a statically linked
AArch64 image. SLEIGH's p-code is lifted in process
(`crates/romwright-core/src/native_runtime/lift.rs`, kuna's Rust SLEIGH
runtime) and `native/vsa.rs` emulates the dispatch path once per index, as
`JumpBasic::buildAddresses` does over the decompiler's IR.

It is scored against truth rather than against stock, because stock is the
baseline to beat, not the answer: a case target is right when it decodes as
an instruction **and** lies inside the extent of the function that branches to
it, taken from the image's own symbol table. On the host libc, 34 of stock's
targets fall outside the branching function and 5 do not decode
(`tests/m13-001_vsa_switch.py`, `benchmarks/reports/m13-001.json`):

| Path | Dispatches | Targets | Unsound | Soundness | Switch phase |
|---|---|---|---|---|---|
| stock Ghidra | 132 | 1891 | 39 | 0.9794 | -- |
| decompiler only | 130 | 1813 | 8 | 0.9956 | 62 s |
| value-set analysis only | 90 | 883 | **1** | **0.9989** | 0.85 s |
| **both (default)** | **142** | 1832 | 6 | **0.9967** | 0.4 s + 55 s |

The default answers **13 dispatches stock has no table for** and misses 3 of
stock's. The 13 are real: relative tables in the hand-written SSE string
routines, which stock's decompiler declines. `ROMWRIGHT_NO_SWITCH_VSA=1` turns
the pass off.

Four rules earned their place by measurement: a table must be read by a
*strided* load; the bound is the *guard branch* being taken, not any constant
compared nearby; guard analysis runs separately from path emulation, per
predecessor block, on the dispatch block's *real* predecessors (taken
positionally, a guard was found for 15 of 132); and the tracked index is held
through the guard block, because a guard recomputes it from values the
emulator cannot know and then compares the very value that reaches the
dispatch -- that rule alone took the pass from 18 dispatches to 90.

One function's decompile is now bounded at 60 s and the child killed, which is
Ghidra's own remedy (`DecompileProcess.sendCommandTimeout` arms a timer whose
only action is `dispose`; `DecompilerSwitchAnalyzer` sets 60 seconds). An
import that never finished now takes 137 s, and the signature gate went from
two 900 s timeouts to 871 of 871 matches correct in 237 s.

### The ground-truth regression gate (M3)

`benchmarks/regression_gate.py` joins the two: native against DWARF from
m3-001, the frozen stock baseline from m3-002, per corpus row. It
re-measures both by default (about a minute) because stale evidence is the
likeliest failure, and it refuses evidence whose recorded source hashes no
longer match the tree.

| Family | native | frozen baseline |
|---|---|---|
| `dwarf.fn.recall` (1 640 functions) | **1.0000** | 1.0000 |
| `proto.arity` (1 640 matched) | **0.7537** | 0.7537 |

Two rules, and one honest admission:

- **native >= baseline per row.** Falling behind stock Ghidra fails, even
  where the absolute number still looks respectable.
- **The deficit set is pinned.** A row where *either* producer scores below
  0.98 against truth is named in the report, so matching a broken reference
  cannot read as success. Today exactly one: `i386_many_o2:proto.arity`,
  where stock Ghidra and native both score 0.0000. A new deficit fails the
  gate; a fixed one has to be recorded rather than quietly absorbed.
- Native currently *equals* the baseline everywhere. M3 measures; M4 is where
  exceeding it is the job.

<!-- not gated: reproduces a gate that needs the locked corpus and the pinned Ghidra install; CI runs it in the corpus job -->
```sh
python3 tests/m3-003_regression.py --corpus-dir CORPUS
```

Native ELF32/ELF64 discovery shares `.init`, `.fini` and `.plt` section-start
seeds, alongside unwind-index entries, PLT metadata, flow-confirmed
initializer/data pointers and the existing batched flow walker.
Established function entries can seed pure direct-jump thunk destinations,
optionally after one contiguous instruction with no SLEIGH p-code operations.
The in-process flow decoder supplies the explicit `no_op` and `pure_jump`
evidence. Missing evidence fails closed. Multiple prefixes,
conditional/interior branches, effects, weak seeds and jump chains returning
into their own body do not establish additional functions.

ELF/PE discovery now uses the generic SLEIGH worklist over native mappings;
without the optional console, only structural facts are retained. The
`x86_decoder` discovery feature and hand-versus-console comparison scripts
are removed. The small instruction decoder remains for listing and graph
consumers, not as a discovery accelerator.

ELF PIE addresses use Ghidra's loaded coordinate system: a zero-based ELF64
receives bias `0x100000`, ELF32 `0x10000`; nonzero prelinked bases are preserved.
REL, RELA and RELR pointer words are materialized with ELF width/endianness.
Native memory, console images and both worker paths share those loaded bytes,
including BSS zero-fill. Scoring performs no address normalization.

The all-20 discovery gate reports **20 pass, 0 fail, 0 skipped**, with the
architecture check passing and precision/recall 1.0 on every x86-64, i386,
AArch64 and PowerPC BE32 row. The separate stripped-DOL acceptance matches
634/644 reference functions (recall 0.984472; precision 0.940653).
These are discovery results, not a claim of complete program-model parity.

## Native function constants

The in-process propagation (`native_runtime/propagation`,
`Propagator::constants`) evaluates the function over `[start, end)` using
native p-code from the kuna-sleigh lifter. It returns `ConstantFact` rows with
`pc`, `value`, and varnode storage (`space`, `offset`, `size`). Only
pointer-sized constants targeting the image's mappings are reported;
symbolic register/stack offsets are never reported as literal addresses.

Initial writable memory is untrusted unless explicitly enabled. Queries do not
modify image bytes or persist references. Undecodable flow and exhausted
analysis limits produce errors, not successful empty analyses.
This M2 primitive does not establish program-model parity or enable a new
import analyzer by default.

## Native string facts

Native import stores null-terminated ASCII, UTF-8, and endian-aware UTF-16
data strings with at least four Unicode scalar values. BOMs, data-reference
starts, and UTF-16 alignment resolve overlapping candidates. Existing data
references retain their physical source and target addresses.

ELF string tables retain their declared UTF-8 encoding, including non-loaded
tables. Metadata addresses are space-qualified in the desktop table
(`.shstrtab::0x1`), not displayed or cached as RAM. Database format 6 introduced
typed non-RAM addresses; existing RAM hex cells require no re-encoding.

Worker string queries serve those RAM facts as UTF-8, without guessing strings
from unclassified backing bytes. Their character limits follow Ghidra's UTF-16
code-unit convention; responses include the byte length, truncation flag, and
NUL terminator. Missing facts and valid empty strings remain distinct.

`benchmarks/string_gate.py` compares the unchanged 20-entry corpus against
defined reference strings. Its summary links hashed per-binary difference
files in `<report-stem>-details/`; no missing or extra addresses are discarded.

## Prototype and type storage

Database format 7 adds prototype ownership, producer, and optional confidence.
Prototypes and xrefs share `FactProvenance`: `asserted` or `inferred`, a source
label, and confidence in `[0, 1]` or `null` when unknown. Inference cannot replace
an assertion; bulk prototype replacement retains assertions. Legacy prototype
records retain their signatures and conventions with unknown source/confidence.

The existing `type_defs` and `type_fields` tables store primitives, pointers,
arrays, and composites. `primitive` classifies signed/unsigned integers, floats,
booleans, or void; `base_type` identifies pointer/array targets; `element_count`
is nullable and preserves zero-length arrays. Composite fields retain their
ordinal, offset, size, and type reference. Legacy kind labels and unclassified
records remain intact. This is storage support, not a claim of recovered
prototype or type-analysis parity.

Structured native decompilation also returns an optional `prototype` alongside
the existing tokens: calling convention, ordered parameters, return type, and
variadic status. These come from packed function metadata and local parameter
symbols, never from parsing rendered C. Named types retain their native IDs;
inline pointer/array/function types retain their nested targets. Missing type
details remain unknown, and incomplete structural documents have no prototype.
This read path does not persist inferred signatures or change store revisions.

The optional `function_ir` is the semantic representation: stable value and
operation IDs, SSA operations, control-flow edges, high variables and native
type/symbol evidence. C tokens are a presentation, not the semantic authority.
Token `varnode`, `operation`, `symbol_id` and `datatype_id` references remain
independent. Native metadata IDs are unsigned 64-bit values; JSON clients must
preserve integer precision rather than round them through JavaScript `Number`.

Evidence, transformation, structuring and diagnostic passes have separate
contracts; transformations propose typed edits and structuring proposes
original CFG edge cuts. The native worker applies those proposals to the live
function and returns new C tokens and a graph checked against the proposal.
Unverified `DAT_*` literal replacement and text-only helper rewriting are not
supported. Division/remainder helper rewrites require a locally applied,
full-function byte signature bound to the current input and matching native
operand/result widths and signedness.

C tokens are printed by the worker's Rust printer from the printer IR
`ghidra_opt` exports with every decompile (docs/printer-ir.md), after
structuring models that rewrite Ghidra's structured tree to print fewer
`goto`s (`ROMWRIGHT_RUST_STRUCTURING`, default `all`; `none` prints Ghidra's
own structure, byte-identical to PrintC). A response without the printer IR
is an error, never a PrintC fallback.

The same document exposes `jump_tables`: typed branch addresses and ordered
target addresses, including duplicate case destinations. `[]` means a complete
native function has no recovered tables; `null` means structural metadata is
unavailable or incomplete. Targets come from packed native jump tables, not
rendered C. This does not infer case labels/default identities, persist new
functions, or trigger rediscovery. The positive acceptance exercises one
seven-target indirect branch through standalone and warm pooled workers:

<!-- not gated: reproduces a gate that needs the locked corpus and the pinned Ghidra install; CI runs it in the corpus job -->
```sh
python3 tests/m2-007_switches.py
cargo test -p romwright-worker --test jump_tables
python3 benchmarks/switch_gate.py --corpus-dir "$CORPUS" \
  --report benchmarks/reports/m2-007.json
```

The corpus comparison records exact recovered branch/target sets against fresh
stock exports and preserves immutable references in `oracle/switches-v1`.
Zero-table cases are not positive recovery evidence. This comparison adds no
II.3 metric and is not the full M2 program-model parity gate.

Standalone and pooled workers consume Core's captured input and configuration,
including the stored language. They share provider metadata and specification
registration, including core types, decode contexts and tracked ABI registers.
The default interactive job budget is 60 seconds. One absolute deadline covers
queueing, registration, native commands, semantic passes and publication; retries
and additional phases do not receive a fresh clock. Cancellation interrupts
native I/O, and owned child process groups are killed and reaped. Late or
stale-revision output is not published or returned to the warm pool.

Imports capture binary, mapping and key inputs as content-addressed artifacts.
Execution requests select an explicit imported image; a mutable source pathname is
not a substitute for the captured input. Warm demand analysis keeps at most four
program images, evicts obsolete inputs and atomically publishes function extents
and references against the captured revision. Its completion stamp is the final
committed revision, so an unchanged next request can reuse the analysis.

Stored call xrefs seed callee prototypes, but are not assumed exhaustive:
newly encountered native calls activate their stored prototypes before semantic
transformation. Unrelated prototypes are not parsed. Recovery unlocks inferred
target parameters, return type and calling convention; stored callees and
analyst assertions remain locked. Inferred declarations never rename functions.
The native command resets its parameters between applications.

The internal standalone worker interface is
`romwright-worker <ghidra_opt> <lang-dir> <program> <addr-hex>... --project DIR`;
binary paths and rebasing are no longer worker arguments. The selected input
comes from the captured request or the project's input record. `--structure`
reads graph requests from stdin under the same stored-input contract.

Matching runs retain the captured source/context, recipe, compiler identity,
distinct target/candidate objects, diagnostics and objdiff result. Identical
object bytes are valid, but the two comparison paths must remain distinct.
Compile failures are durable results; cancellation and revision conflicts
prevent publication. These controls do not sandbox compiler commands: use
trusted recipes and the existing local-only deployment boundary.

Core can persist a completed recovery batch through the existing prototype
store. Nested pointer/array/callback declarations are rendered from structured
types; absent types are rejected rather than replaced by `void`. The write
checks its input revision, retains assertions, and leaves unchanged facts at
the same revision. Native round-trips cover variadic callback pointers.
The API method `infer_prototypes` takes `binary`, `program`, optional `base`,
and `budget_ms` (default 60000). It analyzes all functions once, then only
callers of changed callees, for at most 3 rounds under one absolute deadline.
It reports completed `rounds`, `analyzed` functions, changed facts, and a
`stop_reason` of `converged`, `round_limit`, or `budget`. An interrupted partial
round is discarded; zero budget starts no worker and writes no facts.
Imported linkage entries retain their flow-proven external identity in the
store. Their unresolved callee signatures are not persisted as `void(void)`;
inference must not turn an unknown library prototype into a locked zero-argument
fact that removes live inputs from callers. Analyst-supplied signatures still
apply normally.
Context-dependent entries require a bounded pure-linkage shape plus one
consistent imported read slot from completed propagation within that exact span.
Direct-call targets are evaluated by that same proof, so import names come from
relocation slots on architectures without a recognized PLT table layout.

<!-- not gated: builds native components whose toolchains are host-specific; the workflow they enable is gated by tests/m6-001_documented_workflow.py -->
```sh
cargo build -p romwright-cli -p romwright-api -p romwright-worker
python3 tests/m2-005_prototype.py
python3 tests/m2-006_revision.py
cargo test -p romwright-worker --test prototype_recovery -- --ignored
python3 tests/m2-006_inference.py
python3 tests/m2-006_thunks.py --corpus-dir /path/to/corpus
python3 tests/m2-006_thunks.py --corpus-dir /path/to/corpus --architecture powerpc
```

`infer_nonreturning` takes `binary` and `program`; `return_behaviors` reads the
stored facts for a `program`. This is an explicit pass, not an import default.
Seeds combine the pinned Ghidra ELF/PE no-return names, protected stored facts,
and completed native decompiler CFG hints (`prototype.no_return`). Complete
executable flows without reachable returns establish further facts; missing,
invalid, or unresolved indirect flow remains unknown. Known non-returning
callees terminate call fallthrough, and their callers are reanalyzed. Hint
workers start from assertions only, never recycling this pass's old inferences.
Schema v8 publishes owned inferred facts, completed caller extents, and owned
call xrefs in one revision-checked transaction. Assertions and other sources
remain protected; unsupported previous inferences are retracted. Repeating an
unchanged analysis does not bump the revision. Standalone and pooled workers
apply stored no-return flags without overwriting asserted prototypes.

<!-- not gated: reproduces a gate that needs the locked corpus and the pinned Ghidra install; CI runs it in the corpus job -->
```sh
python3 tests/m2-008_nonreturn.py --report benchmarks/reports/m2-008-positive.json
python3 tests/m2-008_ppc_linkage.py --corpus-dir /path/to/corpus
python3 benchmarks/nonreturn_gate.py --corpus-dir /path/to/corpus \
  --report benchmarks/reports/m2-008.json
```

The locked-corpus comparison uses `code-functions-v1` eligibility and fresh,
context-matched stock return flags and function body ranges. It records II.3
`fn.bounds` before/after inference and requires improvement over the unchanged
optimized recipes; it is not the full M2 parity gate. Current-provenance raw
and scoring references can be supplied with `--raw-oracle-dir` and
`--scoring-dir`. The temporary fixture proves positive inference and caller
fallthrough removal; it is not a replacement corpus member.
Stock `hasNoReturn() == false` is absence of metadata, not proof of returning:
the comparison requires coverage of stock positives and reports additional
native inferences separately. Compressed, hash-linked reference evidence keeps
the raw oracle, scoring view, and exact body/flag export; architecture reports
and JSONL mismatch sidecars retain the complete comparison.

`thunks` reads persisted thunk facts for a `program`; native import publishes
them. A `direct` fact names the thunked function entry, a `linkage` fact the
proven import slot the stub leaves through. Recognition follows one
unconditional transfer from a function entry: a jump to another entry, a jump
or call to a pinned non-returning function, or a proven PLT/ifunc stub. A tail
call from inside a larger body is not a thunk. Facts are owned per producer, so
re-import refreshes them while assertions and other owners survive. Schema v9
stores them; an unchanged pass bumps no revision.

<!-- not gated: reproduces a gate that needs the locked corpus and the pinned Ghidra install; CI runs it in the corpus job -->
```sh
python3 tests/m2-009_thunks.py
python3 benchmarks/thunk_gate.py --report benchmarks/reports/m2-009.json
```

The libc comparison scores thunk-function counts against fresh stock analysis
within ±1% on one host libc; it is not an II.3 metric or the full M2 gate.
Report evidence links hash-verified JSONL lists of matched, native-only and
stock-only entries. Ghidra also creates thunks at synthetic external-linkage
addresses outside every image section; native records the executable stub that
reaches the same import instead.

The benchmark-only arity reference runs stock parameter ID on the 20 stripped
ELF corpus entries, then scores against their unstripped DWARF twins. It never
loads DWARF into either analyzer. References are immutable; `--check` verifies
and scores them without rerunning stock analysis. Reports retain complete
mismatches in SHA-256-linked JSONL files.

`romwright-cli signatures build` turns one static archive into a `.vsig` database
(`docs/vsig.md`): every exported `STT_FUNC` symbol becomes a byte pattern whose
relocated bytes are masked out, using the public relocation widths for that
architecture. A relocation type with no ABI width in the tables skips its
function instead of guessing, patterns carrying fewer than `--min-bytes`
compared bytes are dropped, and one name defined twice with different bodies is
dropped entirely. Package and license are required arguments: they are
declared, never inferred. `signatures info` decodes a database and reports its
records, languages, packages and licenses.

<!-- not gated: illustrates the surfaces documented and executed by docs/core-api.md and docs/scripting.md -->
```sh
romwright-cli signatures build --archive libc.a --package glibc-2.36-8 \
  --license LGPL-2.1-or-later --out libc.vsig --report libc.json
romwright-cli signatures info --db libc.vsig
python3 benchmarks/signature_gate.py --report benchmarks/reports/m2-011.json
```

The gate builds databases from the pinned cross sysroot archives, checks that a
rebuild is byte-identical, and reports record count and byte size per source.
Missing archives are recorded as skipped with a reason, not silently passed.

`import --signatures DB[,DB]` runs the matcher after the import; the API
takes the same list as `import_native`'s `signatures` parameter, `apply_signatures`
repeats the pass on a stored program, and `signature_matches` reads the facts.
Each match is an inferred fact with its package, license, compared bytes and
confidence; it renames only generated `FUN_*` names, and databases that
disagree about a function leave it unnamed. Schema v10 owns the facts per
producer, so a repeated pass writes no new revision.

<!-- not gated: illustrates the surfaces documented and executed by docs/core-api.md and docs/scripting.md -->
```sh
romwright-cli import ./program --name p --signatures libc.vsig
python3 benchmarks/match_gate.py --report benchmarks/reports/m2-012.json
```

The match gate statically links a corpus source against a pinned `libc.a`,
strips it, and scores every match against the unstripped twin: `docs/vsig.md`
records the measured false-positive rate.

Native import also recovers Itanium C++ classes from the image itself:
`classes` reads the facts, `recover_classes` repeats the pass. A loader-bound
relocation naming one of the ABI's `__cxxabiv1` type_info vtables anchors the
chain, the word after a `type_info`'s vptr must be a mangled type name, and a
data word holding that `type_info`'s address is a vtable's `type_info` slot.
Each fact carries the primary vtable, its function-pointer slot count, the ABI
shape (`class`, `single_base`, `multiple_base`) and the base list with offsets
and virtual/public flags. Names are demangled only for the grammar the parser
covers; anything else keeps its mangled form. Schema v11 owns the facts.

<!-- not gated: reproduces a gate that needs the locked corpus and the pinned Ghidra install; CI runs it in the corpus job -->
```sh
python3 benchmarks/rtti_gate.py --corpus-dir /path/to/corpus \
  --report benchmarks/reports/m2-013.json
```

The gate compares recovered classes with the compiler's own `_ZTV` symbols in
unstripped twins, across PIE and non-PIE links, and requires the locked corpus
C++ entries — whose source declares no classes — to stay empty.

PE images take the MSVC path into the same facts. A `TypeDescriptor` is found
by its `.?A` decorated name, a `RTTICompleteObjectLocator` is confirmed by its
signature, the descriptor it names, its hierarchy descriptor and — on 64-bit
images — a self reference that fixes the image base without reading a header.
Bases come from the class hierarchy descriptor's base array, with the `PMD`
displacement triple deciding offset and virtual inheritance.

<!-- not gated: reproduces a gate that needs the locked corpus and the pinned Ghidra install; CI runs it in the corpus job -->
```sh
python3 benchmarks/msvc_rtti_gate.py --corpus-dir /path/to/corpus \
  --report benchmarks/reports/m2-014.json
```

That gate links a freestanding MSVC-ABI fixture for both machine widths — no
MSVC installation needed — and compares recovery with the link map's own
`??_R4` complete object locators.

<!-- not gated: reproduces a gate that needs the locked corpus and the pinned Ghidra install; CI runs it in the corpus job -->
```sh
python3 scripts/gen_prototype_oracle.py --corpus-dir "$CORPUS" \
  --report benchmarks/reports/m2-006-reference.json
```

The native gate checks all 20 frozen references, runs inference on stripped
inputs, and scores persisted prototypes against DWARF with the same metric.
Known functions without persisted prototypes count as incorrect, not as missing
matches. Each case must reach stock arity accuracy minus 0.02; missing inputs
or references cannot produce a passing gate. Architecture detail and complete
mismatch records are linked from the aggregate by SHA-256.
The committed m2-006 run passes 20/20 cases with no skips and equals stock in
every case. This includes i386 `many_o2`, where both score 0/401; relative
parity is not an absolute accuracy claim.

<!-- not gated: reproduces a gate that needs the locked corpus and the pinned Ghidra install; CI runs it in the corpus job -->
```sh
python3 scripts/gen_native_specs.py --corpus-dir "$CORPUS"
python3 benchmarks/prototype_gate.py --corpus-dir "$CORPUS" \
  --report benchmarks/reports/m2-006.json
```

## Getting started

`docs/getting-started.md` walks from `cargo build` to a decompiled function
using the fixture binary in this repository, and states which steps need the
pinned Ghidra install for SLEIGH language data. Every command and every output
line on that page is executed by `tests/m6-001_documented_workflow.py`, in
both environments -- with the pinned Ghidra install and without it -- so the page
cannot drift from the tool. That gate also fails when the CLI dispatches a
verb its own usage text does not list, which is how `xrefs`, `undo`, `open`,
`comment`, `comments` and `types` were found missing from it.

## Releasing

`docs/releasing.md` documents the procedure -- build, stage, SBOM, manifest,
verify -- and `tests/m6-004_release_artifacts.py` runs those commands and
checks the results: every artifact manifested with its size and digest, the
SBOM naming **every** workspace crate with a declared licence,
verification rejecting both a flipped byte (`SHA-256 mismatch`) and a
truncation (`size mismatch`), and the staged `romwright-cli` writing a
project from its embedded templates and pinned tool manifest (the desktop
archive ships that CLI too). Tagging stays reserved to the human, and the
page states what is *not* claimed: no reproducibility, no signing.

## The desktop workstation

`docs/desktop.md` documents the build, the release archive written by
`packaging/package_desktop.py` and the launch, and
`tests/m6-003_desktop_package.py` runs that packaging command, extracts the
archive into a clean prefix and launches the *extracted* `romwright-desktop`
headless (wgpu offscreen, on a software adapter when there is no GPU) with
every `ROMWRIGHT_*` variable removed. Two metrics the app measures for itself
replace an assertion that was previously handed to it:
`ui.install.prefix_ok` (not a build tree) and `ui.install.store_only_ok` (no
external configuration). Both go false when they should -- a build-tree binary
and a configured run each fail the gate. The report names the platform it ran
on and the wgpu adapter it rendered with; the CI `desktop` job runs it on
Linux, macOS and Windows.

`tests/m6-007_desktop_projects.py` drives the same extracted app through
`--gate --project-image`: Program setup's **Create project** runs the shipped
`romwright-cli new-project` on the open image, and the Match panel runs
`match` on the largest function of the repository it wrote and paints the
variant table (`ui.new_project.*`, `ui.match.*`); it needs the Ghidra install
and a `clang` and is skipped, saying so, without them.

## Every fact says what proved it

A fact's `source` names the pass that produced it, and every surface used to
show that string raw or not at all -- the desktop's xrefs dock had no
provenance column whatsoever. One table in
`crates/romwright-model/src/provenance.rs` gives each class a sentence, and every
surface reads it: the API serialises `explanation` inside each `provenance`
object, `romwright-cli provenance` prints the table or just the classes one program
holds, and the desktop renders the sentence in an Evidence column with the raw
class as its tooltip.

| Metric | Measured |
|---|---|
| `provenance.classes` | **15** in the table |
| `provenance.declared` / `provenance.observed` | 15 declared in the crates, 11 observed in stores |
| `provenance.unexplained` | **0** |
| `provenance.api_facts_checked` | 10 facts carried the table's sentence through a real `romwright-api` |
| `ui.xrefs.rows` / `ui.xrefs.unexplained` | 19 rows rendered, **0** unexplained |

The desktop number is measured, not asserted: the xrefs dock counts what it
put in the table and the UI gate publishes it, so a class the core stops
explaining shows up as a rendered row with no sentence
(`tests/m9-001_provenance_explained.py`, `benchmarks/reports/m9-001.json`).

## Token identity against the oracle, per language

`tests/differential.sh` proved the native decompiler emits the oracle's token
stream for one x86-64 fixture. This measures it for every language
`native/specs` bundles, on every committed corpus row of every build variant
the lock holds -- unoptimised, optimised, C++ with exceptions and RTTI, and a
400-function image -- and names the cause of every difference
(`tests/m4-003_language_parity.py`, `benchmarks/reports/m4-003.json`, pinned by
`benchmarks/reports/parity-baseline.json`):

| Checked | Measured |
|---|---|
| bundled languages, each measured or blocked with a verified reason | 9 = 4 measured + 5 blocked |
| corpus rows compared (`plain_o0`, `plain_o2`, `cpp_o2`, `many_o2` per language) | 16 |
| functions compared, both ways, on the same stripped image | 1845 |
| token-identical to the oracle | **1739** |
| differing only because our type is the stronger one | 89 |
| differing, every one attributed to a named fact | 106 |
| differing tokens no named class accounts for | **0** |

The last row is the load-bearing one. Naming *a* class used to be enough for
a function to count as explained, which let a fact nobody recorded hide behind
one that did differ -- the x86 entry rows differed by a name *and* by a
calling convention, and only the name was named. The gate now subtracts what
each class licenses, token by token, and fails on whatever is left: a name it
substitutes, a label both stores name, the casts a typed slot moves, a
derived variable, a warning comment, a type keyword a missing prototype would
supply. Notation is never a difference (`0x0` and `0` are the same number); a
differing *value* still is.

The classes separate the gaps from the choices, and the *direction* of a
difference decides which it is. Gaps -- and no `flow` row at all, so every
warning either side emits is accounted for:
no `data-type-unknown` row either, since
`m4-027` types the words that carried it (a `.got` word, and a referenced word
holding a function's entry, are pointers on both sides); and
`language-variant` 3 -- **measured, and
not ours**: `m4-023` proves nothing in the install separates the two
languages, so stock's `PowerPC:BE:32:e500` is the first element of its own
hash-ordered candidate set and ours is the neutral `PowerPC:BE:32:default`,
whose four-byte view of `r2` is spelled `r2` rather than `_r2`. Not ours:
`oracle-warning` 19, stock warning
about its own recovery (`Unknown calling convention -- yet parameter storage
is locked`, on stubs whose text is otherwise ours exactly). Choices:
`name-convention` 11 -- the whole
difference is a name we picked on purpose, decided mechanically by
substituting the oracle's name into its own text and finding the token streams
equal (`_plt` names the section that proved the start; stock calls it
`FUN_00201710`). The decision is kept and bounded: `m4-031` holds every coined
name to its section's loaded start, on a function stock also holds, where
stock's name is its own default and the image's symbol tables name nothing --
and no `data-name-convention` row either: `m4-029` gives the addresses the
dynamic table declares the names it declares (`__DT_PLTGOT`, `__DT_PPC_GOT`,
`__DT_INIT`), beside whatever else names them, and prefers the tag's name over
a label composed from the import a linkage slot resolves to -- which is what
stock does, since it keeps that import in its EXTERNAL block,
no `mangled-name` row any more: `m4-028` demangles the name a COPY relocation
carries (`_ZTIi`) into the symbol Ghidra applies beside it -- `typeinfo` in the
namespace `int` -- and both stores now print `int::typeinfo`,
`type-stronger` 58,
where the only difference is where each side needed a cast because the store
types a slot from what the image declares its target is and the oracle types
every word its loader marks up `undefined *`. `m4-030` holds that to its
evidence: a linkage relocation for a function and an initializer array declare
a code pointer, a word that merely happens to hold a function's entry does
not, and the gate fails on a slot typed either way without the fact to match --
which is what took the class from 89 to 58 rows. And
`name-rendering` 12, which is stock's own
warning text: **both decompilers print the same identifier**
(`__i686_get_pc_thunk_bx`), and stock's `Function: ... replaced with
injection` warning cites the declared `__i686.get_pc_thunk.bx` instead.
Measured, not assumed -- m4-026 tried the client side three ways (the
declared name in both the `name` and `label` attributes, the identifier in
both, and one in each per query path) and the pinned decompiler prints
`getDisplayName()` in both places every time, so no name a client can send
reproduces stock's two spellings at once.
A name that is *missing* is not a choice: if ours were the decompiler's own
default and the oracle had a real name, the gate would count `missing-name`.

Twenty tasks have shrunk the gaps by carrying facts the image, its ABI or the
pinned install already declares:

* strings and data references (`tests/m4-004_data_names.py`): it prints
  `DAT_002038f8` and `s_sum___d__002004d0` where it printed
  `cRam00000000002038f8` and `0x2004d0`;
* transfers (`tests/m4-005_thunk_flow.py`): a thunk's jump is delivered as
  Ghidra's own `<flow type="callreturn">` override, so `_INIT_0` calls
  `FUN_00201600` instead of decompiling to `return;` with its call discarded;
* the PLT header (`tests/m4-006_plt_header.py`): the System V ABI reserves
  `DT_PLTGOT + 2 words` for the dynamic linker's resolver, so the jump that
  reads it is a `callreturn` override, recorded per instruction as Ghidra
  records its own;
* the reserved words themselves (`tests/m4-007_got_pointers.py`): all three
  are pointers, so the decompiler stops overlaying a wider global of its own;
* library declarations (`tests/m4-009_library_prototypes.py`): the pinned C
  library archive declares 6627 functions,
  exported once by an oracle-only script and committed with the archive's
  hash, so `printf("sum: %d\n",(ulong)uVar1)` is the oracle's text exactly --
  a declaration is applied only when every type in it is one the decompiler
  already has, in a shape its C parser accepts.
* the branch, not the load (`tests/m4-010_stub_transfers.py`): a stub loads a
  slot and branches through it, and on AArch64 and PowerPC those are different
  instructions -- the override now names the indirect branch the flow walk
  proved, so 8 stubs across
  3 architectures stop asking for a jumptable.
* widths, exits and names (`tests/m4-011_widths_exits_names.py`): a pointer is
  as wide as the space its language addresses (2
  32-bit rows, 0 field extractions left), a name on Ghidra's own pinned
  no-return list is a fact the loader records, so the AArch64 entry function
  stops at `abort()` instead of swallowing the next function, and a label C
  cannot spell (`__i686.get_pc_thunk.bx`) is rendered with the characters
  replaced while the store keeps what the image declared.
* a declaration in the language's own type names
  (`tests/m4-025_declaration_types.py`): `long strtol(char **, ...)` was
  applied on the 64-bit rows and refused on the 32-bit ones, because a 32-bit
  `coretypes.xml` names `longlong` and no `long` -- and one name the
  decompiler's C parser cannot resolve fails the whole decompile, not one
  prototype. The parser asks the client for a name it does not hold
  (`TypeFactoryGhidra::findById`, `typegrp_ghidra.cc`:20-36), so the worker
  now answers from the compiler spec's `<data_organization>`, with Ghidra's
  own defaults where a spec omits it (PowerPC's does:
  `DataOrganizationImpl`:43-53). **23 declared prototypes across all 20 ELF
  rows, each recorded with the archive's own types and each printed with
  stock's own signature**; 235 declarations whose types no language can
  express stay refused, and a `noreturn` stock spells inside its signature is
  compared where we keep it -- as a fact.
  `missing-external-prototype` **4 -> 0**, `function-facts` **2 -> 0**.
* the ranges an image declares protected
  (`tests/m4-024_exception_annotations.py`): Ghidra's exception analyzer walks
  each function's LSDA call-site table and writes `try { // try from X to Y
  has its CatchHandler @ Z` at the range's first address. The loader now reads
  the same table -- through `.eh_frame`'s `L` augmentation, whose personality
  pointer is `DW_EH_PE_indirect|pcrel|sdata8` on AArch64 and only has to be
  stepped over -- and records the range and its handler as facts
  (`native-import:elf-exception`), which the worker renders into Ghidra's own
  comment. **4 ranges across the four C++ rows, each identical to the comment
  stock recorded for the same bytes**, none invented, and none on a row whose
  call sites have no handler. Two defects fell out of it: a batched decompile
  never sent the `flushNative` Ghidra's own client sends after every function
  (`DecompInterface.decompileFunction`:828-834), so every function after the
  first saw the first one's caches -- no comments, and a stale "already
  applied" memo that decompiled `printf` as `void printf(void)`; and a PRE
  comment was sent as `header` where Ghidra sends `user2`
  (`DecompileCallback.encodeCommentsType`:576-595), which the decompiler's
  default body mask drops. `exception-annotation` **4 -> 0**.
* the install decides the language (`tests/m4-023_language_selection.py`):
  selection came from a hand-written table that answered `ARM:LE:32:v7` where
  the pinned `ARM.opinion` pins `variant="v8"` -- and `v8LEInstruction` behind
  the `EF_ARM_BE8` bit, a secondary key the table never read. The loader now
  queries the install's own opinion data as `ElfLoader` does, with `e_machine`
  as the primary key and `e_flags` as the secondary one, and filters candidates
  by the image's endianness and pointer size: **6 of 7 measured rows are the
  language stock selects for the same bytes**, ARM included, where three were
  wrong before. The seventh is PowerPC, where the data pins no variant at all
  and stock's answer is the first of 12 equally preferred candidates in a
  `HashSet` iteration; ours is the neutral `default`, and the gate records the
  disagreement with the evidence that nothing separates them.
* four variants, two bugs (`tests/m4-003_language_parity.py`): widening the
  gate from one build per language to four -- unoptimised, optimised, C++ with
  exceptions, and a 400-function image, 56 functions -> **1845** -- found two
  defects no single-variant row could reach. A declaration whose base type the
  language does not name (`long` on a 32-bit `coretypes`) failed the decompile
  of every function that called it, so the filter now reads the language's own
  type document instead of a constant list. And `DT_PLTGOT + 2 words` is only
  a reserved slot where the PLT object has room for it: this image's `.plt` is
  two words long, so the third address is a `.bss` guard byte, and the
  `callreturn` override the rule installed on the ordinary load that reads it
  truncated `_FINI_0` to `halt_baddata()`. An override belongs on a branch
  that transfers, and on nothing else.
* a slot that holds code (`tests/m4-021_initializer_slots.py`): an
  `.init_array` word holds a code address -- the same evidence that names its
  target `_INIT_0` -- so the slot is typed as a pointer and rendered `PTR_`
  rather than `DAT_`. And a name we render survives a row that differs
  elsewhere too, so the injection warning both decompilers emit stops being
  counted once in each direction: `flow` 1 -> **0**.
* what a label says (`tests/m4-020_label_prefixes.py`): an unnamed address in
  an executable mapping is `LAB_`, not `DAT_` -- Ghidra's own two default
  prefixes (`SymbolUtilities`:49-53) -- so the AArch64 entry passes
  `&LAB_002106f4` as stock does; and a warning that differs only by a name we
  render as a C identifier is named `name-rendering`, not flow. Token identity
  **35 -> 36**, `flow` 3 -> 1, `data-type-unknown` 2 -> 1.
* a gap has a direction (`tests/m4-019_prototype_direction.py`): the last
  `missing-external-prototype` rows named `__libc_start_main` and
  `__gmon_start__`, which the pinned archive does not declare (it declares
  6627 others, `abort` and `printf` among them) and which **stock records no
  signature for either**. The class asked only whether *our* store had one, so
  a name nobody declares counted against us: 5 -> **0**. Stock holding a
  signature we lack still counts, which is the control.
* the instrument's own silence (`tests/m4-018_oracle_prototypes.py`): the
  bridge exported no signatures at all, so every return type we recovered read
  as a divergence against a `None`. It now exports what stock says it
  recovered -- with `getSignatureSource()`, so Ghidra's own
  `undefined FUN_x(void)` placeholder is not recorded as a fact -- and a
  signature is compared by content (return type, parameter count) rather than
  by either decompiler's parameter spelling. The `function-facts` class went
  10 -> 5 -> **0**.
* the loader's own entry names (`tests/m4-017_entry_names.py`): `entry` for
  `e_entry` and `_DT_INIT`/`_DT_FINI` for the single-entry dynamic tags are
  names stock's loader gives from documented rules, and ours were a section
  name or an invented underscore. A symbol from the image's own table still
  wins, and `_plt` -- where stock has no name at all and ours says which
  section proved the start -- stands. Token identity **30 -> 35**.
* which side a difference belongs to (`tests/m4-016_class_direction.py`): the
  `flow` class licensed any warning in either direction, and the prototype
  class matched a callee name in the decompiled function's *own signature*
  while looking for a prototype at the import slot, which never carries one --
  so stock's defects and our own signature counted against us. Measured in the
  direction each points: `flow` 8 -> 3,
  `missing-external-prototype` 10 -> 5.
* how wide each access is (`tests/m4-015_reference_widths.py`): the console
  already decodes the load or store that reaches a location and dropped its
  size, so a referenced word arrived as a one-byte symbol and a four-byte read
  over it made the decompiler warn that a global overlaps it. The width is now
  a fact with provenance, and two rows stop warning.
* a branch that leaves its function (`tests/m4-013_shared_returns.py`): an
  unconditional jump whose destination is another function's entry is a call
  that returns, which stock records as a `CALL_RETURN` flow override
  (`SharedReturnAnalysisCmd`); the tree already typed such a branch a call and
  recorded nothing, so the PowerPC entry followed the jump into a stub and
  asked for a jumptable. It now prints `__libc_start_main();`.
* what the exact accounting named (`tests/m4-012_remaining_facts.py`): the
  process-entry model the ABI reserves for `e_entry`, recorded as a fact with
  provenance and applied only where the language declares such a model; the
  compiler spec's own call fixups, so `__i686.get_pc_thunk.bx` is replaced by
  the p-code the spec carries instead of being called; and the dynamic table's
  labels (`_DYNAMIC`, `__DT_<TAG>`), applied where nothing else names the
  address.

Token identity has gone **18 -> 36**
of 56 across those tasks, with no class
growing and every count pinned.

Blocked languages are blocked for one reason: no ELF row exists for them in
the corpus lock, and adding one is reserved to the human (II.1). The
cartridge images that do exist are containers the oracle has no loader for --
verified, not assumed: the gate asks the oracle to load the GBA ROM and
records its refusal.

Four controls prove the rules bite: a divergence class that stops being
recognised, a blocked language that gains a corpus row, a spec bundle nobody
classified, and a container the oracle turns out to load after all.

## Measured improvement over stock, as one claim

The opt-in passes are enumerated from `RuntimeConfig::from_env`, not listed by
hand, and each is measured against DWARF truth on the locked corpus
(`tests/m4-002_improvement_milestone.py`, `benchmarks/reports/m4-002.json`):

| Checked | Measured |
|---|---|
| opt-in passes, each carried by a gate | **2** (`m4-001`, `m5-007`) |
| each pass off unless asked, proved by the facts it leaves | 400 register-parameter facts with the flag, 0 without |
| arities correct by default, equal to stock | 1236 / 1640 |
| arities correct with the passes enabled, against stock's 1236 | **1637 / 1640** |
| arities neither producer recovers, explained as dead parameters | 3 |

The residual is a ceiling, not a defect: in each of those functions the ABI's
second-argument register never appears in the recovered body -- 0 reads
against 400, 801 and 802 reads of the first -- so the image carries no
evidence for the parameter DWARF declares. Inventing it would be a rule that
fits one fixture.

Six controls prove the rules bite: an ungated opt-in pass, a pass forced on by
default, a flag wired to nothing, a row where native drops below stock, a
residual whose register *is* read, and a carried gate that stops passing. The
first run of two of them passed against a stale binary; the gate now builds
what it measures.

## Multi-image projects, as one claim

The methods are not listed by hand: the gate scans every dispatch arm in
`crates/romwright-api/src/lib.rs` that reads `params.program`, then drives each one
against a project holding two images
(`tests/m10-004_multi_image_milestone.py`, `benchmarks/reports/m10-004.json`):

| Checked | Measured |
|---|---|
| methods take a `program`, each driven or excused with a reason | **41**, 0 excused |
| reads answer identically beside another image and alone | 54, of which 13 tell the images apart |
| writes leave the other image byte-identical across every read | 14, 4 recorded inert on this fixture |
| `m10-001`..`m10-003` exist, pass, and carry their metrics | 3 gates |

A method that starts taking a `program` and is driven nowhere fails the gate,
which is what the milestone was missing. Five controls prove the rules bite: a
read ignoring which program asked, a write landing in every program, a new
undriven arm, a carried gate that stops passing, and an active write excused
as inert.

## Carrying names from one build onto another

`romwright-cli diff <program> --reference DIR` matches the functions of a program in
another project onto this one and ports the reference's names across
(`--apply` writes them, as one undoable command). It answers "which function
in B is this function of A", which is a different question from "what known
function is this": the second is `romwright-cli match`'s signature database, and no
decompiler or JVM is involved in either.

The matcher works on facts the import already recorded: instruction, block and
edge counts per body, loops, largest block, digests of the body bytes and of
the decoded shape (`function_features`, schema v17), plus calls, callers,
string reads and named imports. Two strategies over exactly those facts:

- `--matcher greedy` expands a set of anchors over the call graph, taking the
  best local pair each round — the maximum-common-edge-subgraph strategy of
  Dullien & Rolles, *Graph-based comparison of executable objects* (SSTIC'05).
- `--matcher nap` (default) solves the whole assignment at once as a network
  alignment problem, maximising `λ·content + (1−λ)·induced call edges` over
  one-to-one mappings — the formulation of Mengin & Rossi,
  *Binary Diffing as a Network Alignment Problem* (arXiv:2112.15337), whose
  quadratic objective is maximised here by integer projected fixed point
  iteration (Leordeanu, Hebert & Sukthankar, NIPS'09) over a sparse candidate
  set, each iteration solving an exact minimum-cost-flow assignment.

Scored against symbol truth the matcher never reads
(`tests/m12-001_diff.py`, `benchmarks/reports/m12-001.json`):

| Case | Truth | Precision | Recall | Ported names right |
|---|---|---|---|---|
| every corpus row against its unstripped twin | address identity, 1903 pairs | **1.0** | **1.0** | **1.0** over 1702 |
| `plain_o0` against `plain_o2`/`plain_pie`, 4 architectures | name identity, 147 pairs | **1.0** | 0.8639 | 0.9535 |
| two Agent Under Fire modules, target stripped | name identity, 1176 pairs | 0.9662 | 0.9473 | 0.9272 over 1208 |
| anchors alone, pooled over every row above | | **1.0** | | over 2802 judged |

An anchor is an identification rather than a guess — a key unique on both
sides — so its precision is gated at 1.0 and is not a tunable floor. Every
error is in the propagated class: 0.878 for the network alignment against
0.868 for the greedy strategy on the module pair. On a harder pair still —
zlib built at `-O0` and at `-O2`, 147 named functions, target stripped — the
alignment measures precision 0.908, recall 0.469 and 0.825 of ported names
right, against 0.879, 0.395 and 0.783 for the greedy strategy, which is why
the alignment is the default.

## What a second import must not disturb

Analysing one image and then importing another into the same project is the
ordinary case, and an import replaces a program's facts. The gate renames a
function, writes a comment, imports the second image, and checks what moved
(`tests/m10-003_edit_durability.py`, `benchmarks/reports/m10-003.json`):

| Checked | Measured |
|---|---|
| the first image answers exactly as before | 8 reads identical, revision unchanged at 9 |
| the second image is complete beside another program | the same 8 reads as importing it alone |
| `undo` on the unedited image reverses nothing | and the rename survives it |
| `undo` on the edited image reverses its own last edit, then the one before | `undid comment seq 2 at 00400466`, then `undid rename seq 1 (00400466 -> add)` |

**This found no defect** -- the store already scopes facts, revisions and the
journal per program. Three controls prove the gate would notice if that
changed: an import that clears every program's functions, one that bumps every
program's revision, and an `undo` that ignores which program asked. A fourth
control, an import clearing every comment, passed and was replaced: an import
writes no comments, so it exercised nothing.

## Moving between the images

`locate --follow` prints what each image holds at an address -- the containing
function, the symbols there, the references in each direction -- and the
desktop's **Images** selector switches the docks between the programs a
project holds (`tests/m10-002_image_navigation.py`,
`benchmarks/reports/m10-002.json`):

| Checked | Measured |
|---|---|
| every number `--follow` prints matches the service, per program | 8 facts over 2 images |
| the two images disagree there, so a `--follow` reading the wrong one fails | `tiny` 0 references, `win` 1 |
| the window lists the project's images | 2 |
| switching changes the function list to the other image's | 12 functions before, **112** after |

Two controls fire: a `--follow` that reads references from the first program
for every row, and a selector that lists images without switching.

**A crash was found doing this.** `MainWindow::search_edit_` was declared and
never constructed, so `loadProgramPanels()` dereferenced null -- opening a
program, importing one, or switching images killed the window. The Facts dock
owns its own search box, so the field is gone and the term is empty.

## A project is not one image

A DS cartridge is two CPU images and an executable can carry overlays, so a
project holds several programs -- and they overlap: a stripped `tiny_pe32.exe`
and `tiny_bin` both map `0x00401000`. `programs`
lists what a project holds; `locate` names every program mapping an address,
with the region that maps it and the function containing it
(`tests/m10-001_multi_image.py`, `benchmarks/reports/m10-001.json`):

| Checked | Measured |
|---|---|
| sharing a project changes no answer | 16 reads per program identical to single-image projects, over 607 rows |
| the inventory names both, with language, functions and revision | 2 programs |
| `locate` names both at an overlapping address, one where only the ELF maps, none outside either | region and function verified against the program that owns them |
| a malformed address is refused | `invalid_params` |

Two controls fire: a `locate` that ignores whether the region holds the
address, and one that stops at the first program.

## Fact explanation, as one measured claim

Every surface that shows a fact is enumerated from the repository and then
driven: the API methods `docs/core-api.md` publishes, the verbs `romwright-cli`
prints in its own usage, and the window the UI gate measures
(`tests/m9-005_explanation_milestone.py`, `benchmarks/reports/m9-005.json`):

| Claim | Measured |
|---|---|
| every fact an API answer carries says what proved it | **28** of 52 published methods answered, 0 silent facts |
| every `source=` the terminal prints is explained | 5 distinct classes |
| the window shows no unexplained row and narrows when filtered | 13 declared rows, 0 unexplained |
| explanation table (`m9-001`) | 15 classes, 0 unexplained |
| evidence kinds (`m9-002`) | 15 classes, 0 underived numbers |
| filtered reads (`m9-003`) | 104 references, 135 symbols |
| user surfaces (`m9-004`) | 12 rows, 2 narrowing addresses |

A fact a person asserted needs no sentence -- the person is the evidence -- and
that is the only exemption. Three controls fire: a class losing its sentence,
a window report claiming unexplained rows, and any of the four gates ceasing
to pass.

## The filter, where a user can reach it

`romwright-cli xrefs --evidence declared|decoded|inferred` prints only the facts of
that kind, and the Xrefs dock carries a selector for the same three. Both go
through the store's filter, so neither keeps a second pass over rows it already
fetched (`tests/m9-004_filter_surfaces.py`, `benchmarks/reports/m9-004.json`):

| Checked | Measured |
|---|---|
| the terminal prints exactly what the service returns | 12 rows across three kinds |
| a kind that narrows the set is exercised, so a flag accepted and ignored fails | 2 addresses |
| an unknown kind is refused, and so is filtering with no address | both exit non-zero |
| the window's rows match the service at the address it opened | app run in gate mode |
| the window narrows on a real binary | 13 declared of 19 rows (`ui-gate.json`) |

The gate reads the address the window reports (`ui.xrefs.address`) rather than
assuming which one it opened -- an address the app never navigated to would
prove nothing, and the first draft of this gate compared zero against zero
until that was fixed.

## Asking for facts by what proved them

Saying what proved a fact is only half of it; a consumer has to be able to ask
by that standard. `symbols_page` and `xrefs_page` take `evidence` --
`declared`, `decoded` or `inferred` -- and the filter is built from the shared
table's sources, so it cannot mean one set in a query and another in the fact
it returns.

| Checked over the API | Measured |
|---|---|
| filtered rows are exactly the unfiltered rows of that kind | 20 addresses across 5 images |
| the filtered `total` counts filtered facts, and `revision` is unchanged | 104 references, 135 symbols |
| two half-pages reassemble the filtered set in order | every kind with two or more facts |
| an unknown kind is `invalid_params` | refused on every image |

An audit that wants only what the image states no longer fetches every
reference to throw most away, and the page total stops describing rows the
page cannot return (`tests/m9-003_evidence_filter.py`,
`benchmarks/reports/m9-003.json`).

## What a class proves, and when a number may exist

A sentence says what a class read; it does not say how much weight it carries.
Rather than invent probabilities, each class declares which of the three kinds
of evidence the importer actually has -- `declared` (the image or platform
states it), `decoded` (SLEIGH decoded the instruction that performs it), or
`inferred` (a pass concluded it) -- and two rules follow
(`tests/m9-002_fact_confidence.py`, `benchmarks/reports/m9-002.json`):

| Rule | Measured |
|---|---|
| a `declared` class cannot be wrong about a function start | **1.0000** attribution over 4536 entries named by declared classes |
| every declared class is exercised somewhere | 7 scored here, 1 by another committed gate |
| a number must be derived | `evidence.unbacked_confidence` **0** over 4665 promoted references |

`confidence` stays `null` for every native fact because nothing derives one:
the single derivation that exists is a signature match's share of compared
bytes. A class carrying a number it does not derive fails the gate, and a
`declared` class claiming one fails a unit test -- a header either says a
thing or it does not.

Kinds are recorded in `benchmarks/reports/evidence-classes.json` and never
rewritten in place: quietly downgrading `native-import:pe-unwind` to
`inferred`, which would excuse it from the attribution rule, fails against the
record.

## PE parity, as one measured claim

Every PE evidence class is read from the importer's own vocabulary -- the
`native-import:pe-*` provenance strings it can emit -- and each one has to be
exercised by a committed fixture *and* named by a committed report, so a class
the code grows without a gate behind it fails
(`tests/m8-006_pe_parity.py`, `benchmarks/reports/m8-006.json`):

| Claim | Measured |
|---|---|
| `pe.classes.declared` | **4**, none unexercised, none unmeasured |
| `pe.references` / `pe.externals` | 865 references, 260 external symbols over 4 fixtures |
| PE32+ recovery (`m8-001`) | recall **1.0000**, 0 unattributed |
| PE32 recovery (`m8-002`) | recall **0.8065** against stock 0.7634, 0 unattributed |
| Body extents (`m8-003`) | 0 crossing, **0.9873** exact |
| Declared roots (`m8-004`) | 8 TLS callbacks, 3 exports |
| Imports (`m8-005`) | 166 named, 0 unnamed stubs |

Three controls fire: a provenance string the code declares but no fixture
produces, a class no report names any more, and a report whose `passed` turns
false. Redundant coverage is fine -- several gates name the same class -- but
removing the last holder fails.

## PE32+ recovery

A stripped PE32+ image names its functions through the exception directory:
`IMAGE_DIRECTORY_ENTRY_EXCEPTION` holds a `RUNTIME_FUNCTION` record for every
function the compiler gave unwind data, which is how a function no call
reaches is still found. The promotion rule is Ghidra's, read from the pinned
`ImageRuntimeFunctionEntries_X86` and `PEx64UnwindInfo`: mark
`ImageBase + BeginAddress` unless the unwind info sets `UNW_FLAG_CHAININFO`,
because a chained record describes a fragment of another function.

Recovery is scored against the compiler's own truth -- concrete
`DW_TAG_subprogram` entries with a low PC, inside executable sections, read
from the PE container, the same definition `m3-001` uses for ELF
(`tests/m8-001_pe_unwind.py`, `benchmarks/reports/m8-001.json`):

| Fixture | `pe.dwarf.fn.recall` | `pe.dwarf.fn.unattributed` | `RUNTIME_FUNCTION` records |
|---|---|---|---|
| `tiny_pe.exe` | **1.0000** over 90 functions | 0 | 95 |
| `dispatch.exe` | **1.0000** over 90 functions | 0 | 97 |
| `tiny_pe32.exe` | 0.8065 (recorded, not gated) | 31 | 0 |

Before the pass, recall on `tiny_pe.exe` was 0.5667: 39 of 90 functions --
`WinMainCRTStartup`, `__do_global_ctors`, `__mingw_TLScallback` and the rest
of the CRT -- were unreachable by flow from the entry point.

### PE imports, named the way an ELF's are

An ELF import lands in the store as an external symbol at the slot the loader
fills, and the stub that jumps through it takes the imported name. A PE had
none of that: `tiny_pe32.exe` imported with **zero symbols**, because nothing
read `IMAGE_DIRECTORY_ENTRY_IMPORT`. It now holds 81, and its import stubs are
named `__set_app_type`, `_initterm`, `_cexit` rather than `FUN_...` -- the
existing linkage machinery names them once the slots have names, so PE and ELF
share one path (`tests/m8-005_pe_imports.py`,
`benchmarks/reports/m8-005.json`):

| Metric | 4 PE fixtures |
|---|---|
| `pe.imports.declared` | **166** imports, each an external symbol at its IAT slot |
| `pe.imports.libraries` | 8 library references |
| `pe.imports.misnamed` | 0 -- every name matches what the image imports |
| `pe.imports.unnamed_stubs` | 0 -- every stub through a slot carries its import's name |

The rules are Ghidra's, from `ImportDataDirectory.parse` and `ThunkData`: the
name table is `OriginalFirstThunk` when it maps and `FirstThunk` otherwise, the
walk ends at the first zero entry, the ordinal flag names `Ordinal_<n>`, and a
name RVA points at `IMAGE_IMPORT_BY_NAME` -- a two-byte hint *then* the string.
Reading the name without skipping the hint fails the gate, as does dropping the
pass. An IAT slot holds a pointer, so nothing is promoted to code there; that
is what a bound image, whose slots already hold resolved addresses, would
otherwise invite.

The library a symbol came from is recorded in the report, not in the store:
neither format models it yet, and ELF external symbols carry a bare name too.

### The roots a PE declares itself

Two more directories name code no call reaches. The TLS directory's
`AddressOfCallBacks` is a null-terminated array of **virtual addresses**
(Ghidra's `TLSDataDirectory` walks at most 20 slots and stops at the first
null), and the export directory's `AddressOfFunctions` names entry points with
the names the image publishes -- skipping gap slots holding RVA 0 and
forwarders, whose "address" points inside the export directory at a string
naming another library (`ExportDataDirectory.parse`).

| Fixture evidence | Count |
|---|---|
| `pe.tls.callbacks` recovered with a `native-import:pe-tls` reference | **8** |
| `pe.exports` recovered with a `native-import:pe-export` reference and their exported name | **3** |
| `pe.exports.forwarded` left as data | 0 |

The three exports in `tests/fixtures-src/exports32.dll` were recovered by
nothing before this: the importer reads no COFF symbol table and no code in
the image calls them. The TLS callbacks *were* recovered, but only because a
base relocation happened to point at them -- a relocation says a pointer lives
in that slot, while the directory says what the pointer is, so the reference
is upgraded rather than duplicated. No committed fixture exports a forwarder,
so that rule is pinned by a unit test in
`crates/romwright-core/src/native/pe_roots.rs` rather than claimed from an image.

### PE32 x86, where there is no unwind directory

32-bit PE declares no exception directory, so nothing proves a function start
from outside the code. The first measurement showed what that costs: 31
recovered entries no evidence described. They were case labels inside
`___mingw_pformat` -- a PE32 switch table holds absolute addresses, so every
case carries a base relocation, and a relocation into code is exactly what the
importer treats as a candidate function.

What separates a case label from a function is the shape of its flow-proven
span, not a byte pattern: **two functions cannot share code**. The cases'
chains interleave through the switch's shared tail, so one case's span runs
past the next case's start, while a real function's span abuts its
neighbour's. Overlapping spans are retracted unless a call reaches them
(`crates/romwright-core/src/native/discovery.rs`).

| Metric | `tiny_pe32.exe` |
|---|---|
| `pe32.dwarf.fn.recall` | **0.8065** over 93 functions |
| `pe32.dwarf.fn.unattributed` | **0**, from 31 |
| `ghidra.dwarf.fn.recall` | 0.7634 on the same stripped image |

Stock Ghidra is the bar for recall here, not a number picked in this
repository: it reads the same image with the same absent evidence. The
18 functions still missed are classified against the image --
18 reachable only through a symbol the strip removed, 0 reached only
through an indirect transfer -- and an unclassified miss fails the gate, so
the deficit cannot grow quietly.

Every recovered entry must be described by DWARF or named by a COFF symbol in
the unstripped fixture; nothing else excuses one. Two further excuses were
tried and dropped as measured-inert (bounded by a `RUNTIME_FUNCTION`, or a
thunk the store proved), while removing the symbol class fails 29 entries.
Neither gated fixture carries a chained record, so that rule is pinned by a
unit test rather than claimed from these images.

### How long a function is

A recovered body is the furthest instruction the flow walk attributed to an
entry, and one fallthrough across inter-function padding used to stretch that
over everything after it: `FUN_00401c80` in `tiny_pe32.exe` claimed
**27 KB across 69 other functions**. That number is what the store reports as
`size`, what a containing-function lookup resolves with, and what a listing
renders.

Two rules now hold it. A body ends where the next entry begins, because two
functions cannot overlap. And a size of zero means *no body was proven*, which
the store fills from the next entry -- while a **proven** size of one is a
fact, not a placeholder: the MinGW CRT really contains a one-instruction
function, and filling that one in made it own a kilobyte of unrelated code.

Extents are scored against the compiler's own `DW_AT_low_pc`/`DW_AT_high_pc`
per image (`tests/m8-003_body_extents.py`, `benchmarks/reports/m8-003.json`):

| Metric | 23 images, 1895 matched bodies |
|---|---|
| `body.crossing` | **0** bodies contain another entry |
| `body.exact` | **0.9873** end exactly where the compiler says |
| `body.padding_overshoot` | 19 end within one 16-byte alignment slot past it |
| `body.overshoot_into_missed` | 1 run into a function nobody discovered |
| `body.undershoot` | 4 stop short at a tail nothing claims (worst 36 bytes) |

Every deviation is classified against the image rather than tolerated. An
overshoot may run *into* one undiscovered DWARF function and stop inside it --
that is the recall deficit `m8-002` records, showing up as bytes -- but
crossing a second start or running past the end of the one it entered fails,
which is exactly what a size taken from the distance to the next entry does.
A body may stop short only when no entry starts and no reference lands in the
bytes it left behind; the four that do are C++ landing pads, reached by the
personality routine rather than by a branch.

## What an import costs

Both producers import the same 20 locked ELF entries, measured the same way
(`os.wait4`, whose `ru_maxrss` covers the process and the children it waited
for). Per entry the native import must peak lower and finish sooner than stock
analysis, and stay inside a recorded envelope
(`tests/m7-001_cost_envelope.py`, `benchmarks/reports/m7-001.json`):

| Metric | Median over 20 entries |
|---|---|
| `cost.native.peak_kb.median` | **36 102 KiB** |
| `cost.stock.peak_kb.median` | 423 920 KiB |
| `cost.native.wall_s.median` | **0.255 s** |
| `cost.stock.wall_s.median` | 8.855 s |
| `cost.peak_ratio.median` | **12.11x** less memory |
| `cost.wall_ratio.median` | **32.91x** faster |

Decompiling one function is measured the same way, with import and analysis
done first and untimed in both producers -- `romwright-cli decompile` against an
imported project, `analyzeHeadless -process -noanalysis -postScript
scripts/DecompileOne.java` against an analysed and saved one. Both decompile
`main` **by name** in each entry's unstripped twin, so no address is guessed
and PIE image bases cannot make the two disagree about what was decompiled
(`tests/m7-002_decompile_envelope.py`, `benchmarks/reports/m7-002.json`):

| Metric | Median over 20 entries |
|---|---|
| `decompile.native.peak_kb.median` | **34 594 KiB** |
| `decompile.stock.peak_kb.median` | 286 368 KiB |
| `decompile.native.wall_s.median` | **0.091 s** |
| `decompile.stock.wall_s.median` | 5.933 s |
| `decompile.peak_ratio.median` | **8.32x** less memory |
| `decompile.wall_ratio.median` | **74.03x** faster |

A session is a third question: the desktop and every script hold a project
open through one `romwright-api` process and ask it many things. Per entry one
session answers the same seven requests for four warm-up rounds and eight
measured rounds, with the *process tree*'s resident size -- the service plus
the decompiler child -- sampled every 25 ms
(`tests/m7-003_session_envelope.py`, `benchmarks/reports/m7-003.json`):

| Metric | Median over 20 entries |
|---|---|
| `session.peak_kb.median` | 42 940 KiB |
| `session.growth_kb.max` | **28 KiB** over eight measured rounds |
| `session.latency_ms.functions.median` | 0.265 ms |
| `session.latency_ms.decompile_doc.median` | 6.002 ms |
| `session.drift_ratio.max` | 1.68x |
| `session.drift_excess_ms.max` | -0.863 ms, i.e. inside the bound |

Warm-up is excluded because a warm cache is not a leak: on the PowerPC entries
`decompile_doc` settles from 33 ms to 7 ms to 3.3 ms over the first four
rounds. What the gate refuses is a cache that never stops filling -- growth
across the measured rounds beyond `max(4 MiB, 5%)`, or growth in every single
round totalling more than 512 KiB -- and a session that gets slower, each
method's late-round median having to stay within twice its early-round median
plus 2 ms. Absolute latency is recorded rather than gated: it tracks the
host's CPU, while drift does not. `session.drift_ratio.max` counts only
methods slow enough for a ratio to mean anything (2 ms or more), and
`session.drift_excess_ms.max` says how far the worst method is from failing,
so a passing run cannot report an alarming ratio.

Both producers must emit a real function body, asserted rather than assumed:
the native run has to print a body for the resolved address and the stock
script has to report a non-empty `getC()`.

`benchmarks/reports/cost-envelope.json` and
`benchmarks/reports/decompile-envelope.json` record the native peak per entry and
are never edited: the gates allow 25% headroom for host noise and fail on
anything larger, so a regression appears as a failure rather than as a new
number. Shrinking one envelope entry, deleting one, and asking `--write` to
overwrite the file all fail every one of the three gates, as does asking for
a function the store does not have; a synthetic 1 MiB-per-round leak and an
eightfold slowdown in the late rounds each fail the session gate. `benchmarks/cost.py` holds the single definition of what
"it cost" means, so the two gates cannot drift apart.

Stock analysis does more than a native import does -- it runs Ghidra's full
analysis chain -- so this is a cost comparison of the two default paths, not of
identical work. The parity of what each produces is measured separately by
`m3-001` and the differential gates.

## Documentation coverage

`tests/m6-006_documentation_coverage.py` states what the documentation
milestone means, with the surfaces enumerated from the repository rather than
from a list in the test: the workspace's `bin` targets (the desktop
included), the modules under `python/`, and the scripts under `packaging/` must
each be named by `README.md` or a page under `docs/`. Every `console`/`json`
block sits on a page some gate executes; every `sh`/`bash` block -- including
one on a gated page -- carries `<!-- not gated: reason -->`, so an
illustrative command cannot pass as a proven one. And no page may cite a
metric name no committed report carries, which is how a retired metric would
be caught in prose.

## Scripting

`docs/scripting.md` shows `examples/facts_report.py` driving a project through
`python/romwright_sdk.py`: read the functions, write a rename, undo it. The page
is executed by `tests/m6-005_scripting.py` in two environments -- with the
the configured environment and with every `ROMWRIGHT_*` variable stripped -- because it
claims the script runs either way. The gate also compares the page against the
client: a helper the client grows and the page omits fails it, which is how
twelve undocumented helpers were found.

## The Core API

`docs/core-api.md` documents the stdio interface every consumer speaks --
envelope, error codes, typed addresses, fact provenance, paged reads, and
which requests need the pinned Ghidra install. Every documented exchange is sent to a
real `romwright-api` process by `tests/m6-002_documented_api.py`, and each
documented response must be a subset of the real one, so an invented field
fails the gate. Writing that page found a live defect: the `function` field of
a reference named whichever function row a scan reached first, because the
containing-function test compared hex text with an integer expression in SQL.

## Evidence index

Every gate writes a JSON report under `benchmarks/reports/`; the table
below is generated from those files by `scripts/gen_evidence_index.py`,
so it cannot claim a number no report carries. Intermediate diagnostic
runs live in `benchmarks/reports/diagnostics/` and are not evidence of
anything current: twelve of them record `passed: false`, because they are the
intermediate measurements that diagnosed a problem rather than gates that
held. A report that records a failure at the top of `benchmarks/reports/`
fails the generator, and `tests/m5-012_evidence_index.py` additionally
requires every acceptance test that writes a `--report` to have a committed
report carrying its id -- a measured result cannot live only in a transcript.

<!-- evidence-index:begin -->
| Report | Gate | Milestone | Status | Measured | Produced by |
|---|---|---|---|---|---|
| `acceptance-audit.json` | `acceptance-audit` | - | recorded | `schema_version` 1 | - |
| `cast_diff_stage2.json` | `cast_diff_stage2` | - | recorded | `decompiled` 1600; `identical` 1588 | - |
| `combined_gate_20261012.json` | `combined_gate_20261012` | - | recorded | recorded | - |
| `combined_gate_compiler_rules_20261012.json` | `combined_gate_compiler_rules_20261012` | - | recorded | recorded | - |
| `compiler_detection_accuracy.json` | `compiler_detection_accuracy` | - | recorded | `abstained` 8; `exact` 55; `games` 64; `lineage` 1; `wrong` 0 | `benchmarks/compiler_detection_accuracy.py` |
| `compiler_detection_accuracy_pc_20261015.json` | `compiler_detection_accuracy_pc_20261015` | - | recorded | `abstained` 0; `exact` 8; `games` 8; `lineage` 0; `wrong` 0 | - |
| `compiler_rules_gate_vs_20261012.json` | `compiler_rules_gate_vs_20261012` | - | recorded | recorded | - |
| `compiler_rules_loo.json` | `compiler_rules_loo` | - | recorded | `reach` 60; `sample` 40 | `benchmarks/compiler_rules_loo.py` |
| `console-processors.json` | `console-processors` | - | pass | `processors` 22 | - |
| `console_research.json` | `console_research` | - | recorded | `n` 200; `seed` 20261006 | `benchmarks/console_research.py` |
| `console_research_dwarf1.json` | `console_research_dwarf1` | - | recorded | `n` 200; `seed` 20261006 | - |
| `console_research_final.json` | `console_research_final` | - | recorded | `n` 200; `seed` 20261006 | - |
| `console_research_final2.json` | `console_research_final2` | - | recorded | `n` 200; `seed` 20261006 | - |
| `console_research_integration_20261009.json` | `console_research_integration_20261009` | - | recorded | `n` 200; `seed` 20261006 | - |
| `console_research_pairs_gba.json` | `console_research_pairs_gba` | - | recorded | `n` 200; `seed` 20261006 | - |
| `console_research_pairs_ps2.json` | `console_research_pairs_ps2` | - | recorded | `n` 200; `seed` 20261006 | - |
| `console_research_proto_psv-need-for-speed-most-wanted.json` | `console_research_proto_psv-need-for-speed-most-wanted` | - | recorded | `n` 200; `seed` 20261006 | - |
| `console_research_proto_x360-black-ops-2.json` | `console_research_proto_x360-black-ops-2` | - | recorded | `n` 200; `seed` 20261006 | - |
| `console_research_prototypes.json` | `console_research_prototypes` | - | recorded | `n` 200; `seed` 20261006 | - |
| `console_research_protowork.json` | `console_research_protowork` | - | recorded | `n` 200; `seed` 20261006 | - |
| `console_research_psp.json` | `console_research_psp` | - | recorded | `n` 200; `seed` 20261006 | - |
| `console_research_vita_20261009.json` | `console_research_vita_20261009` | - | recorded | `n` 200; `seed` 20261006 | - |
| `console_research_wave_20261009.json` | `console_research_wave_20261009` | - | recorded | `n` 500 | - |
| `console_research_wave_20261009_newtree.json` | `console_research_wave_20261009_newtree` | - | recorded | `n` 500 | - |
| `console_research_wave_20261010.json` | `console_research_wave_20261010` | - | recorded | `n` 500 | - |
| `console_research_wave_20261011_ps2.json` | `console_research_wave_20261011_ps2` | - | recorded | `n` 500 | - |
| `console_research_wave_20261011_ps2_precision.json` | `console_research_wave_20261011_ps2_precision` | - | recorded | `n` 500 | - |
| `console_research_wave_20261012_other_combined.json` | `console_research_wave_20261012_other_combined` | - | recorded | `n` 500 | - |
| `console_research_wave_20261012_ps2_combined.json` | `console_research_wave_20261012_ps2_combined` | - | recorded | `n` 500 | - |
| `console_research_wave_20261012_psp_n200_combined.json` | `console_research_wave_20261012_psp_n200_combined` | - | recorded | `n` 200 | - |
| `console_research_wave_compiler_rules_20261012_other_combined.json` | `console_research_wave_compiler_rules_20261012_other_combined` | - | recorded | `n` 500 | - |
| `console_research_wave_compiler_rules_20261012_poolrule_off.json` | `console_research_wave_compiler_rules_20261012_poolrule_off` | - | recorded | `n` 500 | - |
| `console_research_wave_compiler_rules_20261012_ps2_combined.json` | `console_research_wave_compiler_rules_20261012_ps2_combined` | - | recorded | `n` 500 | - |
| `console_research_wave_compiler_rules_20261012_psp_n200_combined.json` | `console_research_wave_compiler_rules_20261012_psp_n200_combined` | - | recorded | `n` 200 | - |
| `console_research_wave_old_20261012.json` | `console_research_wave_old_20261012` | - | recorded | `n` 500 | - |
| `console_research_wave_pc_20261015.json` | `console_research_wave_pc_20261015` | - | recorded | `n` 100 | - |
| `cost-envelope.json` | `cost-envelope` | - | recorded | `headroom` 1.2500 | - |
| `dark-workbench.json` | `dark-workbench` | - | recorded | `schema` 1 | - |
| `decompile-envelope.json` | `decompile-envelope` | - | recorded | `headroom` 1.2500 | - |
| `dwarf1_differential.json` | `dwarf1_differential` | - | recorded | `agreement_rate` 1.0000; `arity_agreement` 5221; `compared` 5221; `disagreement_count` 0 | - |
| `evidence-classes.json` | `evidence-classes` | - | recorded | recorded | - |
| `fact_pack_gating.json` | `fact_pack_gating` | - | recorded | recorded | `benchmarks/fact_pack_gating.py` |
| `fact_pack_loo.json` | `fact_pack_loo` | - | recorded | recorded | - |
| `finish_gate_20261015.json` | `finish_gate_20261015` | - | recorded | recorded | - |
| `ghidra_master_trial.json` | `ghidra_master_trial` | - | recorded | `schema` 1 | `benchmarks/ghidra_master_trial.py` |
| `head-to-head-libc.json` | `head-to-head-libc` | - | recorded | recorded | - |
| `import-speed.json` | `import-speed` | - | recorded | `limit_s` 3600; `quality_margin` 0.0100; `speed_tolerance_floor` 0.0500 | - |
| `import_precision_20261015.json` | `import_precision_20261015` | - | recorded | recorded | - |
| `import_precision_20261015_harness_hp.json` | `import_precision_20261015_harness_hp` | - | recorded | `n` 60; `seed` 1 | - |
| `import_precision_20261015_harness_nds.json` | `import_precision_20261015_harness_nds` | - | recorded | `n` 60; `seed` 1 | - |
| `import_precision_20261015_harness_psp.json` | `import_precision_20261015_harness_psp` | - | recorded | `n` 60; `seed` 1 | - |
| `locals_truth.json` | `locals_truth` | - | recorded | recorded | `benchmarks/locals_truth.py` |
| `m22-ps2_p4.json` | `m22-ps2_p4` | - | recorded | recorded | - |
| `m22-ps2_p4_combined_20261012.json` | `m22-ps2_p4_combined_20261012` | - | recorded | recorded | - |
| `m22-ps2_p4_combined_compiler_rules_20261012.json` | `m22-ps2_p4_combined_compiler_rules_20261012` | - | recorded | recorded | - |
| `m22-ps2_p4_eegcc.json` | `m22-ps2_p4_eegcc` | - | recorded | recorded | - |
| `m22-ps2_p4_eegcc_BASELINE_compiler_rules_20261012.json` | `m22-ps2_p4_eegcc_BASELINE_compiler_rules_20261012` | - | recorded | recorded | - |
| `m22-ps2_p4_eegcc_combined_20261012.json` | `m22-ps2_p4_eegcc_combined_20261012` | - | recorded | recorded | - |
| `m22-ps2_p4_eegcc_combined_compiler_rules_20261012.json` | `m22-ps2_p4_eegcc_combined_compiler_rules_20261012` | - | recorded | recorded | - |
| `m22-ps2_p4_eegcc_pre_ps2cmatch.json` | `m22-ps2_p4_eegcc_pre_ps2cmatch` | - | recorded | recorded | - |
| `m22-ps2_p4_eegcc_sharedwork_compiler_rules_20261012.json` | `m22-ps2_p4_eegcc_sharedwork_compiler_rules_20261012` | - | recorded | recorded | - |
| `m22-ps2_p4_old_20261012.json` | `m22-ps2_p4_old_20261012` | - | recorded | recorded | - |
| `m22-ps2_p4_pre_ps2cmatch.json` | `m22-ps2_p4_pre_ps2cmatch` | - | recorded | recorded | - |
| `m22-ps2_p4_pre_ps2printer.json` | `m22-ps2_p4_pre_ps2printer` | - | recorded | recorded | - |
| `m22-ps2_p4_seed20261011.json` | `m22-ps2_p4_seed20261011` | - | recorded | recorded | - |
| `m22-ps2_p4_seed20261011_combined_20261012.json` | `m22-ps2_p4_seed20261011_combined_20261012` | - | recorded | recorded | - |
| `m22-ps2_p4_seed20261011_combined_compiler_rules_20261012.json` | `m22-ps2_p4_seed20261011_combined_compiler_rules_20261012` | - | recorded | recorded | - |
| `m22-ps2_p4_seed20261011_pre_ps2cmatch.json` | `m22-ps2_p4_seed20261011_pre_ps2cmatch` | - | recorded | recorded | - |
| `m22-ps2_p4_seed20261011_pre_ps2printer.json` | `m22-ps2_p4_seed20261011_pre_ps2printer` | - | recorded | recorded | - |
| `match_search_20261014.json` | `match_search_20261014` | - | recorded | `budget` 24 | - |
| `matching-workflow.json` | `matching-workflow` | - | recorded | `schema` 1 | - |
| `memory_fix_20261015.json` | `memory-fix` | - | pass | `images.cpu_ratio.max` 0.9790; `images.rows_compared` 784555; `images.wall_ratio.max` 0.9750; `import.entries_over_limit` 0; `import.peak_kb.median.after` 34294.0000; `import.peak_kb.median.before` 246968.0000; `import.peak_over_limit.worst_ratio` 0.9220; `session.entries_over_limit` 1; `session.peak_kb.max.after` 54376; `session.processes_at_end.after` 2 | - |
| `merge_diff_stage3_20261014.json` | `merge_diff_stage3_20261014` | - | recorded | `decompiled` 1600; `identical` 1600 | - |
| `merge_port_measure_stage3.json` | `merge_port_measure_stage3` | - | recorded | `decompiler` 0; `entries` 310769; `explicit` 123545; `functions` 1600; `implied` 54441; `merges` 109767; `named` 9034; `new_ops` 2492; `speculative` 5560; `worker` 1600 | - |
| `merge_verify_stage3_20261014.json` | `merge_verify_stage3_20261014` | - | recorded | `decided` 7619; `declined` 0; `mismatch` 0; `verified` 7619 | - |
| `n64_segments.json` | `n64_segments` | - | recorded | `corroborating_entries` 4942; `truth_named` 4086 | `benchmarks/n64_segments_score.py` |
| `ownership.json` | `ownership` | - | recorded | `n` 200; `seed` 20261006 | `benchmarks/ownership.py` |
| `ownership_corpuswave.json` | `ownership_corpuswave` | - | recorded | `n` 200; `seed` 20261006 | - |
| `ownership_default_coverage.json` | `ownership_default_coverage` | - | recorded | `functions` 400 | - |
| `ownership_expressions.json` | `ownership_expressions` | - | recorded | `n` 200; `seed` 20261006 | - |
| `ownership_final.json` | `ownership_final` | - | recorded | `n` 200; `seed` 20261006 | - |
| `ownership_stock_coverage.json` | `ownership_stock_coverage` | - | recorded | `functions` 400 | `benchmarks/ownership_stock_coverage.py` |
| `ownership_structuring.json` | `ownership_structuring` | - | recorded | `n` 50; `seed` 20261006 | - |
| `ownership_switch_feed.json` | `ownership_switch_feed` | - | recorded | `n` 200; `seed` 20261006 | - |
| `parity-baseline.json` | `parity-baseline` | - | recorded | recorded | - |
| `pc_c_output_20261015.json` | `pc_c_output_20261015` | - | recorded | recorded | - |
| `pc_c_output_20261015_mini_off.json` | `pc_c_output_20261015_mini_off` | - | recorded | recorded | - |
| `pc_c_output_20261015_mini_on2.json` | `pc_c_output_20261015_mini_on2` | - | recorded | recorded | - |
| `pc_c_output_20261015_pc-glquake-msvc42_off.json` | `pc_c_output_20261015_pc-glquake-msvc42_off` | - | recorded | recorded | - |
| `pc_c_output_20261015_pc-glquake-msvc42_on.json` | `pc_c_output_20261015_pc-glquake-msvc42_on` | - | recorded | recorded | - |
| `pc_c_output_20261015_pc-glquake-msvc42_on2.json` | `pc_c_output_20261015_pc-glquake-msvc42_on2` | - | recorded | recorded | - |
| `pc_c_output_20261015_pc-ioq3-ded-mingw32_off.json` | `pc_c_output_20261015_pc-ioq3-ded-mingw32_off` | - | recorded | recorded | - |
| `pc_c_output_20261015_pc-ioq3-ded-mingw32_on2.json` | `pc_c_output_20261015_pc-ioq3-ded-mingw32_on2` | - | recorded | recorded | - |
| `pc_c_output_20261015_pc-quake2-msvc8_no_EXPORT_CALLEE_CONVENTIONS.json` | `pc_c_output_20261015_pc-quake2-msvc8_no_EXPORT_CALLEE_CONVENTIONS` | - | recorded | recorded | - |
| `pc_c_output_20261015_pc-quake2-msvc8_no_EXPORT_LONG_DOUBLE.json` | `pc_c_output_20261015_pc-quake2-msvc8_no_EXPORT_LONG_DOUBLE` | - | recorded | recorded | - |
| `pc_c_output_20261015_pc-quake2-msvc8_no_PE_CONVENTIONS.json` | `pc_c_output_20261015_pc-quake2-msvc8_no_PE_CONVENTIONS` | - | recorded | recorded | - |
| `pc_c_output_20261015_pc-quake2-msvc8_no_PE_IAT_REGIONS.json` | `pc_c_output_20261015_pc-quake2-msvc8_no_PE_IAT_REGIONS` | - | recorded | recorded | - |
| `pc_c_output_20261015_pc-quake2-msvc8_no_PE_WINDOWS_SPEC.json` | `pc_c_output_20261015_pc-quake2-msvc8_no_PE_WINDOWS_SPEC` | - | recorded | recorded | - |
| `pc_c_output_20261015_pc-quake2-msvc8_off.json` | `pc_c_output_20261015_pc-quake2-msvc8_off` | - | recorded | recorded | - |
| `pc_c_output_20261015_pc-quake2-msvc8_on.json` | `pc_c_output_20261015_pc-quake2-msvc8_on` | - | recorded | recorded | - |
| `pc_c_output_20261015_pc-quake2-msvc8_on2.json` | `pc_c_output_20261015_pc-quake2-msvc8_on2` | - | recorded | recorded | - |
| `pc_import_20261015.json` | `pc_import_20261015` | - | recorded | recorded | - |
| `pc_import_discovery_ours_20261015.json` | `pc_import_discovery_ours_20261015` | - | recorded | recorded | - |
| `pc_import_discovery_stock_20261015.json` | `pc_import_discovery_stock_20261015` | - | recorded | recorded | - |
| `pc_rules_loo_20261015.json` | `pc_rules_loo_20261015` | - | recorded | recorded | - |
| `pc_upgrade_20261015.json` | `pc_upgrade_20261015` | - | recorded | recorded | - |
| `printer_diff.json` | `printer_diff` | - | recorded | `decompiled` 1800; `identical` 1800; `identical_rate` 1.0000 | `benchmarks/printer_diff.py` |
| `printer_diff_expressions.json` | `printer_diff_expressions` | - | recorded | `decompiled` 1800; `identical` 1800; `identical_rate` 1.0000 | - |
| `printer_diff_stage2.json` | `printer_diff_stage2` | - | recorded | `decompiled` 1800; `identical` 1800; `identical_rate` 1.0000 | - |
| `printer_diff_stage3_20261014.json` | `printer_diff_stage3_20261014` | - | recorded | `decompiled` 1800; `identical` 1800; `identical_rate` 1.0000 | - |
| `ps2_decompile_success_after_20261011.json` | `ps2_decompile_success_after_20261011` | - | recorded | recorded | - |
| `ps2_decompile_success_before_20261011.json` | `ps2_decompile_success_before_20261011` | - | recorded | recorded | - |
| `ps2_decompile_success_combined_20261012.json` | `ps2_decompile_success_combined_20261012` | - | recorded | recorded | - |
| `ps2_decompile_success_combined_compiler_rules_20261012.json` | `ps2_decompile_success_combined_compiler_rules_20261012` | - | recorded | recorded | - |
| `ps2_decompile_success_handoff_default.json` | `ps2_decompile_success_handoff_default` | - | recorded | recorded | - |
| `ps2_decompile_success_handoff_stock.json` | `ps2_decompile_success_handoff_stock` | - | recorded | recorded | - |
| `ps2_decompile_success_stage2_def.json` | `ps2_decompile_success_stage2_def` | - | recorded | recorded | - |
| `ps2_decompile_success_stage2_followup.json` | `ps2_decompile_success_stage2_followup` | - | recorded | recorded | - |
| `ps2_decompile_success_stage2_off.json` | `ps2_decompile_success_stage2_off` | - | recorded | recorded | - |
| `psp_stock_compare.json` | `psp_stock_compare` | - | recorded | `dwarf_functions` 145; `truth_functions` 622 | `benchmarks/psp_stock_compare.py` |
| `service_memory_20261015-nih.json` | `service-memory` | - | pass | `documents.entries_equal` 16; `documents.entries_tokens_equal` 20; `service.peak_kb.median.after` 12622; `service.peak_kb.median.before` 14584; `session.entries_over_limit.after` 0; `session.entries_over_limit.before` 5; `session.margin_kb.min.after` 717; `session.peak_kb.max.after` 79256; `session.peak_kb.max.before` 95608 | - |
| `service_memory_20261015-smt-cold.json` | `service-memory` | - | pass | `documents.entries_equal` 16; `documents.entries_tokens_equal` 20; `service.peak_kb.median.after` 12498; `service.peak_kb.median.before` 14404; `session.entries_over_limit.after` 0; `session.entries_over_limit.before` 5; `session.margin_kb.min.after` 685; `session.peak_kb.max.after` 79244; `session.peak_kb.max.before` 95504 | - |
| `service_memory_20261015-smt-warm.json` | `service-memory` | - | pass | `documents.entries_equal` 16; `documents.entries_tokens_equal` 20; `service.peak_kb.median.after` 12492; `service.peak_kb.median.before` 14450; `session.entries_over_limit.after` 0; `session.entries_over_limit.before` 5; `session.margin_kb.min.after` 569; `session.peak_kb.max.after` 79432; `session.peak_kb.max.before` 95520 | - |
| `session-envelope.json` | `session-envelope` | - | recorded | `headroom` 1.2500; `rounds` 8; `warmup_rounds` 4 | - |
| `spurious_gotos.json` | `spurious_gotos` | - | recorded | recorded | `benchmarks/spurious_gotos.py` |
| `spurious_gotos_before.json` | `spurious_gotos_before` | - | recorded | recorded | - |
| `spurious_gotos_current_tree.json` | `spurious_gotos_current_tree` | - | recorded | recorded | - |
| `spurious_gotos_final.json` | `spurious_gotos_final` | - | recorded | recorded | - |
| `spurious_gotos_final_before.json` | `spurious_gotos_final_before` | - | recorded | recorded | - |
| `spurious_gotos_final_current_tree.json` | `spurious_gotos_final_current_tree` | - | recorded | recorded | - |
| `spurious_gotos_final_variants.json` | `spurious_gotos_final_variants` | - | recorded | recorded | - |
| `spurious_gotos_variants.json` | `spurious_gotos_variants` | - | recorded | recorded | - |
| `stage2_followup_20261013.json` | `stage2_followup_20261013` | - | recorded | recorded | - |
| `stage2_gates_20261013.json` | `stage2_gates_20261013` | - | recorded | recorded | - |
| `stage3_gates_20261014.json` | `stage3_gates_20261014` | - | recorded | recorded | - |
| `stage4-gate.json` | `stage4-gate` | - | recorded | `median_wall_s` 0.7500; `peak_decompile_kb` 39280; `peak_disasm_kb` 40884; `peak_import_kb` 40876 | - |
| `stage4_gates_20261015.json` | `stage4_gates_20261015` | - | recorded | recorded | - |
| `struct_gate_sweep_20261013.json` | `struct_gate_sweep_20261013` | - | recorded | recorded | - |
| `struct_gate_sweep_qword_20261013.json` | `struct_gate_sweep_qword_20261013` | - | recorded | recorded | - |
| `struct_inference_audit.json` | `struct_inference_audit` | - | recorded | `schema` 1 | `benchmarks/struct_inference_audit.py` |
| `struct_layer_20261013.json` | `struct_layer_20261013` | - | recorded | recorded | - |
| `struct_layer_final_20261013.json` | `struct_layer_final_20261013` | - | recorded | recorded | - |
| `struct_layer_rerun_20261013.json` | `struct_layer_rerun_20261013` | - | recorded | recorded | - |
| `struct_pointer_fields_stage4_20261015.json` | `struct_pointer_fields_stage4_20261015` | - | recorded | `addresses` 200; `functions_with_a_pointer_field` 1; `structs_printed` 9 | - |
| `struct_print_capcom_20261013.json` | `struct_print_capcom_20261013` | - | recorded | `addresses` 1000 | - |
| `struct_print_dungeon_20261013.json` | `struct_print_dungeon_20261013` | - | recorded | `addresses` 324 | - |
| `structure_handoff.json` | `structure_handoff` | - | recorded | `compared` 1600; `functions` 1600; `identical` 1598; `neutral` 2; `rust_else` 1478; `rust_failed` 0; `rust_gotos` 151; `rust_labels` 103; `stock_else` 1478; `stock_failed` 0; `stock_gotos` 151; `stock_labels` 103; `verify_checked` 0; `verify_mismatched` 0 | `benchmarks/structure_handoff.py` |
| `structuring_baseline.json` | `structuring_baseline` | - | recorded | recorded | `benchmarks/structuring_baseline.py` |
| `structuring_compile.json` | `structuring_compile` | - | recorded | recorded | `benchmarks/structuring_compile.py` |
| `structuring_cutover.json` | `structuring_cutover` | - | recorded | recorded | - |
| `structuring_cutover_m22.json` | `structuring_cutover_m22` | - | recorded | recorded | - |
| `structuring_cutover_m22_no_structure.json` | `structuring_cutover_m22_no_structure` | - | recorded | recorded | - |
| `structuring_cutover_no_structure.json` | `structuring_cutover_no_structure` | - | recorded | recorded | - |
| `structuring_goto_passes.json` | `structuring_goto_passes` | - | recorded | recorded | - |
| `structuring_goto_passes_compile.json` | `structuring_goto_passes_compile` | - | recorded | recorded | - |
| `structuring_goto_passes_compile_current_tree.json` | `structuring_goto_passes_compile_current_tree` | - | recorded | recorded | - |
| `structuring_goto_passes_current_tree.json` | `structuring_goto_passes_current_tree` | - | recorded | recorded | - |
| `structuring_goto_passes_m22.json` | `structuring_goto_passes_m22` | - | recorded | recorded | - |
| `structuring_goto_passes_variants.json` | `structuring_goto_passes_variants` | - | recorded | recorded | - |
| `structuring_m22.json` | `structuring_m22` | - | recorded | recorded | `benchmarks/structuring_m22.py` |
| `structuring_models.json` | `structuring_models` | - | recorded | recorded | `benchmarks/structuring_models.py` |
| `structuring_models_ir_none.json` | `structuring_models_ir_none` | - | recorded | recorded | - |
| `structuring_sailr.json` | `structuring_sailr` | - | recorded | recorded | - |
| `structuring_sailr_before.json` | `structuring_sailr_before` | - | recorded | recorded | - |
| `structuring_sailr_budget.json` | `structuring_sailr_budget` | - | recorded | recorded | - |
| `structuring_sailr_compile.json` | `structuring_sailr_compile` | - | recorded | recorded | - |
| `structuring_sailr_ir_none.json` | `structuring_sailr_ir_none` | - | recorded | recorded | - |
| `structuring_sailr_m22.json` | `structuring_sailr_m22` | - | recorded | recorded | - |
| `switch_feed.json` | `switch_feed` | - | recorded | `n` 200; `seed` 20261006 | `benchmarks/switch_feed.py` |
| `symbol_layout_20261015.json` | `symbol_layout_20261015` | - | recorded | recorded | - |
| `type-headtohead-aarch64.json` | `type-headtohead` | - | recorded | `slots` 37 | - |
| `type-headtohead-mips32be.json` | `type-headtohead` | - | recorded | `slots` 37 | - |
| `type-headtohead-mips32le.json` | `type-headtohead` | - | recorded | `slots` 37 | - |
| `type-headtohead-x86_64.json` | `type-headtohead` | - | recorded | `slots` 37 | - |
| `type-headtohead.json` | `type-headtohead` | - | recorded | `slots` 37 | - |
| `types_port_measure_stage2.json` | `types_port_measure_stage2` | - | recorded | recorded | - |
| `types_port_measure_stage4_20261015.json` | `types_port_measure_stage4_20261015` | - | recorded | recorded | - |
| `upgrade1_failure_classes_def_20261014.json` | `upgrade1_failure_classes_def_20261014` | - | recorded | recorded | - |
| `upgrade1_failure_classes_off_20261014.json` | `upgrade1_failure_classes_off_20261014` | - | recorded | recorded | - |
| `upgrade1_gates_20261014.json` | `upgrade1_gates_20261014` | - | recorded | recorded | - |
| `variant_quality_stage3_20261014.json` | `variant_quality_stage3_20261014` | - | recorded | recorded | - |
| `variant_smoke_stage3_20261014.json` | `variant_smoke_stage3_20261014` | - | recorded | recorded | - |
| `wave_text_diff_stage3_20261014.json` | `wave_text_diff_stage3_20261014` | - | recorded | `compared` 7409; `different` 0; `identical` 7409; `missing` 91; `missing_a` 91; `missing_b` 91 | - |
| `workbench-acceptance.json` | `workbench-acceptance` | - | recorded | recorded | - |
| `workbench-interactions.json` | `workbench-interactions` | - | recorded | `interaction_wall_seconds` 1.8300 | - |
| `workbench-quality.json` | `workbench-quality` | - | recorded | recorded | - |
| `ui-gate.json` | `ui` | M0 | pass | 1 pass, 0 fail, 0 skipped | `benchmarks/ui_gate.py` |
| `discovery-gate.json` | `discovery` | M1 | pass | 20 pass, 0 fail, 0 skipped | `benchmarks/discovery_gate.py` |
| `m1-003.json` | `m1-003` | M1 | pass | recorded | `tests/m1-003_batched_flow.sh` |
| `m1-006.json` | `m1-006` | M1 | recorded | `passed_entries` 20; `skipped_entries` 5; `total_entries` 25 | `tests/m1-006_corpus.sh` |
| `m1-007.json` | `m1-007` | M1 | pass | 20 pass, 0 fail, 0 skipped | `tests/m1-007_oracle_test.py` |
| `oracle-regen.json` | `m1-007` | M1 | pass | 20 pass, 0 fail, 0 skipped | `tests/m1-007_oracle_test.py` |
| `m1-008.json` | `m1-008` | M1 | pass | 6 pass, 0 fail, 0 skipped | `tests/m1-008_languages.py` |
| `m1-008b-classification.json` | `m1-008b` | M1 | recorded | recorded | `tests/m1-008b_pointer_seeds.py` |
| `m1-008b-v1.json` | `m1-008b` | M1 | pass | 2 pass, 0 fail, 0 skipped | `tests/m1-008b_pointer_seeds.py` |
| `m1-008b-scoring.json` | `m1-008b-scoring` | M1 | pass | 20 pass, 0 fail, 0 skipped | `tests/m1-008b_pointer_seeds.py` |
| `m1-009.json` | `m1-009` | M1 | pass | 1 pass, 0 fail, 0 skipped | `tests/m1-009_dol.py` |
| `m1-010.json` | `m1-010` | M1 | pass | recorded | `tests/m1-010_macho.py` |
| `m10-001.json` | `m10-001` | M10 | pass | `images.overlapping_address` 4198400; `images.programs` 2; `images.reads_compared` 16; `images.rows_compared` 607 | `tests/m10-001_multi_image.py` |
| `m10-002.json` | `m10-002` | M10 | pass | `images.follow_facts_compared` 8; `images.followed_programs` 2; `images.ui_programs` 2; `images.ui_switch_functions` 112 | `tests/m10-002_image_navigation.py` |
| `m10-003.json` | `m10-003` | M10 | pass | `edits.reads_compared` 16; `edits.revision_after_second_import` 9; `edits.win_functions` 112 | `tests/m10-003_edit_durability.py` |
| `m10-004.json` | `m10-004` | M10 | pass | `images.methods_excused` 0; `images.methods_program_scoped` 41; `images.reads_discriminating` 13; `images.reads_isolated` 54; `images.writes_inert` 4; `images.writes_isolated` 14 | `tests/m10-004_multi_image_milestone.py` |
| `m10-005.json` | `m10-005` | M10 | recorded | recorded | `tests/m10-005_overlay_isolation.py` |
| `m11-001.json` | `m11-001` | M11 | pass | `session.bounded_analyzed` 1770; `session.decompile_ms` 19.0394; `session.decompiled` 5; `session.edit_survived_reimport` 1.0000; `session.fn_precision` 0.9093; `session.fn_recall` 0.9802; `session.functions_matched` 8353; `session.functions_recovered` 9186; `session.import_peak_kb` 228664; `session.import_wall_s` 45.0100; `session.inference_analyzed` 1770; `session.language_is_powerpc_be32` 1.0000; `session.listing_rows` 16; `session.memory_bytes` 8; `session.oracle_functions` 8522; `session.page_ms` 312.1910; `session.worker_recycles` 10; `session.xrefs_rows` 1 | `tests/m11-001_game_session.py` |
| `m11-002.json` | `m11-002` | M11 | pass | boot.elf: 694 functions in 2.8 s, recall 0.9472 precision 0.8790 over 644 symbols, 5 decompiled (median 25 ms), 1206 inferred; base.elf: 694 functions in 2.8 s, recall 0.9472 precision 0.8790 over 644 symbols, 5 decompiled (median 22 ms), 1206 inferred; Movie.elf: 1678 functions in 7.1 s, recall 0.9550 precision 0.7849 over 1379 symbols, 5 decompiled (median 21 ms), 2415 inferred; driving.elf: 5954 functions in 25.4 s, recall 0.9669 precision 0.9172 over 5648 symbols, 5 decompiled (median 28 ms), 1498 inferred | `tests/m11-002_game_modules.py` |
| `m12-001-modules.json` | `m12-001` | M12 | recorded | recorded | `tests/m12-001_diff.py` |
| `m12-001.json` | `m12-001` | M12 | recorded | recorded | `tests/m12-001_diff.py` |
| `m12-002.json` | `m12-002` | M12 | pass | recorded | `tests/m12-002_cross_compiler.py` |
| `m13-001-rerun-20261008.json` | `m13-001` | M13 | recorded | recorded | `tests/m13-001_vsa_switch.py` |
| `m13-001-rerun-20261009-before-fix.json` | `m13-001` | M13 | recorded | recorded | `tests/m13-001_vsa_switch.py` |
| `m13-001-rerun-20261009.json` | `m13-001` | M13 | recorded | recorded | `tests/m13-001_vsa_switch.py` |
| `m13-001.json` | `m13-001` | M13 | recorded | recorded | `tests/m13-001_vsa_switch.py` |
| `m13-002.json` | `m13-002` | M13 | recorded | `import_wall_s` 74.8000 | `tests/m13-002_manifest_switch.py` |
| `m14-001.json` | `m14-001` | M14 | recorded | recorded | `tests/m14-001_interactive_import.py` |
| `m14-002.json` | `m14-002` | M14 | pass | `batch_seconds` 185.2540; `bodies_inventing_xrefs` 0; `first_open_seconds` 0.3640; `load_seconds` 1.8540; `median_analyse_seconds` 0.0150; `median_decompile_seconds` 0.1820; `median_total_seconds` 0.1990; `sampled` 20; `size_exact_vs_batch` 20; `size_overruns_vs_batch` 0; `walked` 20; `worst_total_seconds` 1.1640; `xref_sets_identical_to_batch` 20 | `tests/m14-002_demand.py` |
| `m14-003.json` | `m14-003` | M14 | pass | `analysed_in_pass` 100; `budgeted_pass_seconds` 4.0740; `libc_functions` 3898; `libc_seeded_at_load` 3898; `load_seconds` 1.3770; `revision_moved` 100; `small_analysed` 405; `small_finish_seconds` 4.6630; `small_functions` 405; `small_rounds_to_finish` 3; `small_undecodable` 0 | `tests/m14-003_facts_so_far.py` |
| `m14-004.json` | `m14-004` | M14 | pass | `analysed` 405; `final_shown` analysed: 405; `first_shown` provisional: 0 analysed, 405 to go; `polls_while_filling` 24; `seconds` 4.3210; `seeded` 0; `stale` False | `tests/m14-004_ui_progress.py` |
| `m15-001.json` | `m15-001` | M15 | pass | `answered` 400; `block_disagreements_without_tables` 0; `comparable` 394; `duplicated_tails` 321; `functions_we_structure_better` 121; `functions_we_structure_worse` 58; `functions_with_gotos` 198; `our_unstructured_edges` 1998; `ours_over_stock` 0.7907; `refused` 0; `scored` 400; `stock_unstructured_edges` 2527; `table_functions_that_agree` 0; `with_tables` 6; `without_tables` 388; `worst_regression` 6 | `tests/m15-001_structuring.py` |
| `m16-001.json` | `m16-001` | M16 | pass | `conservative_rate` 0.9559; `exact` 43; `exact_rate` 0.6324; `scored` 68; `silent` 0; `wrong` 3; `wrong_rate` 0.0441 | `tests/m16-001_types.py` |
| `m16-002.json` | `m16-002` | M16 | recorded | recorded | `tests/m16-002_indirect_calls.py` |
| `m17-001.json` | `m17-001` | M17 | pass | recorded | `tests/m17-001_cfg_functions.py` |
| `m17-002.json` | `m17-002` | M17 | pass | recorded | `tests/m17-002_producer_classes.py` |
| `m18-001.json` | `m18-001` | M18 | recorded | recorded | `tests/m18-001_robust_dispatch.py` |
| `m18-002.json` | `m18-002` | M18 | recorded | recorded | `tests/m18-002_zlib_match.py` |
| `m18-003.json` | `m18-003` | M18 | pass | recorded | `tests/m18-003_scale.py` |
| `m19-001.json` | `m19-001` | M19 | recorded | recorded | `tests/m19-001_pe_import.py` |
| `m19-002.json` | `m19-002` | M19 | recorded | recorded | `tests/m19-002_failure_classes.py` |
| `m19-003.json` | `m19-003` | M19 | recorded | recorded | `tests/m19-003_byte_scan.py` |
| `m19-004.json` | `m19-004` | M19 | recorded | recorded | `tests/m19-004_breadth.py` |
| `m2-002-g8.json` | `m2-002` | M2 | pass | 20 pass, 0 fail, 0 skipped | `tests/m2-002_context.py` |
| `m2-002-h.json` | `m2-002` | M2 | pass | 20 pass, 0 fail, 0 skipped | `tests/m2-002_context.py` |
| `m2-003.json` | `m2-003` | M2 | pass | 20 pass, 0 fail, 0 skipped | - |
| `m2-004.json` | `m2-004` | M2 | recorded | recorded | - |
| `m2-005.json` | `m2-005` | M2 | recorded | recorded | `tests/m2-005_prototype.py` |
| `m2-006-aarch64.json` | `m2-006` | M2 | recorded | `budget_ms` 60000 | `tests/m2-006_inference.py` |
| `m2-006-i386.json` | `m2-006` | M2 | recorded | `budget_ms` 60000 | `tests/m2-006_inference.py` |
| `m2-006-powerpc.json` | `m2-006` | M2 | recorded | `budget_ms` 60000 | `tests/m2-006_inference.py` |
| `m2-006-x86_64.json` | `m2-006` | M2 | recorded | `budget_ms` 60000 | `tests/m2-006_inference.py` |
| `m2-006.json` | `m2-006` | M2 | pass | 20 pass, 0 fail, 0 skipped | `tests/m2-006_inference.py` |
| `m2-006-reference.json` | `m2-006-b2-reference` | M2 | pass | 20 pass, 0 fail, 0 skipped | `tests/m2-006_inference.py` |
| `m2-007-positive.json` | `m2-007` | M2 | pass | recorded | `tests/m2-007_switches.py` |
| `m2-007.json` | `m2-007` | M2 | pass | 20 pass, 0 fail, 0 skipped | `tests/m2-007_switches.py` |
| `m2-008-aarch64.json` | `m2-008` | M2 | recorded | recorded | `tests/m2-008_nonreturn.py` |
| `m2-008-i386.json` | `m2-008` | M2 | recorded | recorded | `tests/m2-008_nonreturn.py` |
| `m2-008-positive.json` | `m2-008` | M2 | pass | `asserted_return_controls` 2; `inferred_functions` 5; `removed_call_xrefs` 3; `restored_call_xrefs` 3 | `tests/m2-008_nonreturn.py` |
| `m2-008-powerpc.json` | `m2-008` | M2 | recorded | recorded | `tests/m2-008_nonreturn.py` |
| `m2-008-x86_64.json` | `m2-008` | M2 | recorded | recorded | `tests/m2-008_nonreturn.py` |
| `m2-008.json` | `m2-008` | M2 | pass | 20 pass, 0 fail, 0 skipped | `tests/m2-008_nonreturn.py` |
| `m2-009.json` | `m2-009` | M2 | pass | 1 pass, 0 fail, 0 skipped | `tests/m2-009_thunks.py` |
| `m2-011.json` | `m2-011` | M2 | pass | 4 pass, 0 fail, 0 skipped | - |
| `m2-012.json` | `m2-012` | M2 | pass | 3 pass, 0 fail, 0 skipped | - |
| `m2-013.json` | `m2-013` | M2 | pass | 8 pass, 0 fail, 1 skipped | - |
| `m2-014.json` | `m2-014` | M2 | pass | 2 pass, 0 fail, 5 skipped | - |
| `m2-015.json` | `m2-015` | M2 | pass | `decompile` 1; `decompile-doc` 1; `disasm` 4; `functions` 12 | `tests/m2-015_native_default.py` |
| `m2-016.json` | `m2-016` | M2 | pass | `flow.seconds` 2.8605; `references.speedup` 2.9409; `total.seconds` 9.2999 | `tests/m2-016_import_budget.py` |
| `m20-001.json` | `m20-001` | M20 | pass | `agreement` 0.9946; `elf_symbols` 11019; `map_rows` 12050; `named_recall` 0.9946 | `tests/m20-001_cw_map.py` |
| `m20-002.json` | `m20-002` | M20 | pass | `map_names` 818; `named_recall` 0.9976 | `tests/m20-002_psyq_map.py` |
| `m20-003.json` | `m20-003` | M20 | pass | `map_names` 5280; `named_recall` 1.0000 | `tests/m20-003_gnuld_map.py` |
| `m20-005.json` | `m20-005` | M20 | pass | `dwarf1_subroutines` 5221; `functions` 8795; `symtab_func` 8794 | `tests/m20-005_flat_map.py` |
| `m20-006.json` | `m20-006` | M20 | pass | `bare_functions` 572; `mapped_functions` 29488 | `tests/m20-006_dtk_roundtrip.py` |
| `m20-012.json` | `m20-012` | M20 | pass | `scalar` 849/849; `vector` 64/64 | `tests/m20-012_rsp.py` |
| `m20-013.json` | `m20-013` | M20 | pass | `gte` 328/328; `vu` 0/0 | `tests/m20-013_vector.py` |
| `m20-014.json` | `m20-014` | M20 | pass | recorded | `tests/m20-014_rel.py` |
| `m20-015.json` | `m20-015` | M20 | pass | recorded | `tests/m20-015_objdiff_units.py` |
| `m20-016.json` | `m20-016` | M20 | pass | recorded | `tests/m20-016_gc_disc.py` |
| `m21-001_combined_20261012.json` | `m21-001` | M21 | recorded | recorded | `tests/m21-001_real_images.py` |
| `m21-001_combined_compiler_rules_20261012.json` | `m21-001` | M21 | recorded | recorded | `tests/m21-001_real_images.py` |
| `m21-001_old_20261012.json` | `m21-001` | M21 | recorded | recorded | `tests/m21-001_real_images.py` |
| `m21-001_stage2.json` | `m21-001` | M21 | recorded | recorded | `tests/m21-001_real_images.py` |
| `m21-001_structs_20261013.json` | `m21-001` | M21 | recorded | recorded | `tests/m21-001_real_images.py` |
| `pc_import_m21_gate_20261015.json` | `m21-001` | M21 | recorded | recorded | `tests/m21-001_real_images.py` |
| `m22-003_dc.json` | `m22-003_dc` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_dc_fix2.json` | `m22-003_dc_fix2` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_dc_fix3.json` | `m22-003_dc_fix3` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_dds.json` | `m22-003_dds` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_dds_fix2.json` | `m22-003_dds_fix2` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_dds_romonly.json` | `m22-003_dds_romonly` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_dk.json` | `m22-003_dk` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_dk_fix2.json` | `m22-003_dk_fix2` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_dk_fix3.json` | `m22-003_dk_fix3` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_failure_classes.json` | `m22-003_failure_classes` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_ff.json` | `m22-003_ff` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_ff_fix2.json` | `m22-003_ff_fix2` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_ff_fix3.json` | `m22-003_ff_fix3` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_ff_fix4.json` | `m22-003_ff_fix4` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_ff_fix5.json` | `m22-003_ff_fix5` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_gh.json` | `m22-003_gh` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_gh_fix2.json` | `m22-003_gh_fix2` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_p4.json` | `m22-003_p4` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_p4-eegcc.json` | `m22-003_p4-eegcc` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_p4-eegcc_fix2.json` | `m22-003_p4-eegcc_fix2` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_p4-eegcc_on_m22-002_sample.json` | `m22-003_p4-eegcc_on_m22-002_sample` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_p4_fix2.json` | `m22-003_p4_fix2` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_p4_on_m22-002_sample.json` | `m22-003_p4_on_m22-002_sample` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_p4_on_m22-002_sample_seed20261011.json` | `m22-003_p4_on_m22-002_sample_seed20261011` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_p4_seed20261011.json` | `m22-003_p4_seed20261011` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_rc.json` | `m22-003_rc` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_rc_fix2.json` | `m22-003_rc_fix2` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_rcpal.json` | `m22-003_rcpal` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_rcpal_fix2.json` | `m22-003_rcpal_fix2` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m23-001_compiler_detection.json` | `m23-001_compiler_detection` | M23 | recorded | recorded | `tests/m23-001_new_project_ps2.py` |
| `m23-001_new_project_ps2.json` | `m23-001_new_project_ps2` | M23 | recorded | recorded | `tests/m23-001_new_project_ps2.py` |
| `m3-001.json` | `m3-001` | M3 | pass | 20 pass, 0 fail, 0 skipped | `tests/m3-001_dwarf_truth.py` |
| `baseline-ghidra-truth.json` | `m3-002` | M3 | recorded | `dwarf.arity_matched` 1640; `dwarf.functions` 1640; `ghidra.arity_correct` 1236; `ghidra.dwarf.fn.recall` 1.0000; `ghidra.dwarf.proto.arity` 0.7537; `ghidra.entries_matched` 1640; `ghidra.functions` 2008 | `tests/m3-002_baseline.py` |
| `m3-003.json` | `m3-003` | M3 | pass | 20 pass, 0 fail | `tests/m3-003_regression.py` |
| `m4-001.json` | `m4-001` | M4 | pass | recorded | `tests/m4-001_register_params.py` |
| `m4-002.json` | `m4-002` | M4 | pass | `improvement.arity_correct_native_default` 1236; `improvement.arity_correct_native_enabled` 1637; `improvement.arity_correct_stock` 1236; `improvement.arity_truth_functions` 1640; `improvement.passes_default_off` 2; `improvement.passes_gated` 2; `improvement.residual_dead_parameters` 3 | `tests/m4-002_improvement_milestone.py` |
| `m4-003.json` | `m4-003` | M4 | pass | `parity.class.data-name-convention` 4; `parity.class.data-type-unknown` 4; `parity.class.language-variant` 3; `parity.class.name-convention` 11; `parity.class.name-rendering` 12; `parity.class.oracle-warning` 23; `parity.class.type-stronger` 66; `parity.functions_compared` 2292; `parity.functions_fact_attributed` 96; `parity.functions_token_identical` 2196; `parity.functions_unattributed` 0; `parity.languages_blocked` 1; `parity.languages_bundled` 9; `parity.languages_measured` 6; `parity.languages_unreached` 2; `parity.rows_measured` 21 | `tests/m4-003_language_parity.py` |
| `m4-004.json` | `m4-004` | M4 | pass | `data.fallback_names` 0; `data.invented_labels` 0; `data.labels_rendered` 1; `data.slots_rendered` 1; `data.strings_rendered` 1 | `tests/m4-004_data_names.py` |
| `m4-005.json` | `m4-005` | M4 | pass | `flow.functions_untouched` 6; `flow.jumptable_warnings` 0; `flow.thunks_direct` 1; `flow.thunks_linkage` 1; `flow.unreachable_warnings` 0 | `tests/m4-005_thunk_flow.py` |
| `m4-006.json` | `m4-006` | M4 | pass | `plt.overrides` 1; `plt.pe_overrides` 0; `plt.resolver_slot` 2111720; `plt.thunks_unchanged` 2 | `tests/m4-006_plt_header.py` |
| `m4-007.json` | `m4-007` | M4 | pass | `got.overlap_warnings` 0; `got.pe_definitions` 0; `got.pointer_width` 8; `got.reserved_definitions` 3 | `tests/m4-007_got_pointers.py` |
| `m4-009.json` | `m4-009` | M4 | pass | `library.declared_functions` 6627; `library.invented_prototypes` 0; `library.typed_imports` 1 | `tests/m4-009_library_prototypes.py` |
| `m4-010.json` | `m4-010` | M4 | pass | `stubs.jumptable_warnings` 0; `stubs.linkage_stubs` 8; `stubs.overrides` 14; `stubs.rows_measured` 3 | `tests/m4-010_stub_transfers.py` |
| `m4-011.json` | `m4-011` | M4 | pass | `render.field_extractions` 0; `render.no_return_facts` 1; `render.pointer_widths` 2; `render.sanitised_names` 2 | `tests/m4-011_widths_exits_names.py` |
| `m4-012.json` | `m4-012` | M4 | pass | `entry` 00201590; `rendered` void processEntry _entry(undefined8 param_1,undefined8 param_2) | `tests/m4-012_remaining_facts.py` |
| `m4-013.json` | `m4-013` | M4 | pass |  | `tests/m4-013_shared_returns.py` |
| `m4-014.json` | `m4-014` | M4 | pass | `broken_sibling` tive runtime: worker failed (exit status: 3): this worker is deliberately broken; `explicit_override` tive runtime: worker failed (exit status: 3): this worker is deliberately broken; `sibling` /* WARNING: Removing unreachable block (ram,0x0040040f) *//* WARNING: Removing u; `workspace_agreement` 14 | `tests/m4-014_worker_resolution.py` |
| `m4-015.json` | `m4-015` | M4 | pass | `named_in_text` 13; `overlap_warnings` 0; `rows` 4; `widths_recorded` 19 | `tests/m4-015_reference_widths.py` |
| `m4-016.json` | `m4-016` | M4 | pass |  | `tests/m4-016_class_direction.py` |
| `m4-017.json` | `m4-017` | M4 | pass | `symbol_wins` _start | `tests/m4-017_entry_names.py` |
| `m4-018.json` | `m4-018` | M4 | pass | `agreed_return_type` int; `oracle_prototypes` 2 | `tests/m4-018_oracle_prototypes.py` |
| `m4-019.json` | `m4-019` | M4 | pass |  | `tests/m4-019_prototype_direction.py` |
| `m4-020.json` | `m4-020` | M4 | pass | `data_labels` 5 | `tests/m4-020_label_prefixes.py` |
| `m4-021.json` | `m4-021` | M4 | pass |  | `tests/m4-021_initializer_slots.py` |
| `m4-023.json` | `m4-023` | M4 | pass | `language.rows_identical_to_stock` 6; `language.rows_measured` 7; `language.rows_stock_unconstrained` 1; `language.rows_unexplained` 0 | `tests/m4-023_language_selection.py` |
| `m4-024.json` | `m4-024` | M4 | pass | `exception.ranges_invented` 0; `exception.ranges_missing` 0; `exception.ranges_recorded` 4; `exception.rows_measured` 8; `exception.rows_with_ranges` 4 | `tests/m4-024_exception_annotations.py` |
| `m4-025.json` | `m4-025` | M4 | pass | `declaration.applied_with_other_types` 0; `declaration.declared_by_stock` 23; `declaration.held` 23; `declaration.noreturn_recorded_as_facts` 5; `declaration.rows_measured` 20; `declaration.signatures_printed_as_stock` 23; `declaration.unexpressible_declarations_refused` 235 | `tests/m4-025_declaration_types.py` |
| `m4-027.json` | `m4-027` | M4 | pass | `pointer.rows_measured` 20; `pointer.slots_held` 37; `pointer.slots_invented` 0; `pointer.slots_missing` 0; `pointer.slots_stock_types` 37 | `tests/m4-027_pointer_slots.py` |
| `m4-028.json` | `m4-028` | M4 | pass | `demangle.mangled_names_kept` 4; `demangle.names_held` 4; `demangle.names_invented` 0; `demangle.names_missing` 0; `demangle.names_stock_derives` 4; `demangle.rows_measured` 20 | `tests/m4-028_demangled_names.py` |
| `m4-029.json` | `m4-029` | M4 | pass | `tags.names_held` 243; `tags.names_invented` 0; `tags.names_missing` 0; `tags.names_stock_holds` 243; `tags.rows_measured` 20 | `tests/m4-029_dynamic_tags.py` |
| `m4-030.json` | `m4-030` | M4 | pass | `pointee.code_pointers` 116; `pointee.plain_pointers` 74; `pointee.rows_measured` 20; `pointee.under_typed` 0; `pointee.unproven` 0 | `tests/m4-030_pointer_targets.py` |
| `m4-031.json` | `m4-031` | M4 | pass | `coined.invented` 0; `coined.misplaced` 0; `coined.names` 14; `coined.rows_measured` 20; `coined.shadowed` 0 | `tests/m4-031_section_names.py` |
| `m5-001.json` | `m5-001` | M5 | pass | `dwarf.fn.recall` 1.0000; `dwarf.functions` 6; `functions` 7; `unattributed` 0 | `tests/m5-001_gba.py` |
| `m5-002.json` | `m5-002` | M5 | pass | imported nds.arm9 natively (5 functions, ARM:LE:32:v5t)
imported nds.arm7 natively (3 functions, ARM:LE:32:v4t) | `tests/m5-002_nds.py` |
| `m5-003.json` | `m5-003` | M5 | pass | `dwarf.fn.recall` 1.0000; `dwarf.functions` 5; `functions` 5; `unattributed` 0 | `tests/m5-003_psx.py` |
| `m5-004.json` | `m5-004` | M5 | pass | `dwarf.fn.recall` 1.0000; `dwarf.functions` 5; `functions` 5; `unattributed` 0 | `tests/m5-004_n64.py` |
| `m5-005.json` | `m5-005` | M5 | pass | `blocked_platforms` 5; `catalog_platforms` 5; `generated_rows` 4 | `tests/m5-005_platform_matrix.py` |
| `m5-006.json` | `m5-006` | M5 | pass | `flow_xref.call.precision` 1.0000; `flow_xref.call.recall` 0.9830; `flow_xref.jump.cross_recall` 1.0000; `flow_xref.jump.precision` 1.0000; `loops_excluded` 2; `transfers_recorded` 1 | `tests/m5-006_tailcall.py` |
| `m5-007.json` | `m5-007` | M5 | pass | `arm7.dwarf.fn.recall` 1.0000; `corpus_unattributed` 0; `promoted` 037f8000 | `tests/m5-007_tailcall_promotion.py` |
| `m5-008.json` | `m5-008` | M5 | pass | `thunk.destination.equal` 114; `thunk.destination.explained` 71; `thunk.destination.unexplained` 0; `thunk.entry.exact` 0.9343; `thunk.entry.precision` 1.0000; `thunk.entry.recall` 1.0000; `thunk.entry.unexplained` 0 | `tests/m5-008_thunk_parity.py` |
| `m5-009.json` | `m5-009` | M5 | pass | `linkage.name.agreement` 1.0000; `linkage.name.missing_import` 0; `linkage.name.presentation` 0; `linkage.name.unexplained` 0; `linkage.name.unsupported` 0 | `tests/m5-009_linkage_names.py` |
| `m5-010.json` | `m5-010` | M5 | pass | `initializer.name.agreement` 0.9553; `initializer.name.equivalent` 74; `initializer.name.missing` 0; `initializer.name.pattern_labels` 11; `initializer.name.unbacked` 0; `initializer.name.unexplained` 0; `initializer.slots` 40 | `tests/m5-010_initializer_names.py` |
| `m5-011.json` | `m5-011` | M5 | pass | `pattern.label.applied` 11; `pattern.label.disagreed` 0; `pattern.label.missing` 0; `pattern.label.spurious` 0 | `tests/m5-011_pattern_labels.py` |
| `m5-012.json` | `m5-012` | M5 | pass | `current_reports` 104; `diagnostic_runs` 12; `generated_rows` 103; `published_ids` 87 | `tests/m5-012_evidence_index.py` |
| `m5-013.json` | `m5-013` | M5 | pass | `arm9.module_bytes` 1122040; `arm9.stored_bytes` 762644; `fn.precision` 0.9909; `fn.recall` 0.6924; `fn.recovered` 7700; `fn.symbols` 11019 | `tests/m5-013_nds.py` |
| `m5-017.json` | `m5-017` | M5 | recorded | `functions` 43487; `language` AARCH64:LE:64:v8A; `stock_ratio` 0.9608; `switch_dispatches` 690; `symbol_precision` 0.9755; `symbol_recall` 1.0000; `symbols` 42423; `wall_seconds` 1333.5000 | `tests/m5-017_switch_module.py` |
| `m6-001.json` | `m6-001` | M6 | pass | `commands` 24; `output_lines` 37; `skipped_blocks` 0; `verbs` 63 | `tests/m6-001_documented_workflow.py` |
| `m6-002.json` | `m6-002` | M6 | pass | `exchanges` 14; `skipped_blocks` 0 | `tests/m6-002_documented_api.py` |
| `m6-003.json` | `m6-003` | M6 | pass | `ui.install.prefix_ok` True; `ui.install.store_only_ok` True; `ui.list.filter_ms` 16.1084; `ui.list.load_ms` 22.6387; `ui.source.fold_reverse_sync` True; `ui.source.follow_rename` True; `ui.source.hints_excluded_from_copy` True; `ui.source.read_only` True; `ui.source.selection_copy` True | `tests/m6-003_desktop_package.py` |
| `m6-004.json` | `m6-004` | M6 | pass | `artifacts` 5; `commands` 6; `listed_platforms` 15; `project_pinned_tools` 2; `sbom_packages` 466 | `tests/m6-004_release_artifacts.py` |
| `m6-005.json` | `m6-005` | M6 | pass | `client_helpers` 23; `commands` 1; `output_lines` 8 | `tests/m6-005_scripting.py` |
| `m6-006.json` | `m6-006` | M6 | pass | `excused_blocks` 51; `gated_pages` 6; `metric_names` 496; `pages` 28; `surfaces` 18 | `tests/m6-006_documentation_coverage.py` |
| `m6-007.json` | `m6-007` | M6 | pass | `ui.match.best_percent` 1.7635; `ui.match.compiled_rows` 7; `ui.match.compiles` 6; `ui.match.decompiles` 7; `ui.match.default_percent` 1.5991; `ui.match.function` FUN_00405380; `ui.match.ms` 11267.2242; `ui.match.rendered_rows` 7; `ui.match.root_follows_project` True; `ui.match.rows` 7; `ui.new_project.config` True; `ui.new_project.files` 13; `ui.new_project.image` project_image; `ui.new_project.job_logged` True; `ui.new_project.ms` 1402.4391; `ui.new_project.readme` True | `tests/m6-007_desktop_projects.py` |
| `m7-001.json` | `m7-001` | M7 | pass | `cost.native.peak_kb.median` 36090.0000; `cost.native.wall_s.median` 0.2670; `cost.peak_ratio.median` 12.0900; `cost.stock.peak_kb.median` 423274.0000; `cost.stock.wall_s.median` 8.4260; `cost.wall_ratio.median` 29.7000 | `tests/m7-001_cost_envelope.py` |
| `m7-002.json` | `m7-002` | M7 | pass | `decompile.native.peak_kb.median` 34594.0000; `decompile.native.wall_s.median` 0.0910; `decompile.peak_ratio.median` 8.3200; `decompile.stock.peak_kb.median` 286368.0000; `decompile.stock.wall_s.median` 5.9330; `decompile.wall_ratio.median` 74.0300 | `tests/m7-002_decompile_envelope.py` |
| `m7-003.json` | `m7-003` | M7 | pass | `session.drift_excess_ms.max` -0.8630; `session.drift_ratio.max` 1.6800; `session.growth_kb.max` 28; `session.growth_kb.median` 14.0000; `session.latency_ms.decompile_doc.median` 6.0020; `session.latency_ms.functions.median` 0.2650; `session.latency_ms.memory_regions.median` 0.2600; `session.latency_ms.search.median` 0.3890; `session.latency_ms.strings.median` 0.4670; `session.latency_ms.symbols.median` 0.1590; `session.latency_ms.xrefs.median` 0.1880; `session.peak_kb.median` 42940.0000 | `tests/m7-003_session_envelope.py` |
| `m8-001.json` | `m8-001` | M8 | pass | `pe.dwarf.fn.recall` 1.0000; `pe.dwarf.fn.unattributed` 0 | `tests/m8-001_pe_unwind.py` |
| `m8-002.json` | `m8-002` | M8 | pass | `ghidra.dwarf.fn.recall` 0.7634; `ghidra.functions` 106; `pe32.dwarf.fn.recall` 0.8065; `pe32.dwarf.fn.unattributed` 0; `pe32.functions` 110; `pe32.undescribed` 35 | `tests/m8-002_pe32_roots.py` |
| `m8-003.json` | `m8-003` | M8 | pass | `body.crossing` 0 | `tests/m8-003_body_extents.py` |
| `m8-004.json` | `m8-004` | M8 | pass | `pe.exports` 3; `pe.exports.forwarded` 0; `pe.exports.forwarder_functions` 0; `pe.exports.misnamed` 0; `pe.exports.missing` 0; `pe.exports.unproven` 0; `pe.tls.callbacks` 8; `pe.tls.missing` 0; `pe.tls.unproven` 0 | `tests/m8-004_pe_roots.py` |
| `m8-005.json` | `m8-005` | M8 | pass | `pe.imports.bound_descriptors` 0; `pe.imports.declared` 166; `pe.imports.libraries` 8; `pe.imports.misnamed` 0; `pe.imports.missing` 0; `pe.imports.not_external` 0; `pe.imports.unnamed_stubs` 0 | `tests/m8-005_pe_imports.py` |
| `m8-006.json` | `m8-006` | M8 | pass | `pe.classes.declared` 4; `pe.classes.unexercised` 0; `pe.classes.unmeasured` 0; `pe.externals` 260; `pe.references` 865 | `tests/m8-006_pe_parity.py` |
| `m9-001.json` | `m9-001` | M9 | pass | `provenance.api_facts_checked` 10; `provenance.classes` 18; `provenance.declared` 18; `provenance.observed` 11; `provenance.unexplained` 0; `ui.xrefs.rows` 19; `ui.xrefs.unexplained` 0 | `tests/m9-001_provenance_explained.py` |
| `m9-002.json` | `m9-002` | M9 | pass | `evidence.attributed.native-analysis:constant-propagation` 1.0000; `evidence.attributed.native-import` 1.0000; `evidence.attributed.native-import:branch` 1.0000; `evidence.attributed.native-import:elf-got` 1.0000; `evidence.attributed.native-import:elf-pointer` 1.0000; `evidence.attributed.native-import:elf-reloc` 1.0000; `evidence.attributed.native-import:elf-unwind` 1.0000; `evidence.attributed.native-import:pe-export` 1.0000; `evidence.attributed.native-import:pe-reloc` 1.0000; `evidence.attributed.native-import:pe-tls` 1.0000; `evidence.attributed.native-import:pe-unwind` 1.0000; `evidence.attributed.native-import:thunk` 1.0000; `evidence.classes` 31; `evidence.declared` 19; `evidence.declared_elsewhere` 11; `evidence.declared_exercised` 8; `evidence.references` 4669; `evidence.unbacked_confidence` 0 | `tests/m9-002_fact_confidence.py` |
| `m9-003.json` | `m9-003` | M9 | pass | `filter.addresses` 20; `filter.facts_matched` 104; `filter.images` 5; `filter.kinds` 3; `filter.symbols_matched` 135 | `tests/m9-003_evidence_filter.py` |
| `m9-004.json` | `m9-004` | M9 | pass | `surface.cli_rows_checked` 12; `surface.committed_ui_declared_rows` 13; `surface.narrowing_addresses` 2; `surface.ui_declared_rows` 0; `surface.ui_rows` 1 | `tests/m9-004_filter_surfaces.py` |
| `m9-005.json` | `m9-005` | M9 | pass | `explanation.methods_answered` 28; `explanation.methods_published` 52; `explanation.printed_sources` 5; `explanation.silent_facts` 0; `explanation.window_declared_rows` 13; `explanation.window_unexplained` 0 | `tests/m9-005_explanation_milestone.py` |
<!-- evidence-index:end -->

## Support matrix

<!-- support-matrix:begin -->
| Input | Structural native import | Native flow/decode/decompile |
|---|---|---|
| ELF x86-64 | supported | **supported and gated**; **parity measured**: 437 of 453 functions token-identical to the JVM oracle across 4 build variants, the rest attributed to named facts (`tests/m4-003_language_parity.py`) |
| ELF x86-32 | supported | **parity measured**: 437 of 466 functions token-identical to the JVM oracle across 4 build variants, the rest attributed to named facts (`tests/m4-003_language_parity.py`) |
| PE32+ x86-64 | supported | **gated**: DWARF recall 1.0000 over 180 functions, 192 `RUNTIME_FUNCTION` records (`tests/m8-001_pe_unwind.py`) |
| PE32 x86 | supported | **gated**: DWARF recall 0.8065 over 93 functions, 0 unattributed, stock Ghidra 0.7634 on the same image (`tests/m8-002_pe32_roots.py`) |
| ELF AARCH64 LE64 | supported | **parity measured**: 449 of 473 functions token-identical to the JVM oracle across 4 build variants, the rest attributed to named facts (`tests/m4-003_language_parity.py`) |
| ELF ARM LE32 | supported | **parity measured**: 4 of 4 functions token-identical to the JVM oracle across 1 build variants, the rest attributed to named facts (`tests/m4-003_language_parity.py`) |
| ELF MIPS LE32 | supported | **parity measured**: 431 of 443 functions token-identical to the JVM oracle across 4 build variants, the rest attributed to named facts (`tests/m4-003_language_parity.py`) |
| ELF RISC-V LE64 | supported | decodes on `RISCV:LE:64:default`; spec bundle present; not parity-gated |
| ELF PowerPC | supported | **parity measured**: 438 of 453 functions token-identical to the JVM oracle across 4 build variants, the rest attributed to named facts (`tests/m4-003_language_parity.py`); e500 verified on Agent Under Fire |
| GBA cartridge ROM | supported | **gated**: DWARF recall 1.0000 over 6 functions on `ARM:LE:32:v4t` (`tests/m5-001_gba.py`) |
| NDS cartridge (ARM9 + ARM7) | supported | **gated**: DWARF recall nds.arm9 1.0000 over 5 functions on `ARM:LE:32:v5t`; nds.arm7 0.7500 over 4 functions on `ARM:LE:32:v4t` with 1 recorded deficit (`tests/m5-002_nds.py`) |
| PlayStation PS-EXE | supported | **gated**: DWARF recall 1.0000 over 5 functions on `MIPS:LE:32:default` (`tests/m5-003_psx.py`) |
| Nintendo 64 ROM (`.z64`) | supported | **gated**: DWARF recall 1.0000 over 5 functions on `MIPS:BE:64:64-32addr` (`tests/m5-004_n64.py`) |
| NES iNES ROM (`.nes`) | supported | decodes on `6502:LE:16:default`; PRG at `0x8000`, vectors seeded; no gate report |
| Genesis / Mega Drive ROM (`.gen`) | supported | decodes on `68000:BE:32:default`; vectors + entry seeded; no gate report |
| Game Boy ROM (`.gb`) | supported | decodes on `GameBoy:LE:16:default`; header-checksum detection, banks at `0x0000`/`0x4000`; no gate report |
| SNES LoROM (`.sfc`) | supported | decodes on `65816:LE:16:default`; checksum+complement detection, 32 KiB chunks at `bank:0x8000`; no gate report |
| Sony PSP ELF (`e_type=0xffa0`) | supported | decodes on `Allegrex:LE:32:default` with the pinned install's full VFPU model (`allegrexVfpu*.sinc`); decrypted PRX modules import, `~PSP` images decrypt with the public KIRK vault; per-title key material is the encrypted-container row below |
| PlayStation 2 (R5900 ELF) | supported | decodes on `r5900:LE:32:default` (vendored `ghidra-emotionengine-reloaded`: MMI and VU0 macro mode); VU0 macro ops lift to per-lane float p-code (`native/languages/r5900/gen_vu.py`; MAC/status flags, the R register and `vcallms` stay opaque) |
| PlayStation 3 (SPU ELF) | supported | decodes on `SPU:BE:128:default` (vendored `GhidraSPU`); PPU side is `PowerPC:BE:64`; the SELF/SPRX loader unwraps PPU images and carves embedded SPU images |
| Xbox 360 (XEX2) | supported | maps the embedded PE on `PowerPC:BE:64:Xenon-32addr` (VMX128 registers modelled); retail XEX decryption (AES-CBC, retail key) and decompression (basic/LZX) are in the loader; encrypted-container row below for keys that are not bundled |

**Not supported.** Each row names the fact that blocks it, and where
that fact was checked.

| Platform | Blocker | Checked |
|---|---|---|
| Encrypted console containers (3DS CIA, PS3/Vita SELF, Switch NCA/XCI, Xbox 360 XEX) | Retail images are encrypted. The loaders decrypt with bundled public keys where those exist (Xbox 360 XEX retail key, PS3 APP vault, Vita public MetaKeys, 3DS zeros fixed key, and now PSP ~PSP via the long-public KIRK key vault + tag tables in native/kirk_tables.rs), and accept user-supplied keys through a KeyStore (`--keys <file>`): a Switch prod.keys supplies header_key/key_area_key, a PS3 .rap derives the NPDRM title key, a Vita .klic unwraps NPDRM, and a 3DS aes_keys.txt supplies slot0xNN/fixed_system. What remains unreachable is content whose key only the console holds and the user has not dumped — Switch retail NCA/XCI without a prod.keys, 3DS slot-key content without the slot key, PS3/Vita NPDRM without the .rap/.klic. II.1 still forbids any runtime fetch; the keys come only from a file the user provides. | crates/romwright-core/src/native/keys.rs (KeyStore) + native/kirk.rs + native/kirk_tables.rs (PSP KIRK vault/tag tables, public constants); import_with(data, keys) on switch/threeds/vita/ps3/psp; tests prove a retail-keyed NCA, an NPDRM SELF via .rap, a klic-wrapped Vita SELF, and a ~PSP round-trip all import. |
**Disassembly failure classes.** Instances observed over the measured corpus; zero is the gate, so any row with a count is a recorded defect.

| Class | Observed | Section |
|---|---|---|
| data-in-code | 0 over 465 functions (aarch64, i386, x86-64) (`tests/m19-002_failure_classes.py`) | Pang §III-A |
| overlapping decode | 0 disagreements, 0 mid-body control targets over 465 functions (aarch64, i386, x86-64) (`tests/m19-002_failure_classes.py`) | Pang §III-A |
| indirect-branch targets | bounded sets scored by m13-001 (`benchmarks/reports/m13-001.json`) | Pang §III-D |
<!-- support-matrix:end -->

**Processor coverage.** Every processor language the pinned install can
decode has a spec bundle under `native/specs/` — 189 of 191 current
languages. The two exceptions are disabled upstream, not unmapped here:
both `65802` and `CR16AB` have their `<language>` element commented out in
the `.ldefs`, so discovery never sees them (and `65802` additionally has no
`.sla` built). Deprecated variants (the `old/` RISCV set) carry bundles but
are not selectable.

**Spec lint.** `romwright-cli lint-specs [--ghidra DIR]` is a stricter spec
compiler: it validates every language module and errors on the defect
classes that produce a bad bundle — unknown `.opinion` constraint
attributes (the `load=`/`loader=` class), `.ldefs` entries naming a `.sla`,
`.pspec`, or `.cspec` that is absent, a `.slaspec` whose `@include` tree
resolves to zero instruction constructors, and `.cspec` schema drift
(`segmentop` without a `<pcode>` body, `callotherfixup` without
`targetop`). Over the pinned install it reports 0 errors and 2 warnings —
the two disabled languages above.

Console platforms with a gate report get a measured row above; the new-project
shapes per platform are in [docs/new-project.md](docs/new-project.md). The
input rows without a gate report of their own (NES, Genesis, Game Boy, SNES,
PSP, PS2, PS3 SPU, Xbox 360) come from `docs/platform-tiers.json` and say so.

The PE parser supports PE32+ (x86-64) and PE32 (i386). Native decompilation
requires the matching compiled SLEIGH language and static specification bundle.
Corpus prototype arity is not full token or program-model parity. The Agent
Under Fire e500 bundle has separate game-specific parity evidence.
The catalog itself was exercised against the pinned Ghidra installation.

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
