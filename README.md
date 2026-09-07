# Ventris

Ventris is a lightweight reverse-engineering platform that reuses Ghidra's
proven components (SLEIGH, p-code, the native decompiler) as compiler
technology rather than reimplementing them. It is **not** a Ghidra fork and
claims no drop-in compatibility.

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
tree**: `lre-cli import <binary>`, `decompile`, `decompile-doc`, `disasm` and
store browsing. The Stage-1 Java bridge is reachable only through `--oracle`,
which exists to produce comparison oracles — `import --oracle`,
`decompile --oracle`, `disasm --oracle` and `dump-specs --oracle` — and needs
`--ghidra DIR` or the service jar. Continuous integration takes that path only
in oracle-generating steps. Native decompilation still reads SLEIGH language
data from the Ghidra install; that is data, not a JVM.

## Layout

service/           Java JSON-RPC stdio bridge over pinned Ghidra APIs
crates/lre-model   IDs, address-space+offset Address, API rows
crates/lre-db      SQLite durable store (WAL, FKs, schema versioning)
crates/lre-core    CoreService facade: store + native import/worker API
crates/lre-worker  no-JVM decompiler worker (pinned ghidra_opt protocol)
crates/lre-api     versioned stdio/HTTP Core API
crates/lre-debug isolated GDB/LLDB read-only debugger backend
crates/lre-cli     scriptable CLI over the facade
desktop/ventris-qt Qt 6 Widgets workstation
python/            SDK, console, permissioned plugins, AI tool adapter
tests/             differential test (native vs Ghidra oracle)
benchmarks/        gold baseline, Stage-4 gate, reports
native/            build scripts, specs, SLEIGH patch (see support matrix)
packaging/         SPDX SBOM and release update metadata tools
third_party/ghidra pinned Ghidra 12.1.3 decompiler C++ + language sources
```

## Prerequisites

- Rust stable (tested 1.98)
- A Ghidra 12.1.3 installation; default lookup is `$VENTRIS_GHIDRA`, then
  `~/ghidra_12.1.3_PUBLIC`. The JVM and JDK are needed only for the bridge
  (Java service) and oracle-side tests.
- Native C++ builds: `binutils-devel` (bfd.h) for the SLEIGH console,
  a C++ toolchain; JDK 25 for the Java side.
- Python 3.10+ for the SDK, console, plugin host, and packaging scripts.
- Qt 6.4+ Widgets/Concurrent and CMake 3.21+ for the desktop build.

## Build

```sh
cargo build --workspace
# Native decompiler worker (patched ghidra_opt; raw-SLEIGH, no JVM)
./native/build_ghidra_opt.sh
# Optional: SLEIGH console (disasm / import --discover)
./native/build_console.sh   # needs binutils-devel
# Versioned Core API (stdio by default, HTTP with --listen)
cargo build -p lre-api
# Java service (only for bridge compatibility paths; Ghidra install jars)
./service/build.sh
# Qt desktop package (requires Qt development files)
cmake -S desktop/ventris-qt -B build/ventris-qt
cmake --build build/ventris-qt --config Release
cmake --build build/ventris-qt --target package --config Release
```

## API, scripting, and extensions

The versioned Core API uses newline-delimited JSON over stdio or `POST /v2`
over HTTP. It is the same `lre-core` service used by the CLI and desktop
bridge:

```sh
./target/debug/lre-api --project ./proj
./target/debug/lre-api --project ./proj --listen 127.0.0.1:8787
python3 python/ventris_console.py --project ./proj \
  --api-executable ./target/debug/lre-api \
  -c 'print(client.ping())'
python3 python/ventris_plugin_host.py plugin.py --project ./proj --permission read
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

`python/ventris_sdk.py` is dependency-free and supports both transports.
`ventris_plugin_host.py` runs each plugin in a child process and gates API
methods by `read`, `write`, `types`, and `native` permissions. The optional
`ventris_ai.py` adapter exposes the same read tools and requires an explicit
mutation opt-in.

`lre-debug` provides isolated GDB/LLDB read commands (backtrace, registers,
and bounded memory reads) through fresh child processes with deadlines. Its
read-only `DolphinGdb` client speaks acknowledged GDB RSP for live target
memory; the Core/API/Qt `memory_live` surface reuses that connection.
`trace_events` stores an ordered timeline; `collab_ops` stores idempotent
Lamport/actor-ordered operations and explicit apply state, so API clients can
share durable analysis changes without sharing SQLite connections.

## End-to-end (supported workflow, no JVM)

```sh
export VENTRIS_SLA=$HOME/ghidra_12.1.3_PUBLIC/Ghidra/Processors/x86/data/languages/x86-64.sla
export VENTRIS_GHIDRA=$HOME/ghidra_12.1.3_PUBLIC          # console defaults

./target/debug/lre-cli import ./smoke_bin --name smoke --project ./proj
./target/debug/lre-cli functions smoke --project ./proj   # store only
./target/debug/lre-cli xrefs smoke --to 00400466 --project ./proj
./target/debug/lre-cli rename smoke 00400466 my_add --project ./proj
./target/debug/lre-cli open smoke --project ./proj        # reopen, no reanalysis
./target/debug/lre-cli disasm ./smoke_bin 00400466 -n 8
./target/debug/lre-cli decompile ./smoke_bin 00400466 --name smoke --project ./proj
```

Import measures itself. `--timings` prints one machine-readable line: the
total, the phases (`parse`, `patterns`, `flow`, `discovery`, `references`,
`store`), the console shard count, and what the flow phase asked of the
console. Batch-parallel work (flow batches, reference rounds) runs one
console per physical core, capped at eight; `VENTRIS_CONSOLE_SHARDS` pins
that count. Requests inside a batch or a reference round are independent, so
shards change wall time and nothing else — `tests/m2-016_import_budget.py`
asserts that a one-console import and an N-console import write identical
function, xref, string, symbol and thunk sets.

```sh
./target/debug/lre-cli import /usr/lib64/libc.so.6 --name libc \
    --project ./proj --timings
# TIMINGS {"total":9.30,"functions":3961,"shards":6,
#          "flow":{"requests":3146,"instructions":297390},
#          "phases":{"parse":0.02,"patterns":0.12,"flow":2.86,
#                    "discovery":3.60,"references":5.32,"store":0.19}}
```

Only `--oracle` starts the JVM: `import --oracle`, `decompile --oracle`,
`disasm --oracle` and `dump-specs --oracle --out DIR` accept `--ghidra DIR`
or the service jar, and exist for oracle generation, not for daily use.

```sh
./target/debug/lre-cli import ./smoke_bin --oracle --project ./oracle-proj
python3 tests/m2-015_native_default.py
```

GameCube DOL import maps the section table and preserves initialized data
inside BSS bounds. Discovery requires the native console and installed
`PowerPC:BE:32:default` language; the console loads a temporary sparse XML
image and supplies instruction flow to the generic worklist. No symbol ELF
is supplied to the importer. `.rel` loading is not implemented.

```sh
./target/debug/lre-cli import /path/to/sys/main.dol --name dol --project ./proj
python3 tests/m1-009_dol.py --dol /path/to/sys/main.dol --oracle /path/to/files/boot.elf
```

The real-input gate requires the hash-pinned GQFE78 pair; missing private
inputs produce a skipped, non-passing report. It is a local gate, not a claim
that CI possesses or tests the game binary.

## Verification

```sh
cargo test --workspace
VENTRIS_SLA=... ./tests/differential.sh     # native vs Ghidra oracle
RUNS=3 VENTRIS_SLA=... ./benchmarks/gate.sh # memory/perf gates
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
  `benchmarks/reports/stage4-gate.json`.
  **Honest comparison caveat**: this is not an apples-to-apples throughput
  benchmark. The native pipeline performs **no auto-analysis** (import is
  structural discovery; analysis facts come from symbols, flow walking, and
  the SLEIGH console) while the stock baseline runs Ghidra's full analyzer.
  Speed/memory win is real but is *at the price of analysis depth* — a trade
  against Ghidra, not a replacement.
- **Historical real-binary measurement (`/usr/lib64/libc.so.6`, 2.48 MB,
  stripped, this machine)**: native import recovered 3,999 functions in 0.54 s (exported
  symbols, init/fini arrays, two-path flow closure); a real 192-byte varargs
  function (`__GI___asprintf`) decompiles natively in 0.9 s. Against the
  Ghidra oracle (3,987): intersection 3,930 — **precision 0.983, recall
  0.986** (69 native-only / 57 oracle-only entries, mostly boundary and
  alias differences). Function-set agreement, not just count proximity.
- **Gate semantics**: `benchmarks/gate.sh` distinguishes a COMPLETE run
  (every required phase executed) from a PARTIAL one (missing SLEIGH
  console → `"complete": false, "skipped": ["disasm"],
  "functional_pass": false, "performance_pass": true`, exit 2). A complete
  PASS (exit 0) requires all phases; the current environment (no
  binutils-devel, no sudo) yields PARTIAL on both the gate and the
  console-dependent differential steps — the worker/CLI parity steps run
  unconditionally and pass.

## Code-function scoring

Raw SHA-keyed `oracle/*.json` references remain unchanged. The separately
versioned `oracle/scoring-v1/` views exclude only Ghidra synthetic external
placeholders with positive loader evidence: an artificial `EXTERNAL` block,
source `Elf Loader`, and a thunk to an external function. Each exclusion
records its reason and evidence; each view hashes its raw reference and exporter.
Permissions or address-range membership alone never exclude a function.
Executable PLT stubs, thunks and unreferenced code remain scored.

```sh
python3 scripts/gen_function_scoring.py --corpus-dir CORPUS \
  --check --report /tmp/function-scoring.json
python3 tests/m1-008b_pointer_seeds.py --corpus-dir CORPUS
```

Omit `--check` to regenerate evidence with pinned Ghidra. `--oracle-dir` and
`--output-dir` support isolated toolchain-specific references without replacing
the committed raw corpus. The policy covers all 20 ELF inputs; the m1-008b
discovery gate covers x86-64 `plain_o0` and `cpp_o2`, with recall >=0.98.
The CI M1 job builds the native console and separately generates a matching
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

```sh
python3 tests/m3-001_dwarf_truth.py --corpus-dir CORPUS
```

Thresholds: `dwarf.fn.recall >= 0.98` per row and in aggregate for both
producers, `dwarf.fn.unattributed == 0`. Evidence:
`benchmarks/reports/m3-001.json` (20 rows, per-row provenance digests for the
binary, its twin and the pinned oracle).

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

```sh
python3 tests/m3-003_regression.py --corpus-dir CORPUS
```

Native ELF32/ELF64 discovery shares `.init`, `.fini` and `.plt` section-start
seeds, alongside unwind-index entries, PLT metadata, flow-confirmed
initializer/data pointers and the existing batched flow walker.
Established function entries can seed pure direct-jump thunk destinations,
optionally after one contiguous instruction with no SLEIGH p-code operations.
Rebuild the console with `native/build_console.sh` to supply explicit `no_op`
and `pure_jump` evidence. Missing evidence fails closed. Multiple prefixes,
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

`ConsoleSession::constants(start, end, mappings, trust_writable)` evaluates
the function over `[start, end)` using native p-code. It returns `ConstantFact`
rows with `pc`, `value`, and varnode storage (`space`, `offset`, `size`).
Only pointer-sized constants targeting supplied mappings are reported;
symbolic register/stack offsets are never reported as literal addresses.

The console command is `constants <start> <end-exclusive> <trust-writable:0|1>
<map-start> <map-end> <flags> ...`, with mapping flags write=1, read=2,
execute=4. Initial writable memory is untrusted unless explicitly enabled.
Queries do not modify image bytes or persist references. Missing commands,
undecodable flow and exhausted analysis limits produce errors, not successful
empty analyses. Rebuild the native console after updating.
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

The same document exposes `jump_tables`: typed branch addresses and ordered
target addresses, including duplicate case destinations. `[]` means a complete
native function has no recovered tables; `null` means structural metadata is
unavailable or incomplete. Targets come from packed native jump tables, not
rendered C. This does not infer case labels/default identities, persist new
functions, or trigger rediscovery. The positive acceptance exercises one
seven-target indirect branch through standalone and warm pooled workers:

```sh
python3 tests/m2-007_switches.py
cargo test -p lre-worker --test jump_tables
python3 benchmarks/switch_gate.py --corpus-dir "$CORPUS" \
  --report benchmarks/reports/m2-007.json
```

The corpus comparison records exact recovered branch/target sets against fresh
stock exports and preserves immutable references in `oracle/switches-v1`.
Zero-table cases are not positive recovery evidence. This comparison adds no
II.3 metric and is not the full M2 program-model parity gate.

Standalone and pooled workers share language resolution; pooled children receive
their SLEIGH configuration explicitly without process-global environment edits.
The pool's 60-second operation deadline includes native registration, not just
decompilation. Failed and timed-out children are killed and reaped; late output
is not published or returned to the warm pool. Protocol errors remain distinct
from elapsed deadlines.
Pool snapshots follow the store revision: edits invalidate idle workers, and a
revision change during analysis discards the result. Both native entrypoints
apply stored callee signatures before analyzing a caller, using call xrefs and
stored function extents rather than neighboring function-entry distances.
Recovery unlocks inferred target parameters, return type, and calling convention;
stored callees and analyst assertions remain locked. Inferred declarations never
rename functions. The native command resets its parameters between applications.
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

```sh
cargo build -p lre-cli -p lre-api -p lre-worker
python3 tests/m2-005_prototype.py
python3 tests/m2-006_revision.py
cargo test -p lre-worker --test prototype_recovery -- --ignored
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

`lre-cli signatures build` turns one static archive into a `.vsig` database
(`docs/vsig.md`): every exported `STT_FUNC` symbol becomes a byte pattern whose
relocated bytes are masked out, using the public relocation widths for that
architecture. A relocation type with no ABI width in the tables skips its
function instead of guessing, patterns carrying fewer than `--min-bytes`
compared bytes are dropped, and one name defined twice with different bodies is
dropped entirely. Package and license are required arguments: they are
declared, never inferred. `signatures info` decodes a database and reports its
records, languages, packages and licenses.

```sh
lre-cli signatures build --archive libc.a --package glibc-2.36-8 \
  --license LGPL-2.1-or-later --out libc.vsig --report libc.json
lre-cli signatures info --db libc.vsig
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

```sh
lre-cli import ./program --name p --signatures libc.vsig
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

```sh
python3 benchmarks/msvc_rtti_gate.py --corpus-dir /path/to/corpus \
  --report benchmarks/reports/m2-014.json
```

That gate links a freestanding MSVC-ABI fixture for both machine widths — no
MSVC installation needed — and compares recovery with the link map's own
`??_R4` complete object locators.

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

```sh
python3 scripts/gen_native_specs.py --corpus-dir "$CORPUS"
python3 benchmarks/prototype_gate.py --corpus-dir "$CORPUS" \
  --report benchmarks/reports/m2-006.json
```

## Support matrix

| Input | Structural native import | Native flow/decode/decompile |
|---|---|---|
| ELF x86-64 | supported | **supported and gated** |
| PE32+ x86-64 | supported | in progress |
| ELF AARCH64 LE64 | supported | discovery gated; decompile parity pending |
| ELF ARM LE32 | supported | selected SLEIGH bundle required; not parity-gated |
| ELF MIPS LE32 | supported | selected SLEIGH bundle required; not parity-gated |
| ELF RISC-V LE64 | supported | selected SLEIGH bundle required; not parity-gated |
| ELF PowerPC | supported | BE32 discovery gated; e500 parity verified; other configurations not gated |
| GBA cartridge ROM | supported | **gated**: DWARF recall 1.0000 on the built fixture, native ARM decompilation verified (`tests/m5-001_gba.py`) |
| NDS cartridge (ARM9 + ARM7) | supported | **gated**: two programs, one per CPU; ARM9 recall 1.0000, ARM7 0.7500 with one recorded deficit (`tests/m5-002_nds.py`) |
| PlayStation PS-EXE | supported | **gated**: DWARF recall 1.0000, native MIPS decompilation verified (`tests/m5-003_psx.py`) |
| Nintendo 64 ROM (`.z64`) | supported | **gated**: DWARF recall 1.0000 on `MIPS:BE:64:64-32addr`; byte-swapped dumps refused by name (`tests/m5-004_n64.py`) |

The PE parser supports PE32+ (x86-64) and PE32 (i386). Native decompilation
requires the matching compiled SLEIGH language and static specification bundle.
Corpus prototype arity is not full token or program-model parity. The Agent
Under Fire e500 bundle has separate game-specific parity evidence.
The catalog itself was exercised against the pinned Ghidra installation.

## Packaging and desktop status

`desktop/ventris-qt` contains the Qt 6 Widgets workstation and CPack TGZ
configuration. `packaging/sbom.py` emits an SPDX 2.3 dependency inventory;
`packaging/update_manifest.py` creates release artifact size/SHA-256 metadata;
`packaging/verify_update.py` verifies downloaded artifacts before use.
This workstation has Qt 6 development files; CMake configure and the
`ventris-qt` target build pass locally, and the app has an offscreen launch
smoke check. CI remains authoritative for the cross-platform package.
CMake configure and visual UI verification remain unavailable on machines
without the Qt development package.

Known limits remain: the all-input discovery gate is incomplete and PE
function-set parity is not claimed. The x86-64 worker needs `VENTRIS_SLA`
and a patched `ghidra_opt`; the API HTTP listener is localhost-oriented and
does not provide authentication; the Python plugin host is the capability
boundary for untrusted scripts. The live overlay was also smoke-tested against
Dolphin 2606a's real GDB stub using the Agent Under Fire RVZ. A live read at
0x80000000 returned the game ID bytes `GW7E69`.
