# STATUS

## Current phase/generation
Stage 9 optional surfaces are implemented. Stage 4 remains the gated native
workflow baseline (39.6 MB peak vs 375 MiB stock; see gate numbers below and
`benchmarks/reports/stage4-gate.json`).

## Current implementation surface

- Phases 5–7 are implemented in `romwright-core`, `romwright-api`, the Qt workstation
  source, and `python/`: symbols/strings/search, memory and graph views,
  bookmarks/patches, typed data manager and propagation, a versioned
  stdio/HTTP API, a dependency-free SDK and console, an isolated
  permissioned plugin host, and an AI tool adapter.
- Phase 9 surfaces now include isolated GDB/LLDB read backends, a read-only
  Dolphin GDB-RSP memory client for the live overlay, durable trace timeline
  events, and a deterministic, idempotent collaboration operation log exposed
  by Core/API/Qt/SDK.
- Native ELF structural import selects Ghidra language ids for x86-64,
  AARCH64, ARM, MIPS, RISC-V and PowerPC. ELF/PE discovery now uses the generic
  SLEIGH worklist; without the console, only structural facts remain. Worker
  verification covers x86-64 and the Agent Under Fire PPC e500 target.
- `romwright-cli architectures --project DIR` scans the installed `.ldefs` catalog.
  Non-x86 native decompile parity is not claimed without a matching compiled
  SLEIGH language and normalized specification bundle.
- `desktop/romwright-qt` has CPack TGZ packaging. `packaging/sbom.py` emits an
  SPDX 2.3 SBOM; `update_manifest.py` and `verify_update.py` produce and
  validate release artifact metadata.
- `.github/workflows/ci.yml` is the cross-platform build/test definition.
  The Qt 6 development files are available on this workstation; the Qt
  configure, target build, and offscreen launch smoke path run locally.

## Completed and verified
- Scrap of the old partial-decompiler-port architecture; pinned Ghidra
  12.1.3 reference tree kept and hash-manifested (commit 993605f, 8cf03d3).
- Java bridge (`service/`): JSON-RPC over stdio; methods import/open/close/
  functions/function/symbols/read_memory/xrefs_to/xrefs_from/
  function_xrefs_from/export_facts/rename/decompile/disassemble/ping/
  dump_specs. Written against verified Ghidra sources only.
- Rust workspace: romwright-model, romwright-db (SQLite WAL+FK, schema_version=1,
  revision-stamped mutations), romwright-core (CoreService facade), romwright-cli,
  romwright-worker, romwright-worker-client, romwright-api, and romwright-debug. `cargo test
  --workspace`: 82 tests pass across 20 suites.
- E2E proven on x86-64 ELF fixture (gcc -O0, 12.6 KB):
  - import: 15 functions, 34 xrefs, 93 symbols persisted with
    provenance `ghidra-bridge / 12.1.3`
  - store-only `open` (no JVM launched): works
  - rename persists in store, revision bump verified in unit tests
  - decompile + disasm through bridge against saved program
- Native worker protocol (romwright-worker) fixed to the pinned C++ exactly:
  - registerProgram (queries answered from store/binary),
  - arch-id frame for decompileAt/setAction (ghidra_process.cc:82-97),
  - packed `<addr>` element + attribute ids from the marshal tables,
  - response tail (result stream, warnings frame 0x10..0x11, 0x07),
  - interleaved queries inside the result stream (Java readResponse model),
  - callbacks: getBytes, getMappedSymbols (doc/mapsym/function),
    getRegister, getRegisterName, getCodeLabel, getUserOpName,
    isNameUsed (bool), tracked-register pointset, plus safe empties.
  - deferred cleanly: stdin close before wait (Drop no longer deadlocks).
- Differential test (tests/differential.sh): x86-64 ELF, native (pinned
  console decompiler, no JVM) vs bridge oracle:
  - add: both decompile to "return A + B" (oracle params vs native
    unaff registers normalized),
  - main: both call add (0x400466) and printf (0x400370), return 0.
  - PASS: native matches the oracle modulo naming.

## Measured (benchmarks/reports/)
- Stock Ghidra (analyzeHeadless, tiny ELF fixture, 3 runs): median wall
  10.83 s, median peak process-tree RSS 375 MiB.
- Native spike: pinned C++ decompiler + sleigh_opt compiled x86-64.sla;
  `add` and `main` decompiled with zero JVM in the process tree
  (benchmarks/reports/native-spike.md).
- Stage-1 CLI import (bridge): ~5-10 s Ghidra work + ~7 s JVM startup.

## Stage 3 closed: JVM-free protocol decompile (getPcode gap)
- Out-of-tree `ghidra_opt` gains a raw-SLEIGH translator hook
  (native/ghidra-opt-sleigh.patch + native/build_ghidra_opt.sh; the pinned
  third_party tree is untouched): when ROMWRIGHT_SLA points at the compiled
  x86-64.sla, ArchitecutureGhidra::buildTranslator registers the
  `<sleigh>`-path tag (SleighArchitecture::buildSpecFile handshake,
  sleigh_arch.cc:410-418) and builds a real `Sleigh`; buildContext then
  uses ContextInternal (ContextGhidra blocks registerVariable).
- Consequence: GhidraTranslate::oneInstruction's client-side getPcode
  query is gone — the decompiler self-disassembles, the worker's
  getBytes callback feeds the bytes, and the whole register →
  mappedsymbols → setAction → decompileAt flow runs with zero JVM.
- Verified end to end on the x86-64 ELF fixture:
  - add: `int add(int param_1,int param_2){return param_2 + param_1;}`
    — token-identical to the bridge oracle (differential test's
    "exact worker-vs-oracle check").
  - main: calls add + printf with the right consts, returns 0.
- native/ghidra-opt-sleigh.patch = the two hunks (buildTranslator,
  buildContext) plus the Makefile link rule for the SLEIGH objects.
- Repro: `native/build_ghidra_opt.sh` (copies sources aside, git-apply
  the patch, `make ghidra_opt`), binary at native/build/ghidra_opt.

## Stage 4 closed (this phase)
- CLI `decompile <binary> <addr> [--name P] [--project DIR] [--base HEX]`:
  the supported no-JVM decompile route. Spawns `romwright-worker` against the
  patched ghidra_opt (env ROMWRIGHT_GHIDRA_OPT, default native/build/ghidra_opt)
  with vendored specs (native/specs) and the store project. Verified
  token-identical to the bridge oracle (`int add(int param_1,int param_2){
  return param_2 + param_1;}`) — differential step "CLI decompile".
- `native/build_console.sh`: reproducible SLEIGH console build (needs
  binutils-devel/bfd.h, Ghidra's own native-build prerequisite; the bfd-less
  spike binary predates the pinned tree). Console env defaults now derive
  from the Ghidra install (ROMWRIGHT_GHIDRA) instead of /tmp/spike.
- `benchmarks/gate.sh`: full JVM-free workflow gate (import ->
  functions/xrefs/rename/open -> disasm -> decompile),
  per-phase peak RSS + total wall; asserts < 100 MB and < 120 s.
  Result on the tiny ELF fixture: peak 39 920 KB, median wall 0.32 s (3 runs) —
  9.5x under the 375 MiB stock baseline (benchmarks/reports/stage4-gate.json).
- Bridge robustness: null CodeUnit guard in export_facts comments
  (Dispatcher.getCommentAddressIterator can yield addresses with no code
  unit; the NPE aborted bridge imports).
- Bridge lifecycle fixes (service/ + bridge.rs):
  - `shutdown` method in the service (the CLI's shutdown RPC used to hit
    "unknown method", then child.wait() blocked on a JVM whose read loop
    never saw EOF — the import CLI hung >120 s at exit).
  - The bridge closes its stdin pipe before waiting, so an unresponsive
    service can't stall the CLI.
  - Session.close releases only import-flow programs (open-flow programs
    are released by GhidraProject.close; releasing them first threw
    "unknown consumer" at every shutdown).
  - GhidraBootstrap.shutdown skips GhidraProject.close: import-flow
    programs register the bootstrap consumer, so the project's own
    release throws; the process exit releases the project lock anyway.
- Differential fixes: dump_specs now runs after the import (ordering bug
  on fresh runs), stale project locks are removed at the start, and the
  CLI decompile check compares token-identical content (the
  worker's C text carries no layout whitespace).
- Final differential (2026-09-02): PASS — protocol worker and CLI
  decompile token-identical to the oracle; native import parity
  11/11; stripped CLI discovery 7/7 subsets of the oracle; add/main
  semantic parity.

## QA-003 corpus matrix: earned its keep
- `tests/corpus.sh`: builds and imports plain C (O0/O2), PIE, C++ (exceptions
  + TLS + switch), and a 400-function binary; writes
  benchmarks/reports/corpus.json. Result: 5/5, **many_o2 = 406 functions**.
- The matrix immediately found a critical decoder default bug: `op_info`
  assumed no ModRM for unlisted opcodes, but most one-byte opcodes (01 add,
  03 or, all /r forms...) carry one — `add eax,ebx` decoded as 1 byte and
  misaligned every walk past the first arithmetic instruction (main of the
  400-fn fixture stopped after its first call). Fixed: default ModRM, with
  an explicit no-modrm set (push/pop, nop/xchg, cbw-family, enter/leave,
  aam/aad, loop, int1, clc-family, movs/cmps). Regression tests:
  `main_prologue_lengths` (1,5,5,2,5,5,2) and the existing suite.
- Also fixed: last-function size cap used `start+16` as the fallback
  "next entry" — capping proven bodies at 16 bytes for the final function
  of a section; now uses the end of the current map.

## CORE-006: command + undo journal
- `command_journal` table (schema v2, migrate): per-program monotonic seq,
  kind, JSON payload/undo_payload, done flag.
- romwright-db composes command transactions: `rename_command` (rename + revision
  bump/event + journal push, one tx) and `undo_rename` (rename back + event
  + mark done, one tx); `journal_latest`/`journal_push`.
- Core: `rename_command` (captures prior name for undo) + `undo_last`
  (dispatches on kind; rename undo verified). `rename` (CLI) now goes
  through the command path; new CLI `undo <program>`.
- E2E: rename my_add -> undo -> add; second undo reports "nothing to undo";
  journal shows (1, rename, done=1, payload).
- Test `rename_command_undo_roundtrip`. 37 workspace tests.

## CORE-005: revision/event model
- `revision_events` table (schema v2, created by migrate): every mutation is
  transactional with a revision bump + an event row (kind/detail).
- Wired: rename ("rename" + new name) and all five replace_* paths
  ("replace-functions"/"replace-symbols"/"replace-xrefs"/
  "replace-comments"/"replace-datatypes" + row count). rename_function is
  now transactional.
- `romwright-model::RevisionEvent { revision, kind, detail }`; store
  `events_since(program, since)`; `Core::events_since`.
- Evidence (native import + rename, real store):
  (2, replace-functions, 11), (3, replace-xrefs, 3), (4, rename,
  renamed_add) — strictly increasing, observable windows.
- Tests: `revision_events_recorded` (kinds, revisions, since-windows);
  paged test updated for bump semantics. 36 workspace tests.

## CORE-004: paged query API
- `romwright-model::Page<T> { rows, offset, total, revision }`; store methods
  `functions_page`/`symbols_page`/`xrefs_page` (LIMIT/OFFSET windows +
  COUNT + revision); Core exposes the same three.
- CLI: `functions --offset N --limit M` proves the window path (header
  prints the window, total, and rev); default remains the full list.
- Test: `paged_functions_window` (100 rows; 10-row windows; boundaries;
  revision 1).
- 35 workspace tests.

## CORE-001: typed address migration
- Model rows now carry `Address { space, offset }` (FunctionRow/SymbolRow/
  XrefRow/CommentRow/DisasmRow); strings exist only at serialization edges:
  romwright-db (hex TEXT columns, `addr_cell`/`addr_from_cell`), the JSON-RPC
  bridge (tolerant `parse_rows`: rows with unsupported-space addresses
  — e.g. Ghidra stack comments `Stack[-0x10]` — are skipped with a count,
  not silently mangled or import-aborting), and the CLI (argument parsing).
- `Address` has a custom `Deserialize` (hex string OR `{space, offset}`;
  last-colon split for overlay names like `.annobin.notes::00000000`) and
  `Display`/`hex()`.
- API: `Core::{xrefs_to, xrefs_from, rename_function}` take typed
  `&Address`; `romwright-db` same; the worker consumes `f.entry.offset` directly.
- Verification: 34 workspace tests; differential RC=0 (bridge boundary
  exercised through import + oracle steps); CLI e2e (functions/xrefs/rename)
  clean; corpus 5/5.

## Phase 1 correctness closure (review batch)
- CORE-008 shape: SLEIGH-first discovery — with the pinned console present,
  its disassembly is the primary flow source (unioned with the in-Rust
  two-path walk, which is now explicitly the fallback/cross-check; the
  handwritten decoder is no longer the sole production source).
- Conservative function bodies: the walk records each function's proven
  extent (span of decoded instructions, stop-based) capped at the next
  entry's distance; flow_discover uses those sizes instead of the
  always-distance-to-next fiction. tiny_stripped: `_entry` 38 (was 64),
  `0x4003c0` 33 (was 112), `0x400430` 33 (was 48) — walk-verified bodies.
- QA-002 fuzz smoke: deterministic malformed-input loop (truncated/
  magic-only/absurd-section-table ELF+PE + decode over byte soups) — no
  panic, typed errors (19 romwright-core tests incl. this).
- PIE evidence: gcc `-fPIE -pie -O2 -s` executable imports natively
  (11 functions; entries include `_entry` 0x800 with the RDI convention;
  zero-based vaddrs like ET_DYN). Remaining (QA-003 corpus): oracle
  differential on PIE binaries is part of the matrix work.
- Differential policy (QA-004): comparisons are categorized —
  exact (byte/whitespace-normalized token identity: worker + CLI
  decompile), semantic (add/main A+B and call targets), subset
  (native entries ⊆ oracle), skipped (console-dependent, explicit note).
  No claim mixes categories.

## Sessionful runtime foundation (review Phase 2 start)
- `romwright-core::session`: `RuntimeConfig` (immutable; env-derived defaults, the
  internal contract services take — native_runtime migration continues),
  `MemoryRegion { vaddr, size, file_off, file_size, flags }`,
  `ProgramImage` (one read-only `memmap2` mapping + regions + sparse patch
  overlay; BSS zero-fill bounded by `file_size`), `ProgramSession`
  (program name + `Arc<ProgramImage>` + metadata with language/format/image
  base).
- `Core::open_session` (map-once) and `Core::mem_native` now served from a
  cached `ProgramImage` — repeated reads no longer re-read, re-parse, or
  re-discover the binary (review CORE-002 / 4.8).
- New dependency: `memmap2` (safe `Mmap`; the one reviewed FFI-adjacent
  site, read-only mappings only).
- Tests (18 romwright-core, 32 workspace): region file-byte reads, BSS zero-fill,
  patch overlay, unmapped/crossing reads, `RuntimeConfig` defaults, and
  `ProgramImage::open` against the real fixture (add's bytes at 0x400466).
- The environment-var contract inside `native_runtime` moves to accept a
  `RuntimeConfig` next (CORE-001 typed identity; CORE-004 paging...), per
  the ratified 9-phase roadmap.

## Post-review hardening (facade contract + real-binary evidence)
- Native paths moved into the Core facade (review: "a GUI can't reuse the
  native decompile/disasm without copying romwright-cli's spawn logic"): new
  `romwright-core::native_runtime` + `Core::{import_native, disasm_native,
  decompile_native, mem_native}`; romwright-cli is now a thin delegate (same
  methods a GUI consumes). `decompile` validates ROMWRIGHT_SLA
  existence — a missing .sla used to surface as a silent "no architecture
  registered" decompiler exception.
- Typed address accessors on the model rows (FunctionRow::entry_addr,
  XrefRow::{to_addr, from_addr}, Address::parse_ram_hex/hex) — the storage
  stays canonical hex strings, consumers get typed values.
- Durable-store dedupe: replace_functions/symbols/xrefs now dedupe within
  a batch — libc's versioned exporter aliases (memcpy/__GI_memcpy broke
  the UNIQUE index on the bridge import of libc.so.6).
- **Real-binary sample (`/usr/lib64/libc.so.6`, 2.48 MB, stripped)**:
  native import recovers 3,999 functions in 0.54 s (dynsym exports +
  init/fini arrays + flow closure; no console rounds); the Ghidra-oracle
  bridge import recovers 3,987 in ~2 min — count parity within 0.3%.
  Same-function decompile (`asprintf`): native and oracle both produce
  the full 1.4 KB C bodystructurally; the delta is naming/type knowledge
  (oracle: `__ptr`/`__fmt`/`iVar1` from libc type info; native: generic
  `param_N`/stack names). That is exactly the analysis-depth trade the
  review called: the native path brings no Ghidra knowledge, only the
  same decompiler.
- **Address-base note**: Ghidra rebases ET_DYN imports to image base
  0x100000 (asprintf at 0x135b40) while the native import is zero-based
  (0x35b40) — same bytes, different space convention; document for
  cross-tool comparisons.
- Environment: the SLEIGH console (native/build_console.sh) needs
  binutils-devel (bfd.h) which is not installed here; console-dependent
  test steps are skipped with an explicit note, worker/CLI parity runs
  unconditionally.
## Second-review hardening (decoder/parser correctness, gate honesty)
- Decoder fixes with regression tests (all in `short_branch_and_no_modrm_0f_lengths`):
  - short branches (EB/70..7F) read the displacement as ONE sign-extended
    byte; the old 4-byte reader included following instructions in the
    target (frame_dummy's `jmp -0x76` used to mislabel its target).
  - 0F opcodes without ModRM (syscall, rdtsc/cpuid, bswap, emms, ...) no
    longer take a phantom ModRM byte (length 2, not 3+).
  - F6/F7 group: the immediate exists only for the TEST form (modrm ext 0);
    NOT/NEG/MUL/DIV no longer gain 1/4 phantom bytes.
- PE: executable classification now tests IMAGE_SCN_MEM_EXECUTE only
  (0x20000000); the old mask OR'd in MEM_READ and classified readable data
  sections as code (regression `pe_exec_requires_execute_characteristic`).
- ELF: a magic-only/truncated header returns a typed error instead of
  panicking on `data[4]`/`data[5]` (`truncated_elf_magic_errors_not_panics`).
- Discovery: the walk became genuinely two-path (conditional branches
  explore the taken edge and resume the fall-through from an explicit
  stack). The decoder fixes had dropped 0x4003c0 from the stripped fixture
  because dtors_aux's `jne` skipped the fall-through body containing its
  call; with both edges explored it returns (7/15, correct edges, not
  decoder luck). Regression `conditional_fallthrough_discovers_call_target`.
- `mem_native` no longer re-reads/re-discovers the binary per read (one-entry
  parsed-import cache).
- Gate honesty (review 4.13): `rss()` defined before use (console-present
  runs previously tripped `command not found` under `set -e`); reports now
  carry `complete`/`skipped`/`performance_pass`/`functional_pass` and exit 2
  on PARTIAL — an incomplete run can no longer read as PASS.
- `.gitignore`: volatile `benchmarks/reports/gate-run/` + run sqlite files.
- SECURITY.md: removed stale Python-wheel/VSCode claims from the scrapped
  project; documents the actual child-process and parser boundaries.
- libc function-set metrics (not count proximity): 3,930 common of
  native 3,999 / oracle 3,987; precision 0.983, recall 0.986; residuals are
  boundary/alias differences (e.g. native-only 0x774 `_dl_argv`-adjacent
  aliases vs oracle-only 0x7b0).


## Native import (no-JVM) landed
- `romwright-core::native`: ELF64 + PE (PE32/PE32+) parsers (sections -> memory map,
  SHT_SYMTAB function symbols, SHT_DYNSYM externals, SHT_RELA GOT relocs
  naming the `ff 25` PLT stubs), direct-call sweep (call/jcc/jmp rel32),
  and the call-target closure (FUN_<hex> naming). Facts land in the same
  store tables with provenance `native-import / 12.1.3`.
- CLI: `romwright-cli import <binary> [--name N] [--project DIR]` — the
  whole import with zero JVM.
- Verified: tiny_bin native import = 12 code functions whose entry set
  is a subset of the bridge oracle's (differential "import parity" step);
  tiny_pe.exe native import = 310 functions (entry + CRT call closure vs
  Ghidra's 138 — closure granularity differs, documented approximation;
  the ELF parity is exact at the entry-set level).

## Memory measurement (ADR-0001 target: beat 375 MiB stock)
- Protocol worker run (register + setAction + decompileAt on the x86-64
  ELF fixture, ROMWRIGHT_SLA self-disassembling build):
  peak RSS 39.5 MB — **9.5× under the 375 MiB stock-Ghidra baseline**.
- The native console path and the store-only workflows stay in the same
  order of magnitude (no JVM in any no-JVM path).

## JVM-free workflow CLI (added this phase)
- `romwright-cli import <binary> [--name N]` — ELF/PE -> store, no JVM.
- `romwright-cli mem <binary> <vaddr> <size>` — mapping-backed memory dump.
- `romwright-cli disasm <binary> <addr>` — SLEIGH disassembly via the
  pinned console (no JVM).
- `romwright-cli comments <program>` / `types <program>` — store-owned facts.

## PE parity closed
- PE32+ ImageBase fixed (PE32+ has no BaseOfData: ImageBase at optional+24,
  not +28) — the mingw fixture parses to the true base 0x140000000; worker
  --base matches; the section map (RVA -> raw) now feeds byte resolution.
- PE protocol worker: add == oracle exactly (`return param_2 + param_1`);
  main semantically identical (__main, add(2,0x28), printf+format addr,
  return 0). The differential's PE step checks add.

## Stripped-binary discovery (closed)
- In-Rust flow discovery: seed walk (symtab/dynsym, entry, externals) with
  direct call/branch closure, the ELF `_start` -> `__libc_start_main` RDI
  convention (mov rdi imm64/imm32, lea rdi [rip+disp32] scan), and
  init/fini-array function-pointer seeds.
- Fixed a pre-existing decoder bug: ModRM index for prefixed instructions
  (`m = p + len` read the wrong byte; REX-prefixed memory operands
  misaligned every walk) — regression test `prefixed_memory_lengths`.
- tiny_stripped (no symbols, no JVM): 7 functions recovered (__gmon_start__,
  _entry, frame_dummy, __do_global_dtors_aux, deregister_tm_clones, add,
  main) — every one in the Ghidra oracle's 15; the oracle-only remainder is
  indirect-only CRT and PLT shims (`register_tm_clones`, `_init`/`_fini`,
  0x404000+), outside the call-closure model by construction.
## Known gaps / risks
- Bridge project lock is single-writer: concurrent CLI invocations fail
  with "Unable to lock project" (Ghidra project lock); stale locks need
  manual removal after an aborted JVM.
- Decompilation latency bounded by JVM startup for one-shot CLI use; a
  persistent service session amortizes it.
- `Loaded.save`+`ProgramLoader` path persists correctly, but re-import of
  the same binary name creates `.1` duplicates (Ghidra duplicate naming).
- The CLI's `xrefs --from <entry>` is address-addressed.

## Store ownership (Stage 2-3 remainder)
- Schema v2 (migration in place): `comments` (address, function, type,
  text) and `datatypes` (name, definition) tables, revision-stamped by the
  same replace/upsert path as functions/xrefs.
- Bridge export_facts now includes comments (eol/pre from the function
  body via the listing) and datatypes (dtm.getAllDataTypes, pointers
  skipped, deduped on insert).
- CLI: `comments <program>` and `types <program>` (store-only, no JVM).
- Verified: PE import (tests/fixtures-src/tiny_pe.exe, mingw x86-64)
  stores 138 functions incl. add @ 0x140001450 and main @ 0x140001464,
  win32 types (BOOL/BYTE/CRITICAL_SECTION/...), and pre-comments.
- Worker protocol: getComments answered safely (empty response; the C++
  guards the decode, comment_ghidra.cc:46).

## UI roadmap (2026-09-02, v0.5.0)

Phases 0-3 of the desktop roadmap are implemented and tagged `v0.5.0`
(31 commits, qt-001..qt-021 + core-008..core-011). Phase 0 split the
1,914-line `main.cpp` into one file per class with typed views; Phase 1
finished the core loop (server-side filter/sort on `functions_page`,
inline rename + undo, virtualized listing over core-007 windows with
operand jumps and a context menu, paint-based token decompiler with
hit testing and a revision-keyed cache, two-tab xrefs with containing-
function resolution, go-to dialogs, per-project session persistence);
Phase 2 added BB-graph extraction + layered layout in core, a
virtualized hex canvas with pointer detection, paged strings, and job
surfacing with cancel; Phase 3 added themes, the command palette,
project management, the first-run gate dialog, and CPack packaging.

Verified on this machine: libc (2.48 MB) imports in 4.5 s with 4,023
functions; server-side filter answers in 20-30 ms; listing windows and
decompilation render (malloc_printerr decompiled JVM-free); the Qt app runs
the libc project offscreen without crashing; `cargo test --workspace` is
green (82 tests across 20 suites); the CPack TGZ builds.

- Engine-gated progress:
- WorkerPool is wired through API and Qt `decompile_doc`; `jobs_page`
  reports bounded job rows, idle/busy workers, restart count, configured
  memory cap, and memory-cap hits. The x86 tiny API smoke returned a
  succeeded row with one idle worker; a `/bin/false` worker smoke returned
  a failed row with `restarts=1`.
- Listing rows now carry explicit `function_header`, `bb_separator`, `label`,
  `data`, and `instruction` kinds from the core model. The parser acceptance
  fixture covers all five kinds; native console smoke emitted four basic-block
  separators, the API default-overscan smoke returned structural rows, and
  the Qt target built and launched offscreen without a crash.
- UI gate baseline (`benchmarks/reports/ui-gate.json`) now records the
  frozen II.2 schema and three-run libc metrics on a clean package install:
  load 9.648 ms, filter 4.762 ms, sync 2.216 ms, graph layout 11.571 ms,
  graph paint 7.891 ms, and install.ok true. All six UI metrics pass their
  frozen thresholds (`passed: true`).
- m0-002 instrumentation now records all six frozen UI fields on libc
  (`ui.list.load_ms`, `ui.list.filter_ms`, `ui.sync_ms`, `ui.graph.layout_ms`,
  `ui.graph.paint_ms`, and `ui.install.ok`); the acceptance smoke confirms
  every field is non-null.
- Phase 4 (game-first surfaces): the target arrived (007 Agent Under
  Fire, GameCube GQFE78). ELF32 BE PowerPC import landed (644 functions
  with symbols from base.elf), the first two Phase 4 surfaces ship
  (signature search + vtable recovery, core-012/qt-022), and PPC
  decompile parity is DONE (core-013): the decompile path resolves the
  SLA, language dir, and spec bundle from the program's stored language
  id; the PPC e500 bundle is vendored; base.elf __start decompiles
  JVM-free with zero configuration. x86 unchanged.
  - Prototype injection is complete: the worker sends a packed function
    shell, the native command parses and applies the full C prototype to
    `FuncProto`, renames the loaded function, clears analysis, and the
    Agent Under Fire PPC target smoke renders the edited name and params.
  - Live-target memory overlay is complete at the transport, Core/API,
    and Qt layers: `romwright-debug` implements read-only GDB RSP memory reads,
    Core reuses a bounded connection, and the hex canvas exposes a live
    endpoint toggle and source marker. A deterministic local RSP server
    verifies acknowledgements, checksum rejection, target errors, bounds,
    connection reuse, and the two-byte read path. A real Dolphin validation
    now also passes: Dolphin 2606a, headless `Null` backend, and the Agent
    Under Fire RVZ served GDB port 24689; `memory_live` read 16 bytes at
    `0x80000000`, beginning with `47 57 37 45 36 39` (`GW7E69`).

- m0-003: added `romwright-cli graph <program> --largest --binary <path>` locator
  which sorts recovered functions by size descending, analyzes their native
  basic-block graphs, and returns the target function with >= 200 blocks
  (found `__vfscanf_internal` at `00042cb0` with 297 basic blocks on libc).
  The acceptance smoke `tests/largest_graph.sh` passes against `/usr/lib64/libc.so.6`.

- m0-004: measured and verified Qt layout/paint execution on the largest-BB graph
  (`__vfscanf_internal` at `00042cb0`, 297 blocks). Pre-resolved edge node indices
  in `GraphCanvas` to eliminate repeated quadratic string scans, accelerating paint
  >3x (paint: ~9.1ms vs 50ms threshold, layout: ~11.9ms vs 200ms threshold), and
  streamlined view address synchronization (`ui.sync_ms` down to ~2.4ms vs 16.0ms threshold).
  The acceptance smoke `tests/largest_graph_qt.sh` passes against `/usr/lib64/libc.so.6`.

- m0-005: decoupled auxiliary panel loading from `FunctionTableModel::refreshed`
  into `loadProgramPanels()`, eliminating queue contention in `CoreBridge` during
  filtering. `ui.list.filter_ms` on fresh libc imports dropped from ~416ms to 5.69ms
  (median of 3 runs, threshold 100.0ms), and `ui.sync_ms` reduced to 2.15ms (threshold 16.0ms).
  The acceptance smoke `tests/filter_latency.sh` passes against `/usr/lib64/libc.so.6`,
  and `benchmarks/reports/ui-gate.json` now records all 5 numeric metrics passing.

- m0-004: added package installation smoke test `tests/package_install_smoke.sh`
  building the CPack release archive, extracting to a clean prefix, and running
  the gate on libc with install evaluation enabled. All six metrics pass within
  thresholds (`ui.install.ok: true`, `passed: true`). Final README matrix
  citation is deferred until verified on three-OS CI.

- m0-007: recovered RIP-relative data xrefs (`InstrInfo::rip_data` over `[rip + disp32]`),
  full near/short conditional branch kinds, and CRT helpers (`_init`, `_fini`, and
  relative relocation function pointers like `register_tm_clones`) in the native import
  pipeline. Recovered 11,282 `DATA` xrefs on libc and all 4 xref kinds on tiny_bin.
  The acceptance smoke `tests/data_xrefs.sh` passes.

- m0-009: added `CONTRIBUTING.md` with explicit clean-room policy (no proprietary
  or leaked material; citation rules; docs/third-party.md) and gate-file rule.
  Updated `AGENTS.md` with the verbatim Section II.0 operating loop and Section
  II.1 human reservations. Added CI check (`tests/agents_policy_test.py`) in
  `.github/workflows/ci.yml` asserting the verbatim loop is present. Acceptance
  smoke `tests/agents_policy_test.py` passes.
- m0-006: split `main_window.cpp` from 2,195 lines down to 377 lines (<= 400 lines)
  across 10 modular dock classes (`functions_dock`, `decompiler_dock`, `facts_dock`,
  `memory_dock`, `graph_dock`, `analyst_dock`, `types_dock`, `xrefs_dock`,
  `jobs_dock`, `vtables_dock`) and extracted `gate_runner`. App behavior
  unchanged per m0-001; acceptance smoke `tests/main_window_split_test.py` passes.

- m0-010: added `scripts/gen_support_matrix.py` to regenerate the README support
  matrix from committed gate files, preventing manual overclaiming; added CI
  staleness check and acceptance test `tests/support_matrix_test.py`.

## Current milestone
M5 — Console platforms, measurable tier first
(m5-001 GBA, m5-002 NDS, m5-003 PS-EXE, m5-004 N64 complete)
(M4 opened with m4-001; further M4 passes resume after the first console
platforms land, per the sequencing decision recorded below)
(M3 complete: DWARF scoring m3-001, frozen baseline m3-002, regression gate
m3-003, all three wired into continuous integration)

## M1 progress
- m1-003-d: benchmarked hand decoder vs console flow on libc and the x86-64 corpus.
  All corpus rows scored against unstripped symbol references (zero null metrics).
  On libc, hand achieves exact set equality against console flow (3,953/3,953),
  and against the Ghidra oracle libc recall is 0.991472. Median speedup on libc: 1.1964×.
  hand decoder is 1.2× faster than console (<2.0× threshold) even though set-metrics are equal against the oracle;
  decision: keep_disasm_rs: false; deactivated default hand-decoder production path (default = []).

- m1-005: implemented PE base relocations (.reloc directory 5, IMAGE_REL_BASED_DIR64/HIGHLOW),
  entry point calculation fix (opt + 16), strict PE machine/magic pair validation without mock fallbacks
  (PE32+ AMD64 0x8664/0x20b and PE32 i386 0x014c/0x10b; typed errors on truncated fields, parsing
  NumberOfRvaAndSizes before accessing directory 5 without requiring six directories), and durable
  store writes of relocated pointers as data xrefs with provenance (`native-import:pe-reloc`, independent
  of whether targets land in executable code). Extracted candidate filtering to pure helper
  `CandidateFilterContext` / `filter_candidate` with unit tests verifying rejection of internal and out-of-code
  candidates under `--no-default-features`. Containment uses actual flow-proven extents (`proven_bodies`
  tracked from instruction spans during BFS walk; size-1 stripped entries cannot disable containment;
  positive regression test confirms relocation-only code functions in gaps are promoted, descendant origins are canonicalized/reparented to merge full spans, and internal candidates reached via fallthrough/branches are reconciled/dropped while call targets remain separate). Console-only path explores
  trusted seeds first and rejects relocation candidates already visited inside those bodies. Guarded x86-64
  hand decoder against x86-32, propagating detected language into `ConsoleSession` and BFD selection (`pei-i386`),
  routing PE32 through console-backed flow confirmation. Restored deterministic console child process cleanup
  via `impl Drop for ConsoleSession`. Restricted `close_call_targets` strictly to call xrefs (never branches or DATA).
  Added real 32-bit x86 PE32 test fixture (`tests/fixtures-src/tiny_pe32.exe`) testing language (`x86:LE:32:default`),
  ImageBase (`0x400000`), entry point (`0x401400`), HIGHLOW relocations, data xrefs, and discovery using CARGO_MANIFEST_DIR.
  Added load_native regression proving a PE32 data-to-data relocation remains an xref and never becomes a function.
  On `tiny_pe` unstripped twin (123 oracle symbols): 33 discovered, overlap 33, p=1.0000, r=0.2683;
  on `dispatch` unstripped twin (125 oracle symbols): 35 discovered, overlap 35, p=1.0000, r=0.2800.
  Acceptance tests `tests/m1-005_pe_relocs.sh` and `tests/m1-003_benchmark.sh` pass (PASS).
- m1-003-f: hand decoder candidate pre-pass confirmed by batched flow; achieves
  fn.precision=1.0000 and exact set equality (3,953/3,953) on libc describing hand-versus-console
  parity (neither Bad nor Unimpl, with pad and body containment checks; no opcode blacklists).

- m1-003-e: implemented batched flow in the console (`flow <addr1> <addr2> ...`);
  console-path libc import runs in 3.56s (acceptance threshold < 5.0s, PASS).
- m1-004: implemented ELF PIE relative relocation discovery (SHT_RELA / R_*_RELATIVE
  and SHT_RELR packed relocations across architectures), image base selection
  via `elf_image_base` (minimum PT_LOAD vaddr or 0x100000/0x10000 default for ET_DYN),
  and durable store writes of relocated pointers as data xrefs with provenance (`native-import:elf-reloc`).
  Acceptance test `tests/m1-004_pie.sh` passes with fn.recall=1.0000 on both
  plain_pie (8/8 oracle functions) and relr_pie (12/12 oracle functions).
- m1-001: implemented native SLEIGH console request `flow(addr)` extracting
  {length, fallthrough, targets, kind} from p-code (BRANCH, CBRANCH, BRANCHIND,
  CALL, CALLIND, RETURN, FALLTHROUGH) across loaded architectures. Unit test
  `test_pcode_flow_x86_and_ppc` passes on x86-64 (`tiny_bin` return/fallthrough)
  and PowerPC (`base.elf` 0x80680000 fallthrough length=4 and 0x8068001c CBRANCH
  targets=[0x80680030]).
- m1-003-c: wired console flow path for x86-64 when `x86_decoder` is off.
  `sweep_calls_x86` and `flow_discover_x86` now use a persistent SLEIGH
  console session; the acceptance `tests/m1-003_x86_flow.sh` asserts
  fn.precision=1.0000 and fn.recall>=0.9965 against the hand-decoder
  baseline on /usr/lib64/libc.so.6. Result: precision=1.000000,
  recall=1.000000 (exact set equality 3,953/3,953), PASS.

## Sub-tasks (m1-003)
- m1-003-a: split `x86_decoder` feature and add failing acceptance test.
- m1-003-b: implement persistent SLEIGH console session for x86-64.
- m1-003-c: wire `sweep_calls` and `flow_discover` to use console flow when
  `x86_decoder` is off.
- m1-003-d: benchmark the two paths on libc and the x86-64 corpus and decide
  keep/delete `disasm.rs`.

## Known gaps
- Corpus-binary discovery vs unstripped symbols is far below the M1 threshold
  (cpp_o2 p=0.43 r=0.56, plain_o0 0.80/0.80).
- m1-008b (before m1-010): dump missed/extra entries for cpp_o2 and plain_o0;
  classify each as (a) reference noise Ghidra also omits, (b) reachable only
  via data pointers (vtables, init/fini arrays, function-pointer tables), or
  (c) unreferenced. Add seeds for (b): scan .init_array/.fini_array, and pointer-sized
  values in .data/.rodata/.data.rel.ro that land in executable sections and confirm
  via batched flow. Acceptance: cpp_o2 and plain_o0 recall >= 0.98 against the
  m1-007 Ghidra oracle.
- Commit rule note: commits `e0db463` (1,386 insertions) and `0dca6cd` (1,148 changed lines:
  919 additions + 229 deletions across generator, lockfile, gate, and report) exceeded the 800
  changed line limit; per II.0, recorded as acknowledged violations without history rewriting.

- m1-006: generated multi-architecture corpus across 4 target architectures (x86-64,
  x86-32, aarch64, powerpc) × 5 variants (plain_o0, plain_o2, plain_pie, cpp_o2, many_o2)
  = 20 binaries + 20 unstripped twins containing .symtab function symbols. Committed sources
  in tests/corpus-src/ (plain.c, src.cpp, many.c) and lockfile tests/corpus.lock.json (with
  zero host-specific absolute paths). Added scripts/gen_corpus.py with --architectures and
  --msvc-only support. Primaries derived by stripping copies of twins (via llvm-strip --strip-all
  or PE debug directory zeroing), ensuring bit-for-bit loadable code identity while stripped
  primaries lack .symtab and twins contain function symbols (plain_o0 stripped).
  Added machine 0x3 (EM_386) to elf_language in romwright-core, enabling native ELF32 x86 import.
  All 20 binaries import cleanly natively: x86-64 (8..408 functions), i386 (6..13 functions),
  aarch64 (3..5 functions), and powerpc (9..408 functions). Gate outputs and import
  databases are temporary; source digests, artifact hashes, recipes, unique matrix entries,
  independently counted symbols, twin identity and native imports are checked.
  Committed report: benchmarks/reports/m1-006.json (local MSVC skips with reasons).
  Added dedicated Windows CI job (corpus-windows with MSVC activation) and Linux CI job (corpus-linux).

## m1-006 corrective sub-tasks
- m1-006-a: reject missing/duplicate entries; enforce recipes, hashes and isolated
  gate outputs; preserve the recipe schema in explicit lock updates.
  Acceptance: `tests/m1-006_integrity_test.py`.
  Verified: 3 integrity tests (8 manifest mutations), 97 workspace tests,
  legacy corpus 5/5 and m1-006 Linux corpus 20/20; only 5 local MSVC skips allowed.
- m1-006-b: replace C++ exception stubs with real cross-target runtimes; execute
  the exception/TLS fixture on supported hosts. Acceptance: corpus gate runtime checks.
  Verified: exception/TLS inputs execute on all 4 ELF targets (native x86-64,
  QEMU i386/AArch64/PPC32-BE), 8/8 expected outcomes. Corpus 20/20 imports;
  3 integrity tests, 97 workspace tests and legacy corpus 5/5 pass.
- m1-006-c: validate PDB streams, symbols and exact CodeView association; use
  the linker PDB. Acceptance: `tests/m1-006_pdb_test.py`.
  Verified locally: real LLVM PE/PDB pair exposes 2 function symbols; 7 PDB
  corruptions rejected (header-only, truncation, block reference, GUID, age,
  missing symbol stream, malformed record). MSVC uses a separate compiler PDB
  and explicit linker `/PDB`. CI run 33914542193 passed MSVC corpus and all
  Rust/Qt jobs; Linux exposed host loader-cache leakage under qemu-i386.
  Cross execution now sets the pinned target library path explicitly.
  Run 33914879326 then passed i386/AArch64 runtime checks but exposed a PPC
  C++ PIE fault, reproduced with Ubuntu 24.04 LLVM 18/QEMU 8.2. Explicit
  non-PIE C++ output passed both inputs; the `cpp_o2` ELF recipe now fixes
  that relocation model on every target. `plain_pie` is unchanged.
- Closed m1-006 corrections at `2ea65bac64eb5921fd5c2939e2d9ecabb2941db1`:
  [CI run 33915494027](https://github.com/Raikaru/romwright/actions/runs/33915494027)
  passed 9/9 jobs, including Linux corpus 20 entries, MSVC corpus 5 entries,
  Rust on 3 operating systems, and Qt packages on 3 operating systems.
  Normal local gate: exit 0; `git diff --exit-code`: 0; porcelain output empty.
  All corrective commits stayed below 800 changed lines. No m1-007 implementation
  or acceptance test was started in this session.

## m1-007 sub-tasks
- m1-007-a: failing acceptance, bridge image-base metadata and SHA-keyed oracle
  generator. Acceptance: `tests/m1-007_oracle_test.py`; all 20 ELF entries,
  cache reuse without Java, invalid-cache and missing-input rejection.
- m1-007-b: publish the five x86-64 oracle references.
- m1-007-c: publish the five i386 oracle references.
- m1-007-d: publish the five AArch64 oracle references.
- m1-007-e: publish the five PPC32-BE oracle references.
- m1-007-f: commit the generated report and verification evidence.
  Generated reference arrays are split by architecture to keep each commit
  below 800 changed lines. The existing libc reference is unchanged.
- Completed: 20/20 ELF references committed, 0 failed, 0 skipped.
  `benchmarks/reports/m1-007.json` was generated from implementation
  `dfed639191be266c07079231c03ff8ef8ee69c2d` and committed in `718128a`.
  Non-external function totals: x86-64 488, i386 505, AArch64 526, PPC32-BE 489.
  Each architecture has 5 SHA-keyed references; total 2,008 entries.
  Provenance includes Ghidra 12.1.3 revision, bridge source SHA-256, automatic
  language selection and image base. Addresses remain in Ghidra coordinates.
  Ghidra selected `PowerPC:BE:32:e500` for all 5 PPC inputs; no native language
  selection or frozen discovery metric was changed.
- Verification: `tests/m1-007_oracle_test.py` passes 4 tests, including 20 fresh
  imports, 20 cache hits without Java, 4 invalid-cache cases and missing-primary
  rejection. Published-cache `--check`: 20 hits, 0 generated, 0 skips.
  `cargo test --workspace`: 97 passed; `tests/corpus.sh`: 5/5 passed;
  README support matrix check passed. Artifact commits contain 573, 590, 611
  and 574 added lines respectively. Added a Linux CI oracle job using the
  SHA-256-verified official Ghidra release.

## Extracted-source tracking cleanup
- Human-requested maintenance; no milestone implementation changes.
- cache-a: ignore `/.ghidra-java/` and record this tracking-only cleanup.
- cache-b: remove the 5,382 extracted files from the Git index, retaining local
  bytes. This is a bulk generated-source deletion, not a source modification.
- cache-c: verify local hashes are unchanged and the pushed branch tree has
  no `.ghidra-java` entry. Historical commits remain unchanged.
- Local verification: all 5,382 files retained with identical SHA-256 hashes;
  0 files remain tracked under `.ghidra-java/`. The root ignore rule prevents
  re-adding the extraction during ordinary staging.

## m1-008 verified
- Test-first commit `5af21d9`: 5 language cases passed and the ARM BE8 case
  failed (selected `ARM:BE:32:v7` instead of `ARM:LEBE:32:v7LEInstruction`).
- ELF language selection now reads `e_flags`; ARM `EF_ARM_BE8` selects the
  pinned mixed-endian language. ELF32 i386, ARM LE/BE32 and PE32 selection
  remain unchanged. No corpus matrix or discovery metric was changed.
- `tests/m1-008_languages.py`: 6/6 passed, 0 failed, 0 skipped. It checks real
  compiler-produced ELF32 inputs, the existing PE32 fixture, an ELF64 control,
  installed `.ldefs`/SLA metadata and the native architecture catalog.
  Generated report: `benchmarks/reports/m1-008.json`.
- `cargo test --workspace`: 97 passed; legacy corpus: 5/5; m1-006 Linux corpus:
  20/20 (5 MSVC skips permitted on Linux). README matrix check passed.
  The existing Ghidra CI job also runs the language gate.
- CI run `33919780791` passed all ARM/PE language cases but exposed 2 x86
  probe link failures with Ubuntu LLVM 18: generic ELF targets routed through
  GCC's default PIE link. Both failures were reproduced; explicit Linux GNU
  targets with `-fno-pie -no-pie` passed both compiler checks. The corrected
  full local gate again passed 6/6; compiler stderr is retained on failures.

## m1-009 sub-tasks and oracle decision
- Human approved the real `sys/main.dol` with `files/boot.elf` as its oracle.
  All 644 function bodies and all 10 file-backed allocated sections match
  byte-for-byte at their original addresses. `base.elf` is a different build:
  only 44/644 function entry addresses overlap. Exact-address recall >=0.95
  is unchanged; no address normalization or oracle seeds enter discovery.
- m1-009-a: commit the failing real-DOL acceptance and this oracle decision.
- m1-009-b: parse DOL section mappings, preserve initialized data inside BSS,
  reject malformed ranges, and integrate the shared native mapping loader.
- m1-009-c: use the existing SLEIGH XML image loader and generic flow worklist
  for sparse DOL discovery; do not modify the pinned upstream tree.
- m1-009-d: commit the generated recall report, regression evidence and docs.

## m1-009 verified
- Acceptance test first: `56e8c31`; implementation: `f52d1f7`.
  Generated real-input report committed in `a874753`:
  `benchmarks/reports/m1-009.json`.
- Matching GQFE78 `main.dol` / `boot.elf`: 644 oracle entries, 699 native
  entries, 633 matches. Recall 0.982919 >= 0.95; precision 0.905579.
  There are 11 misses and 66 native-only entries; both lists are recorded.
  This passes the specified recall gate, not a broader precision/parity gate.
- All 10 initialized section mappings and BSS zero fill checked through
  the consumer memory API; malformed file ranges, address wrap and overlap
  rejected. Unit tests also cover initialized data inside BSS and invalid entry.
- Sparse XML loading uses the pinned console without upstream changes.
  SLEIGH direct calls and return-boundary candidates feed the generic worklist.
  Decoded instruction ranges, not distant-branch bounding spans, prove
  candidate containment. The focused gap regression failed before the fix.
- `cargo test --workspace`: 100 passed; no-default-feature core: 51 passed;
  `tests/corpus.sh`: 5/5; README support-matrix check passed.
  Actual DOL disassembly at `80680040`: `bl 80680154`, `bl 80680230`,
  `li r0,-1`. Rust formatting could not run: `rustfmt` is not installed.
- The private DOL/ELF pair is not redistributed; the real-input gate ran
  locally, not in CI. Missing inputs remain skipped/non-passing.
  `.rel` support is not implemented. No corpus or metric definition changed.

## m1-008b prerequisite investigation
- CI run `33923983804` for `6e1bae6` passed all 10 jobs.
- The recorded m1-003 gap concerns the x86-64 `plain_o0` and `cpp_o2`
  corpus variants. Acceptance `tests/m1-008b_pointer_seeds.py` scores the
  corresponding locked m1-006 inputs against unchanged m1-007 references.
  No cross-architecture gate claim or address normalization is introduced.
- Failing acceptance: plain_o0 10/15 (0.666667), cpp_o2 14/29 (0.482759);
  precision 1.0 for both, 0 native-only entries. Every missing entry is
  retained in the generated report.
- Fresh bridge imports identify 3 plain_o0 and 9 cpp_o2 oracle functions at
  `00204000` and above as external symbols outside the binary's allocated
  sections (including `__libc_start_main`, `__gmon_start__`, and `printf`).
  Code-entry recovery alone is capped at 12/15 and 20/29, below 0.98.
  The other misses include unreferenced code and PLT resolver paths, not just
  data-pointer seeds. No implementation or oracle changes have been made.

## Approved scoring contract (m1-008b)
- Human approved excluding positively identified Ghidra-created synthetic
  external placeholders from code-function discovery scoring. This is not
  blanket filtering by executable permissions or address-range membership.
- Keep executable PLT stubs, thunks and unreferenced code. Preserve raw
  `oracle/*.json` unchanged. Publish a separately versioned scoring view
  with the raw-reference hash, evidence and reason for every exclusion.
- Apply the rule consistently to all 20 ELF corpus entries. The m1-008b
  discovery acceptance remains the two x86-64 variants and recall >=0.98.
- m1-008b-a: failing scoring-view acceptance and policy edge cases.
- m1-008b-b: oracle-only evidence exporter and scoring-view generator.
- m1-008b-c: publish each corpus input's generated view as its own bounded
  artifact sub-task/commit: x86_64, i386, aarch64, powerpc, each with
  plain_o0, plain_o2, plain_pie, cpp_o2 and many_o2. Never rewrite raw refs.
- m1-008b-d: update discovery acceptance to the approved scoring view,
  then fix legitimate remaining misses without oracle-derived seeds.
- m1-008b-e: required gates, generated reports and final verification.

## m1-008b verified
- Test-first commits: `9cbe142` (scoring policy), `35e07be` (pointer flow),
  `e50bafb` (approved-score discovery). Implementation: `16555ca`, `9189859`.
- Generated reports committed in `1c0cd74`:
  `benchmarks/reports/m1-008b-scoring.json` and
  `benchmarks/reports/m1-008b-v1.json`, both naming implementation `9189859`.
  Historical failure/classification reports and raw `oracle/*.json` are unchanged.
- All 20 ELF scoring views: 2,008 raw functions, 1,903 scored, 105 positively
  identified synthetic external placeholders excluded. Every exclusion records
  loader/block/thunk evidence; each view includes raw-reference/exporter hashes.
  PLT stubs, thunks and unreferenced code remain scored. No permission-only or
  address-range exclusion is used.
- x86-64 plain_o0: 12/12 matches; cpp_o2: 20/20 matches. Recall and precision
  are 1.0 for both; 0 misses, 0 extras. Recall threshold remains 0.98.
  This is the two-input prerequisite gate, not cross-architecture discovery parity.
- Native discovery now retains dynamic-symbol index zero, reads ELF unwind
  function indexes and the PLT resolver entry, and flow-confirms initializer/data
  pointers. Candidate traversal follows indirect-call fallthrough. The broad
  linear-scan experiment was discarded; no oracle-derived seeds are used.
- Verification: workspace 102 tests; core no-default 53; core x86_decoder 54.
  Scoring acceptance 4 tests passed with 20 fresh temporary raw oracles and
  20 fresh evidence exports; committed raw bytes stayed unchanged. CI runs this
  isolated acceptance without depending on this workstation's compiler hashes.
  Legacy corpus 5/5; DOL remains 633/644 matches, 699 native entries; support
  matrix check passed. Isolated release libc import: 4,046 functions in 3.879 s
  (<5 s). A run overlapping Ghidra verification took 5.454 s; no performance
  claim is made for concurrent verification workloads. Rustfmt is unavailable.

## m1-010 sub-tasks
- Acceptance: `benchmarks/discovery_gate.py` writes
  `benchmarks/reports/discovery-gate.json`; exact function-entry precision and
  recall must both reach 0.98 on each of the 20 locked ELF inputs covered by
  m1-007 and scoring-v1. Missing inputs/oracles are skipped and non-passing.
  Raw references and the approved scoring policy remain unchanged.
- Existing libc performance and real-DOL recall checks remain regressions with
  their existing thresholds; this task does not redefine their metrics.
- m1-010-a: commit and run the failing all-input acceptance, retaining every
  missed/extra entry and checking that legacy ISA-specific discovery has left
  native.rs. The generic discovery module must contain no ISA-specific logic.
- m1-010-b: move the shared flow worklist into the generic discovery module.
- m1-010-c: remove legacy architecture-specific production discovery routes;
  any retained accelerator must be separate and equivalence-tested.
- m1-010-d: fix remaining M1 loader/seed/flow failures exposed by the gate.
  If an M2 analyzer is necessary, record it under Blocked on and stop.
- m1-010-e: required regressions, generated gate evidence and CI integration.
  Keep each commit below 800 changed lines; no milestone pass until all rows
  and the architecture check pass.

## m1-010 progress and sequencing blocker
- Failing acceptance committed first in `bc0e10f`; the complete initial
  20-input report was committed in `ea0fed1`. Shared flow worklist extraction
  committed in `9f9bcf9`: no algorithm or caller behavior changed.
- Gate results before/after extraction: 7 pass, 13 fail, 0 skipped.
  All four PIE inputs have zero exact-address overlap. Smaller i386/AArch64
  inputs miss functions; PPC also has native-only entries. Full address lists
  remain in `benchmarks/reports/discovery-gate.json`. The legacy-route source
  check still fails. M1 and m1-010 are not complete.
- Concrete later-milestone dependency: stripped `i386_plain_o0`, SHA-256
  `cea7cb1a23dbe84ab789761e612422415ee857945668ed2d28f06b5b1e3237ba`,
  retains oracle entry `004014d0` (`register_tm_clones` in the source twin).
  `llvm-objdump` shows its only direct transfer is `00401540: jmp 004014d0`
  from `frame_dummy`. The stripped file contains zero absolute pointer
  occurrences of that address; `llvm-dwarfdump --eh-frame` lists FDE starts
  `00401440`, `00401470`, `00401550`, `00401570`, not `004014d0`.
- Recovering that distinct entry requires thunk/tail-call recognition
  (roadmap m2-009), not blanket branch-target promotion. Per the hard rule on
  later-milestone dependencies, implementation stops for a sequencing decision.
  No M2 analyzer, reference exclusion, corpus change or threshold change was made.
- Extraction verification: workspace 102 tests; legacy corpus 5/5; real DOL
  remains 633/644 matches with 699 native functions. Sub-tasks c–e are not
  complete; the failing gate is evidence, not a passing milestone claim.

## Approved m1-010 thunk prerequisite
- Human approved moving the minimal m2-009 thunk/tail-call prerequisite into
  M1. Scope: an established function whose first instruction is a pure
  direct jump; validate and retain its destination as a distinct function.
  Conditional jumps, interior branches, side-effecting transfers, self loops
  and invalid destinations do not establish functions. No blanket branch
  promotion, full thunk analyzer, signature matching or metric change.
- m1-010-t: commit failing thunk acceptance, add SLEIGH purity evidence and
  generic destination discovery, then verify the real i386 blocker and gates.
  Acceptance: `native::discovery::tests` and the existing discovery gate.

## m1-010-t verified
- Acceptance committed first in `ab61328`; implementation in `8be0ec7`.
  The console now supplies `pure_jump` evidence only for a single direct
  SLEIGH branch operation. Missing evidence defaults to false.
- Six regressions cover thunk chains, conditional/interior/effectful branches,
  invalid or mismatched destination flow, weak seeds, later-discovered body
  containment, and entry jumps that return into their own body.
- Real i386 blocker resolved: native import retains `00401540` with size 2
  and `004014d0` with size 57; the connecting xref is
  `UNCONDITIONAL_JUMP`, provenance `native-import:thunk`, not a call.
- i386 plain_o0/plain_o2: 11/15 matches (previously 10/15); cpp_o2: 19/23
  (previously 18/23); many_o2: 409/413 (previously 408/413). Precision is 1.0
  for all four. The full discovery gate remains 7 pass, 13 fail, 0 skipped;
  remaining PIE/loader/architecture-cutover failures are not marked resolved.
- Verification: workspace 108 tests; core no-default 59; legacy corpus 5/5;
  DOL unchanged at 633/644 matches, 699 native functions. An intermediate
  DOL false-positive regression exposed jump-over-body sequences and was fixed
  before committing. Isolated release libc import: 4,046 functions, 4.700 s
  (<5 s). Rebuilt console from the out-of-tree patch; pinned source unchanged.
- This completes the approved minimal prerequisite, not all of m2-009 or M1.
  Raw references, scoring exclusions and thresholds remain unchanged.

## m1-010-c execution slices
- c1: remove native.rs ISA dispatch/sweeps and decoder-backed discovery;
  ELF/PE use the shared SLEIGH worklist, DOL retains its mapped-image seed scan.
  Candidate admission uses decoded flow, not architecture-specific pad bytes.
- c2: delete the now-unused hand-decoder discovery implementation and its
  route-selection feature flags; retain instruction decoding used by listing
  and graph consumers. No discovery accelerator is retained.
- c3: retire the obsolete hand-versus-console benchmark producer and its
  acceptance wrapper, plus the unreferenced console text-discovery API and
  its seed/next-entry-size helpers. Publish the existing gate and regressions.
  Historical benchmark reports remain unchanged. Each slice is a separate
  commit below 800 changed lines; c1/c2/c3 precede m1-010-d.
- Acceptance is the existing discovery gate architecture check, extended to
  cover retired decoder discovery and feature switches, plus a failing
  candidate-flow regression. Precision/recall thresholds remain unchanged.

## m1-010-c verified cutover
- Test-first commits: `66331bd` and `6b6c236`. Implementation slices:
  `18e83bf` (generic routing), `7ff1b59` (decoder retirement), `6d32467`
  (orphaned console discovery and obsolete comparison tooling).
- Architecture check: 0 legacy native.rs discovery definitions, 0 retained
  decoder/console discovery helpers, 0 discovery feature switches, 0 ISA
  matches in the shared worklist. No accelerator retained. Listing/graph
  instruction decoding remains separate and unchanged in behavior.
- Full 20-input report: 4 pass, 16 fail, 0 skipped (previously 7/13/0).
  x86-64 plain_o0/plain_o2 are 11/12; cpp_o2 is 19/20, all precision 1.0.
  The affected m1-008b acceptance was run and fails both rows. Its thresholds,
  raw references and scoring policy were deliberately not weakened.
- Generic non-x86 flow improves AArch64 plain_o0/plain_o2 from 11/17 to
  15/17 matches and cpp_o2 from 13/24 to 20/24, with precision 1.0.
  PowerPC plain_o0/plain_o2 are 8/12 with precision 1.0; missing PLT/init
  seeds and remaining flow failures still belong to m1-010-d.
- Required checks: workspace 105 tests, core no-default 57, legacy corpus
  5/5. DOL retains 633/644 matches with 698 native functions (previously
  699), 65 extras (previously 66), 10 mappings and BSS checked. A candidate
  filter regression rejecting the one-instruction __OSDBJump call was
  reproduced, covered and fixed before the cutover commit.
- Isolated release libc import: 4,049 functions in 4.627 s (<5 s).
  Generated discovery and DOL reports name implementation `6d32467`;
  the support-matrix staleness check passes. M1 is not passed.
- c1–c3 are complete. Retired hand-versus-console comparison scripts cannot
  compare distinct routes after this cutover; historical results remain in git.

## Approved landing-prefix prerequisite
- Human approved extending minimal thunk recognition to one SLEIGH-verified
  landing instruction before the pure direct jump. Ghidra
  CreateThunkFunctionCmd.getThunkedAddr skips one empty-p-code instruction
  (extracted source lines 567–572, explicitly mentioning ENDBR64).
- m1-010-d1: emit explicit empty-p-code evidence; accept one contiguous,
  valid no-op at an established entry, followed immediately by the already
  validated pure branch. Preserve original entry, actual jump xref and both
  instruction extents. Missing evidence, extra prefixes, effects, weak seeds,
  invalid destinations and source-body jump-back chains remain rejected.
- Acceptance: native::discovery::tests plus existing m1-008b and full discovery
  gates. Complete d1 only; remaining loader/seed failures remain m1-010-d.

## m1-010-d1 verified
- Failing acceptance committed in `1883c39`; implementation in `27721f2`.
  Three landing regressions cover entry/extent/xref preservation, prefix and
  target rejection, and jump-chain return into the source body. All 11 generic
  discovery tests pass.
- The rebuilt console reports `00201670` as length 4, `no_op=1`, falling to
  `00201674`; that instruction is length 2, `pure_jump=1`, targeting `00201600`.
  The destination's first MOV is `no_op=0`. Native import persists separate
  function extents of 6 and 49 bytes, and a jump xref from `00201674` with
  `native-import:thunk` provenance, not a call or an entry at the jump itself.
- m1-008b restored: x86-64 plain_o0 12/12 and cpp_o2 20/20, precision 1.0.
  Full discovery: 7 pass, 13 fail, 0 skipped; architecture check passes.
  All four non-PIE x86-64 rows have precision/recall 1.0. Remaining PIE and
  non-x86 loader/seed failures are not marked resolved.
- Workspace 108 tests; core no-default 60; legacy corpus 5/5; DOL unchanged
  at 633/644 matches, 698 native functions and 65 extras, with 10 mappings and
  BSS checked. Isolated release libc import: 4,049 functions in 4.059 s (<5 s).
  Generated discovery, m1-008b and DOL reports name `27721f2`.
- No ISA-specific discovery, mnemonic matching, reference exclusions, metric
  changes or pinned-source edits. The approved prerequisite is complete;
  broader m2-009 remains outside scope and M1 remains incomplete.

## m1-010-d execution slices
- d2: share existing ELF64 `.init`, `.fini` and `.plt` section-start seeds
  with ELF32. Acceptance: `native::tests::elf32_startup_section_seeds`,
  covering little/big-endian inputs and non-executable section rejection;
  existing full discovery gate measures the resulting function sets.
- Source-twin inspection identifies i386 misses as `__x86.get_pc_thunk.bx`,
  `_init`, `_fini` and the PLT header. PowerPC misses include `_init`, `_fini`
  and `plt_call32` stubs. No symbol names are used as scoring exceptions.
- d3: fix PIE load bias consistently across imported mappings, address facts,
  memory readers and native runtime consumers. Ghidra preserves nonzero
  prelinked bases; zero-based ET_DYN defaults are 0x100000 for ELF64 and
  0x10000 for ELF32. Do not normalize addresses inside the scorer.
- d4: investigate remaining flow/seed misses without extending the approved
  thunk prerequisite. AArch64 plain_o0 misses `0021078c` (NOP immediately
  before the existing `00210790` function) and `002108a0` (`__gmon_start__`
  PLT stub). PowerPC cpp_o2 extra `10010980` is the `.glink` section start.
- Execute d2 first; d3/d4 and sub-task e remain open. References, corpus,
  metric definitions and thresholds remain unchanged.

## m1-010-d2 verified
- Failing acceptance committed in `5dcc13b`; implementation in `f55b15d`.
  ELF32 little- and big-endian startup sections produced 0 seeds before
  the fix; the regression now passes and rejects non-executable namesakes.
- ELF32 and ELF64 now use one section-start seed collector. No changes to
  the generic flow worklist, thunk recognition or scoring policy.
- i386 non-PIE matches: plain_o0 15/15, plain_o2 15/15, cpp_o2 23/23,
  many_o2 413/413; precision and recall 1.0 for all four.
- PowerPC matches: plain_o0/plain_o2 11/12 (previously 8/12), cpp_o2 18/19
  with 19 native entries, many_o2 409/410. The remaining non-PIE miss is
  the `__libc_start_main` PLT stub; cpp_o2 still has extra `10010980`.
- Full gate: 10 pass, 10 fail, 0 skipped; architecture check passes.
  `benchmarks/reports/discovery-gate.json` was generated from `f55b15d`.
  PIE address alignment and remaining non-x86 failures are not resolved.
- Workspace 109 tests; core no-default 61; legacy corpus 5/5. README
  support-matrix staleness check passes. M1 is not passed.
- d2 is complete. d3/d4 and e remain open.

## m1-010-d3 acceptance
- `crates/romwright-core/tests/elf_image.rs` checks ELF64 LE and ELF32 LE/BE
  REL, RELA and RELR pointers, zero/signed addends, prelinked bases, partial
  memory reads and user-patch precedence against console mapping bytes.
- `tests/m1-004_pie.sh` compares zero-based PIE symbols at Ghidra's loaded
  base. Unsupported RELR generation exits 77 instead of substituting RELA.
- Before implementation: the image regression fails at the first rebased
  entry; both real PIE fixtures have 0 oracle matches at loaded addresses.

## m1-010-d3 verified
- Acceptance commits: `4024f16` (loaded ELF addresses/pointers) and `21250ec`
  (worker short reads). Implementation: `ed6bbf1`.
- One loader path applies PIE bias and REL/RELA/RELR words for ELF64 LE and
  ELF32 LE/BE. Mmap readers and console images retain identical relocated
  bytes; both worker entry points use ProgramImage instead of raw-file maps.
  Nonzero prelinked bases, BSS zero-fill and user-patch precedence are checked.
- Real PIE smoke: pointer at `00103010` reads `0010300c`; its pointee reads 41.
  Console listing at `00100469` loads that pointer; worker output is
  `return *piRam0000000000103010 + 1`. End-of-section `_fini` at `00100488`
  reproduced DataUnavailError and now decompiles after the bounded-read fix.
- PIE acceptance: plain 8/8 and RELR 12/12 symbol matches at loaded addresses.
  Full gate: 12 pass, 8 fail, 0 skipped. All ten x86-64/i386 rows have
  precision/recall 1.0. PowerPC PIE improves to 12/13 matches, precision 1.0.
- Workspace 111 tests; core no-default 62; legacy corpus 5/5. m1-008b remains
  12/12 and 20/20. DOL remains 633/644 matches, 698 native functions, 65 extras,
  with 10 mappings and BSS checked.
- Isolated release libc import: 3,959 functions in 3.949 s (<5 s); this is
  a timing/function-count result, not an oracle-recall measurement.
- Discovery, m1-008b and DOL reports were generated from `ed6bbf1`. No raw
  oracle, scoring policy, threshold or pinned-source changes. M1 is not passed.
- d3 is complete; d4 and e remain open.

## m1-010-d4 investigation
- PowerPC plain_o0 `_start` at `100103f0` performs register/stack setup,
  then branches from `10010420` to the missing `10010568` libc PLT stub.
  This is an interior tail transfer, not the approved entry-jump case.
  `.rela.plt` identifies GOT slot `1003074c` for `__libc_start_main`, not
  stub entry `10010568`; its undefined dynamic symbol has value 0.
  The two FDEs cover `100104e4..10010510` and `10010510..10010568`.
- Fresh Ghidra evidence export confirms AArch64 `0021078c` is a separate
  `FUN_0021078c` with no thunk target, followed by `_FINI_0` at `00210790`.
  The missing `002108a0` entry is the `__gmon_start__` PLT thunk. Padding
  entries must not be mislabeled as already-approved direct-jump thunks.
- A separate M1 loader defect is identified: PowerPC cpp_o2 dynamic symbol
  `__gxx_personality_v0` has nonzero value `10010980` but SHN_UNDEF. ELF32
  currently admits it as a defined function. A symbol-definition regression
  and repair remain pending; no scoring exclusion is proposed.
- No d4 analyzer implementation, oracle change or metric change was made.
  Implementation stops at the required later-milestone sequencing decision.

## m1-010-d4a ELF32 symbol admission
- Regression commit `d0b3e01` fails before implementation: a nonzero
  `SHN_UNDEF` function symbol incorrectly becomes a native function.
- Defined-symbol admission now requires a nonzero section index. The
  regression covers little/big endian, retained external identity, and
  the same symbol becoming a function when assigned a defined section.
- Verification: workspace 112 tests; corpus 5/5. Full discovery now
  11 pass / 9 fail / 0 skipped. PowerPC C++ precision rises to 1.0;
  i386 C++ recall is 22/23 because its unreferenced PLT entry at
  `004019f0` needs real discovery rather than undefined-symbol admission.
- Function-start/PLT prerequisite research proceeds against pinned Ghidra
  processor patterns and analyzers. No reference or metric is changed.

## m1-010-d4b loaded external relocation facts
- Regression commit `172bf78` fails before implementation when an imported
  function's relocated GOT slot has no instruction stub in the image.
- REL/RELA linkage records now retain loaded slot addresses and names through
  their linked dynamic symbol/string tables, including ELF32 big endian.
  Undefined symbols do not become function definitions through this path.
- Workspace: 113 tests. Full discovery remains 11 pass / 9 fail / 0 skipped.
  No new entry-discovery capability or gate pass is claimed for loader facts.

## m1-010-d4c bounded linkage evidence
- Regression commit `1e3d496` fails on the missing native `linkage` command.
- The out-of-tree console now propagates constants and loaded-slot identity
  through SLEIGH p-code. The typed client rejects missing/mismatched responses.
- Real-console acceptance resolves slot `0x3008` on x86-64, i386, AArch64
  and PowerPC; rejects unknown registers, unused register writes, stores
  and a 9-instruction chain. Requests after rejection remain usable.
- Locked PowerPC plain_o0 smoke: entry `10010568` resolves slot `1003074c`
  over 16 bytes; the native console exits 0.
- Limits: 8 instructions, 128 operations/instruction, 64 live values.
  Both console and worker builds pass; workspace 114 tests; corpus 5/5.
  Full discovery remains 11 pass / 9 fail / 0 skipped pending integration.

## m1-010-d4d shared linkage-target discovery
- Regressions `f989a8a` and `0a70260` cover sweep and seeded imports.
  Ordinary ELF imports use the seeded path; DOL uses the section sweep.
- Both paths now use the same flow/linkage provider and promotion rule.
  Unconditional targets require bounded slot evidence plus an imported slot;
  conditional targets and unbound indirect transfers remain internal.
- Workspace 115 tests; corpus 5/5. Full gate improves to
  14 pass / 6 fail / 0 skipped. All non-PIE PowerPC rows are 1.0/1.0.
- Release libc: 3959 functions in 4.658 seconds on one isolated run.
  Seeded imports do not retain a redundant instruction cache.
- Completed below: PLT-entry metadata, per-caller PIC context and removal of
  the ELF64 x86 byte scan. No process-wide register value is assumed.

## m1-010-d4d PLT-entry cutover
- Acceptance `69e8a93` fails before implementation on an unreferenced i386 PLT
  entry. The regression also exercises AArch64 register setup and rejects
  non-executable tables and missing external-slot bindings.
- Both ELF classes retain `sh_entsize`; zero-width canonical tables require
  matching `.rel[a].plt` record counts. Each candidate needs bounded SLEIGH
  evidence within its entry width. The ELF64 x86 byte scan is removed.
- Workspace 116 tests; corpus 5/5; console and worker builds pass.
  Full discovery is 15 pass / 5 fail / 0 skipped, with precision 1.0 on all rows.
- Release libc retains 3959 functions in 4.424 seconds on one isolated run.
- Remaining misses: AArch64 prefix entries `0021078c` (o0/o2),
  `001107fc` (PIE), `00210a8c` (C++), and PowerPC PIE `00020698`.
  The AArch64 case matches the pinned `possiblefuncstart` wildcard-prefix
  pattern; it is not another PLT entry.
- PLT report: `benchmarks/reports/m1-010-d4d-plt.json`.

## m1-010-d4d per-caller PIC linkage
- Regressions `c7dd198`, `4ac12d4` and `94db212` cover unknown inputs,
  conflicting strong/weak callers, setup-bypassing branches and caller extent.
- Caller proof is bounded to 64 straight-line instructions; the linkage body
  retains its 8-instruction, imported-slot and side-effect constraints.
- Promotion follows strong and weak flow closure. Every validated caller must
  agree; decoded flow filters probes and supplies exact ownership boundaries.
- Workspace 117 tests; corpus 5/5; console and worker builds pass.
- Full discovery: 16 pass / 4 fail / 0 skipped; precision 1.0 on all 20 rows.
  PowerPC PIE now has precision 1.0 and recall 1.0 (13/13 functions).
- Release libc: 3959 functions in 4.619 seconds on one isolated run.
- Remaining failures are the AArch64 prefix entries listed above; d4e is next.

## m1-010-d4e implementation slices
- d4e1: expose native pattern selection and matching using the pinned XML
  grammar and existing parser. Acceptance: native-runtime
  `function_pattern_queries_preserve_prefix_marks_and_range_bounds`.
- d4e2: apply upstream function-start actions against established code,
  function ownership and validated flow; commit eligibility regressions first.
  Keep each test/implementation commit below 800 changed lines.

## m1-010-d4e1 native pattern matcher
- Acceptance commits `d17e3f9`, `28c123b` and `71fc4df` cover pinned prefix/pair
  marks, alignment, fixed-bit thresholds, scan-window edges and XML integer wrap.
- Native CLI smoke matched AArch64, PowerPC, i386 GCC and x86-64 GCC fixtures.
  Shared action metadata is returned without creating functions.
- Workspace 118 tests; corpus 5/5; console and worker builds pass.
- Full discovery remains 16 pass / 4 fail / 0 skipped, precision 1.0 on all rows.
- Integration prerequisite: mapped XML currently appends `:default`; x86 resolves
  that to Windows specifications. Retain loader compiler selection before
  applying compiler-specific patterns to ELF imports.

## m1-010-d4e2a loader compiler selection
- Acceptance `91be6d1` failed: ELF64 selected Windows rules and missed the GCC
  prologue. The same native-console regression now passes with the loader spec.
- ELF32/ELF64 retain base compiler opinions alongside their language ids:
  gcc for x86/RISC-V, default for the other supported ELF machines.
- Workspace 119 tests; corpus 5/5. Full discovery remains 16 pass / 4 fail /
  0 skipped; precision 1.0 on all 20 rows. Architecture check passes.
- No pattern action eligibility is enabled by this change.

## m1-010-d4e2b entry eligibility slices
- Acceptance `66c48d9` fails on the missing four-byte prefix entry while
  preserving the following seeded function. It also covers owned prefixes,
  minimum valid instruction counts, invalid flow and undefined predecessors.
- b1: expose instruction-level SLEIGH flow and delay-slot facts. Current raw
  p-code flow conflates intra-instruction branches with machine transfers;
  numeric pattern validation needs the instruction boundaries as well.
- b2: implement source-defined pattern prerequisites and bounded validation.
- b3: integrate definite/possible entry scheduling with existing ownership
  and flow closure before final PIC linkage reconciliation.
- Execute these prerequisites in order; each source commit stays below 800
  changed lines. The pending entry acceptance remains required throughout.

## m1-010-d4e2b1 instruction flow metadata
- `9a83b52` reproduced REP MOVSB incorrectly reporting a machine branch.
  `33ad564` reproduced lost conditional-return paths and invented terminal-call
  fallthrough. These regressions now pass; 10 targeted flow/linkage tests pass.
- Native CLI: MIPS return reports length 8 with a four-byte delay slot; its
  slot queried separately reports length 4 and no slots. ARM conditional return
  reports both terminal and conditional flags with a real fallthrough address.
- Console and worker builds pass. Entry-eligibility acceptance `66c48d9`
  remains pending b2/b3; no full-workspace pass is claimed for this intermediate
  state.
- Corpus 5/5; full discovery 16 pass / 4 fail / 0 skipped, precision 1.0 on
  all 20 rows. Architecture check passes with the shared fallthrough handling.

## m1-010-d4e2b publication slices
- Formatting plus new scheduling regressions exceeds 800 changed lines in the
  test module. Publish canonical formatting separately from behavioral tests.
- b3a: format existing tests in separate prefix and constrained-rule slices.
- b3b: correct the constrained-rule fixture and add the two deferred-creation
  regressions (loader-derived conditional references; same-batch references).
- b2: publish the pattern protocol and source-defined eligibility validator.
- b3c: publish phased scheduling and ownership reconciliation.
- d4f: generate and commit the complete unchanged gate from the source commit.
  Each publication commit stays below 800 changed lines.

## m1-010-d4e2b2/b3 implementation verification
- `2cd5f1b` isolates constrained AArch64 rules with RET x19 rather than the
  unconstrained RET prepattern. The adjacent four-byte entry and its following
  function both survive; owned prefixes and insufficient/invalid code do not.
- Two additional regressions reproduced premature possible-function creation:
  a relocation-rooted conditional reference and a same-pattern-batch reference.
  Both now pass after phased discovery and post-disassembly reconciliation.
- Workspace 125 tests; corpus 5/5. The source-defined validator uses retained
  native instruction/data/reference facts; unavailable section/context
  prerequisites fail closed. Full BytePatterns annotation coverage is not claimed.
- Source publication and the committed d4f gate report remain required.

## m1-010-d4 prerequisite sub-tasks
- d4b: record loaded external relocation slots for ELF32/ELF64, independently
  of instruction decoding; preserve symbol-table linkage and endian/load bias.
- d4c: expose bounded SLEIGH p-code linkage-thunk evidence, rejecting unknown
  inputs, stores and non-thunk control flow.
- d4d: consume that evidence for PLT and branch-target discovery; remove the
  ELF64 x86 byte-scan path rather than maintaining two discovery conventions.
- d4e: add the function-start prerequisite for independently justified
  adjacent entries. Match actual upstream action semantics: `validcode="function"`
  requires an already-defined function; it is not a new-entry validation rule.
- d4f: rerun the unchanged complete gate and commit fresh evidence.
  Each implementation/test commit range stays below 800 changed lines.

## Authorized prerequisite sequencing
- The maintainer authorized scheduling necessary later-milestone analyzer
  prerequisites autonomously so the current milestone can pass unchanged gates.
  This includes required function-start and indirect-thunk/tail-call work,
  not changes to corpus, metrics, release policy or other reserved decisions.
- The maintainer requested deletion of `AGENTS.md`. The file and its obsolete
  verbatim-content test/CI invocation are removed; no replacement agent-policy
  file is introduced.

## m1-010-e remaining regression and CI work
- Source `0332279` reaches precision/recall 1.0 on all 20 ELF rows locally.
  DOL improves to 634/644 matches, 674 functions and 40 extras.
- Existing `tests/m1-003_batched_flow.sh` fails: libc import takes
  5.136486053 s against the unchanged 5.0 s threshold (3,959 functions).
  Perf attributes 17.65% of sampled cycles to the shared worklist and 4.30%
  to pattern eligibility. No timing pass is claimed.
- e1: restore the existing timing acceptance without changing discovery sets.
- e2: run the complete discovery gate in CI using the matching generated corpus,
  raw oracles and scoring views; retain failed reports as artifacts.
- M1 remains open until these regressions and committed gate evidence pass.

## m1-010-e1 libc timing
- The unchanged acceptance failed at 5.553236246 s before output buffering.
  Flushing once per flow batch instead of per instruction reduces the measured
  import to 4.635571003 s against the 5.0 s threshold, with 3,959 functions.
- Candidate filtering avoids repeated address checks and uses bounded searches
  over sorted instruction extents during pattern eligibility.
- Workspace 125 tests; corpus 5/5; local full discovery 20 pass / 0 fail /
  0 skipped with precision/recall 1.0. Final committed gate evidence remains d4f.

## m1-010-e2 complete discovery CI
- Acceptance `7f789bf` adds the full gate with matching generated inputs and
  failed-report artifact retention. An unavailable-console smoke run exits 1
  with 4 pass / 16 fail / 0 skipped.
- The job now provisions the native console and its build dependencies.
  Replaying its exact build/input/gate commands locally generates 20 raw
  oracles, 20 scoring views and 20 passing discovery rows, with 0 skipped.
- This verifies the CI commands locally, not a completed hosted CI run.

## m1-010-e3 support claim scope
- Regression `0155d6e` failed because an M1 discovery pass changed the ARM
  support claim. It now verifies unchanged ARM/MIPS/RISC-V claims, gated
  AArch64 discovery and explicitly BE32-only PowerPC evidence.
- The generator no longer extends discovery claims to unmeasured architectures.
  CI runs the scope regression and README staleness check together; both pass.

## m1-010-d4f final measured evidence
- Source `081879b5cb262bb05ca9d142a61ca7fb69f90a44` produces the complete
  `benchmarks/reports/discovery-gate.json`: 20 pass / 0 fail / 0 skipped,
  precision/recall 1.0 on every row, architecture check passed.
- Fresh DOL report: 634/644 matches, 674 functions, 40 extras; recall
  0.984472049689441 and precision 0.940652818991098.
- Workspace 125 tests; corpus 5/5; support-scope/staleness acceptance passes.
  Final libc timing acceptance: 4.550281763 s < 5.0 s, 3,959 functions.
- Native console and worker builds pass; MIPS delay-slot and ARM conditional
  return smoke checks are recorded above. No M2 parity claim is made.
- Hosted CI run 33966774392 passes all 10 jobs on published commit
  `3d768a4c219fc380efafb2513bc2ae6c185aabe2`. Its downloaded discovery report
  has 20 pass / 0 fail / 0 skipped and precision/recall 1.0 on every row.
  Rust and Qt build/package jobs pass on Linux, macOS and Windows.
  https://github.com/Raikaru/romwright/actions/runs/33966774392

## m2-001 mapped pointer propagation complete
- Acceptance `b5073a3` failed on the missing `constants` command. Its x86-64
  and PowerPC BE32 fixtures load a readonly pointer into mapped BSS, propagate
  pointer arithmetic and reject an unmapped loaded value.
- The named evaluator exists. It supplies policy; SymbolicPropogator and
  VarnodeContext supply state, memory and call semantics. Reuse native
  OpBehavior arithmetic and Funcdata flow rather than an ISA-specific decoder.
- a (`b8e7e82`): sparse known-bit/affine storage. C++11 smoke passes alias
  overwrites, predecessor joins, temporary lifetime and 80,000 randomized
  reads in both byte orders.
- b (`e5b0162`): native function propagation and mapped-memory policy.
  Query-scoped entry metadata preserves recursive calls without retaining
  new symbols or replacing existing function bodies.
- c (`d5e9e61`): typed Rust results, call-stack regressions, native CI and
  query/source documentation. Implementation slices stay below 800 changed
  lines per commit.
- Two native acceptance tests pass, including readonly global loads on
  x86-64/PowerPC BE32, ordinary-call stack restoration, CALL-to-next and
  recursive-call continuation. The recursive case failed before the fix.
- Fourteen native smoke scenarios pass with identical repeated-query results:
  spills, partial registers, joins, call clobbers/preservation, opaque
  pointers, writable-memory trust, stores, stack aliases, PC capture,
  unknown-store joins and recursion. Throwaway drivers were removed.
- Workspace: 127 tests pass. Corpus: 5/5. Native console and worker builds
  pass. Support-matrix scope and staleness checks pass.
- Retained M1 discovery evidence is regenerated from source `d5e9e61` in
  `benchmarks/reports/discovery-gate.json`: 20 pass / 0 fail / 0 skipped,
  precision/recall 1.0 on every row; architecture check passed.
  This is not an M2 program-model parity gate or a new default analyzer.
- Hosted CI run 33979109416 passes all 10 jobs on published commit
  `49b027b62a99ac7a0531b858e3cc246e72e67456`, including the native constant
  propagation step and the complete oracle/discovery gate.
  https://github.com/Raikaru/romwright/actions/runs/33979109416

## m2-002 implementation slices
- User authorized correcting the missing `ReferenceCodeAnalyzer` citation.
  Verified sources: `RefTypeFactory.getMemRefType` classifies direct p-code
  references; `SymbolicPropogator.makeReference` inserts analysis references;
  `ConstantPropagationAnalyzer` supplies propagation policy.
- a: commit the failing `benchmarks/xref_gate.py` acceptance, then make the
  oracle export cover all memory reference sources rather than function
  bodies alone. Preserve non-RAM targets and every reference category.
- b: expose read/write/data use-site references from native propagation,
  retaining instruction PCs and the verified reference policy.
- c: typed inferred/asserted provenance and confidence for xrefs; migrate
  stored rows and preserve analyst assertions during inference.
- d: integrate the pass at native import, execute the 20-entry differential
  acceptance, and commit measured evidence. Each implementation slice must
  remain below 800 changed lines; split further before exceeding that limit.
- e: align indirect-flow access kinds and conditional instruction coverage
  with the verified Ghidra policies.
- f: distinguish literal operand references from computed parameter/return/
  use-site eligibility, replacing eager computed-output references.
  Split f into f1 (decoded literal operands) and f2 (computed eligibility and
  source tracking), each below 800 changed lines.
  f3: `data_references_do_not_promote_fallthrough` isolates call return-address
  storage at a function boundary; real reads of following data must survive.
  f4: `scalar_reference_eligibility_respects_instruction_alignment` separates
  unused AArch64 address formation from an address returned to the caller.
  f5: `x86_computed_address_operands_create_references` isolates Ghidra's
  x86 LEA policy from ordinary unused arithmetic; keep it outside discovery.
  Publish f5 implementation and its complete generated evidence as separate
  sub-tasks/commits; the 20-entry JSON report exceeds 800 lines.
- g: recover PIC reference contexts and flow-established resolver coverage.
  User-prioritized prerequisite g0: `tests/m2-002_context.py` must first fail
  when an explicit oracle language/compiler is ignored. Record and compare
  native/oracle contexts before classifying remaining propagation mismatches.
  Preserve automatic-selection oracles; explicit-context references use a
  separate cache namespace. Do not change reference metric definitions.
  Split g0 publication into context-selection code and a separate generated
  evidence commit; the complete 20-entry diagnostic report is 1,425 lines.
  g1: `references_apply_pc_helper_fixups` must fail before reusing compiler
  call-fixups for pattern-labeled existing functions. Preserve unknown ordinary
  calls; pattern labels must not create new discovery roots.
  Publish g1 implementation and the complete generated matrix report separately.
  g2: extend `references_apply_pc_helper_fixups` with a pre-call stack alignment
  and stale-alias rejection. Follow `VarnodeContext.and`'s symbolic alignment
  rule without equating the old and realigned stack origins.
  Publish g2 implementation and the complete generated matrix report separately.
- h: run the complete differential acceptance and wire its CI gate.
- User-approved acceptance: data_xref recall >= 0.95 and precision >= 0.98
  versus oracle; full II.3 xref metrics are retained separately.

## Approved m2-002 acceptance scope
- User approved distinct `data_xref.precision` / `data_xref.recall` metrics
  for code-origin read/write/data references to mapped program memory, with
  0.98 / 0.95 thresholds. Full II.3 `xref.*` and m2-016 remain unchanged.
- Preserve the complete oracle, including synthetic loader metadata and
  non-RAM references. Oracle instruction-origin evidence and input ELF
  PT_LOAD bounds define eligibility, not native analysis output.
- Score every reference produced by `native-analysis:constant-propagation`;
  do not mask erroneous native PCs or targets with oracle eligibility.

## m2-002b native reference query
- `references` reports instruction-origin READ, WRITE, READ_WRITE and DATA
  records without mutating the loaded image. Rust exposes typed query rows.
- Access-kind regression passes; all 9 native-runtime tests pass.
  `cargo test --workspace`: 128 tests pass. `tests/corpus.sh`: 5/5 pass.
- Differential acceptance still fails 20/20 inputs with data precision and
  recall both 0.0: native import does not yet persist the new query results.
  Raw oracle exports remain separate from the function-only M1 format.
- Remaining m2-002 slices: c (durable ownership/confidence and assertion
  preservation), then d (import integration and differential gate).

## m2-002c durable reference ownership
- Acceptance `82941db` failed on missing typed ownership and pass replacement.
  The ownership, rollback and schema-4 migration regressions now pass.
- Schema 5 stores source, inferred/asserted ownership and nullable confidence.
  Unknown legacy ownership is preserved as asserted; no confidence is invented.
  NaN is rejected before SQLite can convert it to NULL.
- The incompatible provenance-object contract uses API 2 and `/v2`; CLI,
  SDK and Qt bridge consumers are migrated. CLI and SDK HTTP smoke checks
  exercised typed durable rows and rejection of API 1 and `/v1`.
- `cargo test --workspace`: 130 tests pass. `tests/corpus.sh`: 5/5 pass.
  Java bridge builds with source ownership exported on all reference queries.
- Native propagation import integration and the data-reference gate remain
  outstanding; m2-002 is not complete.

## m2-002d import integration
- Acceptance `872a1d9` failed on PE section permissions and ELF mapping
  attributes in the reference request. Both regressions now pass.
- Import reuses the discovery console and publishes the reference pass only
  after all bounded function queries succeed. Inferred source remains
  `native-analysis:constant-propagation`; confidence remains unknown.
- A conditional-exit regression exposed missing synthetic exits in
  `FlowInfo`'s visited map. The out-of-tree patch fixes target lookup.
  Symbol-owned temporary functions avoid jump-table clone scope collisions.
- `cargo test --workspace`: 130 pass. `tests/corpus.sh`: 5/5 pass.
  The rebuilt worker decompiles `tiny_bin`'s `add` to
  `return param_2 + param_1;` through the native CLI.
- `tests/differential.sh` stops at its obsolete `/tmp/spike/decomp_native`
  invocation; no full differential-script pass is claimed.
- The 20-entry data-reference gate reports 0 pass, 20 fail, 0 skipped.
  Data precision ranges from 0.461538 to 1.0; recall from 0.090909 to
  0.882353. Reference classification, computed origins and PIC context
  remain in slices e–h; m2-002 is not complete.

## m2-002e reference access and conditional coverage
- The acceptance now checks indirect-call READ versus indirect-jump DATA,
  bounded exits, and references on a provably untaken conditional path.
  Constant-value queries still exclude that untaken path.
- A separate x86-64 ELF oracle probe confirms 2 memory-call READ references
  and 2 indirect-jump INDIRECTION references, covering internal and external
  targets. Original SLEIGH flow distinguishes calls from jumps rewritten by
  `FlowInfo.truncateIndirectJump`; no instruction encodings are matched.
- `cargo test --workspace`: 130 pass. `tests/corpus.sh`: 5/5 pass.
- The 20-entry gate still reports 0 pass, 20 fail, 0 skipped. x86-64 plain
  O0/O2 now have data precision 1.0 and recall 13/15. AArch64 plain O0/O2
  reach recall 1.0 but precision 14/22. Literal operands, computed origins
  and PIC contexts remain in slices f–h.

## m2-002f1 decoded literal operands
- Acceptance `7ea13b5` failed on a CMP address literal with no pointer-valued
  output. Its DATA reference now appears, including on an untaken path.
- Literal extraction walks SLEIGH display metadata and retains scalar widths.
  It does not parse assembly text or treat every p-code constant as an operand.
  Direct call/jump targets are excluded from this DATA producer.
- `cargo test --workspace`: 130 pass. `tests/corpus.sh`: 5/5 pass.
  Console and worker rebuild; the native worker CLI still decompiles `add`
  to `return param_2 + param_1;`.
- The full gate reports 3 pass, 17 fail, 0 skipped. x86-64 plain O0/O2 and
  many O2 have data precision 1.0 and recall 1.0. Computed-pointer eligibility,
  source attribution and PIC context remain; m2-002 is not complete.

## m2-002f2 computed reference eligibility
- Acceptance `1dd118c` failed because an unused arithmetic intermediate
  produced a DATA reference. References now require an eligible use rather
  than every complete output. Return/argument references trace their setters.
- The regression also covers equal values with two reaching setters,
  AArch64 arguments observed before call clobbers, and the e500 return-source
  fallback for an unnamed register slice.
- `cargo test --workspace`: 131 pass. `tests/corpus.sh`: 5/5 pass. Console
  and worker rebuild; native `add` still decompiles to
  `return param_2 + param_1;`. Automatic bridge import returns 15 functions.
- The pre-context gate reports 4 pass, 16 fail, 0 skipped. Its PowerPC
  comparison is not context-matched: native selects `PowerPC:BE:32:default`,
  while the automatic oracle selected `PowerPC:BE:32:e500`. No propagation
  correction is justified by those mismatches until g0 aligns the contexts.

## m2-002g0 matching analysis contexts
- Acceptance `0c1bd7c` failed with `Oracle language mismatch`. Explicit
  default/e500 imports now select the requested language and produce
  different reference sets; an invalid compiler is rejected.
- The gate pins language/compiler pairs independently of inferred references,
  validates actual oracle identities, and checks native stored language.
  A native ABI regression observes RDI argument references under SysV but
  not Windows x64. `cargo test --workspace`: 132 pass.
- All 20 automatic-selection oracle files retain their previous SHA-256.
  Explicit-context oracles use a separate cache namespace.
- Report committed as `6e5bc23`: 20 matching contexts; 4 pass,
  16 fail, 0 skipped. All 5 PowerPC inputs now have data precision 1.0,
  without changing propagation to compensate for their former e500 oracles.
  PowerPC recall ranges from 0.5 to 0.9473684210526315.
- `tests/corpus.sh`: 5/5 pass. Automatic bridge import and native worker
  smoke paths still run. No M2 gate pass is claimed.

## m2-002f3 call fallthrough references
- Acceptance `52eb786` failed on a saved return PC at a function boundary.
  The native pass now follows `evaluatePureDataRef`'s fallthrough rule.
  The paired real-read regression still reports the following data.
- Focused `x86_64_cpp_o2` import: 24 native / 24 oracle data references,
  24 matched, 0 missing, 0 extra. The later f4 matrix measurement includes
  this isolated correction.
- `cargo test --workspace`: 133 pass. `tests/corpus.sh`: 5/5 pass.
  Console and worker rebuild; native `add` still returns the sum.

## m2-002f4 scalar analyzer eligibility
- Acceptance `e9bf5a6` failed on an unused AArch64 ADR. The scalar pass now
  honors Ghidra's instruction-alignment eligibility; the returned-address
  regression remains positive.
- Focused `aarch64_plain_o0`: 14 native / 14 oracle data references,
  14 matched, 0 missing, 0 extra.
- `benchmarks/reports/m2-002-context.json` now reports 10 pass, 10 fail, 0 skipped.
  All 20 entries have data precision 1.0. All x86-64 and AArch64 entries
  pass; i386 and PowerPC remain below the recall threshold.
- `cargo test --workspace`: 134 pass. `tests/corpus.sh`: 5/5 pass.
  Console and worker rebuild; the native `add` smoke still returns the sum.
- Remaining classes are separated: x86 computed LEA references, PIC helper
  context, resolver flow coverage, and the C++ exception landing pad.
  AArch64 C++ recall is 21/22, within its threshold; its missing landing-pad
  reference is not a scalar or constant-propagation arithmetic defect.

## m2-002f5 x86 computed address operands
- Acceptance `6fdaa9e` failed with no reference for a discarded computed LEA.
  The x86-specific policy now follows Ghidra's `X86Analyzer.evaluateContext`;
  unused ADD results remain unpromoted.
- `cargo test --workspace`: 135 pass. `tests/corpus.sh`: 5/5 pass.
  Both native executables rebuild.
- Generated evidence, published separately as `benchmarks/reports/m2-002-f5.json`:
  10 pass, 10 fail, 0 skipped; all 20 data precisions remain 1.0.
  i386 PIE data recall rises from 1/22 to 2/22. Other row scores are unchanged.
- Next focused classes: i386 PC-helper context and PowerPC PIC loads/resolver
  coverage. The plain PowerPC resolver's missing READs use locally constructed
  `r12` addresses in `.glink`, not an unknown incoming TOC register.

## m2-002g1 compiler-defined PC-helper context
- Acceptance `839b68f` failed with no caller reference after a PC helper.
  It now passes the recognized-helper case and rejects a pattern without a
  validated function and a helper-shaped function that reads an argument.
- Reuse discovery's pattern-label evidence and the selected compiler's
  call-fixup targets/p-code. No instruction-byte recognizer, new function root,
  or native function rename is added.
- Original instruction flow still excludes CALL operands from scalar DATA
  references after Ghidra expands their call-fixups.
- `cargo test --workspace`: 136 pass. `tests/corpus.sh`: 5/5 pass.
  Console and worker rebuild.
- `benchmarks/reports/m2-002-g1.json`: 10 pass, 10 fail, 0 skipped;
  all 20 data precisions remain 1.0. i386 PIE recall is 15/22 (was 2/22);
  i386 O0/O2/C++/many recall is 15/17, 14/16, 23/25, 12/14.
  Other architectures' row scores are unchanged.

## m2-002g2 symbolic stack realignment
- Acceptance extension `37319ac` failed after `and esp,-16` before a PC helper.
  The aligned frame now remains usable; pre-alignment pointer and memory
  aliases are retired rather than equated with the realigned frame.
- The paired regression rejects post-alignment constants derived from stale
  aliases while allowing the valid literal stored before alignment.
- `cargo test --workspace`: 136 pass. `tests/corpus.sh`: 5/5 pass.
  Console and worker rebuild.
- `benchmarks/reports/m2-002-g2.json`: 11 pass, 9 fail, 0 skipped;
  all 20 data precisions remain 1.0. i386 PIE recall is 16/22;
  i386 O0/O2/C++/many recall is 16/17, 15/16, 24/25, 13/14.
  Other architectures' row scores are unchanged.

## m2-002g3 writable-image reference policy
- Acceptance `a89c3c1` failed on the second dereference through a writable
  initial-image pointer. The importer now matches
  `ConstantPropagationAnalyzer`'s default writable-memory trust.
  Explicit strict constant queries retain their previous behavior.
- `cargo test --workspace`: 137 pass. `tests/corpus.sh`: 5/5 pass.
- `benchmarks/reports/m2-002-g3.json`: 14 pass, 6 fail, 0 skipped;
  all 20 data precisions remain 1.0. The four non-PIE i386 rows reach
  data recall 1.0; i386 PIE is 17/22 and PowerPC PIE is 18/26.
- Remaining failures are i386 PIE linkage references and the five PowerPC
  linkage/resolver rows. Implementation and generated evidence are published
  separately; no M2 gate pass is claimed.

## m2-002g4 ELF PLT register context
- Acceptance `0c40e58` failed without loader context; extension `9431bcb`
  failed when a computed indirect jump slot was classified as DATA.
  Both now pass. Missing `DT_PLTGOT`, non-PLT code, and strict constant
  queries do not receive EBX context.
- Match `X86_32_ElfExtension`'s executable PLT scope. Computed LOAD operands
  retain READ; fixed-address indirect-jump operands retain DATA normalization.
- `cargo test --workspace`: 138 pass. `tests/corpus.sh`: 5/5 pass.
  Console and worker rebuild; both computed and fixed indirect-access
  regressions pass.
- `benchmarks/reports/m2-002-g4.json`: 15 pass, 5 fail, 0 skipped.
  All 20 data precisions are 1.0; i386 PIE data recall is 22/22.
  The five PowerPC rows remain below the recall threshold.
- Next focused class: PowerPC linkage/resolver instruction coverage,
  separately from incoming PIC register context. No M2 gate pass is claimed.
- Publication sub-tasks remain separate: g4 implementation, then g4-report
  generated evidence. Preserve the complete gate JSON.

## m2-002g5 section-address reference roots
- Acceptance: `elf_linkage_references_do_not_require_functions`. Follow
  executable section-address roots without inserting functions. Reject
  non-executable sections and unseeded disconnected bytes; section names
  do not determine whether a root is code.
- The initial sweep assumption was rejected: it added READs at PowerPC C++
  `0x100109bc` and `0x100109cc`. An isolated matching oracle import defines
  only four instructions at `0x10010980..0x1001098c`.
- `ElfProgramBuilder.markupSectionHeaders` creates imported references to
  section starts. Reuse that entry-root evidence, not a linear code sweep.
  Do not change reference eligibility, normalization, or gate thresholds.
- Acceptance `b949d8b` passes. `cargo test --workspace`: 139 pass;
  `tests/corpus.sh`: 5/5 pass. Console and worker rebuild.
- `benchmarks/reports/m2-002-g5.json`: 19 pass, 1 fail, 0 skipped;
  all 20 data precisions are 1.0. PowerPC PIE recall is 20/26.
- Remaining classes: three READs needing incoming PIC register context,
  and three DATA refs from non-stack symbolic load offsets.
  No M2 gate pass is claimed.
- Publication sub-tasks: g5 implementation, then g5-report generated evidence.

## m2-002g6 non-stack symbolic offsets
- Acceptance: `non_stack_symbolic_offsets_are_data_references`. A mapped
  large offset from an unknown non-stack base is a DATA candidate, never a
  proven memory access. Stack aliases and original call instructions are
  excluded; strict constant queries remain unchanged.
- Match `SymbolicPropogator.addLoadStoreReference` and the existing constant
  evaluator filters. This is generic p-code behavior, not a PowerPC pattern.
- Acceptance `2bc129d` passes, including stack aliases, original call flow,
  and strict-query separation. `cargo test --workspace`: 140 pass;
  `tests/corpus.sh`: 5/5 pass. Console and worker rebuild.
- `benchmarks/reports/m2-002-g6.json`: 19 pass, 1 fail, 0 skipped;
  all data precisions are 1.0. PowerPC PIE remains 20/26.
- A raw PowerPC probe produces the expected symbolic-offset DATA reference
  when its target is mapped. The ELF import's first mapping is `0x10194`,
  leaving the three targets `0x10048`, `0x1004c`, and `0x10054` unmapped.
  Next: preserve PT_LOAD bytes outside allocated sections, then PIC call context.
- Publication sub-tasks: g6 implementation, then g6-report generated evidence.

## m2-002g7 complete PT_LOAD byte coverage
- Acceptance: `load_segment_gaps_preserve_bytes_and_section_precedence`.
  Preserve loaded ELF headers, inter-section file bytes, and zero-filled
  segment tails. Allocated section mappings and their relocated bytes keep
  precedence; segment completion must not create overlapping mappings.
- Exercise ELF64 little-endian and ELF32 in both byte orders. Reject truncated
  segment bytes rather than silently replacing them with zeroes.
- Do not add function seeds or change the gate's PT_LOAD eligibility rule.
- Publication sub-tasks: g7 implementation, then g7-report generated evidence.
- Acceptance: failed on missing loaded ELF header bytes before implementation;
  passes after completion. Workspace: 141 passed. Corpus: 5/5 passed.
- Matched-context gate: 19 passed, 1 failed; data precision 1.0 on every row.
  PowerPC PIE recall increased from 20/26 to 23/26. The three symbolic DATA
  destinations now exist in native memory; PIC-context READ references remain.
  Evidence: `benchmarks/reports/m2-002-g7.json`.

## m2-002g8 caller-derived PowerPC GOT context
- Acceptance: `powerpc_pic_context_follows_calls_not_unrelated_functions`.
  Analyze the callee before its caller; a caller-proven r30 value must still
  resolve the callee's READ. An uncalled function must not inherit that value,
  and removing DT_PPC_GOT must disable propagation.
- Match the ELF32 PowerPC policy in `PowerPCAddressAnalyzer`: propagate actual
  register values at calls, not a global guessed GOT base. Keep this context
  transient and exclude it from strict constant queries.
- Publication sub-tasks: g8 implementation, then g8-report generated evidence.
- Acceptance failed on the missing callee READ before implementation. Added
  zero/unknown-value, preserved DATA, and caller-order regressions; each exposed
  a failing behavior before its correction. Workspace: 142 passed. Corpus: 5/5.
- Complete diagnostic run: all 20 rows meet the data-reference thresholds;
  precision 1.0 throughout, PowerPC PIE recall 25/26 (0.9615384615), AArch64 C++
  recall 21/22 (0.9545454545), and recall 1.0 on the other 18 rows.
  Evidence: `benchmarks/reports/m2-002-g8.json`, committed in `4ef169f`;
  measured implementation `d49d518`.
- Remaining PowerPC READ: `0x2069c -> 0x408c0`, reached through `_start`'s
  non-linking branch at `0x204f0`, not a call. Do not broaden call propagation
  or `close_call_targets` to hide that distinction.

## m2-002h differential acceptance and CI
- Acceptance: existing `benchmarks/xref_gate.py`, committed before native
  reference inference. Enforce all 20 ELF rows in the pinned-Ghidra CI job,
  with a separate explicit-context oracle cache and retained JSON evidence.
- Run the context regression and native Core tests with the built console.
  Retain the M1 discovery gate and its reports unchanged.
- Publication sub-tasks: h CI integration, then h-report generated evidence.
- Fresh corpus: 20/20 binaries generated; 20/20 explicit-context oracles
  regenerated in an empty cache. Differential acceptance: 20 passed, 0 failed,
  0 skipped, with the same precision/recall as g8.
- CI commands executed locally: explicit default/e500 contexts honored;
  invalid compiler rejected; 91 Core tests passed with the console available.
  Workflow YAML parses. `actionlint` is unavailable on this workstation;
  hosted GitHub CI has not yet been observed for this change.
- m2-002 complete: CI integration `f80681a`, fresh-input report
  `benchmarks/reports/m2-002-h.json` committed in `a8e1f6f`.
  Workspace: 142 passed; corpus smoke: 5/5; data-reference acceptance: 20/20.
  This closes the data-reference task, not the full M2 parity gate.

## m2-003 implementation slices
- Frozen acceptance: reference string addresses, minimum length 4, matching
  reference encodings; str.recall >= 0.95. The 20-entry corpus is unchanged.
- a: failing `data_string_sweep_decodes_utf8_and_utf16` acceptance, then an
  oracle-backed string gate and defined-string export. Actual upstream source:
  `ghidra/app/plugin/core/string/StringsAnalyzer.java`; default discovery is
  ASCII-only. `DefinedStringIterator` covers already-defined Unicode strings.
- b: native data-section sweep for ASCII/UTF-8 and endian-aware UTF-16,
  preserving decoded text and m2-002 references. Exercise supplementary
  characters and minimum character count, not byte or UTF-16 code-unit count.
- b1: retain ELF string-table facts with their declared UTF-8 encoding and
  loaded or metadata address spaces. Baseline recall is 0.02857–0.07547:
  `.shstrtab` addresses and declared encodings are not optional oracle rows.
  First commit `elf_string_tables_preserve_namespaces_and_utf8` failing;
  do not remove non-loaded strings from the metric.
- b2: the real ELF Unicode smoke import loses `A😀BC` behind a shifted
  UTF-16 interpretation beginning in alignment padding. Commit
  `shared_data_strings_use_alignment_and_reference_evidence` failing, then
  resolve overlapping candidates using BOM, reference, and alignment evidence.
- c: verify worker string delivery, complete differential acceptance, and CI.
  Publish implementation and generated reports in separate commits below
  800 changed lines.
- d: publish complete difference sets as hashed per-binary JSON sidecars;
  the first full report contains 3,141 lines. No rows are discarded.
  Execute these report-publication sub-tasks one commit at a time:
  d1 x86-64's five sidecars; d2 i386's three plain sidecars;
  d3 i386's C++/many sidecars; d4 AArch64's five sidecars;
  d5 PowerPC's three plain sidecars; d6 PowerPC's C++/many sidecars;
  d7 the summary referencing all 20 sidecars. Each commit stays below 800
  changed lines; no committed baseline is modified.
- Initial acceptance failed: only ASCII `word` was found; UTF-8 and UTF-16
  strings were absent and executable `CODE` bytes were incorrectly included.
- Native implementation: `1305ebf`; ELF namespaces and supplementary-character
  regressions pass. The Qt smoke displays UTF-8, both UTF-16 byte orders, and
  `.shstrtab`-qualified addresses.
- Worker acceptance `0c1b101` first failed on a typed string query (`None`
  instead of RAM address `0x401178`). Four string protocol regressions and
  nine independent protocol-peer callback cases now pass, including namespace
  isolation, missing/empty strings, UTF-16 limits, and the 12-bit length bound.
- Completion evidence: `benchmarks/reports/m2-003.json`, committed in
  `1c9f318`, measures implementation `5ffe7e9` with fresh reference exports:
  20 passed, 0 failed, 0 skipped; str.recall 1.0 for every binary (threshold
  0.95). All 20 difference-file hashes and counts were verified: 0 missing
  and 363 additional address/encoding pairs; no differences were discarded.
- Final verification: `cargo test --workspace` 149 passed; `tests/corpus.sh`
  5/5; generated support matrix current; workflow YAML parses. Hosted CI
  has not yet been observed for this change. Smoke drivers were removed.
- m2-003 is complete. The full M2 parity gate remains open.

## m2-004 implementation slices
- a: failing version-6 migration acceptance, then format 7 with prototype
  ownership/source/confidence and primitive classification/array count in the
  existing `type_defs` table. Preserve legacy prototype/type/field records.
  Generalize the existing fact-provenance model without a compatibility alias.
- b: migrate consumers and preserve structured metadata through type editing;
  exercise store/API roundtrips and ownership/confidence boundaries.
- c: run workspace and corpus verification, publish measured evidence, and
  document the storage contract. Keep each implementation commit below 800
  changed lines; do not add a parallel type store or grow the Java bridge.
- Acceptance `c296d79` failed on the missing prototype provenance column in a
  version-6 fixture. Migration implementation `5c5c139` preserves legacy
  signatures, conventions, type definitions, and fields in format 7.
- Ownership regression covers assertion retention, inferred replacement, and
  atomic rollback for invalid confidence. `cargo test --workspace`: 151
  passed across 22 suites. `tests/corpus.sh`: 5/5.
- Qt implementation `9bd4d65` was exercised offscreen against the real bridge.
  A separate API process reopened 4 types, 1 field, and 1 prototype:
  signed-integer classification, array count 0, and asserted `ui` provenance
  with null confidence. Initial API roundtrip also retained inferred
  confidence 0.75. Persisted facts: `benchmarks/reports/m2-004.json`.
- String regression rerun on `9bd4d65`: 20 passed, 0 failed, 0 skipped,
  recall 1.0 on every binary; refreshed `benchmarks/reports/m2-003.json`.
  Generated support matrix remains current. Smoke drivers were removed.
- m2-004 is complete. Prototype recovery and the full M2 parity gate remain
  open; no new Java bridge state or runtime dependency was introduced.

## m2-005 implementation slices
- a: commit the failing captured-`add` acceptance, then decode function
  prototypes and ordered parameter symbols from the existing packed response.
  Reuse the packed grammar; do not parse C text or modify pinned native code.
- b: carry optional recovered prototypes through worker/model/client document
  results; verify both standalone and pooled worker paths against real code.
- c: verify workspace/corpus/string regressions, commit measured evidence,
  and document the response contract. Split implementation commits below 800
  changed lines. Durable inference remains m2-006, not this task.
- b prerequisite regression: with no `ROMWRIGHT_SLA` override, the standalone
  fixture recovers `int add(int, int)` but the pooled API emits bad-instruction
  tokens and a void prototype. Keep `tests/m2-005_prototype.py` as the real
  CLI/API acceptance; reuse language resolution and configure the pool's child
  explicitly rather than requiring process-global environment setup.
- Captured-`add` acceptance `a2261e7` first failed on the missing decoder;
  `c2d6711` recovers ordered input types, return type, and calling convention
  from packed metadata. Nested variadic function pointers remain nested.
- API regression `452403e` failed on bad-instruction/void output; `838badf`
  passes the resolved language/SLA to the pooled child. Overflow regression
  `b71faf0` first accepted a 2^64 parameter index as zero; checked accumulation
  now rejects it. Captured token metadata is unchanged with collection enabled.
- Verification on `838badf`: 154 workspace tests across 22 suites; corpus 5/5.
  Removed a copied-watchdog simulation that did not exercise the production
  pool, rather than claiming it as deadline coverage.
- `benchmarks/reports/m2-005.json` records 1 standalone and 3 pooled real
  decompiles (`add`, `main`, `add`), with 1 warm idle worker and 0 restarts.
  Add has 2 int parameters and an int return; standalone/pooled prototypes
  agree. The regression deliberately unsets `ROMWRIGHT_SLA`.
- String regression on the same source: 20 passed, 0 failed, 0 skipped,
  recall 1.0 throughout; `benchmarks/reports/m2-003.json` refreshed.
  Support matrix current; throwaway drivers removed. No baseline was edited.
- m2-005 is complete. These are read-only recovered facts, not persisted
  prototype inference or full M2 parity.

## m2-006 implementation slices
- a: commit the failing real API inference acceptance; add benchmark-only
  DWARF arity projection using readelf and the locked unstripped twins.
  This is test infrastructure for the M2 criterion, not the M3 runtime reader.
- b: export fresh stock parameter-ID results from stripped binaries and add
  the frozen proto.arity comparator/report. Never seed either analysis with
  DWARF; preserve matching denominators and all mismatches in evidence.
  Split b into b1 (stock exporter and comparator tooling), b2 (per-architecture
  reference evidence), and b3 (native gate integration after c/d). Commit
  generated reference evidence per architecture, separately from tooling.
  b1 verification: stock headless `plain_o0` arity 2/2 against DWARF;
  4 Python boundary tests, 154 workspace tests, corpus 5/5, and string
  regression 20/20 passed. b2 reference gate: 20 passed, 0 failed, 0 skipped;
  1,640 DWARF functions matched. `benchmarks/reports/m2-006-reference.json`
  is committed in `c131f4c`. Sixteen cases score 1.0; x86-64, AArch64 and
  PowerPC many score 400/401; i386 many scores 0/401. All 404 mismatches remain
  in linked evidence. This is reference collection, not native inference parity.
  b2 report detail is split from the aggregate: per-binary JSONL mismatch
  evidence retains every entry/expected/actual tuple, with a SHA-256 link.
  Commit that detail separately from the aggregate report to stay below 800 lines.
- c: bound pool registration and decompile operations, refresh workers after
  fact revisions, and apply stored callee prototypes before caller analysis.
  Split c into c1 (production registration deadlines and child teardown),
  c2 (revision invalidation and callee activation), and c3 (unlock inferred
  targets during recovery without unlocking analyst assertions).
- d: implement Core-owned inferred writes and the API inference operation,
  with at most 3 rounds, caller-only re-analysis, a time budget, and assertion
  retention. Existing prototype storage remains authoritative.
  Split d into d1 (structured declaration rendering and atomic inferred
  persistence) and d2 (bounded pool/API orchestration and caller scheduling).
- e: run the full unchanged DWARF corpus gate, fix demonstrated mismatches,
  and publish measured reports. Split any implementation slice further before
  exceeding 800 changed lines; no metric or corpus change is authorized.
  Split e into e1 (reproducible static bundles for the 3 missing locked
  languages), e2 (generic imported-thunk prototype uncertainty), and e3
  (full parity reports). Bundle register lists exceed 800 lines; provision
  generated caches with recorded hashes rather than commit partial bundles.
  Native reports use separately committed architecture detail plus an aggregate.

### m2-006-a evidence
- Failing API acceptance committed in `5960e96`; benchmark projection tests
  committed in `6c67db6` after observing the missing-module failure.
- DWARF projection: 20 locked ELF twins, 1,640 concrete subprograms, 0
  unmapped entries. The real `plain_o0` export reports `add` arity 2 and
  `main` arity 0. Two inheritance/error boundary tests pass.
- Workspace 154 tests passed; corpus 5/5. Existing string regression:
  20 passed, 0 failed, 0 skipped, recall 1.0; report refreshed.
- The pinned stock entry point is `DecompilerFunctionAnalyzer`, which
  delegates to `DecompilerParameterIdCmd`; ELF default enablement is off.
  The reference must explicitly run parameter ID, not score unprocessed
  default signatures. m2-006 parity and the inference API remain unfinished.

### m2-006-c1 evidence
- Failing production registration regression committed in `ee7708e`: two
  250 ms leases took 4.03 s and returned registration errors instead of deadlines.
- The corrected regression takes 0.52 s for two wedged children plus a
  malformed-protocol child that ignores EOF. Deadlines kill/reap and poison;
  immediate protocol failures remain errors instead of waiting for the budget.
- Real native smoke: 1 standalone and 3 pooled decompiles, 2 recovered `add`
  parameters, 1 idle worker. Workspace 154 tests; corpus 5/5; string regression
  20/20 with recall 1.0. No inferred writes or revision invalidation are claimed.

### m2-006-c2 evidence
- `7a75600` committed the failing warm-caller and call-only edge regressions.
  Both pooled and standalone callers now reflect an asserted callee arity
  change from 2 to 1; pooled revision advances from 5 to 8. The target retains
  the asserted parameter name `left`.
- Call edges exclude branches/data, deduplicate call kinds, preserve typed
  spaces, and sort numeric offsets across the 32-bit boundary. Callee lookup
  uses stored extents, not the next function entry. No schema migration.
- Worker snapshot invalidation preserves pool job history; a concurrent
  revision change discards the returned document. Inference writes remain pending.
- Verification: 155 workspace tests, corpus 5/5, both real prototype scripts,
  and string regression 20/20 with recall 1.0.

### m2-006-c3 evidence
- `b0f63a8` committed the missing recovery API/provenance acceptance first.
  The real native test now observes stored inferred arity 0, recovered arity 2,
  and asserted arity 0 in one process; inferred names do not rename functions.
- Repeated application exposed native stream accumulation (`inferredrecovery`).
  The command now clears all 4 string parameters before reading them. Pinned
  `ghidra_arch.cc` confirms append semantics; `fspec.hh` confirms all 3 locks.
- Native build succeeded; the explicit recovery test passed in 0.12 s.
  Workspace: 155 passed, 1 native test ignored by default and exercised above.
  Corpus 5/5, both prototype API/CLI scripts, string regression 20/20 at 1.0.
- Core persistence and bounded inference orchestration remain unfinished.

### m2-006-d1 evidence
- `25184e0` committed missing atomic-merge and typed-persistence acceptance.
  Changed inferred batches advance 1 revision; repeated batches advance 0.
  Assertions survive conflicts; stale revisions and invalid batches write 0 rows.
- The Core renderer round-trips an `int` pointer return, pointer to 4-element
  array, and variadic callback through the actual native parser. Missing type
  information is rejected without changing the stored prototype or revision.
- The regression exposed lost nested varargs in pinned `FunctionModifier`.
  The out-of-tree patch now uses its `dotdotdot` flag, as top-level parsing does;
  no pinned source or baseline reference was edited.
- Verification: native build, 156 workspace tests, 2 explicit native tests in
  0.11 s, corpus 5/5, both prototype scripts, string regression 20/20 at 1.0.
  API orchestration and native arity parity remain unfinished.

### m2-006-d2 evidence
- `5b62686` committed caller scheduling, zero-budget, and shared-deadline
  acceptance. The real inference API passes: 2 initial rounds, 1 repeated round,
  inferred `add` arity 2, and the exact analyst assertion retained.
- The caller regression re-analyzes `main`, not leaf `add`. A zero-budget
  request produces 0 rounds, 0 jobs, and no prototype changes.
- Production deadline regression passes in 0.77 s: two separate 250 ms leases,
  then one shared 250 ms deadline; the expired second shared lease launches no
  fourth child. Protocol errors remain distinct from deadline expiry.
- Verification: 156 workspace tests; 2 explicit native tests in 0.12 s;
  corpus 5/5; inference, prototype, and revision scripts; string regression
  20/20 with recall 1.0. Native corpus arity parity remains unmeasured.

### m2-006-b3 evidence
- Full native gate: 4 passed, 16 failed, 0 skipped. All 20 immutable stock
  references validate; native inference receives only stripped inputs.
- x86-64 C++ scores 2/3 against stock 3/3. At `0x2019e0`, raw native `main`
  has 2 inputs; after inference it has 1. Imported PLT stubs were persisted
  as `void(void)`, and calls to `__isoc23_strtol`/`printf` lost their arguments.
- The other 15 cases fail because i386, AArch64 and PowerPC spec bundles are
  absent. Existing static export uses the bridge only during provisioning.
- Aggregate and 4 architecture reports retain all cases and link full scores
  and mismatches by hash. Repackaging preserved every measured score and count.
- Verification: 156 workspace tests, corpus 5/5, 4 arity/DWARF boundary tests.
  The native gate is not passed.

### m2-006-e1 evidence
- `1a9d622` committed the failing static-bundle acceptance. Provisioned 3
  locked contexts, 5 files each; committed manifests record hashes and
  generation provenance. Regeneration refuses a changed manifest.
- Real native acceptance recovers 2 inputs at i386 `0x401440`, AArch64
  `0x2107c4`, and PowerPC `0x100104e4`; runtime starts no bridge.
- Verification: 156 workspace tests, corpus 5/5. Full native arity gate:
  16 passed, 4 failed, 0 skipped. Each C++ case scores 2/3 versus stock 3/3;
  the other 16 cases equal the reference. Gate reports include spec hashes.
- Next: e2 imported-thunk uncertainty, then e3 final parity evidence.
- Regeneration follow-up: `daf1b0e` exposed rejection of equivalent producer
  inputs. Three ELF copies with unmapped trailing padding now reproduce all
  15 spec files without rewriting any manifest. Context/output hashes remain
  mandatory; the original representative hash remains provenance.
  Verification: static native acceptance on all 3 contexts, 156 workspace
  tests, corpus 5/5. No locked corpus file or baseline was changed.

### m2-006-e2 evidence
- `23b22ab` first demonstrated x86-64 caller arity falling from 2 to 1.
  `caa24ac` extended the failing acceptance to context-dependent PowerPC stubs.
- Both now retain 2 caller inputs after 2 rounds, with 16 and 18 imported
  symbol addresses respectively. Ordinary caller prototypes remain persisted.
- Flow-proven linkage identities survive import. Completed propagation resolves
  context-dependent entries only with a bounded pure-linkage shape and one
  consistent imported read slot inside its exact span; no ISA-specific rule.
- Unknown external prototypes are not written as `void(void)`. All functions
  are still analyzed initially; assertions and caller-only repeat rounds remain.
- Verification: console rebuild, 156 workspace tests, corpus 5/5, both thunk
  regressions and bounded-inference acceptance. Final report publication is e3.

### m2-006-e3 evidence
- `21ec27a` commits the full gate produced from implementation `f45df59`:
  20 passed, 0 failed, 0 skipped. All 1,640 DWARF functions match; native and
  stock each recover 1,236 arities correctly, with 404 retained mismatches.
- Sixteen cases score 1.0. x86-64, AArch64 and PowerPC many score 400/401;
  i386 many scores 0/401 in both analyzers. This meets the relative criterion,
  not an absolute accuracy claim for that case.
- Verified 4 architecture-report hashes and 8 complete mismatch-file hashes.
  Reports include spec-file and linkage-source hashes. Baselines are unchanged.
- Final verification: 156 workspace tests, corpus 5/5, 2 explicit native
  recovery tests, revision/standalone/pooled/inference regressions, both thunk
  regressions, and all 3 static-bundle and equivalent-input rebuild checks.
- m2-006 is complete. M2 program-model parity remains open; next is m2-007.

## m2-007 implementation slices
- a: commit a failing real indirect-switch acceptance and stock target exporter.
  Use a temporary positive fixture, not a change to the locked corpus.
- b: project packed jump-table metadata into standalone and pooled documents,
  preserving typed branch/target addresses, order and duplicate destinations.
  Distinguish unavailable metadata from a recovered function with no tables.
- c: compare targets against stock on the positive fixture and record all 20
  unchanged corpus cases, including zero-table observations and missing inputs.
  The recorded task provides no numeric threshold. No new metric, persistence
  operation, rediscovery pass, or full M2 parity claim is introduced here.
  Evidence publication is split below so each commit stays under 800 changed
  lines: c1 positive fixture; c2 x86-64 references; c3 i386 references;
  c4 AArch64 references; c5 PowerPC references; c6 aggregate report and closure.

### m2-007-a/b evidence
- `e034a98` committed the real fixture acceptance after it failed on unavailable
  switch metadata; `6b432d9` committed packed boundaries before the result field
  existed. Implementation is `3327bb8`.
- `benchmarks/reports/m2-007-positive.json` records 1 recovered indirect branch
  and 7 distinct targets, equal to stock in 1 standalone and 2 pooled dispatch
  documents. The intervening pooled plain function has 0 tables; all 3 pooled
  documents retain 1 store revision.
- Packed regressions preserve target order, duplicate destinations, addresses
  above 32 bits, and non-RAM spaces. Every truncated prefix stays unavailable.
- Verification: 158 workspace tests, 2 explicit native recovery tests, corpus
  5/5, and standalone/pooled prototype, bounded-inference, and revision checks.
  Positive evidence is committed in `fb19d3d`; corpus evidence follows below.

### m2-007-c2–c6 evidence
- `846fa0e`, `3151fbc`, `b4f4865`, and `42eb5f1` pin 20 stock references
  across x86-64, i386, AArch64, and PowerPC, in commits of 553, 570, 591,
  and 554 added lines respectively. No existing baseline was edited.
- `6df0ab2` commits `benchmarks/reports/m2-007.json`, produced against
  `42eb5f1`: 20 equal comparisons, 0 failed, 0 skipped. A second fresh stock
  run matched all 20 immutable references; all 20 reference hashes were checked.
- Native decompiled 1,903 functions; stock exported 2,008. All have 0 recovered
  tables, including the 105 stock-only functions. These corpus observations
  are not positive recovery evidence or a claim of function-set equality.
- The separate x86-64 positive fixture remains the switch-recovery proof.
  Missing-input smoke reported 20 skipped cases, `passed=false`, and exit 1.
- m2-007 is complete. No metric definition, corpus member, persistence
  operation, or rediscovery pass changed. Full M2 parity remains open.

## m2-008 implementation slices
- a: commit failing real native acceptance for a closed-loop callee, a
  non-returning relay, and a conditional caller. Returning, indirect, and
  incomplete-flow controls must not acquire unsupported non-returning facts.
- b: migrate provenance-owned return behavior storage; preserve assertions,
  reject stale publication, and leave unchanged facts at the same revision.
- c: prove non-returning behavior only from complete native flow closure,
  propagate it through calls, and refresh caller extents and owned call xrefs
  atomically. Never use neighboring entry distances as flow evidence.
  - c1: publish owned return facts, caller extents, and call edges in one
    revision-checked transaction; retract unsupported owned inferences.
  - c2: add complete-flow proofs and the native Core orchestration. Keep
    c1 and c2 in separate commits below 800 changed lines.
- d: expose explicit inference and stored facts through the existing Core/API
  conventions, and apply facts in standalone and pooled native workers.
- e: exercise the real acceptance, unchanged corpus, and milestone report;
  publish evidence and update the next task. No new metric threshold or
  corpus member is introduced. Split additional evidence commits below
  800 changed lines if required.
  - e1: add the locked-corpus acceptance and stock return-behavior exporter.
  - e2–e5: commit x86-64, i386, AArch64, and PowerPC architecture reports,
    JSONL mismatches, and compressed raw/scoring/body references separately.
    e6: commit the aggregate report and measured task status. Each evidence
    commit remains below 800 changed lines; a failed gate does not close the task.
- f1: complete the ratified known-name requirement using the pinned ELF/PE
  no-return lists, including `exit`; extend the failing acceptance first.
- f2: produce and consume positive completed-decompiler flow hints. Preserve
  assertions and unknown-flow rejection; do not infer from rendered C text.
- f3: export exact oracle body ranges, reuse `code-functions-v1` eligibility,
  and record before/after `fn.bounds` on the unchanged optimized recipes.
- g (authorized prerequisite): the user approved taking only relocation-proven
  PowerPC linkage/name recovery from m2-009 out of order. Commit a failing
  corpus-backed acceptance first; preserve returning imports and authoritative
  names. Reuse generic p-code linkage evidence, then rerun m2-008. The rest of
  m2-009 remains out of scope until m2-008 closes.

### m2-008 evidence
- `df32929` passes the direct-flow acceptance: 2 inferred functions and
  2 removed call xrefs; 163 workspace tests and corpus 5/5 pass.
- `9286d42` and `cae416a` commit the known-name and resolved-indirect-loop
  regressions before implementation. The extended real acceptance now reports
  5 inferred functions, 3 removed/restored call xrefs, 1 stale inference
  retracted, and 2 asserted-return controls. Workspace: 163 pass, 2 ignored;
  corpus: 5/5. Standalone and pooled worker paths pass.
- `e2ff96c` implements pinned known names and completed native CFG hints.
  `5d085b3`, `3e90d14`, and `df3cb5d` pin boundary and positive-metadata
  regressions; 5 benchmark checks pass.
- `5d32b11` commits the failing corpus-backed PowerPC linkage acceptance
  (`tests/m2-008_ppc_linkage.py`). `471f198` submits direct-call targets to the
  existing bounded p-code linkage proof in both the seeded and swept paths.
  No architecture-specific branch, name guess, or metric/corpus change was added.
  `0x100108b0` now imports as `__cxa_throw`, size 16, and is inferred
  non-returning; `printf` at `0x100108d0` stays returning.
- `benchmarks/reports/m2-008.json` at commit `471f198`: **20 pass, 0 fail,
  0 skipped**. Optimized `fn.bounds` improves from 1771/1789
  (0.98993851313583) to 1774/1789 (0.9916154276131918). Every stock positive
  is covered, all 20 native analyses are revision-idempotent, and the twenty
  compressed reference bundles plus architecture and mismatch links pass
  SHA-256 verification. Raw and `baseline-*.json` references are unchanged.
- Stock false return flags remain unknown rather than returning assertions; the
  15 additional native ELF entry-point inferences are reported separately.
- Verification: `cargo test --workspace` 163 pass/2 ignored;
  `cargo test -p romwright-core --no-default-features native::discovery` 18 pass;
  `tests/corpus.sh` 5/5; `tests/m2-008_nonreturn.py`, `tests/m2-008_ppc_linkage.py`,
  and `tests/m2-006_thunks.py --architecture powerpc` all pass.
- m2-008 is complete. No metric definition, corpus member, or reserved decision changed.

## Blocked on
- None.

## m2-009 implementation slices
- a: commit the failing fixture acceptance (`tests/m2-009_thunks.py`), the
  stock exporter (`scripts/ExportThunks.java`) and the libc gate
  (`benchmarks/thunk_gate.py`) before implementation.
- b: provenance-owned thunk storage at schema v9; assertions and other
  producers survive a re-import, and an unchanged pass bumps no revision.
- c: publish flow-proven thunk facts through import, Core and the API.
- d: recognize the remaining proven shapes — ifunc PLT stubs through
  `*_IRELATIVE` relocations, terminal transfers into pinned non-returning
  functions, and the primary (exported) symbol name at an address.
- e: run the libc gate, publish evidence and record the next task.

### m2-009 evidence
- `7fd3fc4` commits the failing acceptance (`unknown_method: thunks`).
  `c1bf5dc` adds schema-v9 storage with three ownership regressions.
  `46b9619` publishes facts and stops one undecodable range from aborting a
  whole import; `1400539` adds the ifunc, terminal-transfer and naming rules.
- `benchmarks/reports/m2-009.json`: **native 107 vs stock 107 thunks, ratio
  0.000 within the ratified ±1% on `/usr/lib64/libc.so.6`** (sha256
  `01cccbe2…`, `x86:LE:64:default` / `gcc`; stock 3987 functions, native 3961).
  94 entries match exactly; the 13 native-only rows are `.plt.sec` import
  stubs; the 13 stock-only rows are Ghidra's synthetic external-linkage thunks
  at unmapped addresses outside every image section, which native represents as
  those executable stubs. Hash-linked JSONL lists carry the complete sets.
  This comparison is not an II.3 metric. Native kinds: 94 direct, 13 linkage.
- Verification: `cargo test --workspace` 168 pass/2 ignored (schema-v9
  ownership, symbol precedence and undecodable-root regressions included);
  `tests/corpus.sh` 5/5; `tests/m2-009_thunks.py` 2 direct, 1 linkage, 1 tail
  call excluded, 1 assertion preserved; `tests/differential.sh` PASS (import
  parity, stripped subsets, `add`/`main` semantic parity).
- `tests/differential.sh` console paths pointed at the removed `/tmp/spike`
  layout and aborted with status 127; they now use the same defaults as
  `RuntimeConfig::from_env`.
- m2-009 is complete. No metric definition, corpus member, or reserved
  decision changed.

## m2-010 implementation slices
- a: commit the failing round-trip acceptance
  (`crates/romwright-sig/tests/vsig_roundtrip.rs`) with the crate registered in the
  workspace and no format code.
- b: implement the container, its invariants and typed rejections; document
  the layout in `docs/vsig.md` and the clean-room stance in
  `docs/third-party.md`.

### m2-010 evidence
- `638df1d` commits the failing acceptance: `unresolved imports romwright_sig::…`.
- `crates/romwright-sig` implements `.vsig` v1: 16-byte header (`VSIG`, version,
  reserved flags, record count, payload length) and records carrying language,
  name, package, license, pattern and per-byte mask. Masked pattern bytes are
  normalized to zero and records are strictly ascending by
  (language, name, package), so `encode(decode(bytes)) == bytes` holds for
  every accepted file and a rebuilt database is byte-identical.
- Rejections are typed (`VsigError`), never repairs: bad magic, unsupported
  version, reserved flags, truncation, declared/actual payload mismatch,
  trailing bytes, mask length mismatch, mask byte outside {0x00, 0xff},
  non-zero masked pattern byte, fully masked pattern, empty provenance field,
  control characters, non-UTF-8 text, duplicate key, non-canonical order.
- The crate depends only on `thiserror`, already a workspace dependency; no
  new runtime dependency was introduced.
- Verification: `cargo test --workspace` 172 pass (4 acceptance tests in
  `vsig_roundtrip`: canonical round trip, mask comparison semantics,
  construction rejections, corrupt/non-canonical decode rejections). The
  acceptance builds one file from the documented header layout by hand, so the
  documentation and the encoder are pinned to each other.
- m2-010 is complete. No metric definition, corpus member, or reserved
  decision changed.

## m2-011 implementation slices
- a: commit the failing gate (`benchmarks/signature_gate.py`) that builds
  databases from the pinned cross sysroot archives and reports record count and
  byte size per source, with a byte-identical rebuild check.
- b: `romwright-sig` gains the `ar` archive reader and ELF `ET_REL` extraction:
  per-function patterns with relocation-covered bytes masked from public
  relocation width tables, rejecting unknown relocation types instead of
  guessing a width. Unit tests cover both.
- c: `romwright-cli signatures build|info`, the CI job, and the docs. Slices stay
  below 800 changed lines each.

### m2-011 evidence
- `a7c96f8` commits the failing gate (`error: unknown command: signatures`).
  `101e136` adds the `ar` reader and ELF extraction; `19b24bf` adds the CLI
  surface, the CI step and the documentation.
- `benchmarks/reports/m2-011.json` (current, commit `4772795`): **4 sources
  pass, 0 fail, 0 skipped; 3 858 records across 4 585 361 database bytes**,
  every rebuild byte-identical. Per source: aarch64 `libc.a` 1 028 records /
  1 120 263 bytes, i386 `libc.a` 1 416 / 1 691 796, powerpc `libc.a` 1 292 /
  1 557 295, aarch64 `libm.a` 122 / 216 007. Minimum compared bytes is 16.
- Skips are reported, never silent: 1 221 bodies below the evidence threshold,
  8 conflicting definitions, 8 434 dropped as ambiguous once m2-012 proved
  that indistinguishable bodies produce wrong names, and 0 for unknown
  relocations after the PowerPC TLS/REL16 widths were added from public
  `elf.h` numbering. The first run, before the ambiguity policy, held 12 292
  records; that recall bought a 0.77% false-positive rate, so it was dropped.
- Independent verification (throwaway script, this session): decoding the
  generated databases with a separate Python implementation of the documented
  layout reproduced every record; `strlen` in the aarch64 database matches
  `strlen_mte.o`'s `.text` bytes exactly and not the other `strlen` definition;
  PowerPC `_Exit`, `_Fork` and `_IO_cleanup` match their objects at every
  compared byte, and 20 of `_IO_cleanup`'s 54 masked bytes are non-zero in the
  object — the mask removes real linker-rewritable content.
- `.github/workflows/ci.yml` builds the databases in the `corpus-linux` job,
  which already fetches the pinned sysroots, and retains the report as an
  artifact.
- Verification: `cargo test --workspace` 179 pass/2 ignored (archive, object,
  generator and container tests included); the gate passes as above.
- m2-011 is complete for the pinned ELF sources. MinGW CRT (`.lib`/COFF) and
  devkitPPC signature sources need new pinned package inputs, which is a
  reserved decision (II.1: adding a corpus binary or platform); the generator
  refuses unknown formats instead of guessing.

## m2-012 implementation slices
- a: commit the failing gate (`benchmarks/match_gate.py`): build a database
  from a pinned `libc.a`, statically link and strip a corpus source with the
  matching cross toolchain, import it with the database, and score named CRT
  helpers and the false-positive rate against the unstripped twin.
- b: schema-v10 provenance-owned `signature_matches` storage with ownership
  regressions.
- c: the matcher itself (windowed mask comparison, conflict rejection,
  confidence), its Core/API/CLI surface, and the documented false-positive
  rate. Slices stay below 800 changed lines each.

### m2-012 evidence
- `3a7b359` commits the failing gate (`unknown_method: signature_matches`);
  `bfa6b8b` adds schema-v10 storage with two ownership regressions; `4772795`
  adds the matcher, its Core/API/CLI surface, the CI step and the docs.
- `benchmarks/reports/m2-012.json` at commit `4772795`: **3 architectures pass,
  870 matches, 870 correct, 0 false positives, rate 0.000**. Per architecture:
  AArch64 303/303, i386 297/297, PowerPC 270/270. CRT helpers named include
  `abort`, `memcpy`, `memset`, `strcmp` and `strlen`; the rate table is
  recorded in `docs/vsig.md`.
- The first measured run had 7 false positives in 915 matches (0.77%), every
  one an exported wrapper naming its byte-identical `static` twin. Local
  bodies now compete with records even though their names are never published,
  which removed the whole population. Exact-body-length matching and treating
  every weak body as a competitor were both tried and rejected: the first lost
  `abort` and kept the false positives, the second emptied a database.
- Matching semantics: window at the entry satisfies every compared byte, the
  record is at least as long as the proven body, disagreeing databases leave
  the function unnamed, `confidence = compared_bytes / pattern_len`, and only
  generated `FUN_*` names are replaced.
- Verification: `cargo test --workspace` 183 pass/2 ignored; the CLI path
  reports `1418 records, 300 matched, 300 renamed, 0 conflicts` on a stripped
  static i386 twin; both signature gates pass in `corpus-linux`.
- m2-012 is complete. No metric definition, corpus member, or reserved
  decision changed.

## m2-013 implementation slices
- a: commit the failing gate (`benchmarks/rtti_gate.py`) with polymorphic gate
  fixtures (`tests/fixtures-src/rtti.cpp`) plus the locked corpus C++ entries,
  which define no classes and must stay empty.
- b: record named ELF data relocations in the loader and add schema-v11
  provenance-owned class/vtable/base storage with ownership regressions.
- c: recover Itanium typeinfo, its type name, the primary vtable and the base
  list; expose the facts through Core/API and document the shapes. Slices stay
  below 800 changed lines each.

### m2-013 evidence
- `db63dbc` commits the failing gate (`unknown_method: classes`); `2bc46ae`
  adds schema-v11 class/base storage with two ownership regressions;
  `5349c82` adds the loader's named data relocations and the recovery pass.
- `benchmarks/reports/m2-013.json` at commit `5349c82`: **8 targets pass, 0
  fail, 1 skipped (no MSVC corpus binary on this host); 20 classes recovered
  for 20 compiler vtables, 16 base relations, 0 missing and 0 invented.**
  Every fixture target recovers `Base`, `Middle`, `Multi`, `Other` and `Virt`
  with the shapes the ABI encodes: 2 `class`, 1 `single_base`,
  2 `multiple_base`.
- The four locked corpus C++ entries recover zero classes, which is correct:
  `tests/corpus-src/src.cpp` declares none, so they prove only that recovery
  invents nothing. Polymorphic shapes therefore live in a gate input,
  `tests/fixtures-src/rtti.cpp`, because adding a corpus source is reserved
  (II.1). Both link modes are covered: a non-PIE link COPY-relocates the ABI
  type_info vtables into the image, a PIE link binds the vptr slot instead.
- Slot counts were checked by hand against the twins' `_ZTV` sizes: `_ZTV4Base`
  40 bytes → 3 slots, `_ZTV5Multi` 72 → 4 primary slots plus its secondary
  vtable, `_ZTV5Other` 24 → 1, `_ZTV4Virt` 64 → 3 after the virtual-base
  offset word. `Multi` reports `Middle` at 0 and `Other` at 8; `Virt` reports
  its virtual base with the ABI's negative offset slot.
- Loader change: named ELF data relocations (COPY, word-sized absolute and
  linkage forms) are recorded with their symbol and addend. Import naming keeps
  its strict undefined-NOTYPE/FUNC filter; the new reader accepts any symbol
  table and yields no name when a file has none.
- Verification: `cargo test --workspace` 186 pass/2 ignored; `tests/corpus.sh`
  5/5; `tests/differential.sh` PASS; the m2-011 and m2-012 signature gates
  still pass unchanged (3 858 records; 870 matches, 0 false positives).
- m2-013 is complete. No metric definition, corpus member, or reserved
  decision changed.

## m2-014 implementation slices
- a: commit the failing gate (`benchmarks/msvc_rtti_gate.py`) with a
  freestanding MSVC-ABI fixture (`tests/fixtures-src/msvc_rtti.cpp`) for both
  machine widths, plus the locked PE corpus entry, which declares no classes.
- b: recover `RTTICompleteObjectLocator`, `TypeDescriptor`, the class
  hierarchy descriptor and its base descriptors into the schema-v11 class
  facts, sharing the model the Itanium pass writes.
- c: document the layouts and their public sources, wire the CI step and
  publish the evidence. Slices stay below 800 changed lines each.

### m2-014 evidence
- `3d95219` commits the failing gate (5 locators, 0 classes on both widths);
  `8bf4d4f` splits `rtti` into `itanium`/`msvc` modules behind one dispatch
  and adds the MSVC recovery.
- `benchmarks/reports/m2-014.json` at commit `8bf4d4f`: **2 targets pass, 0
  fail, 5 skipped; 10 classes for 10 link-map locators, 10 base relations,
  2 virtual bases, 0 missing and 0 invented.** Both widths recover `Base`,
  `Middle`, `Multi`, `Other`, `Virt` as 2 `class`, 1 `single_base`,
  2 `multiple_base`.
- The five locked MSVC corpus entries are skipped with a reason on this host:
  they are built by the Windows CI job. The fixture is freestanding — clang's
  `*-pc-windows-msvc` target plus `lld-link /nodefaultlib` — so no MSVC
  installation is needed anywhere, and the 32-bit link exercises the absolute
  (`signature == 0`) locator form while the 64-bit link exercises the
  image-relative form whose self reference fixes the image base.
- Hand-checked against the link map: each class's `vtable` is the locator slot
  one pointer before its `??_7<class>@@6B@` address point (`Base`
  `0x140002000` vs `0x140002008`; `Virt` `0x140002240` vs `0x140002248`).
  `Multi` reports `Middle` at 0, the indirect `Base` at 0 and `Other` at 8;
  `Virt` reports `Base` as virtual. Primary vfptr selection uses the smallest
  locator offset, which is what `Virt` needs: its only locator sits at 8.
- Verification: `cargo test --workspace` 187 pass/2 ignored; the m2-013 gate
  still passes unchanged after the module split (20 classes, 20 vtables);
  `tests/corpus.sh` 5/5.
- m2-014 is complete. No metric definition, corpus member, or reserved
  decision changed.

## m2-015 implementation slices
- a: commit the failing cutover acceptance (`tests/m2-015_native_default.py`):
  the default path needs no JVM, the `-native` verbs are gone, `--oracle`
  routes to the bridge, the docs say so and no CI step takes a bridge path
  outside oracle generation.
- b: flip the CLI verbs — `import`, `decompile`, `decompile-doc`, `disasm`
  become native and take `--oracle` for the bridge; `dump-specs` becomes
  explicit oracle tooling. Migrate every caller in tests, gates and scripts.
- c: update the docs and the CI guard, then publish the evidence. Slices stay
  below 800 changed lines each.

### m2-015 evidence
- `1ed4788` commits the failing cutover acceptance; the verbs are now native
  (`import`, `decompile`, `decompile-doc`, `disasm`) with `--oracle` routing
  to the bridge, and `import --oracle --name NAME` stores under the requested
  name (`Core::import_program` takes it).
- `RuntimeConfig::adopt_language`: the console language directory follows the
  image's own language id. Before this, a non-x86 image kept the x86 language
  directory, so the SLEIGH console could not resolve its language and native
  import silently degraded to symtab seeds. PowerPC now runs console flow:
  644 native vs 653 bridge functions on the PPC ELF (fn.recall 0.9862,
  fn.precision 1.0000, 1 773 flow call xrefs).
- Three legacy acceptance scripts were repaired to their own stated criteria:
  `tests/generic_discovery_test.sh` scores libc in the store's RVA space (the
  m1-002 oracle is image-relative; since m1-004 the loader maps ELF PIE at
  Ghidra's default base) -> fn.precision 0.9997, fn.recall 0.9932, and its PPC
  step scores native against the bridge instead of demanding growth over
  symtab seeds; `tests/data_xrefs.sh` reads the current xref provenance
  rendering; `tests/m1-005_pe_relocs.sh` counts every `.text` symbol as an
  oracle function (`ty 20` alone dropped `___chkstk_ms`) -> tiny_pe p=1.0000
  r=0.5290, dispatch p=1.0000 r=0.4000.
- Verification: `cargo test --workspace` 188 pass/2 ignored; `tests/corpus.sh`
  5/5; `tests/differential.sh`, `tests/workflow.sh`, `tests/m1-004_pie.sh`,
  `tests/m1-005_pe_relocs.sh`, `tests/data_xrefs.sh`,
  `tests/generic_discovery_test.sh`, `tests/m2-015_native_default.py`,
  `tests/m1-008_languages.py`, `tests/m2-005_prototype.py`,
  `tests/m2-006_revision.py`, `tests/m2-007_switches.py`,
  `tests/m2-008_nonreturn.py`, `tests/m2-008_ppc_linkage.py`,
  `tests/m2-009_thunks.py` all pass.

## m2-016 implementation slices
- a: commit the failing acceptance (`tests/m2-016_import_budget.py`): phases
  must be measured, sharding must be fact-invariant, the reference pass must
  shard at least 2x, and the flow phase must stay inside m1-003's budget.
- b: measure the pipeline (`import --timings`, `PhaseTiming`, `FlowStats`)
  and shard the console work that is independent inside a round.
- c: rescope the m1-003 acceptance onto the phase it names, refresh the
  bridge-produced oracle provenance, wire continuous integration and publish
  the evidence. Slices stay below 800 changed lines each.

### m2-016 evidence
- `9276c58` commits the failing acceptance (no `TIMINGS` line existed).
- What the diagnosis found, and why the recorded plan was wrong: the
  reference pass issued **3 958 requests in 1 round with 0 repeats**, so
  batching had nothing to buy. The 5.1 ms per request is console work --
  `followFlow` lifting the function, then propagation -- and the only lever
  is running more consoles. The pass now shards across one console per
  physical core, and flow batches shard the same way.
- Measured on this host (release, `/usr/lib64/libc.so.6`, 6 physical cores),
  one console vs six:
  | phase | 1 console | 6 consoles |
  |---|---|---|
  | flow | 4.70 s | 2.86 s |
  | discovery | 5.39 s | 3.60 s |
  | references | 17.44 s | 5.32 s |
  | total | 23.11 s | 9.30 s |
- Shards change wall time and nothing else: 3 961 functions, 29 442 xrefs,
  18 410 strings, 26 symbols and the thunk set are byte-identical between the
  one-console and six-console imports (SHA-256 per table, asserted by the
  acceptance and recorded in `benchmarks/reports/m2-016.json`).
- Default shard count is physical cores, capped at eight: six shards measured
  2.86 s of flow against 3.09 s at eight and 3.11 s at twelve, because SMT
  siblings contend on the same execution units. `ROMWRIGHT_CONSOLE_SHARDS` pins
  it; `ROMWRIGHT_REF_SHARDS` never shipped.
- `tests/m1-003_batched_flow.sh` rescoped (user-authorised): the 5.0 s number
  is unchanged but now reads the `flow` phase instead of total import time,
  best of three runs after a discarded warm-up. It also asserts what batching
  actually claims and no machine speed can flatter: **297 390 instructions
  over 3 146 console requests = 94.5 per request**, against a floor of 20.
  Flow measured 2.96 s.
- Oracle provenance refreshed: the committed `oracle/` tree carried bridge
  source hashes from before the m2-002c/m2-002g0/m2-003-b service edits, so
  every provenance-checking local gate refused it. Regenerated all 20
  references and their scoring views; **entry sets are identical in all 20**,
  the only changes being `bridge_sources_sha256`, a now-recorded `compiler`
  field, and the views' `raw_reference_sha256`. Continuous integration was
  never affected: it generates its own oracles per run.
  `tests/m1-008b_pointer_seeds.py` gained `--oracle-dir` so a local run can
  point at freshly generated references; it now passes.
- Verification: `cargo test --workspace` 187 pass/2 ignored;
  `tests/m2-016_import_budget.py` PASS (6 consoles, references 2.94x, flow
  2.86 s, total 9.30 s); `tests/m1-003_batched_flow.sh` PASS;
  `tests/corpus.sh` 5/5; `tests/differential.sh`, `tests/workflow.sh`,
  `tests/data_xrefs.sh`, `tests/generic_discovery_test.sh`,
  `tests/m1-004_pie.sh`, `tests/m1-005_pe_relocs.sh`,
  `tests/m1-008b_pointer_seeds.py`, `tests/m2-015_native_default.py`,
  `tests/m1-008_languages.py`, `tests/m2-005_prototype.py`,
  `tests/m2-006_revision.py`, `tests/m2-007_switches.py`,
  `tests/m2-008_nonreturn.py`, `tests/m2-008_ppc_linkage.py`,
  `tests/m2-009_thunks.py` pass; gates re-run green after the change:
  discovery (20/20), xref, string, nonreturn, prototype, switch, rtti, thunk.

## M3 implementation slices
- m3-001: score function recovery against DWARF truth on the locked corpus,
  with stock Ghidra scored on the same truth as the baseline column.
- m3-002: record the immutable stock-Ghidra ground-truth baseline that M4
  improvements are measured against.
- m3-003: wire the DWARF regression gates into continuous integration and
  publish the evidence.

### m3-001 evidence
- `6a4d9ba` commits the failing acceptance (`tests/m3-001_dwarf_truth.py`;
  no gate existed).
- New metric definitions, additive -- no II.3 definition changed:
  - `dwarf.fn.recall`: concrete `DW_TAG_subprogram` entries recovered over
    those the compiler emitted, restricted to executable segments and biased
    to the store's own image base for ET_DYN. DWARF records link-time
    addresses; without the bias the three PIE rows score 0.0000, which is how
    the metric was shown to be sensitive.
  - `dwarf.fn.unattributed`: recovered entries that DWARF does not describe
    and nothing else explains -- not a symbol in the unstripped twin, not a
    store thunk row, not a linker stub inside a `.plt*` section, and not a
    function stock Ghidra also created. DWARF is silent about CRT and PLT
    code both tools legitimately recover, so this replaces a precision
    number that DWARF cannot support. Threshold 0.
  - `ghidra.dwarf.fn.recall`: the same recall over the pinned stock-Ghidra
    oracle for the same image -- the M3 baseline column.
- Measured on all 20 locked ELF inputs (`benchmarks/reports/m3-001.json`):
  **1 640 DWARF functions, native recall 1.000000, stock Ghidra recall
  1.000000, 0 unattributed of 263 undescribed** (1 903 native entries total).
  The 263 break down as named twin symbols, store-proven thunks, `.plt*`
  stubs, and entries stock Ghidra also created -- including the i386
  `_start+0x29` four-byte tails, which are in the pinned oracle, so they are
  a CRT artifact both tools see and not a native invention.
- Every row carries provenance: binary, twin and oracle digests plus the
  oracle's `bridge_sources_sha256`; the gate refuses an oracle that does not
  validate against the pinned bridge.
- Verification: `tests/m3-001_dwarf_truth.py` PASS (20/20 rows); the gate is
  wired into the `corpus-linux` CI job after the import-budget step.

### m3-002 evidence
- `ca480cd` commits the failing acceptance (`tests/m3-002_baseline.py`; no
  baseline existed).
- `benchmarks/reports/baseline-ghidra-truth.json` freezes what stock Ghidra
  12.1.3 scores against DWARF on the locked corpus: **`ghidra.dwarf.fn.recall`
  1.000000 over 1 640 functions, `ghidra.dwarf.proto.arity` 0.753659
  (1 236/1 640), 2 008 functions created**. Per-row provenance carries the
  binary, twin, entry-oracle and arity-reference digests, the bridge sources
  hash, the analysis context and the image base.
- The baseline is immutable by construction: without `--write` the recorder
  recomputes and compares. Negative control run this session -- editing one
  row's `ghidra.dwarf.proto.arity` to 0.99 makes both the recorder and the
  acceptance fail naming `x86_64_many_o2`; restoring the file passes again.
- Byte equality is claimed only under the recorded DWARF reader: the baseline
  records `truth_toolchain.readelf`, and a differing reader is reported
  (`verified_bytes: false`) while the metrics must still match exactly. Numbers
  are the guarantee; bytes are the stronger convenience.
- **Finding, and the clearest M4 target on record**: stock arity is
  0.9975-1.0000 on x86-64, AArch64 and PowerPC but **0.0000 on i386
  `many_o2`** -- `DecompilerParameterIdCmd` commits zero parameters for 413 of
  that image's 415 functions while DWARF gives 400 of them one parameter and
  `main` two. Reproduced independently from a fresh `analyzeHeadless` run with
  the same processor/cspec, so it is a stock result, not an export artifact.
  The M2 prototype gate could not surface this: it scores native against
  `ghidra - 0.02`, so a stock 0.0 row makes any native value pass.
- Verification: `tests/m3-002_baseline.py` PASS (20 recorded rows, byte
  identical, cross-checked against every `ghidra.dwarf.fn.recall` in
  `benchmarks/reports/m3-001.json`); wired into the `corpus-linux` CI job.

### m3-003 evidence
- `1a762e9` commits the failing acceptance (`tests/m3-003_regression.py`; no
  regression gate existed).
- `benchmarks/regression_gate.py` joins native DWARF scoring to the frozen
  baseline per corpus row and enforces two rules: **native >= baseline per
  row** for entries and prototype arity, and a **pinned deficit set** -- any
  row where either producer scores below 0.98 against truth is named, so
  matching a broken reference cannot read as success.
- Published in `benchmarks/reports/m3-003.json` (20 rows): native entries
  1.000000 vs baseline 1.000000; native arity 0.753659 vs baseline 0.753659;
  one recorded deficit, `i386_many_o2:proto.arity`, where both producers
  score 0.0000. Native equals the baseline everywhere -- M3 measures, M4 owns
  exceeding it.
- Evidence is re-measured by default (48.9 s: the prototype pass plus the
  DWARF gate) and refused when stale: an artifact must carry source hashes
  that still match the tree.
- **Stale evidence found and fixed**: `benchmarks/reports/m2-006.json` was
  recorded at `f45df59`, before `e2ff96c` changed
  `native/ghidra-opt-sleigh.patch`, so its own freshness pin was broken.
  Re-measured with the current tree: every per-row metric is identical, only
  the commit and patch pins moved. The m3-001 report now carries
  `sources.dwarf_gate_sha256` and `sources.dwarf_reader_sha256` so consumers
  can tell fresh evidence from stale.
- Three negative controls run this session, each with the gate declining to
  pass:
  1. feeding the stale `m2-006.json` -> `passed: false` on freshness;
  2. raising the frozen baseline's i386 arity to 1.0 -> refused with
     `arity reference 0.0 disagrees with the frozen baseline 1.0`, before any
     comparison, which is the right order for a tampered baseline;
  3. doctoring native entry recall to 0.5 on `aarch64_many_o2` ->
     `FAIL aarch64_many_o2: entries 0.5000 vs 1.0000`, one row failing and the
     aggregate falling to 0.877439.
- Verification: `tests/m3-003_regression.py` PASS; all three M3 gates wired
  into the `corpus-linux` CI job.

## M4 implementation slices
- m4-001: recover parameters passed in registers that no shipped prototype
  model claims, behind `ROMWRIGHT_REGISTER_PARAMS`.

### m4-001 evidence
- `98fc02f` commits the failing acceptance
  (`tests/m4-001_register_params.py`).
- What the deficit actually was: clang compiles `static int fn_n(int x)` for
  i386 into `lea 0x3(%ecx),%eax; ret` -- the argument arrives in **ECX**
  under the compiler's internal convention. `__cdecl` has no register
  parameter slot, so `DecompilerParameterIdCmd` commits none. Ghidra's own
  dataflow does see the input: it names the varnode `in_ECX`
  ("Irregular input", `Scope::buildDefaultName`, database.cc:2470-2478 of the
  pinned tree, verified there).
- The document now carries that evidence structurally:
  `romwright_model::StorageSymbol` rows come from `<mapsym>` (symbol plus its
  storage entries, database.cc:2643-2654), so the pass reads mapped storage
  rather than scraping C text.
- `crates/romwright-core/src/register_params.rs` commits exactly the registers the
  evidence names, with three guards, each measured:
  1. **Volatility.** A register must be one the compiler spec says a call
     destroys. A callee-saved live-in is something else -- on i386 PIC it is
     the GOT pointer in EBX, not an argument.
  2. **Storage agreement.** A captured offset must match the register file in
     `registers.txt`, so a name alone never decides which register was read.
  3. **No invented convention.** x86-32 gcc ships no model that passes ECX
     first (`__regparm1/2/3` start at EAX; its `__thiscall` passes `this` on
     the stack), so the row records **no** calling convention rather than a
     false `__cdecl`. A model name is claimed only when the evidence is
     exactly that model's leading registers. Ordering follows a model that
     covers every observed register, else the register file's offsets.
- Both spec encodings are handled: an installed spec names registers
  (`<register name="ECX"/>`), a dumped bundle gives storage (`<addr>` for
  parameter entries, `<varnode>` for register sets). The dumped form was the
  reason the first implementation recovered nothing.
- Measured (`benchmarks/reports/m4-001.json`): `i386_many_o2` prototype arity
  **0.0000 -> 1.0000** against DWARF, one row improved, **no row lost
  arity**, and with the flag off every row still equals the frozen baseline.
  Provenance on the recovered facts reads
  `native-prototype:register-input(ECX)`.
- Off by default: II.1 reserves enabling an M4 pass, so default output is
  byte-identical and `benchmarks/reports/m3-003.json` still records the
  deficit.
- Verification: `cargo test --workspace` 193 pass; `tests/corpus.sh` 5/5;
  `tests/differential.sh`, `tests/m3-001_dwarf_truth.py`,
  `tests/m3-002_baseline.py`, `tests/m3-003_regression.py`,
  `tests/m4-001_register_params.py` pass.

## M5 implementation slices
- m5-001: Game Boy Advance cartridge ROMs, scored against DWARF.

### m5-001 evidence
- `0a2131c` commits the failing acceptance (`tests/m5-001_gba.py`), which the
  loader then had to satisfy: the ROM was first mis-detected as a DOL.
- `crates/romwright-core/src/native/gba.rs` loads a cartridge only on positive
  evidence -- the fixed 0x96 at 0xB2 (gbatek "Cartridge Header") **and** an
  unconditional ARM branch at offset 0 whose target lands inside the image.
  It maps ROM at 0x08000000, seeds the branch target as the entry, and
  declares EWRAM/IWRAM/IO/palette/VRAM/OAM (gbatek "Memory Map") as
  byte-less regions, so discovery cannot walk into RAM that the image does
  not contain. Six unit tests pin the refusals: missing fixed byte,
  conditional branch, branch past the image end, backward branch below ROM.
- Fixture built from committed source (`tests/fixtures-src/gba_rom.c`,
  `gba_header.S`, `gba_rom.ld`) with clang/lld: an ELF twin carrying DWARF
  and a 420-byte raw ROM. The Nintendo logo bytes are deliberately **not**
  reproduced -- they are the BIOS's check, not the loader's.
- Measured (`benchmarks/reports/m5-001.json`): 7 functions recovered from
  flow alone, **`dwarf.fn.recall` 1.0000 over 6 DWARF functions, 0
  unattributed entries**, entry resolved to 0x08000158 from the header
  branch, and native decompilation verified on a recovered function
  (`int FUN_080000c0(int param_1){return param_1 * 3 + 1;}` against the
  source's `x * 3 + 1`).

### Two defects this platform exposed, both affecting every non-x86 language
- **Injections were unreachable without a JVM.** In raw-SLEIGH mode
  `ArchitectureGhidra::buildPcodeInjectLibrary` returned the client-served
  library, which asks the caller for every payload
  (`inject_ghidra.cc:56` of the pinned tree). A JVM-free worker cannot
  answer, so **any** language whose semantics use an injection failed to
  decompile at all: ARM `bx` emits `CALLOTHER setISAMode`, and every
  function that returned that way produced an empty document with exit 0.
  `native/ghidra-opt-sleigh.patch` now installs `PcodeInjectLibrarySleigh`
  in raw mode, which compiles `<callfixup>`/`<callotherfixup>` bodies from
  the loaded compiler spec. Diagnosed by reading the payload the decompiler
  returned: `Low-level Error: Could not retrieve injection: setISAMode`.
- **Exported compiler specs lost those bodies.** `CompilerSpec.encode`
  cannot reproduce a compiled `InjectPayload`, so `dump_specs` wrote
  `<body> local tmp:1 = 0; </body>` placeholders. With injections now
  compiled locally, a placeholder would silently make ARM `bx` a no-op, so
  the bridge copies the language's compiler spec file verbatim
  (`SleighCompilerSpecDescription.getFile()`, verified in
  `.ghidra-java/ghidra/app/plugin/processors/sleigh/`), and the platform
  gate fails if a bundle still carries a placeholder. All five committed and
  generated bundles were re-exported.
- Consequence handled, not hidden: editing the bridge moved
  `bridge_sources_sha256`, so all 21 committed oracles and their scoring
  views were regenerated. **Entry sets are identical in all 21**, and the
  frozen ground-truth baseline was re-recorded with **no metric row
  changed** (1 640 functions, arity 0.753659).
- Verification: `cargo test --workspace` 199 pass; `tests/differential.sh`
  PASS (x86-64 token parity with the bridge survives the spec change);
  `tests/corpus.sh` 5/5; `tests/workflow.sh`, `tests/data_xrefs.sh`,
  `benchmarks/prototype_gate.py` (all four languages), `tests/m1-009_dol.py`
  (e500), `tests/m3-001_dwarf_truth.py`, `tests/m3-002_baseline.py`,
  `tests/m3-003_regression.py`, `tests/m5-001_gba.py` pass.

### m5-002 evidence
- `d70e5fd` commits the failing acceptance (`tests/m5-002_nds.py`); the
  container was first mis-detected as a DOL.
- `crates/romwright-core/src/native/nds.rs` reads the documented CPU descriptors
  (gbatek "DS Cartridge Header", 0x20 for ARM9 and 0x30 for ARM7) and
  accepts a cartridge only when every declared region fits the file, the two
  images do not overlap, each entry lands inside its own image, and each load
  address is where gbatek says that CPU's code runs. Seven unit tests pin the
  refusals: size past the file end, entry outside its image, an address in
  the GBA cartridge window, overlapping images, an image inside the header.
- **One container now yields two programs.** A program holds one language and
  the two processors do not share one, so `native::load_container` runs
  discovery per image and `Core::import_container` stores `<name>.arm9`
  (`ARM:LE:32:v5t`) and `<name>.arm7` (`ARM:LE:32:v4t`). The CLI prints a
  line per program; the API keeps the booted program at the top level and
  lists every program under `programs`, so no existing consumer breaks.
  Signature passes run per program and the reports are summed.
- Two address-basis defects surfaced and were fixed at the root:
  1. The worker's default load base came from the *file*, so a second
     processor's addresses were unmapped. It now comes from the program's own
     image-backed store regions -- a cartridge has two bases, and only the
     store knows which program a request is for.
  2. `ProgramImage` mapped the container's first image regardless of which
     program was being read; it now selects the image whose mappings contain
     the requested base. A platform's *declared* windows are excluded from
     base selection, since they carry no bytes.
- Measured (`benchmarks/reports/m5-002.json`): **`nds.arm9` recall 1.0000
  over 5 DWARF functions, `nds.arm7` 0.7500 over 4, zero unattributed
  entries on both**, entries seeded from the header, and a recovered function
  from each CPU decompiled natively.
- The ARM7 miss is recorded, not smoothed: `mix` is entered only by a tail
  call, so nothing references its entry. **Stock Ghidra misses it on the same
  stripped bytes too** (measured this session: it recovers 037f8008,
  037f8010, 037f8030 and absorbs 037f8000 into the caller's extent). The gate
  pins that address and verifies it is unreached code inside the image, so a
  new miss fails while the known one stays named.
- Verification: `cargo test --workspace` 206 pass; `tests/corpus.sh` 5/5;
  `tests/differential.sh`, `tests/workflow.sh`, `tests/data_xrefs.sh`,
  `tests/m1-004_pie.sh`, `tests/m1-005_pe_relocs.sh`,
  `tests/generic_discovery_test.sh`, `tests/m2-015_native_default.py`,
  `tests/m5-001_gba.py`, `tests/m5-002_nds.py` pass.

### m5-003 and m5-004 evidence
- `9f1b42d` and `4718d75` commit the failing acceptances
  (`tests/m5-003_psx.py`, `tests/m5-004_n64.py`); both images were first
  mis-detected as DOLs.
- `crates/romwright-core/src/native/psx.rs` reads the documented PS-EXE fields
  (psx-spx "Executables": magic, initial PC at 0x10, destination at 0x18,
  size at 0x1C) and accepts an image only when the declared size is in the
  file, the destination is main RAM through one of the three MIPS segment
  windows, and the initial PC lands inside the image. Seven unit tests pin
  the refusals, including the uncached mirror being *accepted* at 0xa0000000.
- `crates/romwright-core/src/native/n64.rs` reads the PI configuration word and the
  boot address (n64brew "ROM header") and maps the game code after the
  0x1000-byte header and boot area. IPL3 is not interpreted or reproduced --
  that code is Nintendo's. **Byte-swapped dumps are refused with their
  reason**: the JVM-free worker reads the file's own bytes, so mapping a
  `.v64` would decompile reordered instructions. Seven unit tests pin that
  and the other refusals.
- Measured (`benchmarks/reports/m5-003.json`, `m5-004.json`): PS-EXE
  **recall 1.0000 over 5 DWARF functions on `MIPS:LE:32:default`**; N64
  `.z64` **recall 1.0000 over 5 on `MIPS:BE:64:64-32addr`**; zero
  unattributed entries on both; entries seeded from the headers; a recovered
  function decompiled natively on each.
- Spec bundles vendored for the new languages: `MIPS-LE-32-default` and
  `MIPS-BE-64-64-32addr`, exported verbatim by the m5-001 exporter fix.

### A pinned SLA could silently decompile the wrong language
- Found while running the platform gates in a shell that exported
  `ROMWRIGHT_SLA` for the x86-64 workflow -- as this repo's own tests and docs
  do. `language_decompile_config` treated the pin as absolute, so an ARM or
  MIPS program was decompiled with the **x86-64** decoder, producing
  plausible-looking nonsense and a `DataUnavailError` at a garbage address
  (`0xffffffffe71f901b`).
- The pin now applies only to the language it pins; a program whose language
  differs resolves from the install instead. Verified by re-running all four
  platform gates plus `tests/differential.sh` and `tests/workflow.sh` with
  `ROMWRIGHT_SLA` exported: all pass, and the x86-64 parity path is unchanged.

### m5-005 evidence
- `db1ad45` commits the failing acceptance (`tests/m5-005_platform_matrix.py`).
- **The four console rows in the README support matrix are now generated
  from the platform's own gate report**, not written by hand. Each of
  `benchmarks/reports/m5-00{1,2,3,4}.json` carries a `platform` block
  (input label, family, test path, and one entry per imported program with
  its language, DWARF recall, function count and recorded deficits), and
  `scripts/gen_support_matrix.py` renders the row from those fields.
- The generator rewrites the block between `<!-- support-matrix:begin -->`
  and `<!-- support-matrix:end -->`, which is what lets it emit the
  supported table and the blocked table in one pass.
- **A support claim with no measurement cannot be printed.** Verified by
  three negative controls, each of which fails the gate: hard-coding the
  recall in the generator, removing the tier-1 evidence check, and
  rendering a failed gate as gated. Deleting a report removes its row
  rather than leaving a stale claim.
- `docs/platform-tiers.json` records the five blocked platforms with the
  fact that stops each one and where that fact was checked in Ghidra 12.1.3:
  PSP (zero `allegrex`/`vfpu` matches under `Ghidra/Processors`), PS2
  (`mips.ldefs:127` names r5900 only as an IDA-PRO alias; no MMI mnemonics
  in any `MIPS/data/languages/*.sinc`), PS3 SPU (no SPU processor directory
  at all), Xbox 360 (`ppc_common.sinc:150` defines vs0..vs63 and nothing
  matches `vmx128`), and encrypted Vita/3DS containers (no keys here, and
  AGENTS.md II.1 reserves the network call that would fetch them).
- Fixed while landing this: **the m0-010 staleness gate was red** from
  m5-001 onward, because the console rows were hand-added to a generated
  table. `tests/support_matrix_test.py` and `tests/m5-005_platform_matrix.py`
  both now pass and both run in the CI `support matrix` step.

### m5-006 evidence
- `5509ed8` commits the failing acceptance (`tests/m5-006_tailcall.py`).
- **A branch that leaves its function is now a recorded reference.** The
  transfer into `nds.arm7`'s `mix` (`037f802c -> 037f8000`) was invisible:
  no reference of any kind existed for it. It is now an
  `UNCONDITIONAL_JUMP` row with provenance `native-import:branch`.
- **The kind follows Ghidra, verified in the pinned sources.**
  `SharedReturnAnalysisCmd.processFunctionJumpReferences:376-425` applies a
  `CALL_RETURN` flow override when an unconditional jump leaves its function
  for another function's entry, and skips the override when the branch
  instruction is itself a function entry (the thunk case). Romwright now
  records the first as `UNCONDITIONAL_CALL` and the second as
  `UNCONDITIONAL_JUMP`. One pass decides the kind of every branch-derived
  reference, including rows the thunk pass produced, so the model cannot
  disagree with itself.
- The pass runs after every pass that can still create a function, and is
  idempotent, because "is the target a function" has no stable answer until
  then. This was found by measurement, not review: deciding the kind inside
  the flow walker mislabelled 5 of 20 corpus entries.
- Measured against the stock-Ghidra oracle over the 20 locked ELF inputs
  (`benchmarks/reports/m5-006.json`), kind-exact:
  `flow_xref.jump.precision` **1.0000**, `flow_xref.jump.cross_recall`
  **1.0000**, `flow_xref.call.precision` **1.0000**,
  `flow_xref.call.recall` **0.9830** (1735 / 1765, up from 1730 before this
  task -- the five thunk rows Ghidra calls calls).
- Four new additive metric names (`flow_xref.*`); no II.3 definition changed.
- Negative controls, each failing the gate: recording every branch as a jump
  (`jump.precision` 0.4412), disabling the pass (the `mix` transfer
  disappears), and rendering loops as transfers (the fixture's two loop
  branches).
- `crates/romwright-core/src/native/discovery/tests.rs` renamed and re-pointed:
  its landing-prefix fixture is exactly the x86-64 `endbr64; jmp target`
  shape the oracle records as a call, so its old expectation pinned
  non-parity behaviour.

### m5-007 evidence
- `0c38cb3` commits the failing acceptance
  (`tests/m5-007_tailcall_promotion.py`).
- Promotion is **off by default** (`ROMWRIGHT_PROMOTE_TAILCALLS`): stock Ghidra
  creates none of these functions, so the pass moves output past the frozen
  baseline and II.1 reserves enabling it. The gate asserts both states.
- A candidate faces the m1-005 evidence standard, not the branch alone: code
  and image-backed, not inside a body another entry proved, and its own flow
  decoded from the entry to a terminator without running into another
  entry (`proven_body_end`). The extent stored is the one that walk proved.
- Measured (`benchmarks/reports/m5-007.json`): `nds.arm7` recall
  **0.7500 -> 1.0000** (recovers `mix`, a leaf entered only by `b`), zero
  invented functions on either NDS CPU, and the promoted function
  decompiles. Over the 20 locked ELF inputs with the flag on: **0
  unattributed**, no row below the committed m3-001 recall, and **0
  promotions** -- every transfer in that corpus already lands on a known
  function, so the corpus is a safety check, not the evidence of gain.
- Coverage split, stated because it is uneven: the acceptance pins the flag,
  the outcome and corpus safety; the *refusals* are pinned by
  `promotion_refuses_targets_without_their_own_evidence` and
  `a_proven_tail_call_target_is_promoted_only_when_asked` in
  `crates/romwright-core/src/native/discovery/tests.rs`. Removing the evidence walk
  fails those two unit tests and no Python gate, which is why they exist.
- Negative controls: forcing the flag on fails the acceptance ("promoted with
  the flag off"); removing the evidence walk fails the unit tests.

### A stale binary passed four shell gates
- `tests/data_xrefs.sh` required an `UNCONDITIONAL_JUMP` row in `tiny_bin`.
  After m5-006 that transfer is a call (its target is a function), so the
  requirement was stale -- and stock Ghidra records no unconditional-jump
  reference in that image either. It now requires the kinds Ghidra records,
  and jump references are scored against the oracle by m5-006 instead.
- The reason m5-006 landed without noticing: `data_xrefs.sh`, `corpus.sh`,
  `differential.sh` and `generic_discovery_test.sh` all ran
  `target/debug/romwright-cli` **without building it**, so they tested whatever
  binary happened to be there. All four now build the CLI they test.

### m5-008 evidence
- **The ARM7 tail call must not be a thunk.** Answered from the pinned
  sources before any code: `CreateThunkFunctionCmd.getThunkedAddr` walks from
  the entry, and `getFlowingAddrFromFinalState` (lines 763-828) returns a
  thunked address only when every register the body set is later used or
  hidden (`setRegisters.size() == 0`). `nds.arm7`'s stub computes and leaves
  its result in a register for the callee, so stock Ghidra records no thunk
  there -- and neither does Romwright. Pinned by
  `a_computing_tail_call_is_not_a_thunk`, with the promotion flag both off
  and on.
- **The existing count comparison was hiding a real difference.**
  `benchmarks/thunk_gate.py` compares thunk counts on one host libc: 107
  against 107. The sets differ by thirteen entries in each direction, and the
  equality was arithmetic, not agreement.
- `01c1798` commits the failing set-level acceptance
  (`tests/m5-008_thunk_parity.py`). It failed three times on the way in,
  each time naming real missing facts: PowerPC stubs, PowerPC PIE stubs, then
  the i386 PIE stubs that the pinned deficit list had wrongly conceded.
- **Fix:** `infer_data_references` already proved which imported slot a stub
  reads -- that is how the stub gets its import name -- but recorded no thunk
  fact, so every stub whose slot is only known from propagated evidence
  (PowerPC glink, i386/PowerPC PIE stubs through a GOT register) was named
  and not thunked. It now records the linkage thunk from the same evidence.
  `promote_linkage` records one too, for the stubs it promotes.
- Measured (`benchmarks/reports/m5-008.json`), 20 locked ELF inputs plus the
  host libc: `thunk.entry.recall` **1.0000 (185/185)**,
  `thunk.entry.precision` **1.0000**, `thunk.entry.unexplained` **0**,
  `thunk.destination.unexplained` **0**; 114 destinations equal, 71 explained
  by the EXTERNAL-block hop, 13 stub-for-slot entries explained by symbol
  (the same thirteen symbols on both sides -- proven, not assumed:
  `{our slot names} == {their EXTERNAL-block names}`).
- Recall was 0.7582 before the fix (69/91 on the corpus alone).
- Negative control: pointing a linkage thunk at `0xdead0000` fails the gate
  as an unexplained destination on three rows.
- Two additive metric families (`thunk.entry.*`, `thunk.destination.*`); no
  II.3 definition changed, and `benchmarks/thunk_gate.py` is untouched -- its
  count comparison stays as the m2-009 artifact it is, now with a set-level
  gate beside it.

### m5-009 evidence
- `20e58ff` commits the failing acceptance
  (`tests/m5-009_linkage_names.py`): five stubs across `i386_plain_pie` and
  `powerpc_plain_pie` carried `FUN_...` names while the store already held
  the import symbol at that exact address.
- `name_linkage_stubs` applies the name the linkage thunk's slot proved, and
  **replaces only a generated name** -- a symbol or section-derived name
  stands (`linkage_naming_replaces_only_generated_names`).
- Measured (`benchmarks/reports/m5-009.json`), 20 locked ELF inputs, scored
  against stock Ghidra's own name at every thunk entry it records inside the
  image: 71 of 91 names equal, 20 classified, **0 import names left
  unapplied**, **0 names without a symbol at their own address**.
- The 20 remaining differences are all `_INIT_n`, Ghidra's label for an entry
  of `.init_array`. That class is accepted only when our store holds the
  reference the label presents (`native-import:elf-pointer`, or
  `native-import:elf-reloc` for a PIE), so a missing fact cannot hide behind
  a naming difference.
- Negative controls: reverting the pass fails the gate on exactly the five
  rows; making the pass invent `import_<address>` names fails it too, because
  a name needs a symbol at its own address.
- One additive metric family (`linkage.name.*`); no II.3 definition changed.

### m5-010 evidence
- `ee2f3e1` commits the failing acceptance
  (`tests/m5-010_initializer_names.py`).
- `collect_initializer_labels` reads `DT_INIT_ARRAY`, `DT_PREINIT_ARRAY` and
  `DT_FINI_ARRAY` with their sizes from the dynamic table, takes each target
  from the slot's own word or from the relocation applied to that slot, and
  takes the index from the slot's position -- the construction Ghidra uses in
  `ElfProgramBuilder.createDynamicEntryPoints:690-750`. `_INIT_<i>`,
  `_PREINIT_<i>`, `_FINI_<i>`, applied only over a generated name.
- **The gate grew past its own charter, on purpose**: comparing every
  function name (not just initializer targets) against stock Ghidra is the
  same work, and it turns "the last name class" into a measurable claim.
  Measured (`benchmarks/reports/m5-010.json`) over 20 locked ELF inputs:
  **1818 of 1903 names equal**, 74 proven-equivalent labels, 11 pinned
  pattern labels, **0 unexplained**. Every function name in the store is now
  accounted for against stock.
- Proven-equivalent means the same address named from a different source, and
  each is proven by reading the header, the dynamic table or the section
  table: `_entry` for `e_entry`, `_init`/`_fini` for `DT_INIT`/`DT_FINI`
  (Ghidra says `_DT_INIT`), `_plt` for the `.plt` section start where Ghidra
  leaves `FUN_`.
- The 11 pinned rows are `__i686.get_pc_thunk.*`, which stock takes from a
  `<funcstart label=...>` entry in `x86gcc_patterns.xml`. Romwright already
  reads those pattern files for function starts; applying their labels is
  m5-011.
- Forced cutover: `tests/m5-009_linkage_names.py` accepted `_INIT_n` as a
  label Ghidra applies and we do not. That class is now closed, so its
  support rule accepts a derived initializer name **only** when the store
  holds the reference from that array slot, and its "presentation class is
  untested" assertion is gone -- the class is empty by construction.
- Unit tests: `initializer_arrays_name_their_targets_by_index` builds a
  synthetic ELF32 with two init entries and one fini entry and asserts the
  indices; `initializer_labels_replace_only_generated_names` pins that a
  symbol name stands and a label for no function is dropped.

### m5-011 evidence
- `215b910` commits the failing acceptance
  (`tests/m5-011_pattern_labels.py`).
- The label was already in hand: `ConsoleSession::function_patterns` collects
  `<funcstart label=... validcode="function">` names, and
  `send_reference_fixups` installs a call fixup at each one. The name was
  never written to the store. `pattern_labels()` exposes the same list,
  discovery records it on the import, and `apply_pattern_labels` applies it
  to a function with a proven body and a generated name.
- Measured (`benchmarks/reports/m5-011.json`), 20 locked ELF inputs: **11
  labels applied, all agreeing with stock Ghidra's name at the same
  address**, 0 missing, 0 spurious. The gate checks both directions against
  the bytes -- bytes matching a labelled pattern must carry its name, and a
  function carrying a pattern label must have those bytes at its entry.
- Negative control: making the pass label the first generated function
  instead of the matched address fails the gate on the row whose bytes no
  longer line up.
- `tests/m5-010_initializer_names.py` now pins **no** pattern-label rows, so
  every function name on the corpus is either equal to stock or a
  proven-equivalent label: **1829 of 1903 equal, 74 equivalent, 0
  unexplained.**
- Forced cutover: `tests/m5-009_linkage_names.py` treats a pattern label as
  supported only when the caller proves the pattern matched at that address,
  rather than accepting the shape of the name.
- Unit test `pattern_labels_need_a_body_and_a_generated_name` pins that a
  one-byte stub and a symbol-named function are both left alone.

### m5-012 evidence
- **The recorded premise for this task was wrong, and checking it came
  first.** The previous "next task" said `gate.sh` reads
  `benchmarks/thunk_gate.py`'s report. It reads none of the reports: nothing
  in the repository consumed them. What was actually missing is an index --
  65 report files with no map from evidence to claim.
- `1979953` commits the failing acceptance
  (`tests/m5-012_evidence_index.py`).
- `scripts/gen_evidence_index.py` generates a README table from the committed
  reports: report file, gate id, milestone, status, the numbers the report
  itself carries, and the file that produces it. Rows are derived -- a
  measured number moves its row, deleting a report removes it, and a report
  recording a failure makes the generator refuse rather than print it.
  `--check` fails on a stale index, wired into the fast CI job.
- **Twelve reports recording `passed: false` were sitting next to current
  evidence.** They are intermediate diagnostic runs (`m2-002-g1..g7`,
  `m1-010-d4d-*`, `m1-008b`, `m2-002-context`, `m2-002-f5`); they moved to
  `benchmarks/reports/diagnostics/` with `git mv`, so the history stays and
  the claim does not. A failing report at the top level now fails the gate.
- Reports with no `passed` field are recorded state, not verdicts -- frozen
  baselines, corpus manifests, per-architecture measurements. The index says
  `recorded` for those rather than implying a gate held.
- **An unpublished measurement was found by the coverage rule**:
  `tests/m2-015_native_default.py` writes a report that had never been
  committed. It is now `benchmarks/reports/m2-015.json`, and the gate
  requires every acceptance test that writes a `--report` to have a committed
  report carrying its id.
- Measured (`benchmarks/reports/m5-012.json`): 55 current reports indexed, 40
  published ids, 12 diagnostic runs separated, 54 generated rows.

### m6-001 evidence
- `b9d7054` commits the failing acceptance
  (`tests/m6-001_documented_workflow.py`).
- `docs/getting-started.md` walks from `cargo build` to a decompiled
  function on the committed fixture. **The page is executed, not described**:
  every `$ ` line in a ```console block runs exactly as written and every
  output line under it must appear in what the command prints.
- Measured (`benchmarks/reports/m6-001.json`): 18 documented commands run,
  22 documented output lines checked, 24 CLI verbs all listed in usage.
- **The gate is run in both environments.** With the SLEIGH console: 18
  commands, 0 skipped. Without the pinned install
  (`ROMWRIGHT_GHIDRA=/nonexistent ROMWRIGHT_CONSOLE=/nonexistent`): 13 commands,
  2 SLEIGH-marked blocks skipped. That forced the walkthrough to stop
  claiming environment-dependent numbers: the console proves `printf`'s
  linkage stub, flow-proven extents and the call reference into `add`, so
  the same import reports 12 functions and 2 references with it and 11 and 1
  without. The page states that difference and gates the larger numbers
  behind the marker instead of averaging them.
- **The CLI's own usage text was incomplete**: `xrefs`, `undo`, `open`,
  `comment`, `comments` and `types` were dispatched and unlisted. They are
  documented now, and the gate fails whenever a dispatched verb is missing
  from usage or the walkthrough uses a verb the CLI does not dispatch.
- Negative controls, each failing the gate: a wrong documented output line, a
  walkthrough command the CLI does not dispatch, and a verb removed from the
  usage text.

### m6-002 evidence
- `3d6d764` commits the failing acceptance
  (`tests/m6-002_documented_api.py`).
- `docs/core-api.md` documents the envelope (`api`, `id`, `method`,
  `params`), the four error codes, typed addresses, fact provenance, the
  paged-read shape, and which requests need the SLEIGH console. Every
  documented exchange is sent to a real `romwright-api` process and the documented
  response must be a **subset** of the real one, so a documented field that
  does not exist fails.
- Measured (`benchmarks/reports/m6-002.json`): 10 exchanges with the console,
  8 with 1 SLEIGH block skipped when the pinned install is absent.
- Negative controls: a wrong field value and an invented field both fail.

### A live defect the page found
- The `function` field of a reference -- the function containing the source
  address -- named **`_init` for a call inside `main`**, and named `_init`
  for a reference from data that has no containing function at all.
- Cause: the SQL predicate `f.entry <= x.src AND x.src < f.entry + f.size`
  compared a hex text column with an integer expression. SQLite coerced
  `'0040033c'` to the decimal 40033, so the containment test compared
  unrelated numbers and the `LIMIT 1` returned whichever row the scan reached
  first. The same subquery was in all five xref accessors, including
  `xrefs_page`, which the desktop uses.
- Fixed by parsing the addresses: `function_extents` reads the extents once
  and `resolve_containing` finds the function whose `[entry, entry+size)`
  holds the source, leaving `None` when none does. Pinned by
  `xref_names_the_function_that_contains_its_source`, which asserts a source
  inside `main`, a source in data, and a source one byte past `main`'s end.

### m6-003 evidence
- `7427641` commits the failing acceptance
  (`tests/m6-003_desktop_package.py`).
- **`ui.install.ok` was never measured.** `gate_runner.cpp` read it from
  `qEnvironmentVariableIsSet("ROMWRIGHT_UI_INSTALL_OK")`, and
  `tests/package_install_smoke.sh` sets that variable itself -- the gate
  asserted a value its own harness supplied.
- Two additive metrics now measure what the old one claimed, both computed by
  the app: `ui.install.prefix_ok` (the executable is not running from a build
  tree: no `CMakeCache.txt`/`CMakeFiles` beside it or one level up) and
  `ui.install.store_only_ok` (the store-facing workflow completed with **no**
  `ROMWRIGHT_*` variable set). A new `--gate --store-only` mode stops after
  import, list and filter, so a packaged run needs no SLEIGH data.
- The gate builds the CPack archive with the three commands
  `docs/desktop.md` documents, asserts the page documents those targets,
  extracts the archive into a clean prefix, refuses an archive member that
  escapes it, and launches the extracted binary offscreen with every
  `ROMWRIGHT_*` variable stripped from the environment.
- Measured (`benchmarks/reports/m6-003.json`): `romwright-0.5-Linux-x86_64.tar.gz`
  on Linux/x86_64 with Qt 6.11.2, `ui.install.prefix_ok` true,
  `ui.install.store_only_ok` true, `ui.list.load_ms` 1.96 and
  `ui.list.filter_ms` inside the M0 thresholds. **The report names its own
  platform**, so single-machine evidence cannot read as three-OS evidence;
  the CI `qt` job runs it on Linux, macOS and Windows and uploads each report.
- Negative controls, run against the same binary: the build-tree executable
  reports `ui.install.prefix_ok: false`, and setting any `ROMWRIGHT_*` variable
  reports `ui.install.store_only_ok: false`.

## Proposed changes (reserved for the human)
- **New II.3 metric: instruction match rate.** Definition for approval, not
  in use: for one function, emit C, compile it with a named toolchain and
  flags, disassemble both the compiled object and the original image over that
  function's extent, normalise (drop symbol names, resolve branch targets to
  offsets within the function, keep mnemonic + operand shape), and score
  `matched_instructions / truth_instructions`, plus `matched_functions` at
  rate 1.0000. It needs no oracle and no JVM: the ground truth is the image
  itself, which makes it the strongest metric in the repo -- stronger than
  DWARF recall or oracle token identity, both of which measure agreement with
  a tool. Inputs it pins: the toolchain identity and flags per corpus row, the
  normalisation rules, and the extent source (the store's recovered body).
  II.1 reserves adding a metric definition, so nothing here is implemented.
- **Proposed milestone (M11), first task is the harness, not the emitter.**
  Task one scores *current* `decomp_native` output on the locked corpus and
  commits the number, however low. Only then is the emitter question
  answerable: Ghidra's `PrintC` is already a C backend, and what breaks
  matching is the pipeline before it -- the simplifying actions and the
  printer's cosmetic choices -- both of which this repo already reaches
  through `native/ghidra-opt-sleigh.patch` and the action pool. So the first
  candidate is a *constrained emission mode* of the existing backend behind a
  flag, in the shape the M4 passes already use (`ROMWRIGHT_REGISTER_PARAMS`,
  `ROMWRIGHT_PROMOTE_TAILCALLS`, off by default per II.1): keep the
  transformations soundness requires, drop the ones that discard
  instruction-level structure, name locals after ABI storage, spell stack
  slots explicitly. A second emitter is only unavoidable for what a mode
  cannot do -- per-toolchain idioms if suppression proves too invasive, and
  emitting anything that is not C, which is the real fork: matching projects
  fall back to per-function inline asm or `.s` for what will not match, and
  "C or nothing" is not the contract. Which side of that fork is needed is a
  measurement, not a judgement.
- **Clean-room note for that milestone.** `m2c` (MIT) is the documented
  precedent for the technique. Under the clean-room policy the *approach* is
  citable with a `docs/third-party.md` entry recording the licence; its code
  is never linked or copied.
- Retire `ui.install.ok` from the M0 UI gate. It reports whether
  `ROMWRIGHT_UI_INSTALL_OK` is set, not whether an installation works, and
  `ui.install.prefix_ok` plus `ui.install.store_only_ok` (m6-003) measure the
  fact instead. AGENTS.md II.1 reserves metric-definition changes, so the
  metric and `benchmarks/reports/ui-gate.json` are untouched;
  `tests/package_install_smoke.sh` still passes because it still sets the
  variable. Removing it means deleting the metric from
  `benchmarks/ui_gate.py`'s `ALL_METRICS`, the `qEnvironmentVariableIsSet`
  read in `desktop/romwright-qt/src/gate_runner.cpp`, and the `ROMWRIGHT_UI_INSTALL_OK`
  export in the smoke test, then re-recording the UI gate report.

### m6-004 evidence
- **The recorded premise was wrong again, and checking came first.** The
  previous "next task" said `RELEASING.md` describes the steps: no such file
  exists. What existed was three CI steps -- an SBOM, an update manifest over
  `LICENSE` alone, and a verification of that one-file manifest. No release
  artifact set was ever produced or checked.
- `c7a75d0` commits the failing acceptance
  (`tests/m6-004_release_artifacts.py`).
- `docs/releasing.md` documents build, stage, SBOM, manifest and verify; the
  gate runs those nine commands and then checks the results, so a documented
  step that stops working fails here.
- `packaging/stage_release.py` copies whatever the build produced (`.exe`
  suffixes, the CPack archive named after system and processor) and fails on a
  missing binary rather than staging a partial set.
  `packaging/update_manifest.py` now accepts a directory, manifesting every
  file below it and excluding its own output, so the artifact list cannot
  drift from what was staged.
- Measured (`benchmarks/reports/m6-004.json`): 9 documented commands on
  Linux/x86_64, **5 artifacts manifested and verified**, tampering and
  truncation both rejected, SBOM covering 60 packages including every
  workspace crate with a declared licence.
- Negative controls: dropping one workspace crate from the SBOM fails
  (`the SBOM omits workspace crates: ['romwright-worker']`), and neutering
  `verify_update.py` fails (`a flipped byte in romwright-api passed verification`).
- CI cutover: the three placeholder packaging steps are replaced by this
  gate, so the SBOM and manifest are now checked against real artifacts.
- The page states what is not claimed: no reproducibility (two builds are not
  asserted byte-identical) and no signing (digests, not signatures). Tagging
  stays reserved to the human per II.1.

### m6-005 evidence
- `0367538` commits the failing acceptance (`tests/m6-005_scripting.py`).
- `docs/scripting.md` shows `examples/facts_report.py` driving a project
  through `python/romwright_sdk.py`: import, read the functions, write a rename,
  undo it. The gate runs the documented command **in two environments** --
  with the SLEIGH console and with every `ROMWRIGHT_*` variable stripped --
  because the page claims the script runs either way, and matches all four
  output lines in both.
- The gate also compares the page against the client. **Twelve helpers were
  undocumented**: `comment`, `types`, `type_fields`, `type_graph`,
  `trace_events`, `append_trace_event`, `collaboration_ops`,
  `append_collaboration_op`, `apply_collaboration_op`, `debug_backtrace`,
  `debug_registers`, `debug_memory`. All 23 are now in a table on the page,
  and a helper the client grows without the page fails the gate.
- The example script demonstrates three things worth copying, each verified by
  the gate's output match: addresses arrive typed and are unpacked rather than
  assumed; the containing function is **computed from the extents by the
  script**, because the store answers with what it proved; edits are
  journalled, so a script can undo its own work.
- Measured (`benchmarks/reports/m6-005.json`): 1 documented command run twice,
  8 output lines checked, 23 client helpers all documented.
- Negative controls: a wrong documented output line, an undocumented helper
  added to the client, and the script dropping one printed line all fail.
- Found while writing the loader: a module executed through
  `importlib.util.spec_from_file_location` must be registered in
  `sys.modules` before `exec_module`, or a `@dataclass` inside it cannot
  resolve its own annotations.

### m6-006 evidence
- `483311d` commits the failing acceptance
  (`tests/m6-006_documentation_coverage.py`).
- Three rules, all derived from the repository rather than from a list in the
  test:
  1. **Surfaces are enumerated, not listed.** The workspace's `bin` targets
     (`cargo metadata`), the desktop `add_executable` target, the modules
     under `python/` and the scripts under `packaging/` -- 13 surfaces -- must
     each be named by `README.md` or a page under `docs/`.
  2. **Command blocks are covered block by block.** A `console`/`json` block
     must sit on a page a gate executes; an `sh`/`bash` block must carry
     `<!-- not gated: reason -->` **even on a gated page**, because a page
     that a gate names would otherwise hide new blocks. 5 pages gated, 30
     blocks excused with a recorded reason.
  3. **No page cites a metric no report carries.** 79 metric names are
     collected recursively from the committed reports (they nest under
     `metrics`, `totals`, `checks`, and pass-specific blocks such as
     `optimized_bounds.before`), and a citation counts as a metric only when
     its parent path is one a report uses -- so `ghidra.dwarf.fn.recall` is
     checked and the Java package `ghidra.program.model.listing` is not.
- Found and fixed: `docs/desktop.md` showed its build in a bare fence, so the
  coverage rule read it as a record while `tests/m6-003` was in fact running
  those commands; it is now a `console` block and m6-003 reads the `$ `
  prefix. 29 command blocks in `README.md` and `docs/toolchains.md` had no
  statement of why nothing runs them; each now carries its reason.
- A loophole I had to close in my own gate: naming a page inside this test
  marked it covered, so the gate excludes its own source when checking.
- Negative controls, each failing: a stale metric citation
  (`ui.install.retired_metric`), a new `sh` block on an already-gated page, a
  removed reason, and a surface renamed out of every page.

## M6 state
- Documentation is complete and gated: `docs/getting-started.md` (workflow),
  `docs/core-api.md` (wire protocol), `docs/desktop.md` (packaged desktop),
  `docs/releasing.md` (artifacts, SBOM, manifest), `docs/scripting.md` (SDK),
  each executed by its own acceptance, plus `m6-006` stating what coverage
  means. Reports: `m6-001` .. `m6-006`.
- Every gate in the repository is indexed in the README evidence table
  (`m5-012`), 61 current reports and 60 rows, regenerated and checked in CI.

### m7-001 evidence
- `cf01a48` commits the failing acceptance
  (`tests/m7-001_cost_envelope.py`): the envelope did not exist yet.
- Both producers import the **same 20 locked ELF entries**, measured the same
  way with `os.wait4` -- its `ru_maxrss` covers the process and the children it
  waited for, the accounting `baseline-stock.json` documents for the stock
  launcher. Before this, cost was measured on one tiny fixture and never
  compared per entry.
- Measured (`benchmarks/reports/m7-001.json`), median over 20 entries:
  `cost.native.peak_kb.median` **36 034 KiB** against
  `cost.stock.peak_kb.median` 418 976 KiB, and
  `cost.native.wall_s.median` **0.26 s** against
  `cost.stock.wall_s.median` 8.21 s -- **12.39x less memory, 29.35x faster**.
  Per entry the gate requires the native import to peak lower *and* finish
  sooner than stock analysis; both hold on all 20.
- `benchmarks/reports/cost-envelope.json` records the native peak per entry
  once and is never edited (`--write` refuses to overwrite). The gate allows
  25% headroom for host noise, so a regression is a failure rather than a new
  number.
- Stated in the README beside the table: stock analysis runs Ghidra's full
  chain, so this compares the two **default paths**, not identical work; what
  each produces is compared by `m3-001` and the differential gates.
- Negative controls: shrinking one envelope entry fails
  (`aarch64_cpp_o2: (36328, 1280)`), deleting an entry fails, and `--write`
  over an existing envelope fails.
- Six additive metric names (`cost.*`); no II.3 definition changed.

### m7-002 evidence
- `790146b` commits the failing acceptance
  (`tests/m7-002_decompile_envelope.py`): the envelope did not exist yet.
- Both producers decompile **`main` resolved by name** in each locked entry's
  unstripped twin, so no address is guessed and PIE image bases cannot make
  the two disagree about what was decompiled. Import and analysis run first
  and are **not** timed -- `romwright-cli import` for the native path, an
  `analyzeHeadless -import` that analyses and saves for stock. Each timed run
  opens the stored program and decompiles one function
  (`analyzeHeadless -process -noanalysis -postScript scripts/DecompileOne.java`,
  options verified in `.ghidra-java/ghidra/app/util/headless/AnalyzeHeadless.java`;
  `getGlobalFunctions`, `DecompInterface.decompileFunction` and
  `DecompiledFunction.getC` verified in the extracted sources).
- Measured (`benchmarks/reports/m7-002.json`), median over 20 entries:
  `decompile.native.peak_kb.median` **34 594 KiB** against
  `decompile.stock.peak_kb.median` 286 368 KiB, and
  `decompile.native.wall_s.median` **0.091 s** against
  `decompile.stock.wall_s.median` 5.933 s -- **8.32x less memory, 74.03x
  faster**. Per entry the gate requires the native decompile to peak lower
  *and* finish sooner; both hold on all 20.
- Output is asserted, not assumed: the native run must print a body
  containing `main(`, and the stock script must report a non-empty `getC()`.
- `benchmarks/cost.py` now holds the one definition of the measurement and of
  the write-once envelope rule; `m7-001` was moved onto it and re-verified
  (12.09x memory, 29.7x wall), so the two gates cannot drift apart.
- Negative controls: shrinking one envelope entry fails
  (`aarch64_cpp_o2: (34848, 1280)`), deleting an entry fails, `--write` over
  an existing envelope fails, and asking for a function the store does not
  have fails.
- Six additive metric names (`decompile.*`); no II.3 definition changed.

### m7-003 evidence
- `602ff06` commits the failing acceptance
  (`tests/m7-003_session_envelope.py`): the envelope did not exist yet.
- One long-lived `romwright-api` process per locked entry answers the same seven
  requests (`functions`, `symbols`, `strings`, `memory_regions`, `search`,
  `xrefs`, `decompile_doc`) for 4 warm-up and 8 measured rounds, with the
  **process tree**'s resident size -- the service plus the SLEIGH console
  child -- sampled every 25 ms through `/proc`.
- Measured (`benchmarks/reports/m7-003.json`): `session.peak_kb.median`
  42 940 KiB, `session.growth_kb.max` **28 KiB** across eight measured
  rounds, `session.latency_ms.functions.median` 0.265 ms,
  `session.latency_ms.decompile_doc.median` 6.002 ms.
- **The first draft's drift rule was measuring the warm-up, not a
  regression.** `decompile_doc` on the PowerPC entries settles 33 ms -> 7 ms
  -> 3.3 ms over four rounds, so a two-versus-three-round median comparison
  failed in both directions depending on where the descent landed. Fixed by
  measuring four warm-up rounds separately and excluding them from both the
  plateau baseline and the drift comparison; four consecutive runs then pass.
- **The reported drift number was also self-contradictory**: a passing run
  printed `9.06x`, because a 0.15 ms read moving to 0.37 ms is a large ratio
  and no regression. `session.drift_ratio.max` now counts only methods whose
  early median is at least the 2 ms floor, and
  `session.drift_excess_ms.max` (-0.863 ms) says how far the worst method is
  from failing, so the number a passing run prints cannot look alarming.
- Rules per entry: peak inside the recorded envelope; growth across measured
  rounds within `max(4 MiB, 5%)`; not strictly increasing every round unless
  total growth is under 512 KiB; each method's late-round median within twice
  its early-round median plus 2 ms.
- Negative controls: a synthetic 1 MiB-per-round leak fails
  (`grew 7168 KiB across 8 measured rounds`), an eightfold late-round
  slowdown fails (`strings slowed from 0.38ms to 3.08ms`), shrinking an
  envelope entry fails, deleting one fails, `--write` over an existing
  envelope fails.
- Eleven additive metric names (`session.*`); no II.3 definition changed.

### m8-001 evidence
- `38e2469` commits the failing acceptance (`tests/m8-001_pe_unwind.py`):
  recall on `tiny_pe.exe` was **0.5667**, 39 of 90 DWARF functions missing --
  `WinMainCRTStartup`, `__do_global_ctors`, `__mingw_TLScallback` and the rest
  of the CRT, none of them reachable by flow from the entry point.
- `crates/romwright-core/src/native/pe_unwind.rs` reads
  `IMAGE_DIRECTORY_ENTRY_EXCEPTION` (data directory 3, AMD64 only -- ARM
  records have a different layout, as Ghidra's own dispatch shows) and
  promotes `ImageBase + BeginAddress` for every non-chained
  `RUNTIME_FUNCTION`, emitting a `native-import:pe-unwind` reference from the
  record that proved it. Rule and layout verified in
  `.ghidra-java/ghidra/app/util/bin/format/pe/ImageRuntimeFunctionEntries_X86.java`
  (`beginAddress != 0 && (unwindInfo == null || !hasChainedUnwindInfo())`) and
  `PEx64UnwindInfo.java` (`version = b & 0x7`, `flags = (b >> 3) & 0x1f`,
  `UNW_FLAG_CHAININFO = 0x4`).
- Measured (`benchmarks/reports/m8-001.json`): `pe.dwarf.fn.recall`
  **1.0000** over 180 DWARF functions across `tiny_pe.exe` and
  `dispatch.exe`, `pe.dwarf.fn.unattributed` **0**, 192 `RUNTIME_FUNCTION`
  records. The support-matrix row for PE32+ now derives from this report
  instead of from `stage4-gate.json`, which runs on the tiny ELF fixture.
- **Truth had to be read differently, not redefined.** `m3-001` projects DWARF
  through `readelf`, which refuses a PE outright; this gate reads the same
  concrete `DW_TAG_subprogram` low PCs through `llvm-dwarfdump` and restricts
  them to executable sections the same way.
- **Two of my own controls were vacuous and one attribution class was wrong.**
  Nulling the whole unattributed predicate "passed", which proved nothing;
  when the class was actually removed, `dispatch.exe`'s three static
  dispatch-table targets appeared, because `llvm-nm` lists only external
  symbols for a PE. Symbols now come from the COFF symbol table via
  `llvm-objdump -t`, storage class included -- the PE equivalent of
  `readelf -sW`.
- Attribution is two classes, both measured: DWARF-described, or COFF-named.
  Dropping the symbol class fails 29 entries. Being bounded by a
  `RUNTIME_FUNCTION` and being a store-proven thunk were both measured inert
  and deleted rather than kept as decoration.
- Neither gated fixture carries a chained record (95 and 97 records, all
  plain), so `UNW_FLAG_CHAININFO` is pinned by a unit test in `pe_unwind.rs`
  and not claimed from these images.
- PE32 x86 recorded, not gated: recall 0.8065 with 31 unattributed entries and
  no exception directory to confirm any of them.
- Six additive metric names (`pe.*`); no II.3 definition changed.

## Reserved decisions
- **Extending the corpus with MinGW PE entries is reserved (II.1, "adding or
  removing a corpus binary, target game, or platform").** `scripts/gen_corpus.py`
  can build PE only through MSVC, which needs Windows and `cl`; this host has
  MinGW-w64 16.1.1 for `x86_64-w64-mingw32` and `i686-w64-mingw32`, which
  emits PE carrying DWARF, so ten locked PE entries (5 variants x 2
  architectures, with a DLL standing in for the ELF `plain_pie` slot) are
  buildable. **Approved 2026-09-11; landed partially:** `pe64` (x86_64) is
  locked with 4 rows (no `cpp_o2`: no mingw cc1plus on this host, no
  sudo to install `mingw64-gcc-c++`, so C++ stays unbuildable here) and
  scores 1.0 native / >=0.989 stock under m3 with 0 unattributed, and
  1.0 under the folded m19-001 (locked rows, no gate-time build) after
  PE import-stub recovery (IAT `jmp` stubs as named linkage entries;
  REX-prefixed matches rejected as mid-instruction); `pe32`
  builds but sits below m3's floor (0.80-0.97, a jmp-only-reached CRT
  chain with no unwind tables on SJLJ 32-bit -- same tail-call rule
  family as m5-007) and stays out of the lock and default build until
  that rule lands. `expected_variants` is now a per-arch matrix.

### m8-002 evidence
- `c9a1201` commits the failing acceptance (`tests/m8-002_pe32_roots.py`):
  **31 recovered entries on `tiny_pe32.exe` had no evidence at all.**
- They were case labels inside `___mingw_pformat`. A PE32 switch table holds
  absolute addresses, so every case carries a base relocation, and a
  relocation into code is what the importer treats as a candidate function.
  The container's own walk never reaches them: the transfer is indirect.
- **Two rules were tried and rejected by measurement before the third.**
  Containment in a proven body retracted six real functions
  (`_gnu_exception_handler`, `_dtoa_lock_cleanup`, ...) and every retraction
  was attributed to one absurd container -- `00401c80` with a span of
  `00401c80..00408796`, 27 KB across dozens of functions -- so the rule had no
  discriminating power at all. Requiring branch-target evidence retracted
  nothing, because the labels are reached only indirectly.
- The rule that holds is a property of function bodies: **two functions cannot
  share code.** The cases' chains interleave through the switch's shared tail,
  so one case's flow-proven span runs past the next case's start, while a real
  function's span abuts its neighbour's without overlapping it. Overlapping
  data-derived spans are retracted unless a call reaches them; a loader-declared
  seed is never touched. Unit test:
  `overlapping_relocation_candidates_are_case_labels_not_functions`.
- Measured (`benchmarks/reports/m8-002.json`): `pe32.dwarf.fn.recall`
  **0.8065** over 93 DWARF functions with `pe32.dwarf.fn.unattributed`
  **0** (from 31), against `ghidra.dwarf.fn.recall` **0.7634** on the same
  stripped image. Recall is unchanged by the retraction -- no real function
  was lost -- and the gate requires native >= stock rather than a number
  chosen here.
- All 18 remaining misses are classified against the image: 8 reachable only
  through a symbol the strip removed, 10 reached only through an indirect
  transfer. An unclassified miss fails the gate.
- Regression: `cargo test --workspace` 232 pass, `corpus.sh`,
  `differential.sh`, `workflow.sh`, `data_xrefs.sh`,
  `m1-005_pe_relocs.sh`, `generic_discovery_test.sh`, `m3-001`, `m3-003`,
  `m5-008`..`m5-011` all pass, so the retraction changed no ELF result.
- Four additive metric names (`pe32.*`); no II.3 definition changed.

### m8-003 evidence
- `d3182b6` commits the failing acceptance (`tests/m8-003_body_extents.py`):
  three PE images had a body swallowing 78, 78 and 69 other entries --
  `FUN_00401c80` claimed **27 KB** of `tiny_pe32.exe`.
- Two defects, both fixed:
  1. A proven span is the furthest instruction attributed to an origin, so one
     fallthrough across inter-function padding stretched it over everything
     after it. A body now ends where the next entry begins: two functions
     cannot overlap.
  2. `store_import` filled any size `<= 1` from the distance to the next
     entry, which **overwrote a proven one-byte body** -- the MinGW CRT's
     one-instruction `__mingw_invalidParameterHandler` was given 1023 bytes
     and swallowed `__tmainCRTStartup` and `WinMainCRTStartup` whole. Size
     zero now means "no body proven" and is the only thing the store fills.
- Measured (`benchmarks/reports/m8-003.json`) over 23 images and 1895 bodies
  matched to a DWARF range: `body.crossing` **0**, `body.exact`
  **0.9873**, 19 within one 16-byte alignment slot, 1 running into an
  undiscovered function, `body.undershoot` 4, `body.unexplained_overshoot`
  **0**.
- Every deviation is classified against the image, not tolerated. An
  overshoot may run into **one** undiscovered DWARF function and stop inside
  it -- that is the `m8-002` recall deficit in bytes -- while crossing a
  second start or running past the end of the one it entered fails. A body
  may stop short only when no entry starts and no reference lands in the bytes
  it left behind; the four that do are C++ landing pads, reached by the
  personality routine rather than by a branch.
- **Both fixes are gated, and I checked that.** Removing the next-entry clamp
  fails with the 27 KB bodies; restoring the `size <= 1` fill fails with
  `00401000 to 00401400 (+1023)`. The first draft of the overshoot rule passed
  with the sentinel bug restored, which is why the rule now bounds the
  overshoot to a single function.
- Regression: `cargo test --workspace` 232 pass; `corpus.sh`,
  `differential.sh`, `workflow.sh`, `data_xrefs.sh`, `m1-005`, `m1-006`,
  `generic_discovery_test.sh`, `m8-001`, `m8-002`, `m2-015`, `m6-001`,
  `m6-002`, `m3-001`, `m3-003`, `m4-001`, `m5-008`..`m5-011` all pass.
- Eight additive metric names (`body.*`); no II.3 definition changed.

### m8-004 evidence
- `4de643e` commits the failing acceptance (`tests/m8-004_pe_roots.py`) and one
  new fixture, `tests/fixtures-src/exports32.dll` with its source: an i686
  MinGW DLL exporting three functions that nothing inside the image calls.
- `crates/romwright-core/src/native/pe_roots.rs` reads two directories, both
  verified in the pinned sources:
  - **TLS callbacks** (`TLSDirectory`, `TLSDataDirectory.markup`):
    `AddressOfCallBacks` is the fourth pointer-sized field and holds
    **virtual addresses**; at most 20 slots are walked and the first null ends
    the array.
  - **Exports** (`ExportDataDirectory.parse`, `PeLoader.processExports`): a
    slot holding RVA 0 is a gap in the ordinal space, and an RVA *inside* the
    export directory is a forwarder naming another library -- a string, not
    code. Every other export becomes a function carrying the name the image
    publishes.
- Measured (`benchmarks/reports/m8-004.json`): **8 TLS callbacks** and
  **3 exports** across four fixtures, each with the reference that named it
  (`native-import:pe-tls`, `native-import:pe-export`) and each export named as
  published.
- **The measurement came before the claim.** The three DLL exports were
  recovered by nothing beforehand -- stripped or unstripped -- because the
  importer reads no COFF symbol table. The TLS callbacks *were* already
  recovered, but only because a base relocation pointed at them: a relocation
  says a pointer lives in that slot, the directory says what the pointer is,
  so the reference is **upgraded** rather than duplicated.
- This closes **no** PE32 recall gap, and the report says so. Of the 18 misses
  `m8-002` classified, 2 (`__tmainCRTStartup`, `__do_global_ctors`) are
  reached only by an unconditional jump from discovered code -- the tail-call
  promotion II.1 reserves and m5-007 decided stays off -- and the other 16
  carry no reference of any kind in the store; stock Ghidra misses them too.
- No committed fixture exports a forwarder, so that rule is pinned by the unit
  test `exports_carry_their_name_and_skip_gaps_and_forwarders` rather than
  claimed from an image.
- Controls: removing the TLS pass fails (`tls_unproven`), removing the export
  pass fails (`exports_missing`), and dropping the exported name fails
  (`misnamed`).
- Regression: `cargo test --workspace` 235 pass; `corpus.sh`,
  `differential.sh`, `workflow.sh`, `data_xrefs.sh`, `m1-005`,
  `generic_discovery_test.sh`, `m8-001`, `m8-002`, `m8-003`, `m2-015`,
  `m3-001`, `m5-008`, `m5-011` all pass.
- Nine additive metric names (`pe.tls.*`, `pe.exports.*`); no II.3 definition
  changed.

## Reserved decision, now with numbers
- **Promoting tail-call targets by default** (II.1: "enabling any M4 pass by
  default rather than behind a flag"; m5-007 recorded it off). On
  `tiny_pe32.exe` it would recover `__tmainCRTStartup` and
  `__do_global_ctors`, raising `pe32.dwarf.fn.recall` from 0.8065 to 0.8280,
  still with `pe32.dwarf.fn.unattributed == 0`, because both are proven by an
  `UNCONDITIONAL_JUMP` from code already discovered. Stock Ghidra creates
  neither. **Not done: waiting on your decision.**

### m8-005 evidence
- `9c970fc` commits the failing acceptance (`tests/m8-005_pe_imports.py`):
  `tiny_pe32.exe` imported into a store holding **zero symbols**.
- `pe_roots::collect_imports` reads `IMAGE_DIRECTORY_ENTRY_IMPORT` by the
  pinned rules (`ImportDataDirectory.parse`, `ImportDescriptor`, `ThunkData`):
  20-byte descriptors ending when `OriginalFirstThunk` and `FirstThunk` are
  both zero; the name table is `OriginalFirstThunk` when it maps and
  `FirstThunk` otherwise; the walk ends at the first zero entry; the ordinal
  flag (`1 << (width*8 - 1)`) names `Ordinal_<n>`; otherwise the value is an
  RVA to `IMAGE_IMPORT_BY_NAME`, whose name follows a **two-byte hint**. The
  address an import occupies is its IAT slot.
- Measured (`benchmarks/reports/m8-005.json`): **166 imports** across four
  fixtures from 8 library references, every one an external symbol at its IAT
  slot named as imported, `pe.imports.misnamed` 0,
  `pe.imports.unnamed_stubs` 0.
- **The naming came for free, which was the point.** Populating `externals`
  let the existing format-agnostic `name_linkage_stubs` name the PE import
  stubs, so `tiny_pe32.exe` now shows `__set_app_type`, `_initterm`, `_cexit`
  instead of `FUN_...` -- 81 symbols and dozens of `linkage` thunks, the same
  shape `m5-009` gives ELF. No second convention was added.
- An IAT slot holds a pointer, so nothing is promoted to code there; the unit
  test `imports_name_their_iat_slots_by_name_and_by_ordinal` pins that, and it
  is what a bound image (`TimeDateStamp != 0`, slots already resolved) would
  otherwise invite.
- Controls: dropping the pass fails (`missing`), and reading the name without
  skipping the two-byte hint fails (`missing`, with names shifted off).
- The library a symbol came from is recorded in the report, not in the store:
  neither format models it, ELF externals carry a bare name too. Stated in
  the README rather than left implied.
- Regression: `cargo test --workspace` 236 pass; `corpus.sh`,
  `differential.sh`, `workflow.sh`, `data_xrefs.sh`, `m1-005`, `m8-001`,
  `m8-002`, `m8-003`, `m8-004`, `m2-015`, `m3-001`, `m5-008`, `m5-009` all
  pass.
- Seven additive metric names (`pe.imports.*`); no II.3 definition changed.

### m8-006 evidence
- `707b9d9` commits the failing acceptance (`tests/m8-006_pe_parity.py`):
  three of the four PE evidence classes had **no committed report naming
  them** -- `pe-unwind`, `pe-tls` and `pe-export` were asserted by gates that
  never recorded which class they proved.
- The classes are read from the importer's own vocabulary (the
  `native-import:pe-*` provenance strings in `crates/romwright-core/src`), then
  checked three ways: every class must be **exercised** by a committed
  fixture, **measured** by a committed report other than this one, and the
  five milestone claims must each exist, pass, and carry their metric.
- Fixed by having `m8-001` and `m8-004` record `provenance_proven` -- the
  classes their own stores prove -- instead of a boolean.
- Measured (`benchmarks/reports/m8-006.json`): 4 declared classes, 0
  unexercised, 0 unmeasured, **865 references** and **260 external symbols**
  across the four PE fixtures.
- Controls: a declared-but-unproduced class fails
  (`native-import:pe-fake`), stripping a class from *every* report fails, and
  a report whose `passed` turns false fails. Removing one of several holders
  passes, which is correct: redundant coverage is still coverage.
- **M8 is closed.** PE32+ recall 1.0000 with 0 unattributed; PE32 recall
  0.8065 against stock 0.7634 with 0 unattributed and every miss classified;
  body extents 0 crossing and 0.9873 exact; 8 TLS callbacks and 3 exports from
  the directories that declare them; 166 imports named through the same
  linkage path ELF uses.
- Five additive metric names (`pe.classes.*`, `pe.references`,
  `pe.externals`); no II.3 definition changed.

### m9-001 evidence
- `dad2bfe` commits the failing acceptance
  (`tests/m9-001_provenance_explained.py`): there was no table to fail
  against -- `romwright-cli provenance` did not exist, and the desktop's xrefs dock
  had **no provenance column at all**, so a user could not learn what a base
  relocation proves.
- `crates/romwright-model/src/provenance.rs` holds one table: 15 classes, each a
  sentence. `FactProvenance` now serialises `explanation` from it via a
  hand-written `Serialize`, so every API and CLI consumer receives the
  sentence with the fact and no construction site has to remember it.
- Surfaces read that table rather than copying it: `romwright-cli provenance
  [<program>] [--json]` prints it (or only the classes one program holds and
  fails on an unexplained one), and `XrefsDock` renders the sentence in an
  Evidence column with the raw class as tooltip.
- **The desktop number is measured.** `XrefsDock` counts the rows it filled
  and how many arrived without a sentence, emits `loadFinished` when both
  tables have answered, and `GateRunner` publishes `ui.xrefs.rows` and
  `ui.xrefs.unexplained`; `benchmarks/ui_gate.py` takes the worst run for
  counts (min rows, max unexplained) and fails the gate on either.
  First attempt read the counters from a zero-delay timer and measured an
  empty table -- fixed by waiting for the signal.
- Measured (`benchmarks/reports/m9-001.json`): 15 classes in the table, 15
  declared in the crates, 11 observed in stores over four corpus entries and
  four PE fixtures, `provenance.unexplained` **0**, 10 facts checked through a
  real `romwright-api`, and the desktop rendered 19 xref rows with **0**
  unexplained.
- Controls: deleting one class's sentence fails, a UI report claiming three
  unexplained rows fails, and a UI report that stops measuring the metric at
  all fails.
- `crates/romwright-db` had a test pinning the exact provenance JSON; it now pins
  the new shape, including `explanation: null` for a source the table does not
  know.
- Regression: `cargo test --workspace` 237 pass; `corpus.sh`,
  `differential.sh`, `workflow.sh`, `data_xrefs.sh`, `m6-001`, `m6-002`,
  `m6-005`, `m6-006`, `m8-006`, `m5-012` all pass.
- Seven additive metric names (`provenance.*`, `ui.xrefs.*`); no II.3
  definition changed.

### m9-002 evidence
- `02576c4` commits the failing acceptance
  (`tests/m9-002_fact_confidence.py`): no class said what kind of evidence it
  was, so nothing could be held to a standard.
- **No probability was invented.** Each class declares one of the three kinds
  the importer actually has -- `declared` (the image or platform states it),
  `decoded` (SLEIGH decoded the instruction that performs it), `inferred` (a
  pass concluded it) -- in the same table as its sentence, exposed as
  `provenance.evidence` through the API, `romwright-cli provenance`, and the
  desktop's Evidence tooltip.
- Two measured rules, over the locked corpus and the four PE fixtures:
  a `declared` class must attribute **1.0000** of the entries it names
  (4536 references over 7 exercised declared classes, the eighth --
  `native-import:platform-map` -- exercised by `m5-001`, which now records its
  region sources); and no fact may carry a numeric `confidence` its class does
  not derive (`evidence.unbacked_confidence` **0** over 4665 promoted
  references).
- Attribution follows `m3-001`: DWARF truth, a twin symbol, a linker-stub
  section, or a name the store proved. That last class was found by
  measurement -- five i386 references pointed at `__i686.get_pc_thunk.bx`,
  named by a pattern label `m5-011` already gates, and nothing else attributes
  them.
- `confidence` stays `null` for native facts because nothing derives one; the
  only derivation in the tree is `romwright-sig`'s share of compared bytes. A
  `declared` class claiming a number fails a unit test: a header either says a
  thing or it does not.
- **A control caught a hole in my own gate.** Downgrading
  `native-import:pe-unwind` to `inferred` first *passed*, because fewer
  declared classes meant fewer to hold at 1.0000. Kinds are now recorded in
  `benchmarks/reports/evidence-classes.json`, appended with `--write` and
  never rewritten in place; the same downgrade now fails
  (`recorded declared, table says inferred`).
- Regression: `cargo test --workspace` 238 pass; `m9-001`, `m9-002`,
  `m5-001`, `m6-001`, `m6-002`, `m6-005`, `m6-006`, `m8-006`, `m5-012`,
  `support_matrix_test.py`, `corpus.sh`, `differential.sh`, `workflow.sh`,
  `data_xrefs.sh` all pass.
- Six additive metric names (`evidence.*`); no II.3 definition changed.

### m9-003 evidence
- `da0c44e` commits the failing acceptance
  (`tests/m9-003_evidence_filter.py`): `evidence` was ignored, so a filtered
  page returned the unfiltered rows.
- `symbols_page` and `xrefs_page` now take `evidence` (`declared`, `decoded`,
  `inferred`) through `romwright-api`, `romwright-core`, `romwright-db` and the Qt bridge. The
  `IN (...)` clause is built from `provenance::sources(kind)`, so the filter
  is the same table the API reports on each fact and cannot drift from it.
- Measured (`benchmarks/reports/m9-003.json`): over 5 images and 20
  addresses, each of the three kinds returns **exactly** the unfiltered rows
  of that kind -- 104 references and 135 symbols -- with the filtered `total`
  counting filtered facts, `revision` unchanged, two half-pages reassembling
  the set in order, and an unknown kind refused as `invalid_params`.
- The narrowed count is the point: a total that counted facts the page cannot
  return would be a lie about the page. The control that makes the total
  ignore the filter fails (`total is 2 for 0 filtered facts`), and the control
  that answers an unknown kind instead of refusing it fails.
- Documented where paging is documented (`docs/core-api.md`), with both
  exchanges executed by `m6-002` -- which caught my first draft claiming
  `total: 1` where the real answer is 2.
- Regression: `cargo test --workspace` 238 pass; `m9-001`, `m9-002`,
  `m9-003`, `m6-001`, `m6-002`, `m6-005`, `m6-006`, `m8-006`, `m5-012`,
  `support_matrix_test.py`, `m2-015`, `corpus.sh`, `differential.sh`,
  `workflow.sh`, `data_xrefs.sh` all pass.
- Five additive metric names (`filter.*`); no II.3 definition changed.

### m9-004 evidence
- `debef96` commits the acceptance (`tests/m9-004_filter_surfaces.py`). Its
  first meaningful failure was the desktop metric it needs
  (`KeyError: ui.xrefs.declared_rows`); the CLI flag landed in the same
  session slightly ahead of its test, so its rule is proved by a control
  instead: making the CLI drop the filter fails
  (`the terminal shows 1 rows, the API returns 0`).
- `romwright-cli xrefs --evidence declared|decoded|inferred` routes through
  `xrefs_page`, so the terminal and the service share one filter; filtering
  with no address is refused rather than answered, and an unknown kind exits
  non-zero.
- `XrefsDock` carries an evidence selector (All/declared/decoded/inferred)
  that reloads through the store. `GateRunner` measures the filtered window --
  `ui.xrefs.declared_rows` -- and publishes `ui.xrefs.address`, the address the
  window actually navigated to.
- **That address is why the first draft proved nothing.** The gate compared the
  service's answer at an address it chose, while the window had navigated to
  the first function it listed: 0 declared against 0 declared, which passes and
  means nothing. The window now reports its address and the gate reads it, and
  also checks the window's unfiltered count against the service.
- Measured (`benchmarks/reports/m9-004.json`): 12 rows matched between the
  terminal and the service across three kinds, **2 addresses where a kind
  narrows the set** (so an accepted-and-ignored flag fails), an unknown kind
  refused. On `libc` the committed UI gate records **13 declared of 19 rows**,
  which is the window narrowing on a real binary.
- Controls: a CLI that drops the filter fails; a UI report claiming more
  declared rows than rows fails.
- Documented where a user meets it: `docs/getting-started.md` runs the
  filtered command (executed by `m6-001`, 19 commands, 23 output lines) and
  `docs/desktop.md` describes the selector with the gate's numbers.
- Regression: `cargo test --workspace` 238 pass; `m9-001`..`m9-004`,
  `m6-001`, `m6-002`, `m6-003`, `m6-005`, `m6-006`, `m5-012`,
  `support_matrix_test.py`, `corpus.sh`, `differential.sh`, `workflow.sh`,
  `data_xrefs.sh` all pass.
- Five additive metric names (`surface.*`, `ui.xrefs.declared_rows`,
  `ui.xrefs.address`); no II.3 definition changed.

### m9-005 evidence
- `840f002` commits the failing acceptance
  (`tests/m9-005_explanation_milestone.py`).
- The surfaces are enumerated from the repository and then driven: the API
  methods `docs/core-api.md` publishes, the verbs `romwright-cli` prints in its own
  usage (bare, not `--help`, which it does not accept), and the window the UI
  gate measures.
- Measured (`benchmarks/reports/m9-005.json`): **28 of 52** published methods
  answered on a real project with **0 silent facts**; **5** distinct sources
  printed by the terminal, all explained; the window rendered **13 declared
  rows with 0 unexplained**; the four M9 reports each exist, pass, and carry
  their metric.
- The single exemption is stated rather than implied: a fact a person asserted
  (`kind: asserted`) needs no sentence, because the person is the evidence.
- The 24 unanswered methods are those needing more than a program name; each
  is driven by the gate that owns it, and the report lists them with the error
  code they returned rather than dropping them.
- Controls: removing one class's sentence fails through the terminal
  (`native-analysis:constant-propagation` printed but unexplained), a window
  report claiming 2 unexplained rows fails, and flipping any of the four
  reports' `passed` fails the claim.
- **M9 is closed.** 15 provenance classes, each with a sentence and an
  evidence kind; no fact carries a number nothing derives; paged reads filter
  by kind with an honest total; the terminal and the window both filter, the
  window measured at the address it opened.
- Regression: `cargo test --workspace` 238 pass; `m9-001`..`m9-005`,
  `m8-006`, `m6-001`, `m6-002`, `m6-005`, `m6-006`, `m5-012`,
  `support_matrix_test.py`, `m2-015`, `corpus.sh`, `differential.sh`,
  `workflow.sh`, `data_xrefs.sh`, `generic_discovery_test.sh` all pass.
- Six additive metric names (`explanation.*`); no II.3 definition changed.

### m10-001 evidence
- `7747625` commits the failing acceptance (`tests/m10-001_multi_image.py`):
  `programs` was `unknown_method`, so nothing could say what a project holds.
- `ProjectDb::programs` lists every program with its language, function count
  and revision; `ProjectDb::locate` answers which programs map an address,
  with the region that maps it and the function containing it. Both reach
  `romwright-api` (`programs`, `locate`) and the terminal
  (`romwright-cli programs`, `romwright-cli locate <hex>`).
- **The interesting case is real, not synthetic.** A stripped `tiny_pe32.exe`
  and `tiny_bin` both map `0x00401000`, so an address alone names no program:
  `locate 00401000` returns `tiny` (`elf:8`, no function) and `win`
  (`pe:0`, `FUN_00401000`).
- Measured (`benchmarks/reports/m10-001.json`): **16 reads per program**
  (`functions`, `symbols`, `strings`, `memory_regions`, `thunks`,
  `return_behaviors`, `prototypes`, plus `symbols_page` window and total)
  identical to projects holding only that image, over **607 rows**; both
  programs listed; `locate` naming both at the overlap, one where only the ELF
  maps, none outside either; a malformed address refused.
- Each returned region is checked to hold the address, and each named function
  to belong to that program and contain the address -- the row cannot name a
  region or a function from the other image.
- Controls: a `locate` that ignores whether the region holds the address fails
  (`the named region does not hold the address`), and one that stops at the
  first program fails (`named ['elf']`).
- **A metric name collided with prose.** `project.programs` made
  `docs/assumptions.md`'s mention of `project.sqlite` look like a stale metric
  citation and failed `m6-006`; the metrics are `images.*` instead. The
  documentation gate caught it, which is what it is for.
- Regression: `cargo test --workspace` 238 pass; `m10-001`, `m9-001`..`m9-005`,
  `m8-006`, `m6-001`, `m6-002`, `m6-005`, `m6-006`, `m5-012`, `m3-001`,
  `support_matrix_test.py`, `m2-015`, `corpus.sh`, `differential.sh`,
  `workflow.sh`, `data_xrefs.sh` all pass. `m6-002` now drives 14 documented
  exchanges and `m6-001` checks 27 verbs.
- Four additive metric names (`images.*`); no II.3 definition changed.

### m10-002 evidence
- `1ff00c9` commits the failing acceptance
  (`tests/m10-002_image_navigation.py`): `--follow` printed nothing and the
  window listed no images.
- `romwright-cli locate <hex> --follow` prints, under each program mapping the
  address, that program's containing function, the symbols at the address and
  the references in each direction. The desktop has an **Images** selector
  filled from `programs`; choosing one points every dock at it.
- `programs` and `locate` were added to the Qt bridge as well as the API --
  the desktop speaks the in-process bridge, so an API-only method is invisible
  to it, which is why the window first reported 0 images.
- **A crash in the shipped app came out of this.**
  `MainWindow::search_edit_` was declared and never constructed, so
  `loadProgramPanels()` dereferenced null: opening a program, importing one,
  or switching images killed the window (`SIGSEGV` in `QLineEdit::text`). The
  Facts dock owns its own search box, so the field is deleted and the term is
  empty. An audit of the other 22 widget members found no second case.
- Switching no longer makes a bridge round trip: the name came from
  `programs`, so `switchProgram` points the docks at it directly. The gate's
  wait for the refreshed list is bounded at two seconds, because a selector
  that never switches must report what the list holds rather than hang the
  gate -- the first control run timed out at 240 s instead of failing.
- Measured (`benchmarks/reports/m10-002.json`): **8 facts** compared across
  two images at `00401000`, every number matching the service; the window
  listed **2** programs and held **112** functions after switching, against
  12 before.
- Controls: a `--follow` reading references from the first program for every
  row fails (`printed (..., '0', ...) where the service says (..., 1, ...)`),
  and a selector that lists images without switching fails
  (`the list held 12 functions where win has 112`). The first draft of the
  first control mutated the symbol lookup, where both images answer 0 -- it
  passed, and was replaced.
- Regression: `cargo test --workspace` 238 pass; `m10-001`, `m10-002`,
  `m9-001`..`m9-005`, `m6-001`, `m6-002`, `m6-003`, `m6-005`, `m6-006`,
  `m5-012`, `support_matrix_test.py`, `corpus.sh`, `differential.sh`,
  `workflow.sh`, `data_xrefs.sh` all pass.
- Four additive metric names (`images.ui_*`, `ui.programs`,
  `ui.programs_switch_functions`); no II.3 definition changed.

### m10-003 evidence
- `486c0f8` commits the acceptance (`tests/m10-003_edit_durability.py`), which
  **passed on its first run**: the store already scopes facts, revisions and
  the journal per program, so there was no defect to fix. That is recorded as
  what it is -- new coverage, not a repair.
- What it checks, after renaming a function and writing a comment in the first
  image and then importing a second into the same project: 8 reads identical
  for the first image with its revision unchanged at 9; the same 8 reads for
  the second image whether imported beside another program or alone; `undo` on
  the unedited image reversing nothing while the rename survives; and two
  undos on the edited image reversing `undid comment seq 2 at 00400466` then
  `undid rename seq 1 (00400466 -> add)`.
- **Three controls prove it would notice a regression**: an import that clears
  every program's functions fails
  (`changed the first image's ['functions']`), one that bumps every program's
  revision fails (`moved from 9 to 15`), and an `undo` that ignores which
  program asked fails (`undid comment seq 2` on the unedited image).
- **A fourth control passed and was replaced.** Making an import delete every
  comment changed nothing, because an import writes no comments -- the control
  exercised no path. It was replaced with the functions and revision controls,
  which do.
- One tautological assertion (`... or True`) written while drafting was
  removed rather than left to look like a check.
- Regression: `cargo test --workspace` 238 pass; `m10-001`..`m10-003`,
  `m9-001`..`m9-005`, `m8-003`, `m6-001`, `m6-002`, `m6-005`, `m6-006`,
  `m5-012`, `support_matrix_test.py`, `m2-015`, `corpus.sh`,
  `differential.sh`, `workflow.sh`, `data_xrefs.sh`,
  `generic_discovery_test.sh` all pass.
- Three additive metric names (`edits.*`); no II.3 definition changed.

### m10-004 evidence
- The gate enumerates its own subject: it scans every dispatch arm in
  `crates/romwright-api/src/lib.rs` that reads `params.program` -- **41 methods** --
  and fails when one is driven nowhere. That is the hole the milestone had.
- Measured: 54 reads answered identically in a two-image project and in a
  project holding that image alone (13 of 26 read methods tell the images
  apart, the rest answer equal-and-empty and are listed); 14 writes left the
  other image byte-identical across all 27 reads while each showed its own
  effect on the program it named; 4 writes are recorded inert on this fixture
  with the reason and the reads that must stay empty.
- **Five controls fire**: a read ignoring which program asked
  (`tiny.open, tiny.functions, tiny.function_graph` and the `win` three), a
  write landing in every program (`set_bookmark on tiny changed win's
  ['bookmarks']`), a new undriven arm (`probe_undriven`), a carried gate that
  stops passing (`m10-003: report does not pass`), and an active write excused
  as inert (`set_bookmark -> ['bookmarks']`).
- Two drafting defects fixed before the gate could claim anything: an excuse
  for `import_native`, which the scan never claims because it names programs
  with `name`; and a collaboration op with an empty payload, which the store
  rejected -- it now carries the rename it replays, so applying it is a real
  write.
- Metric names moved from `project.*` to `images.*`: `m6-006` reads
  `project.sqlite` in `docs/assumptions.md` prose as a metric citation, and
  the collision made it fail. Same drift m10-001 hit.
- Regression: `cargo test --workspace` 238 pass; `m10-001`..`m10-004`,
  `m9-005`, `m8-006`, `m6-001`, `m6-002`, `m6-005`, `m6-006`, `m5-012`,
  `support_matrix_test.py`, `corpus.sh`, `differential.sh`, `workflow.sh`,
  `data_xrefs.sh` pass. 83 reports indexed, both README generators in sync.

## Current milestone
- M10 closed: multi-image projects are read (`m10-001`), navigated
  (`m10-002`), durable across a second import (`m10-003`), and published as
  one derived claim over all 41 program-taking methods (`m10-004`).
- M4 (C2, improvement over stock) now states its claim: `m4-002` derives it
  from the gates that measured it.

### m4-002 evidence
- The passes are enumerated from `RuntimeConfig::from_env`, so an opt-in pass
  with no gate behind it fails: **2 passes** (`ROMWRIGHT_REGISTER_PARAMS` ->
  `m4-001`, `ROMWRIGHT_PROMOTE_TAILCALLS` -> `m5-007`).
- Off by default is proved by facts, not by reading source: the register pass
  leaves **400** prototypes carrying `native-prototype:register-input` when
  asked and **0** with a clean environment; the promoted leaf `0x37f8000` is
  absent by default and present when asked.
- The C2 number, over 1640 DWARF functions on the 20 locked ELF rows: stock
  **1236**, native by default **1236** (equal, as II.1 requires while the
  passes stay off), native with the passes enabled **1637**
  ($0.7537 \to 0.9982$). Native is below stock on no row and no II.3 metric.
- The three arities neither producer recovers are `main`'s dead second
  parameter on x86-64, AArch64 and PowerPC: in the recovered body the ABI's
  second-argument register appears **0** times against 400, 801 and 802 reads
  of the first, so the image holds no evidence for it. The extent is the
  store's recovered size, not DWARF's, so the claim is about the image.
- **Six controls fire**: an ungated opt-in pass, a pass forced on by default,
  a flag wired to nothing, a row where native drops below stock, a residual
  whose register is read after all, and a carried gate that stops passing.
- **The gate failed its own first audit**: two controls passed because the
  behavioural checks ran a stale `target/debug/romwright-api`. The gate now builds
  what it measures -- the same trap `tests/differential.sh` records in its
  header.

### m4-003 evidence
- The gate enumerates the languages `native/specs` bundles (**9**) and, for
  each, either measures token identity against the JVM oracle on a committed
  corpus row or names a blocker it verifies. Report:
  `benchmarks/reports/m4-003.json`, pinned by
  `benchmarks/reports/parity-baseline.json`.
- Measured: **4 languages, 56 functions** compared both ways on the same
  stripped image. **18 token-identical**, 38 differing, **0 unexplained**.
  Per language: x86-64 4/12, x86-32 5/15, AArch64 5/17, PowerPC BE32 4/12.
- Every difference names its cause, and the counts are pinned so neither a
  regression nor an improvement passes unrecorded: `flow` 22,
  `missing-external-prototype` 19, `function-facts` 15,
  `missing-data-symbol` 8, `string-not-rendered` 4.
- **5 languages blocked**, all for the same reason: no ELF row exists for them
  in the corpus lock and adding one is II.1-reserved. The images that do exist
  are containers the oracle has no loader for -- verified by asking the oracle
  to load the GBA ROM and recording its refusal.
- **Four controls fire**: a divergence class that stops being recognised (the
  pinned classes move), a blocked language that gains a corpus row, a spec
  bundle nobody classified, and a container the oracle loads after all -- the
  last caught for real when the check first pointed at the ELF twin instead of
  the ROM.
- The support matrix now carries these numbers instead of "decompile parity
  pending"; `gen_support_matrix.py` derives them, and an `ELF x86-32` row was
  added because the corpus has i386 ELF rows and nothing reported them.
- Regression: `cargo test --workspace` 238 pass; `m4-002`, `m3-003`,
  `m10-003`, `m10-004`, `m9-005`, `m6-001`, `m6-002`, `m6-006`, `m5-012`,
  `support_matrix_test.py`, `corpus.sh`, `differential.sh`, `workflow.sh`,
  `data_xrefs.sh` pass. 86 reports indexed, both generators in sync.

### m4-004 evidence
- Two `m4-003` divergence classes are closed by passing facts the store
  already held: `string-not-rendered` **4 -> 0** and `missing-data-symbol`
  **8 -> 0**. Token identity against the oracle rose **18 -> 23** of 56, and
  no other class grew (`flow` 22, `missing-external-prototype` 19,
  `function-facts` 15 unchanged); `benchmarks/reports/parity-baseline.json`
  is re-recorded in this commit.
- What was missing was the `getMappedSymbols` answer for anything that is not
  a function: the worker replied empty, so the decompiler named locations
  itself (`cRam00000000002038f8`). It now answers, in the shapes the pinned
  tree decodes: `<symbol>` + `char[n]` for a stored string
  (`s_sum___d__002004d0`), `<symbol>` + pointer-to-`code` for a named import
  slot (`PTR_printf_002038f0`), and `<labelsym>` for a location only a data
  reference names (`DAT_002038f8`).
- Rules verified in the pinned sources, not guessed:
  `SymbolUtilities.DYNAMIC_PREFIX_ARRAY` (:84-86) and `getDynamicDataName`
  (:541-544) for the names, `PointerDataType.getLabelString` (:212-238) for
  the pointer form, `Scope::addMapSym` (database.cc:1564-1606) and
  `SymbolEntry::decode` (:206) for the framing, `LabSymbol` (:728-757) for the
  untyped case, and `TypeFactory::decodeType` (type.cc:4638-4666) for types.
- **Three defects found while wiring it**, each visible only by running the
  thing: the decompiler resolves `<typeref>` by **id**, so name-only
  references failed with `Unable to resolve type: char` and silently emptied
  the function -- the ids now come from the language's own `coretypes.xml`
  (`parse_core_types`, unit-tested against the shipped file). Data references
  live under kinds `DATA`, `READ` and `WRITE`, and filtering on `DATA` alone
  missed the byte `_FINI_0` guards. And the runtime launches
  `target/debug/romwright-worker`, so a release-only build measured a stale worker.
- Residual, now named rather than hidden: `data-type-unknown` 4 -- both sides
  name the location and only the oracle knows a pointer is there, because its
  analyzers define data and the native store records a reference. That is the
  next task's subject.
- Regression: `cargo test --workspace` **239 pass** (one new unit test);
  `m4-002`, `m4-003`, `m4-004`, `m3-001`, `m3-003`, `m2-005`, `m2-009`,
  `m5-009`, `m5-011`, `m6-002`, `m6-006`, `m5-012`, `support_matrix_test.py`,
  `m9-005`, `m10-004`, `corpus.sh`, `differential.sh`, `workflow.sh`,
  `data_xrefs.sh` pass. 87 reports indexed, both generators in sync.

### m4-005 evidence
- The largest divergence class shrinks: `flow` **22 -> 16**, and token
  identity against the oracle **23 -> 25** of 56, with no class growing
  (`function-facts` 15, `data-type-unknown` 4 unchanged;
  `missing-external-prototype` 19 -> 18).
- The store already held the fact and nothing carried it. A thunk's jump is
  now delivered as Ghidra's own `<flow type="callreturn">` override inside the
  function element (`Override::decode`, override.cc:356-400, types :421-433;
  accepted by `Funcdata::decode`, funcdata.cc:811). Measured effect:
  `_INIT_0` was `void _INIT_0(void){return;}` with its call discarded as two
  unreachable blocks and is now `void _INIT_0(void){FUN_00201600();return;}`,
  the oracle's text exactly; the `printf` linkage stub no longer asks for a
  jumptable.
- **The override had to travel through the preload, not the callback.** The
  decompiler never queries `getMappedSymbols` for a function it already has
  from `registerProgram`, so a function whose flow the store corrects is now
  sent whole instead of as a lazy shell.
- **The first rule was too broad and the measurement caught it**: overriding
  every stored transfer cost two token-identical functions on AArch64 and
  PowerPC. Ghidra sets no shared-return override when the jumping instruction
  is itself a function entry (`SharedReturnAnalysisCmd`:400-423); with that
  rule restored, and a linkage stub as the stated exception (its transfer goes
  through a slot the store names as an import), x86-64 gained one and x86-32
  gained one, with no losses anywhere.
- **Two controls fire**: not forwarding the store's thunk facts leaves
  `_INIT_0` with its call discarded, and ignoring Ghidra's entry rule moves
  the pinned per-language counts.
- Regression: `cargo test --workspace` 239 pass; `m4-002`..`m4-005`,
  `m3-001`, `m3-003`, `m2-009`, `m5-008`, `m5-009`, `m6-006`, `m5-012`,
  `support_matrix_test.py`, `corpus.sh`, `differential.sh`, `workflow.sh`,
  `data_xrefs.sh` pass. 88 reports indexed, both generators in sync.

### m4-006 evidence
- The PLT header's indirect jump is now a call the image's own ABI names. The
  System V psABI reserves the first three `DT_PLTGOT` words -- `.dynamic`,
  the link-map, the resolver -- so the instruction reading
  `DT_PLTGOT + 2 words` (here `002038e8`) transfers like a call. Measured: the
  header's decompilation went from two warnings ("Could not recover jumptable
  at 0x00201716", "Treating indirect jump as call") to
  `void _plt(void){(*PTR_002038e8)();return;}`, and `data-type-unknown`
  fell **4 -> 2**.
- **The first shape was wrong and a parity gate caught it.** Recording the
  transfer as a linkage *thunk* broke `m5-008`: stock Ghidra's thunk table is
  empty for this image, so the row was a fact stock records nowhere. What
  stock holds is a per-instruction flow override
  (`Instruction.getFlowOverride`), so the store now holds the same: schema 12
  adds `flow_overrides(address, kind, provenance)`, written by the importer as
  `native-import:plt-header` and read by the worker, which turns it into
  Ghidra's `<flow type="callreturn">`. `m5-008` passes again.
- Two controls fire: not reading `DT_PLTGOT` leaves the store with no override
  (`it holds []`), and firing on any data reference instead of the reserved
  slot corrects instructions that read nothing of the kind
  (`002015a8`, `002015d0`, ...) -- the gate now requires every override to
  read the slot, so a loose rule fails rather than passing wider.
- `m4-004` had to narrow with it: a slot the store knows holds a code pointer
  renders `PTR_002038e8`, not `DAT_002038e8`, so its selection excludes
  pointer slots and accepts `READ`/`WRITE` references, which is what Ghidra
  counts as a data reference anyway.
- Regression: `cargo test --workspace` **240 pass** (one new store test);
  `m4-002`..`m4-006`, `m3-001`, `m3-003`, `m2-009`, `m2-016`, `m5-008`..
  `m5-011`, `m6-001`, `m6-002`, `m6-006`, `m5-012`, `support_matrix_test.py`,
  `m10-003`, `m10-004`, `m9-005`, `corpus.sh`, `differential.sh`,
  `workflow.sh`, `data_xrefs.sh`, `generic_discovery_test.sh` pass. 89 reports
  indexed, both generators in sync.

### m4-007 evidence
- The store gained a place for typed data -- schema 13 adds
  `data_definitions(address, type, size, provenance)` -- because "this
  location holds typed data" is a program-model fact and `strings` was the
  only shape that could hold one.
- Its first producer is the ABI: the three words `DT_PLTGOT` reserves are
  8-byte pointers on this image (`002038d8`, `002038e0`, `002038e8`),
  provenance `native-import:plt-reserved`. Measured: `flow` **16 -> 14** and
  `data-type-unknown` **2 -> 1**; the PLT header no longer makes the
  decompiler overlay `_DAT_002038e0` over a one-byte label, and its
  "Globals starting with '_' overlap smaller symbols" warning is gone.
- A heuristic died with it: the worker used to infer pointer slots from thunk
  destinations and from what a corrected instruction reads. It now reads the
  store's definitions, so the rendering follows a fact with provenance instead
  of a chain of guesses.
- Both new provenance classes carry their sentence and evidence kind, which
  `m9-001` and `m9-002` require: `native-import:plt-header` (declared) and
  `native-import:plt-reserved` (declared), 16 classes recorded.
- Regression: `cargo test --workspace` 240 pass; `m4-002`..`m4-007`,
  `m3-003`, `m8-002`, `m8-003`, `m8-005`, `m5-008`..`m5-010`, `m9-001`,
  `m9-002`, `m9-003`, `m9-005`, `m6-002`, `m6-006`, `m5-012`, `corpus.sh`,
  `differential.sh`, `workflow.sh`, `data_xrefs.sh` pass. 90 reports indexed,
  both generators in sync.

### m4-008 evidence
- The parity gate was counting a *choice* as a *gap*. Four of the 15
  `function-facts` divergences were nothing but our own loader-derived names:
  `_plt` vs `FUN_00201710`, `_init` vs `_DT_INIT`, `_fini` vs `_DT_FINI`,
  `_entry` vs `entry`. The split is decided mechanically -- substitute the
  oracle's name into its own text and compare token streams -- so no judgement
  enters the count: `function-facts` **15 -> 11**, `name-convention` **4**.
- A missing name is still a gap: when ours is the decompiler's own default
  (`FUN_`, `SUB_`, `UNK_`) and the oracle has a real name, the gate counts
  `missing-name`, so the new class cannot be used as cover. None occur today.
- The names were checked against the pinned tree before being called a
  convention: Ghidra names the ELF entry `ElfLoader.ELF_ENTRY_FUNCTION_NAME`
  and gives it the `processEntry` convention
  (`ElfProgramBuilder.processEntryPoints`:651-675), and creates `_INIT_0` /
  `_FINI_0` from `DT_INIT`/`DT_FINI` (:678-686) -- which the store already
  matches at `00201670`. The differing four are section-derived names that say
  more than `FUN_00201710` does, so they stand.
- Not a defect list: 11 `function-facts` remain and every one of them differs
  in signature or return type as well, which is the prototype gap the next
  task owns.
- Regression: `m4-003` re-recorded and passing; evidence index, support matrix
  and documentation-coverage gates in sync.

### m4-009 evidence
- Imports now carry the prototypes the pinned C library archive declares.
  Measured: token identity **25 -> 29** of 56 (every one of the four measured
  languages gained one), `missing-external-prototype` **18 -> 14**. The x86-64
  call site is now the oracle's text exactly:
  `printf("sum: %d\n",(ulong)uVar1)`.
- **Where the declarations come from, and why.** The archive
  (`generic_clib_64.gdt`) is a Ghidra packed database; a parser for it in the
  JVM-free path would be a lot of format for one table of names. Instead
  `scripts/ExportLibraryPrototypes.java` reads it once through the pinned
  install (oracle-only, `FileDataTypeManager.openFileArchive`), and
  `scripts/gen_library_prototypes.py` commits the table with the archive's
  SHA-256: **6627 declarations**, 1.1 MB, checked in CI so a changed archive
  is a failure and not a drift. The runtime reads JSON; no JVM.
- **Two facts had to arrive for the string to render.** The prototype gives
  `printf`'s first parameter type `char *`; the printer then needs the
  location to be read-only, which `PrintC::printCharacterConstant` requires
  (printc.cc:1772). The store already knew: the mapped region is `r--`, so
  string symbols in unwritable memory now carry `readonly`.
- **A parse error taught the applicability rule.** `long strtol(char * *
  __endptr, ...)` made the decompiler answer `Syntax error at line 0`, which
  fails the whole function, and `powerpc_cpp_o2` with it. A declaration is
  applied only when every type is a core type *and* has at most one pointer;
  the arity gate went back to 20/20. A unit test pins the refusal.
- Two tests had to change with the behaviour, both narrowed rather than
  re-pinned: `m4-004`'s string rule accepts the label or the literal (never
  the bare address), and `m2-006_inference` compares the retained prototype
  *fact* instead of the provenance rendering, which m9-001 extended with the
  explanation and evidence kind. That failure predated this task.
- Regression: `cargo test --workspace` **244 pass**; `m4-002`..`m4-009`,
  `m3-001`, `m3-003`, `m2-005`, `m2-006`, `m5-008`, `m5-009`, `m9-001`..
  `m9-005`, `m6-001`, `m6-002`, `m6-006`, `m5-012`, `support_matrix_test.py`,
  `corpus.sh`, `differential.sh`, `workflow.sh`, `data_xrefs.sh`,
  `generic_discovery_test.sh` pass. 91 reports indexed, both generators in
  sync.

### m4-010 evidence
- The override was on the wrong instruction outside x86. A stub loads its slot
  and branches through it; on AArch64 and PowerPC those are two instructions,
  so `m4-005`'s rule keyed the correction to the load and the branch stayed a
  jumptable candidate. The importer now records the **indirect branch the flow
  walk proved** -- the same ending `linkage_flow_shape` accepted -- and the
  direct-thunk case records the branch the reference pass recorded.
- Measured: 8 linkage stubs across 3 architectures carry a `callreturn`
  override on their branch (AArch64 `0021088c`, `0021089c`, `002108ac`,
  `002108bc`; PowerPC `10010574`, `10010584`, `100105d8`; x86-64 `00201720`),
  the AArch64 PLT header's own branch `00210870` with it, and none of those
  functions asks for a jumptable. `flow` **14 -> 13**, token identity 29 of 56
  held.
- **The worker stopped guessing.** It used to derive call-like branches from
  thunk rows plus xrefs at decompile time; that heuristic is deleted. The
  branch address is a fact the importer records, with its own provenance, and
  the worker only reads it.
- **Two regressions of my own, caught by the batteries and fixed before the
  commit**: removing the worker heuristic dropped the *direct* thunk case
  (`_INIT_0` lost its call again) until the importer covered it, keeping
  Ghidra's rule that an entry-point branch gets no shared-return override; and
  `m4-006`'s "nothing else is corrected" rule had to scope to its own
  provenance, because a stub's transfer is now another producer's row.
- Controls: not recording stub transfers leaves all four AArch64 stubs with no
  override, and taking the address from the reference table instead of the flow
  walk records nothing at all there -- the reference pass has not run when the
  stub is proven, which is precisely why the fact belongs to the walk.
- Regression: `cargo test --workspace` 244 pass; `m4-002`..`m4-010`,
  `m3-001`, `m3-003`, `m2-006`, `m5-001`..`m5-004`, `m5-008`..`m5-011`,
  `m9-001`, `m9-002`, `m6-006`, `m5-012`, `support_matrix_test.py`,
  `corpus.sh`, `differential.sh`, `workflow.sh`, `data_xrefs.sh`,
  `generic_discovery_test.sh` pass. 92 reports indexed, both generators in
  sync.

### m4-011 evidence
- Three defects, one per kind of fact, each visible as text a person reads:
  - **width.** The worker's pointer width was the constant 8, so PowerPC BE32
    rendered `PTR___gmon_start___10020730._0_4_` -- the decompiler carving
    four bytes out of something it was told was eight. It now comes from the
    language's own tspec (`<space name="ram" size="4">`); 0 field extractions
    remain on either 32-bit row.
  - **exit.** Nothing recorded that `abort` does not return, so the AArch64
    entry function walked past the call and printed the *next* function's body
    (`FUN_002107c4`, `printf`). The name is on Ghidra's pinned list, which the
    tree already read for its thunk rule; the loader now records the fact
    (`native-import:known-name`) and the function ends at
    `/* WARNING: Subroutine does not return */ abort();`, the oracle's shape.
  - **name.** Ghidra's own x86 pattern file labels a stub
    `__i686.get_pc_thunk.bx`, and we printed it into C, where `.` is a member
    access. The worker now renders `__i686_get_pc_thunk_bx` while the store
    keeps what the image declared.
- Measured: token identity 29 -> **28**, and the reason is recorded rather
  than hidden -- correcting the pointer width removed a cast the oracle still
  needs, so one function moved into a new class, `type-stronger` (**4**): the
  only difference is that the store types an import slot as a code pointer
  where the oracle types it `undefined *` and casts at the call.
  `missing-external-prototype` **15 -> 11** with it, `flow` **13 -> 12**.
  28 identical plus 4 stronger-typed is 32 of 56 functions where the native
  text is the oracle's or better.
- Three controls fire: assuming the width brings the field carving back
  (`10010588: ._0_4_`), not recording the pinned exit leaves the store empty
  (`['00210880']; the store holds {}`), and printing the name verbatim emits
  `void __i686.` into C.
- **Three older tests pinned the previous staging and were narrowed to the
  contract**, not re-pinned to new text: `m2-008` asserted a known no-return
  name was invisible until inference ran (it is a loader fact now) and that
  the asserted prototype was the *only* row (library imports carry archive
  declarations now); its stale-positive seeding took its source from
  `facts[0]`, which is no longer the inference pass's row, so the source is
  named explicitly. `romwright-worker-client`'s synthetic tspec had no ram width,
  which the contract now requires; the fixture declares one.
- Regression: `cargo test --workspace` **244 pass**; `m4-002`..`m4-011`,
  `m3-001`, `m3-003`, `m2-006`, `m2-008`, `m2-009`, `m5-001`, `m5-002`,
  `m5-008`, `m9-001`..`m9-003`, `m9-005`, `m6-002`, `m6-006`, `m5-012`,
  `support_matrix_test.py`, `corpus.sh`, `differential.sh`, `workflow.sh`,
  `data_xrefs.sh`, `generic_discovery_test.sh` pass. 93 reports indexed, both
  generators in sync.

### m4-012 evidence
- **The gate's contract changed first.** Naming *a* divergence class used to
  make a function "explained". `residue()` now subtracts what each named class
  licenses -- token by token, over a `difflib` alignment -- and fails on what
  is left. Numeric notation is normalised (`0x0` == `0`); a differing *value*
  still differs. Two normalisations now compose (a name we chose *and* a cast
  a typed slot moved), where before either one alone short-circuited.
- **What the residue found, measured, then fixed.** Across 56 functions the
  unaccounted tokens were: `processEntry` (x86-64/x86-32 entry rows),
  `+ 0x1288`/`__i686_get_pc_thunk_bx` (three x86-32 rows), `__DT_PLTGOT` (one
  PowerPC row) and `0` vs `0x0` (two rows, notation). Three facts, one
  notation rule:
  - **the process-entry model.** `e_entry` of an ELF executable or shared
    object under OS ABI Linux/unspecified carries `processEntry`
    (`ElfProgramBuilder.processEntryPoints:655-673`). Recorded in a new
    `calling_conventions` table (schema **13 -> 14**) with provenance
    `native-import:entry-convention`, applied only where the language's cspec
    declares the model -- Ghidra's own silent skip, and necessary: an
    unrecognized name makes the decompiler build a *placeholder* model with no
    storage (`fspec.cc:4695-4698`). Reaches the worker as
    `<prototype model=... modellock="true">`, the shape Ghidra's Java writes
    whenever the name is known (`FunctionPrototype.grabFromFunction:135-136`).
    The dead `functions.calling_convention` column is gone; readers get the
    fact through a join, so one value has one owner.
  - **the compiler spec's call fixups.** Ghidra maps every `<callfixup>`'s
    `<target>` to its fixup and sets it on a function of that name, trying one
    and two leading underscores (`CallFixupAnalyzer:436-459`, `:200-222`). The
    worker does the same from the cspec it already loads and sends
    `<inject content=...>`; the body never travels, because this build compiles
    it (`PcodeInjectLibrarySleigh`, via `native/ghidra-opt-sleigh.patch`).
    Two x86-32 callers stop calling `__i686.get_pc_thunk.bx`.
  - **the dynamic table's labels.** `_DYNAMIC` at the table and `__DT_<TAG>`
    at every nonzero ADDRESS-valued tag's target, only where nothing else
    names the address (`markupDynamicTable:2691-2723`,
    `addDynamicMemoryReference:2753-2773`). 10 labels on the PowerPC row;
    the `DT_PLTGOT` slot keeps the import name it holds, which is Ghidra's own
    guard. One defect caught by its own control: the first version labelled
    the table at its *file offset* -- `dynamic_value` wants `p_offset`, a
    label wants `p_vaddr`.
- Measured: token identity **28 -> 30** of 56, `flow` 12 -> 10,
  `function-facts` 16 -> 11, `missing-external-prototype` 11, and
  **0 differing tokens unaccounted for** (previously unmeasured). New class
  `data-name-convention` **3**: both stores name the same address on purpose,
  matched by the address our label embeds. `type-stronger` 4 -> 9 because the
  cast rule is now two-sided and bound to a slot the store types.
- Controls (all fire): OS ABI byte 9, `e_type` = ET_REL, a PE image, and a
  language declaring no such model each record no convention; a spec copy with
  its `<callfixup>` elements removed brings the thunk call back; AArch64,
  whose only fixup targets `___NotARealFunctionName___`, fixes up nothing; and
  `residue()` reports `processEntry` when handed a text no class licenses.
- Commit size: 1010 insertions across 29 files, above the 800-line rule. The
  split boundary AGENTS asks for does not exist here in a green state -- the
  accounting fails without the facts, and committing the facts first would
  have re-recorded the pinned baseline twice for no review value. Recorded
  rather than hidden.
- Regression: `cargo test --workspace` **244 pass**; `m4-002`..`m4-012`,
  `m3-001`, `m3-003`, `m2-006`, `m2-008`, `m2-009`, `m5-001`, `m5-002`,
  `m5-008`..`m5-012`, `m6-001`, `m6-002`, `m6-006`, `m8-003`, `m9-001`,
  `m9-002`, `m9-003`, `m9-005`, `m10-003`, `m10-004`, `support_matrix_test.py`,
  `corpus.sh`, `differential.sh`, `workflow.sh`, `data_xrefs.sh`,
  `generic_discovery_test.sh` pass. 94 reports indexed, both README
  generators in sync.

### m4-013 evidence
- The recorded hypothesis was **wrong, and the measurement says so**: m4-013
  was written down as "supply the library declarations the remaining imports
  need". Decompiling all 11 `missing-external-prototype` rows both ways showed
  that is not what they differ by. Five of them (`printf`/`abort` stubs on
  four languages) are *already* the oracle's text minus a warning the oracle
  emits about **its own** locked-storage prototype; two more differ only by a
  data label both stores name on purpose. What was actually missing was one
  flow fact.
- **The fact.** Ghidra's default-enabled `SharedReturnAnalyzer` converts a
  branch to a function into a call that returns
  (`SharedReturnAnalysisCmd.processFunctionJumpReferences`, :376-424): an
  unconditional jump reference to a function entry, one flow reference on the
  instruction, no function *at* the branch, the containing function not being
  the destination, and no override already there. This tree already decided
  the *consequence* -- `record_branch_transfers` types such a branch
  `UNCONDITIONAL_CALL` and cites the same command -- and never recorded the
  override, so nothing reached the decompiler. Now
  `native-analysis:shared-return` records it, applied last so a stub's or the
  PLT header's override keeps its owner, exactly as Ghidra skips an
  instruction that already carries one.
- Measured: the PowerPC entry went from
  `/* Could not recover jumptable at 0x10010574 */ (*PTR___libc_start_main_1003074c)();`
  to `__libc_start_main();`, and the AArch64 `.init` caller from the same
  shape to `__gmon_start__();`. Class `flow` **10 -> 9**; token identity
  **30** of 56 unchanged, because both rows still differ elsewhere (the
  PowerPC row by a warning *we* emit about a global wider than the label we
  sent, the AArch64 row by a pointer type on a GOT slot).
- Controls, on a fixture built for the rule's four conditions: a tail call is
  overridden; a jump to its own function's entry is neither overridden nor
  recorded as a transfer; a conditional branch to a function entry is not
  overridden (`considerConditionalBranches` is false by default); and a branch
  that *is* a function entry keeps the thunk rule's provenance.
- `m4-010` asserted every override belongs to a stub or a reserved slot -- an
  exhaustive claim that a third owner falsified. Extended, not re-pinned: each
  override must now show *its own* evidence, and a shared-return override must
  point at a function entry outside the function that holds the branch.
- Regression: `cargo test --workspace` **244 pass**; `m4-002`..`m4-013`,
  `m3-001`, `m3-003`, `m2-008`, `m2-009`, `m5-001`, `m5-002`, `m5-008`..
  `m5-012`, `m6-002`, `m6-006`, `m8-003`, `m9-001`..`m9-003`, `m9-005`,
  `m10-003`, `corpus.sh`, `differential.sh`, `workflow.sh`, `data_xrefs.sh`,
  `generic_discovery_test.sh` pass. 95 reports indexed, both generators in
  sync.

### m4-014 evidence
- **The recorded task was refuted, and the refutation found a worse bug.**
  m4-014 was written down as "answer a data query the way Ghidra answers it":
  send nothing where the store holds neither a name nor a type, so a symbol
  narrower than the access stops making the decompiler warn
  (`Funcdata::checkGlobals`, funcdata_varnode.cc:1742;
  `DecompileCallback.encodeData`, :841-848). Implemented, it read **25 of 56**
  token-identical against a pinned 30. Two more variants -- typing the words
  the relocation table names as pointers, then as `undefined<width>` -- read
  25 as well. So did an unmodified tree at `HEAD`, twice.
- The cause was not the data rule. `RuntimeConfig::from_env` resolved the
  worker as the literal `target/debug/romwright-worker`, so the **release** CLI that
  every gate builds drove whatever `cargo build` had last left in
  `target/debug`. Three measurement rounds were made against a build that was
  not the tree, and the conclusion drawn from them was wrong. After
  `cargo build --workspace` at the same `HEAD`: **30 of 56**, the pinned
  number, reproducibly.
- Fixed where it belongs: `ROMWRIGHT_WORKER` still wins, then the worker
  **beside the running executable**, then the workspace's release and debug
  paths, each of which has to exist. Every gate that measures with the release
  CLI now builds the release worker with it (11 gates), so a gate's number
  comes from the binaries that gate built.
- Controls, all three firing: a CLI with a working worker beside it decompiles
  from a directory where no workspace path resolves; the same CLI with a
  *broken* worker beside it fails (without which the first control proves
  nothing about which worker ran); and `ROMWRIGHT_WORKER` still overrides a good
  sibling. Plus: the release and debug builds now produce identical text for
  the same function.
- The data-answer question is **not** closed, and the measurement says why:
  our composed `DAT_` labels earn 5 of the 30 identical rows, and stock earns
  them by holding *undefined data of the access width* at referenced
  locations, which is a fact we do not record. Typing relocated words as
  pointers is not it -- stock's own text names them `DAT_`, not `PTR_`.
- Regression: `cargo test --workspace` **244 pass**; `m4-002`..`m4-014`,
  `m3-001`, `m3-003`, `m2-008`, `m2-009`, `m2-016`, `m5-001`, `m5-002`,
  `m5-006`..`m5-012`, `m6-001`, `m6-002`, `m6-005`, `m6-006`, `m8-003`,
  `m9-001`..`m9-003`, `m9-005`, `m10-003`, `m10-004`, `corpus.sh`,
  `differential.sh`, `workflow.sh`, `data_xrefs.sh`,
  `generic_discovery_test.sh` pass. 96 reports indexed, both generators in
  sync, parity re-verified at 30 of 56 with 0 unaccounted tokens.

### m4-015 evidence
- **The fact three m4-014 variants were substituting for.** A referenced
  location reached the decompiler as a bare `<labelsym>` -- a name and no type,
  so one byte -- and a four- or eight-byte access over it raised
  `Globals starting with '_' overlap smaller symbols at the same address`
  (`Funcdata::checkGlobals`, funcdata_varnode.cc:1742). Stock never warns
  because it answers with the *data defined there*
  (`DecompileCallback.encodeData`, :835-855) and its analyzers define it as
  wide as the access. Answering "nothing" instead, which is what stock does
  only when it has neither symbol nor data, costs **5 of 30** identical
  functions -- measured, twice, with correct builds.
- The width was already decoded and thrown away. `romwright_constants.hh`
  recorded `{pc, target, access}` per reference; it now records the bytes the
  access touches -- a `CPUI_LOAD`'s output size, a `CPUI_STORE`'s value size,
  a memory varnode's own size -- merges the widest when two accesses share a
  location, and sends it as `"size"` in the `REFERENCES` payload. A taken
  address proves no width and carries zero.
- Stored as `undefined<width>` data with provenance
  `native-analysis:data-width`, and answered as a symbol of that width with
  the name the store would have used anyway -- so the label m4-004 earned is
  kept and the width is what is new. A location another rule types (the three
  `DT_PLTGOT` words) keeps that type.
- Measured: **19 access widths** on four corpus rows, 0 overlap warnings, and
  token identity **30 of 56 unchanged** with 0 unaccounted tokens -- the point
  was to stop lying about a width without losing a name. Classes improved:
  `flow` 9 -> **8**, `function-facts` 11 -> **10**,
  `missing-external-prototype` 11 -> **10**, `name-convention` 9 -> **10**
  (one row's whole difference is now just its name). Baseline re-recorded.
- Controls: a width nothing dereferenced is refused (the gate fails if a
  `DATA`-only target carries one), every stored width is 1..8 and has a
  READ/WRITE/READ_WRITE access to prove it, and a unit test decodes
  `mov eax,[rip]` (4), `mov rax,[rip]` (8) and `lea rax,[rip]` (0).
- Three `native_runtime` tests compared whole `ReferenceFact` literals; they
  assert *which* references exist, so they now compare `(from, to, kind)`
  triples and the width has its own test rather than being pinned in nine
  unrelated literals.
- Regression: `cargo test --workspace` **245 pass**; `m4-002`..`m4-015`,
  `m3-001`, `m3-003`, `m2-002`, `m2-008`, `m2-009`, `m2-016`, `m5-001`,
  `m5-002`, `m5-008`..`m5-012`, `m6-002`, `m6-006`, `m8-003`, `m9-001`..
  `m9-003`, `m9-005`, `m10-003`, `corpus.sh`, `differential.sh`,
  `workflow.sh`, `data_xrefs.sh`, `generic_discovery_test.sh` pass. 97 reports
  indexed, both generators in sync.

### m4-016 evidence
- Two accounting defects, both of which counted something that is not ours
  against us:
  - **direction.** The `flow` class licensed any `/* WARNING: */` comment in
    either direction, so `Unknown calling convention -- yet parameter storage
    is locked` -- which *stock* prints about its own locked-storage prototype,
    on `printf`/`abort` stubs whose text is otherwise ours exactly -- was
    filed as flow we disagree about. A warning we emit and stock does not is
    ours; the reverse is now `oracle-warning`, licensing its own tokens and
    nothing else.
  - **the prototype class.** Its second condition matched the callee name
    anywhere in the oracle's text, including the decompiled function's *own
    signature*, and looked for a prototype at the import **slot**, which
    carries none by construction. It now requires a call in the oracle's body
    and looks for the signature on the stub the name resolves to.
- The cast class became a contributing class as well as an early return: a row
  can differ by a typed slot *and* by a warning stock emits, and both have to
  be named for the token accounting to close.
- Measured, on the same 56 functions: `flow` 8 -> **3**,
  `missing-external-prototype` 10 -> **5**, `oracle-warning` **8** (new),
  `type-stronger` 9 -> **18**; token identity **30** unchanged, 0 unaccounted
  tokens. Baseline re-recorded. What remains a gap of ours is now
  `function-facts` 10, `missing-external-prototype` 5, `flow` 3 and
  `data-type-unknown` 2.
- Controls: a warning only we emit still counts as `flow` (without which the
  split would be an excuse); warnings in both directions are named in both;
  and the recorded `printf` stub pair -- the real texts from both decompilers,
  byte for byte in the test -- is accounted for with no residue and no missing
  prototype.
- Regression: `cargo test --workspace` **245 pass**; `m4-002`, `m4-004`,
  `m4-010`..`m4-016`, `m3-001`, `m3-003`, `m9-001`, `m9-002`, `corpus.sh`,
  `differential.sh`, `workflow.sh`, `data_xrefs.sh` pass. 98 reports indexed,
  both generators in sync.

### m4-017 evidence
- Diagnosis first, on the committed divergence files: `function-facts` (10)
  split into exactly two causes of five rows each -- a differing **name**
  (`entry`/`_entry`, `_DT_INIT`/`_init`, `_DT_FINI`/`_fini`) and a differing
  **return type**, every one of the latter being `[None, ...]`: the oracle
  store holds **zero** prototype rows, so that field compared our recovered
  type against the instrument's silence.
- The names were not a convention we chose. Stock's come from documented
  loader rules -- `ElfLoader.ELF_ENTRY_FUNCTION_NAME = "entry"` applied to
  `e_entry` (`processEntryPoints`:657), and `createDynamicEntryPoints(DT_INIT,
  null, ...)` naming its target `"_" + tag.name` (:678-679, :704), whose array
  forms this tree already matched in m5-010. Ours came from the section table
  (`_init`) or an invented underscore (`_entry`). Adopted, with Ghidra's own
  precedence: the target must be in an executable block, and **a function that
  already exists there keeps its name** (`createEntryFunction`:783-798), so a
  symbol from the image's table wins over the loader's name and the loader's
  name wins over a section-derived guess.
- Measured: token identity **30 -> 35** of 56, 0 unaccounted tokens.
  `function-facts` 10 -> **5** (only the return-type cause remains),
  `name-convention` 10 -> **3** -- and all three that remain are `_plt`, where
  stock has no name at all and ours says which section proved the start.
  Baseline re-recorded.
- Controls: `.plt` keeps `_plt` on every row; the **unstripped twin** of the
  x86-64 image keeps `_start` at its entry, because its own symbol table names
  it; and a PE image gains no ELF dynamic-entry names.
- Four gates anchored a bias or an allowlist on the old name and were updated
  to the contract rather than to the text: `m5-009` accepts a loader name as
  evidence-backed beside a section name, `m5-010`'s three-pair equivalence is
  now empty because the names agree, and `m5-010`/`m5-011`/`m5-009` anchor on
  `entry`.
- Regression: `cargo test --workspace` **245 pass**; `m4-002`..`m4-017`,
  `m3-001`, `m3-003`, `m2-008`, `m2-009`, `m2-016`, `m5-001`, `m5-002`,
  `m5-006`..`m5-012`, `m6-001`, `m6-002`, `m6-005`, `m6-006`, `m8-003`,
  `m9-001`..`m9-003`, `m9-005`, `m10-003`, `m10-004`, `corpus.sh`,
  `differential.sh`, `workflow.sh`, `data_xrefs.sh`,
  `generic_discovery_test.sh` pass. 99 reports indexed, both generators in
  sync.

### m4-018 evidence
- The instrument was silent and the gate counted the silence. `exportFacts`
  sent name, entry and size per function and no signature at all, so the
  oracle store held **0** prototype rows and every `return_type` comparison
  read `[None, ours]` -- on rows whose text already agreed
  (`int printf(char *__format,...)` both ways).
- The bridge now exports `getSignature().getPrototypeString(true)`,
  `getReturn()`'s type, `getCallingConventionName()` **and**
  `getSignatureSource()`, and only a non-`DEFAULT` source is persisted:
  Ghidra's placeholder is `undefined FUN_x(void)`, which is not a fact about
  the image. Recorded as `ghidra-bridge:recovered-signature`.
- A signature is compared by **content**: return type and parameter count,
  parsed from either side's spelling, because `int f(char *name)` and
  `int f(char *)` say the same thing and neither decompiler's parameter naming
  is a fact. A differing return type or arity still counts.
- Measured: `function-facts` 10 -> 5 (m4-017) -> **0**; token identity **35**
  of 56 unchanged, 0 unaccounted tokens, baseline re-recorded. What is left is
  5 `missing-external-prototype`, 3 `flow` and 2 `data-type-unknown` as gaps;
  3 `name-convention` (all `_plt`), 3 `data-name-convention` and 18
  `type-stronger` as choices; 8 `oracle-warning` as stock's own.
- Controls: no function carrying Ghidra's placeholder signature is recorded as
  having a prototype; two spellings of one signature are not a divergence; a
  differing return type is; a differing arity is.
- Regression: `cargo test --workspace` **245 pass**; `m4-002`, `m4-009`,
  `m4-012`, `m4-015`..`m4-018`, `m2-016`, `m9-001`, `m9-002`, `m5-012`,
  `m6-006`, `differential.sh`, `workflow.sh` pass. 100 reports indexed, both
  generators in sync.

### m4-019 evidence
- Diagnosis, measured offline before touching anything: the five remaining
  `missing-external-prototype` rows named exactly two imports,
  `__libc_start_main` (3) and `__gmon_start__` (2). The pinned archive
  declares **6627** functions -- `abort`, `printf`, `exit` among them -- and
  neither of those two. And after m4-018 the oracle store records every
  signature stock says it recovered: for these two names, at the stub and in
  its EXTERNAL block alike, it records **none**. There was nothing to supply.
- So the class was over-firing a third time, in the same shape m4-016 fixed
  for warnings: it asked only whether *our* store held a signature. A name
  nobody declares is nobody's gap. It now requires that stock hold one and we
  not: `missing-external-prototype` 5 -> **0**.
- Measured: token identity **35** of 56, 0 unaccounted tokens, baseline
  re-recorded. What remains, in the direction each points: gaps `flow` 3 and
  `data-type-unknown` 2; choices `name-convention` 3 (all `_plt`),
  `data-name-convention` 3, `type-stronger` 18; stock's own `oracle-warning`
  8.
- Controls: stock holding a signature we lack still counts (m4-016's own
  "real gap" case, updated to supply it); holding one stock lacks does not;
  the two names carry no signature in either store on the corpus; and the
  PowerPC row that used to carry the class is still accounted for token by
  token with the class gone.
- Regression: `cargo test --workspace` **245 pass**; `m4-003`, `m4-009`,
  `m4-012`, `m4-016`, `m4-018`, `m4-019`, `m5-012`, `m6-006` pass; both
  generators in sync, 101 reports indexed.

### m4-020 evidence
- Two facts, both small, both from a pinned rule:
  - **a label says whether the address is code.** Our provider prefixed every
    unnamed location `DAT_`; Ghidra has two constants,
    `DEFAULT_SYMBOL_PREFIX = "LAB_"` for a code address and
    `DEFAULT_DATA_PREFIX = "DAT_"` for data (`SymbolUtilities`:49-53). The
    worker now reads the store's own executable regions, so the AArch64 entry
    passes `&LAB_002106f4` exactly as stock does.
  - **a rendered name is a rendering.** All three `flow` rows carried the same
    warning from *both* decompilers, differing only in the name inside it:
    stock prints `__i686.get_pc_thunk.bx`, we print
    `__i686_get_pc_thunk_bx`, because m4-011 renders a name C cannot spell
    while the store keeps what the image declared. Comparing text now applies
    the same rendering to stock's names and names the choice
    `name-rendering`, instead of filing it as flow we disagree about.
- Measured: token identity **35 -> 36** of 56, 0 unaccounted tokens.
  `flow` 3 -> **1**, `data-type-unknown` 2 -> **1**, `oracle-warning` 8 -> 6,
  `name-rendering` **2** (new), `data-name-convention` 3 -> 2. Baseline
  re-recorded.
- Controls: no label contradicts its own mapping's permissions on any of the
  four ELF rows (5 data addresses keep `DAT_`), and a warning that differs by
  anything other than a rendered name is still `flow`.
- Regression: `cargo test --workspace` **245 pass**; `m4-003`, `m4-004`,
  `m4-011`, `m4-012`, `m4-015`, `m4-018`..`m4-020`, `m5-009`, `m5-012`,
  `m6-006`, `m9-003`, `data_xrefs.sh`, `differential.sh`, `workflow.sh` pass.
  102 reports indexed, both generators in sync.

### m4-021 evidence
- The last row with gap classes, x86-32 `00401440`, carried two independent
  defects and both are closed:
  - **the slot.** An `.init_array` word holds a code address -- the array
    proves it, which is the same evidence m5-010 uses to name the target
    `_INIT_0` while leaving the word that holds it untyped. The loader now
    records the slot as an 8/4-byte pointer
    (`native-import:elf-pointer`), so it renders `PTR_` rather than `DAT_`:
    **8 slots** across the four ELF rows.
  - **the name.** `classify` built its name classes (`name-convention`,
    `missing-name`, `name-rendering`) and then *dropped* them whenever the row
    differed elsewhere too, and compared the rest against the un-rendered
    text. So the injection warning both decompilers emit was counted once as
    `flow` (ours, with the C identifier) and once as `oracle-warning`
    (stock's, with the dotted name). The classes are now kept and the rest of
    the comparison runs against the rendered text.
- Measured: token identity **36** of 56, 0 unaccounted tokens. `flow`
  **1 -> 0**: no row now carries a warning we emit and stock does not.
  `oracle-warning` 6 -> 5, `name-rendering` 2 -> 3, `data-type-unknown` 1
  (the same slot, now a naming choice between `PTR_FUN_004026d8` and our
  `PTR__INIT_0_004026d8`). Baseline re-recorded.
- **The bridge change in m4-018 invalidated every committed oracle
  reference**, by design: `gen_oracle.py` pins `bridge_sources_sha256` over
  the bridge sources, so the references and the DWARF baseline both refused.
  Regenerated with the scripts that own them, and the regeneration is the
  evidence: all 21 oracle references are **byte-identical apart from that
  hash**, and the recomputed ground-truth baseline has **identical totals and
  identical per-row metrics**, with only `bridge_sources_sha256` and
  `oracle_sha256` moving. `m3-001` recall 1.0000 native / 1.0000 stock and
  `m3-003` arity 0.7537 both sides, as recorded.
- Controls: a word with no array behind it keeps `DAT_` and gains no pointer
  type; a warning that genuinely differs is still counted in its own
  direction.
- Regression: `cargo test --workspace` **245 pass**; `m1-007`, `m2-016`,
  `m3-001`, `m3-003`, `m4-002`..`m4-021`, `m5-009`, `m5-010`, `m5-012`,
  `m6-006`, `m8-002`..`m8-006`, `m9-001`..`m9-003` pass; 104 reports indexed,
  both generators in sync.

### m4-022 evidence
- The widening is the measurement: the gate compared one build per language
  (`plain_o0`, 56 functions). It now compares every variant the lock holds --
  `plain_o0`, `plain_o2`, `cpp_o2`, `many_o2` -- for the same four languages:
  **16 rows, 1845 functions, 1739 token-identical, 106 attributed, 0
  unaccounted tokens.** Per-row identical/attributed counts are pinned in
  `benchmarks/reports/parity-baseline.json`, so a variant regressing is a
  gate failure rather than an aggregate that still adds up.
- **Two defects only a new variant could reach**, both fixed at the source:
  - **a declaration whose base type the language has no name for.** m4-009
    filtered library declarations against a hand-written list of core types,
    which was the 64-bit set. A 32-bit language's own `coretypes.xml` names
    `longlong` and **no `long`**, so `long strtol(char **, ...)` reached the
    decompiler's C parser as `Syntax error at line 0 in stream / long`, and
    one unresolvable name fails the *whole* decompile, not one prototype. The
    filter now reads the language's own type document
    (`library_types::core_type_names`), so the declaration is applied on the
    64-bit rows (AArch64 `00210ca0` is now token-identical) and refused on
    the 32-bit ones. Pointer depth is no longer a limit: the parser's
    `pointer` rule is recursive and stock applies `char **__endptr`.
  - **a reserved slot that is someone else's byte.** m4-006 reserves
    `DT_PLTGOT + 2 words` for the resolver. In `powerpc_many_o2` the `.plt`
    object is **two words long**, so the third address is `.bss` -- the
    `completed.0` guard byte `_FINI_0` reads -- and the rule installed a
    `callreturn` override on the ordinary `lbz`/`stb` that touch it. The
    decompiler truncated the function to `halt_baddata()`. Reserved words are
    now bounded by the section that holds `PLTGOT`, and the override is
    installed only on a branch the flow walk proved: `_FINI_0` is
    token-identical to stock.
- **A pin pins one language.** `RuntimeConfig::adopt_language` kept
  `ROMWRIGHT_SLA` while rewriting `language_id` to the image's language, so an
  exported x86-64 `.sla` made a 32-bit import resolve the *64-bit* spec
  bundle -- which is how the `long` filter above passed at import time and
  failed at decompile time, where `language_decompile_config` refuses a
  mismatched pin. Adopting another language now drops the pin, and
  `m7-002`/`m7-003` pass with a foreign `ROMWRIGHT_SLA` exported.
- Three new classes, each with the evidence for it, none of them an excuse:
  `mangled-name` 8 (both stores hold `_ZTIi` from the COPY relocation that
  names it -- newly recorded as `native-import:elf-copy` -- and stock prints
  what its demangler made of it, `int::typeinfo`), `exception-annotation` 4
  (the try/catch comments Ghidra's exception analyzer writes from
  `.gcc_except_table`, which we do not read), and `language-variant` 3
  (**stock and we disagree about the language**: its opinion files select
  `PowerPC:BE:32:e500` for `powerpc_cpp_o2`, we select
  `PowerPC:BE:32:default`, whose four-byte view of `r2` is spelled `r2` and
  not `_r2`).
- `missing-external-prototype` now licenses the declaration stock prints when
  the missing prototype is the decompiled function's **own** -- its parameter
  names and the assignment a non-void return introduces -- and nothing when
  the prototype belongs to a function it merely calls (m4-019's direction).
- Regression: `cargo test --workspace` **248 pass**; `m2-002`, `m2-006`,
  `m2-008`, `m3-001`..`m3-003`, `m4-001`..`m4-021`, `m5-006`..`m5-011`,
  `m7-001`, `m8-003`, `m9-001`..`m9-003` pass, plus `corpus.sh`,
  `differential.sh`, `workflow.sh`, `data_xrefs.sh`,
  `generic_discovery_test.sh`.
- Recorded deficit, pre-existing and **not** m4-022's: `m2-006_thunks`
  (a decompiler-recovered prototype on an import stub, `00201710`,
  `processEntry`), `m1-008b_pointer_seeds` (2 of 2 rows fail),
  `m2-006_specs`/`m2-006_specs_rebuild` (`gen_native_specs.py --check`
  refuses the committed bundles on this host) and `main_window_split_test`
  (`main_window.cpp` 446 lines, cap 400). All four fail identically at
  `05b8b4e` with the source changes stashed, so they are earlier tasks' debts,
  recorded here rather than folded into this commit.

### m4-023 evidence
- The rule, read from the pinned tree before changing anything:
  `ElfLoader.findSupportedLoadSpecs` queries the opinion database with
  `e_machine` as the primary key and `e_flags` as the secondary one, then
  drops every answer whose endianness or pointer size contradicts the image.
  The constraint that matches names the processor and the compiler spec, and
  often the variant: `ARM.opinion` pins `variant="v8"`, and
  `variant="v8LEInstruction"` behind a masked secondary key
  (`0b .... .... 1... ...` = `EF_ARM_BE8`); `AARCH64.opinion` pins `v8A`;
  x86 pins `compilerSpecID="gcc"`. **PowerPC pins nothing**: primary 20,
  processor PowerPC, size 32, no variant and no secondary.
- **Why stock says `e500`.** Probed with a throwaway Ghidra script against the
  pinned install: the ELF query for primary 20 returns **27** pairs in
  `HashSet<QueryResult>` iteration order, all with `preferred=true` except
  the non-`default` compiler specs; `PowerPC:BE:32:e500/default` is index
  **0** and `PowerPC:BE:32:default/default` is index **12**. After the
  loader's endian/size filter the first surviving preferred spec wins, so
  stock's variant is hash order, not evidence from the image. Recorded, not
  copied: Romwright takes the neutral `default` variant.
- **Our own defect, found by the same reading:** the loader answered from a
  hand-written table that said `ARM:LE:32:v7`, `ARM:BE:32:v7` and
  `ARM:LEBE:32:v7LEInstruction` -- three rows the pinned install contradicts,
  and a secondary key the table never read. Selection is now
  `opinion::elf_selection`, which parses the install's `*.opinion` and
  `*.ldefs` (declaration order, variants, compiler specs, `deprecated`
  excluded) and applies Ghidra's own filter.
- Measured (`tests/m4-023_language_selection.py`,
  `benchmarks/reports/m4-023.json`): **7 ELF rows, 6 identical to what stock
  selects for the same bytes** (x86-64, i386, AArch64 and all three ARM rows,
  where three were wrong before), **1 stock-unconstrained** (PowerPC) recorded
  with the proof that no constraint pins a variant, no secondary key matches
  `e_flags = 0x0`, both languages sit at the same processor/endian/size, and
  ours is the neutral one. `language.rows_unexplained` **0**.
- An import still needs no Ghidra install (`m2-015`): the offline rows are the
  install's own answers for the machines the corpus holds, and
  `the_offline_rows_match_the_pinned_install` compares every one against the
  pinned tree, so the fallback cannot drift from the data it stands in for.
- `m1-008`'s hand-written expectations moved to the install's answer
  (`v7 -> v8`, `v7LEInstruction -> v8LEInstruction`), with the opinion file
  cited in the case table and `docs/toolchains.md` rewritten to the rule.
- Regression: `cargo test --workspace` **255 pass** (7 in `opinion`, 2 of them
  against the pinned install); `m1-006`..`m1-009`, `m2-002`, `m2-005`..`m2-009`,
  `m2-015`, `m2-016`, `m3-001`..`m3-003`, `m4-001`..`m4-021`, `m4-023`,
  `m5-001`..`m5-012`, `m6-001`..`m6-006`, `m7-001`..`m7-003`, `m8-001`,
  `m8-003`..`m8-006`, `m9-001`..`m9-005`, `m10-001`..`m10-004`,
  `corpus.sh`, `differential.sh`, `workflow.sh`, `data_xrefs.sh`,
  `generic_discovery_test.sh` pass. `m4-003` is unchanged at **1739 of 1845**
  with the same eleven classes: no corpus row's language moved.
### The four failing gates, closed
Every gate the tree carried into this session now passes. Each cause, and its
evidence:
- **`m2-006_specs`, `m2-006_specs_rebuild`.** `gen_native_specs.py --check`
  pins `bridge_sources_sha256` over the bridge sources, which m4-018 changed;
  m4-021 regenerated the oracle references for the same reason and missed the
  three spec bundles. Regenerated through the JVM bridge with the script that
  owns them: the **15 spec files are byte-identical** (git reports only the
  three manifests modified) and the only key that moved in each manifest is
  `bridge_sources_sha256`.
- **`m1-008b_pointer_seeds`, and `m1-008b_scoring_test`'s input.** The same
  hash, one level up: each scoring view pins `raw_reference_sha256` over the
  raw oracle reference m4-021 regenerated. Regenerated with
  `gen_function_scoring.py`: **all 20 views moved in exactly that one key**,
  20 of 20 rows pass, and the scored/excluded counts are unchanged.
- **`m2-006_thunks`.** A real disagreement between two committed tasks, and
  the test was the wrong side of it. Its assertion said *no* prototype may sit
  at an imported address; m4-009 deliberately applies the pinned archive's
  declaration to the stub an import names, which is what makes
  `printf("sum: %d\n",(ulong)uVar1)` the oracle's text exactly. What the gate
  protects is the caller: an **inferred** prototype recovered from an unknown
  thunk's body would erase the caller's parameters. The assertion now names
  that -- no prototype at an imported address may carry inferred evidence, and
  any that sits there must come from `native-import:type-archive` -- and the
  caller's two parameters are still asserted before and after inference, on
  both x86-64 and PowerPC.
- **`main_window_split_test`.** `main_window.cpp` had grown to 446 lines
  against a 400-line cap. The analyst's mutating commands (rename, comment,
  undo) and the two search dialogs moved to `main_window_commands.cpp`:
  **378 lines**, all ten docks present, and the Qt gates (`m6-003`,
  `m9-004`, `m10-002`) pass against a rebuilt binary.

### m4-024 evidence
- The rule, from the pinned tree: `GccExceptionAnalyzer.processCallSiteRecord`
  marks every LSDA call site whose landing-pad offset is nonzero, and
  `markStartOfTry` (:292-303) writes `try { // try from <first> to <last> has
  its CatchHandler @ <pad>` as a **PRE** comment at the range's first address.
  `LSDAHeader.createLPStartPointer` supplies the default the encoding omits
  (`lpStart = region.getRangeStart()`, the function the FDE describes), and
  `LSDACallSiteRecord.create` fixes the arithmetic: range
  `[lpStart + position, lpStart + position + length - 1]`, handler
  `lpStart + landingPadOffset`.
- Implemented as facts, not text: `native/elf_exception.rs` walks `.eh_frame`
  (CIE augmentation `z`/`P`/`L`/`R`, 32- and 64-bit length forms, FDE CIE
  back-pointers) to the LSDA and records
  `exception_sites(function, start, end, landing_pad)` with provenance
  `native-import:elf-exception` (store schema **14 -> 15**). The worker
  renders Ghidra's comment from the range; the analyst's `comments` table is
  untouched, which the gate asserts.
- **The personality pointer is skipped, not decoded.** AArch64 builds encode
  it `DW_EH_PE_indirect|pcrel|sdata8` (`0x9b`), which cannot be resolved to an
  address without reading the slot it names; refusing to decode it had cost
  the whole CIE, and with it every AArch64 range.
- Measured (`tests/m4-024_exception_annotations.py`,
  `benchmarks/reports/m4-024.json`): **4 ranges across the four `cpp_o2`
  rows**, each identical to the comment stock recorded for the same bytes,
  each present in the text our worker prints; **0 missing, 0 invented**, and
  the four `plain_o0` controls record none. `m4-003`'s
  `exception-annotation` class is **4 -> 0**, with token identity unchanged at
  1739 of 1845 and 0 unexplained.
- **Two defects the comment exposed**, both in our own plumbing:
  - a batched decompile never sent `flushNative`, which Ghidra's client sends
    after *every* decompile (`DecompInterface.decompileFunction`:828-834). The
    comment cache is filled once per function and only `clear()` refills it
    (`comment_ghidra.hh`), so every function after the first in a batch saw
    the first one's comments -- none. Worse, our own "already applied"
    prototype memo survived the flush, so the second appearance of a stub
    decompiled as `void printf(void)` where a single-address run printed
    `int printf(char *__format,...)`. The memo is cleared with the flush.
  - a PRE comment was sent to the decompiler as `header`, where Ghidra sends
    `user2` (`DecompileCallback.encodeCommentsType`:576-595). The decompiler's
    default body mask is `user2 | warning` (`printlanguage.cc`:586), so every
    pre-comment -- ours and the analyst's -- was silently dropped from the
    function body.
- Regression: `cargo test --workspace` **257 pass**; every gate in `tests/`
  passes, plus `corpus.sh`, `differential.sh`, `workflow.sh`,
  `data_xrefs.sh`, `generic_discovery_test.sh`.

### Gate wall time, measured and reduced
- Where it went: `m4-003` 690-1300 s (16 rows x native import + JVM oracle
  import + two batched decompiles), four M5 gates at 172-185 s each (one
  `analyzeHeadless` export per corpus row), `m4-023` 65 s, `m4-024` 54 s.
  Every one of those re-analysed bytes that had not changed with an analyser
  that had not changed.
- `benchmarks/gate_cache.py` reuses an artifact under the provenance that
  produced it: an oracle artifact by binary digest + `bridge_sources_sha256` +
  the install's `upstream_revision`; a stock headless export by binary +
  exporter-script + install; a native artifact by binary + the `romwright-cli` and
  `romwright-worker` digests, because m4-014 is the standing proof that a key
  without the build is a stale-worker trap. A miss, a changed input, a corrupt
  marker or a crashed build all fall through to real work
  (`tests/gate_cache_test.py`, 8 tests).
- Rows now run concurrently (`--jobs`, default 4, bounded by JVM memory) and
  `m4-024` decompiles a row's functions in one launch instead of one each.
- Measured: `m4-003` **250 s cold, 3 s reused** (from 690-1300 s), `m5-008`
  172 -> **14 s**, `m5-011` 177 -> **6 s**, `m5-009` 176 -> **6 s**, `m5-010`
  169 -> **6 s**, `m4-023` 65 -> **0.6 s**, `m4-024` 54 -> **0.3 s**, and
  `m4-018`/`m4-019` **0.2 s** each by sharing `m4-003`'s stores. Numbers, not
  adjectives: the whole `tests/*.py` sweep was 2375 s with `m4-003` included
  and every cache cold.
- The cost gates (`m7-001`..`m7-003`) do not use the cache: they measure the
  work it skips. `ROMWRIGHT_GATE_CACHE=` switches reuse off everywhere.

### m4-025 evidence
- The rule, from the pinned tree: the decompiler's C parser resolves a type
  name through `CParse::lookupIdentifier` -> `TypeFactory::findByName`, and
  `TypeFactoryGhidra::findById` asks the *client* for any name the factory
  does not already hold (`typegrp_ghidra.cc`:20-36). The answer needs a name,
  a size and a metatype; the id may be omitted, and
  `Datatype::decodeBasic` then derives `hashName(name)` itself
  (`type.cc`:698-700). Widths come from the compiler spec's
  `<data_organization>`, and where a spec omits it -- PowerPC's has no such
  block at all -- Ghidra's own defaults apply: `short` 2, `int` 4, **`long`
  4**, `long long` 8, `float` 4, `double` 8, `long double` 8
  (`DataOrganizationImpl`:43-53).
- Implemented: `library_types::language_base_types` reads those widths (with
  the defaults), the import filter accepts a declaration whose base types the
  language's `coretypes.xml` *or* its data organization names, and the worker
  answers the decompiler's type query from the same table. So a 32-bit row
  applies `long strtol(char *__nptr,char **__endptr,int __base)` and prints
  it, where the same declaration used to fail the whole decompile with
  `Syntax error at line 0 in stream / long`.
- Measured (`tests/m4-025_declaration_types.py`,
  `benchmarks/reports/m4-025.json`): **23 declared prototypes across all 20
  ELF rows**, every one stock applied to a function we know is recorded by us
  with the same declared types, and every one **printed with stock's own
  signature** -- the only proof the type reached the decompiler. Controls:
  **235** archive declarations whose types no language can express (`FILE *`)
  stay refused, and a `noreturn` stock spells inside its signature string is
  compared where we keep it -- in `return_behaviors`, not in the text.
- `m4-003`: `missing-external-prototype` **4 -> 0** and `function-facts`
  **2 -> 0**; eight classes left, 1739 of 1845 token-identical, 0 unexplained,
  baseline re-recorded. The stub rows still differ, and now only by classes
  that already had a direction: stock's own `Unknown calling convention`
  warning and the cast our typed slot moves.
- Regression: `cargo test --workspace` **258 pass**; every gate in `tests/`
  passes, plus the five shell suites. Two of them caught the same omission
  before this landed: `base_types` was set only on the CLI's provider, so the
  API's own worker (`infer_prototypes`, `decompile_doc`) still failed the
  parse -- the table now loads with the rest of the language facts in
  `load_language_info`, which every provider calls.

### m4-026: hypothesis refuted, recorded
- The task assumed `name-rendering` 12 was ours: m4-011 renders a name C
  cannot spell as an identifier before handing it to the decompiler, and stock
  appeared to print `__i686.get_pc_thunk.bx` verbatim. Measured, it is not
  ours.
- What stock actually prints, on `i386_plain_o0` and `i386_cpp_o2`:
  `void __i686_get_pc_thunk_bx(void)` in the declaration -- the **same
  identifier we print** -- and `/* WARNING: Function:
  __i686.get_pc_thunk.bx replaced with injection: get_pc_thunk_bx */` in the
  caller. Two spellings of one name, in one run.
- Three client-side attempts, each built and measured: the declared name in
  both `name` and `label` (declaration *and* warning both dotted -- two
  x86-64 rows became unattributed); the identifier in both (both sanitised,
  which is what we already did); and one in each, split by query path
  (`getMappedSymbols` versus the preloaded function shell -- both sanitised).
  The pinned decompiler prints `getDisplayName()` at both sites
  (`printc.cc`:2724 for the declaration, `flow.cc`:1326-1345 through
  `FuncCallSpecs::getName`, whose `name` is `fd->getDisplayName()`,
  `fspec.cc`:4958), so no single name a client can send produces stock's mix.
  Ghidra's own encoder sends no `label` at all headless: its transformer is
  `IdentityNameTransformer` (`DecompileOptions.getNameTransformer`:1333-1338,
  and `HighFunction.encode`:437-442 writes the label only when `simplify`
  changes the name).
- One thing the attempts did find, and it is now in the code's comments:
  `FunctionSymbol::decode` has no "empty display name means the name"
  fallback (`database.cc`:593-615), so a function element without a `label`
  prints an empty identifier -- a called function's argument came out as
  `(,param_2,...)`. The shell encoder already wrote both attributes; that is
  why.
- Left as it was, with parity re-verified unchanged at **1739 of 1845, 0
  unexplained**, eight classes. The gate written for the refuted claim is
  removed rather than weakened into something that passes.

### m4-027 evidence
- Two rules from the pinned tree, both needed, and each measured before it
  was written:
  - `OperandReferenceAnalyzer.checkForPointer` (:952-1035): a reference lands
    on an undefined location, the pointer-sized value there is read, and the
    location becomes `PointerDataType` unless the value is below 4096, is not
    in memory, is offcut, or lands inside a function that is not its entry.
  - `ElfDefaultGotPltMarkup.processGOTSections` (:78-94) and `processGOT`
    (:400-416): every initialized block whose name starts with `.got` is
    walked in pointer-size steps and **every** word is typed through
    `createPointer` (:562-585). The value decides only whether the reference
    survives (`isValidPointer`, :611-623: mapped memory, or a name); a word
    holding zero is still a pointer, which is why stock labels it
    `PTR_10020728` with no referent.
- The label is composed, not stored: `PointerDataType.getLabelString`
  (:192-238) takes the primary reference from the slot, cleans the referent's
  name with `SymbolUtilities.getCleanSymbolName` (:950-972, which strips a
  trailing `_<address>` only when the name is exactly base plus that address),
  and yields `PTR_<clean>`; the listing appends the slot. So a default name
  contributes its prefix -- `FUN_00401570` at the slot `004026d8` prints
  `PTR_FUN_004026d8`.
- Implemented: `elf_pointers::confirm_referenced_pointers` (the reference
  rule, run after reference inference, since the reference is its evidence)
  and `elf_pointers::collect_got` (the loader rule, run on both ELF widths),
  with sources `native-analysis:data-pointer` and `native-import:elf-got`.
  A word another rule owns keeps that rule's provenance -- the ABI-reserved
  `.got.plt` head, an initializer entry, an ifunc slot, an import -- and the
  width rule now yields the address instead of claiming it `undefined`
  (the store's `ON CONFLICT DO NOTHING` makes the first writer the owner).
  The worker composes the label from any pointer-typed slot's stored target,
  not from one rule's provenance.
- Measured (`tests/m4-027_pointer_slots.py`,
  `benchmarks/reports/m4-027.json`): **37 slots across 20 ELF rows**, every
  one typed as a pointer on both sides, **0 missing and 0 invented**. Stock's
  side is read from labels because the oracle export carries no data
  definitions at all (measured: 0 rows), so a slot where stock has its own
  name (`__DT_PLTGOT`, `__DT_PPC_GOT`) is evidence-free and out of scope; the
  rendering is proven by parity instead.
- `m4-003`: `data-type-unknown` **4 -> 0** (the class is gone) and
  `data-name-convention` **8 -> 4**, so 154 -> 146 attributed differences.
  1739 of 1845 token-identical, 0 unexplained, seven classes left, baseline
  re-recorded.
- Regression: `cargo test --workspace` **258 pass**; every gate in `tests/`
  passes, plus the five shell suites.

### m4-028 evidence
- Three facts, not one, and the third was found by measuring rather than by
  reasoning. Stock prints `int::typeinfo` where we printed `_ZTIi`, and the
  pinned install's own answer at that address
  (`analyzeHeadless` probe on `x86_64_cpp_o2`, `00202d08`) is:
  `dataAt=undefined1[16]`, `primary=typeinfo ns=int source=ANALYSIS`,
  `sym=_ZTIi ns=Global source=IMPORTED`, `extRef=null`.
  - The **name**: `GnuDemanglerParser.getSpecialPrefixHandler` (:502-514)
    routes `typeinfo for int` to `AddressTableHandler` (:1877-1913), whose
    name is the prefix up to its last space and whose namespace is the type;
    `DemangledAddressTable.applyTo` (:74-90) applies it with
    `SourceType.ANALYSIS` and makes it primary.
  - The **namespace**: a mapped-symbol answer carries the symbol's namespace
    id (`DecompileCallback.encodeResult`, :807-826), the decompiler asks for
    its path (`ArchitectureGhidra::getNamespacePath`, ghidra_arch.cc:608-622;
    `Database::decodeScopePath`, database.cc:3395-3425), and a symbol outside
    the global scope prints scope-qualified (`PrintC::pushSymbolScope`,
    printc.cc:202-231).
  - The **width**: an ELF `OBJECT` symbol with a size gets undefined data of
    exactly that size (`ElfProgramBuilder.processSymbols`, :1703-1706, and
    `allocateUndefinedSymbolData`, :1358-1381, through
    `Undefined.getUndefinedDataType`, :47-55). `_ZTIi` declares 16 bytes, so
    stock holds `undefined1[16]` there, and the C printer drops the `&` in
    front of an array (printc.cc:1082-1090). On 32-bit rows the same symbol
    declares 8 bytes, stays a scalar, and stock prints `&int::typeinfo` --
    which is exactly what we now print.
- Implemented: `romwright_core::demangle`, an Itanium C++ ABI demangler for the
  four names the ABI defines for data (`TV`, `TT`, `TI`, `TS`) over the type
  grammar it parses -- builtins, nested and `std`-scoped class names,
  sequential and standard substitutions, pointers, references, cv-qualifiers,
  arrays, function types, integer and boolean template literals. It refuses
  everything else (function encodings, construction vtables, thunks,
  expressions in template arguments) rather than guessing; 7 unit tests pin
  every rendering against the GNU demangler's own output. The importer
  applies it beside the mangled name (`native-analysis:demangle`), records
  object sizes (`native-import:elf-object`), and the worker sends the
  demangled name -- stock's primary -- inside the namespace the mangled name
  names.
- One trap, worth keeping: `ScopeGhidraNamespace::isNameUsed`
  (database_ghidra.cc:373-381) asks the client before every insertion into a
  namespace, and our answer was "any symbol anywhere has this name", so the
  symbol was refused and printed as `&ram0x00202d08`. Ghidra skips symbols in
  the global scope outright (`DecompileCallback.isNameUsed`, :491-533); with
  that rule the insertion succeeds. A second trap: scope ids share a space
  with the function ids the same session hands out, so namespaces now start
  at `1 << 48` -- with a colliding id the decompiler silently reuses the
  function's scope and never asks for the path.
- Measured (`tests/m4-028_demangled_names.py`,
  `benchmarks/reports/m4-028.json`): **4 names stock derives from a mangled
  name across 20 ELF rows**, every one held at the same address with the same
  text, **0 invented**, and every mangled name kept beside the name derived
  from it.
- `m4-003`: `mangled-name` **8 -> 0** (the class is gone), **1745 of 1845**
  token-identical (up from 1739), 0 unexplained, six classes left, baseline
  re-recorded.
- Regression: `cargo test --workspace` **263 pass**; every gate in `tests/`
  passes, plus the five shell suites.

### m4-029 evidence
- The rule: Ghidra's loader labels every nonzero ADDRESS-valued dynamic tag's
  target `__DT_<TAG>` (`ElfProgramBuilder.markupDynamicTable` through
  `addDynamicMemoryReference`, :2691-2773), and the processor extensions
  declare tags of their own -- `DT_PPC_GOT` is `ElfDynamicValueType.ADDRESS`
  in `PowerPC_ElfExtension` (:44-45), whose `canHandle` is `EM_PPC && is32Bit`
  (:61-63), so the tag number is only asked for there.
- What we had wrong, measured on the pinned install rather than assumed:
  - We dropped the label wherever anything else already named the address.
    Stock applies it *beside* the other name: at `10010588` on
    `powerpc_plain_o0` the probe reports both the function `_DT_INIT`
    (primary) and the label `__DT_INIT` (non-primary), and at `1003074c` --
    `DT_PLTGOT`, which on PowerPC is also the first `R_PPC_JMP_SLOT` slot --
    it holds **only** `__DT_PLTGOT`, because the import the slot resolves to
    lives in its EXTERNAL block, tied to the slot by a reference.
  - So the worker now resolves a name the way stock's primary symbol does:
    demangled name, then a name the image gives the object, then the dynamic
    table's label, then the import a linkage slot resolves to. A tag-named
    slot is sent as it stands rather than as a composed `PTR_<import>_<addr>`
    label -- composition is for data stock has no symbol for.
  - And the type it is sent with is the store's, locked. `HighCodeSymbol`
    (:41-46) sets `setNameLock(true)` **and** `setTypeLock(true)` on every
    mapped data symbol stock answers with; we locked only the name, so the
    decompiler retyped our slots and dropped the cast stock prints. Locking
    the type closed four more rows on its own.
- Measured (`tests/m4-029_dynamic_tags.py`,
  `benchmarks/reports/m4-029.json`): **243 dynamic-tag names across 20 ELF
  rows**, every one held at the same address with the same text, **0
  invented**.
- `m4-003`: `data-name-convention` **4 -> 0** (the class is gone) and
  `type-stronger` **89 -> 85**, **1749 of 1845** token-identical (up from
  1745), 0 unexplained, five classes left, baseline re-recorded.
- Regression: `cargo test --workspace` **263 pass**; every gate in `tests/`
  passes, plus the five shell suites.

### m4-030 evidence
- The question the class posed: stock types every word its loader marks up a
  plain pointer (`ElfDefaultGotPltMarkup.createPointer`, :562-585) and we
  typed every pointer row `code *`, so its text carried a `(code *)` cast that
  ours did not. Some of ours was evidence and some was invention, and the
  audit separated them: of the slots we typed as code pointers, 90 were import
  slots, 46 held a function's entry, and **68 held neither** -- the ABI's
  reserved `.got.plt` head, `.got` words holding zero or a data address.
- The rule now: a slot is a code pointer only where the *image declares* the
  target is code -- a linkage relocation for a function (a jump slot by
  definition, a GLOB_DAT slot when its symbol declares `STT_FUNC`; a symbol
  declaring `STT_OBJECT` declares data) or an initializer array, which the ABI
  defines as function pointers and whose entries the loader has already
  confirmed decode as code. A word that merely *happens* to hold a function's
  entry is a coincidence, not a declaration, and keeps the plain pointer both
  stores give it. The store records the split as the type itself
  (`code-pointer` beside `pointer`), so it is auditable rather than a decision
  buried in the worker.
- Two details the pinned tree settled:
  - The plain pointer points at `undefined`, size 1 -- the core type the
    decompiler registers for itself (`ArchitectureGhidra::buildTypegrp`,
    ghidra_arch.cc:341), which no language's `coretypes.xml` declares. Sending
    `undefined1` instead printed `undefined1 *` where stock prints
    `undefined *`; the type is sent by description with no id, which
    `Datatype::decodeBasic` (type.cc:698-700) hashes itself.
  - A word the dynamic table names keeps the weaker type only where the claim
    came from a relocation, since `DT_PLTGOT` on PowerPC is the ABI's reserved
    table head *and* the first jump slot. An initializer array's first entry
    is also named by `DT_INIT_ARRAY` and is still a function pointer.
- Measured (`tests/m4-030_pointer_targets.py`,
  `benchmarks/reports/m4-030.json`): **116 slots typed as code pointers and 74
  left plain across 20 ELF rows**; every code pointer has a fact in the same
  store proving its target is code, every declaring rule's row carries the
  declaration, and no such address is a function on stock's side. The gate was
  committed failing first and fails again if the split is removed (measured by
  stashing the crates: "no slot is typed a code pointer").
- `m4-003`: `type-stronger` **89 -> 58**, **1761 of 1845** token-identical (up
  from 1749), 0 unexplained, five classes left, baseline re-recorded. The
  residual 58 rows are the justified half: stock casts in front of a slot our
  store types from the image's own declaration.
- Regression: `cargo test --workspace` **263 pass**; every gate in `tests/`
  passes, plus the five shell suites. `m4-021` and `m4-027` were taught that
  `code-pointer` is a pointer with its target named -- the same claim, not a
  weaker one.
- Local note, not a code change: the gate cache moved off `/tmp`
  (`ROMWRIGHT_GATE_CACHE=/home/raikaru/romwright-cache/gate`) after tmpfs filled;
  Ghidra refuses a project path with a dot component
  (`NamingUtilities.checkName`), so `~/.cache` will not do.

### m4-031 evidence
- Decision: **the coined name is kept.** The class is one decision repeated 11
  times -- the function at the head of `.plt` is `_plt` here and
  `FUN_<address>` in stock -- and the name is derived from a fact the image
  declares (the section header), on a function both stores hold, where stock
  has no name of its own. Ghidra names the PLT *entries* after the imports
  they resolve, which we match (`m5-008`, `m5-009`); only the resolver stub at
  the head is unnamed there.
- Bounded rather than assumed. `tests/m4-031_section_names.py` reads the
  image's own section and symbol tables (in the gate, so the claim needs no
  `readelf`) and the store's own image bias, and holds the coinage to four
  conditions: **14 coined names across 20 ELF rows**, every one at its
  section's loaded start, every one on a function stock also holds, every
  stock name at those addresses its own `FUN_` default, and **0** coined over
  an address the image itself names. It is a guard for a kept decision, so it
  passes on arrival -- its four controls are the ways the coinage could spread
  (a name away from a section start, a name on a function stock lacks, a name
  over a real symbol, a name where stock is not silent).
- `_init` and `_fini` never appear in a store: the dynamic table's own
  `_DT_INIT`/`_DT_FINI` already name those entries (m4-029), and the coinage
  yields to a function that exists.
- `m4-003` unchanged at **1761 of 1845** token-identical, 0 unexplained, five
  classes. Regression: `cargo test --workspace` **263 pass**; every gate in
  `tests/` passes, plus the five shell suites.

### M4 divergence: the explained floor
- Five classes remain and each one is now named, measured and directional:
  - `type-stronger` **58** -- ours, justified: a slot typed from the image's
    own declaration (m4-030), where stock types every marked-up word
    `undefined *`.
  - `oracle-warning` **19** -- stock's, about its own recovery (`Unknown
    calling convention -- yet parameter storage is locked`).
  - `name-rendering` **12** -- stock's own two spellings of one name, proved
    unreachable from any client (m4-026).
  - `name-convention` **11** -- ours, kept and bounded (m4-031).
  - `language-variant` **3** -- measured and not ours: nothing in the install
    separates `PowerPC:BE:32:e500` from `default` (m4-023).
- Closing any of the remaining five means either a human decision (a corpus
  row for a blocked language, a user-visible naming or typing reversal) or a
  change in stock, so **M4's parity work has reached its explained floor**.
  The next unreserved work was C3 itself: the approved target had already
  arrived (Phase 4 above), so the session was measured rather than deferred --
  see m11-001.

### m11-001 evidence (GOAL C3)
- The claim the criterion asks for is a *session*, so the gate runs one, on
  the approved target (007 Agent Under Fire, GameCube GQFE78,
  `files/Bond.elf` pinned by sha256 `42488079...`), with no JVM in any step:
  blind import, navigation, decompilation, the recovery passes, an analyst
  edit, and the running console. Report:
  `benchmarks/reports/m11-001.json`.
- **Blind recovery.** The module is stripped into the work directory (the copy
  is asserted to carry no symbol table) and imported: **8899 functions in
  11.5 s at 65 MB peak**, language `PowerPC:BE:32:default`, scored against the
  unstripped module's own **8522** `STT_FUNC` symbols -- **recall 0.9799,
  precision 0.9384** (8351 matched). The symbols never reach the importer.
- **The session's surfaces**, through one real `romwright-api` process: paged
  functions filtered and unfiltered, xrefs into a recovered callee, a listing
  window, **5 functions decompiled** (median **17 ms**, tokens and a prototype
  for each), static memory, `recover_classes` (recorded, not asserted: a
  CodeWarrior image carries no Itanium `type_info`, and it found none), and
  prototype inference over the module -- **1744 functions analysed** under a
  20 s budget.
- **The live console.** Dolphin 2606a serving GDB on 24689 with the retail RVZ
  booted headless (`Null` backend): `memory_live` read 16 bytes at
  `0x80000000` beginning `47 57 37 45 36 39` -- the disc id `GW7E69` -- in
  0.9 ms. Dolphin's stub accepts one client per boot, which the gate documents.
- **Two defects the session found, both fixed here:**
  - `infer_prototypes` died on this module with `worker exceed memory cap
    (rss 270200832 > cap 268435456); killed`. The cap exists to bound a long
    session's memory, not to fail the request that discovers the growth, and
    the cap's own comment already described a retry path nobody implemented.
    Every pooled operation now recycles once on a cap hit
    (`with_worker_retrying`), the pass counts the recycles, and the gate proves
    the path on purpose: with `ROMWRIGHT_WORKER_MEMORY_CAP` at 120 MiB the same
    inference **recycled 8 workers and still analysed 1716 functions** instead
    of failing. A fresh worker over the cap still fails -- then the cap is
    below the language's floor.
  - An analyst rename did **not** survive re-importing the same image:
    `replace_functions` deletes and reinserts every row. An assertion outlives
    the pass that rediscovered the function -- Ghidra never renames a
    `USER_DEFINED` symbol during re-analysis -- so the store now re-applies
    the name every live `rename` in the command journal asserts, and an undone
    rename is never resurrected. Two store regressions pin both directions.
- `ROMWRIGHT_WORKER_MEMORY_CAP` is new and documented in README: a host with
  less memory bounds its workers lower, and the parse refuses a value under
  16 MiB rather than failing every request.
- Not wired into CI, for the same reason `m1-009` is not: the image is a
  retail disc. With the target absent the gate records `skipped` with that
  reason and passes, so a machine without the disc reports honestly instead of
  failing.
- Regression: `cargo test --workspace` **266 pass**; every gate in `tests/`
  passes, plus the five shell suites.

### m4-032 evidence (every flow request is answered)
- The rule: a batched `flow` request answers exactly one result per address,
  whatever the bytes at that address are. It did not. `IfcFlow::execute`
  caught `BadDataError` and `UnimplError` only, so any other low-level fault
  escaped the command and **discarded the rest of the command line** -- the
  console printed its prompt and the remaining addresses in that batch were
  never answered.
- Two faults reach it in practice, both from the pinned tree:
  `LoadImageXml::loadFill` raises `DataUnavailError` for an address the image
  does not cover (`loadimage_xml.cc:236`), and `SleighBuilder::delaySlot`
  raises a plain `LowlevelError` when a delay slot's own instruction never
  reached the pcode state (`sleigh.cc:385`). Both mean what Ghidra's
  `Disassembler` concludes for the same bytes -- no instruction here -- so the
  command now answers `kind=BAD` and keeps going.
- Measured on the MIPS-III corpus image (`dungeon_game.elf`, stripped, 781
  `STT_FUNC` symbols): the batch of 149 addresses came back with **82**
  answers, discovery treated the short batch as a console failure, and the
  import fell back to pointer-only seeds -- **247 functions, recall 0.3065**.
  With the arm in place the same import runs the flow phase (1013 requests,
  9417 instructions decoded) and recovers **480 functions, recall 0.4353**.
- The silent part is fixed too: a discovery fallback now records *why* in
  `ProgramSummary::discovery_note`, which `romwright-cli import --timings` prints,
  naming the first unanswered address. A whole architecture lost half its
  functions to a fallback that reported nothing.
- Regression: `flow_batch_answers_every_address_it_is_asked` pins the
  invariant with sixteen bytes of real MIPS text (a branch-likely at an odd
  address, its undecodable delay slot, and an unmapped address in one batch).
  It fails against a console built without the arm and passes with it.

### m4-033 evidence (the install's own languages, and pattern starts kept)
- A PlayStation 2 executable arrived in the corpus (`SLUS_209.50`, Capcom
  Fighting Evolution, 8794 `STT_FUNC` symbols in its own symbol table; the
  scored copy is stripped). Stock Ghidra on this install answers it with
  `r5900:LE:32:default` -- a language an installed *extension* supplies
  (`Ghidra/Extensions/ghidra-emotionengine-reloaded`). Romwright read opinions
  and language definitions from `Ghidra/Processors` only, so that language was
  invisible and the image was typed as plain MIPS32. Both readers now walk
  every module of the install's `Ghidra` tree, which is what
  `QueryOpinionService.initialize` does, and the selection matches stock.
- Three defects the image found, each one measured:
  - **Code ranges outran the image.** The one `PT_LOAD` declares 0x308e80 of
    memory over 0x22a400 of file, and the pattern search was asked to read all
    of it. `loadFill` raised `DataUnavailError`, the whole search failed, and
    the import kept **1** function. `code_ranges` now stops at the bytes the
    image carries, as Ghidra searches loaded *and initialized* memory.
  - **A pattern match on decoded bytes was refused.** Ghidra creates a
    function at a match that already holds an instruction, provided no
    function body contains it and nothing above flows into it
    (`FunctionStartAnalyzer.applyActionToSet`, 289-324;
    `checkAlreadyInFunctionAbove`, 491-530). Romwright refused every match the
    walk had already decoded.
  - **Prologue matches were treated as addresses read from data.** The
    overlap rule that retracts PE32 switch case labels was applied to pattern
    entries too, deleting **618 of 4835** real function starts.
- Measured against the module's own 8794 symbols, JVM-free:
  **6540 functions, recall 0.7422, precision 0.9980, 3.6 s, 37 MB peak**.
  Stock Ghidra on the same stripped copy: 6662 functions, recall 0.7560,
  precision 0.9979, **181.7 s, 1.19 GB peak**. Romwright is 1.4 points of recall
  behind at 50x the speed and 3% of the memory.
- The same fixes on the MIPS-III corpus image (`dungeon_game.elf`, 781
  symbols): recall **0.3065 -> 0.7695**, precision **0.7083 -> 0.8394**.
- `romwright-cli import --timings` now reports `patterns` as
  `{hits, accepted, refused}`, keyed by prerequisite name. Every number above
  was read off that field rather than guessed.
- Regression: `cargo test --workspace` **268 pass**; `corpus.sh`,
  `differential.sh`, `workflow.sh`, `data_xrefs.sh` and
  `generic_discovery_test.sh` all pass.

### m4-034 evidence (ARM: the mode the image declares)
- An Android ARM library arrived in the corpus (`librealfootball2011.so`,
  Real Football 2011, 12136 `STT_FUNC` symbols; the scored copy has its
  symbol table stripped and keeps only the dynamic one). Romwright recovered
  **8** of them. Three things were missing, each one in Ghidra's own rules:
  - **The Thumb bit is a mode, not an address.** ARM marks Thumb code with
    the low bit of a function's address and with `$t`/`$a` mapping symbols;
    the address is the aligned one and the bit means `TMode=1`
    (`ARM_ElfExtension.creatingFunction`, 116-140, `evaluateElfSymbol`,
    142-209). Every odd address was taken literally before, so nothing lined
    up with anything.
  - **The console had no way to be told.** It does now: `context <name>
    <address> <value>` calls `ContextDatabase::setVariable`, and the import
    sends every declaration the image makes immediately after the image
    loads, before anything decodes. A pattern's own `<setcontext>` -- which
    is how ARM's pattern file separates Thumb prologues from ARM ones -- is
    applied the same way, at the match address, and only where nothing has
    been decoded yet (`FunctionStartAnalyzer`, 133-150, 709-742). It used to
    abort the whole pattern search as an unavailable prerequisite.
  - **A mode declaration could kill the console.** Setting a value invalidates
    two caches -- `ContextCache` holds a pointer into the database's own blob
    that a set may move, and every `ParserContext` in the disassembly cache
    was resolved under the old value -- so the console rebuilds both. And
    reading arbitrary bytes in Thumb mode drove the constructor walk past the
    parser's fixed 75 states (`sleigh.cc:457`); indexing past the end took the
    process down with SIGSEGV mid-import. Out of states is now a decode
    failure, which is what every caller already handles.
- Measured, JVM-free: **12680 functions, recall 0.9698, precision 0.9282**,
  16.5 s, 95 MB peak, 795921 instructions decoded. The dynamic symbol table
  supplies most starts, so this is a symbol-assisted number, not blind
  recovery -- what it establishes is that ARM/Thumb images are now *read*
  rather than mangled.
- Regressions: `flow_batch_answers_every_address_it_is_asked`,
  `pattern_search_reads_only_the_bytes_the_image_carries` and
  `a_mode_declaration_never_takes_the_console_down` pin the three console
  rules with real bytes. `cargo test --workspace` **269 pass**; all five
  shell suites pass.
- Two batching deadlocks fixed on the way: writing thousands of commands in
  one `write_all` filled the console's stdout pipe while it waited for the
  rest of its input, and both sides blocked forever. `set_contexts` and the
  reference fixups now write in batches of 128 and read each batch's answers.

### m4-035 evidence (four approved platforms, measured)
- The corpus gained PlayStation 4, PlayStation Portable and PlayStation
  prototype binaries. Each was imported JVM-free and scored against the
  truth its own file carries.
- **PlayStation 4, x86-64** (`game-ps4-prof.elf`, Crash Team Racing Nitro
  Fueled, 53 MB after `--strip-all`; the copy carries **no symbol table and
  no dynamic symbols**, so this is blind recovery). Scored against the
  unstripped module's 145576 sized `STT_FUNC` symbols:
  **146441 functions, recall 0.9992, precision 0.9933**, 343 s,
  962 MB peak, 6.9 M instructions decoded and 354004 pattern matches.
  The image keeps `.eh_frame`, and the unwind pass reads it.
  Two defects stood between the import and that number, both fixed:
  - The propagation command asked `Funcdata::followFlow` to *throw* on an
    unresolvable instruction. `FlowInfo` already truncates control flow at bad
    bytes and warns (flow.cc:420-456) whenever `error_unimplemented` is clear,
    so the command now clears it for the duration of its own walk and restores
    it. A single undecodable byte used to fail the whole import.
  - One range the console still cannot answer now costs that range's
    references, not the image. The count is reported as
    `references_refused` by `romwright-cli import --timings` rather than swallowed.
- **PlayStation, MIPS R3000 PS-EXE** (`VS.EXE`, Darkstalkers 3 prototype,
  1998-05-25, with the build's own `VS.MAP`). The map names 818 addresses
  inside the main `.text` (0x801395f0-0x8018ed2b): **751 matched, recall
  0.9181**. A linker map names only what the linker exported, so the 1993
  functions Romwright recovers there cannot be scored for precision against it.
- **PlayStation Portable, MIPS Allegrex PRX** (`BOOT.BIN`, Puzzle Bobble
  Pocket, 621 sized `STT_FUNC` symbols): **634 functions, recall 0.7778,
  precision 0.7618**. The oracle needs care: this is a relocatable module, so
  a symbol's address is its section's base plus its value
  (`ElfLoadAdapter.getSectionSymbolRelativeOffset`, 561-567), and reading the
  values as absolute makes every symbol 0x40 low. Ghidra's own
  `isRelocatable()` is `e_type == ET_REL` (ElfHeader:1532), which a PSP
  module's `0xffa0` is not, so stock places these symbols exactly as Romwright
  does -- the skew is in the oracle, not in either store.
- Regression: `cargo test --workspace` **269 pass**.

### console-processors evidence (every supported console CPU decompiles)
- `tests/console_processors.py` imports a minimal function into each of the
  22 console processors and asserts the native worker decompiles it. All 22
  pass: 20 host CPUs decompile to C; the two coprocessors (PS2-VU, N64-RSP)
  import cleanly — the VU sla has no `return` (a VLIW microcode DSL), so a
  bare `decompile` is not its path and is recorded `ok(coproc)`, not gated.
- Three defects fixed to get here: the GBA fixture's Nintendo header carried
  `0x00` at `0xB2` where the logo check requires `0x96`; `ghidra_opt` was a
  stale build missing `setISAMode`; and `with_mwcc_callfixups` re-injected
  `_savegpr_N`/`_restgpr_N` into the Gekko_Broadway cspec that already ships
  them (now skips fixups the cspec declares), plus `rel.rs` mapped Gekko to
  `PowerPC:BE:32:Gekko` instead of `Gekko_Broadway`.

### m4-036 evidence (the oracle can load every corpus container)
- The parity gate measured five bundled languages and blocked four. Three of
  the four were blocked on the *oracle's* loaders, not on Romwright, so the
  install at `~/ghidra_12.1.3_PUBLIC` was completed, with every extension
  built by `javac` against its jars (no gradle on the box) and verified with
  stock `analyzeHeadless`, headless, on a real corpus image. Each port's diff
  is kept beside its clone under `~/opt/`:
  - **GameCubeLoader** (already installed, two defects): `findSupportedLoadSpecs`
    claimed every file (`binaryType` starts at `UNKNOWN` and the guard tested
    `!= null`), which is why a GBA cartridge imported as
    `PowerPC:BE:32:Gekko_Broadway` with no memory; and the DOL/RAM-dump/REL
    builders opened a Swing symbol-map dialog, which is why `main.dol`
    threw `HeadlessException`. Now: `!= BinaryType.UNKNOWN`, a declared
    `-loader-symbolMapFile` option, and `SystemUtilities.isInHeadlessMode()`
    guards. `main.dol` imports headlessly as `PowerPC:BE:32:Gekko_Broadway`,
    622 stock functions against our 675.
  - **gba-ghidra-loader** was never broken: `GBALoader.findSupportedLoadSpecs`
    reads the first eight Nintendo-logo bytes and the `0x96` at `0xB2`, and
    the m5-001 fixture header carried only the latter. The fixture now carries
    the eight logo bytes (not the bitmap). Its `load` maps the whole console
    address space, which is why a 420-byte cartridge ran the JVM out of a 2G
    heap: the bridge now launches with `-Xmx8g` (`ROMWRIGHT_BRIDGE_MAXMEM`).
  - **PsxLoader** (`lab313ru/ghidra_psx_ldr` 6f6be18): Swing RAM choosers
    replaced by declared options, the MIPS pre-analyzer un-shadowed. `VS.EXE`
    imports as `MIPS:LE:32:default`, 2012 functions, `main`/`VSync`/
    `ResetGraph` at the addresses `VS.MAP` names.
  - **N64Loader** (`zeroKilo/N64LoaderWV` 2bd5376): a physical cartridge view
    added; `perfect_dark_ntsc_final.z64` imports as
    `MIPS:BE:64:64-32addr:o32`, 131 functions in the boot segment (the game
    payload is compressed; a per-game unpacker is not a loader and was not
    shipped).
  - **XEXLoaderWV** (`zeroKilo/XEXLoaderWV` edbceeb): an upstream bug fixed --
    basic-compressed XEX decryption ran past the declared block sizes and
    threw on this file's 105410 trailing bytes (bounded per Xenia's
    `ReadImageBasicCompressed`). Black Ops II `default_mp_script.exe`
    imports as `PowerPC:BE:32:default`, 19897 functions, three `.map`
    symbols on analyzed function starts.
  - **Ghidra3DS** (`Stary2001/ghidra-3ds` ea387e0): Fire Emblem Fates'
    `code.bin` (reverse-LZSS, 3.4 MB -> 6.3 MB, decompressor checked against
    GodMode9 `codelzss.c`) imports as `ARM:LE:32:v6`, 15839 functions.
  - **Vita**: no loader can help -- `eboot.bin` is an NPDRM SELF with all
    three segments `encryption=1`. Decrypted locally (never into a repository)
    with the title's published zRIF via `sceutils`; the ELF's SHA256 equals
    the SELF's embedded file hash, stock imports it as `ARM:LE:32:v7`, 19842
    functions, `main`/`free`/`memcpy` on function starts from its `.MAP`.
  - Two install facts learned the hard way and recorded for the next port:
    `ClassJar.isModuleDependencyJar` requires the jar basename to start with
    the module directory name, case-sensitively, or the jar is ignored; and
    `analyzeHeadless -loader` takes the Java class simple name, not the
    display name ("missing opinion for GBALoader" was a refused file, not a
    missing opinion).
- **Parity, MIPS:LE:32:default: four rows measured, all pass.** Three store
  facts were missing and one bridge fact was invisible:
  - The tracked-register seed (`t9`) went into the compiler spec for the
    *first* address of a batch only, so `_DT_INIT` decompiled as
    `in_t9 + 0x200d0` in a batch and as `PTR___gmon_start___000407a0` alone.
    The spec now carries a `<tracked_set>` for every function entry, as
    `MipsAddressAnalyzer` seeds every function.
  - The linkage evaluator refused every MIPS PLT stub because `JXWritePC`
    computes `(addr & 1) != 0` for `setISAMode` and branches to `addr & -2`
    (`mips.sinc`). On a language that declares `LowBitCodeMode` -- Ghidra's
    own criterion, `PseudoDisassembler.hasLowBitCodeModeInAddrValues` -- the
    mask is identity for the pointer and the mode bit is a flag value, which
    `CreateThunkFunctionCmd` tolerates (`allow8bitNonUse`). `AND` is matched
    both ways round because SLEIGH writes it both ways. `printf` is now
    named and typed exactly as stock (`int printf(char *__format,...)`).
  - `R_MIPS_COPY` (126) was not in the copy-relocation table, so `_ZTIi` in
    `.bss.rel.ro` had no symbol and `__cxa_throw` took `&DAT_00030b8c` where
    stock takes `&int::typeinfo`.
  - Stock's `entry` prints `local_10`/`local_c`/`local_8` where ours prints
    `uStack_10`/`uStack_c`/`puStack_8`. The names are Ghidra's Java stack
    analyzer's (`SymbolUtilities.getDefaultLocalName`), fed to its decompiler
    as declared locals; the C++ decompiler alone cannot produce `local_`
    (`ScopeLocal::buildVariableName`, varmap.cc). The bridge did not export
    that frame, so the oracle store showed 0 `stack_variables` and the
    difference was unattributable. It now exports every function's stack
    frame (16 rows on `plain_o0`), and the gate attributes the names to a
    new class `missing-stack-frame` only when the oracle store declares slots
    for that function, ours declares none, and the oracle text prints those
    names -- and only the analyzer's own `local_` names, since a stack
  parameter the frame also lists (`__format`) is a prototype's fact.
  Native stack-frame recovery is the open item that closes it.
- **ARM:LE:32:v4t measured** from the committed m5-001 fixture, not a prose
  blocker: 4 of 4 shared functions token-identical.
- **MIPS:BE:64:64-32addr measured but not at parity**, and ratcheted rather
  than noted: the native loader refused every retail ROM because it required
  the whole image to fit in RDRAM (Perfect Dark is 32 MB against 8), so the
  file fell through to the DOL parser; it now maps the boot segment resident
  and the whole cartridge at `0x10000000`. Both stores load the ROM, share
  116 functions, and 17 are token-identical; the gate fails if either number
  drops. A batch no longer dies when one function branches into unmapped
  memory (`DataUnavailError` at `0x8712bcb4`): that function is omitted from
  the answer, as Ghidra's client reports one failed function.
- `m4-003`: **PASS -- 6 of 9 languages measured on 21 rows, 1796 of 1892
  functions token-identical, 96 attributed, 0 unexplained; 1 unreached
  (17/116); 2 blocked** (`ARM:LE:32:v5t`: no DS image existed on the box
  until today, no NDS loader in the install; `PowerPC:BE:32:e500`: no image
  selects it). Baseline re-recorded.
- Ground truth for handhelds: `pret/pokeemerald` built with `agbcc` and a
  from-source `arm-none-eabi` binutils **byte-matches the retail Emerald ROM**
  (SHA256 `a9dec84d…85af` both sides); `pokeemerald.elf` carries 15858
  `FUNC` symbols and lives beside the ROM in the corpus cache, not the repo.
  `pret/pokeheartgold` (0985e87, `mwccarm` under wine, NitroSDK 3.2) built
  in 536 s and **byte-matches the retail HeartGold ROM** (SHA256
  `65f02a56…0105`, 128 MiB, verified against the zip member independently of
  the project's own `rom.sha1` check); `pokeheartgold.elf` (ARM9, 170814
  `FUNC` symbols) and `ichneumon_sub.elf` (ARM7, 1107) sit beside it.
- Regression: `cargo test --workspace` **270 pass** (one new: a ROM larger
  than RDRAM loads with its boot segment resident).

### m11-002 evidence (the approved target's other modules)
- `tests/m11-002_game_modules.py` runs m11-001's session on the four other modules of 007 Agent Under Fire (`boot.elf`, `base.elf`, `Movie.elf`, `driving.elf`, each pinned by sha256), through m11-001's own helpers: blind import of a stripped copy scored against the module's `STT_FUNC` symbols, paged and filtered functions, xrefs, a listing window, five `decompile_doc`s with prototypes, `recover_classes`, `infer_prototypes` under a budget, `memory`, a rename that survives a second import. Report `benchmarks/reports/m11-002.json`.
- Measured: boot/base 694 functions in 2.8 s, recall 0.9472 precision 0.8790 over 644 symbols; Movie 1679 functions, recall 0.9550 precision 0.7844 over 1379; driving 5954 functions in 21 s, recall 0.9669 precision 0.9172 over 5648. Floors are per module with room below these. Movie's precision is jump-table case labels the module's own data pointers name as function candidates, which each end in the switch's shared tail; the overlap rule retracts those that overlap, and the rest stand -- recorded, not hidden.
- The surface that answers differently on a module loaded rather than booted: `boot.elf`/`base.elf` link at 0x80680000 and the game modules all at 0x80007100, so a live read answers for whichever is resident; the gate records the load addresses from the headers and makes no live claim. Every file-backed surface answered as it does for Bond.elf.
- m11-001 re-measured after the day's discovery changes: 9186 functions (was 8899), recall 0.9802 (0.9799), precision 0.9093 (0.9384), import 45 s at 229 MB peak (was 11.5 s at 65 MB): the switch round's decompiles run in parallel workers and count in the peak. The precision moved before the switch round (flowed modes and the pattern-round order), not with it.
- Switch round fixes found by these runs: a jump is asked once per body size (Ghidra re-runs its switch analyzer when a function's body changes), a table counts as a reason to walk again only when a case reaches bytes nothing decoded, and each parallel worker reads its own copy of the scratch store -- sharing one gave `database is locked` and made the DS function count vary 7200-7329 between runs; it is 7329 on every run since.

### m5-014 evidence (switch tables feed discovery)
- Discovery's round loop now does what `DecompilerSwitchAnalyzer` does: every function holding an indirect jump (`indirect_jumps`, recorded whatever the image's linkage) is decompiled through the worker against a scratch store, each recovered `JumpTable` is kept on `switch_tables`, and the next walk treats the jump's cases as its own flow, owned by the function (`FlowKind::BranchInd` in both walk loops). The jump-to-case references are stored as `COMPUTED_JUMP` with provenance `native-import:switch`. A branch already holding a table is not asked again; the round repeats while a computed target or a table is new.
- HeartGold ARM9: 277 tables over two rounds, 7026 -> 7329 functions; m5-013 fn.recall 0.6320 -> 0.6594, precision 0.9914; import 95 -> 116 s. Parity sample 376 -> 394 of 512, shared 6874 -> 7168 (ratchets raised). Committed rows unchanged (1796/1892, same classes); every acceptance script passes.

### m4-038 evidence (N64 parity ratchet 17 -> 58 of 116)
- Raw-SLEIGH mode ignored the tspec's `<truncate_space space="ram" size="4"/>`: `GhidraTranslate::decode` applied it in client-driven mode, the `Sleigh` path never did, so `Architecture::decodeStackPointer` (architecture.cc:1006-1012) kept an 8-byte stack pointer in a 4-byte space and no sp-relative access on MIPS64-32addr was a stack address (`(longlong)((int)&stack0x00000000 + -0x18)`, `unaff_retaddr` stores kept). `ArchitectureGhidra` now keeps the tspec's truncations and applies them from `modifySpaces` as `SleighArchitecture::modifySpaces` does (sleigh_arch.cc:423-429).
- `getCodeLabel` answers `LAB_<addr>` for a branch target inside a function body with no symbol -- Ghidra's flow leaves a reference on every branch target and `SymbolUtilities.getDynamicInstructionName` (:584-607) names it so; the decompiler printed `code_r0x...` before.
- The propagation wraps a sign-extended value into the space before it becomes a location (`SymbolicPropogator.makeReference`, :2624-2633): MIPS64's `lui` sign-extends every 32-bit address, so the N64 store held 1 READ across 116 functions; now 68 READ, 41 WRITE, and the decompiler prints `DAT_` where the oracle does.
- m4-003: N64 row 17 -> 58 of 116 identical (ratchet raised to 58), DS 373 -> 376, committed rows unchanged (1796/1892, same classes). m5-013 unchanged (0.6320/0.9912).

### m5-014 evidence (decode contexts reach the decompiler, and flow carries the instruction set)
- Diagnosis: 182 of the 512 sampled DS functions decompiled to "bad instruction data" natively. The worker read every Thumb body as ARM: discovery's `LowBitCodeMode` values lived only in the console sessions and the store kept none.
- The store now holds `decode_contexts` (`replace_decode_contexts`/`decode_contexts`): every pattern-declared mode, computed-target mode, flowed mode and entry mode discovery settled, `TMode`/`ISA_MODE` folded to the `LowBitCodeMode` each language aliases (ARM.sinc:90-93, mips.sinc:416-417). `romwright-worker` replays them as `<context_set>` ranges in the cspec's `<context_data>` (`ContextInternal::decodeFromSpec`, globalcontext.cc:531-553), each value holding to the next recorded point.
- Discovery carries the instruction set along flow as `DisassemblerContextImpl` does: the console names, per branch/call target, the value that flows there (`flow_modes=`; a globalset at the target -- an ARM `blx`, ARMinstructions.sinc:773 -- wins and is named so sibling shards learn it), and discovery sets it before the target decodes. Entry modes disagreeing with the ELF's `$a`/`$t` mapping symbols: 116 of 6818 before, 11 of 7021 after.
- Pattern rounds now follow Ghidra's pass order: a match landing inside a body an earlier match of the same round decoded is refused as `offcut` (the disassembler's conflict; `PossibleDelayedFunctionCreator` 1001-1012), and a refused match hands the console region back the mode it held (`setCurrentContext` sets one address; the console paints to the next change point). Before this a Thumb `push.w` pattern two bytes into an ARM `stmdb` painted the stretch Thumb and, with flow, cascaded into 164 lost ARM functions.
- Measured: m5-013 fn.recall 0.6144 -> 0.6320, fn.precision 0.9924 -> 0.9912 (7026 functions); DS parity sample 211 -> 373 of 512 token-identical, 0 native-only "bad instruction data"; ratchet raised to 373. m4-003 re-recorded: `missing-stack-frame` 4 -> 0 (native frames), every other class unchanged, 1796/1892 identical.
- `m1-006_corpus.sh` runs the mipsel row under `qemu-mipsel` with the vendored sysroot instead of exec'ing it on the host.

### m5-013 evidence (a retail Nintendo DS cartridge, scored and measured)
- The corpus gained Pokemon HeartGold (USA) and a byte-matching
  `pret/pokeheartgold` build; `tests/m5-013_nds.py` scores the `nds.rs`
  loader's ARM9 program against the build's 11019 sized `FUNC` symbols inside
  the static module and pins the images by hash. **PASS: 6822 functions,
  fn.recall 0.6144, fn.precision 0.9924; NitroMain 420 bytes, decompiled.**
  Stock Ghidra with the NDS loader installed tonight reaches 8528 functions,
  recall 0.7698, on the same module.
- Four things stood between 189 functions and that number, each a rule
  Ghidra has and we did not:
  - **The ARM9 module is stored compressed.** `_start_ModuleParams[5]`
    (NitroSDK `crt0.c`:362-372) names where the packed archive ends, and
    `MIi_UncompressBackward` (crt0.c:396-457) unpacks it in place before
    anything runs. `nds.rs` now does exactly that, byte for byte, and the
    session image carries bytes a loader hands over that the file does not
    hold at that offset (a patch over the file-backed view). 762644 stored
    bytes become 1122040.
  - **A pattern's prerequisite is met one function at a time.**
    `after="function"` needs the bytes before the match decoded, and the
    function that decodes them is usually itself a match; Ghidra's
    FunctionStartAnalyzer runs again on every new instruction range. The
    pattern round now repeats until it accepts nothing (8293 refusals became
    2050).
  - **Computed calls create functions, in the mode their target names.**
    The propagation reports a call or branch through a register whose value
    it knows (`COMPUTED_CALL`/`COMPUTED_JUMP`, Ghidra's RefType names), with
    the target's instruction set read from the interworking switch register
    Ghidra's ARM analyzer reads (`ArmAnalyzer.flowArmThumb`: "if the TB
    register is set, that trumps any mode we are tracking"; the pspec aliases
    `TB` as `ISAModeSwitch`, so the name travels by option). Discovery then
    seeds those targets with `LowBitCodeMode` set as
    `PseudoDisassembler.setTargetContextForDisassembly` sets it, and re-walks;
    three rounds reached every target. Two propagation rules were wrong for
    this and are now Ghidra's: a load from writable memory within 4096 bytes
    ahead of the instruction is read without asking (`VarnodeContext.getValue`
    -- the ARM literal pool), and a CALLOTHER clears only its output
    (`SymbolicPropogator.applyPcode`) rather than every register. crt0's
    `ldr r1,=NitroMain; bx r1` is a `COMPUTED_CALL` to `0x02000ca4` in Thumb.
  - **A probing console poisons its own context.** Every candidate the
    discovery console decodes writes the mode switches its bytes carry into
    the one context database (SLEIGH `globalset`), so by the time the
    reference pass ran, crt0 read as Thumb and yielded nothing. The flow
    answer now reports the mode each entry was decoded in, discovery records
    it, and the reference pass runs on fresh consoles that know only the
    recorded contexts.
- `m4-003`: **ARM:LE:32:v5t is measured, not blocked** -- the ARM9 program
  shares 6685 functions with the oracle's, 251 of the first 512 are
  token-identical, both numbers ratcheted. The blocked list is down to
  `PowerPC:BE:32:e500`. All 21 committed rows unchanged (1796/1892
  identical, 0 unexplained); the eight shell gates, m5-001 and
  `cargo test --workspace` (270) pass.

### m12-001 evidence (carrying names from one build onto another)

The gap the tool had was version diffing: nothing matched the functions of one
program onto another, which is what makes a decompilation with symbols usable
as an oracle for a retail image. `crates/romwright-diff` does it over facts the
import already holds, no decompiler and no JVM.

- **The store was missing the primitives.** A diff needs per-body structure,
  and the store held only entry, size and references. `function_features`
  (schema v17) now carries instruction, block and edge counts, loops, the
  largest block, and digests of the body bytes and of the decoded shape.
  Blocks and edges are Ghidra's basic-block model, checked against
  `BasicBlockModel.hasEndOfBlockFlow` (:64-78): a jump or a terminal ends a
  block, a call does not, a branch target starts one. Everything is counted
  from what the walk already decoded (`native/features.rs`), so no pass
  re-reads the image.
- **Two matchers, measured against each other.** `--matcher greedy` is the
  maximum-common-edge-subgraph strategy of Dullien & Rolles (SSTIC'05) that
  BinDiff uses; `--matcher nap` is Mengin & Rossi's network-alignment
  formulation (arXiv:2112.15337), maximised by integer projected fixed point
  iteration (Leordeanu et al., NIPS'09) with an exact minimum-cost-flow
  assignment each round. The alignment wins on precision, recall and ported
  names at once, so it is the default.
- **Scored against symbol truth the matcher never reads**
  (`tests/m12-001_diff.py`, `benchmarks/reports/m12-001.json`): 20 corpus rows
  against their unstripped twins, 1903 pairs, precision and recall 1.0 and all
  1702 ported names right; 12 cross-optimisation rows (`plain_o0` against
  `plain_o2` and `plain_pie`, four architectures), 147 pairs, precision 1.0,
  recall 0.8639, names 0.9535; two Agent Under Fire modules with the target
  stripped, 1176 pairs, precision 0.9662, recall 0.9473, names 0.9272.
- **Anchors are gated at 1.0, not floored.** An anchor is a key unique on both
  sides, so a wrong one means the key does not identify what it claims:
  measured 1.0 over 2802 judged pairs. Every error is in the propagated class
  -- 0.878 for the alignment against 0.868 for the greedy strategy on the
  module pair. On zlib built at `-O0` against `-O2`, target stripped, 147
  named functions: 0.908 precision, 0.469 recall, 0.825 of ported names right,
  against 0.879, 0.395 and 0.783 greedy.
- The earlier version of this measurement scored 1.0 on the module pair and
  was wrong: both sides were unstripped, so the matcher was matching by
  symbol name. The gate now strips the target and takes the truth from a twin
  the matcher never opens.

### m5-017 evidence (a Nintendo Switch module, no JVM)

`crates/romwright-core/src/native/nso.rs` loads an NSO0: three LZ4-block segments
assembled at their memory offsets, mapped at `0x71_0000_0000` where
`SwitchLoader.load` puts a 64-bit module, then the `MOD0` header the word at
text offset 4 names, and through it an ELF64 dynamic table. The symbol table's
length is `nchain` from `DT_HASH`, which is the same rule
`ElfCompatibilityProvider.getSymbolTable` (:157-172) uses. `DT_RELA` and
`DT_JMPREL` are applied before the image is mapped, so every pointer the
discovery pass reads is the value the console would see. The LZ4 decoder is
ours, 60 lines against the block-format specification, so no dependency was
added for it.

Measured on Xenoblade Chronicles: Definitive Edition's `main`
(`tests/m5-017_switch_module.py`, `benchmarks/reports/m5-017.json`): 43465
functions in 420 s, **recall 1.0000 over all 42423 `STT_FUNC` symbols the
module declares**, precision 0.9760 (1042 functions flow found that the
symbol table does not name), language `AARCH64:LE:64:v8A`. Stock Ghidra with
the Adubbz `SwitchLoader` extension installed in the pinned install recovers
45259 functions on the same module, so this is 0.9604 of stock. The gate
parses the module's symbols itself -- a different LZ4 implementation, a
different dynamic-table reader -- so the score does not rest on the loader it
scores. The target is a retail dump; the gate skips with a reason where it is
absent.

### m13-001 evidence (jump tables without the decompiler, better than stock)

The switch round was the last pass in a native import that called the
decompiler, and the most expensive: 130 of 137 s on a statically linked
AArch64 image, with two bodies hitting the per-function deadline. The console
now exports SLEIGH's p-code (`native/romwright_pcode.hh`, export only -- no
analysis was added to the pinned tree), and `native/vsa.rs` emulates the
dispatch path once per index, as `JumpBasic::buildAddresses`
(jumptable.cc:1451-1478) does over the decompiler's IR.

**Scored against truth, not against stock.** A case target is right when it
decodes as an instruction *and* lies inside the extent of the function that
branches to it, taken from the image's own symbol table. Stock is the
baseline C2 asks us to beat, and it is not itself the truth: on the host libc
34 of stock's targets fall outside the branching function and 5 do not decode
at all (`tests/m13-001_vsa_switch.py`, `benchmarks/reports/m13-001.json`):

| Path | Dispatches | Targets | Unsound | Soundness |
|---|---|---|---|---|
| stock Ghidra | 132 | 1891 | 39 | 0.9794 |
| ours, decompiler only | 130 | 1813 | 8 | 0.9956 |
| ours, value-set analysis only | 90 | 883 | **1** | **0.9989** |
| **ours, both (the default)** | **142** | 1832 | 6 | **0.9967** |

The pass plus the decompiler answers 13 dispatches stock has no table for,
misses 3 of stock's, and is sounder than stock everywhere. Those 13 are real:
they are the relative tables in the hand-written SSE string routines
(`movslq (%r11,%rdx,4); lea (%r11,%rcx,1); notrack jmp *%rcx`), which stock's
decompiler declines. The pass alone is the soundest column in the table and
costs 0.85 s.

Four rules earned their place by measurement, each replacing something that
scored worse:

- **A table is read by a strided load.** Feeding indices to any live register
  produces "targets" wherever the arithmetic lands in code. Requiring a load
  whose address advances by a fixed stride, and ending the table when it
  stops, is what makes the answer a table.
- **The guard is the branch, not a nearby constant.** Taking any constant
  compared in the neighbourhood as the case count sized tables by strangers'
  bounds. The range is where the conditional branch starts sending the index
  to the default case, which the emulator observes by running it.
- **Guard analysis is separate from path emulation**, as `analyzeGuards` is
  from `buildAddresses`, and each predecessor block runs on its own: merging
  them let one block's call clear the index another block compares. The
  predecessors come from the recorded flow, not from address order -- taken
  positionally, a guard was found for 15 of 132 dispatches, because a
  dispatch block is jumped to, not fallen into.
- **The tracked value is held through the guard block.** A guard recomputes
  the index from values the emulator cannot know -- `mov 0x4(%rbx),%edx; sub
  $0x3,%edx; cmp $0xa,%edx` -- and then compares it. What it compares is by
  definition the value that reaches the dispatch, so holding the seeded value
  through the block makes the comparison read exactly what the dispatch will
  use. This one rule took recall over stock's answers from 0.12 to 0.45 and
  the dispatch count from 18 to 90.

An unmodelled operation now makes its own output unknown instead of
abandoning the run; only a call clears state, and not the value being
tracked, which by construction survives to the dispatch.

Enabling it does not move a ratchet: `m4-003` is unchanged at 1796 of 1892
token-identical with the pass on.

**The abstract interpreter (`ROMWRIGHT_SJA=1`), and why it is opt-in.** Emulating
one straight-line window per index is the wrong instrument for a dispatch
whose index is bounded in a *different* block than the one that loads it, so
`crates/romwright-core/src/native/sja.rs` adds SJA-style relational abstract
interpretation over the whole function CFG: a lattice of `Top`, `Const`,
`Strided {lo, hi, stride}` and explicit target `Set`s, joined at merges,
widened only on the values that keep changing, with comparison predicates
carried across blocks so a guard in a predecessor sizes a table read further
down. It runs only where the pattern-shaped pass refused, so it can only add.

Measured on the host libc by the same truth scorer, both settings in one gate
run (`tests/m13-001_vsa_switch.py`, which now scores five paths):

| Path | Dispatches | Unsound targets | Soundness |
|---|---|---|---|
| pattern-shaped pass alone | 90 | 1 | 0.9989 |
| pass + abstract interpreter | **93** | 1 | **0.9989** |
| both plus the decompiler (default) | 142 | 6 | 0.9967 |

Three more dispatches, no loss of soundness, and the three it adds are three
of the 54 that stock answers and the pass alone does not. It is **opt-in**
because of what it costs: the switch phase goes from 1.9 s to 12.4 s on libc,
since it decodes and interprets whole function bodies where the pass decoded a
window. That breaches `m2-016`'s 5 s import-phase budget, so making it the
default would trade a measured budget for three dispatches.

**The parity gate is not met, and this says by how much.** "Reach at
decompiler parity with the proven tier still sound" wants the proven tier at
142; it stands at 93. The interpreter's refusals on libc are now dominated by
492 unknown-target dispatches and 96 too-few-target ones. The unknowns are
mostly not switches at all: the largest single class is PLT stubs
(`jmp *GOT[n]`), whose target is one pointer, not a table of code addresses,
and which the interpreter rightly refuses. The genuine remaining gap is PIC
tables of 32-bit offsets reached through boolean guard combinations, plus
the computed-goto class the mask rule below now covers.

**A mask is a bound.** `and $0xf, %ecx` states `index in 0..=15` outright,
with no guard needed -- but only when `mask + 1` is a power of two, since any
other constant clears scattered bits and the result is not a contiguous
range. That rule (`sja.rs`, `mask_bound`) is what converts the computed-goto
dispatches: `and $0xf; shl $6; add base; jmp *reg` materialises a strided
target set of 16 case blocks. It is also what exposed the next defect: those
case blocks are reachable *only* through the dispatch, so at analysis time
they belong to no function, and the old "target must lie inside the
branching function's extent" check refused them as `Outside`. The check is
now "not inside a *different* function's extent" (`Image::owner`), which is
the same rule the gate's truth scorer applies. A target that does land in a
neighbour is still refused, and a test pins that.

Two defects found here were mine, and both were found by reading the gate's
own report rather than the code:

- The unguarded tier `m13-001` had been silently carrying: deleting it cost
  49 dispatches. Restored and measured on its own, it scores 0.73 soundness
  against 0.999 for the guarded answer, so it stays recorded and unreturned
  (`vsa.rs`, the `let _ = unguarded` with the numbers beside it).
- A "regression" where the decompiler path answered zero dispatches was a
  stale `romwright-worker` binary refusing store schema 19 -- exactly the guard
  `m4-014` added. The switch round now reports that refusal in its
  `discovery_note`, and `ROMWRIGHT_TRACE_VSA` prints the round's inputs
  (candidates, indirect jumps, asked, known tables) so an empty round is
  distinguishable from a failing one.

Also fixed here: `NativeWorker::decompile_at_within` bounds one function's
decompile at 60 s and kills the child, which is Ghidra's own remedy
(`DecompileProcess.sendCommandTimeout`:564-595 arms a timer whose only action
is `dispose`, and `DecompilerSwitchAnalyzer` sets 60 seconds). The import that
never finished now takes 137 s, and `m2-012` went from two 900 s timeouts to
871 of 871 signature matches correct in 237 s.

**A width is not a guard, and a bound must reach its origin.** `movzbl`
says the index is a byte, not that the table is 256 entries: a bound that
is only `0..=2^w-1` reads past the table into whatever follows it.
`Strided` now carries `guarded` -- set by a comparison or a mask,
propagated through arithmetic, required for a table read -- and a
transform on a width-only bound refuses rather than producing a set that
lost the flag (`sja.rs`, `map_values`). A bound also has to reach the
value it constrains: `origins` now carries the narrowest width crossed,
a `unique` temporary is never an origin (it is dead by the next block),
and a compare only propagates a bound to an origin that already fits the
narrowest width -- which is also the operand's own width, since a bound
on `%al` is a bound on one byte whatever wider slot it came from. A
zero-extension of a value that already fits is a no-op, so the bound
carries through with its flag.

Measured by the same gate (`tests/m13-001_vsa_switch.py`):

| Path | Dispatches | Unsound targets | Soundness |
|---|---|---|---|
| pattern-shaped pass alone | 90 | 1 | 0.9989 |
| pass + abstract interpreter | **131** | 1 | **0.9994** |
| both plus the decompiler (default) | 142 | 6 | 0.9967 |

The interpreter now answers one more dispatch than the decompiler (131 to
130) in 4.5 s, inside the 5 s budget, so the parity gate is met. The
remaining gap to the combined 142 is the PIC tables of 32-bit offsets
reached through boolean guard combinations that the domain still cannot
name. Five defects found and fixed in this round, each measured on the
same gate:

- A leader with no instruction at its own address (dead bytes after a
  branch) was not a block start: `index_of` mapped an address to a block
  only by exact leader hit, so the next real instruction was absorbed into
  the branch's block and the block ended up holding two branches. It now
  maps to the last leader at or before the address. (117 -> 118.)
- An analysis answers every indirect branch in the function, but only the
  asked branch's table was recorded; a dispatch asked in an earlier round
  -- when the CFG was still missing the case blocks an unresolved jump hid
  -- is not asked again, so its table was dropped. Every table the analysis
  produces is now kept for the recording loop. (Measured earlier in the
  round; the Set-arm fix below is what took 118 to 120.)
- The `Set` arm of `materialise` refused every case outside the branching
  function's extent, where the `Strided` arm already allowed a case in
  space no other function has claimed. The same `Image::owner` rule now
  applies to both. (118 -> 120: the two gained were the `__memcpy_ssse3`
  shared-tail cases at 0x265f94 and 0x265fcd.)
- A bound on a compared slot did not reach a slot that was a truncation
  of the same origin: `rax = zext(eax)` is a 4-byte piece of `r14 - 0x20`,
  and `eax <= 0x5a` bounds `rax` to `0x5a` because `0x5a` fits the piece.
  The origin walk skipped any slot whose link crossed a narrowing; it now
  applies the bound when it fits the truncated width. (120 -> 131.)
- A function whose entry block is a loop header was never analysed: its
  back-edge gave it a predecessor, so in-degree seeding left it unvisited.
  Seeding is now by reachability -- any block not yet reached is seeded
  and its reachable set marked. (No count change on libc; the fix is for
  the class, not this image.)

### m14-002 evidence (one function, on demand, on a warm image)

`tests/m14-002_demand.py`, `benchmarks/reports/m14-002.json`, cold imports
(`ROMWRIGHT_NO_IMPORT_CACHE=1`), libc.so.6, 20 sampled bodies:

| Measured | Value |
|---|---|
| Loader-only import | 1.85 s |
| Whole-image analysis of the same bytes | 185.25 s |
| First request (parse + console load, paid once) | 0.364 s |
| Median function, analyse + decompile | 0.199 s |
| ... of which the walk | 0.015 s |
| ... of which the vendored decompiler | 0.182 s |
| Worst sampled body | 1.164 s |
| Bodies whose extent equals whole-image analysis | 20/20 |
| Bodies whose reference set equals whole-image analysis | 20/20 |
| Bodies inventing a reference batch does not have | 0 |

So the incremental fact set is identical to the batch one for everything a
single body can prove on its own: extent, references, call edges, and the
branches that leave it, including Ghidra's shared-return promotion of a tail
call. Facts that exist only because another function was analysed stay the
batch pass's and remain separable by provenance. Rows carry
`analysis_state` (`seeded`, `walked`, `undecodable`, `batch`) and
`analysed_revision`, so a loader's declaration is never mistaken for a
decoded body (store schema 18).


### Why the Switch import went from 420 s to 1333 s (attributed, not guessed)

Two suspects were eliminated on libc rather than by re-importing a 45k-symbol
module:

| Suspect | Instrument | Result |
|---|---|---|
| Release `overflow-checks = true` | libc import, `-C overflow-checks=off` A/B | 95.3 s vs 93.4 s -- 2%, inside noise, and it caught the AArch64 wrap bug, so it stays |
| Refusing switch tables no guard bounds | switch facts in two libc stores | byte-identical: 142 dispatches, 1832 edges either way (the unguarded path was opt-in, so the default never used it) |

The cause is in the stores already on disk, not in a new measurement: the
420 s run (`nxnative`, commit 7a14e1e) resolved **0** switch dispatches on
this module, and the current one resolves **690** (4,684 edges), each a
decompile of a real body. The old budget priced an import that did less
work. So `m5-017` now pins both sides: a 1800 s ceiling *and* a floor of 690
dispatches, so a faster import that stops answering them fails instead of
looking like an improvement.

One real defect fell out of the attribution: the switch round sized its
chunks with `div_ceil(lanes).clamp(1, 256)` and spawned one worker per
*chunk*, so a large image produced more chunks than lanes and ran more
decompilers than the host has cores. Bounding chunks to lanes took the module
from 1452 s to 1333.5 s. Bringing it down further is the jump-table
milestone's work -- sound analysis instead of the decompiler -- not a budget
to relax again.


### m15-001 evidence (stock structuring, over our own CFGs)

The decompiler already exposes structuring as a service: `structureGraph`
(`ghidra_process.cc:503`) takes an encoded `BlockGraph`, runs
`structureLoops`, `calcForwardDominator` and `CollapseStructure` over a copy
of it, and returns the collapsed hierarchy. No function, no p-code, no
decompilation -- so it runs on *our* blocks and *our* edges, and **no patch to
the pinned tree was needed**. Two details cost a day if rediscovered:
`BlockMap::resolveBlock` decodes `t_copy` as `BlockCopy(nullptr)` and
`CollapseStructure` asks a block for its split point when it structures a
loop, so a graph of `copy` blocks kills the process on anything cyclic --
`plain` blocks answer for themselves; and writing a whole batch of requests
before reading any answer deadlocks both pipes at about 100 graphs.

`tests/m15-001_structuring.py`, `benchmarks/reports/m15-001.json`, libc,
cold imports:

| Measured | Value |
|---|---|
| Canonical shapes structured as defined | 5/5 (if/else, self-loop, two-block loop: 0 gotos; irreducible, two-exit loop: 1 each) |
| Functions scored | 400 multi-block, 394 comparable (same extent both producers) |
| Block counts equal to whole-image analysis, functions with no recovered jump table | 388/388 |
| Functions with a recovered jump table | 6, all differing -- the case edges come from the switch round, which one walk does not run |
| **Stock baseline** | **2527 edges left unstructured over 394 functions; 198 hold at least one** |
| **Ours (`structuring::structure`)** | **1998 — 0.7907 of stock; better on 121 functions, worse on 58 by at most 6** |

The Rust pass collapses regions in the order that commits to the least:
sequences, short-circuit conditions (`BlockCondition`'s shape -- without it a
`&&` costs a jump, and adding it alone took 2529 to 2199), two-way and
multi-way branches, then natural loops whose bodies are structured
recursively with their back edges removed (2199 to 1998). A terminal tail
shared by several paths is duplicated rather than jumped to. Only when
nothing matches is an edge virtualised, choosing the one a structured shape
is least likely to want, deterministically. The measure is named
carefully: `structureGraph` stops after `CollapseStructure`, before the
printing pass (`finalizePrinting` -> `scopeBreak`) that decides which
unstructured edges print as `break` or `continue`, so every one is reported
as `f_goto_goto` here. It is a comparison of structurings over identical
graphs, not a count of `goto` keywords in emitted C -- and our own pass will
be scored on the same category, so neither side may count a `break` as
structured while the other does not. The partition is
asserted both ways, so the exception cannot quietly grow: a disagreement
outside the jump-table class fails, and so does a jump-table function that
starts agreeing.


### m16-001 evidence (types from p-code, scored against DWARF)

Constraint-based inference over p-code (`crates/romwright-core/src/types_infer.rs`):
each operation an operand takes part in is a constraint, constraints join
over a small lattice, and nothing is claimed where nothing constrained it.
Scored on a fixture built at `-O0` and `-O2` (`tests/fixtures-src/types_fixture.c`)
rather than the locked corpus, whose DWARF says `int32` almost everywhere --
a constant answering `int32` would have scored well on it.

| Measured (68 typed positions) | Value |
|---|---|
| Exact | 0.50 |
| Conservative (a generalisation of the truth, never false) | 0.9559 |
| Contradicting the compiler | 3 |
| Silent (`unknown`) | 10 |

Four findings, each measured rather than assumed:

* **A flag nothing branches on is not evidence.** x86 `CMP` emits a signed
  test *and* an unsigned one; taking both made twelve of thirteen fixture
  functions report contradictory parameters. Sign evidence is now taken only
  from comparisons whose result reaches a `CBRANCH`.
* **The width is the narrowest read, not the widest.** A 32-bit parameter
  arrives in a 64-bit slot; `max` reported `int64` for every `int32`.
* **Widening is the machine's, not the type's.** Reading `mov eax, ...`'s
  zero-extension as unsigned made every `int32` return come back `uint32`.
* **Spilled parameters keep their identity.** Tracking frame slots
  (`base + displacement`) took the silent answers from 20 to 10, which is
  most of what an unoptimised build hid.

The three contradictions share one cause, recorded rather than tuned away:
the pass tracks registers, not SSA values, so a register the body reuses as
scratch stops carrying its entry identity. Value numbering is the next
increment.


### m14-003 evidence (facts so far: answer now, say what is missing)

`tests/m14-003_facts_so_far.py`, `benchmarks/reports/m14-003.json`, cold
imports:

| Measured | Value |
|---|---|
| libc loaded without analysis | 1.38 s, 3898 seeds, status `provisional` |
| 100 bodies analysed one at a time | 4.07 s; store revision moved exactly 100 |
| Worst query *while* the pass committed | 0.063 s (`functions`, `symbols`, `status`) |
| 405 functions analysed to completion | 4.66 s, and the answer stopped being provisional |

`Core::analysis_status` reports what the store can answer and what it cannot
(`analysed` / `seeded` / `undecodable`, plus `stale`), so a consumer renders
an answer *and* marks it provisional instead of choosing between showing
nothing and pretending to be finished. `Core::analyse_pending` is the other
half: it walks seeds in address order under a caller-chosen budget, commits
each body on its own, and bumps the revision per function, so
`events_since` shows the store growing.

The gate found a real defect on its first run: a listing query *failed*
(`database is locked`) while the pass committed beside it. WAL lets readers
run during a write, but the brief exclusive lock a commit takes returns
`SQLITE_BUSY` immediately without a timeout. Store connections now set
`busy_timeout`, so a reader waits microseconds instead of erroring -- which
is the difference between an interactive tool and one that fails under its
own background work.


### m14-004 evidence (the window shows facts so far, then fills them in)

`tests/m14-004_ui_progress.py`, `benchmarks/reports/m14-004.json`, the real
window driven offscreen:

| Measured | Value |
|---|---|
| First completeness the window rendered | `provisional: 0 analysed, 405 to go` |
| Polls while it filled in | 24 |
| Final state | 405 analysed, 0 seeded, no longer provisional |
| Wall time | 4.3 s |

The window opens a project the way a large image forces you to -- map it,
show the loader's answer, analyse in the background -- driven by a timer
that runs bounded `analyse_pending` calls and stops itself when nothing is
left, so an idle window does no work. `ROMWRIGHT_UI_LOAD_ONLY` selects that
path in the gate; without it the harness imports everything up front and
the provisional state never exists, which is why the first version of this
gate passed while proving nothing.


### m17-001 evidence (functions from the shape of the graph)

A producer that needs nothing pointing at a function: sweep a range,
cluster what decodes into connected components over intraprocedural edges
(calls excluded -- they are the edges that leave a function), and call each
component a function. Nucleus's observation, over our console's decode
(`crates/romwright-core/src/cfg_functions.rs`).

Scored standalone -- the sweep covers the whole executable range with
nothing claimed in advance, so it cannot be handed the answers -- against
DWARF, on four architectures:

| Row | Called components (recall / precision) | Every component (recall / precision) |
|---|---|---|
| x86_64_many_o2 | 0.9975 / 0.9975 | 0.9975 / 0.4932 |
| i386_many_o2 | 0.9975 / 0.9901 | 0.9975 / 0.4908 |
| aarch64_many_o2 | 0.9975 / 0.9901 | 0.9975 / 0.9615 |
| powerpc_many_o2 | 0.9975 / 0.9950 | 1.0000 / 0.9663 |

The two tiers are reported separately because they are not equally
trustworthy, and one number would hide it: a component something *calls* is
a function almost every time, while a component nothing calls is either the
code no other producer can see or a run of padding that happened to decode.
On the variable-length machines the untrusted tier is half noise; on the
fixed-width ones it is not, which is exactly what stepping one byte at a
time through x86 padding predicts.


### m17-002 evidence (each producer scored on its own)

Function recall was one number over six passes. The store now records which
producer claimed each entry (`functions.producer`, schema 19, derived in
one place from evidence each pass already recorded: linkage stub, the
image's own symbol, byte pattern, pointer in data, a call, or the flow
walk), and the gate scores them separately against DWARF on four
architectures:

| Row | recall | call | flow | thunk | pattern | entries nothing explains |
|---|---|---|---|---|---|---|
| x86_64_many_o2 | 1.0000 | 402 @ 1.00 | 6 @ 1.00 | 1 @ 1.00 | -- | 0 |
| i386_many_o2 | 1.0000 | 401 @ 1.00 | 8 @ 1.00 | 2 @ 1.00 | 2 @ 0.50 | 1 |
| aarch64_many_o2 | 1.0000 | 403 @ 1.00 | 8 @ 0.875 | 4 @ 1.00 | -- | 1 |
| powerpc_many_o2 | 1.0000 | 401 @ 1.00 | 6 @ 1.00 | 3 @ 1.00 | -- | 0 |

An entry DWARF is silent about is not automatically wrong -- `_start`, the
PLT header and linker stubs are code the compiler emits without debug
information -- so precision here uses `m3-001`'s allowance: a symbol in the
unstripped twin or an address inside a `.plt*` section is explained.

Two entries across the four rows are explained by nothing, and both are the
same shape: a four-byte "function" at the address immediately after a real
one ends, with no reference to it (`aarch64 002132cc`, right after
`FUN_00213290`+60). That is a real defect and it is recorded rather than
absorbed: the gate holds the count at no more than two per row, so it
cannot grow quietly, and precision floors apply to classes of twenty or
more claims where a rate means something.

### m18-001 evidence (console loaders + the Xenon VMX128 language)

The console-container surface the platform-tiers file called blocked is now
mostly loaders, not missing processors. `parse_container` routes each magic
to a dedicated native loader, each verified by synthetic-fixture unit tests
in its module:

| Console | formats | loader | processor |
|---|---|---|---|
| 3DS | NCCH / NCSD / CIA | `native/threeds.rs` | `ARM:LE:32:v6` |
| PS3 | SELF / SPRX (+SPU carve) | `native/ps3.rs` | `PowerPC:BE:64:64-32addr`, `SPU:BE:128:default` |
| Vita | SELF | `native/vita.rs` | `ARM:LE:32:v7` |
| PSP | PRX | `native/psp.rs` | `Allegrex:LE:32:default` |
| Switch | NCA / XCI | `native/switch.rs` | `AARCH64:LE:64:v8A` |
| Xbox 360 | XEX | `native/xex.rs` | `PowerPC:BE:64:Xenon-32addr` |

The Xenon language is the new piece: `native/languages/xenon` compiles a
`PowerPC:BE:64:Xenon-32addr` `.sla` adding VMX128's 128 vector registers to
the A2/AltiVec base. The register operands are split fields whose high bits
sit inside the low-11 opcode region, so each is a sub-table over four
display/variable field pairs (one per 32-register bank); the opcode matches
on `XOP4`+`VMXB4`, `XOP7`, or `XOP9` by format. Opcodes come from xenia's
`ppc_opcode_table_gen.cc` cross-checked against Biallas `vmx128.txt`. Verified
by a `libsla.a` disasm harness: `vaddfp128 vmx69,vmx74,vmx52`, `vmx127`, all
sixteen loads/stores, compares, `vperm128`, `vsldoi128`, and base PPC all
decode. `xex.rs` now names `Xenon-32addr`; a `native::tests` dispatch test
proves each console magic reaches its loader.

What was still blocked at m18-001 — PS2 R5900 MMI/VU0-macro, PS3 SPU decode,
PSP VFPU — turned out to be stale: the pinned install ships all three
(GhidraSPU, ghidra-emotionengine-reloaded, Processors/Allegrex VFPU), and the
console gate's SPECIAL_INSTRUCTIONS pass now proves each decodes. The only
real blocker left was key material, addressed by m18-002.

### m18-002 evidence (user-supplied console keys)
The encrypted-container blockers were not "private keys" but two honest
classes: bundled public keys the loaders already use, and keys only the
console holds. The second class now has a channel. `native::keys::KeyStore`
parses the formats key material actually arrives in — `prod.keys`/
`aes_keys.txt` named-hex and raw `.rap`/`.klic` blobs — and threads through
`parse_container_with` to `import_with(data, keys)` on each console loader.
The CLI takes `--keys <file>` (repeatable); the API takes a `keys` list.

What each loader does with it, verified by a fixture that imports only when
the key is supplied:
- Switch NCA/XCI: `header_key` + `key_area_key_application_00` from a
  prod.keys drive the XTS header unwrap and key-area ECB unwrap.
- 3DS NCCH/NCSD/CIA: `slot0xNN`/`fixed_system` from an aes_keys.txt supply
  the bootrom keyslot / system fixed key the ncchflag selects.
- PS3 NPDRM SELF: a `.rap` derives the per-title key (RAP→klic→content key,
  public RPCS3 constants) that unwraps the metadata.
- Vita NPDRM SELF: a `.klic` unwraps the per-title metadata key.
- PSP `~PSP`: KIRK is device-key crypto no file can drive — it stayed a
  decrypt-first error at m18-002. m18-003 corrects that: the KIRK keys are
  long-public constants, so `~PSP` now decrypts with no file at all.

### m18-003 evidence (PSP ~PSP/KIRK decryption)
The m18-002 claim that PSP KIRK was unreachable device-key crypto was wrong.
The KIRK key vault (128×16), the CMD1 master key, and the ~18 tag→key table
entries are dumped console secrets that have been public for ~15 years
(PSARDUMPER/JPCSP) — the same class as the Xbox 360 XEX retail key already
embedded. `native/kirk.rs` ports the algorithm as facts (no code copied):
`pspDecryptPRX` tries types 0/1/2/5/6/9, each looks the 0xD0 tag up in a
public table, unscrambles the key/id fields with `kirk7` (AES-128-CBC, zero
IV, keyed by the vault), SHA-1-verifies the rearranged header, then KIRK
CMD1 AES-decrypts the payload. `native/kirk_tables.rs` holds the generated
constants. A KL4E/KL3E/KL2E payload is zlib-inflated before import. The
decrypted PRX feeds the existing `import_prx`. Proven by a type-2
round-trip test that encrypts a known PRX and decrypts+imports it with
exact names; garbage/truncated/scrambled inputs error cleanly. 340 lib
tests + 27/27 console-gate rows pass.

II.1 is untouched: keys come only from a file the user dumps, never a
runtime fetch.



### m20-014 evidence (console-support expansion: the P-gap closure)
The console-support sweep closed the remaining P-items, each proven by a
test that exercises the behaviour rather than the source:

- **P1.6 DS overlays** — `native/nds_overlays.rs` walks the ARM9 OVT and
  FAT, mints one `ov<N>` module per overlay (RAM addr + zero-filled bss),
  and binds `(overlay-id, addr)` to module/file offset. Wired into
  `native/nds.rs`; 7 tests.
- **P2.2 shared fact database** — `romwright-facts` (new crate) is the
  hosted store `fact_sync` pushes to: SQLite-backed, keyed by
  `binary_sha256` for exact matches and indexed by per-function semantic
  signature for cross-build transfer. `pull_facts` returns the bundle that
  best covers the query's signatures at `MATCH_FLOOR`. JSON-line TCP
  server (`serve_tcp`); 5 tests.
- **P2.3 MWCC prologue/epilogue** — the worker injects `_savegpr_N`/
  `_restgpr_N` callfixups into a PowerPC cspec so a `bl _savegpr_14` reads
  as callee-saved stores, not an opaque call. Proven by a test over the
  injected pcode (all 18 save + 18 restore helpers, correct offsets).
- **P2.4 IDO o32 cspec** — the MIPS bundles (`MIPS-LE-32-default`,
  `MIPS-BE-64-64-32addr`) carry the o32 convention: integer args in
  a0..a3, FP args in the f12/f14 family independent of the integer slots.
  Proven by a `register_params` test over the shipped cspecs.
- **P3.4 RVZ** — `native/wii.rs` decompresses RVZ (header + per-chunk
  codec) and imports the recovered ISO; round-trip test per codec.
- **P3.11 emulator adapters** — `romwright-debug` gains `pine` (PCSX2),
  `ppsspp` (WebSocket), and `trace` (shared TraceHit→CSV) clients; 22
  tests over mock servers.
- **P4.2 Gekko paired-singles** — `gekko.rs` decodes every `ps_*`/`psq_*`
  opcode and renders lane-wise float C; 9 tests.
- **P4.3 VU0-macro semantics** — `vuupper.sinc` is `@include`d via
  `cop2.sinc`; the installed `r5900.sla` was rebuilt (43 KB → 53 KB) so the
  VU macro set is compiled in.
- **P4.4 RSP parity + GBI** — `rsp_parity.rs` sweeps the decoder against
  the slaspec (1344/1344) and `gbi.rs` annotates F3DEX2 display lists.
- **P4.5 VU-micro finder + parity** — `vif.rs` finds MPG uploads + MSCAL
  calls and decodes VU LIWs with reserved-encoding rejection; 9 tests.
- **P4.6 m2c-parity emission** — `emit_m2c.rs` renders a `DecompDoc` token
  stream as m2c-shaped C; 7 tests.

Regression: `cargo test --release --workspace` — 407 lib + all crate
suites pass, 0 failures.

## Next task
Every task the previous list named has landed (m4-037, m4-038, m5-014,
m11-002, m12-001, m5-017, m13-001; evidence above). What the measurements now
point at, none reserved:
- m13-002: the proven tier answers 103 of the 142 dispatches the default
  recovers (the abstract interpreter landed opt-in; evidence above), so the
  decompiler is still needed for 39. The refusal accounting on libc, taken
  with the interpreter on, names them: 233 dispatches whose index is
  unbounded (no comparison the interpreter reads ever narrows it) and 174
  whose target set stays unknown, dominated by PIC tables of 32-bit offsets
  reached through boolean guard combinations. Both are one missing
  capability -- a backward slice over real predecessors on SSA, which
  `JumpBasic::findDeterminingVarnodes` does. Acceptance is unchanged and not
  to be relaxed: the proven tier answering as many dispatches as the
  decompiler at no less than its 0.9989 soundness, at which point the
  decompiler leaves the switch round. The interpreter also has to come inside
  `m2-016`'s 5 s phase budget before it can be the default; it is at 12.4 s.
  (2026-09-14 partial: `State.predicates`/`comparisons` now carry a Vec of
  bounds per boolean instead of one, so a `BOOL_AND`/`BOOL_OR` combining
  comparisons on different slots keeps every bound rather than dropping all
  but the first; the CBranch body extracted to `apply_guard_bound` and runs
  per bound. Regression test `a_guard_anded_with_another_bound_still_bounds
  _the_index` fails pre-fix, passes post. Measured on libc: SJA resolved 30
  dispatches both before and after -- the remaining `unknown` class is the
  backward-slice gap below, not the guard-combination drop this fixed.)
- m12-002: the propagated class is 0.878 on the module pair and 0.469 recall
  on zlib `-O0` against `-O2`. Both matchers see the same content features,
  and the content score is what the alignment's commit rule turns on, so the
  next gain is a feature, not a solver: an instruction-class histogram (the
  34 mnemonic classes of arXiv:2112.15337 Table II, or the interpretable set
  TIKNIB measured as competitive with learned models, IEEE TSE 2022). The
  console reports flow kinds but not mnemonics; acceptance is the propagated
  class above 0.93 on the module pair with anchors still exactly 1.0.
- m12-003: DONE (2026-09-14). Named a retail image from a decompilation
  with symbols: `diff retail --reference <decomp-ELF project> --apply`
  on Pokemon Emerald (retail .gba vs the decomp's own .elf) matched 14210
  of 16167 target functions (13372 body-digest anchors) and applied 14067
  names. Scored against the decomp's `pokeemerald.map` truth: 4507 of 4550
  scored ports correct (99.05%); the 43 misses are propagated
  (alignment/context) pairs, not anchors. Perfect Dark's .z64 is on disk
  but has no companion decomp ELF in the corpus, so Emerald carried the
  acceptance; the mechanism is format-agnostic.
- m5-015: the eleven DS entries whose recorded instruction set disagrees with
  the ELF's mapping symbols (was 116). Each is an ARM function inside a
  stretch a Thumb pattern painted to the next change point; the console's
  `context` set paints where Ghidra sets one address and lets flow carry it.
  Bounding an accepted pattern's paint to the body its `validcode` walk
  proved, and re-painting the tail with the value it held, closes the class;
  acceptance is 0 disagreements and no DS ratchet moving down.
- m5-016: HeartGold ARM9 recall 0.6594 over 11019 symbols. The 3757 functions
  stock and the symbols hold and we do not: score them by how stock reached
  each (pattern, switch case, data pointer, call from a body we lack) with
  the m5-013 scorer's `sample misses`, and take the largest class. The
  ratchets move up with each.
- m4-039: the DS parity residue, 118 of 512. The first-token classes are
  callee prototypes (`longlong`/`int` widths at the callee, 31 before
  truncation on N64 -- the same fact class on ARM), `thunk_FUN_` naming for
  a tail-call thunk stock creates and we do not (15), and the oracle's
  stack-slot merging (`uStack_` vs our `local_`). Each is a fact class to
  name or a store fact to add.
- m11-003: the switch round's cost. m11-001's import is 11.5 s -> 45 s and
  65 -> 229 MB peak because every function with an indirect jump is
  decompiled, in parallel workers that count in the peak. Ghidra pays the
  same decompiles; what is ours to reduce is the second walk each round
  triggers (a walk is 4-18 s on Bond) -- resume the walk from the new case
  targets instead of re-walking the image.
- Movie.elf precision 0.7844: case labels named by the module's own data
  pointers stand as functions where their flow-proven spans do not overlap.
  Stock creates them too (the shared DS set holds 64 such), so the parity
  gate holds them; whether to refuse them against the symbols' evidence is a
  user-visible choice and is recorded here rather than made.
- Coverage research, verified by a read-only scout (2026-09-10) so the three
  items below start from sources rather than recollection:
  - **Disassembly failure classes as support-matrix rows.** Pang et al.,
    "SoK: All You Ever Wanted to Know About x86/x64 Binary Disassembly But
    Were Afraid to Ask", S&P 2021, doi 10.1109/SP40001.2021.00012 (PDF
    arXiv:2007.14266). Its corpus is 3,788 binaries and **x86/x64 only**, so
    it cannot supply rows for our ARM/MIPS/PowerPC platforms. It does not
    publish one exhaustive failure-class table: §III-D names three
    indirect-jump subclasses (jump tables, indirect tail calls, hand-written
    indirect jumps such as `longjmp`) and treats indirect calls, tail calls
    and non-returning functions separately, while data-in-code, overlapping
    instructions, PIC constructs, invalid opcodes, padding, code gaps and
    xref/function-entry errors appear as constructs and error modes in
    §III-A and the introduction. A support-matrix row therefore has to state
    which section it comes from; claiming "Pang's taxonomy" as a closed list
    would be an invented citation. Each row needs a detectable observable,
    which for us means: bytes decoded inside a ground-truth non-instruction
    region (data-in-code), recovered instruction ranges that overlap or a
    target landing mid-instruction (overlapping), and a bounded target set at
    an indirect branch (jump table) -- all three of which our store already
    holds the inputs for.
  - **Pre-disassembly byte analysis.** Nguyen, Priyadarshan, Jiang and Sekar,
    "Analyzing Bytes: Pre-Disassembly Static Binary Analysis", PACMPL 2026,
    doi 10.1145/3808292: exhaustive disassembly at every offset gives a
    superset CFG, and backward analyses prune it without polluting the
    intended instructions, in O(n) with a result for every n-byte offset.
    Inputs are raw bytes plus architecture semantics -- no symbols. The
    reference implementation is <https://github.com/nhuhuan/sba> under
    **GPL-3.0**, which is incompatible with vendoring into this Apache-2.0
    tree; a port must be clean-room from the paper, as the decompiler port
    was. A gate can assert only per-offset agreement with symbol-table truth
    on the offsets that truth covers, and must refuse claims beyond them.
- Reserved, and the only things left that are: adding a *new* target game,
  platform or corpus binary (II.1) -- the retail images used (Perfect Dark,
  Emerald, HeartGold, the Vita and 3DS titles, Agent Under Fire) were
  approved by the user in conversation and live outside the repository;
  tagging a release; and reversing a user-visible naming or typing choice to
  close `name-convention` 11 or `type-stronger` 66 -- both now decided at
  user discretion 2026-09-11: `type-stronger` stays ours (the class is a
  symmetric cast difference and stock's cast, e.g. `(code *)`, is absent
  from our output because the slot is already typed per m4-030 --
  matching stock would delete information); `name-convention` also
  stays ours, and the premise was checked rather than assumed: WE coin
  `_plt`, stock leaves `FUN_<address>` (m4-031 documents and bounds the
  coinage, green 2026-09-11), so there is nothing to adopt and no
  re-baseline to do.

- Recorded deficit, now half closed: a tail-called leaf function is
  invisible to flow analysis in both Romwright and stock Ghidra. **The
  transfer is recorded as of m5-006** (`037f802c -> 037f8000`,
  `UNCONDITIONAL_JUMP`); the function is still not created, and neither
  does stock Ghidra create it. Promoting it is m5-007 and needs evidence,
  not a rule that happens to fit one fixture.

- Recorded deficit (mipsel follow-ups, 2026-09-11): the PIE twins gap is
  closed (ET_DYN slide on pointer words, GOT slots as candidates, reloc
  shapes recorded), but two rows remain. `mipsel_cpp_o2` is 17/18:
  `_Z7do_worki`'s entry *is* recovered, unwind-seeded from the
  `.eh_frame_hdr` index (proven: index xref `0x10738 -> 0x20940`,
  stored as `FUN_00020940`) -- the twins miss is walk-divergence only,
  64 bytes stripped versus 108 unstripped (a `bltz` at entry plus TLS
  `rdhwr` shape), so no body anchor fires. Same bytes,
  seed-dependent walk outcome; imports are deterministic run to run
  (m12 twins exemption, staleness-guarded). `mipsel_many_o2` recovers
  7 of 408: `main` arrives only as a `__libc_start_main` argument (a
  const-prop DATA xref, never a call target), and nothing seeds
  argument-held function addresses on any architecture
  (x86_64_many_o2 misses `main` the same way) -- that one is a
  seeding gap, not a walk gap (producer pinpoint: the 7 recovered are
  flow 5 / call 1 / thunk 1; pattern, pointer and unwind claim nothing
  on this image, so the walk starts from entry+calls alone). FIXED
  2026-09-11 by const-prop DATA-to-code seeding (`const_data_targets`):
  every constant-propagated DATA value into executable code seeds a
  candidate, flow confirmation still applying downstream. mipsel_many_o2
  7/401 -> 401/401 (m3 exemption retired by its own stale guard);
  x86_64_many_o2 `main` recovered the same way. A call-site window was
  tried first and dropped: MIPS calls through registers leave no call
  fact to window around. Scale residue, measured on libc (3987
  recovered): the p-code use filter (denies comparisons, bool/float
  shapes) killed 12 CMP-seeded orphans; 4 LEA-materialized stubs remain
  (table bases/segment bounds, no symbols, no callers, stock creates
  none) plus 22 pre-existing flow/call orphans. Cost of the rule at
  scale is 0.1%, isolated and non-swallowing; a store-time containment
  guard retracts any const seed that would swallow better-evidenced
  entries, and emitted features are filtered to stored rows (retracted
  seeds left 4 orphan feature rows at libc scale).
- Reliability incident 2026-09-11: a disk-pressured m12 run published
  partial analyses to the shared import cache, which read back fine
  and silently served 95 functions for a 124-function twin (twins
  recall 0.77). Cache keys bumped v1 -> v2 (old files linger
  inertly); operational rule is TMPDIR/SQLITE_TMPDIR plus gate work
  dirs on disk-backed storage, and m13 refuses under 2GB free. A
  publish-time disk guard needs statvfs (no such dep); skipped. A wiring
  gap is ruled out: the console loads 582 MIPS rules and returns 4
  matches here (7 on plain_o2); x86_64 patterns are equally sparse by
  design (20 rules, 6 matches on a 400-function image). Stock's 411
  tile .text at median 8B gaps (our 7 are a subset); stock is working
  the whole block, but not by promoting everything (it misses the
  unreferenced `add` leaf too). Next probe for the fix: what stops our
  walk at 0x205c0 -- gp-relative `jalr $t9` following is the suspect,
  not seeds and not tables (many.c has no switch).
- Head-to-head goto delta, root-caused: the pilot imports the
  *stripped* copy, whose symtab is gone -- and the 64-bit loop harvests
  function names from SHT_SYMTAB only, never from SHT_DYNSYM, so all
  ~2000 defined dynamic FUNCs arrive unnamed (16 named of 4090; the
  unstripped twin keeps 3905). Without names, noreturn misses
  (`__stack_chk_fail` is FUN_-named), flow falls through the call
  into 10KB of neighbors (54KB of C, 106 gotos), and the worker
  faithfully renders the soup. Fixed by harvesting defined dynsym
  FUNCs; on a current store the same decompile emits 1059 bytes.
  (Prior investigation on the degraded store stays valid as a protocol
  fact: MAPSYM body ranges were tried and reverted -- ranges decode
  into symbol uselimit, not flow span. Ruled out along the way, kept so
  the dead ends stay dead: VSA handed nothing bogus (3 callreturn
  overrides in range), recovery at parity (same 6 in-range entries),
  inlining out (the inlined callee is 9584 bytes).)
- Recorded deficits (PE format, observed once on a large MSVC image now
  out of the corpus; need small-format reproducers, which need user
  approval as new corpus binaries under II.1): (1) linker MAPs list
  chained SEH fragments (`UNW_FLAG_CHAININFO` records) as functions,
  but the unwind pass deliberately skips them per Ghidra's rule -- a
  chained record continues a function that already has a start
  (`pe_unwind.rs`, unit-tested; m8-001 promotes the 192 plain
  records). Low recall against that denominator is a truth-set
  spurious entries. Both are format properties, not image
  properties: any SEH or delay-load PE should reproduce them.
  (verified by double import).

## Console sequencing decision (agent judgement, 2026-09-07)
The ten platforms recorded in "Reserved decisions" split by what can be
*proved* with the machinery that exists, not by appeal:
- **Tier 1, now** -- language present in the pinned install, container
  documented, and a DWARF twin buildable from source, so an M3-style gate row
  is possible on day one: GBA (`ARM:LE:32:v4t`, raw ROM), NDS
  (`ARM:LE:32:v5t` + `v4t`, two CPU images per container), PS1
  (`MIPS:LE:32:default`, PS-EXE), N64 (`MIPS:BE:64:64-32addr`, Z64/V64/N64).
- **Tier 2, prerequisite-gated** -- the processor blockers recorded here on
  2026-09-07 are now all cleared: the pinned install ships PSP's Allegrex
  *with* the VFPU (Processors/Allegrex/allegrexVfpu*.sinc), PS2's R5900 with
  MMI and VU0-macro (Extensions/ghidra-emotionengine-reloaded), PS3's Cell
  SPU (Extensions/GhidraSPU), and Xbox 360's VMX128 is modelled natively
  (native/languages/xenon, PowerPC:BE:64:Xenon-32addr). Verified by decode:
  paddw, vadd.s, and SPU a/nop all disassemble. The one remaining blocker is
  per-title/console-provisioned key material for the encrypted containers
  (3DS CIA, PS3/Vita SELF, Switch NCA/XCI). II.1 forbids the runtime fetch,
  so the loaders take a user-supplied KeyStore (`--keys <file>`): a Switch
  prod.keys, a PS3 .rap, a Vita .klic, or a 3DS aes_keys.txt now decrypts on
  import (m18-002). PSP ~PSP/KIRK now decrypts too — the KIRK vault and tag
  keys are long-public constants (PSARDUMPER/JPCSP), embedded in
  native/kirk_tables.rs like the XEX retail key (m18-003).
- Rule for every platform: it is "supported" only with a loader, a language
  mapping proven by decoding, and a gate row scoring it. No platform is
  claimed from a successful import alone.
- Corpus membership stays reserved (II.1): each platform's gate input needs
  human approval before it becomes a corpus member.

## Reserved decisions
- m1-010 gate amendment: architecture-specific code is permitted only in a
  clearly separated accelerator module with an equivalence test, never in the
  discovery core. (Recorded per user direction; do not re-argue.)
- Rewriting the vendored C++ decompiler is **not** the next milestone, and
  never a transliteration. The old repo's partial port reached 79% of rules
  and 44% of actions and still did not converge on real functions, and no
  oracle can score it: stock Ghidra *is* the oracle. Instead take ownership
  of the layers where published work beats it and where ground truth already
  exists here -- structuring (SAILR, goto count against stock on the same
  functions), types (TIE/Retypd against the DWARF we hold for 1,640
  functions), indirect flow (SJA; the combined switch path already answers
  142 dispatches to stock's 132 at 0.9967 soundness, without the
  decompiler), and variable/stack recovery against DWARF. Its entry
  criterion is ownership, not a date: **we own more of the decompiled output
  than the vendored tree does**, measured by those gates, at which point the
  remaining core is the simplifier and it can be replaced against a known
  interface, known metrics, and a regression corpus that reports the day it
  gets worse. Corollary: the first work under this plan is an *export* from
  the pinned tree (block graph, varnode facts), and that export is a
  documented stable surface, because it is the seam the eventual replacement
  plugs into. (Recorded per user direction; do not re-argue.)
- Console platform targets (recorded per user direction, 2026-09-06; not
  scheduled yet): PS1, PS2, N64, Game Boy Advance, NDS, 3DS, PS3, Xbox 360,
  PSP, PS Vita. What the pinned Ghidra 12.1.3 install already supplies, from
  `romwright-cli architectures`:
  - PS1 R3000A -> `MIPS:LE:32:default`; N64 VR4300 -> `MIPS:BE:64:64-32addr`;
    PSP Allegrex -> `MIPS:LE:32:default` (VFPU unmodelled); GBA ARM7TDMI ->
    `ARM:LE:32:v4t`; NDS ARM946E-S/ARM7TDMI -> `ARM:LE:32:v5t` + `v4t`;
    3DS ARM11/Cortex-A9 -> `ARM:LE:32:v6` + `v7`; Vita Cortex-A9 ->
    `ARM:LE:32:v7`; PS3 PPE and Xbox 360 Xenon -> `PowerPC:BE:64:default`.
  - Missing from the pinned install: no R5900 language id (the `r5900l/r5900r`
    strings in `mips.ldefs` are IDA aliases on generic MIPS, so PS2 MMI and
    VU0 macro ops are unmodelled) and no Cell SPU processor at all. VMX128 for
    Xenon is now modelled natively: `native/languages/xenon` builds
    `PowerPC:BE:64:Xenon-32addr` with the 128-register vector unit, and the
    XEX loader names it.
  - No console loader ships with Ghidra; OSI-licensed third-party loaders and
    processor extensions exist and are citable under the clean-room policy
    once each licence is recorded in `docs/third-party.md`: NDS
    `pedro-javierf/NTRGhidra` (Apache-2.0), Vita `CreepNT/VitaLoaderRedux`
    (BSD-3-Clause-Clear), PS2 `chaoticgd/ghidra-emotionengine-reloaded`
    (Apache-2.0, also supplies R5900 MMI/VU0 SLEIGH), GBA
    `pudii/gba-ghidra-loader` (Apache-2.0), PSP `kotcrab/ghidra-allegrex`,
    N64 `zeroKilo/N64LoaderWV`, Xbox 360 `zeroKilo/XEXLoaderWV`, 3DS
    `StartForKiller/ghidra-ctr-loader`, PS1 `lab313ru/ghidra_psx_ldr`.
    They are Java Ghidra extensions; the JVM is temporary here, so the reuse
    path is to port the documented format facts into the native loader and
    record provenance and licence, never to link their code.
  - Encrypted containers (3DS NCCH/CIA, PS3 SELF, PSP EBOOT, Vita SELF,
    Xbox 360 XEX) are accepted only already decrypted: no keys are bundled and
    no runtime network call is permitted (II.1).
  - Adding any of these as a corpus member still requires a human decision per
    II.1, one platform at a time.

- Head-to-head follow-up, N64 row 58 -> 57: bisected to 83fac980
  (const-data seeding), which coined `_FUN_8008fa74` over the known data
  symbol `DAT_8008fa74` -- the seeded counter is load/store-accessed, and
  the decompiler rendered the overlap warning plus the wrong name, breaking
  token identity for 80002538. Fixed at the store, not the seed: a
  const-seeded entry the analysis itself reached as data
  (`reference_widths`) is retracted like a swallowed entry -- access wins
  over seeding, order-independent, const class only. Reviewed 2026-09-11:
  a callback address is never memory-accessed (only called), so the guard
  cannot fire on the rule's intended wins (mipsel/x86 callbacks); slot vs
  target addresses differ, so table-driven seeds are safe. m4-003 back to
  58/116; m3/m12/m17/m19/m16 identical pre/post.

- m18-002 red by improvement, owner to re-bar (2026-09-11): the dynsym
  harvest recovers the zlib pair's real names, so the judged set grows
  106 -> 157 and both settings go 157/157 correct (precision 1.0, recall
  0.9345 vs floors 0.908/0.469; pure-HEAD control: 98/97 correct, recall
  0.5833, PASS). The gate's structural bar -- context must gain a correct
  pair -- is vacuous at that ceiling: raw similarity already maxes the
  judged set, so there is nothing left for context to rescue. Not a
  regression on any recorded metric; but the bar's intent (prove context
  helps) needs a name-scarce construction again, which is the m18 owner's
  call -- left red deliberately, not re-barred unilaterally.

- Residue (2026-09-11): the const-data retraction only fires where a sized
  access was recorded, so on the N64 image 8008fa74/8008fdf0/8005ce74
  retract but 8008fa80 (size 13), 8008faa8 (24) and 8008fac0 (size 1) --
  all producer='const', same data window, all absent from the oracle --
  survive. 8008fac0 never decoded a body (size 1: no flow confirmation,
  which the seeding rule claims to require). No gate is red because of
  them (token row green, recall intact); closing the class wants a second
  retraction condition on undecodable const seeds, recorded here as a
  deficit, not implemented.

- Out-edge retraction tried and rejected (2026-09-11): a const seed with
  no CALL inbound and no body-range out-edge looked like the residue
  killer (N64 fa80/faa8/fac0 have DATA-only inbound, zero out-edges;
  real functions emit body out-xrefs). It cleared the window (136 -> 117,
  all oracle-absent) but retracted the real leaf restorer __restore_rt
  on libc (recall 1.0 -> 0.9997, discovered 1.0 -> 0.9994). First version
  was worse (point match on entry: 136 -> 116). Verdict: taken-address
  vs quiet-leaf is undecidable at store time; the residue deficit above
  stands, this direction is closed.

- m18-002 re-barred (2026-09-11): the gain rule (semantic-on must hold a
  correct match semantic-off misses) is retired, not weakened around --
  with the stripped import recovering real names both settings resolve
  the whole judged set (157/157), so an empty margin is expected.
  Control: the passing era's gain pair still matches in both settings,
  lost stays empty. Kept: no-loss (hard gate) plus floors raised to
  lock the win (precision 0.908 -> 0.95, recall 0.469 -> 0.85; measured
  1.0/0.9345 twice). The context demonstration lives in b47e9656.

- m13-002 progress (2026-09-11): the refusal ledger is now per-branch,
  not per-class. Memory-expression seeding (force a load's symbolic
  address to each index; stride/escape/contiguity logic untouched)
  recovers the PIC-offset shape (`movsxd [base+i*4]; add base; jmp` with
  the index behind a pointer): 0x16ed3d answered. Constant pre-seeding
  (input-free COPY/ADD chains across window+guard defs, single-def,
  persistent slots only) answers 0x1db6be (its table base is a guard
  `LEA`). vsa 90 -> 94, interpreted 131 -> 133 at 1.0 soundness, phase
  3.9s. Gate truth now merges `.cold` partitions into parents
  (exact-name match): the two "outside" targets sit in cold FUNCs both
  tools report, so the 0.9989 bar stands unrelaxed. Still missed (11:
  the 13 decode-checked branches minus 0x16ed3d and 0x1db6be, since
  recovered; the junk verdict itself stays retracted):
  loop-carried bounds (0x190be9/0x19b3b9),
  unguarded offset composition (0x184aba), unknown bases (0x1ce42a R12),
  object dispatch (0x1dae47), absolute-table extent (0x2366c7), three
  stock-only big switches, two notrack-guarded dispatches (0x121073
  shows the movzbl/movslq/add/jmp PIC chain but no in-window load moves
  (base R15 and index dl both Top from outside), so it is outer-base
  class with 0x1ce42a, not reload-after-compare like 0x16ed3d;
  0x265ffe is a computed ladder with two independent blockers: no
  strided load (target computed arithmetically, refused by construction
  through the measured 0.42-precision requirement) and no loop-carried
  bound in reach. A loop-bound design recovers 190be9/19b3b9 but not
  this one; it additionally needs a no-load path with a bound strong
  enough to replace the load requirement.
  Cutover (decompiler out of the
  switch round) waits on missed <= 3.

- Switch windows deduplicate (2026-09-11): flow shapes accumulate across
  discovery rounds, so later rounds emulated identical predecessor blocks
  twice per index. Sort+dedup in `switch_window` (window and guard) is
  answer-identical, recovers ~0.5 s of switch phase (3.9 -> 3.7 s).

- R12 verdict (0x1ce42a, 2026-09-11): its `LEA` block falls into a loop
  header (back-edge `JG 0x1ce400` from 0x1ce439 alongside the fallthrough), so sole
  entry correctly refuses and a wider predecessor trawl measured zero
  twice -- reverted. The sound generalisation is no-write-between: R12
  is set before the loop and never rewritten inside it, so carry a
  constant when no block on any path between def and dispatch writes
  the slot (checkable from decoded blocks), not when entry is sole.

- Why multi-source collection also missed R12: the loop body reloads it
  (`MOV R12,[RBP-0x20]` at three sites for one `LEA`), so single-def
  counting drops the slot even with every predecessor collected. Same
  value, three definitions -- carrying it needs spill-aware resolution
  (LOAD[FP-c] through STORE[FP-c] to the LEA value), not wider
  collection. Unbuilt; the trace-first rule from here on is to watch
  the per-branch candidate lines on a 30 s traced import before paying
  for a gate run.

- Entry-block preseed tried and reverted (2026-09-11): carrying
  function-entry constants (R15's `LEA` for 0x121073) poisoned a working
  chain instead (0x15a792 lost: trial loads went empty), and bought
  nothing (0x121073 still missed). An entry const holds only where the
  entry dominates; collected-region single-def cannot see middle-block
  redefinitions, and neither a sole filter nor no filter saves it. The
  window+guard joint preseed (which demonstrably fired for 0x1db6be)
  stays; the entry channel is fully reverted, restoration confirmed at
  trace level.

- m12-002 indexed mode, histogram tried and reverted (2026-09-11):
  `m12-001_diff.py --index` indexes semantics before diffing and floors
  the propagated (alignment) class on optimisation rows (precision 1.0
  over 9 judged, twice). The indexed run lifts optimisation recall
  0.9377 -> 0.9532 with twins and anchors exact -- but ablation
  (HIST_WEIGHT=0, identical numbers) proves the gain is the semantic
  term, not the new instruction-class histogram: p-code class mixes are
  too dense to move any pairing on these rows, and near-duplicates with
  identical data-flow have identical op mixes by construction, so a
  content histogram cannot separate the false-pair zone either. The
  term is reverted rather than shipped unmeasured; the mode stays as
  the vehicle for the module pair. That acceptance is unblocked: the
  pair lives under ~/Projects (not the corpus), pinned by m11-002;
  propagated 0.9372 against the brief's 0.93 bar, anchors exact save
  three exempted identical-code ambiguities recorded below.

- Recorded deficit (module rows, 2026-09-11): three anchor misses are
  body/shape keys colliding across distinct degenerate functions,
  exempted visibly with the twins tripwire (m12 modules exemption,
  staleness-guarded) -- not truth ambiguity: EXI2_Poll and Hu_IsStub
  are different functions sharing one stub slot's bytes at the same
  address in both modules (crossed spellings both directions), and
  EXIDeselect vs CheckDVDError share a shape digest with distinct
  names. Narrowing the keys (minimum body size) was judged riskier
  than three documented addresses: tiny-but-unique bodies are often
  the best anchors elsewhere. Both modules link at 0x80680000, so
  same-address coincidence across them carries no identity. Module
  evidence lives in benchmarks/reports/m12-001-modules.json, recorded
  where the pair exists; CI machines without it skip those rows.

- Better-than-Ghidra games program (research 2026-09-11, three scouts).
  Nobody decompiles vector units (Ghidra: no RSP/VU/GTE/DSP, one
  unfinished community VU0; IDA: disassembly-only plugins; decomp
  projects use hand-asm, blobs, or recompilers, never auto-C), console
  format support is community-fragmented everywhere (Ghidra/IDA/Binja
  all rely on per-format plugins; Nintendo MAP unsupported by all;
  containers external via hactool/wit/Dolphin; splat lives outside RE
  tools), and Ghidra carries years-open game bugs (PPC r13 SDA #325,
  PS3 TOC #570, MIPS enum casts #4236, ROM mutability #278). No
  head-to-head game benchmark exists anywhere. Axes, sequenced by
  value over cost: (1) quick wins this codebase already brackets --
  PPC r13 SDA globals (Agent Under Fire is PPC and on disk), MIPS
  enum casts, ROM mutability in our memory model, Nintendo MAP
  ingestion, container-direct import; (2) overlay-aware project model
  (DOL/REL/NSO cross-module xrefs/names; m10 multi-image is the base)
  plus splat segment interop and asm matching (m12-003); (3) vector
  specs for disassembly first (RSP/VU0/GTE), then lifting to readable
  C -- the greenfield moat, months. Every axis gets a superiority
  gate (beat stock), never a parity gate: parity is C1, this program
  is C2 generalising to games.

- Better-than-Ghidra breadth closed (2026-09-11, four more scouts).
  PSP/Vita: PBP/PRX/SELF/PFS all external-decrypt, NIDs via sparse
  external DBs, PPSSPP WebSocket + Vita3K GDB as runtime backends nobody
  integrates. Xbox: XEX crypto/XEXP/STFS preprocessing fragmented,
  retail PDBs unavailable, BN/Rizin need external prep. PS3: no
  maintained SPU lifter anywhere (community plugins dead/WIP), TOC/OPD
  still partial (#570 + #1540), RPCS3 debugger unintegrated. GBA closed
  (mature + mGBA); mobile gap is Unity/Il2CppDumper workflow
  (dump.cs -> names) integration, not CPU support. Thin spots gone:
  every console is now mapped.
- #325 reproduced live on the pinned install (not fixed upstream):
  stock names the SDA global (`HadError = HadError + iVar4`), ours
  emits raw `unaff_r13 + -0x7f00` on Agent Under Fire `RunNextModule`
  (0x80682770). Chain pinned: HadError OBJECT at 0x806a9980 (.sbss),
  _SDA_BASE_ ABS 0x806b1880, target = r13 - 0x7f00 exactly; our store
  holds no symbol or data-definition for it. Recommended first slice:
  SDA data symbols from symtab OBJECTs through store to the worker's
  r13-relative application, gated on this function rendering `HadError`
  while stock keeps naming it -- then find stock's remaining
  `(r13 - x)` cases and beat those.

- #325 first slice landed (2026-09-12): SDA data symbols from symtab
  OBJECTs through the store to the worker's r13-relative application.
  `RunNextModule` (0x80682770) renders `HadError = HadError + iVar2`
  (was `*(undefined4 *)(unaff_r13 + -0x7f00)`); r13 = `_SDA_BASE_` ABS
  0x806b1880, HadError OBJECT 0x806a9980, both measured against
  `PowerPC_ElfRelocationContext.getBaseOffset` (symbol wins, else
  `.sdata`+`.sbss` min, midpoint past 0x7fff, no width gate on r2).
  Two raw-SLEIGH traps found live: register names in `<context_set>`
  fail registration (registers ride `<tracked_set>` only), and one
  `<tracked_set>` per range (a second element over a range clears the
  first). Gates: `tests/ppc_sda.sh` (synthetic 495-byte PPC32 fixture,
  red pre-slice as `unaff_r13 + 8`), 6 seeder unit tests, elf_image
  7/7, corpus.sh 5/5. Follow-up 98cae1f2: the r13 rows also reached
  the reference console, whose setVariable rejects real registers --
  every SDA import silently skipped reference inference (`Non-existent
  context variable: r13`). `load_mapped` now skips exactly r13/r2 (not
  registers.txt: ARM `TMode` rows share a register name and must load);
  the gate asserts a note-free import, MIPS unaffected. Typed split
  landed next: the seeder writes `register_contexts` ranges (the t9
  shape), the store funnels one decode point per range for r13/r2, and
  the console filter is gone -- `imp.contexts` carries variables only.
  The reference pass now folds r13: base.elf holds constant-prop DATA
  xrefs to HadError (were 0) and imports 648 functions (were 644), and
  `HadError` still renders with no `unaff_r13`. m5-013 NDS fails
  identically pre-slice (worktree control at 2ccbfdad^): pre-existing,
  not this slice; last green report 09-09. Open follow-ups:
  `_SDA_BASE_` ANALYSIS label on the section-fallback path, r2 second
  register in the fixture, ABS-0 skip (inert on Linux rows: no
  r13-relative code, verified by decompile), PPC64 convention gate.

- m4-003 language parity re-run (2026-09-12, after #325 + m5-013 slices):
  PASS, 2196 of 2292 functions token-identical across 21 corpus rows,
  classes byte-identical to baseline (type-stronger 66, oracle-warning
  23, name-rendering 12, name-convention 11, data-unknown/name 4+4,
  language-variant 3; missing-data-symbol 0 before and after -- the
  Linux rows carry no SDA code, so nothing to shrink). ARM cartridge
  row holds 4/4 identical; NDS UNREACHED row 395/512 identical of 7364
  shared (floor 394). Baseline stands, no re-record. Note: run needs
  TMPDIR on /home -- /tmp tmpfs (7.5G) overflows on the JVM rows.

- m20-001 (2026-09-12): CodeWarrior MAP ingestion, first M-A row. New
  `native/cwmap.rs` reads the mwldarm grammar (`N](name,type)` link rows,
  `# .subsection` layout headers, `(lib.a member.o)` archive TUs, CRLF)
  and dtk's `N] name (type,vis)` shape; kind precedence is link-map
  `func`/`object` first, then section heuristic (code section -> Func,
  data -> Object) because the link map lists globals only -- static
  functions exist solely as layout rows. `romwright-cli import --map FILE`
  seeds named functions (linker truth renames discovery coinage),
  object sizes/names, and `$t`/`$a` mode contexts before discovery;
  the map digest rides the import-cache flavour. Gate
  `tests/m20-001_cw_map.py` on HeartGold (11 MB MAP + full-symtab ELF +
  byte-exact ROM): **named recall 0.9946 over 11019 ELF FUNCs, MAP/ELF
  agreement 0.9946**; stock Ghidra has no DS MAP importer (R7 baseline).
  Overlay-range FUNC rows are gated out of the static import by the
  executable-mapping check until M-C gives them programs.

- m20-002..006 (2026-09-12): linker-MAP and decomp-symbol ingestion,
  five grammars through one `--map` flag (`native/linkmap.rs` sniffs):
  mwldarm/dtk (m20-001, HeartGold, recall 0.9946 over 11019 ELF FUNCs),
  PsyQ/SN (m20-002, VS.MAP, 0.9976 over 818 .text-extent names), GNU ld
  (m20-003, pokeemerald.map, 1.0 over 5280 .text rows), MSVC /MAP
  (m20-004, ffxv_s.map, 1.0 over 154379 publics), flat ADDR NAME
  (m20-005, FE Fates symbols.map on raw code.bin via new `--raw BASE
  --language ID`, 1.0 over 26117 rows). dtk symbols.txt / splat
  symbol_addrs.txt ride the same flag (m20-006, Agent Under Fire
  dtk-template: 1.0 over 8522 function rows, export->reimport
  round-trip 8522/8522 via new `export-symbols`). Kind precedence where
  a grammar types rows: linker `func`/`object` wins, `notype`/absent
  falls through to the section heuristic -- link maps list globals
  only, so static .text rows are still code. Overlay-range rows are
  gated out of static imports by the executable-mapping check until
  M-C. PSX .SYM and PS2 DWARF1/Vita-NID are the remaining M-A rows
  (agents in flight); decomp.me API and objdiff unit mapping are M-B
  follow-ups, not yet gated.

- m20-005b (2026-09-12): MIPS `.debug` (SHT_MIPS_DEBUG) ingestion. New
  `native/mdebug.rs` sniffs two grammars under the one section type:
  ECOFF/mdebug (HDRR/FDR/PDR/SYMR/AUX/EXTR, layouts from binutils
  `include/coff/{sym,mips}.h`, semantics from gdb `mdebugread.c` --
  procedure size via the stEnd aux indirection, packed-line instruction
  count as fallback, `-x` files resolving PDR isym through the external
  table) and Metrowerks DWARF 1 (length-includes-self DIEs, attribute
  codes packing `(attr<<4)|form`, 4-byte null entries). SLUS_209.50
  carries the MW shape: 5221 subroutine DIEs, every one already a FUNC
  symtab entry with identical name and size, so the gate asserts
  agreement plus no regression rather than a count delta. The `mdebug`
  phase in `--timings` output proves the reader ran. Gate
  `tests/m20-005_mdebug.py`: PASS, 8795 functions, all 5221 DWARF1
  subroutines agreeing with symtab. Line info (`.line` section,
  AT_stmt_list) has no destination table in the model and is skipped.

- m20-006b (2026-09-12): Vita SCE ELF + BINMAP. `native/sce.rs` walks
  ET_SCE_EXEC export/import tables (segment offsets, NID-keyed stubs);
  `native/binmap.rs` parses the 39461-record BINMAP blob and renames
  sce_import_*/sce_export_* placeholders through its NID->name table.
  PT_LOAD fallback covers stripped section headers. Gate
  `tests/m20-006_vita_elf.py`: **PASS, 572 SCE-seeded + 29488
  BINMAP-named functions, NID imports resolved**.

- m20-006c (2026-09-12): decomp-project emit side. `export-dtk` writes
  config.yml + symbols.txt + splits.txt from the store; verified by
  `dtk dol diff` on the emitted project against bond.elf: **0 errors**
  (the project's own symbols.txt diffs with 9 ambiguous @456 rows).
  `export-splat` writes <program>.yaml + symbol_addrs.txt; the emitted
  symbol_addrs re-imports 8524 functions. parse_flat now accepts
  splat's `0xADDR name;` rows (previously required bare 8-hex, dropped
  every splat row). This is the first half of our own splitter: the
  store already holds everything splat's split step needs (functions,
  data defs, regions, xrefs); the remaining piece is `split` emitting
  per-function asm + linker script, which lands as its own milestone.

- m20-007 (2026-09-12): PSX/PS2 `.SYM` ingestion, closing M-A. New
  `linkmap::parse_sym` sniffs the binary `(u32 addr, u32 name-off)`
  record + string-table grammar; `MapKind::Sym` carries the untyped
  rows and the executable-mapping check decides code vs name. Gate
  `tests/m20-007_sym.py` on nightfire-ps2 DRIVING.ELF+DRIVING.SYM:
  **PASS, 8055 functions, recall 1.0 over 8054 code-range rows**
  (12719 total; the rest are data/linker-defined names). M-A complete:
  5 text MAP grammars + dtk/splat + .SYM + mdebug + Vita NID/BINMAP.

- m20-006d (2026-09-12): objdiff + decomp.me interop, closing M-B.
  `export-objdiff` emits objdiff.json units grouped by splits.txt TU
  (new `SplitExtent.tu`); verified end-to-end — `objdiff-cli report
  generate` on the emitted config against the real build objects:
  **41 units, 548 functions, 99.45% matched**. `export-scratch` emits
  a decomp.me payload (target_asm.s + ctx.c + scratch.json) from a
  stored function's disassembly; the POST itself is Cloudflare-gated
  here, so the payload is the deliverable. M-B complete: dtk
  (import+export+dol-diff), splat (import+export), objdiff
  (export+report-verified), decomp.me (payload).

- m20-009 (2026-09-12): container-direct import, first M-D row. New
  `native/iso9660.rs` reads the primary volume descriptor, walks the
  root directory, resolves `SYSTEM.CNF`'s `BOOT2` to the boot ELF, and
  imports every root ELF as a sibling image (boot first). Gate
  `tests/m20-009_iso.py` on the nightfire-ps2 ISO: **PASS — 4 programs,
  boot=nightfire.SLUS_205.79, ACTION.ELF 3038 functions** from its own
  symtab (DRIVING/SLUS are stripped; their names live in the .SYM,
  gated by m20-007).

- m20-009 (2026-09-12): container-direct import, first M-D row. New
  `native/iso9660.rs` reads the primary volume descriptor, walks the
  root directory, resolves `SYSTEM.CNF`'s `BOOT2` to the boot ELF, and
  imports every root ELF as a sibling image (boot first). Gate
  `tests/m20-009_iso.py` on the nightfire-ps2 ISO: **PASS — 4 programs,
  boot=nightfire.SLUS_205.79, ACTION.ELF 3038 functions** from its own
  symtab (DRIVING/SLUS are stripped; their names live in the .SYM,
  gated by m20-007). M-D complete: every container format with a real
  test file imports directly (ELF, PE, N64, NSO, PSX, GBA, NDS, DOL,
  ISO9660); formats without fixtures (WAD, PBP, XBE, NCCH, SELF) are
  ungateable, not unimplemented.

- m20-010 + m20-011 (2026-09-12): M-E toolchain detection + M-F trace
  ingest. `NativeImport.toolchain` (distinct from `compiler`, the
  SLEIGH spec) is detected from ELF `.comment` (GCC/clang) and from
  DOL mwcc runtime symbols post-map; `ProgramSummary.compiler` reports
  it. `import-trace` ingests `addr,kind[,thread]` CSV into
  trace_events and marks exec/call/bp-hit functions traced. Gates:
  **m20-010 PASS (bond.dol=mwcc, gcc-elf=gcc 16.1.1)**, **m20-011 PASS
  (5 events, 3 traced, read/miss unmarked)**. The schema half
  (programs.compiler, functions.traced, mark_traced, ModuleRow/
  ModuleXrefRow model rows) came from the rate-limited CompilerTrace
  agent's partial work, completed here.

- m20-008 (2026-09-12): overlay-aware project model, closing M-C.
  Schema v21 adds `modules` + `module_xrefs`; `store_import` populates
  one module per memory region (DOL sections, ELF segments, REL images
  when a REL loader lands); `locate` reports the covering module on
  `LocationRow.module`; xrefs crossing module boundaries become
  `module_xrefs` rows. Gate `tests/m20-008_overlay.py`: **PASS — 12
  modules on bond.dol, locate names 'dol:0', 11 cross-module xrefs**
  on an analysed GCC hello (.text->.plt). REL loader deferred: no REL
  fixture on disk, and the modules model is format-agnostic so a REL
  lands as modules when one arrives.
- m20-013: PS2 VU + PSX GTE disassembly. `crates/romwright-core/src/vu.rs`
  decodes the EE COP2 VU macro set (tables from Ghidra's vendored
  `vuupper.sinc`/`cop2.sinc`, operand order verified against rabbitizer
  R5900); `crates/romwright-core/src/gte.rs` decodes the PSX GTE command set.
  Gate `tests/m20-013_vector.py`: VU 19281/19281 mnemonics on real
  nightfire-ps2 code, GTE 328/328 on an exhaustive command+flag sweep.
  M-G vector units complete: RSP (m20-012) + VU + GTE (m20-013).


- m16-002 (2026-09-13): type recovery scored head-to-head against stock
  Ghidra across four processors, not just against DWARF on x86.
  `benchmarks/type_headtohead.py` compiles a type-rich freestanding fixture
  (`int`/`uint`/`float`/`double`/struct-ptr/array) for a `--target`, strips
  it, and scores each tool's inferred parameter and return classes against
  the unstripped twin's `DW_AT_type`. Ghidra's side is read through the
  Stage-1 bridge's decompiler — its *inferred* prototype, not a DWARF-read
  signature. clang is the cross-compiler (no sysroot needed freestanding).
- m16-002 (2026-09-13): type recovery scored head-to-head against stock
  Ghidra **and IDA Pro 9.4** (Hex-Rays via idalib) on a stripped fixture,
  truth from the unstripped twin's DWARF. Scores (exact + 0.5·partial over
  ~37 slots):

  | target | romwright | Ghidra | IDA |
  |---|---|---|---|
  | x86_64 | 26.5 | 26.5 | 20.0 |
  | mips32le | 24.5 | 24.0 | 23.0 |
  | mips32be | 24.5 | 24.0 | 23.0 |
  | aarch64 | 25.0 | 25.5 | 20.0 |

  romwright beats IDA on every target and ties-or-beats Ghidra on three of
  four. IDA's loss is structural: Hex-Rays reports the *register* width for
  nearly every return (`__int64` where truth is `int32`) and reports pointer
  parameters as `__int64`, not `ptr` — it never narrows a return and never
  proves a pointer. Ghidra's remaining edge is the signedness convention
  (`int`/`uint` where we report sign-unproven `num`/`opaque`); we win every
  pointer and aggregate slot on every architecture.
  `long`); there is no other capability gap — we win every pointer and
  aggregate slot on every arch. Cross-arch work exposed and fixed five real
  bugs the x86-only gate hid: `address_of` now propagates through `COPY`
  (MIPS computes `*(fp+disp)` as `t=fp+disp` then `u=t`), `INT_ZEXT` carries
  any input's alias (aarch64 reloads a spilled param via `w8 = zext(LOAD)`),
  `integer_entries`/`float_entries` skip `storage="float"`/`hiddenret`
  pentries (aarch64's x8/q0-q7 polluted the integer model), a float slot
  resolves to the pair's offset for a `double` *and* the first single's for
  a `float` (big-endian MIPS puts the single at the pair's high offset), and
  a `LOAD` produces `Opaque(width)` — Ghidra's `undefined<N>` — so a
  returned load reports its size rather than `unknown`, and a `movzx` of a
  byte load reports `opaque8` not the register's 32. `void` return requires
  the return register be *untouched*, not merely unclassified. A `signature`
  field now renders the C prototype a reader sees — `num`/`opaque` take C's
  signed default (`int`/`short`/`long`/`char`), a proven struct/array
  pointer spells `void *`, arity is the highest parameter register the body
  read — while `parameters`/`structural`/`returns` keep the honest classes.
  Reports: `benchmarks/reports/type-headtohead-*.json`.

- m13-002 progress (2026-09-14): the backward slice landed -- the
  `findDeterminingVarnodes` fallback the refusal accounting named. A
  `DefIndex` (reaching definitions per block, built lazily on the first
  dispatch the forward pass leaves `Top`) backs `slice_expr`, which walks
  a `BRANCHIND`'s address input back through the SSA def-use graph into a
  `Sliced` expression. `match_table` pulls the `Load` out of it; the index
  is bounded by the expression's own structure (a mask or width) or by a
  `CBRANCH` whose compared varnode is a `quasi_copy` of a point leaf --
  the guard the forward pass could not connect. The bound is substituted
  back into the index expression before evaluation, so `r8 - 0x10` under
  `r8 < 0x20` resolves to `[-0x10, 0xf]` and the negative low end refuses
  it (the over-read the old code claimed). `read_table` scans to the first
  entry that does not read/decode/stay in-extent rather than requiring all
  `entry_count`, which keeps a loose bound from reading into the next
  table -- and for a PIC table the next table's offsets resolve against
  *this* base, so an over-read self-corrects. libc: SJA resolved 30 -> 49
  (interval-subtraction, then the slice, then bound-substitution), unknown
  133 -> 118, outside 8 -> 8, at 1.0 soundness. The remaining 131
  `None` slice attempts are a mix: real guard-less dispatches (computed
  gotos, unbounded indexes no `CBRANCH` bounds) and non-switch BRANCHINDs
  (UD2 traps and the like) that are correctly refused -- so the true gap
  is smaller than 131. Ghidra answers the guard-less real switches through
  `SwitchNormalisation` (bounds from the CFG's case-block count and the
  default edge), not a comparison -- a different mechanism than the slice,
  and the named next capability (m13-002b). Acceptance unmet: 49 of the
  142 the decompiler recovers, bar 103.

- m13-002b scoping (2026-09-14): the guard-less bound mechanism is
  `JumpBasic::calcRange` (jumptable.cc:1135), not a comparison. For a
  switch variable with no guard the range is `getMaxValue(vn)` -- the
  `INT_AND` covering mask, or the varnode's own width -- intersected with
  whatever guards apply, then `findSmallestNormal` (jumptable.cc:1180)
  picks the smallest-range varnode on the path and accepts a 1-byte
  variable only when a guard or a load sits in the path
  (`isLoadInPath`). Two slice-level pieces of that landed: the width
  bound a `movzbl`/`movzwl` index states is now honoured for PIC tables
  (`index_width_bound`, PIC-only because an over-read there self-corrects
  through wrong-base offsets; an absolute table has no such check). On
  libc it gained nothing -- the 128 remaining `None` dispatches are not
  narrow-indexed PIC reads; their index points are already wide registers
  with no mask, no guard, no narrow width. Ghidra bounds those through
  `matchsize` -- the case-block count recovered from the decompiler's
  CFG -- which is not reachable at the slice level: it needs the
  recovered switch CFG, a milestone-scale mechanism, not a slice fix.
  The honest boundary: the slice answers every dispatch whose bound a
  comparison, mask, or narrow width states; the rest need the CFG.

  A second slice-level piece landed the same day: the guard-less PIC table
  whose index is `Top` outright -- no comparison, mask, or width anywhere.
  Ghidra's bound there is the memory scan in `JumpBasic::sanityCheck`
  (jumptable.cc:1592): read entries until one does not decode as in-extent
  code. `read_table` now takes a `Value::Top` index as exactly that scan,
  by entry position (`table_base + k*entry_size`), and `slice_dispatch`
  reaches it only for `offset_base.is_some()` -- PIC-only, because the
  next table's offsets resolve against *this* base so an over-read
  self-corrects, while an absolute table's neighbours are valid code and
  the scan would over-read into them (the `a_dispatch_no_comparison_bounds
  _is_refused` / `a_zero_extended_index_without_a_guard_is_refused` tests
  pin that refusal). On libc it recovered nothing -- every PIC table there
  carries a guard, so the `Top` arm never fires; the new
  `a_guardless_pic_table_is_scanned_to_its_first_invalid_entry` test
  exercises it. The capability is real but the corpus that needs it is
  embedded (game) images, not PIC-guarded libc.

## Semantic IR, immutable execution, and matching runs (2026-09-14)

This replaces the earlier token-backed transform prototype. It does not close
the separate M1–M4 corpus acceptance gates.

- `romwright-model::function_ir` owns the shared semantic graph: stable values
  and operations, SSA ownership, predecessor/successor multiplicity, high
  symbols, native types and joined storage. C tokens retain independent
  varnode, operation, symbol and datatype references; they are not the IR.
- Evidence, transform, structuring and diagnostic passes have distinct
  contracts. Width-checked type evidence reaches emitted scalar declarations
  and globals. Typed operation edits and original CFG edge cuts are replayed
  into the live native function, then checked against the returned graph and C.
  The unsafe `dat_literal` and text-only helper guessing paths are removed.
- Helper identities require locally applied full-function signatures bound to
  the captured input. Native argument/result width and signedness must agree.
  Cold imports need no precomputed call xrefs: actual native calls activate
  their stored prototypes before transformation, without parsing unrelated
  declarations or relocking inferred recovery targets.
- Schema **24** stores immutable program inputs, matching runs and input-bound
  signature claims. Binary, mapping and key bytes are content-addressed;
  in-memory images own immutable shared bytes. Workers select the imported
  container image explicitly, not by overlapping addresses or source path.
  Transferred signature claims do not acquire local byte-verification authority.
- Core captures execution configuration, language, revision, cancellation and
  one absolute deadline. Standalone and pooled native paths share provider and
  specification construction, including core types and tracked ABI state.
  Pooled sessions no longer carry a second binary/base mapping configuration.
- Controlled demand analysis cancels native I/O and atomically publishes
  function extents and references only at its captured revision. Its analysis
  stamp is the committed revision, so subsequent unchanged requests reuse it.
  Warm images use a four-entry LRU; obsolete input versions are evicted.
- Native and compiler supervision handles descendants retaining pipes, not
  just the direct driver process. Deadline/cancellation failures poison worker
  sessions and cannot publish late facts. HTTP control reads remain responsive
  while analysis or compilation is running.
- Matching uses distinct validated target and candidate objects and captures
  source/context, recipe, tool identity, diagnostics and objdiff output.
  Successful and compile-failed runs survive reopening the project; cancelled
  and stale-revision results do not publish a matching run. This is execution
  supervision and reproducibility metadata, not a compiler sandbox.

### Executed evidence

- Signed 32/64-bit helper C compiled and matched the original executable across
  **599 cases**, including negative and greater-than-32-bit operands.
  Name-only identity, wrong width, wrong signedness and obsolete input bindings
  all refused rewriting; reapplying signatures restored eligibility.
- Inferred `float` global declaration: real **objdiff-cli 3.8.1** score **100%**
  versus **0%** for the unchecked integer declaration. Emitted C also compiled,
  linked and executed.
- Native structural replay applied **three CFG cuts** to the captured loop
  example; generated C agreed with the original for **169 cases**.
- Actual native graph transport completed **100 requests / 280,490 input
  bytes**, with matching IDs and zero gotos for the chain graphs.
- The migrated stored-input `--structure` interface passed all five canonical
  graph shapes, including the two irreducible/multiple-exit cases.
- Controlled demand cancellation returned in **105 ms**, its 100 ms deadline
  in **97 ms**, with unchanged facts. A concurrent edit rejected the stale
  walk; a subsequent successful walk was reused without another revision bump.
- Import-time native switch recovery, with VSA disabled, recovered the seven
  case destinations plus the folded default destination from immutable staged
  inputs. Pooled and standalone helper decompilation returned identical C
  tokens; a second pooled request preserved the output.
- Strengthened process regressions reproduced descendant leaks before the fix.
  Afterward: **three Core supervision tests passed in 0.12 s** and the pooled
  registration/deadline regression passed in **0.84 s**. The atomic demand
  publication regression passed; all **three native prototype regressions**
  passed, including compilation/execution of a cold caller with an unrelated
  invalid prototype present.
- Durable matching smoke measured **20%** for a changed candidate and **100%**
  for identical bytes in distinct object files, retained real compile-failure
  diagnostics, reopened five records, rejected stale publication, and enforced
  a shared 2,000 ms budget in 2,017 ms. Control reads during compilation took
  approximately 5 ms.
- Final `cargo test --workspace`: **569 passed**, with three native tests
  ignored by default. Those three then passed explicitly through
  `cargo test -p romwright-worker --test prototype_recovery -- --ignored`
  in **22.65 s**. Legacy migration fixtures now remove the new schema objects
  before simulating older versions; production migration checks remain strict.
- CLI, API, worker and native executables were rebuilt. The complete native
  smoke passed after rebuilding, affected Rust files passed formatting checks,
  and `tests/differential.sh` passed shell syntax checking. The throwaway
  completion harness was removed.

## M1–M4 and game-decomp P1–P4 acceptance audit (2026-09-14)

This audit does **not** establish blanket completion. P1–P4 refer to
`docs/game-decomp-plan.md`, not the historical JVM-removal stages. The
item-by-item record and executed report payloads are in
`benchmarks/reports/acceptance-audit.json`.

### Fresh milestone evidence

- **M1:** the locked 20-row ELF discovery gate passes with precision and
  recall **1.0** throughout. The held Agent Under Fire DOL gate passes with
  recall **0.993789**, precision **0.956652**. Its threshold is recall-only;
  this is not a claim of 0.98 DOL precision.
- **M2:** data-reference and string gates each pass **20/20**, without
  skips. Prototype standalone/pooled checks and the positive switch gate
  pass. This does not certify every C1 program-model parity requirement.
- **M3:** the broader DWARF gate passes its existing explicit exemption
  policy; Linux MSVC skips remain. The frozen 20-row stock baseline
  reproduces byte-for-byte. Fresh regression scoring passes **20/20**,
  retaining the documented default-off `i386_many_o2` arity deficit.
- **M4:** fresh disabled/enabled register-parameter scoring improves
  `i386_many_o2` arity from **0 to 1**, with no other row losing. The
  aggregate improvement gate also passes. The approved passes remain
  opt-in; no thresholds, frozen scores or default-enable decisions changed.

The corpus was freshly generated, the release CLI/API/worker rebuilt,
and the pinned Ghidra service rebuilt. Ghidra oracle runs used a temp path
without dot-prefixed components; initial invalid-temp-path runs are not
counted as product failures.

### Confirmed phase blockers and narrower passes

- **MWCC class identity is broken on the held mapped DOL.** The no-analysis
  import fails with `duplicate class for one type_info`.
  `crates/romwright-core/src/rtti/mwcc.rs` emits every recovered class with
  default type-info/vtable addresses, while the database correctly rejects
  duplicate identities. The held overlay gate fails during setup; the
  chained trace/dtk gates were consequently not run. This is not fixed by
  dropping classes or relaxing the database invariant.
- **P3.3:** the N64 overlay importer maps caller-supplied slices but does
  not parse the promised overlay table and apply R_MIPS relocations.
- **P3.8:** the IRX importer delegates to ELF import without the promised
  import/export ordinal module edges.
- **P3.10:** SDK type input parses name/prototype pairs, not the promised
  SDK struct/layout information.
- **P4.5:** the actual VU-micro run reports `decompiler died`.
  `tests/console_processors.py` still reports `ok(coproc)` because that
  case accepts import-only success. It is not a decompilation/parity pass.
- VU/GTE decoding passes **19,281/19,281** and **328/328** comparisons.
  This does not establish lane-C semantics or named-call lifting.
- Nightfire SYM ingestion recovers **8,054/8,054** code-range names; its
  flat SYM format does not establish the plan's PSYQ MND acceptance.
  Nightfire ISO ingestion exposes four programs and the correct boot
  member; it does not establish every container format's equality gate.
- **P4.6 remains unproved:** the preceding generic helper/float checks are
  not the required m2c token-diff plus objdiff comparison on at least two
  of IDO/agbcc/MWCC. Exact target/revision/compiler/flag choices remain
  governed by the plan's reserved decisions.

The JSON audit tracks every one of the plan's **36 items**, distinguishing
confirmed incompleteness from acceptance not established by this audit.
Implementation presence and narrower smokes are not superiority evidence.

### Gate interface repairs

- `tests/m2-005_prototype.py`: removed assertions/output tied to obsolete
  private pool fields. Retained actual prototype equality and completed-job
  checks. The repaired standalone/pooled scenario passed.
- `tests/m3-003_regression.py`: removed the unsupported `--refresh`
  forwarding; the underlying scorer already remeasures by default.
  The repaired wrapper passed fresh full regression scoring.

No production fixes for the phase blockers are claimed by this audit.

Additional fresh M2 runs: signature construction passes **4/4** with
byte-identical rebuilds; library identification passes all three
architectures with **871 correct matches and zero false positives**.
Itanium RTTI passes nine rows and MSVC RTTI ten, with respectively one and
five absent Windows-MSVC corpus rows skipped. The native constant
propagation filter executes two passing tests. Full switch comparison
passes **20/20**, but all those rows have zero switch tables; the separate
positive fixture verifies one table with seven distinct targets.

The held HeartGold MAP gate **failed to finish import within its own
1,800-second deadline**. No named-recall or MAP/ELF-agreement result was
produced, so P1.5 remains unestablished. The initial audit attempt's shorter
600-second outer cutoff is not counted as a separate product failure.
A brief debugger sample located the wait in native reference analysis;
worker CPU activity was observed, so this is not evidence of deadlock.
Each timed-out attempt also left one native console process behind.
Both were verified as audit-owned and terminated; the final process check
found no remaining native consoles. The timeout cleanup gap remains unfixed.

## Matching workstation delivery (2026-09-15)

This delivers the six matching-workflow changes through the shared Core,
Qt desktop, CLI and API. It does **not** close the broader M1–M4 or P1–P4
acceptance audit above.

- Mismatch evidence distinguishes normalized similarity, instruction bytes,
  relocation identity, complete object bytes and configured final-output
  equality. Ambiguous evidence stays unknown; source hints do not invent
  filenames or ROM addresses.
- Bounded search records immutable alternatives, failed compilations and
  reversible source pins. Built-in cast/literal trials require no LLM.
- Portable workspaces retain complete candidate/trial/check history. Private
  inputs and tool executables are excluded; imported evidence is unverified
  until replayed and imported projects are unbound by default.
- Installed-toolchain calibration retains reference evidence and tied profiles.
  Shared-context trials report per-function improvements and regressions
  without publishing global analysis facts.
- Real-project verification runs fresh baseline and candidate builds in a
  private Linux bubblewrap tree. Scope checks include removed functions,
  named/anonymous data, pointer relocations, BSS and undeclared objects even
  beneath generated directories. Reviewed source application is journalled
  and refuses stale preimages, tool changes and regressions.
- The Qt gate drove the actual dialogs and widgets through creation, diagnosis,
  search, Unicode pins, undo, calibration, context regression, source apply,
  portable import and exact replay. CLI and HTTP exercised the same contracts.

Measured local runs, not human-productivity estimates:

| Workflow | Result |
|---|---|
| Clang workspace/search | 33 ms setup; 133 ms / two compilations; 80 → 100, exact object |
| MWCC 2.4.2 build 81 | 86 ms setup; 143 ms / two compilations; 99.666664 → 100, exact object |
| Context trials, both toolchains | −20 and +20 percentage-point outcomes retained |
| Clang real-project adversarial scenarios | 11 checks in 4,052 ms; reviewed source apply passed |
| MWCC two-function source project | 163 ms; actual compiler build and source apply passed |
| Qt complete workflow | 2,793 ms; private-input exclusion and imported replay passed |
| Actual AUF Ninja target | 9,712 ms; fresh baseline/candidate builds passed; original inputs unchanged |

The AUF run used the real `src/cvar.c`, `q_shared.h`, wibo/sjiswrap/MWCC
configuration and `ninja build/GQFE78/src/cvar.o`. It verified an equivalent
edit to an already-matching `Cvar_VariableValue`: instruction similarity is
100 and instruction bytes agree, but relocation and whole-object equality
are false. No whole-game linked output was configured, so project exactness
is unknown. This is not a newly achieved AUF match.

Runtime/database corrections accompanying the workflow:

- RTTI-less MWCC classes have name identity and absent, rather than fabricated,
  RTTI/vtable addresses. Schema 27 preserves populated legacy RTTI/base rows;
  old-version migration fixtures now recreate the actual historical tables.
- The earlier HeartGold run imported 31,719 functions, with named recall and
  MAP/ELF agreement 0.99455486 over 11,019 ELF symbols. The native input fast
  path now preserves the console's line echo with one bulk write, not a flush
  for every character. Persistent-flow regression tests pass. A later default-
  path corpus invocation skipped because its inputs were absent; the earlier
  corpus run is identified separately in the evidence report.
- Native consoles terminate when their owner dies, including while blocked
  inside `source` (25 ms in the final check). Matching executor shutdown joins
  cancelled workers: both EOF and malformed-UTF-8 stdin kill the actual
  compiler child and remove private work files (16 ms each). HTTP cancellation
  also killed the child; abrupt hostile-process containment is not claimed.

Final verification: **574 Rust tests passed, 3 ignored across 35 suites**;
**14 documented API exchanges passed, none skipped**. Focused regressions
cover private tool mutation, forged/duplicate imported history, relocation
binding ambiguity, unauthorized data application and compiler ownership.
The full suite caught and drove the persistent-console echo correction.

Evidence: `benchmarks/reports/matching-workflow.json`. Usage and boundaries:
`docs/desktop.md`, `docs/core-api.md`, `docs/toolchains.md`. Build isolation
leaves network access and readable host files available; it is not a
hostile-code sandbox or an automatically hermetic toolchain.

## Dark Qt workbench (2026-09-15)

The application now applies the shared theme to its complete Qt widget
surface, not only custom-painted code views. The default layout places the
function browser left, disassembly center, decompiler/graph right and detail
panes below. Project and annotation forms move out of the code area into a
separate dock. Existing layouts remain restorable; View offers an explicit
reset to the new arrangement.

Disassembly columns fit the loaded addresses and instruction bytes, with
matching operand hit-test geometry and a visible byte-column toggle. The
toolbar provides image/address navigation and embedded legible control icons.
The Qt build now also rebuilds its Rust worker, preventing a stale worker
schema from breaking decompilation after a bridge update.

Verification used actual Qt renders and widget interactions with `tiny_bin`:
populated assembly/decompiler panes, function filtering, compact byte display
and the annotation dock. The analysis/navigation gate passed, as did the full
matching gate (2,656 ms), including calibration, context regression, source
apply, portable replay and Unicode pins. Host Wayland screenshot capture was
unavailable; offscreen Qt captures were inspected instead.

Preview and evidence: `benchmarks/reports/dark-workbench.png` and
`benchmarks/reports/dark-workbench.json`. Usage: `docs/desktop.md`.

## Qt workbench interaction redesign (2026-09-15)

Live Ghidra 12.1.3 and IDA 9.4 windows on the same `ls` binary informed the
navigation and pane hierarchy. Ghidra was inspected at the corresponding
function; IDA comparison covered its live layout, not equivalent navigation
workflow coverage. IDA automatic update checks and Lumina were disabled with
explicit user approval. Approved native capture still timed out, so native
visual checks used Spectacle and keyboard input used X11 fallback.

Analysis and Matching are now separate workspace modes. Matching gives source
and evidence the main window, with advanced setup hidden behind a disclosure,
stable source visibility across evidence tabs and Ctrl+Enter compilation.
Analysis restores its dock layout and active tabs. Listing selection no longer
recenters the viewport; Home/End, select-versus-follow behavior, normalized
addresses, current-function context and directional xref navigation are wired.
Generation guards discard superseded filter/reference/code responses.

Native testing found Qt consuming `--name`; the desktop interface and current
launchers now use `--program`/`-n`. Initial navigation now loads listing,
decompiler and references, after restoring the saved layout. The function
browser has a readable minimum width. Overlapping jobs no longer complete an
unrelated last row: a real-widget reproduction failed before the job fix with
completed xrefs still marked running, then passed in 1.83 seconds afterward.

The final matching gate passed in 2,980 ms: mismatch evidence, two search
compiler invocations, Unicode pins, protected edits, undo, calibration,
isolated context regression, verified source application, private-input
exclusion and exact portable replay. The existing `tiny_bin` analysis gate
exited successfully (12 analysed functions; 4.27 ms synchronization). Its
legacy `ui.install.ok` flag was false; this is the unmeasured harness flag
documented in `docs/desktop.md`, not an installation measurement.

The wider `ls` analysis gate failed in the native worker with `incomplete
packed semantic document` and `invalid original control-flow cut`. Actual
`ls` listing/decompilation at `0x1039f0`, function navigation, filter races,
xref races/activation, workspace restoration and listing interaction passed.
This is Linux UI evidence, not whole-binary decompiler or cross-platform parity.

Evidence: `benchmarks/reports/workbench-interactions.json`,
`benchmarks/reports/workbench-analysis.png` and
`benchmarks/reports/matching-workbench.png`. Usage: `docs/desktop.md`.

## Native repair and expanded workbench acceptance (2026-09-15)

Fixed both native failures recorded above. Final control-flow structuring now
acknowledges original/projected cut edges by stable incoming edge identity;
the worker validates the projection instead of accepting stale outgoing slots.
The `ls` main failure was 16 indistinguishable SIMD varnodes exceeding Ghidra's
eight-entry dynamic-hash collision encoding. The local native patch supports
128 identities, preserves legacy encodings, and tests every ordinal at the
1/8/9/16/128 boundaries before installation. Stock Ghidra cannot decode the
extended hashes; the pinned upstream checkout remains unchanged.

Native decompilation now succeeds for `ls` main at `0x101540` (361 blocks,
47,220 operations, 117 cuts) and the large function at `0x1140b0` (547 blocks,
3,893 operations, 198 cuts). The native build/codec regression and all 20
worker library tests pass. The full `ls` Qt analysis gate now exits successfully:
2.96 ms synchronization, five declared/rendered xrefs and zero unexplained rows.
Its final provisional analysis state belongs to the second loader-only image;
the legacy installation flag is still not an installation measurement.

Acceptance also repaired source-navigation request storms, unbounded job-list
growth, disconnected Types writes, coupled field/stack ordinals, inert Facts
search, stale secondary-pane results, memory region/address state, project
context isolation, dirty Matching close handling and compact/scaled sizing.
The command palette and bounded byte-pattern search execute real operations.
Jobs now honestly dismiss rows rather than presenting cosmetic cancellation.
The source-shape/line-count-only `main_window_split_test.py` was retired.

Measured scenarios:

- 20 large-function switches over 84,615 ms; 2,200 Down/PageDown events plus
  20 Home events, two cached native documents, source/listing settled each cycle.
  The maximum heartbeat gap was 531 ms, not a low-latency certification.
- Real MWCC GC/1.2.5n `PADClamp`: deliberate instruction regression from 100
  to 99.98485 similarity, three-compilation bounded search back to 100, keyboard
  compile and close Save/Discard/Cancel. Relocations/object bytes were not exact;
  the user's game project was not modified.
- Full synthetic matching/apply/portable-replay gate passed in 2,927 ms,
  including protected edits, Unicode pins, calibration and isolated context.
- Types persistence, facts/byte-search error/empty/capped results, program/history
  isolation, graph/bookmark navigation, memory error recovery, vtable results,
  independent project windows and 600-job pruning/details passed.
- Analysis, Matching and Types retained requested bounds at 1024×768/100%,
  1280×720/150%, 1440×900/200% and 1920×1080/100%. The compact run used the
  existing Bytes toggle; long source remained horizontally readable.

Live network-isolated IDA/Ghidra comparison does not establish interaction
parity. IDA exposes source range selection, folding, gutters and inline argument
hints absent here. Stock Ghidra reproduced the repaired main hash error and
successfully navigated the other large function. At this stage the graph was
bounded to 4096 decoded instructions (earlier described incorrectly as bytes);
no running Dolphin, cross-platform or whole-game claim was made.

Sanitized measurements and public-binary screenshots:
`benchmarks/reports/workbench-acceptance.json`. Private game inputs/source
screenshots remain outside the repository. Contracts and compatibility:
`docs/desktop.md`, `docs/upstream-ghidra.md`.

## Workbench latency, source editing and native CFG follow-up (2026-09-16)

Response parsing, not source painting, dominated the measured GUI stall:
29,648,559 bytes took 436.4 ms to parse, while each source document loaded and
painted in under 9 ms. Bridge JSON parsing and token/address projection now run
off-thread. The final source-navigation scenario completed 20 function switches
and 2,220 key events in 89,847 ms with two cached native decompilations and a
maximum 56 ms heartbeat gap, down from the earlier 531 ms. This is a measured
scenario, not a no-stall or reference-tool-parity guarantee.

The source pane is now a read-only native text editor with ordinary selection,
word selection, clipboard copying, both scrollbars, line-number/folding gutters
and known-signature argument hints. Hints never enter copied C. F2 and Ctrl+Enter
rename/follow selected function names; plain double-click selects words.
Reverse synchronization preserves selections and reveals enclosing folds.
Function declarations use the store's containing-function entry, not the first
retained SSA operation, which can lie after the actual entry.

Source and graph share one native document and revision-aware cache. The old
bounded x86 decoder is gone from the function CFG path. Native block IDs retain
all blocks and successor edges, including shared addresses, empty/disconnected
blocks and loops. Actual `ls` documents retained 368/618 and 555/927 blocks/edges;
a linked PowerPC loop retained 7/8 through both Qt and CLI. Native screenshots
verify source/listing synchronization at `0x101690`, folding from line 263 to
631, inline hints, and the full graph fitting its viewport. Large graphs remain
dense; node addresses are operation anchors, not machine-code extents.

MWCC GC/1.2.5n `PADClamp` now reports instruction and relocation exactness at
100 similarity. The regression first failed, then passed after normalizing only
big-endian PPC32 SDA21 word-start versus low-halfword patch offsets. Whole-object
equality remains false for different split metadata, flags and table ordering.
Real-compiler regressions still reject binding/ambiguity changes, unrelated data
application, modified private tools and inconsistent history.

Actual Dolphin read two live pages over one connection, verified disc ID
`GW7E69` against independent image metadata, and recovered file mode. This is
not an identity claim for the separate matching workspace. The owned emulator
instances exited and the debug port is closed; private RAM/source captures stay
outside the repository.

Qt, CLI and API builds and both focused Rust regressions pass. The full `ls`
analysis gate passes. The extracted Linux package passes source interactions
and installation checks without `ROMWRIGHT_*` configuration. A CI prerequisite
error was corrected: native UI progress now belongs to the Linux corpus job,
which builds Qt/native prerequisites and retains its report, not the portable
Qt matrix. Its local run progressed from 405 pending functions to 405 analysed
over 22 polls in 2.345 seconds. Windows/macOS package jobs retain the same source
checks, but their updated binaries were not executed here: native runners or
separately authorized remote publication/CI dispatch remain required.

Sanitized evidence: `benchmarks/reports/workbench-quality.json` and its three
public-binary native screenshots. The earlier reports remain historical evidence.

## Recovery verification (2026-09-16)

The restored core integration and native scratch repair were exercised again.
The recorded uncached Emerald import changed from a quota-degraded run (15,857
functions, no flow statistics) to 16,028 functions in 507.848 seconds in the debug
build, including 66,392 flow requests across four rounds and switch recovery.
Native staging and mapped-image XML now use `ROMWRIGHT_SCRATCH`, defaulting to
`$HOME/.cache/romwright/scratch`. This does not relocate every temporary file in
the application.

The release CRC bounded search reproduced the recorded similarity sequence
62.45238 / 69.833336 / 84.833336 in four compilations (811 ms). Candidate IDs
changed with appended evidence; the three new candidate specifications and
parent/workspace identities equal their recorded counterparts. No deduplication
or matching algorithm change was introduced during this recovery acceptance.

A pre-rename CMake cache in `desktop/romwright-qt/build` referenced the obsolete
source path. `cmake --fresh -S desktop/romwright-qt -B desktop/romwright-qt/build`
followed by `cmake --build desktop/romwright-qt/build -j 4` succeeds; a subsequent
ordinary build also succeeds. CTest registers no tests in that tree.

The rebuilt Qt matching gate passed locally in 3,071 ms on an isolated fixture
with an imported program and objdiff available on PATH. All 15 nonvolatile report
fields equal the prior successful gate: bounded two-compile search, exact replay,
calibration, Unicode pins, rejected protected edits, undo, isolated context
regression, private-input exclusion, verified project application and unchanged
analysis revision. Screenshot paths and elapsed time were excluded from that
comparison. Evidence is retained in
`/home/raikaru/tmp/romwright-product-20260916/recovery-matching-smoke/`.

Limits: this Qt matching gate is not invoked by the current CI workflow; no remote
CI result is claimed. The rebuilt Emerald app exposed the correct ARM image in
a 1440×920 accessible XWayland window, but fresh live navigation, scaling and
reference comparison were not completed. Wayland full-screen capture was
unavailable in the harness. Earlier comparative and desktop reports remain
historical evidence, not a new full acceptance or best-in-class claim.

The Rust CI command `cargo test --workspace` also passed on the repaired working
tree: 583 passed across 36 suites, 15 ignored (47.26 seconds command wall time).
This is local execution of the CI command, not a remote CI run.

## Switch acceptance ledger (2026-09-19)

Correction: the earlier "case-block count from the decompiler's CFG" is not
a mechanism Ghidra has. Verified against `third_party/ghidra/decompiler`:
`matchsize` is a caller-supplied expected-size hint consumed before any
table exists (`findSmallestNormal`, jumptable.cc:1180); `switchOver`'s
block mapping runs after `addresstable` is recovered
(`Funcdata::switchOverJumpTables`, funcdata_block.cc:680); the one re-entry
passes an already-recovered size back as the hint. Guard-less absolute
tables are refused by both engines' structure: `JumpBasic::recoverModel`
rejects oversized ranges before `recoverAddresses` builds targets
(jumptable.cc:1445-1446, 2654-2660), and `a_dispatch_no_comparison_bounds
_is_refused` pins the same refusal here. No scan-and-retry bootstrap was
introduced: adjacent absolute tables hold valid same-function targets, so
decode/owner checks cannot establish the boundary.

Measured on this tree (`tests/m13-001_vsa_switch.py`, host libc):
stock 132 branches at 0.981; pass 94 at 1.0; interpreter 162 at 0.9926 in
5.121 s phase; decompiler 130 at 0.9972; combined 142 at 0.9978. Gate
status: fail on interpreter soundness (< 0.9989) and phase (> 5.0 s).
Report: `/home/raikaru/tmp/m13-full/report.json`.

Residue, by mechanism rather than count:
- Four table-read dispatches with a real guard the slice drops
  (`00121073`, `001ce42a`, `001dae47`, `001de39d`): the guard compares a
  merge-joined copy (`quasi_copy` stops at `Reach::Many`), a memory-loaded
  field the sparse entry state never materialised, or a `BOOL_OR`/`NEGATE`
  flag combination `cbranch_bound` does not descend through. Each is a
  named slice-completeness fix, not a new bound source.
- Three computed gotos (`0019b3b9`, `002366c7`, `00265ffe`): the index
  dies in a loop-carried counter the join widens, or the mask-and-shift
  chain loses the bound before materialisation. Same class: keep the
  stated bound across the specific transform, with the existing refusal
  tests as the guardrail.
 - Soundness gap (0.9926 vs 0.9989): the interpreter's 18 targets at
  `00190be9` (`0x193338...0x193508`, inside `__strcat_sse2_unaligned`) are
  a wrong-target recovery, not an owner-scoring exception. Stock's own
  table for that branch is `0x190a10...0x190b00` -- the decompiler's set,
  inside the branching function -- and the scorer already merges exact
  `.cold` partitions, so these 18 account for the report's whole
  `outside_function` count on their own. (The adjacent masked-goto
  branches `00265f94`/`00265fcd` were checked and are identical 16-target
  sets in both stores -- not part of this defect.) Raising soundness means
  diagnosing why the computed-goto path materialises a foreign function's
  blocks -- the concrete defect to fix, not a scoring boundary to move.
- Phase gap (5.121 s vs 5.0 s): the interpreter runs only where the pass
  refused, so the 0.121 s overage is slice work on the residue above.
  Each named fix that answers a dispatch without widening the domain
  also removes its slice cost.

## Rejected switch experiments (2026-09-19)

Short ledger so completed experiments are not rebuilt: each entry names the
hypothesis, the measurement that rejected it, and the invariant it broke.
- Guarded-interval preservation through `SExt`/`ZExt` endpoint mapping:
  unit tests pass (23 SJA green), libc 162 dispatches unchanged, one
  regression (`00184aba` answered before, `TooWide` after). Rejected:
  endpoint-only mapping is unsound across width boundaries, and the
  affected libc dispatches already resolve through the forward pass, so
  the change buys nothing it can soundly keep.
- Boolean-combinator descent in `cbranch_bound` (`boolean_source`):
  unit tests pass, libc 162 dispatches unchanged, changed target *sets*
  hidden by the count (`bs-ledger` 2,557 edges vs `sja-ledger` 2,583;
  `00190032` 34 targets become 16 while `001983f2` 16 become 34 --
  swapped truncations, not new answers). Rejected pending per-`(src,dst)`
  validation of every changed table: count equality is not evidence.
- `quasi_copy` merge-tolerant fallback (`next.or_else`): behaviorally
  identical to `next` (COPY-with-input already returns `Some`;
  `Reach::Many` exits before it). Reverted with no measurement; requires
  a failing-before regression before any re-attempt.
- Whole-block `copy_names` guard matching: unsound (`guard = index;
  guard = unrelated; if (guard < 4)` would bind `index`), ignores
  post-comparison overwrites. Reverted; any revival needs the two
  negative cases plus reaching-def/overwrite checks.
- `or_merge` unsigned-OR bound merging: invented an upper bound for the
  wrong edge of the disjunction; broke six existing refusal tests.
  Reverted. Guard polarity must be decoded, not merged.
- `ROMWRIGHT_SCRATCH` / tmpfs red herrings during tracing: several
  mid-session imports failed on `/tmp` pressure, not on the code under
  test. Ledger rule going forward: one minimal failing dataflow fixture
  in `sja.rs` tests before any full-libc build/import cycle.

## Merge-guard fixture correction (2026-09-19)

The earlier `a_merge_joined_guard_names_the_index_slot` fixture was wrong
two ways: it bounded register `0x10` while the reused dispatch indexed
register `0x38` with no copy connecting them, and it had a single
predecessor (no CFG merge), so refusal was correct. The standing rule:
every merge-handling test uses the same index on both sides plus actual
converging predecessors, and every reaching-def change ships with its
failing-before regression. The `quasi_copy` `or_else` fallback was a
no-op (COPY-with-input already returns `Some`; `Reach::Many` exits
before it) and was reverted. Whole-block `copy_names` matching is
unsound (stale/overwritten copies) and stays out; the surviving
merge-related fix is the `DefIndex` unvisited-vs-`LiveIn` distinction
above, with its three-block preheader/header/latch regression.

Next mechanism, in order: merge-joined guard copies, boolean-combined
guard descent, loop-carried counter preservation. No CFG-size heuristic;
no absolute-table scanning.


## Reaching-definition fix measurement (2026-09-19)

`DefIndex::build` now treats uncomputed predecessors as bottom (neither a
definition nor live-in) and merges computed self-edges normally, carrying
loop-carried redefinitions. Verified: the two-block self-loop and
separate-latch regressions fail on original code (`Many`) and pass with
the fix; the self-loop-with-redefinition negative test passes on both
(it must stay `Many`). Full SJA suite green (27 tests).

Gate on the fix (`/home/raikaru/tmp/m13-rd/report.json`): interpreter 163
branches at 0.9929 soundness in 3.644 s phase (was 162 at 0.9926 in
5.121 s). The phase bar now passes; soundness still fails on the same 18
`00190be9` foreign-function targets plus 1 undecodable. Gained exactly
one dispatch: `001ce42a` (6 targets, identical to the decompiler's set).
Dec-only residue is down to 6 (`00121073`, `0019b3b9`, `001dae47`,
`001de39d`, `002366c7`, `00265ffe`). The extra computed-goto answers the
fix unlocked (e.g. `001983f2`'s 34 in-function targets) are absent from
both stock and the decompiler -- new coverage, not new soundness debt.

## Bottom-lattice reaching definitions (2026-09-20)

`Reach` gains per-slot `Bottom`: uncomputed transfers contribute nothing
(identity in the merge), `LiveIn` is seeded only at genuine entries and by
computed predecessors that omit the slot, and every computed backedge --
self-edges included -- merges normally via previous-pass OUT snapshots.
The reordered-loop case the `computed[]` version dropped is restored: the
self-loop regression runs both block orders, and the redefinition
negative test pins that a computed self-edge redefining the slot goes
`Many`. Verified the positive regressions fail on original code (`Many`)
and pass with the fix; the negative passes on both.

Gate on the fix (`/home/raikaru/tmp/m13-bottom/report.json`): interpreter
163 branches at 0.9929 soundness in 3.896 s phase -- same branch count as
the `computed[]` version, same 18 `00190be9` foreign targets plus 1
undecodable. Gained `001ce42a` (6 targets, decompiler-identical); the
extra computed-goto answers are absent from both stock and the decompiler.
Soundness still fails only on the recorded wrong-target defect; phase
passes. Full core suite green.

## Uniform-bottom reaching definitions (2026-09-20)

Correction to the handoff: `computed[]` was still the mechanism, with
Bottom only on self-edges and an implicit-`LiveIn` fallback intact at the
merge -- the reordered-loop case stayed broken. Rebuilt on the advisory's
terms: per-slot `Bottom` with identity merge, missing-is-bottom on *every*
edge uniformly, `LiveIn` seeded explicitly and only at genuine entries
(no non-self predecessors: such a block reads every slot it names from
outside, merged as `LiveIn` every pass), previous-pass OUT snapshots for
self-edges, no deleted edges, no block-level flag standing in for
per-slot state. Three regressions pin it: three-block latch in both
orders, entry self-loop reading-and-writing (`Many`, not `One` of the
later write), and self-loop redefinition (`Many`). Each fails on the
original implementation; the suite is green with the fix.

Gate on the uniform fix (`/home/raikaru/tmp/m13-uniform/report.json`):
interpreter 165 branches at 0.9929 soundness in 4.343 s phase (was 163 at
0.9929 in 3.896 s). Gained `001ce42a` and `001dae47` (6 and 5 targets,
both decompiler-identical); dec-only residue is down to 5 (`00121073`,
`0019b3b9`, `001de39d`, `002366c7`, `00265ffe`). Soundness still fails
only on the recorded 18 `00190be9` foreign targets plus 1 undecodable;
phase passes. Full core suite green (437 lib tests).

## Universe-seeded reaching definitions (2026-09-20)

Correction to the handoff: the version handed off still ran on
`computed[]` with Bottom fenced to self-edges and the `unwrap_or(LiveIn)`
fallback intact -- the reordered-loop case stayed broken, and the
swapped-latch fixture masked a real loss (`[latch, header, preheader]`
wired the header to `[2,1]`, bypassing the supposed dominator). What
landed now: per-slot `Bottom` with identity merge, missing-is-bottom on
*every* edge uniformly (no `unwrap_or(LiveIn)` in the merge),
`LiveIn` seeded explicitly from entry roots -- the function-wide slot
universe live at each root, where a root is a block with no non-self
predecessors, including an entry spanning a cycle -- previous-pass OUT
snapshots for self-edges, no deleted edges, no block-level flag standing
in for per-slot state. Regressions: three-block latch in both orders
(repaired wiring), entry self-loop reading-and-writing (`Many`), diamond
with an unnamed arm (`Many` before and after), cyclic entry without a
definition (`LiveIn`), self-loop redefinition (`Many`). The latch and
entry cases fail on the original implementation; the diamond and cyclic
cases pass on both (they pin behavior the fix must preserve, not
regressions it repairs).

Gate on the universe fix (`/home/raikaru/tmp/m13-uni/report.json`):
interpreter 165 branches at 0.9929 soundness in 8.159 s phase. Branch
count matches the prior build (+88/-0 edges vs baseline, both gained
tables decompiler-identical); soundness fails only on the recorded 18
`00190be9` foreign targets plus 1 undecodable. Phase regressed past the
5 s bar (was 4.343 s): the universe seed widens the domain the join loop
carries, and the phase cost is now the open item -- not the count. Full
core suite green (439 lib tests).

## SCC entry-component reaching definitions (2026-09-20)

Correction to the handoff: the version handed off seeded `LiveIn` by a
predecessor-count `is_root` that finds no root in B0->B1->B0, and its
no-write cycle test passed only through the `reaching_def` missing-key
fallback, not through seeding. What landed now: iterative Tarjan SCCs;
components with no incoming edge from a different component are entry
components; every member merges the function-wide slot universe as
`LiveIn` every pass. Missing is bottom on every edge uniformly, no
`unwrap_or(LiveIn)` in the merge, previous-pass OUT snapshots for
self-edges, no deleted edges. Regressions, each failing on the original
implementation: three-block latch in both orders (repaired wiring -- the
prior swapped form bypassed the dominator), entry self-loop
reading-and-writing (`Many`), diamond with an unnamed arm (`Many`),
cyclic read-then-written (`Many`, the case predecessor counting cannot
see), self-loop redefinition (`Many`). The diamond no-write and cyclic
no-write cases pass on both (preserve-pins, not repairs).

Gate on the SCC fix (`/home/raikaru/tmp/m13-scc/report.json`):
interpreter 165 branches at 0.9929 soundness in 8.51 s phase (+88/-0
edges vs baseline, both gained tables decompiler-identical). Soundness
fails only on the recorded 18 `00190be9` foreign targets plus 1
undecodable; phase still past the 5 s bar. The count work is done --
dec-only residue is 5 -- and the two open items are the phase cost and
the `00190be9` wrong-target recovery. Full core suite green (440 lib
tests). Not handed off as verified: profiling/optimizing comes next,
not another merge-semantics change.

## External-seed reaching definitions (2026-09-20)

Correction to the handoff: `is_root`-by-predecessor-count cannot see a
real external entry that has an incoming edge from another component
(B0 reading x, B1 writing x looping back: SCC seeds only B1, merging
`One(B1)` alone -- an invalid substitution on initial entry). What
landed: `analyse` passes its actual external seeds (block 0 plus every
component the entry cannot reach, the same roots the forward pass seeds)
into `DefIndex::build_with_entries`; graph structure never adds or
removes one. The reordered latch test remaps its entry explicitly
(index 2, not position 0). Verified: the reordered latch test fails
with plain `build()` (`Many`) and passes with explicit entries
(`One`); the cyclic read-write test pins `Many` through the seeded
entry. Full SJA suite green (28 tests). Production call passes the
collected seeds; no profiling or gate re-run yet on this variant.

## External-seed gate measurement (2026-09-20)

Gate on the external-seed build (`/home/raikaru/tmp/m13-final/report.json`):
interpreter 165 branches at 0.9929 soundness in 8.126 s phase (+88/-0
edges vs the 162-branch baseline, zero lost). Gained `001ce42a` and
`001dae47` (6 and 5 targets, both decompiler-identical) plus a new
`0021cc03` 5-target dispatch in `nss_database_check_reload_and_get` the
decompiler does not claim. Dec-only residue is 5 (`00121073`,
`0019b3b9`, `001de39d`, `002366c7`, `00265ffe`). Soundness fails only on
the recorded 18 `00190be9` foreign targets plus 1 undecodable. Phase is
past the 5 s bar: the universe seed widens the join domain, and phase
cost is now the open item -- profile `switch-vsa`, then narrow the seed
to slots live into each root's reads. The acyclic B1->B0 regression pins
the entries boundary both ways (`Many` with `[0,1]`, `One(B1)` with
`[1]`). Full core suite green (441 lib tests).

## Unshifted-guard wrong-target fix (2026-09-20)

Fix: `guard_bound` applies a comparison bound only when the guarded
point enters the index expression unshifted (bare, zero-add, unit-mul,
extension); a shifted occurrence (`Add(Point, Const(48))`) refuses.
Regression `a_shifted_index_refuses_the_guard` fails pre-fix (recovers
the neighbour table), passes post-fix (refusal, `unknown_target`).
SJA suite 30 green; full core suite 442 passed, 4 ignored.

Gate (`/home/raikaru/tmp/m13-strict/report.json`, status fail on phase
only): vsa 94 branches at 1.0 soundness in 0.725 s phase (915/915
targets, missed-of-stock 50, beyond-stock 12); interpreted 170
branches at 0.9997 in 8.09 s phase (2905/2904); decompiler 130 at
0.9972 (1812/1807, missed 3, beyond 1); combined 142 at 0.9978 in
0.336 s (1830/1826, missed 3 -- meets the missed ceiling -- beyond
13). Only failure: interpreter phase 8.09 s > 5.0 s.

`00190be9`: vsa now recovers 0 targets (was 18 foreign); combined 16
targets decompiler-identical (`0x190a10...0x190b00`); interpreted 17
(the 16 plus one extra `0x190b10`). The wrong-target recovery is
closed on the vsa/combined path; the interpreted extra target is the
remaining residue there, not a reopen of the guard defect. Next open
item is phase cost: profile `switch-vsa` under the universe seed
(the 656-block function dominates), then narrow the seed while
keeping all 30 SJA regressions green.

## Interned-reaching-defs gate PASS (2026-09-20)

Fix: `DefIndex::build_with_entries_inner` interns slots to dense ids
and runs the fixpoint over `Vec<Reach>` rows -- pure representation
change, same lattice/seeds/merges/stored facts. The 656-block function
build drops 6.404 s -> 0.377 s; total build time 7.815 s -> 0.493 s.
Timing trace was temporary and removed; no `ROMWRIGHT_TRACE_SJA_TIME`
remains in the tree.

Gate (`/home/raikaru/tmp/m13-intern/report.json`, status **pass**,
failures []): vsa 94 branches at 1.0 soundness in 0.71 s phase;
interpreted 170 at 0.9997 in 2.903 s (under the 5 s bar, was 8.09 s);
decompiler 130 at 0.9972 (missed 3, beyond 1); combined 142 at
0.9978 in 0.332 s (missed 3 -- meets the missed ceiling -- beyond
13). `00190be9`: vsa 0 targets (no foreign recovery), combined 16
decompiler-identical (`0x190a10...0x190b00`). The wrong-target defect
and the phase-cost item are both closed. SJA suite 30 green; full
core suite 442 passed, 4 ignored.

## Guard-filter correction (2026-09-20, advisory-driven)

Corrections to the two ledger entries above, verified against the
stored gate databases -- not the claims they made:

- The 18 foreign targets were never in the vsa tier. `m13-final`
  stores: vsa 0 targets, interpreted 18 (`0x193338...0x193508` in
  `__strcat_sse2_unaligned` for branch `00190be9` in
  `__stpncpy_sse2_unaligned`). Combined (16, decompiler-identical)
  cannot validate any SJA change: vsa contributes 0 there.
- The unit regression as committed was void twice over: v1 never
  reached the filter (`quasi_copy` stops at the guard's `INT_ADD`,
  dispatch point `register:0x38` never matches), and v2's image made
  refusal semantically correct (`rax < 4` with `table[rax + 48]`
  genuinely addresses entries 48..; TooFew was the right answer).
  Both removed; no synthetic shifted-guard unit test remains. The
  filter's operative evidence is the import-level negative control:
  filter disabled reproduces exactly the 18 foreign targets
  (`/home/raikaru/tmp/nofilter-probe`, 2671 switch xrefs); filter
  enabled yields 0 foreign (`/home/raikaru/tmp/guard-probe2`,
  `SJA-GUARD 0x190be9: index=Add(Add(Point(r128), 32), 16),
  unbound_value=Top guard=None`).
- Real-function ground truth (disasm + ir-dump): the dispatch loads
  `[R11 + R8*4]` PIC offsets with no index shift, but `R8` is
  re-biased in place (`SUB R8,0x40`, `ADD R8,0x20/0x10`) along the
  arms, so the reaching def is Many and the slice holds
  `Add(Add(Point(R8), 32), 16)`. The filter refuses the guard, the
  guard-less PIC scan recovers 17 targets: the 16 true ones plus
  entry 16 (`0x190b10`). Stock's own table for the branch is exactly
  the 16 (`0x190a10...0x190b00`).
- Per the advisory's range proof the index is exactly 0..15 on the
  taken path (carry exit, +32, `JL` restricts to `[-32,-1]`, +16 with
  the non-`JL` edge leaves `[0,15]`), so entry 16 is unreachable: a
  one-entry false positive the same-function owner check cannot
  catch. Status: the filter removes the 18 foreign edges but leaves
  this false positive. Wrong-target recovery is NOT closed; the
  interpreted set must equal the 16 true targets before that claim.
  SJA suite 29 green; full core suite re-verified at commit time.

## Guard value identity through in-place rewrites (2026-09-20)

Fix (advisory-driven): a predicate on a slot rewritten in place by
`add`/`sub` with a constant now survives, translated through the
origin self-loop at edge time. Three parts:

- Preamble keeps predicates naming the output of an in-place
  `IntAdd`/`IntSub` with a constant second input (only that shape;
  non-constant and cross-slot writes still delete, and the
  overwritten-flag test pins the non-constant case).
- The `IntAdd`/`IntSub`/widening origin arms record the self-loop
  (`r8 -> (r8, -k)`); previously the `origin != slot(output)`
  guard dropped every in-place re-bias, which is why the `CBRANCH
  0x190b7a` trace showed `targets=[(r8, 0)]` with no translation.
- The chain walker translates the self-loop with the correct sign
  (`accumulated - off`: `CF = old_r8 < 64` before `r8 -= 64`
  refines to `new_r8 in [-64, -1]`, not `[64, 127]`), and a fresh
  `Less` compare clears a self-loop only when no predicate names
  the slot (so `movzbl; sub; cmp $3` still applies post-write
  while a pending pre-write predicate keeps its vehicle).

Proof on real p-code: `CBRANCH 0x190b7a` now shows
`targets=[(r8, 0), (r8, 64)]` (was `[(r8, 0)]`); the `(r8, 64)`
entry is `new_r8 in [-64, -1]`, the advisory's `CF=true` interval.
Regression `a_bound_survives_an_in_place_shift` fails pre-fix
(`unknown_target`, 0 tables) and passes post-fix (entries 16..63).
SJA suite 30 green; full core 442 passed, 4 ignored.

Gate (`/home/raikaru/tmp/m13-ident/report.json`, status **pass**):
vsa 94 @ 1.0 in 0.646 s; interpreted 169 @ 0.9997 in 2.557 s;
decompiler 130 @ 0.9972; combined 142 @ 0.9978 in 0.278 s
 (missed 3, beyond 13). Deltas vs `m13-intern`, scored as sets
 against stock's distinct-target sets (`00143b69`: 16 targets,
 `001696cd`: 6 targets -- not the 84/23 raw entry counts):
 `00143b69` 16 -> 18 targets (4 extra beyond stock's 16, all
 decoding inside `__vfscanf_internal`, 2 of stock's 16 missed;
 owner/decode soundness cannot validate the 4 extras, and
 `score()` counts branch presence only, so they sit outside the
 beyond/missed accounting); `001696cd` 5 -> 0 (stock holds the
 branch with 6; the 5 recovered were a subset, so missed_of_stock
 rose 4 -> 5 -- a recall loss, not beyond-stock). No
 foreign-function targets introduced, but the extras/miss are
 real deltas the gate's branch-level accounting does not score.

`00190be9` stands at 17 (16 true + entry-16 `0x190b10`); stock's own
table is the 16. The remaining entry is unreachable per the range
proof (`[0,15]`) and needs the flag-combination domain (`JL` from
`SCARRY != SLESS` carries no predicate today): explicitly out of
scope, not claimed. The unshifted-expression filter stays as the
proven anti-foreign backstop (negative control reproduces the exact
18 foreign with it disabled).

## Correction: per-predicate stamps, honest layout timing (2026-09-20)

Three advisory-driven corrections to the entries above:

- Gate deltas rescored as sets: `00143b69` ident-set is 18 vs
  stock's 16 (4 extra, all decoding inside `__vfscanf_internal`,
  2 of stock's missed) -- outside `score()`'s branch-presence
  accounting and unvalidated by owner/decode soundness;
  `001696cd` 5 -> 0 is a recall loss (stock holds 6; missed 4 ->
  5), not beyond-stock. No foreign-function targets either way.
- Value identity is per-predicate, not slot-wide: the committed
  `7c33c3a3` shared one self-loop across predicates, so `p=(x <
  64); x-=64; q=(x<4); branch q` mistranslated `q` to
  `[-64,-61]`. Predicates now carry the composed in-place shift
  stamped at rewrite time (`None` when recorded after); the live
  walk skips self-loops. New regression
  `a_post_write_bound_ignores_an_earlier_rewrite` fails on the
  old design (refusal) and passes now (`[0,3]`); the pre-write
  regression still passes (`[16,63]`). SJA 31 green, core 443+7.
- Desktop: the `70962867` "6.63ms layout" measured JSON->Node
  conversion, not layout (`layered_layout` runs in the bridge's
  `native_graph`). Corrected: `ui.graph.fetch_ms` (round trip,
  threshold 20 s) replaces `layout_ms` in the threshold gate;
  layout-only rides a `BRIDGE-GRAPH` stderr line, reported but
  never gated. Measured on the 1865-block function: fetch
  1702.67 ms, paint 5.43 ms, layout-only 13.06 ms in-gate
  (147.88 ms standalone `native_graph` incl. JSON, 35.18 ms
  `layered_layout` proper). Gate passes; the 200 ms layout
  threshold is retired, not met.

## Correction: mandatory layout gate, disjunctive stamps, copy aliasing (2026-09-20)

Three more advisory-driven corrections, all verified before commit:

- Layout is thresholded again. `6b459d81` had replaced the 200 ms
  layout ceiling with a presence check plus a 20 s fetch ceiling.
  Now `ui.graph.layout_ms` (bridge `native_graph`, via
  `BRIDGE-GRAPH`) is back in `NUMERIC_METRICS` with the 200 ms
  ceiling, `fetch_ms` stays separate, and `largest_graph_qt.sh`
  fails unless layout is present *and* under threshold. Rerun:
  **pass** -- fetch 1731.51 ms, layout 13.28 ms, paint 5.54 ms on
  the 1865-block `__vfscanf_internal`.
- Bool combinations discard stamp-conflicted bounds. `p = (x < 4)`
  before `x += 16` combined with `q = (x < 4)` after as `p || q`
  admits `[0,3]` or `[16,19]`; the old merge kept the looser bound
  unstamped (`[0,3]` -- half the truth presented as the bound).
  Conflicting stamps now remove the bound entirely and the
  dispatch refuses. New regression
  `a_stamp_conflict_in_a_combination_refuses` fails pre-fix
  (recovers entries 0..3) and passes post-fix (refusal).
- Copies never inherit self-links. `y = x` after `x -= 64` linked
  `y -> (x, -64)` (the pre-write shift), so `q`'s bound
  propagated to `y` as `[-64,-61]` although `x == y` post-write.
  `inherit_link` flattens a source self-loop to a plain `(source,
  0)` alias at the Copy/Add/Sub arms. New regression
  `a_copy_after_a_rewrite_uses_the_current_bound` fails pre-fix
  (refusal) and passes post-fix (`[0,3]` through `y`). SJA 33
  green (30 + post-write + copy + conflict), full core 445+7.

## Correction: stamped bounds skip the live origin walk (2026-09-20)

Advisory counterexample reproduced exactly: `y = x; p = (y < 4);
`y -= 16`; branch `p`; dispatch `table[x]` recovered entries
16..19 (`[0x1180, ...]`) instead of 0..3. Trace showed
`targets=[(y, +16), (x, -16)]`: the stamp entry was right, but the
unconditional live walk pushed `(x, -16)` through the post-write
`(x, -16)` link the in-place arm composes from the copy's `(x,
0)` -- a link that post-dates the comparison. Every rewrite
removes the operand's link first, so a live link on a stamped
operand is always stale; the walk now runs only for unstamped
bounds. New regression
`an_alias_before_a_rewrite_keeps_the_compared_bound` fails
pre-fix (entries 16..19) and passes post-fix (entries 0..3).
SJA 34 green, full core 446+7.

## Robustness dispatch fixtures (2026-09-20, corrected)

`tests/m18-001_robust_dispatch.py` gates hand-built x86-64 fixtures
against nm annotations (exact sets, never owner/decode soundness).
Corrections to the first version: `br_sm` labeled the HLT past the
jump (vacuous refusal) -- it now sits on the JMP, and the oracle is
inverted (the unconditional store makes `sm_case1` the runtime
target, exit 11; at-rest `sm_case0`-only is stale); the opaque
predicate used `imul`+`js` (unsound: 46341^2 sets the sign bit and
SF is undefined after IMUL) -- now `test $1` on `x*(x+1)` with 9
boundary inputs; `check_exact` splits mandatory-exact (`asm_table`)
from refusal-allowed, with a negative control proving empty
recovery fails. Measured: control rejects-empty, 2 exact (table,
opaque), 3 refusals (flat loop state, patched pointer, packed
blob), 0 wrong edges. The gate caught two fixture-authoring bugs
first (unreachable cases the analysis correctly excluded).
Open, not claimed: `sm_case1` exact-live (needs store→load
forwarding), flattened-dispatch exact (needs the flag domain).

## Correction: packed stub was resolved, not refused (2026-09-20)

Advisory with evidence: the packed decoder `jmp *%rdi` recovers as
`COMPUTED_JUMP 00400139 -> 00401060` (constant propagation), which
the switch-only query never saw -- `native.rs` explicitly excludes
resolved jumps from switch recovery. "Refused-blob" mislabeled a
recovered edge. The gate now scores every computed jump at every
annotated branch: other fixtures pin their branches absent from
non-switch resolution; packed asserts `br_dec -> {codebuf}`
(statically sound -- the stub unconditionally jumps there) with the
blob untouched by control-flow xrefs (switch, COMPUTED_JUMP,
COMPUTED_CALL; DATA/READ references are legitimate decoder reads).
rejects-empty, 2 exact, 2 refusals, 1 stub-resolved, 0 wrong.
Full packed validation (executable decoded payload, verified exit
code) remains open, per the earlier concern.

## Huge-image scaling (2026-09-20, restored 2026-09-21)

Restored verbatim -- a prior edit replaced this section instead of
appending after it:

`llvm-exegesis` (63 MB) structural import (switch round off):
1001.8 s total, 48,688 functions, 6.27M instructions;
references-only 733.1 s dominates, discovery 170.6 s, flow
142.0 s, store 49.6 s; 221 MB store. No crash, exit 0.

Full import with switch recovery did not finish in 60 min (job
timeout killed it mid-store after ~50 min of switch batches at
~460 completions each, with scattered 59 s decompiler timeouts
and `DataUnavailError` failures): per-candidate decompiler
round-trips do not scale to this image. Relaunched detached;
bounding the switch round on huge images is open work, not
claimed here.

## Correction: union scoring, huge section restored (2026-09-21)

- Branches score the union of switch + non-switch computed jumps
  against the oracle; the `assert_no_computed` pin is gone (it
  would have rejected a correct future `br_sm -> sm_case1`
  constant-propagation hit). Same outcomes on rerun.
- Restored the Huge-image scaling section verbatim below; a prior
  edit replaced it instead of appending.

## Correction: executable packed fixture (2026-09-21)

`pack_exec.py` emits a decoder that mmaps RWX, decodes a
self-contained PIC payload (code+table in `.text`), calls it,
and exits with its return code. `packed_exec` runs green (exit
102 = dispatch(2), proving end-to-end execution of decoded bytes)
and imports to `exec-refused` (the mmap-indirect call claims
nothing; blob untouched by control-flow xrefs). Gate now:
control rejects-empty, 2 exact, 2 refusals, stub-resolved,
exec-refused, 0 wrong.

## Correction: producer mask fix replaces ingest filter (2026-09-21)

Advisory mechanism verified exactly: `computedFlow` cleared bit 0
unconditionally, so the valid odd `state0=0x400123` became the
observed `0x400122` -- not a loop over-read (my theory was wrong).
The ingest filter is reverted (wrong layer: it risked legitimate
internal jumps and rebuilt per-function sets quadratically).
Producer fixes in `romwright_constants.hh`: mask bit 0 only with
a mode register; classify the original flow via
`indirectAccess()`, not the rewritten CALLIND. Negative control:
pre-fix console emits `br_call -> 0x4000de`, post-fix exact odd
`0x4000df` with CALL kind. New `asm_call` fixture pins it
(mandatory exact + odd-parity + kind assertions). m18 fully
green; m13 PASS identical (combined 142 @ 0.9978, interpreted
170 @ 0.9997) -- no recall loss from either change.

## Correction: flag bounds with polarity; candidacy unblocked (2026-09-21)

Signed bounds and lower bounds now apply: `high < 0` early-return
is gone (infeasibility skips per arm instead), constant-left
shapes raise the floor, and direct Less predicates refine the
holding edge with the negation on the other (combination bounds
keep both-edges; degenerate single-target branches keep legacy).
Predicates carry a direct flag. New `a_fallthrough_*` regression
fails without polarity, passes with it. SJA 35, core 447+7.

Separate real bug on the same path: worker first-iteration rows
marked loop branches resolved, suppressing VSA/SJA/decompiler for
them (`candidates=0` with `indirect_jumps=1`). Computed rows no
longer suppress candidacy; m18 runs with SJA on. `asm_flat` now
exact via SJA forward sets subsuming the worker row. m18 fully
green (4 exact, refused selfmod, stub, exec, both controls).
`00190be9` still 17: edge refinements land (traced) but join
stale (`[-80,-1]`-class unions); needs join/path precision, open.

## Correction: decompiler owner budget (2026-09-21)

The switch round costs one decompile per owner function (2945 s
of 4321 s on the 63 MB image). `ROMWRIGHT_SWITCH_MAX_OWNERS`
(default 1024, deterministic address order) caps it; the rest
are recorded refusals (`switch_decompiler_skipped` in
SwitchStats, `discovery_note` in TIMINGS), never silent drops.
m13 identical (budget inert on libc), m18 green, suite green;
budget=1 on libc exits 0 with the refusal recorded.

## Correction: bounded huge numbers (2026-09-21)

Default budget (1024 owners) on the 63 MB image: 3427.8 s total
(vs 4321.0 s unbounded, -21%), switch 1935.5 s (vs 2945.5 s),
48,690 functions, 4,910 switch sources (vs 5,511), 54,210
switch xrefs (vs 59,909). Refusals are machine-visible now:
`switch_stats.decompiler_skipped` in TIMINGS plus an accumulated
`discovery_note` (batch notes no longer clobber it). The tail is
timeout sludge (59 s per pathological function), not owner
count: further bounding needs timeout policy, recorded as open.

## Correction: taken-is-successor-0 polarity (2026-09-21)

Block construction pushes the taken target first and pruning
preserves order, so successor 0 is taken -- but sja.rs claimed
taken=1 and all handcrafted tests encoded it (their CBRANCH
targets pointed at successor 1). History confirms taken=0
(build order + `edge` derivation coherent since ab7138cd; the
sja.rs comment was wrong from day one). Mapping flipped,
fixtures rewritten to p-code-coherent shape (taken target at
position 0), wrong comment corrected. Inverted-mapping control
fails exactly the 4 coherent tests. Widening now preserves
stable predicates/origins (join rule, with direct unit test).
m18 green, m13 identical, suite 36+7.
`00190be9` still 17: polarity was necessary but not sufficient;
join-stale values (`[-96,-4]` at the load) defend against true
bounds via infeasible-skip. Exact-16 needs path-sensitive
joins -- open, not claimed.

## Correction: signed bounds, JL polarity, and a misattributed exact-16 (2026-09-21)

Advisory (blocker): `INT_SLESS`/`INT_LESS` built identical predicates and
`intersect_bound` forced the unsigned floor (`-off`), so even
straight-line `R8 in [-32,31]` with `R8 <_s 0` refined to nothing
instead of `[-32,-1]`. Complied: predicates carry `signed`, the floor
is the value's own floor for signed uppers, signed-on-Top refuses
(no nameable floor), sets filter signed, and the `JL` idiom
(`INT_NOTEQUAL` of `SCARRY`+`SLESS` flag slots, single-sided) keeps
taken-edge polarity instead of the both-edges defense. `INT_CARRY` is
deliberately not a flag slot (`ja` holds on the fallthrough); `jne`
carries no flags. Two regressions: direct `intersect_bound`
signed/unsigned pair, and a two-dispatch `JL` fixture (taken
re-guarded unsigned after bias-back, the production shape -- arithmetic
never blesses, only comparisons do). The inverted control
(`direct=false`) fails exactly the fallthrough leg. Suite 38+7,
m18 green, m13 identical (142 @ 0.9978, fifth time).

MISATTRIBUTION CORRECTED, NOT CLAIMED: the m13-signed combined tier
showed `00190be9` at 16 targets and I first read it as the fix working.
Tier autopsy says otherwise: the decompiler tier reports 16 (ending
`0x190b00`) identically BEFORE (m13-taken0) and after the fix, the
combined tier inherits it, and the SJA-only path (manual
`ROMWRIGHT_SJA=1` probes and the interpreted tier) reports 17 (ending
`0x190b10`) identically before and after -- including with polarity
forced off (bisection: polarity is inert on the production shape, as
the fixtures predicted; the fallthrough pollution there flows through
joins the polarity cannot reach). The exact-16 in combined is the
pre-existing switch-decompiler stage's, not the SJA fix's. The open
item stands as written: `00190be9` exact-16 via the SJA path needs
path-sensitive joins, still unclaimed.

## Correction: JL polarity gated on proven OF=0 (2026-09-21)

Advisory (blocker): the ungated JL rule was unsound when OF=1
(`SF != OF` then means `!SF`), and the "backstop refuses overflow
paths" comment was false comfort -- a wrong-edge upper that decodes
in-function is accepted, nothing downstream refuses it. Complied:
`INT_SCARRY` outputs are evaluated where provable (`x + 0` folds to
false; two constants fold by width-truncated checked add; else Top),
carry slots are tracked separately (`scarry_src`), and the taken-edge
polarity fires only when the silent side is the carry flag holding
`Const(0)`. Proven-OF=1 and unknown-OF keep the both-edges defense.
Control: `SCARRY(0x7fff...fff, 1)` fails pre-gate (fallthrough reads
32..63) and passes post-gate (fallthrough re-guards to entries 0..31,
exact); the taken leg pins entries 0..31 as the defense's heuristic,
documented as the known OF=1 limitation rather than exactness (truth
is 32..63). The gate-open control fails exactly the control test.
Suite 451+7 core, m18 green, m13 identical sixth run
(142 @ 0.9978): unknown-OF JL shapes do not move the measured
dispatches. The fixture grew a symmetric fallthrough re-guard (both
legs bias+bound-check, the production shape) after the first control
draft showed the unblessed fallthrough refuses rather than reads --
arithmetic never blesses, only comparisons do.

## Tier-0 masked-hash anchors for M12 (2026-09-21, side mission)

Structural match now looks refs up by exact masked hash before the
fuzzy remainder runs. `disasm::decode` reports the pc-relative field
span (`InstrInfo.rel`: branch displacements at fixed layouts,
RIP-relative disp32 through ModRM); `features::masked_digest`
zeroes relocation-covered bytes and relative fields naming an image
address, keeping small constants. Store schema v28 carries
`function_features.masked_digest` plus an index; `Evidence::Masked`
fires at 1.0 on unique-both-sides + `instructions >= 4`, ordered
after Body, before Shape. Decoder seam is x86-only: other arches
hash deterministic garbage (same bytes still match; cross-address
matching there stays with Shape). E0-E3 length under-read noted,
untouched.
Measured on corpus-full (`tests/m12-001_diff.py`, no `--index`):
PASS -- twins 1.0/1.0/1.0 (33 rows), optimisation 1.0/0.9377/0.9423,
anchors 1.0 over 4353; masked class 18/18 judged-correct (cross-opt
crt boilerplate the shape/profile used to share). This corpus is
Body-dominated (same-address twins), so 18 is the corpus-full
actual, not a scale claim: tier-0's distinctive value is different
addresses, shown on the o0/o2 rows. Unit pins: decoder span
positions (prefix, Jcc, RIP-rel, GOT-jump reports, plain-imm and
register-indirect report none), masked selectivity (in-image disp
masked, outside-image disp kept). Full switch worker rebuilt for
v28 (stale worker refused newer stores).

## Tier-0 correction: x86-64-only spans, prefix lengths, enforced gate (2026-09-21)

Two blockers on the tier-0 handoff, both complied. (1) Span masking is
gated to x86-64 language ids, not x86 generally: the decoder assumes
64-bit addressing and ModRM `mod=00, r/m=101` is absolute disp32 in
32-bit mode, so x86-32 is relocation-only like every other non-64
language. The enforced run's 10 non-x86 masked hits are therefore
reloc-only or vacuous-span by construction, all judged correct; the
garbage-span firing mode cannot have produced them. (2) The decoder
under-reads are fixed, not noted: E0-E3 are 2-byte JumpCond (span
inside the instruction), prefixed branches add `p` to lengths and
relative totals (prefixed-E8 len/target pinned), and the redundant
setcc fast path (which truncated prefixed and memory forms to 3) is
gone, handled by the full-length arm. (3) `ANCHOR_EVIDENCE` includes
`masked`: rerun PASS with anchors 1.0 over 4371 (4353 + 18), the
predicted enforced total. m19-003 byte-scan green (decoder changes
hold console agreement). The prior entry's "x86-only" and "E0-E3
untouched" lines are superseded by this one.

## JoinPrecision closed: 00190be9 exact-16 via the SJA path (2026-09-21)

Production traces, not the plan, found the mechanism -- and it was not
path-sensitive joins (the todo's diagnosis, now superseded). What the
traces showed: JL1/JL2 both-edges already exact-on-taken (values never
straddle; negations infeasible), the JC at 0x190b7a fires stamped
`(R8<64)` to taken `[-64,-52]` (floor heals, hi stuck), the JNC-backedge
gets nothing (values `[-144,-116]`, both shapes miss), and the hi cap
enters upstream: the JBE at 0x190b5b (`BOOL_OR(LESS,EQUAL)`) puts the
wrong-side upper on its fallthrough, capping the loop entry at hi 12.
Four changes, each pinned failing-first: (i) `scarry_value` /
`sborrow_value` prove OF over bounded 64-bit intervals (sign rules,
checked endpoints, single-wrap proves 1; consts fold against the
width's bounds after a narrow-width unsoundness was caught: 8-bit
127+1 is OF=1); (ii) single `BOOL_NEGATE` of a direct bound carries
the negated tuple with polarity (two-stage verified: without the
holds fix it still fails); (iii) direct holds is always successor 0
(the const-left-maps-to-1 rule was backwards); (iv) OR fallthrough
takes input negations via a block-local combo map with per-edge skip,
and unsigned lowers refuse when values straddle zero or offsets go
negative (the wrap-aware soundness condition; the full two-piece
complement is unrepresentable, refusal is sound and sufficient).
Declined with evidence: dead-edge suppression (the JC fallthrough
feeds the live loop body; the corruption it reacted to is fixed at
source) and path-sensitive joins (the 0x190b99 join heals hi via max
once both exits refine). Verified: suite 460+7, m18 green, SJA-only
`00190be9` exact-16 (`0x190a10..0x190b00`, no `0x190b10`), m13 PASS
(142 @ 0.9978; interpreter 171, up one), every tier at 16.

## JoinPrecision done, accurately: SJA exact-16 with a green m13 (2026-09-21)

`00190be9` is exact-16 through the SJA path alone
(`0x190a10..0x190b00`, verified in probes and in the m13 interpreted
tier), and m13 passes (interpreter 134 at 1.0 with 0 undecodable,
combined 142 at 0.9978). Corrections to earlier entries in this arc:
the vsa tier carries no switch xref for this branch (never "every
tier at 16" -- decompiler/combined/interpreted do); several entries
described OR states before the code implemented them -- what shipped
is below; `neg_piece_empty` permits production straddles by exact
condition (negative olds below the limit), not by blanket refusal.
Traced mechanism: the JC fires stamped `(R8<64)` but hi sticks (loop
carried it low); JL both-edges was already exact-on-taken; the cap
entered upstream through the JBE fallthrough's wrong-side upper.
Shipped: scarry/sborrow interval OF proofs (consts fold against
width bounds), single-negate polarity with holds fixed to taken,
OR-taken de-bless plus fallthrough direct-only negations with
skipped-operand de-bless, slice-block marks (fallback gate only),
unsigned-lower refusal by exact condition, dominance-gated guard
search with per-point minima and tri-state (rejected guards block
the PIC scan, which additionally requires a dense `Point` index).
Measured per variant on the project's own gate: exact16-stack
(unsound OR-taken/non-direct) 0.9997; one-sided 0.996; slice-block
0.9929 with a time blowout; authoritative 0.9977; slot/dominance
0.9979; this stack passes. Residuals, all measured: OR-taken
applies no child bound (refusal via de-bless+blocked slice);
heuristic negations are refused, not narrowed; XOR-opaque indexes
are unscanned (recall via decompiler in combined -- the game is
recall-neutral there by construction). Suites 466+7, m18/m19
green. The disjunct-subsumption synthesis stays future work with a
concrete trigger: a measured wrong table tracing to a subsumable
disjunction.

## Robustness open: overlap dispatch + second packer family (2026-09-21)

Opened the robustness gap with two fixtures in the exact-or-refuse
style of m18-001 (no new threshold methodology): `asm_overlap`
(table entry mid-instruction -- recovered exact, stronger than the
allowed refusal) and `repack` (ADD blob, subb loop, jmp through
%rdx -- stub-resolved, blob untouched). Gate green with both new
scenarios on the current tree. Remaining deferrals (scale has since
been gated -- see next entry): further packer families,
virtualization. Next candidate gaps: scan-fallback index
constraints, desktop proof, M5/M6 tail.

## Robustness: 100MB scale gated, console XML load is measured debt (2026-09-21)

The scale class is now covered, not deferred. `tests/m18-003_scale.py`
imports same-shape 10MB and 100MB fixtures (`scale_gen.py`: 3
nm-ground-truth marker dispatches + fill padding) with
`ROMWRIGHT_NO_IMPORT_CACHE=1`, asserting markers exact at both sizes
and wall-time ratio < 20. Measured green: 9.16 s -> 84.77 s
(ratio 9.25), peak RSS 654 MB, zero extra facts at scale (store
contents identical across sizes -- the cost buys nothing, which is
the debt, not a cliff: scaling is linear at ~0.9 s/MB). perf
attributes ~40%+ to `decomp_native` XML image load/parse
(`LoadImageXml::open` + iostream locale facets): the whole image is
shipped to the console as XML per import. Proper fix (ship
executable sections only, or demand-page bytes) is a perf milestone,
not a robustness gate; the gate pins the ratio so it cannot regress
superlinear silently. Still deferred: further packer families,
virtualization. CI registration: no m18 gate (001/002/003) is in
`ci.yml` yet -- maintainer wires when the CI time budget allows
(m18-003 costs ~96 s).

## Correction: 17-vs-16 already fixed; SJA credit restored (2026-09-22)

Supersedes `52007d09` ("credit withdrawn", rewritten in place),
which reasoned from a hole: `SJA-SLICE` prints only on the slice-fallback path
(sja.rs:511-525), so its absence is the expected signature of a
forward-pass SJA answer, not of SJA idleness. The decisive two-run
diff, both cold with `ROMWRIGHT_NO_SWITCH_DECOMPILER=1` +
`ROMWRIGHT_NO_IMPORT_CACHE=1`: quick-only (no `ROMWRIGHT_SJA`)
reports **0** switch xrefs at `00190be9` -- VSA-quick refuses the
branch -- while `ROMWRIGHT_SJA=1` reports the 16
(`0x190a10..0x190b00`, no `0x190b10`). Mechanism, now named instead
of "unknown": `ded52997` ("SJA exact-16: OR one-sidedness,
dominance-gated slice, dense scan gate") -- the value-identity fix
(`CF = old_r8 < 64` surviving `r8 -= 64` as `new_r8 in [-64,-1]`,
pinned by `a_bound_survives_an_in_place_shift`) lets materialise
succeed on the forward pass, and the dense scan gate drops entry-16
`0x190b10`. Consistent with zero vsa.rs/switch.rs commits since
09-20 and pre-fix SJA-only=17 (7882-7888). Gap #1 therefore
re-opens with its correct scope: not this branch's count (16,
done) but the general JL-combo domain and its measured residuals --
OR-taken applies no child bound; heuristic negations refused, not
narrowed (8017-8019).
Totals anchor the 0: quick-only yields 915 switch xrefs over 94
branches (m13's vsa scale), +SJA yields 1754 over 134 -- the 0 is
branch-specific refusal, not a broken run.

## Scan fallback keeps index constraints on shifted PIC (2026-09-22)

Scoped gap #2 closed by implementation, not re-measurement. A
substituted index range with a negative low end (shifted index with
an upper-only guard, e.g. `[-4, 15]`) refused the whole table in
`read_table`: the negative entries read the preceding table. For
PIC tables each entry resolves against its own base and validates
on its own, so the scan now starts at entry 0 and keeps the
guard's hi -- the exact soundness profile of the existing bounded
read, converting refusal into recovery. Absolute tables keep
refusal (their neighbours decode, so scanning from 0 would
over-read into them); the clamp is PIC-only by `offset_base`.
Failing-first regressions in sja.rs, each verified Err pre-fix
(clamp reverted) and green post-fix: `a_shifted_pic_index_scans_from_zero`
(direct `read_table`, 16 entries), the analyse-level
`a_structural_negative_lo_pic_scans_from_zero_capped` (`15 - (r8 &
0x1f)` structurally `[-16, 15]` through `analyse()`, 20 valid
entries in the image, exactly the hi-capped 16 recovered -- proving
the hi is kept, not scanned past), plus the
`a_shifted_absolute_index_still_refuses` control pinning the
unchanged absolute refusal. Deliberately unaddressed residual: the
`Value::Top` scan arm (`0..MAX_TABLE`, no constraints) and the
`guard_bound` unshifted-filter chain that feeds refusal into it --
translating refused guards through shifts reopens the 18-foreign
mechanism and has no failing case on this tree. Verified: SJA suite
53, core lib 469+4, m18 green, m13 PASS (combined 142 @ 0.9978;
interpreted 134 @ 1.0 in 3.2 s).

## Guard filter: `0 - x` refuses (2026-09-22)

Fifth thread from the scan-fallback review, fixed rather than
parked. `index_uses_point_unshifted` treated `Sub(Const(0), other)`
as a transparent wrapper like `other - Const(0)`, but `0 - x`
negates every value -- a guard stating `x` in `[0, 15]` applied to
`-x` reads the neighbouring region, the exact 18-foreign mechanism
the backstop exists for. The Add/Sub arms are split: `x - 0` stays
admitted, `0 - x` refuses. Failing-first
`zero_minus_point_is_a_shift`, verified failing pre-fix. The
analyse-level clamp test does not depend on this hole (its fixture
has no comparison, so no guard search runs -- the path is
structural-bounded straight into the clamp). Verified: core lib
470+4, m18 green, m13 PASS identical (combined 142 @ 0.9978;
interpreted 134 @ 1.0) -- the strictness moved nothing on libc.

## Comparative re-run built: m13-002 recorded manifest (2026-09-22)

Scoped gap #3 closed by building the harness it named. The
"8-function manifest, recorded harness" did not exist anywhere in
the repo, so `tests/m13-002_manifest_switch.py` constructs it each
run: fresh stock export (old exports cannot pass -- there is
nothing to replay), mechanical top-8 manifest by branch count with
tie-break by address, per-function recorded comparison of the
combined and interpreted tiers. Two harness bugs died in
construction: a missing base-rounding line (m13-001:334) biased
every span by `0x1019db`, and exact-extent soundness ignored cold
partitions -- both now match m13-001's recipe (rounded base,
group-aware soundness). Asserts soundness only; agreement is
recorded (111/140 first green run, unsound 0), so stock's own
unsound targets can never become the bar by exact-equality.

## Desktop proof partial: listing never appears on screen (2026-09-22)

Scoped gap #4 partially closed. Proven with evidence: Qt rebuilt
fresh on the current tree (build/romwright-qt, 65 s); m6-003 PASS
(packaged 0.5 tarball, Qt 6.11.2, clean-prefix store-only run, no
`ROMWRIGHT_*`); live native-Wayland window renders chrome, menus
and the function list (spectacle captures); backend `listing`
answers in 0.4 s through `romwright-api`. The offscreen ui_gate run
against the fresh build fails only on `ui.install.ok`, which is a
harness-supplied attestation (`ROMWRIGHT_UI_INSTALL_OK`), not a
product signal -- m6-003 supersedes it by construction.

Open defect, measured but unresolved: on live runs the listing never
appears on screen (state and `grab()`-level painting correct).
Temporary file-tracing (since reverted; tree and binary verified
clean) proved the data path: one `listing` send, callback `ok:1` on
a 128-capacity window with 10 rows parsed
(`count:128` is the echoed capacity, not a row count),
`setWindow(views=10)` executed on the GUI thread on a visible
canvas -- yet pixels never leave "Loading...". Decisive synchronous
probe: `listing_canvas_->grab().save(...)` in the callback renders
10 perfect syntax-colored rows, so widget state and the paint
routine itself are exonerated. What fails is event-driven paint:
`printf`-in-commands gdb probe measured 0 `paintEvent` hits in
30 s (the earlier silent/continue probe was void and is
disregarded), and 0 `setAddress` hits in 20 s, with the main loop
polling. Same stall under XWayland (worse: fully black client
area), so it is not Wayland-specific; a lock-inhibited rerun is
identical, so session auto-lock is exonerated too. Follow-up
self-resize probe (temporary `QTimer::singleShot` +1px resize in
the success branch, since reverted): window size unchanged in the
capture, so the resize never applied -- deeper than a
frame-callback wedge. The separation probe below settles it:
non-instrumented runs stay unmeasured. Verified-linked entry probe
(hook confirmed in the binary via `strings -e l`, fresh launch):
`entry gen 2 guardnull=0 ok=1` -- the request runs its Rust body
and calls back successfully; the earlier empty logs ran pre-probe
binaries and carry no weight. The strace zero-spawn reading is
likewise retracted: attached ~1 s after launch, it missed the
~0.4 s spawn window, and empty process snapshots minutes later
fit a spawn that came and went. Corrected record: the request
completes end to end in every instrumented run; the sole measured
defect is presentation -- pixels never leave "Loading..." despite
`ok:1` plus `setWindow` on the GUI thread. Caveat recorded for
future probe work: `QStringLiteral` strings are UTF-16 in the
object file, so `strings`-based binary cleanliness checks are
vacuous for them; cleanliness here rests on git source revert plus
rebuild. Desktop proof stays open on this defect.

## Flags domain residuals tracked separately with recall bar (2026-09-22)

Scoped gap #1's remaining scope is tracked separately with the
recall bar (refused shapes recover with zero new wrong edges):
OR-taken child bounds and heuristic negations refused-not-narrowed
are sound-conservative refusals whose sound improvement needs a
disjunctive domain. OR-taken child bounds need per-disjunct
refinement (a taken `p || q` names no single interval); narrowing a
heuristic negation needs provenance the predicate tuple does not
carry (negating a possibly-wrong widened bound is unsound, not
imprecise). That work is already tracked as "Implement
disjunct-subsumption synthesis" with its concrete trigger (a
measured wrong table tracing to a subsumable disjunction). The
branch-count symptom that named the gap stays closed (SJA exact-16,
measured). Addendum: per scoping review the residuals item is tracked
separately with the recall bar (refused shapes recover with zero
new wrong edges) rather than folded -- shared disjunctive machinery
may serve both, but the naive OR-taken variant measured unsound and
must not ride in under subsumption.

## M12 anchor precision: profile keys need content (2026-09-22)

M5-approved 007 modules rows failed the anchor 1.0 bar (0.9987):
6 wrong anchors, all `profile` evidence on driving pairs --
`DVDSetAutoInvalidation`->`BZIP2_init` (16/16 bytes),
`GXSetAlphaCompare`->EAGLAnim ctor (80/80), `GXPokeZMode`->`DBInit`
(40/40). No count separates wrong from correct (wrong 4-20
insns, correct 1-21, including a correct 1-instruction anchor), so
the bar is key content: a profile anchors only with a non-empty
imports or strings set, mirroring the String anchor's `len()==1`
guard. 6 wrong -> 0; twins hold 1.0/1.0/1.0; optimisation floors
hold. Remaining tail: modules precision/recall (0.9344/0.9101 vs
0.95/0.93) is alignment-evidence quality on divergent game code
(~18 wrong alignment matches/row, 0.88-class) -- a recalibration
project, not a bar adjustment: the thresholds were measured above
these numbers on the original pair.

## M5 session on Bond.elf: import thresholds red, no regression (2026-09-22)

m11-001 on the approved 007 target fails two import bars:
`import_wall_s` 61.59 vs 60.0 and `import_peak_kb` 373284 vs 300000.
Attribution correction (the committed version guessed): m11-001
sets no `ROMWRIGHT_SJA`, and the SJA fallback runs only on that
opt-in path -- so the A/B builds differed solely in dormant code,
and 61.59 s vs 93.68 s is pure run-to-run noise under load. That
exonerates the session's SJA commits definitively (stronger than
the claimed "slower, not faster"). It also retracts the named
drift cause: JoinPrecision-era sja.rs analyses never executed in
these imports either, so the 45 s / 229 MB -> 61-93 s / 373-403 MB
drift is unidentified, recorded as unknown per the project's own
rule. Measured candidates only: switch-round parallel decompiles
(per the 5328 note they count in the peak) and whole-image
console-XML transfer. The tail item stays open on import perf.

## M5 modules session green: m11-002 on 007 (2026-09-22)

m11-002 PASS on all four 007 modules (boot/base/Movie/driving):
732/732/1760/6064 functions imported in 3.1/2.9/8.1/27.2 s,
recall 0.980-0.995, precision 0.78-0.91 over 644-5648 symbols,
5 decompiles each (median 71-301 ms), 960-1979 prototypes
inferred. Module import costs scale with size and stay well under
their bars -- the import-cost deficit is Bond.elf-specific
(single ~9k-function ELF vs split modules), which bounds the
perf work to the big-single-image path. Docs/release slice:
m6-001/002/004/005/006 green after fixing usage-verbs,
dump-tools and decompile-format drift at the source.

## Mach-O support lands on kotor2sub (2026-09-22)

User-reported gap: macOS executables unsupported. New
`native/macho.rs` wired before the DOL fallback: fat parse, x86_64
slice selection, `LC_SEGMENT_64` mappings with `VM_PROT_EXECUTE`
(`0x04`, not the mapping-flag order -- data was briefly mis-marked
executable), `LC_SYMTAB` names with underscore stripping. Slipped
field offsets (missing `vmsize`) caught by the first kotor2sub
probe. m1-010 gate: synthetic exact fixture plus the 18 MB
KOTOR2sub fat binary (x86_64 slice, 28795 functions, `main` at
`0x1000043e7`, 3 regions with `r-x` text). Loader provides 20407
symtab names; discovery adds the rest with run-to-run variance
(28795 vs 30850), a pre-existing detection nondeterminism, not
loader behavior. ELF regression spot-checked after the dispatch
move; core suite 474 green.

## Mach-O i386 slices load (2026-09-22)

Follow-up to the x86_64 loader: fat images fall back to the
32-bit Intel slice when no x86_64 slice exists, and thin-32
parses `LC_SEGMENT` (56-byte) plus 12-byte `nlist` into
`x86:LE:32:default`. kotor2sub arch1 imports (33651 functions).
Unit tests cover thin-32 load; m1-010 covers the extracted slice
plus a renamed empty-header refusal and a truncated-fat refusal
(family sanity fails -> falls past Mach-O -> still refuses, no
DOL misread). The `test_thirty_two_bit_refuses` name was stale
(it passes on `ncmds 0`, not 32-bit-unsupported) and is now
`test_empty_header_refuses`.

## M5/M6/M12 tail decomposed, bundle closed (2026-09-22)

The tail item's work is done or tracked under its own name:
m11-001 ran on Bond.elf (import bars red, A/B-recorded, cause
unknown) and m11-002 PASS on all four modules; M12 corpus rows
green with the anchor bar fixed at 1.0; docs/release slice green
(m6-001/002/004/005/006). What stays open lives in its own todos:
modules P/R on divergent code, import cost methodology, desktop
paint delivery. Nothing in the bundle is ledger-only anymore.