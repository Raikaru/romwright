# STATUS

## Current phase/generation
Stage 9 optional surfaces are implemented. Stage 4 remains the gated native
workflow baseline (39.6 MB peak vs 375 MiB stock; see gate numbers below and
`benchmarks/reports/stage4-gate.json`).

## Current implementation surface

- Phases 5–7 are implemented in `lre-core`, `lre-api`, the Qt workstation
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
- `lre-cli architectures --project DIR` scans the installed `.ldefs` catalog.
  Non-x86 native decompile parity is not claimed without a matching compiled
  SLEIGH language and normalized specification bundle.
- `desktop/ventris-qt` has CPack TGZ packaging. `packaging/sbom.py` emits an
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
- Rust workspace: lre-model, lre-db (SQLite WAL+FK, schema_version=1,
  revision-stamped mutations), lre-core (CoreService facade), lre-cli,
  lre-worker, lre-worker-client, lre-api, and lre-debug. `cargo test
  --workspace`: 82 tests pass across 20 suites.
- E2E proven on x86-64 ELF fixture (gcc -O0, 12.6 KB):
  - import: 15 functions, 34 xrefs, 93 symbols persisted with
    provenance `ghidra-bridge / 12.1.3`
  - store-only `open` (no JVM launched): works
  - rename persists in store, revision bump verified in unit tests
  - decompile + disasm through bridge against saved program
- Native worker protocol (lre-worker) fixed to the pinned C++ exactly:
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
  third_party tree is untouched): when VENTRIS_SLA points at the compiled
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
  the supported no-JVM decompile route. Spawns `lre-worker` against the
  patched ghidra_opt (env VENTRIS_GHIDRA_OPT, default native/build/ghidra_opt)
  with vendored specs (native/specs) and the store project. Verified
  token-identical to the bridge oracle (`int add(int param_1,int param_2){
  return param_2 + param_1;}`) — differential step "CLI decompile".
- `native/build_console.sh`: reproducible SLEIGH console build (needs
  binutils-devel/bfd.h, Ghidra's own native-build prerequisite; the bfd-less
  spike binary predates the pinned tree). Console env defaults now derive
  from the Ghidra install (VENTRIS_GHIDRA) instead of /tmp/spike.
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
- lre-db composes command transactions: `rename_command` (rename + revision
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
- `lre-model::RevisionEvent { revision, kind, detail }`; store
  `events_since(program, since)`; `Core::events_since`.
- Evidence (native import + rename, real store):
  (2, replace-functions, 11), (3, replace-xrefs, 3), (4, rename,
  renamed_add) — strictly increasing, observable windows.
- Tests: `revision_events_recorded` (kinds, revisions, since-windows);
  paged test updated for bump semantics. 36 workspace tests.

## CORE-004: paged query API
- `lre-model::Page<T> { rows, offset, total, revision }`; store methods
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
  lre-db (hex TEXT columns, `addr_cell`/`addr_from_cell`), the JSON-RPC
  bridge (tolerant `parse_rows`: rows with unsupported-space addresses
  — e.g. Ghidra stack comments `Stack[-0x10]` — are skipped with a count,
  not silently mangled or import-aborting), and the CLI (argument parsing).
- `Address` has a custom `Deserialize` (hex string OR `{space, offset}`;
  last-colon split for overlay names like `.annobin.notes::00000000`) and
  `Display`/`hex()`.
- API: `Core::{xrefs_to, xrefs_from, rename_function}` take typed
  `&Address`; `lre-db` same; the worker consumes `f.entry.offset` directly.
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
  panic, typed errors (19 lre-core tests incl. this).
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
- `lre-core::session`: `RuntimeConfig` (immutable; env-derived defaults, the
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
- Tests (18 lre-core, 32 workspace): region file-byte reads, BSS zero-fill,
  patch overlay, unmapped/crossing reads, `RuntimeConfig` defaults, and
  `ProgramImage::open` against the real fixture (add's bytes at 0x400466).
- The environment-var contract inside `native_runtime` moves to accept a
  `RuntimeConfig` next (CORE-001 typed identity; CORE-004 paging...), per
  the ratified 9-phase roadmap.

## Post-review hardening (facade contract + real-binary evidence)
- Native paths moved into the Core facade (review: "a GUI can't reuse the
  native decompile/disasm without copying lre-cli's spawn logic"): new
  `lre-core::native_runtime` + `Core::{import_native, disasm_native,
  decompile_native, mem_native}`; lre-cli is now a thin delegate (same
  methods a GUI consumes). `decompile` validates VENTRIS_SLA
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
- `lre-core::native`: ELF64 + PE (PE32/PE32+) parsers (sections -> memory map,
  SHT_SYMTAB function symbols, SHT_DYNSYM externals, SHT_RELA GOT relocs
  naming the `ff 25` PLT stubs), direct-call sweep (call/jcc/jmp rel32),
  and the call-target closure (FUN_<hex> naming). Facts land in the same
  store tables with provenance `native-import / 12.1.3`.
- CLI: `lre-cli import <binary> [--name N] [--project DIR]` — the
  whole import with zero JVM.
- Verified: tiny_bin native import = 12 code functions whose entry set
  is a subset of the bridge oracle's (differential "import parity" step);
  tiny_pe.exe native import = 310 functions (entry + CRT call closure vs
  Ghidra's 138 — closure granularity differs, documented approximation;
  the ELF parity is exact at the entry-set level).

## Memory measurement (ADR-0001 target: beat 375 MiB stock)
- Protocol worker run (register + setAction + decompileAt on the x86-64
  ELF fixture, VENTRIS_SLA self-disassembling build):
  peak RSS 39.5 MB — **9.5× under the 375 MiB stock-Ghidra baseline**.
- The native console path and the store-only workflows stay in the same
  order of magnitude (no JVM in any no-JVM path).

## JVM-free workflow CLI (added this phase)
- `lre-cli import <binary> [--name N]` — ELF/PE -> store, no JVM.
- `lre-cli mem <binary> <vaddr> <size>` — mapping-backed memory dump.
- `lre-cli disasm <binary> <addr>` — SLEIGH disassembly via the
  pinned console (no JVM).
- `lre-cli comments <program>` / `types <program>` — store-owned facts.

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
    and Qt layers: `lre-debug` implements read-only GDB RSP memory reads,
    Core reuses a bounded connection, and the hex canvas exposes a live
    endpoint toggle and source marker. A deterministic local RSP server
    verifies acknowledgements, checksum rejection, target errors, bounds,
    connection reuse, and the two-byte read path. A real Dolphin validation
    now also passes: Dolphin 2606a, headless `Null` backend, and the Agent
    Under Fire RVZ served GDB port 24689; `memory_live` read 16 bytes at
    `0x80000000`, beginning with `47 57 37 45 36 39` (`GW7E69`).

- m0-003: added `lre-cli graph <program> --largest --binary <path>` locator
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
  Added machine 0x3 (EM_386) to elf_language in lre-core, enabling native ELF32 x86 import.
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
  [CI run 33915494027](https://github.com/Raikaru/ventris/actions/runs/33915494027)
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
- `crates/lre-core/tests/elf_image.rs` checks ELF64 LE and ELF32 LE/BE
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
  https://github.com/Raikaru/ventris/actions/runs/33966774392

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
  https://github.com/Raikaru/ventris/actions/runs/33979109416

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
- b prerequisite regression: with no `VENTRIS_SLA` override, the standalone
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
  agree. The regression deliberately unsets `VENTRIS_SLA`.
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
  `cargo test -p lre-core --no-default-features native::discovery` 18 pass;
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
  (`crates/lre-sig/tests/vsig_roundtrip.rs`) with the crate registered in the
  workspace and no format code.
- b: implement the container, its invariants and typed rejections; document
  the layout in `docs/vsig.md` and the clean-room stance in
  `docs/third-party.md`.

### m2-010 evidence
- `638df1d` commits the failing acceptance: `unresolved imports lre_sig::…`.
- `crates/lre-sig` implements `.vsig` v1: 16-byte header (`VSIG`, version,
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
- b: `lre-sig` gains the `ar` archive reader and ELF `ET_REL` extraction:
  per-function patterns with relocation-covered bytes masked from public
  relocation width tables, rejecting unknown relocation types instead of
  guessing a width. Unit tests cover both.
- c: `lre-cli signatures build|info`, the CI job, and the docs. Slices stay
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
  siblings contend on the same execution units. `VENTRIS_CONSOLE_SHARDS` pins
  it; `VENTRIS_REF_SHARDS` never shipped.
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
  model claims, behind `VENTRIS_REGISTER_PARAMS`.

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
  `lre_model::StorageSymbol` rows come from `<mapsym>` (symbol plus its
  storage entries, database.cc:2643-2654), so the pass reads mapped storage
  rather than scraping C text.
- `crates/lre-core/src/register_params.rs` commits exactly the registers the
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
- `crates/lre-core/src/native/gba.rs` loads a cartridge only on positive
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
- `crates/lre-core/src/native/nds.rs` reads the documented CPU descriptors
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
- `crates/lre-core/src/native/psx.rs` reads the documented PS-EXE fields
  (psx-spx "Executables": magic, initial PC at 0x10, destination at 0x18,
  size at 0x1C) and accepts an image only when the declared size is in the
  file, the destination is main RAM through one of the three MIPS segment
  windows, and the initial PC lands inside the image. Seven unit tests pin
  the refusals, including the uncached mirror being *accepted* at 0xa0000000.
- `crates/lre-core/src/native/n64.rs` reads the PI configuration word and the
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
  `VENTRIS_SLA` for the x86-64 workflow -- as this repo's own tests and docs
  do. `language_decompile_config` treated the pin as absolute, so an ARM or
  MIPS program was decompiled with the **x86-64** decoder, producing
  plausible-looking nonsense and a `DataUnavailError` at a garbage address
  (`0xffffffffe71f901b`).
- The pin now applies only to the language it pins; a program whose language
  differs resolves from the install instead. Verified by re-running all four
  platform gates plus `tests/differential.sh` and `tests/workflow.sh` with
  `VENTRIS_SLA` exported: all pass, and the x86-64 parity path is unchanged.

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
  instruction is itself a function entry (the thunk case). Ventris now
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
- `crates/lre-core/src/native/discovery/tests.rs` renamed and re-pointed:
  its landing-prefix fixture is exactly the x86-64 `endbr64; jmp target`
  shape the oracle records as a call, so its old expectation pinned
  non-parity behaviour.

### m5-007 evidence
- `0c38cb3` commits the failing acceptance
  (`tests/m5-007_tailcall_promotion.py`).
- Promotion is **off by default** (`VENTRIS_PROMOTE_TAILCALLS`): stock Ghidra
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
  `crates/lre-core/src/native/discovery/tests.rs`. Removing the evidence walk
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
  `target/debug/lre-cli` **without building it**, so they tested whatever
  binary happened to be there. All four now build the CLI they test.

### m5-008 evidence
- **The ARM7 tail call must not be a thunk.** Answered from the pinned
  sources before any code: `CreateThunkFunctionCmd.getThunkedAddr` walks from
  the entry, and `getFlowingAddrFromFinalState` (lines 763-828) returns a
  thunked address only when every register the body set is later used or
  hidden (`setRegisters.size() == 0`). `nds.arm7`'s stub computes and leaves
  its result in a register for the callee, so stock Ghidra records no thunk
  there -- and neither does Ventris. Pinned by
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
  `<funcstart label=...>` entry in `x86gcc_patterns.xml`. Ventris already
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
  (`VENTRIS_GHIDRA=/nonexistent VENTRIS_CONSOLE=/nonexistent`): 13 commands,
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
  documented exchange is sent to a real `lre-api` process and the documented
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
  `qEnvironmentVariableIsSet("VENTRIS_UI_INSTALL_OK")`, and
  `tests/package_install_smoke.sh` sets that variable itself -- the gate
  asserted a value its own harness supplied.
- Two additive metrics now measure what the old one claimed, both computed by
  the app: `ui.install.prefix_ok` (the executable is not running from a build
  tree: no `CMakeCache.txt`/`CMakeFiles` beside it or one level up) and
  `ui.install.store_only_ok` (the store-facing workflow completed with **no**
  `VENTRIS_*` variable set). A new `--gate --store-only` mode stops after
  import, list and filter, so a packaged run needs no SLEIGH data.
- The gate builds the CPack archive with the three commands
  `docs/desktop.md` documents, asserts the page documents those targets,
  extracts the archive into a clean prefix, refuses an archive member that
  escapes it, and launches the extracted binary offscreen with every
  `VENTRIS_*` variable stripped from the environment.
- Measured (`benchmarks/reports/m6-003.json`): `ventris-0.5-Linux-x86_64.tar.gz`
  on Linux/x86_64 with Qt 6.11.2, `ui.install.prefix_ok` true,
  `ui.install.store_only_ok` true, `ui.list.load_ms` 1.96 and
  `ui.list.filter_ms` inside the M0 thresholds. **The report names its own
  platform**, so single-machine evidence cannot read as three-OS evidence;
  the CI `qt` job runs it on Linux, macOS and Windows and uploads each report.
- Negative controls, run against the same binary: the build-tree executable
  reports `ui.install.prefix_ok: false`, and setting any `VENTRIS_*` variable
  reports `ui.install.store_only_ok: false`.

## Proposed changes (reserved for the human)
- Retire `ui.install.ok` from the M0 UI gate. It reports whether
  `VENTRIS_UI_INSTALL_OK` is set, not whether an installation works, and
  `ui.install.prefix_ok` plus `ui.install.store_only_ok` (m6-003) measure the
  fact instead. AGENTS.md II.1 reserves metric-definition changes, so the
  metric and `benchmarks/reports/ui-gate.json` are untouched;
  `tests/package_install_smoke.sh` still passes because it still sets the
  variable. Removing it means deleting the metric from
  `benchmarks/ui_gate.py`'s `ALL_METRICS`, the `qEnvironmentVariableIsSet`
  read in `desktop/ventris-qt/src/gate_runner.cpp`, and the `VENTRIS_UI_INSTALL_OK`
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
  (`the SBOM omits workspace crates: ['lre-worker']`), and neutering
  `verify_update.py` fails (`a flipped byte in lre-api passed verification`).
- CI cutover: the three placeholder packaging steps are replaced by this
  gate, so the SBOM and manifest are now checked against real artifacts.
- The page states what is not claimed: no reproducibility (two builds are not
  asserted byte-identical) and no signing (digests, not signatures). Tagging
  stays reserved to the human per II.1.

### m6-005 evidence
- `0367538` commits the failing acceptance (`tests/m6-005_scripting.py`).
- `docs/scripting.md` shows `examples/facts_report.py` driving a project
  through `python/ventris_sdk.py`: import, read the functions, write a rename,
  undo it. The gate runs the documented command **in two environments** --
  with the SLEIGH console and with every `VENTRIS_*` variable stripped --
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
  and are **not** timed -- `lre-cli import` for the native path, an
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
- One long-lived `lre-api` process per locked entry answers the same seven
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
- `crates/lre-core/src/native/pe_unwind.rs` reads
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
  buildable. That would score PE the way `m3-001` scores ELF, across
  optimisation levels and C++, instead of on two committed fixtures. It also
  requires `expected_variants` to stop being one cross product for every
  architecture. **Not done: waiting on your decision.**

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
- `crates/lre-core/src/native/pe_roots.rs` reads two directories, both
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
  `native-import:pe-*` provenance strings in `crates/lre-core/src`), then
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
  against -- `lre-cli provenance` did not exist, and the desktop's xrefs dock
  had **no provenance column at all**, so a user could not learn what a base
  relocation proves.
- `crates/lre-model/src/provenance.rs` holds one table: 15 classes, each a
  sentence. `FactProvenance` now serialises `explanation` from it via a
  hand-written `Serialize`, so every API and CLI consumer receives the
  sentence with the fact and no construction site has to remember it.
- Surfaces read that table rather than copying it: `lre-cli provenance
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
  real `lre-api`, and the desktop rendered 19 xref rows with **0**
  unexplained.
- Controls: deleting one class's sentence fails, a UI report claiming three
  unexplained rows fails, and a UI report that stops measuring the metric at
  all fails.
- `crates/lre-db` had a test pinning the exact provenance JSON; it now pins
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
  `provenance.evidence` through the API, `lre-cli provenance`, and the
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
  only derivation in the tree is `lre-sig`'s share of compared bytes. A
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
  `inferred`) through `lre-api`, `lre-core`, `lre-db` and the Qt bridge. The
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
- `lre-cli xrefs --evidence declared|decoded|inferred` routes through
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

## Next task
- m9-005: close M9 the way `m8-006` closed M8 -- publish fact explanation as
  one milestone whose claim is derived, not written. Four gates now exist
  (`m9-001`..`m9-004`) and each writes its own report; nothing states the
  milestone-level claim or fails when a surface that shows a fact does not
  show what proved it. The acceptance must enumerate the fact-bearing surfaces
  from the repository (the API methods that return a `provenance` object, the
  CLI verbs that print one, the desktop docks that render one), require each to
  be measured by a committed report, and fail when a surface has no gate
  behind it. Its acceptance test does not exist yet; write it first.

- Recorded deficit, now half closed: a tail-called leaf function is
  invisible to flow analysis in both Ventris and stock Ghidra. **The
  transfer is recorded as of m5-006** (`037f802c -> 037f8000`,
  `UNCONDITIONAL_JUMP`); the function is still not created, and neither
  does stock Ghidra create it. Promoting it is m5-007 and needs evidence,
  not a rule that happens to fit one fixture.

## Console sequencing decision (agent judgement, 2026-09-07)
The ten platforms recorded in "Reserved decisions" split by what can be
*proved* with the machinery that exists, not by appeal:
- **Tier 1, now** -- language present in the pinned install, container
  documented, and a DWARF twin buildable from source, so an M3-style gate row
  is possible on day one: GBA (`ARM:LE:32:v4t`, raw ROM), NDS
  (`ARM:LE:32:v5t` + `v4t`, two CPU images per container), PS1
  (`MIPS:LE:32:default`, PS-EXE), N64 (`MIPS:BE:64:64-32addr`, Z64/V64/N64).
- **Tier 2, prerequisite-gated** -- named blockers, each recorded rather than
  worked around: PSP (`MIPS:LE:32:default` decodes, VFPU unmodelled); PS2
  (no R5900 model in the pinned install, so MMI and VU0 macro ops do not
  decode); PS3 (no Cell SPU processor at all); Xbox 360 (VMX128 unmodelled);
  Vita and 3DS (encrypted containers accepted only already decrypted, and no
  keys are ever bundled -- II.1 forbids the runtime network call that would
  fetch them).
- Rule for every platform: it is "supported" only with a loader, a language
  mapping proven by decoding, and a gate row scoring it. No platform is
  claimed from a successful import alone.
- Corpus membership stays reserved (II.1): each platform's gate input needs
  human approval before it becomes a corpus member.

## Reserved decisions
- m1-010 gate amendment: architecture-specific code is permitted only in a
  clearly separated accelerator module with an equivalence test, never in the
  discovery core. (Recorded per user direction; do not re-argue.)
- Console platform targets (recorded per user direction, 2026-09-06; not
  scheduled yet): PS1, PS2, N64, Game Boy Advance, NDS, 3DS, PS3, Xbox 360,
  PSP, PS Vita. What the pinned Ghidra 12.1.3 install already supplies, from
  `lre-cli architectures`:
  - PS1 R3000A -> `MIPS:LE:32:default`; N64 VR4300 -> `MIPS:BE:64:64-32addr`;
    PSP Allegrex -> `MIPS:LE:32:default` (VFPU unmodelled); GBA ARM7TDMI ->
    `ARM:LE:32:v4t`; NDS ARM946E-S/ARM7TDMI -> `ARM:LE:32:v5t` + `v4t`;
    3DS ARM11/Cortex-A9 -> `ARM:LE:32:v6` + `v7`; Vita Cortex-A9 ->
    `ARM:LE:32:v7`; PS3 PPE and Xbox 360 Xenon -> `PowerPC:BE:64:default`.
  - Missing from the pinned install: no R5900 language id (the `r5900l/r5900r`
    strings in `mips.ldefs` are IDA aliases on generic MIPS, so PS2 MMI and
    VU0 macro ops are unmodelled), no Cell SPU processor at all, and no
    VMX128 for Xenon. These need SLEIGH data we do not yet have.
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
