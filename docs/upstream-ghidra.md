# Upstream Ghidra: verified interfaces

Pinned upstream: **Ghidra 12.1.3 PUBLIC** (installed at
`~/ghidra_12.1.3_PUBLIC`; also vendored under `third_party/ghidra/` with
hashes). JDK 25 is the runtime the shipped jars are built for.

Everything below was verified against the extracted sources in
`.ghidra-java/` (from the install's `*-src.zip` files) or against the jars
directly — not from memory or docs.

## Program lifecycle (the three traps)

1. **Application initialization is mandatory.** Any `GhidraProject` call
   before `Application.initializeApplication(new GhidraApplicationLayout(),
   cfg)` dies in `ToolChestImpl.<init>` →
   `Application.checkAppInitialized` (`AssertException`).
   `HeadlessGhidraApplicationConfiguration#setInitializeLogging(false)`
   keeps Ghidra's logging off our stdout.
2. **Persisting an import: use `ProgramLoader` + `Loaded.save`, NOT
   `GhidraProject.save`.** The deprecated `GhidraProject.importProgram`
   hands back a Program whose `DomainFile` is a proxy;
   `GhidraProject.save` then throws `ReadOnlyException: Location does not
   exist for a save operation!` (`DomainFileProxy.save`). Correct flow
   (as HeadlessAnalyzer does):
   `ProgramLoader.builder().source(f).project(p).load()` →
   `loadResults.getPrimary()` → `primary.save(monitor)` →
   `DomainFile` in `idata/` (`~index.dat` gains the entry).
3. **Analysis needs an open DB transaction.** Without
   `program.startTransaction(...)` around the analyze call,
   `AutoAnalysisManager.startAnalysis` → `StoredAnalyzerTimes.set...`
   throws `NoTransactionException` when it writes timing options.

Also verified:
- `GhidraProject.createProject` DELETES any existing project of the same
  name (`deletePreviousProject`); `openProject` requires `.gpr` to exist.
  Our bootstrap: open when `NAME.gpr` exists, create otherwise.
- `GhidraProject.openProgram(folderPath, name, readOnly)` composes
  `folderPath + "/" + name`; folderPath `"/"` yields `//name` (not found)
  and `null` stringifies to `"null"`. Use `""` for the root folder.
- Exception FQNs: `ghidra.util.exception.DuplicateNameException`,
  `ghidra.util.exception.InvalidInputException`,
  `ghidra.util.InvalidNameException`,
  `ghidra.util.exception.NotFoundException`,
  `ghidra.util.NotOwnerException` (FileSystem.jar),
  `ghidra.framework.store.LockException`.

## Query surface used by the bridge

- `Program`: `getFunctionManager().getFunctions(true)`,
  `getListing().getInstructions(addr, true)`, `getMemory().getBytes`,
  `getReferenceManager().getReferencesTo/From`, `getSymbolTable()
  .getAllSymbols(true)`, `getAddressFactory().getAddress(String)`,
  `getLanguageID().getIdAsString()`.
- `Function` (interface, `ghidra.program.model.listing`):
  `getName()`, `getEntryPoint()`, `getBody()` (→ `getNumAddresses()`,
  `getAddresses(true)`), `getSignature().getPrototypeString(true)`,
  `getCallingConventionName()`. `setName(name, SourceType)` throws
  `DuplicateNameException` + `InvalidInputException` and returns void.
- Outgoing xrefs of a function body: iterate `getBody().getAddresses(true)`
  and call `getReferencesFrom(addr)` per address. A single query at the
  entry misses mid-body call sites (e.g. main's call at 00400488).
- Instruction text: `Instruction.toString()` (mnemonic + operands);
  `getMnemonicString()` is on `CodeUnit`.
- `DecompInterface.openProgram(program)` →
  `decompileFunction(f, timeoutSecs, monitor)` →
  `getDecompiledFunction().getC()`; `dispose()` after use.

## JVM flags

Required `--add-opens` for JDK 25:
`java.base/java.lang`, `java.lang.invoke`, `java.lang.ref`, `java.util`,
`java.io`, `java.desktop/java.awt`. Note: `--add-opens java.base/java
.desktop/java.awt` is invalid; the module is `java.desktop`.

## Native decompiler (Stage 3 path)

`third_party/ghidra/decompiler/` is the verbatim
`Ghidra/Features/Decompiler/src/decompile/cpp` tree — the C++ that already
runs as `decompile_exe` inside every Ghidra session. The old project's
`tools/` (in git history) built it unmodified; the old Rust bridge spoke
its XML protocol. That is the feasibility-spike starting point for
Stage 3/4, which is why the tree is kept pinned.

### Romwright native compatibility extensions

`native/build_ghidra_opt.sh` applies `native/ghidra-opt-sleigh.patch` to a
temporary copy; the vendored tree remains unchanged.

- Dynamic variable hashes support collision groups of up to **128** entries.
  Groups of eight or fewer retain the exact upstream encoding. Larger groups
  use previously unused bits 55–62 for the additional position/total bits.
  **Stock Ghidra cannot decode those extended hashes correctly.** They are
  Romwright-native identities, not an interchange format for an unmodified
  Ghidra decompiler. Groups beyond 128 still fail rather than guess an identity.
  The build runs `native/dynamic_hash_test.cc`, checking legacy packing,
  extended round trips and invalid bounds before installing the executable.
- Final native structuring may negate a condition and reorder its outgoing
  edges. The structured-document envelope explicitly acknowledges each cut's
  original and projected edge slot using its stable incoming reverse edge.
  The worker validates the acknowledgement and projected control-flow cut;
  it does not weaken the IR's slot/target validation.
- Upstream GP-7003 ("Use non-zero mask in jump-table recovery", Ghidra commit `64606271a`, Apache-2.0, after 12.1.3) is
  backported in the patch (`jumptable`, `rangeutil`, `coreaction`, `ruleaction`) with two corrections of ours; the
  unmodified upstream change loses jump tables, see "GP-7003 follow-up" below.

The September 2026 acceptance run recovered the two previously failing `ls`
functions at `0x101540` and `0x1140b0`. This is targeted regression evidence,
not a claim that every native decompilation succeeds.

## Master trial (2026-10-12): does upstream master beat the pin?

Question: would re-pinning to upstream master (918d44e, 2026-10-08, reports 12.3; no 12.2 tag exists) make
console output better, and which upstream changes should the Rust port use as its reference. Method: two
`ghidra_opt` builds behind one `romwright-cli`/`worker` (12.1.3 + `native/ghidra-opt-sleigh.patch`, and master +
the same patch rebased), the same `.sla` files (format version 4 on both sides; upstream changed no language of
ours), the same projects, `benchmarks/ghidra_master_trial.py` for the paired export, classification, attribution
and report. Full tables, the rebase conflict list, attribution and the per-stage port reference are in
`benchmarks/reports/ghidra_master_trial.{json,md}`; the rebased patch and the cherry-pick are in
`benchmarks/reports/ghidra_master_trial/`.

**Result.** Do not re-pin now; GP-7003 with the two corrections of the follow-up below is now in `native/ghidra-opt-sleigh.patch`; re-run on the 12.2 release.

- GP-7310 (`Varnode::setDef` throws on any definition of a constant) fails 262 of 390 sampled N64 functions and 80
  of 200 sampled Xbox 360 functions (loads from constant addresses; the worker runs `readonly on`). Restored by
  moving the check back to `VarnodeBank::setDef`. PS2 (8 games), GameCube, GBA and NDS: decompile success, recall
  and precision identical; stored switch tables identical except one God Hand table (stored tables only; the
  decompiler-only comparison in the follow-up finds 20 more lost tables).
- Elsewhere the text moves both ways: 80.4% of 2,043 paired functions print identically, 64 better / 33 worse /
  164 neutral outside N64 by the printed-text measure; gotos in the unaffected wave samples 515 -> 492. m22-002:
  MWCC +1 exact per seed, **ee-gcc −7 exact** (GP-7115's arm order; one branch of `ruleBlockIfNoExit` explains 9 of
  14 moved functions).
- GP-7003 (non-zero mask in jump-table recovery) is the one decompiler gain: Fatal Frame `FActExecOccur` 72 ->
  507 lines, three jump tables instead of one. **It is not safe as upstream wrote it**, and master carries the
  same two flaws (follow-up below): applied to 12.1.3 it loses 20 jump tables in seven games, and master loses
  the same 20. The fixed cherry-pick is in `native/ghidra-opt-sleigh.patch` and kept standalone as `benchmarks/reports/ghidra_master_trial/gp7003-12.1.3.cpfix.patch`.
  God Hand `cIDManager_getLocalFileName` and `func_0039A140` are not helped.

**What a re-pin must handle.** Two wire changes the unchanged worker cannot read (packed `ATTRIB_METATYPE` is an
integer, GP-7253; warnings are a new burst `0x12`, GP-6985): the trial restores both in C++
(`marshal.cc`, `ghidra_arch/ghidra_process`) rather than touching `wire.rs`/`provider.rs`. Three textual patch
conflicts (`context.hh`, `fspec.cc`, `ghidra_process.cc`), four compile breaks (`SymbolEntry::getAddr`, `BlockIf`
split, `Funcdata::encode`), and the printer export needs `wireKind()` plus an `ifnoexit` list (upstream prints no
`else` there). `max_baddata` now defaults to 4 (GP-6945; unmeasured on these samples). The patch RustStructure is
editing already conflicts with master in `blockaction.cc`.

Re-running: build both `ghidra_opt`s, `benchmarks/console_research.py --corpus-wave` per arm for the wave,
`benchmarks/ghidra_master_trial.py sample|export|classify|attribute|switchdiff|report` for the rest.

### GP-7003 follow-up: why God Hand 0x274828 drops to 5 targets, and the fix

The six targets 12.1.3 recovers at God Hand 0x274828 are right: the retail guard is `sltiu a0,6`, the table at
0x4475c0 has six words, and the decomp repo source is `switch (irand() % 5)` with cases 0 to 5 (case 5 is dead
at run time but in the binary). GP-7003 reads the `% 5` as the range [0,5), tighter than the guard. The first
correction applies the `INT_REM`/`INT_SREM` bound only when no guard bounds the switch variable; the upstream
datatest `switchmask.xml` (an unguarded `x % 10` switch) still passes with it, and fails when the bound is
dropped altogether.

Widening found a second flaw: starting every range from the non-zero mask gives a shifted byte the range
[0,0xff000020) with step 32 (stride capped at 32), the guard reaches it with step 2^24, and `CircleRange::
intersect`/`newStride` wraps the right edge to 0 and reports an empty range, which `findSmallestNormal` picks as
the smallest and the table is lost. The second correction keeps the estimate when a guard would empty the range.
Measured with the stored tables removed over 12 games (3,087 functions): the first cherry-pick and master lose 20
tables (master 102 more on N64 through GP-7310) and the fixed cherry-pick loses none, gains 4 (Fatal Frame 3, God
Hand 1) and changes no other table; 83 of 84 upstream datatests print identical text in every build; m21 (7
images) and m22-002 (MWCC x2, ee-gcc) are identical, because their samples contain none of the changed switches.
Numbers: `benchmarks/reports/ghidra_master_trial/gp7003_cherrypick.{json,md}` (`benchmarks/gp7003_cherrypick.py`).

Applied 2026-10-12: `native/ghidra-opt-sleigh.patch` carries the six files (`coreaction.cc/hh`, `jumptable.cc/hh`,
`rangeutil.cc`, `ruleaction.cc`); `ghidra_opt` sha256 `4561fbea361d602cec0576f2c28a18da19dc5155cb9973d1a5b4e762c87ca598`,
one build for the combined gate (`benchmarks/combined_gate.py`, `benchmarks/reports/combined_gate_20261012.{json,md}`). The
ownership metric counts the patch's added lines as ours (+187 code lines, 662 -> 849), including the upstream ones.
