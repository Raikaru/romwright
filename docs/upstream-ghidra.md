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

The September 2026 acceptance run recovered the two previously failing `ls`
functions at `0x101540` and `0x1140b0`. This is targeted regression evidence,
not a claim that every native decompilation succeeds.
