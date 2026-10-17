# Ownership: how much of the decompiled output is Rust, how much is vendored Ghidra C++

STATUS.md ("Reserved decisions") makes this the entry criterion for replacing
the vendored decompiler: **we own more of the decompiled output than the
vendored tree does**. This document defines the measurement. The numbers come
from `benchmarks/ownership.py`, which writes `benchmarks/reports/ownership.json`
and `.md`; nothing in them is entered by hand. The results section below
quotes that report and names its generation time.

## What is measured

There is no single honest percentage. A decompiled function is the product of
a dozen stages, and each stage's unit differs (bytes, dispatches, operations,
tokens), so a mean of per-stage shares would be an invented weighting. The
metric is therefore a table, one row per stage, with the owner shares of that
stage's own unit, plus three whole-output lenses:

1. **Printed tokens** (the stream `export-c` and the desktop show): which
   implementation emitted each visible text token.
2. **Counterfactual** (what the Rust components change): how many functions
   print differently with the Rust structuring models and the Rust IR passes
   switched off.
3. **Executed code**: which lines of which implementation actually ran for the
   run's imports and decompiles.

Owner classes, used everywhere in the report:

| owner | meaning |
|---|---|
| `rust_first_party` | this repository's crates (`crates/*/src`), tests excluded |
| `rust_third_party` | `kuna-sleigh`, kuna-base, kuna-num: a Rust port of Ghidra's `Sleigh` translator (`third_party/kuna-sleigh`, patched copy; `crates/romwright-core/src/native_runtime/lift.rs`). Rust, but not ours, and it re-implements Ghidra's algorithm; reported separately so neither side is flattered |
| `cpp_ours` | our C++: lines `native/ghidra-opt-sleigh.patch` adds and `native/romwright_*.hh` |
| `cpp_vendored` | the pinned tree, `third_party/ghidra/decompiler`, as built (patch applied) minus the lines we added |

"Rust owns X" means the Rust code made the decision that is stored or printed,
not that Rust code ran nearby. A Rust process that forwards what the C++
computed does not count.

## Instrumentation

Everything below is read from the code or from a run; nothing changes the
printed text.

- **`ROMWRIGHT_OWNERSHIP_LOG=<file>`** (worker; `crates/romwright-worker/src/worker.rs`
  `NativeWorker::log_ownership`, called from `finalize_document`). One JSON
  line per decompiled function, taken from the document that is actually
  published (a rejected cut render is not logged):
  - `print.tokens`: visible text tokens handed to the pretty printer, split into
    `fragments` (replayed from the Emit calls PrintC's own handlers recorded,
    `native/romwright_printir.hh` `RomwrightCaptureEmit`) and `block_layer`
    (emitted by `printc/printer.rs`: keywords, braces, `goto`, labels, case
    syntax). `fragments_by_kind` and `fragments_by_region` break the former down.
    Spacing tokens are counted apart.
  - `print.constructs`: a census of the block tree's control-flow constructs
    (`if`, loops, `switch`, goto blocks, conditions, leaves; each keyed by kind,
    block index and exit) before and after the structuring models. "Before" is
    Ghidra's tree after `ActionFinalStructure`. A printed construct that is also
    in Ghidra's census (multiset) is Ghidra's; the rest were created by a Rust
    model. `gotos`/`labels` before and after, and the models that fired.
    (`crates/romwright-worker/src/printc/ownership.rs`, `mod.rs`
    `render_with_stats`.)
  - `edits`, `cuts`, `passes`: what the Rust semantic passes proposed and what
    survived (`additive_inverse` edits have an empty `helper`), against the
    operation count of the final SSA.
  - `stored_prototype`, `printed_prototype`, `calls_with_stored_prototype`:
    which prototype the store gave the decompiler (its provenance source), and
    how many call sites name a callee with a stored one.
  - `jump_tables`: the tables printed. `switch_sources`: for each, how the import's
    stored table related to what `jumptable.cc` recovers for the branch (`none`,
    `confirmed`, `applied`, `observed`; see "Stored switch tables fed to the
    decompiler").
- **Import facts** from the project database: functions by `producer`, facts by
  `provenance` (xrefs, data definitions, flow overrides), memory and symbols,
  and `import --timings` phase times.
- **Switch attribution**: a second import with `ROMWRIGHT_NO_SWITCH_DECOMPILER=1`
  (value-set analysis only). A stored dispatch the VSA-only import also has was
  recovered by Rust; every other stored dispatch was recovered by the
  decompiler path. Imports are deterministic.
- **Counterfactual passes** over the same sample: `ROMWRIGHT_RUST_STRUCTURING=none`,
  `ROMWRIGHT_IR_PASSES=""` with `--transforms ""`, and (since 2026-10-10)
  `ROMWRIGHT_RUST_EXPRESSIONS=off`, which prints PrintC's fragments instead of
  the Rust expression printer (a pass whose expected result is 0 differing
  functions). The report's "either" is the union of the first two.
  `ROMWRIGHT_GTE_MACROS=0` switches off the PSX GTE macro pass (printc/gte.rs;
  its statements print as `Source::Rust`, and `PrintStats.gte` counts the calls).
  The held PSX image has no GTE command and no GTE load or store the pass
  matches, so it changes none of the 2,206 functions there (STATUS.md,
  "PSX GTE macro lifter") and the figures in this document do not move.
- **Coverage.** `ghidra_opt` is built with clang
  source-based coverage (`benchmarks/ownership_build_coverage.sh`, same
  sources, patch and flags as the product builds apart from the compiler);
  `romwright-cli`, `romwright-worker` and `romwright-api` with
  `-C instrument-coverage`. Both use continuous mode (`%c`), because the worker
  kills `ghidra_opt` with SIGKILL (`exec::kill_child`) and a
  normal-exit profile would be lost. Profiles merge with `llvm-profdata`;
  `llvm-cov export -format=lcov` gives per-line counts. A C++ line is
  `cpp_ours` when it is in `romwright_*.hh` or is a line the patch adds
  (parsed from the patch's hunks), `cpp_vendored` otherwise. A Rust file is
  first-party when it is under `crates/`, third-party when it is kuna.
  Stage membership is by file (`RUST_RULES` and `CPP_RULES` in the script);
  the report lists any executed first-party file no rule claims.

The import and the first decompile pass are profiled; the ablation passes and
the switch-off import are not merged into coverage, so the executed-line
numbers describe the default pipeline.

## The two sample profiles

- **default**: a fresh default import per image, then `export-c --address` for
  the 200 functions `benchmarks/console_research.py`'s rule draws from it
  (same stratified sampler, seed 20261006, DWARF-covered functions first on
  gba, nds and ps2-dungeon). `infer_prototypes` has not run, which is what the
  product does until a user asks for it.
- **persisted prototypes**: the same worker over the project an earlier research
  run left after `infer_prototypes` with the inferred-types merge on, copied and
  never mutated, decompiling the sample that run used. The job costs 10 s (psx)
  to 5,202 s (Vita), so it is read, not rerun; the report names each project
  and the tree that built it. Only projects whose job finished its rounds are
  used.

## Stage attribution

Each stage names where the decision is made and how the report attributes it.
The shares are in `ownership.md` (the report), not here, so that they cannot
drift from the code.

| stage | decision made by | unit and attribution |
|---|---|---|
| **load** | Rust loaders (`crates/romwright-core/src/native/*.rs`: ELF, PE/XEX, DOL, GBA, NDS, PS2/PSX/PSP/PS3/Vita/3DS containers, RELs, decryption; GameCube/Wii RVZ, WIA, WBFS and Wii partition decryption go through the `nod` crate, which only supplies the decoded byte stream of the data partition: the boot header, FST, DOL and REL choices are made by `native/disc.rs`, and `nod` is an external crate outside every owner class above) | Every byte, symbol, type and flow fact the decompiler reads is answered by the Rust `ProgramProvider` (`crates/romwright-worker/src/provider.rs`; `answer_getbytes`, `from_store`). No Ghidra loader decides anything: imports hand the decompiler Rust-mapped chunks (and the in-process SLEIGH lifter reads the same chunks), and `loadimage_bfd.cc` is not linked into `ghidra_opt` at all. The C++ side stores what it is handed. Share: 100% Rust by construction; coverage reports the C++ loader lines that run |
| **discovery** | Rust (`native/discovery.rs`, `src/native.rs` `discover`, `native/references.rs`) deciding from SLEIGH flow facts; the function-start pattern search, the linkage (thunk) evidence and the data and code references are in-process Rust too (`native_runtime/patterns.rs`, `native_runtime/linkage.rs`, `native_runtime/propagation.rs` with `propagation/{state,lang,graph}.rs` and `reference_pass.rs`, over kuna-sleigh; the console's `functionstarts`, `linkage`, `constants`, `references` and `referencefixup` commands and their headers are gone) | Unit: stored analysis facts by `provenance`. Every provenance is a Rust decision; `native-analysis:constant-propagation` and `native-analysis:data-width` (`native/references.rs` `infer_data_references`, `store.rs` `DATA_WIDTH_SOURCE`) were the console's until 2026-10-09. Reported beside it: sampled functions by `producer` and the share of import wall time in console-owned phases (`PHASE_OWNER`) |
| **flow** | two implementations. *Import walk*: in-process `kuna-sleigh` (`native_runtime/flow.rs` `SleighFlow`), driven by `native/discovery.rs`; the reference propagation follows flow over the same decoder (`native_runtime/propagation/graph.rs`, a port of `FlowInfo`). *Decompile*: the decompiler's own `FlowInfo` (`cpp/flow.cc`) builds each function's p-code and block graph | No C++ answers flow during import: the SLEIGH console, whose `flow` command (`native/romwright_flow.hh`) the walk once asked and the reference propagation used until 2026-10-09 (the report then counted 96 of 120 of that header's lines executed), was retired on 2026-10-09 (STATUS.md, ConsoleRetire). Rows: import walk 100% third-party Rust by code; decompile 100% vendored |
| **p-code lift** | two implementations. Decompile: the decompiler's own SLEIGH in `ghidra_opt`, selected by `ROMWRIGHT_SLA` (`native_runtime.rs` `worker_command`; the patch's raw-SLEIGH hook reads `getenv("ROMWRIGHT_SLA")`). Analysis: `kuna-sleigh` (`native_runtime/lift.rs`) feeding VSA (`native/vsa.rs`), SJA (`native/sja.rs`), the type solver (`types_infer.rs`) and the prototype job | The printed text is built from the C++ lift. Unit: instructions in the sampled functions, all lifted by vendored C++ on the printed path. The Rust lift never reaches printed text; coverage shows both |
| **switch recovery** | two outputs. *Stored* import tables: Rust VSA (`native/vsa.rs`, `switch_tables.rs` `recover_switch_tables_native`) first, the decompiler (`recover_switch_tables` -> `native_runtime.rs` `recover_native_switches`, the worker's `--switches` mode, vendored `jumptable.cc`) for what VSA refuses. *Printed* tables: the stored table is the authority for the branch's addresses since 2026-10-09 (`ProgramProvider::from_store` reads the `COMPUTED_JUMP` edges, the worker sends them in the function-shell document, `JumpTable::recoverStored` compares them with `jumptable.cc`'s own recovery and installs them where it differs); `jumptable.cc` still derives the normalization, guards and case values | The stored share is measured with the VSA-only import. The printed share is split by the log's `switch_sources`: printed tables whose stored table was recovered by Rust VSA (the branch is in the VSA-only import) are Rust's, the other printed tables came from the import's own decompiler pass or have none. Before 2026-10-09 the stored tables were not given to the decompiler and every printed table was 100% vendored. The report also counts how many Rust-recovered dispatches in the sample printed as a `switch` |
| **simplification** | Ghidra's action pipeline (`coreaction.cc`, `ruleaction.cc`, `heritage.cc`, `subflow.cc`, ...) up to high variables; Rust edits two kinds of operation through `renderFunctionIR` (`crates/romwright-core/src/func_ir.rs`: `AdditiveInverse`, `CanonicalHelpers`) | Unit: final p-code operations. Rust share: operations a Rust transform edited, over all operations in the final SSA |
| **type inference** | Ghidra's `ActionInferTypes` and `typeop.cc`/`type.cc` (the types; since 2026-10-13 not the casts, next row). The Rust solver (`types_infer.rs`, `subtype.rs`) runs in two places: as an evidence pass on every decompile (`func_ir.rs`; its classes only steer export-c's `temp_f`/`temp_v` naming and global declarations, `emit_m2c.rs`), and in the `infer_prototypes` job, where it can upgrade a stored parameter type (`types_infer/prototypes.rs`) | Unit: printed type tokens. Rust share: parameter types the merge upgraded (the `->` records in the stored prototype's provenance), an upper bound of one printed token per slot. Default profile: none, because no prototype is stored |
| **casts** | Since 2026-10-13 (IR version 6) the worker's `printc/casts.rs`, a port of `CastStrategyC`, the cast methods of `typeop.cc` and `ActionSetCasts`, decides every cast over the exported pre-cast typed print trees (docs/types-port.md); `ActionSetCasts` runs only for the functions the worker declines (union or `needsResolution` types, address-space pointers, `PTRADD` undo, a few const retypes) and on the stock-structure path | Unit: `CAST` operators (printed cast tokens). Rust share: operators in functions the worker cast (`ROMWRIGHT_OWNERSHIP_LOG`, `print.expressions.cast_functions`, `native_cast_ops`; `benchmarks/types_port_measure.py`) |
| **prototype** | Ghidra's `fspec.cc`/`modelrules.cc` recovers every prototype unless the store supplies one: a user assertion, a library or SDK table (`library_types.rs`, `sdk_types/`), or a persisted `infer_prototypes` row, applied by `worker.rs` `apply_stored_prototype`. The job persists the *decompiler's* recovered signature; Rust only persists it (and may upgrade slots, above) | Unit: printed function prototypes. Default profile: Rust share = functions with a stored prototype (none), plus call sites whose callee has one. Persisted profile: a row whose provenance is `native-decompiler prototype recovery` alone is Ghidra's decision stored by Rust; Rust decided the rows that also carry `inferred-types` (at least one slot changed). The report prints the source mix and how many were persisted |
| **structuring** | Since 2026-10-11 the worker's `printc/collapse.rs` (a port of Ghidra's `CollapseStructure` and `BlockGraph`) builds the tree from the unstructured graph `ghidra_opt` exports; `printc/query.rs` answers the C++ pipeline what Ghidra's structurer would have done to the p-code (condition negations, return-block splits, `if`/`else` complements, `while` loops), which `native/romwright_structure.hh` applies (p-code edits that belong to the merge and simplification stages, plus the for-loop analysis, a port of `BlockWhileDo`'s); the Rust models (`printc/structure.rs`) and the IR `structure` pass's cuts (`structuring.rs`, kept only when they reduce gotos, `worker.rs` `finalize_document`) rewrite the tree. Before that date Ghidra's `ActionBlockStructure` (`blockaction.cc`, `block.cc`) built it | Unit: control-flow constructs in the printed tree. Rust share: constructs not in Ghidra's census; with the tree built in Rust there is no Ghidra census on the default path, so every printed construct is Rust's (`PrinterIr::native_tree`; the stock path, `ROMWRIGHT_NATIVE_STRUCTURE=1`, keeps the old accounting). Also gotos and labels before and after, and the models that fired. The code lens is the executed lines of `block.cc`/`blockaction.cc` (vendored) against `printc/collapse*`, `printc/query.rs`, `printc/structure*` and `native/romwright_structure.hh` (ours) |
| **printing** | Since 2026-10-09 statement expressions (operators, parentheses, casts, field and array notation, constants, symbol names and scoping) are printed by `printc/render.rs`, a Rust port of PrintC's expression emission over the exported print trees (docs/printer-ir.md); the data it reads from the data-type system and the symbol table (types, symbol names, cast decisions, one-token constants) is still exported by C++ (`native/romwright_printir.hh`). Declarations (prototype, locals), comments and labels are PrintC's (`printc.cc`), recorded as fragments; the block layer (statement placement, `goto`/`break`/`continue`, braces, `else`, loops, case syntax) is the Rust port in `printc/printer.rs`; line breaking and indentation are `printc/pretty.rs`, a Rust port of `EmitPrettyPrint` | Unit: visible text tokens. Rust share: `block_layer` plus `rust_expressions`; C++ share: `fragments`. Spacing tokens are reported apart: their algorithm is a port (third-party design, first-party code) |
| **postprocess** | Rust `emit_m2c` renames decompiler locals to `temp_*`/`sp*`, marks irregular flow, emits globals and the stack struct | Unit: identifier tokens in the `export-c` text. Rust share: `temp_*`/`sp<HEX>` names |

### Why the rollups are four lenses, not one number

The constructs a Rust model creates are a small number of tokens each; a
`switch` Ghidra builds is thousands of fragment tokens plus a handful of
block-layer ones. Tokens say how much of the *text* Rust emitted; constructs
say how much of the *control flow* Rust decided; the counterfactual says how
much of the *output* depends on Rust at all; executed lines say how much *code*
each side runs. None subsumes the others, so the report prints all four and
the criterion is read against each.

## Results

### 2026-10-14, variable merge, explicit/implied marks and default names handed to Rust (stage 3) (current)

`benchmarks/reports/merge_port_measure_stage3.json` (`benchmarks/merge_port_measure.py`),
`merge_diff_stage3_20261014.json` (`benchmarks/merge_diff.py`),
`wave_text_diff_stage3_20261014.json` (`benchmarks/wave_text_diff.py`) and
`merge_verify_stage3_20261014.json` (`benchmarks/merge_verify.py`), generated on
`nih-vps-u` with one release build (the 8 printer-differential images, 200 sampled
functions each, default build, `ghidra_opt` sha256
`486ace43c12ed3017508f527344dd06552b7ee62304c861566430ca18074ff94`, IR version 7).
Not a full `ownership.py` run (no coverage build): the units of this stage are the
decisions the worker's own log counts (`ROMWRIGHT_RUST_MERGE_LOG`), plus a static
line inventory. The method, wire and switches are in [merge-port.md](merge-port.md).

| lens | value |
|---|---|
| functions whose merge, marks and names the worker decided | **1,600 of 1,600 (100%)**; 0 declined (before the `VariablePiece`/`VariableGroup` port the rate was 5.4%: overlapping address-tied storage, proto-partials, partial struct types) |
| decisions the worker made on those functions | 109,767 high-variable merges (5,560 of them speculative: `ActionMergeAdjacent`, `ActionMergeType`), 123,545 explicit marks, 54,441 implied marks, 2,492 copy trims (new COPY ops), 310,769 log entries, 9,034 default names |
| the worker's time to decide | 0.56 s of 70.0 s decompile wall (0.8%); a 300-function God Hand comparison against `ROMWRIGHT_NATIVE_MERGE=1` is at parity |
| the same decompiles, default against `ROMWRIGHT_NATIVE_MERGE=1` | printed C identical on 1,600 of 1,600 (8 images); on 7,409 of 7,409 PS2 functions both arms decompile (7,500 sampled; the rest fail in the same pre-existing way in both arms) |
| verify mode (the decompiler's stock merge runs, the worker's partition, marks, inserted ops and non-printing ops are compared variable by variable) | 1,600 of 1,600 verified on the sample (0 mismatches); 7,619 of 7,619 on the 8 PS2 images' 7,500 addresses (0 mismatches, 0 declined) |

Static line inventory (`benchmarks/ownership.py --inventory-only`; code lines, the
Rust test module excluded):

| | lines |
|---|---|
| Rust `printc/merge/*` (new) | 5,302 (+179 test lines) |
| `native/romwright_merge.hh` (new C++: the mirror writer, the replay, the stock fallback, the names loop) | 392 |
| vendored C++ no longer run for a function the worker decides | `merge.cc` + `merge.hh` 1,286 (the whole `Merge` class, `HighIntersectTest`), `ActionMarkExplicit`, `ActionMarkImplied` and the default-name loop of `ActionNameVars` (those three actions are 515 code lines of `coreaction.cc`, of which `ActionNameVars` keeps its symbol linking), the for-loop op moves of `romwright_structure.hh` for decided functions |
| vendored C++ that still runs during the replay | `variable.cc` (`HighVariable::merge`, flags, covers) and `cover.cc`: the replay calls the same `HighVariable` methods in the same order, which is how the downstream state stays the stock one |

New attribution stage `variables` in `benchmarks/ownership.py`
(`printc/merge/*`, `romwright_merge*`, `merge*`, `cover*`, `variable*`). The
measurement of the previous stages is unchanged; the previous default is
`ROMWRIGHT_NATIVE_MERGE=1`.

### 2026-10-13, casts handed to Rust (stage 2a)

`benchmarks/reports/types_port_measure_stage2.json`, generated by
`benchmarks/types_port_measure.py` on `nih-vps-u` (the 8 printer-differential images,
200 sampled functions each, default build, `ghidra_opt` sha256
`ffdd5e57e104fc83...`, IR version 6). Not a full `ownership.py` run (no coverage
build): the unit of this stage is the printed `CAST` operator, counted from the
worker's own log (`ROMWRIGHT_OWNERSHIP_LOG`, `print.expressions`).

| lens | value |
|---|---|
| functions whose casts the worker decided | 1,585 of 1,600 (99.1%); 15 declined (union or `needsResolution` types, constants retyped to a string or code pointer or a float, address-of casts), for which `ActionSetCasts` runs |
| printed cast operators decided by the worker | **95.4%** (12,622 of 13,229; the other 607 sit in the declined functions) |
| `PTRSUB` insertions after an op | 0 (a decline) |
| `ActionInferTypes` (stage 2b, stays in C++) | 1.8-3.1 calls per function inside the mainloop, 0.1-2.5% of the decompile time |

`ActionSetCasts`, `CastStrategy` and the cast methods of `typeop.cc` no longer
run for a function the worker accepts; the previous default is
`ROMWRIGHT_NATIVE_CASTS=1`. The stage-1 table above (structuring) is unchanged.

### 2026-10-12, structuring handed to Rust (stage 1)

`benchmarks/reports/ownership_structuring.{json,md}`, generated by
`benchmarks/ownership.py` (started 2026-10-12T04:16:54+00:00, finished 05:05
UTC) on `nih-vps-u` (8 vCPUs shared with other jobs, load average 20-30, 3
export jobs, the build's default of 4 decoder lanes; no timing reported). Tools
fingerprint `ad8291070e1a047e`; working-tree snapshot of 2026-10-11/12 (346
files, digest `13aecb49a6d18986`, not a commit): after the structuring handoff
(IR version 5, `printc/collapse.rs`, `native/romwright_structure.hh`) and
concurrent PS2 work. Instrumented `romwright-cli`/`-worker`/`-api` and the
clang-coverage `ghidra_opt` of the same snapshot (`cpp_build_matches_tree:
true`); `ghidra_opt` of the gates sha256
`153960338f17ef9d2b281028b26b20518a7779dd15d69c4193b3fdabd545aa7c`.

8 images x 50 sampled functions, 400 printed (`-n 50`: the earlier runs'
200 per image would have taken more than the host could give; the two PSP images
could not be imported in this tree, `native/discovery.rs:1170` overflows, another
agent's work in progress, so they are absent). The sample is drawn from this
tree's own import. Samples differ in size and drawing from the 10-10 report, so
its percentages are context, not a baseline; the comparison that is exact is the
next one.

**Same decompiles, stock path against default** (`benchmarks/ownership_stock_coverage.py`:
the 400 sampled functions of the report decompiled with the same instrumented
binaries and projects once with `ROMWRIGHT_NATIVE_STRUCTURE=1` and once by
default; imports and ablation passes are not in either column, so the totals are
smaller than the report's; `ownership_stock_coverage.json`,
`ownership_default_coverage.json`). Executed lines:

| stage / owner | stock path | default (Rust structure) |
|---|---:|---:|
| structuring, vendored C++ (`block.cc`, `blockaction.cc`) | 3,481 | **1,227** |
| structuring, first-party Rust | 2,407 | 4,700 |
| structuring, our C++ (`native/romwright_structure.hh`) | 100 | 446 |
| printing, vendored C++ (`printc.cc`'s block layer and `docFunction`) | 2,947 | 1,739 |
| **all stages, vendored C++** | **49,422** | **45,995** (-3,427) |
| all stages, first-party Rust | 16,857 | 19,111 |
| all stages, our C++ | 1,668 | 1,933 |

What the vendored lines that still execute in the structuring stage are: not
the structurer. `llvm-cov export` over the merged profile of the report
(imports, the default decompile pass and the persisted-prototype pass):

| vendored function | executions |
|---|---:|
| `ActionBlockStructure::apply`, `ActionFinalStructure::apply`, `ActionPreferComplement::apply`, `ActionStructureTransform::apply`, `ActionReturnSplit::apply` | 0 |
| `CollapseStructure::collapseAll` and every rule, `LoopBody`, `TraceDAG` | 0 |
| `BlockGraph::selfIdentify`, `newBlockList` and the other `newBlock*`, `finalizePrinting`, `scopeBreak`, `markUnstructured`, `BlockWhileDo::finalTransform` | 0 |
| `BlockBasic::negateCondition` (applying the worker's answer) | 16,198 |
| `BlockBasic::flipInPlaceTest` / `flipInPlaceExecute` (`ActionPreferComplement`'s test on the worker's split points) | 11,184 / 28,045 |
| `BlockGraph::structureLoops`, `calcForwardDominator` (the basic-block graph's own loop and dominator labelling, run on every control-flow change) | 14,217 each |
| `ActionNodeJoin::apply`, `ConditionalJoin::match`, `ActionNormalizeBranches::apply` (node joining, and the jump-table pipeline's branch normalisation) | 10,479 / 23,708 / 1,724 |

Eleven of `blockaction.cc`'s 83 functions execute (the node-join and
normalise-branches ones), 72 of `block.cc`'s 202 (the basic-block graph
every stage uses). The remaining 1,227 vendored lines of the stage are that
graph's edge bookkeeping, loop labelling and dominators, which belong to the flow
and simplification stages, not to structuring.

| lens | value | note |
|---|---|---|
| printed text tokens emitted by Rust | 91.5% (110,206 of 120,431) | block layer 13.4%, expression printer 78.1% |
| printed control-flow constructs created by Rust | **100.0%** | there is no Ghidra census on the default path: every printed construct is the worker's (was 2.9%: only the models' rewrites) |
| final p-code operations edited by a Rust transform | 0.7% | |
| functions whose text changes with Rust structuring and IR passes off | 27.8% | not comparable with earlier reports: "off" now leaves the worker's own base tree, so it measures the models, not the structurer |
| structuring stage, executed vendored C++ lines | 1,255 of 4,641 (was 3,481 on the stock path) | the code lens above |

The structuring lens therefore reads 100% Rust by decision (every printed
construct) and by code (no line of the vendored structurer executes); the
residue is shared basic-block-graph code. What C++ still decides *because of*
structuring is the p-code consequences of the worker's answers (negations, return
splits, `if`/`else` complements, for-loop op moves), whose application belongs
to the stages above (STATUS.md, "Decompiler port: stage roadmap").

### 2026-10-10, the corpus-wave tree

`benchmarks/reports/ownership_corpuswave.{json,md}`, generated by
`benchmarks/ownership.py` at 2026-10-10T17:04:38+00:00 (13:04 local), tools
fingerprint `901c320a13fdf110`, on the local machine (12 threads, load average
3.5-12.7 from other users, 2 export jobs per process, up to 3 processes, the
build's default of 4 decoder lanes; no timing is reported). The tree is a
working-tree snapshot of 2026-10-10, about 11:30 local time, (322 files, digest
`04ff03f0b32b7537`, not a commit): after ConsoleRetire, ConstPropRust,
PatternsLinkageRust, ExprPrinter, BranchindRust, SwitchDeterminism (work budget
`native/romwright_budget.hh`), ProgramOverhead (pooled decoders,
`native/programs.rs`), WiiDiscovery and the new loaders (`n64_discovery`,
`gba/overlays`, `archive`, `cue`/`iso9660`, `nod` disc import). Instrumented
`romwright-cli`/`-worker`/`-api` (rustc `-C instrument-coverage`, release,
`-j 2`) and the clang-coverage `ghidra_opt` (the patch and headers of the same
snapshot; the report checks the equality, `cpp_build_matches_tree: true`).
There is no SLEIGH console any more, so there is one C++ binary to cover.
The persisted-prototype profile reads the `infer_prototypes` projects of
FinalGate's run (tools `ea27c70333bb669d`, one per image, copied read-only
from the host's cache, `proto-4f53cda18c2b`), decompiled by the instrumented
worker of this tree.

10 images x 200 sampled functions (the 8 research images and both Puzzle Bobble
PSP variants), 2,000 printed. The sample is drawn from each tree's own import,
so it is not the same 2,000 functions as in the earlier reports: 1,275 of the
2,000 addresses coincide with `ownership_expressions` (psx 200, x360 200,
psp-symtab 200, psp 170, dungeon 151, capcom 148, nds 120, psv 66, gba 11, gc
9; the last two moved with the GBA overlay placement and the GameCube
discovery changes). Read differences of a point or two as noise from the
sample, not as an effect.

Before -> after, from the reports' own numbers (`benchmarks/ownership.py
--compare ownership.json ownership_final.json ownership_expressions.json
ownership_corpuswave.json`; `ownership` is the first, 10-08 coverage run on 8
images, `ownership_final` and `ownership_expressions` the 10-09 runs without
coverage on 10):

| lens | ownership (10-08) | ownership_final (10-09) | ownership_expressions (10-09) | **ownership_corpuswave (10-10)** |
|---|---|---|---|---|
| printed text tokens emitted by Rust | 13.3% | 14.5% | 90.7% | **90.9%** (567,094 of 624,050) |
| of which the block layer | n/a | n/a | 14.4% | 14.2% (88,650) |
| of which the expression printer | n/a | n/a | 76.3% | 76.7% (478,444) |
| replayed from PrintC's fragments (C++) | 86.7% | 85.5% | 9.3% | **9.1%** (56,956) |
| printed control-flow constructs created by the Rust models | 2.0% | 3.2% | 3.1% | **2.9%** (882 of 30,894) |
| final p-code operations edited by a Rust transform | 0.5% | 0.5% | 0.5% | **0.5%** (1,318 of 250,591) |
| functions printing differently with Rust structuring and IR passes off | 20.4% | 33.6% | 32.1% | **33.2%** (664 of 2,000) |
| ... Rust structuring alone | 6.3% | 23.1% | 22.3% | 23.1% (461) |
| ... Rust IR passes alone | 16.8% | 19.2% | 18.3% | 18.6% (371) |
| ... Rust expression printer off (PrintC's fragments instead) | n/a | n/a | n/a | **0.0%** (0 of 2,000) |
| executed lines, first-party Rust | 22,300 (27.4%) | n/a | n/a | **30,634 (32.5%)** |
| executed lines, first-party + kuna-sleigh | 27,405 (33.7%) | n/a | n/a | 37,327 (39.6%) |
| executed lines, our C++ | 2,657 | n/a | n/a | **1,423** |
| executed lines, vendored C++ | 51,195 | n/a | n/a | 55,620 |

What the table says, in the order it matters:

- **Tokens.** Rust emits 90.9% of the printed text, as in the expressions
  report (90.7%): the changes since are not in this lens. What stays PrintC's
  (56,956 tokens): the local declarations (`locals` 31,311), the prototype
  (`declaration` 17,809), header comments (2,020), comments, labels and case
  labels (the `body` region 5,816). 74,378 statement expressions were printed
  by Rust, 0 kept as a fragment.
- **The expression printer owns an implementation, not a decision.** With
  `ROMWRIGHT_RUST_EXPRESSIONS=off` 0 of 2,000 functions print differently
  (the pass is in the report, every function compared by text hash). The 76.7%
  of tokens it emits are the tokens PrintC emitted; what to print was decided
  upstream, by the vendored simplification, type and prototype recovery.
- **Decisions.** Rust's share of the control flow (2.9% of constructs, gotos
  844 -> 370 and labels 536 -> 216 over the sample, 461 of 2,000 functions
  printed a Rust tree, 104 of 867 IR `structure` cuts kept) and of the
  operations (0.5%) are unchanged within the sample noise. A third of the
  functions (33.2%) print differently without the Rust structuring and IR
  passes.
- **Executed code.** First-party Rust is 32.5% of the executed lines (39.6%
  with kuna-sleigh), against 27.4% (33.7%) on 10-08. Our C++ ran 1,423 lines,
  down from 2,657, because the console and its headers are gone. Different
  image set (10 against 8) and samples, and the persisted-prototype pass is in
  both; the vendored count grew by 4,425 lines with the added images.

By stage (owner shares of each stage's own unit; the report has every row's
detail and the per-stage executed lines):

| stage | 10-08 | 10-09 (expressions) | **10-10 (corpus wave)** |
|---|---|---|---|
| load | Rust 100% | Rust 100% | Rust 100% (vendored loader lines executed: 2,392, storage only) |
| discovery (stored facts by provenance) | Rust 57.8%, our C++ 42.2% | Rust 100% | **Rust 100%** (0 of 772,258 facts C++); C++-owned import phases 32.0% of import time (the switch stage's decompiler) |
| flow, import walk | kuna 100% | kuna 100% | kuna 100% |
| flow, decompile | vendored 100% | vendored 100% | vendored 100% |
| p-code lift (printed path) | vendored 100% | vendored 100% | vendored 100% (114,620 instructions in the sample) |
| switch recovery, stored | Rust 70.9% of 2,470 dispatches | 81.4% | **82.0% of 2,513 dispatches** (83.6% of 21,292 case edges) |
| switch recovery, printed | 0% | 76.6% | **70.8%**: 65 printed tables, all supplied by a stored table, 46 of them Rust VSA's, 65 agreed with `jumptable.cc`'s own recovery, 0 replaced |
| simplification | Rust 0.5% | 0.5% | 0.5% (1,318 edits, 365 of 2,000 functions) |
| type inference, default / persisted | 0% / 0.9% | 0% / 2.4% | **0% / 2.4%** (339 upgraded parameter types, upper bound) |
| prototype, default | 0% | 2.1% | 2.1% (43 of 2,000 functions, 300 of 7,296 call sites) |
| prototype, persisted | 16.5% | 16.5% | **16.0%** of 1,998 (1,577 are the decompiler's recovery alone) |
| structuring | 2.0% | 3.1% | **2.9%** |
| printing | 13.3% of tokens | 90.7% | **90.9%** |
| postprocess (export-c names) | 19.2% | 20.5% | 20.7% (65,425 of 315,535 identifiers) |

Line inventory (code lines: non-blank, non-comment; Rust test code excluded;
`benchmarks/ownership.py` counts it from the files):

| owner | 10-08 | 10-09 (expressions) | **10-10** | change since 10-09 |
|---|---|---|---|---|
| first-party Rust, all crates | 90,137 | 104,224 | **106,346** | +2,122 (core +2,096, cli +23, worker +2, worker-client +1) |
| first-party Rust, the seven pipeline crates | 70,954 | 85,041 | **87,163** | +2,122 |
| first-party Rust test code | 25,856 | 30,340 | 32,489 | +2,149 |
| kuna-sleigh (patched copy) | 17,540 | 17,846 | **17,854** | +8 |
| our C++ (patch-added + headers) | 3,848 | 4,816 | **2,047** | -2,769 |
| ... patch-added lines (35 files) | 481 | 808 | 634 | -174 |
| ... `native/romwright_*.hh` (6 headers) | 3,367 | 4,008 | **1,413** | -2,595 |
| vendored C++ (the whole pinned tree) | 137,961 | 137,961 | **137,961** | 0 |

The C++ we own fell by 2,769 lines because its users moved to Rust: the
constant-propagation, function-pattern and linkage headers
(`romwright_{constants,constant_state,operand_refs,x86_references,callfixups,patterns,linkage}.hh`,
2,489 lines at 10-09) and the console's `romwright_flow.hh` and
`romwright_parent.hh` (175) are gone; the headers that remain are
`romwright_printir.hh` (1,061, the IR exporter of the expression printer),
`romwright_ir.hh` (222), `romwright_ir_state.hh` (17), `romwright_nonreturn.hh`
(44), the new `romwright_ppc_return.hh` (19) and `romwright_budget.hh` (50).
The Rust side gained the ports (the reference pass over kuna-sleigh, patterns
and linkage, the expression printer, in-flow jump tables, the new loaders) and
its tests. The vendored tree is not touched; its count includes the SLEIGH
compiler, the interactive console and the BFD loader, which `ghidra_opt` does
not link: the coverage map holds 89,681 executable vendored lines in the
binary. Executable lines (coverage map): first-party Rust 69,833 (30,634
executed), kuna-sleigh 20,801 (6,693), our C++ 1,807 (1,423), vendored C++
89,681 (55,620).

**Reading against the criterion** ("we own more of the decompiled output than
the vendored tree does"). By the *text* lens the answer flipped on 10-09 and
stayed: Rust emits 90.9% of the printed tokens. That lens measures where a token
was produced, and 76.7 points of it are the expression printer, whose output is
byte-identical to PrintC's (0 of 2,000 functions differ with it off). By the
lenses that measure *decisions* the vendored tree still owns most of the output:
p-code lift, flow into the function, simplification (99.5% of operations),
type propagation, prototype recovery (default 97.9%, persisted 84.0%) and 97.2%
of the control-flow constructs. Rust owns everything before the decompiler
(load and discovery 100%, 82.0% of the stored switch dispatches, and the stored
table decides 70.8% of the printed ones' addresses), the layer after it (block
layer, expressions, export-c names, the structuring models), and by executed
code a third (32.5%, 39.6% with kuna-sleigh), with our own C++ down to 1,423
executed lines. One function in three prints differently because of the Rust
structuring and IR passes. What remains to take over before the criterion can be
read as met by decisions is the simplifier (`ruleaction.cc`, `coreaction.cc`,
`subflow.cc`, `double.cc`, `heritage.cc`: 16,884 of the 55,620 vendored lines
executed), type propagation (`typeop.cc`, `type.cc`), prototype recovery
(`fspec.cc`) and the declarations PrintC still prints (locals and prototype:
49,120 tokens).

Caveats: one seed and n = 200 per image, a different sample from the earlier
reports (1,275 of 2,000 addresses shared with `ownership_expressions`); the
persisted-prototype profile reads projects an earlier run left (tools
`ea27c70333bb669d`), decompiled by this tree's worker; coverage is merged over
the imports, the default decompile pass and the persisted pass, not the ablation
passes; the stage rules that map files to stages gained the new files
(`native_runtime/{propagation,reference_pass,patterns,linkage,disasm}`,
`native/{programs,n64_discovery,nonreturn,tally}.rs`, `romwright_budget.hh`),
so per-stage executed lines are not comparable with the 10-08 table, only the
totals are.

### 2026-10-08, the first measurement (coverage run, history)

`benchmarks/reports/ownership.{json,md}`, generated 2026-10-08T22:59:57+00:00
by the script from the run recorded below. Tools fingerprint
`ab96daf837699f1a` (instrumented `romwright-cli`/`-worker`/`-api` built from a
working-tree snapshot, source digest `fa7e3e2494034a33`, and the clang-coverage
`ghidra_opt` (and then the SLEIGH console, since retired) built from the same patch
and headers; the report checks that equality). The tree was a moving working tree, not a commit.
8 images, 200 sampled functions each (1,598 printed: capcom and gc lost one
each, as in `console_research`), default profile plus the persisted-prototype
profile (1,599 printed). The tables below are that run's, unchanged; the C++
line counts are the pre-retirement ones (the 10-10 section above has the
current inventory).

| lens | measure | Rust | C++ |
|---|---|---|---|
| printed tokens | 452,185 visible text tokens | 13.3% emitted by the block layer (60,020) | 86.7% replayed from PrintC fragments (392,165). Fragments by kind: variables 114,589, parens 114,202, operators 106,576, types 29,023, punctuation 13,678, function names 7,138, comments 6,077 |
| control flow | 20,175 printed constructs (Ghidra's tree had 20,017) | 2.0% of printed constructs created by Rust models | 98.0% Ghidra's; gotos 371 -> 126, labels 260 -> 92; 100 of 1,598 functions printed a Rust-restructured tree; IR `structure` cuts kept 30 of 328 |
| p-code | 161,418 final operations | 0.5% edited by a Rust transform (867, all `additive_inverse`; 266 functions) | 99.5% |
| counterfactual | functions whose text differs with the Rust components off | 326 of 1,598 (20.4%): 100 depend on Rust structuring (6.3%), 268 on the Rust IR passes (16.8%) | 79.6% print identically without any Rust structuring or IR pass |
| executed lines | the run's imports and decompiles | first-party Rust 22,300 (27.4%), plus kuna-sleigh 5,105 (33.7% together) | ours 2,657, vendored 51,195 |

By stage (shares of each stage's unit; the full table with details is in the
report):

| stage | Rust (first-party) | Rust (kuna) | C++ ours | C++ vendored |
|---|---|---|---|---|
| load | 100% | | | |
| discovery (stored facts) | 100% (by provenance, since 2026-10-09: the constant propagation moved in process; it was 57.8% with 42.2% console constant propagation, 306,509 of 726,130 facts, and console-owned phases were 49.8% of import time) | | 0% | |
| flow, import walk | | 100% | | |
| flow, decompile | | | | 100% |
| p-code lift (printed path) | | | | 100% (88,816 instructions in the sample) |
| switch recovery, stored tables | 70.9% of 2,470 dispatches (65.9% of 20,800 case edges) | | | 29.1% |
| switch recovery, printed | 0% before 2026-10-09 (73 tables, all recovered again by `jumptable.cc`); **61.8% after** (34 of 55 printed tables, 8 images; 37 of 64 with the two Puzzle Bobble variants) are supplied by a table Rust VSA stored | | | 38.2% after: stored by the import's own decompiler pass (21 of 55); `jumptable.cc` still derives their normalization, guards and case values. **100% (55 of 55) of printed switches are supplied by a stored table, 2666 of 2667 over every function that holds one** |
| simplification | 0.5% | | | 99.5% |
| type inference, default | 0% | | | 100% (29,023 type tokens) |
| type inference, persisted prototypes | 0.9% (282 upgraded parameter types, upper bound) | | | 99.1% |
| prototype, default | 0% (no stored prototype, 0 of 5,467 call sites) | | | 100% |
| prototype, persisted | 16.5% of signatures changed by Rust (264 of 1,597) | | | 83.5%: Ghidra's recovery, stored by Rust |
| structuring | 2.0% | | | 98.0% |
| printing | 13.3% of tokens | | | 86.7% |
| postprocess (export-c names) | 19.2% of identifiers | | | 80.8% |

Code size (code lines, tests excluded): first-party Rust 90,137 (70,954 in the
seven pipeline crates; the rest is desktop, debugger, API, differ, signatures),
kuna-sleigh 17,540, our C++ 3,848 (481 patch lines in 30 files, 3,367 in the
headers), vendored C++ 137,961 (including the SLEIGH compiler and console
sources). Executed-line numbers are in the report by stage and owner.

### Printed tokens after the Rust expression printer (2026-10-09)

`benchmarks/reports/ownership_expressions.{json,md}` (`benchmarks/ownership.py`
without coverage, host `nih-vps-u`, fresh imports, 10 images x 200 functions,
2,000 printed, tools fingerprint `647485cad03ebd25`; the 2026-10-08 table above
stays as the coverage run). The printed-token lens counts a token as Rust
when the block layer or the expression printer emitted it:

| population | tokens | Rust | of which block layer | of which expression printer | C++ (PrintC fragments) |
|---|---|---|---|---|---|
| the 8 images of the table above (1,600 printed) | 463,938 | **90.9%** (421,532) | 13.4% (62,385) | 77.4% (359,147) | 9.1% (42,406) |
| all 10 images (+ both Puzzle Bobble PSP variants) | 599,899 | **90.7%** (544,171) | 14.4% (86,521) | 76.3% (457,650) | 9.3% (55,728) |

The 8-image Rust share was 13.3% before (block layer only); the 10-image run of
the earlier `ownership_final` was 14.5%. What the expression printer
emitted on the 8 images, by kind: variables 110,086, parentheses 114,874,
operators 106,747, types 19,769, function names 5,708, punctuation 1,963.
What is still PrintC's (42,406 tokens on the 8 images): the local variable
declarations (22,591, region `locals`), the prototype (13,733 `declaration`,
1,873 `header` comments), comment lines, labels and case labels (body region
4,209). By kind: types 10,789, punctuation 10,081, variables 9,189 (declared
names), parentheses 4,580 (the declarations' own), comments 4,175.

Coverage of statement expressions (the renderer counts every expression it is
given, `PrintStats.expressions`): **all printed by Rust, none kept as a
fragment, on all 10 images** (72,531 expressions: 20,098 assignments, 9,555
stores, 8,334 calls, 2,977 returns, 9,357 conditional branches with their
9,357 branch renderings and 9,357 negations, 3,106 plain branches, 77 switch
dispatches, 236 for-loop headers). The `verify` mode (render, compare with
PrintC's fragment, keep the fragment) compared 50,762 expressions of the 8
images' 200-function samples and 21,260 of the 200-function x86 libc sample
with 0 differences. Expressions the renderer still refuses (a
union or `needsResolution` type, `CPOOLREF`/`NEW`/bit-field ops, user-op
display kinds other than function syntax, non-ASCII character constants) occur
twice in the libc sample (`callother:display`) and nowhere in the console
corpus; they keep PrintC's fragment (docs/printer-ir.md, "Limits").

**Reading against the criterion.** On every lens of the *printed* output the
vendored tree owns most of the result: 86.7% of tokens, 98.0% of control-flow
constructs, 99.5% of operations, and the p-code lift, simplification, type
propagation, prototype recovery and flow-into-function are 100% vendored (the
printed switch's addresses are no longer: 61.8% are Rust VSA's stored table,
100% a stored table, see "Stored switch tables fed to the decompiler"). Rust owns what comes before the decompiler
(load, discovery decisions, 70.9% of the stored switch dispatches), the layer
after it (block layer, export-c names, the structuring models that remove
245 of 371 gotos in the sample) and the `infer_prototypes` upgrades; one
function in five prints differently because of it. By executed code the
split is closer (27.4% first-party Rust, 33.7% with kuna) but that count
includes import plumbing, the database and the console-driving code, none of
which prints a token. The entry criterion, "we own more of the decompiled
output than the vendored tree does", is not met by any lens measured here.
Two things the report cannot show: whether a smaller Rust *share* of tokens
would already be a larger share of *decisions* (the block-layer tokens are the
structural ones, the fragments the leaves), and variable/stack recovery
against DWARF, which STATUS names as a gate but which this metric does not
score.

Caveats: one seed and n = 200 per image; the persisted-prototype profile reads
projects left by earlier runs (origin tools in the report: `cdbbf0f7d1273898`
for six images, `08df1a6eff7987ed` for x360 and Vita) decompiled by the
current worker; the run was made on a shared host, so its timings are not
reported and none of its numbers depends on time.

## Stored switch tables fed to the decompiler

Until 2026-10-09 every printed `switch` was recovered again by vendored
`jumptable.cc` at decompile time and the tables stored at import never reached
the decompiler, so the printed tables could disagree with the stored ones. They
now reach it: `ProgramProvider::from_store` reads each dispatch the import
stored (a branch with `native-import:switch` `COMPUTED_JUMP` edges, and every
`COMPUTED_JUMP` edge it has, whichever pass laid it) and the worker sends them
in `registerProgram`'s function-shell document as `<storedjump>` elements, one
per branch, with its targets. `Architecture::decodeStoredJump`
(`native/ghidra-opt-sleigh.patch`, `architecture.cc`) keeps them by branch
address, so a table holds in every function whose flow reaches the branch
(shared tails included). The import's own switch worker (`--switches`) is never
given them: recovery asks the decompiler what it recovers by itself.

`JumpTable::recoverStored` (`jumptable.cc`) runs `jumptable.cc` first, as it
always did, and compares the address set it recovers with the stored one:

| outcome | when | what is printed |
|---|---|---|
| `confirmed` | the sets are equal | `jumptable.cc`'s model, labels and folded guards: byte-identical to before. The stored table is the authority for the addresses; the decompiler supplies the normalization, guards and case values |
| `applied` | they differ, or `jumptable.cc` failed | the stored table, through Ghidra's own manual-override model (`JumpBasicOverride`). It now takes its normalized switch variable and value range from the guard analysis `JumpBasic` uses (`recoverFromGuards`), emulates each value to its address and keeps the values whose address is stored, so labels are the real case values and the guards fold as for a recovered table |
| `observed` | they differ and the override finds no normalized switch variable (the trivial model labels cases with addresses, which would not match the expression switched on) | `jumptable.cc`'s outcome stands, failure included |
| none | no stored table for the branch | `jumptable.cc` alone |

`ROMWRIGHT_STORED_SWITCHES=off|observe|apply` (default `apply`) selects: `off`
sends nothing (the tree before the cutover), `observe` sends the tables and only
compares. Each printed `<jumptable>` carries `storedout`, `stocksize`,
`storedsize`, `commonsize` (`JumpTable::encode`); the worker's
`ROMWRIGHT_OWNERSHIP_LOG` line has them as `switch_sources`. A stored table the
decompiler proves unreachable (the dispatch is dead after simplification) is not
printed in any mode.

**Census** (`benchmarks/switch_feed.py`, report `benchmarks/reports/switch_feed.json`;
fresh default imports, the 8 research images plus the two Puzzle Bobble
variants, sample rule and seed of the research harness, 200 functions each;
`--extended` adds every function that holds a stored table):

| image | stored tables (functions) | sample: printed / supplied | all holders: printed | confirmed | applied | observed | jumptable.cc alone differs (before) | stored, no switch printed (before) |
|---|---|---|---|---|---|---|---|---|
| gba | 617 (578) | 9 / 9 | 617 | 617 | 0 | 0 | 0 | 0 |
| nds | 408 (377) | 9 / 9 | 406 | 405 | 0 | 1 | 1 | 2 |
| capcom | 468 (408) | 18 / 18 | 617 | 615 | 2 | 0 | 0 | 4 |
| dungeon | 13 (8) | 1 / 1 | 13 | 12 | 1 | 0 | 0 | 1 |
| psx | 21 (19) | 2 / 2 | 20 | 20 | 0 | 0 | 0 | 1 |
| psv | 607 (484) | 1 / 1 | 599 | 599 | 0 | 0 | 0 | 9 |
| x360 | 248 (232) | 1 / 1 | 246 | 244 | 2 | 0 | 1 | 3 |
| gc | 114 (60) | 14 / 14 | 114 | 114 | 0 | 0 | 0 | 0 |
| psp | 18 (18) | 5 / 5 | 17 | 17 | 0 | 0 | 0 | 1 |
| psp (symtab) | 19 (19) | 4 / 4 | 18 | 18 | 0 | 0 | 0 | 1 |
| **all** | 2533 (2203) | 64 / 64 | 2667 | 2661 | 5 | 1 | 2 | 22 |

- **Printed switches supplied by the stored table: 55 of 55 (100%) on the
  8-image 200-function sample** (64 of 64 with the two Puzzle Bobble
  variants; the sample holds few switches because 200 functions rarely do),
  and **2666 of 2667 (99.96%)** over every function that holds a stored table.
  Before, the stored table supplied none of them.
- Before the cutover (`--observe-census`: the tables sent, `jumptable.cc`'s
  result stands): of 2663 switches `jumptable.cc` printed, 2661 had exactly the
  stored address set, 2 differed (nds 0x20a7514, stored 4 against 2; x360
  0x823bff98, 8 against 1). For 22 stored tables it printed no switch: 11 in
  functions that fail to decompile in every mode (capcom 2, psx 1, psv 8), 4
  whose dispatch it proves unreachable (x360 0x827abe88 and 0x827d7414, psp
  0x12560 in both variants of the image), and 7 where it failed or removed the
  switch ("Too many branches"; "Switch with 1 destination removed"): nds
  0x2001764 and 0x2001794, capcom 0x1a2d6c and 0x20c9b4, dungeon 0x129d10, x360
  0x827c8864, psv 0x8140c5d8.
- After: 2661 `confirmed`, 5 `applied` (capcom 0x1a2d6c and 0x20c9b4, dungeon
  0x129d10, x360 0x823bff98 and 0x827c8864), 1 `observed` (nds 0x20a7514).
  `observe` and `off` print the same text as each other on every function run;
  `apply` changes the text of 5 of the 2203 holder functions, exactly the five
  that hold an `applied` table (capcom 2: +87 lines, dungeon 1: +20, x360 2:
  +77), with gotos unchanged (x360 1001 and capcom 443 before and after).
  Psv's holder totals differ only by one function that timed
  out under load in the `apply` pass and prints identically when run alone.

Rulings, each from the bytes and the paths into the dispatch (the 2026-10-08
rulings' method):

| branch | stored | `jumptable.cc` | the binary | ruling | outcome |
|---|---|---|---|---|---|
| capcom 0x1a2d6c | 5 | failed | `sltiu a2,9`; table 0x319fc0 holds 9 slots, 5 distinct targets | stored right (exact) | `applied`: `switch` over cases 0..8 with default, replaces the call-through |
| capcom 0x20c9b4 | 5 | failed | `sltiu a1,6`; table 0x31bc70, 6 slots, 5 distinct | stored right (exact) | `applied` |
| dungeon 0x129d10 | 5 | failed | `sltiu a2,59`; table 0x14cd38, 59 slots, 5 distinct | stored right (exact) | `applied` |
| x360 0x823bff98 | 8 | 1 | 10-08 ruling: r10 is one of six constants, so the index is in {0..7, 12..15, 28, 29}: 8 targets | stored right | `applied` |
| x360 0x827c8864 | 8 | 1 (switch removed) | `cmplwi r11,10` bounds a byte table at 0x820e9648: 11 slots, 8 distinct targets | stored right (exact) | `applied`: the switch is back, 1 unstructured edge gone |
| nds 0x20a7514 | 4 | 2 | 10-08 ruling: r4 is 0, 1, 3 or 2: all 4 slots | stored right | `observed`: the override finds no normalized variable, `jumptable.cc`'s 2 stand |
| nds 0x2001764, 0x2001794 | 2 | failed | the index is one bit (`lsls #0x10; lsrs #0x1f`), so exactly slots 0 and 1: 2 targets | stored right (exact) | not printed: the override finds no normalized variable, `jumptable.cc`'s failure stands (prints a call) |
| psv 0x8140c5d8 | 2 | 1 | `cmp r0,#5; beq; cmp r0,#6; bne` leave r0 = 6 on the only way in, `subs r0,#1`: slot 5 only | **`jumptable.cc` right**: the stored 2 is a superset (the import's decompiler pass runs with `unreachable` off) | not printed: the override finds no normalized variable, `jumptable.cc`'s single destination stands |

Seven of the eight classes are the stored table right, one is the decompiler
right; none needed a fix to the importer. The one superset (psv 0x8140c5d8) is
the import-time decompiler pass, which runs with the `unreachable` action off
(`configure_switch_recovery`) and so cannot use the guard that pins the index.
The `observed` and not-printed rows are where the override cannot give a
correct label (it would print `case <address>:` over an index): they keep
`jumptable.cc`'s result instead of a misleading switch. A first version that
applied the trivial model printed those and was rejected.

An intermediate census (superseded tools) also listed psv 0x810dc4a8 and
0x814ae330, nds 0x20ea4dc and x360 0x82867b48 as stored right against a
`jumptable.cc` table of 1: each is a full guard table in the binary (5, 9, 9 and
12 distinct slots) and `confirmed` in the final run. `[INFERENCE]` an earlier
trivial override in the same function changed the flow the later recovery saw;
not isolated.

`benchmarks/ownership.py` rerun on the same tree (no coverage instrumentation, so
no executed-line lens; `benchmarks/reports/ownership_switch_feed.{json,md}`, the
2026-10-08 `ownership.{json,md}` stay as the coverage lens): the stage row "switch
recovery, printed" moved from 0% Rust to 57.8% over its 10 images (37 of 64
printed tables are supplied by a Rust-VSA table, 100% by a stored table).

**Checks** (host `nih-vps-u`, the tools of the census, `ROMWRIGHT_STORED_SWITCHES=off`
against the default; gate set: the console-research samples and 200 libc
functions, 1800 in all, on the research-eval stores, which predate this change):

- `printer_diff.py`: 1800/1800 identical (the printer differential reads the
  same Funcdata, so it cannot see a different table; it shows the feed does
  not break the printer IR).
- `structuring_models.py --configs baseline,all`: gotos 1499 / 813, labels
  934 / 553 in both modes. Lines +4 and statements +1 in one function, gc
  0x800331a0: its store predates the 2026-10-08 ruling that drops Ghidra's
  folded default from a table, so the stored table has the guard's default
  target as a fifth address; it prints the same four cases under an explicit
  `if (x < 0xd)` instead of a folded guard. A fresh gc import stores the four
  and `confirms`.
- `structuring_compile.py`: 1800 functions, 185 rewritten, 0 new diagnostics
  and 1567 error-free, off and apply alike.
- `structuring_m22.py` standalone: 64.14 (6/33 exact), baseline and `all`, off
  and apply alike.
- `tests/m15-001_structuring.py`: PASS, metrics identical off and apply
  (400 scored, 391 comparable); it never reaches the decompile-time path.
- `tests/m13-001_vsa_switch.py` (libc, import-time recovery, which is never
  fed): stock 132 at 0.981, VSA 41, interpreter 67, decompiler alone 130 at
  0.9978 (126 at 0.9977 in `m13-001-rerun-20261008.json`), combined 130; the
  two failures that stand in the rerun stand.

## What is not measured

- Rust-lifted p-code volume: `SleighLifter` has no counter. Only coverage and
  the code path show where it is used.
- The decompiler's internal pass-by-pass attribution of a single token: a token
  replayed from a fragment is counted C++ even when a Rust edit changed the
  p-code behind it (Rust edits are counted separately, per operation).
- The desktop's own rendering and the matching/diff features: outside the
  decompile path.
- `[INFERENCE]` marks anything the report cannot show from its own data.

## Reproduce

Needs the private corpus, `llvm-cov`/`llvm-profdata`, and clang for the C++
build (copy the output
directory to the same absolute path on the host that runs the images, since
the binaries record absolute source paths).

<!-- not gated: recorded recipe of a coverage study that needs a separate instrumented build tree -->
```sh
# (the script passes -Wno-c++11-narrowing for clang, which g++ does not need. No source is changed.)
# C++ with coverage (persistent tree; paths are recorded in the binaries)
benchmarks/ownership_build_coverage.sh --jobs 4 $HOME/runs/OwnershipMetric/cov-build
# Rust with coverage, continuous mode
RUSTFLAGS="-C instrument-coverage -C llvm-args=-runtime-counter-relocation" \
  CARGO_TARGET_DIR=$HOME/runs/OwnershipMetric/target-cov \
  cargo build --release -p romwright-cli -p romwright-worker -p romwright-api
# the run (imports, 200 functions per image, three ablation passes, the persisted-prototype
# pass, coverage, report). Run it from a snapshot of the tree the binaries were built from
# (rsync the repository, build there, point --source-root at it), so the report's tree
# digest, line inventory and coverage paths describe one tree.
benchmarks/ownership.py --target-dir $HOME/runs/OwnershipMetric/target-cov \
  --cov-build $HOME/runs/OwnershipMetric/cov-build \
  --cache $HOME/runs/OwnershipMetric/cache \
  --prototype-cache $HOME/runs/OwnershipMetric/protocache \
  --source-root $HOME/runs/OwnershipMetric/ventris --jobs 2
# the stock path and the default path on the same decompiles as a report (structuring handoff)
benchmarks/ownership_stock_coverage.py --target-dir $HOME/runs/OwnershipMetric/target-cov \
  --cov-build $HOME/runs/OwnershipMetric/cov-build --cache $HOME/runs/OwnershipMetric/cache \
  --source-root $HOME/runs/OwnershipMetric/ventris --report benchmarks/reports/ownership_structuring.json \
  --out stock.json            # add --default-path for the default one
# static line counts only
benchmarks/ownership.py --inventory-only
# before -> after tables over earlier reports (oldest first)
benchmarks/ownership.py --compare benchmarks/reports/ownership.json \
  benchmarks/reports/ownership_expressions.json benchmarks/reports/ownership_corpuswave.json
```

`--prototype-cache DIR` names a research cache (`projects/`, `samples/`) whose
`infer_prototypes` projects feed the persisted-prototype profile; copy the
`<id>-<sha>-4f53cda18c2b-<tools>-proto-4f53cda18c2b` projects and the samples
of one earlier run into it (no job is rerun). The imports run with the build's
default decoder-lane count (4, `RuntimeConfig::console_shards`), because the
count shapes what is found on mixed-ISA images; `--shards N` overrides it and
then owns the differences. Several processes may share one `--cache` on
disjoint `--images` lists (a result is cached per image only when it is
complete, so two processes on one image duplicate work and race on the
per-function log files); a last `--report-only` run then merges the results
and the profiles. The 2026-10-10 report took three processes (2 jobs each) and
about 1.5 hours on a 12-thread machine at load 4-13.

`--images a,b` runs a subset; `--report-only` rebuilds the report from the
cached per-image results and the merged profiles. The report records a source
digest and the number of uncommitted paths: the tree measured is the working
tree, not a commit.

Stored switch tables (no instrumentation needed; `--cache` is shared with the
research harness, so the imports are reused):

<!-- not gated: recorded recipe of the switch feed census that needs the cached corpus imports -->
```sh
CARGO_TARGET_DIR=$HOME/runs/SwitchFeed/target cargo build --release -p romwright-cli -p romwright-worker -p romwright-api
# the census: apply over the sample and every holder function, off and observe over the holders
benchmarks/switch_feed.py --target-dir $HOME/runs/SwitchFeed/target --cache $HOME/runs/SwitchFeed/cache --jobs 2 --extended
# the census before the cutover (observe over every holder function), added to the report
benchmarks/switch_feed.py --target-dir ... --cache ... --observe-census
# the ownership stage row without coverage: --cov-build holds ghidra_opt (links are enough)
benchmarks/ownership.py --target-dir ... --cov-build DIR --cache ... --out benchmarks/reports/ownership_switch_feed.json
```
