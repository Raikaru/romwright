# Decompiler port, stage 3: high-variable merge, explicit/implied, names

Status: done 2026-10-14 (Stage3Merge). Sections 1-9 are the design as written
before the code, corrected where the build differed; "Result" and "Limits" at the
end are what the gates measured.

Context: STATUS.md, "Decompiler port: stage roadmap". Stage 1 moved structuring,
stage 2a the casts. Stage 3 moves **who decides which p-code values share a C
variable, which values print as sub-expressions, and what the variables are
called**.

## 1. The C++ surface

All of it runs once per function, between the end of the `mainloop` /
structuring and `ActionSetCasts` (`coreaction.cc` `universalAction`, lines
~5774-5794):

| step | where | what it decides | reads |
|---|---|---|---|
| `ActionAssignHigh` | `Funcdata::setHighLevel`, `funcdata_varnode.cc` | one `HighVariable` per varnode (symbol and type from the varnode) | symbol entries |
| `ActionMergeRequired` | `Merge::mergeAddrTied`, `groupPartials`, `mergeMarker` (`merge.cc`) | forced merges: all address-tied varnodes of one storage; the input and output of every MULTIEQUAL/INDIRECT. **Edits p-code**: where covers intersect it snips reads / trims ops by inserting `COPY` ops with new `unique` varnodes (`snipReads`, `trimOpInput`/`Output`, `mergeIndirect`) | covers (`cover.cc`), `HighIntersectTest` (`variable.cc`), flags |
| `ActionMarkExplicit` | `coreaction.cc:3049-3319` | which varnodes are *explicit* (own a variable / statement) and which may be implied (inlined into the reading expression): descendant counts, `max_implied_ref`, term counting (`max_term_duplication`) | HighVariable instance counts, flags |
| `ActionMarkImplied` | `coreaction.cc:3326-3502` | implied vs explicit for the rest, by a cover test of the propagated expression (`Merge::inflateTest`, STORE/LOAD/call crossings, `isPossibleAlias`) | covers, calls, store guards |
| `ActionMergeMultiEntry`, `ActionMergeCopy`, `ActionDominantCopy` | `Merge::mergeMultiEntry`, `mergeOpcode(COPY)`, `processCopyTrims` | merge symbol entries of one symbol; merge COPY in/out; replace several trim COPYs from one source with one dominating COPY (**edits p-code**) | symbols, covers, dominators |
| `ActionMarkIndirectOnly` | `Funcdata::markIndirectOnly` | flags illegal inputs that only feed INDIRECTs | def-use |
| `ActionMergeAdjacent`, `ActionMergeType` | `Merge::mergeAdjacent`, `mergeByDatatype` | **speculative** merges: input/output of one op with the same type; all non-intersecting highs of one type | covers, types |
| `ActionHideShadow`, `ActionCopyMarker` | `Merge::hideShadows`, `markInternalCopies` | rewires shadow COPY chains; marks COPYs inside one variable (and redundant ones) *non-printing* | covers, shadows |
| `ActionDynamicSymbols`, `ActionOutputPrototype`, `ActionInputPrototype` | `coreaction.cc` | dynamic symbols (none exist in romwright: no hash symbols), return and parameter symbols | `FuncProto`, scope |
| `ActionNameVars` | `coreaction.cc:2859-3042`, `Scope::buildDefaultName`, `ScopeInternal::buildVariableName` | links each variable to a symbol (creating one), then names the undefined ones: parameter names recommended by locked callees, `param_N`, `in_`/`unaff_`/`extraout_` + register, `local_`/`Stack` offsets, `iVar3` (type character + running counter over the address-ordered variables) | scope, symbols, types, call specs |
| for-loop op moves | `romwright_structure.hh`: `romwrightLoopTransform` (at `ActionStructureTransform`, before variables merge) and `romwrightLoopFinalize` (at `ActionFinalStructure`, after names) | which ops are a `for` loop's initializer/iterator (`BlockWhileDo::finalTransform` / `finalizePrinting`), and moves them to the ends of their blocks | op order, `isMoveable`, explicit flags, `Funcdata::moveRespectingCover` |

`HighVariable` (`variable.cc`, 1,206 lines) is the container the actions edit:
instance list (kept sorted by storage address), flags, lazily derived type
(the most specific / typelocked instance, `getTypeRepresentative`) and name
representative, cover (union of its instances' covers) and symbol link.

## 2. The Rust surface today

* `printc/` holds printing (stage 0), structuring (1) and casts (2a). It reads
  the *result* of merge and naming through the print trees (a leaf names its
  symbol) and has **no p-code model**: a print tree is one statement.
* `casts.rs` has a `Datatype::typeOrder` subset and the type table (`Tables`)
  with the per-type data a type lattice needs (meta, size, base, typedef).
* The query channel (`ELEM_ROMWRIGHT_STRUCTURE`, id 4092) already carries
  structuring queries (first value = block count), cast queries (first value
  0, then a marker) and answers per function with an accept or decline.

## 3. The cut

Stage 2 rejected a Funcdata mirror because a cast pass works on one statement
tree. Merge cannot: covers are intervals of the whole p-code in block order,
and the decisions edit the data flow. **Stage 3 therefore gives Rust a
mirror of the function's p-code (ops, varnodes, def-use, blocks, dominators)
at exactly one point, and takes back a log of decisions.**

```
 C++ ... NormalizeBranches  AssignHigh        ->  merge query ->  Rust: loop moves, MergeRequired,
                            (C++, unchanged)                      MarkExplicit, MarkImplied, MultiEntry,
                                                                  MergeCopy, DominantCopy, IndirectOnly,
                                                                  MergeAdjacent, MergeType, HideShadow,
                                                                  CopyMarker, loop finalize
                                                  <- decision log
 C++ applies the log to Funcdata/HighVariable (same calls, same order the stock actions make)
 C++ ... OutputPrototype InputPrototype DynamicSymbols  NameVars (names: naming query, section 6)
 C++ ... (casts query, print IR export: unchanged)
```

* **The mirror** is the state right after `ActionAssignHigh` (one
  `HighVariable` per varnode, symbols and types attached). `romwright_merge.hh`
  writes it; `printc/merge/` reads it (`model.rs`).
* **Rust runs the actions** it replaces over that mirror, in the pipeline's
  order (`printc/merge/`: `model.rs` the mirror, its edits and the `HighVariable`
  state; `cover.rs` = `cover.cc`; `actions.rs` = `merge.cc` and
  `HighIntersectTest`; `pieces.rs` = `VariableGroup`/`VariablePiece`,
  `groupPartials`, `PieceNode`; `explicit.rs` = `ActionMarkExplicit` and
  `ActionMarkImplied`; `loops.rs` = the for-loop moves and
  `Funcdata::moveRespectingCover`; `names.rs` = the default names;
  `sortcxx.rs` = libstdc++'s `std::sort`, because `mergeLinear` sorts with a
  comparator that has ties and the order of tied elements is what the library's
  partitioning leaves; `variant.rs` = the knob; `mod.rs` = the driver, the log
  encoding and verify mode). Every p-code edit the merge makes (insert a COPY,
  rewire a read, destroy an op) is applied to the mirror as well, so covers stay
  right, **and appended to the log**.
* **The log** has 19 entry kinds: new COPY op (address taken from an op or a block
  end), new `unique` varnode (size, type of another varnode), set output, set
  input, insert (before/after an op, at a block's beginning or end), uninsert,
  destroy op, total replace, high remove, merge two highs (speculative or not),
  set explicit, clear implied, mark implied, mark op non-printing / printing /
  special print, mark indirect-only, group two highs, clear proto-partial, then
  the for-loop records (head, tail, initializer, iterator). C++ replays it with
  the same `Funcdata`/`HighVariable` calls the stock actions make, in the log's
  order, so varnode creation indices, op times and `HighVariable` internals (merge
  classes, instance order) end up as the stock path leaves them. The print IR
  and the cast query that follow run on that state, unchanged.
* **Per-function authority** (as stage 2): the worker answers `o` + log or `n`.
  On `n` (or with `ROMWRIGHT_NATIVE_MERGE=1`) the stock actions run in
  `RomwrightMerge::apply` in their stock order. Declines: a symbol with several
  entries (`mergeMultiEntry`, not ported), dynamic symbols, a COPY trim of a
  constant or of a value whose type `needsResolution` (a union), a type pair the
  table does not order, an INDIRECT whose effect op is not alive, a
  `LowlevelError` the stock merge would raise (forced merge impossible), and a
  panic in the port (caught: it costs the function its worker decision, never the
  worker). `VariablePiece`/`VariableGroup` (`groupWith`, CONCAT trees,
  overlapping address-tied storage) **are** ported. The reasons are counted in
  `ROMWRIGHT_RUST_MERGE_LOG`.
* **Why decisions and not the whole state.** The symbol table, `FuncProto`,
  `ActionInputPrototype` and the type factory stay C++ until stages 4-6.
  A log of decisions replayed on the real objects keeps every consumer after
  the cut (prototype actions, naming, the cast query, the exporter) on its
  native data and makes the port *checkable*: verify mode (below) compares the
  stock result with the worker's decisions variable by variable.
* **For-loops.** `romwrightLoopTransform` ran at structuring time and moved
  ops before `AssignHigh`; it needs only op order (`isMoveable`) and the
  worker's loop candidates, so it moves into Rust's sequence as step 0 (the
  `NormalizeBranches` action that runs in between does not read op order).
  `romwrightLoopFinalize` (explicit flags, `moveRespectingCover`) ran after
  the casts' place in the pipeline but, since stage 2a, on pre-cast p-code
  (`types-port.md` section 11); it runs at the end of Rust's sequence on the
  same p-code, which is the identical input. The loop records go back in the
  log and replace `RomwrightFunctionState::loops`.

**Alternatives rejected.**

* *Per-action queries* (one round trip per stage-3 action): six snapshots per
  function for state that changes between them.
* *Own the symbol table and `FuncProto` as well*: stage 4+ work; the port stays
  gateable only if everything after the cut is unchanged C++.
* *Re-implement the merge inside the exporter in C++*: not a port.
* *Mirror after the merge (print-tree level)*: Rust would only see the answer.

## 4. IR wire change

The **print IR version goes 6 -> 7** (`printc/ir.rs`, `romwright_printir.hh`,
`docs/printer-ir.md`): the header gains `merge owner` (0: stock C++ merge,
1: the worker decided the function) after `casts pending`, which the
ownership measurement and the for-loop records read. The **merge query** and
its answer are new messages on the structuring channel (first value 0,
marker 2); the **naming query** is marker 3. They are internal to the pair
(`ghidra_opt`, worker), versioned by the same `printer IR version 7` check.

Merge query payload (six-bit varints, `RomwrightIrBytes`;
`RomwrightPrintIrExport::mergeQuery`, `printc/ir.rs` `decode_merge_query`): `0`,
marker 2, the function address, `max_implied_ref`, `max_term_duplication`, the
for-loop flag, the next op time, the next varnode creation index, the next
`unique` offset and the unique space, flags for multi-entry and dynamic symbols,
the **type table** (the cast query's `tables()` encoding, so `Datatype::typeOrder`
data is shared) plus each type's stripped form, the **space table** (index,
kind, endianness), the symbols (isolated flag, metatype), the blocks (in-edges,
out-edges with their reverse index, immediate dominator, start/stop address, op
list), the ops in alive-list order (time, address, opcode, block, order, flags,
inputs, output, INDIRECT effect op, a bit per input saying whether its local
type equals the output's), the varnodes in location order (create index, size,
space, offset, flags, type, defining op, readers in descend order, symbol and
offset, symbol entry and offset), the calls, the call and guarded-STORE ops that
can affect a cover (`StackAffectingOps`), the for-loop candidates and the CONCAT
roots (`Merge::protoPartial`). Answer: `o`, the log, the loop records; or `n`;
or `v` in verify mode.

Verify dump (marker 4): per block its ops (time, opcode, non-printing and
special-print flags, output and input creation indices), per varnode its
creation index, its variable's smallest creation index, explicit, implied and
indirect-only flags, and the loop records.

## 5. Variant knob (for the later near-miss search)

`printc/merge/variant.rs` defines `Variant`. Every choice the search could
want is a field; the default is the stock behaviour (all fields neutral).

| field | stock behaviour it changes |
|---|---|
| `adjacent: bool` | `ActionMergeAdjacent` (speculative merge of an op's input and output of equal type) |
| `datatype: bool` | `ActionMergeType` (speculative merge of all non-intersecting variables of one type) |
| `copy: bool` | `ActionMergeCopy` (merge COPY input and output) |
| `dominant: bool`, `hide_shadow: bool` | `ActionDominantCopy`, `ActionHideShadow` |
| `max_implied_ref`, `max_term_duplication` | `Architecture::max_implied_ref` (default 2) / `max_term_duplication` (default 2): how many readers/terms a value may have and still be inlined |
| `explicit: [VarRef]` | values forced to be a variable of their own (statement) |
| `separate: [(VarRef, VarRef)]` | pairs of values a *speculative* merge may not put in one variable (required merges, by definition, still happen) |

`VarRef` names a value stably across variants: the op `time` of its defining
op (`t<time>`) or `i<space>:<offset>:<size>` for a function input. Required
merges, the marker/INDIRECT merges and the copy trims are not exposed: they
are not a choice but the SSA-to-variables construction.

Setting it:
* **Environment** `ROMWRIGHT_MERGE_VARIANT` (read by the worker): `default`;
  `key=value,...` (`adjacent=off`, `maxref=3`, `explicit=t120+t455`,
  `separate=t12~t40`); or `@file.json` with `{"<function address hex>":
  {...}, "*": {...}}`. A function with no entry takes the stock variant. There
  is no decompile cache: every `export-c` decompiles again, so the variable is
  read at each call (the worker process inherits it from the CLI).
* **Per decompile request** (core): `RuntimeConfig::worker_env` /
  `M2cOptions::worker_env` are environment pairs the decompiler worker gets on
  top of the process's own; `export_m2c` sets them for its request. The
  near-miss search uses it to give each printing its own `ROMWRIGHT_MERGE_VARIANT`
  (and the cast and structuring switches) without touching the CLI process's
  environment, so no C++ change is needed. Empty (the default) is today's output
  byte for byte.
* **API** (worker crate): `printc::merge::Variant::parse(&str)` and
  `printc::merge::set_variants(map)` (thread-local override used by tests and
  by an in-process caller).

The search that drives this knob is `romwright-cli match`, documented in
[match.md](match.md).

## 6. Naming (marker 3)

`ActionNameVars::apply` stays in C++ through `linkSymbols` (symbol creation,
which needs the scope), `recoverNameRecommendationsForSymbols`, the bad
jump-table and callee-parameter recommendations. What it then does with the
list of variables still unnamed - choose a default name for each, in the order it
visits them, with one running counter - is `Scope::buildDefaultName` /
`ScopeInternal::buildVariableName` / `ScopeLocal::buildVariableName`. The worker
owns that decision (`printc/merge/names.rs`, `romwrightNameVars` in
`romwright_merge.hh`). For each still-undefined symbol C++ sends the facts the
builder reads of the varnode, symbol and scope (the flags with `input` added for a
parameter, the parameter index, `Datatype::printNameBase`, the storage's space
name, offset, address size and word offset, `Translate::getRegisterName`, and for
a stack variable of the local scope its signed offset and whether it lies in the
unusual region) plus the names the local scope already has; the worker answers
the names (`param_N`, `in_`/`unaff_`/`extraout_` + register, `iStackX_10`, `DAT`
forms, `iVar3` with the counter and its skip-over of taken names) and the final
counter. The scope's own uniqueness check (`makeNameUnique`) stays C++ and is
applied to every answer that says so (everything except an `iVar3` that found a
free name). `ROMWRIGHT_RUST_NAMES=off` and `ROMWRIGHT_NATIVE_MERGE=1` give the
stock loop back.

## 7. Switches that restore the C++ path

* `ROMWRIGHT_NATIVE_MERGE=1` (read by `ghidra_opt`): `RomwrightMerge` runs the
  stock actions, the loop moves stay in `romwright_structure.hh` as before and
  names come from `ActionNameVars`: the previous default byte for byte (the
  **off arm** of every differential). The IR says `merge owner = 0`.
* `ROMWRIGHT_RUST_MERGE=off|on|verify` (worker, default `on`): `off` declines
  every function; `verify` has the decompiler run its stock actions and
  compares them with the worker's decisions (partition, explicit/implied,
  inserted ops, non-printing ops), reported in `ROMWRIGHT_RUST_MERGE_LOG`.
* `ROMWRIGHT_RUST_NAMES=off` : names from `ActionNameVars` (merge still Rust).
* No quality-fix switches: the quality pass (section 10) found no merge-owned fix that loses nothing.

## 8. Differentials and gates

1. **Verify mode** on the standard sample (8 images x 200 functions): zero
   mismatching functions, every mismatch class listed.
2. **Printer and C differential**: default against `ROMWRIGHT_NATIVE_MERGE=1`
   on the same 8 images x 200 functions (`benchmarks/merge_diff.py`: the C
   text of each function), every diff classified; the stock-path printer
   differential (`benchmarks/printer_diff.py`) must stay 1,800 / 1,800.
3. **Paired C text** over m22-002 (3 lanes) and the 7 m22-003 lanes, off arm
   against default: better / worse / same by compile and match percent; no
   exact or compiled function lost.
4. **Quality pass** after parity: partial members on locals, undeclared stack
   locals, `stack0x00000000` as an address, VU intrinsics into ints, each
   behind its own switch, kept only if nothing is lost.
5. **Gates, one build**: m21-001, m22-002 x 3, m22-003 x 7,
   `ps2_decompile_success`, printer differential, ownership metric.
6. **Declines** are counted per reason (`ROMWRIGHT_RUST_MERGE_LOG`) and
   reported as a rate.

## 9. Order of work

1. This document.
2. `native/romwright_merge.hh`: mirror writer, log replay, the stock fallback
   action, verify support; `romwright_structure.hh`/patch: pipeline hook.
3. `printc/merge/`: model + reader, cover, high-variable and intersection
   cache, merge, explicit/implied, loops, log writer, query wiring.
4. Verify mode to zero mismatches on the sample; fix.
5. Naming query; differential; quality pass; knob smoke on a real near-miss.
6. Gates and reports.

## 10. Result

One release build; `ghidra_opt` sha256
`486ace43c12ed3017508f527344dd06552b7ee62304c861566430ca18074ff94` (IR
version 7). Reports: `benchmarks/reports/stage3_gates_20261014.{json,md}` and
the `*_stage3_*` files beside it.

**Parity.** Default against `ROMWRIGHT_NATIVE_MERGE=1`, printed C text:
1,600 of 1,600 identical on the 8 images x 200 functions
(`merge_diff_stage3_20261014.json`), 7,409 of 7,409 on the PS2 wave's 7,500
addresses (the other 91 are in two chunks that fail the same way in both arms:
persona-4 60 s deadline, dark-cloud `Flow exceeded maximum allowed`,
`wave_text_diff_stage3_20261014.json`). Verify mode (the decompiler's stock merge
runs, the worker's result is compared variable by variable): 1,600 of 1,600
verified on the sample, 7,619 of 7,619 on the PS2 images, 0 mismatches
(`merge_verify_stage3_20261014.json`). **Declines: 0 of 1,600, 0 of 7,619.**
(The first build, before the `VariablePiece`/`VariableGroup` port, declined 86 of
1,600 = 5.4%: overlapping address-tied storage, CONCAT proto-partials and partial
struct types.) Printer differential (the stock path): 1,800 of 1,800.

**Divergences found by verify mode while porting** (each fixed, none left): a
cover extension of an op that was dirty, the `same_local_type` mask of a new COPY
op, a 32-bit shift in the cover masks, and the tie order of `std::sort` in
`mergeLinear` (ported as libstdc++'s introsort with its heap-sort fallback,
`sortcxx.rs`).

**Gates**, off = `ROMWRIGHT_NATIVE_MERGE=1`, default = the worker decides; fresh
import and work directory per arm; every lane equals Upgrade1's final gate and
the off arm exactly (paired better / worse / same 0 / 0 / 200):

| gate | exact / compiled / mean % |
|---|---|
| m22-002 MWCC 20261010 / 20261011 / ee-gcc | 55 / 193 / 76.968, 57 / 194 / 78.316, 106 / 197 / 86.403 |
| m22-003 dds, rc, p4, gh (harness clone) | 61 / 200 / 77.224, 26 / 200 / 68.158, 60 / 193 / 79.400, 78 / 199 / 82.119 |
| m22-003 ff, dc, dk | 21 / 195 / 61.753, 38 / 186 / 69.844, 29 / 189 / 75.561 |
| m21-001 | PASS in both arms, rows identical |
| `ps2_decompile_success`, 8 fresh PS2 images | 7,448 of 7,500 in both arms, the same 52 failures per game |
| printer differential | 1,800 of 1,800 |

(Upgrade1's gate decompiled 7,447; one more function decompiles here, in both
arms. The 52 failures: persona-4 `002be530` (60 s deadline), the two
`Backward normalization not implemented` functions of the Ratchet & Clank images,
dark-cloud's 49 (`Flow exceeded maximum allowed`), all pre-existing and equal in
both arms. The 10,342-function wave's projects are gone, so the 8-image set is the
gate.)

**Cost.** The worker's decisions take 0.56 s of 70 s decompile wall (0.8%); the
replay and the mirror writer are in the decompiler's own time. A 300-function
God Hand run of default against `ROMWRIGHT_NATIVE_MERGE=1` is at parity within
noise.

**Knob smoke** (`variant_smoke_stage3_20261014.json`; m22-003 dds; the 30 best
non-exact functions; 12 variants; each variant printed, compiled and matched in
the lane). Mean match with the default variant 93.066%:

| variant | exact | mean % |
|---|---|---|
| default | 0 | 93.066 |
| `adjacent=off` / `copy=off` / `dominant=off` / `hideshadow=off` | 0 | 93.066 (no output change on these 30) |
| `datatype=off` | 1 | 93.223 |
| `adjacent=off,datatype=off` | 1 | 93.018 |
| `maxref=1` | 1 | 93.364 |
| `maxref=4` | 0 | 93.075 |
| `maxdup=1` / `maxdup=4` | 0 | 92.992 / 92.694 |

`sndAddSourceReferences`: 88.842% -> **100.000%** under `maxref=1` (the value
`*(int *)param_1` is read twice, so it gets a variable of its own:
`temp_v0 = *(int *)param_1; temp_v1 = *(int *)((int)param_1 + 8);`).
`btlReleaseModelEntry`: 99.646% -> **99.958% (exact)** under `datatype=off`
(each reload keeps its own variable, `temp_v1`..`temp_v3`, where the default
reuses `temp_v0`, `ActionMergeType` having put them together). The best variant
per function is 93.623% mean with 2 exact; 5 of the 30 functions improve under
some variant. The search over these variants is the next step and is not built.

**Quality pass.** The stage-3-shaped leftovers Upgrade1 named were traced to their
origin. They are not merge decisions: partial members (`uStack_8._4_4_`,
`temp_v7._0_8_`), undeclared and unnamed stack locals and `stack0x...` as an
address come from how `ScopeLocal`/`linkSpacebaseSymbol` lay out stack symbols and
from global symbol sizes (571 of 7,409 PS2 functions print a partial member,
63 a `stack0x`, 17 an `undefinedN`); VU intrinsics assigned to ints are type
inference (`ActionInferTypes` gives the intrinsic's output the type of the use).
Each non-compiling function of ff (5) and dk (11) was printed under six merge
variants (`variant_quality_stage3_20261014.json`): none compiles in any, so no
merge-guarded fix was kept.

## 11. Limits

* Multi-entry symbols (`mergeMultiEntry`) and dynamic symbols make the worker
  decline the function (the stock actions then run); none occurred in 1,600 +
  7,619 functions. A COPY trim of a union-typed value (`needsResolution`) or of a
  constant also declines; none occurred either.
* The symbol table, `FuncProto`, `ActionInputPrototype`/`ActionOutputPrototype`,
  `ActionDynamicSymbols`, scope name uniqueness and the type factory stay C++;
  `HighVariable::merge` and the covers are still computed by the vendored C++
  during the replay, which is how everything after the cut sees the stock state.
* The mirror is taken after `ActionAssignHigh`; the worker never sees p-code
  earlier or the C++ symbol table, so a variant cannot rename or retype.
* The for-loop finalize still runs on pre-cast p-code, as since stage 2a.
* `ROMWRIGHT_RUST_MERGE=off` still lets the worker compose names
  (`ROMWRIGHT_RUST_NAMES=off` for the C++ names).
* The variant knob can only change speculative merges, the implied/explicit
  thresholds and forced explicit/separated values; required merges and copy trims
  are not choices. `separate=` is unit-tested; `explicit=` was run on a real function (God Hand
  `0010b698`: `explicit=t1+...+t12` turns `return (*(unsigned int *)(param_1 +
  0x15f4) & 0x400000) != 0;` into the three-statement form with `uVar2`/`bVar1`);
  neither was measured on a lane.
* A panic in the port is caught and costs the function its worker decision
  (decline), never the worker.
