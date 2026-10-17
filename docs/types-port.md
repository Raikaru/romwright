# Decompiler port, stage 2: types and casts

Status: design written 2026-10-13 (Stage2Types), before the code. Sections
"Result" and "Measured" at the end are filled in as the gates run.

Context: STATUS.md, "Decompiler port: stage roadmap". Stage 1 moved the
C++ -> Rust handoff from the printed block tree to the unstructured control-flow
graph. Stage 2 moves the next piece upstream: **who decides the casts**, and
(2b) **who infers the types** the casts are decided from.

## 1. The C++ surface

| piece | where | what it does | reads |
|---|---|---|---|
| `ActionSetCasts` | `coreaction.cc:2390-2816` | per op in block order: undo a `PTRADD`/`PTRSUB` that no longer fits its pointer (`opUndoPtradd`, `PTRSUB`->`COPY`/`INT_ADD`), then for every input slot `resolveUnion` + `castInput`, then `castOutput`. A cast is a new `CAST` op (or a `PTRSUB #0` when `testStructOffset0` says the first field/element fits) with a new implied unique varnode; a constant instead gets `updateType`; an implied varnode's type is overwritten by the token type | `getInputCast`, `getOutputToken`, `castStandard`, varnode and HighVariable types |
| `CastStrategyC` | `cast.cc` (546 lines) | `castStandard` (the cast rules), `arithmeticOutputStandard`, `intPromotionType`/`localExtensionType`, `checkIntPromotionForCompare/Extension`, `markExplicitUnsigned`/`LongSize` (flags on constants), `isZextCast`/`isSextCast`/`isSubpieceCast`/`isExtensionCastImplied` (printer-side; already in `printc/render.rs`) | types, and the *shape* of the expression (explicit or implied, defining opcode) |
| `TypeOp::getInputCast`/`getOutputToken` and ~50 overrides | `typeop.cc:283-2610` | which type an op's input must have and which type the op's result has "as a C compiler would parse it" | `inputTypeLocal`/`outputTypeLocal` (`getInputLocal`/`getOutputLocal`), current types, fspec (calls, return), `TypeFactory::getBase/getTypePointer`, `typeOrder`, `downChain`, `findTruncation` |
| `ActionInferTypes` and `TypeOp::propagateType` | `coreaction.cc:~3400-3900`, `typeop.cc` (every op), `type.cc` | the lattice propagation that gives every varnode a type; runs **inside `mainloop`** (line ~5559) so simplification rules read its result; also `ActionLocalRecovery`/`ScopeLocal` typing of stack and global symbols, struct field resolution, unions | the whole data-flow graph, the symbol tables, `TypeFactory` |
| `TypeFactory` | `type.cc` (5161 lines) | canonical `Datatype` objects, uniqued by structure; type identity is pointer equality (`curtype == reqtype`) | |

`ActionSetCasts` is the **last action that edits p-code**: after it come only
`ActionFinalStructure` (stage 1 already left that to Rust) and
`ActionPrototypeWarnings`. Nothing that follows reads a `CAST` op. That makes
it a clean cut: everything before it is unchanged C++; everything it does is
local to one statement's expression tree plus per-varnode types.

`ActionInferTypes` is the opposite: it sits in the middle of the simplification
loop and the rules (`ruleaction.cc`) read the types it sets. It cannot be
handed over as one downstream cut (see 2b).

## 2. The Rust surface today

* `printc/render.rs` (2,400 lines) already ports PrintC's expression emission
  and the *printer-side* cast decisions: `isZextCast`/`isSextCast`/
  `isSubpieceCast`, `isExtensionCastImplied` (exported as a flag), the
  `CAST`/`FLOAT_*` nodes print as `(type)expr`, `pushType*`.
* `printc/tree.rs` print trees (IR v4). Leaves carry the symbol, constants
  carry their read-facing type, **op nodes carry the output type only for
  `INT_ZEXT`/`INT_SEXT`/`SUBPIECE`/`CAST`/`FLOAT_*` and the `CAST` ops are
  already inserted** (the exporter runs after `ActionSetCasts`). No leaf
  carries its type, no op carries the types `getInputCast` reads.
* Type table (`Tables.types`, per function): name, meta, size, display format,
  char/enum/union flags, pointee/element, struct fields. Missing for casting:
  submeta, typedef link, pointer word size and address space, alignment size,
  the varnode's *own* type (as opposed to its HighVariable's), variable-length
  flag.
* The struct layer (`romwright-core/struct_*`, `worker/struct_types.rs`)
  answers the decompiler's struct-datatype request; it is a *type source*, not
  a cast decision.
* Compiler identity (`romwright-core/compiler`, `programs.compiler`) exists but
  nothing in the printer reads it.

## 3. The cut, as built

**2a (casts): the worker decides every cast, over a pre-cast typed print tree,
function by function.**

* `ghidra_opt` does not run `ActionSetCasts` in the pipeline. Its place there
  is `RomwrightSetCasts` (`native/romwright_structure.hh`), which only calls
  `startCastPhase` and marks the function pending. The decision is made where
  the p-code is first read to print it: `romwrightFinishCasts`
  (`native/romwright_printir.hh`), called from the patch's `DecompileAt` and
  from `RenderFunctionIr`. (A pipeline action cannot ask the worker anything
  useful: it has no print state. The query needs the function's `PrintC`
  scope and symbol tables, which exist at the print step.)
* There it (1) reads what the cast phase needs of every op and varnode
  (`RomwrightCastFacts`), **before** anything probes the function; PrintC's
  handlers update lazily evaluated state (a `HighVariable`'s type), so a
  probing export would hand the cast phase different types than
  `ActionSetCasts` read; (2) exports the statements' pre-cast print trees
  (the IR's version-6 print tree: types, local requirement types, flags;
  [printer-ir.md](printer-ir.md#pre-cast-trees-version-6-default)) as a query
  on the stage-1 channel (element 4092, payload starting with 0);
  (3) takes the worker's answer.
* `printc/casts.rs` ports `CastStrategyC`, the cast methods of `typeop.cc`
  and `ActionSetCasts` (list in printer-ir.md) over that tree. The result
  is the print tree `printc/render.rs` prints, so the printed cast tokens are Rust's
  from decision to character. The worker repeats the (pure, deterministic)
  pass while decoding the final IR, whose trees are the same pre-cast trees;
  C++ read the facts once, so both passes read the same input.
* Types are the worker's table; `TypeFactory`'s subset in `casts.rs` resolves
  `getBase(size, meta)` against the core types the exporter seeded for every
  size the function uses, and `getTypePointer` by structure (a new pointer
  type is appended). `typeOrder` is ported for the base, pointer and array
  lattice; the exporter supplies it for any pair of enum, structure, union or
  code types of equal sub-metatype and size.
* **Per-function authority.** The worker answers `o` (it casts; plus the
  pointer-size warnings `checkPointerIssues` would have added, which C++
  attaches to the function before the header comments are read) or `n`. On `n`,
  `ActionSetCasts` runs at that point and the IR says `casts pending = 0`,
  which is the previous default. A function is declined for: a union or
  `needsResolution` type, a pointer with an address space, a constant retyped
  to something whose spelling needs a string or code-pointer probe, a
  `PTRADD` that no longer fits (`opUndoPtradd`), a `PTRSUB` misfit that is not
  an offset-0 `COPY`, a `PTRSUB #0` inserted after an op (its own output
  token), a cast around the output of a for-loop initializer or iterator,
  a type order the exporter did not supply, a node the renderer refuses,
  `ROMWRIGHT_RUST_EXPRESSIONS` other than `on`, `nocasts` and the other
  options the renderer does not model. The reasons are counted in
  `ROMWRIGHT_RUST_CASTS_LOG`.
* **What stayed in C++, and why** (limits): the for-loop analysis
  (`romwrightLoopFinalize`, stage 3) runs on the p-code before the casts. The
  worker's semantic IR passes (`func_ir`: `additive_inverse`,
  `canonical_helpers`, type evidence) and the C spelling pass read the encoded
  document, which for a function the worker casts has no casts, so the worker
  gives it back what the casts changed: `FunctionIr::cast_types` (the type names
  the C spelling pass needs) and the CAST operations themselves
  (`casts::IrEdit`, `doc.rs apply_cast_edits`; one op and one value per
  `castInput`/`castOutput`, the replacement of an existing cast). Without the
  operations the evidence differs where a cast marks a type change (rc `_d2b`:
  a `SUBPIECE` of a `double` was recovered as an integer intrinsic and the C did
  not compile); with them the op and evidence counts equal the C++ path's.

**Compiler awareness.** The compiler layer keys one rule through this work:
`mwcc-void-pointer-arithmetic` (`compiler_rules/mwcc.json`, kind `flag`, `on`
for the MWCC family). The export's conform pass (`emit_m2c/conform.rs`) puts a
`(char *)` cast on a *global* the project declares `void *` when it is added to
or subtracted from (MWCC compiles the unit as C++, where that is an error). It
lives in the conform pass and not in the cast pass because the failing operands
are context-declared `void *` globals (`edit_info`, `nowMonster`) that the
decompiler types as `int`: no cast decision of the decompiler is involved.
Parameters and locals are deliberately left alone: the decompiler's `param_1 + 1`
on a `void *` counts elements of the type it inferred (a `PTRADD` of stride 0xac
prints as `+ 1`), so `(char *)param_1 + 1` would be a different address; the first
version of the rule cast them too and m22-002 ee-gcc lost an exact match
(`004c3d30`). A first version also cast decompiler-typed `void *` operands in
`printc/casts.rs`; it measured nothing beyond the conform rule on dc, dk and p4 and
was removed. No compiler name is in the cast pass.

**Alternatives rejected.**
* *Ship the typed p-code of the whole function and run SetCasts on real ops in
  Rust.* Needs a Rust `Funcdata`/`PcodeOp`/`Varnode` mirror with def-use
  chains. The expression tree already is the unit casts act on (casts never
  cross a statement), so the mirror would be larger and no more faithful.
* *Hand over `ActionInferTypes` first.* See 2b.
* *Per-slot query "which cast here?".* One round trip per op slot; the worker
  has the tree anyway.
* *Run `ActionSetCasts` in C++ and send its result.* That is what the
  `ROMWRIGHT_NATIVE_CASTS=1` path is; it keeps every decision in C++.

**Why the local-type requirements stay in C++.** `getInputLocal`/`getOutputLocal`
read the function prototype, the call specifications and the address space
(`TypeOpCall`, `TypeOpReturn`, `TypeOpCallother`, `TypeOpIndirect`). They are
exported as data per slot; the *dynamic* methods (`getInputCast`,
`getOutputToken`) are the Rust port. This is the split Ghidra itself uses
(static per-opcode requirement vs. per-op decision) and keeps the port off
the `FuncProto` machinery, which belongs to stages 4-6.

## 4. 2b (type inference): what it takes, and the decision

`ActionInferTypes::apply` (`coreaction.cc`) is a worklist propagation over
`TypeOp::propagateType` for all ~70 opcodes, over `TypeFactory`
(`getTypePointer`, `getTypeArray`, struct `getSubType`/`downChain`,
`resolveInFlow`), seeded from locked types and symbol types, run to a fixpoint
every `mainloop` iteration (the loop runs the whole rule pool in between; the
rules branch on the result, e.g. `RulePtrArith`, `RulePushPtr`, `RuleStructOffset0`,
`RulePtraddUndo`). The stage-1 pattern (a per-function query answered by Rust)
applies, but the query payload is the typed data-flow graph *every iteration*:
every varnode (size, flags, locked type, symbol type, def) and op, and the answer
a type per varnode. The port is `type.cc`'s lattice (`compare`, struct/array/ptr
`getSubType`, `downChain`), `propagateType` for each opcode, and the
type-recovery of `ScopeLocal` (stack/global symbol types), plus keeping the
C++ `Datatype` objects the rules call into in sync with Rust's answers
(the rules call `getHigh()->getType()`, `Varnode::updateType`,
`TypeFactory`). That is the size of stage 4's rule port; it also changes what
the rules do (they read types), so it cannot be gated by a byte-identical
printed-token differential until the whole typed graph is exact.

The plan for 2b is therefore: land 2a; measure the inference workload
(`ActionInferTypes` invocations per function, varnodes typed, iterations) so
the cost of the per-iteration query is a number, not a guess; and keep
`ActionInferTypes` in C++ as the default with the struct layer feeding it types
(unchanged). The measured reason is in "Measured". What 2a *does* move is the
second half of "types": every place the types are *used* to print.

## 5. Wire change: IR version 6

See [printer-ir.md](printer-ir.md#pre-cast-trees-version-6-default). The
header gains `casts pending`; the type table gains per-type sub-metatype,
typedef link, pointer word size and space, alignment size, variable-length
flag, then `getSizeOfInt`, the core-type seeds and the `typeOrder` pairs; a
pending function's print trees are pre-cast (nodes carry types, flags and the
local requirement types). The version is checked on both sides
(`printer IR version 6`).

## 6. Switches that restore the C++ path

* `ROMWRIGHT_NATIVE_CASTS=1` (read by `ghidra_opt`): `ActionSetCasts` stays in
  the pipeline for every function and the IR says `casts pending = 0`: the
  previous default byte for byte (the **off arm** of every differential). The
  stock structuring path (`ROMWRIGHT_NATIVE_STRUCTURE=1`, the printer
  differential's reference) always casts in C++.
* `ROMWRIGHT_RUST_CASTS=off|on|verify` (read by the worker, default `on`):
  `off` declines every function (the same as the C++ answer `n`); `verify` has
  the decompiler cast and compares, per statement, the worker's tree with
  `ActionSetCasts`' (`ROMWRIGHT_RUST_CASTS_LOG`).
* `ROMWRIGHT_COMPILER_RULES_DISABLE=mwcc-void-pointer-arithmetic` switches the
  compiler rule off (the `off` and `parity` arms of the gates).
* `ROMWRIGHT_RUST_CASTS_AGGREGATE=off` prints constants of an aggregate type as
  `(unsigned char [8])0x...` again; `ROMWRIGHT_RUST_CASTS_CALLS=cast` reads the
  prototypes of undeclared callees off the calls as cast, as the C++ path did.

## 7. Differentials and gates

1. **Verify mode** (`ROMWRIGHT_RUST_CASTS=verify`) on the standard
   printer-differential sample (`benchmarks/printer_diff.py` images + the x86
   libc sample): zero statements differing, every diff classified
   (`reason` histogram).
2. **Printer differential**: default (Rust casts) against
   `ROMWRIGHT_NATIVE_CASTS=1`, tokens byte for byte on the same Funcdata
   population; diffs are classified (cast `opref` markup only, `varref`, text).
3. **Paired C text** across the m22-002 and m22-003 samples, off arm
   (`ROMWRIGHT_NATIVE_CASTS=1`) against default: better/worse/same by
   compile and match percent.
4. Gates, one build: m21-001, m22-002 (3 lanes), m22-003 (7 lanes),
   `ps2_decompile_success` over the wave sample, the printer differential,
   the ownership metric (`docs/ownership.md`).
5. Quality pass after parity, each fix measured alone on the lanes and m22-002,
   kept only when no exact or compiled function is lost.

## 8. Order of sub-stages

1. Wire: exporter pre-cast data + `casts_done`, worker decode (v6).
2. `printc/casts.rs`: strategy, per-opcode methods, the SetCasts driver,
   `TypeFactory` subset; fallback reasons.
3. Query + `romwright_casts.hh`; verify mode; fix until verify is clean on the
   sample.
4. Differentials and gates for 2a.
5. Compiler-aware rules and the placeholder/pointer-field fixes (quality pass).
6. 2b: measurement only (or what passes the gates), documented.

## 9. Result (2026-10-13)

One build per gate on `nih-vps-u`: `ghidra_opt` sha256
`ffdd5e57e104fc8383e52a161eacddaa3f8ed39e192afeef7d0e31b6420e8890` (IR version 6; was
`4561fbea…`, IR version 5). The worker and CLI of the gates are the tree's
default build; the MWCC gates (m22-002 three lanes, dc, dk, p4) were re-run on
the final one, which differs from the earlier build of the day in the removal of
the cast pass's `void *` arm and in the conform rule being limited to globals
(both inactive outside MWCC-stamped programs; dc, dk and p4 are identical on both
builds). Arms:
**off** = `ROMWRIGHT_NATIVE_CASTS=1` with the compiler rule disabled (the previous
default); **default**; **parity** = the worker's casts with the compiler rule
disabled (the port alone). Every arm has its own fresh import or prepared work
directory, `ROMWRIGHT_NO_IMPORT_CACHE=1`, `ROMWRIGHT_NO_FACT_PACK=1`. Report:
`benchmarks/reports/stage2_gates_20261013.{json,md}` (`benchmarks/stage2_report.py`).
exact / compiled / mean %; paired = better / worse / same by match percent.

| gate | off | default | paired | parity (port alone) |
|---|---|---|---|---|
| m22-002 MWCC, seed 20261010 | 55 / 193 / 76.976 | 55 / 193 / 76.968 | 0 / 1 / 199 | same as default |
| m22-002 MWCC, seed 20261011 | 57 / 194 / 78.321 | 57 / 194 / 78.316 | 0 / 1 / 199 | same as default |
| m22-002 ee-gcc (fresh work dir per arm) | 106 / 197 / 86.403 | 106 / 197 / 86.403 | 0 / 0 / 200 | same as default |
| dds | 61 / 196 / 76.818 | 61 / 196 / 76.818 | 0 / 0 / 200 | |
| rc | 26 / 199 / 68.130 | 26 / 199 / 68.113 | 0 / 1 / 199 | |
| p4 | 60 / 193 / 79.129 | 60 / 193 / 79.400 | 2 / 0 / 198 | same as default |
| gh (harness clone) | 78 / 199 / 82.057 | 78 / 199 / 82.119 | 1 / 0 / 199 | |
| ff | 20 / 145 / 49.294 | 20 / 145 / 49.350 | 1 / 0 / 199 | |
| dc | 36 / 166 / 62.625 | **38 / 176 / 66.605** | 17 / 0 / 183 | 36 / 166 / 63.314 (7 / 0 / 193) |
| dk | 28 / 169 / 67.360 | **29 / 176 / 70.804** | 15 / 0 / 185 | 28 / 169 / 68.054 (8 / 0 / 192) |

No gate lost an exact match or a compiled function. m22-002 ee-gcc needs a note: the first run of the gate ran lane 3 after lanes 1 and 2 in one work directory per arm, which is order-dependent (the `off` arm read 106 / 199 / 87.149, the known shared-work-directory value, against the fresh 106 / 197 / 86.403) and made the default look like a loss of 2 compiled functions. With a brand-new import and work directory per arm (`stage2_followup_20261013.md`: off, parity, default) all three arms are 106 / 197 / 86.403 and the 200 functions are identical. The compiler rule's first version (which also cast parameters and locals) did lose the exact match of `004c3d30` there; the version shipped casts globals only. gh: the stage 2 gate run read 196 compiled in both arms because the lane was run on the pristine repo copy `~/runs/Ps2Lanes/repos/gh`, whose own build matches 6,250 functions (the harness's own clone matches 7,367 and is what the 199-compiled baselines were measured on): a different 200-function sample, not a regression. On the harness clone and a fresh import per arm the off arm reproduces the baseline exactly (78 / 199 / 82.057) and the default is 78 / 199 / 82.119 (1 better, 0 worse; `stage2_followup_20261013.md`). The other lanes' off arms on their pristine copies reproduced their baselines, so only gh was affected.

* **The port alone is parity or better.** The parity arm differs from `off`
  only through the worker's casts: m22-002 and the other lanes lose nothing; dc
  gains 7 functions (+0.7 mean) and dk 8 (+0.7), p4 2. The gain is the callee
  prototypes: an undeclared callee's prototype is read off its calls; the C++
  path read them off the calls *as cast* (constants retyped to what the callee's
  parameter wants, so a parameter became `short` where the decompiler had inferred
  `int`), the port reads them off the uncast calls. The two worse functions on
  m22-002 / rc are the same effect the other way (`unsigned short` against
  `short` in `001d94d0`; rc `__fixunsdfdi`). `ROMWRIGHT_RUST_CASTS_CALLS=cast`
  restores the C++ reading.
* **The compiler rule** `mwcc-void-pointer-arithmetic` (`on`) is what takes dc
  from 166 to 176 compiled and dk from 169 to 176: the compile-failure class
  `illegal or unknown type name` (MWCC rejecting arithmetic on a context-declared
  `void *`) goes from dc 11 and dk 8 to 0. The same rule had no effect on p4 or
  m22-002.
* **Printer differential** (`benchmarks/printer_diff.py`, the stock path, which
  always casts in C++): 1,800 of 1,800 functions identical, 0 errors
  (`printer_diff_stage2.json`).
* **Cast differential** (`benchmarks/cast_diff.py`, default against
  `ROMWRIGHT_NATIVE_CASTS=1`, the C text of the 8 sample images x 200 functions,
  `cast_diff_stage2.json`): **1,588 of 1,600 identical**. The 12 others:
  five psv and one dungeon function print an aggregate constant bare
  (`*(int *)(0x0 + 0x4)` for `(unsigned char [16])0x0 + (unsigned char [16])0x4`,
  `ConstKind::Bare`, a declared quality change that never compiled before);
  three dungeon functions and one gc function spell a cast type the document does
  not carry (`ulong`, `longlong`) where the decompiler spells `unsigned long long`
  (`FunctionIr::cast_types`: the spelling pass reads types by id, the document
  lists only variable and prototype types); two x360 functions are in the
  declined set (`const-retype-float`), where `ActionSetCasts` runs *after* the
  exporter's probes and prints a store as `char *` where the earlier run had
  `unsigned char *` (PrintC's probes update lazily evaluated `HighVariable` types:
  the order dependence the pre-probe fact capture exists to avoid, and cannot for
  a function the worker declines).
* **Declines**: 15 of 1,600 sampled functions (1%): dungeon 3, psv 10, x360 2,
  for `cast:const-retype-string-or-code`/`-float` and `cast:address-of`.
* **`ps2_decompile_success`**: the full set (11 projects, 10,342 addresses, the wave's
  own samples, a copy of each wave project, default build): **10,338 of 10,342**, the
  baseline's count; the four failures are the same addresses as before (two 60 s
  deadlines, Dark Cloud `01db08a0` and Persona 4 `002be530`, and two `Backward
  normalization not implemented`, R&C `00239780` and PAL `0023aa38`).
  `stage2_followup_20261013.md`. The earlier off/default comparison on 7 freshly
  imported games (6,563 addresses) is 6,560 in both arms.
* **m21-001**: PASS (7 images scored, 0 known timeouts, 0 skipped).
* **Ownership** (`benchmarks/types_port_measure.py`, the 8 printer-differential
  images x 200 functions, `types_port_measure_stage2.json`): the worker decided the
  casts of 1,585 of 1,600 functions (99.1%); its pass printed 12,622 cast
  operators, the decompiler 607 (in the 15 declined functions): **95.4% of
  printed cast operators are the worker's**. `PTRSUB` insertion after an op
  (a decline) happened 0 times.
* **Compile-failure classes** (the seven m22-003 lanes, the first diagnostic of
  every function that did not compile, `tests/m22-003/classes.py`), off -> default:
  135 -> 118 functions that do not compile. `illegal or unknown type name`
  (MWCC rejecting arithmetic on a `void *`) **19 -> 1** (dc 11 -> 0, dk 8 -> 0);
  `call does not match prototype` 4 -> 5; unchanged: `type mismatch` 43,
  `member access on a type the context lacks` 35, `syntax error` (the
  `undefinedN` placeholders) 20, `undeclared identifier` 9. The counts are of
  the 200-function samples of this run, not the ranked totals of
  `m22-003_failure_classes.md` (46 / 36 / 20 / 19 there).

## 10. Measured: what 2b costs, and why `ActionInferTypes` stays in C++

`RomwrightInferTypes` (an `ActionInferTypes` wrapper active only with
`ROMWRIGHT_INFER_LOG`) counted the calls and their time on the 8 sample images
x 200 functions (`types_port_measure_stage2.json`): the mainloop runs the action
1.8 to 3.1 times per function (maximum 12) over a data-flow graph of 68 to 610
alive ops (119 to 1,135 varnodes) on average, **0.1% to 2.5% of the decompile time**
(dungeon, the largest functions, is the 2.5%). So a type query per mainloop
iteration (stage 1's pattern) would add 2 to 3 round trips per function carrying
the typed graph, to move a part that costs almost nothing in C++, and the port is the
size of stage 4's rule port (the lattice, `propagateType` for ~70 opcodes,
`TypeFactory`, the symbol-driven seeding, and the rules read the result every
iteration, so only a byte-identical typed graph can gate it). The worker already has
a solver (`types_infer.rs`) with a different job (evidence for the printed names and
the prototype merge). Decision: `ActionInferTypes` stays in C++; the cast handoff (2a)
already moves the places the types are *used* to print. 2b is not attempted.

## 11. Limits

* **For-loop statements.** The loop analysis (since stage 3, 2026-10-14, the
  worker's `printc/merge/loops.rs`; `romwrightLoopFinalize` for a declined
  function) runs on the p-code before the casts. A cast around the output of an initializer
  or iterator makes the *cast* the loop's statement; the pass prints that
  statement, which is what the C++ path prints in the cases measured, but the
  C++ analysis, run after the casts, could in principle choose differently.
* **Declined functions** (1% of the sample) run `ActionSetCasts` after the
  exporter's probes and are not guaranteed to equal the previous default.
* **The semantic IR and the spelling pass read the document the decompiler
  encodes, which has no casts** for a function the worker casts. The worker
  gives them back the types (`cast_types`) and the CAST operations (`IrEdit`);
  the ids of the new values follow the C++ order only because the edits are
  sorted into block order, and a type the document does not list can still
  be spelled differently (the `ulong` cases above).
* **Prototypes of undeclared callees** are read off the uncast calls (default);
  the other reading is `ROMWRIGHT_RUST_CASTS_CALLS=cast`.
* **Not addressed**: pointer-typed struct fields (`subtype.rs`), the `undefinedN`
  placeholder syntax errors (`extern undefined6 _530;`: a declaration in
  `emit_m2c/globals.rs`, and the uses would need an array-typed global), the
  missing-member class (ff, 25: Ghidra's synthetic storage members on a global
  the context declares with a real type), array-cast type mismatches (ff 22:
  `(unsigned char *)0x3f333333...` assigned to a `float`-sized local is printed by
  the export's declaration typing, not by a cast decision; `ConstKind::Bare`
  changes the declined-function cases only and moved no lane).
* **2b** is not ported; the C++ inference runs unchanged.
* The cast pass reads `ROMWRIGHT_RUST_CASTS_AGGREGATE` from the environment of
  the worker process.


## 12. Stage 4: the type decisions that fix the failing C (2026-10-14, Stage4Types)

**Question.** Port `ActionInferTypes` (2b), a type mirror and a replay, "only where it buys C-output quality". **Answer: it
buys none of the classes that still failed.** The 38 functions of the seven m22-003 lanes that did not compile after Upgrade
round 1 were traced one by one (Section 12.1): in every one the types the decompiler inferred were not what the compiler
rejected. The compiler rejected what the Rust layers did with them: a cast spelled `float **` for a pointer to
`float [4]`, a `return v;` kept in a function the project declares `void`, a pointer in a `&`, a structure passed as the
integer or byte block the decompiler saw, a call one argument short of its declaration. Every one of those is decided
downstream of the cast query (`conform` in `romwright-core/src/emit_m2c/conform.rs`, the dependency pass, and the worker's
cast pass), so none needs a `Funcdata` mirror and none needs C++ to replay a decision: **`ghidra_opt` is unchanged (sha256
`486ace43...`, IR v7), 2b stays in C++, and the new decisions are the Rust side's.** `ROMWRIGHT_NATIVE_TYPES=1` is the off
switch (all of them off, the previous output byte for byte); each rule also has its own `=off` switch.

### 12.1 Failures before, by cause (the first diagnostic of each function that did not compile; `m22-003` lanes, 200 functions each)

| cause | functions | owner after tracing |
|---|---|---|
| a local array passed for a `sceVu0FMATRIX` (`float [4][4]`) parameter, cast `(float **)` | dk 4, dc 5 | `conform`: the pointer-to-array was spelled as a pointer to the decayed element; the type had no element count |
| `void` function that returns a value | dc 3 | `conform`: the head took the project's `void`, the body kept `return v;` |
| a pointer in `&`, `|`, `-`: `lcp & 0xf` (a `void *` object), `in_hi \| (char *)&t`, `(int)p - (char *)&t` | ff 2, dk 1 | `conform`: the declaration makes an object a pointer the decompiler printed as an integer |
| a structure passed by value (`mgRect<int>` as `unsigned char [16]`, `FclVec2` as `0x42ce0000`, a `float` for a structure) | p4 3, dc 1 | `conform`: the call passes the registers or bytes, not the structure |
| fewer arguments than the declaration takes (a register the decompiler took for dead at the call) | p4 1, dc 1 | `conform` |
| `(undefined5 **)` and `(int7)` (`CONCAT71`) | dc 1, dk 2 | `conform::spelled`, `dependencies.rs`: widths with no C type |
| a `void *` object dereferenced or indexed | dk 1 | `conform` |
| `(char **)0x0` passed where the project declares `char` | dk 1 | the worker's cast pass: a zero constant keeps the pointer type of the callee's *inferred* parameter |
| `__sinit_*.cpp` heads | dk 2 | the failure-class regex reads a function name as a member access (not a compile failure of the text) |
| the unit's post-processing rejects the object | dc 1 | lane harness |
| `stack0x00000000` as an address | p4 1 | stack symbol layout (a later slice) |
| `_vrnext(in_vuR)` assigned to a byte array | ff 1 | an intrinsic with a 16-byte result (no C declaration can return it) |
| `LoadScript(now_script_file.whole)`, a union member passed as `char *` | dc 1 | `conform` does not type members of the storage unions |
| a self-recursive call one argument short, `LoadMDSFile` through a mangled name the context does not link | dc 1, dk 1 | callee identity (name to declaration), not inference |
| `float` against a declared aggregate in arithmetic | p4 1 | not traced beyond the diagnostic |
| `no candidate` | gh 1 | the exporter (a function it prints nothing for) |

Not stage 4 and not changed: pointer evidence for struct fields (below), VU intrinsic result types, struct returned by value.

### 12.2 What was built

All Rust, no C++ edit. Rules in `conform.rs` run on the printed function against the project's declarations (tree-sitter), as the
existing rules do; the worker's rule is in `printc/casts.rs`.

* `ROMWRIGHT_EXPORT_MATRIX_CASTS`: `Ty::Array` carries its count; a pointer to an array is spelled `float (*)[4]`.
* `ROMWRIGHT_EXPORT_VOID_RETURNS`: `return v;` becomes `return;` (`{ f(x); return; }` when the value has an effect) in a function
  whose declaration the project spells `void`.
* `ROMWRIGHT_EXPORT_POINTER_OPERANDS`: a pointer operand of `& | ^ * / % << >>` and the right operand of `integer - pointer` is cast
  to `unsigned int`; pointer minus pointer and pointer minus integer are C and are left.
* `ROMWRIGHT_EXPORT_AGGREGATE_ARGS`: an argument for a by-value structure parameter is read as that structure: `(*(T *)buf)` of a
  byte array, `(*(T *)&v)` of an lvalue, a temporary (`unsigned long long romwright_aggN;`) for a value with no address.
* `ROMWRIGHT_EXPORT_MISSING_ARGS`: trailing arguments the declaration takes and the decompiler did not recover are passed as
  `/* unrecovered */ 0` (`0.0f` for a float), for integer, pointer and float parameters only.
* `ROMWRIGHT_EXPORT_ODD_POINTEES` (`undefined3/5/6/7` behind a pointer is `void`), `ROMWRIGHT_EXPORT_ODD_PIECES` (`int7`, `uint3`... are
  the next wider integer, and `CONCAT71` and the other odd-width `PIECE`s are rendered: the lower piece is masked to its width).
* `ROMWRIGHT_EXPORT_VOID_POINTEES`: an object the project declares `void *` that the decompiler printed as `int *` is cast where it
  is dereferenced or indexed.
* Worker: `ROMWRIGHT_RUST_TYPES_NULL_ARGS`: a null pointer constant that is an argument of a call prints as `0x0`, not `(char **)0x0`.

Tried and removed: a worker cast rule for a pointer in an integer operator (`CastRules::integer_operands`): it fired on no function
of the failing set, because the pointer type came from the context's declaration, which only `conform` reads.

Unit tests: `conform` 27 (all green on the host build), the worker `printc` tests 79.

### 12.3 Why no mirror and no replay, and what 2b costs

A mirror pays when a decision must change data the *next C++ action* reads (stage 3's merges feed names, prototypes and the cast
query). None of these does: the facts they decide from (the declarations of the project, the printed expression's types) exist
only after the cast query, and nothing in C++ reads their result. A replay of, say, a retyped local would also have to
reproduce the cast pass on the new type, which is what the worker already does at print time.

`ActionInferTypes` cost (`benchmarks/types_port_measure.py`, 8 images x 200 functions, `types_port_measure_stage4.json`):
1.8 to 3.1 calls per function (maximum 12) over 68 to 610 alive ops, **1.25 s of 149.6 s of decompile wall time (0.8%; 0.1% to
3.6% per image, the Dungeon image the largest)**. The worker decided the casts of 1,585 of 1,600 functions (the same 15 declined).

### 12.4 Pointer evidence for struct fields

Measured on the dk lane's 200 functions (`benchmarks/struct_pointer_fields.py`, default build): 9 structs printed, 71 fields, one
pointer field (a `void *`), 3 non-pointer fields read through a pointer cast. This slice changed nothing in the struct layer: the 73-field
class of the Upgrade 1 measurement needs evidence from the decompiled body (a loaded value used as a base after
arithmetic), which `subtype.rs` collects flow-insensitively by register; retyping fields has lost functions before (section 6 of
`structs.md`), and the failing C of the lanes has no field-type cause. Left as it was.

### 12.5 Gates (one host, nih-vps-u; one release build; `ghidra_opt` sha256 `486ace43...`; a fresh import and a restored work directory and repo per arm; `ROMWRIGHT_NO_IMPORT_CACHE=1`, `ROMWRIGHT_NO_FACT_PACK=1`)

off = `ROMWRIGHT_NATIVE_TYPES=1` (wrapper binary per arm: the m22-002 harness drops `ROMWRIGHT_*`; the off arms reproduce the Stage 3 gate numbers exactly,
which is the proof the wrapper acts; the default arms differ from them on the lanes the rules touch). exact / compiled / mean %; paired better / worse / same:

| gate | off | default | paired |
|---|---|---|---|
| m22-002 MWCC 20261010 | 55 / 193 / 76.968 | 55 / 195 / 77.324 | 2 / 0 / 198 |
| m22-002 MWCC 20261011 | 57 / 194 / 78.316 | 57 / 194 / 78.316 | 0 / 0 / 200 |
| m22-002 ee-gcc | 106 / 197 / 86.403 | 106 / 197 / 86.622 | 1 / 0 / 199 |
| dds | 61 / 200 / 77.224 | 61 / 200 / 77.224 | 0 / 0 / 200 |
| rc | 26 / 200 / 68.158 | 26 / 200 / 68.158 | 0 / 0 / 200 |
| p4 | 60 / 193 / 79.400 | 60 / 198 / 80.732 | 5 / 0 / 195 |
| gh (harness clone) | 78 / 199 / 82.119 | 78 / 199 / 82.119 | 0 / 0 / 200 |
| ff | 21 / 195 / 61.753 | 21 / 199 / 62.913 | 4 / 1 / 195 |
| dc | 38 / 186 / 69.844 | 41 / 197 / 73.653 | 11 / 0 / 189 |
| dk | 29 / 189 / 75.561 | 29 / 197 / 78.277 | 8 / 0 / 192 |

**No exact and no compiled function is lost on any gate.** Gained: dc 3 exact and 11 compiled, dk 8, p4 5, ff 4, m22-002 MWCC 20261010 2 compiled.
The one function that is worse by percent and still compiles is ff `ZushiBonjiAfterDisp` (65.6 to 63.8): its `CONCAT17` was an unsupported
intrinsic (an implicit `int` function, which compiled as a call to an undefined symbol); it is now the 64-bit `romwright_piece_1_7`, which is the
right value and the right instruction count for it, and scores lower only because the old text matched some bytes by accident.
m21-001 PASS in both arms; **printer differential 1,800 of 1,800 identical** (default build); decompile success 7,448 of 7,500 in both arms (the
same 52 failures as Stage 3). Compile failures of the seven m22-003 samples (the first diagnostic of every function that did not compile,
`tests/m22-003/classes.py`), off -> default: type mismatch 26 -> 4, call does not match prototype 3 -> 1, undeclared identifier 4 -> 1, illegal type
name 1 -> 0, member access 2 -> 2 (`__sinit_*` heads), unit post-processing 1 -> 1; **37 -> 9 failing functions** (plus gh's `no candidate`, which the classes do not count), and compiled functions across the seven lanes 1,362 -> 1,390
of 1,400. Report `benchmarks/reports/stage4_gates_20261015.{json,md}` (`benchmarks/stage4_report.py`); host scripts and per-arm outputs in
`~/runs/Stage4Types/{out,logs}`.

### 12.6 Limits

* Still not compiling (10 functions, gh's included): `SetBrother` (a self-recursive call the decompiler passes one argument short of the method's two: the declaration is
  not linked to the mangled name), `ReloadMapScript` (a storage-union member, `now_script_file.whole`, passed as `char *`: `conform` does not type members),
  `FishingLoad` (`LoadMDSFile_..._char_char` has no declaration under that name), `GetSmokePartAddr` (a 16-byte intrinsic result), p4 `stack0x00000000` and a float
  against a declared aggregate, the two `__sinit_*` heads, `ChangeSetUnit`, gh `cEvent__isPlaying`.
* `MonsterNamePosSet` and the shape `(int)(((int)(x * 7) << 0x21) >> 0x21)` print identically on the C++ cast path: a Ghidra printing property of a 64-bit shift pair,
  not decided here (it now compiles through the `void *` rule; it is not exact).
* The rules are text rules over the printed function and the project's declarations: they read only declarations, and only change a call, a head or an operand
  that the project's compiler rejects, except `ROMWRIGHT_EXPORT_ODD_PIECES` and `ROMWRIGHT_RUST_TYPES_NULL_ARGS`, which also change text that compiled
  (`CONCAT17` above; a `(void *)0x0` argument printed `0x0`). A struct passed in registers is rebuilt through a temporary the width of one register: a structure wider than
  8 bytes with no address in the call is not rebuilt (the argument stays as it was).
* Missing arguments are zeros: the call compiles and the retail register is not recovered; it is marked, and no exact match depends on it in the gates.
* Pointer evidence for struct fields, struct returns and VU intrinsic result types are unchanged (Section 12.4); stack/global symbol layout is section 13.


## 13. Stack and global symbol layout (2026-10-15, SymbolLayout)

Stage 3's quality pass left four symptoms that no merge decision causes: partial members (`local_10._2_2_`, `DAT_00252750._4_4_`),
`stack0x...` as an address or an lvalue, `undefinedN` of a width no C type has, and `_NAME` uses of a symbol the access does not fit.
They come from how the stack frame and the global objects are laid out into symbols. This section traces each to its decision and
changes five of them: two in the worker (the global objects), three in `ghidra_opt` (the frame), plus a fix for the density of the first.
`ROMWRIGHT_NATIVE_LAYOUT=1` turns all of them off (Stage 4's output byte for byte, proved on the wave and on every gate below); each has its own
`=off` switch.

### 13.1 What the PS2 wave prints, by symptom and cause

`benchmarks/symbol_layout_wave.py` decompiles the 7,409 functions of the PS2 wave (the 8 imported images of `ps2_decompile_success`, 7,500
addresses; 91 do not decompile in any arm, as in section 10 of `merge-port.md`) with the worker alone and counts the functions that print each
symptom in the decompiler's own text (before the export layer rewrites any of it). Stage 4's build reproduces Stage 3's counts exactly
(571 / 63 / 17, 13,286 partial members).

| symptom | functions | what it is | decision |
|---|---|---|---|
| partial member of a **global** | 370 | an ELF object wider than a word is `undefined1[N]`, so every word read prints as a member of a byte array (`key_now._4_4_`); and the access rows the importer stores *inside* the object are symbols of their own, so the same object prints under two names (`key_now._4_4_`, `DAT_00252750._4_4_`) according to which address the decompiler asked first (the cache keeps what it has) | `ProgramProvider`'s answer to `getMappedSymbols`: `native/store.rs` writes both kinds of data row, `provider.rs` answers the nearest row at or before the address |
| partial member of a **stack local** | 107 | a pointer into the frame is an *open* range typed by what it points at; the aligned-down address of an unaligned load or store (`sdl`/`sdr`, `ldl`/`ldr`: the pointer is `sp + c + 7`) types an `ulong` range at an odd offset, which swallows the aligned accesses beside it (`MapState::gatherOpen`, then `RangeHint::merge` concedes a size that is no power of two to a byte array) | `ScopeLocal::restructure` (`varmap.cc`) |
| partial member of a **register value** | 141 | a 128-bit `lq`/MMI value is `unsigned char [16]` and its words print as members (`auVar8._0_4_`) | not layout: the type of a 16-byte register value |
| `stack0x...` | 63 | 47: the address of a parameter-area location (`GetOsdConfigParam(&stack0x00000000)`): `ActionInputPrototype` clears the `fake_input` symbols before `ActionNameVars::linkSymbols`, and `linkSymbolReference` looks a symbol up *without a use point*, which finds none of the use-limited symbols `linkSymbol` makes for the same varnodes. 16: the unaligned-store idiom above leaves the aligned 8-byte accesses without a symbol (`adjustFit` refuses an entry that overlaps the byte array) | `ActionNameVars::linkSymbols`, `Funcdata::linkSymbolReference`; `restructure` |
| `_NAME` (mismatch) | 31 | an 8-byte store of a `PIECE` into a stack location whose symbols are two 4-byte ones, and the same idiom | `MapState::gatherVarnodes` (a PIECE is two COPYs, by design), the idiom |
| `undefinedN` (3, 5, 6, 7) | 17 | 6- and 7-byte symbols made by the idiom's partial accesses; `CONCAT13(.., (undefined3)DAT_..)` of a word written by bytes | the idiom; byte writes of a word (not changed) |

Two partial members of a parameter (a stack-passed `double` typed from a floating register by the prototype) are not counted above and were not the target.

### 13.2 What was built

**Worker** (`crates/romwright-worker/src/layout.rs`; three hook sites in `provider.rs`; the element size in `wire::encode_array_type`). The provider reads the
importer's data rows and answers the decompiler's symbol queries from them. `layout::globals` decides, per ELF object, from the access rows inside it (the
access at the object's own address is not stored: the row there is the object's), what it is made of:

* `ROMWRIGHT_LAYOUT_ELEMENTS`: the element `W` (1, 2, 4, 8) that most of the accesses are exactly one of, no wider than the narrowest access (an access inside an
  element would print as a member of it, which C has no spelling for), dividing the object's size; narrower elements win a tie. The object becomes
  `undefinedW[N/W]`: `key_now._4_4_` is `key_now[1]`, a byte table is indexed (`adpcm_map[0x42c]`), and the accesses that are wider or unaligned print as members of the
  whole array (`_8_8_`), which `emit_m2c/locals.rs` already spells. At least half of the elements must be touched (`ROMWRIGHT_LAYOUT_DENSITY=N`, default 2, 0 = no test): the first
  version retyped a table of structures read at three of its fields (`NameRegistFont_Table`, 60 bytes) and turned `*(int *)(table + i * 0xc)` into `table[i * 3]`, which the retail compile
  does not match (dk, dc, ff lost 0.1-0.15 mean percent on it).
* `ROMWRIGHT_LAYOUT_CONTAIN`: the access rows inside a retyped object are evidence, not symbols: the address is the object.

An object is left as it was when it has no access inside it, is a string, is a function entry (an object row on one gave the function's name to a second, data symbol: the
decompile-success gate found `conflicting storage views for MajinBeemProcess` in the export of one function), has its address taken (a `DATA` reference lands in it: a pointer
to it would be an `unsigned int *` where the callee takes a `char *`, which MWCC rejects: the first version without this test lost 4 compiled functions on dc), or when most
accesses do not fit any element.

**`ghidra_opt`** (`native/romwright_layout.hh`, 20 inserted lines of patch in `varmap.cc`, `coreaction.cc`/`.hh` and `funcdata.hh`; `ghidra_opt` sha256 `4532792dc965f05c67f12d89450bc032a30fdfe85c639b4f0519d1eb0032938c`, IR
version 7 unchanged). Stack layout is decided inside `mainloop` (`ScopeLocal::restructure` ran 8 to 16 times per function in the traces) from hints, one per stack varnode and
one per pointer into the frame, and read by the rules that follow. A Rust decision would need a mirror of `MapState`/`RangeHint` and a replay of the symbol table at each of
those calls, for decisions that are one predicate each; the rules are C++ hooks with switches, and the symbol table, the naming (the worker still composes the names of the
symbols this makes) and the stage 3 replay are untouched.

* `ROMWRIGHT_LAYOUT_STACK_REFS`: `ActionNameVars::linkSymbols` links the stack addresses the first visit found no symbol for after every varnode has its symbol
  (`romwrightStackReference`): the symbol covering the address ignoring where it is in use, or a new one as wide as the widest value stored there. `&stack0x00000000` is `&in_stack_00000000`.
* `ROMWRIGHT_LAYOUT_STACK_FOLD`: the entry stack pointer is aligned, so `(sp + c) & 7` is `c & 7` (`RuleRomwrightStackAlign`: MIPS languages only, masks of up to 3 bits,
  offsets relative to the entry stack pointer). The aligned-down address arithmetic of `sdl`/`sdr` and its relatives becomes a constant and the access a plain store of the doubleword it
  always was (God Hand `FUN_00179220`: sixteen lines of mask arithmetic and four `stack0x` lvalues become sixteen stores to `asStack_50[0..15]`).
* `ROMWRIGHT_LAYOUT_STACK_ALIGN`: an open range that starts where its element type cannot be (a 4- or 8-byte integer or float at an odd offset, a 2-byte one at an odd one) is typed as
  bytes (`romwrightOpenType`, used by `gatherOpen` and `addGuard`). On the PS2 wave it changes nothing once `STACK_FOLD` is on; alone (fold off) it takes the partial members of stack
  locals from 525 to 500 functions and `stack0x` from 14 to 2. It is the rule for a frame the fold does not reach (`[INFERENCE]` another language: no other image
  was measured).

### 13.3 Measured

Class counts over the 7,330 functions that every arm decompiled (of the 7,409; on a loaded host an arm now and then loses a 40-function chunk to the worker's 60 s deadline, so the arms are counted on what all of them have; functions that print the symptom; one worker, one `ghidra_opt`, the same imported projects). `off` = `ROMWRIGHT_NATIVE_LAYOUT=1`: its printed C is
Stage 4's, function for function (**7,330 of 7,330 identical**), which proves the switch acts on the decompiler as well as on the worker. `no-<rule>` = that rule off:

| arm | partial | `stack0x` | `undefinedN` | `_NAME` | any of the four |
|---|---|---|---|---|---|
| off (Stage 4) | 567 | 63 | 17 | 31 | 624 |
| **default** | 496 | 1 | 20 | 21 | 503 |
| no-elements | 554 | 1 | 20 | 21 | 559 |
| no-contain | 495 | 1 | 20 | 21 | 502 |
| no-stack-align | 496 | 1 | 20 | 21 | 503 |
| no-stack-fold | 500 | 2 | 20 | 31 | 517 |
| no-stack-refs | 496 | 50 | 20 | 21 | 547 |
| no-stack-fold-no-stack-align | 525 | 14 | 17 | 31 | 540 |

Functions with a partial member, by what it is a member of, off -> default: global 368 -> 325, stack 107 -> 69, register value 137 -> 135,
parameter 2 -> 2. The 12,596 partial members of the wave are 11,674; 321 functions print differently, 148 of them with fewer partial
members and 8 with more (a function that printed `DAT_0033f24e` and now prints `rel_csr[3]` is counted by what remains in it). Each rule's share: `ELEMENTS` takes the partial
count from 554 to 496 (`CONTAIN` is not about the count: without it the count is 495, but an object prints under two names again, the array and an address-named word inside it); `STACK_REFS` is the 49 `stack0x` that are addresses; `STACK_FOLD` the 10 `_NAME`, the 4 partial-member functions and the `stack0x`
of the idiom. `undefinedN` goes from 17 to 20: three 8-byte stack values that were byte arrays are now
`uStack_f0 = CONCAT26(uStack_f0._6_2_ - 4,(undefined6)uStack_f0)`, which `ROMWRIGHT_EXPORT_ODD_PIECES` renders.

### 13.4 Gates

Fresh arms on `nih-vps-u`: one release build of the Stage 4 tree (the tree its numbers came from) with this change added, `ghidra_opt` built by `native/build_ghidra_opt.sh` from the regenerated patch (sha256 `4532792dc965f05c67f12d89450bc032a30fdfe85c639b4f0519d1eb0032938c`),
a wrapper binary per arm (the m22-002 harness drops `ROMWRIGHT_*`), `ROMWRIGHT_NO_IMPORT_CACHE=1`, `ROMWRIGHT_NO_FACT_PACK=1`, a fresh import and a restored pristine work directory and repo per arm. off =
`ROMWRIGHT_NATIVE_LAYOUT=1`; **every off arm reproduces Stage 4's default to the digit**, which is the proof the wrapper acts. exact / compiled / mean %; paired = functions better / worse / same by match percent:

| gate | off | default | paired better / worse / same |
|---|---|---|---|
| m22-002 MWCC 20261010 | 55 / 195 / 77.324 | 55 / 196 / 77.638 | 1 / 0 / 199 |
| m22-002 MWCC 20261011 | 57 / 194 / 78.316 | 57 / 195 / 78.712 | 1 / 0 / 199 |
| m22-002 ee-gcc | 106 / 197 / 86.622 | 106 / 197 / 86.622 | 0 / 0 / 200 |
| dds | 61 / 200 / 77.224 | 61 / 200 / 77.402 | 4 / 0 / 196 |
| rc | 26 / 200 / 68.158 | 26 / 200 / 68.327 | 1 / 0 / 199 |
| p4 | 60 / 198 / 80.732 | 60 / 199 / 80.85 | 1 / 0 / 199 |
| gh (harness clone) | 78 / 199 / 82.119 | 78 / 199 / 82.119 | 0 / 0 / 200 |
| ff | 21 / 199 / 62.913 | 22 / 199 / 63.148 | 7 / 3 / 190 |
| dc | 41 / 197 / 73.653 | 41 / 197 / 73.562 | 2 / 2 / 196 |
| dk | 29 / 197 / 78.277 | 29 / 197 / 78.194 | 0 / 2 / 198 |

No exact and no compiled function is lost on any gate lane. Gained: ff 1 exact (`SettleGhostBattleEnd` 94.6 -> 100%; `SetForcusDepth2` 22.9 -> 55.3% is the fold), p4 1 compiled (the `&stack0x00000000` function of
section 12.6, which is also the one m22-002 MWCC 20261010 and 20261011 gain). Worse by percent: dc 2 (`EnterDataMenu` 47.7 -> 32.3 and `_GET_DIR_VECTOR` 12.8 -> 6.2: each reads a retyped small array, `MenuDCMsg[3]` and the literal-pool object `_2311[2]`, where the old print read separate address-named words), dk 2 (`GetNowManualPartTgaNum` 52.1 -> 36.3, `WorldMapMoveKey` 65.6 -> 65.0), ff 3 (the largest is `PhotoScoreDisp` 20.0 -> 13.9); the cause is the changed print of a global, not traced further. The dc, dk and ff rows are the arms with the density test (`ROMWRIGHT_LAYOUT_DENSITY`); the first version without it moved the mean percent by -0.09 / -0.15 / +0.18 on dc / dk / ff (3, 4 and 4 worse functions). compile-failure classes of the seven m22-003 samples (first diagnostic, `tests/m22-003/classes.py`), off -> default: 9 -> 8
functions that do not compile (`undeclared identifier` 1 -> 0: the p4 `stack0x`). m21-001 PASS in both arms; printer differential 1,800 of 1,800 identical (the stock path; `ghidra_opt` rules
do not touch the printer IR); decompile success on the 8 PS2 images 7,448 of 7,500 (off 7,448; the same 52 failures).
Report: `benchmarks/reports/symbol_layout_20261015.{json,md}` (`benchmarks/symbol_layout_report.py`); host scripts and per-arm outputs in `~/runs/SymbolLayout/{out,logs}`.

### 13.5 Limits and not done

* 135 functions of the wave still print a register-value member (`auVar8._0_4_`): a 16-byte value is `unsigned char [16]`. A type for it (a structure of words that the project header
  declares) is a type decision, not a layout one, and is the same piece as the VU intrinsic result types of section 12.6 (`_vrnext(in_vuR)` has no C declaration that returns 16 bytes); neither it nor
  struct returned by value was touched, because they share no cause with symbol layout.
* Globals that are structures (mixed widths: `adpcm_map` with bytes, halves and words) keep their members as `_o_w_` pieces; that is structure recovery (`struct_types.rs`), not an element size. An object
  whose address is taken keeps its byte array (about a third of the objects that have accesses inside them); the cure is a cast where the pointer is passed, which the cast pass does not decide for a pointer to
  an unknown element.
* The evidence for an element is the importer's data rows inside the object: the width of the access at the object's own address is not stored (`store.rs` excludes it so that a row does not replace the
  object), so an array accessed mostly at offset 0 (`battle_scr_effct._76_4_`) has no evidence. The fix is one more fact (a row source) and an importer change; none was made. An element typed by its uses
  (a `float` table, not `undefined4`) was tried in the export layer and removed: it changed no lane.
* The `_NAME` class (21 functions with the fold) is the PIECE-as-two-COPYs design of `MapState::gatherVarnodes`; an 8-byte store of two 4-byte registers stays `_fStack_70 = CONCAT44(..)`.
* The fold is for MIPS only (it keys on `hi`/`lo`). `STACK_ALIGN` and `STACK_REFS` are language-independent and were measured on PS2 only; PcProject reports `stack0x` and `._1_3_` as the largest compile-failure
  class of its i386 PE lanes, which `STACK_REFS` may reach, unmeasured here.
