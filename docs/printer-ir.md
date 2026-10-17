# Printer IR and the Rust C printer

Status: default since 2026-10-07. Every decompiled function's C is printed
by the worker's Rust printer from the exported IR, after every structuring
model (`ROMWRIGHT_RUST_STRUCTURING`, default `all`, copy budget 5). Since
2026-10-09 (IR version 4) the expressions are the worker's too: a Rust port of
PrintC's expression emission (`printc/render.rs`) prints each statement from
its exported print tree (`printc/tree.rs`, "Print trees (version 4)" below),
and keeps PrintC's recorded fragment only for the few statements it does not
print yet (`ROMWRIGHT_RUST_EXPRESSIONS`). Since 2026-10-11 (IR version 5) the
block tree is the worker's as well: `ghidra_opt` exports the unstructured
control-flow graph and `printc/collapse.rs`, a port of Ghidra's
`CollapseStructure`, builds the tree the printer prints ("Unstructured
handoff" below); `ActionBlockStructure`'s tree, `ActionFinalStructure` and
`PrintC::docFunction` no longer run by default. Since 2026-10-13 (IR version 6)
the casts are the worker's too: `ActionSetCasts` no longer runs by default, the
exported print trees are the pre-cast ones and `printc/casts.rs`, a port of
`CastStrategy`, `ActionSetCasts` and the cast parts of `typeop.cc`, decides
every cast ("Pre-cast trees (version 6, default)" below, and
[types-port.md](types-port.md)). Since 2026-10-14 (IR version 7) the variables
are the worker's: `ActionMergeRequired` .. `ActionCopyMarker`, the explicit/implied
marking, `ActionNameVars`' default names and the for-loop op moves are decided in
Rust over a mirror of the function's p-code ("Merge handoff (version 7, default)"
below, and [merge-port.md](merge-port.md)); the IR only gains a header flag.
PrintC's own markup survives
only on the stock path (`ROMWRIGHT_NATIVE_STRUCTURE=1`), as the reference of
the printer differential (`benchmarks/printer_diff.py`,
`romwright-worker --printer-diff`), which prints the IR *without* structuring
models (`printc::reference`) and compares byte for byte. Policy (GOAL.md C1):
Ghidra is the bar to beat, so the default output diverges from PrintC wherever
a structuring model removes a goto. Numbers and commands:
[structuring-baseline.md](structuring-baseline.md#printer-differential),
[the cutover](structuring-baseline.md#default-cutover),
[the handoff](structuring-baseline.md#unstructured-handoff-stage-1).

## Why

Structuring research (break/continue modelling, multi-exit loops, switch
shared tails, tail duplication, SAILR-style goto removal) has to change the C
that is printed. Steering Ghidra's `PrintC` from outside only reaches it
through forced `goto` cuts (`renderFunctionIR`), which the native structurer
then re-collapses around; on the console corpus that made 28 functions worse
for every 7 it improved. Owning the block layer of the printer in Rust lets a
pass rewrite the structured tree and print exactly that.

## Topology

ADR 0001 §4 is unchanged: the decompiler is the isolated `ghidra_opt`
subprocess. The C++ additions live in `native/romwright_printir.hh`,
`romwright_structure.hh` (the structuring actions and their query),
`romwright_bytes.hh` (the shared integer writer and reader) and a few hunks of
`native/ghidra-opt-sleigh.patch` (`DecompileAt`, the query in `ghidra_arch.cc`,
the pipeline's constructors in `coreaction.cc`, `Funcdata::opMarkPrinting`);
the pinned `third_party/ghidra` tree is not edited.

```
ghidra_opt (C++)                                worker (Rust)
  action pipeline -> Funcdata                   doc::decode_document_with_ram_space
  romwrightEncodePrintIr -> <romwright_printir>   ├─ Funcdata/prototype/switch collectors
    (v5: unstructured graph, statements)          └─ printc::collapse (the block tree) -> printc::render(IR) -> markup -> tokens
  ActionBlockStructure --romwright_structure--> printc::query (flips, return splits, if/else, loops)
  (stock path only: PrintC::docFunction -> <function> markup, the differential's reference)
```

On the stock path both outputs travel in the same `decompileAt`/`renderFunctionIR`
response, so the differential compares them on the same Funcdata.

## What crosses the pipe

`<romwright_printir content=BLOB>` (element id 4091) follows PrintC's markup.
The blob (NUL-free six-bit varints, because the burst protocol reserves NUL)
holds:

| part | contents |
|------|----------|
| header | `RWPI`, version 7 (6 before the merge handoff, 5 before the casts handoff, 4 before the unstructured handoff), max line size, indent increment, the four brace styles, `TokenSplit::countbase` after PrintC's `docFunction`; version 4: the options expression emission reads (`option_nocasts`, `option_hide_exts`, `option_NULL`, `option_inplace_ops`, `hide_thisparam`), the persistent `mods` bits and `PrintC::sizeSuffix`; version 6: `casts pending`; version 7: `merge owner` (the worker decided this function's merge) |
| function fragments | header comments (`emitCommentFuncHeader`), prototype (`emitFunctionDeclaration`, which also enters the local scope for everything after it), local declarations (`emitLocalVarDecls`) |
| tables (version 4) | the symbols (colour, display name, namespace path) and data-types (names, `getUnsizedId`, metatype, size, display format, flags, element type, structure fields) the print trees index; written before the block tree they serve |
| block tree | stock path only (`ROMWRIGHT_NATIVE_STRUCTURE`; the default exports the graph instead, "Unstructured handoff" below): `fd->getStructure()` after `ActionFinalStructure`: per node its `block_type`, index (the `blockref`), `lastOp()` time, and the `emitAnyLabelStatement` label when one prints; children in `getBlock(i)` order; per kind: leaf (`BlockCopy`: the `emitLabel` fragment of every leaf, printed or not), goto (`gotoPrints`, type, target), list (`nextInFlow` breaks), condition (`&&`/`||`), if (goto type and target), while (overflow syntax, initializer and iterator expressions), switch (case labels via `emitSwitchCase`, goto type and target, exit flag, case block). A goto *target* is its front basic block's index plus its label fragment |
| basic blocks | statement candidates in order (no `notPrinted`, implied or plain `BRANCH` ops) with op time, branch flag, `CommentSorter` bound, and the `emitExpression` fragment (plus the `comma_separate` rendering of a `CBRANCH`); the final branch op's expression; the block's comments with their type filter and `emitLineComment` fragment; its out-edges in the basic-block graph by block index (for a `CBRANCH`, edge 1 is where the printed condition holds); for a `CBRANCH`, the condition as PrintC prints its negation (normal and `comma_separate`); whether it holds a `for` loop's initializer or iterator op; version 3: per statement candidate its *effect* (below); version 4: its print tree (below), shared by the block's branch expression and its negation |

A *fragment* is the sequence of `Emit` calls PrintC's own handlers make for
one emission, recorded by `RomwrightCaptureEmit` (a capture `Emit` swapped in
for the duration of the export). Before version 4 expression construction -- casts, field and
array notation, constants, character and string literals, symbol scoping,
`this` hiding -- therefore stayed exactly PrintC's; version 4 moves it to Rust
and keeps the fragments as the fallback and the reference. The expression *tree* is
not lost: every `pushOp` opens a group or a parenthesis and the matching
`emitOp` closes it, so the open/close events nest exactly as PrintC's RPN
tree did, with atoms as leaves and the operator token between operands.

## Expression trees (version 3)

Fragments are text. Passes that must *compare* expressions -- is this test
the negation of that one, does a path decide it -- read a second encoding of
every statement candidate, its `Effect` (`printc/ir.rs`): the p-code opcode,
whether the statement (or an expression inlined into it) calls or stores,
the explicit variable it writes, a CBRANCH's polarity (`isBooleanFlip`) and
the inputs as `Expr` trees. A tree is what PrintC prints as RPN, structurally:
an implied varnode expands to its defining op (`Op { code, args }`), an
explicit one is a `Var` leaf naming its SSA value (`getCreateIndex`) and its
HighVariable (the C variable PrintC names), a constant is `Const`, and a
subtree past 400 ops or depth 40 is `Opaque`. A `Var` also says where it
lives (register/unique, stack, other memory) and whether it is persistent,
address-tied or address-forced -- what a call or store may change.

`printc/expr.rs` works on the trees: `same` (structure and C variables, not
SSA versions), `Facts` (what holds at one program point: conditions as value
sets on a compared expression -- equality, signed/unsigned orderings against
constants -- and `variable = constant` assignments; `kill` drops what a
statement may change; `value` answers whether a condition is decided) and
`clobbers`. The exporter adds nothing to the printed fragments, so the
printer differential is unaffected: 1800/1800 identical with version 3.

## Print trees (version 4)

Statement expressions are printed by `printc/render.rs`, a Rust port of
PrintC's expression emission, from a *print tree* per statement
(`printc/tree.rs`; exporter: `printTree`/`opNode` in `romwright_printir.hh`).
The tree is what PrintC pushes on its reverse-polish stack, structurally: an
op node holds the inputs the op prints (LOAD its pointer, STORE pointer and
value, CALL its arguments without the callee constant, CBRANCH its condition,
PTRADD base and index, PTRSUB its base ...), an implied varnode is the op
that defines it, an explicit one a leaf. A statement tree is the written
variable (if any) and the root op. The block's final branch op shares its
statement's tree (by index), its negation is the same tree with the CBRANCH
polarity inverted, and a `for` loop's initializer and iterator carry their
own.

What the tree carries beyond opcodes and varnodes is what PrintC reads from
the data-type system and the symbol table:

| node | data |
|---|---|
| every op | `PcodeOp::getTime` (the `opref` of its tokens), output size |
| `INT_ZEXT`, `INT_SEXT` | output and input types (the cast strategy's `isZextCast`/`isSextCast` run in Rust), whether `isExtensionCastImplied` hides the extension, whether the cast prints as `&` |
| `SUBPIECE` | the same, plus `isSubpieceCast`'s offset, and the special printing of a piece of a structured variable (a partial symbol, or `in.field`) |
| `CAST`, `FLOAT_FLOAT2FLOAT`, `FLOAT_TRUNC`, `FLOAT_INT2FLOAT` | the output type (an absorbed `INT_ZEXT` input is already substituted) |
| `CBRANCH` | `isBooleanFlip` |
| `CALL` | callee name (generic `func_0x...` when unnamed) and namespace path; a call the IR passes canonicalised to `/` or `%` (`romwrightIrProjections`) is exported as that op |
| `CALLIND`, `CALLOTHER`, `RETURN` | hidden-`this` slot, user-op display kind and name, halt kind |
| `PTRSUB` | what `opPtrsub` decides from the pointed-to type: structure field (name, id, array flag), spacebase symbol (array/code kind and the symbol leaf, plain or partial, or the unnamed-location token), or array |
| integer, boolean, character constant | varnode create index, size, value, type, `unsigned_print`/`long_print`, the symbol's display format; formatted by Rust (`push_integer`, `pushCharConstant`, the default cast-and-hex form for other types) |
| float, string, function-name, enum, equate constant | the one token PrintC's handler produced (`PT_ATOM`), probed by running the handler against the capture `Emit`; a constant PrintC prints as several tokens that Rust does not port is unsupported |
| variable | symbol index (colour, display name with the unmerged `$n` suffix, namespace path from `Symbol::getResolutionDepth`) or a partial symbol (symbol type, offset, size, the variable's type, endianness); an unnamed location is one probed token |

Types and symbols are interned per function (the tables above); a type
carries name, display name, generic name, `getUnsizedId`, metatype, size,
display format, flags, element/pointee type and structure fields, which is
what `pushTypeStart`, `pushTypeEnd`, `pushPartialSymbol` and `findTruncation`
read.

The renderer is a port of `PrintLanguage::pushOp`/`pushAtom`/`recurse`/
`parentheses`/`emitOp`, the `OpToken` table (including the patch's
`parentheses` rule, which always groups mixed arithmetic/bitwise operators),
and the op handlers of `printc.cc`. It produces the same `Emit` calls PrintC
makes, as a `Fragment`, so the existing replay and `printc/pretty.rs` are
unchanged. A node the exporter or the renderer does not handle makes the
statement keep PrintC's recorded fragment; the reason is counted.

`ROMWRIGHT_RUST_EXPRESSIONS`: `on` (default) prints supported statements
with Rust and the rest from fragments; `off` (also `fragments`, `0`) keeps
every fragment (the reference of the differential); `verify` renders every
supported statement, compares it with PrintC's fragment, counts the
differences and keeps the fragment (`ROMWRIGHT_RUST_EXPRESSIONS_LOG` writes
each difference to stderr). Counts per `context.kind` (`statement`, `branch`,
`negated`, `loop-init`, `loop-iterate` x `assign`, `store`, `call`, `return`,
`cbranch`, `branchind`, `branch`, `other`) and per reason are in
`PrintStats.expressions` (the ownership log) and in each `--printer-diff`
line (`expressions`). The printed-token ownership counts tokens of Rust
expressions apart from fragment tokens (`rust_expressions`).

## Unstructured handoff (version 5, default)

Stage 1 of the back-to-front port (STATUS.md, "Decompiler port: stage
roadmap"): the printed block tree is built in Rust, from the final
control-flow graph of the C++ pipeline. `ROMWRIGHT_NATIVE_STRUCTURE`
(read by `ghidra_opt`) selects the path: unset or `0` is this one, `1` the
stock path (Ghidra structures, the worker prints its tree, PrintC's markup
is exported as the differential's reference), `2` the stock path without
`ActionPreferComplement` (the reference the worker's structurer is compared
with). `ROMWRIGHT_STRUCTURE` (read by the worker) says where the tree comes
from: unset builds it from the graph when the decompiler did not structure,
`rust` always builds it, `native` requires the decompiler's, `verify` builds
it, compares it with the decompiler's (one line per function in
`ROMWRIGHT_STRUCTURE_VERIFY_FILE`) and prints the decompiler's.

**C++ side** (`native/romwright_structure.hh`, `coreaction.cc` builds the
pipeline with these classes when the worker structures):

| action | stock | default |
|---|---|---|
| `ActionBlockStructure` | `buildCopy` + `CollapseStructure` | notes the graph (`isComplex`, edges, polarities), asks the worker (below), negates the conditions it names, leaves one plain block in `getStructure()` so the pipeline sees "structured" until the control flow changes |
| `ActionReturnSplit` | `gatherReturnGotos` on the tree | splits the in-edges the worker's answer names (`nodeSplit`) |
| `ActionPreferComplement` | `BlockIf::preferComplement` | `flipInPlaceTest/Execute` on the split points of the worker's `if`/`else` blocks |
| `ActionStructureTransform` | `BlockWhileDo::finalTransform` | the same analysis (`findLoopVariable`, `findInitializer`, ported into the header) for the worker's `while` loops, inner first |
| `ActionFinalStructure` | `orderBlocks`, `finalizePrinting`, `scopeBreak`, `markUnstructured`, `markLabelBumpUp` | the for-loop tests of `finalizePrinting` only (the rest is the worker's) |
| `PrintC::docFunction` | prints the tree | not run (no tree) |

Structuring is not only downstream: Ghidra's structurer negates a branch
when it lays the arms out the other way (`BlockBasic::negateCondition`
flips `boolean_flip`), `RuleCondNegate` and the boolean rules then turn the
flip into the complemented comparison on the next pass, and `ReturnSplit` and
the for-loop transform change the p-code from the tree. The worker therefore
answers one query, `romwright_structure` (element id 4092, the same query
channel as `getBytes`; `printc/query.rs`), whenever `ActionBlockStructure`
would have run: the shape of the basic-block graph (per block its edges and
their labels, switch/goto flags, last-op kind, fall-through polarity,
`isComplex`). The answer is what Ghidra's structurer would have done: the
blocks whose condition it negates, the in-edge slots of each multi-entry
return block that are `goto`s, the split points of its `if`/`else` blocks (a
basic block, or two joined by `&&`/`||`) and its `while` loops. All come from
one structuring of the graph, as they do from Ghidra's tree.

**What crosses the pipe**: after the print-tree tables, `has_tree` (stock
path only) and then, always, the graph: per basic block the *shape*
(flags, last-op kind and time, fall-through flag, `isComplex`, whether the
exported statements print the condition the other way round from the graph's
edges (`flipped`), its in- and out-edges as (block, slot at the other end,
label); the labels are goto, loop, default-switch and back edge), the block's
`emitLabel` fragment, for a switch block each out-edge's jump-table labels
and `emitSwitchCase` fragment, and the block's statements (the `basic()` record
of version 4); then the for-loops with an initializer or iterator
(head, tail, the two statements with their print trees) and the `if`/`else`
blocks `ActionPreferComplement` complemented. The shape is the graph as
structuring last started: the graph Ghidra would have structured, whose
conditions have since been negated in the p-code, which is why `flipped`
exists. The statements of a for-loop's initializer and iterator stay in their
blocks; the worker removes them only for a loop its structure prints as a
`for` (`take_loop_ops`).

**The structurer** (`printc/collapse.rs` and `collapse/{loops,rules,finish}.rs`)
is a port of `CollapseStructure` (`blockaction.cc`) over the `BlockGraph`
machinery (`block.cc`): the edge bookkeeping (`selfIdentify`, `dedup`,
`replaceInEdge`, ...), loop bodies and exit edges (`LoopBody`), the DAG trace
that picks the unstructured edge when no rule applies (`TraceDAG`), the
rules in Ghidra's order (goto, cat, proper if, if/else, while, do-while,
infinite loop, switch, then if-without-exit and case fall-through when
nothing else applies; `&&`/`||` first), switch recovery
(`grabCaseBasic`, the case order and fall-through chains), and
`ActionFinalStructure` (`orderBlocks`, `scopeBreak`, `markUnstructured`,
`markLabelBumpUp`). The tree is the same [`Node`] tree the decoder produced
from Ghidra's, so the structuring models below are unchanged. The
`ROMWRIGHT_STRUCTURE=verify` comparison with the decompiler's own tree is what
keeps the port exact; `benchmarks/structure_handoff.py` is the differential on
the console corpus (numbers: [structuring-baseline.md](structuring-baseline.md#unstructured-handoff-stage-1)).

## Pre-cast trees (version 6, default)

Stage 2a of the port ([types-port.md](types-port.md)): the worker decides every
cast. `ghidra_opt` no longer runs `ActionSetCasts` for a function the worker
accepts (`romwrightSetCasts`, `native/romwright_structure.hh`, only marks the
function pending). Just before the p-code is read to print it
(`romwrightFinishCasts`, `native/romwright_printir.hh`, called from
`DecompileAt` in the patch and from `RenderFunctionIr`), C++ reads what the
cast phase needs of every op and varnode **before anything probes the
function** (`RomwrightCastFacts`: PrintC's own handlers update lazily evaluated
state, so reading types after them is not what `ActionSetCasts` would have
read), sends the function's pre-cast print trees to the worker over the
query channel (a query whose first varint is 0: `printc/query.rs`
`answer_casts`; structuring queries start with a block count, never 0) and
gets `o` (the worker casts; plus the pointer-size warnings
`ActionSetCasts::checkPointerIssues` would have added), or `n` (it declines;
`ActionSetCasts` runs, at the same point of the pipeline's output, and the IR
is the version-5 shape with `casts pending = 0`).

What a pending function's print tree carries beyond version 4 (`printc/casts.rs`
`CNode`; exporter `leafInfo`/`opInfo`):

| node | data |
|---|---|
| every leaf | read-facing type, the varnode's own type, flags (type-locked, high bit of the non-zero mask, constant, written) |
| every op | output types (definition-facing high type, own type), flags (type-locked, sole reader is a `RETURN`, implied, **several readers**), `outputTypeLocal`, `isBoolOutput`, `isCall`, the absorbed `INT_ZEXT` of an `INT2FLOAT` as a node of its own, per kid its p-code slot and `inputTypeLocal(slot)`; LOAD/STORE the space's word size, PTRADD the element size, PTRSUB its offset, whether its pointer type still fits it and its output type before any cast, SUBPIECE its output type |
| type table | sub-metatype, typedef link, pointer word size and space, alignment size, variable-length flag; the core `INT`/`UINT`/`UNKNOWN`/`BOOL` types of every size the function uses (`TypeFactory::getBase`), `getSizeOfInt`, and `typeOrder` for the pairs of enum, structure, union and code types of equal sub-metatype and size |
| header | `casts pending`; the options (`nocasts`, `NULL`, in-place operators) also travel in the query |

`casts.rs` ports `CastStrategyC`, the cast methods of `typeop.cc`
(`getInputCast`/`getOutputToken` per opcode) and `ActionSetCasts` itself
(`castInput`, `castOutput`, the double-cast test, `PTRSUB #0` into a first
field, `testStructOffset0`, `markExplicitUnsigned`/`markExplicitLongSize`,
the `PTRSUB` -> `COPY` revalidation, `Varnode::updateType` on constants and
implied results) over the tree, in block order (children first). A function
is declined for a union or `needsResolution` type, a pointer with an address
space, a constant that would need a string or code-pointer spelling after a
retype, a `PTRADD` that no longer fits its pointer (`opUndoPtradd`), a
`PTRSUB` that is not an offset-0 misfit, a cast around the output of a for-loop
initializer or iterator (the loop analysis ran on the p-code before the
casts), a type-order pair the exporter did not supply, a node the renderer
refuses, and `ROMWRIGHT_RUST_EXPRESSIONS` other than `on`.

Switches: `ROMWRIGHT_NATIVE_CASTS=1` (`ghidra_opt`) runs `ActionSetCasts` for
every function, as before this stage, and is also the stock-structuring path;
`ROMWRIGHT_RUST_CASTS=off` (worker) declines every function, `verify` has the
decompiler cast and compares the worker's tree of every statement with
`ActionSetCasts`' (`ROMWRIGHT_RUST_CASTS_LOG`: `cast_ok`, `cast_declined`
with the reason, `cast_verified`, `cast_mismatch` with both trees as text),
`ROMWRIGHT_RUST_CASTS_DEBUG=1` prints each pre-cast statement.

The document the decompiler encodes is the p-code *without* the casts for a
function the worker casts. Two things of the semantic IR depend on them, and
the worker supplies both after it printed: the types the casts name that no
variable or prototype of the function carries (`FunctionIr::cast_types`, read
by the C spelling pass), and the CAST operations themselves. A cast is where a
value changes type, so the type evidence read off the IR (an `INT_RIGHT` of a
`double`'s bits, a `SUBPIECE` of a double) needs them: without them the
`romwright_subpiece_8_4_0` intrinsic was recovered for a floating-point
`SUBPIECE` and the C did not compile (rc `_d2b`). `casts::Pass` records every
insertion and replacement as an `IrEdit` and `doc.rs apply_cast_edits` makes
the same ones in `FunctionIr` (an op's output moves to a fresh unique and a CAST
writes the original; a CAST before the reader for an input), which restores the
operation and type-evidence counts of the C++ path. The callee prototypes the
C++ path read off the casted calls are read off the uncast ones instead (they
measured better; `ROMWRIGHT_RUST_CASTS_CALLS=cast` restores the old reading).

## Merge handoff (version 7, default)

Stage 3 of the port ([merge-port.md](merge-port.md)). The print IR changes in one
place: after `casts pending` the header carries `merge owner`, 1 when the worker
decided the function's variables (merge, explicit/implied marks, copy trims,
non-printing copies, the for-loop initializer/iterator moves) and 0 when the
decompiler's own actions did (a declined function, or
`ROMWRIGHT_NATIVE_MERGE=1`). The worker reads it for the ownership accounting
(`ExprStats::merge_functions`). Everything else the IR carries is read off the
decompiler's state *after* the decisions have been replayed on it, so the
statements, symbols and types it exports are the same as before.

The decisions travel on the query channel (element 4092, first varint 0): marker
2 is the merge query, 3 the naming query, 4 the verify dump. Their wire formats
are in [merge-port.md](merge-port.md) (the mirror, the log and the names).

Switches: `ROMWRIGHT_NATIVE_MERGE=1` (`ghidra_opt`) runs the decompiler's own
merge actions, `ActionMarkExplicit`/`ActionMarkImplied`, `ActionNameVars` and the
for-loop moves for every function (the previous default; `merge owner = 0`);
`ROMWRIGHT_RUST_MERGE=off|on|verify` (worker) declines every function, decides
(default) or has the decompiler decide and compares (`ROMWRIGHT_RUST_MERGE_LOG`:
`merge_ok`, `merge_declined`, `merge_mismatch`, `merge_verified`, `names_ok`);
`ROMWRIGHT_RUST_NAMES=off` (worker) leaves the default names to `ActionNameVars`;
`ROMWRIGHT_MERGE_VARIANT` (worker) selects a printing variant
(docs/merge-port.md section 5).

## Token links

The DecompDoc token structure is reproduced byte for byte, not approximated:

- Fragments (and the renderer, which builds the same events from the print
  tree) record the resolved markup each tag carries: `opref`
  (`PcodeOp::getTime`), `varref` (`Varnode::getCreateIndex`), `symref`,
  data-type unsized id and name, field offset, comment/label space and offset,
  case value, colour.
- The block layer emits the same keyword, statement, goto, label and `blockref`
  markup PrintC does, from the node's index and `lastOp`.
- `printc/pretty.rs` ports `EmitPrettyPrint` over `EmitMarkup`, so line
  breaks, indents, the empty syntax tokens the algorithm inserts, and comment
  fill are the same; parenthesis `open`/`close` ids come from `TokenSplit`'s
  global counter, which the export reports and the printer replays (it prints
  twice: once to count the ids a function consumes, once from PrintC's start).

The output is the same packed `<function>` markup PrintC writes, decoded by
the existing `doc::decode_tokens_with_ram_space`.

## How the existing post-processing composes

Nothing downstream changes. `decode_document_with_ram_space` always
substitutes the Rust printer's tokens; the semantic IR pass pipeline, the
StructureGotos guard (`printed_gotos` in `finalize_document`),
`renderFunctionIR` (whose responses carry the IR too), worker-client,
`emit_m2c` / `export-c` and the desktop all read the same `DecompToken`s. A
response with C but no usable IR is an error, never a silent PrintC fallback.

## Structuring passes (default: `ROMWRIGHT_RUST_STRUCTURING=all`)

`printc/structure.rs` rewrites `PrinterIr::body` before `printc::print`;
`printc::render` runs every model unless `ROMWRIGHT_RUST_STRUCTURING`
names others (a comma list, plus an optional `budget=N`; `none` prints
Ghidra's structure, for ablation). Ghidra's tree is the
starting point -- its loops, `for` recovery, `&&`/`||` conditions and
switches stay -- and a model only removes what Ghidra left as `goto`.
Models always run in the table's order:

| model | rewrite |
|---|---|
| `break_continue` | a goto to the innermost loop's continue point prints `continue` (Ghidra never emits one); to the innermost loop or switch exit, `break`; to the block that follows anyway, nothing |
| `collapsed_edges` | one goto per collapsed edge: `if (a) goto L; if (b) goto L;` (also when Ghidra folded the first into the second's condition block) prints `if (a \|\| b) goto L;`; an if/else whose arms both end in `goto L` prints it once after the if; switch cases that jump to one block share a goto |
| `else_join` | `if (c) { A; goto L; } R; L:` becomes `if (c) { A } else { R }` (also for a goto ending the else arm); nothing is copied |
| `thread_test` | jump-threading reversal (below): a `goto` past a test the path decides re-runs the test; a `goto` to a test the path decides goes on to where it leads. Nothing copied |
| `switch_tails` | a goto that stays inside its loop is replaced by a copy of the target's tail when the copy ends where the goto's position continues, at the enclosing `break`/`continue` target (then that statement ends the copy), or returns -- the shared tails of switch cases and compiled if-chains |
| `loop_exits` | the same for a goto that leaves its loop: a loop with several exits returns or breaks in place |
| `irreducible_entry` | a second entry into a region keeps Ghidra's primary entry and splits the other: `if (c) goto L; R` and `if (c) { A; goto L; } R` become if/else with a copy of L's tail when both end at the same place; `if (c) goto L; R; L:` becomes `if (!c) { R }` with PrintC's own negation |
| `sink_join` | `if (c) { ... goto L ... } M; L:` moves M into every arm that falls through to it (adding an else arm when there is none), so the goto ends its arm and the models above remove it; up to 3 nested moves towards one label, kept only when the follow-ups remove a goto. This reverts cross-jumping (a tail the compiler merged out of the arms) and jump threading (a jump past a test whose outcome the compiler knew) by duplicating M; a `switch` before M is sunk the same way: its cases that reach the end take M and `case n: goto L` becomes an empty case; `sink_join` alone changes nothing |
| `cond_merge` | `if (a) { if (b) goto L; } R; L:` becomes `if (a && b) goto L; R; L:` (the inner test must print nothing but itself), after which `irreducible_entry` negates it without copying R; kept only when the follow-ups remove a goto |

### Jump-threading reversal (`thread_test`)

A compiler that knows a test's outcome on one path jumps the path straight
past it. Two rewrites undo that from the printed tree
(`printc/structure/thread.rs`), both only when the conditions that hold on
*every* edge into the target decide the test, and the test prints nothing
but itself and calls nothing:

- **Re-insert.** `goto L` where `L` starts the arm of `if (T)`, at a place
  where control would otherwise continue into `T` (it falls out of the goto,
  `break`s or `continue`s there): the goto is dropped and `T` runs again,
  taking the same edge (gba 0x0816f9d4: `case 2: if (a || b) {..; break;}
  goto L;` with `L` in `if (!b) {..}` becomes `if (a || b) {..} break;`).
- **Forward.** `goto L` (or `if (c) goto L;`) where `L` is the test itself
  and the jump's own facts decide it: the goto goes to the arm that outcome
  takes (`flag = 1; goto L; ... L: if (flag == 0) {..}`); kept only when the
  other models then remove the goto.

Facts at a jump are the enclosing arms' tests, learned `v = constant`
assignments and the tests inside the jump's own body, less whatever an
earlier statement may have written (a variable's HighVariable, or any
aliased variable / memory load on a call or store). They are dropped at a
label other code jumps to and at a loop (every effect in the loop kills
them). The checker accepts the changed edge through `Basic::threaded`
((successor in the block graph, block the printed code flows to)), set only
on the leaves the proof covers; a block carrying one is never copied.

Copies are priced, not bounded by shape: a rewrite (a sink with its
follow-ups counts as one) may add at most `budget` printed lines per goto
it removes, lines counted the way PrintC lays the tree out (statements,
jumps, labels, `if`/loop/switch header and closing brace, `else`, case
labels). The default, 5 (4 until the fake-match metric asked for one more), replaced the former fixed bound (6 statements, 3
blocks); [structuring-baseline.md](structuring-baseline.md#copy-budget)
has the sweep. A copy is never a loop, switch, jump or a block holding a
`for` loop's initializer or iterator. Ghidra's nested lists are printed
flat and the statements it folded into an if's condition block move in
front of the `if` (same C), so neighbouring statements are seen directly;
an arm left with one statement prints as that statement (`else if`). A
composite rewrite (`sink_join`, `cond_merge`, a forward `thread_test`) runs
its follow-ups (at most 16) until the function prints fewer gotos *within
the budget*: a sink that copies one statement into seven cases to remove
seven gotos is priced on all seven, not on the first.
Labels no goto prints to any more are dropped, and so is code the
rewrites made unreachable.

Every rewrite is checked before it is kept. The pass interprets the
printed tree -- where control goes after each printed block on each edge,
through fallthrough, `break`, `continue`, loop back edges and switch
fallthrough -- and compares it with each block's out-edges in the
basic-block graph; a function whose original tree does not check is left
alone, and a rewrite whose result does not check is undone. A rewrite is
kept only when the printed goto count drops, so no function prints more
gotos than PrintC's own structure of the same Funcdata, and a tree that
fails to print falls back to Ghidra's. With
`ROMWRIGHT_RUST_STRUCTURING_LOG` each render also logs the remaining gotos
by cause. Measured in
[structuring-baseline.md](structuring-baseline.md#structuring-models) and
[its SAILR-style passes section](structuring-baseline.md#sailr-style-passes-and-the-copy-budget).

## GTE macro lifting (PSX, default on; `ROMWRIGHT_GTE_MACROS=0` off)

The PSX language decodes COP2 (`native/languages/psx/gte.sinc`): `lwc2`/`mtc2`/
`ctc2` are writes to the named GTE registers (`VXY0 = *param_1;`), `swc2` a
read (`*param_2 = SXY2;`) and each GTE command one named userop
(`gte_rtps(1,0);`). `printc/gte.rs` folds them back into the macro calls the
code was written with, on the decoded IR before the structuring models, so
`reference` (the printer differential) never runs it:

Before (12 statements and a `return OTZ;`, from 14 MIPS instructions):

```c
VXY0 = *param_1;                VZ0 = (int)(short)param_1[1];
VXY1 = param_1[2];              VZ1 = (int)(short)param_1[3];
VXY2 = param_1[4];              VZ2 = (int)(short)param_1[5];
gte_rtpt(1,0);                  gte_nclip();
*param_2 = SXY0;  param_2[2] = SXY1;  param_2[4] = SXY2;
gte_avsz3();
```

After (5 statements and the `return`; the synthetic `project_triangle` of
`tests/p4-1_gte_macros.py`):

```c
gte_ldv3(param_1,&param_1[2],&param_1[4]);
gte_RTPT();
gte_NCLIP();
gte_stsxy3(param_2,&param_2[2],&param_2[4]);
gte_AVSZ3();
```

* *Commands.* `gte_<cmd>(sf,lm)` prints `gte_<CMD>()` (psx-spx's command names);
  `sf`/`lm` print only when they are not the usual `sf=1, lm=0`
  (`gte_NCDS(1,1)`); `NCLIP`/`AVSZ3`/`AVSZ4` take none; `MVMVA` prints its five
  fields.
* *Loads and stores.* A run of consecutive register moves to or from memory
  becomes one call per macro (`gte_ldv0/1/2(p)`, `gte_ldv3(a,b,c)`,
  `gte_ldsxy3`, `gte_ldsz3/4`, `gte_ldrgb3`, `gte_stsxy3`, `gte_strgb3`,
  `gte_stlvl`, `gte_stlvnl`, `gte_SetRotMatrix/LightMatrix/ColorMatrix(p)`,
  `gte_SetTransMatrix(p)`); any other data-register move is a one-register
  call named after the register (`gte_stsxy(p)`, `gte_stotz(p)`,
  `gte_ldir1(p)`). Statements are matched by their `Effect` (opcode, written
  variable, address expression split into base + constant offset), never by
  their text; the argument tokens are the address operand's own tokens
  (`param_1`, `&param_1[2]`, `&uRam80123450`), with a cast, a dereference or
  a `& 0xffff` mask removed. A run whose address has no such form, a lone
  `ctc2` from a register or an arithmetic value, and a statement between two
  halves of a pair stay as written.
* *Ownership.* The new statements have `Source::Rust` and `Effect { code:
  CALLOTHER, calls, stores }`, so no later pass moves anything across them;
  `PrintStats.gte` counts calls by name and the load/store statements folded.

## Limits

- Structured printing only: a printer in `flat` mode refuses the export.
- C comment style is assumed for comment fill (the worker never changes it).
- Names that are not UTF-8 make the render fail rather than be re-encoded.
- Expressions the renderer refuses keep PrintC's fragment: user-op display kinds other than function and no-operator syntax (`callother:display`), `CPOOLREF`/`NEW`/bit-field ops, unions and `needsResolution` types, pointer-relative types, function-pointer type expressions with a prototype, non-ASCII character constants, a hidden `this`, and the non-default options (`NULL`, in-place operators). None occurs in the console corpus or the libc sample (see the coverage numbers in [ownership.md](ownership.md)).
