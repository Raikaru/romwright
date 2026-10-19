# Third-party references and corpus toolchains

## GCC target runtime libraries

The m1-006 corpus links real libstdc++ and libgcc target runtimes from the
SHA-256-pinned Debian packages in `tools/fetch_cross_sysroots.py`. They are
build/test corpus dependencies, not new dependencies of the Rust application.
GCC runtime libraries are distributed under GPLv3 with the
[GCC Runtime Library Exception 3.1](https://www.gnu.org/licenses/gcc-exception-3.1.html).
The extracted Debian packages retain their copyright notices under `usr/share/doc`.

## MSF/PDB format reference

The corpus PDB validator follows the public LLVM format documentation:
[MSF](https://llvm.org/docs/PDB/MsfFile.html),
[PDB Info](https://llvm.org/docs/PDB/PdbStream.html),
[DBI](https://llvm.org/docs/PDB/DbiStream.html), and
[CodeView symbols](https://llvm.org/docs/PDB/CodeViewSymbols.html).
LLVM is licensed under Apache-2.0 with LLVM exceptions
([license](https://llvm.org/LICENSE.txt)). No proprietary tool output or leaked
source is used as an oracle.

## Function signature database

`.vsig` (`docs/vsig.md`, `crates/romwright-sig`) is Romwright' own container. Pattern
plus per-byte compare mask is a general, publicly described idea; no
proprietary signature format documentation, database or tool output was
consulted, and nothing is byte-compatible with one. Every record carries the
exact package build it was extracted from and that package's license, so a
shipped database can be audited and redistributed on those terms.
The matcher fills Ghidra's FunctionID role only: it names a function when
library bytes match, and never re-derives analysis from a proprietary database.
No FunctionID database, signature file or tool output was read.

## Itanium C++ RTTI

`crates/romwright-core/src/rtti.rs` follows the public Itanium C++ ABI: §2.9.5 for
the `__class_type_info`, `__si_class_type_info` and `__vmi_class_type_info`
layouts and their `base_class_type_info` offset/flag encoding, §2.5.2 for
vtable layout (`offset_to_top`, the `type_info` slot and the address point),
and §5.1 for the `_ZTV`/`_ZTI`/`_ZTS` names, which are matched literally. The
ABI vtable symbols are read from the image's own relocations; no analyzer
output or proprietary database is consulted. Ghidra's equivalent analyzers
were not ported: the evidence chain here is relocation-anchored, and unmatched
candidates produce no class.

## MSVC RTTI

`crates/romwright-core/src/rtti/msvc.rs` follows LLVM's Microsoft C++ ABI code
generation (`clang/lib/CodeGen/MicrosoftCXXABI.cpp`, Apache-2.0 WITH
LLVM-exception), which documents `RTTICompleteObjectLocator`,
`RTTIClassHierarchyDescriptor`, `RTTIBaseClassDescriptor`, `TypeDescriptor`
and the `PMD` displacement triple, plus the `.?A` decorated-name prefix. No
Microsoft header, RTTI database or tool output is consulted, and no Ghidra
analyzer was ported: each structure is confirmed from the image's own fields,
including the 64-bit locator's self reference.

## GameCube DOL format

The independent DOL parser follows the public section-table layout documented
by Dolphin's [DolReader.h](https://github.com/dolphin-emu/dolphin/blob/master/Source/Core/Core/Boot/DolReader.h)
and [DolReader.cpp](https://github.com/dolphin-emu/dolphin/blob/master/Source/Core/Core/Boot/DolReader.cpp)
(GPL-2.0-or-later). No Dolphin implementation code is copied or linked.
Sparse console images use the pinned Ghidra `LoadImageXml` implementation
(`third_party/ghidra/decompiler/loadimage_xml.cc`, Apache-2.0), without modifying
the upstream tree. The private game binary and matching symbol ELF are local
gate inputs, not redistributed repository fixtures.

## ELF unwind indexes and synthetic external evidence

The `.eh_frame_hdr` reader follows the published
[LSB DWARF extensions](https://refspecs.linuxfoundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/dwarfext.html)
and Ghidra 12.1.3's `ExceptionHandlerFrameHeader`, `FdeTable`,
`DwarfEHDataDecodeFormat` and `DwarfEHDataApplicationMode` (Apache-2.0).
The implementation reads metadata; it does not copy Ghidra implementation code.

The oracle-only `ExportFunctionScoring.java` API calls were checked against
the installed 12.1.3 Java sources. `ElfProgramBuilder.createExternalBlock`
and `evaluateElfSymbol` establish the positive synthetic-placeholder evidence:
an artificial `EXTERNAL` block sourced from `Elf Loader`, plus a thunk to an
external function. The exporter lives outside the runtime bridge and does not
change its fingerprint or the immutable raw oracle references.

## Instruction flow metadata

`crates/romwright-core/src/native_runtime/flow.rs` follows Ghidra 12.1.3
`SleighInstructionPrototype.walkTemplates`, `flowListToFlowType`,
`gatherFlags` and `convertFlowFlags` (Apache-2.0). Flow facts are collected
during ordinary in-process SLEIGH p-code generation, not through a second
decode. (A C++ header, `native/romwright_flow.hh`, carried the same port
inside the SLEIGH console's patch until the console was retired.) Instruction-local labels and `inst_start`/`inst_next`
branches are not exported as machine flow references.

`FLOW` includes conditional/terminal classification, actual RETURN p-code
evidence, and individual delay-slot lengths. Total length includes slots;
slot effects do not alter the parent's prototype flow classification.
Discovery follows the reported fallthrough, including conditional returns,
and does not invent fallthrough after terminal calls. Console consumers require
the enriched protocol; rebuild both native binaries after this cutover.
Ordinary decompiler translation does not collect the optional flow metadata.

## In-process SLEIGH lifting

`crates/romwright-core/src/native_runtime/lift.rs` lifts p-code with kuna's
`kuna-sleigh` runtime ([noelo-Lab/kuna](https://github.com/noelo-Lab/kuna),
Apache-2.0, commit `c4f735f903026ec486a47f395e0e9944069e95e5`), a Rust port of
Ghidra 12.1.3's C++ `Sleigh` translator, `ContextDatabase` and `.sla` reader.
Romwright uses the translator, the context database and its `<context_data>`
decoder, and kuna's XML reader; its decompiler crates are not used. Kuna's
NOTICE attribution is carried in the root `NOTICE`.

The setup around the translator reproduces, without copying their code, what
Ghidra 12.1.3's C++ console and `SleighArchitecture` (Apache-2.0) did for a
loaded image:
`SleighArchitecture` language resolution (`scanForSleighDirectories`,
`collectSpecFiles`, `normalizeArchitecture`, `buildSpecFile`, `.ldefs`
`<truncate_space>`), `FileManage` search-path order and
`discoverGhidraRoot`, `Architecture::restoreFromSpec`'s processor-then-compiler
`<context_data>`, and the byte views of `LoadImageXml` (including `pad()`),
`RawLoadImage` and, for `pei-*` targets, `LoadImageBfd` over the PE section
table as BFD's `coff_swap_scnhdr_in` sizes it. Kuna grows its parser-state
arena where the pinned `Sleigh` holds 75 states (`sleigh.cc:457`), so a
constructor walk the console reports as bad data is refused before decoding,
counted from kuna's `instruction_mask` operand views. The PowerPC
conditional-LR return rewrite is Romwright's own (`native/romwright_ppc_return.hh`
for `ghidra_opt`, `native_runtime/flow.rs` and `lift.rs` in process).

`kuna-sleigh` is built from `third_party/kuna-sleigh`, a vendored copy at the
same commit with three changes. Its constructor-walk depth bound (`MAX_DEPTH`,
the C++ `ParserWalker::breadcrumb[32]`) is raised to Ghidra's own (Java
`ParserWalker.MAX_PARSE_DEPTH` = 64, `breadcrumb = new int[65]`, read from the
12.1.3 `SoftwareModeling.jar` bytecode), and the `context.hh` hunk of
`native/ghidra-opt-sleigh.patch` raises and checks the C++ array the same way. The C++ walker never checked
its 32: a PowerPC `lmw`/`stmw` naming ~31 registers wrote past the array
(GameCube data decoded as code reached it 8 times), while kuna refused it.
Its operand bound (`MAX_OPERAND`, the C++ `initialize(75,20)` per-state
operand array) is raised from 20 to 74, the console's operand-state count (75
states, the base and 74 operands, `sleigh.cc:457`): the console's
`allocateOperand` hunk grows the array to the operand index named (a VMX128
constructor names 33), so the state count is its only bound, and kuna refuses
an operand index of 74 or more exactly where the console is out of states.
Before the change the in-process flow decoder answered `Bad` for 6249 Xbox 360
VMX128 words the C++ translator decodes (found by the flow differential
against the SLEIGH console, since retired; its last result, 0 differing
answers on 10 corpus images, is recorded in STATUS.md).
The third change is `Sleigh::reset_for_reuse` (`src/sleigh.rs`), a method kuna does not
have: it installs a given context database, empties the context cache and the
remembered constructor matches and commits. It is what lets
`native_runtime/lift.rs` hand a decoder, whose `.sla` decode costs more than a
small image's whole analysis, to the next program of a container (the idle
pool and `ROMWRIGHT_NO_DECODER_POOL`, `docs/environment.md`) instead of
building one per use; the Rust side is Romwright's own.

The memory work (`benchmarks/reports/memory_fix_*.md`) adds to the vendored copy,
none of it in kuna: `src/slaimage.rs` (`SlaImage`, `Sleigh::initialize_from_image`) inflates
a `.sla` once per process and cuts every constructor, every `construct_tpl` and
every subtable's root decision tree out of the packed stream into a shared
buffer, leaving stubs in the stream the eager decode reads; the tables of a
decoder then hold an empty slot for each, and a constructor, template or
decision node is decoded the first time an instruction reaches it. Kuna's
tables are `Rc`-linked to their own address spaces, so they cannot be shared
between lane threads: what is shared is the bytes, and what each decoder
avoids is the objects it never reads (a language's templates alone were 57% of
a decoded x86-64 heap, and a program uses hundreds of its thousands). The
templates come in two variants for one decoder, the language's own and a
caller-supplied transform of them (the flow decoder's markers,
`native_runtime/flow.rs`), selected by a switch on the arena, so a flow lane
and a plain lifter are one decoder (`TemplateArena::set_marked`).
`Sleigh::swap_context_db` lets one decoder serve several lanes' context
databases in turn. Smaller changes: a subtable symbol is boxed (it was five
times the size of any other), the register cross-reference is shared with the
lookup the manager holds instead of copied, the lookup by name scans it, and
a decode from an image registers names in the global scope only (the local
scopes, one per constructor, are the compiler's). `SymbolTable::decode`,
`Sleigh::initialize_from_sla` and every compiler-side path are unchanged and
decode eagerly (`ROMWRIGHT_EAGER_SLA`, `docs/environment.md`).

`crates/romwright-core/src/native_runtime/flow.rs` answers discovery's flow
questions with the same runtime: it implements Ghidra's
`SleighInstructionPrototype.walkTemplates`/`flowListToFlowType` by inserting
marker ops into the translator's constructor templates before each flow op,
label and delay slot, and reading them back out of the emitted p-code.

## Minimal direct-jump thunks

The approved M1 prerequisite follows the single-jump case in Ghidra 12.1.3
`CreateThunkFunctionCmd.getSimpleFlow` (Apache-2.0), checked in the extracted
Java source. The native rule is narrower: an established entry must emit
exactly one direct SLEIGH `BRANCH` operation, with no additional p-code effects,
optionally preceded by one contiguous empty-p-code instruction.
The approved prefix extension follows `getThunkedAddr` lines 567–572, which
skip one empty-p-code instruction and explicitly mention ENDBR64. The console
emits `no_op=1` only after successful decoding with an empty p-code operation
list; no mnemonic or opcode-byte matching is used in discovery. Further prefixes
and missing evidence are rejected.
Its destination must independently decode and survive body-containment
reconciliation. Weak data/boundary candidates do not establish further entries.
Jump xrefs retain `native-import:thunk` provenance only for distinct retained
destinations. This is not the full multi-instruction, indirect or call-return
thunk analyzer.

The bounded indirect-linkage prerequisite also follows `getThunkedAddr` and
`addRegisterUsage` in `CreateThunkFunctionCmd` (Apache-2.0), with stricter
fail-closed handling of unknown inputs and partial register aliases.
`crates/romwright-core/src/native_runtime/linkage.rs` consumes SLEIGH p-code
(kuna-sleigh) and reuses the registered `OpBehavior` constant evaluators
(`kuna_num::opbehavior`); it replaced the console command of the same name
(`native/romwright_linkage.hh`, deleted). It tracks pointer-slot identity,
not invented external pointer values. Stores, calls, other control flow and
unused non-flag register writes are rejected. Bounds are 8 instructions,
128 operations per instruction and 64 live values. Unique temporaries are
discarded between instructions. A successful query alone does not create a
function; discovery must associate the slot with loader metadata.
Seeded ELF/PE imports and the DOL sweep share the same recognition rule:
an unconditional branch target can establish a separate entry only when
bounded SLEIGH linkage evidence resolves a loader-recorded external slot.
Proven direct-call targets enter the same evaluation: a call establishes its
target entry independently, so submitting it costs no extra promotion authority
and recovers architectures whose PLT layout is not table-recognized. Naming
still requires the loader-recorded slot; unresolved stubs keep generated names.
Conditional branches alone do not establish linkage entries. Local unresolved
inputs require independent caller evidence, not an assumed global register value.
For PIC linkage, the native evaluator follows at most 64 straight-line caller
instructions, accepting direct transfers only to the next instruction (PC
capture). Stores in this prefix do not supply memory values; only proven register
constants propagate. The linkage body retains the strict 8-instruction rule.
After strong and weak flow closure, every validated incoming caller must resolve
the same slot and length. Conditional or setup-bypassing entries, unknown inputs
and conflicting callers reject promotion. Already-decoded flow filters probes to
contiguous indirect-branch-ending sequences; successful promotion splits actual
instruction ownership rather than retaining the stub in its caller's body.

Thunk recognition follows `CreateThunkFunctionCmd.getSimpleFlow` and
`computeThunkBody` in the extracted Ghidra 12.1.3 sources (Apache-2.0): one
unconditional, single-target transfer that is a jump, or a call that terminates
flow. A call terminates only when its destination is proven non-returning, so
native reuses the pinned `NoReturnFunctionAnalyzer` name list, which matches the
primary symbol after stripping leading underscores. ELF symbol selection
therefore prefers exported over local bindings and unversioned over
`name@@VERSION` aliases, so an internal alias cannot hide the matched name.
STT_GNU_IFUNC stubs use the public elf.h `*_IRELATIVE` relocation types
(x86-64 37, i386 42, AArch64 1032, ARM 160, PowerPC 248, RISC-V 58): the addend
is the in-image resolver, which supplies a destination where no import name
exists. The benchmark-only `scripts/ExportThunks.java` reads `Function.isThunk`,
`Function.getThunkedFunction(false)`, `Function.isExternal` and
`AddressFactory.getDefaultAddressSpace`, all verified in those sources.

PLT boundaries use ELF `sh_entsize`, executable mapped sections, and the
canonical layouts documented by LLVM lld 19.1
([AArch64](https://github.com/llvm/llvm-project/blob/llvmorg-19.1.0/lld/ELF/Arch/AArch64.cpp),
Apache-2.0 WITH LLVM-exception): a 32-byte resolver header and 16-byte entries.
The [x86](https://github.com/llvm/llvm-project/blob/llvmorg-19.1.0/lld/ELF/Arch/X86.cpp)
and [x86-64](https://github.com/llvm/llvm-project/blob/llvmorg-19.1.0/lld/ELF/Arch/X86_64.cpp)
layouts use a 16-byte resolver header and 16-byte entries; `.plt.sec`
has no header. Missing entry widths are inferred only when `.rel[a].plt`
record counts account for the entire canonical table. Unknown layouts and
zero-width `.plt.got` sections are rejected.
These are untrusted candidates, not functions. The table-specific SLEIGH query
permits unused register setup but still rejects unknown inputs, stores, calls
and non-indirect terminal flow; its result must fit the entry and resolve a
loader-recorded external slot. Generic branch-target recognition remains strict.

## Native function-start pattern matching

`crates/romwright-core/src/native_runtime/patterns.rs` follows Ghidra 12.1.3
BytePatterns (Apache-2.0): `Patterns`, `Pattern`, `PatternPairSet`,
`DittedBitSequence`, `AlignRule`, `LanguageConstraint`, `CompilerConstraint`, and
`generic.constraint.DecisionNode`. It replaced the console command
`functionstarts` (`native/romwright_patterns.hh`, deleted). Kuna's XML reader
(a port of the decompiler's) reads the installed `patternconstraints.xml` and the
selected pattern files. Selection uses the loaded language and resolved compiler
specification, including more-specific decision precedence; it does not infer a
compiler from opcode bytes.

`SleighLifter::function_patterns` takes exclusive-end mapped ranges and returns
the instruction alignment, shared source rules with ordered action attributes,
and address/rule matches. Matching preserves
hex/binary wildcards, explicit marks, pair fixed-bit thresholds and raw-start
alignment. XML integers retain `SpecXmlUtils.decodeInt` low-32-bit semantics.
Parsed sequences are shared across pairs; bounded scan windows retain lookahead.
These are raw matches, not functions. Consumers must enforce action prerequisites
and ownership; `validcode="function"` is never new-function evidence.

ELF imports carry the base compiler specification from the pinned processor
`.opinion` files (Apache-2.0): x86 and RISC-V use `gcc`; AArch64, ARM, MIPS
and PowerPC use `default`. Mapped console images retain this selection rather
than replacing it with the architecture default (Windows on x86). This is
base load-spec selection, not producer identification from Go/Swift metadata.


## Native instruction-flow facts

`native_runtime/flow.rs` follows Ghidra 12.1.3
`SleighInstructionPrototype.walkTemplates`, `flowListToFlowType` and
`convertFlowFlags` (Apache-2.0). It retains template distinctions that resolved
p-code alone loses: instruction-local labels and J_START/J_NEXT are not
independent machine branches.

The `flow <address> ...` response carries terminal/conditional flags, actual
RETURN p-code presence and delay-slot lengths. Parent instruction lengths
include their delay slots; slot instructions remain separately queryable.
Conditional returns preserve their fallthrough. The console flushes once per
batch, including error rows, rather than once per instruction.

## Function-start eligibility and scheduling

`crates/romwright-core/src/native/discovery/patterns.rs` follows Ghidra 12.1.3
`FunctionStartAnalyzer`, `PseudoDisassembler`, `RepeatInstructionByteTracker`
and `PossibleDelayedFunctionCreator` (Apache-2.0). This is entry selection
against retained native facts, not a replacement for all BytePatterns
annotations or context analysis.

Creation requires alignment, a valid decoded instruction and the action's
preconditions. Numeric `validcode` counts contiguous parent instructions, not
delay slots; validation may cross existing instruction boundaries without
granting ownership of another function. Bounded validation rejects unavailable
bytes, zero prefixes, invalid/repeated decoding, overlapping instructions,
known pointer data and offcut references. Subroutine checks distinguish
terminal instructions from actual RETURN p-code and known callees.
`validcode="function"` only applies at an already-defined function.
Rules needing unavailable section/context facts abort selection rather than
silently dropping those prerequisites.

Loader-derived discovery settles first. Definite/possible pattern candidates
then form a separate creation batch; they are not merged as relocation roots.
Possible entries are checked again after their disassembly exposes references:
conditional targets and entries reached from established functions are not
new functions. Definite actions take precedence over possible actions at the
same address. Rejected bodies are reconciled with their surviving owner before
the existing PIC linkage pass.

The flow walk (`discovery.rs`, `RepeatRuns`) also applies Ghidra 12.1.3
`Disassembler.disassembleInstructionBlock`'s use of
`RepeatInstructionByteTracker` (limit `MAX_REPEAT_PATTERN_LENGTH`, 16): the
seventeenth consecutive instruction whose bytes are one repeated value, the
same as the instruction before it, is not decoded and its flow stops. The
count restarts where Ghidra starts a block: an entry, a branch target, and
the instruction after a call (`endBlockOnCall`).

## ELF loaded images and worker memory

ELF record layouts and relative-relocation constants are checked against the
public GNU C Library `elf.h` SDK header (LGPL-2.1-or-later). No implementation
code is copied. REL/RELA/RELR materialization uses ELF word size and byte order.
External GLOB_DAT/JUMP_SLOT records use the same public header constants.
Their linked dynamic symbol table supplies loaded GOT-slot identities for
ELF32/ELF64 REL/RELA in the image's byte order. Recording a slot does not
establish a function; that requires independent instruction/flow evidence.
Ghidra 12.1.3 `ElfLoaderOptionsFactory` and `ElfProgramBuilder` (Apache-2.0)
establish the default image-base policy: zero-based ET_DYN images receive
0x100000 for ELF64 or 0x10000 for ELF32; prelinked bases remain unchanged.

Worker short reads follow `DecompileCallback.getBytes` lines 150–171 and
`ArchitectureGhidra::getBytes` (`ghidra_arch.cc`, lines 723–759), Apache-2.0:
a mapped starting address may return available bytes followed by zeros in
the requested-size buffer; an unmapped start remains unavailable. Ordinary
Core memory reads retain their strict region-boundary contract.

## Function constant propagation

`native_runtime/propagation.rs` and `propagation/{state,lang,graph}.rs`
follow Ghidra 12.1.3's `ConstantPropagationContextEvaluator`,
`SymbolicPropogator` and `VarnodeContext` (Apache-2.0), checked against the
extracted release sources. The evaluator supplies pointer policy; it is not
itself a propagation engine. The Rust implementation runs over the in-process
kuna-sleigh lift (`native_runtime/flow.rs`), with `OpBehavior` arithmetic from
kuna-num and prototype side-effect/stack-pop metadata read from the spec.
`native_runtime/reference_pass.rs` carries the per-round context
(register contexts, call register, externals, call fixups). No pinned
upstream file is modified or linked.

Sparse state distinguishes known bits, unknown values and affine incoming
register values. Partial register writes invalidate overlapping relations;
joins retain only agreeing facts. Unique temporaries are instruction-local.
Virtual stack offsets are internal identities, never exported pointer values.
Ordinary calls discard memory facts and non-preserved register facts, then
apply the prototype's return stack adjustment. Call-to-next handling remains
with the upstream raw-flow generation.
Each query builds its own raw graph over the range; nothing is installed in a
shared function table, so no analysis body or symbol outlives the query.
The end-exclusive query bound is converted to `FlowInfo`'s inclusive bound,
and a synthetic bounded exit is indexed in the visited map so branch-target
lookup can resolve it.

The graph is a Rust port of Ghidra 12.1.3's `FlowInfo` (`cpp/flow.cc`,
Apache-2.0): instruction following with `addrlist`/`unprocessed`,
`findRelTarget` and `branchTarget`, `setupCallSpecs`/`checkContainedCall`,
`truncateIndirectJump` and `earlyJumpTableFail`, and the injection of
call-fixup and call-other-fixup p-code (`doInjection`, with
`PcodeInjectLibrarySleigh::parseInject`'s `PcodeSnippet` compiled by the
vendored kuna-sleigh `compile_snippet`/`inject_pcode`). Stack-pointer,
default-prototype effect, `extrapop` and pointer-storage data come from the
pinned processor/compiler spec XML, with the pointer-sized-argument
assignment following `ModelRules.cc`'s fallback rule. The decompiler's
jump-table recovery runs in the flow as `FlowInfo::recoverJumpTables` orders
it (the table first, the return-address test only when no table is found,
then `truncateIndirectJump`), and the table is the one the import's
value-set pass (`native/vsa.rs`, `JumpBasic::analyzeGuards` and
`buildAddresses` of `jumptable.cc`, cited in its own section) finds over the
ops the flow holds: `propagation/jump.rs` builds the dispatch block, the
guard blocks and the shapes from the traced instructions and reads the
image through the lane's loader. A table is kept only when a guard bounds
the index, every case lies in the traced range, and it holds again once the
flow it opened is traced (`Graph::follow` strikes one that does not and
traces the range again, the way Ghidra re-analyses a jump table whose
function body changed). `Flow::jump_shape` classifies the computation that
makes a jump's target (a load whose address holds an index, arithmetic with
no load, a pointer): only the first two are dispatches. A jump with no
recovered table is treated as a return when it targets the return address and
as a call otherwise, as before.
The operand pass reads `SleighInstructionPrototype.getOpObjects` through the
vendored `Sleigh::operand_objects` / `operand_scalars` (a
`ParserWalker::get_offset` accessor was added to kuna-sleigh).

Initial-image reads follow the 1/2/4/8-byte, byte-order and nonzero rules.
Writable initial memory requires explicit trust and becomes unknown after a
call. Explicit stores remain separate from immutable image bytes. Unknown
stores and unmodeled user operations invalidate affected knowledge rather
than inventing values. Pointer candidates use the evaluator's 1024-byte low
and 256-byte high speculative limits and sentinel exclusions, plus required
membership in a supplied mapping. The function query bounds execution to
one million p-code evaluations; failure returns no successful fact payload.
Reference creation and durable provenance are separate consumers, not hidden
side effects of this request.

The separate `references` query classifies mapped-memory accesses from raw
p-code, following `RefTypeFactory.getMemRefType` and
`SymbolicPropogator.makeReference` (Ghidra 12.1.3, Apache-2.0). It returns
instruction-origin READ, WRITE, READ_WRITE and DATA records; reads and
writes to the same target in one instruction are combined. Internal affine
stack identities are not program-memory targets. The query does not write
database rows; ownership and persistence belong to the Rust core.
Reference queries follow false conditional branches, matching
`ContextEvaluatorAdapter.followFalseConditionalBranches`; constant-value
queries retain their stricter reachability rule. Memory call operands are
READ references, while indirect jump operands retain Ghidra's INDIRECTION
classification (normalized to DATA). This distinction uses original SLEIGH
p-code: `FlowInfo.truncateIndirectJump` may rewrite a jump into CALLIND.
`SymbolicPropogator.evaluatePureDataRef` rejects a pure DATA target equal to
the source instruction's fallthrough, including an implicitly saved return
PC. This uses original instruction-flow metadata and does not suppress READ
or WRITE references to data immediately following an instruction.
Literal references follow `ScalarOperandAnalyzer` and the SLEIGH
`OperandSymbol.printList` / `SleighInstructionPrototype.getOpObjects` rules.
The scalar pass honors `ScalarOperandAnalyzer.getDefaultEnablement2`'s
instruction-alignment restriction. Aligned ISAs still receive memory and
computed-use references, but unused address formation is not promoted by
the scalar pass.
The operand pass in `propagation.rs` walks decoded display operands, not assembly
text or incidental p-code constants. Direct control-flow targets keep their
flow classification; address literals in comparisons need no pointer output.
The x86-only computed-address policy follows `X86Analyzer.evaluateContext`
(Ghidra 12.1.3, Apache-2.0): LEA register outputs may create mapped DATA
references even without a later pointer use. Existing scalar references at
that instruction take precedence; ordinary unused arithmetic is not promoted.
The policy uses the decoded SLEIGH constructor mnemonic and applies only to
reference queries, not discovery or decompiler rewriting.
Computed values are not references merely because they equal mapped addresses.
Register argument/return uses follow `SymbolicPropogator.addParamReferences`,
`addReturnReferences`, and `createVariableStorageReference`. The native query
uses compiler-model storage for up to eight untyped register arguments (not
guessed stack arguments), then traces reaching setters through raw-flow
predecessors. Equal values at a join retain both possible origins. Source
search shares the propagation operation bound; it does not maintain a second
copy of every register state. `VarnodeContext`'s last-set lookup provides the
source policy; when no setter is available, the consuming instruction is used.
The importer runs the pass over in-process propagation lanes and collects the
complete pass before publishing any of its rows. ELF, PE and DOL mapping
permissions use the same low three bits; higher ELF section attributes are not
wire flags. Cross-architecture reference type and origin parity remains gated
by m2-002.

Reference context also consumes `CallFixupAnalyzer`'s compiler target-name
policy (Ghidra 12.1.3, Apache-2.0). Pattern labels with `validcode="function"`
annotate existing discovered functions only. The selected compiler's
`InjectPayloadCallfixup` supplies the p-code (the spec's `<callfixup>` bodies,
matched to a label by target name); `FuncProto.setInjectId` and `FlowInfo`
apply it. Labels are transient reference-pass context
(the import's `pattern_labels` field), not function discoveries or durable renames.
Scalar classification uses original SLEIGH control-flow targets even when
the compiler's fixup replaces a CALL in the raw function.
Symbolic alignment follows `VarnodeContext.and`'s alignment-mask policy.
The native state keeps a usable opaque frame but retires its previous
register and memory aliases before reusing the abstract origin. It does not
assume the unknown pre-alignment pointer already satisfied the alignment.
The importer selects `ConstantPropagationAnalyzer`'s default writable-memory
trust for inferred references. Explicit constant queries retain their own
trust flag and unknown-call invalidation; inference does not silently weaken
that stricter query contract.
ELF i386 PLT queries follow `X86_32_ElfExtension.processX86PltSections`:
only `DT_PLTGOT` supplies EBX, and only executable `.plt` / `.plt.*` ranges
receive it. Loader register context is transient reference-query input;
ordinary code and strict constant queries do not inherit it.
Computed LOAD operands retain `SymbolicPropogator`'s READ classification,
including loads used by indirect jumps. Fixed-address jump operands retain
their separate INDIRECTION classification; normalizing that type to DATA
does not change the classification of a computed load.
ELF section-address roots follow `ElfProgramBuilder.markupSectionHeaders`'s
imported `sh_addr` references (Apache-2.0). Allocated executable sections
supply bounded code entries independently of the function table or section
name. Existing function queries take precedence at the same entry.
As in `ConstantPropagationAnalyzer.analyzeLocation`, analysis follows flow
from a defined entry; it does not sweep disconnected bytes or create functions.
`SymbolicPropogator.addLoadStoreReference` also treats a large mapped offset
from a non-stack symbolic base as speculative DATA. Native inference applies
the existing constant filters to that offset; it does not claim that the
unknown base is zero. Stack aliases and original call instructions are
excluded. Constant-value queries do not receive these speculative facts.
ELF memory includes PT_LOAD file bytes outside allocated sections and the
zero-filled remainder of `p_memsz`, following the public ELF program-header
ABI. Section bytes and permissions retain precedence; uncovered intervals
receive converted PF_R/PF_W/PF_X permissions without overlapping existing
mappings. Completing memory does not add code entries or function seeds.
ELF32 PowerPC enables caller r30 context only with DT_PPC_GOT, following
`PowerPCAddressAnalyzer.getDefaultPropagateR30Option` and
`setRegisterIfNotSet` (Apache-2.0). Complete nonzero values at real calls seed
only their destinations; existing context wins. Local references are collected
before each round activates new call context, so function scheduling does not
erase speculative offset DATA. Contextual analysis adds precise accesses and
deduplicates repeated facts. This transient worklist does not create functions,
modify strict constant queries, or promote branch xrefs into calls.

Reference ownership uses `Reference.getSource` and the documented `SourceType`
priority: USER_DEFINED and IMPORTED become asserted facts; ANALYSIS, AI and
DEFAULT remain inferred. The bridge reports the source without manufacturing
a confidence score. Rust persists ownership separately from the producer
label and preserves assertions when replacing inferred references.

## Jump-table recovery over p-code

`native/vsa.rs` and `native_runtime/propagation/jump.rs` port the method of
Ghidra 12.1.3's `jumptable.cc` (Apache-2.0) onto SLEIGH's p-code instead of
the decompiler's SSA form: `JumpBasic::analyzeGuards` (:1061, the guard that
bounds the switch variable, single-predecessor chains and `maxbranch`),
`JumpBasic::buildAddresses` (:1451-1478, the emulation of the path that feeds
the branch once per index value), `JumpValuesRange` (the value range the
guard gives), `JumpBasic::foldInOneGuard` (:1390, the guard's target follows
the cases) and `JumpBasic::findDeterminingVarnodes` (:554, the path read
backwards from the branch). `FlowInfo::recoverJumpTables` (`cpp/flow.cc`) fixes
the order the reference flow asks in: the table, then the return-address
test, then `truncateIndirectJump`. No source of m2c, PCSX2 or binutils was
read for this; the guard and emulation rules are Ghidra's, restated here in
terms of raw p-code.

## Reference oracle analysis context

The M2 reference comparison uses explicit language/compiler pairs through
Ghidra 12.1.3's `ProgramLoader.Builder.language(String)` and
`compiler(String)` (Apache-2.0). `PowerPC.opinion` constrains ELF machine 20
to 32-bit PowerPC but does not select a variant; automatic import selected
e500 while native ELF import selected the default variant. Their reference
source decisions differ, so an automatic variant is not a parity baseline.
The gate declares the four corpus contexts independently, validates the
oracle's actual language/compiler, and checks the native stored language.
Native compiler transport is the full language/compiler identity in
`MappedImage`'s `binaryimage` attribute; the argument-reference regression
exercises its SysV/Windows ABI difference rather than checking XML text.
Explicit-context references live under `oracle/xrefs-v1/explicit-context-v1/`;
the complete automatic-selection references are retained unchanged. No
reference-kind normalization, precision/recall definition, or threshold is
changed by choosing matching contexts.

## Native string facts

The string oracle enumerates Ghidra 12.1.3 `DefinedStringIterator` and decodes
through `StringDataInstance` (Apache-2.0), including non-loaded metadata.
`ElfProgramBuilder.markupStringTable` declares ELF table entries as UTF-8;
native import retains that encoding and the section's address space rather
than treating `.shstrtab` offsets as RAM addresses.

The native sweep covers ASCII, UTF-8, and endian-aware UTF-16 data, with a
minimum of four Unicode scalar values. BOMs, string-start data references,
and UTF-16 alignment resolve overlapping interpretations. The upstream
`StringsAnalyzer` defaults to ASCII-only discovery; its n-gram model is
not copied into the native decoder.

Worker string responses follow `ArchitectureGhidra::getStringData`
(`ghidra_arch.cc:774–816`) and `DecompileProcess.getStringData`: two six-bit
length fields, truncation byte, A-biased UTF-8 bytes, and a NUL terminator.
`DecompileCallback.StringData` counts UTF-16 code units; a split surrogate
uses Java's UTF-8 `?` replacement. These APIs are from the pinned Apache-2.0
Ghidra sources. Payloads are bounded by the protocol's 12-bit byte length.

## Recovered native prototypes

`crates/romwright-worker/src/prototype.rs` follows the pinned Ghidra 12.1.3
`Funcdata::encode`, `FuncProto::encode`, `ProtoStoreInternal::encode`,
`Symbol::encodeHeader`, and datatype `encodeRef`/`encode` methods
(`funcdata.cc`, `fspec.cc`, `database.cc`, `type.cc`; Apache-2.0).
It shares the existing packed decoder rather than parsing C text or adding
another wire grammar. Symbol category indices order recovered parameters;
nested function-pointer prototypes do not replace the enclosing function's
prototype. Missing references remain unknown, and malformed or truncated
documents do not publish a partial prototype. No pinned source is modified.

The switch projection in `crates/romwright-worker/src/doc.rs` follows
`Funcdata::encodeJumpTable` and `JumpTable::encode` (`funcdata.cc`,
`jumptable.cc`; Apache-2.0). It retains the branch address and every ordered
destination, including duplicates. The structural function's direct address
distinguishes native facts from C markup. Optional labels and the recovered
default block are not reinterpreted as target facts. The benchmark-only
`scripts/ExportSwitchTargets.java` uses `HighFunction.getJumpTables`,
`JumpTable.getSwitchAddress`, and `JumpTable.getCases`, verified against the
extracted Ghidra 12.1.3 Java sources (Apache-2.0).

## Native non-returning recovery

Worker metadata follows `Funcdata::decode` and `FuncProto::encode`/`decode`
in pinned `funcdata.cc` and `fspec.cc` (Apache-2.0): non-returning behavior is
the prototype's `ATTRIB_NORETURN`, not a function-shell attribute. Packed
booleans follow `PackedEncode::writeBool` in `marshal.cc`. Output type storage
stays unlocked so the flag does not replace existing prototype recovery.
Known names and leading-underscore normalization follow Ghidra 12.1.3
`Features/Base/data/{Elf,PE}FunctionsThatDoNotReturn` and
`NoReturnFunctionAnalyzer` (Apache-2.0). `native/romwright_nonreturn.hh` checks
completed basic-block CFGs, halt flags, and recovered jump tables using pinned
`funcdata.hh`, `block.hh`, `op.hh`, and `jumptable.hh`; it exports a transient
prototype flag and restores the cached prototype after encoding.
The benchmark-only `scripts/ExportReturnBehaviors.java` reads
`Function.hasNoReturn`, inherited `Namespace.getBody`, and
`AddressSetView.getAddressRanges` / `AddressRange` endpoints from the extracted
Ghidra 12.1.3 Java API (Apache-2.0). Eligibility reuses `code-functions-v1`.
The native flow closure and revision-owned SQLite publication are Romwright code.

## Benchmark DWARF arity truth

`benchmarks/dwarf_arity.py` invokes GNU `readelf` (GPL-3.0-or-later) on
the locked unstripped ELF twins. No Binutils implementation is copied or
linked into a runtime crate. The projection counts `DW_TAG_formal_parameter`
children, including artificial parameters, and follows abstract origins and
specifications without filtering parameters by available locations. Inline
instances and declaration-only DIEs are not separate functions. Unresolved
origins, conflicting entry arities, and unsupported range-only subprograms
fail the export instead of silently reducing the truth set. Analyzers receive
the stripped twins, never these benchmark-only DWARF facts.

The stock arity reference runs Ghidra 12.1.3's
`DecompilerParameterIdCmd` after ordinary headless analysis, using
`DecompilerFunctionAnalyzer`'s defaults: clear ANALYSIS signatures, commit
data types, do not force void returns, and allow 60 seconds per decompile
(Apache-2.0). This analyzer is normally disabled for ELF, so the exporter
invokes it explicitly. `Function.getParameterCount` includes auto-parameters;
no C rendering is parsed. Immutable `baseline-*.json` records pin stripped
input hashes, exporter identity, language/compiler, and the loaded image base.
DWARF and stock results are joined only in the benchmark, after analysis.

## Rust C printer

`crates/romwright-worker/src/printc/` ports, from the vendored Ghidra 12.1.3
C++ (Apache-2.0), `PrintC`'s block layer (`printc.cc`: `docFunction`,
`emitBlockBasic` ... `emitBlockSwitch`, `emitGotoStatement`, `emitAnyLabelStatement`,
`emitCommentGroup`/`emitCommentBlockTree`), the comment walk of
`CommentSorter` (`comment.cc`), and `EmitPrettyPrint`, `EmitMarkup` and
`TokenSplit` (`prettyprint.{hh,cc}`) with `PackedEncode`'s integer and space
encoding (`marshal.cc`). It was written from those sources; kuna's Rust port
of the same files ([noelo-Lab/kuna](https://github.com/noelo-Lab/kuna) commit
`bca4ae8d`, Apache-2.0) was read for comparison only and no code was taken
from it. `printc/render.rs` (2026-10-09) ports PrintC's expression emission
from the same tree: `PrintLanguage::pushOp`/`pushAtom`/`recurse`/`parentheses`/
`emitOp`/`opBinary`/`opUnary`, `printlanguage.cc`'s `mostNaturalBase` and
`formatBinary`, the `OpToken` table and op handlers of `printc.cc` (`opLoad`,
`opStore`, `opPtradd`, `opPtrsub`, `opCall*`, `opReturn`, `opIntZext`,
`opSubpiece`, `opTypeCast`, `opBoolNegate`, `opCbranch`, `push_integer`,
`pushCharConstant`, `pushConstant`'s default form, `pushSymbol`,
`pushSymbolScope`, `pushPartialSymbol`, `pushTypeStart`/`pushTypeEnd`,
`emitExpression`), `TypeStruct::findTruncation`/`TypeArray::getSubEntry`
(`type.cc`), and `CastStrategyC::isZextCast`/`isSextCast`/`isSubpieceCast`
(`cast.cc`), plus the mixed-operator grouping rule of this repository's own
`native/ghidra-opt-sleigh.patch`. `native/romwright_printir.hh` exports, from
PrintC's own state, the data those routines read (types, symbols, cast
decisions) and, for the leaves the port does not format, the single token
PrintC's handler produced (docs/printer-ir.md).

## Desktop rendering and fonts

`crates/romwright-desktop` draws its window with egui/eframe 0.36 and the
`egui-wgpu` renderer over wgpu 30 (all MIT OR Apache-2.0), docks panels with
`egui_dock` 0.21 (MIT), and encodes offscreen frames with `png` (MIT OR
Apache-2.0). The workbench's information architecture, palette roles and line
icons are Romwright's own, carried over from its earlier desktop frontend; no
third-party UI code was copied.

The UI typeface is Inter 4.1 (<https://github.com/rsms/inter>) and the code
typeface JetBrains Mono 2.304 (<https://github.com/JetBrains/JetBrainsMono>),
both SIL Open Font License 1.1, bundled unmodified with their license texts in
`crates/romwright-desktop/assets/fonts/`. File hashes are recorded in
`THIRD_PARTY_NOTICES.md`.

## GameCube REL, CISO/GCM and Yaz0 (P3.1)

`native/rel.rs`, `native/disc.rs` and `native/yaz0.rs` read GameCube RELs, CISO
and GCM discs, and Yaz0 streams. The REL layout, the relocation-stream opcodes
(`R_PPC_*` 0-13 plus `R_DOLPHIN_NOP/SECTION/END/MRKREF` 201-204) and the merged
placement (`align32(__ArenaLo + 0x2000)`, sections 32-byte aligned, module-id
order) follow encounter/decomp-toolkit v1.8.3 (`src/util/rel.rs`,
`src/cmd/rel.rs`; MIT OR Apache-2.0). CISO, GCM boot header, FST and Yaz0 follow
the community format notes (YAGCD; the Yaz0 and CISO pages of the Custom Mario
Kart / Dolphin wikis). No code was copied from any of them, and no GPL source
(Dolphin, m2c, binutils) was read. `dtk rel info` and `dtk rel merge` are
used as test oracles only (`benchmarks/gc_rel_gate.py`, optional in
`tests/m20-014_rel.py`); the dtk binary is not bundled.

Animal Crossing symbols (`ACreTeam/ac-decomp`, CC0-1.0; see `THIRD_PARTY_NOTICES.md`)
are the function-recovery truth for `foresta.rel`; they are read from a local
clone on the measurement host and not copied into this repository. The GameCubeLoader
extension (Apache-2.0, Cuyler36) is run as the stock comparison only.

## GameCube/Wii disc containers: `nod` (P3.4)

`native/wii.rs` reads RVZ, WIA, WBFS and Wii ISO (encrypted partitions) through
the `nod` crate, `=2.0.0-alpha.9` (<https://github.com/encounter/nod>, Luke
Street; **MIT OR Apache-2.0**, taken as recorded in the crate manifest on
crates.io; maintained, 2.0.0-alpha.9 published 2026-05-26). `nod` is used as a
library, unmodified, with its default features (bzip2, LZMA, zlib and zstd
decoders built from vendored C sources; `threading` on, but no preloader thread
is started). It decodes only the groups a read touches: the boot header, the
FST, the DOL and the RELs, so a disc of any size is never expanded to an ISO in
memory or on disk (`native/disc.rs` `Disc::Partition`; the compressed file
itself is the one captured input, shared by reference).

Transitive crates new to the tree: `aes`/`cbc`/`cipher`/`digest`/`sha1`/`md-5`
(RustCrypto, MIT OR Apache-2.0), `crc32fast`, `xxhash-rust` (BSL-1.0),
`encoding_rs` ((Apache-2.0 OR MIT) AND BSD-3-Clause), `zstd-sys` (BSD-3-Clause
with the vendored zstd), `bzip2-sys`, `liblzma-sys`, `libz-sys` (MIT OR
Apache-2.0, vendored bzip2 / xz / zlib sources under their own permissive
terms), `lru`, `itertools`, `bytes`, `dyn-clone`, `zerocopy`,
`polonius-the-crab`, `tracing`, `crossbeam-*`, `simple_moving_average` (MIT). The
previous in-tree RVZ chunk decoder and its `zstd` and `lz4_flex` dependencies
are gone: that decoder handled only a layout that no real RVZ uses.

`nod` carries the Wii common keys it needs to unwrap a title key from the
disc's own ticket. Romwright adds no key and no key derivation of its own; a
disc whose partitions it cannot open is refused with `nod`'s error (see the
plan's legal register, Wii common key/title keys: never ship or commit).

The Wii data-partition layout (`0x5d1c9ea3` at 0x18, DOL offset, FST offset and
size, and every FST file offset stored shifted right by two) follows YAGCD and
the Wiibrew disc-format notes; no GPL source (Dolphin, wit) was read.

## GameCube/Wii archives and PlayStation CD images (P3.4b)

`native/archive.rs` lists the files of the two archives games pack their RELs
in, so `native/disc.rs` links RELs that are not files of the disc's own file
system (Wind Waker's and Twilight Princess's `RELS.arc`, Skyward Sword's
`rels.arc`): **RARC** (the RARC pages of the Custom Mario Kart and Luigi's
Mansion modding wikis) and **U8** (Wiibrew, "U8 archive"), plain or wrapped in
Yaz0. `native/rel.rs` now places RELs that share a module id as programs of
their own (Mario Party 4's DLLs); that is a layout decision recorded in
STATUS.md, not a format. The Yaz0 decoder gained a prefix mode so a directory
is read without unpacking the archive.

`native/iso9660.rs` and `native/cue.rs` import PlayStation CD images: ECMA-130
(sector layouts: 12 sync bytes, a 4-byte header with the mode, a mode-2 XA
subheader), ECMA-119 (ISO9660 volume and directory records), psx-spx ("CDROM
Disk Images", "CDROM File Formats": 2352- and 2336-byte tracks, the cue-sheet
grammar; "Executables" for the PS-EXE header, already read by `native/psx.rs`)
and the cdrdao/CDRWIN cue grammar. `SYSTEM.CNF`'s `BOOT = cdrom:\FILE;1` line
names the PS-EXE. No code was copied from any of them, and no GPL source
(PCSX2, mednafen, Dolphin, binutils) was read.

## MWCC symbol demangling (P1.7)

`crates/romwright-core/src/qualified_prototypes/mwcc_demangle.rs` decodes
Metrowerks (CodeWarrior) C++ mangling. The output spelling and the edge cases
(`___` runs in names, `Fv_v`-style return types, `Q<n>` scopes, operator
codes, `$localstatic` forms, array/function-pointer declarators) follow
encounter/cwdemangle (<https://github.com/encounter/cwdemangle>, CC0-1.0;
the library inside decomp-toolkit's `dtk demangle`, MIT OR Apache-2.0) as
observed through `dtk demangle` 1.8.3, which is used as a test oracle only
(`benchmarks/mwcc_demangle_diff.py`); the dtk binary is not bundled and no
source was copied. The `T<i>` / `N<n><i>` repeated-parameter back-references
are an extension that follows the gcc-2 mangling description (the format only;
no GPL source was read) and are switched off for the oracle comparison
(`Options::DTK`). Symbol corpora used by the differential: Agent Under Fire
and Nightfire symbol lists and ELF symbol tables from local projects, and
`ACreTeam/ac-decomp` symbols (CC0-1.0), read in place and not copied.

## Metrowerks DWARF 1 types (P3.3)

`native/mdebug/dwarf1.rs` (importer) and `benchmarks/dwarf1_types.py` (the
benchmark's independent reader) decode the DWARF 1 `.debug` stream that
Metrowerks' MIPS compiler writes into SLUS_209.50. The grammar is the DWARF
1.1.0 draft (UNIX International, 1992); tag, attribute and fundamental-type
numbers were checked against the image (names against `.symtab`, sibling
chains, struct layouts). Two Metrowerks facts are measured, not taken from a
reference: `long` is 64-bit (303 struct members, none 4), and `FT 0xa510` is
the 16-byte `I128`/`UI128` multimedia member type. No third-party code was
read or copied, GPL (gdb, binutils) included. The Rust and Python readers share
no code; `benchmarks/dwarf1_diff.py` compares them. The Python reader and the
PSP Puzzle Bobble DWARF 2 are benchmark truth only, never an import input (the
research input is the llvm-strip'd twin).

## Nintendo CTR SDK function declarations (`ctr_sdk.json`)

`oracle/library-prototypes-v1/ctr_sdk.json` (written by `scripts/gen_ctr_sdk_prototypes.py`, applied by
`named_prototypes.rs` to the functions a 3DS project names) holds function names, parameter counts and
parameter/return types read from the DWARF debug info of six retail 3DS games that shipped it. Facts only: no
code, no disassembly, no struct layout or header text; every type is reduced to a core type or `void *`.

## Compiler run-time helper signatures (symbol-name typing)

`oracle/library-prototypes-v1/runtime_helpers.json` (written by
`scripts/gen_runtime_helpers.py`, applied by `native/store.rs`'s symbol-name
pass through `library_types/helpers.rs`) declares the signatures of the
compiler's own helper routines (`__adddf3`, `__udivdi3`, `__fixdfsi`,
`__aeabi_dadd`, ...). Facts only, from two public documents; no libgcc,
compiler-rt or any other library source was read:

- GCC Internals, "The GCC low-level runtime library" (sections 3.1, integer
  routines, and 3.2, soft-float routines), https://gcc.gnu.org/onlinedocs/gccint/Libgcc.html
  (the GCC manuals are published under the GNU Free Documentation License;
  only the routine names and their stated argument and result modes were
  transcribed, no prose). The document types these by machine mode with
  illustrative C types (`long` for `DImode`), so the table keeps the mode and
  the runtime resolves it against the language's own type widths.
- Run-time ABI for the Arm Architecture (`rtabi32`, release 2025Q4, Arm
  Limited, CC-BY-SA-4.0 with a patent license), https://github.com/ARM-software/abi-aa/blob/main/rtabi32/rtabi32.rst
  (the `__aeabi_*` floating-point, long long, integer division, unaligned
  access and memory helpers; signatures only).

Not covered, each for the stated reason: complex-number routines (no C spelling
for the result), `_BitInt` routines (target-defined limb type), decimal-float
and fixed-point routines (`_Decimal32`, `_Fract` and kin are in no language's
type document, so no row could ever be applied), `__value_in_regs` aggregate
returns (`__aeabi_idivmod`, `__aeabi_ldivmod`), the obsolete `__aeabi_fneg` and
`__aeabi_dneg`, and the C++ vector helpers. The MIPS and PowerPC EABI
documents name no C-level helper signatures (their out-of-line routines are
register-convention save/restore stubs), so nothing from them is recorded.

## dtk / splat / objdiff project files (P1.9, P2.1)

`crates/romwright-core/src/export.rs` writes decomp-toolkit `config.yml`,
`splits.txt` and `symbols.txt`, splat `<name>.yaml` and `symbol_addrs.txt`, and
objdiff `objdiff.json` units, and reads objdiff-cli `report generate` JSON.
Formats and behaviour only: dtk's symbol grammar (`name = section:0xADDR; //
type:function size:0x.. scope:global`), the `Sections:` block (entries bind to
a DOL's sections by position, names must not contain `:`), `dtk dol diff`'s
per-symbol check, and the `config.json` `autogenerated` units (decomp-toolkit
1.8.3, MIT OR Apache-2.0, observed through the binary; no source copied);
splat's option set, segment list (`start` is a file offset; the last entry is
the end offset), `symbol_addrs.txt` attributes and its duplicate/filename rules
(splat 0.39.1, MIT, read from its documented behaviour and error messages; no
source copied); objdiff 3.6.1's `objdiff.json` unit keys (`metadata.complete`,
`auto_generated`, `source_path`), report JSON (64-bit counters as strings,
zero fields omitted, `functions` arrays) and `report changes` shape (MIT OR
Apache-2.0, observed through objdiff-cli; no source copied). None of the three
tools is bundled; they are test oracles only.

## N64 segment layouts and codecs (P3.3)

`native/n64_codec.rs` and `native/n64_layouts.json` unpack the code a Nintendo
64 ROM stores compressed. Written from format facts, no code ported:

- **MIO0** and **Yay0**: Hack64 wiki pages "MIO0 Compression"
  (`super_mario_64:mio0`) and "YAY0 Compression" (`paper_mario:yay0`) for the
  header, layout bitmap, 16-bit back reference and the extended length; the
  MIO0 page's own game list (Super Mario 64, Mario Kart 64, F-Zero X, Star Fox
  64, Wave Race 64, Pilotwings 64, ...). **Yaz0**: nintendo-formats.com "Yaz0"
  (`libs/sead/yaz0`) for the header and the code-byte groups; Ocarina of Time
  and Majora's Mask use it. Wiki text is documentation; none of it is copied.
  The libraries those pages list (queueram/sm64tools, ...) were not read.
- **Rare zlib** (`0x1172`, `0x1173`) and the Perfect Dark segment layout: the
  `n64decomp/perfect_dark` repository (MIT, Copyright (c) 2022 Ryan Dwyer)
  documents it in `tools/rareunzip`, `tools/extract-segment`, `tools/extract`
  (magic, 3-byte length, raw DEFLATE; a game segment as a table of offsets to
  4 KiB pages; the `lib`/`data`/`game` ROM offsets of each revision) and
  `ld/pd.ld` (segment order and RAM addresses). Those scripts are MIT and were
  read for their facts; each fact in the layout was re-measured against the
  ROM bytes (declared lengths equal inflated lengths; segment sizes equal the
  linker script's RAM ranges). The decomp's `tools/gzip` and `tools/mkrom`
  contain GPL-derived gzip code and were not opened. DEFLATE itself is
  `miniz_oxide` (MIT OR Zlib OR Apache-2.0), already a dependency.
- **Stock comparison**: the N64LoaderWV extension (zeroKilo, built from
  `~/opt/n64loader-src` with the repo's Ghidra 12.1.3 patch) was run headless
  as a measurement; no code from it is used.

### N64 layout discovery from the ROM's bytes (`native/n64_discovery.rs`, 2026-10-10)

The importer finds segments and overlays for ROMs the catalog does not list.
What it relies on, and where each fact comes from:

- **Entry point per CIC variant**: n64brew wiki "CIC-NUS" (the "Game
  Entrypoint" column: `u32@0x08` for 6101/6102/6105, `-0x100000` for 6103/7103,
  `-0x200000` for 6106/7106). The importer does not identify the chip: it takes
  whichever of the three candidates the boot code's own `jal` targets agree
  with. Wiki text is documentation; none of it is copied.
- **MIPS encodings**: `jal` (opcode 3, 26-bit word index, region of the
  delay-slot PC), `lui`/`addiu`/`ori` constant pairs, `addiu sp, sp, -N` and
  `jr ra` as the o32 prologue/epilogue, and the reserved opcodes and
  must-be-zero fields used to tell code from data. Standard MIPS III; the
  pinned Ghidra MIPS SLEIGH spec (Apache-2.0, already a dependency) agrees.
- **Packed-file headers**: Yaz0 / MIO0 / Yay0 as above. The Banjo-Kazooie
  `0x1172` header (magic, 4-byte big-endian inflated length, raw DEFLATE) was
  measured on that ROM, not read from a source: at every stream the length
  equals what inflates.
- **Truth** (benchmarks only, never an importer input):
  `~/romwright-corpus/extracted/n64-<slug>/truth/{layout.json,functions.tsv}`
  from the matching decomps (`zeldaret/oot`, `zeldaret/mm`, `n64decomp/sm64`,
  `n64decomp/banjo-kazooie`, `pmret/papermario`, `n64decomp/perfect_dark`,
  `sonicdcer/sf64`, `VetriTheRetri/ssb-decomp-re`, `AngheloAlf/drmario64`; GPL
  or unlicensed). `benchmarks/n64_layout_score.py` reads them after the
  import; no file, address or name from them is in the importer, the catalog
  or the tests.

## Calling-convention work: IDO o32 and MWCC register-save helpers (P2.3, P2.4)

- **o32 argument slots** (`romwright-worker` `specs.rs::with_o32_argument_rules`):
  the MIPS o32 convention as the MIPS ABI handbook states it (word slots; a
  leading float run in `f12`/`f14` shadowing `a0`/`a1`; stack arguments from
  `sp+16`), written with the decompiler's own `<group>`/`<rule>` constructs,
  following the shape the pinned stock MIPS32 spec (Ghidra 12.1.3, Apache-2.0)
  already uses for the same convention. No code from m2c, IDO recomp or
  binutils (GPL, reference-only) was read or copied.
- **MWCC `_savegpr_N`/`_restgpr_N`/`_savefpr_N`/`_restfpr_N`**
  (`native/mwcc_runtime.rs`, `specs.rs::mwcc_callfixups`): the sled layout was
  read off the retail bytes of Animal Crossing `main.dol` (0x8009ae00..0x8009af2c)
  and agrees with the labels decomp-toolkit (MIT OR Apache-2.0) and ac-decomp
  (CC0-1.0) assign. The pinned Gekko spec's own `_savegpr_N`/`_restgpr_N`
  fixups address through `r1`; the helper addresses through `r11`, so ours
  replace them.
- **Truth** (benchmarks only, never an import input): `n64decomp/perfect_dark`
  (MIT) function names, C prototypes and link order via
  `benchmarks/pd_ido_truth.py`; function addresses are derived from the ROM's
  own bytes (the game segment is inflated by a decoder written from the Rare
  zlib format facts, not ported from the decomp's `tools/extract`);
  `ACreTeam/ac-decomp` (CC0-1.0) via `benchmarks/ac_mwcc_truth.py`. The PD
  decomp's clone lives under `~/opt` on the build host and is not committed.

## Soft-float PSX and GBA conventions (P2.5)

- **PS-EXE `$gp`** (`native/psx.rs`): psx-spx "Executables" (initial GP at header
  offset 0x14, zero meaning the program sets it) plus a scan of the file's own
  crt0 bytes for psyq's `lui gp,hi; addiu/ori gp,gp,lo`. Validated against the
  linker map's section table (Darkstalkers 3's `.sdata` starts at the value the
  scan finds), and against 302 of 313 `$gp`-based loads and stores landing in
  `.sdata`/`.sbss`. No psyq source or header was used.
- **psyq o32 soft-float** (`specs.rs::with_psyq_soft_float`): the R3000A has no
  FPU, so the float slots of the PSX spec are removed. Written from the
  hardware fact, not from a psyq header.
- **agbcc / APCS**: no cspec change. The pinned `ARM-LE-32-v4t` spec is already
  soft-float with `r4`..`r11`/`sp` callee-saved; the only APCS/AAPCS difference
  that matters (a 64-bit argument's register pairing) is not visible in
  pokeemerald, which passes no `float`/`double`/`s64`, so it was not changed.
  The two hand-assembled bundles `ARM-LE-32-v4t-apcs` (byte-identical to
  `ARM-LE-32-v4t`) and `PSX-LE-32-psyq-soft` (no language to select it) from an
  earlier commit were never wired to anything and are removed.

## PSX language (P4.1 GTE decode)

`native/languages/psx` builds `PSX:LE:32:default` from sources we may use:

- **MIPS base**: Ghidra 12.1.3's MIPS32 little-endian SLEIGH (`mips.sinc`,
  `mips32Instructions.sinc`, `mipsfloat.sinc`), `mips32le.cspec`, `mips32.pspec`
  (Apache-2.0, vendored in `third_party/ghidra/languages/mips`). `install.sh`
  stages those files, applies `stock-cop2.patch` (removes the generic
  `mfc2`/`mtc2`/`cfc2`/`ctc2`; adds the GTE fields to the `instr` token, because
  a constructor cannot mix fields of two tokens) and compiles `psx.slaspec`. The
  MIPS16/microMIPS/MT/DSP sets of the stock slaspec are not included: the
  R3000A has none of them. `psx.cspec` is `mips32le.cspec` plus one `<range>` for
  the GTE register block; `psx.pspec` is `mips32.pspec` minus the MIPS:BE
  assembly rating.
- **GTE/COP2** (`gte.sinc`): psx-spx, "Geometry Transformation Engine (GTE)":
  the cop2r0-63 register map and names, `mfc2`/`mtc2`/`cfc2`/`ctc2`/`lwc2`/`swc2`
  semantics (SXYP FIFO push, IRGB to IR1-3, LZCS to LZCR, 16-bit extension of
  narrow registers, read-only ORGB/LZCR, FLAG bit 31), and the command word
  (`0100101` + `sf` bit 19, `mx` 18:17, `v` 16:15, `cv` 14:13, `lm` bit 10,
  command number bits 5:0) with the 22 command numbers RTPS 0x01, NCLIP 0x06,
  OP 0x0C, DPCS 0x10, INTPL 0x11, MVMVA 0x12, NCDS 0x13, CDP 0x14, NCDT 0x16,
  NCCS 0x1B, CC 0x1C, NCS 0x1E, NCT 0x20, SQR 0x28, DCPL 0x29, DPCT 0x2A,
  AVSZ3 0x2D, AVSZ4 0x2E, RTPT 0x30, GPF 0x3D, GPL 0x3E, NCCT 0x3F. Each command
  is a named pcodeop `gte_<command>(...)` with its decoded flag fields as
  arguments. The arithmetic of a command is not modelled.
- **Inline-macro lifter** (`crates/romwright-worker/src/printc/gte.rs`, P4.1):
  prints GTE register moves and commands as one call per macro. Sources: the
  command names (`RTPS`, `RTPT`, `NCLIP`, `AVSZ3`, ...), register names and the
  register-to-memory moves are psx-spx's (same chapter as above). The macro
  names that group several moves (`gte_ldv0`..`gte_ldv3`, `gte_ldsxy3`,
  `gte_stsxy3`, `gte_stlvnl`, `gte_SetRotMatrix`, ...) and the short store
  names (`gte_stsxy`, `gte_stsz`, `gte_stotz`, `gte_stopz`, `gte_stdp`,
  `gte_strgb`) are the PlayStation SDK's inline-macro API names, written from
  knowledge of that public interface: a name, its argument roles and the
  registers it moves. No SDK header, source, table or documentation text was
  read or copied, no open SDK (PSn00bSDK included) was consulted or
  vendored, and the argument layouts (a vertex is `VXYn` from `p` and `VZn`
  from `p+4`; the translation vector sits at `p+20`) are the structures'
  documented layouts. The names are labels for the reader, not a claim of
  byte-for-byte SDK equivalence; they have not been checked against an SDK
  install. The deleted `gte_lift.rs` (whose tables came from PsxLoader's
  `inline_s.sinc`) was not consulted.
- **Not used**: `lab313ru/ghidra_psx_ldr` ("PsxLoader"): no licence file and no
  licence headers. Its `cop2_regs`, `gtemac`, `inline_c`, `inline_s`,
  `macro_addrs` `.sinc` files and its `mips.ldefs`, `mips32.pspec`,
  `mips32le.cspec` and the bundle's `cspec.xml`/`pspec.xml` were byte-identical
  copies and are removed; `mips.sinc`/`mips32Instructions.sinc` were its
  modified MIPS copies and are replaced by the stock files plus
  `stock-cop2.patch`. The PsxLoader jar remains a Ghidra-side baseline loader
  only; `install.sh` moves its `data/languages` out of the scanned tree so the
  language id resolves to ours.

## XEX2 normal (LZX) compression

`crates/romwright-core/src/native/xex.rs` decodes the base file format's
compression mode 2 as a chain of blocks (`nextSize: u32`, a 20-byte hash,
then big-endian `u16` length-prefixed chunks, a zero length ending the block)
whose chunks are the frames of one LZX stream, windowed by the header's
`window_size`.

- **LZX bitstream**: Microsoft's public [MS-PATCH] LZX DELTA Compression and
  Decompression specification (block types, pretree/path-length coding,
  16-bit-aligned frames of 32 KiB of output). It is decoded by the
  [`lzxd`](https://crates.io/crates/lzxd) crate (`MIT OR Apache-2.0`), which
  implements that specification and is a normal dependency; the regression
  test's bit writer is written from the same specification.
- **Block chain and chunk framing**: checked against the BSD-3-Clause xenia
  XEX loader (`src/xenia/cpu/xex_module.cc`, the de-blocking loop: a block is
  `cur_block->block_size` bytes long, its 4+20-byte header names the *next*
  block, chunks are `u16` BE length plus payload until a zero length) and
  against XEXLoaderWV (Apache-2.0, already cited above). Only the structure
  was taken; xenia's bundled mspack-derived LZX code (LGPL) was not read or
  used, and neither were libmspack or wimlib.
- **Frame = chunk**: not stated by the references above; established on a real
  devkit image (59 blocks, 286 chunks, image size `0x8f0000` = 286 x `0x8000`)
  and confirmed by the decoded image matching the separately staged raw PE.
  No game bytes are in the repository; the regression test builds its LZX and
  XEX structures from the public layouts.
