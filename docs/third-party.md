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

`.vsig` (`docs/vsig.md`, `crates/lre-sig`) is Ventris' own container. Pattern
plus per-byte compare mask is a general, publicly described idea; no
proprietary signature format documentation, database or tool output was
consulted, and nothing is byte-compatible with one. Every record carries the
exact package build it was extracted from and that package's license, so a
shipped database can be audited and redistributed on those terms.

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

`native/ventris_flow.hh` follows Ghidra 12.1.3
`SleighInstructionPrototype.walkTemplates`, `flowListToFlowType`,
`gatherFlags` and `convertFlowFlags` (Apache-2.0). The pinned-tree patch
collects template flow facts during ordinary SLEIGH p-code generation, not
through a second decode. Instruction-local labels and `inst_start`/`inst_next`
branches are not exported as machine flow references.

`FLOW` includes conditional/terminal classification, actual RETURN p-code
evidence, and individual delay-slot lengths. Total length includes slots;
slot effects do not alter the parent's prototype flow classification.
Discovery follows the reported fallthrough, including conditional returns,
and does not invent fallthrough after terminal calls. Console consumers require
the enriched protocol; rebuild both native binaries after this cutover.
Ordinary decompiler translation does not collect the optional flow metadata.

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
`native/ventris_linkage.hh` consumes SLEIGH p-code and reuses the decompiler's
registered `OpBehavior` constant evaluators. It tracks pointer-slot identity,
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

`native/ventris_patterns.hh` follows Ghidra 12.1.3 BytePatterns (Apache-2.0):
`Patterns`, `Pattern`, `PatternPairSet`, `DittedBitSequence`, `AlignRule`,
`LanguageConstraint`, `CompilerConstraint`, and `generic.constraint.DecisionNode`.
The existing native XML parser reads installed `patternconstraints.xml` and the
selected pattern files. Selection uses the loaded language and resolved compiler
specification, including more-specific decision precedence; it does not infer a
compiler from opcode bytes.

The console command `functionstarts <start> <end> ...` accepts exclusive-end
mapped ranges and returns `PATTERNS` JSON: instruction alignment, shared source
rules with ordered action attributes, and address/rule matches. Matching preserves
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

`native/ventris_flow.hh` follows Ghidra 12.1.3
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

`crates/lre-core/src/native/discovery/patterns.rs` follows Ghidra 12.1.3
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

`native/ventris_constants.hh` follows Ghidra 12.1.3's
`ConstantPropagationContextEvaluator`, `SymbolicPropogator` and
`VarnodeContext` (Apache-2.0), checked against the extracted release sources.
The evaluator supplies pointer policy; it is not itself a propagation engine.
The native implementation uses the pinned `Funcdata`/`FlowInfo` raw graph,
`OpBehavior` arithmetic, and prototype side-effect/stack-pop metadata.
No pinned upstream files are modified in place.

Sparse state distinguishes known bits, unknown values and affine incoming
register values. Partial register writes invalidate overlapping relations;
joins retain only agreeing facts. Unique temporaries are instruction-local.
Virtual stack offsets are internal identities, never exported pointer values.
Ordinary calls discard memory facts and non-preserved register facts, then
apply the prototype's return stack adjustment. Call-to-next handling remains
with the upstream raw-flow generation.
Each query creates a temporary symbol-owned function. Its distinct scope id
prevents collisions with anonymous jump-table recovery clones. Removing the
query's symbol also removes its analysis body; pre-existing bodies stay intact.
The end-exclusive query bound is converted to `FlowInfo`'s inclusive bound.
The out-of-tree flow patch indexes synthetic bounded exits in the visited
map so branch-target lookup can resolve them.

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
`native/ventris_operand_refs.hh` walks decoded display operands, not assembly
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
The importer reuses discovery's loaded console and collects the complete pass
before publishing any of its rows. ELF, PE and DOL mapping permissions use
the same low three bits; higher ELF section attributes are not wire flags.
Cross-architecture reference type and origin parity remains gated by m2-002.

Reference context also consumes `CallFixupAnalyzer`'s compiler target-name
policy (Ghidra 12.1.3, Apache-2.0). Pattern labels with `validcode="function"`
annotate existing discovered functions only. The selected compiler's
`InjectPayloadCallfixup` supplies the p-code; `FuncProto.setInjectId` and
`FlowInfo` apply it. The staged native patch exposes two read-only metadata
accessors; it does not modify the pinned source tree. Cached labels are
transient console context, not function discoveries or durable renames.
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

`crates/lre-worker/src/prototype.rs` follows the pinned Ghidra 12.1.3
`Funcdata::encode`, `FuncProto::encode`, `ProtoStoreInternal::encode`,
`Symbol::encodeHeader`, and datatype `encodeRef`/`encode` methods
(`funcdata.cc`, `fspec.cc`, `database.cc`, `type.cc`; Apache-2.0).
It shares the existing packed decoder rather than parsing C text or adding
another wire grammar. Symbol category indices order recovered parameters;
nested function-pointer prototypes do not replace the enclosing function's
prototype. Missing references remain unknown, and malformed or truncated
documents do not publish a partial prototype. No pinned source is modified.

The switch projection in `crates/lre-worker/src/doc.rs` follows
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
`NoReturnFunctionAnalyzer` (Apache-2.0). `native/ventris_nonreturn.hh` checks
completed basic-block CFGs, halt flags, and recovered jump tables using pinned
`funcdata.hh`, `block.hh`, `op.hh`, and `jumptable.hh`; it exports a transient
prototype flag and restores the cached prototype after encoding.
The benchmark-only `scripts/ExportReturnBehaviors.java` reads
`Function.hasNoReturn`, inherited `Namespace.getBody`, and
`AddressSetView.getAddressRanges` / `AddressRange` endpoints from the extracted
Ghidra 12.1.3 Java API (Apache-2.0). Eligibility reuses `code-functions-v1`.
The native flow closure and revision-owned SQLite publication are Ventris code.

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
