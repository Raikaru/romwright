# Struct types in the printed C

Printed C names struct types when a layout is known, prints field access as `p->field`, and carries the
`struct` definitions it uses. The layouts have three sources; a switch selects which of them reach the
decompiler. Numbers live in the reports this page names.

## 1. The switch

`ROMWRIGHT_STRUCTS=off|debug|inferred|all` (default: **`all`**, the most aggressive mode the gates support: no
m22-002 or m22-003 lane lost an exact match and no decompile failed because of it; the one loss in compiled
functions is listed in section 8).

| mode | layouts the decompiler may see | what changes in the output |
|---|---|---|
| `off` | none | parameters stay `void *` / integers: the output before this layer |
| `debug` | the image's debug stream (`native-import:debug-info`), plus asserted layouts | a function the stream types takes `Foo *`; callees' prototypes name the struct |
| `inferred` | layouts synthesized from function bodies (`native-inferred:struct-layout`), plus asserted layouts | a pointer parameter the gate accepts is `fn_<addr>_arg<n> *` |
| `all` | both | DWARF wins where the stream types a parameter; inference fills the rest |

Asserted layouts (a user's, or a fact pack's) are authoritative and are used in every mode but `off`. The mode
is read when a layout would be used, never when it is stored, so one project serves every mode: stored
prototypes that name a struct the mode hides are read with `void` in its place
(`romwright-worker/src/struct_types.rs`, `Layouts::erase_unresolved`).

## 2. Where layouts live

`type_defs` (kind `struct`, `size`, `provenance`) and `type_fields` (`ordinal`, `field_name`, `offset`, `size`,
`type_ref`). The row's `provenance` is its source: `native-import:debug-info`, `native-inferred:struct-layout`,
`fact-pack...`, anything else is the analyst's. `type_ref` is a type name (a core type such as `undefined4` or
`float`, another struct, or a `pointer`/`array` row of the type manager) or a C-style spelling of one: `Foo *`,
`Foo **`, `byte[4]`, `Foo *[4]`, `short[2][3]`. `romwright_model::structs` holds the vocabulary: the mode, the
source classification, the layout type and the spelling parser. `ProjectDb::store_struct_layouts` writes
layouts: a name another source owns is left alone, an unchanged layout is not a write, and a source that stores
its layouts whole (`Some(owner)`) drops the ones its new stream no longer states.

## 3. How a struct reaches the decompiler

A prototype names a struct as a bare type name. The decompiler's C parser resolves a name it does not hold
through `TypeFactoryGhidra::findById` (`typegrp_ghidra.cc`:20-35), which asks the worker
(`ArchitectureGhidra::getDataType`), and the worker answers from the stored layouts.
`romwright-worker/src/struct_types.rs` encodes the answer as the `<type metatype="struct">` element
`TypeStruct::decodeFields` (`type.cc`:2104-2260) accepts. The decoder is strict and a rejected element fails
the whole decompile, so the encoder sends only what the decoder keeps: fields in offset order, none
overlapping, none void or unnamed, the struct's size grown to cover every field's *decoded* size, a field it
cannot type given as `undefined<N>`, a by-value cycle given as bytes. A layout that cannot be encoded is
hidden and the signatures that name it are erased. No C++ changed: `ghidra_opt` is the pinned build
(sha256 `4561fbea...`, printer IR version unchanged).

Tests: the encoder's output is read back by a decoder written to `decodeFields`' rules
(`struct_types::tests`).

## 4. DWARF layouts (debug)

`native/mdebug/dwarf1.rs` turns Metrowerks DWARF 1 structs into layouts (`Dwarf1::structs`): members at their
stated offsets with the type spelled from the stream (`char *`, `Foo *`, `short[4]`, bit-fields at their
container's width, a union or unspellable member as `undefined<N>`/`byte[N]`). A struct is exported when it
is complete, its name is a C identifier no primitive, function or symbol holds, and it has a member the stream
places. Compile units repeat a type; identical layouts under one name are one struct, and a name two units use
for different layouts is `Name`, `Name_2`, ... so every parameter keeps the layout its own unit declared. The
debug prototypes (`DebugPrototype`) name the structs they point at. There is no DWARF 2 reader in the Rust
tree, so ee-gcc images (the Dungeon image) are not read by `debug`: the mode is a no-op there and `inferred`
is what types them.

## 5. Inferred layouts

`subtype.rs` solves a function's accesses; `struct_types::synthesize` turns a pointer parameter proved
dereferenced at several offsets (`Ty::Ptr(Ty::Struct)`) into `struct fn_<entry>_arg<n>`:

* only the accessed fields, each with the class its first use proved; no proof is `undefined<N>`, so the
  field takes whatever the use makes of it (an `int` there would turn a float's bit move into a conversion);
  `lbu`/`lhu` loads are unsigned, `lb`/`lh` signed. Typing a word `undefined4` where sign evidence says `int`
  was tried (the decompiler propagates a field's type into the function's locals) and dropped: the decompiler
  casts nothing stored into an undefined field, so a stored pointer printed uncast and MWCC rejected it (two
  m22-002 lane 1 functions stopped compiling);
* gaps are `unsigned char pad_0x..[..]` in the printed definition and nothing in the decompiler's type;
* a field at an offset its natural alignment forbids, or overlapping an earlier one, is not a field;
* **a field whose loaded value is dereferenced in the same body is a pointer** (`Class::Ptr`), and the
  accesses made through it are the layout of a second struct, `fn_<entry>_arg<n>_p<offset>`, which the field
  names (a one-level pointee; `subtype::Solution::pointees`);
* **what a pointer field points at** is joined to the field when the layouts are built, not carried on
  `types_infer::Field` (`Solution.pointees`, keyed by the parameter's register and the field's offset, is read by
  `struct_types::synthesize`; the join was never missing, the first reading of it in the upgrade round's map was
  wrong). A pointee whose layout passes the gate is `fn_<entry>_arg<n>_p<offset> *` (and a second struct); a
  pointee with one proven scalar class is `T *`; **a pointee that is a run of two or more accesses at consecutive
  offsets of one scalar width and kind (a vector or a table: the accesses of a `float *`, which the gate refuses as
  a struct) is `T *` too** (`ROMWRIGHT_STRUCT_POINTEE_RUNS=off` leaves it `void *`); anything else is `void *`.
  Measured (`benchmarks/struct_pointer_fields.py`, 2,000 sampled addresses of five PS2 games, the default against
  the switch off, `benchmarks/reports/upgrade1_gates_20261014.json`, `struct_pointer_fields`): the printed structs have
  1,308 fields and **one** is a pointer (a `void *`; no scalar or struct pointee); the rule typed none. What limits
  pointer fields is not the join but the evidence: 73 fields typed `int` or `undefined4` are read through a pointer
  cast in the printed body (`(unsigned char *)p->field_0x348`). [INFERENCE: the cause was not traced in `subtype.rs`;
  the likely one is that a field is classed `Ptr` only for a value dereferenced directly in its body, and a pointer
  also added to or compared as an integer joins to an integer class.] That is type inference, not the struct layer, and retyping fields has lost functions before (section 6, the
  two m22-002 pointer-cast losses and four Dark Cloud compiles); no layout change was made for it. The default
  build with the rule on loses no exact and no compiled function on any gate (`docs/c-output-lanes.md`,
  "Upgrade round 1").
* the fields are named `field_0x<offset>`;
* **an `undefined<N>` field takes the type the decompiler's own untyped text gave the accesses at its offset**,
  where they all agree and the width matches (`struct_pass::plan_structs` over
  `struct_types::access_field_types`: `float`, `double`, `int`/`uint`, `short`/`ushort`, `char`/`byte`, any
  pointer as `void *`). The decompiler prints no cast for a value read from or stored into an undefined type, so
  `*(float *)(p+0x10)` compared as a float printed `(float)p->field_0x10`, and a float parameter or a vtable
  pointer stored into one printed uncast (C++ rejects it); a typed field makes the pass-2 text cast them as the
  untyped text did. A plain `long` is not sized (8 bytes on MIPS64, 4 on a 32-bit target) and gives nothing.

Only a parameter whose type says nothing of its pointee is retyped (`undefined<N>`, a pointer-sized integer,
`void *`, `undefined1 *`): a pointer the decompiler or a declaration typed (`char *`, `Node *`) is that source's
claim and stays. Nothing is merged across functions: the context-insensitive caller/callee joins are not
used (docs/console-research.md, "Struct recovery audit": only 43% of the fields they add are real).

### The gate

An inferred layout becomes a struct only when it has **at least 3 placed fields and is not a run of one width**
(`struct_types::gate`: every field the same width, each directly after the last, from any start: `p[2]`, `p[3]`,
`p[4]` of a `float *`). It is measured against the audit's truth with `benchmarks/struct_inference_audit.py`'s
scorer (`benchmarks/struct_gate_sweep.py`; pooled over the six games whose truth the audit found reliable:
Capcom, DDS, God Hand, Ratchet & Clank, Fatal Frame, Dungeon; `benchmarks/reports/struct_gate_sweep_20261012.json`).
A *false struct* is a truth pointer-to-nothing-struct parameter (`void *`, a scalar pointer, a pointer to a
pointer) the gate would still turn into a struct.

| gate | struct recall % | false-struct rate % | of which `void *` / scalar ptr | precision % | offset precision % |
|---|---|---|---|---|---|
| no gate (shipped inference before this work) | 85.5 | 45.8 | 45.3 / 47.7 | 68.1 | 96.2 |
| fields >= 2, not a dense scalar array | 65.6 | 24.2 | 24.3 / 24.7 | 75.7 | 96.1 |
| fields >= 3, not a dense scalar array | 51.7 | 16.3 | 16.6 / 16.5 | 78.4 | 96.1 |
| fields >= 4, not a run of one width | 39.3 | 10.4 | 9.7 / 11.4 | 81.3 | 95.8 |
| **fields >= 3, not a run of one width (shipped)** | **49.8** | **14.2** | **13.3 / 15.6** | **80.1** | **96.0** |

The trade-off: the gate gives up about 36 points of struct recall (85.5 to 49.8) to cut false structs from 45.8%
to 14.2%. No single feature separates a false struct from a true one: many "false" structs are genuine struct
accesses through a `void *` or `u8 *` the donor declared opaque, so no threshold drives the rate to zero without
dropping most true structs too (`fields >= 4` keeps 39% recall for 10% false). Three fields is where precision
stops buying much more per point of recall; the run rule is what stops a matrix or vector held in a `float *`
from printing as a struct, which cost m22-002 lane 1 a function (48.39 to 46.43 percent) before it existed.
Persona 4's truth is m2c-shaped and the audit marks it unreliable; the same gate gives about 29% recall and
19% false there.

## 6. The pass

An export (`export-c`, `decompile`, `decompile-batch`) with `inferred` or `all`
(`struct_pass.rs`): decompile (pass 1); solve the recovered functions' bodies; for every function with a
qualifying parameter store its layouts and decompile it again with its retyped prototype handed to the worker
for that function alone (`ROMWRIGHT_STRUCT_OVERLAY`, a file the pass writes and removes). Nothing goes to the
prototype table, so an asserted prototype stays asserted and no function sees a callee's struct. The worker
applies the overlay to the target only and restores the callee view before the next target of a batch. The
`infer_prototypes` job does the same through the table: `ParameterTypes::apply_structs` retypes the recovered
prototype, `Core::persist_struct_layouts` stores the layouts first, and the row's source carries
`native-prototype:inferred-struct`, which the worker treats as that function's own.

The printed output carries the definitions it uses: `typedef struct S S;` for each struct (the decompiler
prints a struct by its bare name), then the bodies, a struct held by value after the one holding it, each field
ending in `/* +0xN */`. A name the `--context` header already mentions is not defined again. Where an asserted
prototype keeps a parameter `void *`, every use of the parameter in the printed body goes through a cast to the
struct the decompiler typed it as (`((S *)param_1)->field_0x8`, and `((S *)param_1) + 1` for pointer arithmetic,
which the struct's size scales: on `void *` it would be a byte, and one m22-002 function lost its exact match to
exactly that); a parameter the body writes or takes the address of is read through a local of the struct type
instead (`S *param_1_s = (S *)param_1;`). The casts change no code the compiler emits (`emit_m2c/struct_params.rs`).

A function the pass retyped is **kept untyped** when its retyped text takes the address of a member the layout
says nothing typed of (`&p->field_0x20` into a gap, or of an `undefined4` field; `StructTable::takes_untyped_address`).
The decompiler leaves such an address uncast where it is handed on as a `float *` (an undefined type fits any),
and the printed `unsigned char *` is a compile error in C++ (m22-003 Dark Cloud: four functions that compiled
untyped stopped compiling). The cast of a parameter is applied after the project's own declaration has replaced the
header (`conform`), since that declaration, not the decompiler's, is what the header finally says.

It is also kept untyped when the retyped text puts an integer cast directly on a `float`/`double` member
(`(unsigned int)p->field_0x48`, `StructTable::converts_float_member`). The same word was read as a float and,
elsewhere, copied as bits through an integer pointer; the untyped text keeps the two apart as two pointer casts,
the one `float` field turns the copy into a numeric conversion, and the function compiles to other instructions
(m22-003 dds `func_0016F7B0`: 250 instructions became 309, 65.0 to 37.1 percent). The same check keeps a function
untyped when a `float`/`double` cast sits on an `undefined<N>` member (`(float)p->field_0x10`): the decompiler
converts an undefined type to the float a compare wants, a numeric conversion of what were bits.

A parameter is not retyped when the untyped text of its function reads one offset as a float and as bits, or at
two overlapping widths (`struct_types::mixed_accesses`: the printed forms `*(T *)((int)p + N)`, `*(T *)(p + N)`,
`*(T *)p`; a plain `long` is the target's width and is not sized). One field cannot be both. It was added for rc
`_sysbitFlush` and does not change that function (the raw text reads a 64-bit `long` at both widths, so there is
no conflict to see); its effect on the measured lanes was not separated from the float-conversion guard's. It
applies only where the pass-1 text is at hand: the export and decompile paths, not the `infer_prototypes` job.

## 7. Measuring it

* `benchmarks/struct_gate_sweep.py`: gates against the audit's truth and dumps.
* `benchmarks/struct_print_measure.py`: decompile success and the printed field-access share per mode.
* `benchmarks/struct_field_agreement.py`: the share of the donor source's member accesses a candidate prints
  as member accesses at the same offset (`field agreement`).
* m22-002 and m22-003 take `ROMWRIGHT_STRUCTS` through (`--env ROMWRIGHT_STRUCTS=off` for m22-003).

## 8. Results (2026-10-13)

All in `benchmarks/reports/struct_layer_final_20261013.json` (m22-002, m22-003 and success, off against default),
`m21-001_structs_20261013.json`, `struct_gate_sweep_20261013.json` (+ `_qword_`) and
`struct_print_{capcom,dungeon}_20261013.json`. **The tables below are one build**: the combined tree (the
compiler-rules layer's landed code and this layer), one release cli, the pinned `ghidra_opt`; each arm has its own
work directory and its own fresh import. Earlier numbers (`struct_layer_20261013.json`,
`struct_layer_rerun_20261013.json`) are superseded: the first m22-003 arms ran `--layers romwright` alone, and the
harness then asserted only the target's prototype (the callees came from the m2c layer's assembly), so they sat
far under the Ps2Lanes reports; the harness is fixed (Ps2Lanes) and these ran `--layers romwright,m2c`.

**m22-002** (200 functions per lane, context variant, exact / compiled / mean percent):

| lane | off | default | paired (better / worse / same) | exact gained / lost |
|---|---|---|---|---|
| MWCC seed 20261010 | 55 / 193 / 76.976 | 55 / 193 / 76.976 | 0 / 0 / 200 | 0 / 0 |
| MWCC seed 20261011 | 57 / 194 / 78.321 | 57 / 194 / 78.321 | 0 / 0 / 200 | 0 / 0 |
| `--compiler eegcc` | 106 / 197 / 86.406 | 106 / 197 / 86.403 | 1 / 1 / 198 | 0 / 0 |

The off column equals the compiler-rules combined gate (55 / 193 / 76.976, 57 / 194 / 78.321, 106 / 197 / 86.406).
Standalone variant: identical on lanes 1 and 2, eegcc 100 / 182 / 79.649 to 100 / 182 / 79.951. Field agreement
(the share of the truth source's member accesses printed as members at the same offset; off is 0 by construction):
lane 1 0 of 6 (the one function with truth accesses stays untyped: its layout fails the gate), lane 2 7 of 9
(0.78, none at a wrong offset), eegcc 7 of 14 (0.50). Persona 4's truth has member accesses in only 1, 4 and 5
functions of the 200, so these are small samples.

**m22-003** (context variant, `--layers romwright,m2c`):

| lane | off | default | paired (better / worse / same) | exact gained / lost |
|---|---|---|---|---|
| dds | 61 / 196 / 76.802 | 61 / 196 / 76.818 | 1 / 1 / 198 | 0 / 0 |
| rc | 26 / 199 / 68.126 | 26 / 199 / 68.130 | 3 / 2 / 195 | 0 / 0 |
| p4 | 60 / 193 / 79.121 | 60 / 193 / 79.129 | 1 / 0 / 199 | 0 / 0 |
| gh | 78 / 199 / 81.988 | 78 / 199 / 82.057 | 1 / 0 / 199 | 0 / 0 |
| ff | 20 / 145 / 49.247 | 20 / 145 / 49.294 | 3 / 1 / 196 | 0 / 0 |
| dc (C++) | 35 / 166 / 62.571 | 36 / 166 / 62.625 | 2 / 2 / 196 | 1 / 0 |
| dk (C++) | 28 / 169 / 67.360 | 28 / 169 / 67.360 | 1 / 1 / 198 | 0 / 0 |

No exact match is lost and no function stops compiling on any lane. The worse functions that remain, and why:

* rc `_sysbitFlush`, 51.7 to 35.5 percent: the raw decompile reads offset 0 as a 64-bit `long`
  (`*(long *)p << (long)n`), the untyped export prints it as `*(int *)p << (int)n`, and the struct text prints
  `p->field_0x0 << (int)n` on an 8-byte field, a 64-bit shift and store where the untyped text had 32 bits. The
  narrowing is the printer's `canonical` rules' doing [inferred from the diff, the rules were not read to confirm];
  a member access is not a pattern they match. Not gated: excluding every layout with an 8-byte integer field costs
  about 10 points of struct recall (`struct_gate_sweep_qword_20261013.json`, three games: 46.2 to 36.7) for no
  change in false structs.
* dds `sdfTexCreateFromFileHeader` 77.0 to 74.8, rc `_multiply` 77.9 to 76.7, dc `CreatePacket` 76.2 to 75.3 and
  `UpdateGeoramaPartColor` 84.5 to 83.4, dk `CheckEventPoint` 93.1 to 90.5: not diagnosed.
* Two functions the first default builds lost and the layer now handles (both found by the review of the ff, dc and
  dk arms): dds `func_0016F7B0` (65.0 to 37.1: a word read as a float and as bits, the `float` field printed the
  copy as a numeric conversion `(unsigned int)p->field_0x48`; kept untyped, section 6) and dc
  `SetPosition__9mgCObjectFPf` (100 to 0) with dk `__ct__13CCameraFollowFffff` (stopped compiling): fields the
  solver left `undefined4` where the decompiler's untyped text typed the access (`*(float *)(p+0x10)`); the
  decompiler prints no cast for an undefined type, so a float compare printed `(float)p->field_0x10` (a numeric
  conversion of the bits) and a float parameter and a vtable pointer stored into undefined fields printed uncast
  (C++ rejects it). An undefined field now takes the type every untyped access at its offset agrees on, and a
  float cast on an undefined member keeps the function untyped (section 6). (The dc exact gain,
  `AddPoint__17CSWordAfterEffectFPfPf`, was there before this change.)
* A retyped function the decompiler cannot finish (its rule pool rewrites without end; seen on one Dark Cloud
  function) is killed after a share of the remaining deadline (at most 20 s for one function), the batch is
  bisected, and the function is printed untyped with a warning: decompile success is unchanged.
* The pass decompiles a qualifying function twice; no wall-time figure is given (the host was shared).

**DWARF** (`debug`; Capcom DWARF 1, 58 structs / 1354 fields / 5271 prototypes imported):

| Capcom, 1000 addresses | ok | member accesses | offset accesses | member share | functions with struct types |
|---|---|---|---|---|---|
| off | 999 | 564 | 16898 | 3.2% | 10 |
| debug | 999 | 17111 | 914 | 94.9% | 732 |
| inferred | 999 | 7612 | 9844 | 43.6% | 483 |
| all | 999 | 17284 | 757 | 95.8% | 746 |

The one failing address (`001aa860`) fails in every mode. No function fails with a mode that succeeds with off.
Dungeon is DWARF 2 and the Rust tree has no DWARF 2 reader, so `debug` imports nothing there and its row equals
off (324 of 324 sampled functions decompile in every mode; the 176 other sampled addresses fail in off too). `all`
(inferred only) moves its member share from 12.2% to 29.3%, 20 of 324 functions with structs.

**Combined gate**, on the combined build. m21-001 PASS with the layer on (default); every row (recall, precision,
`size_exact`) equals `combined_gate_compiler_rules_20261012.json` exactly (capcom 0.9741 / 0.9945, dungeon 0.9872 /
0.9835, pokeemerald 0.9761 / 0.9972 / 15421, pokeheartgold 0.9735 / 0.9984 / 9888, psx-ds3 0.9878 / 0.3663, psv-nfs
0.9734 / 0.9719, x360-bo2 0.9833 / 0.9964). PS2 decompile success, off and default, fresh projects imported by the
same build: 2000 of 2000 on the first 250 sampled functions of each of the 8 non-symtab wave images (the `-symtab`
variants and the wave's cached projects no longer exist, and the combined gate's 10338 of 10342 over the whole
wave was not rerun). The Capcom and Dungeon member shares above were measured on an earlier build, before the
guards of section 6 that only keep a function untyped and before an undefined field took the type of its untyped
accesses; they were not rerun (the project directories were deleted), so the inferred shares are for that build.
