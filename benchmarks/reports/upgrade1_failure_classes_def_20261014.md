# m22-003 failure classes: where romwright's C output loses

Source: `m22-003_<lane>_def.json` of the nine lanes (headline `context` variant, 200 functions per lane). A compile failure is classified by the compiler's first diagnostic; a compiled candidate that is not exact by a word-level comparison against the retail bytes. `context only` counts failures whose same text compiles without the unit's declarations (the standalone variant), i.e. where the context is what breaks it. `m2c exact` counts the functions m2c gets exact in the same class.

## Per lane

| lane | romwright exact | m2c exact | compile failures | exact rate among compiled |
|---|---|---|---|---|
| dds | 61 | None | 0 of 200 | 0.30 |
| ff | 21 | None | 5 of 200 | 0.11 |
| rc | 26 | None | 0 of 200 | 0.13 |
| dc | 38 | None | 14 of 200 | 0.20 |
| dk | 29 | None | 11 of 200 | 0.15 |
| gh | 78 | None | 1 of 200 | 0.39 |
| p4 | 60 | None | 7 of 200 | 0.31 |

## Ranked classes (across lanes)

Ranked by plausible exact gain: a compile-failure class recovers (failures x the lane's exact rate among the candidates that compile); a byte-difference class recovers all its functions when it is a near miss (a single instruction, register or stack difference, a few instructions, an extension or width, a reordering) and none otherwise. `m2c exact` is the number of those functions that m2c gets exact.

| rank | class | functions | plausible exact gain | m2c exact | context only | owner | per lane |
|---|---|---|---|---|---|---|---|
| 1 | bytes: few instructions differ (<= 4) | 31 | 31 | 0 | - | printer (printc) | dds 3, ff 2, dc 4, dk 8, gh 13, p4 1 |
| 2 | bytes: register allocation | 25 | 25 | 0 | - | printer (printc) | dds 2, ff 2, rc 2, dc 4, dk 6, gh 3, p4 6 |
| 3 | bytes: same instructions, different order (scheduling) | 24 | 24 | 0 | - | printer (printc) | dds 4, ff 8, rc 4, dk 1, gh 4, p4 3 |
| 4 | bytes: single instruction | 20 | 20 | 0 | - | printer (printc) | dds 3, ff 2, rc 1, dc 2, dk 5, gh 3, p4 4 |
| 5 | bytes: register allocation and stack layout | 15 | 15 | 0 | - | printer (printc) | dds 3, ff 2, rc 1, dc 1, dk 4, gh 3, p4 1 |
| 6 | compile: type mismatch (assignment, operand, return, cast) | 26 | 5.1 | 0 | 13 | types/prototypes; printer for the array casts | ff 5, dc 10, dk 6, p4 5 |
| 7 | bytes: access width or signedness (type or cast) | 1 | 1 | 0 | - | types/prototypes | dk 1 |
| 8 | bytes: stack layout | 1 | 1 | 0 | - | printer (printc) | p4 1 |
| 9 | compile: undeclared identifier | 4 | 0.8 | 0 | 0 | printer (printc) | dc 1, dk 2, p4 1 |
| 10 | compile: call does not match prototype | 3 | 0.7 | 0 | 1 | types/prototypes | dc 2, p4 1 |
| 11 | compile: no candidate produced | 1 | 0.4 | 0 | 0 | printer (printc) | gh 1 |
| 12 | compile: member access on a type the context lacks | 2 | 0.3 | 0 | 0 | types/prototypes | dk 2 |
| 13 | compile: unit post-processing rejected the candidate object | 1 | 0.2 | 0 | 0 | lane harness | dc 1 |
| 14 | compile: illegal or unknown type name | 1 | 0.2 | 0 | 0 | printer (printc) | dk 1 |
| 15 | bytes: length differs: mixed arithmetic (expression shape) | 503 | 0 | 0 | - | printer (printc) | dds 58, ff 110, rc 107, dc 63, dk 75, gh 32, p4 58 |
| 16 | bytes: length differs: control flow (branches, calls) | 203 | 0 | 0 | - | printer (printc) | dds 38, ff 15, rc 23, dc 40, dk 24, gh 29, p4 34 |
| 17 | bytes: same length, many instructions differ: mixed arithmetic (expression shape) | 76 | 0 | 0 | - | printer (printc) | dds 13, ff 13, rc 12, dc 10, dk 13, gh 9, p4 6 |
| 18 | bytes: length differs: memory accesses (temporaries, spills, widths) | 68 | 0 | 0 | - | printer (printc) | dds 2, ff 12, rc 12, dc 12, dk 10, gh 12, p4 8 |
| 19 | bytes: same length, many instructions differ: control flow (branches, calls) | 35 | 0 | 0 | - | printer (printc) | dds 7, ff 3, rc 6, dc 2, dk 6, gh 8, p4 3 |
| 20 | bytes: same length, many instructions differ: memory accesses (temporaries, spills, widths) | 21 | 0 | 0 | - | printer (printc) | dds 4, ff 3, rc 4, dc 1, dk 4, gh 2, p4 3 |
| 21 | bytes: length differs: floating-point or vector sequence | 11 | 0 | 0 | - | printer (printc) | dds 1, ff 1, dc 4, dk 1, gh 1, p4 3 |
| 22 | bytes: length differs: few instructions (<= 4) | 7 | 0 | 0 | - | printer (printc) | dds 1, ff 1, dc 3, gh 1, p4 1 |
| 23 | bytes: same length, many instructions differ: floating-point or vector sequence | 3 | 0 | 0 | - | printer (printc) | dk 2, p4 1 |
| 24 | bytes: length differs: nops or register copies (allocation or scheduling) | 2 | 0 | 0 | - | printer (printc) | rc 1, dc 1 |
| 25 | bytes: length differs: nops and register copies | 2 | 0 | 0 | - | printer (printc) | dc 1, gh 1 |
| 26 | bytes: length differs: extension instructions (type or cast) | 1 | 0 | 0 | - | types/prototypes | rc 1 |

## Harness artifacts found (and fixed unless noted)

| artifact | symptom | fix | lanes |
|---|---|---|---|
| context declarations the unit's compiler rejects | `void * __asm__(" ");`, bad typedef order: the harness compiled romwright against a context it could not compile (rcpal 67 of 96 failures; also m2c) | per-unit context repair: drop the rejected declarations, retry | rcpal, p4, dds |
| SN ee-gcc 2.95.3 `long long` is 128-bit | 'unsupported wide integer operation' (rcpal 35, gh 13) and the size-check typedef (gh 3) | descriptor `candidate_type_aliases`: `long long` -> `long` for SN units | gh, rcpal |
| K&R / unspellable target declaration | romwright's head conflicts with a declaration it was never given a signature for | romwright's compile context drops the target's declaration when none was asserted | ff (20 conflicts), dc, dk |
| array-typedef parameters | `typedef float sceVu0FVECTOR[4]` was not in the typedef table, so callees were left unasserted and guessed | `typedef_table_with_arrays` | ff 33 fns, dc 13, dk 16 |
| C++ rename skipped | the definition head regex matched across a comment that names the function | rename on comment-masked text | dc 1 (EndPrim) |
| MWCC `__2` duplicate-name suffix | the unit's build renames a function whose name it knows: 'no symbol' for a compiled candidate | score the unique `<name>__<n>` symbol | dc 2 (_CAMERA_QUAKE, _SCALE_VECTOR) |
| GH wrapper `--extern-jtbl` | the SN wrapper aborts on a jump-table argument that candidates do not have | descriptor `candidate_drop_args` | gh 2 |

### Owners and the evidence for them

- **bytes: few instructions differ (<= 4)** -> printer (printc): at most four instructions differ: expression shape.
- **bytes: register allocation** -> printer (printc): same instructions, different registers: temporaries and expression order.
- **bytes: same instructions, different order (scheduling)** -> printer (printc): statement and expression order (scheduling).
- **bytes: single instruction** -> printer (printc): one instruction differs (register, immediate or opcode): expression shape or a constant's spelling.
- **bytes: register allocation and stack layout** -> printer (printc): same instructions, different registers and frame slots: local variable count, order and lifetimes.
- **compile: type mismatch (assignment, operand, return, cast)** -> types/prototypes; printer for the array casts: ff: constants printed as array casts `(unsigned char [8])0x3f3333333f000000`; struct arrays indexed as scalars (`ene_wrk[temp_v2 + 0x11] = param_2`, `door_keep[..] = 1` with the context's struct-array types); VU intrinsic `_vrnext(in_vuR)` assigned to an int. dc/dk: `(float **)` casts passed for `sceVu0FMATRIX` parameters.
- **bytes: access width or signedness (type or cast)** -> types/prototypes: load/store width or signedness differs: the declared type of the object.
- **bytes: stack layout** -> printer (printc): same instructions, different frame offsets: local declaration order and arrays.
- **compile: undeclared identifier** -> printer (printc): locals the text uses but does not declare (`undefined7 uStack_c0`, `_DAT_00252bf0.whole`, `_iStack_70`, `_abStack_170`).
- **compile: call does not match prototype** -> types/prototypes: calls whose argument count or types disagree with the context's callee prototype (`sceVu0CopyVector(float *)` with a 2-parameter prototype; `sceVu0UnitMatrix()`); romwright guessed the callee because the harness could not assert array-typedef parameters (harness artifact, fixed: `typedef_table_with_arrays`, see the fixed-artifacts table); what remains is the printer's call arguments.
- **compile: no candidate produced** -> printer (printc): export-c emitted no function for the address (gh 1, rcpal 1).
- **compile: member access on a type the context lacks** -> types/prototypes: the printed access uses Ghidra's synthetic storage members (`key_now.u4[0]`, `eff_focus.u4[0]`, `GiftagAD.u4[0]`, `uStack_8._4_4_`) although the context declares the global with its real type (`extern u_short *key_now[32]`, `extern EFF_FOCUS eff_focus`, `extern sceGifTag GiftagAD`, `extern float SysCur[3]`); standalone compiles fail too, none are context-only.
- **compile: unit post-processing rejected the candidate object** -> lane harness: dc `ChangeSetUnit`: the repo's postprocess_object.py for dng_main.cpp raises 'expected one debug event stack' on any candidate that lacks the unit's own static; the unit's build step cannot be dropped without changing the object (left, 1 function).
- **compile: illegal or unknown type name** -> printer (printc): address arithmetic on a `void *` global (`*(unsigned int *)(nowMonster + 0x1490)`, `edit_info + 0x70`, `edit_info + week_no * 0x300`): MWCC rejects void-pointer arithmetic, m2c's text for the same functions compiles and is exact in 3 (the cast to `char *`/`int` is missing).
- **bytes: length differs: mixed arithmetic (expression shape)** -> printer (printc): different instruction count: control-flow shape, expression shape, loop forms.
- **bytes: length differs: control flow (branches, calls)** -> printer (printc): different instruction count: control-flow shape, expression shape, loop forms.
- **bytes: same length, many instructions differ: mixed arithmetic (expression shape)** -> printer (printc): same size, different code: expression shape or control-flow form.
- **bytes: length differs: memory accesses (temporaries, spills, widths)** -> printer (printc): different instruction count: control-flow shape, expression shape, loop forms.
- **bytes: same length, many instructions differ: control flow (branches, calls)** -> printer (printc): same size, different code: expression shape or control-flow form.
- **bytes: same length, many instructions differ: memory accesses (temporaries, spills, widths)** -> printer (printc): same size, different code: expression shape or control-flow form.
- **bytes: length differs: floating-point or vector sequence** -> printer (printc): different instruction count: control-flow shape, expression shape, loop forms.
- **bytes: length differs: few instructions (<= 4)** -> printer (printc): a few instructions more or fewer: redundant temporaries or folded expressions.
- **bytes: same length, many instructions differ: floating-point or vector sequence** -> printer (printc): same size, different code: expression shape or control-flow form.
- **bytes: length differs: nops or register copies (allocation or scheduling)** -> printer (printc): different instruction count: control-flow shape, expression shape, loop forms.
- **bytes: length differs: nops and register copies** -> printer (printc): different instruction count: control-flow shape, expression shape, loop forms.
- **bytes: length differs: extension instructions (type or cast)** -> types/prototypes: sign/zero extension differs: the declared type or a cast.

## Compile failures per lane, with two examples per class

### dds: 0 of 200

| class | count | context only | m2c exact | example 1 | example 2 |
|---|---|---|---|---|---|

### ff: 5 of 200

| class | count | context only | m2c exact | example 1 | example 2 |
|---|---|---|---|---|---|
| type mismatch (assignment, operand, return, cast) | 5 | 0 | 0 | `0x138ff8` sceVu0ViewClipMatrix: `param_1[0xf] = 0.0f;` (incompatible types in assignment) | `0x13a170` GetSmokePartAddr: `temp_v3 = _vrnext(in_vuR);` (incompatible types in assignment) |

### rc: 0 of 200

| class | count | context only | m2c exact | example 1 | example 2 |
|---|---|---|---|---|---|

### dc: 14 of 200

| class | count | context only | m2c exact | example 1 | example 2 |
|---|---|---|---|---|---|
| type mismatch (assignment, operand, return, cast) | 10 | 7 | 0 | `0x137e70` GetWorldPosition__8mgCFrameFPfPf: `sceVu0ApplyMatrix(param_2,(float **)afStack_40,param_3);` (illegal implicit conversion from 'float **' to) | `0x148be0` SetCurrentDir__FPc: `return pcVar1;` (illegal return value in void/constructor/destructor function) |
| call does not match prototype | 2 | 0 | 0 | `0x1371b0` SetBrother__8mgCFrameFP8mgCFrame: `SetBrother__8mgCFrameFP8mgCFrame(*(int *)(param_1 + 0x5c));` (function call 'SetBrother__8mgCFrameFP8mgCFrame(int)' does n) | `0x21c290` GyoraceMenuInit__FP9mgCMemoryPii: `= LoadFileMenu((char *)_5140,(void *)(DAT_01efb9b0[0] + DAT_01efb9b4[0] * 0x10));` (function call 'LoadFileMenu(char *, void *)' does not match) |
| undeclared identifier | 1 | 0 | 0 | `0x1734f0` Initialize__12CActionCharaFP9mgCMemory: `*(undefined5 **)(temp_v3 + 0x718) = &_2210;` (undefined identifier 'undefined5') |  |
| unit post-processing rejected the candidate object | 1 | 0 | 0 | `0x1d4e00` ChangeSetUnit__Fi: `    raise ValueError(f'dng_main: expected one debug event stack, found {len(storage)}')` (    raise ValueError(f'dng_main: expected one debug event st) |  |

### dk: 11 of 200

| class | count | context only | m2c exact | example 1 | example 2 |
|---|---|---|---|---|---|
| type mismatch (assignment, operand, return, cast) | 6 | 4 | 0 | `0x1938b0` _LOAD_LIGHT__FP12RS_STACKDATAi: `sceVu0CopyMatrix((float **)LAB_01d3d500,(float **)(save_l + temp_v2));` (cannot convert) | `0x198f90` EdTalkModeInit__FP12CNPCharacteri: `DAT_01d3d430[0] = ((int)param_1 - (char *)((unsigned char *)&EdVillager)) / 0x14a0;` (illegal operand) |
| undeclared identifier | 2 | 0 | 0 | `0x1d5b30` Draw__15CItemBombEffectFP7CCamera: `(*(unsigned long long *)&uStack_10) = CONCAT71((int7)((unsigned long long)(*(unsigned long` (undefined identifier 'int7') | `0x1d6940` Draw__13CWeaponEffectFv: `(*(unsigned long long *)&uStack_10) = CONCAT71((int7)((unsigned long long)(*(unsigned long` (undefined identifier 'int7') |
| member access on a type the context lacks | 2 | 0 | 0 | `0x29ff40` __sinit_mglib.cpp: `void __sinit_mglib.cpp(void)` (illegal use of 'void') | `0x2a0750` __sinit_editloop3.cpp: `void __sinit_editloop3.cpp(void)` (illegal use of 'void') |
| illegal or unknown type name | 1 | 0 | 0 | `0x20ee10` MonsterNamePosSet__Fii: `*CharaNameMes = param_1 - (int)(((int)(CharaNameMes[6] * 7) << 0x21) >> 0x21);` (illegal type) |  |

### gh: 1 of 200

| class | count | context only | m2c exact | example 1 | example 2 |
|---|---|---|---|---|---|
| no candidate produced | 1 | 0 | 0 | `0x297c20` cEvent__isPlaying: `no candidate` (no candidate) |  |

### p4: 7 of 200

| class | count | context only | m2c exact | example 1 | example 2 |
|---|---|---|---|---|---|
| type mismatch (assignment, operand, return, cast) | 5 | 2 | 0 | `0x317240` func_00317240: `func_002b6c30(0x42ce0000,0x1e4,uStack_8,0xbc);` (illegal implicit conversion from 'int' to) | `0x317320` func_00317320: `func_002b6c30(0x42ce0000,0x1e4,uStack_8,0xbc);` (illegal implicit conversion from 'int' to) |
| call does not match prototype | 1 | 1 | 0 | `0x21ae80` func_0021ae80: `func_0021b310((u8 *)(param_1 + 0xa3c));` (function call 'func_0021b310(unsigned char *)' does not matc) |  |
| undeclared identifier | 1 | 0 | 0 | `0x25fbb0` func_0025fbb0: `if (&stack0x00000000 != (unsigned char *)0x30) {` (undefined identifier 'stack0x00000000') |  |

## Functions m2c gets exact and romwright does not

### dk: 0 functions

| cause | count |
|---|---|

| address | function | bytes | cause | detail |
|---|---|---|---|---|

### dc: 0 functions

| cause | count |
|---|---|

| address | function | bytes | cause | detail |
|---|---|---|---|---|

### dds: 0 functions

| cause | count |
|---|---|

| address | function | bytes | cause | detail |
|---|---|---|---|---|

### ff: 0 functions

| cause | count |
|---|---|

| address | function | bytes | cause | detail |
|---|---|---|---|---|

### rc: 0 functions

| cause | count |
|---|---|

| address | function | bytes | cause | detail |
|---|---|---|---|---|

### gh: 0 functions

| cause | count |
|---|---|

| address | function | bytes | cause | detail |
|---|---|---|---|---|

### p4: 0 functions

| cause | count |
|---|---|

| address | function | bytes | cause | detail |
|---|---|---|---|---|

