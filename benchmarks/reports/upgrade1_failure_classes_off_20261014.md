# m22-003 failure classes: where romwright's C output loses

Source: `m22-003_<lane>_off.json` of the nine lanes (headline `context` variant, 200 functions per lane). A compile failure is classified by the compiler's first diagnostic; a compiled candidate that is not exact by a word-level comparison against the retail bytes. `context only` counts failures whose same text compiles without the unit's declarations (the standalone variant), i.e. where the context is what breaks it. `m2c exact` counts the functions m2c gets exact in the same class.

## Per lane

| lane | romwright exact | m2c exact | compile failures | exact rate among compiled |
|---|---|---|---|---|
| dds | 61 | None | 4 of 200 | 0.31 |
| ff | 20 | None | 55 of 200 | 0.14 |
| rc | 26 | None | 1 of 200 | 0.13 |
| dc | 38 | None | 24 of 200 | 0.22 |
| dk | 29 | None | 24 of 200 | 0.17 |
| gh | 78 | None | 1 of 200 | 0.39 |
| p4 | 60 | None | 7 of 200 | 0.31 |

## Ranked classes (across lanes)

Ranked by plausible exact gain: a compile-failure class recovers (failures x the lane's exact rate among the candidates that compile); a byte-difference class recovers all its functions when it is a near miss (a single instruction, register or stack difference, a few instructions, an extension or width, a reordering) and none otherwise. `m2c exact` is the number of those functions that m2c gets exact.

| rank | class | functions | plausible exact gain | m2c exact | context only | owner | per lane |
|---|---|---|---|---|---|---|---|
| 1 | bytes: few instructions differ (<= 4) | 30 | 30 | 0 | - | printer (printc) | dds 3, ff 2, dc 4, dk 7, gh 13, p4 1 |
| 2 | bytes: register allocation | 25 | 25 | 0 | - | printer (printc) | dds 2, ff 2, rc 2, dc 4, dk 6, gh 3, p4 6 |
| 3 | bytes: same instructions, different order (scheduling) | 23 | 23 | 0 | - | printer (printc) | dds 4, ff 7, rc 4, dk 1, gh 4, p4 3 |
| 4 | bytes: single instruction | 19 | 19 | 0 | - | printer (printc) | dds 3, ff 2, rc 1, dc 2, dk 4, gh 3, p4 4 |
| 5 | bytes: register allocation and stack layout | 15 | 15 | 0 | - | printer (printc) | dds 3, ff 2, rc 1, dc 1, dk 4, gh 3, p4 1 |
| 6 | compile: type mismatch (assignment, operand, return, cast) | 43 | 7.8 | 0 | 11 | types/prototypes; printer for the array casts | dds 1, ff 22, rc 1, dc 8, dk 6, p4 5 |
| 7 | compile: member access on a type the context lacks | 34 | 5.2 | 0 | 0 | types/prototypes | dds 1, ff 25, dc 2, dk 6 |
| 8 | compile: syntax error | 20 | 3.8 | 0 | 0 | printer (printc) | ff 1, dc 11, dk 8 |
| 9 | compile: undeclared identifier | 8 | 1.7 | 0 | 0 | printer (printc) | dds 2, ff 3, dk 2, p4 1 |
| 10 | compile: call does not match prototype | 5 | 1.0 | 0 | 1 | types/prototypes | ff 2, dc 2, p4 1 |
| 11 | bytes: access width or signedness (type or cast) | 1 | 1 | 0 | - | types/prototypes | dk 1 |
| 12 | bytes: stack layout | 1 | 1 | 0 | - | printer (printc) | p4 1 |
| 13 | compile: no candidate produced | 1 | 0.4 | 0 | 0 | printer (printc) | gh 1 |
| 14 | compile: unit post-processing rejected the candidate object | 1 | 0.2 | 0 | 0 | lane harness | dc 1 |
| 15 | compile: incomplete type | 1 | 0.2 | 0 | 0 | types/prototypes | dk 1 |
| 16 | compile: illegal or unknown type name | 1 | 0.2 | 0 | 0 | printer (printc) | dk 1 |
| 17 | compile: conflicting types / redeclaration | 1 | 0.1 | 0 | 1 | export context (emit_m2c declarations/dependencies); the K&R share is harness-owned and fixed | ff 1 |
| 18 | compile: other | 1 | 0.1 | 0 | 0 | printer (printc) | ff 1 |
| 19 | bytes: length differs: mixed arithmetic (expression shape) | 440 | 0 | 0 | - | printer (printc) | dds 54, ff 71, rc 106, dc 54, dk 65, gh 32, p4 58 |
| 20 | bytes: length differs: control flow (branches, calls) | 198 | 0 | 0 | - | printer (printc) | dds 38, ff 12, rc 23, dc 39, dk 23, gh 29, p4 34 |
| 21 | bytes: same length, many instructions differ: mixed arithmetic (expression shape) | 73 | 0 | 0 | - | printer (printc) | dds 13, ff 10, rc 12, dc 10, dk 13, gh 9, p4 6 |
| 22 | bytes: length differs: memory accesses (temporaries, spills, widths) | 66 | 0 | 0 | - | printer (printc) | dds 2, ff 10, rc 12, dc 12, dk 10, gh 12, p4 8 |
| 23 | bytes: same length, many instructions differ: control flow (branches, calls) | 35 | 0 | 0 | - | printer (printc) | dds 7, ff 3, rc 6, dc 2, dk 6, gh 8, p4 3 |
| 24 | bytes: same length, many instructions differ: memory accesses (temporaries, spills, widths) | 20 | 0 | 0 | - | printer (printc) | dds 4, ff 2, rc 4, dc 1, dk 4, gh 2, p4 3 |
| 25 | bytes: length differs: floating-point or vector sequence | 11 | 0 | 0 | - | printer (printc) | dds 1, ff 1, dc 4, dk 1, gh 1, p4 3 |
| 26 | bytes: length differs: few instructions (<= 4) | 7 | 0 | 0 | - | printer (printc) | dds 1, ff 1, dc 3, gh 1, p4 1 |
| 27 | bytes: same length, many instructions differ: floating-point or vector sequence | 3 | 0 | 0 | - | printer (printc) | dk 2, p4 1 |
| 28 | bytes: length differs: nops or register copies (allocation or scheduling) | 2 | 0 | 0 | - | printer (printc) | rc 1, dc 1 |
| 29 | bytes: length differs: nops and register copies | 2 | 0 | 0 | - | printer (printc) | dc 1, gh 1 |
| 30 | bytes: length differs: extension instructions (type or cast) | 1 | 0 | 0 | - | types/prototypes | rc 1 |

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
- **compile: member access on a type the context lacks** -> types/prototypes: the printed access uses Ghidra's synthetic storage members (`key_now.u4[0]`, `eff_focus.u4[0]`, `GiftagAD.u4[0]`, `uStack_8._4_4_`) although the context declares the global with its real type (`extern u_short *key_now[32]`, `extern EFF_FOCUS eff_focus`, `extern sceGifTag GiftagAD`, `extern float SysCur[3]`); standalone compiles fail too, none are context-only.
- **compile: syntax error** -> printer (printc): Ghidra placeholder types printed as C types: `extern undefined6 _530;`, `extern undefined3 _4574;`, `undefined7 whole;` (sizes 3/5/6/7 have no C type); the same text fails standalone.
- **compile: undeclared identifier** -> printer (printc): locals the text uses but does not declare (`undefined7 uStack_c0`, `_DAT_00252bf0.whole`, `_iStack_70`, `_abStack_170`).
- **compile: call does not match prototype** -> types/prototypes: calls whose argument count or types disagree with the context's callee prototype (`sceVu0CopyVector(float *)` with a 2-parameter prototype; `sceVu0UnitMatrix()`); romwright guessed the callee because the harness could not assert array-typedef parameters (harness artifact, fixed: `typedef_table_with_arrays`, see the fixed-artifacts table); what remains is the printer's call arguments.
- **bytes: access width or signedness (type or cast)** -> types/prototypes: load/store width or signedness differs: the declared type of the object.
- **bytes: stack layout** -> printer (printc): same instructions, different frame offsets: local declaration order and arrays.
- **compile: no candidate produced** -> printer (printc): export-c emitted no function for the address (gh 1, rcpal 1).
- **compile: unit post-processing rejected the candidate object** -> lane harness: dc `ChangeSetUnit`: the repo's postprocess_object.py for dng_main.cpp raises 'expected one debug event stack' on any candidate that lacks the unit's own static; the unit's build step cannot be dropped without changing the object (left, 1 function).
- **compile: incomplete type** -> types/prototypes: dk `LoadScript`: `EdScriptBuffer.u4[0]` on a context type that is an incomplete struct.
- **compile: illegal or unknown type name** -> printer (printc): address arithmetic on a `void *` global (`*(unsigned int *)(nowMonster + 0x1490)`, `edit_info + 0x70`, `edit_info + week_no * 0x300`): MWCC rejects void-pointer arithmetic, m2c's text for the same functions compiles and is exact in 3 (the cast to `char *`/`int` is missing).
- **compile: conflicting types / redeclaration** -> export context (emit_m2c declarations/dependencies); the K&R share is harness-owned and fixed: 20 of 23 first-round ff failures were `T f();` K&R declarations against romwright's `unsigned int f(void)` head: the harness asserted no signature but compiled against the declaration (fixed: the unasserted target declaration is dropped from romwright's compile context). Left: `extern unsigned char BCommJmpTbl[84]` re-declaring a global the context already declares as `void (*BCommJmpTbl[])(ENE_WRK *)`.
- **compile: other** -> printer (printc): ff `SetMyLight` uses the value of a `void` call, `StageTitleLoad` an aggregate as an integer.
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

### dds: 4 of 200

| class | count | context only | m2c exact | example 1 | example 2 |
|---|---|---|---|---|---|
| undeclared identifier | 2 | 0 | 0 | `0x284258` mnuDrawPanelSequenceByRow: `_iStack_70 = 0x300000006;` (`_iStack_70' undeclared (first use in this function)) | `0x2848e0` mnuInitializePanelGroupGridSlots: `_iStack_50 = 0x200000000;` (`_iStack_50' undeclared (first use in this function)) |
| type mismatch (assignment, operand, return, cast) | 1 | 0 | 0 | `0x17c220` effPcpChargeLongRespawn: `(-1L << (8 - temp_v1) * 8)) | (*(unsigned long long *)(temp_v2 - temp_v1) >> temp_v1 * 8))` (cast specifies array type) |  |
| member access on a type the context lacks | 1 | 0 | 0 | `0x239e30` func_00239E30: `temp_v7._0_8_ = DAT_003bc2b0;` (request for member `_0_8_' in something not a structure or u) |  |

### ff: 55 of 200

| class | count | context only | m2c exact | example 1 | example 2 |
|---|---|---|---|---|---|
| member access on a type the context lacks | 25 | 0 | 0 | `0x107818` BuffPadMnu: `else if ((((*(unsigned short *)key_now.u4[0] == 1) ||` (request for member `u4' in something not a structure or unio) | `0x127e40` InitEffectScr: `eff_focus.u4[0] = 3;` (structure has no member named `u4') |
| type mismatch (assignment, operand, return, cast) | 22 | 0 | 0 | `0x12cc88` SetForcusDepth2: `temp_v3 = (unsigned char *)0x3f3333333f000000;` (incompatible types in assignment) | `0x138ff8` sceVu0ViewClipMatrix: `param_1[0xf] = 0.0f;` (incompatible types in assignment) |
| undeclared identifier | 3 | 0 | 0 | `0x119f58` tes_p20: `fStack_70 = (float)_DAT_00252bf0.whole;` (`_DAT_00252bf0' undeclared (first use in this function)) | `0x1ae360` ZushiBonjiAfterDisp: `undefined7 uStack_c0;` (`undefined7' undeclared (first use in this function)) |
| call does not match prototype | 2 | 0 | 0 | `0x10cc08` EiInitIopDev: `temp_v0 = sceSifCallRpc(ei_sys,0,0,(void *)0x0,0,(void *)0x0,0,(void *)0x0,(void *)0x0);` (incompatible type for argument 1 of `sceSifCallRpc') | `0x208ed8` PhotoPointChkRare: `PhotoPointCulcRare((unsigned char)temp_v1,photo_wrk,temp_v2,afStack_70[0]);` (incompatible type for argument 2 of `PhotoPointCulcRare') |
| conflicting types / redeclaration | 1 | 1 | 0 | `0x190f88` EneBlinkCtrl: `extern unsigned char BCommJmpTbl[84]; /* 0x322720 */` (conflicting types for `BCommJmpTbl') |  |
| syntax error | 1 | 0 | 0 | `0x1f9318` BtlModSaveInit: `undefined7 whole;` (parse error before `undefined7') |  |
| other | 1 | 0 | 0 | `0x21d5c0` StageTitleLoad: `(unsigned int)(unsigned char)stage_dat[(unsigned int)DAT_00344705[0] * 0xc0 + 0x12] * 4);` (aggregate value used where an integer was expected) |  |

### rc: 1 of 200

| class | count | context only | m2c exact | example 1 | example 2 |
|---|---|---|---|---|---|
| type mismatch (assignment, operand, return, cast) | 1 | 0 | 0 | `0x128d28` _extensionAndUserData: `temp_v1 = (unsigned char *)0x12c9300012cb00;` (incompatible types in assignment) |  |

### dc: 24 of 200

| class | count | context only | m2c exact | example 1 | example 2 |
|---|---|---|---|---|---|
| syntax error | 11 | 0 | 0 | `0x1496f0` GetFullPath__FPcPc: `extern undefined6 _530; /* 0x366fd8 */` (';' expected) | `0x15cf50` MyStrCpyLineFeed__FPcPc: `extern undefined3 _4574; /* 0x367440 */` (';' expected) |
| type mismatch (assignment, operand, return, cast) | 8 | 6 | 0 | `0x137e70` GetWorldPosition__8mgCFrameFPfPf: `sceVu0ApplyMatrix(param_2,(float **)afStack_40,param_3);` (illegal implicit conversion from 'float **' to) | `0x148be0` SetCurrentDir__FPc: `return pcVar1;` (illegal return value in void/constructor/destructor function) |
| call does not match prototype | 2 | 0 | 0 | `0x1371b0` SetBrother__8mgCFrameFP8mgCFrame: `SetBrother__8mgCFrameFP8mgCFrame(*(int *)(param_1 + 0x5c));` (function call 'SetBrother__8mgCFrameFP8mgCFrame(int)' does n) | `0x21c290` GyoraceMenuInit__FP9mgCMemoryPii: `= LoadFileMenu((char *)_5140,(void *)(DAT_01efb9b0[0] + DAT_01efb9b4[0] * 0x10));` (function call 'LoadFileMenu(char *, void *)' does not match) |
| member access on a type the context lacks | 2 | 0 | 0 | `0x22e390` Func_MenuItemBrdPosStep__Fi: `MenuItemBrdUnderBrdPosXY.f4[0] = (float)((int)uStack_8 + 0x10);` (not a struct/union/class) | `0x2d6670` _ESM_CREATE__FP12RS_STACKDATAi: `if (*(int *)(action_info.u4[0] + 0x7dc) == 0) {` ('u4' is not a struct/union/class member) |
| unit post-processing rejected the candidate object | 1 | 0 | 0 | `0x1d4e00` ChangeSetUnit__Fi: `    raise ValueError(f'dng_main: expected one debug event stack, found {len(storage)}')` (    raise ValueError(f'dng_main: expected one debug event st) |  |

### dk: 24 of 200

| class | count | context only | m2c exact | example 1 | example 2 |
|---|---|---|---|---|---|
| syntax error | 8 | 0 | 0 | `0x130fc0` Initialize__15CTextureManagerFi: `extern undefined5 _221; /* 0x298e98 */` (';' expected) | `0x15ff50` InitSystemMes__Fv: `extern undefined5 _333; /* 0x29a078 */` (';' expected) |
| member access on a type the context lacks | 6 | 0 | 0 | `0x13dea0` openGiftag__FP13sceVif1Packet: `sceVif1PkOpenGifTag(param_1,GiftagAD.u4[0]);` ('u4' is not a struct/union/class member) | `0x14eff0` GetMesLen_system__6ClsMesFi: `uStack_8._4_4_ = -1;` (not a struct/union/class) |
| type mismatch (assignment, operand, return, cast) | 6 | 3 | 0 | `0x1938b0` _LOAD_LIGHT__FP12RS_STACKDATAi: `sceVu0CopyMatrix((float **)LAB_01d3d500,(float **)(save_l + temp_v2));` (cannot convert) | `0x198f90` EdTalkModeInit__FP12CNPCharacteri: `DAT_01d3d430[0] = ((int)param_1 - (char *)&EdVillager) / 0x14a0;` (illegal operand) |
| undeclared identifier | 2 | 0 | 0 | `0x1d5b30` Draw__15CItemBombEffectFP7CCamera: `undefined7 uStack_f;` (undefined identifier 'undefined7') | `0x1d6940` Draw__13CWeaponEffectFv: `undefined7 uStack_f;` (undefined identifier 'undefined7') |
| incomplete type | 1 | 0 | 0 | `0x19b9a0` LoadScript__Fv__2: `EdEventData = (char *)EdScriptBuffer.u4[0];` (illegal use of incomplete struct/union/class 'struct CDataAl) |  |
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

