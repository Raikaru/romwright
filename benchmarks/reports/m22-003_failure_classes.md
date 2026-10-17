# m22-003 failure classes: where romwright's C output loses

Source: `m22-003_<lane>_fix2.json` of the nine lanes (except ff: `_fix5`, dc: `_fix3`, dk: `_fix3`) (headline `context` variant, 200 functions per lane). A compile failure is classified by the compiler's first diagnostic; a compiled candidate that is not exact by a word-level comparison against the retail bytes. `context only` counts failures whose same text compiles without the unit's declarations (the standalone variant), i.e. where the context is what breaks it. `m2c exact` counts the functions m2c gets exact in the same class.

## Per lane

| lane | romwright exact | m2c exact | compile failures | exact rate among compiled |
|---|---|---|---|---|
| dds | 61 | 49 | 4 of 200 | 0.31 |
| ff | 20 | 4 | 55 of 200 | 0.14 |
| rc | 26 | 14 | 1 of 200 | 0.13 |
| dc | 35 | 33 | 34 of 200 | 0.21 |
| dk | 27 | 33 | 31 of 200 | 0.16 |
| gh | 78 | 47 | 1 of 200 | 0.39 |
| rcpal | 28 | 34 | 9 of 200 | 0.15 |
| p4 | 60 | 41 | 7 of 200 | 0.31 |
| p4-eegcc | 96 | 85 | 1 of 200 | 0.48 |

## Ranked classes (across lanes)

Ranked by plausible exact gain: a compile-failure class recovers (failures x the lane's exact rate among the candidates that compile); a byte-difference class recovers all its functions when it is a near miss (a single instruction, register or stack difference, a few instructions, an extension or width, a reordering) and none otherwise. `m2c exact` is the number of those functions that m2c gets exact.

| rank | class | functions | plausible exact gain | m2c exact | context only | owner | per lane |
|---|---|---|---|---|---|---|---|
| 1 | bytes: few instructions differ (<= 4) | 39 | 39 | 7 | - | printer (printc) | dds 3, ff 2, dc 4, dk 5, gh 13, rcpal 7, p4 1, p4-eegcc 4 |
| 2 | bytes: register allocation | 29 | 29 | 4 | - | printer (printc) | dds 2, ff 2, rc 2, dc 2, dk 6, gh 3, rcpal 1, p4 6, p4-eegcc 5 |
| 3 | bytes: same instructions, different order (scheduling) | 28 | 28 | 2 | - | printer (printc) | dds 4, ff 7, rc 4, dk 1, gh 4, rcpal 1, p4 3, p4-eegcc 4 |
| 4 | bytes: single instruction | 22 | 22 | 0 | - | printer (printc) | dds 3, ff 2, rc 1, dc 2, dk 5, gh 3, rcpal 1, p4 4, p4-eegcc 1 |
| 5 | bytes: register allocation and stack layout | 17 | 17 | 5 | - | printer (printc) | dds 3, ff 2, dc 1, dk 4, gh 3, rcpal 3, p4 1 |
| 6 | compile: type mismatch (assignment, operand, return, cast) | 46 | 8.1 | 1 | 11 | types/prototypes; printer for the array casts | dds 1, ff 22, rc 1, dc 8, dk 6, rcpal 3, p4 5 |
| 7 | compile: member access on a type the context lacks | 36 | 5.4 | 0 | 0 | types/prototypes | dds 1, ff 25, dc 2, dk 6, rcpal 2 |
| 8 | compile: syntax error | 20 | 3.7 | 0 | 0 | printer (printc) | ff 1, dc 11, dk 8 |
| 9 | compile: illegal or unknown type name | 19 | 3.6 | 3 | 0 | printer (printc) | dc 11, dk 8 |
| 10 | compile: undeclared identifier | 11 | 2.1 | 0 | 0 | printer (printc) | dds 2, ff 3, dk 2, rcpal 3, p4 1 |
| 11 | compile: call does not match prototype | 5 | 1.3 | 0 | 1 | types/prototypes | ff 2, dc 1, p4 1, p4-eegcc 1 |
| 12 | bytes: access width or signedness (type or cast) | 1 | 1 | 0 | - | types/prototypes | dk 1 |
| 13 | bytes: stack layout | 1 | 1 | 0 | - | printer (printc) | p4 1 |
| 14 | compile: no candidate produced | 2 | 0.5 | 0 | 0 | printer (printc) | gh 1, rcpal 1 |
| 15 | compile: unit post-processing rejected the candidate object | 1 | 0.2 | 0 | 0 | lane harness | dc 1 |
| 16 | compile: incomplete type | 1 | 0.2 | 0 | 0 | types/prototypes | dk 1 |
| 17 | compile: conflicting types / redeclaration | 1 | 0.1 | 0 | 1 | export context (emit_m2c declarations/dependencies); the K&R share is harness-owned and fixed | ff 1 |
| 18 | compile: other | 1 | 0.1 | 0 | 0 | printer (printc) | ff 1 |
| 19 | bytes: length differs: mixed arithmetic (expression shape) | 578 | 0 | 25 | - | printer (printc) | dds 54, ff 73, rc 106, dc 54, dk 61, gh 32, rcpal 104, p4 59, p4-eegcc 35 |
| 20 | bytes: length differs: control flow (branches, calls) | 236 | 0 | 23 | - | printer (printc) | dds 38, ff 11, rc 23, dc 36, dk 24, gh 29, rcpal 18, p4 34, p4-eegcc 23 |
| 21 | bytes: same length, many instructions differ: control flow (branches, calls) | 45 | 0 | 6 | - | printer (printc) | dds 7, ff 3, rc 6, dc 2, dk 7, gh 8, rcpal 3, p4 3, p4-eegcc 6 |
| 22 | bytes: length differs: memory accesses (temporaries, spills, widths) | 82 | 0 | 4 | - | printer (printc) | dds 2, ff 10, rc 11, dc 12, dk 9, gh 12, rcpal 8, p4 8, p4-eegcc 10 |
| 23 | bytes: same length, many instructions differ: mixed arithmetic (expression shape) | 91 | 0 | 3 | - | printer (printc) | dds 13, ff 9, rc 12, dc 8, dk 13, gh 9, rcpal 12, p4 5, p4-eegcc 10 |
| 24 | bytes: same length, many instructions differ: memory accesses (temporaries, spills, widths) | 28 | 0 | 1 | - | printer (printc) | dds 4, ff 2, rc 6, dc 1, dk 3, gh 2, rcpal 2, p4 3, p4-eegcc 5 |
| 25 | bytes: length differs: few instructions (<= 4) | 7 | 0 | 1 | - | printer (printc) | dds 1, ff 1, dc 3, gh 1, p4 1 |
| 26 | bytes: same length, many instructions differ: floating-point or vector sequence | 2 | 0 | 1 | - | printer (printc) | dk 2 |
| 27 | bytes: length differs: floating-point or vector sequence | 13 | 0 | 0 | - | printer (printc) | dds 1, ff 1, dc 4, dk 1, gh 1, rcpal 1, p4 4 |
| 28 | bytes: length differs: nops and register copies | 3 | 0 | 0 | - | printer (printc) | dc 1, gh 1, rcpal 1 |
| 29 | bytes: length differs: extension instructions (type or cast) | 2 | 0 | 0 | - | types/prototypes | rc 1, rcpal 1 |
| 30 | bytes: length differs: nops or register copies (allocation or scheduling) | 2 | 0 | 0 | - | printer (printc) | rc 1, dc 1 |

## Harness-owned classes fixed in this round (romwright / m2c at the `context` variant: exact / compiled / mean %)

| lane | romwright before | romwright after | m2c before | m2c after |
|---|---|---|---|---|
| dds | 61 / 193 / 75.6 | 61 / 196 / 76.8 | 49 / 152 / 62.2 | 49 / 153 / 62.7 |
| ff | 20 / 134 / 46.3 | 20 / 145 / 49.2 | 4 / 19 / 7.6 | 4 / 18 / 7.6 |
| rc | 24 / 191 / 65.2 | 26 / 199 / 68.1 | 11 / 112 / 40.7 | 14 / 116 / 42.4 |
| dc | 32 / 159 / 60.5 | 35 / 166 / 62.6 | 33 / 108 / 45.2 | 33 / 109 / 45.7 |
| dk | 26 / 164 / 65.3 | 27 / 169 / 67.4 | 33 / 98 / 43.7 | 33 / 98 / 43.7 |
| gh | 78 / 183 / 75.1 | 78 / 199 / 82.0 | 47 / 134 / 56.5 | 47 / 135 / 57.0 |
| rcpal | 15 / 104 / 36.5 | 28 / 191 / 63.7 | 23 / 76 / 30.4 | 34 / 117 / 46.9 |
| p4 | 59 / 189 / 77.7 | 60 / 193 / 79.1 | 41 / 129 / 54.3 | 41 / 130 / 54.7 |
| p4-eegcc | 96 / 197 / 84.0 | 96 / 199 / 84.8 | 85 / 164 / 72.7 | 85 / 165 / 73.2 |

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
- **compile: illegal or unknown type name** -> printer (printc): address arithmetic on a `void *` global (`*(unsigned int *)(nowMonster + 0x1490)`, `edit_info + 0x70`, `edit_info + week_no * 0x300`): MWCC rejects void-pointer arithmetic, m2c's text for the same functions compiles and is exact in 3 (the cast to `char *`/`int` is missing).
- **compile: undeclared identifier** -> printer (printc): locals the text uses but does not declare (`undefined7 uStack_c0`, `_DAT_00252bf0.whole`, `_iStack_70`, `_abStack_170`).
- **compile: call does not match prototype** -> types/prototypes: calls whose argument count or types disagree with the context's callee prototype (`sceVu0CopyVector(float *)` with a 2-parameter prototype; `sceVu0UnitMatrix()`); romwright guessed the callee because the harness could not assert array-typedef parameters (harness artifact, fixed: `typedef_table_with_arrays`, see the fixed-artifacts table); what remains is the printer's call arguments.
- **bytes: access width or signedness (type or cast)** -> types/prototypes: load/store width or signedness differs: the declared type of the object.
- **bytes: stack layout** -> printer (printc): same instructions, different frame offsets: local declaration order and arrays.
- **compile: no candidate produced** -> printer (printc): export-c emitted no function for the address (gh 1, rcpal 1).
- **compile: unit post-processing rejected the candidate object** -> lane harness: dc `ChangeSetUnit`: the repo's postprocess_object.py for dng_main.cpp raises 'expected one debug event stack' on any candidate that lacks the unit's own static; the unit's build step cannot be dropped without changing the object (left, 1 function).
- **compile: incomplete type** -> types/prototypes: dk `LoadScript`: `EdScriptBuffer.u4[0]` on a context type that is an incomplete struct.
- **compile: conflicting types / redeclaration** -> export context (emit_m2c declarations/dependencies); the K&R share is harness-owned and fixed: 20 of 23 first-round ff failures were `T f();` K&R declarations against romwright's `unsigned int f(void)` head: the harness asserted no signature but compiled against the declaration (fixed: the unasserted target declaration is dropped from romwright's compile context). Left: `extern unsigned char BCommJmpTbl[84]` re-declaring a global the context already declares as `void (*BCommJmpTbl[])(ENE_WRK *)`.
- **compile: other** -> printer (printc): ff `SetMyLight` uses the value of a `void` call, `StageTitleLoad` an aggregate as an integer.
- **bytes: length differs: mixed arithmetic (expression shape)** -> printer (printc): different instruction count: control-flow shape, expression shape, loop forms.
- **bytes: length differs: control flow (branches, calls)** -> printer (printc): different instruction count: control-flow shape, expression shape, loop forms.
- **bytes: same length, many instructions differ: control flow (branches, calls)** -> printer (printc): same size, different code: expression shape or control-flow form.
- **bytes: length differs: memory accesses (temporaries, spills, widths)** -> printer (printc): different instruction count: control-flow shape, expression shape, loop forms.
- **bytes: same length, many instructions differ: mixed arithmetic (expression shape)** -> printer (printc): same size, different code: expression shape or control-flow form.
- **bytes: same length, many instructions differ: memory accesses (temporaries, spills, widths)** -> printer (printc): same size, different code: expression shape or control-flow form.
- **bytes: length differs: few instructions (<= 4)** -> printer (printc): a few instructions more or fewer: redundant temporaries or folded expressions.
- **bytes: same length, many instructions differ: floating-point or vector sequence** -> printer (printc): same size, different code: expression shape or control-flow form.
- **bytes: length differs: floating-point or vector sequence** -> printer (printc): different instruction count: control-flow shape, expression shape, loop forms.
- **bytes: length differs: nops and register copies** -> printer (printc): different instruction count: control-flow shape, expression shape, loop forms.
- **bytes: length differs: extension instructions (type or cast)** -> types/prototypes: sign/zero extension differs: the declared type or a cast.
- **bytes: length differs: nops or register copies (allocation or scheduling)** -> printer (printc): different instruction count: control-flow shape, expression shape, loop forms.

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
| type mismatch (assignment, operand, return, cast) | 22 | 0 | 0 | `0x12cc88` SetForcusDepth2: `temp_v3 = (unsigned char  [8])0x3f3333333f000000;` (cast specifies array type) | `0x138ff8` sceVu0ViewClipMatrix: `param_1[0xf] = 0.0f;` (incompatible types in assignment) |
| undeclared identifier | 3 | 0 | 0 | `0x119f58` tes_p20: `fStack_70 = (float)_DAT_00252bf0.whole;` (`_DAT_00252bf0' undeclared (first use in this function)) | `0x1ae360` ZushiBonjiAfterDisp: `undefined7 uStack_c0;` (`undefined7' undeclared (first use in this function)) |
| call does not match prototype | 2 | 0 | 0 | `0x10cc08` EiInitIopDev: `temp_v0 = sceSifCallRpc(ei_sys,0,0,(void *)0x0,0,(void *)0x0,0,(void *)0x0,(void *)0x0);` (incompatible type for argument 1 of `sceSifCallRpc') | `0x208ed8` PhotoPointChkRare: `PhotoPointCulcRare((unsigned char)temp_v1,photo_wrk,temp_v2,afStack_70[0]);` (incompatible type for argument 2 of `PhotoPointCulcRare') |
| conflicting types / redeclaration | 1 | 1 | 0 | `0x190f88` EneBlinkCtrl: `extern unsigned char BCommJmpTbl[84]; /* 0x322720 */` (conflicting types for `BCommJmpTbl') |  |
| syntax error | 1 | 0 | 0 | `0x1f9318` BtlModSaveInit: `undefined7 whole;` (parse error before `undefined7') |  |
| other | 1 | 0 | 0 | `0x21d5c0` StageTitleLoad: `(unsigned int)(unsigned char)stage_dat[(unsigned int)DAT_00344705[0] * 0xc0 + 0x12] * 4);` (aggregate value used where an integer was expected) |  |

### rc: 1 of 200

| class | count | context only | m2c exact | example 1 | example 2 |
|---|---|---|---|---|---|
| type mismatch (assignment, operand, return, cast) | 1 | 0 | 0 | `0x128d28` _extensionAndUserData: `temp_v1 = (unsigned char  [8])0x12c9300012cb00;` (cast specifies array type) |  |

### dc: 34 of 200

| class | count | context only | m2c exact | example 1 | example 2 |
|---|---|---|---|---|---|
| syntax error | 11 | 0 | 0 | `0x1496f0` GetFullPath__FPcPc: `extern undefined6 _530; /* 0x366fd8 */` (';' expected) | `0x15cf50` MyStrCpyLineFeed__FPcPc: `extern undefined3 _4574; /* 0x367440 */` (';' expected) |
| illegal or unknown type name | 11 | 0 | 2 | `0x1e55d0` _SET_NEXT_ROT__FP12RS_STACKDATAi: `*(unsigned int *)(nowMonster + 0x1490) = temp_v0;` (illegal type) | `0x1e8930` _TRANS_RESERV_IMG__FP12RS_STACKDATAi: `temp_v0 = (int)((int)temp_v2 * 4 + nowMonster);` (illegal type) |
| type mismatch (assignment, operand, return, cast) | 8 | 6 | 1 | `0x137e70` GetWorldPosition__8mgCFrameFPfPf: `sceVu0ApplyMatrix(param_2,(float **)afStack_40,param_3);` (illegal implicit conversion from 'float **' to) | `0x148be0` SetCurrentDir__FPc: `return pcVar1;` (illegal return value in void/constructor/destructor function) |
| member access on a type the context lacks | 2 | 0 | 0 | `0x22e390` Func_MenuItemBrdPosStep__Fi: `MenuItemBrdUnderBrdPosXY.f4[0] = (float)((int)uStack_8 + 0x10);` (not a struct/union/class) | `0x2d6670` _ESM_CREATE__FP12RS_STACKDATAi: `if (*(int *)(action_info.u4[0] + 0x7dc) == 0) {` ('u4' is not a struct/union/class member) |
| call does not match prototype | 1 | 0 | 0 | `0x1371b0` SetBrother__8mgCFrameFP8mgCFrame: `SetBrother__8mgCFrameFP8mgCFrame(*(int *)(param_1 + 0x5c));` (function call 'SetBrother__8mgCFrameFP8mgCFrame(int)' does n) |  |
| unit post-processing rejected the candidate object | 1 | 0 | 0 | `0x1d4e00` ChangeSetUnit__Fi: `    raise ValueError(f'dng_main: expected one debug event stack, found {len(storage)}')` (    raise ValueError(f'dng_main: expected one debug event st) |  |

### dk: 31 of 200

| class | count | context only | m2c exact | example 1 | example 2 |
|---|---|---|---|---|---|
| syntax error | 8 | 0 | 0 | `0x130fc0` Initialize__15CTextureManagerFi: `extern undefined5 _221; /* 0x298e98 */` (';' expected) | `0x15ff50` InitSystemMes__Fv: `extern undefined5 _333; /* 0x29a078 */` (';' expected) |
| illegal or unknown type name | 8 | 0 | 1 | `0x174b60` CommandAMBIENT__FPPv: `*(unsigned int *)(light_no * 0x10 + edit_info + 0x70) = *(unsigned int *)*param_1;` (illegal type) | `0x176e20` CommandTIME_TABLE__FPPv: `temp_v0 = (int)(edit_info + week_no * 0x300 + *(int *)*param_1 * 0x40 + 0x18d00);` (illegal type) |
| member access on a type the context lacks | 6 | 0 | 0 | `0x13dea0` openGiftag__FP13sceVif1Packet: `sceVif1PkOpenGifTag(param_1,GiftagAD.u4[0]);` ('u4' is not a struct/union/class member) | `0x14eff0` GetMesLen_system__6ClsMesFi: `uStack_8._4_4_ = -1;` (not a struct/union/class) |
| type mismatch (assignment, operand, return, cast) | 6 | 3 | 0 | `0x1938b0` _LOAD_LIGHT__FP12RS_STACKDATAi: `sceVu0CopyMatrix((float **)LAB_01d3d500,(float **)(save_l + temp_v2));` (cannot convert) | `0x198f90` EdTalkModeInit__FP12CNPCharacteri: `DAT_01d3d430[0] = ((int)param_1 - (char *)&EdVillager) / 0x14a0;` (illegal operand) |
| undeclared identifier | 2 | 0 | 0 | `0x1d5b30` Draw__15CItemBombEffectFP7CCamera: `undefined7 uStack_f;` (undefined identifier 'undefined7') | `0x1d6940` Draw__13CWeaponEffectFv: `undefined7 uStack_f;` (undefined identifier 'undefined7') |
| incomplete type | 1 | 0 | 0 | `0x19b9a0` LoadScript__Fv__2: `EdEventData = (char *)EdScriptBuffer.u4[0];` (illegal use of incomplete struct/union/class 'struct CDataAl) |  |

### gh: 1 of 200

| class | count | context only | m2c exact | example 1 | example 2 |
|---|---|---|---|---|---|
| no candidate produced | 1 | 0 | 0 | `0x297c20` cEvent__isPlaying: `no candidate` (no candidate) |  |

### rcpal: 9 of 200

| class | count | context only | m2c exact | example 1 | example 2 |
|---|---|---|---|---|---|
| undeclared identifier | 3 | 0 | 0 | `0x1f5148` func_001F5148: `temp_v0 = _DAT_00160920.whole;` (`_DAT_00160920' undeclared (first use in this function)) | `0x1f5800` func_001F5800: `temp_v1 = _DAT_00160940.whole;` (`_DAT_00160940' undeclared (first use in this function)) |
| type mismatch (assignment, operand, return, cast) | 3 | 0 | 0 | `0x217ae8` func_00217AE8: `temp_v6 = (unsigned char  [8])DAT_001e89b0[0];` (cast specifies array type) | `0x21b138` func_0021B138: `temp_v4 = (unsigned char  [8])DAT_001e8a60[0];` (cast specifies array type) |
| member access on a type the context lacks | 2 | 0 | 0 | `0x2175c8` func_002175C8: `temp_v1._0_2_ = (unsigned short)(DAT_00151800[0] >> 0x10);` (request for member `_0_2_' in something not a structure or u) | `0x23e0d8` func_0023E0D8: `temp_v2._0_4_ = DAT_00161320;` (request for member `_0_4_' in something not a structure or u) |
| no candidate produced | 1 | 0 | 0 | `0x11dd68` func_0011DD68: `no candidate` (no candidate) |  |

### p4: 7 of 200

| class | count | context only | m2c exact | example 1 | example 2 |
|---|---|---|---|---|---|
| type mismatch (assignment, operand, return, cast) | 5 | 2 | 0 | `0x317240` func_00317240: `func_002b6c30(0x42ce0000,0x1e4,uStack_8,0xbc);` (illegal implicit conversion from 'int' to) | `0x317320` func_00317320: `func_002b6c30(0x42ce0000,0x1e4,uStack_8,0xbc);` (illegal implicit conversion from 'int' to) |
| call does not match prototype | 1 | 1 | 0 | `0x21ae80` func_0021ae80: `func_0021b310((u8 *)(param_1 + 0xa3c));` (function call 'func_0021b310(unsigned char *)' does not matc) |  |
| undeclared identifier | 1 | 0 | 0 | `0x25fbb0` func_0025fbb0: `if (&stack0x00000000 != (unsigned char *)0x30) {` (undefined identifier 'stack0x00000000') |  |

### p4-eegcc: 1 of 200

| class | count | context only | m2c exact | example 1 | example 2 |
|---|---|---|---|---|---|
| call does not match prototype | 1 | 0 | 0 | `0x4e19a0` toUpperStr: `temp_v0 = strlen();` (too few arguments to function `strlen') |  |

## Functions m2c gets exact and romwright does not

### dk: 18 functions

| cause | count |
|---|---|
| length differs: mixed arithmetic (expression shape) | 5 |
| length differs: control flow (branches, calls) | 4 |
| register allocation | 3 |
| length differs: memory accesses (temporaries, spills, widths) | 1 |
| compile failure: illegal or unknown type name | 1 |
| same length, many instructions differ: floating-point or vector sequence | 1 |
| register allocation and stack layout | 1 |
| same length, many instructions differ: control flow (branches, calls) | 1 |
| same length, many instructions differ: mixed arithmetic (expression shape) | 1 |

| address | function | bytes | cause | detail |
|---|---|---|---|---|
| 0x124770 | __dt__7CCameraFv | 84 | length differs: control flow (branches, calls) | 5 word(s), 92.4% |
| 0x124bf0 | __ct__13CCameraFollowFffff | 136 | length differs: mixed arithmetic (expression shape) | 14 word(s), 88.2% |
| 0x12b8b0 | Down2__8CGamePadFi | 56 | register allocation | 2 word(s), 98.9% |
| 0x1312d0 | GetTexture__15CTextureManagerFPci | 80 | length differs: mixed arithmetic (expression shape) | 108 word(s), 0.0% |
| 0x169ab0 | GetLYf__Fv | 64 | length differs: mixed arithmetic (expression shape) | 7 word(s), 77.5% |
| 0x174b10 | CommandLIGHT_NO__FPPv | 72 | length differs: memory accesses (temporaries, spills, widths) | 12 word(s), 88.9% |
| 0x177550 | CommandTALK_DIR__FPPv | 32 | compile failure: illegal or unknown type name | illegal type |
| 0x178170 | EdSetClock__Ff | 96 | length differs: control flow (branches, calls) | 12 word(s), 84.2% |
| 0x187dd0 | EdCheckTime__Ffff | 132 | same length, many instructions differ: floating-point or vector sequence | 8 word(s), 72.6% |
| 0x191da0 | _SET_CAMERA_SPEED__FP12RS_STACKDATAi | 96 | length differs: mixed arithmetic (expression shape) | 33 word(s), 62.1% |
| 0x1950f0 | _SITEM_GET__FP12RS_STACKDATAi | 104 | register allocation and stack layout | 6 word(s), 98.8% |
| 0x19a210 | GetNextParts__14CEditPartsInfoFi | 112 | same length, many instructions differ: control flow (branches, calls) | 8 word(s), 57.9% |
| 0x1f2db0 | FishingExchangeLoop__Fv | 84 | length differs: mixed arithmetic (expression shape) | 5 word(s), 82.6% |
| 0x2223b0 | SaveMenuKeyEndSaveEnding__Fv | 88 | length differs: control flow (branches, calls) | 18 word(s), 90.7% |
| 0x225530 | PlayerAllItemCheck__Fi | 156 | length differs: control flow (branches, calls) | 44 word(s), 73.2% |
| 0x233520 | GetNowManualPartTgaNum__Fv | 56 | same length, many instructions differ: mixed arithmetic (expression shape) | 10 word(s), 52.1% |
| 0x2356d0 | LoopStep__13CMenuItemStepFi | 76 | register allocation | 2 word(s), 99.5% |
| 0x2410f0 | DeleteReference__5CFishFv | 76 | register allocation | 4 word(s), 98.9% |

### rcpal: 16 functions

| cause | count |
|---|---|
| few instructions differ (<= 4) | 6 |
| length differs: mixed arithmetic (expression shape) | 4 |
| register allocation and stack layout | 3 |
| same length, many instructions differ: mixed arithmetic (expression shape) | 2 |
| length differs: control flow (branches, calls) | 1 |

| address | function | bytes | cause | detail |
|---|---|---|---|---|
| 0x12d340 | func_0012D340 | 64 | length differs: mixed arithmetic (expression shape) | 22 word(s), 57.6% |
| 0x1ec038 | func_001EC038 | 92 | length differs: mixed arithmetic (expression shape) | 35 word(s), 46.3% |
| 0x1f4b68 | func_001F4B68 | 80 | length differs: mixed arithmetic (expression shape) | 17 word(s), 73.0% |
| 0x207e28 | func_00207E28 | 52 | register allocation and stack layout | 2 word(s), 90.8% |
| 0x208208 | func_00208208 | 48 | register allocation and stack layout | 2 word(s), 90.0% |
| 0x209620 | func_00209620 | 120 | length differs: mixed arithmetic (expression shape) | 39 word(s), 65.7% |
| 0x2098a8 | func_002098A8 | 32 | few instructions differ (<= 4) | 3 word(s), 74.4% |
| 0x20e180 | func_0020E180 | 128 | same length, many instructions differ: mixed arithmetic (expression shape) | 27 word(s), 71.3% |
| 0x215c00 | func_00215C00 | 156 | register allocation and stack layout | 21 word(s), 95.9% |
| 0x216028 | func_00216028 | 112 | same length, many instructions differ: mixed arithmetic (expression shape) | 7 word(s), 84.8% |
| 0x216098 | func_00216098 | 72 | few instructions differ (<= 4) | 2 word(s), 93.3% |
| 0x23bf70 | func_0023BF70 | 44 | few instructions differ (<= 4) | 3 word(s), 80.9% |
| 0x23c960 | func_0023C960 | 76 | few instructions differ (<= 4) | 4 word(s), 88.9% |
| 0x23d2e8 | func_0023D2E8 | 84 | few instructions differ (<= 4) | 3 word(s), 91.4% |
| 0x23e450 | func_0023E450 | 40 | length differs: control flow (branches, calls) | 5 word(s), 84.0% |
| 0x23e4e0 | func_0023E4E0 | 48 | few instructions differ (<= 4) | 3 word(s), 82.5% |

### dc: 13 functions

| cause | count |
|---|---|
| length differs: control flow (branches, calls) | 5 |
| length differs: mixed arithmetic (expression shape) | 4 |
| compile failure: illegal or unknown type name | 2 |
| single instruction: different instruction | 1 |
| compile failure: type mismatch (assignment, operand, return, cast) | 1 |

| address | function | bytes | cause | detail |
|---|---|---|---|---|
| 0x164050 | mapPARTS_GROUP__FP9SPI_STACKi | 60 | length differs: mixed arithmetic (expression shape) | 23 word(s), 54.1% |
| 0x1a2790 | CheckItemOver__Fv | 156 | length differs: mixed arithmetic (expression shape) | 28 word(s), 91.3% |
| 0x1b6f20 | IsBurn__10CEditPartsFv | 40 | single instruction: different instruction | 1 word(s), 94.0% |
| 0x253f20 | CalcMenuAdd2__FPiii | 112 | length differs: control flow (branches, calls) | 27 word(s), 70.0% |
| 0x258380 | GetActiveCamera__Fv | 40 | compile failure: illegal or unknown type name | illegal type |
| 0x270480 | _MES_CLOSE__FP12RS_STACKDATAi | 104 | length differs: control flow (branches, calls) | 20 word(s), 63.8% |
| 0x279bd0 | _SPHIDA_SET_BALL_COL__FP12RS_STACKDATAi | 56 | compile failure: illegal or unknown type name | illegal type |
| 0x28fd60 | CheckArea__13CRandomCircleFPff | 164 | length differs: mixed arithmetic (expression shape) | 37 word(s), 31.1% |
| 0x29f580 | changeMasterVolume__FUi | 100 | compile failure: type mismatch (assignment, operand, return, cast) | illegal return value in void/constructor/destructor function |
| 0x2a1710 | Search__14CFuncPointMngrFPc | 168 | length differs: control flow (branches, calls) | 30 word(s), 87.7% |
| 0x2dd8b0 | emGetPenkiItemNo__Fi | 52 | length differs: mixed arithmetic (expression shape) | 11 word(s), 41.5% |
| 0x2dda20 | SystemMesStep__FP6CScene | 68 | length differs: control flow (branches, calls) | 13 word(s), 90.6% |
| 0x31bdd0 | AnalyzeEditMap__FiP8CEditMap | 200 | length differs: control flow (branches, calls) | 27 word(s), 96.6% |

### dds: 11 functions

| cause | count |
|---|---|
| length differs: mixed arithmetic (expression shape) | 3 |
| length differs: control flow (branches, calls) | 3 |
| register allocation and stack layout | 1 |
| same instructions, different order (scheduling) | 1 |
| few instructions differ (<= 4) | 1 |
| length differs: memory accesses (temporaries, spills, widths) | 1 |
| same length, many instructions differ: control flow (branches, calls) | 1 |

| address | function | bytes | cause | detail |
|---|---|---|---|---|
| 0x101818 | kwlnTaskGetRegisteredState | 60 | length differs: mixed arithmetic (expression shape) | 11 word(s), 84.3% |
| 0x164a30 | effThunderReleaseSparkWork | 100 | register allocation and stack layout | 12 word(s), 96.5% |
| 0x1a1448 | btlIsCurrentActorFullyMarked | 56 | length differs: mixed arithmetic (expression shape) | 10 word(s), 81.1% |
| 0x1f1c78 | sndAddSourceReferences | 76 | same instructions, different order (scheduling) | 6 word(s), 88.8% |
| 0x1f9d48 | func_001F9D48 | 140 | length differs: control flow (branches, calls) | 22 word(s), 88.0% |
| 0x1fa2b0 | btlCmdRememberUpperQueuedQuery | 140 | length differs: control flow (branches, calls) | 22 word(s), 88.0% |
| 0x213bc0 | btlMarkRuntimeUpdatePending | 32 | few instructions differ (<= 4) | 4 word(s), 73.8% |
| 0x288148 | evtStageTestCreateModelEffect | 68 | length differs: mixed arithmetic (expression shape) | 9 word(s), 78.7% |
| 0x2aaf70 | effCreateStripNode | 128 | length differs: control flow (branches, calls) | 15 word(s), 94.7% |
| 0x2cb058 | sdfSwapLinkedListNodes | 156 | length differs: memory accesses (temporaries, spills, widths) | 36 word(s), 87.1% |
| 0x2daa68 | sdfQueueAssetRelease | 52 | same length, many instructions differ: control flow (branches, calls) | 7 word(s), 64.6% |

### ff: 2 functions

| cause | count |
|---|---|
| length differs: mixed arithmetic (expression shape) | 1 |
| length differs: memory accesses (temporaries, spills, widths) | 1 |

| address | function | bytes | cause | detail |
|---|---|---|---|---|
| 0x15a088 | Tim2GetMipMapPictureSize | 136 | length differs: mixed arithmetic (expression shape) | 48 word(s), 33.9% |
| 0x21e510 | BattleModeScoreRecord | 32 | length differs: memory accesses (temporaries, spills, widths) | 14 word(s), 75.0% |

### rc: 3 functions

| cause | count |
|---|---|
| length differs: mixed arithmetic (expression shape) | 2 |
| length differs: control flow (branches, calls) | 1 |

| address | function | bytes | cause | detail |
|---|---|---|---|---|
| 0x11b3b8 | SceSifCheckStatRpc | 60 | length differs: control flow (branches, calls) | 14 word(s), 64.0% |
| 0x124a48 | scePad2Init | 60 | length differs: mixed arithmetic (expression shape) | 12 word(s), 64.3% |
| 0x12ba68 | sceMpegReset | 80 | length differs: mixed arithmetic (expression shape) | 17 word(s), 91.0% |

### gh: 9 functions

| cause | count |
|---|---|
| length differs: control flow (branches, calls) | 4 |
| length differs: mixed arithmetic (expression shape) | 4 |
| same length, many instructions differ: control flow (branches, calls) | 1 |

| address | function | bytes | cause | detail |
|---|---|---|---|---|
| 0x1492c8 | Forward149378_1492C8 | 32 | length differs: control flow (branches, calls) | 5 word(s), 80.0% |
| 0x1f6d38 | CasinoWork_ResetWarmUpRoom | 224 | length differs: mixed arithmetic (expression shape) | 65 word(s), 79.7% |
| 0x28ed28 | func_0028ED28 | 76 | length differs: mixed arithmetic (expression shape) | 7 word(s), 80.8% |
| 0x31af40 | func_0031AF40 | 48 | same length, many instructions differ: control flow (branches, calls) | 8 word(s), 56.2% |
| 0x331ce0 | func_00331CE0 | 84 | length differs: mixed arithmetic (expression shape) | 20 word(s), 70.8% |
| 0x337b30 | func_00337B30 | 76 | length differs: control flow (branches, calls) | 9 word(s), 83.4% |
| 0x34cdb0 | SFCON_IsVideoEndcodeSkip | 72 | length differs: mixed arithmetic (expression shape) | 5 word(s), 90.6% |
| 0x3588b0 | func_003588B0 | 128 | length differs: control flow (branches, calls) | 22 word(s), 60.6% |
| 0x35d918 | SFH_IsExistStmId | 108 | length differs: control flow (branches, calls) | 13 word(s), 78.5% |

### p4: 10 functions

| cause | count |
|---|---|
| length differs: control flow (branches, calls) | 4 |
| same length, many instructions differ: control flow (branches, calls) | 2 |
| length differs: few instructions (<= 4) | 1 |
| same length, many instructions differ: memory accesses (temporaries, spills, widths) | 1 |
| register allocation | 1 |
| length differs: memory accesses (temporaries, spills, widths) | 1 |

| address | function | bytes | cause | detail |
|---|---|---|---|---|
| 0x170b50 | func_00170b50 | 112 | same length, many instructions differ: control flow (branches, calls) | 7 word(s), 92.3% |
| 0x18a170 | func_0018a170 | 136 | length differs: few instructions (<= 4) | 4 word(s), 94.0% |
| 0x199e70 | func_00199e70 | 80 | length differs: control flow (branches, calls) | 5 word(s), 92.0% |
| 0x1e3270 | func_001e3270 | 172 | length differs: control flow (branches, calls) | 32 word(s), 75.2% |
| 0x1f6220 | func_001f6220 | 100 | length differs: control flow (branches, calls) | 17 word(s), 66.4% |
| 0x2238f0 | func_002238f0 | 168 | same length, many instructions differ: control flow (branches, calls) | 24 word(s), 14.3% |
| 0x2bc060 | func_002bc060 | 76 | length differs: control flow (branches, calls) | 5 word(s), 91.6% |
| 0x474a90 | func_00474a90 | 56 | same length, many instructions differ: memory accesses (temporaries, spills, widths) | 12 word(s), 48.6% |
| 0x4aec50 | func_004aec50 | 44 | register allocation | 2 word(s), 99.1% |
| 0x4b6da0 | func_004b6da0 | 64 | length differs: memory accesses (temporaries, spills, widths) | 9 word(s), 93.4% |

### p4-eegcc: 9 functions

| cause | count |
|---|---|
| context variant only (standalone is exact) | 4 |
| length differs: mixed arithmetic (expression shape) | 2 |
| same instructions, different order (scheduling) | 1 |
| same length, many instructions differ: control flow (branches, calls) | 1 |
| length differs: control flow (branches, calls) | 1 |

| address | function | bytes | cause | detail |
|---|---|---|---|---|
| 0x4d1068 | ADXSJE_Destroy | 104 | same instructions, different order (scheduling) | 2 word(s), 99.5% |
| 0x4d41b0 | ADXT_StartSj | 132 | same length, many instructions differ: control flow (branches, calls) | 24 word(s), 55.6% |
| 0x4d9148 | func_004d9148 | 56 | context variant only (standalone is exact) | 7 word(s), 78.6% |
| 0x4d91b8 | func_004d91b8 | 56 | context variant only (standalone is exact) | 7 word(s), 78.6% |
| 0x4d91f0 | func_004d91f0 | 40 | context variant only (standalone is exact) | 7 word(s), 84.0% |
| 0x4d9240 | func_004d9240 | 40 | context variant only (standalone is exact) | 7 word(s), 84.0% |
| 0x4e43b0 | func_004e43b0 | 56 | length differs: mixed arithmetic (expression shape) | 11 word(s), 45.3% |
| 0x4e44d8 | func_004e44d8 | 76 | length differs: mixed arithmetic (expression shape) | 9 word(s), 93.7% |
| 0x515c80 | SFCON_IsSystemEndcodeSkip | 72 | length differs: control flow (branches, calls) | 26 word(s), 64.8% |

