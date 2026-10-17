# Ghidra master trial (2026-10-12)

**Verdict: do not re-pin to upstream master now. Cherry-pick GP-7003, with the two corrections of the follow-up (`gp7003-12.1.3.cpfix.patch`), into the current patch now, and re-run this trial when a 12.2 release exists.**

Same Rust, same `.sla` files, two decompilers (12.1.3 + patch against master `918d44e` + the same patch rebased):

- **Master as it stands breaks two console images.** GP-7310 (`Varnode::setDef` now throws `Assignment to constant`, also for a Varnode created with a constant output) fails **262 of 390** sampled Nintendo 64 functions (decompile success 1.000 -> 0.328) and **80 of 200** sampled Xbox 360 functions; the failing instructions are loads from a constant address (`lwz r30,0x9c8(r11)`, `lfs f0,0xca4(r10)`); the worker sets `readonly on` for every program and flags each image's read-only ranges. With the commit's added check removed, N64 is back at 1.000 and 182 of its 200 paired functions print identically. PS2 (8 games), GameCube, GBA and NDS are unaffected: decompile success is the same in every sampled game (and on the 7,500 PS2 wave-sample functions of `benchmarks/ps2_decompile_success.py`, 7,495 decompile with both and the same 5 fail with both), recall and precision are identical in all 11, and the import's stored switch tables are identical in 10 of 12 games (N64 loses 3 through GP-7310; one God Hand table loses a target through GP-7003, below; stored tables only, the follow-up measures more).
- **Everywhere else the output moves a little, in both directions.** Of 2,043 paired functions 1,643 (80.4%) print the same text; 400 changed: 64 better, 167 worse, 169 neutral by the printed-text measure. 134 of the worse are Nintendo 64 (133 of them failures); the other 261 changed functions are 64 better, 33 worse, 164 neutral. Gotos in the 11 unaffected wave samples go 515 -> 492 (Fatal Frame 108 -> 86, Dark Cloud 97 -> 87), labels 220 -> 229, printed lines 1.0% fewer (Dark Cloud 5%).
- **Compiled against retail bytes (m22-002, Persona 4, romwright layer):** MWCC lanes +1 exact on both seeds (55 -> 56, 57 -> 58; mean percent +0.97, +0.61; paired by function 9 better / 2 worse on the first seed, 4 / 7 on the second; GP-6788's immediate-copy protection accounts for 6 of the 11 changed functions per seed) but the **ee-gcc lane loses 7 exact (106 -> 99, mean 86.406 -> 84.665)**: GP-7115's new `ruleBlockIfNoExit` branch prints the returning arm first, and disabling just that branch restores 9 of the 14 functions whose score moved.
- **The one decompiler gain that matters is GP-7003** (non-zero mask in jump-table recovery): Fatal Frame `FActExecOccur` goes from a 72-line stub ending at an unrecovered `BRANCHIND` to a 507-line body with three jump tables (33, 34 and 10 entries). It is separable: GP-7003 alone cherry-picked onto 12.1.3 + the patch (`gp7003-12.1.3.patch`, 6 files, applies with fuzz 2) gives master's exact output for it and changes nothing else on the m22 lanes (it brings the lost tables of the follow-up with it, which the corrections remove). God Hand `cIDManager_getLocalFileName` and `func_0039A140` are **not** helped (no table in either decompiler), and GP-7003 as written costs tables (follow-up, `gp7003_cherrypick.md`): the God Hand table at 0x274828 recovers 5 targets instead of the retail 6 because `x % 5` is read as [0,5) under a guard of [0,6), and 20 whole tables are lost in seven games through an empty range after a stride wrap in `CircleRange::newStride`; master has both flaws. `cpfix` removes both (0 lost, 4 gained).
- **A re-pin also costs:** three textual conflicts, four compile breaks, and two wire changes (the packed data-type metatype became an integer, GP-7253; warnings moved to a new burst, GP-6985) that the unchanged worker cannot read; the trial carries compat hunks for both. Master is not a release (no 12.2 tag; it reports 12.3), and the patch RustStructure is editing already collides with master in a fourth file (`blockaction.cc`).


## Arms and environment

|  | base | master |
|---|---|---|
| decompiler C++ | Ghidra 12.1.3 PUBLIC (Ghidra_12.1.3_build 8b4c91d4), third_party/ghidra/decompiler verbatim | upstream master 918d44e (2026-10-08, application.version 12.3; Ghidra_12.2 merged 2026-10-07) |
| ghidra_opt sha256 | dbd7e74bdd7d04a52da4e5390d7d32a9ad8d1df4f1dc218be805a2868212e32e | 57efa6b2b704caa9093beb22a6330654f197ef0a386c20b3a80c667290f4175c |
| native/ghidra-opt-sleigh.patch | native/ghidra-opt-sleigh.patch sha256 d70f9a20... (snapshot 2026-10-10 05:14 UTC build, the patch behind dbd7e74b) | rebased patch sha256 270bff66..., 36 files (benchmarks/reports/ghidra_master_trial/ghidra-opt-sleigh.master.patch) |
| romwright-cli / worker sha256 | 6aaab51b9179559a... | d2fc11fc33cc8985... |
| host | nih-vps-u, 8 vCPU, 31 GB, shared with other agents' builds and gates | nih-vps-u, 8 vCPU, 31 GB, shared with other agents' builds and gates |
| load while measuring | 1-minute load average sampled each minute from 27 samples: median 26.3, max 36.8 | 1-minute load average sampled each minute from 27 samples: median 26.3, max 36.8 |

## Rebase of `native/ghidra-opt-sleigh.patch` and `native/romwright_*.hh` onto master

The patch was rebased by a three-way merge: base = the 12.1.3 `cpp` tree, ours = base + `native/ghidra-opt-sleigh.patch` (the snapshot behind `ghidra_opt` sha256 `dbd7e74b`, md5 `765c93cc`), theirs = upstream master `918d44e`. Upstream changed 119 decompiler C++ files; the patch touches 35 files, 33 of them among those. Three hunks conflicted textually; four more sites stopped compiling and two broke the worker's wire without any textual conflict. The rebased patch is 36 files (`marshal.cc` is new) and keeps every hook. Its text is in `benchmarks/reports/ghidra_master_trial/ghidra-opt-sleigh.master.patch`.

### Textual conflicts (git three-way merge of the patch onto master)

| file | upstream commit | what collided | resolution | behaviour |
|---|---|---|---|---|
| context.hh | 5328fa2c6 GP-6554 Refactor ConstructState allocation in ParserContext | The patch bounded ParserWalker at Ghidra's depth 64 (breadcrumb[65]), threw when the fixed 75-state array ran out, and resized each ConstructState's operand vector (PowerPC lmw/stmw name up to 32 registers, one nested sub-constructor each). Upstream made `state` a growable vector of pointers and the per-state operand array a fixed `MAX_OPERAND`=20, depth `MAX_DEPTH`=32. | Took upstream's allocation and re-expressed the two bounds as its constants: `MAX_DEPTH`=65 (throws at depth 64, as Ghidra's ParserWalker.java and the old patch) and `MAX_OPERAND`=64. Upstream's own limits (depth 32, 20 operands) would reject Gekko lmw/stmw by construction (not run without the raise). | Equivalent for every valid instruction; a runaway walk now ends at the depth bound instead of the state bound. |
| fspec.cc | bb33bad19 GP-7136, 092f8b573 GP-7272 (rework of FuncProto::updateInputTypes) | The patch added an input-register float override inside `updateInputTypes`, next to the persist/findDisjointCover branch and the `isMark` de-duplication. Upstream moved both into ActionInputPrototype (the types arrive as `typeList`, trials are already disjoint) and left one path. | Re-applied the override after `pieces.type = typeList[slot-1]`: an unknown/int/uint 4- or 8-byte parameter whose address lies in a float-class entry of the model becomes float. | Now also applies to persist (global) trials; those do not live in float registers, so no observable difference is expected. |
| ghidra_process.cc | da5c0f2f3 GP-7010 (Funcdata::encode gained `saveOverrides`) | `fd->encode(encoder,0,sendSyntaxTree)` inside the patch's `RomwrightNoReturnHint` scope. | Kept the hint scope and the call to `romwrightEncodeCallPrototypes`; passed `false` for `saveOverrides` as upstream's own caller does. | Identical (12.1.3 had no override export). |

### Hunks that merged cleanly but no longer compiled or no longer matched the wire

| where | upstream commit | break | fix |
|---|---|---|---|
| variable.cc (HighVariable::encode, a Romwright symbol export) | 6740b8992 GP-7063 | `SymbolEntry` is now an abstract base; `getAddr()` lives on `MapEntry`. | Export the address only for `isMapEntry()` entries (a dynamic or unassigned entry had an invalid address before, and nothing was written). |
| romwright_printir.hh `partialLeaf` | 6740b8992 GP-7063 | Same `SymbolEntry::getAddr`; also PrintC::pushPartialSymbol now takes the byte order from `vn->getHigh()->getNameRepresentative()->getSpace()`. | Mirror upstream's source of the space so the IR carries the endianness PrintC uses. |
| romwright_printir.hh `node` | fefe791da GP-7115 | `BlockIf` no longer has `getGotoType/getGotoTarget` (they moved to `BlockIfGoto`); `t_ifelse`, `t_ifnoexit`, `t_ifgoto` were added to `FlowBlock::block_type` and shifted `t_whiledo`..`t_infloop` by 3, and the IR writes the numeric type. | `wireKind()` maps master's enum back to the 12.1.3 numbering the Rust decoder (`printc/ir.rs kind::`) fixes: if/ifelse/ifgoto are kind 8, loops and switch shift back. `t_ifnoexit` has no wire kind (PrintC prints `if (c) { A } B`, no else): it is exported as the list it prints as (an if without else, then B). Without that the Rust printer printed an `else` upstream does not (103 of 1,520 differential functions); with it all 1,520 print the same text as PrintC. |
| romwright_ir.hh (structured document) | da5c0f2f3 GP-7010 | `Funcdata::encode(encoder,id,saveTree)` became `encode(encoder,id,saveTree,saveOverrides)`. | Pass `false`. |
| wire: packed data-type metatype | 747d581b1 GP-7253 (with 5540df9d8) | Master reads and writes `ATTRIB_METATYPE` of a packed `<type>` as a signed integer (`readDatatypeMeta`/`writeDatatypeMeta`); 12.1.3 and the Rust worker (`wire.rs`, `provider.rs`) use the metatype's name. Every decompile died with `Marshaling error: Expecting signed integer attribute`. | Compat hunk in marshal.cc (below). |
| wire: warnings | 05c8a9c31 GP-6985 | 12.1.3 collected warnings in `ArchitectureGhidra::warnings` and returned them in the 0x10..0x11 result frame; master writes each as it occurs in a new 0x12..0x13 packet and returns only the error in the frame. The worker (`provider.rs run_command`) accepts nothing else mid-command: `unexpected burst 0x12`. | Compat hunk in ghidra_arch/ghidra_process (below). |

### Hooks added so the unchanged Rust keeps working (compat)

| hook | upstream commit | why | what it does |
|---|---|---|---|
| marshal.cc: PackedDecode::readDatatypeMeta / PackedEncode::writeDatatypeMeta | 747d581b1 GP-7253 | The worker's type elements carry the metatype as a string, and the Rust code is unchanged in both arms. | Reads and writes the metatype's name (`string2metatype`, `metatype2string`) as 12.1.3 did. A re-pin that wants upstream's form changes `wire.rs`, `provider.rs` and every Rust reader of `<type>` instead. |
| ghidra_arch.hh/.cc, ghidra_process.cc: warnings | 05c8a9c31 GP-6985 | As above, for the 0x12 packet. | `printWarning` appends to `warnings` (cleared by `loadParameters`); `GhidraCommand::sendResult` writes the warnings and then the error text in the result frame, which is what 12.1.3's `printMessage` produced. |

Not carried over by the trial: the in-flight edits to `native/ghidra-opt-sleigh.patch` and `native/romwright_*.hh` of 2026-10-11 20:18-20:31 EDT (RustStructure: `romwright_structure.hh`, `romwright_bytes.hh`, hooks in `blockaction.cc`, `ghidra_process.cc`). A dry-run merge of that newer patch onto master gives four conflicts instead of three: the same three plus `blockaction.cc`, where upstream's `ActionStructureTransform::apply` (`finalTransform(data, allowOpMoves)`, GP-6788) and `ActionPreferComplement::apply` (`graph.hasFinalTransform()`, GP-6788) sit on the lines the patch's `romwrightNativeStructure()` / `romwrightStructureMode()` guards use. Languages: upstream changed none of MIPS, R5900, ARM, AArch64-for-us, Gekko or the vendored console languages except PowerPC `ppc_isa.sinc` (the `dcbz` user op was renamed `DataCaseBlockSetToZero` -> `DataCacheBlockSetToZero`; the vendored Gekko language does not include it). The `.sla` format version is 4 on both sides, so the trial reuses the 12.1.3 install's compiled `.sla` files for every language.

## Console-research wave (each arm imports and decompiles on its own)

Each arm imports the image and decompiles its own sample (`benchmarks/console_research.py --corpus-wave`, `-n 200`, seeds 1 and 2, default configuration; `baseline-off` and `--stock` not run: stock Ghidra does not touch the decompiler under test, its prior-wave numbers are in the last column; the sample is smaller than the 500 per seed of the published wave and the reference configuration was dropped for time). Same `romwright-cli`/`worker` binaries in both arms. Nintendo 64 is the row GP-7310 breaks; the line under the table is the same wave with master minus that added check.

| game | functions found | recall | precision | decompile success | gotos | labels | irregular fns | printed lines | stock Ghidra 12.1.3 recall / precision (prior wave, same either arm) |
|---|---|---|---|---|---|---|---|---|---|
| gba-kh-chain-of-memories | 5225 | 0.9582 | 0.964 | 1.0 | 26 | 13 | 353 | 17467 -> 17458 | - |
| gc-pikmin-2 | 24991 | 0.9998 | 0.9984 | 1.0 | 25 -> 30 | 10 -> 14 | 263 | 13765 -> 13776 | - |
| n64-super-mario-64 | 3888 | 0.9974 | 0.9053 | 1.0 -> 0.3282 | 7 -> 3 | 4 -> 2 | 271 -> 86 | 10433 -> 2605 | - |
| nds-kh-358-2-days | 20753 | 0.8863 | 0.9922 | 1.0 | 8 | 3 | 348 | 16263 -> 16209 | - |
| ps2-dark-chronicle | 7856 | 0.9987 | 0.9963 | 1.0 | 15 -> 16 | 8 -> 9 | 262 -> 260 | 18350 -> 17934 | 0.9288 / 0.9982 |
| ps2-dark-cloud | 4215 | 0.9988 | 0.9907 | 1.0 | 97 -> 87 | 30 | 277 | 21916 -> 20821 | 0.9173 / 0.985 |
| ps2-digital-devil-saga | 10334 | 0.9974 | 0.9991 | 1.0 | 27 -> 29 | 11 -> 12 | 250 | 15599 -> 15613 | 0.863 / 1.0 |
| ps2-fatal-frame | 4235 | 0.9958 | 0.9993 | 1.0 | 108 -> 86 | 34 -> 35 | 273 -> 274 | 25902 -> 25812 | 0.8334 / 1.0 |
| ps2-god-hand | 11270 | 0.9976 | 0.9943 | 1.0 | 71 -> 72 | 40 -> 42 | 290 | 18113 -> 18118 | 0.8552 / 0.9988 |
| ps2-persona-4 | 13134 | 0.9992 | 0.9967 | 1.0 | 26 | 14 | 276 | 16320 -> 16308 | 0.9028 / 0.9997 |
| ps2-ratchet-clank | 1698 | 0.9281 | 0.9965 | 0.9974 | 61 | 30 | 255 -> 253 | 23314 -> 23037 | 0.7175 / 1.0 |
| ps2-ratchet-clank-pal | 1699 | 0.9276 | 0.9947 | 0.9973 | 51 | 27 | 246 -> 245 | 23375 -> 23114 | 0.7184 / 1.0 |
| all but n64-super-mario-64 | 105410 | identical in every game | identical in every game | 4304 decompiled of 4306 | 515 -> 492 | 220 -> 229 | 3093 -> 3089 | 210384 -> 208200 | - |

`n64-super-mario-64` with master and the check GP-7310 added to `Varnode::setDef` removed (the commit's other changes stay): decompile success 1.0 (390/390), gotos 7, labels 4, irregular functions 272, printed lines 10453, recall 0.9974, precision 0.9053 (base: 1.0, 7, 4, 271, 10433).

### Import switch stage

| game | VSA resolved | VSA refused | decompiler skipped | import seconds (load unrecorded) |
|---|---|---|---|---|
| gba-kh-chain-of-memories | 2 | 86 | 0 | 12.5 -> 14.2 |
| gc-pikmin-2 | 6 | 5 | 0 | 21.6 -> 38.2 |
| n64-super-mario-64 | 0 | 6 | 0 | 10.8 -> 18.6 |
| nds-kh-358-2-days | 3 | 327 | 0 | 42.8 -> 70.0 |
| ps2-dark-chronicle | 6 | 40 | 0 | 54.1 -> 33.5 |
| ps2-dark-cloud | 0 | 7 | 0 | 21.3 -> 15.3 |
| ps2-digital-devil-saga | 0 | 50 | 0 | 32.8 -> 57.8 |
| ps2-fatal-frame | 5 | 25 | 0 | 22.9 -> 39.6 |
| ps2-god-hand | 7 | 125 -> 126 | 0 | 45.4 -> 151.7 |
| ps2-persona-4 | 4 | 48 | 0 | 60.8 -> 69.4 |
| ps2-ratchet-clank | 0 | 16 | 0 | 78.6 -> 42.0 |
| ps2-ratchet-clank-pal | 0 | 15 | 0 | 92.0 -> 42.2 |

### Stored switch tables per arm (COMPUTED_JUMP edges the import stored)

| game | tables | edges | only in base | only in master | same branch, other targets |
|---|---|---|---|---|---|
| gba-kh-chain-of-memories | 368 | 3327 | 0 | 0 | 0 |
| gc-pikmin-2 | 161 | 1890 | 0 | 0 | 0 |
| n64-super-mario-64 | 145 -> 142 | 1202 -> 1179 | 3 | 0 | 0 |
| nds-kh-358-2-days | 988 | 11335 | 0 | 0 | 0 |
| ps2-dark-chronicle | 127 | 1057 | 0 | 0 | 0 |
| ps2-dark-cloud | 80 | 626 | 0 | 0 | 0 |
| ps2-digital-devil-saga | 315 | 2168 | 0 | 0 | 0 |
| ps2-fatal-frame | 278 | 2286 | 0 | 0 | 0 |
| ps2-god-hand | 992 | 7902 -> 7901 | 0 | 0 | 1 |
| ps2-persona-4 | 346 | 2809 | 0 | 0 | 0 |
| ps2-ratchet-clank | 41 | 326 | 0 | 0 | 0 |
| ps2-ratchet-clank-pal | 41 | 332 | 0 | 0 | 0 |

## PS2 decompile success on the wave samples (same projects, both decompilers)

The two arms ran at the same time (3 jobs each), so the wall seconds are paired under one load; one `export-c` process per function.

| game | sampled | base decompiled | master decompiled | base failure classes | master failure classes | wall seconds base / master |
|---|---|---|---|---|---|---|
| ps2-dark-chronicle | 969 | 969 (1.0) | 969 (1.0) | - | - | 713.2 / 716.2 |
| ps2-dark-cloud | 937 | 936 (0.9989) | 936 (0.9989) | {"native runtime: native runtime: execution deadline exceeded": 1} | {"native runtime: native runtime: execution deadline exceeded": 1} | 357.1 / 356.9 |
| ps2-digital-devil-saga | 977 | 977 (1.0) | 977 (1.0) | - | - | 629.8 / 620.6 |
| ps2-fatal-frame | 942 | 942 (1.0) | 942 (1.0) | - | - | 329.1 / 332.4 |
| ps2-god-hand | 980 | 980 (1.0) | 980 (1.0) | - | - | 706.3 / 701.3 |
| ps2-persona-4 | 975 | 974 (0.999) | 974 (0.999) | {"native runtime: native runtime: execution deadline exceeded": 1} | {"native runtime: native runtime: execution deadline exceeded": 1} | 631.0 / 636.1 |
| ps2-ratchet-clank | 861 | 859 (0.9977) | 859 (0.9977) | {"native runtime: native runtime: execution deadline exceeded": 1, "native runtime: worker failed (exit status: N): error: decompiler exception: Low-level Error: Backward normalization not": 1} | {"native runtime: native runtime: execution deadline exceeded": 1, "native runtime: worker failed (exit status: N): error: decompiler exception: Low-level Error: Backward normalization not": 1} | 196.5 / 195.5 |
| ps2-ratchet-clank-pal | 859 | 858 (0.9988) | 858 (0.9988) | {"native runtime: worker failed (exit status: N): error: decompiler exception: Low-level Error: Backward normalization not": 1} | {"native runtime: worker failed (exit status: N): error: decompiler exception: Low-level Error: Backward normalization not": 1} | 298.0 / 294.3 |
| all | 7500 | 7495 | 7495 |  |  | 3861.0 / 3853.3 |

## m21-001 real images (function recovery; the import's switch stage runs the decompiler)

| image | base | master | recall | precision | seconds (load unrecorded) |
|---|---|---|---|---|---|
| gba-pokeemerald | pass | pass | 0.9761 | 0.9972 | 63.0 -> 71.9 |
| nds-pokeheartgold-arm9 | pass | pass | 0.9735 | 0.9984 | 145.2 -> 118.1 |
| ps2-capcom-fighting-evolution | fail | fail | 0.9652 | 0.9954 | 288.6 -> 199.3 |
| ps2-dungeon-game | pass | pass | 0.9885 | 0.9835 | 4.9 -> 3.8 |
| psx-darkstalkers-3 | pass | pass | 0.9866 | 0.366 | 7.9 -> 5.6 |
| psv-need-for-speed-most-wanted | pass | pass | 0.9734 | 0.9719 | 305.0 -> 244.5 |
| x360-black-ops-2 | pass | pass | 0.9833 -> 0.9823 | 0.9964 | 97.1 -> 104.8 |

Overall: base fail, master fail.

## m22-002 compiled C against the retail bytes (romwright layer only; Persona 4, 200 functions per lane)

Same Rust, same imported ELF per arm, the harness's own sample (`--layers romwright`, context variant is the headline; m2c and stock are unchanged by the decompiler and were not run). Differences below one function are within the noise of a 200-function sample; the per-function pairing is the better read.

| lane | variant | compiled | exact | mean percent | percent >= 90 |
|---|---|---|---|---|---|
| MWCC seed 20261010 | context | 193 -> 194 | 55 -> 56 | 76.976 -> 77.943 | 91 -> 92 |
| MWCC seed 20261010 | standalone | 148 -> 149 | 42 -> 43 | 56.976 -> 57.91 | 63 -> 64 |
| MWCC seed 20261010 | paired (context percent) | master better 9 | worse 2 | same 189 |  |
| MWCC seed 20261011 | context | 194 -> 195 | 57 -> 58 | 78.321 -> 78.929 | 95 -> 94 |
| MWCC seed 20261011 | standalone | 148 | 38 -> 39 | 56.463 -> 56.861 | 64 |
| MWCC seed 20261011 | paired (context percent) | master better 4 | worse 7 | same 189 |  |
| ee-gcc 2.96, seed 20261010 | context | 197 | 106 -> 99 | 86.406 -> 84.665 | 126 -> 119 |
| ee-gcc 2.96, seed 20261010 | standalone | 182 | 100 -> 94 | 79.649 -> 78.195 | 119 -> 113 |
| ee-gcc 2.96, seed 20261010 | paired (context percent) | master better 4 | worse 10 | same 186 |  |

## Function-level output diff (same project, both decompilers)

2043 functions. Identical text: 1643. Changed: 400 (better 64, worse 167, neutral 169). Printed by base / master: 2042 / 1909. Timeouts base / master: 0 / 0.

| game | functions | identical | changed | better | worse | neutral | printed base / master | median seconds base / master | median paired ratio |
|---|---|---|---|---|---|---|---|---|---|
| gba-kh-chain-of-memories | 200 | 190 | 10 | 1 | 3 | 6 | 200 / 200 | 5.205 / 5.181 | 0.994 |
| gc-pikmin-2 | 200 | 189 | 11 | 0 | 0 | 11 | 200 / 200 | 4.098 / 4.13 | 0.99 |
| n64-super-mario-64 | 200 | 61 | 139 | 0 | 134 | 5 | 200 / 67 | 1.281 / 1.283 | 1.01 |
| nds-kh-358-2-days | 38 | 30 | 8 | 2 | 0 | 6 | 38 / 38 | 4.846 / 5.021 | 1.008 |
| ps2-dark-chronicle | 179 | 159 | 20 | 9 | 2 | 9 | 179 / 179 | 1.493 / 1.484 | 1.02 |
| ps2-dark-cloud | 175 | 133 | 42 | 19 | 6 | 17 | 175 / 175 | 0.773 / 0.778 | 0.992 |
| ps2-digital-devil-saga | 169 | 152 | 17 | 2 | 1 | 14 | 169 / 169 | 1.529 / 1.489 | 0.99 |
| ps2-fatal-frame | 175 | 132 | 43 | 10 | 13 | 20 | 175 / 175 | 1.057 / 1.039 | 0.99 |
| ps2-god-hand | 172 | 158 | 14 | 1 | 2 | 11 | 172 / 172 | 2.205 / 2.21 | 1.012 |
| ps2-persona-4 | 177 | 156 | 21 | 1 | 1 | 19 | 177 / 177 | 2.256 / 2.246 | 0.989 |
| ps2-ratchet-clank | 179 | 146 | 33 | 9 | 2 | 22 | 179 / 179 | 0.626 / 0.633 | 0.983 |
| ps2-ratchet-clank-pal | 179 | 137 | 42 | 10 | 3 | 29 | 178 / 178 | 0.631 / 0.657 | 1.032 |

Reasons behind the verdicts (a function can carry several):

| verdict:metric | functions |
|---|---|
| better:address_literals | 3 |
| better:casts | 58 |
| better:gotos_labels | 4 |
| better:irregular | 1 |
| neutral:address_literals | 2 |
| neutral:casts | 2 |
| worse:address_literals | 4 |
| worse:casts | 29 |
| worse:gotos_labels | 2 |
| worse:irregular | 2 |
| worse:master | 133 |

Paired timing: 1909 pairs, median master/base ratio 0.997, master slower in 950 pairs; host load1 median 32.47, max 56.06. one process per function and arm; the arm order alternates; seconds include process start, project open and the decompile.

Nintendo 64 against master with GP-7310's added check removed: 200 functions, identical 182, changed 18 (better 1, worse 1, neutral 16), printed base / master 200 / 200.

## Printer differential (Rust printer from the exported IR against each decompiler's own PrintC)

The Rust printer prints from an IR the patch exports after PrintC; `benchmarks/printer_diff.py` compares its output with the same decompiler's PrintC markup byte for byte. It is the check that the rebased export is faithful. Base: 1,800 of 1,800 identical. Master: every difference is `markup-only` (the DecompDoc tokens, i.e. the printed text, are equal; block ids differ because upstream's `BlockIfNoExit` is exported as the list it prints as) and the 80 x360 functions GP-7310 fails are decompile errors, not differences. Before the `ifnoexit` export was fixed the same run had 103 `text` differences (an `else` upstream does not print).

| image | base identical | master identical | base differences | master differences | master decompile errors |
|---|---|---|---|---|---|
| gba-pokeemerald | 200/200 | 196/200 | {} | {"markup-only": 4} | 0 |
| gc-animal-crossing | 200/200 | 185/200 | {} | {"markup-only": 15} | 0 |
| nds-pokeheartgold-arm9 | 200/200 | 163/200 | {} | {"markup-only": 37} | 0 |
| ps2-capcom-fighting-evolution | 200/200 | 185/200 | {} | {"markup-only": 15} | 0 |
| ps2-dungeon-game | 200/200 | 195/200 | {} | {"markup-only": 5} | 0 |
| psv-need-for-speed-most-wanted | 200/200 | 192/200 | {} | {"markup-only": 8} | 0 |
| psx-darkstalkers-3 | 200/200 | 199/200 | {} | {"markup-only": 1} | 0 |
| x360-black-ops-2 | 200/200 | 102/120 | {} | {"markup-only": 18} | 80 |
| x86-libc | 200/200 | 109/200 | {} | {"markup-only": 91} | 0 |

## Attribution: master minus one commit group, on the changed functions

261 changed functions that both arms printed. `restores` = the variant prints the 12.1.3 text (that group alone explains the change); `moves` = the variant prints something else than master (the group contributes); `none` = the group is not involved. 4 functions are restored by no single group.

| group | reverted commits | restores 12.1.3 text | moves the text | not involved | failed |
|---|---|---|---|---|---|
| jtnz | GP-7003 64606271a (non-zero mask off) | 0 | 4 | 257 | 0 |
| cp7003 | GP-7003 only, on 12.1.3 + patch | 257 | 4 | 0 | 0 |
| no7310 | GP-7310 bc858e1ec reverted | 0 | 0 | 261 | 0 |
| rules | GP-7353, 7346, 7309, 7280, 7272, 7227, 7210, 7126, 7058 reverted (not 7310, not 7166) | 1 | 1 | 259 | 0 |
| thunk | GP-6946 ff4f0ed1f reverted | 0 | 0 | 261 | 0 |
| nosym7038 | GP-7038 7f538e0af off (toggle) | 0 | 0 | 261 | 0 |
| nonear7080 | GP-7080 792e529e7 off (toggle) | 2 | 3 | 256 | 0 |
| nobaddata6945 | GP-6945 d424b6ff9 off (default) | 0 | 0 | 261 | 0 |
| noexitpref | GP-7115 fefe791da, `BlockIfNoExit::preferComplement` (toggle) | 3 | 7 | 251 | 0 |
| noexitrule | GP-7115 fefe791da, `ruleBlockIfNoExit` branch for two exit-less arms (toggle) | 44 | 13 | 204 | 0 |
| nocopyimm | GP-6788 4661fc0be, `BlockBasic::hasNoImmediateCopy` (toggle) | 44 | 24 | 193 | 0 |

## Individual findings

### GP-7310 fails every constant load on images with a read-only region

The trial's single regression class. `Varnode::setDef` (master) throws `Assignment to constant at <addr>` for any definition of a constant Varnode, and `VarnodeBank::createDef` reaches it; 12.1.3 checked only in `VarnodeBank::setDef`. The worker sets `readonly on` for every program and the provider flags each image's read-only ranges; a load from a constant address in one is folded to its value (inferred path: `ActionDeadCode` -> `Funcdata::fillinReadOnly`), and on those functions master throws. The failing instructions seen: `lwz r30,0x9c8(r11)`, `lwz r9,-0x37d0(r11)`, `lfs f0,0xca4(r10)` (Xbox 360), constant-address `lw` in the Mario 64 ROM. Measured: N64 262 of 390 sampled functions fail (all of them `Assignment to constant`), x360 80 of 200; both are restored 262/262 and 80/80 by the build with the added check removed (`no7310`), and the printed text of the rest of N64 is within 18 functions of 12.1.3. The import's switch stage hits it too: N64 stores 142 tables instead of 145, x360 recall 0.9833 -> 0.9823 with one `partial` switch-stage diagnostic. PS2, GC, GBA and NDS images were not affected (no read-only loads resolved).

### GP-7003: FActExecOccur, and what it does not fix

`FActExecOccur` (Fatal Frame 0x1ca9d8, 2,932 bytes) holds three computed jumps. 12.1.3 recovers the one at 0x1caa54 (33 entries, 5 distinct) and stops: `Could not recover jumptable ... Too many branches`, `Treating indirect jump as call`, 72 printed lines. Master also recovers 0x1caab4 (34 entries, 30 distinct targets in 0x1caabc..0x1cb51c) and 0x1cab80 (10 entries, 3 distinct) and prints the whole function: 507 lines, 70 `case` labels, no jump-table warning. Turning off only the non-zero mask in `JumpBasic::getInitialRange` (`jtnz`) gives 12.1.3's single table (33 entries) again; adding only GP-7003 to 12.1.3 (`cp7003`) gives master's 507. The import does not see it: the stored tables of Fatal Frame are identical in both arms because the import's switch stage only asks the decompiler about branches discovery has marked; the decompile run finds the others itself, so the gain appears in the printed C, not in recall or precision. God Hand `cIDManager_getLocalFileName` (0x2acfa8, `jr` at 0x2ad018) and `func_0039A140`: no table from 12.1.3, master, `jtnz` or `cp7003`; the model recovery fails in all four. The cost: God Hand's table at 0x274828 (function 0x2744e0) has six targets in 12.1.3 (0x274830, 848, 860, 878, 890 and the default 0x274c80) and five in master, `cp7003` and every variant that keeps GP-7003 (0x274890 is missing, though it continues the table's 0x18 stride): the import stores 7,901 edges instead of 7,902. Cause (follow-up, `gp7003_cherrypick.md`): `x % 5` is read as [0,5) although the retail guard is `sltiu a0,6`, the table has six words and the decomp source has cases 0 to 5, so six is right; turning off the non-zero mask (`jtnz`), the exact INT_AND bound (`jtand`) or the range preference (`jtpref`) did not restore it, only dropping the REM bound did. A silently missing case is a worse failure than a visible `Could not recover jumptable`, and the same commit loses 20 whole tables elsewhere; both are corrected in `gp7003-12.1.3.cpfix.patch`. `SetRoomDirecPazzEne`: both recover its 7 targets (the stored project already had them).

### GP-7115 changes the arm order and loses ee-gcc matches

`ruleBlockIfNoExit` gained a branch for a decision whose two out-edges both lead to exit-less blocks (both return): upstream builds a `BlockIfNoExit` and prints the returning arm first, no `else`. ee-gcc 2.96 (the CRI middleware, 568 of the 592 matched functions of the lane) emits the error return out of line, so 12.1.3's `if (x != 0) { error; return -3; } work;` matched and master's `if (x == 0) { work; return; } error; return -3;` does not: ADXF_ReadNw 100 -> 42.67, SFD_SetSpeed 100 -> 0. Disabling that one branch (`noexitrule`) restores 9 of the 14 changed ee-gcc functions; disabling only the new `BlockIfNoExit::preferComplement` (`noexitpref`) restores none. The MWCC lanes are untouched by it (0 of 11 restored). The same arm swap is the commonest neutral change in the function diff (`!= 1 return 0` first became `== 1 return x` first).

### GP-6788 and GP-7115 account for most of the text that moves

Re-decompiling the 261 changed non-N64 functions with one commit's effect switched off: the new `ruleBlockIfNoExit` branch of GP-7115 restores 44 (and changes 13 more); GP-6788's block-removal protection for a block with an immediate COPY (`hasNoImmediateCopy`) restores 44 (and changes 24 more); the arm-preference of `BlockIfNoExit` restores 3; GP-7080's nearby-symbol search 2; the rules group 1 (God Hand 0x33a730); GP-7003 changes 4 (and restores none); GP-7038, GP-6946, GP-6945 and GP-7310 change none of them. Four functions are explained by no single switch. GP-6788 is the source of the MWCC gains in m22 (6 of 11 changed functions per seed), e.g. `func_001056e0` 40 -> 100: the base keeps a `temp_v0` copy across the branch (`temp_v0 = param_2; if (param_1 != 1) { ...; temp_v0 = DAT_007973cc[0]; } DAT_007973cc[0] = temp_v0;`) where master writes `if (param_1 == 1) DAT_007973cc[0] = param_2; else *(short *)(...) = param_2;`.

### Wire and protocol changes the unchanged worker cannot read

Both were found by the first smoke test, not by the compiler. GP-7253 (`747d581b1`): `ATTRIB_METATYPE` of a packed `<type>` is a signed integer in master, a name in 12.1.3 and in `wire.rs`/`provider.rs`: every decompile died with `Marshaling error: Expecting signed integer attribute`. GP-6985 (`05c8a9c31`): each warning is a burst `0x12 ... 0x13` mid-command in master; the worker accepts only the response frame and fails with `unexpected burst 0x12`. The trial restores both on the C++ side (marshal.cc, ghidra_arch/ghidra_process: 36 patch files, +807/-80 lines against master). A re-pin that wants upstream's forms changes `wire.rs`, `provider.rs` and the readers of `<type>` instead; the new elements `calldest`, `baddatacount`, `sharestack` and attributes `backfill`, `minelements`, `maxelements` are additive.

### GP-6945: the bad-data limit defaults to 4

`max_baddata = 4`: the fifth undecodable instruction in a function throws `Bad instruction count exceeded` instead of becoming a `halt_baddata`. 12.1.3 had no limit. No sampled function reaches it (no output of either arm carries a bad-data message; the `nobaddata6945` build prints the same text as master on all 261 changed functions), so it is a source-level risk for code with data in it (literal pools, VU0 macro words), unmeasured here. The `baddatacount` option (empty = no limit) restores 12.1.3.

### Address-as-number printing and symbol references

GP-7038/7080/7063 change which symbols a constant resolves to. In the paired diff the visible effects are: `&LAB_002ab080` printed as `(char *)&DAT_002ab080` (the label and the data symbol at one address are no longer both created), the warning `Globals starting with '_' overlap smaller symbols` gone, and a Romwright storage-view union for `DAT_01c752c0` replaced by two plain globals. GP-7080 alone (`nonear7080`) restores 1 function of the m22 lanes; GP-7038 (`nosym7038`) none. The printed-text measure counts raw 6-or-more-digit hex constants: base 0 net change in most games (see the reasons table), so the claimed gain from named references is small on these images; GP-7063 could not be isolated (reverting it does not build).

### The hooks behave the same

Counting hook-specific text over the 1,842 non-N64 functions both arms print (`work/export/c`): `Switch table taken from the stored dispatch table` 3 / 3, `Treating indirect jump as return` (the nonreturn and PowerPC return hooks) 175 / 175, `Treating indirect jump as call` 3 / 3, `Could not recover jumptable` 3 / 3, `/* irregular` markers 1,301 / 1,301, `Removing unreachable block` 208 / 208, `switch(` statements 81 / 81. The printer differential is 1,800 / 1,800 identical for base and, for master, every one of the 1,720 decompiled functions has equal tokens. `native/dynamic_hash_test.cc` (legacy and 128-entry collision hashes) passes in the master build (the build script runs it); upstream's change to `dynamic.cc` is GP-2917's `listOps` for the INDIRECT container, which lists the ops at an address from two containers; whether any stored hash moves was not measured. What does move is not a hook: raw gotos 182 -> 152, Romwright storage-view unions for globals 1,796 -> 1,004 (fewer globals need a multi-width view after the symbol changes), piece macros 54 -> 56.

### The in-flight patch

The shared tree's `native/ghidra-opt-sleigh.patch` and `native/romwright_*.hh` changed after this trial's snapshot (RustStructure: `romwright_structure.hh`, `romwright_bytes.hh`, hooks in `blockaction.cc`). A dry-run merge of that newer patch onto master gives four conflicts: the three above plus `blockaction.cc` (`ActionStructureTransform::apply`, `ActionPreferComplement::apply`). Both are the places upstream's GP-6788 added `finalTransform(data, allowOpMoves)` and `hasFinalTransform()`; the Rust structuring that replaces them has to decide the same two questions (does the final transform run, may it move ops).

## Port reference list: upstream commits since 12.1.3 the Rust port should take as its reference

Taken from the 45 non-merge commits that touch `Ghidra/Features/Decompiler/src/decompile/cpp` between `Ghidra_12.1.3_build` and master `918d44e`, read in the diffs, not the titles. Stages follow `docs/ownership.md` (back to front). A commit appears under every stage it changes; mechanical or SLEIGH-compiler-only commits are at the end of the flow list. `12806006b` (custom `printRaw` for ambiguous TypeOps) only changes debug printing and is not needed.

### Structuring and printing (stage 1, in progress)

`printc/collapse.rs` ports `CollapseStructure`/`ActionFinalStructure`; `printc/printer.rs` and `render.rs` port PrintC. These are the commits that change what those two files must reproduce.

| commit | title | why the port needs it |
|---|---|---|
| `fefe791da` | GP-7115 Split out BlockIfElse BlockIfGoto BlockIfNoExit | `BlockIf` becomes if / ifelse / ifnoexit / ifgoto; `ruleBlockIfNoExit` also fires when both out edges of a decision go to exit-less blocks; `BlockIfNoExit::preferComplement` orders the arms by structure depth, then basic-block count, then halt type; blocks gain `structureDepth`, `leafCount`, `getHaltType`; PrintC prints no `else` for ifnoexit; `typeToName` now names ifelse/ifnoexit/ifgoto (the `structure.rs` kind names). |
| `4661fc0be` | GP-6788 Keep track of immediate COPY propagation | `finalTransform(data, allowOpMoves)` with `f_final_transform`; `BlockBasic::finalTransform` normalises a flipped CBRANCH (`opNormalizeFlip`) instead of flipping ops; `ActionPreferComplement` stops after the final transform; `hasNoImmediateCopy` keeps a block whose COPY the merge must put back out of the do-nothing removal in structuring; `flipInPlaceTest` gets `allowOpRemoval`. |
| `9aa2fdaef` | GP-7329 add pushMismatchSymbol to pushAnnotation | A symbol smaller than the annotated range prints through `pushMismatchSymbol` instead of a bogus partial. |
| `6740b8992` | GP-7063 New detection of symbol conflicts (the printc.cc part) | `pushPartialSymbol` takes the byte order from the name representative's space; symbol colour comes from `getSymbolHighlight`. |
| `e37c57f3d` | GP-7251 getCodePoint range check | String literals never read past the buffer; truncated UTF-16/32 prints as before-the-end text instead of garbage. |

### Types and casts

`ActionInferTypes`, `ActionSetCasts`, `typeop.cc`, `type.cc`, pointer and symbol-reference recovery (`ActionConstantPtr`).

| commit | title | why the port needs it |
|---|---|---|
| `7f538e0af` | GP-7038 Do additional symbol reference check if pointer is discovered | `ptrcheck` is replaced by `symcheck_incomplete/complete`: a constant tested too early is re-tested once its type turns out to be a pointer (the offcut case `read_sub(&glob1.d)`; `datatests/offcut.xml`). |
| `792e529e7` | GP-7080 Nearby symbol search | `Scope::findSymbolBefore/After` (8-byte steps) feed `TypePointer`'s arrayed-component search, so an access just before or after a symbol resolves into its array/struct instead of a stack-corner or raw offset (`datatests/stackcorner.xml`). |
| `6740b8992` | GP-7063 New detection of symbol conflicts | `SymbolEntry` is split into `MapEntry`, `MapEntryConflict`, `DynamicEntry`, `UnassignedEntry`; conflicts are decided when a Varnode is mapped (`Funcdata::syncVarnodesWithSymbols`), which changes which symbol a shared address prints as. |
| `f17a0b571` | GP-7167 highPtrPossible in ActionConstantPtr | `highPtrPossible` decides from the space's pointer width (`space.cc`, `address.cc`) which constants `ActionConstantPtr` may treat as pointers; every 32-bit console constant passes through it. |
| `7cfdb5031` | Do not apply rule ptrsubundo for pointers targeting ARM Thumb functions | A PTRSUB into a TYPE_CODE target is kept when the offset is non-negative: Thumb function pointers keep their `+1`, GBA/NDS callbacks print as pointers to the function. |
| `86f4daefc` | Handle TYPE_CODE in isPtrsubMatching | Completes the previous commit for the `TYPE_CODE` metatype case. |
| `9e547d2b5` | GP-5525 More targeted data-type warnings | Changes when the `WARNING: ... data-type` comments appear in the printed text. |
| `e12d821d8` | GP-6492 Adjustments to union scoring | Union resolution scoring (`funcdata.cc` +143, `float.cc`, `unionresolve.cc`) decides which union member a use prints as. |
| `3e6eddca0` | GP-7126 RuleAndStructure | `and(x,#mask)` on a structure-typed value becomes a field extraction (`Datatype::findSmallestContainer`); `RuleDumptyHumpLate` also folds SUBPIECE of SUBPIECE. |
| `5540df9d8, 747d581b1` | Split out type_metatype / GP-7253 Adjustments to Encode Decode | Not decisions, but the Rust data-type model must know the metatype is now a signed integer on the packed wire (the trial reverts that on the wire). |

### Merge (HighVariable, symbol assignment)

`merge.cc`, `variable.cc`, `Funcdata::syncVarnodesWithSymbols`.

| commit | title | why the port needs it |
|---|---|---|
| `6740b8992` | GP-7063 New detection of symbol conflicts | Which Varnodes may share one symbol is decided in `funcdata_varnode.cc` (+92/-70) before merge; the port must agree or the merged names differ. |
| `4661fc0be` | GP-6788 Keep track of immediate COPY propagation | `MULTIEQUAL` inputs remember an immediate COPY (`hasCopyImmed`); `Funcdata::createReplaceVarnode` keeps a replacement in its HighVariable when blocks are removed; merge puts the COPY back. |
| `e12d821d8` | GP-6492 Adjustments to union scoring | `merge.cc` (3 lines) and `variable.cc` change with the union scoring. |
| `bb33bad19` | GP-7136 join_per_primitive padding and shared stack | `merge.cc` and `variable.cc` change in the same commit as the join-address work (the diff was not read line by line); the port's merge must agree with heritage on how a join is split and rejoined. |

### Rules (ruleaction.cc, subflow, transform, prefersplit)

Every rule or transform whose result or failure mode changed.

| commit | title | why the port needs it |
|---|---|---|
| `bc858e1ec` | GP-7310 Prevent all assignments to a constant | `Varnode::setDef` (and so `VarnodeBank::createDef`) throws `Assignment to constant` for any op whose output is in the constant space; 12.1.3 only checked in `VarnodeBank::setDef`. The Xenon language produced such ops: 80 of 200 sampled x360 functions fail. The port must either throw the same error (it is a language defect to fix) or tolerate it deliberately. |
| `0b0a8ac0a` | GP-7346 Preserve least significant offset in createReplacement | Piece replacement transfers Varnode properties with the least-significant offset, not the endian-adjusted one: wrong properties on big-endian targets (GameCube, N64, Xbox 360) before. |
| `54ffbc94c` | GP-7353 Check for size consistency in RuleSignForm | RuleSignForm no longer fires when the extended source is not the output's size. |
| `f5dd65d18` | GP-7309 Reinsert collapsed MULTIEQUAL | `ActionStackPtrFlow::analyzeExtraPop` re-inserts a MULTIEQUAL at the block start after rewriting its inputs (op order was broken). |
| `4df2c14ac` | GP-7280 Check for non-zero bits outside terminal variable | `SubvariableFlow` terminal patches require the non-zero mask to fit; `RuleSubvarCompZero` uses `popcount(wholemask) >= 8` instead of two byte tests. |
| `8cb5167ad` | GP-7227 Check for output descendants when splitting read COPY | `PreferSplitManager` (prefersplit.cc +236/-130) no longer splits a COPY whose output has other descendants. |
| `8492bf14b` | GP-7210 Check for negative shift amount to leftshift | Division-by-multiplication recognition (`RuleDivOpt`, `RuleDivTermAdd*`) uses unsigned shift amounts and rejects n > 127. |
| `3e6eddca0` | GP-7126 RuleAndStructure | New cleanup rule, see types. |
| `b1cb6573b` | GP-7058 Fix COPY path | `ConditionalExecution::resolveIblockRead` returns the COPY's input when its definition is not in the block. |
| `6732a6ad6` | GP-7166 More efficient versions of RulePropagateCopy and RuleIndirectCollapse | Same results, much less scanning (`funcdata_op.cc` +165); port the new traversal, not the old one, or the port is the slow part. |
| `590c94926` | GP-2917 Move INDIRECTs into separate container | INDIRECT ops live in their own list; actions that iterate ops (bitfield, constseq, double precision, comment, dynamic hash) changed their loops; `DynamicHash` lists the ops of both containers (`listOps`). |

### Heritage

`heritage.cc`, SSA construction, join and input handling.

| commit | title | why the port needs it |
|---|---|---|
| `bb33bad19` | GP-7136 join_per_primitive padding and shared stack | `splitJoinWrite` and `ActionReturnRecovery::buildReturnOutput` handle a join of N pieces (a 64-bit value in two 32-bit registers, a double in a register pair) with `joinPieces`; constants are no longer split; `ProtoParameter::hasStorage` guards every parameter loop. Directly relevant to o32/GC doubles and `long long`. |
| `092f8b573` | GP-7272 Adjust writemask on input Varnodes. Add check for unlocked trials | `markRangeHeritaged` replaces `setWriteMask` on inputs; `placeMultiequals`/`rename` are skipped when there is nothing disjoint; locked varargs prototypes keep their unlocked trials (`collectUnlockedTrials`): matters for every library `printf`-style prototype Romwright asserts. |
| `590c94926` | GP-2917 Move INDIRECTs into separate container | INDIRECT ops (created by heritage's call guards) now live in their own container; the actions that iterate ops changed their loops (bitfield, constseq, double precision, comment, dynamic hash). |
| `f17a0b571` | GP-7167 highPtrPossible in ActionConstantPtr | One line in heritage beside the main change (the pointer-range test). |

### Flow (flow.cc, jump tables)

What the decompiler's own `FlowInfo` and `jumptable.cc` do; the import walk is already Rust.

| commit | title | why the port needs it |
|---|---|---|
| `d424b6ff9` | GP-6945 Count bad data exceptions | `max_baddata` defaults to 4: the fifth undecodable instruction in a function throws `Bad instruction count exceeded` instead of getting a `halt_baddata` per site (12.1.3 had no limit). Console code can carry data in code. The option `baddatacount` (empty = unlimited) restores 12.1.3; the port must pick the limit on purpose. |
| `48f4c0b04` | GP-6957 Relative branch to next instruction is more flexible | A relative p-code branch past the instruction's last op is a branch to the next instruction (`PcodeOpBank::findLastOp`) rather than only one op past the previous seqnum: SLEIGH `goto inst_next`-style forms. |
| `da5c0f2f3` | GP-7010 Add support for CALLOTHER -> CALL overrides | A CALLOTHER (syscall, `swi`) can be overridden into a CALL with a destination (`<calldest>` replaces `<indirectoverride>`, `Override::insertDestinationOverride`); would let the Rust layer name syscall stubs instead of printing a userop. |
| `64606271a` | GP-7003 Use non-zero mask in jumptable recovery | `JumpBasic::getInitialRange` starts from the non-zero mask (and INT_REM/INT_SREM constants) instead of only a top-level INT_AND: switches with no guard whose index is masked or taken modulo are recovered (`datatests/switchmask.xml`); `findSmallestNormal` compares against the previous model's range. |
| `ff4f0ed1f` | GP-6946 Refactor JumpTable thunk check | A single-entry table is a thunk only when the function is just branches (`JumpTable::isThunk`); 12.1.3 called any single-target jump more than 0xffff away a thunk and threw `Likely thunk`. |
| `376ac1a0a, e5ee5ed77, 5328fa2c6, 827ebe6a0, 031cdcaa4, e465f9b3d` | GP-6995, 6545, 6554, 6608, 7155, 6967 (SLEIGH) | Not decompiler stages: decode checks, a deque for PcodeCacher, the ParserContext state refactor, integer parsing and `optimizeGather` size in the SLEIGH compiler. `kuna-sleigh` (the Rust SLEIGH) should take GP-6995 (bad symbol id, invalid space element) and GP-6554 (state growth, depth bound) as its reference. |

## Recommendation

**Do not re-pin now. Cherry-pick GP-7003 with its two corrections; take the rest as the Rust port's reference; re-run this trial on the 12.2 release.**

1. *Re-pin to master now: no.* Measured against the pin it is worse on two console images (N64 decompile success 1.000 -> 0.328, x360 40% of a sample failing: GP-7310), worse on one compiled-output lane (ee-gcc −7 exact: GP-7115), neutral-to-slightly-better elsewhere (MWCC +1 exact per seed, gotos −4.5% on the unaffected wave samples), and it needs a rebased patch with two wire compat hunks. Master is also a moving target: no 12.2 tag exists, the branch reports 12.3, and the GP-7310 defect is in the tip.
2. *Cherry-pick into the patch: GP-7003 with the two corrections, `gp7003-12.1.3.cpfix.patch`.* The original `gp7003-12.1.3.patch` (6 files, fuzz 2) reproduces master's recovery of Fatal Frame `FActExecOccur`'s two missed tables (72 -> 507 printed lines) and leaves the m22 functions as they were, but loses jump tables 12.1.3 recovers (God Hand 0x274828 6 -> 5 targets, 20 whole tables in seven games); the corrected patch loses none, gains 4 and is measured in `gp7003_cherrypick.md`. It needs no Rust change and no wire change. Not worth taking: GP-6946 (the thunk test) and GP-6945 (the bad-data limit) change none of the 261 changed functions when reverted; GP-7010 and GP-6957 were not isolated.
3. *Wait for a release: yes, for everything else.* When 12.2 is tagged re-run `benchmarks/ghidra_master_trial.py` (sample, export, classify, report) with the new tag as the master arm; adopt it only if GP-7310 is fixed upstream (or the check is moved back in the patch, one line), the arm-order change in GP-7115 has a switch or is accepted for ee-gcc code, and the two wire changes are taken into `wire.rs`/`provider.rs` rather than reverted in C++.
4. *The Rust port should take master, not 12.1.3, as its reference for the stages in the list below.* It is cheaper to port GP-7115/GP-6788 (structuring) and GP-7136/GP-7272 (heritage and call arguments) once, from the newer source, than to port 12.1.3 and port the delta later; the trial's evidence that the delta matters is the ee-gcc lane, Fatal Frame and the two N64/x360 failures.

## Limits

- One snapshot of the shared tree (2026-10-11 23:50 UTC) for the Rust and the patch; edits that landed later (RustStructure's structuring hooks, other agents' Rust changes) are not in either arm.
- The trial shares one host with other agents; the load was 11-56 (median 26-33) while it ran, so seconds are indicative only. The paired timing reads: median master/base ratio about 1.0, master slower in about half the pairs; neither decompiler is measurably faster.
- The wave uses 200 functions per seed instead of 500 and no `baseline-off` or `--stock` run; stock Ghidra is untouched by the trial and its prior-wave numbers are shown for reference.
- The verdict classes (better/worse/neutral) are a measure of printed text (gotos, irregular markers, casts, raw address constants), not of correctness; the compiled lanes of m22-002 are the correctness evidence and cover 200 functions per lane.
- NDS contributes 38 paired functions: the overlay modules of a wave image are projects of their own that the report does not record, so only the main module is paired.
- The variants isolate a commit only where a source toggle or a clean revert exists: GP-7115 (the new branch and the arm preference), GP-7003, GP-7310, GP-7038, GP-7080, GP-6945 and the rules group were isolated; GP-6788 (its block-removal protection), GP-7063, GP-7136, GP-2917, GP-7166, GP-7167, GP-6957, GP-7010 and the types group do not revert cleanly or have no clean toggle and are attributed by reading the diffs only (GP-6788's other half, the boolean-flip normalisation, was not toggled).
- The `ifnoexit` export builds a list node the C++ block tree does not have; the printed text is checked against PrintC (all 1,720 decompiled functions have equal tokens) but block ids in the markup differ.
- The Hex-Rays and stock figures of earlier waves are not part of this trial.
