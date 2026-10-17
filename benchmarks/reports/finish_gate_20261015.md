# Finish gate (20261015)

One integrated gate of the finished tree on one build: every lane, success run, import comparison, per-platform project smoke and the desktop gate, each number set next to the value the last agent reported. **Against the latest defaults (PcUpgrade's console readings and PC table, MemoryFix's m21-001, SymbolLayout's PS2 success, PcImport's PC import) every number is equal**: dc 42 / 197 / 73.877, dds 61 / 200 / 77.402, m22-002 MWCC 20261010 56 / 196 / 78.031, the six m22-004 fixtures cell for cell, m21-001 field for field, PS2 decompile success 7,448 of 7,500, the eight PC import rows score field for field. Against SymbolLayout's table (which predates two PcUpgrade rules) six console lanes read slightly higher, never lower (D1, D2): no lane lost an exact or a compiled function. Every project smoke rebuilds the retail image byte for byte (sha1 equal) or, for the PE and the scaffold, reports per function (D3, D4 and D5 explain where a number differs from an earlier document). The desktop gate passes with the numbers ReleaseReady recorded.

## Build and tree

* Tree frozen 2026-10-15 14:07:14 to 14:07:30 UTC: one `rsync -a --delete --exclude target --exclude .cargo/config.toml --exclude 'project.sqlite*' --exclude native/build` of the laptop tree to `nih-vps-u:~/runs/FinalGate2/ventris` (manifest sha1 `c0d31114200b12debd7428095f38d8fc19963032` over every non-`target` file), `native/build/ghidra_opt` copied from the laptop (sha256 `4532792d...`, unchanged since SymbolLayout). Never synced again.
* Built once, 14:07:58 to 14:13:46 UTC (5 min 48 s): `cargo build --release -p romwright-cli -p romwright-api -p romwright-worker -p romwright-desktop -j8`, rustc 1.98.1, `CARGO_PROFILE_RELEASE_LTO=false CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16` (the allowed gate profile; the tree's release profile is `lto = "fat"`, `codegen-units = 1`). sha256: `romwright-cli` `a820e725...`, `romwright-worker` `71ef64db...`, `romwright-api` `7ba0b41d...`, `romwright-desktop` `2c3416c4...`. The lanes, imports and smokes ran on copies of these binaries; `tests/m6-007` repackaged from the same `target/` and cargo recompiled nothing (the four hashes are unchanged after the gate).
* Hosts: `nih-vps-u` (8 vCPU, 31 GB, load 5 to 32 from other agents: no wall time in this report is a measurement) for everything except the two 32-bit compilers; `smt-cloud` for `match` with `ee-gcc` (PS2) and `psp-gcc` (PSP): a `bwrap` sandbox that maps the paths the binary was built against, the same three binaries, a full copy of the host's Ghidra 12.1.3 (with the `r5900` extension) and the frozen tree's `native/`, `oracle/` and `third_party/ghidra`. `fates-vps` was not used.
* Every import is fresh (`ROMWRIGHT_NO_IMPORT_CACHE=1 ROMWRIGHT_NO_FACT_PACK=1`); an m22-003 lane restores a pristine snapshot of its prepared work directory and repository at the same path before each run (the prepare records absolute paths); `gh` runs on the harness's own clone (no `--repo`); the m22-002 lanes and m21-001 go through a wrapper binary (the harness drops `ROMWRIGHT_*`). The scripts are `~/runs/FinalGate2/*.sh` on the host (Stage4Types' per-arm scripts with the paths changed).

## 1. Console C-output lanes (exact / compiled / mean objdiff %)

Fresh import and fresh work directory per lane, `ROMWRIGHT_NO_IMPORT_CACHE=1 ROMWRIGHT_NO_FACT_PACK=1`, wrapper binary (the m22-002 harness drops `ROMWRIGHT_*`), one build. Expected: SymbolLayout's table (`symbol_layout_20261015.md`, default arm) and PcUpgrade's console readings (`pc_upgrade_20261015.md`).

| gate | got | SymbolLayout | PcUpgrade | got - SymbolLayout | verdict |
|---|---|---|---|---|---|
| m22-002 MWCC 20261010 | 56 / 196 / 78.031 | 55 / 196 / 77.638 | 56 / 196 / 78.031 | +1 / +0 / +0.393 | deviation D1; = PcUpgrade |
| m22-002 MWCC 20261011 | 57 / 195 / 78.712 | 57 / 195 / 78.712 | - | +0 / +0 / +0.000 | = SymbolLayout |
| m22-002 ee-gcc | 106 / 197 / 86.622 | 106 / 197 / 86.622 | - | +0 / +0 / +0.000 | = SymbolLayout |
| m22-003 dds | 61 / 200 / 77.402 | 61 / 200 / 77.402 | 61 / 200 / 77.402 | +0 / +0 / +0.000 | = SymbolLayout |
| m22-003 rc | 26 / 200 / 68.327 | 26 / 200 / 68.327 | - | +0 / +0 / +0.000 | = SymbolLayout |
| m22-003 p4 | 60 / 199 / 81.202 | 60 / 199 / 80.85 | - | +0 / +0 / +0.352 | deviation D1 |
| m22-003 gh (harness clone) | 78 / 199 / 82.129 | 78 / 199 / 82.119 | - | +0 / +0 / +0.010 | deviation D2 |
| m22-003 ff | 22 / 199 / 63.373 | 22 / 199 / 63.148 | - | +0 / +0 / +0.225 | deviation D1 |
| m22-003 dc | 42 / 197 / 73.877 | 41 / 197 / 73.562 | 42 / 197 / 73.877 | +1 / +0 / +0.315 | deviation D1; = PcUpgrade |
| m22-003 dk | 29 / 197 / 78.223 | 29 / 197 / 78.194 | - | +0 / +0 / +0.029 | deviation D1 |

Functions that differ from SymbolLayout's default arm (per-function reports of the same lanes, same samples):

| gate | function | SymbolLayout (compiled, exact, %) | got |
|---|---|---|---|
| m22-002 MWCC 20261010 | `btlUnitCreateMoveToUnitPacket` (160 B) | True, False, 21.5 | True, True, 100.0 |
| m22-003 p4 | `func_002b6c30` (292 B) | True, False, 66.712 | True, False, 91.37 |
| m22-003 p4 | `func_002b8200` (108 B) | True, False, 0.0 | True, False, 45.852 |
| m22-003 gh (harness clone) | `Quaternion_SetVectorRotation` (296 B) | True, False, 20.541 | True, False, 22.392 |
| m22-003 ff | `SettleGhostBattleSet` (208 B) | True, False, 13.25 | True, False, 58.25 |
| m22-003 dc | `SetBSphere__8mgCFrameFPff` (68 B) | True, False, 84.706 | True, True, 100.0 |
| m22-003 dc | `SetAttrParamObjAlpha__8mgCFrameFfi` (108 B) | True, False, 57.0 | True, False, 82.778 |
| m22-003 dc | `EntryDamage2__12CActionCharaFP8mgCFrameP8mgCFramePcfPcffPc` (352 B) | True, False, 56.295 | True, False, 78.17 |
| m22-003 dk | `Set__14CWeaponElementFPA4_fPffif` (244 B) | True, False, 46.951 | True, False, 52.689 |

## 2. m22-004 PC lanes (exact / compiled / mean objdiff %, 200 functions, seed 20261015)

| fixture | got | PcUpgrade default | equal | import s |
|---|---|---|---|---|
| pc-glquake-msvc42 | 50 / 191 / 72.535 (73 at >= 90%) | 50 / 191 / 72.535 (73) | yes | 8.8 |
| pc-quake2-msvc8 | 38 / 196 / 67.99 (65 at >= 90%) | 38 / 196 / 67.99 (65) | yes | 12.1 |
| pc-ioq3-ded-mingw32 | 22 / 181 / 41.968 (29 at >= 90%) | 22 / 181 / 41.968 (29) | yes | 18.3 |
| pc-doomgeneric-mingw32 | 35 / 176 / 47.829 (43 at >= 90%) | 35 / 176 / 47.829 (43) | yes | 13.0 |
| pc-quake2-game-msvc8 | 35 / 195 / 63.132 (43 at >= 90%) | 35 / 195 / 63.132 (43) | yes | 5.9 |
| pc-quake2-refgl-msvc8 | 94 / 197 / 73.786 (100 at >= 90%) | 94 / 197 / 73.786 (100) | yes | 6.3 |

## 3. m21-001, PS2 decompile success, PC import against stock

**m21-001** `pass` (7 images; MemoryFix: pass); every scalar field of every row equal to the MemoryFix run: **True**.

| image | truth | found | recall | precision | invented | recall (MemoryFix) | precision (MemoryFix) |
|---|---|---|---|---|---|---|---|
| gba-pokeemerald | 15856 | 15520 | 0.9761 | 0.9972 | 43 | 0.9761 | 0.9972 |
| nds-pokeheartgold-arm9 | 11078 | 10804 | 0.9746 | 0.9994 | 7 | 0.9746 | 0.9994 |
| ps2-capcom-fighting-evolution | 8794 | 8570 | 0.9692 | 0.9945 | 47 | 0.9692 | 0.9945 |
| ps2-dungeon-game | 783 | 786 | 0.9885 | 0.9847 | 12 | 0.9885 | 0.9847 |
| psx-darkstalkers-3 | 818 | 2205 | 0.9878 | 0.3664 | 1397 | 0.9878 | 0.3664 |
| psv-need-for-speed-most-wanted | 26495 | 26535 | 0.9734 | 0.9719 | 746 | 0.9734 | 0.9719 |
| x360-black-ops-2 | 27730 | 27364 | 0.9833 | 0.9964 | 98 | 0.9833 | 0.9964 |

**PS2 decompile success** (`benchmarks/ps2_decompile_success.py`, the 8-image wave sample): 7,448 of 7,500 (expected 7448 / 7500); every game equal to SymbolLayout's default arm: **True**.

| game | decompiled / sampled | SymbolLayout |
|---|---|---|
| ps2-fatal-frame | 942 / 942 | 942 / 942 |
| ps2-ratchet-clank-pal | 858 / 859 | 858 / 859 |
| ps2-god-hand | 980 / 980 | 980 / 980 |
| ps2-digital-devil-saga | 977 / 977 | 977 / 977 |
| ps2-dark-chronicle | 969 / 969 | 969 / 969 |
| ps2-ratchet-clank | 860 / 861 | 860 / 861 |
| ps2-persona-4 | 974 / 975 | 974 / 975 |
| ps2-dark-cloud | 888 / 937 | 888 / 937 |

**PC import against stock Ghidra** (`benchmarks/pc_import.py`, ours fresh, stock cached, 8 fixtures): every score field of every fixture equal to PcImport's recorded run: **True**. Fixtures (of 8) where ours is ahead of stock by >= 0.5 pp (time: by 10%): recall 8, precision 5, verified recall 8, verified precision 5, wall time 8, CPU time 8 (precision ties: no loss on any fixture).

| fixture | truth | ours R / P (verified R / P) | stock R / P (verified R / P) | ours s (cpu) | stock s (cpu) |
|---|---|---|---|---|---|
| pc-doomgeneric-mingw32 | 1077 | 0.9499 / 1.0 (0.9499 / 1.0) | 0.6546 / 1.0 (0.6546 / 1.0) | 7.57 (9.39) | 36.4 (56.0) |
| pc-glquake-msvc42 | 1331 | 0.9662 / 0.9938 (0.9662 / 0.9938) | 0.8174 / 0.9802 (0.8174 / 0.9802) | 6.4 (9.47) | 39.0 (51.3) |
| pc-ioq3-ded-mingw32 | 1887 | 0.9417 / 1.0 (0.9417 / 1.0) | 0.6386 / 1.0 (0.6386 / 1.0) | 15.74 (21.06) | 54.2 (67.1) |
| pc-ioq3-ded-mingw64 | 1963 | 1.0 / 1.0 (1.0 / 1.0) | 0.9282 / 1.0 (0.9282 / 1.0) | 11.15 (18.4) | 51.8 (70.1) |
| pc-quake2-game-msvc8 | 1945 | 0.8463 / 0.9677 (0.8463 / 0.9722) | 0.4931 / 0.9486 (0.4931 / 0.9504) | 5.95 (8.57) | 56.2 (63.3) |
| pc-quake2-game-msvc8-debug | 3393 | 0.8895 / 0.9714 (0.8895 / 0.9751) | 0.7551 / 0.9249 (0.7551 / 0.9273) | 57.14 (65.32) | 68.2 (117.4) |
| pc-quake2-msvc8 | 2094 | 0.8367 / 0.9793 (0.8367 / 0.9793) | 0.6055 / 0.952 (0.6055 / 0.9534) | 9.6 (12.81) | 35.1 (55.7) |
| pc-quake2-refgl-msvc8 | 1517 | 0.7897 / 0.9638 (0.7897 / 0.9646) | 0.4357 / 0.9323 (0.4357 / 0.9323) | 6.36 (8.11) | 45.9 (62.7) |

## 4. new-project, configure, build and `match` per platform (real images)

Fresh import per project (`ROMWRIGHT_NO_IMPORT_CACHE=1 ROMWRIGHT_NO_FACT_PACK=1`), `configure.py` fetching the pinned tools, `ninja` (or `build.py` for PE and scaffold), then `match` on three functions (budget 6) where the platform has `match`.

| platform | new-project / configure / build (s) | build result | expected | `match` (default print -> best) |
|---|---|---|---|---|
| PS2 (Digital Devil Saga, SLUS_209.74) | 24.9 / 36.1 / 126.0 | sha1 6d18898e2724bf1d145392766e8ba1e678487419 (equal to expected) | 6d18898e2724bf1d145392766e8ba1e678487419; no earlier number; any result | `0x17b3d8` default 100.000% exact (default 100.000%) 1 decompiles, 1 compiles, 0.9s; `0x21a088` default 100.000% exact (default 100.000%) 1 decompiles, 1 compiles, 0.5s; `0x2a5a00` default 55.636% (default 55.636%) 7 decompiles, 1 compiles, 3.2s |
| GameCube (Pikmin 2 main.dol) | 24.3 / 11.7 / 1.2 | build/PIKMIN2/main.dol: OK (equal to expected) | build/PIKMIN2/main.dol: OK; 0x800c03ec 100%, 0x8006bd04 100%, 0x800c0394 49.250% (NewProjectGC) | `0x800c03ec` default 100.000% exact (default 100.000%) 1 decompiles, 1 compiles, 0.9s; `0x8006bd04` default 100.000% exact (default 100.000%) 1 decompiles, 1 compiles, 1.0s; `0x800c0394` default 49.250% (default 49.250%) 7 decompiles, 1 compiles, 6.6s |
| Wii (Pikmin 2 NPC main.dol) | 51.6 / 34.9 / 3.4 | build/PIKMIN2WII/main.dol: OK (equal to expected) | build/PIKMIN2WII/main.dol: OK; 0x800060b8, 0x80067628, 0x800e8c5c exact (NewProjectGC) | `0x800060b8` default 100.000% exact (default 100.000%) 1 decompiles, 1 compiles, 1.2s; `0x80067628` default 100.000% exact (default 100.000%) 1 decompiles, 1 compiles, 1.1s; `0x800e8c5c` default 100.000% exact (default 100.000%) 1 decompiles, 1 compiles, 1.2s |
| N64 (Super Mario 64 US) | 10.4 / 15.6 / 39.5 | sha1 9bef1128717f958171a4afac3ed78ee2bb4e86ce (equal to expected) | 9bef1128717f958171a4afac3ed78ee2bb4e86ce; no earlier number for these three; any result (NewProjectMips: 8-40 byte 13 of 24, 48-160 byte 0 of 30) | `0x80284cfc` default 62.333% (default 62.333%) 7 decompiles, 1 compiles, 1.6s; `0x802a10f0` default 46.474% (default 46.474%) 7 decompiles, 1 compiles, 1.6s; `0x802ee9cc` default 34.773% (default 34.773%) 7 decompiles, 1 compiles, 1.9s |
| PSX (Silent Hill SLUS_007.07) | 0.9 / 2.4 / 5.0 | sha1 f38344565fb731befc52fd968eb5a667be37acf3 (equal to expected) | f38344565fb731befc52fd968eb5a667be37acf3; no earlier number for these three; any result (NewProjectMips: 7 exact of 40, mean 73.2) | `0x80012e1c` default 71.273% (default 71.273%) 7 decompiles, 1 compiles, 0.7s; `0x80013efc` default 91.667% (default 91.667%) 7 decompiles, 2 compiles, 1.0s; `0x80018784` default 91.667% (default 91.667%) 7 decompiles, 1 compiles, 0.7s |
| PSP (psp-melodie EBOOT.BIN, a PRX) | 4.5 / 11.8 / 42.8 | sha1 724fe026421bfc1f881924d657099b07def869cb (equal to expected) | 724fe026421bfc1f881924d657099b07def869cb; no earlier number for these three; any result (NewProjectMips: small functions 4 exact of 24, 81.2) | `0x28990` default 64.200% (default 64.200%) 7 decompiles, 1 compiles, 2.4s; `0x92540` default 0.000% (default 0.000%) 7 decompiles, 1 compiles, 2.5s; `0xbd21c` default 99.429% (default 99.429%) 7 decompiles, 1 compiles, 2.4s |
| GBA (Fire Emblem: The Sacred Stones) | 17.2 / 23.8 / 164.2 | sha1 c25b145e37456171ada4b0d440bf88a19f4d509f (equal to expected) | c25b145e37456171ada4b0d440bf88a19f4d509f; 0x080a6f0c exact (docs/new-project.md example; NewProjectArm: 7 exact of 16) | `0x080a6f0c` default 100.000% exact (default 100.000%) 1 decompiles, 1 compiles, 0.8s |
| NDS (The World Ends With You) | 20.1 / 3.4 / 2.9 | sha1 23e87b1e72aab7f9b718f83e92fd1c3039f23675 (equal to expected) | 23e87b1e72aab7f9b718f83e92fd1c3039f23675; no earlier number for these three; any result (NewProjectArm: 14 ARM + 1 Thumb of 28-100 bytes) | `0x02018edc` default 100.000% exact (default 100.000%) 1 decompiles, 1 compiles, 0.8s; `0x02027564` default 80.000% (default 80.000%) 7 decompiles, 2 compiles, 3.2s; `0x020391d4` default 68.909% (default 68.909%) 7 decompiles, 1 compiles, 3.0s |
| Windows PE (GLQuake, MSVC 4.2) | 362.1 / 5.4 / 823.0 | 243 of 1293 functions match exactly, 1249 compile, 120 at >= 90%, mean 68.416%  | per-function report; six functions 98.5 to 99.7 (83.2 for one) at the default flags (PcProject) | `0x425320` default 99.667% (default 99.667%) 7 decompiles, 2 compiles, 4.8s; `0x4393d0` default 99.643% (default 99.643%) 7 decompiles, 1 compiles, 3.4s; `0x42f840` default 83.214% (default 83.214%) 7 decompiles, 1 compiles, 3.4s |
| scaffold (3DS Fire Emblem Fates `.code`) | 202.0 / - / 207.8 fetch, 0.8 | 37/38 compile (clang 22.1.8), `build.py report`: 36 units, 16.108% (objdiff)  | per-function report; 38 sources, 37/38 compile, 36 objdiff units, 61 calls relocated, 16.1% (NewProjectScaffold) | n/a (`match` refuses a scaffold: `config/project.json names no compiler`) |

GLQuake project, where its numbers come from (D3): functions / compile / exact / at >= 90% / mean objdiff %, `build.py report` over every function of the project

| arm | functions | compile | exact | >= 90% | mean % |
|---|---|---|---|---|---|
| PcProject's own binary (`~/runs/PcProject/target2`, `ghidra_opt` 486ace43): the docs/pc-project.md smoke | 1283 | 1179 | 232 | 98 | 64.501 |
| this build with PcImport's nine PE discovery rules, SymbolLayout's layout rules (`ROMWRIGHT_NATIVE_LAYOUT=1`) and PcUpgrade's eleven switches all off | 1424 | 1267 | 232 | 98 | 58.801 |
| this build, only PcImport's PE discovery rules on | 1293 | 1189 | 231 | 100 | 64.536 |
| this build, only SymbolLayout's layout rules on | 1424 | 1334 | 232 | 103 | 61.008 |
| this build, only PcUpgrade's eleven switches on | 1424 | 1269 | 243 | 114 | 60.142 |
| this build, default (the smoke above) | 1293 | 1249 | 243 | 120 | 68.416 |

## 5. Desktop headless gate

`tests/m6-007_desktop_projects.py` (builds the archive with `packaging/package_desktop.py`, extracts it and drives the extracted `romwright-desktop --gate --project-image`): **PASS** on llvmpipe (LLVM 22.1.8, 256 bits) (Vulkan): packaged romwright-0.5.0-Linux-x86_64.tar.gz on Linux/x86_64 rendering on llvmpipe (LLVM 22.1.8, 256 bits) (Vulkan): Create project wrote 13 files in 303 ms; Match on FUN_00405380 showed 7 variants, 7 compiled, best 1.763% against stock 1.599% The direct `--gate --project-image` run on the build's binary exited 0. Expected (ReleaseReady: Create project 13 files; Match on FUN_00405380 7 variant rows, 7 compiled, best 1.763 % against the stock print's 1.599 %); equal: **True**.

## Deviations, each traced to its change

### D1: five console lanes read higher than SymbolLayout's table: the float-store rule

m22-003 ff 22 / 199 / 63.373 (SymbolLayout 63.148), dk 78.223 (78.194), p4 81.202 (80.85), dc 42 / 197 / 73.877 (41 / 197 / 73.562) and m22-002 MWCC 20261010 56 / 196 / 78.031 (55 / 196 / 77.638): in each lane one to three functions score higher (table above), none lower, and the sums explain the means to the third decimal (each lane's `mean_delta_from_changed_functions`). Cause: `ROMWRIGHT_EXPORT_FLOAT_STORES` (PcUpgrade, `emit_m2c/conform.rs`), which prints a float stored through an integer-typed pointer as `*(float *)&p[i] = x` instead of `p[i] = (float)x`. It was written for Visual C++ (`fstp dword` against `fistp`) but is gated only by the stage-4 switch, not by platform, so it prints the MIPS lane functions that store a float through a `u32 *` as well. Established three ways: (1) SymbolLayout's own final binary (`~/runs/SymbolLayout/bin-f4-def`) on this tree's harness reproduces SymbolLayout's ff and dk lanes exactly (63.148, 78.194), so the harness and the host did not move; (2) the same functions with only `ROMWRIGHT_EXPORT_FLOAT_STORES=off` on this build equal SymbolLayout's rows exactly (`off_arm` in the JSON: ff, dk, p4, dc, every changed function), and the whole m22-002 MWCC 20261010 lane with that one switch off is 55 / 196 / 77.638, SymbolLayout's; (3) for ff, the other twelve PcUpgrade/PcProject switches off one at a time leave the function at its new value (58.25), and old binaries bracket the change (PcProject's 04:29 build 13.25, PcImport's 07:12 build 58.25; the raw `export-c` of the function is byte-identical across eight builds, the difference appears with the lane's asserted prototypes and context). One exact function is gained (dc `SetBSphere__8mgCFrameFPff` 84.706 -> 100, m22-002 `btlUnitCreateMoveToUnitPacket` 21.5 -> 100) and none lost. PcUpgrade's console gate (off equal to default at dc 42 / 197 / 73.877) did not catch the rule because its `off` arm evidently left this switch on [INFERENCE: its arm list is not in its report; the dc value with the switch off is 41 / 197 / 73.562 here]. Not a regression; the rule is neutral-to-better on these lanes. Whether it should be gated to i386 is a decision for the owner of `conform.rs`: it changes five PS2 lanes' numbers.

### D2: m22-003 gh (harness clone) reads 82.129, SymbolLayout 82.119: the sqrt rule

One function, `Quaternion_SetVectorRotation` (296 B), 20.541 -> 22.392 (+1.851 / 200 = +0.009; exact 78 and compiled 199 unchanged). Cause: `ROMWRIGHT_EXPORT_SQRT` (PcUpgrade, `emit_m2c/dependencies.rs`), which prints the p-code `FLOAT_SQRT` as a call of C's `sqrt` instead of an unsupported intrinsic; it was written for the x87 `fsqrt` and is not gated to x86, so MIPS `sqrt.s` is printed as `sqrt` too. Established with 15 single-function arms on the harness clone (this build's default, SymbolLayout's own binary, and each of the thirteen PcProject/PcUpgrade switches off one at a time): only `ROMWRIGHT_EXPORT_SQRT=off` (20.541, SymbolLayout's value) and SymbolLayout's binary (20.541) give the old value; the default, the float-store switch off and the eleven other switches give 22.392. Same caveat as D1: PcUpgrade's console gate did not include gh.

### D3: the GLQuake PE project smoke is better than the numbers in docs/pc-project.md (232 exact, 1,179 compile, mean 64.501)

`docs/pc-project.md` (PcProject, before PcImport, SymbolLayout and PcUpgrade) records for the GLQuake project: 1,284 functions imported, 1,283 decompiled, 5,472 call and 12,227 data relocations, 1,179 of 1,283 compile, 232 match exactly, 98 at >= 90%, mean 64.501%, and `match` at 98.5 to 99.7% on six functions (83.2 for one). This gate: 1,294 imported, 1,293 decompiled (one refusal, `FUN_00445dc3`, a decompiler `Low-level Error`), 5,487 / 12,295 relocations, **1,249 of 1,293 compile, 243 exact, 120 at >= 90%, mean 68.416%**, and `match` on the same three addresses 99.667 / 99.643 / 83.214. PcProject's own binary (`~/runs/PcProject/target2/release`, with its own `ghidra_opt` 486ace43) reproduces the document on this host to the digit (1,284 / 1,283, 5,472 / 12,227, 1,179, 232, 98, 64.501) and gives the same three `match` numbers as this build, so the tool and the host did not drift; the difference is the tree. The table above runs this build with the groups of changes since PcProject off or on one at a time (the other two groups off): the exact count is PcUpgrade's (231 to 232 with all three groups off, with SymbolLayout's alone and with PcImport's alone; 243 with PcUpgrade's eleven switches alone and in the default: +11; the at-least-90% count goes 98 -> 114 with PcUpgrade's alone, 120 with all); the function count and the mean are PcImport's PE discovery rules (nine rules, `compiler_rules/pe.json`): with them off the project has 1,424 functions (1,438 imported) and the mean reads 58.801; with only them on, 1,293 functions (131 fewer: PcImport's report counts the invented rows, 153 before its rules and 8 after) and 64.536; the compile rate is SymbolLayout's (the `stack0x` / partial-member failures: 1,267 -> 1,334 of 1,424 with only the layout rules on, +67) and the dropped rows (89.0% -> 92.0% with PcImport's rules alone); PcUpgrade's switches add 2 on the 1,424-function project (1,269); together 1,249 of 1,293 = 96.6%, from 91.9%. Not isolated [INFERENCE]: the all-off arm of this build is not PcProject's binary (1,267 against 1,179 compile, 1,438 against 1,284 imported): it also contains PcImport's non-rule discovery changes (`pe_roots`, local calls) and `ghidra_opt` 4532792d instead of 486ace43, neither of which has a switch.

### D4: Super Mario 64 repository: 4,525 asm units and 41 binary units, docs/new-project.md says 4,592 / 186

The all-assembly rebuild still hits the retail sha1 (`9bef1128...`). The unit counts differ because the importer found fewer functions: NewProjectMips' binary (`~/runs/NewProjectMips/ventris/target`) and SymbolLayout's binary both give 4,592 / 186 on this host today; the integrated build gives 4,525 / 41. ImportPrecision (finish item 1, after both) added three MIPS rules to `compiler_rules/common.json` (`epilogue-not-entry`, `case-run-in-one-function`, `branch-table-after-dispatch`; the other three of its six existed) and edited `native/discovery.rs`: with those three rules off this build reads 4,537 (`epilogue-not-entry` alone: 12), and with all six off 5,008 (what both older binaries give with their rules off); the other 55 functions and the 145 binary units of the gap are ImportPrecision's `discovery.rs` edits [INFERENCE: not isolated one by one]. ImportPrecision's own report has Super Mario 64's invented entries 368 -> 17 against 3 lost truth rows (`import_precision_20261015_loo.md`). `docs/new-project.md` records the number of the earlier importer.

### D5: `match` of a PS2 repository on nih-vps-u compiles nothing (0.000% in `smoke/ps2-dds.json`)

`ee-gcc` is a 32-bit ELF and nih-vps-u has no `/lib/ld-linux.so.2` (the m22-003 harness runs it through a glibc32 overlay under `bwrap`; `romwright-cli match` does not). Every row of that `match` reads `cannot run .../ee-gcc: No such file or directory`. The valid PS2 `match` is the one on `smt-cloud` (`smoke-smt-cloud/ps2-dds.json`), which has the loader; the repository there is the same (10,348 objects, 10,327 functions, sha1 `6d18898e...` = the retail file's). The nih-vps-u run still gives the PS2 import, configure and `ninja` rows.

## Not in the frozen tree

* ReleaseProfile ran in parallel (STATUS section "Release follow-ups: a shipping build profile, the service's resident set, m6-006") and none of its changes is in the frozen tree or in the binaries measured. An `rsync -ani` of the laptop tree against the host copy at the end of the gate lists exactly its files: `Cargo.toml` (profiles), `Cargo.lock`, `README.md`, `STATUS.md`, `.github/workflows/ci.yml`, `benchmarks/cost.py`, `benchmarks/service_memory.py` and `benchmarks/reports/service_memory_20261015-*`, `crates/romwright-api/{Cargo.toml,src/lib.rs,src/main.rs}`, `crates/romwright-worker-client/{Cargo.toml,src/lib.rs}`, `docs/{desktop,environment,import-speed,pc-project,releasing,third-party}.md`, `packaging/{package_desktop.py,stage_release.py}`, `tests/m7-001_cost_envelope.py`, `tests/m7-002_decompile_envelope.py`, `tests/m7-003_session_envelope.py`. None is in `romwright-core`, the importer, the decompiler or the printer, so no number here depends on it.
* What that means for this gate: (1) the frozen `Cargo.toml` has the profile MemoryFix left (`release` = `lto = "fat"`, `codegen-units = 1`); the gate built it with LTO off and sixteen units, which is what ReleaseProfile's new development `release` profile is (`overflow-checks = true` only), so these binaries are the new `cargo build --release` build, not the shipping `dist` profile (fat LTO, one unit; `dist-service` for the API) that ReleaseProfile's packaging builds; the profiles differ in memory and speed, not in output, and this gate measures only output; (2) `romwright-api` was built from the pre-change source (before the `JobOutput::{Tree, Document}` reply path) and not run; (3) `tests/m6-007` here packaged the frozen `package_desktop.py` (`cargo build --release`, `target/release`), not ReleaseProfile's (`--profile dist`).
* Already in the frozen tree and so measured: MemoryFix (decoder sharing, lazy tables, executor threads, the pattern-scan speed-up), ReleaseFixes, PcUpgrade, SymbolLayout, PcImport, PcProject, ReleaseReady, ImportPrecision, Stage4Types and the new-project slices.

## User-WIP files

This gate edited none of the listed user-WIP files (`crates/romwright-cli/src/main.rs`, `crates/romwright-core/src/{emit_m2c.rs,lib.rs,native.rs,native/elf.rs,native/elf_image.rs,native/tests.rs}`, `crates/romwright-sig/src/object.rs`, `crates/romwright-worker/src/{provider.rs,specs.rs}`, `crates/romwright-core/src/sdk_types/`, `tests/m22-001_c_output.py`) and no source file at all. Added: `benchmarks/finish_gate_report.py` (reads the raw arms, writes the report), `benchmarks/reports/finish_gate_20261015.{json,md}`, `benchmarks/reports/finish_gate_20261015_arms/` (raw lane, import, smoke and bisect reports, `prose.json`); appended: the "Finish gate" section of `STATUS.md`; and the one `finish_gate_20261015.json` row of `README.md`'s evidence index, written by `scripts/gen_evidence_index.py` (the generator rewrites only the index block).

## Limits

* One build with LTO off and sixteen code-generation units (allowed: no behaviour change); the memory envelopes (`m7-001`, `m7-003`) and the unit and doc suites (ReleaseReady, ReleaseFixes, MemoryFix) were not re-run: they measure the release profile or the tree, not these lanes.
* No wall time here is a measurement (load 5 to 32 on `nih-vps-u`); the PC import wall times are ours fresh against stock's cached seconds from PcImport's run.
* The PC import's stock side is PcImport's cached Ghidra 12.1.3 run (`benchmarks/pc_import.py --cache`), not a new stock run; ours is fresh.
* The NDS repository has no `symbols.txt` (dsd's layout), so `match` ran on three ARM9 functions picked by hand from `config/romwright/main.symbols.txt` (quartiles of the 28-100 byte ARM functions at 0x02000000 and above); the other platforms' three functions are picked by script (the 1/4, 2/4, 3/4 points of the 24-96 byte functions of `config/**/symbols.txt`), except Pikmin 2 (GC and Wii) and FE8, whose addresses are the earlier agents' (so the numbers compare), and GLQuake's three addresses (PcProject's smoke list).
* The scaffold is the 3DS Fire Emblem Fates `.code` (`--decompile first:40`; 202 s); the Switch Xenoblade import (2,023 s under load, 420 s unloaded) was not run. `match` does not apply to a scaffold (`config/project.json names no compiler`), so its row has a per-function objdiff report instead of a match.
* Procedure notes: the first `smt-cloud` attempts imported with no Ghidra install visible inside the sandbox, then with a trimmed Ghidra that lacks the `r5900` extension (PS2 imported as plain MIPS, 10,457 functions); both were discarded and rerun with the full install. The PSP repository there has 3,379 objects, the PS2 one the same 10,348 as on `nih-vps-u`. Missing Python dependencies of splat (`n64img`, `crunch64`, `pygfxd`, `pydantic`, ...) were installed into a venv beside the sandbox, not into the repository.

