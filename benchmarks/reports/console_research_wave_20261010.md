# Console research wave (2026-10-10T23:09:41+00:00)

Tools fingerprint `5d47c57fe192c622`; sample n=500 per seed, seeds [1, 2]; combined = the union of the seeds' samples (rows deduplicated). Truth: `<corpus>/<id>/truth/{meta.json,functions.tsv}`. Headline metrics are the frozen ones (recall, precision, success rate, arity, type exact); `recall_verified` / `precision_verified` are the supplement over `verified=1` rows (docs/console-research.md).

## Images

| id | game | version | match | truth | compiler | linked % | truth fns | verified | nested (size 0) | scored modules | unplaced fns | stripped | status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| gba-fire-emblem-sacred-stones | Fire Emblem: The Sacred Stones | USA/AU (BE8E) | True | decomp-build | agbcc (pret/agbcc, -O2 -g) with old_agbcc for src/m4a.c; mgfembp SIO payload built with the tpcs_frame agbcc variant (010110-ThumbPatch) | 99.76 | 8516 | 8279 | 0 (0) | main | 0 | False | ran |
| gba-golden-sun | Golden Sun (The Broken Seal) | USA/Europe English (AGSE) -- alchemy edition tbs-en | True | decomp-build | agscc (GCC 2.96 snapshot 2000-07-31, Thumb, -O2 -mthumb-interwork -fcall-used-r4) for game code; pret agbcc for MusicPlayer2000/flash library; agbcc_arm for RAM ARM code | 89.93 | 11884 | 5758 | 0 (0) | main, ov0, ov1, ov2 (+93) | 0 | False | ran |
| gba-kh-chain-of-memories | Kingdom Hearts: Chain of Memories | USA (B8CE) | True | decomp-build | agbcc (pret/agbcc, -O2) + binutils 2.10 legacy assembler; libgcc/libc members prebuilt | 100.0 | 5257 | 5137 | 0 (0) | main | 0 | False | ran |
| gba-klonoa-empire-of-dreams | Klonoa: Empire of Dreams | USA (AKLE) | True | decomp-build | agbcc (pret/agbcc, -O2) with old_agbcc for m4a.c and eeprom.c; arm-none-eabi binutils | 100.0 | 562 | 464 | 0 (0) | main | 0 | False | ran |
| gba-nascar-heat-2002 | NASCAR Heat 2002 | USA (ANHE) | True | decomp-build | old_agbcc (Dream-Atelier/agbcc submodule a0f70c9, -O2), arm-none-eabi binutils; libgcc/newlib members compiled from tools/agbcc | 100.0 | 1316 | 1023 | 0 (0) | main, gba:ram.02000000, gba:ram.02000b96 | 0 | False | ran |
| gc-mario-party-4 | Mario Party 4 | GMPE01 USA Rev 1 (repo version GMPE01_01) | True | decomp-symbols | MWCC GC/1.3.2 (82.8% of linked code bytes), GC/2.6 (12.5% of linked code bytes), GC/1.2.5n (2.6% of linked code bytes), GC/1.2.5 (1.1% of linked code bytes), GC/1.3 (1.0% of linked code bytes) | 100.0 | 10984 | 10984 | 0 (0) | main, _minigameDll, bootDll, instDll (+90) | 0 | False | ran |
| gc-melee | Super Smash Bros. Melee | GALE01 USA v1.02 (Redump/Vimm Rev 2) | True | decomp-symbols | MWCC GC/1.2.5n (94.7% of linked code bytes), GC/1.2.5 (4.8% of linked code bytes), GC/1.1p1 (0.5% of linked code bytes) | 100.0 | 19827 | 19827 | 0 (0) | main | 0 | False | ran |
| gc-pikmin | Pikmin | GPIE01 USA Rev 1 (repo version GPIE01_01) | True | decomp-symbols | MWCC GC/1.2.5n (90.7% of linked code bytes), GC/1.2.5 (8.5% of linked code bytes), GC/1.1p1 (0.8% of linked code bytes) | 100.0 | 8068 | 8068 | 0 (0) | main | 0 | False | ran |
| gc-pikmin-2 | Pikmin 2 | GPVE01 USA Rev 0 | True | decomp-symbols | MWCC GC/2.6 (95.7% of linked code bytes), GC/1.2.5n (4.3% of linked code bytes) | 98.09 | 24956 | 24625 | 0 (0) | main | 0 | False | ran |
| gc-super-mario-strikers | Super Mario Strikers | G4QE01 USA Rev 0 | True | decomp-symbols | MWCC GC/2.6 (80.3% of linked code bytes), GC/1.3.2 (7.8% of linked code bytes), GC/1.2.5n (6.9% of linked code bytes), GC/2.0 (2.5% of linked code bytes), GC/2.5 (2.3% of linked code bytes), GC/1.3 (0.1% of linked code bytes) | 100.0 | 8604 | 8604 | 0 (0) | main | 0 | False | ran |
| gc-tiger-woods-2004 | Tiger Woods PGA Tour 2004 | GW4E69 USA Rev 0 (main.dol identical on Disc 1 and Disc 2) | True | decomp-symbols | MWCC GC/2.5 (82.2% of linked code bytes), GC/1.2.5n (11.3% of linked code bytes), GC/1.3.2 (2.9% of linked code bytes), ProDG/3.5 (2.5% of linked code bytes), GC/1.3 (1.0% of linked code bytes) | 100.0 | 7647 | 7647 | 0 (0) | main | 0 | False | ran |
| gc-twilight-princess | The Legend of Zelda: Twilight Princess | GZ2E01 USA Rev 0 | True | decomp-symbols | MWCC GC/2.7 (98.3% of linked code bytes), GC/1.2.5n (1.7% of linked code bytes) | 87.12 | 48106 | 43237 | 0 (0) | main, f_pc_profile_lst, d_a_andsw, d_a_bg (+754) | 0 | False | ran |
| gc-wind-waker | The Legend of Zelda: The Wind Waker | GZLE01 USA Rev 0 | True | decomp-symbols | MWCC GC/1.3.2 (96.5% of linked code bytes), GC/1.2.5n (2.8% of linked code bytes), GC/1.3 (0.7% of linked code bytes) | 67.38 | 39315 | 28956 | 0 (0) | main, f_pc_profile_lst, d_a_agbsw0, d_a_andsw0 (+412) | 0 | False | ran |
| n64-banjo-kazooie | Banjo-Kazooie | USA 1.0 (us.v10) | True | decomp-build | IDO 5.3 (decompals/ido-static-recomp v1.2) | 100.0 | 8500 | 8471 | 0 (0) | main | 1636 | False | ran |
| n64-dr-mario-64 | Dr. Mario 64 | USA (VERSION=us) | True | decomp-build | KMC GCC 2.7.2 (tools/gcc_kmc 2.7.2) + egcs 1.1.2-4 for libegcs | 100.0 | 1406 | 1375 | 0 (0) | main | 0 | False | ran |
| n64-majoras-mask | The Legend of Zelda: Majora's Mask | USA N64 1.0 (zeldaret/mm VERSION=n64-us) | True | decomp-build | IDO 7.1 (game code) + IDO 5.3 (libultra, jpeg, osFlash) | 100.0 | 17147 | 17147 | 0 (0) | main | 13062 | False | ran |
| n64-ocarina-of-time | The Legend of Zelda: Ocarina of Time | USA NTSC 1.0 (zeldaret/oot VERSION=ntsc-1.0) | True | decomp-build | IDO 7.1 (game code) + IDO 5.3 (libultra, jpeg, libleo) | 100.0 | 13347 | 13347 | 0 (0) | main | 10252 | False | ran |
| n64-paper-mario | Paper Mario | USA (ver/us) | True | decomp-build | GCC 2.8.1 (pmret/gcc-papermario, 3484 objs) + GCC 2.7.2 (decompals mips-gcc-2.7.2, 111 libultra objs) + IDO 5.3 (1 obj); binutils-papermario/2.6 | 100.0 | 12636 | 12447 | 0 (0) | main | 9823 | False | ran |
| n64-perfect-dark | Perfect Dark | USA NTSC 8.7 final (ROMID=ntsc-final) | True | decomp-build | IDO 5.3 + IDO 7.1 for a subset (build/recomp/{5.3,7.1} from decompals ido-static-recomp v1.1 binaries) | 100.0 | 5658 | 5559 | 0 (0) | main | 0 | False | ran |
| n64-star-fox-64 | Star Fox 64 | USA 1.0 / rev0 (No-Intro "Star Fox 64 (USA)"); repo builds only US rev1 (1.1) | False | decomp-build | IDO 5.3 (decompals ido-static-recomp v1.0) | 100.0 | 2806 | 2806 | 0 (0) | main | 1242 | False | ran |
| n64-super-mario-64 | Super Mario 64 | USA (VERSION=us) | True | decomp-build | IDO 5.3 (ido-static-recomp built from tools/ido-static-recomp) | 100.0 | 3813 | 3806 | 0 (0) | main | 284 | False | ran |
| n64-super-smash-bros | Super Smash Bros. | USA (VERSION=us) | True | decomp-build | IDO 7.1 (decompals/ido-static-recomp v1.1) + IDO 5.3 (libultra); IRIX 4 frontend (ido4.1 accom) for src/ovl8/ovl8_8.c | 100.0 | 7205 | 7187 | 0 (0) | main | 6291 | False | ran |
| nds-dragon-quest-iv | Dragon Quest IV: Chapters of the Chosen | delivered: USA (YIVE); repo targets: EUR | False | decomp-symbols | mwccarm 2.0/sp1p6 package for game code, 2.0/sp1p2 for libraries (tools/configure.py MWCC_VERSION/LIBS_MWCC_VERSION; request list gives banner 3.0 build 131/133), mwldarm | 100.0 | 9521 | 9521 | 0 (0) | main, ov0, ov1, ov2 (+19) | 0 | False | ran |
| nds-kh-358-2-days | Kingdom Hearts 358/2 Days | EU (YKGP) | True | decomp-symbols | mwccarm 3.0 build 139 (a few precompiled-middleware units with an older mwccarm per config/arm9/file_compilers.json), mwldarm | 100.0 | 23233 | 23233 | 0 (0) | main, ov0, ov1, ov2 (+293) | 0 | False | ran |
| nds-kh-recoded | Kingdom Hearts Re:coded | USA (BK9E) revision 0 | True | decomp-symbols | mwccarm 4.0 build 1036 and 3.0 build 139, mwldarm | 67.83 | 10386 | 9573 | 0 (0) | main, ov0, ov1, ov2 (+102) | 0 | False | ran |
| nds-pokemon-platinum | Pokemon Platinum | USA (CPUE) revision 0 (builds with ROM_REVISION=0; repo default is rev 1) | True | decomp-build | mwccarm 2.0/sp2p2 (meson/cross.ini; mwasmarm/mwldarm via metroskrew 0.1.3; NitroSDK 4.2.30001, NitroSystem, NitroDWC, NitroWiFi built from source subprojects) | None | 34671 | 34669 | 0 (0) | main, ov1, ov4, ov5 (+113) | 0 | False | ran |
| nds-world-ends-with-you | The World Ends With You | USA (AWLE) | True | decomp-symbols | mwccarm 2.0/sp1p5 package (tools/configure.py MWCC_DEFAULT_VERSION; request list gives banner 3.0 build 131), 1.2/sp4 for assembly units, mwldarm | 17.43 | 14413 | 2732 | 0 (0) | main, ov0, ov1, ov2 (+40) | 0 | False | ran |
| ps2-dark-chronicle | Dark Chronicle (Dark Cloud 2) | PAL SCES-51190 (En,Fr,De,Es,It) | True | decomp-symbols | MWCC PS2 3.0 (CodeWarrior for PS2, via Satans Fiddle/wibo; repo config compiler: MWCCPS2) | 88.18 | 7837 | 7714 | 0 (0) | main | 0 | True | ran |
| ps2-dark-chronicle-symtab | Dark Chronicle (Dark Cloud 2) | PAL SCES-51190 (En,Fr,De,Es,It) | True | decomp-symbols | MWCC PS2 3.0 (CodeWarrior for PS2, via Satans Fiddle/wibo; repo config compiler: MWCCPS2) | 88.18 | 7837 | 7714 | 0 (0) | main | 0 | debug | ran |
| ps2-dark-cloud | Dark Cloud | USA NTSC SCUS-97111 (v1.02 per repo) | True | decomp-symbols | MWCC PS2 2.3.3 (Metrowerks CodeWarrior for PS2; repo config compiler: MWCCPS2) | 100.0 | 4181 | 4181 | 0 (0) | main, title, dun | 0 | True | ran |
| ps2-dark-cloud-symtab | Dark Cloud | USA NTSC SCUS-97111 (v1.02 per repo) | True | decomp-symbols | MWCC PS2 2.3.3 (Metrowerks CodeWarrior for PS2; repo config compiler: MWCCPS2) | 100.0 | 4181 | 4181 | 0 (0) | main, title, dun | 0 | debug | ran |
| ps2-digital-devil-saga | Shin Megami Tensei: Digital Devil Saga | USA SLUS-20974 | True | decomp-symbols | EE GCC 2.96 (ee-gcc; ee-as 2.9-ee; repo config compiler EEGCC) | 76.02 | 10352 | 9864 | 0 (0) | main | 0 | False | ran |
| ps2-fatal-frame | Fatal Frame (Project Zero) | USA NTSC-U SLUS-20388 | True | decomp-symbols | EE GCC 2.9-991111 (ee-gcc, repo config compiler EEGCC; platform ps2) | 69.84 | 4250 | 3437 | 0 (0) | main | 0 | True | ran |
| ps2-fatal-frame-symtab | Fatal Frame (Project Zero) | USA NTSC-U SLUS-20388 | True | decomp-symbols | EE GCC 2.9-991111 (ee-gcc, repo config compiler EEGCC; platform ps2) | 69.84 | 4250 | 3437 | 0 (0) | main | 0 | debug | ran |
| ps2-god-hand | God Hand | USA NTSC-U SLUS-21503 (disc 1.00) | True | decomp-symbols | SN ProDG ee-gcc 2.95.3 (matched TUs) + EE GCC 2.96 (dvp-as, ee-ld); SN small-data (.sndata) | 43.53 | 10091 | 7946 | 0 (0) | main | 0 | False | ran |
| ps2-persona-4 | Shin Megami Tensei: Persona 4 | USA SLUS-21782 v1.00 | True | decomp-symbols | MWCC PS2 3.0.1 build 210 (-O2) for Atlus code; MWCC build 119 (-O4,p -inline auto) for RenderWare; EE GCC 2.96 (-O2 -G0) for configured CRI/other units | 72.65 | 13102 | 9857 | 0 (0) | main | 0 | False | ran |
| ps2-ratchet-clank | Ratchet & Clank | USA NTSC-U SCUS-97199 | True | decomp-symbols | EE GCC 2.95.2 (ee-gcc, repo config compiler EEGCC; some units use an optional patched EE-GCC profile) | 68.41 | 2460 | 1643 | 0 (0) | main | 0 | False | ran |
| ps2-ratchet-clank-pal | Ratchet & Clank | PAL SCES-50916 v2.00 (En,Fr,De,Es,It) | True | decomp-symbols | SN ProDG 3.01 (ee-gcc 2.95-based) for game code; SCE SDK 2.4 objects (ee29) for SDK code | 61.22 | 1862 | 1607 | 0 (0) | main | 0 | False | ran |
| psp-hot-pixel | Hot Pixel | unspecified (cognac_release.prx) | True | dwarf | GNU C/C++ 3.3.6+allegrex-2.2.2-psp-1.9.2 -g (372 C + 39 C++ CUs; 8 CUs psp-1.12.1.internal) | 100.0 | 9983 | 9983 | 3 (0) | main | 0 | True | ran |
| psp-hot-pixel-symtab | Hot Pixel | unspecified (cognac_release.prx) | True | dwarf | GNU C/C++ 3.3.6+allegrex-2.2.2-psp-1.9.2 -g (372 C + 39 C++ CUs; 8 CUs psp-1.12.1.internal) | 100.0 | 9983 | 9983 | 3 (0) | main | 0 | debug | ran |
| psp-melodie | Melodie | Unreleased, 2005-09-02 | True | dwarf | GNU C 3.3.3+allegrex-2.2.2-psp-1.6.1.internal -g (DW_AT_producer) | 100.0 | 3242 | 3242 | 0 (0) | main | 0 | True | ran |
| psp-melodie-symtab | Melodie | Unreleased, 2005-09-02 | True | dwarf | GNU C 3.3.3+allegrex-2.2.2-psp-1.6.1.internal -g (DW_AT_producer) | 100.0 | 3242 | 3242 | 0 (0) | main | 0 | debug | ran |
| psp-pac-man-rally | Pac-Man Rally | Europe, Beta 2007-05-01 | True | dwarf | GNU C 4.0.3+allegrex-2.2.3-psp-2.4.1.internal -g (DW_AT_producer); also an 'SN Systems 1.1.07' string | 100.0 | 6379 | 6379 | 0 (0) | main | 0 | True | ran |
| psp-pac-man-rally-symtab | Pac-Man Rally | Europe, Beta 2007-05-01 | True | dwarf | GNU C 4.0.3+allegrex-2.2.3-psp-2.4.1.internal -g (DW_AT_producer); also an 'SN Systems 1.1.07' string | 100.0 | 6379 | 6379 | 0 (0) | main | 0 | debug | ran |
| psp-psp-camera-01 | PSP Camera 01 | Japan | True | dwarf | Metrowerks CodeWarrior for PSP, MW MIPS C Compiler 2.4.1.01 (.comment); DWARF 1 in MIPS_DEBUG .debug (10.5 MB) | 100.0 | 6516 | 6516 | 0 (0) | main | 0 | True | ran |
| psp-psp-camera-01-symtab | PSP Camera 01 | Japan | True | dwarf | Metrowerks CodeWarrior for PSP, MW MIPS C Compiler 2.4.1.01 (.comment); DWARF 1 in MIPS_DEBUG .debug (10.5 MB) | 100.0 | 6516 | 6516 | 0 (0) | main | 0 | debug | ran |
| psp-tetris | Tetris | USA, 2009-09-04 build | True | dwarf | Metrowerks CodeWarrior for PSP, MW MIPS C Compiler 2.4.1.01 (.comment); DWARF 1 in MIPS_DEBUG .debug | 100.0 | 8513 | 8513 | 0 (0) | main | 0 | True | ran |
| psp-tetris-symtab | Tetris | USA, 2009-09-04 build | True | dwarf | Metrowerks CodeWarrior for PSP, MW MIPS C Compiler 2.4.1.01 (.comment); DWARF 1 in MIPS_DEBUG .debug | 100.0 | 8513 | 8513 | 0 (0) | main | 0 | debug | ran |
| psx-digimon-world | Digimon World | USA SLUS-01032 | True | decomp-symbols | CodeWarrior for PlayStation R4 (mwccpsx via cc_mips.dll + mwccwrap/wibo, Makefile TOOLCHAIN=mwcc); psyq libs linked from original asm | 100.0 | 3354 | 2741 | 0 (0) | main, btl, dget, doo2 (+12) | 0 | False | ran |
| psx-legend-of-mana | Legend of Mana | USA SLUS-01013 | True | decomp-symbols | Psy-Q GCC 2.7.2-cdk / 2.8.0-psx / 2.6.0-psx / 2.7.2-psx-gnu (old-gcc) + maspsx | 100.0 | 6453 | 5977 | 0 (0) | main, ADDHERO, CARDA, CHECKPS (+14) | 0 | False | ran |
| psx-nfs-high-stakes | Need for Speed: High Stakes (Road Challenge) | USA retail (Redump), boot SLUS_008.26 -> NFS4.EXE + FRONT.BIN overlay | False | decomp-symbols | SN/PsyQ 4.3: cc1 GNU C 2.8.0 + ASPSX 2.77 (repo README/BUILDING.md); some Sony library files gcc 2.7.2 (PsyQ 4.0) | 100.0 | 2686 | 2465 | 0 (0) | main, front | 0 | False | ran |
| psx-parasite-eve | Parasite Eve | USA SLUS-00662 (Disc 1; Disc 2 SLUS-00668 has identical executable sha1) | True | decomp-symbols | GCC 2.7.2 (PSX cc1) + maspsx; Psy-Q 4.0 lib objects | 100.0 | 11741 | 11741 | 0 (0) | main, boot_display, fx_common, fx_field (+186) | 0 | False | ran |
| psx-parasite-eve-2 | Parasite Eve II | USA SLUS-01042 (Disc 1) / SLUS-01055 (Disc 2; byte-identical executable) | True | decomp-symbols | GCC 2.8.1 (PSX cc1) + maspsx; Psy-Q 4.5 lib objects (lib/) | 100.0 | 13300 | 13266 | 0 (0) | main, gameplay, title, acropolis_bridge (+373) | 0 | False | ran |
| psx-rage-racer | Rage Racer | USA SLUS-004.03 | True | decomp-symbols | GCC 2.6.3 (cc1-psx-263) + maspsx, PsyQ libs | 100.0 | 1194 | 1194 | 0 (0) | main | 0 | False | ran |
| psx-silent-hill | Silent Hill | USA 1.1 SLUS-00707 | True | decomp-symbols | GCC 2.7.2-cdk + GCC 2.8.1 (PsyQ) + maspsx | 99.99 | 7042 | 7025 | 0 (0) | main, BODYPROG, MAP0_S00, MAP0_S01 (+46) | 0 | False | ran |
| psx-vagrant-story | Vagrant Story | USA SLUS-01040 | True | decomp-symbols | GCC 2.7.2-psx / 2.7.2-cdk / 2.8.1-psx (old-gcc) + maspsx, Psy-Q libs | 45.03 | 4183 | 3080 | 0 (0) | main, BATTLE.PRG, INITBTL.PRG, EFFPURGE.BIN (+85) | 0 | False | ran |
| wii-mario-strikers-charged | Mario Strikers Charged | R4QE01 USA Rev 1 | True | decomp-symbols | MWCC GC/3.0a5 (78.7% of linked code bytes), GC/3.0a5.2 (20.8% of linked code bytes), GC/2.7 (0.5% of linked code bytes), GC/3.0a3 (0.0% of linked code bytes) | 98.07 | 17688 | 17487 | 0 (0) | main | 0 | False | ran |
| wii-npc-pikmin-2 | New Play Control! Pikmin 2 | R92E01 USA | True | decomp-symbols | MWCC GC/3.0a5.2 (65.2% of linked code bytes), GC/3.0a3p1 (34.7% of linked code bytes), GC/2.7 (0.0% of linked code bytes) | 10.9 | 28115 | 3708 | 0 (0) | main | 0 | False | ran |
| wii-rock-band-3 | Rock Band 3 | SZBE69 USA | True | decomp-symbols | MWCC Wii/1.3 (100.0% of linked code bytes) | 1.1 | 59103 | 389 | 0 (0) | main | 0 | False | ran |
| wii-skyward-sword | The Legend of Zelda: Skyward Sword | SOUE01 USA Rev 0 (NTSC-U 1.0), WBFS from Vimm's Lair | True | decomp-symbols | MWCC Wii/1.5 (79.2% of linked code bytes), Wii/1.3 (13.3% of linked code bytes), Wii/1.6 (7.5% of linked code bytes) | 15.75 | 76970 | 16443 | 0 (0) | main, d_profileNP, d_SoftwareKeyboardNP, d_s_bootNP (+633) | 0 | False | ran |
| wii-super-mario-galaxy | Super Mario Galaxy | RMGE01 USA Rev 0 | True | decomp-symbols | MWCC GC/3.0a3 (95.0% of linked code bytes), GC/3.0a5.2 (3.9% of linked code bytes), GC/2.7 (0.8% of linked code bytes), GC/3.0a3.2 (0.1% of linked code bytes), GC/3.0a5 (0.1% of linked code bytes) | 55.53 | 41993 | 24524 | 0 (0) | main | 0 | False | ran |
| x360-amped-3 | AMPED 3 | 2005-10-15 default build (PyroXenon Release Final Xenon) | True | pdb | Microsoft (R) Optimizing Compiler 14.0.1863 (S_COMPILE3 in PDB); linker 8.0 (pre-release Xenon toolchain) | 100.0 | 36152 | 36152 | 14740 (14740) | main | 0 | False | ran |
| x360-burnout-crash | Burnout Crash | 2011-03-01 Release (CRASH_X360_RELEASE.DLL.XEX) | True | pdb | Microsoft (R) Optimizing Compiler 16.0.11886 (S_COMPILE3); linker 10.0; plus MASM 10.0.11886 | 100.0 | 10961 | 10961 | 20 (20) | main | 0 | False | ran |
| x360-call-of-duty-advanced-warfare | Call of Duty: Advanced Warfare | 2014-09-16 1-s1_sp (single-player) build | True | pdb | Microsoft (R) Optimizing Compiler 16.0.11886 (S_COMPILE3); linker 10.0 | 100.0 | 40276 | 40276 | 837 (837) | main | 0 | False | ran |
| x360-call-of-duty-modern-warfare-2 | Call of Duty: Modern Warfare 2 | 2009-07-13 iw4sp_ship build (default.xex) | True | pdb | Microsoft (R) Optimizing Compiler 15.0.8153 (S_COMPILE3 in PDB); linker 9.0 (PE optional header) | 100.0 | 18576 | 18576 | 0 (0) | main | 0 | False | ran |
| x360-forza-horizon-2-prototype | Forza Horizon 2 (Prototype) | 2014-05-04 default (Release_Final) build | True | pdb | Microsoft (R) Optimizing Compiler 16.0.11886 (S_COMPILE3); linker 10.0 | 100.0 | 81860 | 81860 | 744 (744) | main | 0 | False | ran |

## gba

| game | tool | recall | precision | success | arity | type exact | recall (verified) | precision (verified) | sampled |
|---|---|---|---|---|---|---|---|---|---|
| gba-fire-emblem-sacred-stones | default | 0.9536 | 0.9893 | 1.0000 | 0.9364 | 0.5202 | 0.9580 | 0.9989 | 975 |
| gba-fire-emblem-sacred-stones | baseline-off | 0.9536 | 0.9893 | 1.0000 | 0.9364 | 0.5202 | 0.9580 | 0.9989 | 975 |
| gba-fire-emblem-sacred-stones | stock Ghidra | **stock DNF (>4 h auto-analysis)** | – | – | – | – | – | – | – |
| gba-golden-sun | default | 0.8873 | 0.9766 | 1.0000 | – | – | 0.9043 | 0.9977 | 984 |
| gba-golden-sun | baseline-off | 0.8875 | 0.9766 | 1.0000 | – | – | 0.9043 | 0.9977 | 984 |
| gba-golden-sun | stock Ghidra | 0.6214 | 0.6421 | 1.0000 | – | – | 0.6684 | 0.6932 | 208 |
| gba-golden-sun | default (main module only) | 0.8667 | 0.9781 | 1.0000 | – | – | 0.9435 | 0.9974 | 984 |
| gba-kh-chain-of-memories | default | 0.9582 | 0.9640 | 1.0000 | – | – | 0.9634 | 0.9924 | 961 |
| gba-kh-chain-of-memories | baseline-off | 0.9426 | 0.9634 | 0.9771 | – | – | 0.9474 | 0.9923 | 961 |
| gba-kh-chain-of-memories | stock Ghidra | **stock crashed (StackOverflowError in CreateFunctionCmd / CreateThunkFunctionCmd)** | – | – | – | – | – | – | – |
| gba-klonoa-empire-of-dreams | default | 0.8612 | 0.9254 | 1.0000 | 0.9748 | 0.7239 | 0.9418 | 0.9583 | 484 |
| gba-klonoa-empire-of-dreams | baseline-off | 0.8434 | 0.9240 | 0.9793 | 0.9519 | 0.7104 | 0.9203 | 0.9574 | 484 |
| gba-klonoa-empire-of-dreams | stock Ghidra | 0.6708 | 0.0153 | 0.9979 | 0.9794 | 0.3087 | 0.6961 | 0.4562 | 484 |
| gba-nascar-heat-2002 | default | 0.8009 | 0.9741 | 1.0000 | – | – | 0.8094 | 0.9869 | 769 |
| gba-nascar-heat-2002 | baseline-off | 0.8009 | 0.9741 | 1.0000 | – | – | 0.8094 | 0.9869 | 769 |
| gba-nascar-heat-2002 | stock Ghidra | 0.7244 | 0.0321 | 1.0000 | – | – | 0.7034 | 0.9426 | 518 |
| gba-nascar-heat-2002 | default (main module only) | 0.8151 | 0.9818 | 1.0000 | – | – | 0.8165 | 1.0000 | 769 |

**Sign tests, gba**

| comparison | games | wins | losses | ties | one-sided p |
|---|---|---|---|---|---|
| recall vs baseline-off | 5 | 2 | 0 | 3 | 0.2500 |
| precision vs baseline-off | 5 | 0 | 0 | 5 | – |
| success_rate vs baseline-off | 5 | 2 | 0 | 3 | 0.2500 |
| arity_accuracy vs baseline-off | 2 | 1 | 0 | 1 | 0.5000 |
| type_exact_rate vs baseline-off | 2 | 1 | 0 | 1 | 0.5000 |
| recall_verified vs baseline-off | 5 | 2 | 0 | 3 | 0.2500 |
| precision_verified vs baseline-off | 5 | 0 | 0 | 5 | – |
| recall vs stock | 3 | 3 | 0 | 0 | 0.1250 |
| precision vs stock | 3 | 3 | 0 | 0 | 0.1250 |
| arity_accuracy vs stock | 1 | 0 | 0 | 1 | – |
| type_exact_rate vs stock | 1 | 1 | 0 | 0 | 0.5000 |
| recall_verified vs stock | 3 | 3 | 0 | 0 | 0.1250 |
| precision_verified vs stock | 3 | 3 | 0 | 0 | 0.1250 |

## gc

| game | tool | recall | precision | success | arity | type exact | recall (verified) | precision (verified) | sampled |
|---|---|---|---|---|---|---|---|---|---|
| gc-mario-party-4 | default | 0.9983 | 0.9966 | 1.0000 | – | – | 0.9983 | 0.9970 | 984 |
| gc-mario-party-4 | baseline-off | 0.9983 | 0.9426 | 1.0000 | – | – | 0.9983 | 0.9429 | 984 |
| gc-mario-party-4 | stock Ghidra | 0.9608 | 0.9890 | 1.0000 | – | – | 0.9608 | 0.9890 | 308 |
| gc-mario-party-4 | default (main module only) | 0.9988 | 0.9897 | 1.0000 | – | – | 0.9988 | 0.9908 | 984 |
| gc-melee | default | 0.9997 | 0.9993 | 0.9990 | – | – | 0.9997 | 0.9994 | 988 |
| gc-melee | baseline-off | 0.9997 | 0.9963 | 0.9990 | – | – | 0.9997 | 0.9964 | 988 |
| gc-melee | stock Ghidra | 0.8559 | 0.9992 | 1.0000 | – | – | 0.8559 | 0.9992 | 988 |
| gc-pikmin | default | 0.9993 | 0.9959 | 1.0000 | – | – | 0.9993 | 0.9963 | 965 |
| gc-pikmin | baseline-off | 0.9993 | 0.9943 | 1.0000 | – | – | 0.9993 | 0.9947 | 965 |
| gc-pikmin | stock Ghidra | 0.8168 | 0.9971 | 1.0000 | – | – | 0.8168 | 0.9971 | 965 |
| gc-pikmin-2 | default | 0.9998 | 0.9984 | 0.9990 | – | – | 0.9998 | 0.9985 | 986 |
| gc-pikmin-2 | baseline-off | 0.9998 | 0.9942 | 1.0000 | – | – | 0.9998 | 0.9942 | 986 |
| gc-pikmin-2 | stock Ghidra | 0.7383 | 0.9990 | 1.0000 | – | – | 0.7390 | 0.9990 | 986 |
| gc-super-mario-strikers | default | 0.9993 | 0.9958 | 1.0000 | – | – | 0.9993 | 0.9961 | 971 |
| gc-super-mario-strikers | baseline-off | 0.9993 | 0.9840 | 1.0000 | – | – | 0.9993 | 0.9842 | 971 |
| gc-super-mario-strikers | stock Ghidra | 0.8679 | 0.9955 | 1.0000 | – | – | 0.8679 | 0.9955 | 971 |
| gc-tiger-woods-2004 | default | 0.9993 | 0.9982 | 0.9990 | – | – | 0.9993 | 0.9983 | 961 |
| gc-tiger-woods-2004 | baseline-off | 0.9993 | 0.9734 | 0.9990 | – | – | 0.9993 | 0.9735 | 961 |
| gc-tiger-woods-2004 | stock Ghidra | 0.9245 | 0.9980 | 1.0000 | – | – | 0.9245 | 0.9980 | 961 |
| gc-twilight-princess | default | 0.9999 | 0.9975 | 1.0000 | – | – | 0.9999 | 0.9974 | 997 |
| gc-twilight-princess | baseline-off | 0.9999 | 0.9147 | 1.0000 | – | – | 0.9999 | 0.9094 | 997 |
| gc-twilight-princess | stock Ghidra | 0.8350 | 0.9962 | 1.0000 | – | – | 0.8498 | 0.9953 | 351 |
| gc-twilight-princess | default (main module only) | 0.9998 | 0.9962 | 1.0000 | – | – | 0.9997 | 0.9959 | 997 |
| gc-wind-waker | default | 0.9999 | 0.9979 | 1.0000 | – | – | 1.0000 | 0.9991 | 997 |
| gc-wind-waker | baseline-off | 0.9999 | 0.9292 | 1.0000 | – | – | 1.0000 | 0.9455 | 997 |
| gc-wind-waker | stock Ghidra | 0.8560 | 0.9957 | 1.0000 | – | – | 0.8502 | 0.9989 | 359 |
| gc-wind-waker | default (main module only) | 0.9997 | 0.9962 | 1.0000 | – | – | 0.9999 | 0.9996 | 997 |

**Sign tests, gc**

| comparison | games | wins | losses | ties | one-sided p |
|---|---|---|---|---|---|
| recall vs baseline-off | 8 | 0 | 0 | 8 | – |
| precision vs baseline-off | 8 | 5 | 0 | 3 | 0.0312 |
| success_rate vs baseline-off | 8 | 0 | 0 | 8 | – |
| recall_verified vs baseline-off | 8 | 0 | 0 | 8 | – |
| precision_verified vs baseline-off | 8 | 5 | 0 | 3 | 0.0312 |
| recall vs stock | 8 | 8 | 0 | 0 | 0.0039 |
| precision vs stock | 8 | 0 | 0 | 8 | – |
| recall_verified vs stock | 8 | 8 | 0 | 0 | 0.0039 |
| precision_verified vs stock | 8 | 0 | 0 | 8 | – |

## n64

| game | tool | recall | precision | success | arity | type exact | recall (verified) | precision (verified) | sampled |
|---|---|---|---|---|---|---|---|---|---|
| n64-banjo-kazooie | default | 0.9876 | 0.9982 | 1.0000 | – | – | 0.9876 | 0.9984 | 964 |
| n64-banjo-kazooie | baseline-off | 0.9876 | 0.9982 | 1.0000 | – | – | 0.9876 | 0.9984 | 964 |
| n64-banjo-kazooie | stock Ghidra | 0.0096 | 1.0000 | 1.0000 | – | – | 0.0094 | 1.0000 | 964 |
| n64-dr-mario-64 | default | 0.9374 | 0.9887 | 1.0000 | – | – | 0.9367 | 0.9923 | 813 |
| n64-dr-mario-64 | baseline-off | 0.9374 | 0.9887 | 1.0000 | – | – | 0.9367 | 0.9923 | 813 |
| n64-dr-mario-64 | stock Ghidra | 0.1615 | 0.9784 | 1.0000 | – | – | 0.1498 | 1.0000 | 813 |
| n64-majoras-mask | default | 0.9782 | 0.9980 | 1.0000 | – | – | 0.9782 | 0.9980 | 938 |
| n64-majoras-mask | baseline-off | 0.9763 | 0.9965 | 0.9979 | – | – | 0.9763 | 0.9965 | 938 |
| n64-majoras-mask | stock Ghidra | 0.0859 | 0.9972 | 1.0000 | – | – | 0.0859 | 0.9972 | 938 |
| n64-ocarina-of-time | default | 0.9842 | 0.9977 | 1.0000 | – | – | 0.9842 | 0.9977 | 919 |
| n64-ocarina-of-time | baseline-off | 0.9806 | 0.9977 | 0.9956 | – | – | 0.9806 | 0.9977 | 919 |
| n64-ocarina-of-time | stock Ghidra | 0.0384 | 0.9917 | 1.0000 | – | – | 0.0384 | 0.9917 | 919 |
| n64-paper-mario | default | 0.9701 | 0.9963 | 1.0000 | – | – | 0.9783 | 0.9981 | 910 |
| n64-paper-mario | baseline-off | 0.9282 | 0.9958 | 0.9484 | – | – | 0.9718 | 0.9977 | 910 |
| n64-paper-mario | stock Ghidra | 0.6584 | 0.5786 | 1.0000 | – | – | 0.6632 | 0.5790 | 910 |
| n64-perfect-dark | default | 0.9525 | 0.9901 | 0.9990 | – | – | 0.9534 | 0.9921 | 957 |
| n64-perfect-dark | baseline-off | 0.9521 | 0.9901 | 0.9990 | – | – | 0.9530 | 0.9921 | 957 |
| n64-perfect-dark | stock Ghidra | 0.0002 | 0.5000 | 0.0000 | – | – | 0.0000 | – | 957 |
| n64-super-mario-64 | default | 0.9974 | 0.9053 | 1.0000 | – | – | 0.9974 | 0.9052 | 923 |
| n64-super-mario-64 | baseline-off | 0.9974 | 0.9053 | 1.0000 | – | – | 0.9974 | 0.9052 | 923 |
| n64-super-mario-64 | stock Ghidra | 0.9547 | 0.9997 | 1.0000 | – | – | 0.9554 | 0.9997 | 923 |
| n64-super-smash-bros | default | 0.9551 | 0.9898 | 1.0000 | – | – | 0.9732 | 0.9898 | 717 |
| n64-super-smash-bros | baseline-off | 0.9497 | 0.9897 | 0.9930 | – | – | 0.9676 | 0.9897 | 717 |
| n64-super-smash-bros | stock Ghidra | 0.8709 | 1.0000 | 1.0000 | – | – | 0.8884 | 1.0000 | 717 |

**Sign tests, n64**

| comparison | games | wins | losses | ties | one-sided p |
|---|---|---|---|---|---|
| recall vs baseline-off | 8 | 2 | 0 | 6 | 0.2500 |
| precision vs baseline-off | 8 | 0 | 0 | 8 | – |
| success_rate vs baseline-off | 8 | 2 | 0 | 6 | 0.2500 |
| recall_verified vs baseline-off | 8 | 2 | 0 | 6 | 0.2500 |
| precision_verified vs baseline-off | 8 | 0 | 0 | 8 | – |
| recall vs stock | 8 | 8 | 0 | 0 | 0.0039 |
| precision vs stock | 8 | 4 | 2 | 2 | 0.3438 |
| recall_verified vs stock | 8 | 8 | 0 | 0 | 0.0039 |
| precision_verified vs stock | 7 | 2 | 3 | 2 | 0.8125 |

## nds

| game | tool | recall | precision | success | arity | type exact | recall (verified) | precision (verified) | sampled |
|---|---|---|---|---|---|---|---|---|---|
| nds-kh-358-2-days | default | 0.8863 | 0.9922 | 1.0000 | – | – | 0.8863 | 0.9993 | 987 |
| nds-kh-358-2-days | baseline-off | 0.8758 | 0.9921 | 0.9889 | – | – | 0.8758 | 0.9994 | 987 |
| nds-kh-358-2-days | stock Ghidra | 0.8388 | 0.9497 | 1.0000 | – | – | 0.8388 | 0.9994 | 83 |
| nds-kh-358-2-days | default (main module only) | 0.8662 | 0.9395 | 1.0000 | – | – | 0.8662 | 0.9995 | 987 |
| nds-kh-recoded | default | 0.7803 | 0.9635 | 1.0000 | – | – | 0.7795 | 0.9992 | 970 |
| nds-kh-recoded | baseline-off | 0.7651 | 0.9633 | 0.9825 | – | – | 0.7638 | 0.9990 | 970 |
| nds-kh-recoded | stock Ghidra | 0.8685 | 0.9682 | 1.0000 | – | – | 0.8879 | 1.0000 | 276 |
| nds-kh-recoded | default (main module only) | 0.8977 | 0.9570 | 1.0000 | – | – | 0.9208 | 1.0000 | 970 |
| nds-pokemon-platinum | default | 0.8884 | 0.9977 | 1.0000 | – | – | 0.8884 | 0.9996 | 994 |
| nds-pokemon-platinum | baseline-off | 0.8478 | 0.9975 | 0.9567 | – | – | 0.8478 | 0.9994 | 994 |
| nds-pokemon-platinum | stock Ghidra | 0.8500 | 0.9939 | 1.0000 | – | – | 0.8499 | 0.9996 | 366 |
| nds-pokemon-platinum | default (main module only) | 0.9755 | 0.9943 | 1.0000 | – | – | 0.9755 | 0.9995 | 994 |
| nds-world-ends-with-you | default | 0.8857 | 0.9986 | 1.0000 | – | – | 0.8532 | 1.0000 | 985 |
| nds-world-ends-with-you | baseline-off | 0.8771 | 0.9983 | 0.9838 | – | – | 0.8518 | 0.9991 | 985 |
| nds-world-ends-with-you | stock Ghidra | 0.9068 | 0.9972 | 1.0000 | – | – | 0.8961 | 1.0000 | 200 |
| nds-world-ends-with-you | default (main module only) | 0.9042 | 0.9935 | 1.0000 | – | – | 0.9001 | 1.0000 | 985 |

**Sign tests, nds**

| comparison | games | wins | losses | ties | one-sided p |
|---|---|---|---|---|---|
| recall vs baseline-off | 4 | 4 | 0 | 0 | 0.0625 |
| precision vs baseline-off | 4 | 0 | 0 | 4 | – |
| success_rate vs baseline-off | 4 | 4 | 0 | 0 | 0.0625 |
| recall_verified vs baseline-off | 4 | 3 | 0 | 1 | 0.1250 |
| precision_verified vs baseline-off | 4 | 0 | 0 | 4 | – |
| recall vs stock | 4 | 3 | 0 | 1 | 0.1250 |
| precision vs stock | 4 | 0 | 2 | 2 | 1.0000 |
| recall_verified vs stock | 4 | 3 | 0 | 1 | 0.1250 |
| precision_verified vs stock | 4 | 0 | 0 | 4 | – |

## ps2

| game | tool | recall | precision | success | arity | type exact | recall (verified) | precision (verified) | sampled |
|---|---|---|---|---|---|---|---|---|---|
| ps2-dark-chronicle | default | 0.9844 | 0.9972 | 1.0000 | – | – | 0.9842 | 0.9997 | 965 |
| ps2-dark-chronicle | baseline-off | 0.9843 | 0.9965 | 1.0000 | – | – | 0.9841 | 0.9991 | 965 |
| ps2-dark-chronicle | stock Ghidra | 0.9288 | 0.9982 | 1.0000 | – | – | 0.9278 | 0.9997 | 965 |
| ps2-dark-cloud | default | 0.9840 | 0.9906 | 0.9989 | – | – | 0.9840 | 0.9990 | 934 |
| ps2-dark-cloud | baseline-off | 0.9830 | 0.9930 | 0.9979 | – | – | 0.9830 | 0.9990 | 934 |
| ps2-dark-cloud | stock Ghidra | 0.9173 | 0.9850 | 1.0000 | – | – | 0.9173 | 0.9856 | 884 |
| ps2-dark-cloud | default (main module only) | 0.9835 | 0.9905 | 0.9989 | – | – | 0.9835 | 0.9990 | 934 |
| ps2-digital-devil-saga | default | 0.9854 | 0.9917 | 0.9980 | – | – | 0.9854 | 0.9932 | 978 |
| ps2-digital-devil-saga | baseline-off | 0.9851 | 0.9618 | 0.9980 | – | – | 0.9851 | 0.9678 | 978 |
| ps2-digital-devil-saga | stock Ghidra | 0.8630 | 1.0000 | 0.9990 | – | – | 0.8585 | 1.0000 | 978 |
| ps2-fatal-frame | default | 0.9369 | 0.9893 | 0.9796 | – | – | 0.9412 | 0.9890 | 930 |
| ps2-fatal-frame | baseline-off | 0.9362 | 0.8976 | 0.9785 | – | – | 0.9404 | 0.8835 | 930 |
| ps2-fatal-frame | stock Ghidra | 0.8334 | 1.0000 | 1.0000 | – | – | 0.8484 | 1.0000 | 930 |
| ps2-god-hand | default | 0.9709 | 0.8950 | 0.9990 | – | – | 0.9664 | 0.9938 | 968 |
| ps2-god-hand | baseline-off | 0.9706 | 0.6375 | 0.9990 | – | – | 0.9660 | 0.7708 | 968 |
| ps2-god-hand | stock Ghidra | 0.9117 | 0.9565 | 0.9990 | – | – | 0.8919 | 1.0000 | 968 |
| ps2-persona-4 | default | 0.9857 | 0.9973 | 1.0000 | – | – | 0.9875 | 0.9990 | 974 |
| ps2-persona-4 | baseline-off | 0.9847 | 0.9919 | 0.9979 | – | – | 0.9864 | 0.9919 | 974 |
| ps2-persona-4 | stock Ghidra | 0.9028 | 0.9997 | 1.0000 | – | – | 0.8991 | 0.9997 | 974 |
| ps2-ratchet-clank | default | 0.6463 | 0.9882 | 0.9988 | – | – | 0.8850 | 0.9911 | 836 |
| ps2-ratchet-clank | baseline-off | 0.6463 | 0.9117 | 0.9988 | – | – | 0.8850 | 0.9139 | 836 |
| ps2-ratchet-clank | stock Ghidra | 0.5317 | 1.0000 | 0.9976 | – | – | 0.7961 | 1.0000 | 836 |
| ps2-ratchet-clank-pal | default | 0.8539 | 0.9882 | 1.0000 | – | – | 0.8463 | 0.9993 | 841 |
| ps2-ratchet-clank-pal | baseline-off | 0.8539 | 0.9112 | 1.0000 | – | – | 0.8463 | 0.9510 | 841 |
| ps2-ratchet-clank-pal | stock Ghidra | 0.7030 | 1.0000 | 1.0000 | – | – | 0.6951 | 1.0000 | 841 |

**Sign tests, ps2**

| comparison | games | wins | losses | ties | one-sided p |
|---|---|---|---|---|---|
| recall vs baseline-off | 8 | 0 | 0 | 8 | – |
| precision vs baseline-off | 8 | 6 | 0 | 2 | 0.0156 |
| success_rate vs baseline-off | 8 | 0 | 0 | 8 | – |
| recall_verified vs baseline-off | 8 | 0 | 0 | 8 | – |
| precision_verified vs baseline-off | 8 | 6 | 0 | 2 | 0.0156 |
| recall vs stock | 8 | 8 | 0 | 0 | 0.0039 |
| precision vs stock | 8 | 1 | 5 | 2 | 0.9844 |
| recall_verified vs stock | 8 | 8 | 0 | 0 | 0.0039 |
| precision_verified vs stock | 8 | 1 | 4 | 3 | 0.9688 |

## psp

| game | tool | recall | precision | success | arity | type exact | recall (verified) | precision (verified) | sampled |
|---|---|---|---|---|---|---|---|---|---|
| psp-hot-pixel | default | 0.8883 | 0.8961 | 1.0000 | 0.8628 | 0.3464 | 0.8883 | 0.9201 | 940 |
| psp-hot-pixel | baseline-off | 0.8880 | 0.8270 | 1.0000 | 0.8628 | 0.3464 | 0.8880 | 0.8474 | 940 |
| psp-hot-pixel | stock Ghidra | 0.5763 | 0.9633 | 1.0000 | 0.8638 | 0.3164 | 0.5763 | 1.0000 | 940 |
| psp-melodie | default | 0.9605 | 0.8982 | 1.0000 | 0.9146 | 0.7025 | 0.9605 | 0.9276 | 851 |
| psp-melodie | baseline-off | 0.9605 | 0.7828 | 1.0000 | 0.9146 | 0.7025 | 0.9605 | 0.8051 | 851 |
| psp-melodie | stock Ghidra | 0.5126 | 0.9640 | 1.0000 | 0.9146 | 0.6736 | 0.5126 | 0.9982 | 851 |
| psp-pac-man-rally | default | 0.9072 | 0.9035 | 1.0000 | 0.8889 | 0.7205 | 0.9072 | 0.9313 | 862 |
| psp-pac-man-rally | baseline-off | 0.9067 | 0.7920 | 1.0000 | 0.8889 | 0.7205 | 0.9067 | 0.8133 | 862 |
| psp-pac-man-rally | stock Ghidra | 0.3099 | 0.9588 | 1.0000 | 0.8704 | 0.6698 | 0.3099 | 0.9980 | 862 |
| psp-psp-camera-01 | default | 0.9457 | 0.9600 | 1.0000 | 0.8188 | 0.3984 | 0.9457 | 0.9931 | 938 |
| psp-psp-camera-01 | baseline-off | 0.9454 | 0.9399 | 1.0000 | 0.8188 | 0.3984 | 0.9454 | 0.9715 | 938 |
| psp-psp-camera-01 | stock Ghidra | 0.6421 | 0.9576 | 1.0000 | 0.8593 | 0.3701 | 0.6421 | 0.9978 | 938 |
| psp-tetris | default | 0.9385 | 0.9710 | 1.0000 | 0.7714 | 0.5811 | 0.9385 | 0.9947 | 935 |
| psp-tetris | baseline-off | 0.9384 | 0.9025 | 1.0000 | 0.7714 | 0.5811 | 0.9384 | 0.9230 | 935 |
| psp-tetris | stock Ghidra | 0.5079 | 0.9579 | 1.0000 | 0.8000 | 0.4868 | 0.5079 | 1.0000 | 935 |

**Sign tests, psp**

| comparison | games | wins | losses | ties | one-sided p |
|---|---|---|---|---|---|
| recall vs baseline-off | 5 | 0 | 0 | 5 | – |
| precision vs baseline-off | 5 | 5 | 0 | 0 | 0.0312 |
| success_rate vs baseline-off | 5 | 0 | 0 | 5 | – |
| arity_accuracy vs baseline-off | 5 | 0 | 0 | 5 | – |
| type_exact_rate vs baseline-off | 5 | 0 | 0 | 5 | – |
| recall_verified vs baseline-off | 5 | 0 | 0 | 5 | – |
| precision_verified vs baseline-off | 5 | 5 | 0 | 0 | 0.0312 |
| recall vs stock | 5 | 5 | 0 | 0 | 0.0312 |
| precision vs stock | 5 | 1 | 3 | 1 | 0.9375 |
| arity_accuracy vs stock | 5 | 1 | 2 | 2 | 0.8750 |
| type_exact_rate vs stock | 5 | 5 | 0 | 0 | 0.0312 |
| recall_verified vs stock | 5 | 5 | 0 | 0 | 0.0312 |
| precision_verified vs stock | 5 | 0 | 4 | 1 | 1.0000 |

## psx

| game | tool | recall | precision | success | arity | type exact | recall (verified) | precision (verified) | sampled |
|---|---|---|---|---|---|---|---|---|---|
| psx-digimon-world | default | 0.9195 | 0.9428 | 0.9826 | – | – | 0.9135 | 1.0000 | 920 |
| psx-digimon-world | baseline-off | 0.9192 | 0.9428 | 0.9815 | – | – | 0.9135 | 1.0000 | 920 |
| psx-digimon-world | stock Ghidra | 0.9194 | 0.9371 | 0.9980 | – | – | 0.9393 | 1.0000 | 505 |
| psx-digimon-world | default (main module only) | 0.9686 | 1.0000 | 0.9826 | – | – | 0.9806 | 1.0000 | 920 |
| psx-legend-of-mana | default | 0.9695 | 0.9973 | 1.0000 | – | – | 0.9766 | 1.0000 | 966 |
| psx-legend-of-mana | baseline-off | 0.9692 | 0.9973 | 1.0000 | – | – | 0.9762 | 1.0000 | 966 |
| psx-legend-of-mana | stock Ghidra | 0.7183 | 0.9686 | 1.0000 | – | – | 0.7232 | 1.0000 | 111 |
| psx-legend-of-mana | default (main module only) | 0.8498 | 1.0000 | 1.0000 | – | – | 0.8120 | 1.0000 | 966 |
| psx-parasite-eve | default | 0.8222 | 0.9742 | 1.0000 | – | – | 0.8222 | 0.9999 | 969 |
| psx-parasite-eve | baseline-off | 0.8220 | 0.9742 | 1.0000 | – | – | 0.8220 | 0.9999 | 969 |
| psx-parasite-eve | stock Ghidra | 0.8120 | 0.9912 | 1.0000 | – | – | 0.8120 | 0.9984 | 209 |
| psx-parasite-eve | default (main module only) | 0.9275 | 0.9954 | 1.0000 | – | – | 0.9275 | 0.9995 | 969 |
| psx-parasite-eve-2 | default | 0.9624 | 0.9671 | 0.9990 | – | – | 0.9643 | 0.9956 | 983 |
| psx-parasite-eve-2 | baseline-off | 0.9613 | 0.9671 | 0.9969 | – | – | 0.9631 | 0.9956 | 983 |
| psx-parasite-eve-2 | stock Ghidra | 0.8166 | 0.9139 | 1.0000 | – | – | 0.8324 | 0.9622 | 94 |
| psx-parasite-eve-2 | default (main module only) | 0.9293 | 0.9545 | 0.9990 | – | – | 0.9481 | 0.9542 | 983 |
| psx-rage-racer | default | 0.9523 | 0.9948 | 1.0000 | – | – | 0.9523 | 0.9948 | 779 |
| psx-rage-racer | baseline-off | 0.9523 | 0.9948 | 1.0000 | – | – | 0.9523 | 0.9948 | 779 |
| psx-rage-racer | stock Ghidra | 0.8844 | 0.9944 | 0.9987 | – | – | 0.8844 | 0.9944 | 779 |
| psx-silent-hill | default | 0.9024 | 0.9879 | 1.0000 | – | – | 0.9023 | 0.9964 | 968 |
| psx-silent-hill | baseline-off | 0.9007 | 0.9874 | 0.9979 | – | – | 0.9006 | 0.9959 | 968 |
| psx-silent-hill | stock Ghidra | 0.8720 | 0.8558 | 1.0000 | – | – | 0.8702 | 0.9005 | 20 |
| psx-silent-hill | default (main module only) | 0.9953 | 0.8898 | 1.0000 | – | – | 0.9952 | 0.9000 | 968 |
| psx-vagrant-story | default | 0.9481 | 0.9577 | 0.9989 | – | – | 0.9526 | 0.9997 | 943 |
| psx-vagrant-story | baseline-off | 0.9457 | 0.9569 | 0.9958 | – | – | 0.9494 | 0.9986 | 943 |
| psx-vagrant-story | stock Ghidra | 0.7520 | 0.9842 | 1.0000 | – | – | 0.7215 | 1.0000 | 184 |
| psx-vagrant-story | default (main module only) | 0.8614 | 0.9988 | 0.9989 | – | – | 0.8404 | 0.9981 | 943 |

**Sign tests, psx**

| comparison | games | wins | losses | ties | one-sided p |
|---|---|---|---|---|---|
| recall vs baseline-off | 7 | 0 | 0 | 7 | – |
| precision vs baseline-off | 7 | 0 | 0 | 7 | – |
| success_rate vs baseline-off | 7 | 0 | 0 | 7 | – |
| recall_verified vs baseline-off | 7 | 0 | 0 | 7 | – |
| precision_verified vs baseline-off | 7 | 0 | 0 | 7 | – |
| recall vs stock | 7 | 7 | 0 | 0 | 0.0078 |
| precision vs stock | 7 | 5 | 0 | 2 | 0.0312 |
| recall_verified vs stock | 7 | 7 | 0 | 0 | 0.0078 |
| precision_verified vs stock | 7 | 0 | 1 | 6 | 1.0000 |

## wii

| game | tool | recall | precision | success | arity | type exact | recall (verified) | precision (verified) | sampled |
|---|---|---|---|---|---|---|---|---|---|
| wii-mario-strikers-charged | default | 0.9973 | 0.9969 | 0.9980 | – | – | 0.9973 | 0.9970 | 984 |
| wii-mario-strikers-charged | baseline-off | 0.9972 | 0.9771 | 0.9980 | – | – | 0.9972 | 0.9769 | 984 |
| wii-mario-strikers-charged | stock Ghidra | 0.8653 | 0.9977 | 0.9959 | – | – | 0.8646 | 0.9977 | 984 |
| wii-npc-pikmin-2 | default | 0.9978 | 0.9958 | 1.0000 | – | – | 0.9978 | 0.9968 | 995 |
| wii-npc-pikmin-2 | baseline-off | 0.9978 | 0.9868 | 1.0000 | – | – | 0.9978 | 0.9880 | 995 |
| wii-npc-pikmin-2 | stock Ghidra | 0.6913 | 0.9983 | 1.0000 | – | – | 0.7319 | 1.0000 | 995 |
| wii-rock-band-3 | default | 0.9873 | 0.9983 | 1.0000 | – | – | 1.0000 | 1.0000 | 995 |
| wii-rock-band-3 | baseline-off | 0.9873 | 0.9938 | 1.0000 | – | – | 1.0000 | 1.0000 | 995 |
| wii-rock-band-3 | stock Ghidra | 0.8612 | 0.9961 | 1.0000 | – | – | 0.9794 | 1.0000 | 995 |
| wii-skyward-sword | default | 0.9712 | 0.9963 | 0.9990 | – | – | 0.9915 | 0.9968 | 998 |
| wii-skyward-sword | baseline-off | 0.9712 | 0.9877 | 0.9990 | – | – | 0.9915 | 0.9917 | 998 |
| wii-skyward-sword | stock Ghidra | 0.6205 | 0.9982 | 1.0000 | – | – | 0.5660 | 1.0000 | 362 |
| wii-skyward-sword | default (main module only) | 0.9894 | 0.9935 | 0.9990 | – | – | 0.9897 | 0.9954 | 998 |
| wii-super-mario-galaxy | default | 0.9970 | 0.9981 | 1.0000 | – | – | 0.9965 | 0.9977 | 993 |
| wii-super-mario-galaxy | baseline-off | 0.9970 | 0.9931 | 1.0000 | – | – | 0.9965 | 0.9932 | 993 |
| wii-super-mario-galaxy | stock Ghidra | 0.8490 | 0.9987 | 1.0000 | – | – | 0.8531 | 0.9979 | 993 |

**Sign tests, wii**

| comparison | games | wins | losses | ties | one-sided p |
|---|---|---|---|---|---|
| recall vs baseline-off | 5 | 0 | 0 | 5 | – |
| precision vs baseline-off | 5 | 4 | 0 | 1 | 0.0625 |
| success_rate vs baseline-off | 5 | 0 | 0 | 5 | – |
| recall_verified vs baseline-off | 5 | 0 | 0 | 5 | – |
| precision_verified vs baseline-off | 5 | 3 | 0 | 2 | 0.1250 |
| recall vs stock | 5 | 5 | 0 | 0 | 0.0312 |
| precision vs stock | 5 | 0 | 0 | 5 | – |
| recall_verified vs stock | 5 | 5 | 0 | 0 | 0.0312 |
| precision_verified vs stock | 5 | 0 | 0 | 5 | – |

## x360

| game | tool | recall | precision | success | arity | type exact | recall (verified) | precision (verified) | sampled |
|---|---|---|---|---|---|---|---|---|---|
| x360-amped-3 | default | 0.9756 | 0.9915 | 1.0000 | 0.7727 | 0.3043 | 0.9756 | 0.9931 | 981 |
| x360-amped-3 | baseline-off | 0.9747 | 0.9874 | 1.0000 | 0.7727 | 0.3043 | 0.9747 | 0.9890 | 981 |
| x360-amped-3 | stock Ghidra | 0.8194 | 0.9956 | 1.0000 | 0.4506 | 0.4196 | 0.8194 | 0.9972 | 981 |
| x360-burnout-crash | default | 0.9958 | 0.9987 | 1.0000 | 0.2246 | 0.2819 | 0.9958 | 1.0000 | 601 |
| x360-burnout-crash | baseline-off | 0.9958 | 0.9987 | 1.0000 | 0.2246 | 0.2819 | 0.9958 | 1.0000 | 601 |
| x360-burnout-crash | stock Ghidra | 0.9952 | 0.9987 | 1.0000 | 0.2113 | 0.2787 | 0.9952 | 1.0000 | 601 |
| x360-call-of-duty-advanced-warfare | default | 0.9041 | 0.9972 | 1.0000 | 0.8363 | 0.3067 | 0.9041 | 0.9972 | 996 |
| x360-call-of-duty-advanced-warfare | baseline-off | 0.9001 | 0.9971 | 0.9920 | 0.8343 | 0.3031 | 0.9001 | 0.9972 | 996 |
| x360-call-of-duty-advanced-warfare | stock Ghidra | 0.7201 | 0.9974 | 1.0000 | 0.5382 | 0.3893 | 0.7201 | 0.9975 | 996 |
| x360-call-of-duty-modern-warfare-2 | default | 0.8011 | 0.9936 | 0.9990 | 0.8335 | 0.3729 | 0.8011 | 0.9936 | 985 |
| x360-call-of-duty-modern-warfare-2 | baseline-off | 0.7983 | 0.9936 | 0.9980 | 0.8325 | 0.3726 | 0.7983 | 0.9936 | 985 |
| x360-call-of-duty-modern-warfare-2 | stock Ghidra | 0.6631 | 0.9935 | 1.0000 | 0.6924 | 0.4187 | 0.6631 | 0.9935 | 985 |
| x360-forza-horizon-2-prototype | default | 0.9510 | 0.9989 | 1.0000 | 0.8060 | 0.3429 | 0.9510 | 0.9989 | 995 |
| x360-forza-horizon-2-prototype | baseline-off | 0.9500 | 0.9989 | 0.9980 | 0.8040 | 0.3421 | 0.9500 | 0.9989 | 995 |
| x360-forza-horizon-2-prototype | stock Ghidra | 0.6817 | 0.9987 | 1.0000 | 0.5719 | 0.4683 | 0.6817 | 0.9987 | 995 |

**Sign tests, x360**

| comparison | games | wins | losses | ties | one-sided p |
|---|---|---|---|---|---|
| recall vs baseline-off | 5 | 0 | 0 | 5 | – |
| precision vs baseline-off | 5 | 0 | 0 | 5 | – |
| success_rate vs baseline-off | 5 | 1 | 0 | 4 | 0.5000 |
| arity_accuracy vs baseline-off | 5 | 0 | 0 | 5 | – |
| type_exact_rate vs baseline-off | 5 | 0 | 0 | 5 | – |
| recall_verified vs baseline-off | 5 | 0 | 0 | 5 | – |
| precision_verified vs baseline-off | 5 | 0 | 0 | 5 | – |
| recall vs stock | 5 | 4 | 0 | 1 | 0.0625 |
| precision vs stock | 5 | 0 | 0 | 5 | – |
| arity_accuracy vs stock | 5 | 5 | 0 | 0 | 0.0312 |
| type_exact_rate vs stock | 5 | 0 | 4 | 1 | 1.0000 |
| recall_verified vs stock | 5 | 4 | 0 | 1 | 0.0625 |
| precision_verified vs stock | 5 | 0 | 0 | 5 | – |

## All games

**Sign tests over all games**

| comparison | games | wins | losses | ties | one-sided p |
|---|---|---|---|---|---|
| recall vs baseline-off | 55 | 8 | 0 | 47 | 0.0039 |
| precision vs baseline-off | 55 | 20 | 0 | 35 | 0.0000 |
| success_rate vs baseline-off | 55 | 9 | 0 | 46 | 0.0019 |
| arity_accuracy vs baseline-off | 12 | 1 | 0 | 11 | 0.5000 |
| type_exact_rate vs baseline-off | 12 | 1 | 0 | 11 | 0.5000 |
| recall_verified vs baseline-off | 55 | 7 | 0 | 48 | 0.0078 |
| precision_verified vs baseline-off | 55 | 19 | 0 | 36 | 0.0000 |
| recall vs stock | 53 | 51 | 0 | 2 | 0.0000 |
| precision vs stock | 53 | 14 | 12 | 27 | 0.4225 |
| arity_accuracy vs stock | 11 | 6 | 2 | 3 | 0.1445 |
| type_exact_rate vs stock | 11 | 6 | 4 | 1 | 0.3770 |
| recall_verified vs stock | 53 | 51 | 0 | 2 | 0.0000 |
| precision_verified vs stock | 52 | 6 | 12 | 34 | 0.9519 |

## Supplement: symtab variants

The staged ELF with its symbol table kept and only DWARF removed (`<id>-symtab`). It isolates type/arity recovery from discovery: its discovery numbers are the symtab's and say nothing about discovery. Not in the per-platform tables or the sign tests.

| game | tool | recall | precision | success | arity | type exact | recall (verified) | precision (verified) | sampled |
|---|---|---|---|---|---|---|---|---|---|
| ps2-dark-chronicle-symtab | default | 1.0000 | 0.9972 | 0.9979 | – | – | 1.0000 | 0.9997 | 962 |
| ps2-dark-chronicle-symtab | baseline-off | 1.0000 | 0.9972 | 0.9979 | – | – | 1.0000 | 0.9997 | 962 |
| ps2-dark-chronicle-symtab | stock Ghidra | 1.0000 | 0.9995 | 1.0000 | – | – | 1.0000 | 0.9997 | 962 |
| ps2-dark-cloud-symtab | default | 0.9995 | 0.9448 | 0.9989 | – | – | 0.9995 | 0.9995 | 940 |
| ps2-dark-cloud-symtab | baseline-off | 0.9995 | 0.9448 | 0.9989 | – | – | 0.9995 | 0.9995 | 940 |
| ps2-dark-cloud-symtab | stock Ghidra | 1.0000 | 0.9267 | 1.0000 | – | – | 1.0000 | 0.9818 | 884 |
| ps2-fatal-frame-symtab | default | 1.0000 | 0.9995 | 0.9766 | – | – | 1.0000 | 1.0000 | 940 |
| ps2-fatal-frame-symtab | baseline-off | 1.0000 | 0.9979 | 0.9766 | – | – | 1.0000 | 0.9980 | 940 |
| ps2-fatal-frame-symtab | stock Ghidra | 1.0000 | 1.0000 | 1.0000 | – | – | 1.0000 | 1.0000 | 940 |
| psp-hot-pixel-symtab | default | 1.0000 | 0.9140 | 0.9979 | 0.8484 | 0.3806 | 1.0000 | 0.9362 | 963 |
| psp-hot-pixel-symtab | baseline-off | 1.0000 | 0.8973 | 0.9990 | 0.8494 | 0.3816 | 1.0000 | 0.9187 | 963 |
| psp-hot-pixel-symtab | stock Ghidra | 1.0000 | 0.9763 | 1.0000 | 0.8411 | 0.3677 | 1.0000 | 1.0000 | 963 |
| psp-melodie-symtab | default | 1.0000 | 0.9617 | 1.0000 | 0.8909 | 0.7344 | 1.0000 | 0.9942 | 846 |
| psp-melodie-symtab | baseline-off | 1.0000 | 0.9362 | 1.0000 | 0.8909 | 0.7344 | 1.0000 | 0.9669 | 846 |
| psp-melodie-symtab | stock Ghidra | 1.0000 | 0.9681 | 1.0000 | 0.9818 | 0.7574 | 1.0000 | 1.0000 | 846 |
| psp-pac-man-rally-symtab | default | 1.0000 | 0.9683 | 1.0000 | 0.9163 | 0.7682 | 1.0000 | 0.9973 | 779 |
| psp-pac-man-rally-symtab | baseline-off | 1.0000 | 0.9542 | 1.0000 | 0.9163 | 0.7682 | 1.0000 | 0.9824 | 779 |
| psp-pac-man-rally-symtab | stock Ghidra | 1.0000 | 0.9733 | 1.0000 | 0.9655 | 0.7421 | 1.0000 | 1.0000 | 779 |
| psp-psp-camera-01-symtab | default | 1.0000 | 0.9677 | 0.9979 | 0.0554 | 0.0419 | 1.0000 | 0.9994 | 939 |
| psp-psp-camera-01-symtab | baseline-off | 1.0000 | 0.9600 | 0.9979 | 0.0554 | 0.0419 | 1.0000 | 0.9912 | 939 |
| psp-psp-camera-01-symtab | stock Ghidra | 1.0000 | 0.9683 | 1.0000 | 0.8626 | 0.3822 | 1.0000 | 0.9986 | 939 |
| psp-tetris-symtab | default | 1.0000 | 0.9772 | 0.9883 | 0.0286 | 0.0132 | 1.0000 | 0.9998 | 938 |
| psp-tetris-symtab | baseline-off | 1.0000 | 0.9768 | 0.9883 | 0.0286 | 0.0132 | 1.0000 | 0.9993 | 938 |
| psp-tetris-symtab | stock Ghidra | 1.0000 | 0.9776 | 0.9883 | 0.8000 | 0.4868 | 1.0000 | 1.0000 | 938 |

## Supplement: version-mismatch images

meta.json says `version_match: false` (the decomp targets another build of the game; the truth is usable but not exact for this image). Not in the per-platform tables above or in any sign test.

| game | tool | recall | precision | success | arity | type exact | recall (verified) | precision (verified) | sampled |
|---|---|---|---|---|---|---|---|---|---|
| n64-star-fox-64 | default | 0.9725 | 0.9578 | 1.0000 | – | – | 0.9725 | 0.9941 | 841 |
| n64-star-fox-64 | baseline-off | 0.9725 | 0.9578 | 1.0000 | – | – | 0.9725 | 0.9941 | 841 |
| n64-star-fox-64 | stock Ghidra | 0.9309 | 0.9707 | 1.0000 | – | – | 0.9309 | 0.9993 | 841 |
| nds-dragon-quest-iv | default | 0.8263 | 0.9944 | 1.0000 | – | – | 0.8263 | 0.9961 | 979 |
| nds-dragon-quest-iv | baseline-off | 0.7957 | 0.9893 | 0.9612 | – | – | 0.7957 | 0.9910 | 979 |
| nds-dragon-quest-iv | stock Ghidra | 0.8606 | 0.9979 | 1.0000 | – | – | 0.8606 | 0.9990 | 630 |
| psx-nfs-high-stakes | default | 0.9852 | 0.9701 | 1.0000 | – | – | 0.9839 | 0.9991 | 894 |
| psx-nfs-high-stakes | baseline-off | 0.9852 | 0.9701 | 1.0000 | – | – | 0.9839 | 0.9991 | 894 |
| psx-nfs-high-stakes | stock Ghidra | 0.9502 | 0.9892 | 1.0000 | – | – | 0.9489 | 1.0000 | 584 |

The sign tests are a supplement. A game is a win when `default` beats the other tool by at least 0.5 pp (the harness's materiality floor), a loss when it trails by as much, else a tie (dropped). One-sided p = P(X >= wins), X ~ Binomial(wins + losses, 1/2). Games whose meta.json says `version_match: false` are in the supplement table only. vs stock uses discovery on the main module only (the module stock was run on). A game whose stock run did not finish within the limit (DNF) or crashed has a labelled stock row and is in no vs-stock test: it counts neither as a win nor as a loss.

## Per seed (default vs baseline-off)

| game | seed | config | recall | precision | success | arity | type exact | sampled |
|---|---|---|---|---|---|---|---|---|
| gba-fire-emblem-sacred-stones | 1 | default | 0.9536 | 0.9893 | 1.0000 | 0.9440 | 0.5189 | 500 |
| gba-fire-emblem-sacred-stones | 1 | baseline-off | 0.9536 | 0.9893 | 1.0000 | 0.9440 | 0.5189 | 500 |
| gba-fire-emblem-sacred-stones | 2 | default | 0.9536 | 0.9893 | 1.0000 | 0.9320 | 0.5222 | 500 |
| gba-fire-emblem-sacred-stones | 2 | baseline-off | 0.9536 | 0.9893 | 1.0000 | 0.9320 | 0.5222 | 500 |
| gba-golden-sun | 1 | default | 0.8873 | 0.9766 | 1.0000 | – | – | 500 |
| gba-golden-sun | 1 | baseline-off | 0.8875 | 0.9766 | 1.0000 | – | – | 500 |
| gba-golden-sun | 2 | default | 0.8873 | 0.9766 | 1.0000 | – | – | 500 |
| gba-golden-sun | 2 | baseline-off | 0.8875 | 0.9766 | 1.0000 | – | – | 500 |
| gba-kh-chain-of-memories | 1 | default | 0.9582 | 0.9640 | 1.0000 | – | – | 500 |
| gba-kh-chain-of-memories | 1 | baseline-off | 0.9426 | 0.9634 | 0.9760 | – | – | 500 |
| gba-kh-chain-of-memories | 2 | default | 0.9582 | 0.9640 | 1.0000 | – | – | 500 |
| gba-kh-chain-of-memories | 2 | baseline-off | 0.9426 | 0.9634 | 0.9800 | – | – | 500 |
| gba-klonoa-empire-of-dreams | 1 | default | 0.8612 | 0.9254 | 1.0000 | 0.9748 | 0.7239 | 484 |
| gba-klonoa-empire-of-dreams | 1 | baseline-off | 0.8434 | 0.9240 | 0.9793 | 0.9519 | 0.7104 | 484 |
| gba-klonoa-empire-of-dreams | 2 | default | 0.8612 | 0.9254 | 1.0000 | 0.9748 | 0.7239 | 484 |
| gba-klonoa-empire-of-dreams | 2 | baseline-off | 0.8434 | 0.9240 | 0.9793 | 0.9519 | 0.7104 | 484 |
| gba-nascar-heat-2002 | 1 | default | 0.8009 | 0.9741 | 1.0000 | – | – | 500 |
| gba-nascar-heat-2002 | 1 | baseline-off | 0.8009 | 0.9741 | 1.0000 | – | – | 500 |
| gba-nascar-heat-2002 | 2 | default | 0.8009 | 0.9741 | 1.0000 | – | – | 500 |
| gba-nascar-heat-2002 | 2 | baseline-off | 0.8009 | 0.9741 | 1.0000 | – | – | 500 |
| gc-mario-party-4 | 1 | default | 0.9983 | 0.9966 | 1.0000 | – | – | 500 |
| gc-mario-party-4 | 1 | baseline-off | 0.9983 | 0.9426 | 1.0000 | – | – | 500 |
| gc-mario-party-4 | 2 | default | 0.9983 | 0.9966 | 1.0000 | – | – | 500 |
| gc-mario-party-4 | 2 | baseline-off | 0.9983 | 0.9426 | 1.0000 | – | – | 500 |
| gc-melee | 1 | default | 0.9997 | 0.9993 | 1.0000 | – | – | 500 |
| gc-melee | 1 | baseline-off | 0.9997 | 0.9963 | 1.0000 | – | – | 500 |
| gc-melee | 2 | default | 0.9997 | 0.9993 | 0.9980 | – | – | 500 |
| gc-melee | 2 | baseline-off | 0.9997 | 0.9963 | 0.9980 | – | – | 500 |
| gc-pikmin | 1 | default | 0.9993 | 0.9959 | 1.0000 | – | – | 500 |
| gc-pikmin | 1 | baseline-off | 0.9993 | 0.9943 | 1.0000 | – | – | 500 |
| gc-pikmin | 2 | default | 0.9993 | 0.9959 | 1.0000 | – | – | 500 |
| gc-pikmin | 2 | baseline-off | 0.9993 | 0.9943 | 1.0000 | – | – | 500 |
| gc-pikmin-2 | 1 | default | 0.9998 | 0.9984 | 1.0000 | – | – | 500 |
| gc-pikmin-2 | 1 | baseline-off | 0.9998 | 0.9942 | 1.0000 | – | – | 500 |
| gc-pikmin-2 | 2 | default | 0.9998 | 0.9984 | 0.9980 | – | – | 500 |
| gc-pikmin-2 | 2 | baseline-off | 0.9998 | 0.9942 | 1.0000 | – | – | 500 |
| gc-super-mario-strikers | 1 | default | 0.9993 | 0.9958 | 1.0000 | – | – | 500 |
| gc-super-mario-strikers | 1 | baseline-off | 0.9993 | 0.9840 | 1.0000 | – | – | 500 |
| gc-super-mario-strikers | 2 | default | 0.9993 | 0.9958 | 1.0000 | – | – | 500 |
| gc-super-mario-strikers | 2 | baseline-off | 0.9993 | 0.9840 | 1.0000 | – | – | 500 |
| gc-tiger-woods-2004 | 1 | default | 0.9993 | 0.9982 | 0.9980 | – | – | 500 |
| gc-tiger-woods-2004 | 1 | baseline-off | 0.9993 | 0.9734 | 0.9980 | – | – | 500 |
| gc-tiger-woods-2004 | 2 | default | 0.9993 | 0.9982 | 0.9980 | – | – | 500 |
| gc-tiger-woods-2004 | 2 | baseline-off | 0.9993 | 0.9734 | 0.9980 | – | – | 500 |
| gc-twilight-princess | 1 | default | 0.9999 | 0.9975 | 1.0000 | – | – | 500 |
| gc-twilight-princess | 1 | baseline-off | 0.9999 | 0.9147 | 1.0000 | – | – | 500 |
| gc-twilight-princess | 2 | default | 0.9999 | 0.9975 | 1.0000 | – | – | 500 |
| gc-twilight-princess | 2 | baseline-off | 0.9999 | 0.9147 | 1.0000 | – | – | 500 |
| gc-wind-waker | 1 | default | 0.9999 | 0.9979 | 1.0000 | – | – | 500 |
| gc-wind-waker | 1 | baseline-off | 0.9999 | 0.9292 | 1.0000 | – | – | 500 |
| gc-wind-waker | 2 | default | 0.9999 | 0.9979 | 1.0000 | – | – | 500 |
| gc-wind-waker | 2 | baseline-off | 0.9999 | 0.9292 | 1.0000 | – | – | 500 |
| n64-banjo-kazooie | 1 | default | 0.9876 | 0.9982 | 1.0000 | – | – | 500 |
| n64-banjo-kazooie | 1 | baseline-off | 0.9876 | 0.9982 | 1.0000 | – | – | 500 |
| n64-banjo-kazooie | 2 | default | 0.9876 | 0.9982 | 1.0000 | – | – | 500 |
| n64-banjo-kazooie | 2 | baseline-off | 0.9876 | 0.9982 | 1.0000 | – | – | 500 |
| n64-dr-mario-64 | 1 | default | 0.9374 | 0.9887 | 1.0000 | – | – | 500 |
| n64-dr-mario-64 | 1 | baseline-off | 0.9374 | 0.9887 | 1.0000 | – | – | 500 |
| n64-dr-mario-64 | 2 | default | 0.9374 | 0.9887 | 1.0000 | – | – | 500 |
| n64-dr-mario-64 | 2 | baseline-off | 0.9374 | 0.9887 | 1.0000 | – | – | 500 |
| n64-majoras-mask | 1 | default | 0.9782 | 0.9980 | 1.0000 | – | – | 500 |
| n64-majoras-mask | 1 | baseline-off | 0.9763 | 0.9965 | 0.9960 | – | – | 500 |
| n64-majoras-mask | 2 | default | 0.9782 | 0.9980 | 1.0000 | – | – | 500 |
| n64-majoras-mask | 2 | baseline-off | 0.9763 | 0.9965 | 1.0000 | – | – | 500 |
| n64-ocarina-of-time | 1 | default | 0.9842 | 0.9977 | 1.0000 | – | – | 500 |
| n64-ocarina-of-time | 1 | baseline-off | 0.9806 | 0.9977 | 0.9940 | – | – | 500 |
| n64-ocarina-of-time | 2 | default | 0.9842 | 0.9977 | 1.0000 | – | – | 500 |
| n64-ocarina-of-time | 2 | baseline-off | 0.9806 | 0.9977 | 0.9980 | – | – | 500 |
| n64-paper-mario | 1 | default | 0.9701 | 0.9963 | 1.0000 | – | – | 500 |
| n64-paper-mario | 1 | baseline-off | 0.9282 | 0.9958 | 0.9400 | – | – | 500 |
| n64-paper-mario | 2 | default | 0.9701 | 0.9963 | 1.0000 | – | – | 500 |
| n64-paper-mario | 2 | baseline-off | 0.9282 | 0.9958 | 0.9600 | – | – | 500 |
| n64-perfect-dark | 1 | default | 0.9525 | 0.9901 | 0.9980 | – | – | 500 |
| n64-perfect-dark | 1 | baseline-off | 0.9521 | 0.9901 | 0.9980 | – | – | 500 |
| n64-perfect-dark | 2 | default | 0.9525 | 0.9901 | 1.0000 | – | – | 500 |
| n64-perfect-dark | 2 | baseline-off | 0.9521 | 0.9901 | 1.0000 | – | – | 500 |
| n64-star-fox-64 | 1 | default | 0.9725 | 0.9578 | 1.0000 | – | – | 500 |
| n64-star-fox-64 | 1 | baseline-off | 0.9725 | 0.9578 | 1.0000 | – | – | 500 |
| n64-star-fox-64 | 2 | default | 0.9725 | 0.9578 | 1.0000 | – | – | 500 |
| n64-star-fox-64 | 2 | baseline-off | 0.9725 | 0.9578 | 1.0000 | – | – | 500 |
| n64-super-mario-64 | 1 | default | 0.9974 | 0.9053 | 1.0000 | – | – | 500 |
| n64-super-mario-64 | 1 | baseline-off | 0.9974 | 0.9053 | 1.0000 | – | – | 500 |
| n64-super-mario-64 | 2 | default | 0.9974 | 0.9053 | 1.0000 | – | – | 500 |
| n64-super-mario-64 | 2 | baseline-off | 0.9974 | 0.9053 | 1.0000 | – | – | 500 |
| n64-super-smash-bros | 1 | default | 0.9551 | 0.9898 | 1.0000 | – | – | 500 |
| n64-super-smash-bros | 1 | baseline-off | 0.9497 | 0.9897 | 0.9920 | – | – | 500 |
| n64-super-smash-bros | 2 | default | 0.9551 | 0.9898 | 1.0000 | – | – | 500 |
| n64-super-smash-bros | 2 | baseline-off | 0.9497 | 0.9897 | 0.9940 | – | – | 500 |
| nds-dragon-quest-iv | 1 | default | 0.8263 | 0.9944 | 1.0000 | – | – | 500 |
| nds-dragon-quest-iv | 1 | baseline-off | 0.7957 | 0.9893 | 0.9640 | – | – | 500 |
| nds-dragon-quest-iv | 2 | default | 0.8263 | 0.9944 | 1.0000 | – | – | 500 |
| nds-dragon-quest-iv | 2 | baseline-off | 0.7957 | 0.9893 | 0.9600 | – | – | 500 |
| nds-kh-358-2-days | 1 | default | 0.8863 | 0.9922 | 1.0000 | – | – | 500 |
| nds-kh-358-2-days | 1 | baseline-off | 0.8758 | 0.9921 | 0.9940 | – | – | 500 |
| nds-kh-358-2-days | 2 | default | 0.8863 | 0.9922 | 1.0000 | – | – | 500 |
| nds-kh-358-2-days | 2 | baseline-off | 0.8758 | 0.9921 | 0.9840 | – | – | 500 |
| nds-kh-recoded | 1 | default | 0.7803 | 0.9635 | 1.0000 | – | – | 500 |
| nds-kh-recoded | 1 | baseline-off | 0.7651 | 0.9633 | 0.9860 | – | – | 500 |
| nds-kh-recoded | 2 | default | 0.7803 | 0.9635 | 1.0000 | – | – | 500 |
| nds-kh-recoded | 2 | baseline-off | 0.7651 | 0.9633 | 0.9780 | – | – | 500 |
| nds-pokemon-platinum | 1 | default | 0.8884 | 0.9977 | 1.0000 | – | – | 500 |
| nds-pokemon-platinum | 1 | baseline-off | 0.8478 | 0.9975 | 0.9680 | – | – | 500 |
| nds-pokemon-platinum | 2 | default | 0.8884 | 0.9977 | 1.0000 | – | – | 500 |
| nds-pokemon-platinum | 2 | baseline-off | 0.8478 | 0.9975 | 0.9460 | – | – | 500 |
| nds-world-ends-with-you | 1 | default | 0.8857 | 0.9986 | 1.0000 | – | – | 500 |
| nds-world-ends-with-you | 1 | baseline-off | 0.8771 | 0.9983 | 0.9860 | – | – | 500 |
| nds-world-ends-with-you | 2 | default | 0.8857 | 0.9986 | 1.0000 | – | – | 500 |
| nds-world-ends-with-you | 2 | baseline-off | 0.8771 | 0.9983 | 0.9820 | – | – | 500 |
| ps2-dark-chronicle | 1 | default | 0.9844 | 0.9972 | 1.0000 | – | – | 500 |
| ps2-dark-chronicle | 1 | baseline-off | 0.9843 | 0.9965 | 1.0000 | – | – | 500 |
| ps2-dark-chronicle | 2 | default | 0.9844 | 0.9972 | 1.0000 | – | – | 500 |
| ps2-dark-chronicle | 2 | baseline-off | 0.9843 | 0.9965 | 1.0000 | – | – | 500 |
| ps2-dark-chronicle-symtab | 1 | default | 1.0000 | 0.9972 | 0.9980 | – | – | 500 |
| ps2-dark-chronicle-symtab | 1 | baseline-off | 1.0000 | 0.9972 | 0.9980 | – | – | 500 |
| ps2-dark-chronicle-symtab | 2 | default | 1.0000 | 0.9972 | 0.9980 | – | – | 500 |
| ps2-dark-chronicle-symtab | 2 | baseline-off | 1.0000 | 0.9972 | 0.9980 | – | – | 500 |
| ps2-dark-cloud | 1 | default | 0.9840 | 0.9906 | 1.0000 | – | – | 500 |
| ps2-dark-cloud | 1 | baseline-off | 0.9830 | 0.9930 | 1.0000 | – | – | 500 |
| ps2-dark-cloud | 2 | default | 0.9840 | 0.9906 | 0.9980 | – | – | 500 |
| ps2-dark-cloud | 2 | baseline-off | 0.9830 | 0.9930 | 0.9960 | – | – | 500 |
| ps2-dark-cloud-symtab | 1 | default | 0.9995 | 0.9448 | 0.9980 | – | – | 500 |
| ps2-dark-cloud-symtab | 1 | baseline-off | 0.9995 | 0.9448 | 0.9980 | – | – | 500 |
| ps2-dark-cloud-symtab | 2 | default | 0.9995 | 0.9448 | 1.0000 | – | – | 500 |
| ps2-dark-cloud-symtab | 2 | baseline-off | 0.9995 | 0.9448 | 1.0000 | – | – | 500 |
| ps2-digital-devil-saga | 1 | default | 0.9854 | 0.9917 | 0.9960 | – | – | 500 |
| ps2-digital-devil-saga | 1 | baseline-off | 0.9851 | 0.9618 | 0.9960 | – | – | 500 |
| ps2-digital-devil-saga | 2 | default | 0.9854 | 0.9917 | 1.0000 | – | – | 500 |
| ps2-digital-devil-saga | 2 | baseline-off | 0.9851 | 0.9618 | 1.0000 | – | – | 500 |
| ps2-fatal-frame | 1 | default | 0.9369 | 0.9893 | 0.9820 | – | – | 500 |
| ps2-fatal-frame | 1 | baseline-off | 0.9362 | 0.8976 | 0.9800 | – | – | 500 |
| ps2-fatal-frame | 2 | default | 0.9369 | 0.9893 | 0.9780 | – | – | 500 |
| ps2-fatal-frame | 2 | baseline-off | 0.9362 | 0.8976 | 0.9780 | – | – | 500 |
| ps2-fatal-frame-symtab | 1 | default | 1.0000 | 0.9995 | 0.9700 | – | – | 500 |
| ps2-fatal-frame-symtab | 1 | baseline-off | 1.0000 | 0.9979 | 0.9700 | – | – | 500 |
| ps2-fatal-frame-symtab | 2 | default | 1.0000 | 0.9995 | 0.9820 | – | – | 500 |
| ps2-fatal-frame-symtab | 2 | baseline-off | 1.0000 | 0.9979 | 0.9820 | – | – | 500 |
| ps2-god-hand | 1 | default | 0.9709 | 0.8950 | 1.0000 | – | – | 500 |
| ps2-god-hand | 1 | baseline-off | 0.9706 | 0.6375 | 1.0000 | – | – | 500 |
| ps2-god-hand | 2 | default | 0.9709 | 0.8950 | 0.9980 | – | – | 500 |
| ps2-god-hand | 2 | baseline-off | 0.9706 | 0.6375 | 0.9980 | – | – | 500 |
| ps2-persona-4 | 1 | default | 0.9857 | 0.9973 | 1.0000 | – | – | 500 |
| ps2-persona-4 | 1 | baseline-off | 0.9847 | 0.9919 | 1.0000 | – | – | 500 |
| ps2-persona-4 | 2 | default | 0.9857 | 0.9973 | 1.0000 | – | – | 500 |
| ps2-persona-4 | 2 | baseline-off | 0.9847 | 0.9919 | 0.9960 | – | – | 500 |
| ps2-ratchet-clank | 1 | default | 0.6463 | 0.9882 | 1.0000 | – | – | 500 |
| ps2-ratchet-clank | 1 | baseline-off | 0.6463 | 0.9117 | 1.0000 | – | – | 500 |
| ps2-ratchet-clank | 2 | default | 0.6463 | 0.9882 | 0.9980 | – | – | 500 |
| ps2-ratchet-clank | 2 | baseline-off | 0.6463 | 0.9117 | 0.9980 | – | – | 500 |
| ps2-ratchet-clank-pal | 1 | default | 0.8539 | 0.9882 | 1.0000 | – | – | 500 |
| ps2-ratchet-clank-pal | 1 | baseline-off | 0.8539 | 0.9112 | 1.0000 | – | – | 500 |
| ps2-ratchet-clank-pal | 2 | default | 0.8539 | 0.9882 | 1.0000 | – | – | 500 |
| ps2-ratchet-clank-pal | 2 | baseline-off | 0.8539 | 0.9112 | 1.0000 | – | – | 500 |
| psp-hot-pixel | 1 | default | 0.8883 | 0.8961 | 1.0000 | 0.8640 | 0.3443 | 500 |
| psp-hot-pixel | 1 | baseline-off | 0.8880 | 0.8270 | 1.0000 | 0.8640 | 0.3443 | 500 |
| psp-hot-pixel | 2 | default | 0.8883 | 0.8961 | 1.0000 | 0.8620 | 0.3535 | 500 |
| psp-hot-pixel | 2 | baseline-off | 0.8880 | 0.8270 | 1.0000 | 0.8620 | 0.3535 | 500 |
| psp-hot-pixel-symtab | 1 | default | 1.0000 | 0.9140 | 1.0000 | 0.8380 | 0.3860 | 500 |
| psp-hot-pixel-symtab | 1 | baseline-off | 1.0000 | 0.8973 | 1.0000 | 0.8380 | 0.3860 | 500 |
| psp-hot-pixel-symtab | 2 | default | 1.0000 | 0.9140 | 0.9960 | 0.8600 | 0.3806 | 500 |
| psp-hot-pixel-symtab | 2 | baseline-off | 1.0000 | 0.8973 | 0.9980 | 0.8620 | 0.3827 | 500 |
| psp-melodie | 1 | default | 0.9605 | 0.8982 | 1.0000 | 0.9146 | 0.7025 | 500 |
| psp-melodie | 1 | baseline-off | 0.9605 | 0.7828 | 1.0000 | 0.9146 | 0.7025 | 500 |
| psp-melodie | 2 | default | 0.9605 | 0.8982 | 1.0000 | 0.9146 | 0.7025 | 500 |
| psp-melodie | 2 | baseline-off | 0.9605 | 0.7828 | 1.0000 | 0.9146 | 0.7025 | 500 |
| psp-melodie-symtab | 1 | default | 1.0000 | 0.9617 | 1.0000 | 0.8909 | 0.7344 | 500 |
| psp-melodie-symtab | 1 | baseline-off | 1.0000 | 0.9362 | 1.0000 | 0.8909 | 0.7344 | 500 |
| psp-melodie-symtab | 2 | default | 1.0000 | 0.9617 | 1.0000 | 0.8909 | 0.7344 | 500 |
| psp-melodie-symtab | 2 | baseline-off | 1.0000 | 0.9362 | 1.0000 | 0.8909 | 0.7344 | 500 |
| psp-pac-man-rally | 1 | default | 0.9072 | 0.9035 | 1.0000 | 0.8889 | 0.7205 | 500 |
| psp-pac-man-rally | 1 | baseline-off | 0.9067 | 0.7920 | 1.0000 | 0.8889 | 0.7205 | 500 |
| psp-pac-man-rally | 2 | default | 0.9072 | 0.9035 | 1.0000 | 0.8889 | 0.7205 | 500 |
| psp-pac-man-rally | 2 | baseline-off | 0.9067 | 0.7920 | 1.0000 | 0.8889 | 0.7205 | 500 |
| psp-pac-man-rally-symtab | 1 | default | 1.0000 | 0.9683 | 1.0000 | 0.9163 | 0.7682 | 500 |
| psp-pac-man-rally-symtab | 1 | baseline-off | 1.0000 | 0.9542 | 1.0000 | 0.9163 | 0.7682 | 500 |
| psp-pac-man-rally-symtab | 2 | default | 1.0000 | 0.9683 | 1.0000 | 0.9163 | 0.7682 | 500 |
| psp-pac-man-rally-symtab | 2 | baseline-off | 1.0000 | 0.9542 | 1.0000 | 0.9163 | 0.7682 | 500 |
| psp-psp-camera-01 | 1 | default | 0.9457 | 0.9600 | 1.0000 | 0.8520 | 0.3936 | 500 |
| psp-psp-camera-01 | 1 | baseline-off | 0.9454 | 0.9399 | 1.0000 | 0.8520 | 0.3936 | 500 |
| psp-psp-camera-01 | 2 | default | 0.9457 | 0.9600 | 1.0000 | 0.7860 | 0.3987 | 500 |
| psp-psp-camera-01 | 2 | baseline-off | 0.9454 | 0.9399 | 1.0000 | 0.7860 | 0.3987 | 500 |
| psp-psp-camera-01-symtab | 1 | default | 1.0000 | 0.9677 | 0.9980 | 0.0500 | 0.0404 | 500 |
| psp-psp-camera-01-symtab | 1 | baseline-off | 1.0000 | 0.9600 | 0.9980 | 0.0500 | 0.0404 | 500 |
| psp-psp-camera-01-symtab | 2 | default | 1.0000 | 0.9677 | 0.9980 | 0.0600 | 0.0459 | 500 |
| psp-psp-camera-01-symtab | 2 | baseline-off | 1.0000 | 0.9600 | 0.9980 | 0.0600 | 0.0459 | 500 |
| psp-tetris | 1 | default | 0.9385 | 0.9710 | 1.0000 | 0.7714 | 0.5811 | 500 |
| psp-tetris | 1 | baseline-off | 0.9384 | 0.9025 | 1.0000 | 0.7714 | 0.5811 | 500 |
| psp-tetris | 2 | default | 0.9385 | 0.9710 | 1.0000 | 0.7714 | 0.5811 | 500 |
| psp-tetris | 2 | baseline-off | 0.9384 | 0.9025 | 1.0000 | 0.7714 | 0.5811 | 500 |
| psp-tetris-symtab | 1 | default | 1.0000 | 0.9772 | 0.9920 | 0.0286 | 0.0132 | 500 |
| psp-tetris-symtab | 1 | baseline-off | 1.0000 | 0.9768 | 0.9920 | 0.0286 | 0.0132 | 500 |
| psp-tetris-symtab | 2 | default | 1.0000 | 0.9772 | 0.9860 | 0.0286 | 0.0132 | 500 |
| psp-tetris-symtab | 2 | baseline-off | 1.0000 | 0.9768 | 0.9860 | 0.0286 | 0.0132 | 500 |
| psx-digimon-world | 1 | default | 0.9195 | 0.9428 | 0.9860 | – | – | 500 |
| psx-digimon-world | 1 | baseline-off | 0.9192 | 0.9428 | 0.9860 | – | – | 500 |
| psx-digimon-world | 2 | default | 0.9195 | 0.9428 | 0.9800 | – | – | 500 |
| psx-digimon-world | 2 | baseline-off | 0.9192 | 0.9428 | 0.9780 | – | – | 500 |
| psx-legend-of-mana | 1 | default | 0.9695 | 0.9973 | 1.0000 | – | – | 500 |
| psx-legend-of-mana | 1 | baseline-off | 0.9692 | 0.9973 | 1.0000 | – | – | 500 |
| psx-legend-of-mana | 2 | default | 0.9695 | 0.9973 | 1.0000 | – | – | 500 |
| psx-legend-of-mana | 2 | baseline-off | 0.9692 | 0.9973 | 1.0000 | – | – | 500 |
| psx-nfs-high-stakes | 1 | default | 0.9852 | 0.9701 | 1.0000 | – | – | 500 |
| psx-nfs-high-stakes | 1 | baseline-off | 0.9852 | 0.9701 | 1.0000 | – | – | 500 |
| psx-nfs-high-stakes | 2 | default | 0.9852 | 0.9701 | 1.0000 | – | – | 500 |
| psx-nfs-high-stakes | 2 | baseline-off | 0.9852 | 0.9701 | 1.0000 | – | – | 500 |
| psx-parasite-eve | 1 | default | 0.8222 | 0.9742 | 1.0000 | – | – | 500 |
| psx-parasite-eve | 1 | baseline-off | 0.8220 | 0.9742 | 1.0000 | – | – | 500 |
| psx-parasite-eve | 2 | default | 0.8222 | 0.9742 | 1.0000 | – | – | 500 |
| psx-parasite-eve | 2 | baseline-off | 0.8220 | 0.9742 | 1.0000 | – | – | 500 |
| psx-parasite-eve-2 | 1 | default | 0.9624 | 0.9671 | 1.0000 | – | – | 500 |
| psx-parasite-eve-2 | 1 | baseline-off | 0.9613 | 0.9671 | 0.9980 | – | – | 500 |
| psx-parasite-eve-2 | 2 | default | 0.9624 | 0.9671 | 0.9980 | – | – | 500 |
| psx-parasite-eve-2 | 2 | baseline-off | 0.9613 | 0.9671 | 0.9960 | – | – | 500 |
| psx-rage-racer | 1 | default | 0.9523 | 0.9948 | 1.0000 | – | – | 500 |
| psx-rage-racer | 1 | baseline-off | 0.9523 | 0.9948 | 1.0000 | – | – | 500 |
| psx-rage-racer | 2 | default | 0.9523 | 0.9948 | 1.0000 | – | – | 500 |
| psx-rage-racer | 2 | baseline-off | 0.9523 | 0.9948 | 1.0000 | – | – | 500 |
| psx-silent-hill | 1 | default | 0.9024 | 0.9879 | 1.0000 | – | – | 500 |
| psx-silent-hill | 1 | baseline-off | 0.9007 | 0.9874 | 0.9980 | – | – | 500 |
| psx-silent-hill | 2 | default | 0.9024 | 0.9879 | 1.0000 | – | – | 500 |
| psx-silent-hill | 2 | baseline-off | 0.9007 | 0.9874 | 0.9980 | – | – | 500 |
| psx-vagrant-story | 1 | default | 0.9481 | 0.9577 | 0.9980 | – | – | 500 |
| psx-vagrant-story | 1 | baseline-off | 0.9457 | 0.9569 | 0.9960 | – | – | 500 |
| psx-vagrant-story | 2 | default | 0.9481 | 0.9577 | 1.0000 | – | – | 500 |
| psx-vagrant-story | 2 | baseline-off | 0.9457 | 0.9569 | 0.9960 | – | – | 500 |
| wii-mario-strikers-charged | 1 | default | 0.9973 | 0.9969 | 1.0000 | – | – | 500 |
| wii-mario-strikers-charged | 1 | baseline-off | 0.9972 | 0.9771 | 1.0000 | – | – | 500 |
| wii-mario-strikers-charged | 2 | default | 0.9973 | 0.9969 | 0.9960 | – | – | 500 |
| wii-mario-strikers-charged | 2 | baseline-off | 0.9972 | 0.9771 | 0.9960 | – | – | 500 |
| wii-npc-pikmin-2 | 1 | default | 0.9978 | 0.9958 | 1.0000 | – | – | 500 |
| wii-npc-pikmin-2 | 1 | baseline-off | 0.9978 | 0.9868 | 1.0000 | – | – | 500 |
| wii-npc-pikmin-2 | 2 | default | 0.9978 | 0.9958 | 1.0000 | – | – | 500 |
| wii-npc-pikmin-2 | 2 | baseline-off | 0.9978 | 0.9868 | 1.0000 | – | – | 500 |
| wii-rock-band-3 | 1 | default | 0.9873 | 0.9983 | 1.0000 | – | – | 500 |
| wii-rock-band-3 | 1 | baseline-off | 0.9873 | 0.9938 | 1.0000 | – | – | 500 |
| wii-rock-band-3 | 2 | default | 0.9873 | 0.9983 | 1.0000 | – | – | 500 |
| wii-rock-band-3 | 2 | baseline-off | 0.9873 | 0.9938 | 1.0000 | – | – | 500 |
| wii-skyward-sword | 1 | default | 0.9712 | 0.9963 | 0.9980 | – | – | 500 |
| wii-skyward-sword | 1 | baseline-off | 0.9712 | 0.9877 | 0.9980 | – | – | 500 |
| wii-skyward-sword | 2 | default | 0.9712 | 0.9963 | 1.0000 | – | – | 500 |
| wii-skyward-sword | 2 | baseline-off | 0.9712 | 0.9877 | 1.0000 | – | – | 500 |
| wii-super-mario-galaxy | 1 | default | 0.9970 | 0.9981 | 1.0000 | – | – | 500 |
| wii-super-mario-galaxy | 1 | baseline-off | 0.9970 | 0.9931 | 1.0000 | – | – | 500 |
| wii-super-mario-galaxy | 2 | default | 0.9970 | 0.9981 | 1.0000 | – | – | 500 |
| wii-super-mario-galaxy | 2 | baseline-off | 0.9970 | 0.9931 | 1.0000 | – | – | 500 |
| x360-amped-3 | 1 | default | 0.9756 | 0.9915 | 1.0000 | 0.7920 | 0.3070 | 500 |
| x360-amped-3 | 1 | baseline-off | 0.9747 | 0.9874 | 1.0000 | 0.7920 | 0.3070 | 500 |
| x360-amped-3 | 2 | default | 0.9756 | 0.9915 | 1.0000 | 0.7580 | 0.2992 | 500 |
| x360-amped-3 | 2 | baseline-off | 0.9747 | 0.9874 | 1.0000 | 0.7580 | 0.2992 | 500 |
| x360-burnout-crash | 1 | default | 0.9958 | 0.9987 | 1.0000 | 0.2320 | 0.2851 | 500 |
| x360-burnout-crash | 1 | baseline-off | 0.9958 | 0.9987 | 1.0000 | 0.2320 | 0.2851 | 500 |
| x360-burnout-crash | 2 | default | 0.9958 | 0.9987 | 1.0000 | 0.2220 | 0.2723 | 500 |
| x360-burnout-crash | 2 | baseline-off | 0.9958 | 0.9987 | 1.0000 | 0.2220 | 0.2723 | 500 |
| x360-call-of-duty-advanced-warfare | 1 | default | 0.9041 | 0.9972 | 1.0000 | 0.8380 | 0.3216 | 500 |
| x360-call-of-duty-advanced-warfare | 1 | baseline-off | 0.9001 | 0.9971 | 0.9900 | 0.8340 | 0.3169 | 500 |
| x360-call-of-duty-advanced-warfare | 2 | default | 0.9041 | 0.9972 | 1.0000 | 0.8360 | 0.2919 | 500 |
| x360-call-of-duty-advanced-warfare | 2 | baseline-off | 0.9001 | 0.9971 | 0.9940 | 0.8360 | 0.2892 | 500 |
| x360-call-of-duty-modern-warfare-2 | 1 | default | 0.8011 | 0.9936 | 1.0000 | 0.8320 | 0.3805 | 500 |
| x360-call-of-duty-modern-warfare-2 | 1 | baseline-off | 0.7983 | 0.9936 | 1.0000 | 0.8320 | 0.3805 | 500 |
| x360-call-of-duty-modern-warfare-2 | 2 | default | 0.8011 | 0.9936 | 0.9980 | 0.8380 | 0.3708 | 500 |
| x360-call-of-duty-modern-warfare-2 | 2 | baseline-off | 0.7983 | 0.9936 | 0.9960 | 0.8360 | 0.3701 | 500 |
| x360-forza-horizon-2-prototype | 1 | default | 0.9510 | 0.9989 | 1.0000 | 0.8040 | 0.3288 | 500 |
| x360-forza-horizon-2-prototype | 1 | baseline-off | 0.9500 | 0.9989 | 0.9960 | 0.8000 | 0.3272 | 500 |
| x360-forza-horizon-2-prototype | 2 | default | 0.9510 | 0.9989 | 1.0000 | 0.8100 | 0.3580 | 500 |
| x360-forza-horizon-2-prototype | 2 | baseline-off | 0.9500 | 0.9989 | 1.0000 | 0.8100 | 0.3580 | 500 |


# Console research components (2026-10-10T23:09:41+00:00)

Tools fingerprint `5d47c57fe192c622`; sample n=500 seeds=[1, 2]. Thresholds: rates 0.5 pp, counts 1% of the reference (min 1), counts over functions both configurations decompiled. Output is deterministic: deltas are exact. `~` marks a change below the threshold.

## Verdict matrix (component effect vs its reference)

| component | config | reference | gba-fire-emblem-sacred-stones | gba-golden-sun | gba-kh-chain-of-memories | gba-klonoa-empire-of-dreams | gba-nascar-heat-2002 | gc-mario-party-4 | gc-melee | gc-pikmin | gc-pikmin-2 | gc-super-mario-strikers | gc-tiger-woods-2004 | gc-twilight-princess | gc-wind-waker | n64-banjo-kazooie | n64-dr-mario-64 | n64-majoras-mask | n64-ocarina-of-time | n64-paper-mario | n64-perfect-dark | n64-star-fox-64 | n64-super-mario-64 | n64-super-smash-bros | nds-dragon-quest-iv | nds-kh-358-2-days | nds-kh-recoded | nds-pokemon-platinum | nds-world-ends-with-you | ps2-dark-chronicle | ps2-dark-chronicle-symtab | ps2-dark-cloud | ps2-dark-cloud-symtab | ps2-digital-devil-saga | ps2-fatal-frame | ps2-fatal-frame-symtab | ps2-god-hand | ps2-persona-4 | ps2-ratchet-clank | ps2-ratchet-clank-pal | psp-hot-pixel | psp-hot-pixel-symtab | psp-melodie | psp-melodie-symtab | psp-pac-man-rally | psp-pac-man-rally-symtab | psp-psp-camera-01 | psp-psp-camera-01-symtab | psp-tetris | psp-tetris-symtab | psx-digimon-world | psx-legend-of-mana | psx-nfs-high-stakes | psx-parasite-eve | psx-parasite-eve-2 | psx-rage-racer | psx-silent-hill | psx-vagrant-story | wii-mario-strikers-charged | wii-npc-pikmin-2 | wii-rock-band-3 | wii-skyward-sword | wii-super-mario-galaxy | x360-amped-3 | x360-burnout-crash | x360-call-of-duty-advanced-warfare | x360-call-of-duty-modern-warfare-2 | x360-forza-horizon-2-prototype |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| all research (default vs baseline-off) | default | baseline-off | helps | helps | helps | helps | helps | helps | helps | helps | helps | helps | helps | helps | helps | helps | helps | helps | helps | helps | helps | helps | helps | helps | helps | helps | helps | helps | helps | helps | helps | helps | mixed | helps | helps | helps | helps | helps | helps | helps | helps | helps | helps | helps | helps | mixed | helps | helps | helps | helps | helps | helps | helps | helps | helps | helps | helps | helps | helps | helps | helps | helps | helps | helps | helps | helps | helps | helps |

## Deltas

| component | image | verdict | vs reference | vs default | vs baseline-off |
|---|---|---|---|---|---|
| all research (default vs baseline-off) | gba-fire-emblem-sacred-stones | helps | gotos -78, labels -40, lines +81 | no change | gotos -78, labels -40, lines +81 |
| all research (default vs baseline-off) | gba-golden-sun | helps | recall -0.0pp~, gotos -80, labels -38, irregular_functions -1~, lines +143 | no change | recall -0.0pp~, gotos -80, labels -38, irregular_functions -1~, lines +143 |
| all research (default vs baseline-off) | gba-kh-chain-of-memories | helps | recall +1.6pp, precision +0.1pp~, success_rate +2.3pp, gotos -571, labels -270, irregular_functions -3~, native_warnings +2~, lines +1101, recall_verified +1.6pp, precision_verified +0.0pp | no change | recall +1.6pp, precision +0.1pp~, success_rate +2.3pp, gotos -571, labels -270, irregular_functions -3~, native_warnings +2~, lines +1101, recall_verified +1.6pp, precision_verified +0.0pp |
| all research (default vs baseline-off) | gba-klonoa-empire-of-dreams | helps | recall +1.8pp, precision +0.1pp~, success_rate +2.1pp, gotos -243, labels -139, irregular_functions -1~, lines +336, arity_accuracy +2.3pp, type_exact_rate +1.4pp, recall_verified +2.1pp, precision_verified +0.1pp | no change | recall +1.8pp, precision +0.1pp~, success_rate +2.1pp, gotos -243, labels -139, irregular_functions -1~, lines +336, arity_accuracy +2.3pp, type_exact_rate +1.4pp, recall_verified +2.1pp, precision_verified +0.1pp |
| all research (default vs baseline-off) | gba-nascar-heat-2002 | helps | gotos -149, labels -75, irregular_functions -4~, lines +252 | no change | gotos -149, labels -75, irregular_functions -4~, lines +252 |
| all research (default vs baseline-off) | gc-mario-party-4 | helps | precision +5.4pp, gotos -141, labels -60, native_warnings +1~, lines +277, precision_verified +5.4pp | no change | precision +5.4pp, gotos -141, labels -60, native_warnings +1~, lines +277, precision_verified +5.4pp |
| all research (default vs baseline-off) | gc-melee | helps | precision +0.3pp~, gotos -89, labels -36, lines +178, precision_verified +0.3pp | no change | precision +0.3pp~, gotos -89, labels -36, lines +178, precision_verified +0.3pp |
| all research (default vs baseline-off) | gc-pikmin | helps | precision +0.2pp~, gotos -41, labels -19, irregular_functions -3~, lines +109, precision_verified +0.2pp | no change | precision +0.2pp~, gotos -41, labels -19, irregular_functions -3~, lines +109, precision_verified +0.2pp |
| all research (default vs baseline-off) | gc-pikmin-2 | helps | precision +0.4pp~, success_rate -0.1pp~, gotos -60, labels -28, irregular_functions -4~, native_warnings +1~, lines +168, precision_verified +0.4pp | no change | precision +0.4pp~, success_rate -0.1pp~, gotos -60, labels -28, irregular_functions -4~, native_warnings +1~, lines +168, precision_verified +0.4pp |
| all research (default vs baseline-off) | gc-super-mario-strikers | helps | precision +1.2pp, gotos -115, labels -57, irregular_functions -2~, lines +287, precision_verified +1.2pp | no change | precision +1.2pp, gotos -115, labels -57, irregular_functions -2~, lines +287, precision_verified +1.2pp |
| all research (default vs baseline-off) | gc-tiger-woods-2004 | helps | precision +2.5pp, gotos -72, labels -28, irregular_functions -4~, lines +72, precision_verified +2.5pp | no change | precision +2.5pp, gotos -72, labels -28, irregular_functions -4~, lines +72, precision_verified +2.5pp |
| all research (default vs baseline-off) | gc-twilight-princess | helps | precision +8.3pp, gotos -94, labels -46, irregular_functions -1~, native_warnings -1~, text_warnings -1~, lines +202, precision_verified +8.8pp | no change | precision +8.3pp, gotos -94, labels -46, irregular_functions -1~, native_warnings -1~, text_warnings -1~, lines +202, precision_verified +8.8pp |
| all research (default vs baseline-off) | gc-wind-waker | helps | precision +6.9pp, gotos -84, labels -30, irregular_functions -1~, lines +257, precision_verified +5.4pp | no change | precision +6.9pp, gotos -84, labels -30, irregular_functions -1~, lines +257, precision_verified +5.4pp |
| all research (default vs baseline-off) | n64-banjo-kazooie | helps | gotos -55, labels -27, irregular_functions -5~, lines +117 | no change | gotos -55, labels -27, irregular_functions -5~, lines +117 |
| all research (default vs baseline-off) | n64-dr-mario-64 | helps | gotos -244, labels -126, irregular_functions -6, lines +365 | no change | gotos -244, labels -126, irregular_functions -6, lines +365 |
| all research (default vs baseline-off) | n64-majoras-mask | helps | recall +0.2pp~, precision +0.1pp~, success_rate +0.2pp~, gotos -171, labels -88, irregular_functions -12, lines +244, recall_verified +0.2pp, precision_verified +0.1pp | no change | recall +0.2pp~, precision +0.1pp~, success_rate +0.2pp~, gotos -171, labels -88, irregular_functions -12, lines +244, recall_verified +0.2pp, precision_verified +0.1pp |
| all research (default vs baseline-off) | n64-ocarina-of-time | helps | recall +0.4pp~, success_rate +0.4pp~, gotos -177, labels -90, irregular_functions -8, native_warnings +2~, lines +261, recall_verified +0.4pp | no change | recall +0.4pp~, success_rate +0.4pp~, gotos -177, labels -90, irregular_functions -8, native_warnings +2~, lines +261, recall_verified +0.4pp |
| all research (default vs baseline-off) | n64-paper-mario | helps | recall +4.2pp, precision +0.1pp~, success_rate +5.2pp, gotos -193, labels -98, irregular_functions -6, native_warnings +1~, text_warnings -2, lines +592, recall_verified +0.7pp, precision_verified +0.0pp | no change | recall +4.2pp, precision +0.1pp~, success_rate +5.2pp, gotos -193, labels -98, irregular_functions -6, native_warnings +1~, text_warnings -2, lines +592, recall_verified +0.7pp, precision_verified +0.0pp |
| all research (default vs baseline-off) | n64-perfect-dark | helps | recall +0.0pp~, gotos -245, labels -122, irregular_functions -9, lines +129, recall_verified +0.0pp | no change | recall +0.0pp~, gotos -245, labels -122, irregular_functions -9, lines +129, recall_verified +0.0pp |
| all research (default vs baseline-off) | n64-star-fox-64 | helps | gotos -226, labels -116, irregular_functions -5~, lines +471 | no change | gotos -226, labels -116, irregular_functions -5~, lines +471 |
| all research (default vs baseline-off) | n64-super-mario-64 | helps | gotos -16, labels -8, lines +249 | no change | gotos -16, labels -8, lines +249 |
| all research (default vs baseline-off) | n64-super-smash-bros | helps | recall +0.5pp, precision +0.0pp~, success_rate +0.7pp, gotos -113, labels -58, irregular_functions -4~, native_warnings +1~, text_warnings +1~, lines +150, recall_verified +0.6pp, precision_verified +0.0pp | no change | recall +0.5pp, precision +0.0pp~, success_rate +0.7pp, gotos -113, labels -58, irregular_functions -4~, native_warnings +1~, text_warnings +1~, lines +150, recall_verified +0.6pp, precision_verified +0.0pp |
| all research (default vs baseline-off) | nds-dragon-quest-iv | helps | recall +3.1pp, precision +0.5pp, success_rate +3.9pp, gotos -69, labels -21, irregular_functions -2~, native_warnings -12~, text_warnings -17, lines +306, recall_verified +3.1pp, precision_verified +0.5pp | no change | recall +3.1pp, precision +0.5pp, success_rate +3.9pp, gotos -69, labels -21, irregular_functions -2~, native_warnings -12~, text_warnings -17, lines +306, recall_verified +3.1pp, precision_verified +0.5pp |
| all research (default vs baseline-off) | nds-kh-358-2-days | helps | recall +1.1pp, precision +0.0pp~, success_rate +1.1pp, gotos -50, labels -27, irregular_functions -1~, native_warnings +1~, lines +207, recall_verified +1.1pp, precision_verified -0.0pp | no change | recall +1.1pp, precision +0.0pp~, success_rate +1.1pp, gotos -50, labels -27, irregular_functions -1~, native_warnings +1~, lines +207, recall_verified +1.1pp, precision_verified -0.0pp |
| all research (default vs baseline-off) | nds-kh-recoded | helps | recall +1.5pp, precision +0.0pp~, success_rate +1.8pp, gotos -258, labels -122, irregular_functions -8, lines +515, recall_verified +1.6pp, precision_verified +0.0pp | no change | recall +1.5pp, precision +0.0pp~, success_rate +1.8pp, gotos -258, labels -122, irregular_functions -8, lines +515, recall_verified +1.6pp, precision_verified +0.0pp |
| all research (default vs baseline-off) | nds-pokemon-platinum | helps | recall +4.1pp, precision +0.0pp~, success_rate +4.3pp, gotos -30, labels -12, irregular_functions -1~, native_warnings +2~, lines +162, recall_verified +4.1pp, precision_verified +0.0pp | no change | recall +4.1pp, precision +0.0pp~, success_rate +4.3pp, gotos -30, labels -12, irregular_functions -1~, native_warnings +2~, lines +162, recall_verified +4.1pp, precision_verified +0.0pp |
| all research (default vs baseline-off) | nds-world-ends-with-you | helps | recall +0.9pp, precision +0.0pp~, success_rate +1.6pp, gotos -102, labels -39, irregular_functions -3~, lines +276, recall_verified +0.1pp, precision_verified +0.1pp | no change | recall +0.9pp, precision +0.0pp~, success_rate +1.6pp, gotos -102, labels -39, irregular_functions -3~, lines +276, recall_verified +0.1pp, precision_verified +0.1pp |
| all research (default vs baseline-off) | ps2-dark-chronicle | helps | recall +0.0pp~, precision +0.1pp~, gotos -73, labels -35, irregular_functions -4~, lines +400, recall_verified +0.0pp, precision_verified +0.1pp | no change | recall +0.0pp~, precision +0.1pp~, gotos -73, labels -35, irregular_functions -4~, lines +400, recall_verified +0.0pp, precision_verified +0.1pp |
| all research (default vs baseline-off) | ps2-dark-chronicle-symtab | helps | gotos -89, labels -41, irregular_functions -4~, lines +401 | no change | gotos -89, labels -41, irregular_functions -4~, lines +401 |
| all research (default vs baseline-off) | ps2-dark-cloud | helps | recall +0.1pp~, precision -0.2pp~, success_rate +0.1pp~, gotos -64, labels -32, irregular_functions -5~, native_warnings +3~, text_warnings -1~, lines +516, recall_verified +0.1pp | no change | recall +0.1pp~, precision -0.2pp~, success_rate +0.1pp~, gotos -64, labels -32, irregular_functions -5~, native_warnings +3~, text_warnings -1~, lines +516, recall_verified +0.1pp |
| all research (default vs baseline-off) | ps2-dark-cloud-symtab | mixed | gotos -61, labels -30, irregular_functions -4~, native_warnings +8~, text_warnings +8, lines +284 | no change | gotos -61, labels -30, irregular_functions -4~, native_warnings +8~, text_warnings +8, lines +284 |
| all research (default vs baseline-off) | ps2-digital-devil-saga | helps | recall +0.0pp~, precision +3.0pp, gotos -209, labels -104, irregular_functions -8, lines +221, recall_verified +0.0pp, precision_verified +2.5pp | no change | recall +0.0pp~, precision +3.0pp, gotos -209, labels -104, irregular_functions -8, lines +221, recall_verified +0.0pp, precision_verified +2.5pp |
| all research (default vs baseline-off) | ps2-fatal-frame | helps | recall +0.1pp~, precision +9.2pp, success_rate +0.1pp~, gotos -371, labels -196, irregular_functions -17, native_warnings -7~, text_warnings -1~, lines +519, recall_verified +0.1pp, precision_verified +10.5pp | no change | recall +0.1pp~, precision +9.2pp, success_rate +0.1pp~, gotos -371, labels -196, irregular_functions -17, native_warnings -7~, text_warnings -1~, lines +519, recall_verified +0.1pp, precision_verified +10.5pp |
| all research (default vs baseline-off) | ps2-fatal-frame-symtab | helps | precision +0.2pp~, gotos -436, labels -235, irregular_functions -17, native_warnings -15~, text_warnings -11, lines +201, precision_verified +0.2pp | no change | precision +0.2pp~, gotos -436, labels -235, irregular_functions -17, native_warnings -15~, text_warnings -11, lines +201, precision_verified +0.2pp |
| all research (default vs baseline-off) | ps2-god-hand | helps | recall +0.0pp~, precision +25.8pp, gotos -434, labels -220, irregular_functions -6~, native_warnings -1~, text_warnings -1, lines +617, recall_verified +0.0pp, precision_verified +22.3pp | no change | recall +0.0pp~, precision +25.8pp, gotos -434, labels -220, irregular_functions -6~, native_warnings -1~, text_warnings -1, lines +617, recall_verified +0.0pp, precision_verified +22.3pp |
| all research (default vs baseline-off) | ps2-persona-4 | helps | recall +0.1pp~, precision +0.5pp, success_rate +0.2pp~, gotos -69, labels -40, irregular_functions -3~, native_warnings +1~, text_warnings +1~, lines +225, recall_verified +0.1pp, precision_verified +0.7pp | no change | recall +0.1pp~, precision +0.5pp, success_rate +0.2pp~, gotos -69, labels -40, irregular_functions -3~, native_warnings +1~, text_warnings +1~, lines +225, recall_verified +0.1pp, precision_verified +0.7pp |
| all research (default vs baseline-off) | ps2-ratchet-clank | helps | precision +7.6pp, gotos -241, labels -128, irregular_functions -8, native_warnings +1~, lines +245, precision_verified +7.7pp | no change | precision +7.6pp, gotos -241, labels -128, irregular_functions -8, native_warnings +1~, lines +245, precision_verified +7.7pp |
| all research (default vs baseline-off) | ps2-ratchet-clank-pal | helps | precision +7.7pp, gotos -215, labels -106, irregular_functions -8, native_warnings +1~, lines +244, precision_verified +4.8pp | no change | precision +7.7pp, gotos -215, labels -106, irregular_functions -8, native_warnings +1~, lines +244, precision_verified +4.8pp |
| all research (default vs baseline-off) | psp-hot-pixel | helps | recall +0.0pp~, precision +6.9pp, gotos -718, labels -437, irregular_functions -26, native_warnings +2~, text_warnings +2~, lines +1251, recall_verified +0.0pp, precision_verified +7.3pp | no change | recall +0.0pp~, precision +6.9pp, gotos -718, labels -437, irregular_functions -26, native_warnings +2~, text_warnings +2~, lines +1251, recall_verified +0.0pp, precision_verified +7.3pp |
| all research (default vs baseline-off) | psp-hot-pixel-symtab | helps | precision +1.7pp, success_rate -0.1pp~, gotos -750, labels -488, irregular_functions -23, native_warnings -2~, text_warnings -1~, lines +923, arity_accuracy -0.1pp~, type_exact_rate -0.1pp~, precision_verified +1.8pp | no change | precision +1.7pp, success_rate -0.1pp~, gotos -750, labels -488, irregular_functions -23, native_warnings -2~, text_warnings -1~, lines +923, arity_accuracy -0.1pp~, type_exact_rate -0.1pp~, precision_verified +1.8pp |
| all research (default vs baseline-off) | psp-melodie | helps | precision +11.5pp, gotos -148, labels -73, irregular_functions -12, lines +251, precision_verified +12.2pp | no change | precision +11.5pp, gotos -148, labels -73, irregular_functions -12, lines +251, precision_verified +12.2pp |
| all research (default vs baseline-off) | psp-melodie-symtab | helps | precision +2.5pp, gotos -130, labels -71, irregular_functions -9, lines +275, precision_verified +2.7pp | no change | precision +2.5pp, gotos -130, labels -71, irregular_functions -9, lines +275, precision_verified +2.7pp |
| all research (default vs baseline-off) | psp-pac-man-rally | helps | recall +0.1pp~, precision +11.2pp, gotos -161, labels -88, irregular_functions -11, native_warnings -1~, lines +315, recall_verified +0.1pp, precision_verified +11.8pp | no change | recall +0.1pp~, precision +11.2pp, gotos -161, labels -88, irregular_functions -11, native_warnings -1~, lines +315, recall_verified +0.1pp, precision_verified +11.8pp |
| all research (default vs baseline-off) | psp-pac-man-rally-symtab | mixed | precision +1.4pp, gotos -159, labels -93, irregular_functions -5, native_warnings +4~, text_warnings +4, lines +273, precision_verified +1.5pp | no change | precision +1.4pp, gotos -159, labels -93, irregular_functions -5, native_warnings +4~, text_warnings +4, lines +273, precision_verified +1.5pp |
| all research (default vs baseline-off) | psp-psp-camera-01 | helps | recall +0.0pp~, precision +2.0pp, gotos -93, labels -52, irregular_functions -3~, native_warnings -2~, text_warnings -1, lines +407, recall_verified +0.0pp, precision_verified +2.2pp | no change | recall +0.0pp~, precision +2.0pp, gotos -93, labels -52, irregular_functions -3~, native_warnings -2~, text_warnings -1, lines +407, recall_verified +0.0pp, precision_verified +2.2pp |
| all research (default vs baseline-off) | psp-psp-camera-01-symtab | helps | precision +0.8pp, gotos -96, labels -43, irregular_functions -4~, lines +246, precision_verified +0.8pp | no change | precision +0.8pp, gotos -96, labels -43, irregular_functions -4~, lines +246, precision_verified +0.8pp |
| all research (default vs baseline-off) | psp-tetris | helps | recall +0.0pp~, precision +6.9pp, gotos -211, labels -109, irregular_functions -10, lines +361, recall_verified +0.0pp, precision_verified +7.2pp | no change | recall +0.0pp~, precision +6.9pp, gotos -211, labels -109, irregular_functions -10, lines +361, recall_verified +0.0pp, precision_verified +7.2pp |
| all research (default vs baseline-off) | psp-tetris-symtab | helps | precision +0.0pp~, gotos -243, labels -115, irregular_functions -12, lines +351, precision_verified +0.1pp | no change | precision +0.0pp~, gotos -243, labels -115, irregular_functions -12, lines +351, precision_verified +0.1pp |
| all research (default vs baseline-off) | psx-digimon-world | helps | recall +0.0pp~, success_rate +0.1pp~, gotos -89, labels -43, irregular_functions -1~, native_warnings -1~, lines +176 | no change | recall +0.0pp~, success_rate +0.1pp~, gotos -89, labels -43, irregular_functions -1~, native_warnings -1~, lines +176 |
| all research (default vs baseline-off) | psx-legend-of-mana | helps | recall +0.0pp~, gotos -148, labels -74, irregular_functions -6, lines +142, recall_verified +0.0pp | no change | recall +0.0pp~, gotos -148, labels -74, irregular_functions -6, lines +142, recall_verified +0.0pp |
| all research (default vs baseline-off) | psx-nfs-high-stakes | helps | gotos -280, labels -145, irregular_functions -10, lines +242 | no change | gotos -280, labels -145, irregular_functions -10, lines +242 |
| all research (default vs baseline-off) | psx-parasite-eve | helps | recall +0.0pp~, gotos -115, labels -56, irregular_functions -2~, lines +315, recall_verified +0.0pp | no change | recall +0.0pp~, gotos -115, labels -56, irregular_functions -2~, lines +315, recall_verified +0.0pp |
| all research (default vs baseline-off) | psx-parasite-eve-2 | helps | recall +0.1pp~, success_rate +0.2pp~, gotos -465, labels -231, irregular_functions -8, lines +613, recall_verified +0.1pp | no change | recall +0.1pp~, success_rate +0.2pp~, gotos -465, labels -231, irregular_functions -8, lines +613, recall_verified +0.1pp |
| all research (default vs baseline-off) | psx-rage-racer | helps | gotos -194, labels -102, irregular_functions -7, lines +309 | no change | gotos -194, labels -102, irregular_functions -7, lines +309 |
| all research (default vs baseline-off) | psx-silent-hill | helps | recall +0.2pp~, precision +0.1pp~, success_rate +0.2pp~, gotos -1065, labels -529, irregular_functions -29, lines +1512, recall_verified +0.2pp, precision_verified +0.1pp | no change | recall +0.2pp~, precision +0.1pp~, success_rate +0.2pp~, gotos -1065, labels -529, irregular_functions -29, lines +1512, recall_verified +0.2pp, precision_verified +0.1pp |
| all research (default vs baseline-off) | psx-vagrant-story | helps | recall +0.2pp~, precision +0.1pp~, success_rate +0.3pp~, gotos -399, labels -233, irregular_functions -8, native_warnings +1~, lines +833, recall_verified +0.3pp, precision_verified +0.1pp | no change | recall +0.2pp~, precision +0.1pp~, success_rate +0.3pp~, gotos -399, labels -233, irregular_functions -8, native_warnings +1~, lines +833, recall_verified +0.3pp, precision_verified +0.1pp |
| all research (default vs baseline-off) | wii-mario-strikers-charged | helps | recall +0.0pp~, precision +2.0pp, gotos -98, labels -49, irregular_functions -3~, native_warnings +1~, lines +91, recall_verified +0.0pp, precision_verified +2.0pp | no change | recall +0.0pp~, precision +2.0pp, gotos -98, labels -49, irregular_functions -3~, native_warnings +1~, lines +91, recall_verified +0.0pp, precision_verified +2.0pp |
| all research (default vs baseline-off) | wii-npc-pikmin-2 | helps | precision +0.9pp, gotos -90, labels -35, irregular_functions -1~, lines +134, precision_verified +0.9pp | no change | precision +0.9pp, gotos -90, labels -35, irregular_functions -1~, lines +134, precision_verified +0.9pp |
| all research (default vs baseline-off) | wii-rock-band-3 | helps | precision +0.4pp~, gotos -30, labels -14, irregular_functions -1~, lines +91 | no change | precision +0.4pp~, gotos -30, labels -14, irregular_functions -1~, lines +91 |
| all research (default vs baseline-off) | wii-skyward-sword | helps | precision +0.9pp, gotos -50, labels -22, irregular_functions -1~, lines +160, precision_verified +0.5pp | no change | precision +0.9pp, gotos -50, labels -22, irregular_functions -1~, lines +160, precision_verified +0.5pp |
| all research (default vs baseline-off) | wii-super-mario-galaxy | helps | precision +0.5pp, gotos -18, labels -10, lines +53, precision_verified +0.4pp | no change | precision +0.5pp, gotos -18, labels -10, lines +53, precision_verified +0.4pp |
| all research (default vs baseline-off) | x360-amped-3 | helps | recall +0.1pp~, precision +0.4pp~, gotos -318, labels -154, irregular_functions -3~, lines +563, recall_verified +0.1pp, precision_verified +0.4pp | no change | recall +0.1pp~, precision +0.4pp~, gotos -318, labels -154, irregular_functions -3~, lines +563, recall_verified +0.1pp, precision_verified +0.4pp |
| all research (default vs baseline-off) | x360-burnout-crash | helps | gotos -107, labels -61, irregular_functions -1~, lines +179 | no change | gotos -107, labels -61, irregular_functions -1~, lines +179 |
| all research (default vs baseline-off) | x360-call-of-duty-advanced-warfare | helps | recall +0.4pp~, precision +0.0pp~, success_rate +0.8pp, gotos -267, labels -151, irregular_functions -3~, lines +389, arity_accuracy +0.2pp~, type_exact_rate +0.4pp~, recall_verified +0.4pp | no change | recall +0.4pp~, precision +0.0pp~, success_rate +0.8pp, gotos -267, labels -151, irregular_functions -3~, lines +389, arity_accuracy +0.2pp~, type_exact_rate +0.4pp~, recall_verified +0.4pp |
| all research (default vs baseline-off) | x360-call-of-duty-modern-warfare-2 | helps | recall +0.3pp~, success_rate +0.1pp~, gotos -216, labels -107, irregular_functions -1~, lines +385, arity_accuracy +0.1pp~, type_exact_rate +0.0pp~, recall_verified +0.3pp | no change | recall +0.3pp~, success_rate +0.1pp~, gotos -216, labels -107, irregular_functions -1~, lines +385, arity_accuracy +0.1pp~, type_exact_rate +0.0pp~, recall_verified +0.3pp |
| all research (default vs baseline-off) | x360-forza-horizon-2-prototype | helps | recall +0.1pp~, success_rate +0.2pp~, gotos -129, labels -64, irregular_functions -1~, lines +187, arity_accuracy +0.2pp~, type_exact_rate +0.1pp~, recall_verified +0.1pp | no change | recall +0.1pp~, success_rate +0.2pp~, gotos -129, labels -64, irregular_functions -1~, lines +187, arity_accuracy +0.2pp~, type_exact_rate +0.1pp~, recall_verified +0.1pp |

## Absolute values

| image | config | success | gotos | labels | irregular | warnings | lines | recall | precision | arity | type exact | m22 sim | m22 standalone | median s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| gba-fire-emblem-sacred-stones | default | 1.0000 | 18 | 9 | 896 | 3168 | 26936 | 0.9536 | 0.9893 | 0.9364 | 0.5202 | – | – | 0.5650 |
| gba-fire-emblem-sacred-stones | baseline-off | 1.0000 | 96 | 49 | 896 | 3168 | 26855 | 0.9536 | 0.9893 | 0.9364 | 0.5202 | – | – | 0.5670 |
| gba-golden-sun | default | 1.0000 | 42 | 19 | 972 | 3876 | 30388 | 0.8873 | 0.9766 | – | – | – | – | 0.4830 |
| gba-golden-sun | baseline-off | 1.0000 | 122 | 57 | 973 | 3876 | 30245 | 0.8875 | 0.9766 | – | – | – | – | 0.4840 |
| gba-kh-chain-of-memories | default | 1.0000 | 68 | 36 | 837 | 3124 | 41944 | 0.9582 | 0.9640 | – | – | – | – | 0.9910 |
| gba-kh-chain-of-memories | baseline-off | 0.9771 | 639 | 306 | 832 | 3090 | 40398 | 0.9426 | 0.9634 | – | – | – | – | 0.7250 |
| gba-klonoa-empire-of-dreams | default | 1.0000 | 129 | 74 | 421 | 4846 | 36151 | 0.8612 | 0.9254 | 0.9748 | 0.7239 | – | – | 0.1190 |
| gba-klonoa-empire-of-dreams | baseline-off | 0.9793 | 372 | 213 | 412 | 4826 | 34944 | 0.8434 | 0.9240 | 0.9519 | 0.7104 | – | – | 0.1160 |
| gba-nascar-heat-2002 | default | 1.0000 | 122 | 66 | 612 | 2197 | 30379 | 0.8009 | 0.9741 | – | – | – | – | 0.3490 |
| gba-nascar-heat-2002 | baseline-off | 1.0000 | 271 | 141 | 616 | 2197 | 30127 | 0.8009 | 0.9741 | – | – | – | – | 0.4220 |
| gc-mario-party-4 | default | 1.0000 | 136 | 70 | 754 | 6631 | 84260 | 0.9983 | 0.9966 | – | – | – | – | 1.2840 |
| gc-mario-party-4 | baseline-off | 1.0000 | 277 | 130 | 754 | 6630 | 83983 | 0.9983 | 0.9426 | – | – | – | – | 1.3250 |
| gc-melee | default | 0.9990 | 41 | 21 | 708 | 2814 | 37954 | 0.9997 | 0.9993 | – | – | – | – | 1.1520 |
| gc-melee | baseline-off | 0.9990 | 130 | 57 | 708 | 2814 | 37776 | 0.9997 | 0.9963 | – | – | – | – | 1.1110 |
| gc-pikmin | default | 1.0000 | 30 | 22 | 599 | 2009 | 44614 | 0.9993 | 0.9959 | – | – | – | – | 0.5410 |
| gc-pikmin | baseline-off | 1.0000 | 71 | 41 | 602 | 2009 | 44505 | 0.9993 | 0.9943 | – | – | – | – | 0.5320 |
| gc-pikmin-2 | default | 0.9990 | 39 | 18 | 633 | 2425 | 36869 | 0.9998 | 0.9984 | – | – | – | – | 2.3820 |
| gc-pikmin-2 | baseline-off | 1.0000 | 119 | 59 | 638 | 2627 | 45955 | 0.9998 | 0.9942 | – | – | – | – | 1.6830 |
| gc-super-mario-strikers | default | 1.0000 | 96 | 57 | 697 | 3431 | 56741 | 0.9993 | 0.9958 | – | – | – | – | 0.7480 |
| gc-super-mario-strikers | baseline-off | 1.0000 | 211 | 114 | 699 | 3431 | 56454 | 0.9993 | 0.9840 | – | – | – | – | 0.7400 |
| gc-tiger-woods-2004 | default | 0.9990 | 30 | 17 | 595 | 2615 | 39126 | 0.9993 | 0.9982 | – | – | – | – | 0.4480 |
| gc-tiger-woods-2004 | baseline-off | 0.9990 | 102 | 45 | 599 | 2615 | 39054 | 0.9993 | 0.9734 | – | – | – | – | 0.4110 |
| gc-twilight-princess | default | 1.0000 | 42 | 20 | 760 | 3497 | 45608 | 0.9999 | 0.9975 | – | – | – | – | 3.2950 |
| gc-twilight-princess | baseline-off | 1.0000 | 136 | 66 | 761 | 3498 | 45406 | 0.9999 | 0.9147 | – | – | – | – | 3.8470 |
| gc-wind-waker | default | 1.0000 | 37 | 12 | 666 | 2675 | 34963 | 0.9999 | 0.9979 | – | – | – | – | 5.1070 |
| gc-wind-waker | baseline-off | 1.0000 | 121 | 42 | 667 | 2675 | 34706 | 0.9999 | 0.9292 | – | – | – | – | 5.8550 |
| n64-banjo-kazooie | default | 1.0000 | 14 | 8 | 618 | 1875 | 22800 | 0.9876 | 0.9982 | – | – | – | – | 1.8870 |
| n64-banjo-kazooie | baseline-off | 1.0000 | 69 | 35 | 623 | 1875 | 22683 | 0.9876 | 0.9982 | – | – | – | – | 1.7840 |
| n64-dr-mario-64 | default | 1.0000 | 42 | 25 | 506 | 1591 | 36274 | 0.9374 | 0.9887 | – | – | – | – | 0.2590 |
| n64-dr-mario-64 | baseline-off | 1.0000 | 286 | 151 | 512 | 1591 | 35909 | 0.9374 | 0.9887 | – | – | – | – | 0.2460 |
| n64-majoras-mask | default | 1.0000 | 147 | 62 | 537 | 1769 | 38659 | 0.9782 | 0.9980 | – | – | – | – | 2.4890 |
| n64-majoras-mask | baseline-off | 0.9979 | 318 | 150 | 548 | 1766 | 38326 | 0.9763 | 0.9965 | – | – | – | – | 1.8620 |
| n64-ocarina-of-time | default | 1.0000 | 69 | 33 | 532 | 1457 | 35615 | 0.9842 | 0.9977 | – | – | – | – | 1.8640 |
| n64-ocarina-of-time | baseline-off | 0.9956 | 246 | 123 | 538 | 1447 | 35183 | 0.9806 | 0.9977 | – | – | – | – | 1.8810 |
| n64-paper-mario | default | 1.0000 | 98 | 40 | 576 | 1601 | 38582 | 0.9701 | 0.9963 | – | – | – | – | 2.8190 |
| n64-paper-mario | baseline-off | 0.9484 | 291 | 138 | 542 | 1480 | 37234 | 0.9282 | 0.9958 | – | – | – | – | 3.0560 |
| n64-perfect-dark | default | 0.9990 | 115 | 61 | 545 | 1949 | 51416 | 0.9525 | 0.9901 | – | – | – | – | 0.5440 |
| n64-perfect-dark | baseline-off | 0.9990 | 360 | 183 | 554 | 1949 | 51287 | 0.9521 | 0.9901 | – | – | – | – | 0.6490 |
| n64-star-fox-64 | default | 1.0000 | 108 | 52 | 637 | 2392 | 44720 | 0.9725 | 0.9578 | – | – | – | – | 0.3450 |
| n64-star-fox-64 | baseline-off | 1.0000 | 334 | 168 | 642 | 2392 | 44249 | 0.9725 | 0.9578 | – | – | – | – | 0.3570 |
| n64-super-mario-64 | default | 1.0000 | 15 | 4 | 633 | 1754 | 25380 | 0.9974 | 0.9053 | – | – | – | – | 0.8650 |
| n64-super-mario-64 | baseline-off | 1.0000 | 31 | 12 | 633 | 1754 | 25131 | 0.9974 | 0.9053 | – | – | – | – | 0.8590 |
| n64-super-smash-bros | default | 1.0000 | 52 | 20 | 464 | 1332 | 29011 | 0.9551 | 0.9898 | – | – | – | – | 0.4530 |
| n64-super-smash-bros | baseline-off | 0.9930 | 165 | 78 | 468 | 1331 | 28677 | 0.9497 | 0.9897 | – | – | – | – | 0.5790 |
| nds-dragon-quest-iv | default | 1.0000 | 12 | 5 | 658 | 2193 | 30216 | 0.8263 | 0.9944 | – | – | – | – | 0.5230 |
| nds-dragon-quest-iv | baseline-off | 0.9612 | 81 | 26 | 634 | 2122 | 28649 | 0.7957 | 0.9893 | – | – | – | – | 0.5000 |
| nds-kh-358-2-days | default | 1.0000 | 24 | 10 | 865 | 2673 | 44617 | 0.8863 | 0.9922 | – | – | – | – | 1.0920 |
| nds-kh-358-2-days | baseline-off | 0.9889 | 74 | 37 | 863 | 2666 | 43864 | 0.8758 | 0.9921 | – | – | – | – | 1.0900 |
| nds-kh-recoded | default | 1.0000 | 53 | 20 | 697 | 2285 | 40623 | 0.7803 | 0.9635 | – | – | – | – | 0.7660 |
| nds-kh-recoded | baseline-off | 0.9825 | 309 | 141 | 694 | 2248 | 39435 | 0.7651 | 0.9633 | – | – | – | – | 0.8680 |
| nds-pokemon-platinum | default | 1.0000 | 21 | 12 | 762 | 2347 | 30789 | 0.8884 | 0.9977 | – | – | – | – | 0.8190 |
| nds-pokemon-platinum | baseline-off | 0.9567 | 51 | 24 | 735 | 2263 | 29643 | 0.8478 | 0.9975 | – | – | – | – | 0.6970 |
| nds-world-ends-with-you | default | 1.0000 | 66 | 27 | 722 | 2168 | 36203 | 0.8857 | 0.9986 | – | – | – | – | 0.3420 |
| nds-world-ends-with-you | baseline-off | 0.9838 | 164 | 63 | 721 | 2144 | 35180 | 0.8771 | 0.9983 | – | – | – | – | 0.3230 |
| ps2-dark-chronicle | default | 1.0000 | 70 | 34 | 625 | 2374 | 45009 | 0.9844 | 0.9972 | – | – | – | – | 0.6990 |
| ps2-dark-chronicle | baseline-off | 1.0000 | 143 | 69 | 629 | 2374 | 44609 | 0.9843 | 0.9965 | – | – | – | – | 0.5360 |
| ps2-dark-chronicle-symtab | default | 0.9979 | 84 | 41 | 594 | 2263 | 46284 | 1.0000 | 0.9972 | – | – | – | – | 0.8930 |
| ps2-dark-chronicle-symtab | baseline-off | 0.9979 | 173 | 82 | 598 | 2263 | 45883 | 1.0000 | 0.9972 | – | – | – | – | 0.7310 |
| ps2-dark-cloud | default | 0.9989 | 25 | 13 | 628 | 2572 | 45896 | 0.9840 | 0.9906 | – | – | – | – | 0.4540 |
| ps2-dark-cloud | baseline-off | 0.9979 | 89 | 45 | 633 | 2569 | 45376 | 0.9830 | 0.9930 | – | – | – | – | 0.4560 |
| ps2-dark-cloud-symtab | default | 0.9989 | 80 | 39 | 598 | 2396 | 53355 | 0.9995 | 0.9448 | – | – | – | – | 0.7050 |
| ps2-dark-cloud-symtab | baseline-off | 0.9989 | 141 | 69 | 602 | 2388 | 53071 | 0.9995 | 0.9448 | – | – | – | – | 0.6290 |
| ps2-digital-devil-saga | default | 0.9980 | 138 | 50 | 648 | 2292 | 37113 | 0.9854 | 0.9917 | – | – | – | – | 0.6250 |
| ps2-digital-devil-saga | baseline-off | 0.9980 | 347 | 154 | 656 | 2292 | 36892 | 0.9851 | 0.9618 | – | – | – | – | 0.8270 |
| ps2-fatal-frame | default | 0.9796 | 140 | 69 | 570 | 1867 | 49189 | 0.9369 | 0.9893 | – | – | – | – | 0.4570 |
| ps2-fatal-frame | baseline-off | 0.9785 | 508 | 263 | 586 | 1856 | 48290 | 0.9362 | 0.8976 | – | – | – | – | 0.4540 |
| ps2-fatal-frame-symtab | default | 0.9766 | 198 | 80 | 570 | 2106 | 53113 | 1.0000 | 0.9995 | – | – | – | – | 0.4630 |
| ps2-fatal-frame-symtab | baseline-off | 0.9766 | 634 | 315 | 587 | 2121 | 52912 | 1.0000 | 0.9979 | – | – | – | – | 0.4480 |
| ps2-god-hand | default | 0.9990 | 193 | 110 | 700 | 2004 | 44197 | 0.9709 | 0.8950 | – | – | – | – | 0.8210 |
| ps2-god-hand | baseline-off | 0.9990 | 627 | 330 | 706 | 2005 | 43580 | 0.9706 | 0.6375 | – | – | – | – | 1.0890 |
| ps2-persona-4 | default | 1.0000 | 58 | 43 | 645 | 2013 | 38947 | 0.9857 | 0.9973 | – | – | – | – | 1.3580 |
| ps2-persona-4 | baseline-off | 0.9979 | 127 | 83 | 646 | 2009 | 38675 | 0.9847 | 0.9919 | – | – | – | – | 1.5560 |
| ps2-ratchet-clank | default | 0.9988 | 94 | 46 | 552 | 2807 | 47827 | 0.6463 | 0.9882 | – | – | – | – | 0.3400 |
| ps2-ratchet-clank | baseline-off | 0.9988 | 335 | 174 | 560 | 2806 | 47582 | 0.6463 | 0.9117 | – | – | – | – | 0.2720 |
| ps2-ratchet-clank-pal | default | 1.0000 | 130 | 59 | 559 | 2651 | 47438 | 0.8539 | 0.9882 | – | – | – | – | 0.2310 |
| ps2-ratchet-clank-pal | baseline-off | 1.0000 | 345 | 165 | 567 | 2650 | 47194 | 0.8539 | 0.9112 | – | – | – | – | 0.1530 |
| psp-hot-pixel | default | 1.0000 | 585 | 294 | 710 | 2544 | 62975 | 0.8883 | 0.8961 | 0.8628 | 0.3464 | – | – | 2.8030 |
| psp-hot-pixel | baseline-off | 1.0000 | 1303 | 731 | 736 | 2542 | 61724 | 0.8880 | 0.8270 | 0.8628 | 0.3464 | – | – | 2.6360 |
| psp-hot-pixel-symtab | default | 0.9979 | 642 | 291 | 702 | 2390 | 61547 | 1.0000 | 0.9140 | 0.8484 | 0.3806 | – | – | 2.8460 |
| psp-hot-pixel-symtab | baseline-off | 0.9990 | 1614 | 896 | 726 | 2401 | 65264 | 1.0000 | 0.8973 | 0.8494 | 0.3816 | – | – | 1.7440 |
| psp-melodie | default | 1.0000 | 183 | 81 | 547 | 2107 | 47623 | 0.9605 | 0.8982 | 0.9146 | 0.7025 | – | – | 0.4560 |
| psp-melodie | baseline-off | 1.0000 | 331 | 154 | 559 | 2107 | 47372 | 0.9605 | 0.7828 | 0.9146 | 0.7025 | – | – | 0.4480 |
| psp-melodie-symtab | default | 1.0000 | 44 | 22 | 530 | 2028 | 48296 | 1.0000 | 0.9617 | 0.8909 | 0.7344 | – | – | 0.4880 |
| psp-melodie-symtab | baseline-off | 1.0000 | 174 | 93 | 539 | 2028 | 48021 | 1.0000 | 0.9362 | 0.8909 | 0.7344 | – | – | 0.4840 |
| psp-pac-man-rally | default | 1.0000 | 73 | 36 | 471 | 1845 | 35801 | 0.9072 | 0.9035 | 0.8889 | 0.7205 | – | – | 2.9440 |
| psp-pac-man-rally | baseline-off | 1.0000 | 234 | 124 | 482 | 1846 | 35486 | 0.9067 | 0.7920 | 0.8889 | 0.7205 | – | – | 2.4760 |
| psp-pac-man-rally-symtab | default | 1.0000 | 69 | 39 | 459 | 2463 | 32673 | 1.0000 | 0.9683 | 0.9163 | 0.7682 | – | – | 2.7280 |
| psp-pac-man-rally-symtab | baseline-off | 1.0000 | 228 | 132 | 464 | 2459 | 32400 | 1.0000 | 0.9542 | 0.9163 | 0.7682 | – | – | 2.0640 |
| psp-psp-camera-01 | default | 1.0000 | 61 | 21 | 592 | 1989 | 33777 | 0.9457 | 0.9600 | 0.8188 | 0.3984 | – | – | 0.6430 |
| psp-psp-camera-01 | baseline-off | 1.0000 | 154 | 73 | 595 | 1991 | 33370 | 0.9454 | 0.9399 | 0.8188 | 0.3984 | – | – | 0.6490 |
| psp-psp-camera-01-symtab | default | 0.9979 | 19 | 11 | 593 | 2206 | 32816 | 1.0000 | 0.9677 | 0.0554 | 0.0419 | – | – | 0.6950 |
| psp-psp-camera-01-symtab | baseline-off | 0.9979 | 115 | 54 | 597 | 2206 | 32570 | 1.0000 | 0.9600 | 0.0554 | 0.0419 | – | – | 0.8120 |
| psp-tetris | default | 1.0000 | 114 | 66 | 513 | 1439 | 40192 | 0.9385 | 0.9710 | 0.7714 | 0.5811 | – | – | 0.8330 |
| psp-tetris | baseline-off | 1.0000 | 325 | 175 | 523 | 1439 | 39831 | 0.9384 | 0.9025 | 0.7714 | 0.5811 | – | – | 0.6350 |
| psp-tetris-symtab | default | 0.9883 | 73 | 42 | 488 | 1315 | 39551 | 1.0000 | 0.9772 | 0.0286 | 0.0132 | – | – | 1.0030 |
| psp-tetris-symtab | baseline-off | 0.9883 | 316 | 157 | 500 | 1315 | 39200 | 1.0000 | 0.9768 | 0.0286 | 0.0132 | – | – | 0.7580 |
| psx-digimon-world | default | 0.9826 | 54 | 29 | 720 | 2615 | 44478 | 0.9195 | 0.9428 | – | – | – | – | 0.2440 |
| psx-digimon-world | baseline-off | 0.9815 | 143 | 72 | 721 | 2616 | 44297 | 0.9192 | 0.9428 | – | – | – | – | 0.2100 |
| psx-legend-of-mana | default | 1.0000 | 53 | 26 | 515 | 1194 | 37298 | 0.9695 | 0.9973 | – | – | – | – | 0.2670 |
| psx-legend-of-mana | baseline-off | 1.0000 | 201 | 100 | 521 | 1194 | 37156 | 0.9692 | 0.9973 | – | – | – | – | 0.2330 |
| psx-nfs-high-stakes | default | 1.0000 | 77 | 43 | 555 | 1711 | 46102 | 0.9852 | 0.9701 | – | – | – | – | 0.3410 |
| psx-nfs-high-stakes | baseline-off | 1.0000 | 357 | 188 | 565 | 1711 | 45860 | 0.9852 | 0.9701 | – | – | – | – | 0.3350 |
| psx-parasite-eve | default | 1.0000 | 52 | 26 | 540 | 1932 | 55070 | 0.8222 | 0.9742 | – | – | – | – | 0.1060 |
| psx-parasite-eve | baseline-off | 1.0000 | 167 | 82 | 542 | 1932 | 54755 | 0.8220 | 0.9742 | – | – | – | – | 0.1060 |
| psx-parasite-eve-2 | default | 0.9990 | 130 | 70 | 711 | 2694 | 68778 | 0.9624 | 0.9671 | – | – | – | – | 0.0950 |
| psx-parasite-eve-2 | baseline-off | 0.9969 | 595 | 301 | 718 | 2689 | 68028 | 0.9613 | 0.9671 | – | – | – | – | 0.0920 |
| psx-rage-racer | default | 1.0000 | 110 | 59 | 501 | 1664 | 41128 | 0.9523 | 0.9948 | – | – | – | – | 0.3040 |
| psx-rage-racer | baseline-off | 1.0000 | 304 | 161 | 508 | 1664 | 40819 | 0.9523 | 0.9948 | – | – | – | – | 0.2420 |
| psx-silent-hill | default | 1.0000 | 444 | 223 | 591 | 1856 | 70534 | 0.9024 | 0.9879 | – | – | – | – | 0.1460 |
| psx-silent-hill | baseline-off | 0.9979 | 1504 | 748 | 618 | 1848 | 68326 | 0.9007 | 0.9874 | – | – | – | – | 0.1290 |
| psx-vagrant-story | default | 0.9989 | 185 | 116 | 636 | 3381 | 70758 | 0.9481 | 0.9577 | – | – | – | – | 0.2310 |
| psx-vagrant-story | baseline-off | 0.9958 | 584 | 349 | 644 | 3380 | 69884 | 0.9457 | 0.9569 | – | – | – | – | 0.2100 |
| wii-mario-strikers-charged | default | 0.9980 | 108 | 56 | 775 | 3652 | 53284 | 0.9973 | 0.9969 | – | – | – | – | 1.2790 |
| wii-mario-strikers-charged | baseline-off | 0.9980 | 206 | 105 | 778 | 3651 | 53193 | 0.9972 | 0.9771 | – | – | – | – | 1.3040 |
| wii-npc-pikmin-2 | default | 1.0000 | 41 | 21 | 687 | 2645 | 41695 | 0.9978 | 0.9958 | – | – | – | – | 1.5470 |
| wii-npc-pikmin-2 | baseline-off | 1.0000 | 131 | 56 | 688 | 2645 | 41561 | 0.9978 | 0.9868 | – | – | – | – | 1.5570 |
| wii-rock-band-3 | default | 1.0000 | 8 | 4 | 868 | 3262 | 29067 | 0.9873 | 0.9983 | – | – | – | – | 3.8350 |
| wii-rock-band-3 | baseline-off | 1.0000 | 38 | 18 | 869 | 3262 | 28976 | 0.9873 | 0.9938 | – | – | – | – | 3.9080 |
| wii-skyward-sword | default | 0.9990 | 50 | 29 | 632 | 1960 | 33796 | 0.9712 | 0.9963 | – | – | – | – | 0.1170 |
| wii-skyward-sword | baseline-off | 0.9990 | 100 | 51 | 633 | 1960 | 33636 | 0.9712 | 0.9877 | – | – | – | – | 0.1220 |
| wii-super-mario-galaxy | default | 1.0000 | 15 | 9 | 770 | 3347 | 29884 | 0.9970 | 0.9981 | – | – | – | – | 1.9130 |
| wii-super-mario-galaxy | baseline-off | 1.0000 | 33 | 19 | 770 | 3347 | 29831 | 0.9970 | 0.9931 | – | – | – | – | 1.9780 |
| x360-amped-3 | default | 1.0000 | 145 | 82 | 806 | 3699 | 59801 | 0.9756 | 0.9915 | 0.7727 | 0.3043 | – | – | 4.3960 |
| x360-amped-3 | baseline-off | 1.0000 | 463 | 236 | 809 | 3699 | 59238 | 0.9747 | 0.9874 | 0.7727 | 0.3043 | – | – | 5.0950 |
| x360-burnout-crash | default | 1.0000 | 146 | 91 | 405 | 1268 | 30269 | 0.9958 | 0.9987 | 0.2246 | 0.2819 | – | – | 3.3630 |
| x360-burnout-crash | baseline-off | 1.0000 | 253 | 152 | 406 | 1268 | 30090 | 0.9958 | 0.9987 | 0.2246 | 0.2819 | – | – | 2.3720 |
| x360-call-of-duty-advanced-warfare | default | 1.0000 | 113 | 63 | 867 | 3902 | 46272 | 0.9041 | 0.9972 | 0.8363 | 0.3067 | – | – | 2.9580 |
| x360-call-of-duty-advanced-warfare | baseline-off | 0.9920 | 380 | 214 | 867 | 3899 | 45827 | 0.9001 | 0.9971 | 0.8343 | 0.3031 | – | – | 3.4880 |
| x360-call-of-duty-modern-warfare-2 | default | 0.9990 | 71 | 39 | 791 | 3013 | 43759 | 0.8011 | 0.9936 | 0.8335 | 0.3729 | – | – | 2.7260 |
| x360-call-of-duty-modern-warfare-2 | baseline-off | 0.9980 | 287 | 146 | 791 | 3012 | 43367 | 0.7983 | 0.9936 | 0.8325 | 0.3726 | – | – | 2.6060 |
| x360-forza-horizon-2-prototype | default | 1.0000 | 47 | 26 | 862 | 3277 | 37898 | 0.9510 | 0.9989 | 0.8060 | 0.3429 | – | – | 5.9740 |
| x360-forza-horizon-2-prototype | baseline-off | 0.9980 | 176 | 90 | 863 | 3277 | 37696 | 0.9500 | 0.9989 | 0.8040 | 0.3421 | – | – | 4.4930 |
