# Console research wave (2026-10-10T04:29:14+00:00)

Tools fingerprint `4fea0a3df98a1a18`; sample n=500 per seed, seeds [1, 2]; combined = the union of the seeds' samples (rows deduplicated). Truth: `<corpus>/<id>/truth/{meta.json,functions.tsv}`. Headline metrics are the frozen ones (recall, precision, success rate, arity, type exact); `recall_verified` / `precision_verified` are the supplement over `verified=1` rows (docs/console-research.md).

## Images

| id | game | version | match | truth | compiler | linked % | truth fns | verified | nested (size 0) | scored modules | unplaced fns | stripped | status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| gc-melee | Super Smash Bros. Melee | GALE01 USA v1.02 (Redump/Vimm Rev 2) | True | decomp-symbols | MWCC GC/1.2.5n (94.7% of linked code bytes), GC/1.2.5 (4.8% of linked code bytes), GC/1.1p1 (0.5% of linked code bytes) | 100.0 | 19827 | 19827 | 0 (0) | main | 0 | False | ran |
| gc-wind-waker | The Legend of Zelda: The Wind Waker | GZLE01 USA Rev 0 | True | decomp-symbols | MWCC GC/1.3.2 (96.5% of linked code bytes), GC/1.2.5n (2.8% of linked code bytes), GC/1.3 (0.7% of linked code bytes) | 67.38 | 39315 | 28956 | 0 (0) | main, f_pc_profile_lst, d_a_agbsw0, d_a_andsw0 (+412) | 0 | False | ran |
| n64-ocarina-of-time | The Legend of Zelda: Ocarina of Time | USA NTSC 1.0 (zeldaret/oot VERSION=ntsc-1.0) | True | decomp-build | IDO 7.1 (game code) + IDO 5.3 (libultra, jpeg, libleo) | 100.0 | 13347 | 13347 | 0 (0) | main | 10252 | False | ran |
| nds-pokemon-platinum | Pokemon Platinum | USA (CPUE) revision 0 (builds with ROM_REVISION=0; repo default is rev 1) | True | decomp-build | mwccarm 2.0/sp2p2 (meson/cross.ini; mwasmarm/mwldarm via metroskrew 0.1.3; NitroSDK 4.2.30001, NitroSystem, NitroDWC, NitroWiFi built from source subprojects) | None | 34671 | 34669 | 0 (0) | main, ov1, ov4, ov5 (+113) | 0 | False | ran |
| ps2-dark-cloud | Dark Cloud | USA NTSC SCUS-97111 (v1.02 per repo) | True | decomp-symbols | MWCC PS2 2.3.3 (Metrowerks CodeWarrior for PS2; repo config compiler: MWCCPS2) | 100.0 | 4181 | 4181 | 0 (0) | main, title, dun | 0 | True | ran |
| ps2-dark-cloud-symtab | Dark Cloud | USA NTSC SCUS-97111 (v1.02 per repo) | True | decomp-symbols | MWCC PS2 2.3.3 (Metrowerks CodeWarrior for PS2; repo config compiler: MWCCPS2) | 100.0 | 4181 | 4181 | 0 (0) | main, title, dun | 0 | debug | ran |
| ps2-god-hand | God Hand | USA NTSC-U SLUS-21503 (disc 1.00) | True | decomp-symbols | SN ProDG ee-gcc 2.95.3 (matched TUs) + EE GCC 2.96 (dvp-as, ee-ld); SN small-data (.sndata) | 43.53 | 10091 | 7946 | 0 (0) | main | 0 | False | ran |
| psp-hot-pixel | Hot Pixel | unspecified (cognac_release.prx) | True | dwarf | GNU C/C++ 3.3.6+allegrex-2.2.2-psp-1.9.2 -g (372 C + 39 C++ CUs; 8 CUs psp-1.12.1.internal) | 100.0 | 9983 | 9983 | 3 (0) | main | 0 | True | ran |
| psp-hot-pixel-symtab | Hot Pixel | unspecified (cognac_release.prx) | True | dwarf | GNU C/C++ 3.3.6+allegrex-2.2.2-psp-1.9.2 -g (372 C + 39 C++ CUs; 8 CUs psp-1.12.1.internal) | 100.0 | 9983 | 9983 | 3 (0) | main | 0 | debug | ran |
| psp-melodie | Melodie | Unreleased, 2005-09-02 | True | dwarf | GNU C 3.3.3+allegrex-2.2.2-psp-1.6.1.internal -g (DW_AT_producer) | 100.0 | 3242 | 3242 | 0 (0) | main | 0 | True | ran |
| psp-melodie-symtab | Melodie | Unreleased, 2005-09-02 | True | dwarf | GNU C 3.3.3+allegrex-2.2.2-psp-1.6.1.internal -g (DW_AT_producer) | 100.0 | 3242 | 3242 | 0 (0) | main | 0 | debug | ran |
| psp-tetris | Tetris | USA, 2009-09-04 build | True | dwarf | Metrowerks CodeWarrior for PSP, MW MIPS C Compiler 2.4.1.01 (.comment); DWARF 1 in MIPS_DEBUG .debug | 100.0 | 8513 | 8513 | 0 (0) | main | 0 | True | ran |
| psp-tetris-symtab | Tetris | USA, 2009-09-04 build | True | dwarf | Metrowerks CodeWarrior for PSP, MW MIPS C Compiler 2.4.1.01 (.comment); DWARF 1 in MIPS_DEBUG .debug | 100.0 | 8513 | 8513 | 0 (0) | main | 0 | debug | ran |
| psx-rage-racer | Rage Racer | USA SLUS-004.03 | True | decomp-symbols | GCC 2.6.3 (cc1-psx-263) + maspsx, PsyQ libs | 100.0 | 1194 | 1194 | 0 (0) | main | 0 | False | ran |
| psx-silent-hill | Silent Hill | USA 1.1 SLUS-00707 | True | decomp-symbols | GCC 2.7.2-cdk + GCC 2.8.1 (PsyQ) + maspsx | 99.99 | 7042 | 7025 | 0 (0) | main, BODYPROG, MAP0_S00, MAP0_S01 (+46) | 0 | False | ran |
| wii-super-mario-galaxy | Super Mario Galaxy | RMGE01 USA Rev 0 | True | decomp-symbols | MWCC GC/3.0a3 (95.0% of linked code bytes), GC/3.0a5.2 (3.9% of linked code bytes), GC/2.7 (0.8% of linked code bytes), GC/3.0a3.2 (0.1% of linked code bytes), GC/3.0a5 (0.1% of linked code bytes) | 55.53 | 41993 | 24524 | 0 (0) | main | 0 | False | ran |
| x360-amped-3 | AMPED 3 | 2005-10-15 default build (PyroXenon Release Final Xenon) | True | pdb | Microsoft (R) Optimizing Compiler 14.0.1863 (S_COMPILE3 in PDB); linker 8.0 (pre-release Xenon toolchain) | 100.0 | 36152 | 36152 | 14740 (14740) |  |  |  | error: import failed: error: native: xex: PE image has no sections |
| x360-burnout-crash | Burnout Crash | 2011-03-01 Release (CRASH_X360_RELEASE.DLL.XEX) | True | pdb | Microsoft (R) Optimizing Compiler 16.0.11886 (S_COMPILE3); linker 10.0; plus MASM 10.0.11886 | 100.0 | 10961 | 10961 | 20 (20) | main | 0 | False | ran |

## gc

| game | tool | recall | precision | success | arity | type exact | recall (verified) | precision (verified) | sampled |
|---|---|---|---|---|---|---|---|---|---|
| gc-melee | default | 0.9996 | 0.9992 | 1.0000 | – | – | 0.9996 | 0.9993 | 988 |
| gc-melee | baseline-off | 0.9996 | 0.9968 | 1.0000 | – | – | 0.9996 | 0.9969 | 988 |
| gc-melee | stock Ghidra | 0.8559 | 0.9992 | 1.0000 | – | – | 0.8559 | 0.9992 | 988 |
| gc-wind-waker | default | 0.9831 | 0.9977 | 1.0000 | – | – | 0.9831 | 0.9992 | 997 |
| gc-wind-waker | baseline-off | 0.9831 | 0.9445 | 1.0000 | – | – | 0.9831 | 0.9559 | 997 |
| gc-wind-waker | stock Ghidra | 0.8560 | 0.9957 | 1.0000 | – | – | 0.8502 | 0.9989 | 321 |
| gc-wind-waker | default (main module only) | 0.9891 | 0.9963 | 1.0000 | – | – | 0.9941 | 0.9997 | 997 |

**Sign tests, gc**

| comparison | games | wins | losses | ties | one-sided p |
|---|---|---|---|---|---|
| recall vs baseline-off | 2 | 0 | 0 | 2 | – |
| precision vs baseline-off | 2 | 1 | 0 | 1 | 0.5000 |
| success_rate vs baseline-off | 2 | 0 | 0 | 2 | – |
| recall_verified vs baseline-off | 2 | 0 | 0 | 2 | – |
| precision_verified vs baseline-off | 2 | 1 | 0 | 1 | 0.5000 |
| recall vs stock | 2 | 2 | 0 | 0 | 0.2500 |
| precision vs stock | 2 | 0 | 0 | 2 | – |
| recall_verified vs stock | 2 | 2 | 0 | 0 | 0.2500 |
| precision_verified vs stock | 2 | 0 | 0 | 2 | – |

## n64

| game | tool | recall | precision | success | arity | type exact | recall (verified) | precision (verified) | sampled |
|---|---|---|---|---|---|---|---|---|---|
| n64-ocarina-of-time | default | 0.0446 | 0.9787 | 0.9928 | – | – | 0.0446 | 0.9787 | 138 |
| n64-ocarina-of-time | baseline-off | 0.0446 | 0.9787 | 0.9928 | – | – | 0.0446 | 0.9787 | 138 |
| n64-ocarina-of-time | stock Ghidra | 0.0384 | 0.9917 | 1.0000 | – | – | 0.0384 | 0.9917 | 138 |

**Sign tests, n64**

| comparison | games | wins | losses | ties | one-sided p |
|---|---|---|---|---|---|
| recall vs baseline-off | 1 | 0 | 0 | 1 | – |
| precision vs baseline-off | 1 | 0 | 0 | 1 | – |
| success_rate vs baseline-off | 1 | 0 | 0 | 1 | – |
| recall_verified vs baseline-off | 1 | 0 | 0 | 1 | – |
| precision_verified vs baseline-off | 1 | 0 | 0 | 1 | – |
| recall vs stock | 1 | 1 | 0 | 0 | 0.5000 |
| precision vs stock | 1 | 0 | 1 | 0 | 1.0000 |
| recall_verified vs stock | 1 | 1 | 0 | 0 | 0.5000 |
| precision_verified vs stock | 1 | 0 | 1 | 0 | 1.0000 |

## nds

| game | tool | recall | precision | success | arity | type exact | recall (verified) | precision (verified) | sampled |
|---|---|---|---|---|---|---|---|---|---|
| nds-pokemon-platinum | default | 0.8884 | 0.9977 | 1.0000 | – | – | 0.8884 | 0.9995 | 994 |
| nds-pokemon-platinum | baseline-off | 0.8478 | 0.9975 | 0.9467 | – | – | 0.8478 | 0.9994 | 994 |
| nds-pokemon-platinum | stock Ghidra | 0.8500 | 0.9939 | 1.0000 | – | – | 0.8499 | 0.9996 | 351 |
| nds-pokemon-platinum | default (main module only) | 0.9755 | 0.9943 | 1.0000 | – | – | 0.9755 | 0.9995 | 994 |

**Sign tests, nds**

| comparison | games | wins | losses | ties | one-sided p |
|---|---|---|---|---|---|
| recall vs baseline-off | 1 | 1 | 0 | 0 | 0.5000 |
| precision vs baseline-off | 1 | 0 | 0 | 1 | – |
| success_rate vs baseline-off | 1 | 1 | 0 | 0 | 0.5000 |
| recall_verified vs baseline-off | 1 | 1 | 0 | 0 | 0.5000 |
| precision_verified vs baseline-off | 1 | 0 | 0 | 1 | – |
| recall vs stock | 1 | 1 | 0 | 0 | 0.5000 |
| precision vs stock | 1 | 0 | 0 | 1 | – |
| recall_verified vs stock | 1 | 1 | 0 | 0 | 0.5000 |
| precision_verified vs stock | 1 | 0 | 0 | 1 | – |

## ps2

| game | tool | recall | precision | success | arity | type exact | recall (verified) | precision (verified) | sampled |
|---|---|---|---|---|---|---|---|---|---|
| ps2-dark-cloud | default | 0.9840 | 0.9906 | 0.9989 | – | – | 0.9840 | 0.9990 | 934 |
| ps2-dark-cloud | baseline-off | 0.9830 | 0.9930 | 0.9979 | – | – | 0.9830 | 0.9990 | 934 |
| ps2-dark-cloud | stock Ghidra | 0.9173 | 0.9850 | 1.0000 | – | – | 0.9173 | 0.9856 | 884 |
| ps2-dark-cloud | default (main module only) | 0.9835 | 0.9905 | 0.9989 | – | – | 0.9835 | 0.9990 | 934 |
| ps2-god-hand | default | 0.9709 | 0.8950 | 0.9979 | – | – | 0.9664 | 0.9938 | 968 |
| ps2-god-hand | baseline-off | 0.9706 | 0.6375 | 0.9990 | – | – | 0.9660 | 0.7708 | 968 |
| ps2-god-hand | stock Ghidra | 0.9117 | 0.9565 | 0.9990 | – | – | 0.8919 | 1.0000 | 968 |

**Sign tests, ps2**

| comparison | games | wins | losses | ties | one-sided p |
|---|---|---|---|---|---|
| recall vs baseline-off | 2 | 0 | 0 | 2 | – |
| precision vs baseline-off | 2 | 1 | 0 | 1 | 0.5000 |
| success_rate vs baseline-off | 2 | 0 | 0 | 2 | – |
| recall_verified vs baseline-off | 2 | 0 | 0 | 2 | – |
| precision_verified vs baseline-off | 2 | 1 | 0 | 1 | 0.5000 |
| recall vs stock | 2 | 2 | 0 | 0 | 0.2500 |
| precision vs stock | 2 | 1 | 1 | 0 | 0.7500 |
| recall_verified vs stock | 2 | 2 | 0 | 0 | 0.2500 |
| precision_verified vs stock | 2 | 1 | 1 | 0 | 0.7500 |

## psp

| game | tool | recall | precision | success | arity | type exact | recall (verified) | precision (verified) | sampled |
|---|---|---|---|---|---|---|---|---|---|
| psp-hot-pixel | default | 0.8883 | 0.8961 | 1.0000 | 0.8628 | 0.3464 | 0.8883 | 0.9201 | 940 |
| psp-hot-pixel | baseline-off | 0.8880 | 0.8270 | 1.0000 | 0.8628 | 0.3464 | 0.8880 | 0.8474 | 940 |
| psp-hot-pixel | stock Ghidra | 0.5763 | 0.9633 | 1.0000 | 0.8638 | 0.3164 | 0.5763 | 1.0000 | 940 |
| psp-melodie | default | 0.9605 | 0.8982 | 1.0000 | 0.9146 | 0.7025 | 0.9605 | 0.9276 | 851 |
| psp-melodie | baseline-off | 0.9605 | 0.7828 | 1.0000 | 0.9146 | 0.7025 | 0.9605 | 0.8051 | 851 |
| psp-melodie | stock Ghidra | 0.5126 | 0.9640 | 1.0000 | 0.9146 | 0.6736 | 0.5126 | 0.9982 | 851 |
| psp-tetris | default | 0.9385 | 0.9710 | 1.0000 | 0.7714 | 0.5811 | 0.9385 | 0.9947 | 935 |
| psp-tetris | baseline-off | 0.9384 | 0.9025 | 1.0000 | 0.7714 | 0.5811 | 0.9384 | 0.9230 | 935 |
| psp-tetris | stock Ghidra | 0.5079 | 0.9579 | 1.0000 | 0.8000 | 0.4868 | 0.5079 | 1.0000 | 935 |

**Sign tests, psp**

| comparison | games | wins | losses | ties | one-sided p |
|---|---|---|---|---|---|
| recall vs baseline-off | 3 | 0 | 0 | 3 | – |
| precision vs baseline-off | 3 | 3 | 0 | 0 | 0.1250 |
| success_rate vs baseline-off | 3 | 0 | 0 | 3 | – |
| arity_accuracy vs baseline-off | 3 | 0 | 0 | 3 | – |
| type_exact_rate vs baseline-off | 3 | 0 | 0 | 3 | – |
| recall_verified vs baseline-off | 3 | 0 | 0 | 3 | – |
| precision_verified vs baseline-off | 3 | 3 | 0 | 0 | 0.1250 |
| recall vs stock | 3 | 3 | 0 | 0 | 0.1250 |
| precision vs stock | 3 | 1 | 2 | 0 | 0.8750 |
| arity_accuracy vs stock | 3 | 0 | 1 | 2 | 1.0000 |
| type_exact_rate vs stock | 3 | 3 | 0 | 0 | 0.1250 |
| recall_verified vs stock | 3 | 3 | 0 | 0 | 0.1250 |
| precision_verified vs stock | 3 | 0 | 3 | 0 | 1.0000 |

## psx

| game | tool | recall | precision | success | arity | type exact | recall (verified) | precision (verified) | sampled |
|---|---|---|---|---|---|---|---|---|---|
| psx-rage-racer | default | 0.9523 | 0.9948 | 1.0000 | – | – | 0.9523 | 0.9948 | 779 |
| psx-rage-racer | baseline-off | 0.9523 | 0.9948 | 1.0000 | – | – | 0.9523 | 0.9948 | 779 |
| psx-rage-racer | stock Ghidra | 0.8844 | 0.9944 | 0.9987 | – | – | 0.8844 | 0.9944 | 779 |
| psx-silent-hill | default | 0.9024 | 0.9879 | 1.0000 | – | – | 0.9023 | 0.9964 | 968 |
| psx-silent-hill | baseline-off | 0.9007 | 0.9874 | 0.9979 | – | – | 0.9006 | 0.9959 | 968 |
| psx-silent-hill | stock Ghidra | 0.8720 | 0.8558 | 1.0000 | – | – | 0.8702 | 0.9005 | 20 |
| psx-silent-hill | default (main module only) | 0.9953 | 0.8898 | 1.0000 | – | – | 0.9952 | 0.9000 | 968 |

**Sign tests, psx**

| comparison | games | wins | losses | ties | one-sided p |
|---|---|---|---|---|---|
| recall vs baseline-off | 2 | 0 | 0 | 2 | – |
| precision vs baseline-off | 2 | 0 | 0 | 2 | – |
| success_rate vs baseline-off | 2 | 0 | 0 | 2 | – |
| recall_verified vs baseline-off | 2 | 0 | 0 | 2 | – |
| precision_verified vs baseline-off | 2 | 0 | 0 | 2 | – |
| recall vs stock | 2 | 2 | 0 | 0 | 0.2500 |
| precision vs stock | 2 | 1 | 0 | 1 | 0.5000 |
| recall_verified vs stock | 2 | 2 | 0 | 0 | 0.2500 |
| precision_verified vs stock | 2 | 0 | 0 | 2 | – |

## wii

| game | tool | recall | precision | success | arity | type exact | recall (verified) | precision (verified) | sampled |
|---|---|---|---|---|---|---|---|---|---|
| wii-super-mario-galaxy | default | 0.8567 | 0.9985 | 1.0000 | – | – | 0.8603 | 0.9978 | 993 |
| wii-super-mario-galaxy | baseline-off | 0.8567 | 0.9981 | 1.0000 | – | – | 0.8602 | 0.9971 | 993 |
| wii-super-mario-galaxy | stock Ghidra | 0.8490 | 0.9987 | 1.0000 | – | – | 0.8531 | 0.9979 | 993 |

**Sign tests, wii**

| comparison | games | wins | losses | ties | one-sided p |
|---|---|---|---|---|---|
| recall vs baseline-off | 1 | 0 | 0 | 1 | – |
| precision vs baseline-off | 1 | 0 | 0 | 1 | – |
| success_rate vs baseline-off | 1 | 0 | 0 | 1 | – |
| recall_verified vs baseline-off | 1 | 0 | 0 | 1 | – |
| precision_verified vs baseline-off | 1 | 0 | 0 | 1 | – |
| recall vs stock | 1 | 1 | 0 | 0 | 0.5000 |
| precision vs stock | 1 | 0 | 0 | 1 | – |
| recall_verified vs stock | 1 | 1 | 0 | 0 | 0.5000 |
| precision_verified vs stock | 1 | 0 | 0 | 1 | – |

## x360

| game | tool | recall | precision | success | arity | type exact | recall (verified) | precision (verified) | sampled |
|---|---|---|---|---|---|---|---|---|---|
| x360-burnout-crash | default | 0.9958 | 0.9987 | 1.0000 | 0.2246 | 0.2819 | 0.9958 | 1.0000 | 601 |
| x360-burnout-crash | baseline-off | 0.9958 | 0.9987 | 1.0000 | 0.2246 | 0.2819 | 0.9958 | 1.0000 | 601 |
| x360-burnout-crash | stock Ghidra | 0.9952 | 0.9987 | 1.0000 | 0.2113 | 0.2787 | 0.9952 | 1.0000 | 601 |
| x360-amped-3 | **did not run** | – | – | – | – | – | – | – | error: import failed: error: native: xex: PE image has no sections |

**Sign tests, x360**

| comparison | games | wins | losses | ties | one-sided p |
|---|---|---|---|---|---|
| recall vs baseline-off | 1 | 0 | 0 | 1 | – |
| precision vs baseline-off | 1 | 0 | 0 | 1 | – |
| success_rate vs baseline-off | 1 | 0 | 0 | 1 | – |
| arity_accuracy vs baseline-off | 1 | 0 | 0 | 1 | – |
| type_exact_rate vs baseline-off | 1 | 0 | 0 | 1 | – |
| recall_verified vs baseline-off | 1 | 0 | 0 | 1 | – |
| precision_verified vs baseline-off | 1 | 0 | 0 | 1 | – |
| recall vs stock | 1 | 0 | 0 | 1 | – |
| precision vs stock | 1 | 0 | 0 | 1 | – |
| arity_accuracy vs stock | 1 | 1 | 0 | 0 | 0.5000 |
| type_exact_rate vs stock | 1 | 0 | 0 | 1 | – |
| recall_verified vs stock | 1 | 0 | 0 | 1 | – |
| precision_verified vs stock | 1 | 0 | 0 | 1 | – |

## All games

**Sign tests over all games**

| comparison | games | wins | losses | ties | one-sided p |
|---|---|---|---|---|---|
| recall vs baseline-off | 13 | 1 | 0 | 12 | 0.5000 |
| precision vs baseline-off | 13 | 5 | 0 | 8 | 0.0312 |
| success_rate vs baseline-off | 13 | 1 | 0 | 12 | 0.5000 |
| arity_accuracy vs baseline-off | 4 | 0 | 0 | 4 | – |
| type_exact_rate vs baseline-off | 4 | 0 | 0 | 4 | – |
| recall_verified vs baseline-off | 13 | 1 | 0 | 12 | 0.5000 |
| precision_verified vs baseline-off | 13 | 5 | 0 | 8 | 0.0312 |
| recall vs stock | 13 | 12 | 0 | 1 | 0.0002 |
| precision vs stock | 13 | 3 | 4 | 6 | 0.7734 |
| arity_accuracy vs stock | 4 | 1 | 1 | 2 | 0.7500 |
| type_exact_rate vs stock | 4 | 3 | 0 | 1 | 0.1250 |
| recall_verified vs stock | 13 | 12 | 0 | 1 | 0.0002 |
| precision_verified vs stock | 13 | 1 | 5 | 7 | 0.9844 |

## Supplement: symtab variants

The staged ELF with its symbol table kept and only DWARF removed (`<id>-symtab`). It isolates type/arity recovery from discovery: its discovery numbers are the symtab's and say nothing about discovery. Not in the per-platform tables or the sign tests.

| game | tool | recall | precision | success | arity | type exact | recall (verified) | precision (verified) | sampled |
|---|---|---|---|---|---|---|---|---|---|
| ps2-dark-cloud-symtab | default | 0.9995 | 0.9448 | 0.9989 | – | – | 0.9995 | 0.9995 | 940 |
| ps2-dark-cloud-symtab | baseline-off | 0.9995 | 0.9448 | 0.9989 | – | – | 0.9995 | 0.9995 | 940 |
| ps2-dark-cloud-symtab | stock Ghidra | 1.0000 | 0.9267 | 1.0000 | – | – | 1.0000 | 0.9818 | 884 |
| psp-hot-pixel-symtab | default | 1.0000 | 0.9140 | 0.9979 | 0.8484 | 0.3806 | 1.0000 | 0.9362 | 963 |
| psp-hot-pixel-symtab | baseline-off | 1.0000 | 0.8973 | 0.9990 | 0.8494 | 0.3816 | 1.0000 | 0.9187 | 963 |
| psp-hot-pixel-symtab | stock Ghidra | 1.0000 | 0.9763 | 1.0000 | 0.8411 | 0.3677 | 1.0000 | 1.0000 | 963 |
| psp-melodie-symtab | default | 1.0000 | 0.9617 | 1.0000 | 0.8909 | 0.7344 | 1.0000 | 0.9942 | 846 |
| psp-melodie-symtab | baseline-off | 1.0000 | 0.9362 | 1.0000 | 0.8909 | 0.7344 | 1.0000 | 0.9669 | 846 |
| psp-melodie-symtab | stock Ghidra | 1.0000 | 0.9681 | 1.0000 | 0.9818 | 0.7574 | 1.0000 | 1.0000 | 846 |
| psp-tetris-symtab | default | 1.0000 | 0.9772 | 0.9883 | 0.0286 | 0.0132 | 1.0000 | 0.9998 | 938 |
| psp-tetris-symtab | baseline-off | 1.0000 | 0.9768 | 0.9883 | 0.0286 | 0.0132 | 1.0000 | 0.9993 | 938 |
| psp-tetris-symtab | stock Ghidra | 1.0000 | 0.9776 | 0.9883 | 0.8000 | 0.4868 | 1.0000 | 1.0000 | 938 |

The sign tests are a supplement. A game is a win when `default` beats the other tool by at least 0.5 pp (the harness's materiality floor), a loss when it trails by as much, else a tie (dropped). One-sided p = P(X >= wins), X ~ Binomial(wins + losses, 1/2). Games whose meta.json says `version_match: false` are in the supplement table only. vs stock uses discovery on the main module only (the module stock was run on).

## Per seed (default vs baseline-off)

| game | seed | config | recall | precision | success | arity | type exact | sampled |
|---|---|---|---|---|---|---|---|---|
| gc-melee | 1 | default | 0.9996 | 0.9992 | 1.0000 | – | – | 500 |
| gc-melee | 1 | baseline-off | 0.9996 | 0.9968 | 1.0000 | – | – | 500 |
| gc-melee | 2 | default | 0.9996 | 0.9992 | 1.0000 | – | – | 500 |
| gc-melee | 2 | baseline-off | 0.9996 | 0.9968 | 1.0000 | – | – | 500 |
| gc-wind-waker | 1 | default | 0.9831 | 0.9977 | 1.0000 | – | – | 500 |
| gc-wind-waker | 1 | baseline-off | 0.9831 | 0.9445 | 1.0000 | – | – | 500 |
| gc-wind-waker | 2 | default | 0.9831 | 0.9977 | 1.0000 | – | – | 500 |
| gc-wind-waker | 2 | baseline-off | 0.9831 | 0.9445 | 1.0000 | – | – | 500 |
| n64-ocarina-of-time | 1 | default | 0.0446 | 0.9787 | 0.9928 | – | – | 138 |
| n64-ocarina-of-time | 1 | baseline-off | 0.0446 | 0.9787 | 0.9928 | – | – | 138 |
| n64-ocarina-of-time | 2 | default | 0.0446 | 0.9787 | 0.9928 | – | – | 138 |
| n64-ocarina-of-time | 2 | baseline-off | 0.0446 | 0.9787 | 0.9928 | – | – | 138 |
| nds-pokemon-platinum | 1 | default | 0.8884 | 0.9977 | 1.0000 | – | – | 500 |
| nds-pokemon-platinum | 1 | baseline-off | 0.8478 | 0.9975 | 0.9440 | – | – | 500 |
| nds-pokemon-platinum | 2 | default | 0.8884 | 0.9977 | 1.0000 | – | – | 500 |
| nds-pokemon-platinum | 2 | baseline-off | 0.8478 | 0.9975 | 0.9500 | – | – | 500 |
| ps2-dark-cloud | 1 | default | 0.9840 | 0.9906 | 1.0000 | – | – | 500 |
| ps2-dark-cloud | 1 | baseline-off | 0.9830 | 0.9930 | 1.0000 | – | – | 500 |
| ps2-dark-cloud | 2 | default | 0.9840 | 0.9906 | 0.9980 | – | – | 500 |
| ps2-dark-cloud | 2 | baseline-off | 0.9830 | 0.9930 | 0.9960 | – | – | 500 |
| ps2-dark-cloud-symtab | 1 | default | 0.9995 | 0.9448 | 0.9980 | – | – | 500 |
| ps2-dark-cloud-symtab | 1 | baseline-off | 0.9995 | 0.9448 | 0.9980 | – | – | 500 |
| ps2-dark-cloud-symtab | 2 | default | 0.9995 | 0.9448 | 1.0000 | – | – | 500 |
| ps2-dark-cloud-symtab | 2 | baseline-off | 0.9995 | 0.9448 | 1.0000 | – | – | 500 |
| ps2-god-hand | 1 | default | 0.9709 | 0.8950 | 1.0000 | – | – | 500 |
| ps2-god-hand | 1 | baseline-off | 0.9706 | 0.6375 | 1.0000 | – | – | 500 |
| ps2-god-hand | 2 | default | 0.9709 | 0.8950 | 0.9960 | – | – | 500 |
| ps2-god-hand | 2 | baseline-off | 0.9706 | 0.6375 | 0.9980 | – | – | 500 |
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
| psp-tetris | 1 | default | 0.9385 | 0.9710 | 1.0000 | 0.7714 | 0.5811 | 500 |
| psp-tetris | 1 | baseline-off | 0.9384 | 0.9025 | 1.0000 | 0.7714 | 0.5811 | 500 |
| psp-tetris | 2 | default | 0.9385 | 0.9710 | 1.0000 | 0.7714 | 0.5811 | 500 |
| psp-tetris | 2 | baseline-off | 0.9384 | 0.9025 | 1.0000 | 0.7714 | 0.5811 | 500 |
| psp-tetris-symtab | 1 | default | 1.0000 | 0.9772 | 0.9920 | 0.0286 | 0.0132 | 500 |
| psp-tetris-symtab | 1 | baseline-off | 1.0000 | 0.9768 | 0.9920 | 0.0286 | 0.0132 | 500 |
| psp-tetris-symtab | 2 | default | 1.0000 | 0.9772 | 0.9860 | 0.0286 | 0.0132 | 500 |
| psp-tetris-symtab | 2 | baseline-off | 1.0000 | 0.9768 | 0.9860 | 0.0286 | 0.0132 | 500 |
| psx-rage-racer | 1 | default | 0.9523 | 0.9948 | 1.0000 | – | – | 500 |
| psx-rage-racer | 1 | baseline-off | 0.9523 | 0.9948 | 1.0000 | – | – | 500 |
| psx-rage-racer | 2 | default | 0.9523 | 0.9948 | 1.0000 | – | – | 500 |
| psx-rage-racer | 2 | baseline-off | 0.9523 | 0.9948 | 1.0000 | – | – | 500 |
| psx-silent-hill | 1 | default | 0.9024 | 0.9879 | 1.0000 | – | – | 500 |
| psx-silent-hill | 1 | baseline-off | 0.9007 | 0.9874 | 0.9980 | – | – | 500 |
| psx-silent-hill | 2 | default | 0.9024 | 0.9879 | 1.0000 | – | – | 500 |
| psx-silent-hill | 2 | baseline-off | 0.9007 | 0.9874 | 0.9980 | – | – | 500 |
| wii-super-mario-galaxy | 1 | default | 0.8567 | 0.9985 | 1.0000 | – | – | 500 |
| wii-super-mario-galaxy | 1 | baseline-off | 0.8567 | 0.9981 | 1.0000 | – | – | 500 |
| wii-super-mario-galaxy | 2 | default | 0.8567 | 0.9985 | 1.0000 | – | – | 500 |
| wii-super-mario-galaxy | 2 | baseline-off | 0.8567 | 0.9981 | 1.0000 | – | – | 500 |
| x360-burnout-crash | 1 | default | 0.9958 | 0.9987 | 1.0000 | 0.2320 | 0.2851 | 500 |
| x360-burnout-crash | 1 | baseline-off | 0.9958 | 0.9987 | 1.0000 | 0.2320 | 0.2851 | 500 |
| x360-burnout-crash | 2 | default | 0.9958 | 0.9987 | 1.0000 | 0.2220 | 0.2723 | 500 |
| x360-burnout-crash | 2 | baseline-off | 0.9958 | 0.9987 | 1.0000 | 0.2220 | 0.2723 | 500 |


# Console research components (2026-10-10T04:29:14+00:00)

Tools fingerprint `4fea0a3df98a1a18`; sample n=500 seeds=[1, 2]. Thresholds: rates 0.5 pp, counts 1% of the reference (min 1), counts over functions both configurations decompiled. Output is deterministic: deltas are exact. `~` marks a change below the threshold.

## Verdict matrix (component effect vs its reference)

| component | config | reference | gc-melee | gc-wind-waker | n64-ocarina-of-time | nds-pokemon-platinum | ps2-dark-cloud | ps2-dark-cloud-symtab | ps2-god-hand | psp-hot-pixel | psp-hot-pixel-symtab | psp-melodie | psp-melodie-symtab | psp-tetris | psp-tetris-symtab | psx-rage-racer | psx-silent-hill | wii-super-mario-galaxy | x360-burnout-crash |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| all research (default vs baseline-off) | default | baseline-off | helps | helps | helps | helps | helps | mixed | helps | helps | helps | helps | helps | helps | helps | helps | helps | helps | helps |

## Deltas

| component | image | verdict | vs reference | vs default | vs baseline-off |
|---|---|---|---|---|---|
| all research (default vs baseline-off) | gc-melee | helps | precision +0.2pp~, gotos -62, labels -25, irregular_functions -2~, lines +66, precision_verified +0.2pp | no change | precision +0.2pp~, gotos -62, labels -25, irregular_functions -2~, lines +66, precision_verified +0.2pp |
| all research (default vs baseline-off) | gc-wind-waker | helps | precision +5.3pp, gotos -59, labels -26, lines +225, precision_verified +4.3pp | no change | precision +5.3pp, gotos -59, labels -26, lines +225, precision_verified +4.3pp |
| all research (default vs baseline-off) | n64-ocarina-of-time | helps | gotos -20, labels -11, irregular_functions -4, lines +16 | no change | gotos -20, labels -11, irregular_functions -4, lines +16 |
| all research (default vs baseline-off) | nds-pokemon-platinum | helps | recall +4.1pp, precision +0.0pp~, success_rate +5.3pp, gotos -45, labels -14, native_warnings +3~, lines +216, recall_verified +4.1pp, precision_verified +0.0pp | no change | recall +4.1pp, precision +0.0pp~, success_rate +5.3pp, gotos -45, labels -14, native_warnings +3~, lines +216, recall_verified +4.1pp, precision_verified +0.0pp |
| all research (default vs baseline-off) | ps2-dark-cloud | helps | recall +0.1pp~, precision -0.2pp~, success_rate +0.1pp~, gotos -64, labels -32, irregular_functions -5~, native_warnings +3~, text_warnings -1~, lines +516, recall_verified +0.1pp | no change | recall +0.1pp~, precision -0.2pp~, success_rate +0.1pp~, gotos -64, labels -32, irregular_functions -5~, native_warnings +3~, text_warnings -1~, lines +516, recall_verified +0.1pp |
| all research (default vs baseline-off) | ps2-dark-cloud-symtab | mixed | gotos -61, labels -30, irregular_functions -4~, native_warnings +8~, text_warnings +8, lines +284 | no change | gotos -61, labels -30, irregular_functions -4~, native_warnings +8~, text_warnings +8, lines +284 |
| all research (default vs baseline-off) | ps2-god-hand | helps | recall +0.0pp~, precision +25.8pp, success_rate -0.1pp~, gotos -314, labels -169, irregular_functions -6~, native_warnings -1~, text_warnings -1, lines +473, recall_verified +0.0pp, precision_verified +22.3pp | no change | recall +0.0pp~, precision +25.8pp, success_rate -0.1pp~, gotos -314, labels -169, irregular_functions -6~, native_warnings -1~, text_warnings -1, lines +473, recall_verified +0.0pp, precision_verified +22.3pp |
| all research (default vs baseline-off) | psp-hot-pixel | helps | recall +0.0pp~, precision +6.9pp, gotos -718, labels -437, irregular_functions -26, native_warnings +2~, text_warnings +2~, lines +1251, recall_verified +0.0pp, precision_verified +7.3pp | no change | recall +0.0pp~, precision +6.9pp, gotos -718, labels -437, irregular_functions -26, native_warnings +2~, text_warnings +2~, lines +1251, recall_verified +0.0pp, precision_verified +7.3pp |
| all research (default vs baseline-off) | psp-hot-pixel-symtab | helps | precision +1.7pp, success_rate -0.1pp~, gotos -750, labels -488, irregular_functions -23, native_warnings -2~, text_warnings -1~, lines +923, arity_accuracy -0.1pp~, type_exact_rate -0.1pp~, precision_verified +1.8pp | no change | precision +1.7pp, success_rate -0.1pp~, gotos -750, labels -488, irregular_functions -23, native_warnings -2~, text_warnings -1~, lines +923, arity_accuracy -0.1pp~, type_exact_rate -0.1pp~, precision_verified +1.8pp |
| all research (default vs baseline-off) | psp-melodie | helps | precision +11.5pp, gotos -148, labels -73, irregular_functions -12, lines +251, precision_verified +12.2pp | no change | precision +11.5pp, gotos -148, labels -73, irregular_functions -12, lines +251, precision_verified +12.2pp |
| all research (default vs baseline-off) | psp-melodie-symtab | helps | precision +2.5pp, gotos -130, labels -71, irregular_functions -9, lines +275, precision_verified +2.7pp | no change | precision +2.5pp, gotos -130, labels -71, irregular_functions -9, lines +275, precision_verified +2.7pp |
| all research (default vs baseline-off) | psp-tetris | helps | recall +0.0pp~, precision +6.9pp, gotos -211, labels -109, irregular_functions -10, lines +361, recall_verified +0.0pp, precision_verified +7.2pp | no change | recall +0.0pp~, precision +6.9pp, gotos -211, labels -109, irregular_functions -10, lines +361, recall_verified +0.0pp, precision_verified +7.2pp |
| all research (default vs baseline-off) | psp-tetris-symtab | helps | precision +0.0pp~, gotos -243, labels -115, irregular_functions -12, lines +351, precision_verified +0.1pp | no change | precision +0.0pp~, gotos -243, labels -115, irregular_functions -12, lines +351, precision_verified +0.1pp |
| all research (default vs baseline-off) | psx-rage-racer | helps | gotos -194, labels -102, irregular_functions -7, lines +309 | no change | gotos -194, labels -102, irregular_functions -7, lines +309 |
| all research (default vs baseline-off) | psx-silent-hill | helps | recall +0.2pp~, precision +0.1pp~, success_rate +0.2pp~, gotos -1065, labels -529, irregular_functions -29, lines +1512, recall_verified +0.2pp, precision_verified +0.1pp | no change | recall +0.2pp~, precision +0.1pp~, success_rate +0.2pp~, gotos -1065, labels -529, irregular_functions -29, lines +1512, recall_verified +0.2pp, precision_verified +0.1pp |
| all research (default vs baseline-off) | wii-super-mario-galaxy | helps | precision +0.0pp~, gotos -20, labels -9, native_warnings -1~, lines +6, recall_verified +0.0pp, precision_verified +0.1pp | no change | precision +0.0pp~, gotos -20, labels -9, native_warnings -1~, lines +6, recall_verified +0.0pp, precision_verified +0.1pp |
| all research (default vs baseline-off) | x360-burnout-crash | helps | gotos -107, labels -61, irregular_functions -1~, lines +179 | no change | gotos -107, labels -61, irregular_functions -1~, lines +179 |

## Absolute values

| image | config | success | gotos | labels | irregular | warnings | lines | recall | precision | arity | type exact | m22 sim | m22 standalone | median s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| gc-melee | default | 1.0000 | 61 | 32 | 714 | 2824 | 39986 | 0.9996 | 0.9992 | – | – | – | – | 2.9290 |
| gc-melee | baseline-off | 1.0000 | 123 | 57 | 716 | 2824 | 39920 | 0.9996 | 0.9968 | – | – | – | – | 3.0550 |
| gc-wind-waker | default | 1.0000 | 22 | 12 | 677 | 2535 | 37950 | 0.9831 | 0.9977 | – | – | – | – | 6.6050 |
| gc-wind-waker | baseline-off | 1.0000 | 81 | 38 | 677 | 2535 | 37725 | 0.9831 | 0.9445 | – | – | – | – | 7.5610 |
| n64-ocarina-of-time | default | 0.9928 | 7 | 4 | 93 | 278 | 3961 | 0.0446 | 0.9787 | – | – | – | – | 0.5140 |
| n64-ocarina-of-time | baseline-off | 0.9928 | 27 | 15 | 97 | 278 | 3945 | 0.0446 | 0.9787 | – | – | – | – | 0.6620 |
| nds-pokemon-platinum | default | 1.0000 | 13 | 8 | 772 | 2408 | 30454 | 0.8884 | 0.9977 | – | – | – | – | 1.0020 |
| nds-pokemon-platinum | baseline-off | 0.9467 | 58 | 22 | 739 | 2304 | 28837 | 0.8478 | 0.9975 | – | – | – | – | 0.9610 |
| ps2-dark-cloud | default | 0.9989 | 25 | 13 | 628 | 2572 | 45896 | 0.9840 | 0.9906 | – | – | – | – | 0.3670 |
| ps2-dark-cloud | baseline-off | 0.9979 | 89 | 45 | 633 | 2569 | 45376 | 0.9830 | 0.9930 | – | – | – | – | 0.3020 |
| ps2-dark-cloud-symtab | default | 0.9989 | 80 | 39 | 598 | 2396 | 53355 | 0.9995 | 0.9448 | – | – | – | – | 0.4590 |
| ps2-dark-cloud-symtab | baseline-off | 0.9989 | 141 | 69 | 602 | 2388 | 53071 | 0.9995 | 0.9448 | – | – | – | – | 0.5240 |
| ps2-god-hand | default | 0.9979 | 164 | 88 | 699 | 1967 | 40982 | 0.9709 | 0.8950 | – | – | – | – | 1.3900 |
| ps2-god-hand | baseline-off | 0.9990 | 627 | 330 | 706 | 2005 | 43580 | 0.9706 | 0.6375 | – | – | – | – | 1.3630 |
| psp-hot-pixel | default | 1.0000 | 585 | 294 | 710 | 2544 | 62975 | 0.8883 | 0.8961 | 0.8628 | 0.3464 | – | – | 1.1610 |
| psp-hot-pixel | baseline-off | 1.0000 | 1303 | 731 | 736 | 2542 | 61724 | 0.8880 | 0.8270 | 0.8628 | 0.3464 | – | – | 1.2370 |
| psp-hot-pixel-symtab | default | 0.9979 | 642 | 291 | 702 | 2390 | 61547 | 1.0000 | 0.9140 | 0.8484 | 0.3806 | – | – | 0.8520 |
| psp-hot-pixel-symtab | baseline-off | 0.9990 | 1614 | 896 | 726 | 2401 | 65264 | 1.0000 | 0.8973 | 0.8494 | 0.3816 | – | – | 0.8200 |
| psp-melodie | default | 1.0000 | 183 | 81 | 547 | 2107 | 47623 | 0.9605 | 0.8982 | 0.9146 | 0.7025 | – | – | 0.5830 |
| psp-melodie | baseline-off | 1.0000 | 331 | 154 | 559 | 2107 | 47372 | 0.9605 | 0.7828 | 0.9146 | 0.7025 | – | – | 0.3960 |
| psp-melodie-symtab | default | 1.0000 | 44 | 22 | 530 | 2028 | 48296 | 1.0000 | 0.9617 | 0.8909 | 0.7344 | – | – | 0.2570 |
| psp-melodie-symtab | baseline-off | 1.0000 | 174 | 93 | 539 | 2028 | 48021 | 1.0000 | 0.9362 | 0.8909 | 0.7344 | – | – | 0.2220 |
| psp-tetris | default | 1.0000 | 114 | 66 | 513 | 1439 | 40192 | 0.9385 | 0.9710 | 0.7714 | 0.5811 | – | – | 0.8010 |
| psp-tetris | baseline-off | 1.0000 | 325 | 175 | 523 | 1439 | 39831 | 0.9384 | 0.9025 | 0.7714 | 0.5811 | – | – | 0.6820 |
| psp-tetris-symtab | default | 0.9883 | 73 | 42 | 488 | 1315 | 39551 | 1.0000 | 0.9772 | 0.0286 | 0.0132 | – | – | 0.7010 |
| psp-tetris-symtab | baseline-off | 0.9883 | 316 | 157 | 500 | 1315 | 39200 | 1.0000 | 0.9768 | 0.0286 | 0.0132 | – | – | 0.5590 |
| psx-rage-racer | default | 1.0000 | 110 | 59 | 501 | 1664 | 41128 | 0.9523 | 0.9948 | – | – | – | – | 0.1610 |
| psx-rage-racer | baseline-off | 1.0000 | 304 | 161 | 508 | 1664 | 40819 | 0.9523 | 0.9948 | – | – | – | – | 0.0960 |
| psx-silent-hill | default | 1.0000 | 444 | 223 | 591 | 1856 | 70534 | 0.9024 | 0.9879 | – | – | – | – | 0.0570 |
| psx-silent-hill | baseline-off | 0.9979 | 1504 | 748 | 618 | 1848 | 68326 | 0.9007 | 0.9874 | – | – | – | – | 0.0540 |
| wii-super-mario-galaxy | default | 1.0000 | 30 | 12 | 777 | 3960 | 35726 | 0.8567 | 0.9985 | – | – | – | – | 2.7580 |
| wii-super-mario-galaxy | baseline-off | 1.0000 | 50 | 21 | 777 | 3961 | 35720 | 0.8567 | 0.9981 | – | – | – | – | 1.9240 |
| x360-burnout-crash | default | 1.0000 | 146 | 91 | 405 | 1268 | 30269 | 0.9958 | 0.9987 | 0.2246 | 0.2819 | – | – | 3.1500 |
| x360-burnout-crash | baseline-off | 1.0000 | 253 | 152 | 406 | 1268 | 30090 | 0.9958 | 0.9987 | 0.2246 | 0.2819 | – | – | 3.3830 |
