# Combined gate compiler_rules_20261012

## m21-001 (7 images)

Status pass, failures none. `without GP-7003` = the same tree with the previous `ghidra_opt` (15396033...). `earlier tree` = the 2026-10-12 master-trial base arm (`ghidra_opt` dbd7e74b, before the PS2 discovery work); Ps2Precision's figure is the capcom row it recorded.

| image | recall | precision | size exact | without GP-7003 recall / precision | earlier tree recall / precision | Ps2Precision recall / precision |
|---|---|---|---|---|---|---|
| gba-pokeemerald | 0.9761 | 0.9972 | 15421 | - | 0.9761 / 0.9972 | - |
| nds-pokeheartgold-arm9 | 0.9735 | 0.9984 | 9888 | - | 0.9735 / 0.9984 | - |
| ps2-capcom-fighting-evolution | 0.9741 | 0.9945 | 8548 | - | 0.9652 / 0.9954 | 0.9741 / 0.9945 |
| ps2-dungeon-game | 0.9872 | 0.9835 | 751 | - | 0.9885 / 0.9835 | - |
| psx-darkstalkers-3 | 0.9878 | 0.3663 | 0 | - | 0.9866 / 0.3660 | - |
| psv-need-for-speed-most-wanted | 0.9734 | 0.9719 | 16304 | - | 0.9734 / 0.9719 | - |
| x360-black-ops-2 | 0.9833 | 0.9964 | 0 | - | 0.9833 / 0.9964 | - |

## m22-002 (PS2 C match, romwright layer, context variant, 200 functions)

Each row: exact / compiled / mean percent. `frozen` = the report the lane's last owner wrote (`m22-ps2_p4*.json`: Ps2CMatch's 55 / 76.624, 57 / 78.321, 106 / 86.406); RustStructure measured 55 / 76.976 on lane 1 with the same code (its tree carried other agents' work).

| lane | frozen | this build | delta exact / compiled / mean | paired better / worse / same | exact gained / lost |
|---|---|---|---|---|---|
| MWCC seed 20261010 | 55 / 192 / 76.624 | 55 / 193 / 76.976 | +0 / +1 / +0.352 | 1 / 1 / 198 | 0 / 0 |
| MWCC seed 20261011 | 57 / 194 / 78.321 | 57 / 194 / 78.321 | +0 / +0 / +0.000 | 0 / 0 / 200 | 0 / 0 |
| ee-gcc seed 20261010 | 106 / 197 / 86.406 | 106 / 197 / 86.406 | +0 / +0 / +0.000 | 0 / 0 / 200 | 0 / 0 |

Functions whose percent moved:

- MWCC seed 20261010, worse: `func_001e7080` 001e7080 96.60 -> 94.62 %
- MWCC seed 20261010, better: `func_0038d9f0` 0038d9f0 0.00 -> 72.30 %

## PS2 decompile success on the wave's samples (`ps2_decompile_success.py`, 11 projects)

| game | this build | RustStructure (handoff default) | Ps2CMatch (after) |
|---|---|---|---|
| ps2-dark-chronicle | 969 / 969 | 969 / 969 | 969 / 969 |
| ps2-dark-chronicle-symtab | 962 / 962 | 962 / 962 | 962 / 962 |
| ps2-dark-cloud | 936 / 937 | 936 / 937 | 936 / 937 |
| ps2-dark-cloud-symtab | 940 / 940 | 940 / 940 | 940 / 940 |
| ps2-digital-devil-saga | 977 / 977 | 977 / 977 | 977 / 977 |
| ps2-fatal-frame | 942 / 942 | 942 / 942 | 942 / 942 |
| ps2-fatal-frame-symtab | 940 / 940 | 940 / 940 | 940 / 940 |
| ps2-god-hand | 980 / 980 | 980 / 980 | 980 / 980 |
| ps2-persona-4 | 974 / 975 | 974 / 975 | 974 / 975 |
| ps2-ratchet-clank | 861 / 861 | 859 / 861 | 860 / 861 |
| ps2-ratchet-clank-pal | 859 / 859 | 858 / 859 | 858 / 859 |
| all | 10340 / 10342 | 10337 / 10342 | 10338 / 10342 |

Failed functions (`*` = also failing in RustStructure's run):

- * ps2-dark-cloud 01db08a0: native runtime: native runtime: execution deadline exceeded
- * ps2-persona-4 002be530: native runtime: native runtime: execution deadline exceeded

## PS2 wave (8 games and symtab variants, `--corpus-wave --stock`, n = 500, seeds 1,2)

Tools fingerprint `d1f2cf0f0a648b08` against `8089735f6fb1f18e` (Ps2Precision's `console_research_wave_20261011_ps2_precision`, whose success column is 0.0: the printer and `ghidra_opt` disagreed on the IR version, so its decompile numbers are not a baseline; recall and precision are).

| image | status | decompiled / sampled | success | recall | vs frozen | precision | vs frozen | gotos / labels | frozen gotos / labels |
|---|---|---|---|---|---|---|---|---|---|
| ps2-dark-chronicle | ran | 969 / 969 | 1.0000 | 0.9987 | +0.0000 | 0.9963 | +0.0000 | 49 / 27 | 0 / 0 |
| ps2-dark-chronicle-symtab | ran | 962 / 962 | 1.0000 | 1.0000 | +0.0000 | 0.9973 | +0.0000 | 84 / 41 | 0 / 0 |
| ps2-dark-cloud | ran | 936 / 937 | 0.9989 | 0.9988 | +0.0000 | 0.9907 | +0.0000 | 48 / 21 | 0 / 0 |
| ps2-dark-cloud-symtab | ran | 940 / 940 | 1.0000 | 0.9995 | +0.0000 | 0.9448 | +0.0000 | 80 / 39 | 0 / 0 |
| ps2-digital-devil-saga | ran | 977 / 977 | 1.0000 | 0.9974 | +0.0000 | 0.9987 | +0.0000 | 73 / 43 | 0 / 0 |
| ps2-fatal-frame | ran | 942 / 942 | 1.0000 | 0.9958 | +0.0000 | 0.9993 | +0.0000 | 247 / 93 | 0 / 0 |
| ps2-fatal-frame-symtab | ran | 940 / 940 | 1.0000 | 1.0000 | +0.0000 | 0.9998 | +0.0000 | 263 / 105 | 0 / 0 |
| ps2-god-hand | ran | 980 / 980 | 1.0000 | 0.9976 | +0.0000 | 0.9943 | +0.0000 | 186 / 95 | 0 / 0 |
| ps2-persona-4 | ran | 974 / 975 | 0.9990 | 0.9992 | +0.0000 | 0.9967 | +0.0000 | 101 / 80 | 0 / 0 |
| ps2-ratchet-clank | ran | 861 / 861 | 1.0000 | 0.9281 | +0.0000 | 0.9965 | +0.0000 | 226 / 117 | 0 / 0 |
| ps2-ratchet-clank-pal | ran | 859 / 859 | 1.0000 | 0.9276 | +0.0000 | 0.9947 | +0.0000 | 230 / 97 | 0 / 0 |

Default against baseline-off (this build):

| image | baseline-off recall | default recall | baseline-off precision | default precision | verdict |
|---|---|---|---|---|---|
| ps2-dark-chronicle | 0.9987 | 0.9987 | 0.9962 | 0.9963 | helps |
| ps2-dark-chronicle-symtab | 1.0000 | 1.0000 | 0.9972 | 0.9973 | helps |
| ps2-dark-cloud | 0.9988 | 0.9988 | 0.9907 | 0.9907 | helps |
| ps2-dark-cloud-symtab | 0.9995 | 0.9995 | 0.9448 | 0.9448 | helps |
| ps2-digital-devil-saga | 0.9973 | 0.9974 | 0.9762 | 0.9987 | helps |
| ps2-fatal-frame | 0.9958 | 0.9958 | 0.9927 | 0.9993 | helps |
| ps2-fatal-frame-symtab | 1.0000 | 1.0000 | 0.9984 | 0.9998 | helps |
| ps2-god-hand | 0.9976 | 0.9976 | 0.8815 | 0.9943 | helps |
| ps2-persona-4 | 0.9992 | 0.9992 | 0.9961 | 0.9967 | helps |
| ps2-ratchet-clank | 0.9281 | 0.9281 | 0.9953 | 0.9965 | helps |
| ps2-ratchet-clank-pal | 0.9276 | 0.9276 | 0.9935 | 0.9947 | helps |

## gc / n64 / gba / nds / psp decompile success and discovery (`--corpus-wave`, default, n = 500, seeds 1,2)

Frozen = `console_research_wave_20261010` (tools `5d47c57fe192c622`; the last wave that ran these images).

| image | status | decompiled / sampled | success | recall | vs frozen | precision | vs frozen | gotos / labels | frozen gotos / labels |
|---|---|---|---|---|---|---|---|---|---|
| gba-kh-chain-of-memories | ran | 961 / 961 | 1.0000 | 0.9582 | +0.0000 | 0.9640 | +0.0000 | 94 / 44 | 68 / 36 |
| gc-pikmin-2 | ran | 986 / 986 | 1.0000 | 0.9998 | +0.0000 | 0.9984 | +0.0000 | 59 / 31 | 39 / 18 |
| n64-super-mario-64 | ran | 923 / 923 | 1.0000 | 0.9974 | +0.0000 | 0.9053 | +0.0000 | 15 / 4 | 15 / 4 |
| nds-kh-358-2-days | ran | 987 / 987 | 1.0000 | 0.8863 | +0.0000 | 0.9922 | +0.0000 | 55 / 19 | 24 / 10 |
| psp-hot-pixel | ran | 940 / 940 | 1.0000 | 0.8884 | +0.0001 | 0.9057 | +0.0096 | 614 / 312 | 585 / 294 |
| psp-melodie | ran | 851 / 851 | 1.0000 | 0.9605 | +0.0000 | 0.9477 | +0.0495 | 114 / 54 | 183 / 81 |
| psp-pac-man-rally | ran | 862 / 862 | 1.0000 | 0.9074 | +0.0002 | 0.9280 | +0.0245 | 61 / 28 | 73 / 36 |
| psp-psp-camera-01 | ran | 938 / 938 | 1.0000 | 0.9597 | +0.0140 | 0.9585 | -0.0015 | 48 / 22 | 61 / 21 |
| psp-tetris | ran | 939 / 939 | 1.0000 | 0.9876 | +0.0491 | 0.9671 | -0.0039 | 105 / 65 | 114 / 66 |

PSP at `-n 200` (Ps2Precision's measurement of 2026-10-12, overflow-checked build):

| image | decompiled | success | recall | Ps2Precision recall | precision | Ps2Precision precision |
|---|---|---|---|---|---|---|
| psp-hot-pixel | 386 | 0.9974 | 0.8884 | 0.8884 | 0.9057 | 0.9057 |
| psp-melodie | 312 | 1.0000 | 0.9605 | 0.9605 | 0.9477 | 0.9477 |
| psp-pac-man-rally | 292 | 1.0000 | 0.9074 | 0.9074 | 0.9280 | 0.9280 |
| psp-psp-camera-01 | 389 | 1.0000 | 0.9597 | 0.9597 | 0.9585 | 0.9585 |
| psp-tetris | 362 | 1.0000 | 0.9876 | 0.9876 | 0.9671 | 0.9671 |

## What GP-7003 changes on four images (same tree, build with and without it)

not run

