# Near-miss search (`romwright-cli match`) on the PS2 lanes (m22-003, and m22-002 where listed)

Generated 2026-10-14T19:34:46Z. Budget 24 variants per searched function; the plan is the product command's (`romwright-cli match --plan`), see docs/match.md. Every arm is a fresh import and a fresh work-dir snapshot; `ROMWRIGHT_NO_IMPORT_CACHE=1 ROMWRIGHT_NO_FACT_PACK=1`; ghidra_opt sha256 `486ace43c12e` (unchanged).

Scores are the lane harness's headline (`context`) compile: `exact` = same length and every byte equal outside relocation fields; `mean %` = objdiff `match_percent` (functionRelocDiffs=none) over all sampled functions, a function that does not compile counting 0. Only functions whose default print compiles and is not exact are searched; the retail bytes and the pinned compiler are the only oracle (no lane truth C is read by the search).

| lane | n | default exact / compiled / mean % | searched exact / compiled / mean % | searched functions | improved | newly exact | winners (improved functions) | decompiles | compiles | wall s default arm | wall s search arm |
|---|---|---|---|---|---|---|---|---|---|---|---|
| dds | 200 | 61 / 200 / 77.224 | 64 / 200 / 78.792 | 139 | 37 | 3 | datatype=off 13, structuring=none 10, maxref=1 6, structuring=none+datatype=off 2, maxref=1+datatype=off 2, structuring=none+adjacent=off+datatype=off 1, maxref=3 1, datatype=off+structuring=none 1, adjacent=off 1 | 2051 | 310 | 221 | 787 |
| rc | 200 | 26 / 200 / 68.158 | 27 / 200 / 70.380 | 174 | 52 | 1 | structuring=none 13, datatype=off 9, maxref=1 8, maxref=1+datatype=off 3, maxref=3 3, calls=cast 2, structuring=none+maxref=1 1, structuring=none+maxref=4 1, maxdup=3 1, maxref=1+adjacent=off 1, structuring=no_arm_order+maxref=1 1, structuring=none+copy=off 1, copy=off+datatype=off 1, maxdup=4+structuring=none 1, maxref=1+calls=cast 1, structuring=none+maxdup=3+datatype=off 1, structuring=none+dominant=off 1, maxdup=4 1, structuring=none+datatype=off 1, adjacent=off 1 | 2552 | 351 | 76 | 259 |
| p4 | 200 | 60 / 193 / 79.400 | 60 / 193 / 80.007 | 133 | 32 | 0 | maxref=1 14, datatype=off 7, structuring=none 6, adjacent=off 2, maxref=1+adjacent=off 1, dominant=off 1, maxdup=3 1 | 1940 | 271 | 434 | 793 |
| gh | 200 | 78 / 199 / 82.119 | 80 / 199 / 83.869 | 121 | 28 | 2 | structuring=none 10, datatype=off 9, maxref=1 4, datatype=off+maxref=1 2, maxref=3 1, structuring=none+maxref=1 1, structuring=none+datatype=off 1 | 1747 | 232 | 373 | 915 |
| ff | 200 | 21 / 195 / 61.753 | 24 / 195 / 64.178 | 174 | 53 | 3 | datatype=off 13, structuring=none 11, maxref=1 9, maxref=4 3, maxref=3+datatype=off 2, structuring=none+maxref=1 2, maxref=3 2, structuring=none+datatype=off 2, maxdup=3 1, adjacent=off+datatype=off 1, adjacent=off 1, datatype=off+maxdup=1+structuring=no_arm_order 1, dominant=off+datatype=off 1, calls=cast 1, maxdup=1 1, maxref=1+datatype=off 1, dominant=off 1 | 2578 | 437 | 172 | 736 |
| dc | 200 | 38 / 186 / 69.844 | 40 / 186 / 70.719 | 148 | 30 | 2 | maxref=1 14, datatype=off 5, calls=cast 3, adjacent=off 2, maxref=4 1, calls=cast+datatype=off 1, structuring=none 1, maxdup=1 1, maxdup=4 1, maxref=1+datatype=off 1 | 2120 | 271 | 635 | 2991 |
| dk | 200 | 29 / 189 / 75.561 | 31 / 189 / 76.387 | 160 | 46 | 2 | datatype=off 18, maxref=1 8, calls=cast 3, maxref=3 3, maxref=1+datatype=off 2, maxdup=3 2, adjacent=off+datatype=off 2, maxdup=3+datatype=off 2, dominant=off 1, adjacent=off 1, maxref=4+datatype=off 1, calls=cast+datatype=off 1, maxref=4 1, maxdup=1 1 | 2309 | 289 | 235 | 1036 |
| m22-002 MWCC seed 20261010 | 200 | 55 / 193 / 76.968 | 58 / 193 / 77.562 | 138 | 38 | 3 | maxref=1 9, datatype=off 9, maxref=1+datatype=off 3, maxdup=3 3, structuring=none 2, maxref=4 2, maxref=3 1, structuring=none+maxref=1 1, calls=cast 1, datatype=off+maxref=1 1, maxdup=1+datatype=off 1, maxref=3+datatype=off 1, maxdup=3+datatype=off 1, maxdup=4 1, adjacent=off+datatype=off 1, maxdup=3+maxref=3 1 | 2026 | 264 | 364 | 863 |
| m22-002 MWCC seed 20261011 | 200 | 57 / 194 / 78.316 | 57 / 194 / 78.767 | 137 | 30 | 0 | datatype=off 11, maxref=1 7, structuring=none 5, adjacent=off+datatype=off 2, structuring=none+calls=cast 1, maxref=3 1, maxdup=4 1, maxref=4 1, maxdup=3 1 | 1988 | 243 | 364 | 848 |
| m22-002 ee-gcc | 200 | 106 / 197 / 86.403 | 107 / 197 / 87.736 | 91 | 16 | 1 | datatype=off 7, structuring=none 3, structuring=none+datatype=off 3, maxref=1 3 | 1304 | 137 | 333 | 751 |

m22-003 lanes: 1400 functions, default exact 313 -> searched 326 (+13), 1049 functions searched, 278 improved, 15297 decompiles and 2161 compiles. Winners: datatype=off 74, maxref=1 63, structuring=none 51, maxref=3 10, maxref=1+datatype=off 9, calls=cast 9, adjacent=off 8, structuring=none+datatype=off 6, maxdup=3 5, maxref=4 5, structuring=none+maxref=1 4, dominant=off 3, adjacent=off+datatype=off 3, maxdup=1 3, maxref=1+adjacent=off 2, maxdup=4 2, datatype=off+maxref=1 2, maxref=3+datatype=off 2, calls=cast+datatype=off 2, maxdup=3+datatype=off 2, structuring=none+adjacent=off+datatype=off 1, datatype=off+structuring=none 1, structuring=none+maxref=4 1, structuring=no_arm_order+maxref=1 1, structuring=none+copy=off 1, copy=off+datatype=off 1, maxdup=4+structuring=none 1, maxref=1+calls=cast 1, structuring=none+maxdup=3+datatype=off 1, structuring=none+dominant=off 1, datatype=off+maxdup=1+structuring=no_arm_order 1, dominant=off+datatype=off 1, maxref=4+datatype=off 1.

m22-002 lanes: 600 functions, default exact 218 -> searched 222 (+4), 366 functions searched, 84 improved, 5318 decompiles and 644 compiles. Winners: datatype=off 27, maxref=1 19, structuring=none 10, maxdup=3 4, maxref=1+datatype=off 3, maxref=4 3, adjacent=off+datatype=off 3, structuring=none+datatype=off 3, maxref=3 2, maxdup=4 2, structuring=none+maxref=1 1, calls=cast 1, datatype=off+maxref=1 1, maxdup=1+datatype=off 1, maxref=3+datatype=off 1, maxdup=3+datatype=off 1, maxdup=3+maxref=3 1, structuring=none+calls=cast 1.

The m22-002 lanes sample the same Persona 4 decompilation as the p4 lane (a different harness, sample and context handling): their functions overlap the p4 lane's and are not added to it.

Default-arm check against the baseline table: dds ok, rc ok, p4 ok, gh ok, ff ok, dc ok, dk ok, m22-002 MWCC seed 20261010 ok, m22-002 MWCC seed 20261011 ok, m22-002 ee-gcc ok.

Default arm of the search run (the `romwright` layer of the `--search` run) equals the separate default arm: dds yes, rc yes, p4 yes, gh yes, ff yes, dc yes, dk yes, m22-002 MWCC seed 20261010 yes, m22-002 MWCC seed 20261011 yes, m22-002 ee-gcc yes.

## dds

Standalone compile (no context): default 48 exact / mean 72.476, searched 51 exact / mean 73.827. Improved / searched by the default print's byte-difference class: length differs: mixed arithmetic (expression shape) 20/58, length differs: control flow (branches, calls) 11/38, same length, many instructions differ 4/24, same instructions, different order (scheduling) 1/4, single instruction 0/3, register allocation and stack layout 0/3, few instructions differ (<= 4) 0/3, length differs: memory accesses (temporaries, spills, widths) 0/2, register allocation 1/2, length differs: floating-point or vector sequence 0/1, length differs: few instructions (<= 4) 0/1. Search time summed over functions 515.3 s.

| function | size | winner | from % | to % | exact |
|---|---|---|---|---|---|
| ptyAnyUnitFlagMatch | 112 | structuring=none | 65.714 | 100.0 | yes |
| sndAddSourceReferences | 76 | maxref=1 | 88.842 | 100.0 | yes |
| btlReleaseModelEntry | 192 | datatype=off | 99.646 | 99.958 | yes |
| fldReleaseTextureSlots | 180 | maxref=1 | 30.622 | 58.444 |  |
| func_00205EF8 | 556 | structuring=none+datatype=off | 1.295 | 26.734 |  |
| btlAverageCurrentValueForMask | 180 | structuring=none+adjacent=off+datatype=off | 65.444 | 85.667 |  |
| effFlashOrbitArcSetParticleColors | 240 | datatype=off | 72.75 | 92.333 |  |
| effCreateSurfaceNodeForGrid | 56 | structuring=none | 46.286 | 64.5 |  |
| evtUpdateMessageValueDialog | 520 | structuring=none | 49.154 | 65.015 |  |
| evtDrawHeapUsageOverlay | 304 | maxref=1 | 46.461 | 60.947 |  |
| fileSlotSelectPollClear | 196 | structuring=none | 21.796 | 36.265 |  |
| sndApplyToActiveActors | 132 | structuring=none | 60.788 | 73.455 |  |
| btlCommandTaskStartEffects | 468 | structuring=none | 39.017 | 51.59 |  |
| scrFindSlot | 64 | maxref=1 | 47.438 | 58.688 |  |
| effInitExpandRingPacketSchedule | 112 | structuring=none | 1.321 | 12.107 |  |
| func_00195CD8 | 240 | maxref=1 | 53.85 | 62.833 |  |
| itfPanelStartEntry | 156 | structuring=none | 63.103 | 72.077 |  |
| func_002738A0 | 396 | structuring=none+datatype=off | 82.0 | 88.646 |  |
| sdfTexCreateFromFileHeader | 448 | datatype=off | 74.786 | 81.188 |  |
| func_002D1D80 | 624 | maxref=1+datatype=off | 49.032 | 53.859 |  |
| func_0020FC48 | 776 | datatype=off+structuring=none | 78.948 | 82.881 |  |
| func_001E6260 | 264 | maxref=3 | 69.424 | 73.136 |  |
| effSeedParticleSpanParameters | 300 | maxref=1+datatype=off | 84.88 | 88.547 |  |
| mnuInitializePanelGroupGridSlots | 432 | datatype=off | 71.657 | 75.259 |  |
| func_00243BF0 | 212 | datatype=off | 89.962 | 93.019 |  |
| ... 12 more in the JSON | | | | | |

## rc

Standalone compile (no context): default 23 exact / mean 65.262, searched 24 exact / mean 67.384. Improved / searched by the default print's byte-difference class: length differs: mixed arithmetic (expression shape) 36/107, length differs: control flow (branches, calls) 7/23, same length, many instructions differ 6/22, length differs: memory accesses (temporaries, spills, widths) 2/12, same instructions, different order (scheduling) 0/4, register allocation 1/2, single instruction 0/1, length differs: extension instructions (type or cast) 0/1, register allocation and stack layout 0/1, length differs: nops or register copies (allocation or scheduling) 0/1. Search time summed over functions 180.8 s.

| function | size | winner | from % | to % | exact |
|---|---|---|---|---|---|
| read | 116 | structuring=none | 91.0 | 100.0 | yes |
| sceIpuSync | 104 | structuring=none | 1.346 | 56.731 |  |
| _sysbitJump | 84 | maxdup=4 | 45.857 | 88.571 |  |
| ConvertMultibyteCharacter | 60 | structuring=none | 28.333 | 67.333 |  |
| __pack_d | 300 | structuring=none+copy=off | 15.053 | 42.867 |  |
| sceClose | 380 | structuring=none | 37.726 | 61.0 |  |
| UpdateTempTrackData | 116 | structuring=none+dominant=off | 52.414 | 71.724 |  |
| dptoli | 148 | maxdup=4+structuring=none | 23.865 | 40.73 |  |
| _skipMB0 | 188 | structuring=none+maxdup=3+datatype=off | 44.894 | 61.085 |  |
| InitThread | 212 | datatype=off | 34.717 | 49.717 |  |
| _pack_header | 336 | structuring=none | 87.179 | 99.202 |  |
| dptoul | 160 | structuring=none | 9.425 | 20.05 |  |
| fflush | 260 | structuring=none+maxref=1 | 39.415 | 49.754 |  |
| _decPicture | 204 | structuring=none | 56.412 | 66.529 |  |
| _dualPrimeVector | 388 | maxref=3 | 16.278 | 26.392 |  |
| Dcmp | 104 | maxref=1+datatype=off | 74.923 | 84.885 |  |
| _free_r | 796 | structuring=none+maxref=4 | 56.628 | 66.377 |  |
| write | 124 | structuring=none | 88.29 | 96.71 |  |
| scePad2LinkDriver | 84 | maxref=1 | 72.429 | 79.381 |  |
| _decodeOrSkipField | 348 | structuring=none+datatype=off | 84.138 | 89.885 |  |
| sceGsExecLoadImage | 380 | structuring=none | 29.158 | 34.716 |  |
| mceStorePwd | 132 | structuring=none | 61.97 | 67.455 |  |
| litodp | 184 | maxref=3 | 50.674 | 55.891 |  |
| __smakebuf | 336 | maxref=1+datatype=off | 68.19 | 73.202 |  |
| __fixunsdfdi | 236 | maxref=3 | 66.288 | 71.186 |  |
| ... 27 more in the JSON | | | | | |

## p4

Standalone compile (no context): default 45 exact / mean 56.856, searched 45 exact / mean 57.056. Improved / searched by the default print's byte-difference class: length differs: mixed arithmetic (expression shape) 21/58, length differs: control flow (branches, calls) 8/34, same length, many instructions differ 1/13, length differs: memory accesses (temporaries, spills, widths) 1/8, register allocation 0/6, single instruction 0/4, same instructions, different order (scheduling) 0/3, length differs: floating-point or vector sequence 1/3, length differs: few instructions (<= 4) 0/1, register allocation and stack layout 0/1, stack layout 0/1, few instructions differ (<= 4) 0/1. Search time summed over functions 460.8 s.

| function | size | winner | from % | to % | exact |
|---|---|---|---|---|---|
| func_00466280 | 756 | structuring=none | 0.0 | 26.27 |  |
| func_00356820 | 68 | maxref=1 | 54.706 | 66.471 |  |
| func_00383c40 | 296 | structuring=none | 70.608 | 81.757 |  |
| CameraUpdateZShiftScale | 184 | structuring=none | 0.0 | 10.696 |  |
| func_00121de0 | 320 | maxref=1+adjacent=off | 73.425 | 81.638 |  |
| func_001bc3a0 | 444 | maxref=1 | 48.946 | 56.559 |  |
| func_004d2080 | 32 | maxref=1 | 33.625 | 39.25 |  |
| func_0011ac70 | 532 | structuring=none | 85.015 | 89.977 |  |
| func_001bb790 | 296 | maxref=1 | 53.473 | 58.405 |  |
| _rwFrameListStreamGetSize | 168 | maxref=1 | 79.381 | 83.667 |  |
| func_001e6dc0 | 224 | maxref=1 | 95.804 | 99.464 |  |
| func_0016b540 | 560 | maxref=1 | 69.65 | 72.471 |  |
| func_001e85c0 | 300 | maxref=1 | 96.2 | 98.933 |  |
| TextureImageReadAndSize | 888 | structuring=none | 78.342 | 80.698 |  |
| func_001e1620 | 240 | datatype=off | 67.667 | 69.5 |  |
| func_00276630 | 244 | datatype=off | 98.164 | 99.967 |  |
| func_00115380 | 156 | maxref=1 | 19.103 | 20.897 |  |
| func_001dea90 | 288 | datatype=off | 75.0 | 76.458 |  |
| func_00354660 | 340 | maxref=1 | 88.471 | 89.882 |  |
| func_0012ff60 | 868 | datatype=off | 73.917 | 75.184 |  |
| func_001664a0 | 348 | maxref=1 | 81.207 | 82.402 |  |
| func_0038d890 | 224 | maxdup=3 | 88.821 | 89.821 |  |
| func_0035bc10 | 268 | structuring=none | 81.896 | 82.881 |  |
| func_0010c750 | 556 | maxref=1 | 59.871 | 60.317 |  |
| func_003040d0 | 532 | datatype=off | 46.654 | 46.917 |  |
| ... 7 more in the JSON | | | | | |

## gh

Standalone compile (no context): default 76 exact / mean 81.107, searched 78 exact / mean 82.487. Improved / searched by the default print's byte-difference class: length differs: mixed arithmetic (expression shape) 10/32, length differs: control flow (branches, calls) 9/29, same length, many instructions differ 5/19, few instructions differ (<= 4) 0/13, length differs: memory accesses (temporaries, spills, widths) 3/12, same instructions, different order (scheduling) 0/4, register allocation and stack layout 0/3, register allocation 0/3, single instruction 0/3, length differs: floating-point or vector sequence 1/1, length differs: few instructions (<= 4) 0/1, length differs: nops and register copies 0/1. Search time summed over functions 502.6 s.

| function | size | winner | from % | to % | exact |
|---|---|---|---|---|---|
| func_0037C6A0 | 124 | datatype=off | 82.71 | 100.0 | yes |
| cCoreSave_useGodItem | 88 | maxref=1 | 93.545 | 100.0 | yes |
| func_003BACA0 | 104 | structuring=none | 1.346 | 56.731 |  |
| lo0bits | 192 | maxref=1 | 0.0 | 44.562 |  |
| func_0018C4A8 | 116 | structuring=none | 63.172 | 99.793 |  |
| BankTable_isKeyFree | 140 | datatype=off+maxref=1 | 41.229 | 74.371 |  |
| ColiseumBattle_spawnWave | 172 | structuring=none | 52.884 | 82.326 |  |
| __srefill | 360 | structuring=none+datatype=off | 62.067 | 84.722 |  |
| StreamBuf_startRead | 268 | structuring=none+maxref=1 | 65.657 | 85.045 |  |
| _IO_file_setbuf | 80 | structuring=none | 69.95 | 87.45 |  |
| func_00146190 | 408 | structuring=none | 2.186 | 14.48 |  |
| func_00202058 | 628 | structuring=none | 61.885 | 71.777 |  |
| func_00115F60 | 316 | structuring=none | 55.861 | 63.076 |  |
| func_00281D10 | 136 | maxref=1 | 81.324 | 87.794 |  |
| func_001BBB48 | 188 | datatype=off | 81.213 | 85.787 |  |
| SpawnCylinderDamageAndFlagPartsA | 492 | datatype=off | 49.789 | 53.846 |  |
| cDataManager_loadSeWait | 476 | structuring=none | 81.429 | 84.941 |  |
| func_003288E0 | 680 | datatype=off | 91.618 | 95.006 |  |
| UpdateBetAdjustScreenB | 864 | datatype=off | 85.796 | 89.083 |  |
| func_00274238 | 636 | structuring=none | 49.195 | 52.403 |  |
| CasinoWork_ResetWarmUpRoom | 224 | datatype=off+maxref=1 | 79.714 | 82.375 |  |
| BlackJack_UpdateClearTable | 552 | datatype=off | 87.08 | 89.413 |  |
| func_00102DE8 | 244 | structuring=none | 76.803 | 78.803 |  |
| func_001C2378 | 140 | datatype=off | 43.114 | 43.971 |  |
| cSndMemHeap_FindUnusedBlk | 56 | maxref=1 | 81.0 | 81.714 |  |
| ... 3 more in the JSON | | | | | |

## ff

Standalone compile (no context): default 13 exact / mean 33.546, searched 16 exact / mean 34.592. Improved / searched by the default print's byte-difference class: length differs: mixed arithmetic (expression shape) 37/110, same length, many instructions differ 6/19, length differs: control flow (branches, calls) 5/15, length differs: memory accesses (temporaries, spills, widths) 3/12, same instructions, different order (scheduling) 0/8, few instructions differ (<= 4) 0/2, single instruction 0/2, register allocation 1/2, register allocation and stack layout 0/2, length differs: floating-point or vector sequence 0/1, length differs: few instructions (<= 4) 1/1. Search time summed over functions 538.9 s.

| function | size | winner | from % | to % | exact |
|---|---|---|---|---|---|
| mimGetKeymdlTop | 32 | maxref=1 | 59.375 | 100.0 | yes |
| DoorKeyLock | 72 | datatype=off | 83.056 | 100.0 | yes |
| DrawOne2D_P2 | 132 | maxref=1 | 99.242 | 100.0 | yes |
| DelDataLoadWrk | 200 | structuring=none+maxref=1 | 11.24 | 76.54 |  |
| mimAddFrame | 256 | structuring=none | 8.906 | 58.578 |  |
| NakasuHazeSet | 92 | structuring=none | 23.13 | 67.696 |  |
| SceneIsEnd | 512 | structuring=none+maxref=1 | 0.0 | 42.758 |  |
| motGetAniMdl | 220 | structuring=none | 31.891 | 49.091 |  |
| PosInAreaJudge0 | 268 | structuring=none | 39.896 | 56.985 |  |
| PlyrCondChk | 332 | structuring=none | 35.614 | 52.494 |  |
| AEneEntry | 420 | structuring=none | 32.705 | 48.419 |  |
| motPlyrActSowasowa | 240 | maxref=1 | 50.383 | 61.617 |  |
| LoadStoryWrk | 228 | dominant=off | 23.351 | 34.386 |  |
| EJob04C | 192 | structuring=none | 42.0 | 50.375 |  |
| SceneInitEnvironment | 260 | datatype=off | 49.846 | 58.154 |  |
| Tim2LoadImage2 | 848 | maxref=3+datatype=off | 56.009 | 64.316 |  |
| UncompressData | 144 | structuring=none | 28.833 | 35.972 |  |
| PhotoPointCulcRare | 344 | maxref=3 | 66.988 | 74.07 |  |
| SetMapCamDat2 | 784 | datatype=off | 40.959 | 47.949 |  |
| viBufRestartDMA | 800 | maxref=4 | 49.235 | 56.155 |  |
| SetPrePEImage | 192 | maxref=1+datatype=off | 83.229 | 90.104 |  |
| CameraGetDoorCameraNo | 424 | maxref=3+datatype=off | 36.057 | 42.821 |  |
| FACheckSquareArea | 508 | maxref=1 | 59.031 | 65.748 |  |
| StageTitleLoad | 544 | maxref=1 | 72.331 | 78.765 |  |
| viBufAddDMA | 496 | adjacent=off+datatype=off | 72.331 | 78.661 |  |
| ... 28 more in the JSON | | | | | |

## dc

Standalone compile (no context): default 30 exact / mean 54.851, searched 32 exact / mean 55.515. Improved / searched by the default print's byte-difference class: length differs: mixed arithmetic (expression shape) 16/63, length differs: control flow (branches, calls) 7/40, same length, many instructions differ 3/13, length differs: memory accesses (temporaries, spills, widths) 1/12, length differs: floating-point or vector sequence 1/4, register allocation 0/4, few instructions differ (<= 4) 0/4, length differs: few instructions (<= 4) 0/3, single instruction 1/2, length differs: nops and register copies 1/1, length differs: nops or register copies (allocation or scheduling) 0/1, register allocation and stack layout 0/1. Search time summed over functions 1563.0 s.

| function | size | winner | from % | to % | exact |
|---|---|---|---|---|---|
| GetMdsList__11CMdsListSetFi | 52 | adjacent=off | 78.077 | 100.0 | yes |
| IsBurn__10CEditPartsFv | 40 | maxref=1 | 94.0 | 100.0 | yes |
| _SET_NEXT_ROT__FP12RS_STACKDATAi | 72 | maxref=1 | 23.611 | 42.278 |  |
| _GET_CHARA_WEIGHT__FP12RS_STACKDATAi | 76 | maxref=1 | 44.158 | 59.684 |  |
| UpDateMapInfo__6CSceneFv | 352 | maxref=1 | 38.182 | 50.739 |  |
| _MES_CLOSE__FP12RS_STACKDATAi | 104 | calls=cast | 63.846 | 75.385 |  |
| GetTextureBlock__17mgCTextureManagerFi | 80 | adjacent=off | 69.75 | 81.0 |  |
| Draw__15CHitEffectImageFv | 128 | structuring=none | 17.656 | 28.438 |  |
| __TEX_NAME__FP9SPI_STACKi | 72 | calls=cast | 23.333 | 33.0 |  |
| __REPEAT__FP9SPI_STACKi | 100 | maxref=1 | 72.76 | 80.96 |  |
| mapPARTS_GROUP__FP9SPI_STACKi | 60 | maxref=1 | 54.067 | 61.067 |  |
| ReCalcBox__FP9mgVu0FBOX9mgVu0FBOX | 148 | maxref=1 | 55.973 | 61.622 |  |
| _OBJS_ATTACH_CAMERA__FP12RS_STACKDATAi | 120 | maxref=1 | 44.967 | 50.467 |  |
| AddHp_Rate__16CUserDataManagerFif | 120 | calls=cast | 63.5 | 68.833 |  |
| GetParts__4CMapFPc | 148 | maxref=1 | 81.568 | 86.73 |  |
| GetLine__FPPcPcPc__2 | 416 | maxref=1+datatype=off | 92.481 | 97.048 |  |
| CheckEventItem__5CShopFv | 824 | maxdup=4 | 84.393 | 88.112 |  |
| _GET_STS_ATTR__FP12RS_STACKDATAi | 76 | maxref=1 | 44.421 | 46.526 |  |
| CreatePacket__12mgCVisualMDTFP14mgCDrawManager | 636 | maxref=4 | 75.289 | 77.082 |  |
| _SCALE_VECTOR__FP12RS_STACKDATAi | 112 | maxref=1 | 24.429 | 26.036 |  |
| CheckEnableCharaChange__16CUserDataManagerFiPi | 468 | calls=cast+datatype=off | 67.205 | 68.744 |  |
| _MES_MAKE__FP12RS_STACKDATAi | 464 | maxref=1 | 78.448 | 79.802 |  |
| FalseLoop__FP6CSceneP11CPadControl | 632 | maxref=1 | 65.462 | 66.62 |  |
| DeleteKanketuParts__FP6CSceneP8CEditMapPfi | 712 | datatype=off | 31.399 | 31.933 |  |
| Birth__9CRainDropFi | 364 | datatype=off | 87.945 | 88.44 |  |
| ... 5 more in the JSON | | | | | |

## dk

Standalone compile (no context): default 22 exact / mean 53.217, searched 24 exact / mean 53.695. Improved / searched by the default print's byte-difference class: length differs: mixed arithmetic (expression shape) 30/75, same length, many instructions differ 6/25, length differs: control flow (branches, calls) 8/24, length differs: memory accesses (temporaries, spills, widths) 0/10, few instructions differ (<= 4) 0/8, register allocation 1/6, single instruction 0/5, register allocation and stack layout 0/4, length differs: floating-point or vector sequence 1/1, same instructions, different order (scheduling) 0/1, access width or signedness (type or cast) 0/1. Search time summed over functions 677.9 s.

| function | size | winner | from % | to % | exact |
|---|---|---|---|---|---|
| SetParent__6CFrameFP6CFrame | 68 | maxref=1 | 81.706 | 100.0 | yes |
| GetWidth__9CMapPartsFv | 88 | maxref=3 | 97.273 | 100.0 | yes |
| CommandEDITAREA_RECT__FPPv | 168 | maxdup=3 | 24.071 | 63.524 |  |
| _SYNC_CHARA_ITEM__FP12RS_STACKDATAi | 216 | datatype=off | 78.222 | 89.352 |  |
| Step__7CEffectFi | 632 | maxref=1+datatype=off | 72.462 | 82.937 |  |
| BtGetWeaponNamePath3__FPcPci | 180 | maxref=1 | 85.111 | 94.222 |  |
| EdInitVillagerTable__FfP13EDIT_MAP_INFO | 148 | maxref=1 | 83.649 | 90.486 |  |
| GetNextParts__14CEditPartsInfoFi | 112 | calls=cast+datatype=off | 57.857 | 64.286 |  |
| GetPackFile__FPUiPcPi | 216 | maxref=1 | 74.815 | 81.111 |  |
| FrameObjectOnOff__10CMapObjectFPci | 292 | maxref=3 | 94.014 | 99.863 |  |
| createAttachVolume__Fii | 232 | maxref=1 | 76.293 | 81.897 |  |
| EdDrawLensFlare__FfPP6CFrame | 812 | maxref=4+datatype=off | 67.985 | 72.69 |  |
| QuatSlerp__FPfPffPf | 432 | adjacent=off+datatype=off | 82.954 | 87.583 |  |
| set_spu__Fiiii | 360 | datatype=off | 82.022 | 85.578 |  |
| SetReverb__6CSoundFiii | 288 | maxdup=3 | 76.292 | 79.069 |  |
| ShopCurDraw__Fiiiiiii | 764 | adjacent=off+datatype=off | 85.22 | 87.497 |  |
| GetAllSaveFileInfo__17CMemoryCardAccessFv | 216 | datatype=off | 79.444 | 81.667 |  |
| SkipSpace__FR9input_str | 148 | calls=cast | 37.378 | 39.541 |  |
| ArrangementPos__12CMonstorUnitFP11CDungeonMapiii | 920 | maxdup=3+datatype=off | 81.587 | 83.5 |  |
| SetBuffInfo__10MenuClsMesFPs | 540 | maxdup=3+datatype=off | 95.444 | 97.296 |  |
| Initialize__14CEditPartsInfoFi | 456 | maxref=1 | 86.64 | 88.307 |  |
| Step__7CCameraFi | 728 | maxref=1+datatype=off | 80.797 | 82.319 |  |
| Step__13CWeaponEffectFv | 472 | maxdup=1 | 68.72 | 70.229 |  |
| _OBJ_DRAW__FP12RS_STACKDATAi | 164 | calls=cast | 87.902 | 89.244 |  |
| AtoraCompOrEvent__FP14EDITPARTS_INFO | 356 | datatype=off | 91.393 | 92.629 |  |
| ... 21 more in the JSON | | | | | |

## m22-002 MWCC seed 20261010

Standalone compile (no context): default 42 exact / mean 56.916, searched 44 exact / mean 57.067. Improved / searched by the default print's byte-difference class: unclassified 38/138. Search time summed over functions 459.9 s.

| function | size | winner | from % | to % | exact |
|---|---|---|---|---|---|
| func_002214d0 | 232 | maxdup=3+datatype=off | 94.707 | 100.0 | yes |
| func_00175ea0 | 200 | maxref=3 | 95.7 | 100.0 | yes |
| func_0035e820 | 140 | maxdup=3 | 96.829 | 100.0 | yes |
| func_00199350 | 420 | structuring=none | 62.143 | 80.857 |  |
| func_002bb9e0 | 732 | maxdup=3+maxref=3 | 79.454 | 89.126 |  |
| func_001999f0 | 776 | structuring=none+maxref=1 | 64.17 | 73.057 |  |
| func_002e6b20 | 360 | maxref=1 | 90.278 | 96.767 |  |
| func_002bab80 | 300 | maxref=1 | 79.32 | 84.853 |  |
| func_0011ac70 | 532 | structuring=none | 85.015 | 89.977 |  |
| func_0047fbf0 | 276 | maxref=4 | 76.855 | 81.275 |  |
| func_0022cc90 | 284 | maxdup=4 | 88.31 | 92.535 |  |
| func_001bd620 | 344 | maxref=1 | 61.395 | 65.465 |  |
| func_001e6dc0 | 224 | maxref=1 | 95.804 | 99.464 |  |
| func_0024acf0 | 116 | datatype=off | 75.345 | 78.966 |  |
| func_00279780 | 768 | maxref=1+datatype=off | 80.318 | 83.307 |  |
| func_0024ba60 | 160 | maxdup=3 | 96.975 | 99.75 |  |
| func_00205950 | 712 | maxdup=1+datatype=off | 93.966 | 96.607 |  |
| func_0045a570 | 448 | maxref=4 | 86.759 | 89.08 |  |
| func_00174c20 | 492 | maxref=1 | 80.244 | 82.154 |  |
| func_001e1cc0 | 240 | datatype=off | 67.667 | 69.5 |  |
| func_00115380 | 156 | maxref=1 | 19.103 | 20.897 |  |
| func_00202890 | 716 | maxref=1+datatype=off | 89.257 | 90.961 |  |
| func_001de370 | 720 | datatype=off | 96.167 | 97.833 |  |
| func_00207140 | 472 | datatype=off | 88.966 | 90.492 |  |
| func_001dea90 | 288 | datatype=off | 75.0 | 76.458 |  |
| ... 13 more in the JSON | | | | | |

## m22-002 MWCC seed 20261011

Standalone compile (no context): default 38 exact / mean 56.458, searched 38 exact / mean 56.489. Improved / searched by the default print's byte-difference class: unclassified 30/137. Search time summed over functions 445.7 s.

| function | size | winner | from % | to % | exact |
|---|---|---|---|---|---|
| func_004da5b8 | 120 | structuring=none | 5.6 | 26.3 |  |
| func_00159a60 | 748 | structuring=none+calls=cast | 70.77 | 81.369 |  |
| func_001e3fd0 | 184 | maxref=1 | 83.587 | 91.63 |  |
| func_003d3460 | 392 | structuring=none | 50.918 | 56.939 |  |
| func_00380d80 | 276 | maxref=4 | 93.696 | 98.261 |  |
| func_0034bea0 | 636 | datatype=off | 66.138 | 70.132 |  |
| func_0027b230 | 216 | datatype=off | 50.556 | 54.352 |  |
| func_00247dd0 | 228 | maxref=1 | 62.456 | 66.228 |  |
| func_0024acf0 | 116 | datatype=off | 75.345 | 78.966 |  |
| func_001db360 | 544 | maxref=3 | 91.213 | 94.522 |  |
| func_00155bf0 | 540 | maxref=1 | 95.607 | 98.881 |  |
| func_00248b80 | 376 | structuring=none | 74.032 | 77.277 |  |
| func_00273cc0 | 676 | datatype=off | 81.136 | 84.243 |  |
| func_00255b90 | 820 | datatype=off | 91.844 | 94.332 |  |
| func_001e3050 | 260 | datatype=off | 55.385 | 57.077 |  |
| func_0044ef70 | 452 | maxref=1 | 83.159 | 84.487 |  |
| func_00291900 | 116 | maxdup=4 | 95.172 | 96.379 |  |
| func_0027d800 | 364 | maxref=1 | 61.967 | 62.967 |  |
| func_0035bc10 | 268 | structuring=none | 81.896 | 82.881 |  |
| func_00477810 | 236 | maxdup=3 | 50.542 | 51.322 |  |
| func_001ef5f0 | 300 | adjacent=off+datatype=off | 85.733 | 86.32 |  |
| func_003b6cc0 | 212 | maxref=1 | 71.057 | 71.509 |  |
| func_0029d2f0 | 876 | datatype=off | 95.114 | 95.525 |  |
| func_001e26c0 | 392 | datatype=off | 64.082 | 64.388 |  |
| func_00370290 | 376 | maxref=1 | 61.064 | 61.362 |  |
| ... 5 more in the JSON | | | | | |

## m22-002 ee-gcc

Standalone compile (no context): default 100 exact / mean 79.951, searched 101 exact / mean 81.102. Improved / searched by the default print's byte-difference class: unclassified 16/91. Search time summed over functions 282.5 s.

| function | size | winner | from % | to % | exact |
|---|---|---|---|---|---|
| ACSSND_GetStatPause | 72 | structuring=none | 29.389 | 100.0 | yes |
| ADXB_GetOutBps | 96 | datatype=off | 25.75 | 73.25 |  |
| LSC_GetStmStat | 148 | structuring=none+datatype=off | 34.676 | 71.162 |  |
| SJRBF_GetNumData | 76 | structuring=none | 62.632 | 96.316 |  |
| SFCON_IsVideoEndcodeSkip | 72 | datatype=off | 64.778 | 90.556 |  |
| ADXERR_ItoA | 260 | maxref=1 | 45.815 | 57.815 |  |
| ACSSBADX_CreateHndl | 132 | structuring=none | 65.212 | 77.182 |  |
| ADXB_EntryData | 124 | maxref=1 | 11.742 | 20.968 |  |
| SFD_GetOutVol | 108 | datatype=off | 77.259 | 82.222 |  |
| sfply_IsTermAny | 156 | datatype=off | 90.256 | 93.846 |  |
| ADXT_ExecErrChk | 588 | structuring=none+datatype=off | 79.816 | 82.707 |  |
| MPV_GoNextDelimSj | 344 | datatype=off | 16.791 | 19.488 |  |
| func_004be9c0 | 216 | structuring=none+datatype=off | 88.296 | 90.648 |  |
| ADXSJE_Create | 464 | datatype=off | 4.06 | 5.784 |  |
| adxt_nlp_trap_entry | 740 | maxref=1 | 69.081 | 70.054 |  |
| ADXT_GetTimeSfreq | 200 | datatype=off | 74.84 | 74.96 |  |

