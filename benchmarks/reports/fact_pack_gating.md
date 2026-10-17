# Fact pack gating study

Generated 2026-10-11T20:19:57+00:00 by `benchmarks/fact_pack_gating.py`; pack `fact-pack.sqlite` (106.0 MB, 48 donors), `romwright-cli` c3b621287fddc706. Leave-one-out over the 48 donor games (twin groups excluded); every `FUN_` rename the pack made, scored against truth with the LOO report's classifier. Definitions: see the script's docstring.

## The renames

- renames: 30,804; scoreable 26,539; correct 25,342 (strict equal 24,604, base name 48, base name but another class 690); unscoreable 4,265
- strict wrong (every scoreable non-correct): 1,197 (4.51%): spelling 43, affix 183, collision 145, different 826
- function-wrong (collision: another function of the target has this name, or both are different mangled methods): 161 (0.61%); of the 145 collision rows 68 are rule A (name in target), 77 mangled-vs-mangled

## Aliases and wrong functions inside `different`

- `different` rows: 826
- rule A (the pack's name is the truth name of another function of the target): settles 0. It is already how `collision` is assigned, so it cannot settle a row left in `different`.
- rule B (another donor, outside the excluded game and its twins, names the same digest with the truth name): settles 7 as alias; 7 of them only through a donor that holds the body twice (a stub there: a shared tiny body, which is evidence of a collision more than of an alias)
- unsettled: 819 of 826
- not a usable rule: the excluded game's own row of the same digest carries the truth name in 810 of 826 `different` rows (it holds whenever our body is the truth function's, alias or not).

Rule B aliases (examples):

- truth `localeconv` = pack `GetStateResourceWrapper` (36 B; truth name also given by ps2-dark-chronicle (stub there), ps2-dark-cloud (stub there))
- truth `DsDataCallback` = pack `CdDataCallback` (36 B; truth name also given by psx-digimon-world (stub there), psx-parasite-eve (stub there), psx-parasite-eve-2 (stub there), psx-vagrant-story (stub there))
- truth `NANDGetStatus` = pack `NANDMove` (100 B; truth name also given by wii-npc-pikmin-2 (stub there), wii-super-mario-galaxy (stub there))
- truth `HBMSetAdjustFlag` = pack `NHTTPCleanupAsync` (52 B; truth name also given by wii-skyward-sword (stub there))
- truth `HBMCreateSound` = pack `DisposeCallbackFunc__Q36nw4hbm3snd9SoundHeapFPvUlPv` (84 B; truth name also given by wii-skyward-sword (stub there))
- truth `__amu__7Vector3Ff` = pack `dVectorScale__FPff` (40 B; truth name also given by wii-super-mario-galaxy (stub there))
- truth `VFiPFPATH_cmpTailSFN` = pack `needSave__Q34Game12ItemPikihead4ItemFv` (44 B; truth name also given by wii-mario-strikers-charged (stub there))

### 20 random unsettled pairs

| game | address | truth name | pack name | length | agreeing donors | donor games |
|---|---|---|---|---:|---:|---|
| nds-world-ends-with-you | 0x20384e8 | `OS_SetDMAInterruptCallback` | `OSi_EnterDmaCallback` | 72 | 2 | nds-kh-358-2-days, nds-pokemon-platinum |
| n64-ocarina-of-time | 0x800ce810 | `PrintUtils_VPrintf` | `vaprintf` | 52 | 1 | n64-majoras-mask |
| nds-world-ends-with-you | 0x2038604 | `OS_ResetIRQRequestFlags` | `OS_ResetRequestIrqMask` | 44 | 2 | nds-kh-358-2-days, nds-pokemon-platinum |
| n64-ocarina-of-time | 0x800c9a20 | `Audio_SetUnusedBankLerp` | `AudioSfx_SetBankLerp` | 148 | 1 | n64-majoras-mask |
| n64-ocarina-of-time | 0x800ac9b0 | `Matrix_SetTranslateScaleMtx2` | `Mtx_SetTranslateScaleMtx` | 252 | 1 | n64-majoras-mask |
| gc-pikmin-2 | 0x801d0db8 | `clear__Q24Game8GameStatFv` | `UI_UnregisterStreamClients` | 88 | 1 | gc-tiger-woods-2004 |
| gc-mario-party-4 | 0x800d6bb8 | `CARDDelete` | `CARDFastDelete` | 72 | 1 | gc-pikmin |
| n64-perfect-dark | 0x7f18961c | `mp_get_weaponset_slotnum` | `gcGetDefaultGObjStack` | 36 | 1 | n64-super-smash-bros |
| nds-pokemon-platinum | 0x20d2e4c | `CTRDGi_TaskThread` | `JobQueue_WorkerLoop` | 240 | 1 | nds-kh-358-2-days |
| gba-klonoa-empire-of-dreams | 0x804fe10 | `MP2K_event_endtie` | `ply_endtie` | 64 | 1 | gba-fire-emblem-sacred-stones |
| psx-parasite-eve-2 | 0x80132db4 | `_actor503500SetRoomBackgroundSpritesVisible` | `play_movie__Fc` | 32 | 1 | psx-nfs-high-stakes |
| gba-golden-sun | 0x80fa83c | `AudioEngine_SetMode` | `m4aSoundMode` | 152 | 2 | gba-fire-emblem-sacred-stones, gba-klonoa-empire-of-dreams |
| psx-silent-hill | 0x8009bfb0 | `sendAtMainMode` | `PADCMD_OBJ_AA0` | 84 | 1 | psx-legend-of-mana |
| wii-mario-strikers-charged | 0x8035932c | `dVectorScale__FPff` | `__amu__7Vector3Ff` | 40 | 1 | wii-rock-band-3 |
| psx-parasite-eve | 0x80083ea4 | `CardObj_EmitCommand46` | `PADCMD_OBJ_BA8` | 32 | 1 | psx-legend-of-mana |
| n64-ocarina-of-time | 0x800cdbb8 | `SystemArena_GetSizes` | `GetFreeArena` | 56 | 1 | n64-majoras-mask |
| n64-majoras-mask | 0x801a72cc | `AudioSfx_StopByPos` | `Audio_StopSfxByPos` | 92 | 1 | n64-ocarina-of-time |
| psx-nfs-high-stakes | 0x800ba0d0 | `DeInitArtResources__Fv` | `shelterB1SterilizationRoomResetSpawnMaskTask` | 36 | 1 | psx-parasite-eve-2 |
| psx-legend-of-mana | 0x80025d38 | `akao_collect_channel_voice_mask` | `ChannelMaskToVoiceMaskFiltered` | 96 | 1 | psx-vagrant-story |
| nds-world-ends-with-you | 0x203e9f8 | `FS_FileStop` | `FS_CancelFile` | 72 | 1 | nds-kh-358-2-days |

## Ungated, by the number of agreeing donors

| bucket | renames | scoreable | correct | strict wrong | strict rate | function-wrong | function rate |
|---|---:|---:|---:|---:|---:|---:|---:|
| 1 donor | 13,811 | 11,763 | 10,765 | 998 | 8.48% | 138 | 1.17% |
| 2 donors | 5,058 | 4,032 | 3,890 | 142 | 3.52% | 21 | 0.52% |
| 3-4 donors | 8,035 | 6,941 | 6,888 | 53 | 0.76% | 2 | 0.03% |
| 5+ donors | 3,900 | 3,803 | 3,799 | 4 | 0.11% | 0 | 0.00% |

## Ungated, by pack body length

| bucket | renames | scoreable | correct | strict wrong | strict rate | function-wrong | function rate |
|---|---:|---:|---:|---:|---:|---:|---:|
| 32-47 B | 3,256 | 2,701 | 2,406 | 295 | 10.92% | 52 | 1.93% |
| 48-63 B | 2,852 | 2,449 | 2,266 | 183 | 7.47% | 48 | 1.96% |
| 64-95 B | 4,455 | 3,838 | 3,593 | 245 | 6.38% | 40 | 1.04% |
| 96-127 B | 3,907 | 3,441 | 3,295 | 146 | 4.24% | 3 | 0.09% |
| 128+ B | 16,334 | 14,110 | 13,782 | 328 | 2.32% | 18 | 0.13% |

## Gates, overall

| gate | renames kept | % kept | scoreable | correct | strict wrong | strict rate | function-wrong | function rate |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| len>=32 (any) | 30,804 | 100.00% | 26,539 | 25,342 | 1,197 | 4.51% | 161 | 0.61% |
| len>=32 (any), >=2 donors if len<64 | 27,890 | 90.54% | 24,063 | 23,252 | 811 | 3.37% | 77 | 0.32% |
| len>=32 (any), >=2 independent donors (twin groups merged) if len<64 | 27,850 | 90.41% | 24,026 | 23,227 | 799 | 3.33% | 67 | 0.28% |
| len>=32 (any), >=2 donors if len<128 | 23,526 | 76.37% | 20,200 | 19,727 | 473 | 2.34% | 39 | 0.19% |
| len>=32 (any), >=2 independent donors (twin groups merged) if len<128 | 23,465 | 76.18% | 20,143 | 19,686 | 457 | 2.27% | 26 | 0.13% |
| len>=32 (any), >=2 donors | 16,993 | 55.16% | 14,776 | 14,577 | 199 | 1.35% | 23 | 0.16% |
| len>=32 (any), >=2 independent donors (twin groups merged) | 16,923 | 54.94% | 14,710 | 14,528 | 182 | 1.24% | 10 | 0.07% |
| len>=48 | 27,548 | 89.43% | 23,838 | 22,936 | 902 | 3.78% | 109 | 0.46% |
| len>=48, >=2 donors if len<64 | 26,224 | 85.13% | 22,692 | 21,937 | 755 | 3.33% | 71 | 0.31% |
| len>=48, >=2 independent donors (twin groups merged) if len<64 | 26,209 | 85.08% | 22,679 | 21,932 | 747 | 3.29% | 63 | 0.28% |
| len>=48, >=2 donors if len<128 | 21,860 | 70.96% | 18,829 | 18,412 | 417 | 2.21% | 33 | 0.18% |
| len>=48, >=2 independent donors (twin groups merged) if len<128 | 21,824 | 70.85% | 18,796 | 18,391 | 405 | 2.15% | 22 | 0.12% |
| len>=48, >=2 donors | 15,327 | 49.76% | 13,405 | 13,262 | 143 | 1.07% | 17 | 0.13% |
| len>=48, >=2 independent donors (twin groups merged) | 15,282 | 49.61% | 13,363 | 13,233 | 130 | 0.97% | 6 | 0.04% |
| len>=64 | 24,696 | 80.17% | 21,389 | 20,670 | 719 | 3.36% | 61 | 0.29% |
| len>=64, >=2 donors if len<128 | 20,332 | 66.00% | 17,526 | 17,145 | 381 | 2.17% | 23 | 0.13% |
| len>=64, >=2 independent donors (twin groups merged) if len<128 | 20,311 | 65.94% | 17,506 | 17,129 | 377 | 2.15% | 20 | 0.11% |
| len>=64, >=2 donors | 13,799 | 44.80% | 12,102 | 11,995 | 107 | 0.88% | 7 | 0.06% |
| len>=64, >=2 independent donors (twin groups merged) | 13,769 | 44.70% | 12,073 | 11,971 | 102 | 0.84% | 4 | 0.03% |
| len>=96 | 20,241 | 65.71% | 17,551 | 17,077 | 474 | 2.70% | 21 | 0.12% |
| len>=96, >=2 donors if len<128 | 18,097 | 58.75% | 15,605 | 15,257 | 348 | 2.23% | 18 | 0.12% |
| len>=96, >=2 independent donors (twin groups merged) if len<128 | 18,093 | 58.74% | 15,601 | 15,253 | 348 | 2.23% | 18 | 0.12% |
| len>=96, >=2 donors | 11,564 | 37.54% | 10,181 | 10,107 | 74 | 0.73% | 2 | 0.02% |
| len>=96, >=2 independent donors (twin groups merged) | 11,551 | 37.50% | 10,168 | 10,095 | 73 | 0.72% | 2 | 0.02% |
| len>=128 | 16,334 | 53.03% | 14,110 | 13,782 | 328 | 2.32% | 18 | 0.13% |
| len>=128, >=2 donors | 9,801 | 31.82% | 8,686 | 8,632 | 54 | 0.62% | 2 | 0.02% |
| len>=128, >=2 independent donors (twin groups merged) | 9,792 | 31.79% | 8,677 | 8,624 | 53 | 0.61% | 2 | 0.02% |
| len>=32 (any), family = detected (any donor) | 30,510 | 99.05% | 26,334 | 25,172 | 1,162 | 4.41% | 161 | 0.61% |
| len>=32 (any), >=2 donors if len<64, family = detected (any donor) | 27,654 | 89.77% | 23,891 | 23,095 | 796 | 3.33% | 77 | 0.32% |
| len>=32 (any), >=2 independent donors (twin groups merged) if len<64, family = detected (any donor) | 27,614 | 89.64% | 23,854 | 23,070 | 784 | 3.29% | 67 | 0.28% |
| len>=32 (any), >=2 donors if len<128, family = detected (any donor) | 23,346 | 75.79% | 20,066 | 19,601 | 465 | 2.32% | 39 | 0.19% |
| len>=32 (any), >=2 independent donors (twin groups merged) if len<128, family = detected (any donor) | 23,285 | 75.59% | 20,009 | 19,560 | 449 | 2.24% | 26 | 0.13% |
| len>=32 (any), >=2 donors, family = detected (any donor) | 16,934 | 54.97% | 14,728 | 14,529 | 199 | 1.35% | 23 | 0.16% |
| len>=32 (any), >=2 independent donors (twin groups merged), family = detected (any donor) | 16,864 | 54.75% | 14,662 | 14,480 | 182 | 1.24% | 10 | 0.07% |
| len>=48, family = detected (any donor) | 27,305 | 88.64% | 23,666 | 22,782 | 884 | 3.74% | 109 | 0.46% |
| len>=48, >=2 donors if len<64, family = detected (any donor) | 25,998 | 84.40% | 22,528 | 21,788 | 740 | 3.28% | 71 | 0.32% |
| len>=48, >=2 independent donors (twin groups merged) if len<64, family = detected (any donor) | 25,983 | 84.35% | 22,515 | 21,783 | 732 | 3.25% | 63 | 0.28% |
| len>=48, >=2 donors if len<128, family = detected (any donor) | 21,690 | 70.41% | 18,703 | 18,294 | 409 | 2.19% | 33 | 0.18% |
| len>=48, >=2 independent donors (twin groups merged) if len<128, family = detected (any donor) | 21,654 | 70.30% | 18,670 | 18,273 | 397 | 2.13% | 22 | 0.12% |
| len>=48, >=2 donors, family = detected (any donor) | 15,278 | 49.60% | 13,365 | 13,222 | 143 | 1.07% | 17 | 0.13% |
| len>=48, >=2 independent donors (twin groups merged), family = detected (any donor) | 15,233 | 49.45% | 13,323 | 13,193 | 130 | 0.98% | 6 | 0.05% |
| len>=64, family = detected (any donor) | 24,477 | 79.46% | 21,232 | 20,528 | 704 | 3.32% | 61 | 0.29% |
| len>=64, >=2 donors if len<128, family = detected (any donor) | 20,169 | 65.48% | 17,407 | 17,034 | 373 | 2.14% | 23 | 0.13% |
| len>=64, >=2 independent donors (twin groups merged) if len<128, family = detected (any donor) | 20,148 | 65.41% | 17,387 | 17,018 | 369 | 2.12% | 20 | 0.12% |
| len>=64, >=2 donors, family = detected (any donor) | 13,757 | 44.66% | 12,069 | 11,962 | 107 | 0.89% | 7 | 0.06% |
| len>=64, >=2 independent donors (twin groups merged), family = detected (any donor) | 13,727 | 44.56% | 12,040 | 11,938 | 102 | 0.85% | 4 | 0.03% |
| len>=96, family = detected (any donor) | 20,058 | 65.11% | 17,420 | 16,956 | 464 | 2.66% | 21 | 0.12% |
| len>=96, >=2 donors if len<128, family = detected (any donor) | 17,943 | 58.25% | 15,495 | 15,155 | 340 | 2.19% | 18 | 0.12% |
| len>=96, >=2 independent donors (twin groups merged) if len<128, family = detected (any donor) | 17,939 | 58.24% | 15,491 | 15,151 | 340 | 2.19% | 18 | 0.12% |
| len>=96, >=2 donors, family = detected (any donor) | 11,531 | 37.43% | 10,157 | 10,083 | 74 | 0.73% | 2 | 0.02% |
| len>=96, >=2 independent donors (twin groups merged), family = detected (any donor) | 11,518 | 37.39% | 10,144 | 10,071 | 73 | 0.72% | 2 | 0.02% |
| len>=128, family = detected (any donor) | 16,186 | 52.55% | 14,003 | 13,683 | 320 | 2.29% | 18 | 0.13% |
| len>=128, >=2 donors, family = detected (any donor) | 9,774 | 31.73% | 8,665 | 8,611 | 54 | 0.62% | 2 | 0.02% |
| len>=128, >=2 independent donors (twin groups merged), family = detected (any donor) | 9,765 | 31.70% | 8,656 | 8,603 | 53 | 0.61% | 2 | 0.02% |
| len>=32 (any), family = detected (all donors) | 28,241 | 91.68% | 24,676 | 23,540 | 1,136 | 4.60% | 160 | 0.65% |
| len>=32 (any), >=2 donors if len<64, family = detected (all donors) | 25,385 | 82.41% | 22,233 | 21,463 | 770 | 3.46% | 76 | 0.34% |
| len>=32 (any), >=2 independent donors (twin groups merged) if len<64, family = detected (all donors) | 25,345 | 82.28% | 22,196 | 21,438 | 758 | 3.42% | 66 | 0.30% |
| len>=32 (any), >=2 donors if len<128, family = detected (all donors) | 21,077 | 68.42% | 18,408 | 17,969 | 439 | 2.38% | 38 | 0.21% |
| len>=32 (any), >=2 independent donors (twin groups merged) if len<128, family = detected (all donors) | 21,016 | 68.22% | 18,351 | 17,928 | 423 | 2.31% | 25 | 0.14% |
| len>=32 (any), >=2 donors, family = detected (all donors) | 14,665 | 47.61% | 13,070 | 12,897 | 173 | 1.32% | 22 | 0.17% |
| len>=32 (any), >=2 independent donors (twin groups merged), family = detected (all donors) | 14,595 | 47.38% | 13,004 | 12,848 | 156 | 1.20% | 9 | 0.07% |
| len>=48, family = detected (all donors) | 25,250 | 81.97% | 22,164 | 21,297 | 867 | 3.91% | 108 | 0.49% |
| len>=48, >=2 donors if len<64, family = detected (all donors) | 23,943 | 77.73% | 21,026 | 20,303 | 723 | 3.44% | 70 | 0.33% |
| len>=48, >=2 independent donors (twin groups merged) if len<64, family = detected (all donors) | 23,928 | 77.68% | 21,013 | 20,298 | 715 | 3.40% | 62 | 0.30% |
| len>=48, >=2 donors if len<128, family = detected (all donors) | 19,635 | 63.74% | 17,201 | 16,809 | 392 | 2.28% | 32 | 0.19% |
| len>=48, >=2 independent donors (twin groups merged) if len<128, family = detected (all donors) | 19,599 | 63.62% | 17,168 | 16,788 | 380 | 2.21% | 21 | 0.12% |
| len>=48, >=2 donors, family = detected (all donors) | 13,223 | 42.93% | 11,863 | 11,737 | 126 | 1.06% | 16 | 0.13% |
| len>=48, >=2 independent donors (twin groups merged), family = detected (all donors) | 13,178 | 42.78% | 11,821 | 11,708 | 113 | 0.96% | 5 | 0.04% |
| len>=64, family = detected (all donors) | 22,682 | 73.63% | 19,926 | 19,233 | 693 | 3.48% | 60 | 0.30% |
| len>=64, >=2 donors if len<128, family = detected (all donors) | 18,374 | 59.65% | 16,101 | 15,739 | 362 | 2.25% | 22 | 0.14% |
| len>=64, >=2 independent donors (twin groups merged) if len<128, family = detected (all donors) | 18,353 | 59.58% | 16,081 | 15,723 | 358 | 2.23% | 19 | 0.12% |
| len>=64, >=2 donors, family = detected (all donors) | 11,962 | 38.83% | 10,763 | 10,667 | 96 | 0.89% | 6 | 0.06% |
| len>=64, >=2 independent donors (twin groups merged), family = detected (all donors) | 11,932 | 38.74% | 10,734 | 10,643 | 91 | 0.85% | 3 | 0.03% |
| len>=96, family = detected (all donors) | 18,531 | 60.16% | 16,321 | 15,866 | 455 | 2.79% | 20 | 0.12% |
| len>=96, >=2 donors if len<128, family = detected (all donors) | 16,416 | 53.29% | 14,396 | 14,065 | 331 | 2.30% | 17 | 0.12% |
| len>=96, >=2 independent donors (twin groups merged) if len<128, family = detected (all donors) | 16,412 | 53.28% | 14,392 | 14,061 | 331 | 2.30% | 17 | 0.12% |
| len>=96, >=2 donors, family = detected (all donors) | 10,004 | 32.48% | 9,058 | 8,993 | 65 | 0.72% | 1 | 0.01% |
| len>=96, >=2 independent donors (twin groups merged), family = detected (all donors) | 9,991 | 32.43% | 9,045 | 8,981 | 64 | 0.71% | 1 | 0.01% |
| len>=128, family = detected (all donors) | 14,888 | 48.33% | 13,079 | 12,765 | 314 | 2.40% | 17 | 0.13% |
| len>=128, >=2 donors, family = detected (all donors) | 8,476 | 27.52% | 7,741 | 7,693 | 48 | 0.62% | 1 | 0.01% |
| len>=128, >=2 independent donors (twin groups merged), family = detected (all donors) | 8,467 | 27.49% | 7,732 | 7,685 | 47 | 0.61% | 1 | 0.01% |
| len>=32 (any), family = truth (any donor) | 29,475 | 95.69% | 25,737 | 24,585 | 1,152 | 4.48% | 161 | 0.63% |
| len>=32 (any), >=2 donors if len<64, family = truth (any donor) | 26,711 | 86.71% | 23,325 | 22,543 | 782 | 3.35% | 77 | 0.33% |
| len>=32 (any), >=2 independent donors (twin groups merged) if len<64, family = truth (any donor) | 26,671 | 86.58% | 23,288 | 22,518 | 770 | 3.31% | 67 | 0.29% |
| len>=32 (any), >=2 donors if len<128, family = truth (any donor) | 22,612 | 73.41% | 19,564 | 19,104 | 460 | 2.35% | 39 | 0.20% |
| len>=32 (any), >=2 independent donors (twin groups merged) if len<128, family = truth (any donor) | 22,551 | 73.21% | 19,507 | 19,063 | 444 | 2.28% | 26 | 0.13% |
| len>=32 (any), >=2 donors, family = truth (any donor) | 16,664 | 54.10% | 14,464 | 14,266 | 198 | 1.37% | 23 | 0.16% |
| len>=32 (any), >=2 independent donors (twin groups merged), family = truth (any donor) | 16,594 | 53.87% | 14,398 | 14,217 | 181 | 1.26% | 10 | 0.07% |
| len>=48, family = truth (any donor) | 26,349 | 85.54% | 23,113 | 22,240 | 873 | 3.78% | 109 | 0.47% |
| len>=48, >=2 donors if len<64, family = truth (any donor) | 25,080 | 81.42% | 21,988 | 21,262 | 726 | 3.30% | 71 | 0.32% |
| len>=48, >=2 independent donors (twin groups merged) if len<64, family = truth (any donor) | 25,065 | 81.37% | 21,975 | 21,257 | 718 | 3.27% | 63 | 0.29% |
| len>=48, >=2 donors if len<128, family = truth (any donor) | 20,981 | 68.11% | 18,227 | 17,823 | 404 | 2.22% | 33 | 0.18% |
| len>=48, >=2 independent donors (twin groups merged) if len<128, family = truth (any donor) | 20,945 | 67.99% | 18,194 | 17,802 | 392 | 2.15% | 22 | 0.12% |
| len>=48, >=2 donors, family = truth (any donor) | 15,033 | 48.80% | 13,127 | 12,985 | 142 | 1.08% | 17 | 0.13% |
| len>=48, >=2 independent donors (twin groups merged), family = truth (any donor) | 14,988 | 48.66% | 13,085 | 12,956 | 129 | 0.99% | 6 | 0.05% |
| len>=64, family = truth (any donor) | 23,581 | 76.55% | 20,714 | 20,024 | 690 | 3.33% | 61 | 0.29% |
| len>=64, >=2 donors if len<128, family = truth (any donor) | 19,482 | 63.25% | 16,953 | 16,585 | 368 | 2.17% | 23 | 0.14% |
| len>=64, >=2 independent donors (twin groups merged) if len<128, family = truth (any donor) | 19,461 | 63.18% | 16,933 | 16,569 | 364 | 2.15% | 20 | 0.12% |
| len>=64, >=2 donors, family = truth (any donor) | 13,534 | 43.94% | 11,853 | 11,747 | 106 | 0.89% | 7 | 0.06% |
| len>=64, >=2 independent donors (twin groups merged), family = truth (any donor) | 13,504 | 43.84% | 11,824 | 11,723 | 101 | 0.85% | 4 | 0.03% |
| len>=96, family = truth (any donor) | 19,316 | 62.71% | 16,971 | 16,514 | 457 | 2.69% | 21 | 0.12% |
| len>=96, >=2 donors if len<128, family = truth (any donor) | 17,297 | 56.15% | 15,082 | 14,747 | 335 | 2.22% | 18 | 0.12% |
| len>=96, >=2 independent donors (twin groups merged) if len<128, family = truth (any donor) | 17,293 | 56.14% | 15,078 | 14,743 | 335 | 2.22% | 18 | 0.12% |
| len>=96, >=2 donors, family = truth (any donor) | 11,349 | 36.84% | 9,982 | 9,909 | 73 | 0.73% | 2 | 0.02% |
| len>=96, >=2 independent donors (twin groups merged), family = truth (any donor) | 11,336 | 36.80% | 9,969 | 9,897 | 72 | 0.72% | 2 | 0.02% |
| len>=128, family = truth (any donor) | 15,569 | 50.54% | 13,619 | 13,304 | 315 | 2.31% | 18 | 0.13% |
| len>=128, >=2 donors, family = truth (any donor) | 9,621 | 31.23% | 8,519 | 8,466 | 53 | 0.62% | 2 | 0.02% |
| len>=128, >=2 independent donors (twin groups merged), family = truth (any donor) | 9,612 | 31.20% | 8,510 | 8,458 | 52 | 0.61% | 2 | 0.02% |

Gate columns: `len>=N` keeps renames whose pack body length is at least N bytes; `>=2 donors if len<N` drops a rename of fewer than N bytes that fewer than two donor games agree on (`independent donors` counts a twin group, e.g. both Pikmin 2 discs, once); `family = detected` keeps a rename when an agreeing donor (or every agreeing donor, `all`) has the compiler family the import's own donor vote implies (`implied_compiler` of the apply report), `family = truth` the same against the game's meta.json compiler (not available to a user). Identical kept sets are listed once.

- Baseline (no gate): 30,804 renames, strict rate 4.51%, function-wrong 0.61%.
- Most correct renames kept with strict rate <= 3%: **len>=32 (any), >=2 donors if len<128**: keeps 23,526 renames (76.37%), 19,727 correct, 473 wrong strict (2.34%), 39 function-wrong (0.19%)
- Most correct renames kept with strict rate <= 2%: **len>=32 (any), >=2 donors**: keeps 16,993 renames (55.16%), 14,577 correct, 199 wrong strict (1.35%), 23 function-wrong (0.16%)
- Most correct renames kept with strict rate <= 1%: **len>=48, >=2 independent donors (twin groups merged)**: keeps 15,282 renames (49.61%), 13,233 correct, 130 wrong strict (0.97%), 6 function-wrong (0.04%)
- Most correct renames kept with function-wrong rate <= 0.5%: **len>=32 (any), >=2 donors if len<64**: keeps 27,890 (90.54%), 23,252 correct, strict 3.37%, function-wrong 77 (0.32%)
- Most correct renames kept with function-wrong rate <= 0.2%: **len>=32 (any), >=2 donors if len<128**: keeps 23,526 (76.37%), 19,727 correct, strict 2.34%, function-wrong 39 (0.19%)

## Gates, gba

| gate | renames kept | % kept | scoreable | correct | strict wrong | strict rate | function-wrong | function rate |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| len>=32 (any) | 306 | 100.00% | 299 | 259 | 40 | 13.38% | 0 | 0.00% |
| len>=32 (any), >=2 donors if len<64 | 252 | 82.35% | 250 | 216 | 34 | 13.60% | 0 | 0.00% |
| len>=32 (any), >=2 donors if len<128 | 196 | 64.05% | 195 | 164 | 31 | 15.90% | 0 | 0.00% |
| len>=32 (any), >=2 donors | 134 | 43.79% | 134 | 107 | 27 | 20.15% | 0 | 0.00% |
| len>=48 | 255 | 83.33% | 252 | 221 | 31 | 12.30% | 0 | 0.00% |
| len>=48, >=2 donors if len<64 | 227 | 74.18% | 225 | 195 | 30 | 13.33% | 0 | 0.00% |
| len>=48, >=2 donors if len<128 | 171 | 55.88% | 170 | 143 | 27 | 15.88% | 0 | 0.00% |
| len>=48, >=2 donors | 109 | 35.62% | 109 | 86 | 23 | 21.10% | 0 | 0.00% |
| len>=64 | 213 | 69.61% | 211 | 183 | 28 | 13.27% | 0 | 0.00% |
| len>=64, >=2 donors if len<128 | 157 | 51.31% | 156 | 131 | 25 | 16.03% | 0 | 0.00% |
| len>=64, >=2 donors | 95 | 31.05% | 95 | 74 | 21 | 22.11% | 0 | 0.00% |
| len>=96 | 155 | 50.65% | 154 | 132 | 22 | 14.29% | 0 | 0.00% |
| len>=96, >=2 donors if len<128 | 141 | 46.08% | 140 | 118 | 22 | 15.71% | 0 | 0.00% |
| len>=96, >=2 donors | 79 | 25.82% | 79 | 61 | 18 | 22.78% | 0 | 0.00% |
| len>=128 | 113 | 36.93% | 112 | 99 | 13 | 11.61% | 0 | 0.00% |
| len>=128, >=2 donors | 51 | 16.67% | 51 | 42 | 9 | 17.65% | 0 | 0.00% |

## Gates, gc

| gate | renames kept | % kept | scoreable | correct | strict wrong | strict rate | function-wrong | function rate |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| len>=32 (any) | 8,744 | 100.00% | 8,712 | 8,577 | 135 | 1.55% | 54 | 0.62% |
| len>=32 (any), >=2 donors if len<64 | 7,806 | 89.27% | 7,805 | 7,751 | 54 | 0.69% | 14 | 0.18% |
| len>=32 (any), >=2 independent donors (twin groups merged) if len<64 | 7,792 | 89.11% | 7,791 | 7,739 | 52 | 0.67% | 13 | 0.17% |
| len>=32 (any), >=2 donors if len<128 | 6,494 | 74.27% | 6,494 | 6,463 | 31 | 0.48% | 8 | 0.12% |
| len>=32 (any), >=2 independent donors (twin groups merged) if len<128 | 6,478 | 74.09% | 6,478 | 6,450 | 28 | 0.43% | 7 | 0.11% |
| len>=32 (any), >=2 donors | 4,588 | 52.47% | 4,588 | 4,574 | 14 | 0.31% | 4 | 0.09% |
| len>=32 (any), >=2 independent donors (twin groups merged) | 4,572 | 52.29% | 4,572 | 4,561 | 11 | 0.24% | 3 | 0.07% |
| len>=48 | 7,819 | 89.42% | 7,817 | 7,744 | 73 | 0.93% | 26 | 0.33% |
| len>=48, >=2 donors if len<64 | 7,353 | 84.09% | 7,352 | 7,305 | 47 | 0.64% | 11 | 0.15% |
| len>=48, >=2 donors if len<128 | 6,041 | 69.09% | 6,041 | 6,017 | 24 | 0.40% | 5 | 0.08% |
| len>=48, >=2 independent donors (twin groups merged) if len<128 | 6,039 | 69.06% | 6,039 | 6,016 | 23 | 0.38% | 5 | 0.08% |
| len>=48, >=2 donors | 4,135 | 47.29% | 4,135 | 4,128 | 7 | 0.17% | 1 | 0.02% |
| len>=48, >=2 independent donors (twin groups merged) | 4,133 | 47.27% | 4,133 | 4,127 | 6 | 0.15% | 1 | 0.02% |
| len>=64 | 6,935 | 79.31% | 6,934 | 6,889 | 45 | 0.65% | 10 | 0.14% |
| len>=64, >=2 donors if len<128 | 5,623 | 64.31% | 5,623 | 5,601 | 22 | 0.39% | 4 | 0.07% |
| len>=64, >=2 independent donors (twin groups merged) if len<128 | 5,621 | 64.28% | 5,621 | 5,600 | 21 | 0.37% | 4 | 0.07% |
| len>=64, >=2 donors | 3,717 | 42.51% | 3,717 | 3,712 | 5 | 0.13% | 0 | 0.00% |
| len>=64, >=2 independent donors (twin groups merged) | 3,715 | 42.49% | 3,715 | 3,711 | 4 | 0.11% | 0 | 0.00% |
| len>=96 | 5,652 | 64.64% | 5,652 | 5,628 | 24 | 0.42% | 5 | 0.09% |
| len>=96, >=2 donors if len<128 | 5,079 | 58.09% | 5,079 | 5,059 | 20 | 0.39% | 4 | 0.08% |
| len>=96, >=2 donors | 3,173 | 36.29% | 3,173 | 3,170 | 3 | 0.09% | 0 | 0.00% |
| len>=128 | 4,595 | 52.55% | 4,595 | 4,575 | 20 | 0.44% | 4 | 0.09% |
| len>=128, >=2 donors | 2,689 | 30.75% | 2,689 | 2,686 | 3 | 0.11% | 0 | 0.00% |

## Gates, n64

| gate | renames kept | % kept | scoreable | correct | strict wrong | strict rate | function-wrong | function rate |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| len>=32 (any) | 2,826 | 100.00% | 2,748 | 2,409 | 339 | 12.34% | 5 | 0.18% |
| len>=32 (any), >=2 donors if len<64 | 2,320 | 82.09% | 2,265 | 2,024 | 241 | 10.64% | 4 | 0.18% |
| len>=32 (any), >=2 donors if len<128 | 1,645 | 58.21% | 1,609 | 1,483 | 126 | 7.83% | 4 | 0.25% |
| len>=32 (any), >=2 donors | 773 | 27.35% | 751 | 735 | 16 | 2.13% | 1 | 0.13% |
| len>=48 | 2,453 | 86.80% | 2,396 | 2,108 | 288 | 12.02% | 5 | 0.21% |
| len>=48, >=2 donors if len<64 | 2,232 | 78.98% | 2,183 | 1,944 | 239 | 10.95% | 4 | 0.18% |
| len>=48, >=2 donors if len<128 | 1,557 | 55.10% | 1,527 | 1,403 | 124 | 8.12% | 4 | 0.26% |
| len>=48, >=2 donors | 685 | 24.24% | 669 | 655 | 14 | 2.09% | 1 | 0.15% |
| len>=64 | 2,180 | 77.14% | 2,131 | 1,894 | 237 | 11.12% | 4 | 0.19% |
| len>=64, >=2 donors if len<128 | 1,505 | 53.26% | 1,475 | 1,353 | 122 | 8.27% | 4 | 0.27% |
| len>=64, >=2 donors | 633 | 22.40% | 617 | 605 | 12 | 1.94% | 1 | 0.16% |
| len>=96 | 1,659 | 58.70% | 1,626 | 1,457 | 169 | 10.39% | 3 | 0.18% |
| len>=96, >=2 donors if len<128 | 1,373 | 48.58% | 1,345 | 1,228 | 117 | 8.70% | 3 | 0.22% |
| len>=96, >=2 donors | 501 | 17.73% | 487 | 480 | 7 | 1.44% | 0 | 0.00% |
| len>=128 | 1,302 | 46.07% | 1,276 | 1,160 | 116 | 9.09% | 3 | 0.24% |
| len>=128, >=2 donors | 430 | 15.22% | 418 | 412 | 6 | 1.44% | 0 | 0.00% |
| len>=32 (any), family = detected (any donor) | 2,820 | 99.79% | 2,743 | 2,404 | 339 | 12.36% | 5 | 0.18% |
| len>=32 (any), >=2 donors if len<64, family = detected (any donor) | 2,314 | 81.88% | 2,260 | 2,019 | 241 | 10.66% | 4 | 0.18% |
| len>=32 (any), >=2 donors if len<128, family = detected (any donor) | 1,641 | 58.07% | 1,606 | 1,480 | 126 | 7.85% | 4 | 0.25% |
| len>=32 (any), >=2 donors, family = detected (any donor) | 770 | 27.25% | 748 | 732 | 16 | 2.14% | 1 | 0.13% |
| len>=48, family = detected (any donor) | 2,447 | 86.59% | 2,391 | 2,103 | 288 | 12.05% | 5 | 0.21% |
| len>=48, >=2 donors if len<64, family = detected (any donor) | 2,226 | 78.77% | 2,178 | 1,939 | 239 | 10.97% | 4 | 0.18% |
| len>=48, >=2 donors if len<128, family = detected (any donor) | 1,553 | 54.95% | 1,524 | 1,400 | 124 | 8.14% | 4 | 0.26% |
| len>=48, >=2 donors, family = detected (any donor) | 682 | 24.13% | 666 | 652 | 14 | 2.10% | 1 | 0.15% |
| len>=64, family = detected (any donor) | 2,174 | 76.93% | 2,126 | 1,889 | 237 | 11.15% | 4 | 0.19% |
| len>=64, >=2 donors if len<128, family = detected (any donor) | 1,501 | 53.11% | 1,472 | 1,350 | 122 | 8.29% | 4 | 0.27% |
| len>=64, >=2 donors, family = detected (any donor) | 630 | 22.29% | 614 | 602 | 12 | 1.95% | 1 | 0.16% |
| len>=96, family = detected (any donor) | 1,657 | 58.63% | 1,625 | 1,456 | 169 | 10.40% | 3 | 0.18% |
| len>=96, >=2 donors if len<128, family = detected (any donor) | 1,371 | 48.51% | 1,344 | 1,227 | 117 | 8.71% | 3 | 0.22% |
| len>=96, >=2 donors, family = detected (any donor) | 500 | 17.69% | 486 | 479 | 7 | 1.44% | 0 | 0.00% |
| len>=128, family = detected (any donor) | 1,300 | 46.00% | 1,275 | 1,159 | 116 | 9.10% | 3 | 0.24% |
| len>=128, >=2 donors, family = detected (any donor) | 429 | 15.18% | 417 | 411 | 6 | 1.44% | 0 | 0.00% |
| len>=32 (any), family = detected (all donors) | 2,773 | 98.12% | 2,700 | 2,361 | 339 | 12.56% | 5 | 0.19% |
| len>=32 (any), >=2 donors if len<64, family = detected (all donors) | 2,267 | 80.22% | 2,217 | 1,976 | 241 | 10.87% | 4 | 0.18% |
| len>=32 (any), >=2 donors if len<128, family = detected (all donors) | 1,594 | 56.40% | 1,563 | 1,437 | 126 | 8.06% | 4 | 0.26% |
| len>=32 (any), >=2 donors, family = detected (all donors) | 723 | 25.58% | 705 | 689 | 16 | 2.27% | 1 | 0.14% |
| len>=48, family = detected (all donors) | 2,409 | 85.24% | 2,356 | 2,068 | 288 | 12.22% | 5 | 0.21% |
| len>=48, >=2 donors if len<64, family = detected (all donors) | 2,188 | 77.42% | 2,143 | 1,904 | 239 | 11.15% | 4 | 0.19% |
| len>=48, >=2 donors if len<128, family = detected (all donors) | 1,515 | 53.61% | 1,489 | 1,365 | 124 | 8.33% | 4 | 0.27% |
| len>=48, >=2 donors, family = detected (all donors) | 644 | 22.79% | 631 | 617 | 14 | 2.22% | 1 | 0.16% |
| len>=64, family = detected (all donors) | 2,136 | 75.58% | 2,091 | 1,854 | 237 | 11.33% | 4 | 0.19% |
| len>=64, >=2 donors if len<128, family = detected (all donors) | 1,463 | 51.77% | 1,437 | 1,315 | 122 | 8.49% | 4 | 0.28% |
| len>=64, >=2 donors, family = detected (all donors) | 592 | 20.95% | 579 | 567 | 12 | 2.07% | 1 | 0.17% |
| len>=96, family = detected (all donors) | 1,635 | 57.86% | 1,605 | 1,436 | 169 | 10.53% | 3 | 0.19% |
| len>=96, >=2 donors if len<128, family = detected (all donors) | 1,349 | 47.74% | 1,324 | 1,207 | 117 | 8.84% | 3 | 0.23% |
| len>=96, >=2 donors, family = detected (all donors) | 478 | 16.91% | 466 | 459 | 7 | 1.50% | 0 | 0.00% |
| len>=128, family = detected (all donors) | 1,283 | 45.40% | 1,260 | 1,144 | 116 | 9.21% | 3 | 0.24% |
| len>=128, >=2 donors, family = detected (all donors) | 412 | 14.58% | 402 | 396 | 6 | 1.49% | 0 | 0.00% |

## Gates, nds

| gate | renames kept | % kept | scoreable | correct | strict wrong | strict rate | function-wrong | function rate |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| len>=32 (any) | 2,954 | 100.00% | 1,642 | 1,363 | 279 | 16.99% | 11 | 0.67% |
| len>=32 (any), >=2 donors if len<64 | 2,518 | 85.24% | 1,334 | 1,104 | 230 | 17.24% | 10 | 0.75% |
| len>=32 (any), >=2 donors if len<128 | 1,995 | 67.54% | 955 | 803 | 152 | 15.92% | 6 | 0.63% |
| len>=32 (any), >=2 donors | 1,338 | 45.29% | 496 | 428 | 68 | 13.71% | 1 | 0.20% |
| len>=48 | 2,419 | 81.89% | 1,364 | 1,129 | 235 | 17.23% | 11 | 0.81% |
| len>=48, >=2 donors if len<64 | 2,250 | 76.17% | 1,249 | 1,035 | 214 | 17.13% | 10 | 0.80% |
| len>=48, >=2 donors if len<128 | 1,727 | 58.46% | 870 | 734 | 136 | 15.63% | 6 | 0.69% |
| len>=48, >=2 donors | 1,070 | 36.22% | 411 | 359 | 52 | 12.65% | 1 | 0.24% |
| len>=64 | 2,067 | 69.97% | 1,177 | 973 | 204 | 17.33% | 10 | 0.85% |
| len>=64, >=2 donors if len<128 | 1,544 | 52.27% | 798 | 672 | 126 | 15.79% | 6 | 0.75% |
| len>=64, >=2 donors | 887 | 30.03% | 339 | 297 | 42 | 12.39% | 1 | 0.29% |
| len>=96 | 1,494 | 50.58% | 850 | 701 | 149 | 17.53% | 7 | 0.82% |
| len>=96, >=2 donors if len<128 | 1,261 | 42.69% | 671 | 560 | 111 | 16.54% | 6 | 0.89% |
| len>=96, >=2 donors | 604 | 20.45% | 212 | 185 | 27 | 12.74% | 1 | 0.47% |
| len>=128 | 1,083 | 36.66% | 621 | 517 | 104 | 16.75% | 6 | 0.97% |
| len>=128, >=2 donors | 426 | 14.42% | 162 | 142 | 20 | 12.35% | 1 | 0.62% |

## Gates, ps2

| gate | renames kept | % kept | scoreable | correct | strict wrong | strict rate | function-wrong | function rate |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| len>=32 (any) | 2,887 | 100.00% | 1,736 | 1,696 | 40 | 2.30% | 1 | 0.06% |
| len>=32 (any), >=2 donors if len<64 | 2,727 | 94.46% | 1,682 | 1,655 | 27 | 1.61% | 1 | 0.06% |
| len>=32 (any), >=2 donors if len<128 | 2,475 | 85.73% | 1,600 | 1,581 | 19 | 1.19% | 1 | 0.06% |
| len>=32 (any), >=2 donors | 1,853 | 64.18% | 1,263 | 1,246 | 17 | 1.35% | 1 | 0.08% |
| len>=48 | 2,612 | 90.47% | 1,576 | 1,553 | 23 | 1.46% | 1 | 0.06% |
| len>=48, >=2 donors if len<64 | 2,544 | 88.12% | 1,551 | 1,530 | 21 | 1.35% | 1 | 0.06% |
| len>=48, >=2 donors if len<128 | 2,292 | 79.39% | 1,469 | 1,456 | 13 | 0.88% | 1 | 0.07% |
| len>=48, >=2 donors | 1,670 | 57.85% | 1,132 | 1,121 | 11 | 0.97% | 1 | 0.09% |
| len>=64 | 2,377 | 82.33% | 1,438 | 1,422 | 16 | 1.11% | 1 | 0.07% |
| len>=64, >=2 donors if len<128 | 2,125 | 73.61% | 1,356 | 1,348 | 8 | 0.59% | 1 | 0.07% |
| len>=64, >=2 donors | 1,503 | 52.06% | 1,019 | 1,013 | 6 | 0.59% | 1 | 0.10% |
| len>=96 | 2,031 | 70.35% | 1,246 | 1,236 | 10 | 0.80% | 1 | 0.08% |
| len>=96, >=2 donors if len<128 | 1,912 | 66.23% | 1,199 | 1,193 | 6 | 0.50% | 1 | 0.08% |
| len>=96, >=2 donors | 1,290 | 44.68% | 862 | 858 | 4 | 0.46% | 1 | 0.12% |
| len>=128 | 1,728 | 59.85% | 1,071 | 1,066 | 5 | 0.47% | 1 | 0.09% |
| len>=128, >=2 donors | 1,106 | 38.31% | 734 | 731 | 3 | 0.41% | 1 | 0.14% |
| len>=32 (any), family = detected (any donor) | 2,708 | 93.80% | 1,635 | 1,606 | 29 | 1.77% | 1 | 0.06% |
| len>=32 (any), >=2 donors if len<64, family = detected (any donor) | 2,589 | 89.68% | 1,599 | 1,572 | 27 | 1.69% | 1 | 0.06% |
| len>=32 (any), >=2 donors if len<128, family = detected (any donor) | 2,370 | 82.09% | 1,536 | 1,517 | 19 | 1.24% | 1 | 0.07% |
| len>=32 (any), >=2 donors, family = detected (any donor) | 1,836 | 63.60% | 1,257 | 1,240 | 17 | 1.35% | 1 | 0.08% |
| len>=48, family = detected (any donor) | 2,463 | 85.31% | 1,489 | 1,467 | 22 | 1.48% | 1 | 0.07% |
| len>=48, >=2 donors if len<64, family = detected (any donor) | 2,408 | 83.41% | 1,468 | 1,447 | 21 | 1.43% | 1 | 0.07% |
| len>=48, >=2 donors if len<128, family = detected (any donor) | 2,189 | 75.82% | 1,405 | 1,392 | 13 | 0.93% | 1 | 0.07% |
| len>=48, >=2 donors, family = detected (any donor) | 1,655 | 57.33% | 1,126 | 1,115 | 11 | 0.98% | 1 | 0.09% |
| len>=64, family = detected (any donor) | 2,241 | 77.62% | 1,355 | 1,339 | 16 | 1.18% | 1 | 0.07% |
| len>=64, >=2 donors if len<128, family = detected (any donor) | 2,022 | 70.04% | 1,292 | 1,284 | 8 | 0.62% | 1 | 0.08% |
| len>=64, >=2 donors, family = detected (any donor) | 1,488 | 51.54% | 1,013 | 1,007 | 6 | 0.59% | 1 | 0.10% |
| len>=96, family = detected (any donor) | 1,908 | 66.09% | 1,169 | 1,159 | 10 | 0.86% | 1 | 0.09% |
| len>=96, >=2 donors if len<128, family = detected (any donor) | 1,809 | 62.66% | 1,135 | 1,129 | 6 | 0.53% | 1 | 0.09% |
| len>=96, >=2 donors, family = detected (any donor) | 1,275 | 44.16% | 856 | 852 | 4 | 0.47% | 1 | 0.12% |
| len>=128, family = detected (any donor) | 1,628 | 56.39% | 1,007 | 1,002 | 5 | 0.50% | 1 | 0.10% |
| len>=128, >=2 donors, family = detected (any donor) | 1,094 | 37.89% | 728 | 725 | 3 | 0.41% | 1 | 0.14% |
| len>=32 (any), family = detected (all donors) | 1,062 | 36.79% | 551 | 538 | 13 | 2.36% | 0 | 0.00% |
| len>=32 (any), >=2 donors if len<64, family = detected (all donors) | 943 | 32.66% | 515 | 504 | 11 | 2.14% | 0 | 0.00% |
| len>=32 (any), >=2 donors if len<128, family = detected (all donors) | 724 | 25.08% | 452 | 449 | 3 | 0.66% | 0 | 0.00% |
| len>=32 (any), >=2 donors, family = detected (all donors) | 190 | 6.58% | 173 | 172 | 1 | 0.58% | 0 | 0.00% |
| len>=48, family = detected (all donors) | 975 | 33.77% | 514 | 502 | 12 | 2.33% | 0 | 0.00% |
| len>=48, >=2 donors if len<64, family = detected (all donors) | 920 | 31.87% | 493 | 482 | 11 | 2.23% | 0 | 0.00% |
| len>=48, >=2 donors if len<128, family = detected (all donors) | 701 | 24.28% | 430 | 427 | 3 | 0.70% | 0 | 0.00% |
| len>=48, >=2 donors, family = detected (all donors) | 167 | 5.78% | 151 | 150 | 1 | 0.66% | 0 | 0.00% |
| len>=64, family = detected (all donors) | 913 | 31.62% | 486 | 475 | 11 | 2.26% | 0 | 0.00% |
| len>=64, >=2 donors if len<128, family = detected (all donors) | 694 | 24.04% | 423 | 420 | 3 | 0.71% | 0 | 0.00% |
| len>=64, >=2 donors, family = detected (all donors) | 160 | 5.54% | 144 | 143 | 1 | 0.69% | 0 | 0.00% |
| len>=96, family = detected (all donors) | 762 | 26.39% | 426 | 419 | 7 | 1.64% | 0 | 0.00% |
| len>=96, >=2 donors if len<128, family = detected (all donors) | 663 | 22.97% | 392 | 389 | 3 | 0.77% | 0 | 0.00% |
| len>=96, >=2 donors, family = detected (all donors) | 129 | 4.47% | 113 | 112 | 1 | 0.88% | 0 | 0.00% |
| len>=128, family = detected (all donors) | 642 | 22.24% | 374 | 371 | 3 | 0.80% | 0 | 0.00% |
| len>=128, >=2 donors, family = detected (all donors) | 108 | 3.74% | 95 | 94 | 1 | 1.05% | 0 | 0.00% |
| len>=32 (any), family = truth (any donor) | 1,848 | 64.01% | 1,208 | 1,181 | 27 | 2.24% | 1 | 0.08% |
| len>=32 (any), >=2 donors if len<64, family = truth (any donor) | 1,804 | 62.49% | 1,187 | 1,171 | 16 | 1.35% | 1 | 0.08% |
| len>=32 (any), >=2 donors if len<128, family = truth (any donor) | 1,768 | 61.24% | 1,165 | 1,149 | 16 | 1.37% | 1 | 0.09% |
| len>=32 (any), >=2 donors, family = truth (any donor) | 1,661 | 57.53% | 1,088 | 1,072 | 16 | 1.47% | 1 | 0.09% |
| len>=48, family = truth (any donor) | 1,659 | 57.46% | 1,084 | 1,072 | 12 | 1.11% | 1 | 0.09% |
| len>=48, >=2 donors if len<64, family = truth (any donor) | 1,644 | 56.94% | 1,078 | 1,068 | 10 | 0.93% | 1 | 0.09% |
| len>=48, >=2 donors if len<128, family = truth (any donor) | 1,608 | 55.70% | 1,056 | 1,046 | 10 | 0.95% | 1 | 0.09% |
| len>=48, >=2 donors, family = truth (any donor) | 1,501 | 51.99% | 979 | 969 | 10 | 1.02% | 1 | 0.10% |
| len>=64, family = truth (any donor) | 1,484 | 51.40% | 972 | 967 | 5 | 0.51% | 1 | 0.10% |
| len>=64, >=2 donors if len<128, family = truth (any donor) | 1,448 | 50.16% | 950 | 945 | 5 | 0.53% | 1 | 0.11% |
| len>=64, >=2 donors, family = truth (any donor) | 1,341 | 46.45% | 873 | 868 | 5 | 0.57% | 1 | 0.11% |
| len>=96, family = truth (any donor) | 1,287 | 44.58% | 838 | 835 | 3 | 0.36% | 1 | 0.12% |
| len>=96, >=2 donors if len<128, family = truth (any donor) | 1,266 | 43.85% | 824 | 821 | 3 | 0.36% | 1 | 0.12% |
| len>=96, >=2 donors, family = truth (any donor) | 1,159 | 40.15% | 747 | 744 | 3 | 0.40% | 1 | 0.13% |
| len>=128, family = truth (any donor) | 1,103 | 38.21% | 714 | 712 | 2 | 0.28% | 1 | 0.14% |
| len>=128, >=2 donors, family = truth (any donor) | 996 | 34.50% | 637 | 635 | 2 | 0.31% | 1 | 0.16% |

## Gates, psx

| gate | renames kept | % kept | scoreable | correct | strict wrong | strict rate | function-wrong | function rate |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| len>=32 (any) | 1,595 | 100.00% | 1,408 | 1,210 | 198 | 14.06% | 2 | 0.14% |
| len>=32 (any), >=2 donors if len<64 | 1,433 | 89.84% | 1,297 | 1,166 | 131 | 10.10% | 2 | 0.15% |
| len>=32 (any), >=2 donors if len<128 | 1,274 | 79.87% | 1,167 | 1,094 | 73 | 6.26% | 2 | 0.17% |
| len>=32 (any), >=2 donors | 1,064 | 66.71% | 999 | 972 | 27 | 2.70% | 1 | 0.10% |
| len>=48 | 1,369 | 85.83% | 1,217 | 1,085 | 132 | 10.85% | 2 | 0.16% |
| len>=48, >=2 donors if len<64 | 1,305 | 81.82% | 1,179 | 1,063 | 116 | 9.84% | 2 | 0.17% |
| len>=48, >=2 donors if len<128 | 1,146 | 71.85% | 1,049 | 991 | 58 | 5.53% | 2 | 0.19% |
| len>=48, >=2 donors | 936 | 58.68% | 881 | 869 | 12 | 1.36% | 1 | 0.11% |
| len>=64 | 1,122 | 70.34% | 1,009 | 898 | 111 | 11.00% | 1 | 0.10% |
| len>=64, >=2 donors if len<128 | 963 | 60.38% | 879 | 826 | 53 | 6.03% | 1 | 0.11% |
| len>=64, >=2 donors | 753 | 47.21% | 711 | 704 | 7 | 0.98% | 0 | 0.00% |
| len>=96 | 906 | 56.80% | 816 | 741 | 75 | 9.19% | 1 | 0.12% |
| len>=96, >=2 donors if len<128 | 829 | 51.97% | 752 | 699 | 53 | 7.05% | 1 | 0.13% |
| len>=96, >=2 donors | 619 | 38.81% | 584 | 577 | 7 | 1.20% | 0 | 0.00% |
| len>=128 | 719 | 45.08% | 648 | 597 | 51 | 7.87% | 1 | 0.15% |
| len>=128, >=2 donors | 509 | 31.91% | 480 | 475 | 5 | 1.04% | 0 | 0.00% |
| len>=32 (any), family = detected (any donor) | 1,486 | 93.17% | 1,309 | 1,135 | 174 | 13.29% | 2 | 0.15% |
| len>=32 (any), >=2 donors if len<64, family = detected (any donor) | 1,341 | 84.08% | 1,213 | 1,097 | 116 | 9.56% | 2 | 0.16% |
| len>=32 (any), >=2 donors if len<128, family = detected (any donor) | 1,203 | 75.42% | 1,100 | 1,035 | 65 | 5.91% | 2 | 0.18% |
| len>=32 (any), >=2 donors, family = detected (any donor) | 1,025 | 64.26% | 960 | 933 | 27 | 2.81% | 1 | 0.10% |
| len>=48, family = detected (any donor) | 1,281 | 80.31% | 1,137 | 1,022 | 115 | 10.11% | 2 | 0.18% |
| len>=48, >=2 donors if len<64, family = detected (any donor) | 1,221 | 76.55% | 1,103 | 1,002 | 101 | 9.16% | 2 | 0.18% |
| len>=48, >=2 donors if len<128, family = detected (any donor) | 1,083 | 67.90% | 990 | 940 | 50 | 5.05% | 2 | 0.20% |
| len>=48, >=2 donors, family = detected (any donor) | 905 | 56.74% | 850 | 838 | 12 | 1.41% | 1 | 0.12% |
| len>=64, family = detected (any donor) | 1,045 | 65.52% | 940 | 844 | 96 | 10.21% | 1 | 0.11% |
| len>=64, >=2 donors if len<128, family = detected (any donor) | 907 | 56.87% | 827 | 782 | 45 | 5.44% | 1 | 0.12% |
| len>=64, >=2 donors, family = detected (any donor) | 729 | 45.71% | 687 | 680 | 7 | 1.02% | 0 | 0.00% |
| len>=96, family = detected (any donor) | 848 | 53.17% | 763 | 698 | 65 | 8.52% | 1 | 0.13% |
| len>=96, >=2 donors if len<128, family = detected (any donor) | 780 | 48.90% | 707 | 662 | 45 | 6.36% | 1 | 0.14% |
| len>=96, >=2 donors, family = detected (any donor) | 602 | 37.74% | 567 | 560 | 7 | 1.23% | 0 | 0.00% |
| len>=128, family = detected (any donor) | 673 | 42.19% | 606 | 563 | 43 | 7.10% | 1 | 0.17% |
| len>=128, >=2 donors, family = detected (any donor) | 495 | 31.03% | 466 | 461 | 5 | 1.07% | 0 | 0.00% |
| len>=32 (any), family = detected (all donors) | 910 | 57.05% | 778 | 614 | 164 | 21.08% | 2 | 0.26% |
| len>=32 (any), >=2 donors if len<64, family = detected (all donors) | 765 | 47.96% | 682 | 576 | 106 | 15.54% | 2 | 0.29% |
| len>=32 (any), >=2 donors if len<128, family = detected (all donors) | 627 | 39.31% | 569 | 514 | 55 | 9.67% | 2 | 0.35% |
| len>=32 (any), >=2 donors, family = detected (all donors) | 449 | 28.15% | 429 | 412 | 17 | 3.96% | 1 | 0.23% |
| len>=48, family = detected (all donors) | 752 | 47.15% | 645 | 537 | 108 | 16.74% | 2 | 0.31% |
| len>=48, >=2 donors if len<64, family = detected (all donors) | 692 | 43.39% | 611 | 517 | 94 | 15.38% | 2 | 0.33% |
| len>=48, >=2 donors if len<128, family = detected (all donors) | 554 | 34.73% | 498 | 455 | 43 | 8.63% | 2 | 0.40% |
| len>=48, >=2 donors, family = detected (all donors) | 376 | 23.57% | 358 | 353 | 5 | 1.40% | 1 | 0.28% |
| len>=64, family = detected (all donors) | 616 | 38.62% | 538 | 448 | 90 | 16.73% | 1 | 0.19% |
| len>=64, >=2 donors if len<128, family = detected (all donors) | 478 | 29.97% | 425 | 386 | 39 | 9.18% | 1 | 0.24% |
| len>=64, >=2 donors, family = detected (all donors) | 300 | 18.81% | 285 | 284 | 1 | 0.35% | 0 | 0.00% |
| len>=96, family = detected (all donors) | 489 | 30.66% | 427 | 368 | 59 | 13.82% | 1 | 0.23% |
| len>=96, >=2 donors if len<128, family = detected (all donors) | 421 | 26.39% | 371 | 332 | 39 | 10.51% | 1 | 0.27% |
| len>=96, >=2 donors, family = detected (all donors) | 243 | 15.24% | 231 | 230 | 1 | 0.43% | 0 | 0.00% |
| len>=128, family = detected (all donors) | 378 | 23.70% | 330 | 291 | 39 | 11.82% | 1 | 0.30% |
| len>=128, >=2 donors, family = detected (all donors) | 200 | 12.54% | 190 | 189 | 1 | 0.53% | 0 | 0.00% |
| len>=32 (any), family = truth (any donor) | 1,311 | 82.19% | 1,139 | 973 | 166 | 14.57% | 2 | 0.18% |
| len>=32 (any), >=2 donors if len<64, family = truth (any donor) | 1,183 | 74.17% | 1,059 | 946 | 113 | 10.67% | 2 | 0.19% |
| len>=32 (any), >=2 donors if len<128, family = truth (any donor) | 1,071 | 67.15% | 969 | 906 | 63 | 6.50% | 2 | 0.21% |
| len>=32 (any), >=2 donors, family = truth (any donor) | 930 | 58.31% | 865 | 838 | 27 | 3.12% | 1 | 0.12% |
| len>=48, family = truth (any donor) | 1,129 | 70.78% | 989 | 875 | 114 | 11.53% | 2 | 0.20% |
| len>=48, >=2 donors if len<64, family = truth (any donor) | 1,067 | 66.90% | 953 | 855 | 98 | 10.28% | 2 | 0.21% |
| len>=48, >=2 donors if len<128, family = truth (any donor) | 955 | 59.87% | 863 | 815 | 48 | 5.56% | 2 | 0.23% |
| len>=48, >=2 donors, family = truth (any donor) | 814 | 51.03% | 759 | 747 | 12 | 1.58% | 1 | 0.13% |
| len>=64, family = truth (any donor) | 906 | 56.80% | 805 | 712 | 93 | 11.55% | 1 | 0.12% |
| len>=64, >=2 donors if len<128, family = truth (any donor) | 794 | 49.78% | 715 | 672 | 43 | 6.01% | 1 | 0.14% |
| len>=64, >=2 donors, family = truth (any donor) | 653 | 40.94% | 611 | 604 | 7 | 1.15% | 0 | 0.00% |
| len>=96, family = truth (any donor) | 727 | 45.58% | 645 | 580 | 65 | 10.08% | 1 | 0.16% |
| len>=96, >=2 donors if len<128, family = truth (any donor) | 677 | 42.45% | 605 | 562 | 43 | 7.11% | 1 | 0.17% |
| len>=96, >=2 donors, family = truth (any donor) | 536 | 33.61% | 501 | 494 | 7 | 1.40% | 0 | 0.00% |
| len>=128, family = truth (any donor) | 581 | 36.43% | 515 | 474 | 41 | 7.96% | 1 | 0.19% |
| len>=128, >=2 donors, family = truth (any donor) | 440 | 27.59% | 411 | 406 | 5 | 1.22% | 0 | 0.00% |

## Gates, wii

| gate | renames kept | % kept | scoreable | correct | strict wrong | strict rate | function-wrong | function rate |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| len>=32 (any) | 11,492 | 100.00% | 9,994 | 9,828 | 166 | 1.66% | 88 | 0.88% |
| len>=32 (any), >=2 donors if len<64 | 10,834 | 94.27% | 9,430 | 9,336 | 94 | 1.00% | 46 | 0.49% |
| len>=32 (any), >=2 independent donors (twin groups merged) if len<64 | 10,808 | 94.05% | 9,407 | 9,323 | 84 | 0.89% | 37 | 0.39% |
| len>=32 (any), >=2 donors if len<128 | 9,447 | 82.21% | 8,180 | 8,139 | 41 | 0.50% | 18 | 0.22% |
| len>=32 (any), >=2 independent donors (twin groups merged) if len<128 | 9,402 | 81.81% | 8,139 | 8,111 | 28 | 0.34% | 6 | 0.07% |
| len>=32 (any), >=2 donors | 7,243 | 63.03% | 6,545 | 6,515 | 30 | 0.46% | 15 | 0.23% |
| len>=32 (any), >=2 independent donors (twin groups merged) | 7,189 | 62.56% | 6,495 | 6,479 | 16 | 0.25% | 3 | 0.05% |
| len>=48 | 10,621 | 92.42% | 9,216 | 9,096 | 120 | 1.30% | 64 | 0.69% |
| len>=48, >=2 donors if len<64 | 10,313 | 89.74% | 8,953 | 8,865 | 88 | 0.98% | 43 | 0.48% |
| len>=48, >=2 independent donors (twin groups merged) if len<64 | 10,298 | 89.61% | 8,940 | 8,860 | 80 | 0.89% | 35 | 0.39% |
| len>=48, >=2 donors if len<128 | 8,926 | 77.67% | 7,703 | 7,668 | 35 | 0.45% | 15 | 0.19% |
| len>=48, >=2 independent donors (twin groups merged) if len<128 | 8,892 | 77.38% | 7,672 | 7,648 | 24 | 0.31% | 4 | 0.05% |
| len>=48, >=2 donors | 6,722 | 58.49% | 6,068 | 6,044 | 24 | 0.40% | 12 | 0.20% |
| len>=48, >=2 independent donors (twin groups merged) | 6,679 | 58.12% | 6,028 | 6,016 | 12 | 0.20% | 1 | 0.02% |
| len>=64 | 9,802 | 85.29% | 8,489 | 8,411 | 78 | 0.92% | 35 | 0.41% |
| len>=64, >=2 donors if len<128 | 8,415 | 73.22% | 7,239 | 7,214 | 25 | 0.35% | 7 | 0.10% |
| len>=64, >=2 independent donors (twin groups merged) if len<128 | 8,396 | 73.06% | 7,221 | 7,199 | 22 | 0.30% | 4 | 0.06% |
| len>=64, >=2 donors | 6,211 | 54.05% | 5,604 | 5,590 | 14 | 0.25% | 4 | 0.07% |
| len>=64, >=2 independent donors (twin groups merged) | 6,183 | 53.80% | 5,577 | 5,567 | 10 | 0.18% | 1 | 0.02% |
| len>=96 | 8,344 | 72.61% | 7,207 | 7,182 | 25 | 0.35% | 4 | 0.06% |
| len>=96, >=2 donors if len<128 | 7,502 | 65.28% | 6,419 | 6,400 | 19 | 0.30% | 3 | 0.05% |
| len>=96, >=2 independent donors (twin groups merged) if len<128 | 7,498 | 65.25% | 6,415 | 6,396 | 19 | 0.30% | 3 | 0.05% |
| len>=96, >=2 donors | 5,298 | 46.10% | 4,784 | 4,776 | 8 | 0.17% | 0 | 0.00% |
| len>=96, >=2 independent donors (twin groups merged) | 5,285 | 45.99% | 4,771 | 4,764 | 7 | 0.15% | 0 | 0.00% |
| len>=128 | 6,794 | 59.12% | 5,787 | 5,768 | 19 | 0.33% | 3 | 0.05% |
| len>=128, >=2 donors | 4,590 | 39.94% | 4,152 | 4,144 | 8 | 0.19% | 0 | 0.00% |
| len>=128, >=2 independent donors (twin groups merged) | 4,581 | 39.86% | 4,143 | 4,136 | 7 | 0.17% | 0 | 0.00% |

## Detected against true compiler family

The family of the apply report's `implied_compiler` (the donors' compiler vote of the run) against the game's meta.json compiler family, per program unit that made at least one rename.

| platform | program units with renames | detected = truth | detected differs | no detection |
|---|---:|---:|---:|---:|
| gba | 5 | 5 | 0 | 0 |
| gc | 30 | 30 | 0 | 0 |
| n64 | 9 | 9 | 0 | 0 |
| nds | 26 | 26 | 0 | 0 |
| ps2 | 8 | 1 | 7 | 0 |
| psx | 43 | 30 | 13 | 0 |
| wii | 445 | 445 | 0 | 0 |

