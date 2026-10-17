# Compiler detection accuracy

Generated 2026-10-13 08:01 UTC by `benchmarks/compiler_detection_accuracy.py` (`romwright-cli` sha256 `50b57cb37514854f...`). 

`programs.compiler` after `import --no-analysis`, against the id the game's truth text names (`expected_id` in the script). `exact`: the truth id or one built on it; `lineage`: right toolchain lineage, different family; `abstained`: `unknown`; `wrong`: a different lineage.

## By platform

| platform | scored | exact | lineage only | abstained | wrong |
|---|---|---|---|---|---|
| gba | 6 | 6 | 0 | 0 | 0 |
| gc | 9 | 9 | 0 | 0 | 0 |
| n64 | 9 | 9 | 0 | 0 | 0 |
| nds | 6 | 6 | 0 | 0 | 0 |
| ps2 | 10 | 9 | 1 | 0 | 0 |
| psp | 6 | 6 | 0 | 0 | 0 |
| psx | 8 | 0 | 0 | 8 | 0 |
| wii | 5 | 5 | 0 | 0 | 0 |
| x360 | 5 | 5 | 0 | 0 | 0 |
| **all** | 64 | 55 | 1 | 8 | 0 |

## By game

| game | truth | detected | verdict | evidence |
|---|---|---|---|---|
| gba-fire-emblem-sacred-stones | agbcc | agbcc | exact | 7522 Thumb `pop {rX}; bx rX` returns against 11013 `pop {..,pc}` (share 0.406) |
| gba-golden-sun | agbcc | agbcc | exact | 1969 Thumb `pop {rX}; bx rX` returns against 8055 `pop {..,pc}` (share 0.196) |
| gba-kh-chain-of-memories | agbcc | agbcc | exact | 4359 Thumb `pop {rX}; bx rX` returns against 18731 `pop {..,pc}` (share 0.189) |
| gba-klonoa-empire-of-dreams | agbcc | agbcc | exact | 401 Thumb `pop {rX}; bx rX` returns against 3376 `pop {..,pc}` (share 0.106) |
| gba-nascar-heat-2002 | agbcc | agbcc | exact | 953 Thumb `pop {rX}; bx rX` returns against 2018 `pop {..,pc}` (share 0.321) |
| gc-mario-party-4 | mwcc-gc | mwcc-gc | exact | `Metrowerks Target Resident Kernel` string (no SDK banner names the console) |
| gc-melee | mwcc-gc | mwcc-gc | exact | `Metrowerks Target Resident Kernel` string (no SDK banner names the console) |
| gc-pikmin | mwcc-gc | mwcc-gc | exact | `Metrowerks Target Resident Kernel` string (no SDK banner names the console) |
| gc-pikmin-2 | mwcc-gc | mwcc-gc | exact | `<< Dolphin SDK - ...` library banner (Dolphin SDK, CodeWarrior) |
| gc-super-mario-strikers | mwcc-gc | mwcc-gc | exact | `<< Dolphin SDK - ...` library banner (Dolphin SDK, CodeWarrior) |
| gc-tiger-woods-2004 | mwcc-gc | mwcc-gc | exact | `<< Dolphin SDK - ...` library banner (Dolphin SDK, CodeWarrior) |
| gc-twilight-princess | mwcc-gc | mwcc-gc | exact | `<< Dolphin SDK - ...` library banner (Dolphin SDK, CodeWarrior) |
| gc-wind-waker | mwcc-gc | mwcc-gc | exact | `<< Dolphin SDK - ...` library banner (Dolphin SDK, CodeWarrior) |
| n64-banjo-kazooie | ido | ido | exact | `move` is `or rd,rs,$zero` 10965 times and `addu rd,rs,$zero` 2 times (or-share 1.000) |
| n64-dr-mario-64 | n64-gcc | n64-gcc | exact | `move` is `or rd,rs,$zero` 0 times and `addu rd,rs,$zero` 5589 times (or-share 0.000) |
| n64-majoras-mask | ido | ido | exact | `move` is `or rd,rs,$zero` 53440 times and `addu rd,rs,$zero` 182 times (or-share 0.997) |
| n64-ocarina-of-time | ido | ido | exact | `move` is `or rd,rs,$zero` 36656 times and `addu rd,rs,$zero` 222 times (or-share 0.994) |
| n64-paper-mario | n64-gcc | n64-gcc | exact | `move` is `or rd,rs,$zero` 14 times and `addu rd,rs,$zero` 785 times (or-share 0.018) |
| n64-perfect-dark | ido | ido | exact | `move` is `or rd,rs,$zero` 17666 times and `addu rd,rs,$zero` 12 times (or-share 0.999) |
| n64-star-fox-64 | ido | ido | exact | `move` is `or rd,rs,$zero` 4574 times and `addu rd,rs,$zero` 16 times (or-share 0.997) |
| n64-super-mario-64 | ido | ido | exact | `move` is `or rd,rs,$zero` 2006 times and `addu rd,rs,$zero` 35 times (or-share 0.983) |
| n64-super-smash-bros | ido | ido | exact | `move` is `or rd,rs,$zero` 4576 times and `addu rd,rs,$zero` 45 times (or-share 0.990) |
| nds-dragon-quest-iv | mwcc-arm | mwcc-arm | exact | NitroSDK banner `[SDK+NINTENDO:...]` (SDK libraries are built with CodeWarrior) |
| nds-kh-358-2-days | mwcc-arm | mwcc-arm | exact | NitroSDK banner `[SDK+NINTENDO:...]` (SDK libraries are built with CodeWarrior) |
| nds-kh-recoded | mwcc-arm | mwcc-arm | exact | NitroSDK banner `[SDK+NINTENDO:...]` (SDK libraries are built with CodeWarrior) |
| nds-pokemon-platinum | mwcc-arm | mwcc-arm | exact | NitroSDK banner `[SDK+NINTENDO:...]` (SDK libraries are built with CodeWarrior) |
| nds-world-ends-with-you | mwcc-arm | mwcc-arm | exact | NitroSDK banner `[SDK+NINTENDO:...]` (SDK libraries are built with CodeWarrior) |
| ps2-dark-chronicle | mwcc-ps2 | mwcc-ps2-2.4 | exact | .comment: Metrowerks linker stamp `MW MIPS C Compiler (2.4.1.01)` |
| ps2-dark-cloud | mwcc-ps2 | mwcc-ps2-2.3 | exact | .comment: Metrowerks linker stamp `MW MIPS C Compiler (2.3.1.01)` |
| ps2-digital-devil-saga | ee-gcc | ee-gcc-2.9x | exact | `.mdebug.eabi64` ECOFF debug section (GNU toolchain) |
| ps2-fatal-frame | ee-gcc | ee-gcc-2.9x | exact | `.mdebug` ECOFF debug section (GNU toolchain) |
| ps2-god-hand | sn-prodg | sn-prodg | exact | `.mdebug.eabi64` ECOFF debug section (GNU toolchain) |
| ps2-persona-4 | mwcc-ps2 | mwcc-ps2-2.4 | exact | .comment: Metrowerks linker stamp `MW MIPS C Compiler (2.4.1.01)` |
| ps2-ratchet-clank | ee-gcc | ee-gcc-2.9x | exact | `.vutext`/`.DVP.*` sections (Sony ee-ld/dvp-as output) |
| ps2-ratchet-clank-pal | sn-prodg | ee-gcc-2.9x | lineage | `.vutext`/`.DVP.*` sections (Sony ee-ld/dvp-as output) |
| psp-hot-pixel | allegrex-gcc | allegrex-gcc | exact | `GCC: (GNU) 3.3.6` stamp on a PSP image |
| psp-melodie | allegrex-gcc | allegrex-gcc | exact | `.mdebug.eabi32` ECOFF debug section (GNU linker output) |
| psp-pac-man-rally | allegrex-gcc | allegrex-gcc | exact | `.gcc_compiled_long32` section (GCC's own marker) |
| psp-psp-camera-01 | mwcc-psp | mwcc-psp | exact | `MW MIPS C Compiler (2.4.1.01)` stamp |
| psp-tetris | mwcc-psp | mwcc-psp | exact | `MW MIPS C Compiler (2.4.1.01)` stamp |
| psx-digimon-world | mwcc-psx | unknown | abstained | PlayStation 1: Psy-Q GCC and CodeWarrior images share the Sony library strings and the `move` spelling; no byt |
| psx-legend-of-mana | psyq-gcc | unknown | abstained | PlayStation 1: Psy-Q GCC and CodeWarrior images share the Sony library strings and the `move` spelling; no byt |
| psx-nfs-high-stakes | psyq-gcc | unknown | abstained | PlayStation 1: Psy-Q GCC and CodeWarrior images share the Sony library strings and the `move` spelling; no byt |
| psx-parasite-eve | psyq-gcc | unknown | abstained | PlayStation 1: Psy-Q GCC and CodeWarrior images share the Sony library strings and the `move` spelling; no byt |
| psx-parasite-eve-2 | psyq-gcc | unknown | abstained | PlayStation 1: Psy-Q GCC and CodeWarrior images share the Sony library strings and the `move` spelling; no byt |
| psx-rage-racer | psyq-gcc | unknown | abstained | PlayStation 1: Psy-Q GCC and CodeWarrior images share the Sony library strings and the `move` spelling; no byt |
| psx-silent-hill | psyq-gcc | unknown | abstained | PlayStation 1: Psy-Q GCC and CodeWarrior images share the Sony library strings and the `move` spelling; no byt |
| psx-vagrant-story | psyq-gcc | unknown | abstained | PlayStation 1: Psy-Q GCC and CodeWarrior images share the Sony library strings and the `move` spelling; no byt |
| wii-mario-strikers-charged | mwcc-wii | mwcc-wii | exact | `<< RVL_SDK - ...` library banner (Revolution SDK, CodeWarrior) |
| wii-npc-pikmin-2 | mwcc-wii | mwcc-wii | exact | `<< RVL_SDK - ...` library banner (Revolution SDK, CodeWarrior) |
| wii-rock-band-3 | mwcc-wii | mwcc-wii | exact | `<< RVL_SDK - ...` library banner (Revolution SDK, CodeWarrior) |
| wii-skyward-sword | mwcc-wii | mwcc-wii | exact | `<< RVL_SDK - ...` library banner (Revolution SDK, CodeWarrior) |
| wii-super-mario-galaxy | mwcc-wii | mwcc-wii | exact | `<< RVL_SDK - ...` library banner (Revolution SDK, CodeWarrior) |
| x360-amped-3 | msvc-14 | msvc-14 | exact | PE optional header linker version 8.0 (compiler 14.x) |
| x360-burnout-crash | msvc-16 | msvc-16 | exact | PE optional header linker version 10.0 (compiler 16.x) |
| x360-call-of-duty-advanced-warfare | msvc-16 | msvc-16 | exact | PE optional header linker version 10.0 (compiler 16.x) |
| x360-call-of-duty-modern-warfare-2 | msvc-15 | msvc-15 | exact | PE optional header linker version 9.0 (compiler 15.x) |
| x360-forza-horizon-2-prototype | msvc-16 | msvc-16 | exact | PE optional header linker version 10.0 (compiler 16.x) |
| gba-pokeemerald | agbcc | agbcc | exact | 14638 Thumb `pop {rX}; bx rX` returns against 11400 `pop {..,pc}` (share 0.562) |
| gc-animal-crossing | mwcc-gc | mwcc-gc | exact | `Metrowerks Target Resident Kernel` string (no SDK banner names the console) |
| nds-pokeheartgold | mwcc-arm | mwcc-arm | exact | NitroSDK banner `[SDK+NINTENDO:...]` (SDK libraries are built with CodeWarrior) |
| ps2-capcom-fighting-evolution | mwcc-ps2 | mwcc-ps2-2.4 | exact | .comment: Metrowerks linker stamp `MW MIPS C Compiler (2.4.1.01)` |
| ps2-dungeon-game | ee-gcc | ee-gcc-3.x | exact | .comment: `GCC: (GNU) 3.2.2` |
| psp-puzzle-bobble-pocket | allegrex-gcc | allegrex-gcc | exact | `GCC: (GNU) 3.3.3` stamp on a PSP image |

## Controls

Synthetic images, not corpus games and not in the totals: what the detector says about a toolchain the corpus has no game for.

| control | expected | detected | verdict | evidence |
|---|---|---|---|---|
| gba-gcc15-armv4t-thumb | devkitarm-gcc | devkitarm-gcc | exact | 4926 Thumb `pop {rX}; bx rX` returns against 0 `pop {..,pc}` (share 1.000) |
