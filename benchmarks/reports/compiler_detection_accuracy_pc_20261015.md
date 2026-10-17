# Compiler detection accuracy

Generated 2026-10-15 07:58 UTC by `benchmarks/compiler_detection_accuracy.py` (`romwright-cli` sha256 `a677503efac0ca1e...`). 

`programs.compiler` after `import --no-analysis`, against the id the game's truth text names (`expected_id` in the script). `exact`: the truth id or one built on it; `lineage`: right toolchain lineage, different family; `abstained`: `unknown`; `wrong`: a different lineage.

## By platform

| platform | scored | exact | lineage only | abstained | wrong |
|---|---|---|---|---|---|
| pc | 8 | 8 | 0 | 0 | 0 |
| **all** | 8 | 8 | 0 | 0 | 0 |

## By game

| game | truth | detected | verdict | evidence |
|---|---|---|---|---|
| pc-doomgeneric-mingw32 | mingw-gcc-16 | mingw-gcc-16 | exact | GCC stamp in the image: `GCC: (GNU) 16.2.1 20260819 (Fedora MinGW 16.2.1-1.fc44)` (the commonest one) |
| pc-glquake-msvc42 | msvc-10 | msvc-10 | exact | PE optional header linker version 4.20 (cl 10.x) |
| pc-ioq3-ded-mingw32 | mingw-gcc-16 | mingw-gcc-16 | exact | GCC stamp in the image: `GCC: (GNU) 16.2.1 20260819 (Fedora MinGW 16.2.1-1.fc44)` (the commonest one) |
| pc-ioq3-ded-mingw64 | mingw-gcc-16 | mingw-gcc-16 | exact | GCC stamp in the image: `GCC: (GNU) 16.2.1 20260819 (Fedora MinGW 16.2.1-1.fc44)` (the commonest one) |
| pc-quake2-game-msvc8 | msvc-14 | msvc-14 | exact | PE optional header linker version 8.0 (cl 14.x) |
| pc-quake2-game-msvc8-debug | msvc-14 | msvc-14 | exact | PE optional header linker version 8.0 (cl 14.x) |
| pc-quake2-msvc8 | msvc-14 | msvc-14 | exact | PE optional header linker version 8.0 (cl 14.x) |
| pc-quake2-refgl-msvc8 | msvc-14 | msvc-14 | exact | PE optional header linker version 8.0 (cl 14.x) |

## Controls

Synthetic images, not corpus games and not in the totals: what the detector says about a toolchain the corpus has no game for.

| control | expected | detected | verdict | evidence |
|---|---|---|---|---|
| kotor2 | msvc-13 | msvc-13 | exact | PE optional header linker version 7.0 (cl 13.x) |
| vc6 | msvc-12 | msvc-12 | exact | PE optional header linker version 6.0 (cl 12.x) |
| vc71 | msvc-13.1 | msvc-13.1 | exact | PE optional header linker version 7.10 (cl 13.1.x) |
