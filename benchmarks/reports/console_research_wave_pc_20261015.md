# Console research wave (2026-10-15T07:23:02+00:00)

Tools fingerprint `262f665303b8a4dc`; sample n=100 per seed, seeds [1, 2]; combined = the union of the seeds' samples (rows deduplicated). Truth: `<corpus>/<id>/truth/{meta.json,functions.tsv}`. Headline metrics are the frozen ones (recall, precision, success rate, arity, type exact); `recall_verified` / `precision_verified` are the supplement over `verified=1` rows (docs/console-research.md).

## Images

| id | game | version | match | truth | compiler | linked % | truth fns | verified | nested (size 0) | scored modules | unplaced fns | stripped | status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| pc-doomgeneric-mingw32 | doomgeneric (DOOM engine, Win32 GDI frontend) | None | True | dwarf+coff | GCC 16.2.1 MinGW-w64 13.0.0 (Fedora 44 mingw32-gcc 16.2.1-1.fc44), i686-w64-mingw32, GNU ld 2.46 | None | 1077 | 1077 | 0 (0) | main | 0 | False | ran |
| pc-glquake-msvc42 | GLQuake (Quake 1, WinQuake GL Release target, C-only, no DirectInput mouse path) | None | True | coff | MSVC 10.20 (Visual C++ 4.2, itsmattkc/msvc420@df2c13aad74c094988c6c7e784234c2e778a0e91: cl.exe/link.exe 4.20 under wine 11.0), static CRT libc.lib 4.2 | None | 1331 | 1331 | 0 (0) | main | 0 | False | ran |
| pc-ioq3-ded-mingw32 | ioquake3 dedicated server (Quake III Arena engine) | None | True | dwarf+coff | GCC 16.2.1 MinGW-w64 13.0.0 (Fedora 44 mingw32-gcc 16.2.1-1.fc44), i686-w64-mingw32, GNU ld 2.46 | None | 1887 | 1887 | 0 (0) | main | 0 | False | ran |
| pc-ioq3-ded-mingw64 | ioquake3 dedicated server (Quake III Arena engine), x86-64 | None | True | dwarf+coff | GCC 16.2.1 MinGW-w64 13.0.0 (Fedora 44 mingw64-gcc 16.2.1-1.fc44), x86_64-w64-mingw32, GNU ld 2.46 | None | 1963 | 1963 | 0 (0) | main | 0 | False | ran |
| pc-quake2-game-msvc8 | Quake 2 game module gamex86.dll | None | True | pdb | MSVC 14.00.50727.42 (Visual C++ 2005, widberg/msvc8.0@936f93b9e9e92943ed5c9398d24712a32c2e9fe4: cl.exe 14.00.50727.42 + link.exe 8.00.50727.42 under wine 11.0 / Fedora wine-core 11.0-3.fc44), static CRT libcmt.lib 8.0 | None | 1945 | 1945 | 0 (0) | main | 0 | False | ran |
| pc-quake2-game-msvc8-debug | Quake 2 game module gamex86.dll, Debug build with an incremental link table | None | True | pdb | MSVC 14.00.50727.42 (Visual C++ 2005, widberg/msvc8.0@936f93b9e9e92943ed5c9398d24712a32c2e9fe4: cl.exe 14.00.50727.42 + link.exe 8.00.50727.42 under wine 11.0 / Fedora wine-core 11.0-3.fc44), static CRT libcmt.lib 8.0 | None | 3393 | 3393 | 0 (0) | main | 0 | False | ran |
| pc-quake2-msvc8 | Quake 2 client+server (null sound; ref DLLs loaded) | None | True | pdb | MSVC 14.00.50727.42 (Visual C++ 2005, widberg/msvc8.0@936f93b9e9e92943ed5c9398d24712a32c2e9fe4: cl.exe 14.00.50727.42 + link.exe 8.00.50727.42 under wine 11.0 / Fedora wine-core 11.0-3.fc44), static CRT libcmt.lib 8.0 | None | 2094 | 2094 | 0 (0) | main | 0 | False | ran |
| pc-quake2-refgl-msvc8 | Quake 2 OpenGL renderer ref_gl.dll | None | True | pdb | MSVC 14.00.50727.42 (Visual C++ 2005, widberg/msvc8.0@936f93b9e9e92943ed5c9398d24712a32c2e9fe4: cl.exe 14.00.50727.42 + link.exe 8.00.50727.42 under wine 11.0 / Fedora wine-core 11.0-3.fc44), static CRT libcmt.lib 8.0 | None | 1517 | 1517 | 0 (0) | main | 0 | False | ran |

## pc

| game | tool | recall | precision | success | arity | type exact | recall (verified) | precision (verified) | sampled |
|---|---|---|---|---|---|---|---|---|---|
| pc-doomgeneric-mingw32 | default | 0.9499 | 1.0000 | 1.0000 | – | – | 0.9499 | 1.0000 | 190 |
| pc-doomgeneric-mingw32 | baseline-off | 0.9183 | 1.0000 | 0.9579 | – | – | 0.9183 | 1.0000 | 190 |
| pc-doomgeneric-mingw32 | stock Ghidra | 0.6546 | 1.0000 | 1.0000 | – | – | 0.6546 | 1.0000 | 190 |
| pc-glquake-msvc42 | default | 0.9662 | 0.9938 | 1.0000 | – | – | 0.9662 | 0.9938 | 190 |
| pc-glquake-msvc42 | baseline-off | 0.9654 | 0.8795 | 1.0000 | – | – | 0.9654 | 0.8795 | 190 |
| pc-glquake-msvc42 | stock Ghidra | 0.8174 | 0.9802 | 1.0000 | – | – | 0.8174 | 0.9802 | 190 |
| pc-ioq3-ded-mingw32 | default | 0.9417 | 1.0000 | 1.0000 | – | – | 0.9417 | 1.0000 | 191 |
| pc-ioq3-ded-mingw32 | baseline-off | 0.9210 | 1.0000 | 0.9791 | – | – | 0.9210 | 1.0000 | 191 |
| pc-ioq3-ded-mingw32 | stock Ghidra | 0.6386 | 1.0000 | 1.0000 | – | – | 0.6386 | 1.0000 | 191 |
| pc-ioq3-ded-mingw64 | default | 1.0000 | 1.0000 | 0.9948 | – | – | 1.0000 | 1.0000 | 193 |
| pc-ioq3-ded-mingw64 | baseline-off | 1.0000 | 1.0000 | 1.0000 | – | – | 1.0000 | 1.0000 | 193 |
| pc-ioq3-ded-mingw64 | stock Ghidra | 0.9282 | 1.0000 | 0.9948 | – | – | 0.9282 | 1.0000 | 193 |
| pc-quake2-game-msvc8 | default | 0.8463 | 0.9677 | 1.0000 | – | – | 0.8463 | 0.9722 | 194 |
| pc-quake2-game-msvc8 | baseline-off | 0.8463 | 0.9196 | 1.0000 | – | – | 0.8463 | 0.9237 | 194 |
| pc-quake2-game-msvc8 | stock Ghidra | 0.4931 | 0.9486 | 1.0000 | – | – | 0.4931 | 0.9504 | 194 |
| pc-quake2-game-msvc8-debug | default | 0.8895 | 0.9714 | 1.0000 | – | – | 0.8895 | 0.9751 | 194 |
| pc-quake2-game-msvc8-debug | baseline-off | 0.8895 | 0.8961 | 1.0000 | – | – | 0.8895 | 0.8993 | 194 |
| pc-quake2-game-msvc8-debug | stock Ghidra | 0.7551 | 0.9249 | 1.0000 | – | – | 0.7551 | 0.9273 | 194 |
| pc-quake2-msvc8 | default | 0.8367 | 0.9793 | 1.0000 | – | – | 0.8367 | 0.9793 | 194 |
| pc-quake2-msvc8 | baseline-off | 0.8290 | 0.9819 | 0.9948 | – | – | 0.8290 | 0.9819 | 194 |
| pc-quake2-msvc8 | stock Ghidra | 0.6055 | 0.9520 | 1.0000 | – | – | 0.6055 | 0.9534 | 194 |
| pc-quake2-refgl-msvc8 | default | 0.7897 | 0.9638 | 1.0000 | – | – | 0.7897 | 0.9646 | 195 |
| pc-quake2-refgl-msvc8 | baseline-off | 0.7897 | 0.9403 | 1.0000 | – | – | 0.7897 | 0.9411 | 195 |
| pc-quake2-refgl-msvc8 | stock Ghidra | 0.4357 | 0.9323 | 1.0000 | – | – | 0.4357 | 0.9323 | 195 |

**Sign tests, pc**

| comparison | games | wins | losses | ties | one-sided p |
|---|---|---|---|---|---|
| recall vs baseline-off | 8 | 3 | 0 | 5 | 0.1250 |
| precision vs baseline-off | 8 | 4 | 0 | 4 | 0.0625 |
| success_rate vs baseline-off | 8 | 3 | 1 | 4 | 0.3125 |
| recall_verified vs baseline-off | 8 | 3 | 0 | 5 | 0.1250 |
| precision_verified vs baseline-off | 8 | 4 | 0 | 4 | 0.0625 |
| recall vs stock | 8 | 8 | 0 | 0 | 0.0039 |
| precision vs stock | 8 | 5 | 0 | 3 | 0.0312 |
| recall_verified vs stock | 8 | 8 | 0 | 0 | 0.0039 |
| precision_verified vs stock | 8 | 5 | 0 | 3 | 0.0312 |

## All games

**Sign tests over all games**

| comparison | games | wins | losses | ties | one-sided p |
|---|---|---|---|---|---|
| recall vs baseline-off | 8 | 3 | 0 | 5 | 0.1250 |
| precision vs baseline-off | 8 | 4 | 0 | 4 | 0.0625 |
| success_rate vs baseline-off | 8 | 3 | 1 | 4 | 0.3125 |
| recall_verified vs baseline-off | 8 | 3 | 0 | 5 | 0.1250 |
| precision_verified vs baseline-off | 8 | 4 | 0 | 4 | 0.0625 |
| recall vs stock | 8 | 8 | 0 | 0 | 0.0039 |
| precision vs stock | 8 | 5 | 0 | 3 | 0.0312 |
| recall_verified vs stock | 8 | 8 | 0 | 0 | 0.0039 |
| precision_verified vs stock | 8 | 5 | 0 | 3 | 0.0312 |

The sign tests are a supplement. A game is a win when `default` beats the other tool by at least 0.5 pp (the harness's materiality floor), a loss when it trails by as much, else a tie (dropped). One-sided p = P(X >= wins), X ~ Binomial(wins + losses, 1/2). Games whose meta.json says `version_match: false` are in the supplement table only. vs stock uses discovery on the main module only (the module stock was run on). A game whose stock run did not finish within the limit (DNF) or crashed has a labelled stock row and is in no vs-stock test: it counts neither as a win nor as a loss.

## Per seed (default vs baseline-off)

| game | seed | config | recall | precision | success | arity | type exact | sampled |
|---|---|---|---|---|---|---|---|---|
| pc-doomgeneric-mingw32 | 1 | default | 0.9499 | 1.0000 | 1.0000 | – | – | 100 |
| pc-doomgeneric-mingw32 | 1 | baseline-off | 0.9183 | 1.0000 | 0.9600 | – | – | 100 |
| pc-doomgeneric-mingw32 | 2 | default | 0.9499 | 1.0000 | 1.0000 | – | – | 100 |
| pc-doomgeneric-mingw32 | 2 | baseline-off | 0.9183 | 1.0000 | 0.9600 | – | – | 100 |
| pc-glquake-msvc42 | 1 | default | 0.9662 | 0.9938 | 1.0000 | – | – | 100 |
| pc-glquake-msvc42 | 1 | baseline-off | 0.9654 | 0.8795 | 1.0000 | – | – | 100 |
| pc-glquake-msvc42 | 2 | default | 0.9662 | 0.9938 | 1.0000 | – | – | 100 |
| pc-glquake-msvc42 | 2 | baseline-off | 0.9654 | 0.8795 | 1.0000 | – | – | 100 |
| pc-ioq3-ded-mingw32 | 1 | default | 0.9417 | 1.0000 | 1.0000 | – | – | 100 |
| pc-ioq3-ded-mingw32 | 1 | baseline-off | 0.9210 | 1.0000 | 0.9800 | – | – | 100 |
| pc-ioq3-ded-mingw32 | 2 | default | 0.9417 | 1.0000 | 1.0000 | – | – | 100 |
| pc-ioq3-ded-mingw32 | 2 | baseline-off | 0.9210 | 1.0000 | 0.9800 | – | – | 100 |
| pc-ioq3-ded-mingw64 | 1 | default | 1.0000 | 1.0000 | 1.0000 | – | – | 100 |
| pc-ioq3-ded-mingw64 | 1 | baseline-off | 1.0000 | 1.0000 | 1.0000 | – | – | 100 |
| pc-ioq3-ded-mingw64 | 2 | default | 1.0000 | 1.0000 | 0.9900 | – | – | 100 |
| pc-ioq3-ded-mingw64 | 2 | baseline-off | 1.0000 | 1.0000 | 1.0000 | – | – | 100 |
| pc-quake2-game-msvc8 | 1 | default | 0.8463 | 0.9677 | 1.0000 | – | – | 100 |
| pc-quake2-game-msvc8 | 1 | baseline-off | 0.8463 | 0.9196 | 1.0000 | – | – | 100 |
| pc-quake2-game-msvc8 | 2 | default | 0.8463 | 0.9677 | 1.0000 | – | – | 100 |
| pc-quake2-game-msvc8 | 2 | baseline-off | 0.8463 | 0.9196 | 1.0000 | – | – | 100 |
| pc-quake2-game-msvc8-debug | 1 | default | 0.8895 | 0.9714 | 1.0000 | – | – | 100 |
| pc-quake2-game-msvc8-debug | 1 | baseline-off | 0.8895 | 0.8961 | 1.0000 | – | – | 100 |
| pc-quake2-game-msvc8-debug | 2 | default | 0.8895 | 0.9714 | 1.0000 | – | – | 100 |
| pc-quake2-game-msvc8-debug | 2 | baseline-off | 0.8895 | 0.8961 | 1.0000 | – | – | 100 |
| pc-quake2-msvc8 | 1 | default | 0.8367 | 0.9793 | 1.0000 | – | – | 100 |
| pc-quake2-msvc8 | 1 | baseline-off | 0.8290 | 0.9819 | 0.9900 | – | – | 100 |
| pc-quake2-msvc8 | 2 | default | 0.8367 | 0.9793 | 1.0000 | – | – | 100 |
| pc-quake2-msvc8 | 2 | baseline-off | 0.8290 | 0.9819 | 1.0000 | – | – | 100 |
| pc-quake2-refgl-msvc8 | 1 | default | 0.7897 | 0.9638 | 1.0000 | – | – | 100 |
| pc-quake2-refgl-msvc8 | 1 | baseline-off | 0.7897 | 0.9403 | 1.0000 | – | – | 100 |
| pc-quake2-refgl-msvc8 | 2 | default | 0.7897 | 0.9638 | 1.0000 | – | – | 100 |
| pc-quake2-refgl-msvc8 | 2 | baseline-off | 0.7897 | 0.9403 | 1.0000 | – | – | 100 |


# Console research components (2026-10-15T07:23:02+00:00)

Tools fingerprint `262f665303b8a4dc`; sample n=100 seeds=[1, 2]. Thresholds: rates 0.5 pp, counts 1% of the reference (min 1), counts over functions both configurations decompiled. Output is deterministic: deltas are exact. `~` marks a change below the threshold.

## Verdict matrix (component effect vs its reference)

| component | config | reference | pc-doomgeneric-mingw32 | pc-glquake-msvc42 | pc-ioq3-ded-mingw32 | pc-ioq3-ded-mingw64 | pc-quake2-game-msvc8 | pc-quake2-game-msvc8-debug | pc-quake2-msvc8 | pc-quake2-refgl-msvc8 |
|---|---|---|---|---|---|---|---|---|---|---|
| all research (default vs baseline-off) | default | baseline-off | helps | helps | helps | mixed | helps | helps | helps | helps |

## Deltas

| component | image | verdict | vs reference | vs default | vs baseline-off |
|---|---|---|---|---|---|
| all research (default vs baseline-off) | pc-doomgeneric-mingw32 | helps | recall +3.2pp, success_rate +4.2pp, gotos -89, labels -43, irregular_functions -7, lines +245, recall_verified +3.2pp | no change | recall +3.2pp, success_rate +4.2pp, gotos -89, labels -43, irregular_functions -7, lines +245, recall_verified +3.2pp |
| all research (default vs baseline-off) | pc-glquake-msvc42 | helps | recall +0.1pp~, precision +11.4pp, gotos -36, labels -20, irregular_functions -7, native_warnings -1, text_warnings -1, lines -41, recall_verified +0.1pp, precision_verified +11.4pp | no change | recall +0.1pp~, precision +11.4pp, gotos -36, labels -20, irregular_functions -7, native_warnings -1, text_warnings -1, lines -41, recall_verified +0.1pp, precision_verified +11.4pp |
| all research (default vs baseline-off) | pc-ioq3-ded-mingw32 | helps | recall +2.1pp, success_rate +2.1pp, gotos -109, labels -69, irregular_functions -3, native_warnings +1~, lines +259, recall_verified +2.1pp | no change | recall +2.1pp, success_rate +2.1pp, gotos -109, labels -69, irregular_functions -3, native_warnings +1~, lines +259, recall_verified +2.1pp |
| all research (default vs baseline-off) | pc-ioq3-ded-mingw64 | mixed | success_rate -0.5pp, gotos -135, labels -66, irregular_functions -6, lines +251 | no change | success_rate -0.5pp, gotos -135, labels -66, irregular_functions -6, lines +251 |
| all research (default vs baseline-off) | pc-quake2-game-msvc8 | helps | precision +4.8pp, gotos -74, labels -30, irregular_functions -4, lines +115, precision_verified +4.9pp | no change | precision +4.8pp, gotos -74, labels -30, irregular_functions -4, lines +115, precision_verified +4.9pp |
| all research (default vs baseline-off) | pc-quake2-game-msvc8-debug | helps | precision +7.5pp, gotos -45, labels -20, irregular_functions -10, lines +28, precision_verified +7.6pp | no change | precision +7.5pp, gotos -45, labels -20, irregular_functions -10, lines +28, precision_verified +7.6pp |
| all research (default vs baseline-off) | pc-quake2-msvc8 | helps | recall +0.8pp, precision -0.3pp~, success_rate +0.5pp, gotos -68, labels -37, irregular_functions -9, lines +150, recall_verified +0.8pp, precision_verified -0.3pp | no change | recall +0.8pp, precision -0.3pp~, success_rate +0.5pp, gotos -68, labels -37, irregular_functions -9, lines +150, recall_verified +0.8pp, precision_verified -0.3pp |
| all research (default vs baseline-off) | pc-quake2-refgl-msvc8 | helps | precision +2.4pp, gotos -85, labels -43, irregular_functions -7, lines +186, precision_verified +2.4pp | no change | precision +2.4pp, gotos -85, labels -43, irregular_functions -7, lines +186, precision_verified +2.4pp |

## Absolute values

| image | config | success | gotos | labels | irregular | warnings | lines | recall | precision | arity | type exact | m22 sim | m22 standalone | median s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| pc-doomgeneric-mingw32 | default | 1.0000 | 169 | 103 | 45 | 39 | 10470 | 0.9499 | 1.0000 | – | – | – | – | 0.8030 |
| pc-doomgeneric-mingw32 | baseline-off | 0.9579 | 248 | 139 | 48 | 32 | 9704 | 0.9183 | 1.0000 | – | – | – | – | 1.3940 |
| pc-glquake-msvc42 | default | 1.0000 | 27 | 16 | 53 | 79 | 9098 | 0.9662 | 0.9938 | – | – | – | – | 2.1670 |
| pc-glquake-msvc42 | baseline-off | 1.0000 | 63 | 36 | 60 | 80 | 9139 | 0.9654 | 0.8795 | – | – | – | – | 1.8190 |
| pc-ioq3-ded-mingw32 | default | 1.0000 | 154 | 97 | 72 | 222 | 12319 | 0.9417 | 1.0000 | – | – | – | – | 1.3990 |
| pc-ioq3-ded-mingw32 | baseline-off | 0.9791 | 263 | 166 | 72 | 216 | 11890 | 0.9210 | 1.0000 | – | – | – | – | 1.4590 |
| pc-ioq3-ded-mingw64 | default | 0.9948 | 318 | 194 | 97 | 307 | 14254 | 1.0000 | 1.0000 | – | – | – | – | 1.1000 |
| pc-ioq3-ded-mingw64 | baseline-off | 1.0000 | 668 | 363 | 104 | 316 | 16669 | 1.0000 | 1.0000 | – | – | – | – | 1.2710 |
| pc-quake2-game-msvc8 | default | 1.0000 | 33 | 17 | 55 | 92 | 7528 | 0.8463 | 0.9677 | – | – | – | – | 1.0120 |
| pc-quake2-game-msvc8 | baseline-off | 1.0000 | 107 | 47 | 59 | 92 | 7413 | 0.8463 | 0.9196 | – | – | – | – | 1.0810 |
| pc-quake2-game-msvc8-debug | default | 1.0000 | 12 | 7 | 55 | 105 | 8378 | 0.8895 | 0.9714 | – | – | – | – | 1.7480 |
| pc-quake2-game-msvc8-debug | baseline-off | 1.0000 | 57 | 27 | 65 | 105 | 8350 | 0.8895 | 0.8961 | – | – | – | – | 1.4720 |
| pc-quake2-msvc8 | default | 1.0000 | 111 | 63 | 54 | 80 | 10715 | 0.8367 | 0.9793 | – | – | – | – | 0.7290 |
| pc-quake2-msvc8 | baseline-off | 0.9948 | 179 | 100 | 63 | 80 | 10530 | 0.8290 | 0.9819 | – | – | – | – | 0.5130 |
| pc-quake2-refgl-msvc8 | default | 1.0000 | 61 | 33 | 83 | 159 | 8811 | 0.7897 | 0.9638 | – | – | – | – | 0.6520 |
| pc-quake2-refgl-msvc8 | baseline-off | 1.0000 | 146 | 76 | 90 | 159 | 8625 | 0.7897 | 0.9403 | – | – | – | – | 0.5770 |

## Images without truth (success and time only)

| image | size | import s | functions | export-c ok | stock s | stock functions | both / ours only / stock only | compiler |
|---|---|---|---|---|---|---|---|---|
| pc-kotor2 | 4,964,352 | 2.7 | 7 | 7/7 | 21.3 | 8 | 7 / 0 / 1 | PE optional header linker version 7.0 (cl 13.x) |
