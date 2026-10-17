# Combined gate 20261012

**Verdict: nothing dropped against the per-agent reports; GP-7003 (with its two corrections) is in `native/ghidra-opt-sleigh.patch` and moves no number in any gate.**

One build of the shared tree on `nih-vps-u` (2026-10-12): `ghidra_opt` sha256 `4561fbea361d602cec0576f2c28a18da19dc5155cb9973d1a5b4e762c87ca598` (`native/build_ghidra_opt.sh --jobs 4` under the build lock, from the patch with md5 `ad0975eb`; the build before it, `15396033...`, is RustStructure's and reproduces byte for byte), and the release `romwright-cli`, `-worker`, `-api` of a fresh sync of the shared tree (cli `620b67d5...`, worker `008bff14...`, api `41cd75a7...`). Every table below is from that build; the comparisons are the per-agent reports named in each section.

## m21-001 (7 images)

Status pass, failures none. `without GP-7003` = the same tree with the previous `ghidra_opt` (15396033...). `earlier tree` = the 2026-10-12 master-trial base arm (`ghidra_opt` dbd7e74b, before the PS2 discovery work); Ps2Precision's figure is the capcom row it recorded.

| image | recall | precision | size exact | without GP-7003 recall / precision | earlier tree recall / precision | Ps2Precision recall / precision |
|---|---|---|---|---|---|---|
| gba-pokeemerald | 0.9761 | 0.9972 | 5748 | 0.9761 / 0.9972 | 0.9761 / 0.9972 | - |
| nds-pokeheartgold-arm9 | 0.9735 | 0.9984 | 5156 | 0.9735 / 0.9984 | 0.9735 / 0.9984 | - |
| ps2-capcom-fighting-evolution | 0.9741 | 0.9945 | 8548 | 0.9741 / 0.9945 | 0.9652 / 0.9954 | 0.9741 / 0.9945 |
| ps2-dungeon-game | 0.9872 | 0.9835 | 751 | 0.9872 / 0.9835 | 0.9885 / 0.9835 | - |
| psx-darkstalkers-3 | 0.9878 | 0.3663 | 0 | 0.9878 / 0.3663 | 0.9866 / 0.3660 | - |
| psv-need-for-speed-most-wanted | 0.9734 | 0.9719 | 16304 | 0.9734 / 0.9719 | 0.9734 / 0.9719 | - |
| x360-black-ops-2 | 0.9833 | 0.9964 | 0 | 0.9833 / 0.9964 | 0.9833 / 0.9964 | - |

## m22-002 (PS2 C match, romwright layer, context variant, 200 functions)

Each row: exact / compiled / mean percent. `frozen` = the report the lane's last owner wrote (`m22-ps2_p4*.json`: Ps2CMatch's 55 / 76.624, 57 / 78.321, 106 / 86.406); RustStructure measured 55 / 76.976 on lane 1 with the same code (its tree carried other agents' work).

| lane | frozen | this build | delta exact / compiled / mean | paired better / worse / same | exact gained / lost |
|---|---|---|---|---|---|
| MWCC seed 20261010 | 55 / 192 / 76.624 | 55 / 193 / 76.976 | +0 / +1 / +0.352 | 1 / 1 / 198 | 0 / 0 |
| MWCC seed 20261011 | 57 / 194 / 78.321 | 57 / 194 / 78.321 | +0 / +0 / +0.000 | 0 / 0 / 200 | 0 / 0 |
| ee-gcc seed 20261010 | 106 / 197 / 86.406 | 106 / 197 / 86.406 | +0 / +0 / +0.000 | 0 / 0 / 200 | 0 / 0 |

The same tree without GP-7003 (`ghidra_opt` 15396033..., the build before this patch), MWCC seed 20261010: 55 / 193 / 76.976; 0 of 200 functions score differently from this build.

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
| ps2-ratchet-clank | 860 / 861 | 859 / 861 | 860 / 861 |
| ps2-ratchet-clank-pal | 858 / 859 | 858 / 859 | 858 / 859 |
| all | 10338 / 10342 | 10337 / 10342 | 10338 / 10342 |

Failed functions (`*` = also failing in RustStructure's run):

- * ps2-dark-cloud 01db08a0: native runtime: native runtime: execution deadline exceeded
- * ps2-persona-4 002be530: native runtime: native runtime: execution deadline exceeded
- * ps2-ratchet-clank 00239780: native runtime: worker failed (exit status: N): error: decompiler exception: Low-level Error: Backward normalization not
- * ps2-ratchet-clank-pal 0023aa38: native runtime: worker failed (exit status: N): error: decompiler exception: Low-level Error: Backward normalization not

## PS2 wave (8 games and symtab variants, `--corpus-wave --stock`, n = 500, seeds 1,2)

Tools fingerprint `b2368ce6b5673309` against `8089735f6fb1f18e` (Ps2Precision's `console_research_wave_20261011_ps2_precision`, whose success column is 0.0: the printer and `ghidra_opt` disagreed on the IR version, so its decompile numbers are not a baseline; recall and precision are).

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

Against stock Ghidra (cached, same samples):

| image | default recall | stock recall | default precision | stock precision |
|---|---|---|---|---|
| ps2-dark-chronicle | 0.9987 | 0.9288 | 0.9963 | 0.9982 |
| ps2-dark-chronicle-symtab | 1.0000 | 1.0000 | 0.9973 | 0.9995 |
| ps2-dark-cloud | 0.9988 | 0.9173 | 0.9907 | 0.9850 |
| ps2-dark-cloud-symtab | 0.9995 | 1.0000 | 0.9448 | 0.9267 |
| ps2-digital-devil-saga | 0.9974 | 0.8630 | 0.9987 | 1.0000 |
| ps2-fatal-frame | 0.9958 | 0.8334 | 0.9993 | 1.0000 |
| ps2-fatal-frame-symtab | 1.0000 | 1.0000 | 0.9998 | 1.0000 |
| ps2-god-hand | 0.9976 | 0.8552 | 0.9943 | 0.9988 |
| ps2-persona-4 | 0.9992 | 0.9028 | 0.9967 | 0.9997 |
| ps2-ratchet-clank | 0.9281 | 0.7175 | 0.9965 | 1.0000 |
| ps2-ratchet-clank-pal | 0.9276 | 0.7184 | 0.9947 | 1.0000 |

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
| gba-kh-chain-of-memories | ran | 961 / 961 | 1.0000 | 0.9582 | +0.0000 | 0.9640 | +0.0000 | 68 / 36 | 68 / 36 |
| gc-pikmin-2 | ran | 986 / 986 | 1.0000 | 0.9998 | +0.0000 | 0.9984 | +0.0000 | 59 / 31 | 39 / 18 |
| n64-super-mario-64 | ran | 923 / 923 | 1.0000 | 0.9974 | +0.0000 | 0.9053 | +0.0000 | 15 / 4 | 15 / 4 |
| nds-kh-358-2-days | ran | 987 / 987 | 1.0000 | 0.8863 | +0.0000 | 0.9922 | +0.0000 | 24 / 10 | 24 / 10 |
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

`ghidra_opt` 15396033... (the tree's patch before GP-7003) -> 4561fbea... (with it), same cli and worker, each imported with its own build, `--corpus-wave` default config, n = 500, seeds 1,2.

| image | decompiled | gotos | labels | lines | native warnings | recall | precision |
|---|---|---|---|---|---|---|---|
| gc-pikmin-2 | 986 -> 986 | 59 -> 59 | 31 -> 31 | 46430 -> 46430 | 2628 -> 2628 | 0.9998 -> 0.9998 | 0.9984 -> 0.9984 |
| ps2-fatal-frame | 942 -> 942 | 247 -> 247 | 93 -> 93 | 61387 -> 61387 | 2969 -> 2968 | 0.9958 -> 0.9958 | 0.9993 -> 0.9993 |
| ps2-god-hand | 980 -> 980 | 186 -> 186 | 95 -> 95 | 45366 -> 45366 | 2063 -> 2063 | 0.9976 -> 0.9976 | 0.9943 -> 0.9943 |
| psp-hot-pixel | 940 -> 940 | 614 -> 614 | 312 -> 312 | 65426 -> 65423 | 2580 -> 2580 | 0.8884 -> 0.8884 | 0.9057 -> 0.9057 |

## Explanations

- **m22-002 seed 20261010: 55 / 193 / 76.976 against Ps2CMatch's 55 / 192 / 76.624.** Not GP-7003 and not a drop: the same tree with the previous `ghidra_opt` scores identically (0 of 200 functions differ), and RustStructure measured the same 55 / 76.976 on its tree. Two functions moved since Ps2CMatch's report: `func_0038d9f0` compiles now (0 -> 72.30 %), `func_001e7080` 96.60 -> 94.62 % (the one worse function; a change of the tree between the two reports, not attributed further). The other two lanes (seed 20261011, ee-gcc) are identical to the frozen reports function by function.
- **m21-001.** PASS, and identical image by image to the same tree without GP-7003. Against the master-trial base arm (the tree before the PS2 discovery work) capcom is 0.9652 / 0.9954 -> 0.9741 / 0.9945 (Ps2Precision's own numbers, reproduced), dungeon-game recall 0.9885 -> 0.9872, darkstalkers 0.9866 -> 0.9878; those are the tree's changes between the two runs, not this patch.
- **PS2 decompile success.** `ps2_decompile_success.py` on the 4b53 projects: 10,338 / 10,342 (RustStructure 10,337, Ps2CMatch 10,338). The four failures: Dark Cloud 0x01db08a0 and Persona 4 0x002be530 (the 60 s execution deadline), Ratchet & Clank 0x00239780 and PAL 0x0023aa38 (`Backward normalization not implemented`); RustStructure's run failed one more Ratchet & Clank function (859 / 861); that one did not reproduce here. R&C 0x00239780 fails the same way with the previous `ghidra_opt` and with both projects. The wave's own fresh imports decompile 10,340 / 10,342 (only the two deadlines; its R&C samples do not include the two `Backward normalization` addresses).
- **PS2 wave (n = 500, seeds 1,2, stock cached).** Recall and precision are identical to four places to Ps2Precision's `console_research_wave_20261011_ps2_precision` in all 11 images; against stock Ghidra the same wins and losses (Ps2Precision's loss, R&C PAL against stock's precision, stays: 0.9947 against 1.0000). Its success column was 0.0 (the IR version mismatch of that day); this run's is 1.0000 except Dark Cloud 0.9989 and Persona 4 0.9990, the two deadlines.
- **gc / n64 / gba / nds.** Success 1.0000 in all four (n64 923 / 923: the N64 breakage of the master trial is master's GP-7310, not this tree). gc-pikmin-2 gotos 39 -> 59, labels 18 -> 31, lines +9,561 against the 2026-10-10 wave: in that run 0x800f9d0c (9,251 lines, 20 gotos, 13 labels) hit the 60 s deadline (985 / 986); it decompiles now in 29 s. The build without GP-7003 gives 59 / 31 as well.
- **PSP.** Recall and precision at `-n 200` equal Ps2Precision's five rows to four places. Against the 2026-10-10 wave (n = 500): recall up on Camera (+0.0140) and Tetris (+0.0491), precision up on Hot Pixel (+0.0096), Melodie (+0.0495), Pac-Man Rally (+0.0245), down on Camera (-0.0015) and Tetris (-0.0039), all Ps2Precision's discovery work (their STATUS lists the same figures). Hot Pixel at `-n 200` has one failed function, 0x001032e0 (386 / 387): the 60 s deadline, identical with the previous `ghidra_opt` (two runs each); the n = 500 sample decompiles 940 / 940.
- **What GP-7003 does here.** On the four images re-run without it (gc-pikmin-2, Fatal Frame, God Hand, Hot Pixel; 3,848 functions) gotos, labels, success, recall and precision are identical; lines differ by 0 / 0 / 0 / -3, Fatal Frame has one native warning fewer. With this tree's import the stored switch tables are the same with and without it (Fatal Frame 278 / 278, God Hand 992 / 992 tables), and both builds store Fatal Frame 0x1caab4, 0x1cab80 and God Hand 0x22cca8, which the 4b53 imports (before Ps2Precision's VSA work) lacked; the cause is inferred from that, not traced, and `FActExecOccur` prints 516 lines / 3 switches with either build; God Hand 0x274828 keeps its six targets (distinct 6 in the import). The patch's effect is therefore on the decompiler-only path (tables the import did not store): the follow-up's 2,869 against 2,865 tables over 12 games and the `switchmask.xml` datatest, not on these gates.
- **Not run again.** `tools/vendor_ghidra.py` does not exist in the tree (neither in the working tree nor in any commit); the check was `sha256sum -c third_party/ghidra/MANIFEST.sha256`: every `decompiler/` file matches; two language files do not (`languages/gamecube/ppc_gekko_broadway.slaspec`, `languages/ps2/vuupper.sinc`, edited by earlier commits, manifest not refreshed). `third_party` and the pin are unchanged.

