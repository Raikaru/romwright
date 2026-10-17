# Import speed vs stock Ghidra (generated)

Written by `benchmarks/import_speed.py`; do not edit by hand. Method, tolerance and fairness rules: the script's docstring and `docs/import-speed.md`.

Recorded 2026-10-09T09:36:56+00:00 on 8 threads (shared host), Ghidra 12.1.3, romwright tools `ea27c70333bb669d` (native tools from `/home/raikaru/runs/FinalGate/ventris/native/build`), Ghidra heap 8G, per-run limit 3600 s. Verdict: **FAIL**.

| image | romwright wall s (median, runs) | Ghidra wall s (median, runs) | wall ratio | tol | ratio ex JVM start | CPU s ours / Ghidra | peak RSS MB ours / Ghidra | recall ours / Ghidra | precision ours / Ghidra | verdict |
|---|---|---|---|---|---|---|---|---|---|---|
| psx-darkstalkers-3 | 2.36 (2.36, 2.31, 2.36) | 17.94 (18.95, 17.84, 17.94) | **0.132** | 0.062 | 0.1507 | 6.44 / 29.37 | 121 / 1217 | 0.9878 / 0.9205 | 0.3663 / 0.3743; gated `precision_corroborated` 0.9968 / 0.9995 | pass |
| ps2-dungeon-game | 2.56 (2.56, 2.56, 2.51) | 13.49 (13.49, 13.39, 13.54) | **0.190** | 0.050 | 0.226 | 5.04 / 27.2 | 111 / 984 | 0.9438 / 0.7356 | 0.9880 / 0.9863 | pass |
| gc-animal-crossing | 4.06 (4.06, 4.06, 4.06) | 24.11 (24.61, 24.11, 24.11) | **0.168** | 0.050 | 0.1856 | 10.11 / 41.86 | 195 / 1529 | n/a / n/a | n/a / n/a | pass |
| ps2-capcom-fighting-evolution | 43.11 (43.11, 42.81, 44.22) | 176.02 (177.35, 173.66, 176.02) | **0.245** | 0.050 | 0.248 | 163.85 / 247.2 | 265 / 1920 | 0.9412 / 0.7562 | 0.9964 / 0.9979 | pass |
| x360-black-ops-2 | 46.31 (46.77, 45.85) | 132.5 (131.3, 133.69) | **0.349** | 0.050 | 0.3558 | 118.74 / 193.01 | 1355 / 7253 | 0.9833 / 0.7628 | 0.9964 / 0.9965 | pass |
| psv-need-for-speed-most-wanted | 169.33 (170.01, 168.65) | 350.35 (348.74, 351.96) | **0.483** | 0.050 | 0.4867 | 554.27 / 695.34 | 1601 / 3701 | 0.9731 / 0.7035 | 0.9713 / 0.9657 | pass |
| nds-pokeheartgold-arm9 | 107.25 (111.39, 103.11) | 348.48 (357.53, 339.43) | **0.308** | 0.077 | 0.3099 | 263.79 / 244.16 | 753 / 2733 | 0.9729 / 0.8643 | 0.9984 / 0.9983 | pass |
| gba-pokeemerald | 56.88 (57.21, 56.54) | > 3600.02 (timeout) | < 0.016 | - | - | - | - | 0.9737 / - | 0.9971 / - | incomplete |

## Failures

- **gba-pokeemerald** (incomplete): Ghidra auto-analysis did not finish in any of 2 runs (killed at 3600, 3600 s): wall ratio < 0.016, but no Ghidra function list, so quality is not comparable

## Per image

### psx-darkstalkers-3

Ghidra: `MIPS:LE:32:default`, loader auto-selected -- Stock Ghidra's own MIPS:LE:32:default (the R3000A is MIPS I) under the PsxLoader extension's PS-EXE loader (auto-selected; the loader only lays out the image). Our import uses PSX:LE:32:default (native/languages/psx: this MIPS plus the GTE). Ghidra on PSX:LE:32:default (its own or ours) finds only 1011 functions (recall 0.5844); the cause is not established (the extension keys its function-start patterns to MIPS); MIPS finds 2012 (0.9205), the recorded stock numbers.

Speed faster (wall ratio 0.1315, CPU ratio 0.2193, peak RSS ratio 0.0994); quality not-worse; F1 (informational) romwright 0.5344 / Ghidra 0.5322.

- romwright: language `PSX:LE:32:default`; CPU/wall 2.77; 1-min load before runs [2.62, 2.61, 2.28]; score {"truth": 818, "found": 2206, "recall": 0.9878, "precision": 0.3663, "invented": 1398, "sizes_compared": 0, "size_exact": 0, "size_short": 0, "size_long": 0, "precision_corroborated": 0.9968, "invented_corroborated": 1391, "invented_corroborated_by": {"frame+address-taken": 43, "jal": 545, "table": 803}, "invented_uncorroborated": 7, "corroborated_unfound": 52}
  - phases (first run, s): `{"total": 2.330919, "console": 0.418552, "discovery": 0.719605, "flow": 0.339476, "parse": 0.003191, "patterns": 0.07954, "references": 0.787494, "references-only": 0.368936, "settle": 0.000792, "store": 0.066141, "switch": 0.60094, "switch-vsa": 0.048227}`
  - command: `/home/raikaru/runs/FinalGate/target/release/romwright-cli import /home/raikaru/runs/FinalGate/home/ventris-corpus/extracted/psx-darkstalkers-3/VS.EXE --name psx --project /var/tmp/fg-import-speed/runs/psx-darkstalkers-3/ours-0/project --timings`
- Ghidra: language `MIPS:LE:32:default`, loader `PSX Executables Loader`, 2012 functions (0 in overlays, unscored); CPU/wall 1.65; 1-min load before runs [2.62, 2.56, 2.66]; score {"truth": 818, "found": 2012, "recall": 0.9205, "precision": 0.3743, "invented": 1259, "sizes_compared": 0, "size_exact": 0, "size_short": 0, "size_long": 0, "precision_corroborated": 0.9995, "invented_corroborated": 1258, "invented_corroborated_by": {"frame+address-taken": 39, "jal": 548, "table": 671}, "invented_uncorroborated": 1, "corroborated_unfound": 185}
  - phases (first run, s): `{"jvm_startup": 2.315, "analysis": 13.0, "load_script_save_exit": 3.63, "top_analyzers": {"Decompiler Switch Analysis": 5.102, "MIPS Constant Reference Analyzer": 2.007, "Stack": 1.846, "Call Convention ID": 1.253, "Disassemble": 1.092, "Apply Data Archives": 0.487, "Create Function": 0.452, "Reference": 0.24}}`
  - command: `/home/raikaru/ghidra_12.1.3_PUBLIC/support/analyzeHeadless /var/tmp/fg-import-speed/runs/psx-darkstalkers-3/ghidra-0/ghidra-project proj -import /home/raikaru/runs/FinalGate/home/ventris-corpus/extracted/psx-darkstalkers-3/VS.EXE -processor MIPS:LE:32:default -scriptPath /home/raikaru/runs/FinalGate/ventris/benchmarks/ghidra -postScript ExportFunctionEntries.java /var/tmp/fg-import-speed/runs/psx-darkstalkers-3/ghidra-0/ghidra-functions.json -deleteProject`

### ps2-dungeon-game

Ghidra: `r5900:LE:32:default`, loader auto-selected -- Stock ELF loader, R5900 language; stripped ELF, the same file our import reads.

Speed faster (wall ratio 0.1898, CPU ratio 0.1853, peak RSS ratio 0.1128); quality not-worse; F1 (informational) romwright 0.9654 / Ghidra 0.8427.

- romwright: language `r5900:LE:32:default`; CPU/wall 2.01; 1-min load before runs [2.5, 2.56, 2.66]; score {"truth": 783, "found": 748, "recall": 0.9438, "precision": 0.988, "invented": 9, "sizes_compared": 737, "size_exact": 716, "size_short": 8, "size_long": 13}
  - phases (first run, s): `{"total": 2.492717, "console": 0.617562, "discovery": 0.854966, "flow": 0.234229, "parse": 0.013398, "patterns": 0.088305, "references": 0.833265, "references-only": 0.215697, "settle": 0.00109, "store": 0.121757, "switch": 0.554757, "switch-vsa": 0.016913}`
  - command: `/home/raikaru/runs/FinalGate/target/release/romwright-cli import /var/tmp/fg-import-speed/binaries/ps2-dungeon-game/dungeon_game.elf.stripped --name dungeon --project /var/tmp/fg-import-speed/runs/ps2-dungeon-game/ours-0/project --timings`
- Ghidra: language `r5900:LE:32:default`, loader `Executable and Linking Format (ELF)`, 584 functions (0 in overlays, unscored); CPU/wall 2.03; 1-min load before runs [2.54, 2.56, 2.66]; score {"truth": 783, "found": 584, "recall": 0.7356, "precision": 0.9863, "invented": 8, "sizes_compared": 574, "size_exact": 430, "size_short": 142, "size_long": 2}
  - phases (first run, s): `{"jvm_startup": 2.258, "analysis": 9.0, "load_script_save_exit": 2.23, "top_analyzers": {"Decompiler Switch Analysis": 1.92, "MIPS-R5900 Constant Reference Analyzer": 1.548, "Create Address Tables - One Time": 1.175, "Stack": 0.84, "Disassemble Entry Points": 0.767, "ASCII Strings": 0.757, "Apply Data Archives": 0.412, "Non-Returning Functions - Discovered": 0.379}}`
  - command: `/home/raikaru/ghidra_12.1.3_PUBLIC/support/analyzeHeadless /var/tmp/fg-import-speed/runs/ps2-dungeon-game/ghidra-0/ghidra-project proj -import /var/tmp/fg-import-speed/binaries/ps2-dungeon-game/dungeon_game.elf.stripped -processor r5900:LE:32:default -scriptPath /home/raikaru/runs/FinalGate/ventris/benchmarks/ghidra -postScript ExportFunctionEntries.java /var/tmp/fg-import-speed/runs/ps2-dungeon-game/ghidra-0/ghidra-functions.json -deleteProject`

### gc-animal-crossing

Ghidra: `PowerPC:BE:32:Gekko_Broadway`, loader auto-selected -- GameCubeLoader extension (DOL sections at their load addresses), Gekko/Broadway.

Speed faster (wall ratio 0.1684, CPU ratio 0.2415, peak RSS ratio 0.1275); quality n/a (no truth).

- romwright: language `PowerPC:BE:32:Gekko_Broadway`; CPU/wall 2.49; 1-min load before runs [2.81, 2.61, 2.31]; score null
  - phases (first run, s): `{"total": 3.992431, "console": 0.187696, "discovery": 1.538045, "flow": 0.641854, "parse": 0.003357, "patterns": 0.018177, "references": 0.802968, "references-only": 0.615267, "settle": 0.002976, "store": 0.153972, "switch": 1.054638, "switch-vsa": 0.280458}`
  - command: `/home/raikaru/runs/FinalGate/target/release/romwright-cli import /home/raikaru/runs/FinalGate/home/ventris-corpus/extracted/gc-animal-crossing/main.dol --name gc --project /var/tmp/fg-import-speed/runs/gc-animal-crossing/ours-0/project --timings`
- Ghidra: language `PowerPC:BE:32:Gekko_Broadway`, loader `Nintendo GameCube/Wii Binary (Executable)`, 2734 functions (0 in overlays, unscored); CPU/wall 1.74; 1-min load before runs [2.83, 2.61, 2.53]; score null
  - phases (first run, s): `{"jvm_startup": 2.184, "analysis": 21.0, "load_script_save_exit": 1.43, "top_analyzers": {"Decompiler Switch Analysis": 9.161, "PowerPC Constant Reference Analyzer": 2.96, "Stack": 2.565, "Disassemble": 1.745, "Disassemble Entry Points": 0.977, "Apply Data Archives": 0.584, "Create Function": 0.567, "Create Address Tables - One Time": 0.505}}`
  - command: `/home/raikaru/ghidra_12.1.3_PUBLIC/support/analyzeHeadless /var/tmp/fg-import-speed/runs/gc-animal-crossing/ghidra-0/ghidra-project proj -import /home/raikaru/runs/FinalGate/home/ventris-corpus/extracted/gc-animal-crossing/main.dol -processor PowerPC:BE:32:Gekko_Broadway -scriptPath /home/raikaru/runs/FinalGate/ventris/benchmarks/ghidra -postScript ExportFunctionEntries.java /var/tmp/fg-import-speed/runs/gc-animal-crossing/ghidra-0/ghidra-functions.json -deleteProject`

### ps2-capcom-fighting-evolution

Ghidra: `r5900:LE:32:default`, loader auto-selected -- Stock ELF loader with the emotionengine-reloaded R5900 language; stripped ELF (llvm-strip --strip-all), the same file our import reads.

Speed faster (wall ratio 0.2449, CPU ratio 0.6628, peak RSS ratio 0.138); quality not-worse; F1 (informational) romwright 0.968 / Ghidra 0.8604.

- romwright: language `r5900:LE:32:default`; CPU/wall 3.8; 1-min load before runs [2.82, 2.63, 2.77]; score {"truth": 8794, "found": 8307, "recall": 0.9412, "precision": 0.9964, "invented": 30, "sizes_compared": 8277, "size_exact": 8244, "size_short": 2, "size_long": 31}
  - phases (first run, s): `{"total": 43.032341, "console": 0.333097, "discovery": 3.410867, "flow": 1.901604, "parse": 0.00571, "patterns": 1.250294, "references": 4.049767, "references-only": 3.716662, "settle": 0.006583, "store": 0.243337, "switch": 34.744357, "switch-vsa": 0.332903}`
  - command: `/home/raikaru/runs/FinalGate/target/release/romwright-cli import /var/tmp/fg-import-speed/binaries/ps2-capcom-fighting-evolution/SLUS_209.50.stripped --name capcom --project /var/tmp/fg-import-speed/runs/ps2-capcom-fighting-evolution/ours-0/project --timings`
- Ghidra: language `r5900:LE:32:default`, loader `Executable and Linking Format (ELF)`, 6664 functions (0 in overlays, unscored); CPU/wall 1.4; 1-min load before runs [4.37, 4.01, 4.86]; score {"truth": 8794, "found": 6664, "recall": 0.7562, "precision": 0.9979, "invented": 14, "sizes_compared": 6650, "size_exact": 4349, "size_short": 2299, "size_long": 2}
  - phases (first run, s): `{"jvm_startup": 2.188, "analysis": 173.0, "load_script_save_exit": 2.16, "top_analyzers": {"Decompiler Switch Analysis": 140.995, "MIPS-R5900 Constant Reference Analyzer": 11.236, "Stack": 5.897, "Disassemble": 4.371, "Create Address Tables - One Time": 1.836, "Create Function": 1.684, "Reference": 1.087, "Subroutine References": 1.003}}`
  - command: `/home/raikaru/ghidra_12.1.3_PUBLIC/support/analyzeHeadless /var/tmp/fg-import-speed/runs/ps2-capcom-fighting-evolution/ghidra-0/ghidra-project proj -import /var/tmp/fg-import-speed/binaries/ps2-capcom-fighting-evolution/SLUS_209.50.stripped -processor r5900:LE:32:default -scriptPath /home/raikaru/runs/FinalGate/ventris/benchmarks/ghidra -postScript ExportFunctionEntries.java /var/tmp/fg-import-speed/runs/ps2-capcom-fighting-evolution/ghidra-0/ghidra-functions.json -deleteProject`

### x360-black-ops-2

Ghidra: `PowerPC:BE:64:A2ALT-32addr`, loader auto-selected -- XEXLoaderWV extension. Our language, PowerPC:BE:64:Xenon-32addr, is built by native/languages/xenon/install.sh (A2 + VMX128) and is not a Ghidra module (no Module.manifest), so stock Ghidra cannot load it; A2ALT-32addr (A2 + AltiVec) is the stock language it extends. VMX128 instructions do not decode there, so Ghidra's flow stops at them. The MSVC map is not given to either tool.

Speed faster (wall ratio 0.3495, CPU ratio 0.6152, peak RSS ratio 0.1868); quality not-worse; F1 (informational) romwright 0.9898 / Ghidra 0.8641.

- romwright: language `PowerPC:BE:64:Xenon-32addr`; CPU/wall 2.56; 1-min load before runs [2.71, 2.67]; score {"truth": 27730, "found": 27364, "recall": 0.9833, "precision": 0.9964, "invented": 98, "sizes_compared": 0, "size_exact": 0, "size_short": 0, "size_long": 0}
  - phases (first run, s): `{"total": 46.63326, "console": 4.765155, "discovery": 16.947765, "flow": 13.165233, "parse": 0.146325, "patterns": 0.131515, "references": 10.386109, "references-only": 5.620947, "settle": 0.02267, "store": 1.582868, "switch": 15.704939, "switch-vsa": 1.181935}`
  - command: `/home/raikaru/runs/FinalGate/target/release/romwright-cli import /home/raikaru/runs/FinalGate/home/ventris-corpus/extracted/x360-call-of-duty-black-ops-2/default_mp_script.exe --name x360 --project /var/tmp/fg-import-speed/runs/x360-black-ops-2/ours-0/project --timings`
- Ghidra: language `PowerPC:BE:64:A2ALT-32addr`, loader `XEX Loader by Warranty Voider`, 21228 functions (0 in overlays, unscored); CPU/wall 1.46; 1-min load before runs [3.01, 3.04]; score {"truth": 27730, "found": 21228, "recall": 0.7628, "precision": 0.9965, "invented": 75, "sizes_compared": 0, "size_exact": 0, "size_short": 0, "size_long": 0}
  - phases (first run, s): `{"jvm_startup": 2.258, "analysis": 104.0, "load_script_save_exit": 25.04, "top_analyzers": {"Decompiler Switch Analysis": 32.161, "Non-Returning Functions - Discovered": 28.985, "PowerPC Constant Reference Analyzer": 15.81, "Stack": 7.758, "Create Address Tables - One Time": 5.023, "Reference": 2.352, "ASCII Strings": 2.345, "Subroutine References": 1.828}}`
  - command: `/home/raikaru/ghidra_12.1.3_PUBLIC/support/analyzeHeadless /var/tmp/fg-import-speed/runs/x360-black-ops-2/ghidra-0/ghidra-project proj -import /home/raikaru/runs/FinalGate/home/ventris-corpus/extracted/x360-call-of-duty-black-ops-2/default_mp_script.exe -processor PowerPC:BE:64:A2ALT-32addr -scriptPath /home/raikaru/runs/FinalGate/ventris/benchmarks/ghidra -postScript ExportFunctionEntries.java /var/tmp/fg-import-speed/runs/x360-black-ops-2/ghidra-0/ghidra-functions.json -deleteProject`

### psv-need-for-speed-most-wanted

Ghidra: `ARM:LE:32:v8`, loader auto-selected -- Stock ELF loader (auto-selected) on the decrypted eboot.elf (e_type 0xFE00, SCE executable), ARM:LE:32:v8 as our import.

Speed faster (wall ratio 0.4833, CPU ratio 0.7971, peak RSS ratio 0.4326); quality not-worse; F1 (informational) romwright 0.9722 / Ghidra 0.814.

- romwright: language `ARM:LE:32:v8`; CPU/wall 3.27; 1-min load before runs [2.92, 2.47]; score {"truth": 26495, "found": 26544, "recall": 0.9731, "precision": 0.9713, "invented": 762, "sizes_compared": 25782, "size_exact": 16274, "size_short": 9499, "size_long": 9}
  - phases (first run, s): `{"total": 169.895388, "console": 8.696298, "discovery": 31.547573, "flow": 25.902916, "parse": 0.006189, "patterns": 0.326941, "references": 23.667309, "references-only": 14.971004, "settle": 0.043898, "store": 1.805301, "switch": 106.944811, "switch-vsa": 4.302664}`
  - command: `/home/raikaru/runs/FinalGate/target/release/romwright-cli import /home/raikaru/runs/FinalGate/home/ventris-corpus/extracted/psv-need-for-speed-most-wanted/eboot.elf --name vita --project /var/tmp/fg-import-speed/runs/psv-need-for-speed-most-wanted/ours-0/project --timings`
- Ghidra: language `ARM:LE:32:v8`, loader `Executable and Linking Format (ELF)`, 19846 functions (0 in overlays, unscored); CPU/wall 1.98; 1-min load before runs [3.4, 4.4]; score {"truth": 26495, "found": 19302, "recall": 0.7035, "precision": 0.9657, "invented": 662, "sizes_compared": 18640, "size_exact": 11860, "size_short": 6775, "size_long": 5}
  - phases (first run, s): `{"jvm_startup": 2.394, "analysis": 343.0, "load_script_save_exit": 3.35, "top_analyzers": {"Decompiler Switch Analysis": 197.607, "Disassemble": 55.663, "ARM Constant Reference Analyzer": 27.511, "Stack": 27.465, "Subroutine References": 8.258, "Create Function": 5.126, "Reference": 4.865, "Data Reference": 3.442}}`
  - command: `/home/raikaru/ghidra_12.1.3_PUBLIC/support/analyzeHeadless /var/tmp/fg-import-speed/runs/psv-need-for-speed-most-wanted/ghidra-0/ghidra-project proj -import /home/raikaru/runs/FinalGate/home/ventris-corpus/extracted/psv-need-for-speed-most-wanted/eboot.elf -processor ARM:LE:32:v8 -scriptPath /home/raikaru/runs/FinalGate/ventris/benchmarks/ghidra -postScript ExportFunctionEntries.java /var/tmp/fg-import-speed/runs/psv-need-for-speed-most-wanted/ghidra-0/ghidra-functions.json -deleteProject`

### nds-pokeheartgold-arm9

Ghidra: `ARM:LE:32:v5t`, loader `NTRGhidraLoader` -loader-cpu ARM9 -loader-overlays true -- NdsLoader (NTRGhidra) extension, ARM9 CPU; ARM9 overlays loaded into overlay spaces (our import also analyses them) but not scored. The loader takes one CPU per program: the ARM7 binary our import also analyses (161 KB) is not loaded, a small advantage to Ghidra.

Speed faster (wall ratio 0.3078, CPU ratio 1.0804, peak RSS ratio 0.2755); quality not-worse; F1 (informational) romwright 0.9855 / Ghidra 0.9265.

- romwright: language `ARM:LE:32:v5t`; CPU/wall 2.46; 1-min load before runs [2.53, 0.78]; score {"truth": 11078, "found": 10795, "recall": 0.9729, "precision": 0.9984, "invented": 17, "sizes_compared": 10735, "size_exact": 5151, "size_short": 5583, "size_long": 1}
  - phases (first run, s): `{"total": 111.310774, "console": 2.149792, "discovery": 4.0031, "flow": 2.696411, "parse": 0.189141, "patterns": 0.079644, "references": 3.856356, "references-only": 1.706558, "settle": 0.004126, "store": 0.393357, "switch": 5.247455, "switch-vsa": 1.826476}`
  - command: `/home/raikaru/runs/FinalGate/target/release/romwright-cli import /home/raikaru/runs/FinalGate/home/ventris-corpus/extracted/nds-pokeheartgold/pokeheartgold.us.nds --name nds --project /var/tmp/fg-import-speed/runs/nds-pokeheartgold-arm9/ours-0/project --timings`
- Ghidra: language `ARM:LE:32:v5t`, loader `Nintendo DS (NTR) and DSi (TWL)`, 27821 functions (18230 in overlays, unscored); CPU/wall 0.7; 1-min load before runs [3.7, 2.08]; score {"truth": 11078, "found": 9591, "recall": 0.8643, "precision": 0.9983, "invented": 16, "sizes_compared": 9532, "size_exact": 4453, "size_short": 5079, "size_long": 0}
  - phases (first run, s): `{"jvm_startup": 2.475, "analysis": 351.0, "load_script_save_exit": 4.05, "top_analyzers": {"Decompiler Switch Analysis": 246.242, "Disassemble": 30.02, "ARM Constant Reference Analyzer": 20.872, "Stack": 16.993, "Subroutine References": 11.179, "Create Address Tables - One Time": 5.962, "Reference": 4.382, "Create Function": 4.086}}`
  - command: `/home/raikaru/ghidra_12.1.3_PUBLIC/support/analyzeHeadless /var/tmp/fg-import-speed/runs/nds-pokeheartgold-arm9/ghidra-0/ghidra-project proj -import /home/raikaru/runs/FinalGate/home/ventris-corpus/extracted/nds-pokeheartgold/pokeheartgold.us.nds -loader NTRGhidraLoader -loader-cpu ARM9 -loader-overlays true -processor ARM:LE:32:v5t -scriptPath /home/raikaru/runs/FinalGate/ventris/benchmarks/ghidra -postScript ExportFunctionEntries.java /var/tmp/fg-import-speed/runs/nds-pokeheartgold-arm9/ghidra-0/ghidra-functions.json -deleteProject`

### gba-pokeemerald

Ghidra: `ARM:LE:32:v4t`, loader `GBALoader`  -- gba-ghidra-loader extension (GBALoader), forced because the ROM has no container a stock loader recognises.

- romwright: language `ARM:LE:32:v4t`; CPU/wall 1.95; 1-min load before runs [2.03, 3.22]; score {"truth": 15856, "found": 15484, "recall": 0.9737, "precision": 0.9971, "invented": 45, "sizes_compared": 15437, "size_exact": 5730, "size_short": 9707, "size_long": 0}
  - phases (first run, s): `{"total": 57.106726, "console": 5.787863, "discovery": 12.158221, "flow": 8.528373, "parse": 0.004629, "patterns": 0.258263, "references": 36.539811, "references-only": 30.75194, "settle": 0.022152, "store": 0.962444, "switch": 3.894627, "switch-vsa": 2.052597}`
  - command: `/home/raikaru/runs/FinalGate/target/release/romwright-cli import /home/raikaru/runs/FinalGate/home/ventris-corpus/extracted/gba-pokeemerald/pokeemerald.gba --name gba --project /var/tmp/fg-import-speed/runs/gba-pokeemerald/ours-0/project --timings`
- Ghidra run 1: timeout after 3600.02 s
  - command: `/home/raikaru/ghidra_12.1.3_PUBLIC/support/analyzeHeadless /var/tmp/fg-import-speed/runs/gba-pokeemerald/ghidra-0/ghidra-project proj -import /home/raikaru/runs/FinalGate/home/ventris-corpus/extracted/gba-pokeemerald/pokeemerald.gba -loader GBALoader -processor ARM:LE:32:v4t -scriptPath /home/raikaru/runs/FinalGate/ventris/benchmarks/ghidra -postScript ExportFunctionEntries.java /var/tmp/fg-import-speed/runs/gba-pokeemerald/ghidra-0/ghidra-functions.json -deleteProject`
- Ghidra run 2: timeout after 3600.05 s
  - command: `/home/raikaru/ghidra_12.1.3_PUBLIC/support/analyzeHeadless /var/tmp/fg-import-speed/runs/gba-pokeemerald/ghidra-1/ghidra-project proj -import /home/raikaru/runs/FinalGate/home/ventris-corpus/extracted/gba-pokeemerald/pokeemerald.gba -loader GBALoader -processor ARM:LE:32:v4t -scriptPath /home/raikaru/runs/FinalGate/ventris/benchmarks/ghidra -postScript ExportFunctionEntries.java /var/tmp/fg-import-speed/runs/gba-pokeemerald/ghidra-1/ghidra-functions.json -deleteProject`

## Gate

- speed: median wall ratio ours/Ghidra < 1 - tol, tol = max(0.05, worst (max-min)/median run spread of either tool on the image); inside 1 +- tol is inconclusive and fails.
- quality: recall and precision each >= Ghidra's - 0.01 (m21-001's floor margin), both scored by m21-001 `score()` over the same ranges. Images in PSX_PRECISION_METRIC (psx-darkstalkers-3) gate m21-001's supplementary `precision_corroborated` instead of `precision` (both reported; docs/import-speed.md).

## Fairness

- One process at a time, tools alternating run by run, so host-load drift lands on both; the host is shared (1-min load before each run is recorded), so compare ratios, not seconds.
- Both tools at default parallelism; CPU time and CPU/wall are reported beside wall.
- Both projects are written under the same --work directory on disk; Ghidra's wall includes JVM startup and saving its project, ours writing project.sqlite (the ratio without JVM startup is reported, not gated).
- Our import runs with every ROMWRIGHT_* variable cleared except the native tool paths and ROMWRIGHT_NO_IMPORT_CACHE=1: no import cache, no JVM.
- Ghidra heap 8G (the bridge default); default analyzers; language as our import except X360 (stock A2ALT-32addr; our Xenon language is not a Ghidra module).
- NDS: our import also analyses ARM7 and all overlays; Ghidra loads ARM9 plus overlays. Overlays are scored on neither side.
- PSX: VS.MAP lists globals only (m21-001), so `precision` is a floor for both tools and the gate uses `precision_corroborated`: the same image-bytes rule (psx_corroborated) applied to both tools' entries; `precision` is reported beside it.
- Peak RSS is the largest single process (wait4 ru_maxrss), not the process-tree sum.

