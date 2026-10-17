# Import speed against stock Ghidra

"State-of-the-art import speed" is tracked as a number, never alone:
`benchmarks/import_speed.py` times `romwright-cli import` against stock
Ghidra 12.1.3 headless auto-analysis of the same console images, and scores
both tools' function entries against the same truth with m21-001's
`score()`. A speed win with worse recall or precision does not pass.

Report: `benchmarks/reports/import-speed.json` and `.md`, written by the
script only.

## Running

<!-- not gated: needs the private console corpus and a Ghidra install, and
a full run takes hours of exclusive machine time; the script writes the
report this page describes. -->
```sh
CARGO_TARGET_DIR=$PWD/target/speedgate python3 benchmarks/import_speed.py
# subsets / fewer runs while iterating
python3 benchmarks/import_speed.py --no-build --only psx-darkstalkers-3 --runs 1 \
    --report /tmp/speed.json
```

Needs the corpus (`~/romwright-corpus/extracted`), `native/build/ghidra_opt`,
and a Ghidra 12.1.3 install (`--ghidra`, default `~/ghidra_12.1.3_PUBLIC`)
with the console extensions the corpus needs (gba-ghidra-loader, NdsLoader,
PsxLoader, XEXLoaderWV, ghidra-emotionengine-reloaded,
GameCubeLoader). Per-run results are cached under
`/var/tmp/romwright-import-speed` (`--work`; on disk, and free of `.` path
elements, which Ghidra refuses in a project location), keyed by binary
hashes, Ghidra version, post-script and configuration, so an interrupted run
resumes. `--native DIR` takes `ghidra_opt` from a copy
(take one before a rebuild lands mid-run; the tool fingerprint includes
them, so a changed binary re-runs our imports). `--limit S` sets the per-run
kill time (default 3600 s); a run that timed out is reused only under a
limit no longer than the one it was killed at.

Ghidra is a benchmark reference only. ADR-0001
(`docs/adr/0001-process-topology-no-jvm.md`) requires the product's steady
state to run with no JVM and keeps the bridge "only as dev oracle"; it also
asks every stage to record its own measurement against stock Ghidra in
`benchmarks/reports/`. The harness clears every `ROMWRIGHT_*` variable for
our import (no `ROMWRIGHT_GHIDRA`), so the timed import cannot start a JVM.

## What is measured

Per image and run, one process at a time, alternating tools run by run
(3 runs for PSX, PS2 dungeon/Capcom, GC; 2 for X360, Vita, NDS, GBA):

- wall time; CPU time (user+sys of the process and every descendant it
  reaped, `wait4`); peak RSS of the largest single process;
- the 1-minute load average before and after (the host is shared);
- phases: ours from the `TIMINGS` line (phase times are summed across
  lanes, so they can exceed wall); Ghidra's JVM startup, analysis total and
  top analyzers from its log, and the remainder (load, post-script, save,
  exit);
- recall/precision/size agreement for both, over the same ranges.

## Ghidra configuration

Same processor/language as our import (`programs.language`) wherever stock
Ghidra has it, default analyzers, heap 8G (the bridge's own default; the
stock 2G default would time the garbage collector on the big images).
Functions are exported by `benchmarks/ghidra/ExportFunctionEntries.java`
(entry, size of the body range holding the entry, overlay flag; external
functions skipped).

**PSX stock baseline.** The Ghidra row imports VS.EXE as `MIPS:LE:32:default`
(Ghidra's own MIPS, the R3000A being MIPS I) under PsxLoader's PS-EXE loader, which
only lays out the image; our import uses `PSX:LE:32:default`
(`native/languages/psx`: that MIPS plus our GTE definitions). This is the setup
behind the recorded stock PSX numbers, 0.9205 / 0.3743 (2012 functions; reproduced
on 2026-10-08). Ghidra on `PSX:LE:32:default`, PsxLoader's language or ours, finds
only 1011 functions (0.5844 / 0.4728, what the report recorded before this row
changed). The cause is not established in Ghidra; the extension keys its function-start
patterns to `MIPS:LE:32:default`, and `native_runtime/patterns.rs` borrows them for our import.
`native/languages/psx/install.sh` moves PsxLoader's `data/languages` to
`<install>/.romwright-replaced/PsxLoader-languages` (two modules with one language id
are ambiguous); the harness does not need it.

| image | language | loader / options |
|---|---|---|
| gba-pokeemerald | ARM:LE:32:v4t | `-loader GBALoader` (gba-ghidra-loader) |
| nds-pokeheartgold-arm9 | ARM:LE:32:v5t | `NTRGhidraLoader -loader-cpu ARM9 -loader-overlays true` |
| ps2-capcom-fighting-evolution | r5900:LE:32:default | stock ELF loader, stripped ELF |
| ps2-dungeon-game | r5900:LE:32:default | stock ELF loader, stripped ELF |
| psx-darkstalkers-3 | MIPS:LE:32:default (ours: PSX:LE:32:default) | PsxLoader's PS-EXE loader (see above) |
| psv-need-for-speed-most-wanted | ARM:LE:32:v8 | stock ELF loader (eboot.elf, e_type 0xFE00) |
| x360-black-ops-2 | PowerPC:BE:64:A2ALT-32addr | XEXLoaderWV (see above) |
| gc-animal-crossing | PowerPC:BE:32:Gekko_Broadway | GameCubeLoader (no truth: speed only) |

The script's `GHIDRA_CONFIG` is authoritative; the report repeats it with
the loader Ghidra actually used and fails a run whose language differs.

X360: our language, `PowerPC:BE:64:Xenon-32addr` (A2 + VMX128), is built
by `native/languages/xenon/install.sh` into the Ghidra tree without a
`Module.manifest`, so stock Ghidra does not load it ("Unsupported
language"). The benchmark does not modify the install; it uses
`A2ALT-32addr` (A2 + AltiVec), the stock language Xenon extends. VMX128
instructions do not decode there, so Ghidra's flow stops at them.

## Gate

- **Speed:** median wall ratio ours/Ghidra < 1 - tol, where tol is the
  larger of 5% and the worst (max-min)/median run spread of either tool on
  that image. The claim has to clear the noise the shared host showed on
  that image; the 5% floor covers two or three runs underestimating spread.
  A ratio within 1 ± tol is inconclusive and fails.
- **Quality:** recall and precision each at least Ghidra's minus 0.01 (the
  margin m21-001 uses for its floors). Both tools are deterministic, so a
  run whose scores differ from the image's first run is flagged. PSX
  Darkstalkers 3 is gated on `precision_corroborated` instead of
  `precision` (next section); `precision` is still reported beside it.

### PSX precision: why the gate uses `precision_corroborated`

`precision` (m21-001, unchanged) counts a found entry as right only when
`VS.MAP` names it. The Psy-Q map lists global symbols; the `static`
functions of the same translation units are not in it. Stock Ghidra scores
0.4728 and we score 0.3663 because we find 868 more of those statics, not
because they are wrong: Ghidra recovers 478 of the 818 named functions
(recall 0.5844), we recover 808 (0.9878). Refusing the statics to raise
`precision` would trade real functions for a number, so the gate measures
whether the entries are real.

Classification of our 1,398 entries the map does not name (2026-10-08,
`target/psx` import of `VS.EXE`, inside `.text` 0x801395F0-0x8018ED2C):

| evidence (from the image bytes) | entries | note |
|---|---|---|
| `jal` target | 545 | 146 are called from the body of a map-named function |
| address in a function-pointer table (2+ consecutive data words outside `.text`, each a return-preceded, unbranched entry) | 803 | of the 853 that no `jal` calls, 803 sit in runs of 2+ words in `.data`/`.sdata` (759 in runs of 4+), 8 are lone pointers, 42 have none; the longest run, 158 words at 0x8018FDC4, has an invented entry in every word |
| opens `addiu $sp,$sp,-N`, address formed by `lui`+`addiu`/`ori` or held in a lone data word | 43 | |
| none of the above | 7 | 5 read as real code with no caller in the image (0x801632DC, 0x8016D4D8, 0x801835D0, 0x801837F8, 0x80189858: leaf, array and prologue-opening functions; callers are likely overlays or `jalr`, not checked); 2 look like fragments (0x8014102C, the unreachable epilogue of 0x80140FCC, which ends in an infinite `j` loop; 0x801838CC, 8 bytes in hand-written library code) |

Checks for junk or split bodies (two fragments found, the rest clean):

- 1,397 of 1,398 start right after a `jr $ra` (the exception is the dead
  epilogue 0x8014102C); 0 are the target of any `b*`/`j` in `.text`, as
  0 of the 818 map-named entries are; 0 lie inside another found function's
  extent; 0 begin on a zero word or padding.
- 1,102 (79%) open a stack frame (`addiu $sp,$sp,-N` in the first six
  instructions), against 579 of the 818 named ones (71%). Example:
  0x80141104 follows `jr $ra` at 0x801410FC, is `addiu $sp,-0x18; sw
  $ra,0x14($sp)`, and is the table word at 0x8018EFCC (neighbours
  0x80142930 and 0x80142A48 are functions too).
- Ghidra's own 533 entries the map does not name fall in the same
  classes (521 `jal` targets, 12 table entries), and 530 of them are ours.

The rule (`psx_corroborated` in `tests/m21-001_real_images.py`) is
tool-independent: it reads `VS.EXE`, never a tool's output, and applies to
whichever entries a tool proposes. An address qualifies when it is
word-aligned, follows a `jr $ra` (two words back, skipping zero words), no
branch or `j` in `.text` targets it, and one of: a `jal` calls it; it is in
a function-pointer table (consecutive data words outside `.text` that all
meet the first two conditions); or it opens a stack frame and its address
is taken (`lui`+`addiu`/`ori`, or a data word). `precision_corroborated` is
(entries the map names + entries the rule accepts) / entries found. It is a
floor on real functions, not proof: a leaf function reached only through a
lone pointer or from an overlay qualifies by none of the three.

| | recall | `precision` (map only) | `precision_corroborated` |
|---|---|---|---|
| romwright | 0.9878 | 0.3663 | 0.9968 |
| Ghidra 12.1.3 | 0.5844 | 0.4728 | 1.0000 |

Gate: ours >= Ghidra's - 0.01 on both `recall` and `precision_corroborated`
(0.9968 vs 1.0000). The rule also lists corroborated entries a tool does
not find: 52 for us (49 table entries, 3 `jal` targets; mostly small leaf
handlers in function-pointer tables) against 910 for Ghidra (840 table, 43
frame, 27 `jal`). Our static-function recall is not complete either; it is
not gated.

## Supplement: why stock Ghidra does not finish GBA in 3600 s, and how long it takes

Not a change to the gate: `LIMIT_S` stays 3600, the GBA row stays "killed at
3600 s" and the overall status stays `fail` through it. This records what the
killed run was doing and a measured completion time, taken 2026-10-09 on the
8-vCPU host (`nih-vps-u`, the harness's own command line: `analyzeHeadless ...
-loader GBALoader -processor ARM:LE:32:v4t -postScript ExportFunctionEntries.java
-deleteProject`, 8 GB heap, default analyzers, plus `-log`), under a 6 h
allowance and a `jstack` of the JVM every 180 s.

| | |
|---|---|
| wall (import, analysis, export, save) | **14,284 s (3 h 58 min)**, exit 0; analysis total 14,275 s |
| CPU of the JVM | at least 12,991 s (last sample, 3 h 36 min in), i.e. one busy core: the run is single-thread bound, not I/O or GC bound (young GC 391 s of 6,100 s at 1 h 42, no full GC) |
| peak RSS (sampled) | 8.6 GB (heap cap 8 GB) |
| host load average during the run | 3 to 25 (other jobs on the shared host), so the figure is **not** a paired timing; the near-1:1 CPU/wall ratio is why load moved it little |
| functions Ghidra exports | 202,576 (truth 15,856; ours: recall 0.9737 / precision 0.9971) |
| Ghidra recall / precision, scored by `import_speed.py`'s own `score_entries` | 0.4652 / 0.0364 |
| ours / Ghidra wall, if the 14,284 s were the Ghidra row | 56.9 s / 14,284 s = 0.004 |

Analysis-time summary Ghidra printed (seconds): **Non-Returning Functions -
Discovered 9,201** (64%), ARM Constant Reference Analyzer 2,187, Decompiler
Switch Analysis 1,602, Create Function 969, Create Address Tables - One Time
124, Call-Fixup Installer 84, Stack 40, every other analyzer under 35.

**The analyzer and the loop.** 79 `jstack` samples were taken (every 3 min, 3 h
58 min): 50 had the main thread inside `FindNoReturnFunctionsAnalyzer.added`
(`detectNoReturn`, 49 of them inside `targetOnlyCallsNoReturn`, lines 472,
482 and 490 of the Ghidra 12.1.3 source in `Base-src.zip`), 12 in
`ConstantPropagationAnalyzer`/`ArmAnalyzer` and 11 in `DecompilerSwitchAnalyzer`.
63% of the samples against 64% of the analyzer-reported time. In
`detectNoReturn`, for every call whose callee shows non-returning indicators
and whose evidence stays under the threshold, `targetOnlyCallsNoReturn` walks
every code block reachable from the callee through a `SimpleBlockModel`
(`getCodeBlockAt`, `getDestinations`, a per-call `visited` address set) and
only then decides; and `added` runs again for each batch of new functions
(twice per batch when it found suspicious targets). The cost is therefore
(suspicious targets) x (code reachable from each) x (analyzer re-runs), and
the input is the part that is unusual here: the GBA loader presents the
whole 32 MB cartridge to the analyzers and Ghidra ends with 202,576 function
entries against 15,856 true ones, so every analyzer works on about thirteen
times the functions there are.

**Control run** (diagnostic, not a gate input): the same command with the
analyzer disabled before analysis (`setAnalysisOption(currentProgram,
"Non-Returning Functions - Discovered", "false")` in a `-preScript`) finished in
5,072 s wall (total analysis 5,056 s; ARM Constant Reference 1,413, Decompiler
Switch 1,659, Create Function 1,546, Create Address Tables - One Time 229,
Stack 84; the host load was 11-25), 203,400 functions, recall 0.516, precision
0.0402. So the analyzer is 64% of the time, and the remaining 36% (about
1.4 h on a loaded host) would still be over the 3600 s cap by itself.

**Consequence for the gate.** The verdict is unchanged: a Ghidra row needs a
run that ends inside `LIMIT_S`, and none does on this image. If the cap were
the only thing standing between GBA and a number, it would need to be at least
14,400 s; ours would then be 0.004 of Ghidra's wall, and quality passes (ours
0.9737 / 0.9971 against 0.4652 / 0.0364).

## Fairness notes

- Both tools get the whole machine at default parallelism; CPU time and
  CPU/wall are reported beside wall so parallelism is visible, not hidden.
- NDS: our import also analyses the ARM7 binary and every overlay; Ghidra
  loads ARM9 plus its overlays (one CPU per program). Overlay functions are
  not scored on either side.
- PSX `precision` is a floor on accuracy for both tools (the map lists
  globals only, m21-001); the gate uses `precision_corroborated`, the same
  image-bytes rule applied to both tools' entries (section above).
- Ghidra's time includes JVM startup and saving its project database; ours
  includes writing `project.sqlite`. Both are what a user waits for.

## What a small import costs in memory, and the pattern scan

`benchmarks/memory_fix.py` (report: `benchmarks/reports/memory_fix_*.md`) measures
`romwright-cli import` before and after the decoder memory fix side by side. A tiny
ELF import was 300 MB (x86-64), 244 MB (i386), 249 MB (AArch64) and 91 MB
(PowerPC) because every decoder held its language's whole decoded `.sla`
(35 MB for x86-64) and the import kept five to nine decoders alive; it now peaks
at 40, 33, 36 and 20-22 MB, inside the frozen `cost-envelope.json` with its 25%
headroom, and builds one decoder instead of seven. The x86-64, i386 and AArch64
peaks are the decompiler worker's, not the importing process's (22-23 MB).
Large images are unchanged or faster: the same rows on Persona 4, a GBA and a
GameCube image, wall time 0.96-0.97 on GBA and GameCube, and 0.74 on Persona 4,
where the function-start pattern scan (`native_runtime/patterns.rs`: a second
byte of each pattern is tested from the bucket's own memory before the pattern is
read) went from 5.4 s to 1.3 s on the same 9,602 matches.

The shipping profile (`--profile dist`: `lto = "fat"`, `codegen-units = 1`, `Cargo.toml`) is part of this: it
shrinks the resident code of the importer by 4 MB, which is a fifth of a tiny
PowerPC import. One code-generation unit also exposed the cost of that scan
(5.4 s became 8.5 s on Persona 4 under it), which is why the scan was rewritten
rather than the profile relaxed.
