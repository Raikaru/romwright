# `match`: a near-miss search over alternative C printings

```text
romwright-cli match <name|0xADDR> [--project REPO] [--budget N] [--time SECS] [--write] [--json]
romwright-cli match --plan [--budget N] [--outcomes FILE]
```

A function the decompiler prints and the project's compiler turns into *almost*
the retail bytes is a near miss (`docs/c-output-lanes.md`, "Failure classes":
the byte differences are register allocation, scheduling, a single instruction,
a few instructions, or a different length). The
decompiler makes a handful of printing choices that change which C the same
function becomes: which values share a variable, which print inline as
sub-expressions, how an `if` is shaped. `match` prints the function a bounded
number of ways, compiles each print with the repository's own pinned compiler and
flags, scores the object's bytes against the retail ones and keeps the best.
The retail bytes and the compiler are the only oracle: no rule is fitted, no
decompilation repository is read, and the search never looks at the C a lane's
truth holds.

It runs inside a repository `new-project` wrote (`docs/new-project.md`), after
`python3 configure.py` has put the pinned tools into `build/tools/`:

```text
$ python3 configure.py
$ romwright-cli match 0x001f1c78 --write
$ python3 configure.py swap 0x001f1c78
$ ninja
```

The desktop's **Match** panel runs the same search for the function at the
cursor and shows this table ([desktop.md](desktop.md#new-project-and-match));
Program setup's **Create project** runs `new-project` on the open image.
`docs/getting-started.md` ("Start a matching project") runs the whole path
on the repository's PE32 fixture, with clang as the compile check.

## What it tries

Every knob is one that already exists in the printing path (nothing is added to
the decompiler, and `ghidra_opt` is unchanged):

| knob | axis | what it changes |
|---|---|---|
| `datatype=off` | merge | no speculative merge of non-intersecting variables of one type (`ActionMergeType`) |
| `adjacent=off` | merge | no speculative merge of an op's input and output (`ActionMergeAdjacent`) |
| `copy=off`, `dominant=off`, `hideshadow=off` | merge | `ActionMergeCopy`, `ActionDominantCopy`, `ActionHideShadow` |
| `maxref=1`, `3`, `4` | maxref | how many readers a value may have and still print inline (stock 2) |
| `maxdup=1`, `3`, `4` | maxdup | how many terms an inlined expression may duplicate (stock 2) |
| `calls=cast` | calls | an undeclared callee's prototype is read off the calls as the casts typed them (`ROMWRIGHT_RUST_CASTS_CALLS=cast`) |
| `structuring=none` | structuring | none of the goto-removing structuring models run, so the gotos of the decompiler's own structure stay (`ROMWRIGHT_RUST_STRUCTURING=none`; `printc/structure.rs`) |
| `structuring=no_arm_order` | structuring | every model, but `if`/`else` arms in the decompiler's order, not code order (`ROMWRIGHT_RUST_STRUCTURING=all,no_arm_order`) |

The merge knobs are stage 3's variant (`docs/merge-port.md` section 5). Order of
the search: the stock print, then each single knob (in the order above, which is
only what a small `--budget` keeps), then combinations built from what the single
knobs did *on this function*: the speculative-merge knobs together
(`adjacent=off+datatype=off`, with `copy=off`), and pairs (then the triple) of the
best single knobs on different axes that printed different C and scored no worse
than the stock print. Prints with identical C are compiled once. The search stops at
the first exact variant, at `--budget` variants (default 24, the stock print not
counted) or after `--time` seconds (default 600).

The export switches of Upgrade 1 (`ROMWRIGHT_EXPORT_*`) are not varied: they are
compile-correctness repairs of the printed text (union views, odd widths), not
alternative printings, and they are read from the process environment by the export
code, not per request.

## Scoring

Each print is compiled as `#include "romwright_types.h"` plus the printed C with
`config/project.json`'s compiler and flags exactly as `configure.py` runs them
(`wibo` for a Windows compiler, the profile's `compile_arguments` when
`config/toolchain.local.json` has them). The function's `.text` and relocations are
read from the object; a candidate is **exact** when it is as long as the retail
function and every byte equals the retail one outside the relocation fields. The
score is `objdiff-cli`'s `match_percent` of the two one-function objects
(`functionRelocDiffs=none`, from `build/tools/`); without `objdiff-cli` it falls back to
the share of equal instruction words and says so. The ranking is exact, then
compiled, then percent, then fewer differing bytes; the earliest variant wins a tie,
so the stock print is kept unless something beats it. This is the m22-003 lane
harness's measure (`tests/m22-003/elfobj.py`, ported to
`crates/romwright-core/src/match_search/object.rs`), so a project's number and a
lane's are the same number: `sndAddSourceReferences` is 88.842% in both.

The table shows one row per variant: the hash of its C (variants with the same hash
did not change the print; `= #n` names the row that was compiled), the score, the
number of differing bytes (or the compiled size when it differs from retail) and
the decompile and compile times. `--json` prints the same with every field.
`--write` puts the best C where `configure.py swap` picks it up:
`decompiled/<unit name>.c` for a function that is still an assembly unit (the file
`swap` copies in), `src/<unit>.c` when it is already a C unit.

## How the variants travel

`RuntimeConfig::worker_env` (core) is a list of environment pairs the decompiler
worker gets for one request; `M2cOptions::worker_env` sets it for `export_m2c`.
The worker already reads `ROMWRIGHT_MERGE_VARIANT`, `ROMWRIGHT_RUST_CASTS_CALLS` and
`ROMWRIGHT_RUST_STRUCTURING` from its environment, so a variant is those three
variables, and nothing in the wire format, the IR or the C++ changed. The default
request has an empty list and prints what it always printed, byte for byte.

The plan lives in `crates/romwright-core/src/match_search/plan.rs` and is the only
copy: `match --plan` prints the single knobs as JSON (with `--outcomes FILE` holding
the single knobs' scores, the combinations to try next), and the lane benchmark
harness reads it from there.

## Benchmark

`tests/m22-003_ps2_multigame_c.py LANE --layers romwright --search N` adds a layer,
`romwright-search`: for every sampled function whose default print compiles (the
lane's headline `context` compile) and is not exact, the plan's variants are exported
with their switches, deduplicated, compiled with the unit's own command and scored by
the lane's scorer; the best print per function is the layer's candidate. The
`romwright` layer is the default print, produced exactly as without `--search`. The
export of each variant runs while the project store is in the state the function's
default print saw (the harness asserts names and prototypes cumulatively), and a
batch's variants run in parallel (`--jobs`); a batch is not cut short at an exact
variant the way the command is. `tests/match_search_report.py` rolls the arms up.

### Smoke on a real repository

`romwright-cli new-project` on Digital Devil Saga (`SLUS_209.74`, ee-gcc 2.96, `-O2`), `python3 configure.py`, then
(`FUN_...` are the names the repository's store holds; the lane's names for the same
functions are `sndAddSourceReferences` and `btlReleaseModelEntry`):

```text
$ romwright-cli match 0x001f1c78
FUN_001f1c78 0x1f1c78 (76 bytes)  compiler ee-gcc2.96 -O2  metric: objdiff match %
  #  variant                                        C          match %  exact   bytes   decomp  compile
  0  default                                        15376c1e    88.842     no      16   0.602s   0.053s
  1  datatype=off                                   15376c1e    88.842     no      16   0.484s       0s = #0
  2* maxref=1                                       a6ee33be   100.000    yes       0   0.482s   0.013s
best: maxref=1  100.000% exact  (default 88.842%)  3 decompiles, 2 compiles, 1.6s; stopped at an exact variant
```

| function (lane name) | default | best variant | best | variants / compiles | time |
|---|---|---|---|---|---|
| `0x001f1c78` (`sndAddSourceReferences`) | 88.842% | `maxref=1` | 100.000%, exact | 3 / 2 (stopped at the exact one) | 1.6 s |
| `0x00211390` (`btlReleaseModelEntry`) | 99.167% | `datatype=off` | 99.479%, 5 bytes differ | 15 / 4 | 13.7 s |
| `0x00198528` (`itfReleasePoolNode`) | 94.667% | `datatype=off` | 96.571%, 5 bytes differ | 15 / 3 | 7.5 s |
| `0x002649b0` | 83.091% (188 bytes, retail 176) | default | 83.091% | 17 / 8 | 8.3 s |

`--write` put the first one's C in `decompiled/FUN_001f1c78.c`; `python3 configure.py swap 0x001f1c78` made it
`src/main/0145/FUN_001f1c78.c`, and `ninja progress` (the repository's own objdiff report) reads
`FUN_001f1c78` 76 of 76 code bytes, 100%. On a repository generated after the load-tail fix
(`docs/new-project.md`, item 6), `match --write`, `swap` and `ninja` end with `OK build/SLUS_209.74 sha1 6d18898e…`:
the retail file, rebuilt with this function compiled from the searched C. The lane scores a function with the unit's
declarations in scope and the repository's compile command; the repository
here has neither, so the same function is 88.842% in both and others differ (`btlReleaseModelEntry`: 99.646% default and
exact with `datatype=off` in the lane, 99.167% and 99.479% here).

### The PS2 lanes

`tests/m22-003_ps2_multigame_c.py LANE --layers romwright --search 24` on dds, rc, p4, gh, ff, dc, dk, and
`tests/m22-002_ps2_c_output.py --search 24` on the Persona 4 decompilation (MWCC seeds 20261010 and 20261011, ee-gcc).
Every arm is a fresh import and a fresh snapshot of the prepared work directory and repository; `ghidra_opt` is
the pinned build (sha256 486ace43...). The default arm of each lane is the baseline of its report, to the digit,
and the `romwright` layer of the search run has the same exact, compiled and mean values. Headline (`context`) compile, objdiff percent,
`mean %` over all 200 sampled functions (a function that does not compile counts 0):

| lane | default exact / compiled / mean % | searched exact / compiled / mean % | improved of searched | newly exact | decompiles / compiles | wall s default / search arm |
|---|---|---|---|---|---|---|
| dds | 61 / 200 / 77.224 | 64 / 200 / 78.792 | 37 of 139 | 3 | 2051 / 310 | 221 / 787 |
| rc | 26 / 200 / 68.158 | 27 / 200 / 70.380 | 52 of 174 | 1 | 2552 / 351 | 76 / 259 |
| p4 | 60 / 193 / 79.400 | 60 / 193 / 80.007 | 32 of 133 | 0 | 1940 / 271 | 434 / 793 |
| gh | 78 / 199 / 82.119 | 80 / 199 / 83.869 | 28 of 121 | 2 | 1747 / 232 | 373 / 915 |
| ff | 21 / 195 / 61.753 | 24 / 195 / 64.178 | 53 of 174 | 3 | 2578 / 437 | 172 / 736 |
| dc | 38 / 186 / 69.844 | 40 / 186 / 70.719 | 30 of 148 | 2 | 2120 / 271 | 635 / 2991 |
| dk | 29 / 189 / 75.561 | 31 / 189 / 76.387 | 46 of 160 | 2 | 2309 / 289 | 235 / 1036 |
| m22-002 MWCC seed 20261010 | 55 / 193 / 76.968 | 58 / 193 / 77.562 | 38 of 138 | 3 | 2026 / 264 | 364 / 863 |
| m22-002 MWCC seed 20261011 | 57 / 194 / 78.316 | 57 / 194 / 78.767 | 30 of 137 | 0 | 1988 / 243 | 364 / 848 |
| m22-002 ee-gcc | 106 / 197 / 86.403 | 107 / 197 / 87.736 | 16 of 91 | 1 | 1304 / 137 | 333 / 751 |

m22-003 lanes together: exact 313 -> 326 of 1400, 278 of the 1049 functions the search ran on
improved (a higher objdiff percent, or exact), 15297 decompiles and 2161 compiles. m22-002 lanes
(overlapping the p4 lane's functions, so not added to it): exact 218 -> 222 of 600, 84 of 366 improved.
Winners over the m22-003 lanes: `datatype=off` 74, `maxref=1` 63, `structuring=none` 51, then single
knobs and combinations in smaller numbers (the full histogram per lane is in the report). `compiles` counts the
distinct printed texts compiled: most variants print the same C as the stock one. The search moves many functions up a
little and a few to exact: it finds a better printing, it does not by itself close most near misses.

Wall seconds are of arms that shared the host (three lanes at once, `--jobs 4`, load 11 on 8 vCPU) and include the lane's
own compiles and scoring; the search arm also holds the default arm's work. A rerun of rc's search arm
with the final harness scored every function the same as the first (200 of 200). Report:
`benchmarks/reports/match_search_20261014.{json,md}` (per lane: improved functions with their winning variants, the
default print's byte-difference class of what was improved, search time).

## Nintendo 64, PlayStation and PSP projects

`match` works in the repositories of the three MIPS plugins (`new-project`, "Nintendo 64, PlayStation and PSP"
in [new-project.md](new-project.md)). What differs from PS2:

* **Compile.** `config/project.json` names the compiler kind (`ido`, `gcc-mips`, `psyq`, `psp-gcc`,
  `mwcc-psp`); the search runs `python3 tools/cc.py unit.c unit.o`, the command `ninja` uses, so the tools
  come from `build/tools/` (or a profile) exactly as the build resolves them. PSY-Q units go through
  `CPPPSX.EXE`/`CC1PSX.EXE` under wibo and maspsx; psp-gcc units through `cc1 -S` and the project's binutils.
* **Objects.** IDO objects are big-endian: `match_search/object.rs` reads either byte order, masks
  relocation fields by their byte positions in that order and writes the one-function objects
  `objdiff-cli` scores in it. IDO's `.text` rounding to 16 bytes is trimmed by `cc.py`.
* **Retail bytes.** From the repository's `layout` rows over the ROM or EXE (`orig/`), not from ELF program
  headers. A function in a compressed segment or an overlay is not in the repository, so it is not found.
* **Store program.** `config/project.json` records the program the import produced (`image.program`):
  an N64 ROM's main program is `<name>.main`.

Measured on `nih-vps-u` (compile and score on `nih-vps-u`; PSP on `smt-cloud`, whose 32-bit loader runs
psp-gcc), `--budget 12` (6 for the tiny sets), default flags of the project, fresh store per repository,
`ROMWRIGHT_NO_IMPORT_CACHE=1 ROMWRIGHT_NO_FACT_PACK=1`. "Exact" counts functions whose best variant has
objdiff 100% and the same size:

| repository (compiler, flags) | function set | functions | exact | mean % default print | mean % best variant | improved by a variant |
| --- | --- | --- | --- | --- | --- | --- |
| Super Mario 64 (`ido5.3`, `-O2 -G 0 -mips2 ...`) | 8 - 40 bytes, every 33rd of 791 | 24 | **13** | 74.54 | 74.54 | 0 |
| Super Mario 64 (same) | 48 - 160 bytes, every 25th | 30 | 0 | 49.81 | 49.91 | 1 (`maxref=1`, 48.179 -> 51.250 on `FUN_80181cc8`) |
| Silent Hill (`psyq4.3`, `-O2 -G0`) | first 40 functions of 48 - 256 bytes | 40 | **7** | 73.24 | 73.29 | 3 (`datatype=off`, `maxref=1`) |
| psp-melodie (`psp-gcc-1.7.1`, `-O2 -G0 -mno-abicalls -fno-pic`; `smt-cloud`) | 8 - 40 bytes, every 7th | 24 | **4** | 81.21 | 81.21 | 0 |
| psp-melodie (same) | 48 - 144 bytes, every 40th | 12 | 0 | 46.64 | 49.39 | 2 |

Exact examples: Super Mario 64 `FUN_801702b0`, `FUN_8017c008`, `FUN_8018e144` (IDO, 1 variant, 1.3 - 1.7 s each);
Silent Hill `FUN_80010ad0`, `FUN_80010ecc`, `FUN_80011f48`; psp-melodie `__0fJPSPKernelHGfxTermvT`,
`__0fOCMemoryManagerNFreeAllMemoryv`. `tgMatrixScaleF` (VFPU code in the retail, 84 bytes) scores 0%: the
printed C is scalar and compiles to 220 bytes.

An exact print is also a working unit: `match FUN_801702b0 --write`, `python3 configure.py swap FUN_801702b0`,
`ninja` on the Super Mario 64 repository (two such swaps) still ends with `OK ... sha1 9bef1128...` and
`ninja progress` reads 100% for the two units; the same for PSY-Q on Silent Hill's `FUN_80010ad0`.
The default flags are not calibrated for any game, which is why most non-trivial functions score
40 - 80%; the variant switches move few of them (the search varies printing, not types or flags).

## Game Boy Advance and Nintendo DS projects

`match` works in the repositories of the two ARM plugins (`new-project`, "Game Boy Advance and Nintendo DS" in
[new-project.md](new-project.md)). What differs:

* **Compile.** `compiler.kind` is `agbcc` or `mwcc-arm`; the search runs `python3 tools/cc.py OUT SRC`, the
  command `ninja` uses. GBA: `cpp -nostdinc -undef | agbcc -O2 -mthumb-interwork -fhex-asm | as` with the
  pinned Arm GNU 13.3 `cpp`/`as` and the pret/agbcc release binary, plus pret's trailing `.align 2, 0`. NDS:
  `mwccarm.exe` (the build named by `compiler.mw_version`) through wibo, with `include/romwright_names.h`
  mapping romwright's names (`FUN_02010b18`) onto dsd's symbol names (`func_02010b18`).
* **Objects.** `match_search/object.rs` reads ARM relocatable objects (`.rel.text`, implicit addends) and masks
  the fields the linker rewrites by relocation type (`R_ARM_THM_CALL` covers both halfwords of a `bl`,
  `R_ARM_CALL`/`JUMP24` the 24-bit offset, `ABS32` the word, `THM_PC8`/`LDR_PC_G0` literal loads). The
  one-function objects `objdiff-cli` scores carry `EM_ARM`, a `$t`/`$a` mapping symbol and the low bit of a
  Thumb function symbol; the retail object is the compiled one's with the relocated fields cleared under the
  retail bytes (as for PowerPC). mwccarm objects do not mark Thumb functions, so the mode comes from the
  project's own tables (`config/units.json`, dsd's `symbols.txt`).
* **Retail bytes.** GBA: the ROM (`orig/`) through the `layout` row. NDS: the extracted, decompressed
  `extract/arm9/arm9.bin` (and ITCM/DTCM) at the `base_address` of its `.yaml`; overlay functions share
  addresses and are not served.
* **`--write`.** GBA: the unit's source when the function is already a C unit, else `decompiled/<name>.c`. NDS:
  `decompiled/<dsd name>.c`, or the source in `config/swaps.json`.

Measured on `nih-vps-u` (load 20-45 from other agents; times are not comparable), `--budget 12`, default flags
of the project, a fresh store per repository, `ROMWRIGHT_NO_IMPORT_CACHE=1 ROMWRIGHT_NO_FACT_PACK=1`.

| image | compiler | functions (evenly spaced, 28-96 bytes) | compiled | exact (default print / after search) | others (match %, default -> best) |
|---|---|---|---|---|---|
| FE8 (GBA, Thumb) | agbcc `-O2 -mthumb-interwork -fhex-asm` | 16 | 15 | 7 / 7 | 90.5, 74.4, 99.92, 70.1 -> 81.1, 83.0, 80.5, 83.1, 41.1 -> 81.0 |
| twewy ARM9 (NDS, 14 ARM + 1 Thumb) | mwccarm 2.0/sp2p3 `-O4,p -lang c99 -proc arm946e` | 15 | 15 | 1 / 2 | 65.3, 26.2, 68.1, 22.3, 34.9, 82.6, 94.1, 61.4, 0.0 (compiled to 112 bytes against 52), 87.2, 89.8 -> 100.0 (a variant), 60.0, 71.5, Thumb 11.9 |

The one function of FE8 that did not compile fails on a decompiler union member (`whole`), the usual
class. The agbcc flags are pret's, which FE8's own project uses; the mwccarm flags are a starting point
(game code is built with `-O4,p` and its own `-inline`/`-str` choices), which is why the NDS sample sits lower.
An exact print is also a working unit: seven FE8 functions were swapped into the repository with
`configure.py swap`, and two twewy functions (one found by the variant search), and `ninja` still ends with
`OK ... sha1 c25b145e...` (FE8) and `OK ... sha1 23e87b1e...` (twewy).

## GameCube and Wii projects

A `new-project` repository for a GameCube or Wii DOL (`docs/new-project.md`, "GameCube and Wii")
is a dtk-template layout, and `match` works in it the same way: `config/project.json`
names the pinned compiler (`mwcc-gc-wii-20251118`, directory `compiler.mw_version`, e.g.
`GC/2.6`) and the flags (`compiler.cflags`, one option per entry); the retail bytes come from the DOL's
file-backed sections (`layout`); the function is a row of `config/<ID>/symbols.txt`.
The MWCC runs through wibo; its object is a big-endian PowerPC ELF with `.rela` relocations.
What changes in the scoring is only the mask and the objdiff input:

* the bits a linker rewrites are the PowerPC psABI's (`R_PPC_REL24` and `ADDR24` 0x03FFFFFC,
  `ADDR16`/`LO`/`HI`/`HA` 0xFFFF, `ADDR14`/`REL14` 0xFFFC) plus `R_PPC_EMB_SDA21` (0x001FFFFF: the
  register and offset of a small-data access), so a different `lis`/`addi` target or `@sda21` symbol is
  not a difference;
* the retail object has no relocation records, so its instructions hold final addresses where the
  compiled ones hold zeros plus a relocation. objdiff is given the compiled function's relocations on
  both sides, with the retail bytes cleared under them: relocated fields compare equal and
  `functionRelocDiffs=none` leaves the code.

`--write` puts the best C in `src/<unit>` when the function is already a unit of `splits.txt`
with an `objects.json` source, else in `decompiled/<name>.c`, which `python3 configure.py swap
<name>` installs as `src/main/<name>.c`.

## Windows PE projects

`match` runs inside the per-function repository `new-project` writes for a 32-bit Windows executable
(`docs/new-project.md`, "Windows PE (x86)"; `config/project.json` kind `pe-per-function`), after
`python3 configure.py` has installed the era's Visual C++, `wibo` and `objdiff-cli` and written `build/config.json`
(`match_search/{project,pe}.rs`):

* **Compile:** the pinned `cl.exe` through wibo with the project's flags, `/I include` and the compiler's own include
  directories (`INCLUDE`), one object per print; `long long` is spelled `__int64` for Visual C++ and a `__thiscall`
  definition is written `__fastcall` with an unused `edx`, as the project's own units are (`new_project/pe.rs`). A MinGW or
  unidentified PE has only clang for a Windows target as a compile check.
* **Score:** the object is read as i386 COFF (the function's bytes up to the next function symbol, without the trailing
  `nop`/`int3` alignment; `_f@12`, `@f@8`, `_f` are the name `f`), `exact` is every byte equal outside the `DIR32`/`REL32`
  fields over the retail length (a jump table or padding after the function's own bytes is cut when nothing but relocated
  words and padding follows), and the percent is objdiff-cli `diff` (`functionRelocDiffs=none`) on two one-function ELF i386
  objects that carry the compiled function's relocations on both sides, the same measure as the PC C-output lane
  (`tests/m22-004_pc_c_output.py`). `build.py report` uses objdiff's *report* measure (`fuzzy_match_percent`), which is more
  forgiving of a single wrong instruction: the same function can read 99.6 there and 83.2 here.
* **Retail bytes:** the PE image in `orig/`, as the loader maps it.
* **`--write`:** the best print goes to the unit's own `src/<shard>/<function>.c`, kept `NON_MATCHING` and annotated
  `// FUNCTION:`; `python3 build.py && python3 build.py report` then says whether it matches (there is no `configure.py swap`:
  the repository has no whole-image build).

Real numbers (`nih-vps-u`, repository of GLQuake from the truth fixture `pc-glquake-msvc42`, `msvc4.2 /O2 /Gd /W0`, budget 12;
the last column re-runs the four functions measured after `configure.py --flags "/O2 /G5 /ML /W0"`, which are the flags the game
was built with):

| function | size | default print | best | decompiles / compiles | with the game's flags |
|---|---|---|---|---|---|
| `FUN_0040efc0` | 58 | 98.462 | 98.462 | 13 / 1 | 98.462 |
| `FUN_004139d0` | 43 | 99.222 | 99.222 | 13 / 1 | 99.222 |
| `FUN_00425320` | 61 | 99.667 | 99.667 | 13 / 2 | - |
| `FUN_00427e00` | 159 | 98.966 | 98.966 | 13 / 2 | 98.966 |
| `FUN_0042f840` | 46 | 83.214 | 83.214 | 13 / 2 | **100.000, exact** (stopped at the default print) |
| `FUN_004393d0` | 49 | 99.643 | 99.643 | 13 / 2 | - |

None of the six was improved by the printing variants: 11 or 12 of the 13 variants print the same C as the default
(`= #0` in the table), and the one or none that differs did not score higher. The `FUN_0042f840` gap was the flags: the retail
`shr ecx,1` is `d1 e9` and Visual C++ 4.2 writes `c1 e9 01` for the same expression without `/G5`; with the game's flags the
default print is byte-exact (the default flags of a project are the era's usual ones, not the game's: say so with
`configure.py --flags`). The other three keep the same small differences (the data operand is a `DAT_` symbol on the
retail side and the string's symbol on the compiled side, and register choices).

**As a lane layer on x86.** `tests/m22-004_pc_c_output.py --search 12` runs the same plan on every compiled, non-exact function of a PC fixture
(the export of each variant, the fixture's own compiler and flags, the lane's scorer): GLQuake 50 / 191 / 72.535 -> 50 / 191 / 73.575, Quake 2
38 / 196 / 67.990 -> 39 / 196 / 68.954, ioq3 22 / 181 / 41.968 -> 22 / 181 / 42.460 (exact / compiled / mean %; 34, 28 and 17 functions improved of
the 141, 158 and 159 tried; about 6 seconds a function). On x86 the search adds 0.5 to 1.0 point of mean and at most one exact function
(`benchmarks/reports/pc_upgrade_20261015.md`): what is left there is mostly x87 shape and expression structure, which the knobs do not reach.

## Limits

* PlayStation 2, Nintendo 64, PlayStation, PSP, Game Boy Advance and Nintendo DS projects.
* The search varies printing, not types: a function whose types, prototypes or
  structures are wrong, or whose compile fails, stays as it is. Functions that do not
  compile are not searched.
* The flags are the project's (`-O2` unless `--cflags` or `config/project.json` says
  otherwise): a project with the wrong flags scores low for every variant.
* `ee-gcc` Linux builds need `/lib/ld-linux.so.2` (`docs/new-project.md`); their output
  can depend on the heap layout, which the m22-003 lanes pin with `setarch -R`. `ninja`
  does not.
* Decompiles are one worker launch each (about 0.3 to 1 s); a budget of 24 costs about
  10 s per function on a small one, less when most variants print the same C.
