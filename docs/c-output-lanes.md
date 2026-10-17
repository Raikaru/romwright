# C-output lanes: decompiled C against matched functions of several PS2 games (m22-003)

m22-002 scores C output on one game, Persona 4. Every C-output rule is therefore tuned and measured on one game.
`tests/m22-003_ps2_multigame_c.py` is the generic harness that gives the same measurement on the other PS2
decompilations, so a rule can be scored on games it was not tuned on (the leave-one-out harness of the declarative
compiler-rules layer reads its per-function output; see [Interface for the compiler-rules harness](#interface-for-the-compiler-rules-harness)).

One harness, one descriptor per game (`tests/m22-003/<lane>.json`), no per-repo adapter script. The lanes
(`--list`): `dds` (Digital Devil Saga, ee-gcc 2.96), `dc` (Dark Chronicle, MWCC 3.0), `ff` (Fatal Frame, ee-gcc 2.9-991111),
`rc` (Ratchet & Clank NTSC), `dk` (Dark Cloud, MWCC 2.3.3), `p4` and `p4-eegcc` (Persona 4, the validation lanes), and the two
SN ProDG lanes `gh` (God Hand) and `rcpal` (Ratchet & Clank PAL).

## What a lane measures

For each lane the harness

1. **prepares the repo.** Clones it at the pinned commit; installs the pinned compilers and tools from
   `crates/romwright-core/src/new_project/toolchains.json` through the generated project's own
   `tools/download_tool.py` (`new-project`'s code path: sha256 checked before extraction, one shared cache);
   runs the descriptor's `setup` steps, which are the repo's own configure/split steps with the repo's compiler paths
   pointed at the pinned binaries (a symlink or a copied directory; never a change to repo source).
2. **takes each unit's exact compile command from the repo's own build** and compiles every unit with it:
   `ninja -t compdb` for ninja/cmake repos (Dark Chronicle, Dark Cloud, Digital Devil Saga, Fatal Frame, Ratchet & Clank NTSC);
   `make -n -B` for a make repo (R&C PAL's `Makefile.sn`: the recipe the Makefile expands, run as one script); and for builds that
   are python scripts with no dry-run (Persona 4, God Hand) the commands recorded while the repo's own entry point runs
   (`tests/m22-003/tools/trace/sitecustomize.py`, a `subprocess.Popen` logger; each recorded command is then replayed in a
   scratch overlay of the repo with the pinned compiler). Persona 4's entry point is `tools/verify.py --skip-gcc-units`, run only
   to record the compile commands: the verdict on each function is the harness's own comparison, not verify.py's.
3. **finds the matched functions.** A function is *matched* when it is compiled from C by that build (not an
   `INCLUDE_ASM` body) and its bytes equal the retail image at its address modulo relocation fields: the comparator of
   m22-002, written for this harness in `tests/m22-003/elfobj.py` (every byte equal outside the bits the object's `.text`
   relocations own, same length as the retail function). Addresses come from the game's symbol sources (the corpus truth
   table, the repo's `symbol_addrs.txt`, the retail ELF's own symbol table); functions with no usable name are located by
   content, with ties broken by the unit's own layout. The count is cross-checked against the repo's own progress
   or link where one exists.
4. **samples.** A fixed seeded sample (seed 20261012; Persona 4 keeps m22-002's 20261010 so the two can be compared) of
   200 matched functions of 32..1024 bytes whose definition is found in the preprocessed unit and has no inline assembly
   (C++ lanes: all matched functions of that size). Each function gets one shared context, m22-002's context rule.
5. **scores candidates**, per layer, with that unit's own compile command (the candidate replaces the unit's source in a
   scratch overlay of the repo; the compiler, flags, include roots and post-processing steps are the repo's): `romwright`
   (`assert-names`, `assert-prototypes`, `export-c --context`, one project per lane restored from a pristine snapshot for
   every run), `m2c` (`m2c -t mipsee-gcc-c|mipsee-mwcc-c --context`, on splat assembly of the retail bytes), and the pipeline
   check `oracle` (the unit's own text for the function against the unerased context; it must score high, and the
   misses say what the harness itself loses). Stock Ghidra is `--layers stock`, optional (not run in these reports).
   Scores are m22-002's: `exact`, `compiled` (the object defines the target symbol), objdiff-cli 3.6.1
   `match_percent` (`functionRelocDiffs=none`), a candidate not produced or not compiled scores 0; each candidate is
   compiled twice, `context` (headline) and `standalone`, and `best` is the better of the two.

## Running a lane

```
python3 tests/m22-003_ps2_multigame_c.py --list
python3 tests/m22-003_ps2_multigame_c.py dds --stage prepare          # repo, tools, setup, units, matched set
python3 tests/m22-003_ps2_multigame_c.py dds --layers romwright,m2c,oracle
```

State lives under `--work` (default `~/.cache/romwright/m22-003/work/<lane>`: clone unless `--repo`, per-lane venv, built
objects, `matched.json`, `sample.json`, romwright project and its snapshot, per-function files). Tools are installed
in `--tools-cache` (default `~/.cache/romwright/m22-003/tools`; the runs below used
`nih-vps-u:~/runs/Ps2Lanes/cache/tools`). Lanes whose compiler is an i386 ELF (ee-gcc) re-execute themselves under
`setarch -R` (ee-gcc's output can depend on its heap layout) and, where the host has no `/lib/ld-linux.so.2`, a
bubblewrap mount namespace that supplies `--glibc32` (default `~/opt/glibc32/usr/lib`) at that path; nothing on the host is
written. Run it on a machine with the RAM for a decompiler import (the lanes were run on `nih-vps-u`).

Default reports are `benchmarks/reports/m22-003_<lane>.{json,md}`; `--report` and `--tag` redirect them. Always run
with `ROMWRIGHT_NO_IMPORT_CACHE=1 ROMWRIGHT_NO_FACT_PACK=1` (the harness sets both for the romwright CLI).

### Interface for the compiler-rules harness

One lane under an environment, one layer, per-function JSON:

```
python3 tests/m22-003_ps2_multigame_c.py dds --layers romwright --tag rule-off \
    --env ROMWRIGHT_COMPILER_RULES_DISABLE=<id> --functions-out out.json --report report.json \
    [--work DIR] [--repo CLONE] [--cli ... --worker ... --ghidra-opt ...] [--fresh-import]
```

`--env KEY=VALUE` (repeatable) goes to the romwright CLI processes only (import, assert-names, assert-prototypes, export-c).
Every run starts from the freshly imported project (`<work>/<lane>/project.base`), so runs under different environments are
comparable; use `--fresh-import` when the environment changes import behaviour. The matched set, the sample and the m2c inputs
are cached, so a romwright-only run is minutes. `--functions-out` writes schema `m22-003-functions/1`:

```
{"schema": "m22-003-functions/1", "lane", "game", "tag", "env", "layers", "seed", "n", "matched_count",
 "functions": {"<address, 8 hex digits>": {"name", "address", "size", "file", "compiler",
    "layers": {"romwright": {"context"|"standalone"|"best": {"produced", "compiled", "exact", "percent"}}, "m2c": {...}}}}}
```

The address key joins two runs of one lane; better/worse/same is a comparison of `percent` (headline variant `context`).
Use a separate `--work` per concurrent run (they can share `--repo`, which they only read).

## Descriptor format (`tests/m22-003/<lane>.json`)

| key | meaning |
|---|---|
| `repo`, `retail` | URL and commit; retail ELF path and sha1 (checked) |
| `tools` | ids in `toolchains.json` to install; `env` (placeholders `{repo} {work} {tools} {retail} {python} {glibc32} {jobs} {tool:ID} {lane_tools}`) |
| `compiler`, `unit_compilers` | compiler id of the lane, and rules (`match` on the unit path or `command` on its compile command) that name another |
| `venv` | per-lane virtualenv for the repo's python requirements (repos pin different splat releases) |
| `setup` | shell steps run in the repo once per (commit, steps, tool pins) |
| `build` | `kind: ninja` (`dir`, `compdb_rules`, `output_regex`, `command_regex`, `drop_segments` for dependency/report steps that are not compiles) or `kind: trace` (`trace_run`, `command_regex`); `family` gcc or mwcc; `preprocess` mode (`host-cpp`, `driver-E`, `flags`, `mwccgap-E`) |
| `symbols` | name-to-address sources: corpus truth TSV, splat `symbol_addrs.txt`, the retail ELF's symbol table |
| `include_asm_regex`, `gp`, `seed`, `family_depth` | functions that are assembly includes; gp for m2c; sample seed; directory depth for the by-directory table |
| `shared_context`, `candidate_source` | C++ lanes: one context file for every function, and the extension a candidate is written under |
| `cross_check`, `limits` | the repo's own count (committed report, or its own link compared with retail), and the lane's stated deviations |

## Lanes and results

See the per-lane reports `benchmarks/reports/m22-003_<lane>.md` for the full tables (by directory, size, compile errors).
Headline variant (`context`), 200-function samples of the matched set (seed 20261012; Persona 4 seed 20261010 and 20261011 as m22-002). Cells are exact / compiled / mean objdiff percent; the paired column counts functions on which
romwright's percent is higher / lower / equal to m2c's. `oracle` is the pipeline check (the unit's own text for the function against
the full context): it measures what the compile-and-score path itself loses, not a tool.

| lane | game | compilers | matched | sample | romwright exact / compiled / mean % | m2c exact / compiled / mean % | romwright vs m2c better / worse / same | oracle (pipeline check) |
|---|---|---|---|---|---|---|---|---|
| dds | digital-devil-saga | ee-gcc2.96 | 9022 of 9036 C functions | 200 | 61 / 193 / 75.6 | 49 / 152 / 62.2 | 83 / 59 / 58 | 186 / 199 / 98.0 |
| dc | dark-chronicle | mwcps2-3.0-011126 | 6627 of 6747 C functions | 200 | 32 / 159 / 60.5 | 33 / 108 / 45.2 | 90 / 56 / 54 | - |
| ff | fatal-frame | ee-gcc2.9-991111-01 | 3436 of 3437 C functions | 200 | 20 / 134 / 46.3 | 4 / 19 / 7.6 | 124 / 9 / 67 | 193 / 200 / 98.8 |
| rc | ratchet-clank | ee-gcc2.9-991111-01 | 346 of 367 C functions | 200 | 24 / 191 / 65.2 | 11 / 112 / 40.7 | 131 / 44 / 25 | 197 / 199 / 98.7 |
| dk | dark-cloud | mwcps2-2.3.3-000906 | 3091 of 3446 C functions | 200 | 26 / 164 / 65.3 | 33 / 98 / 43.7 | 98 / 48 / 54 | - |
| p4 (seed 20261010) | persona-4 | mwcps2-3.0.1b119-040914, mwcps2-3.0.1b210-060308 | 8483 of 9053 C functions | 200 | 59 / 189 / 77.7 | 41 / 129 / 54.3 | 117 / 36 / 47 | - |
| p4 (seed 20261011) | persona-4 | mwcps2-3.0.1b119-040914, mwcps2-3.0.1b210-060308 | 8483 of 9053 C functions | 200 | 63 / 192 / 80.4 | 46 / 120 / 52.1 | 121 / 32 / 47 | - |
| p4-eegcc (seed 20261010) | persona-4 | ee-gcc2.96 | 1290 of 2510 C functions | 200 | 96 / 197 / 84.0 | 85 / 164 / 72.7 | 65 / 40 / 95 | - |
| gh (SN ProDG) | god-hand | ee-gcc2.9-991111-01, ee-gcc2.95.3-136, ee-gcc2.96 | 7367 of 7367 C functions | 200 | 78 / 183 / 75.1 | 47 / 134 / 56.5 | 106 / 39 / 55 | 200 / 200 / 100.0 |
| rcpal (SN ProDG) | ratchet-clank-pal | ee-gcc2.9-991111, ee-gcc2.95.3-114 | 1372 of 1374 C functions | 200 | 15 / 104 / 36.5 | 23 / 76 / 30.4 | 41 / 46 / 113 | 148 / 155 / 76.5 |

### Matched counts, this harness against the repo's own

| lane | harness: matched of C functions compiled | the repo's own number | corpus truth `verified` rows (derived from the repo's own config; includes functions assembled from asm units) |
|---|---|---|---|
| dds | 9022 of 9036 C functions (14 differ, 0 no unique address, 0 found nowhere) | the repo's own gate is whole-image equality, so its own count is every C function it compiles: 9036; its link with the pinned compiler is not byte-identical to retail (first code difference at 0x100198) | 9864 of 10352 |
| dc | 6627 of 6747 C functions (79 differ, 25 no unique address, 16 found nowhere) | the repo's own gate is whole-image equality, so its own count is every C function it compiles: 6747; its link with the pinned compiler is not byte-identical to retail (first code difference at 0x100010) | 7714 of 7837 |
| ff | 3436 of 3437 C functions (1 differ, 0 no unique address, 0 found nowhere) | the repo's committed report (`config/us/report.json`, `matched_functions`): 3437 | 3437 of 4250 |
| rc | 346 of 367 C functions (0 differ, 11 no unique address, 10 found nowhere) | the repo's functions in C subsegments: 1643 (corpus truth); this harness compiled 367 of 1473 units with the pinned SDK compiler (see the lane notes) | 1643 of 1823 |
| dk | 3091 of 3446 C functions (319 differ, 9 no unique address, 27 found nowhere) | the repo links 100% of the image (4181 functions incl. library assembly and overlays, corpus truth); this harness: 3446 C functions in the 136 game units | 4181 of 4181 |
| gh | 7367 of 7367 C functions (0 differ, 0 no unique address, 0 found nowhere) | the repo's carved functions with a C unit that compiles byte-identical: 7946 (corpus truth); this harness compiled 2639 of 2722 units (83 fail here, e.g. `ee-as` "problematic short loop for Emotion Engine" in the repo's own wrapper) and matched every function of those | 7946 of 11233 |
| rcpal | 1372 of 1374 C functions (1 differ, 0 no unique address, 1 found nowhere) | the repo's functions in C subsegments: 1605 (corpus truth, includes INCLUDE_ASM stubs); this harness: 1374 C functions + 239 assembly includes = 1613 in 108 of 111 units (3 fail here, e.g. `stdarg.h` is not found: the repo takes it from the SDK mirror, not from the pinned package) | 1605 of 1822 |
| p4 | 8483 of 9053 C functions (41 differ, 69 no unique address, 460 found nowhere) | m22-002's run of the repo's `tools/verify.py` on the same commit: 8474 MATCH rows (MWCC units); this harness's set contains 200/200 and 198/200 of m22-002's two samples | 9857 of 13102 |
| p4-eegcc | 1290 of 2510 C functions (187 differ, 198 no unique address, 835 found nowhere) | m22-002's run of `tools/verify.py` on the ee-gcc units: 1176 MATCH rows; this harness's set contains 195/200 of m22-002's sample | 9857 of 13102 |

### Persona 4 through the generic path against m22-002 (the harness's validation)

| m22-002 sample | functions in both | layer | m22-002 exact / compiled / mean % | m22-003 exact / compiled / mean % | same exact | same compiled | percent within 1 point |
|---|---|---|---|---|---|---|---|
| MWCC, m22-002 seed 20261010 sample | 200 | romwright | 55 / 192 / 76.624 | 54 / 193 / 77.602 | 199 | 199 | 182 |
| MWCC, m22-002 seed 20261010 sample | 200 | m2c | 32 / 101 / 40.41 | 28 / 114 / 44.854 | 196 | 179 | 162 |
| MWCC, m22-002 seed 20261011 sample | 196 | romwright | 56 / 190 / 78.486 | 58 / 190 / 80.424 | 194 | 196 | 177 |
| MWCC, m22-002 seed 20261011 sample | 196 | m2c | 49 / 120 / 50.91 | 46 / 129 / 53.962 | 189 | 181 | 159 |
| ee-gcc 2.96, m22-002 sample | 194 | romwright | 103 / 191 / 86.292 | 104 / 191 / 86.275 | 193 | 194 | 192 |
| ee-gcc 2.96, m22-002 sample | 194 | m2c | 99 / 161 / 75.324 | 92 / 160 / 74.578 | 187 | 193 | 183 |

Reading it: on the *same* 200 functions m22-002 scored, the generic path gives romwright the same exact verdict on 199 of 200
(MWCC seed 20261010), 194 of 196 (seed 20261011) and 193 of 194 (ee-gcc) functions, and m2c on 196, 189 and 187. Its matched set
contains 200/200, 198/200 (196 scored) and 195/200 of m22-002's sample functions; the rest are functions whose retail address is
shared by identical bodies and could not be assigned to one unit (the harness resolves such ties by the unit's layout and gives up
when that is not unique). It has 8483 matched MWCC functions against verify.py's 8474 MATCH rows, and 1290 ee-gcc against 1176
[INFERENCE: the extra rows are functions verify.py's stricter MATCH rule rejects (it also checks relocation symbols and zero padding);
not traced]. The remaining differences in the 200-function means (romwright 76.6 -> 77.6, m2c 40.4 -> 44.9 on MWCC) follow the three places
where the paths differ: the pinned decompals binutils instead of the distribution's, m2c reading splat assembly of the retail bytes
for the sampled functions (m22-002 reads the repo's own splat asm) and Persona 4's compile commands coming from the traced
verifier [INFERENCE: not isolated one by one]. Not reproduced: m22-002's `exact_symbols` column and its stock layer.

### SN ProDG: is a usable SN ee compiler obtainable? Yes, and it is already pinned

The brief expected SN ProDG to be the one family `toolchains.json` lacks. It is not:

- `ee-gcc2.95.3-114` and `ee-gcc2.95.3-136` (decomp.me packages, run under wibo) are the SN Systems ProDG GCC 2.95.3 builds.
  Their `cc1.exe` is byte-identical (git blob sha1) to the ones in AngheloAlf's mirrors that the SN repos themselves build with:
  `…/2.95.3/cc1.exe` `6c232dd6…` = `sce_ps2_sdk_24` (ProDG v1.14, `toolchain/sn-prodg-24` of R&C PAL's `Makefile.sn`) and
  `e5cedd51…` = `SN-Systems-ProDG_for_PS2_3.01` (v1.36, God Hand's `sn-2.95.3-136`); the driver `ee-gcc.exe` is their `ee-gcc2953.exe`
  (`317ab60e…`), and the package ships the SN assembler (`ps2eeas.exe`, `8830225b…` = the SDK 2.4 one). `ee-gcc2.95.2-273a` is the
  SN v2.73a archive (`eegcc_sn_v2.73a`) the Lombyte setup downloaded for its retired SN route. The same packages produce objects here
  under wibo 1.2.0, and `ps2eeas.exe` assembles under wibo too.
- Two SN lanes were run on them: **R&C PAL** (OpenRAC/rac1-decomp: `Makefile.sn`'s own recipes, python rewriting steps and the SN
  assembler) and **God Hand** (`compile.py` and the repo's `ee-cc-wrap.py`/`sn-cc-wrap.py`, Cygnus 2.96 by default and SN 2.95.3-136
  for the `sq`-prologue group). Neither needs a compiler outside `toolchains.json`.
- What is *not* obtainable from `toolchains.json` is Ratchet & Clank NTSC's reconstructed game compiler (see below) and Ps2EeAs
  1.9.25.758 (the 3.01 assembler the retail PAL text was built with; the repo patches it). Neither blocks the SN lanes.

### What each lane could not do (named prerequisites)

Every lane's deviations are also in its report's `Limits` and in the descriptor's `limits`. The ones that decide how far a lane
can be trusted:

- **dds** (ee-gcc 2.96). The compiler is the pinned decomp.me build, unpatched, under `setarch -R` with the 32-bit glibc of `--glibc32`
  (the one m22-002 uses; the repo pins Fedora's glibc 2.43 i686). The repo's `download_tools.py` patches the compiler's GC arena and the EE assembler; those two patches are not
  applied, so 14 of the repo's 9036 C functions do not reproduce (its own gate is whole-image equality, which therefore fails here).
  Not run: the repo's patched toolchain.
- **ff** (ee-gcc 2.9-991111-01). The pinned package replaces the compiler directory the repo ships. 3436 of the repo's 3437
  functions match; `PhotoScoreCount` (a unit built in two steps through the repo's asm patch) does not.
- **dc** (Dark Chronicle, MWCC 3.0-011126, C++). *Missing prerequisite: Satan's Fiddle.* The repo compiles every unit through
  Satan's Fiddle (an LLDB-driven controller of MWCC's internal state with per-unit overrides). Tried: the LLDB development RPMs are
  fetchable without root (`dnf download lldb-devel`) but the pinned Fiddle revision builds against LLVM 19 and the host has 22,
  and Fiddle also needs an unstripped i386 `wibo` built from source (no 32-bit libc development files, no root). The lane runs the
  unmodified pinned compiler through `tests/m22-003/tools/satansfiddle-plain` (a few lines, same command line); 6627 of the 6747
  C functions match plain, the other 79 and 41 more without a resolvable address are what Fiddle's overrides recover or what is
  ambiguous. All 149 game units are C++: candidates are C written as `.c` files at the unit's place, with the retail mangled symbol
  as the function name (romwright prints a demangled name; the harness renames the one function it defines), against the repo's own
  C-compatible m2c context `ctx.c`, from which declarations the unit's compiler rejects are dropped (listed in the report). No per-function
  pragma state and no `oracle` layer.
- **dk** (Dark Cloud, MWCC 2.3.3, C++). Same C++ treatment as dc. The repo's `statefix-wibo.sh` shim (per-unit compiler-state
  fixes) is switched off with the repo's own `STATEFIX=0`, so 3091 of 3446 C functions match (319 differ). Functions of the TITLE and DUN
  overlay modules live outside the main ELF's load segments and are counted among the differing ones.
- **rc** (Ratchet & Clank NTSC). *Missing prerequisites: the reconstructed game compiler and Ps2EeAs 1.9.25.758.* Lombyte builds its
  game code with a Sony/Cygnus 2.9-ee-991111b rebuilt from a GPL archive plus a patch stack (`scripts/build-game-compiler.py`: needs
  `gcc -m32`, which the host cannot do) and assembles it with the SN assembler under wine. Neither is in `toolchains.json`. Tried:
  the pinned `ee-gcc2.9-991111-01` (the repo's own SDK compiler) as a stand-in game compiler and the pinned SN assembler under wibo as
  `Ps2EeAs`: the repo's `link` build did not complete (a wibo run of the SN driver hung on one unit, and most game units produced no
  object). The lane therefore compiles every unit with the pinned SDK compiler
  (the commands of the repo's source-only objdiff base build); 346 of 367 compiled functions match, essentially the SDK block, against
  the repo's much larger matched count. Retail-copy "oracle" objects are excluded.
- **rcpal** and **gh** (SN ProDG): see the verdict above. rcpal: 1372 of 1374 C functions match through `Makefile.sn`'s own recipes
  (`make -n -B`), under wibo instead of wine. gh: all 7367 functions of the 2639 compiled units match; the units include 135 C++ (`.cc`) sources, whose
  functions are dropped at sampling when no definition of that name is found in the preprocessed unit.
- **p4**, **p4-eegcc**: the validation lanes; see the section above. The repo's `tools/verify.py` is run once only to record the compile
  commands (python-trace); its verdicts are not used.
- Not run anywhere: the `stock` Ghidra layer (optional; the code path is m22-002's and is untested in the generic harness).

### Reproduce

```
python3 tests/m22-003_ps2_multigame_c.py --selftest
python3 tests/m22-003_ps2_multigame_c.py LANE --layers romwright,m2c[,oracle]       # LANE in --list
python3 tests/m22-003/compare_m22_002.py benchmarks/reports/m22-ps2_p4.json benchmarks/reports/m22-003_p4_on_m22-002_sample.json
```

Provisioning is the repo's own steps plus the descriptor's `setup`; the first run of a lane clones the repo, installs tools
(network needed) and builds every unit. Needs `m2c` on PATH (the pip m2c m22-002 uses), `bwrap` and a 32-bit glibc for ee-gcc
lanes, `wibo` (installed from the manifest) for MWCC and SN lanes, `cmake`/`ninja`/`make`, and a romwright release build.

Tools cache of the recorded runs: `nih-vps-u:~/runs/Ps2Lanes/cache/tools` (every pinned package with its `.verified` stamp; blobs
in `.cache/` by sha256).


## Failure classes and harness-owned artifacts (2026-10-13)

`tests/m22-003/classes.py` classifies a failed compile by the compiler's first diagnostic (gcc `file:LINE:` and MWCC `# N: code / Error: ^ / message`
blocks; the offending line and its neighbours are kept) and a compiled-but-not-exact function by its bytes (R5900 field decode: one instruction,
register allocation, stack layout, scheduling, a few instructions, or a length difference grouped by the opcode mix). The harness stores
`diagnostics`, `diff` and the candidate's `body`/`mask` per variant, so `--redo-report` recomputes the byte classes offline.
`tests/m22-003/failure_classes.py` reads one report per lane and writes `benchmarks/reports/m22-003_failure_classes.{json,md}`: failure classes per
lane with two examples each, the functions m2c gets exact and romwright does not (with their cause), and a ranking of the classes by the exact
matches a fix would plausibly recover, each with its owning layer (printer, export context, types/prototypes, lane harness).
`python3 tests/m22-003/failure_classes.py --suffix fix2 --lane-suffix ff=fix5,dc=fix3,dk=fix3 --baseline ""` reproduces the checked-in report.

Harness artifacts found and fixed (new reports `m22-003_<lane>_fix2/fix3/fix5`; the first-round reports are unchanged):

- **Contexts the unit's compiler rejects**: the harness compiled romwright (and m2c) against `void * __asm__(" ");`-style declarations; a per-unit
  context repair drops the rejected declarations and retries (descriptor `context_repair: false` disables it; stats in the report's `context_repair`).
- **SN ee-gcc 2.95.3 `long long` is 128 bits** ("unsupported wide integer operation"): descriptor `candidate_type_aliases` maps it to `long` (64-bit) for
  SN units. gh romwright failures 17 -> 1, rcpal 96 -> 9 together with the context repair.
- **Unasserted target declaration**: K&R `T f();` and unspellable parameters left romwright without a signature, yet it was compiled against the
  declaration (ff: 20 "conflicting types"). The declaration is now dropped from romwright's compile context when no signature was asserted.
- **Array-typedef parameters** (`typedef float sceVu0FVECTOR[4]`, with or without `__attribute__`): m22-002's typedef table skips them, so callees with such
  parameters were never asserted and romwright guessed them (ff 33 functions, dc 13, dk 16).
- **Rename skipped / MWCC `__2` suffix / wrapper arguments**: the C++ definition-head regex matched across a comment naming the function (dc EndPrim);
  MWCC renames a function its unit already knows to `f__2` (dc, scored as the unique `<name>__<n>` symbol); the GH SN wrapper aborts on `--extern-jtbl`
  (descriptor `candidate_drop_args`).
- Not fixable in the harness: dc `ChangeSetUnit` (the repo's `postprocess_object.py` rejects any candidate lacking the unit's own static).

Effect, romwright exact / compiled / mean % (first round -> final): dds 61/193/75.6 -> 61/196/76.8; ff 20/134/46.3 -> 20/145/49.2; rc 24/191/65.2 -> 26/199/68.1;
dc 32/159/60.5 -> 35/166/62.6; dk 26/164/65.3 -> 27/169/67.4; gh 78/183/75.1 -> 78/199/82.0; rcpal 15/104/36.5 -> 28/191/63.7; p4 59/189/77.7 -> 60/193/79.1;
p4-eegcc 96/197/84.0 -> 96/199/84.8. The m2c layer moved too where contexts were repaired (rcpal 23/76 -> 34/117).

## Upgrade round 1: the compile-failure classes the Rust layers own (2026-10-14)

Cut from the m22-003 failure classes (the 119 non-compiling functions of the seven stage-2 samples) before stage 3 is ported. Every fix is a Rust-side
rule with its own switch (`=off` disables it); nothing in C++ changed (`ghidra_opt` sha256 `ffdd5e57...`). Report:
`benchmarks/reports/upgrade1_gates_20261014.{json,md}` (written by `benchmarks/upgrade1_report.py`; every arm a fresh import and a restored, never shared, work
directory; m22-002 and m22-003 harnesses as in section "Running a lane", the arm is a wrapper binary that sets the switches, `ROMWRIGHT_NO_IMPORT_CACHE=1`,
`ROMWRIGHT_NO_FACT_PACK=1`). The scout's map of the classes was read-only inference; checked against real failing functions, three things in it were wrong
and are corrected below.

| key | switch | what it does | where |
|---|---|---|---|
| `sub` | `ROMWRIGHT_EXPORT_SUBPIECE_ARITY` | The printer writes a `SUBPIECE` as `SUB84(x, 4)` (the byte offset is a second argument); the macro the export defined took one (`romwright_subpiece_8_4_4(value)`), which a preprocessor rejects. It takes `(value, offset)`. | `emit_m2c/dependencies.rs` |
| `odd` | `ROMWRIGHT_EXPORT_ODD_WIDTHS` | `undefined3/5/6/7` is not a C type: a global, a storage-view member (`whole`) or a local declared with one is `unsigned char NAME[N]`. | `emit_m2c/globals.rs` `declarator`, `emit_m2c/locals.rs` |
| `loc` | `ROMWRIGHT_EXPORT_LOCAL_VIEWS` | A byte-array local the printer assigns whole (`temp_v3 = (unsigned char *)0x3f33...;`) or reads in pieces (`temp_v8._0_4_`) is accessed through its address cast to the scalar of the access's width (`(*(unsigned long long *)temp_v3)`, `(*(unsigned int *)((unsigned char *)&temp_v8 + 4))`), of the evidence's type where the decompiler has one. | `emit_m2c/locals.rs` |
| `mis` | `ROMWRIGHT_EXPORT_MISMATCH_NAMES` | `PrintC::pushMismatchSymbol` prints `_NAME` for a varnode at a symbol's address whose width is not the symbol's, and `stack0x...` inside one: names nothing declares (`_uStack_c0`, `_abStack_170`, `_DAT_00252bf0.whole`). They are the symbol's own name, or its address plus offset, cast to the access's width. | `emit_m2c/locals.rs`, `emit_m2c/globals.rs`, `storage.rs` |
| `dec` | `ROMWRIGHT_EXPORT_DECLARED_VIEWS` | A global the project's header declares used to keep the printer's union view (`key_now.u4[0]`, `eff_focus.whole`) in the body, which the header's declaration has no members of. Its accesses go through the object's address (`(*(unsigned int *)((unsigned char *)&key_now + 0))`, and the whole object as `(*(T (*)[N])&NAME)`). | `emit_m2c/storage.rs`, `globals.rs` |
| `ctx` | `ROMWRIGHT_EXPORT_CONTEXT_NAMES` | `declared_names` did not read `void (*BCommJmpTbl[])(ENE_WRK *)` (a parenthesized declarator has no `declarator` field), so the export redeclared the table as `unsigned char BCommJmpTbl[84]` and conflicted with the header. | `emit_m2c.rs` |
| `acc` | `ROMWRIGHT_EXPORT_DECLARED_ACCESS` | A header object of another shape than the one the printer declared (an array of structures where the body indexes bytes: `ene_wrk[temp_v5 * 0x430 + 0x358] = 0x50`, a struct where it casts the array: `(float *)camera`) is accessed through its address cast to the printed element type. An element of the same width (`int` for `unsigned int`) is left alone. | `emit_m2c/conform.rs` `reread_declared` |
| `flt` | `ROMWRIGHT_EXPORT_FLOAT_ARGS` | An integer literal handed to a `float` parameter is a register's bits: `0x42ce0000` is `103.0f`, not the number 1120403456. Normal patterns only (a small integer, an infinity or a NaN stays). | `emit_m2c/conform.rs` |
| `ptr` | `ROMWRIGHT_STRUCT_POINTEE_RUNS` | A struct field that points at a run of accesses of one scalar width and kind (a vector or table, not a struct) is `T *`. | `struct_types.rs` `synthesize`; see `docs/structs.md` section 5 |

Corrections to the scout's map, from the failing functions themselves: (a) the 20 syntax errors were 13 `undefinedN` declarations and **7 `SUBPIECE` macro calls**
(`LoadGyorace__Fv(_1542.u8[0],4)` is the harness's definition-head regex renaming the macro after the function; the call had two arguments for a one-parameter
macro either way); (c1) the 27 "array cast" failures were not a stage-4 typing problem: the local is Ghidra's declaration of an 8-byte stack slot a `sdl`/`sdr`
pair writes (`unsigned char temp_v3[8]`), and the access is exactly the scalar of the slot's width; (d) the join from `Solution.pointees` to the field already
existed (`struct_types::synthesize`), it was never missing. The mismatch-name rule has no scout entry: `_iStack_70`, `_abStack_170` and `_DAT_00252bf0` are
`pushMismatchSymbol`'s underscore, not an undeclared local. The harness fix made on the way: `rename_definition` (m22-003) searched for the definition head
across preprocessor lines, so a function-like macro could be taken for the function and renamed (dc `LoadGyorace`); preprocessor lines are blanked first.
No fix is keyed through the compiler-rules layer: each rewrite prints the same bytes at the same address in a spelling every C compiler accepts, and the per-lane
results below do not split by compiler family (MWCC C++ lanes dc, dk and p4 gain as the gcc lanes ff and gh do).

### Upgrade round 1: results

exact / compiled / mean %, every fix off against every fix on, one release build, `ghidra_opt` unchanged, a fresh import and a restored work directory per arm
(paired = functions better / worse / same by match percent):

| gate | off | default | paired | exact gained / lost | compiled gained / lost |
|---|---|---|---|---|---|
| m22-002 MWCC 20261010 | 55 / 193 / 76.968 | 55 / 193 / 76.968 | 0 / 0 / 200 | 0 / 0 | 0 / 0 |
| m22-002 MWCC 20261011 | 57 / 194 / 78.316 | 57 / 194 / 78.316 | 0 / 0 / 200 | 0 / 0 | 0 / 0 |
| m22-002 ee-gcc | 106 / 197 / 86.403 | 106 / 197 / 86.403 | 0 / 0 / 200 | 0 / 0 | 0 / 0 |
| m22-003 dds | 61 / 196 / 76.818 | 61 / 200 / 77.224 | 2 / 0 / 198 | 0 / 0 | 4 / 0 |
| m22-003 rc | 26 / 199 / 68.113 | 26 / 200 / 68.158 | 1 / 0 / 199 | 0 / 0 | 1 / 0 |
| m22-003 p4 | 60 / 193 / 79.400 | 60 / 193 / 79.400 | 0 / 0 / 200 | 0 / 0 | 0 / 0 |
| m22-003 gh (harness clone) | 78 / 199 / 82.119 | 78 / 199 / 82.119 | 0 / 0 / 200 | 0 / 0 | 0 / 0 |
| m22-003 gh (pristine repo copy) | 78 / 196 / 79.062 | 78 / 198 / 79.157 | 1 / 0 / 199 | 0 / 0 | 2 / 0 |
| m22-003 ff | 20 / 145 / 49.350 | 21 / 195 / 61.753 | 58 / 1 / 141 | 1 / 0 | 50 / 0 |
| m22-003 dc | 38 / 176 / 66.605 | 38 / 186 / 69.844 | 10 / 0 / 190 | 0 / 0 | 10 / 0 |
| m22-003 dk | 29 / 176 / 70.804 | 29 / 189 / 75.561 | 14 / 0 / 186 | 0 / 0 | 13 / 0 |

gh on the harness clone is unchanged by the round: its 200-function sample has none of the classes (the one failure is `no candidate`, the exporter produced nothing).

m21-001 passes in both arms with identical rows (recall, precision, `size_exact`); the printer differential is 1,800 of 1,800 functions identical (the Rust printer
and its IR are untouched by the round); decompile success on the PS2 wave images, fresh imports, 7,500 sampled functions of 8 games, is 7,447 in both arms with the
same 53 failures (49 of them Dark Cloud's overlay-module entries, `Flow exceeded maximum allocation` in the C++ decompiler, the same in both arms). The wave's
cached projects, and the `-symtab` variants that made its 10,342, no longer exist, so the 7,500 are the ones a fresh import can reproduce.
The one function that is worse by percent without losing a compile is ff `LoadStoryWrk` (24.1 to 23.4, from `acc`).

Compile-failure classes, off -> default, by the compiler's first diagnostic (`tests/m22-003/failure_classes.py`, gh on the harness clone: 116 failing functions -> 38; `benchmarks/reports/upgrade1_failure_classes_{off,def}_20261014.{json,md}`; the sub-classes (a), (b), (c1) by the failing line are in the gates report):

| class | off (all lanes) | default | by lane (off -> default) |
|---|---|---|---|
| (a) syntax error | 20 | 0 | dc 11 -> 0, dk 8 -> 0, ff 1 -> 0 |
| member access on a type the context lacks (b) | 34 | 2 | ff 25 -> 0, dk 6 -> 2, dc 2 -> 0, dds 1 -> 0 |
| (c1) byte-array local value (`cast specifies array type`, `incompatible types in assignment` on `tmp = (unsigned char *)0x...`) | 6 | 0 | ff 4, dds 1, rc 1 -> 0 |
| undeclared identifier (`_NAME`, `stack0x...`, `undefined7`) | 8 | 4 | ff 3 -> 0, dds 2 -> 0, dk 2 -> 2 (`int7`), p4 1 -> 1 (`stack0x00000000`), dc 0 -> 1 (`undefined5` in a cast) |
| conflicting types (`BCommJmpTbl`) | 1 | 0 | ff |
| incomplete type (dk `LoadScript`, `EdScriptBuffer.u4[0]`) | 1 | 0 | dk |
| call does not match prototype | 5 | 3 | ff 2 -> 0, dc 2, p4 1 |
| other (ff `StageTitleLoad`) | 1 | 0 | ff |
| type mismatch (assignment, operand, return, cast) | 43 | 26 | ff 22 -> 5, dc 8 -> 10, dk 6 -> 6, p4 5 -> 5, dds 1 -> 0, rc 1 -> 0 |

The dc rise in type mismatch is two functions that used to stop at a syntax error and now fail on their first real type problem (a `float **` passed for a
`sceVu0FMATRIX` parameter, a `void` function that returns a value: stage 3/4 work). The 2 remaining (b) functions of dk are `__sinit_*.cpp` heads the class regex
reads as member access (`illegal use of 'void'`), not union members.

Each fix alone, and each fix left out of the default, on the functions whose outcome differs between off and default (the others cannot change; every
m22-002 lane-1 arm is the whole sample and is unchanged: 55 / 193 / 76.968 for all nine fixes alone): no fix loses an exact match or a compile alone or left out
of the default, and `sub`, `odd`, `loc`, `mis`, `dec`, `ctx` and `acc` each carry compiles when left out:

| fix | alone gains, compiled (lane: functions) | left out of the default loses, compiled (lane: functions) |
|---|---|---|
| `sub` | dc 2, dk 1 | dc 4, dk 3 |
| `odd` | dc 4, dk 2 | dc 5, dk 5, ff 1 |
| `loc` | dds 2, rc 1, ff 2 | dds 4, rc 1, ff 7 |
| `mis` | gh 1 | dds 2, gh 1, ff 4 |
| `dec` | ff 23, dc 1, dk 4 | ff 31, dc 2, dk 7 |
| `ctx` | ff 1 | ff 1 |
| `acc` | ff 14 compiled and 1 exact, dk 1 | ff 18 compiled and the exact, dk 1 |
| `flt`, `ptr` | none | none (2 ff functions lose a fraction of a percent each; mean 51.608 -> 51.607) |

`odd`, `mis` and `ctx` gain nothing alone on ff and `loc` little: the union view (`dec`) must be gone before the odd-width member, the mismatch name or the
redeclaration is the next error. That is why the leave-one-out arm is reported next to the alone arm. `flt` and `ptr` changed no outcome on any gate; they stay on
because they lose nothing and are correct by construction, and the report says so rather than counting them as wins.

Limits and what is left (named, not hidden):

- **Not in this round's reach** (what the default still fails to compile: ff 5, dc 14, dk 11, p4 7, gh 2, dds and rc none). ff: `sceVu0ViewClipMatrix` (a float
  stored through an `unsigned int *` parameter), `GetSmokePartAddr` (`_vrnext` VU intrinsic assigned to an int), `printLMatC` (`temp_v1 = *param_1`),
  `SgSortGroupP` (`lcp & 0xf` on a pointer), `PSAchk3` (`in_hi | (char *)&ene_wrk`). dc: `float **` passed for `sceVu0FMATRIX` parameters (5) and an
  `unsigned char[16]` for a `float *` (prototype reading off uncast calls, (c2)), a value returned from a `void` function (3, (c3)), `SetBrother`/`GyoraceMenuInit` call
  mismatches, `LoadScript(now_script_file.whole)` (an `unsigned char[64]` union member passed to `char *`: `conform` does not type union members),
  `Initialize__12CActionChara`'s `(undefined5 *)` cast, `ChangeSetUnit` (the repo's post-processing). dk: the same `float **` shape (5), `Draw__15CItemBombEffect` and
  `Draw__13CWeaponEffect` (`CONCAT71(...)` with a 7-byte `(int7)` cast), `EdTalkModeInit` (`(int)p - (char *)&obj`), `MonsterNamePosSet` (`illegal type`), two
  `__sinit_*.cpp` heads. p4: callee prototypes that need real prototypes: struct arguments passed by value (`func_002b6c30(0x42ce0000, ...)` takes
  `FclVec2 position`, not a float, so `flt` does not apply), `stack0x00000000` used as an address, `long long` and `float` arguments. gh: an assembler rejection
  and a function the exporter produced nothing for (pristine copy; on the harness clone only `cEvent__isPlaying`, `no candidate`). Stage 3 (merging) removes the temporaries several of these shapes come from; stage 4 (type inference) types the prototypes.
- **Pointer fields**: see `docs/structs.md` section 5; one pointer field in 1,308 inferred fields, 73 integer fields read through pointer casts, no layout change.
- **Isolation arms** of the m22-003 lanes ran on the functions whose outcome differs between off and default (65 ff, 12 dc, 14 dk, 4 dds, 2 gh pristine, 1 rc),
  not on all 200: a fix cannot change a function whose outcome is the same in off and default except through an interaction that cancels. rc, and the whole m22-002 sample, ran in full.
- Wrapper binaries carry the arms (the m22-002 harness drops `ROMWRIGHT_*`); each arm's `cli-<arm>` sets its switches and `ROMWRIGHT_ARM`. The first isolation
  attempt named its arms wrongly and ran as the default; those results were discarded and re-run (`out/invalid_defaults/`).

## Stage 3: variable merge in Rust, and the printing-variant knob (2026-10-14)

Stage 3 (`docs/merge-port.md`) moves who decides which values share a C variable,
which print inline and what the default names are into the worker. It is a port:
every lane above is unchanged against `ROMWRIGHT_NATIVE_MERGE=1` (0 better / 0
worse / 200 same on all ten lanes; `benchmarks/reports/stage3_gates_20261014.md`).
The 16 functions that still do not compile in ff and dk were printed under six
merge variants each and none compiles (type mismatches and undeclared type names,
not merge decisions). What the port adds for these lanes is the knob:
`ROMWRIGHT_MERGE_VARIANT` changes `max_implied_ref`, `max_term_duplication`, which
speculative merges run, and which values are forced explicit, per function. On the
30 best non-exact dds functions one variant turns `sndAddSourceReferences` from
88.842% to 100% and another `btlReleaseModelEntry` from 99.646% to 99.958% (exact);
`benchmarks/reports/variant_smoke_stage3_20261014.json`.

## Near-miss search: `--search N` (2026-10-14)

`python3 tests/m22-003_ps2_multigame_c.py LANE --layers romwright --search 24` (and
`tests/m22-002_ps2_c_output.py --search 24`) adds a `romwright-search` layer: for each function whose
default print compiles and is not exact, the printings of `romwright-cli match --plan` (the merge
variant knob, `calls=cast`, two structuring switches, then combinations) are exported, compiled with the
unit's own command and scored by the lane's scorer; the layer holds the best print per function. The
`romwright` layer is unchanged. Results and method: [match.md](match.md),
`benchmarks/reports/match_search_20261014.{json,md}`; `python3 tests/match_search_report.py` rolls the arms up.

## Stage 4: type decisions on the C output (2026-10-15)

Stage 4 (`docs/types-port.md` section 12) traced the 38 functions of the seven m22-003 lanes that still did not compile after Upgrade round 1
and fixed the causes that are decisions of the Rust layers (a pointer-to-array cast spelled `float **`, a `return v;` in a `void` function, a pointer in `&`/`|`,
structures passed by value, missing call arguments, odd-width types, a `void *` object dereferenced, a zero constant cast to the callee's inferred pointer type).
Each rule has its own `=off` switch; `ROMWRIGHT_NATIVE_TYPES=1` turns them all off (the off arm of the gates; the harness drops `ROMWRIGHT_*`, so arms are wrapper
binaries, see `~/runs/Stage4Types/arms.sh`). Gates, off -> default (exact / compiled / mean %): dds, rc, gh unchanged; p4 60 / 193 / 79.400 -> 60 / 198 / 80.732; ff 21 / 195 / 61.753 -> 21 / 199 / 62.913;
dc 38 / 186 / 69.844 -> 41 / 197 / 73.653; dk 29 / 189 / 75.561 -> 29 / 197 / 78.277; m22-002 MWCC 20261010 +2 compiled, ee-gcc one function better; no exact or compiled loss.
Functions that do not compile, all lanes: 37 -> 9 (`benchmarks/reports/stage4_gates_20261015.{json,md}`).

## PC lanes (Windows PE, x86)

`tests/m22-004_pc_c_output.py` is the PC counterpart: the same exact / compiled / objdiff-percent measure on a truth fixture
(a game built from source with its period Visual C++ and read back from its PDB or COFF symbols) with the fixture's own
compiler run through the pinned wibo. Method, results and the x86 fixes it gated: [pc-project.md](pc-project.md).

## Symbol layout: stack and global symbols (2026-10-15)

`docs/types-port.md` section 13 traced the partial members (`local_10._2_2_`, `key_now._4_4_`), the `stack0x...` names and the `_NAME` uses that Stage 3 left to the layout of the stack frame
and of the global objects, and changed five decisions: the elements of an ELF object are its accesses' width (`undefined4[]`, not `undefined1[]`) and the object is the only name of its addresses (worker, `layout.rs`);
the address of a stack location gets a symbol, the aligned-down address arithmetic of an unaligned MIPS access is folded on the entry stack pointer's alignment, and a pointer at an odd offset no longer types an
open range (`ghidra_opt`, `native/romwright_layout.hh`). `ROMWRIGHT_NATIVE_LAYOUT=1` turns them all off (the off arm of the gates; the harness drops `ROMWRIGHT_*`, so arms are wrapper
binaries, see `~/runs/SymbolLayout/arms.sh`). On the 7,330 PS2 functions of the wave every arm decompiled: partial members 567 -> 496 functions, `stack0x` 63 -> 1, `_NAME` 31 -> 21.
Gates, off -> default (exact / compiled / mean %; Stage 4's defaults are the off arms): see the table in section 13.4; no exact or compiled function is lost on any lane, and functions that do not compile, all m22-003 lanes: 9 -> 8
(`benchmarks/reports/symbol_layout_20261015.{json,md}`).
