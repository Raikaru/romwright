# Compiler rules

Compiler knowledge in Romwright is **data keyed by the compiler the program was built with**, validated
leave-one-out across games. This page is the format, the engines, how to add a rule, the policy a rule
must pass, and (appendix) an inventory of every place the code was compiler-specific before the layer
existed. Numbers live in the reports it names.

## 1. One compiler identity for every platform

Every program carries one canonical id in `programs.compiler`: `family[-version-class]`, or `unknown`.

| id | what it names | evidence the detector reads |
|---|---|---|
| `mwcc-ps2-2.3`, `mwcc-ps2-2.4` (`mwcc-ps2` when no stamp survived), `ee-gcc-2.9x`, `ee-gcc-3.x`, `sn-prodg` | PS2 toolchains; the MWCC class is the Metrowerks linker stamp (2.3 = CodeWarrior PS2 2.3.x, 2.4 = 3.0 and later) | linker `.comment` stamp, section vocabulary (`.mwcats`, `main`+`heap`, `.mdebug`, `.vutext`, `.DVP.*`, `.sndata`), runtime symbols (`compiler/ps2.rs`, shared with `new-project`) |
| `mwcc-psp`, `allegrex-gcc` | PSP toolchains | `.comment` stamps, `.mwcats`, `.gcc_compiled_long32`, `.mdebug.eabi32`, DWARF 1 `.debug` + `.line` |
| `mwcc-gc`, `mwcc-wii` | CodeWarrior GameCube / Wii | `<< Dolphin SDK` / `<< RVL_SDK` banners, the Metrowerks TRK string, CodeWarrior runtime symbols |
| `mwcc-arm` | CodeWarrior for DS | the NitroSDK banner `[SDK+NINTENDO:`; inherited by the container's overlays |
| `agbcc`, `devkitarm-gcc` (GBA) | `agbcc`: the GCC 2.9x Thumb lineage (agbcc, old_agbcc, agscc); `devkitarm-gcc`: GCC 4+ for ARMv4T | how Thumb code returns: share of `pop {rX}; bx rX` among Thumb returns is 0.106-0.562 on the six agbcc-lineage games and 0.000-0.003 on the NDS images; 1.000 on a control (pokeemerald's C compiled with `arm-none-eabi-gcc` 15.2 `-march=armv4t`, no real devkitARM ROM was available), so `devkitarm-gcc` from a ROM is `low` confidence |
| `ido`, `n64-gcc` | N64 IDO / GCC (KMC, pmret gcc 2.8.1) | how `move` is spelled: `or rd,rs,$zero` (IDO) against `addu rd,rs,$zero` (GCC) |
| `msvc-14`, `msvc-15`, `msvc-16` | Xbox 360 Visual C++ 2005 / 2008 / 2010 | PE optional header linker version 8 / 9 / 10 |
| `msvc-10`, `msvc-11`, `msvc-12`, `msvc-13`, `msvc-13.1`, `msvc-14` ... `msvc-19` | Windows PE (i386 and x86-64): Visual C++ 4.x, 5.0, 6.0, .NET 2002, .NET 2003, 2005 ... 2015-2022 | the optional header's linker version (4.x, 5.x, 6.0, 7.00, 7.10, 8.0 ...: `cl` is six major versions above it; linker 14.x is `cl` 19.x); confidence high with a `Rich` header (whose entries are decoded: object count and the build most objects came from, shown as evidence), else medium; the imported `msvcr*.dll` is evidence too. `new-project` pins `msvc4.2`, `msvc6.0`, `msvc7.0`, `msvc7.1`, `msvc8.0` for them. Measured on the PC fixtures, two controls and KOTOR II: `docs/console-research.md` "Windows PC" |
| `mingw-gcc-<major>` | Windows PE built with MinGW GCC (i386 and x86-64) | the commonest `GCC: (...) x.y.z` string in the image: every object carries one (`.rdata$zzz`), so the program's own objects outvote an older library's (a Fedora MinGW image: 83 stamps of 16.2.1 against 71 of 15.2.1); medium. GNU ld and Borland's linker report 2.x and say nothing else, so a PE without the string is `unknown` |
| `devkitarm-gcc`, `devkitppc-gcc`, `devkita64-gcc`, `gcc-<major>`, `clang-<major>` | any ELF | `.comment`: `GCC: (devkitARM release N)`, `GCC: (GNU) x.y`, `clang version N` |
| `unknown` | nothing proved | the evidence line says what was looked for |

* Detection runs once per image, in the loader phase (`load_container_with`), **after** the linker MAP has
  supplied symbols and **before** discovery, so a rule that changes discovery already sees the compiler. The
  verdict and its evidence line are stored as an `info` import diagnostic (stage `compiler`).
* `romwright-cli import <image> --compiler <id>` (or `ROMWRIGHT_COMPILER=<id>`) records that id instead of
  detecting one. The id joins the import-cache key, so a cached import is never served across an override.
* An image of a container the detectors know nothing about (an NDS overlay, a GameCube REL) inherits the
  compiler of the container's earlier image **of the same language**, with `low` confidence.
* PlayStation 1 is `unknown` on purpose. Psy-Q GCC and CodeWarrior images share the Sony library strings and
  the `move` spelling, and the code-shape features tried (load-delay `nop` rate, `$gp` traffic, branch `nop`
  rate) did not separate the one CodeWarrior image from the seven GCC ones.
* A detector is added only where the image's bytes support it, and its accuracy is measured against the
  corpus truth (`benchmarks/compiler_detection_accuracy.py`, report
  `benchmarks/reports/compiler_detection_accuracy.{json,md}`). Thresholds measured on the corpus (the N64 and
  GBA cuts) are in-sample and say so in their source.

## 2. Rule files

`crates/romwright-core/compiler_rules/<family>.json`, embedded with `include_str!` (`compiler/rules.rs`).
`romwright-cli compiler-rules [--json]` lists them with their switch state.

<!-- not gated: excerpt of the rule-file format; the embedded rules themselves are checked by the compiler rule unit tests -->
```json
{
  "family": "gcc",
  "rules": [
    {
      "id": "thumb-pop-bx-is-return",
      "kind": "flag",
      "compilers": ["agbcc", "gcc", "devkitarm-gcc", "mwcc-arm"],
      "unknown": true,
      "languages": ["ARM"],
      "status": "on",
      "origin": "migrated",
      "derived_from": ["gba-pokeemerald"],
      "note": "what the rule does and why",
      "params": {}
    }
  ]
}
```

| field | meaning |
|---|---|
| `id` | unique, no commas or spaces; what the switches and the reports name |
| `kind` | the engine that executes the rule (table below); a kind with no engine is a load error |
| `compilers` | ids or families the rule covers; `ee-gcc` covers `ee-gcc-2.9x` and not `gcc-4`; `*` is every detected compiler |
| `unknown` | also covers a program whose compiler is `unknown`: the rule behaves as it did before compilers were detected, keyed by platform alone |
| `languages`, `formats` | hard constraints (language-id prefixes, loader formats): the hardware and container facts the rule needs, not a compiler choice |
| `status` | `on`, `off` or `candidate`; `off` and `candidate` run only through `ROMWRIGHT_COMPILER_RULES_ENABLE` |
| `origin` | `migrated` (behaviour that shipped before the layer, moved to data unchanged) or `learned` (added with leave-one-out evidence) |
| `derived_from` | corpus games the rule was learned or tuned on; never held out |
| `params` | the kind's parameters |

Applicability, in order: `languages`/`formats` must match; a known compiler is covered when a `compilers`
entry covers its id; an `unknown` compiler is covered when `unknown` is true; the rule must be switched on.

### Engines

Engines are code; the per-compiler parameters are data.

| kind | engine | params | read by |
|---|---|---|---|
| `register-sled` | names a run of register-save/restore helper entries when the bytes prove it, and gives each helper a call fixup | `first`, `last`, `families[]` (`prefix`, `class` r/f, `op` stw/lwz/stfd/lfd, `slot`) | `native/mwcc_runtime.rs`, `romwright-worker/src/specs.rs` |
| `nonreturn-names` | functions a symbol name proves never return | `names[]` (leading underscores ignored) | `nonreturn.rs`, `native/discovery.rs`, `native/store.rs` |
| `flag` | a yes/no a code path asks (`rules::applies(id, ctx)`) | none | `native/discovery.rs` (`interior_entries`: the import-precision rules of Appendix D), `native/switch_tables.rs`, `emit_m2c.rs` (`mwcc-void-pointer-arithmetic`: the conform pass casts a `void *` operand of `+`/`-` to `char *`; dc 11 and dk 8 compile failures, docs/types-port.md) |
| `c-canonical` | one rewrite of the printed C | `fn`: the rewrite's name in `emit_m2c/canonical.rs` | `emit_m2c/canonical.rs` |
| `literal-pool-extent` | extends a function's stored size through the literal pool its own PC-relative loads name | `isas[]` (`thumb`, `arm`) | `native/pool_extent.rs`, called from `native/store.rs` |

### Switches (read once per process)

* `ROMWRIGHT_NO_COMPILER_RULES=1` -- every rule inactive.
* `ROMWRIGHT_COMPILER_RULES_DISABLE=<id,id>` -- those rules inactive (wins over `ENABLE`).
* `ROMWRIGHT_COMPILER_RULES_ENABLE=<id,id>` -- those rules active where they cover the program, whatever
  their `status`; how the leave-one-out harness measures `candidate` and `off` rules.

The switches reach the worker through the environment (`export-c`), and join the import-cache key
(`compiler::rules::fingerprint`).

### Adding a rule

1. Find the behaviour: a code path that is right for one compiler's output and unmeasured for the others.
   Make its *engine* ask `rules::applies(...)` (or add a kind with an engine; the load error keeps a kind
   without an engine out of the files).
2. Write the entry with `status: candidate`, `origin: learned`, the compilers you believe it covers and
   `derived_from: []`.
3. Run `benchmarks/compiler_rules_loo.py --rules <id>` (below). Choose the compilers and the
   `derived_from` games from the games' own results; every game you tuned on is derived and never counts as
   evidence for the rule.
4. Flip it to `on` only when the held-out result meets the policy, and cite the report in the rule's note.

## 3. Leave-one-out policy

`benchmarks/compiler_rules_loo.py` (report `benchmarks/reports/compiler_rules_loo.{json,md}`). For each rule
and each corpus game that the rule covers **and that is not in `derived_from`**, the same build is run
with the rule on and off (the off arm sets `ROMWRIGHT_COMPILER_RULES_DISABLE`; a `candidate`'s on arm sets
`..._ENABLE`):

* the import twice, with the stored facts digested (functions, thunks, return behaviours, flow overrides,
  xrefs, symbols) -- equal digests on an import-level rule mean the rule does nothing on that game;
* recall and precision against the game's truth (the wave's own metric);
* `export-c --address` on both arms for the functions the rule can reach plus a fixed stratified sample:
  success, and the structure statistics (gotos, labels, irregular, native warnings, `unaff_` locals, printed
  functions that differ);
* for the printed-C rules, a C-output lane's m22 exact / compiled / mean (below).

Outputs are deterministic, so **any difference is real**: there is no noise floor, and the report states
every difference. A rule `helps` a game when a judged metric improves and none worsens, `hurts` it in the
reverse case, is `mixed` when both happen, `neutral` when none moves. Judged: recall, precision, decompile
success (and, for `register-sled`, the helper calls left visible and the `unaff_` locals -- what the
rule is for); the other statistics are reported, not judged. An arm that did not finish loses to one that did.

A rule may ship `on` only when:

* **learned**: it helps at least one held-out game and hurts none;
* **migrated**: it hurts no held-out game. It shipped before the layer, so turning it off is a behaviour
  change; the report states whether it also helps, and a migrated rule with no held-out game to measure
  on is reported `unmeasured`, never as proven.

The printed-C rules (`c-canonical`) are judged by a C-output lane's objdiff match (m22 exact, compiled and mean over the
lane's fixed 200-function sample), run with the rule on and off on a fresh import each
(`tests/m22-003_ps2_multigame_c.py`, the per-game PS2 lanes; the harness takes them through `--c-lanes`). A lane's
project accumulates the names and prototypes its romwright layer asserts, so an arm that reuses a project reads
differently from a fresh one (measured: the same arm compiled 125 and then 133 of Fatal Frame's 200 functions);
every arm therefore starts from a fresh import. A game without a lane stays `unmeasured` (`pending lanes`):
nothing is inferred from Persona 4, where the rewrites were derived.

A rule that fails the bar is narrowed to the compilers it was measured on, or demoted to `off` when no compiler key
separates the games it helped from the games it hurt. The measurements stay in the report: a narrowed rule lists
the games it no longer covers under `excluded`.

## Appendix A. Inventory: compiler-specific code before the layer

Found by grep over `crates/` (the repository's file finder times out). "Moved" means the data is now a rule
and the code reads it; "left" gives the reason.

| where | what | now |
|---|---|---|
| `native/mwcc_runtime.rs` | `SLEDS`: the four register-save helper layouts | moved: `mwcc-register-sleds` (`register-sled`) |
| `romwright-worker/src/specs.rs` | `mwcc_callfixups`, `mwcc_helper_names`, `is_mwcc_helper`: the same helpers as call fixups; applied to every 32-bit PowerPC program | moved: read from the same rule; applied only where the rule covers the program |
| `nonreturn.rs` | `known_no_return`: ELF and PE name lists keyed by loader format | moved: `nonreturn-libc-elf`, `nonreturn-itanium-eh`, `nonreturn-windows-crt` |
| `native/discovery.rs`, `native/switch_tables.rs` | Thumb `pop {rX}; bx rX` is a return, not a computed jump (keyed by `ARM`) | moved: `thumb-pop-bx-is-return` |
| `native/discovery.rs` | a Thumb entry that gives back a frame it never built is the tail of the function above (agbcc's long `bl`) | moved: `thumb-frame-teardown-entry` |
| `emit_m2c/canonical.rs` | six printed-C rewrites (MWCC-shaped), run for every program | moved: six `canonical-*` rules (the engine keeps `ROMWRIGHT_NO_CANONICAL`) |
| `native/store.rs`, `native/elf.rs` | `programs.compiler` from the ELF `.comment` (`gcc 4.9`) and from DOL runtime symbols (`mwcc`) | replaced by `compiler::detect` (canonical ids) |
| `new_project/compiler.rs` | `detect_ps2_compiler` | moved to `compiler/ps2.rs`; `new_project` calls it and adds its manifest vocabulary |
| `native/discovery.rs` | tail-call promotion (`ROMWRIGHT_PROMOTE_TAILCALLS`, off) | engine asks `tailcall-promotion` as well; the global switch still works; the candidate rule fails the policy (Appendix B) |
| `native/store.rs` | a function's stored size is its proven body: pool excluded | new learned rule `literal-pool-extent` (Appendix B) |
| `worker/specs.rs` `with_psyq_soft_float` | PSX has no FPU | left: a hardware fact true for every PSX compiler |
| `worker/specs.rs` `with_o32_argument_rules`, `with_gekko_argument_rules`, `with_allegrex_argument_rules`, `with_entry_register_tracking` | calling-convention spec patches (o32 on the MIPS64 spec, EABI on Gekko/Allegrex, r13/r2/gp bases) | left: ABI of the platform, shared by every compiler that targets it |
| `native/discovery.rs` r5900 branches (`has_undecodable_neighbour`, `undecodable_bodies`) | data that shares the executable flag decodes as plausible r5900 code | left: instruction-set facts tuned on all eight PS2 games (compilers mixed); no held-out game exists |
| `native/switch_tables.rs`, `native/vsa.rs` | guard idioms (GCC and SN `sltiu` scheduling, MWCC `cmplwi/bgtlr`, agbcc `bls dispatch; bl default`) | left: dataflow engines (value-set analysis), not tables |
| `qualified_prototypes*`, `rtti/mwcc.rs` | the MWCC name-mangling grammar | left: a demangler keyed by the name's shape, not by the program's compiler |
| `native/linkmap.rs` | CodeWarrior and Psy-Q linker-map formats | left: file formats |
| `emit_m2c/{conform,machine,token_edits,addresses}.rs` | printed-C conformance to the project's declarations (MWCC strictness, `$gp` small data), r5900 only | left: keyed by the project's declarations and the language, not by data tables |
| `func_ir.rs` `helper_semantics` | libgcc / AEABI / MSVC division helper names | left: a name table on no gate path; would need its own kind |
| `export.rs` `splat_compiler` | splat's `compiler:` vocabulary from the platform | left: export vocabulary |
| `library_types/helpers.rs` | libgcc helper prototypes | left: library data |

## Appendix B. Results

The reports are the numbers; this page does not copy them.

* `benchmarks/reports/compiler_detection_accuracy.{json,md}` -- detection against truth, per platform and game, and
  the controls.
* `benchmarks/reports/compiler_rules_loo.{json,md}` -- every rule, its held-out games, on/off deltas, whether it meets
  the policy, the behaviour-neutrality comparison with a build of the tree before the layer, and the games a narrowed rule
  no longer covers.
* `benchmarks/reports/combined_gate_compiler_rules_20261012.{json,md}` and
  `compiler_rules_gate_vs_20261012.{json,md}` -- the gates on the build with the layer, number by number against
  `combined_gate_20261012`.
* `STATUS.md` -- the dated section.

What the first measurements found, in one place: the migrated rules reproduce the tree before the layer
(stored facts identical on 60 of 61 games; the 61st is not deterministic on the host); `mwcc-register-sleds` and
`thumb-frame-teardown-entry` help held-out games, the other migrated import rules are neutral on recall and precision
(`thumb-pop-bx-is-return` is an import-time saving: GBA imports 2.0-18.6 s on, 9.8-56.5 s off); the printed-C rules are
neutral on five of seven PS2 lanes, `canonical-guarded-loops` lowered two ee-gcc lanes and is now keyed to MWCC,
`canonical-strict-greater-constant` helped one MWCC game (3.0) and hurt another (2.3) and is keyed to `mwcc-ps2-2.4`, the class the Metrowerks linker stamp gives the first; `literal-pool-extent`, learned on
pokeemerald, Fire Emblem 8 and pokeheartgold, raises the exact share of stored sizes from 0.17-0.57 to 0.96-0.999 on
seven held-out GBA/NDS games and changes no other measured number; `tailcall-promotion` does not clear the bar.

## Appendix C. Measuring a rule

`benchmarks/console_research.py` takes extra environment for its imports and decompiles from `CONSOLE_RESEARCH_ENV`
(a JSON object), so a wave can be run with a rule off:
`CONSOLE_RESEARCH_ENV='{"ROMWRIGHT_COMPILER_RULES_DISABLE":"literal-pool-extent"}'`. The m22-002 harness does not
pass `ROMWRIGHT_*` variables on to its `export-c` calls; measure a printed-C rule through
`benchmarks/compiler_rules_loo.py --c-lanes`, which sets them on the lane's own command.

## Appendix D. Import-precision rules (2026-10-14, ImportPrecision)

Six `flag` rules read by `interior_entries` in `native/discovery.rs`: each retracts function entries the walk made
out of something that is not a function start. The numbers are in `benchmarks/reports/import_precision_20261014.{json,md}`
and `docs/console-research.md` ("Import precision against stock Ghidra"); `ROMWRIGHT_COMPILER_RULES_DISABLE=<id>`
switches one off.

| rule | covers | what it retracts | derived from |
|---|---|---|---|
| `landing-pad-not-entry` | every compiler | an uncalled entry that is a landing pad of the image's own exception tables (`exception_sites`): only the unwinder enters it | `psp-hot-pixel` (the only corpus image with exception tables) |
| `wide-switch-case-blocks` | MIPS family | case blocks held by a run of 65-4,096 code pointers (targets within 64 KiB, a bounds-checked dispatch just above the lowest): value-set analysis and the decompiler stop at 1,024 table entries | `psp-pac-man-rally` |
| `case-run-in-one-function` | MIPS family | case blocks of a run of 3+ code pointers wherever the table puts its default: none calls, declares, opens a frame or is a bare `jr ra`, all lie between one function the evidence names and the next, a bounds-checked `jr` sits in it; a run of several tables' words is judged by group and only a group of 64+ is retracted | `psp-hot-pixel`, `psp-pac-man-rally` |
| `branch-table-after-dispatch` | MIPS family | `b L; slot` / `j L; slot` pairs that follow a `jr rX` (X not `ra`) one after another: a dispatch into a table of branches | `psp-tetris` |
| `epilogue-not-entry` | MIPS family | an uncalled entry that opens with `lw $ra, N($sp)` or with `b .+8`: the dead tail of a function that ends in a loop (IDO) | `n64-dr-mario-64` |
| `ido-leaf-return-pair` | `ido` | the second `jr ra; nop` of a frameless function, when the image does it all over (a quarter of its called frameless functions are followed by a bare return, 32 at least) | `n64-super-mario-64` |

Three import fixes that are not rules: NDS autoload blocks are mapped where they run (`native/nds.rs`), a zero
word is no pointer in `interior_entries`' run readers (a PSP `.init` is code at 0), and zero words followed by two
words that name any mapped address are padding before a table (`opens_with_alignment_fill`: R&C PAL 0x12f578, whose table
names `.rodata`, not code).


## Appendix E. PE discovery rules (2026-10-15, PcImport)

Nine `flag` rules in `compiler_rules/pe.json`, read by the Windows PE importer (`native/pe/x86_operands.rs`,
`native/pe/local_calls.rs`, `native/pe/x86_fill.rs`, `native/pe_roots.rs`, `native/elf_pointers.rs`, hooked from
`native/discovery.rs` and `src/native.rs`): eight keep something that is not a function out of the function list, one finds
functions nothing references. The measurement, the
leave-one-out table (`benchmarks/pc_rules_loo.py`) and the stock comparison are in `docs/console-research.md`
("Windows PC") and `benchmarks/reports/pc_import_20261015.{json,md}`; `ROMWRIGHT_COMPILER_RULES_DISABLE=<id>`
switches one off. The compiler column is the detector's id (section 1): `msvc` covers every `msvc-<n>`.

| rule | covers | what it keeps out of the function list | derived from |
|---|---|---|---|
| `pe-jump-table-relocs` | every PE | case labels of a run of adjacent relocated words naming code (one decoded inside a body, none, or fewer, an entry) | `pc-ioq3-ded-mingw32` |
| `pe-dense-case-tables` | every PE | labels of a run of 3+ relocated code words packed inside one routine (two thirds do not follow function fill) | `pc-glquake-msvc42` |
| `pe-x86-memory-operands` | every i386 PE | a code address only read as the displacement of a memory operand (a jump table behind its function) | `pc-glquake-msvc42` |
| `pe-x86-scope-tables` | `msvc` (i386) | filter/handler words of a structured-exception scope-table record (level `-1`/`-2`) | `pc-quake2-refgl-msvc8` |
| `pe-x86-local-calls` | `msvc` (i386) | a `__finally` block or lock region only the function before it calls, starting where its body ends: folded into it | `pc-quake2-game-msvc8` |
| `pe-x86-trailing-data` | `msvc` (i386) | data behind a function (a Debug build's run-time-check frame descriptions) that only that function's code and the data itself name, whose decoded body does not end in a return or jump | `pc-quake2-game-msvc8-debug` |
| `pe-import-stub-position` | every PE | an `ff 25` through an import slot in the middle of a function (its tail call), as a linkage stub | `pc-ioq3-ded-mingw32` |
| `pe-x86-case-runs` | every i386 PE | the case labels of a run of 4+ relocated code words that all lie between two entries with evidence of their own (a switch of one function whose table no walk reached) | `pc-ioq3-ded-mingw32` |
| `pe-x86-fill-starts` | every i386 PE | *adds* the function behind a walked function's `int3`/nop fill (4-byte aligned, covered by no function, named by no relocated word, switch table or branch of the function before it, behind a function with no unresolved indirect jump), one hop per pass, up to 32 passes per discovery | `pc-quake2-msvc8` |
