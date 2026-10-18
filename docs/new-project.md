# `new-project`: a ready-to-decompile repository from a retail image

```
romwright-cli new-project <image> <outdir> [--name NAME] [--platform ID] [--toolchain PROFILE.json]
              [--manifest FILE] [--compiler ID] [--cflags "FLAGS"]
              [--decompile all|first:N|ADDR,ADDR|none] [--fact-pack PACK] [--json]
romwright-cli new-project --list-platforms [--json]
romwright-cli detect-compiler <image> [--json]
```

This is what decomp-toolkit's dtk-template does for GameCube/Wii, for the
platforms romwright imports. The framework is in
`crates/romwright-core/src/new_project/` (a platform matrix, a pinned tool
manifest, compiler detection, one plugin per platform); the CLI is
`crates/romwright-cli/src/new_project.rs`. Every platform romwright imports has
a plugin, in one of three shapes: **byte-matching** (PlayStation 2; GameCube and
Wii; Nintendo 64, PlayStation and PSP; Game Boy Advance and Nintendo DS: the
repository rebuilds the retail image byte for byte before any function is
decompiled), a **non-matching scaffold** (3DS, Switch, PS3, PS4, Vita and Xbox
360: no public toolchain reproduces their compilers' output, so nothing is
claimed beyond decompiled C, target objects and an objdiff project where
objdiff has a backend) and **per-function** (Windows PE x86, a reccmp-style
repository: no whole-executable rebuild exists). Each has its own section below
and a row in the platform matrix; `--platform ID` overrides the detection.
Inside any repository except the scaffold ones, `romwright-cli match`
([match.md](match.md)) searches the printings of one function.

dtk-template (CC0-1.0) was studied for its repository shape and behaviour, not
copied: `configure.py` generating a `build.ninja` and `objdiff.json`, versioned
config, tools fetched by tag into `build/tools/`, a `progress` report, and a
checksum of the built image against the retail one.

## What PS2 `new-project` writes

```
<outdir>/
  README.md            how to build, what was detected, how to swap a function
  configure.py         fetch tools, run splat, write build.ninja + objdiff.json; `swap` subcommand
  tools/               download_tool.py (stdlib, sha256-verified), asm.py, verify.py
  requirements.txt     splat64==0.39.1, ninja
  config/
    <image>.yaml       splat config: the whole file, header + code + trailer segments
    symbol_addrs.txt   names, addresses, sizes from romwright's analysis (and the fact pack, if present)
    undefined_syms.txt absolute names for data no object defines
    checksum.sha1      sha1 of the retail image; `ninja` checks the rebuilt image against it
    project.json       image, layout, detected compiler + evidence, flags
    toolchain.json     the pinned manifest entries this project uses (url, sha256, license, provenance)
    toolchain.local.json   (only with --toolchain) your tool profile, git-ignored
  include/             romwright_types.h (base + Ghidra primitive types), romwright_protos.h (recovered prototypes)
  src/                 your C units
  orig/<image>         your retail image (git-ignored)
  decompiled/          optional non-matching reference C (--decompile), git-ignored, never built
  .romwright/          romwright's project store (git-ignored)
```

`asm/`, `assets/`, `build/`, the linker scripts and `build.ninja` are generated and
git-ignored: they contain the retail bytes. A disc image (ISO9660, cooked or raw
sectors) is accepted in place of the ELF; `SYSTEM.CNF`'s `BOOT2` file is extracted
into `orig/`. When a fact pack is present (`--fact-pack`, `ROMWRIGHT_FACT_PACK`, or the
user's default location) the import applies it, so `symbol_addrs.txt` carries its names
and `include/romwright_protos.h` its prototypes: Persona 4 imported with a pack that contains
Persona 4 itself went from 152 to 669 non-generic names and 0 to 331 prototypes (in-sample,
a plumbing check rather than a measurement).

```
python3 -m pip install -r requirements.txt
python3 configure.py        # downloads + verifies tools, splits the image (splat), writes build.ninja
ninja                       # all-assembly build; ends with  OK build/<image> sha1 <retail sha1>
python3 configure.py swap 0x00102e70 --src my.c     # one function -> C unit, then
ninja                       # still byte-identical, or `MISMATCH ... first difference in <function>`
ninja progress              # objdiff report (build/report.json)
```

### How the all-assembly build reproduces the retail file

The yaml covers the file end to end, in file order: the ELF header and program
headers (`databin`), each file-backed `PT_LOAD` as one `code` segment, and the
tail (symbols, section headers, debug) as a `databin`. Inside a load every function
romwright found is its own `asm` subsegment (`asm/main/NNNN/<name>.s`, 32 per
directory) and every non-function byte range is a `textbin`. Zero padding of up to
`0x40` bytes after a function belongs to it, so a function's slot is the function plus
the padding the retail linker left. `sha1(build/<image>)` equals the retail sha1
when the objects, linked in order at the retail addresses, are flattened with
`objcopy -O binary`. Six things had to be handled for that to hold (each found
by a failure on a real image):

1. **`.align 3` grows objects.** splat writes `.align 3` before 8-byte-aligned
   functions; GNU as then rounds the object's `.text` up to 8 bytes (a `0x94`
   function became `0x98`) and every later function moves. `tools/asm.py` drops
   `.align` directives of 8 and above before assembling; the link uses `SUBALIGN(1)`.
2. **GNU ld is cubic in `file(.section)` statements.** splat lists each object as its
   own statement; 800 objects link in 4 s, a 4000-function image in more than 4 min.
   `configure.py` rewrites runs of objects in one directory into a single wildcard
   statement (the generator keeps 32 functions per directory and gives every binary
   piece a directory of its own, so each directory is one contiguous run; `swap` moves the
   entries after a swapped function to a fresh directory for the same reason), names
   objects left alone by a path-suffix wildcard (`*asm/main/0224/f.s.o`) instead of
   exactly, and passes the objects on the command line in the original order. Fatal
   Frame's 4256 objects link in 3 s; Persona 4's 13,178 in 20 s (205 s with 95 exact
   statements). The object list goes through a response file, since 4000 paths exceed
   the 128 KB single-argument limit.
3. **Names are written into assembly.** Symbol names are flattened to
   `[A-Za-z0-9_.$]` (`CDataAlloc<1,1690000>::Alloc` breaks gas), file stems are
   shortened and made unique case-insensitively, and names that are linker-script
   keywords (`VERSION`) are quoted in `undefined_syms.txt`.
4. **Overlay symbols are not part of the image.** DVP/VU overlay sections have address
   0 and carry their own symbols; only symbols inside a `PT_LOAD`'s memory range
   are exported (before naming, so an overlay `Foo` cannot push the real `Foo` to
   `Foo_<address>`).
5. **Some "functions" are data.** Discovery on a stripped image names a few entries in
   data. Their listings contain words the R5900 assembler rejects (`jalr $zero,$zero`,
   `ddiv`), branches to `.L<address>` labels that exist in no file (the link would fail
   on them), or instructions gas encodes differently from retail (a `vaddx` with an empty
   field mask). The listing carries every instruction's retail word in its comment, so
   `tools/asm.py` checks each object against those words (relocated fields masked) and
   assembles a unit that fails any of the three again with every instruction as a
   `.word`, printing a `note:` that names the file. Such a unit is data, not a
   decompilation target; its symbolic operands are lost. In the gated Persona 4 run 5 of
   13,151 files took this path (on an earlier tree, 154: the count follows discovery
   precision).
6. **A load need not end on a word.** GNU as rounds a MIPS `.text` section up to
   4 bytes, so an `.incbin` of a load's last bytes grew by up to 3 when the load's
   size is not a whole word (Digital Devil Saga's second load is `0x992bd` bytes:
   the rebuilt file was 3 bytes longer and differed from `0x2be6b4` on). The last
   1-3 bytes of such a load are a `databin` piece of their own (`.data`,
   alignment 1); being the load's last piece, it still links in file order.

### The C swap

`swap` changes one function's entry in the yaml from `asm` to `c`, re-runs splat
(which writes the retail assembly of the function under
`asm/nonmatchings/<unit>/` and a stub; unchanged files keep their mtimes, so ninja
rebuilds only what changed), then puts your C in `src/<unit>.c` (`--src FILE`, else
the non-matching reference `decompiled/<name>.c` if `new-project --decompile` wrote
one, else an empty stub). The
unit is compiled with the project's flags; only its `.text` is linked, at its slot, and
the location counter is moved to the slot's end so compiler padding cannot shift
anything after it. A C unit longer than its slot stops the link with ld's "cannot
move location counter backwards"; literals and data it emits are not linked (the
retail bytes are already in the binary segments), so a reference to one is an undefined
symbol, not silent duplication. `objdiff.json` lists every C unit with the retail
object as target and your object as base. A C file must be a whole-function (or
whole-run) replacement; `INCLUDE_ASM` units are not supported.

### Near misses: `romwright-cli match`

When the reference C compiles to almost the retail bytes, `romwright-cli match
0xADDRESS [--write]` run in the repository prints the function in alternative
ways (the decompiler's merge, inlining, cast and structuring switches), compiles each
with the project's pinned compiler and flags and shows which one is closest, or
exact; `--write` puts the best C where `swap` picks it up. See [match.md](match.md).

## Nintendo 64, PlayStation and PSP

The three MIPS platforms share the PS2 layout contract (`new_project/mips.rs`: the yaml covers the whole
image in file order, one `asm` unit per function, `textbin` for the bytes between, an all-assembly link
that reproduces the retail bytes, the same wildcard rewrite of the linker script, the same `swap`) and
differ in the container, the compiler and what the build does after linking. Their repositories use
`tools/toolchain.py` (tool resolution and the compile command of each compiler kind, imported by
`configure.py` and by `tools/cc.py`, so `ninja` and `romwright-cli match` compile a unit identically),
`tools/asm.py` (the PS2 one with the byte order read from `config/project.json`) and the binutils of the
PS2 pin (GNU 2.40, `-EB`/`-EL` and every MIPS ISA level; its `ld` takes `-EB`). The compilers' own
requirements (a gcc's binutils, PSY-Q's wibo and maspsx) are `requires` entries of the manifest tool and
are pinned into the project's `config/toolchain.json` with it.

Measured on `nih-vps-u` (2026-10-14/15) on corpus images, `configure.py` then `ninja` on a fresh repository
(`ROMWRIGHT_NO_IMPORT_CACHE=1 ROMWRIGHT_NO_FACT_PACK=1`); each prints `OK build/<image> sha1 <retail sha1>`:

| platform | image | units (asm / binary) | all-assembly rebuild |
| --- | --- | --- | --- |
| N64 (IDO) | Super Mario 64 (US) | 4,592 / 186 | `OK ... sha1 9bef1128717f958171a4afac3ed78ee2bb4e86ce`; two exact C units swapped in (`match --write` + `swap`) keep it |
| N64 (GCC) | Paper Mario (US) | 2,739 / 42 | `OK ... sha1 3837f44cda784b466c9a2d99df70d77c322b97a0` (312 overlay programs stay binary) |
| N64 (IDO) | Star Fox 64 (US rev 0) | 1,590 / 33 | `OK ... sha1 d8b1088520f7c5f81433292a9258c1184afa1457` |
| N64 (IDO) | Perfect Dark (NTSC final) | 57 / 10 | `OK ... sha1 af8788ac4d1a57260eae9c53ffe851fcf2a3319b` (code is Rare 0x1173 compressed: only the raw preamble is split) |
| PSX | Silent Hill (SLUS_007.07) | 236 / 6 | `OK ... sha1 f38344565fb731befc52fd968eb5a667be37acf3`; an exact PSY-Q 4.3 unit swapped in keeps it |
| PSX | Vagrant Story (SLUS_010.40) | 859 / 30 | `OK ... sha1 fababcfd4325d42f350d95b3472874affeb0e48c` (needs the call-target definitions below) |
| PSP (PRX) | corpus `psp-melodie` (EBOOT.BIN) | 3,371 / 19 | `OK ... sha1 724fe026421bfc1f881924d657099b07def869cb` (74 units with Allegrex-only instructions assembled as `.word`s) |
| PSP (ET_EXEC) | corpus `psp-tetris` (EBOOT.BIN, Metrowerks) | 8,703 / 5 | `OK ... sha1 9c5c0620085246a8e680b388787c83141d51e248` |

### Nintendo 64

* **Byte order.** A `.z64`, `.v64` or `.n64` dump is accepted; `orig/<name>.z64` holds the big-endian
  bytes (the importer and splat read that order), `config/project.json` records `source_byte_order` and the
  dump's sha1, and the retail checksum in `config/checksum.sha1` is the normalised ROM's.
  `python3 tools/n64crc.py swap build/<image> out.v64 v64` converts a build back.
* **Segments.** `header` (splat's N64 `header`, `header_encoding: word` so non-ASCII titles stay
  exact), `ipl3` (0xFC0 `databin`), then every executable region of the main program that is raw bytes of
  the ROM (`export::file_backing` over romwright's layout: the catalog or `native/n64_discovery.rs`) as a
  `code` segment, and every other range as a `databin`. Compressed segments (Yaz0, MIO0, Yay0, Rare, DEFLATE)
  and overlays, which the importer holds as programs of their own at overlapping addresses, are carried as
  their ROM bytes: a decompressed segment cannot be recompressed byte-identically in general, so those
  functions are neither in the build nor visible to `match`. Perfect Dark's code is all compressed: its
  repository has the 57 functions of the raw preamble.
* **Checksums.** CRC1/CRC2 (0x10/0x14) are recomputed by `tools/n64crc.py fix` after linking when the
  boot code is a known CIC (6101, 6102, 6103, 6105, 6106) and the retail header is consistent with it
  (`n64crc.py check` and the plugin both verify this at generation time; the algorithm reproduces the header
  of all nine corpus ROMs). Otherwise the step is left out and the note says why. For an all-assembly or
  byte-identical build it changes nothing; it is what keeps the ROM valid once a C unit differs.
* **Compiler.** The importer's `move` rule decides the family (`or rd,rs,$zero` is IDO, `addu rd,rs,$zero`
  the GCC family; the `or` share is 0.866 - 0.994 for every IDO game and 0.000 - 0.033 for both GCC games of the
  corpus). The version cannot be read from the ROM (5.3 and 7.1 spell it alike): `ido5.3` and `gcc2.7.2kmc` are the
  defaults, `ido7.1` and `gcc2.8.1pm` (pmret's Paper Mario build) are pinned too. Default flags are
  `-O2 -G 0 -mips2 -non_shared -Xcpluscomm -Wab,-r4300_mul -woff 649,838` (IDO) and
  `-O2 -mips3 -mgp32 -mfp32 -G 0 -mno-abicalls -fno-pic -fno-common` (gcc). IDO rounds a unit's `.text` up to
  16 bytes; `tools/toolchain.py` trims trailing zero padding from the object's `.text` header so the unit fits
  the slot of the function it replaces.

### PlayStation

The PS-X EXE's 0x800-byte header is a `databin` and `t_addr`/`t_size`/`gp0` come from it; the image is one
`code` segment and anything after `t_size` a trailer. splat writes `include/macro.inc` and
`include/gte_macros.inc`, so GTE instructions assemble through macros. Compiled units go through PSY-Q:
`CPPPSX.EXE` and `CC1PSX.EXE` under wibo, then maspsx (`--aspsx-version` is read from the
`SDevTC ASPSX version` line `CC1PSX` writes into its own output) and GNU `as`. The PSY-Q generation has no
byte-level tell in the image; the default comes from the date of Sony's libsys `$Id: sys.c` stamp (1996 and
earlier: `psyq3.5`, 1997: `psyq4.0`, 1998 and later: `psyq4.3`; Low confidence, `--compiler` overrides), and every
PSY-Q 3.3 - 4.6 is pinned. Disc images are not routed: extract the boot executable.

### PSP

An ELF as the PSP toolchains write it (`ET_EXEC`, or `ET_PRX` 0xffa0), routed by the Allegrex bits of
`e_flags` (so PS2 and PSP ELFs are told apart). The layout is the PS2 plugin's (`PT_LOAD`s as code
segments, headers and the tail as `databin`). **PRX relocations:** the `.rel.*` sections and the `PT_PSPREL`
table are file bytes outside every load, so the rebuild carries them verbatim and the all-assembly build is
byte-identical; nothing is re-emitted. A C unit that is byte-identical to the retail function at the same
offset keeps the table valid; a unit that moves code or changes which words carry a relocation would
need the tables regenerated, which is not implemented (the sha1 check catches it). GNU as for MIPS does not
know Allegrex-only instructions (VFPU `lv.q`/`vadd`, `max`, `min`): `tools/asm.py` assembles a unit that has
one as raw `.word`s and prints a `note:` naming it. Compilers: `psp-gcc-1.7.1` (i386, needs
`/lib/ld-linux.so.2`; only its `cc1` is driven, with `-S`, and the project's binutils assemble) and
`mwccpsp-3.0.1-219` (Metrowerks, wibo); detection is the importer's (`MW MIPS C Compiler` stamp, `.mwcats`, DWARF 1,
GNU stamps). `~PSP` encryption and `EBOOT.PBP` packing are not part of the build.

## GameCube and Wii

```
romwright-cli new-project <disc image | main.dol> <outdir> [--name NAME] [--version ID]
              [--compiler GC/2.6] [--cflags "FLAGS"] [--toolchain PROFILE.json] [--manifest FILE]
              [--decompile all|ADDR,ADDR] [--fact-pack PACK] [--json]
romwright-cli detect-compiler <disc image | main.dol> [--json]
```

A GameCube or Wii disc in any container romwright imports (ISO, CISO, RVZ, WIA, WBFS, Wii
ISO) or a bare DOL. A disc is read through `native/disc.rs`/`wii.rs` (a Wii disc through its
decrypted data partition): the boot DOL is written to `orig/<game id>/sys/main.dol` and every REL
(file-system RELs, and those packed in `RELS.arc`/`rels.arc`, Yaz0-decoded) to
`orig/<game id>/rels/<name>.rel`. The repository is dtk-template's shape
(`crates/romwright-core/src/new_project/gc.rs`; CLI `new_project_gc.rs`):

```
<outdir>/
  README.md            how to build, what was detected, the proprietary-compiler notice
  configure.py         fetch tools, `dtk dol split`, write build.ninja + objdiff.json; `swap` subcommand
  tools/download_tool.py
  requirements.txt     ninja
  config/
    <ID>/config.yml    object, hash, symbols, splits, mw_comment_version, modules: (the RELs)
    <ID>/splits.txt    the `Sections:` block (names, kinds, alignments), translation units added by `swap`
    <ID>/symbols.txt   names, addresses, sizes from romwright's analysis, in dtk's grammar
    <ID>/build.sha1    sha1 of the DOL (and of the RELs that are copied, not rebuilt)
    <ID>/rels.sha1     sha1 of every REL as `dtk rel make` rebuilds it (`ninja rels`)
    <ID>/objects.json  the units that have C: source, matching flag, per-unit compiler overrides
    <ID>/modules/<REL>/{splits,symbols}.txt   per REL
    project.json       version, image, compiler (+ detection evidence), flags, layout, modules
    toolchain.json     the pinned manifest entries (dtk, wibo, sjiswrap, objdiff-cli, the compilers bundle)
  include/             romwright_types.h, romwright_protos.h (recovered prototypes)
  src/                 your C units (src/<unit>)
  orig/<ID>/{sys/main.dol, rels/*.rel}   your retail files (git-ignored)
```

```
python3 -m pip install -r requirements.txt     # ninja
python3 configure.py        # downloads + verifies tools, `dtk dol split`, writes build.ninja + objdiff.json
ninja                       # all-assembly build: link, elf2dol, `dtk shasum`: build/<ID>/main.dol: OK
ninja rels                  # (discs with RELs) link the modules, `dtk rel make`, check rels.sha1
python3 configure.py swap fn_80003154     # a function -> its own unit src/main/<name>.c; objects.json entry
ninja progress              # objdiff report (build/<ID>/report.json)
romwright-cli match 0x80003154            # near-miss search (docs/match.md)
```

### How the all-assembly build reproduces the retail DOL

dtk writes one relocatable object per translation unit (assembly-only units for everything
no `splits.txt` unit claims), the Metrowerks linker (`mwldeppc.exe`, through wibo) puts them
back under dtk's generated `ldscript.lcf`, and `dtk elf2dol` flattens the ELF. romwright's part
is the input dtk cannot get right alone. Found by failures on real DOLs:

1. **Section names and boundaries.** A DOL says nothing about what its sections are, and
   `Sections:` binds names to dtk's sections by position. dtk's own naming guesses from code
   behaviour and fails on Animal Crossing (an `extab` it names `.data2`) and on Wii DOLs
   (a second `.sbss`). `dol_layout.rs` reads the two tables Metrowerks' linker script leaves at
   the end of `.init` (`_rom_copy_info`: unpadded size per initialised section;
   `_bss_init_info`: one entry per BSS section; the search follows dtk's `process_dol`), so the
   `.sbss2`/`.bss` boundary of a Wii DOL's single BSS range is exact. Names are positional
   (`.init`, `extab`, `extabindex`, `.text`, `.ctors`, `.dtors`, `.rodata`, `.data`, `.sdata`,
   `.sdata2` for the initialised ones; a BSS section is `.sbss` after `.sdata`, `.sbss2` after
   `.sdata2`, else `.bss`; six data slots mean no `extab`/`extabindex`). The alignment of each
   section is the smallest power of two (at least 4) that places it after the previous
   one, which reproduces the `align:` dtk itself writes (checked on Pikmin 2 and Skyward
   Sword) and is what the linker script has to say for the layout to hold. Animal Crossing's
   repository (ACreTeam/ac-decomp, used only as data) has the same `Sections:` block.
2. **The entry function is `__start`.** The loader names it `_entry`; mwld looks for `__start`.
3. **Overlapping functions.** romwright's function table and dtk's control-flow analysis
   disagree on some boundaries (a function dtk follows through a jump table contains an
   entry romwright counted separately). dtk refuses the file (`Overlapping functions ...`,
   `Split ... ends within symbol`, `Found multiple functions inside a symbol`, `Symbol ...
   overlaps with symbol`). The export drops, before writing, the function that starts inside
   an earlier one; `configure.py` drops, after the fact, the row dtk names in such an error and
   splits again (`build/<ID>/dropped-symbols.txt` lists them; dtk's analysis is the authority
   on what it can split).
4. **dtk needs two passes over a fresh symbol file.** `dtk dol split` writes its analysis back
   into `symbols.txt`/`splits.txt`, and the runtime's `__init_cpp_exceptions_reference` (the
   first `.ctors` entry) is only recognised once the file has been through a pass: the first
   split drops that 4-byte pointer and the rebuilt DOL differs there (found on Pikmin,
   Pikmin 2, Super Mario Strikers). `configure.py` splits until a pass leaves the files
   as it found them (at most three).
5. **The startup registrations.** The linker script puts `__init_cpp_exceptions` first in
   `.ctors` and `__destroy_global_chain`, `__fini_cpp_exceptions` first in `.dtors`. How dtk
   handles them depends on how romwright's function boundaries agree with dtk's signatures
   (romwright splits the init and fini functions of Wii DOLs where dtk's signature has one),
   and differs between games: a unit for the `.ctors` entry (`rename:.ctors$10`, the linker's
   ordering key) is needed on Skyward-Sword-era Wii DOLs and breaks Pikmin 2; naming the three
   functions and giving the three entries a unit (`$10`/`$15`) is what Twilight Princess and
   Pikmin 2 Wii need and gives a cyclic link order on Pikmin 2. So `configure.py` links the
   DOL after each split and compares its sha1 with the retail one, and tries the arrangements in
   turn (`keep`, a `.ctors` unit, names + three units; names first when there are RELs, whose
   `dtk rel make` looks `__destroy_global_chain` up by name) until one matches:
   `the DOL rebuilds byte for byte (arrangement: names)`.
6. **Linker and `.comment` pair.** dtk writes a `.comment` section into every object
   (`mw_comment_version`, dtk's own table: 8 CodeWarrior GC 1.0, 10 GC 1.3.2, 11/13 GC 2.7,
   14/15 GC 3.0 alpha). The newer `mwldeppc.exe` builds (`GC/3.0a*`, `Wii/*`) segfault under
   wibo 1.0.3 to 1.2.0 on a `.comment` older than their own (any link, two kernels and glibc
   versions; `GC/2.7` and older accept anything), so the version written follows the linker
   (`gc::comment_version`).

Everything dtk itself computes (relocations, jump tables, small-data objects, object
boundaries) is left to dtk's analysis, which runs on top of romwright's rows.

### REL modules

Each REL with code becomes a `modules:` entry. romwright writes the module's `Sections:` block
(`rel_layout.rs`: after the `.text` slot come `.ctors`, `.dtors`, `.rodata`, `.data`, then
`.bss`; Mario Party 4's DLLs have `.text` in slot 2; alignments from the file offsets; dtk's
own naming stops at `Multiple sections with name .rodata` on some Twilight Princess RELs and
at `Only one of .ctors and .dtors has been found?` on Mario Party 4's); the module's symbols
come from dtk's analysis (romwright's names inside RELs are not exported). RELs that
share a module id are overlays: when another module imports that id, the one in the archive
or directory that holds the most RELs (the importer's rule) is linked and the others are
copied; otherwise every one is linked (Mario Party 4's 99 DLLs), and every module's `links:`
lists the modules with an id of their own, since dtk refuses a link set holding two of one id
(`Duplicate module ID`). RELs without code (Mario Party 4's 144-byte stubs: only `.ctors` and
`.dtors` words, which mwld refuses with `internal linker error`) are copied from the retail
files. `configure.py` links each module twice (`-r`, then `-r1 -lcf`, as dtk-template does) and
`dtk rel make` writes the RELs from the DOL's ELF and the PLFs.

`ninja` builds and checks the DOL (and copied RELs); `ninja rels` links the modules and checks
them against `config/<ID>/rels.sha1`. dtk's analysis alone does not reproduce every REL's
relocation table: a `.dtors` entry it ties to the DOL's `__destroy_global_chain` where the
retail file points at a function of the module itself, so that check is a measure and does not
gate the DOL.

### The C unit

`configure.py swap NAME|ADDR` adds a `splits.txt` unit for one function (`main/<name>.c`, only its
`.text` range), creates `src/main/<name>.c` (from `--src`, `decompiled/<name>.c` or an empty
stub) and an `objects.json` entry. The unit is compiled with the project's MWCC (default flags
are dtk-template's base set; `-enc SJIS` for Wii and 3.0 compilers, `-multibyte` for older
ones) and objdiff compares the object with dtk's target object, but the build keeps
linking dtk's object, so the checksum still holds, until `"matching": true`.

### Near misses: `match` on a GameCube/Wii repository

`romwright-cli match` compiles each printing with the repository's MWCC through wibo, reads the PowerPC
ELF object (`.rela` relocations), masks the bits the linker rewrites
(`R_PPC_REL24`/`ADDR16_HA`/`ADDR16_LO`/`EMB_SDA21`/...) and scores the function with objdiff. Both objdiff
inputs are built with the compiled function's relocations and the retail bytes cleared under
them, so a relocated field compares equal. See [match.md](match.md).

## Game Boy Advance and Nintendo DS

Neither platform has splat support (splat has no ARM), so these two plugins are romwright's own
(`new_project/gba.rs` and `new_project/nds.rs`, with the shared ARM/Thumb decoder `arm.rs`; CLI `new_project_arm.rs`).
Both rebuild the retail file byte for byte before any function is decompiled, and `romwright-cli match`
runs inside them.

### Game Boy Advance

```
romwright-cli new-project fe8.gba fe8        # imports, writes the repository
cd fe8 && python3 configure.py && ninja      # OK build/fe8.gba sha1 c25b145e...  (the retail sha1)
python3 configure.py swap 0x08009674 --src my.c && ninja     # agbcc compiles it into the same slot
romwright-cli match 0x080a6f0c --write
```

`config/units.json` covers the whole ROM in file order, as units: the cartridge header
(`tools/header.py` writes `asm/header.s` from `config/header.json`, **computing** the complement check
`-(sum(0xA0..0xBC)+0x19)` instead of copying it, and reading the logo from your `orig/` with `.incbin`),
every function romwright found with the zero padding after it (`asm/main/NNNN/<name>.s`), and every other
byte range as an `.incbin` of the retail file (`kind: data`). Units link in order at the retail addresses
(`SUBALIGN(1)`, 64 units per directory = one wildcard statement, since GNU ld is cubic in per-file
statements) and `objcopy -O binary` flattens them.

**The assembly** (`arm.rs` decodes, `gba.rs` writes): `.syntax unified`, `thumb_func_start name` /
`arm_func_start name` macros (`include/macro.inc`), `.L<address>` labels for branch targets, switch tables
found as runs of aligned words that are code addresses of the unit (their targets are decoded too), literal
pools as labelled `.4byte`s (`ldr r0, .L080000c4`) whose value is written as a function, a data symbol or a
unit label when it is exactly that address (`.4byte FUN_08003078`, a Thumb function's low bit comes from
`.thumb_func`), `bl` and `b` to functions by name. Each line ends in `@ address raw-halfwords`.
GNU `as` is not the tool that wrote the retail bytes, so `tools/asm.py` checks every assembled unit
against the retail bytes (relocated fields masked) and keeps a line as `.inst.n`/`.inst.w`/`.inst` of its
retail word when `as` encodes it differently (`adds r0, r0, #1` as the 8-bit form, a `mov` between low
registers, a pc-relative `add` with an odd rotation), or the whole unit raw when it must; it prints and
logs each such unit (`build/asm_notes.txt`). The decoder was checked against the pinned `as`: all 65,536
Thumb halfwords (57,759 identical, 431 refused by the ARMv4T assembler, 192 `adds/subs/cmp` encoding
choices) and 3 M random ARM words (2,175,328 identical, 3,851 different, nearly all unpredictable
`pc`/SBZ encodings).

**FE8 (Fire Emblem: The Sacred Stones), fresh repository, pinned tools:** 8,203 function units (8,191
Thumb, 12 ARM), 294 data units plus the header; `ninja` assembles 8,502 objects in about 5 minutes on 4 cores; 3 of the
8,203 units are kept as raw words (`FUN_080cf9b8` has one line, two others are data the discovery took
for code). `build/fe8.gba` has sha1 `c25b145e37456171ada4b0d440bf88a19f4d509f`, the retail sha1.

**C units.** `swap` turns an `asm` unit into a `c` unit; `tools/cc.py` runs `cpp -nostdinc -undef` (Arm GNU
13.3), `agbcc -O2 -mthumb-interwork -fhex-asm` and `as`, and appends the `.align 2, 0` pret appends (without
it `as` pads the section end with Thumb nops where the retail slot has zeros). The unit's `.text` links at
its slot and the location counter is pinned to the slot's end. Globals the decompiler named by address
(`DAT_03001234`, `LAB_08758720`, `iRam0203a8f0`) are defined by `tools/autosyms.py` from the undefined symbols
of the C objects. Seven functions the default print compiled to exactly their retail bytes were swapped into
the FE8 repository at once: the rebuilt ROM still has the retail sha1.

**Compiler.** The detector (`detect_gba_compiler`) is the importer's rule, the share of `pop {rX}; bx rX`
among Thumb returns (0.106-0.562 for the agbcc lineage, 1.0 for GCC 4+), with the AGB SDK library stamps
(`SRAM_V113`, `EEPROM_V124`...) as supporting evidence. The manifest pins the Arm GNU Toolchain 13.3.rel1
(`as`, `ld`, `objcopy`, `nm`, `cpp`; four hosts, sha256 from Arm's `.sha256asc` files) and **agbcc as
pret/agbcc's release binary** (`releases/download/release/agbcc.tar.gz`: `bin/agbcc`, `bin/old_agbcc`,
`bin/agbcc_arm`, the SDK headers, x86-64 Linux; the tag is mutable, the sha256 pins the 2026-01-20 asset). The
matrix row used to say agbcc has no binary release: it does (decomp.me's `gba/agbcc` compiler downloads the
same file), so no source build recipe is needed. `old_agbcc` and `agbcc_arm` are in the same archive; some
games need one of them (`--cflags`, or a toolchain profile).
`detect-compiler` on the six corpus GBA ROMs says agbcc lineage (medium; shares 0.106-0.562 of `pop {rX}; bx rX`); only pokeemerald and FE8 have a known compiler (agbcc), so this is a consistency check, not an accuracy measurement. On the six NDS images it says `mwcc-arm` (medium, from the NitroSDK banner), which is the importer's rule restated, not a version measurement.

### Nintendo DS

```
romwright-cli new-project twewy.nds twewy
cd twewy && python3 configure.py && ninja    # OK build/twewy.nds sha1 23e87b1e...  (the retail sha1)
python3 configure.py swap 0x02000800 && ninja
```

The DS-specific work is [dsd](https://github.com/AetiasHax/ds-decomp) v0.12.1 (MIT) with its embedded
[ds-rom](https://github.com/AetiasHax/ds-rom) v0.8.0 (MIT; the standalone `dsrom` is pinned too):
`dsd rom extract` (ARM9 decompressed, overlays, ARM7, banner, header, files), `dsd init` (config for ARM9,
ITCM/DTCM and every overlay), `dsd delink`, `dsd lcf`, Metrowerks' `mwldarm` through wibo,
`dsd rom config`, `dsd rom build`. Measured on the corpus with that pipeline unmodified (fates-vps):
**World Ends With You: 4 bytes of 128 MiB differ, Kingdom Hearts 358/2 Days (EU): 4 bytes of 256 MiB**,
the same four in both: the secure-area CRC (header `0x6C`) and the header CRC (`0x15E`). The retail header
records the CRC of the *encrypted* secure area, which a decrypted dump gives no key to reproduce, so
`config/header.json` keeps the retail value and `tools/romfix.py` writes it back and recomputes the header
CRC-16 (checked on twewy, KH358 and HeartGold: the corrected header equals the retail one). The
pipeline needed two more things: `mwldarm -nodead` (without it 50 of HeartGold's 129 overlays lost
their sizes in `dsd rom config`) and, on games that have them, no `module:overlays(...)` relocations
(an address that exists in several overlays: dsd's linker script picks one; on HeartGold three words of
an overlay pointer table pointed at the wrong overlay, 6 bytes; dropped, the delinked data keeps the retail
bytes: 5,488 relocations on twewy, 165 on KH358, which relinks identically either way). The merge step
reads every `symbols.txt` row strictly: rows carry nested arguments (`dsprot_range=(0x..,0x..)`) and an
early reader that dropped the rows it could not parse made `dsd delink` fail on KH358.

**What romwright adds.** `new-project` imports the ROM (`<name>.arm9`, `.arm7` and one program per overlay),
and writes every program's functions and symbols in dsd's `symbols.txt` grammar to
`config/romwright/<module>.symbols.txt` (`name kind:function(thumb,size=0x1c8) addr:0x02000ca4`, modes from the
decode contexts, names from the importer, the image or a fact pack). `configure.py` runs `dsd init`, then
`tools/merge_symbols.py` merges them into dsd's files: a romwright name replaces dsd's `func_...` default
(functions and data); a function dsd did not find is added (only inside a `.text` section, inside no dsd
function, with no dsd symbol inside it, in the mode romwright decoded; `--no-add-functions` renames only);
relocations dsd could not attribute to one overlay are dropped. `dsd delink` - the consumer that analyses every
function - validates the result: an added function it cannot analyse (`InvalidStart`) is taken out again, and
a config it still refuses is replaced by dsd's own files. dsd's own analysis supplies the sections
(`delinks.txt`: `.text`, `.rodata`, `.ctor`, `.data`, `.bss`), the relocations and `config.yaml`: those need
the build-info and section layout only its analysis derives, and the ARM7 program, which dsd does not model,
stays a binary in the extract (its functions are emitted for reference only). Inventories on the corpus:
twewy, romwright 12,783 ARM9 and overlay functions against dsd's 14,424, 12,763 in both, 20 romwright's
alone (1 candidate, rejected by `dsd delink`); Kingdom Hearts 358/2 Days 20,786 against 23,253, 20,753 in both,
33 romwright's alone (27 candidates, 25 added after `dsd delink` rejected two); both ROMs still rebuild to the retail
sha1 with the added functions. On a stripped ROM with default names the merge renames nothing; it matters
once names exist (fact pack, symbol tables).

**Compiler.** `detect_nds_compiler`: the NitroSDK banner `[SDK+NINTENDO:<lib>]` (CodeWarrior built the SDK)
-> `mwcc-arm`, medium confidence, default build `mwccarm/2.0/sp2p3`; the version is the default for the class,
not a proof (pokeheartgold builds game code with 2.0/sp2p2 and the SDK with 2.0/sp2p3). The manifest pins
`dsd`, `dsrom`, `wibo` and `mwccarm.zip` from decomp.me's compilers release (proprietary; CodeWarrior 1.2,
2.0 and dsi builds with `mwldarm` and one `license.dat` that `configure.py` copies beside the executables;
the sha256 equals pret/pokeheartgold's `mwccarm.zip`). `swap` adds a `complete` delink file
(`src/<module>/<name>.c`) to the module's `delinks.txt`; `tools/cc.py` runs `mwccarm` through wibo.

**Limits.** HeartGold (the corpus image is pret's own build, not a retail dump): plain `dsd rom extract` +
`dsd rom build` reproduces it except the four header bytes, but the relinked path differs by 62,846 bytes in
overlays (file offsets 0x28xxxxx-0x2bxxxxx), where `dsd rom config` rebuilds the DS Protect state (`pool_size: null`
against 16 in the extract). Kingdom Hearts 358/2 Days, a retail dump whose overlay 28 carries `dsprot_range`
symbols, relinks to the retail sha1, so the difference is probably that pret's build does not encrypt the ranges
dsd re-encrypts [INFERENCE: not tested against a retail HeartGold dump, which is not in the corpus]. An encrypted retail dump needs the ARM7 BIOS (`--arm7-bios`), never stored.
ARM7 and ARM7 overlays are not rebuilt from objects. `match` serves ARM9 and autoload functions.

## 3DS, Switch, PS3, PS4, Vita and Xbox 360: the non-matching scaffold

No public toolchain reproduces most of these platforms' retail compiler output, so there is no byte-identical
build and no checksum gate. `new-project` writes what romwright knows and a way to look at it. The 3DS is
the exception per function: its retail compiler (armcc) is pinned, see "3DS with armcc" below. The plugin
is `new_project/scaffold.rs` (+ `scaffold_obj.rs`), the CLI side `crates/romwright-cli/src/new_project_scaffold.rs`.
The platform is read from the container's magic (`NCCH`/`NCSD`/CIA, `NSO0`, NCA/XCI, `XEX2`, a SELF, an
ELF's machine and OS ABI, a PE with machine `0x1F2`) or given with `--platform 3ds|switch|ps3|ps4|vita|x360`.

```
romwright-cli new-project <image> <outdir> [--platform ID] [--name NAME] [--keys FILE...] [--map FILE]
              [--raw BASE --language ID] [--decompile all|first:N|ADDR,ADDR|none] [--budget-ms N] [--jobs N]
              [--toolchain PROFILE.json] [--manifest FILE] [--fact-pack PACK] [--json]
              [--compiler armcc-<version>-b<build> [--cflags FLAGS]] [--tus FILE]
```

`--keys` hands the container loaders the user's keys (`prod.keys`, a RAP/klic, a 3DS `aes_keys.txt`); they
live in memory for the import and are never written. `--map` is a linker map or BINMAP naming symbols,
`--raw 0x100000 --language ARM:LE:32:v6` imports a flat dump (a 3DS ExeFS `.code`).
`--decompile` defaults to `all`. The selected functions are decompiled in batches of 48, one worker per batch,
on `--jobs N` threads at once (default: the host's cores, at most 16); `--budget-ms` bounds each function and a
batch gets the sum. A batch the decompiler refuses is redone function by function, and a function it refuses is
skipped and counted, never fatal. The smokes below use `first:40` (the first N functions of each module by
address).

`--tus FILE` (`{"units": [{"module": "_code", "address": "0x1b0cb0", "tu": "sdds4/program/battle/btlMain"}]}`)
places functions in the original source files evidence assigns them to (assert paths, file-local data): each
listed function's unit becomes `src/<module>/<file>/<function>.c` (and the same path below `build/obj/` and
`orig/target/`), `config/project.json` records its `file`, and objdiff gets one progress category per file. Every
other function stays in its address shard. A path must be relative, `/`-separated plain names; anything else is
refused. Functions stay one per unit, so the build, objdiff and a relink are unchanged.

**3DS with armcc.** Nintendo's 3DS SDK builds with ARM's armcc (RVCT 4.0/4.1, ARM Compiler 5). The
decomp.me compilers project hosts fourteen builds (`armcc.zip`, compiler and headers only); the manifest pins
each as `armcc-4.0-b771` ... `armcc-4.1-b713` ... `armcc-5.04-b82`, all from that one archive (sha256 of the
bytes seen on 2026-10-17). `--compiler armcc-4.1-b713 --cflags "-O3 -Otime"` makes `build.py` compile every unit
with that build (`--cpu=MPCore --fpmode=fast --apcs=/interwork --c99` plus `--cflags`, default `-O2 -Ospace`;
`--arm`/`--thumb` per unit), natively on Windows and through wibo elsewhere, so objdiff compares armcc's
object with the retail bytes and 100% means the function matches. The armcc bundle has no `armlink` and no C
runtime libraries, so armcc does not build the whole image; `tools/relink.py` (below) relinks the retail `.code`
with GNU ld from the per-function objects instead. Without `--compiler` the 3DS keeps the clang compile check.

The 3DS target objects carry what an armcc object of the same function carries, so a match is reachable:
direct `BL`/`BLX` calls are `R_ARM_CALL`, `B` tail calls and conditional calls `R_ARM_JUMP24` (found from the
bytes, whether or not the analysis recorded the branch), literal pools are `$d` ranges (a pool after the
function's last instruction, which the analysis leaves out of its size, is taken in when it ends before the next
function), and a pool word holding a function address or an address in a non-executable segment is an
`R_ARM_ABS32` to that function or to `DAT_<address>` (eight lowercase hex digits). Each object carries the
`.ARM.attributes` armcc writes (MPCore, ARMv6K, VFPv2), so objdiff decodes both sides as ARMv6K. An NCCH's
exheader code-set info maps `.code` as `.text` (r-x), `.rodata` (r--), `.data` (rw-) and the zero-filled
`.bss`, so the decompiler treats pools as constants and names the global they hold. A large NCCH or NCSD
(64 MiB and up) is read as its program view: headers, exheader and ExeFS, with the RomFS and code-less
partitions left out (`threeds::program_view`). The import stores and maps that view (Shin Megami Tensei IV:
a few MB of a 1.8 GB card), and `config/project.json` still records the whole file's sha256.

**A 3DS project works without romwright.** `orig/` and `build/` are git-ignored (retail bytes), so a fresh clone
has no target objects. Every 3DS project therefore carries stdlib-only Python tools (`tools/n3ds.py`,
`tools/split.py`, `tools/relink.py`):

```sh
python3 build.py fetch      # pinned armcc, objdiff-cli, wibo where needed, arm-none-eabi binutils (for relink)
# put the decrypted dump at orig/<image> (config/project.json says the name and sha256)
python3 build.py split      # rewrite orig/target/**.o from the dump and config/
python3 build.py            # compile src/ with armcc
python3 build.py report     # objdiff-cli -> build/report.json
python3 tools/relink.py --matched   # relink the whole .code with every 100% function from build/obj; prints MATCH
```

* `tools/n3ds.py` is the loader: NCCH (`.cxi`) and NCSD (`.3ds`/`.cci`, the executable partition, or
  `partition<N>` as `config/modules.json` names it), ExeFS `.code`, backward-LZ ("BLZ") decompression, the
  exheader's code-set segments and the same mapped regions romwright reads. It reads only the parts of the file it
  needs. Encrypted content (secure NCCH keys, a fixed-key title, a CIA) is refused with a message: it does no
  cryptography, so decrypt first (`romwright-cli new-project --keys` decrypts in memory, for the import only).
* `tools/split.py` writes `orig/target/**.o` from `orig/<image>`, `config/project.json` (which object is which
  function), `config/symbols.txt` (names, sizes, `mode:thumb`; a function renamed there is the name its callers'
  relocations use after the next `split`) and `config/modules.json` (which sections are data, for `DAT_<address>`),
  and nothing else: no romwright, no analysis store. It is a port of the writer above and produces the same bytes:
  branches (calls, tail calls, conditional calls, recursion) and pool words are found from the bytes. romwright
  also feeds the writer the transfers the analysis recorded; a recorded transfer that the bytes do not show as a
  branch outside a literal pool is the only thing `split.py` cannot reproduce, and on Shin Megami Tensei IV no
  object differs (9,331 of 9,331 byte-identical on v1.0, 9,337 of 9,337 on the v1.2.0 update).
* `tools/relink.py` places every function at its retail address with a generated GNU ld script and compares the
  linked `.code` with the dump's. By default functions without a compiled match are retail bytes; `--matched`
  links each function objdiff scores 100% from `build/obj/` (the decompiled C, proven inside the whole image),
  `--full` links every function from its target object (proves those objects relocate back to retail). A function
  that scores 100% but does not reproduce its bytes in the image is printed with the `--exclude` list to rerun
  with. The Windows binutils asset (298 MB zip) installs only `as`, `ld`, `nm`, `objcopy`, `objdump` and
  `readelf` (standalone executables); other hosts extract Arm's whole 13.3.rel1 toolchain.

`new-project` writes `src/` as well as everything above: regenerating into a directory whose `src/` you edited
overwrites it, so from the first edit on use `split` to bring `orig/target/` back. Regeneration also rewrites
`.gitignore`; keep personal ignore rules (the directory holding your dump, say) in `.git/info/exclude`.

Finding the build and flags: compile a few hundred decompiled functions with every build and a few flag sets and
rank them by objdiff score. On Shin Megami Tensei IV (USA, 9,350 functions, 240 sampled) every RVCT 4.1 build
from b713 on at `-O3 -Otime` scored 55.2% fuzzy with 9 exact matches, 4.0 and 4.1 b561 49.8% with 3, 5.04 b82
54.5% with 7; `-O3` and `-O2` scored lower on every build. The sample does not separate builds 713 to 1454.

```
<outdir>/
  README.md              what was written, per-platform notes, how to read objdiff here
  build.py               compile every unit with the pinned compiler; `fetch`, `split` (3DS), `report`; stdlib only
  tools/download_tool.py sha256-verified fetch of config/toolchain.json's entries (same tool as PS2)
  tools/n3ds.py split.py relink.py   (3DS only) the loader, target-object writer and GNU ld relink described above
  config/
    symbols.txt          one line per function/label/import: name = section:0xADDR; // type:function size:0xN [mode:thumb|arm] [orig:"name"]
                         (config/<module>/symbols.txt when the image has several modules)
    modules.json         per module: language, section map + load addresses, sha256 of the mapped image, build id (NSO0)
    project.json         image sha256, compiler target and flags, one row per unit (function, source, object, mode)
    toolchain.json       the pinned entries: clang-22.1.8 (+ objdiff-cli where objdiff has a backend)
  include/               romwright_types.h (base + Ghidra primitive names), protos_<module>.h, romwright_protos.h
  src/<module>/<shard>/<function>.c   decompiled C, one function per file, marked NON_MATCHING
  orig/<image>           your retail image (git-ignored); orig/target/**.o the retail bytes of each function
  objdiff.json           (ARM v6K, AArch64, x86-64 only) target object vs build/obj, one unit per function
```

Names are made C identifiers (`sut::wcsstr(const` from a map file becomes `sut__wcsstr_const`, the original
kept as `orig:"..."`), unique case-insensitively, never a C keyword or one of the header's type names.
`<shard>` is the function address >> 16.

**Build.** `build.py` compiles each unit with `clang --target=<triple>` in lenient C (`-ffreestanding
-nostdlibinc -O2 -w`, implicit function declarations and int/pointer conversions accepted: decompiled C has no
headers for its callees) and writes `build/compile_report.json` with every failure's first error; it exits 0
unless `--strict`. The compiler is pinned (`clang-22.1.8`, LLVM release `llvmorg-22.1.8`, 1.9 GB archive,
Apache-2.0 with LLVM exception, sha256 from GitHub's asset digests); one clang covers all six CPUs, PowerPC included,
so no cross GCC is pinned. `build.py` also uses `$CLANG`, `--clang`, or a toolchain profile's `{"clang": ...}`.

| platform | clang target | objdiff |
| --- | --- | --- |
| 3DS | `armv6k-none-eabi`, `-mfpu=vfpv2`, per-unit `-marm`/`-mthumb` from the mode the analysis decoded | yes (ARMv6K) |
| Switch | `aarch64-none-elf`, `-mcpu=cortex-a57` | yes |
| PS4 | `x86_64-unknown-none-elf`, `-march=btver2` | yes |
| Vita | `armv7a-none-eabi`, Cortex-A9/NEON, per-unit `-marm`/`-mthumb` | **no**: objdiff-cli 3.6.1 stops on the ARMv7 objects with `ARM arch ARMv7 not supported` |
| PS3 | `powerpc-unknown-none-eabi`, `-maltivec -mcpu=970` (32-bit data model like the PS3 ABI; checks the C, not the ABI) | no PowerPC64 backend |
| Xbox 360 | `powerpc-unknown-none-eabi`, `-maltivec -mcpu=970` | no PowerPC64 backend |

**Target objects and objdiff.** Each decompiled function's retail bytes are cut out of the mapped image and
written as a one-section relocatable ELF named after the function (`scaffold_obj.rs`; the gABI and processor
supplements, no tool's source). A direct call or branch to another known function is rewritten into the
relocation a compiler would emit (`R_ARM_CALL`, `R_ARM_THM_CALL`, `R_AARCH64_CALL26`/`JUMP26`, `R_X86_64_PLT32`,
`R_PPC_REL24`) with the field zeroed the way an assembler leaves it, but only when the instruction decodes to
exactly the target the analysis recorded; data operands (literal pools, RIP-relative loads) are left, so they
show as differences. ARM functions are Thumb when the decode contexts say so or when their address or size
cannot be A32's; a trailing partial instruction is cut. The PowerPC and Vita objects feed
`romwright-cli export-scratch --target-object` and the matching workspaces instead of objdiff.

**Smokes** (real images, `first:40`, nih-vps-u under load from other agents; wall times are not the import's
cost: Xenoblade's `main` is 420 s unloaded):

| image | platform | functions | import | C written | compiles | objdiff.json (clang objects vs retail bytes) |
| --- | --- | --- | --- | --- | --- | --- |
| Fire Emblem Fates `.code` (`--raw 0x100000 --language ARM:LE:32:v6 --map symbols.map`) | 3DS | 27,625 | 279 s | 38 (2 refused: the raw image has no `.bss`) | 37/38 | 36 units, 61 calls relocated, `build.py report` 16.1% overall |
| Xenoblade DE `main` (bare NSO) | Switch | 43,506 | 2023 s (420 s unloaded) | 40 | 40/40, also with the pinned clang | 40 units, 8 at 100%, 49.9% overall; build id `2e071b45...` recorded |
| Need for Speed Most Wanted `eboot.elf` (`--map EBOOT.BINMAP`) | Vita | 30,727 | 787 s | 40 | 33/40 | none (ARMv7); 39 calls relocated in the target objects; 580 `type:import` rows with NID-resolved names |
| AMPED 3 `default.xex` (`--map default.map`) | Xbox 360 | 35,573 | 947 s | 40 | 39/40 | none (PowerPC); target objects written |
| Crash Team Racing Nitro Fueled `game-ps4-prof.elf` (370 MB) | PS4 | 145,632 | 1327 s | 40 (562 s), 4.7 GB peak | 12/40 | 40 units, 19 calls relocated, 19.3% overall, best unit 90% |
| Persona 5 `SW.BIN` | PS3 | n/a | stops at `SELF metadata counts implausible` | | | encrypted retail SELF, no keys on the hosts |
| synthetic PowerPC64 ELF (clang + lld, 4 functions) | PS3 | 4 | 0.3 s | 4 | 3/4 | none; stands in for the missing decrypted image |

The compile failures are the decompiler's, not the scaffold's: 23 of PS4's 28 are 128-bit vector locals
(`temp._0_12_ = ZEXT812(0)`, an `unsigned char[16]` assigned or member-accessed), the rest `stack0x...`/`register0x...`
names and a few parse errors. The pinned toolchain was verified end to end: `build.py fetch` downloaded the
1.94 GB clang archive and objdiff-cli, checked both sha256, extracted, and `build.py` + `build.py report`
ran with them on the Switch scaffold. A tool bug found on the way: objdiff-cli 3.6.1 panics on a unit whose
compiled ARM function is empty (decompiled code ending in `halt_baddata()` compiles to nothing) and fails on a
missing object, so `build.py report` reports those units as target-only for that run.

**Limits.**
* Decompiled C is a reading aid: units fail to compile for missing struct definitions, 128-bit vector
  locals (`unsigned char[16]` assigned), `stack0x…`/`register0x…` names; the report lists each.
* PS3: the corpus image (`SW.BIN`, Persona 5) is an encrypted retail SELF; without keys the import stops at
  `SELF metadata counts implausible`, so no scaffold exists from it. The scaffold path was run on a synthetic
  decrypted PowerPC64 ELF (clang + lld) only.
* A bare `.code` (3DS) has no section table: one region. A Switch NCA/XCI gives one module per NSO but the
  build id is read only from a bare NSO. Retail-encrypted containers need your keys.
* Calls are relocated only where the analysis recorded a direct call/jump; objdiff percentages are a way to
  compare, not a gate. `romwright-cli match` and `swap` do not apply (there is no matching build).

## Windows PE (x86): per-function projects

`new-project` on a 32-bit Windows executable (EXE or DLL, PE32, machine `i386`) writes a **reccmp-style repository of
per-function units**. The platform is read from the headers (`MZ`, `PE\0\0`, machine `0x14C`, optional-header magic
`0x10B`) or given with `--platform pe`; a PE32+ (x86-64) is refused with that reason (no x64 compiler is pinned), an Xbox
360 PE (machine `0x1F2`) goes to the scaffold. The plugin is `new_project/pe.rs`, the CLI side
`crates/romwright-cli/src/new_project_pe.rs`.

```
romwright-cli new-project <image.exe> <outdir> [--name NAME] [--compiler ID] [--cflags "FLAGS"]
              [--decompile all|first:N|ADDR,ADDR|none] [--budget-ms N] [--toolchain PROFILE.json] [--manifest FILE]
              [--fact-pack PACK] [--json]
romwright-cli detect-compiler <image.exe> [--json]
```

**There is no whole-executable rebuild, and no sha1 to hit.** A PC game is linked from its own objects, the vendor's C
runtime and import libraries, in an order and with options nobody recovered, so (unlike every console in this document)
the image cannot be reproduced from the repository. What can be compared is one function against one function, with the
compiler of the right era; that is how reccmp projects work, and the repository is laid out for it. `build.py report`
therefore states **per-function matching status** (objdiff 100% = matched), not a checksum, and the README of every
generated project says so.

```
<outdir>/
  README.md              what was written, the compiler and why, how to read objdiff here, the limits
  configure.py           fetch the pinned compiler + wibo + objdiff-cli, write build/config.json (--compiler, --flags, --no-fetch)
  build.py               compile every unit; `report` (objdiff -> build/progress.{json,tsv}); `status`; one object for objdiff
  tools/download_tool.py sha256-verified fetch (the tool every project uses)
  config/
    project.json         image, compiler (tool, family, flags, the importer's verdict and why), per-unit rows; whole_image_rebuild: false
    functions.tsv        address, size, name, C name, convention (`__stdcall+12`), source, target object
    symbols.txt          functions, labels, imports (name = section:0xADDR; // type:...)
    toolchain.json       the pinned entries: wibo, objdiff-cli, every Visual C++ era (and the chosen compiler)
  include/               romwright_types.h (the decompiler's type spellings, `__int64` for MSVC), protos.h / romwright_protos.h
  src/main/<shard>/<fn>.c   romwright's C, one function per file: `NON_MATCHING`, `// FUNCTION: <PROJECT> 0xADDRESS` (reccmp's marker)
  orig/<image>           your retail executable (git-ignored)
  orig/target/main/<shard>/<fn>.obj   the retail bytes of the function as an i386 COFF object, relocations kept
  objdiff.json           one unit per function (target: orig/target, base: build/obj), custom_make `python3 build.py`
```

**The compiler.** The importer records an `msvc-N` id for a PE (`compiler/detect.rs`, `detect-compiler`): the optional
header's `MajorLinkerVersion.MinorLinkerVersion` is Microsoft's linker (4.x, 5.x, 6.0, 7.0, 7.10, 8.0 ... pair with
`cl` 10, 11, 12, 13.00, 13.10, 14 ...; the Xbox 360 rule in the same file uses the pairing), and a `Rich` header after the DOS
stub raises it from medium to high confidence. A `GCC: (...) x.y.z` string in the image is `mingw-gcc-<major>`. The
manifest pins five Visual C++ builds (all proprietary, hosted by the decomp.me compilers project's sources, sha256-pinned,
run through wibo): `msvc4.2` (cl 10.20.6166), `msvc6.0` (12.00.8168), `msvc7.0` (13.00.9466), `msvc7.1` (13.10.3077),
`msvc8.0` (14.00.50727.42). `msvc-10` is 4.2, `msvc-12` is 6.0, `msvc-13` is 7.0, `msvc-13.1` is 7.1, `msvc-14` is
8.0; Visual C++ 5.0 (`msvc-11`) and 2008 and later (`msvc-15`...) are not pinned, so the nearest pinned era stands in and
the README says so. A MinGW or unidentified PE gets the pinned clang (`--target=i686-pc-windows-msvc`) as a *compile check
only* (there is no pinned MinGW GCC yet); `--compiler msvc6.0` overrides any of it. The flags default to `/O2 /Gd /W0`; the
game's own flags go to `--cflags` (or `configure.py --flags`).

**Target objects.** `orig/target/**.obj` is the shape `cl.exe` writes: a `.text` section with its section symbol, the function
as an external of function type, one undefined external per relocation. Relocations are the ones a compiler would have
left: `REL32` for a `call`/`jmp rel32`/`jcc rel32` whose displacement lands on the transfer the analysis recorded and whose
destination is a recovered function, and `DIR32` for an absolute operand that names a function or a data location
(`DAT_<address>`, or the symbol the image names, such as an import's IAT slot). An operand romwright did not recognise
stays retail bytes and objdiff shows it as a difference; jump tables and string literals are among those.
`build.py` strips the compiler's decoration (`_f@12`, `@f@8`, `_f`) from the compiled object's symbols so both sides name the
function `f`.

**What the C is.** romwright's decompilation, with the calling conventions it recovered printed in the definitions and in
the declarations of callees (`__stdcall`, `__fastcall`; see "x86 C output" in [pc-project.md](pc-project.md)), the x87
`longdouble` spelled `long double`, and, for Visual C++, `long long` spelled `__int64` with `i64`/`ui64` literal suffixes
(its C has neither before 7.1). Visual C's C mode rejects `__thiscall` (error C4234), so the definition of a member function is
written `__fastcall` with an unused `edx` parameter after `this` (same prologue, same `ret N`); the callers of such a
function are not rewritten (the callee is undeclared there, so a caller's stack cleanup can differ).

Results: [pc-project.md](pc-project.md) (the smoke runs on a truth fixture and on KOTOR2). `match` works inside these
repositories: [match.md](match.md#windows-pe-projects).

## Where tools come from

romwright ships no tools and never downloads one. The generated project does,
as dtk-template does: `config/toolchain.json` pins each tool (url, sha256, size,
version, license, provenance) and `tools/download_tool.py` fetches into
`build/tools/`, checking the sha256 **before** extraction, refusing archive members
outside the install directory, and stopping on any mismatch. `file://` URLs work, so
a machine without network builds from local copies via `--manifest`.
A toolchain profile (`--toolchain`, the format in [toolchains.md](toolchains.md))
overrides tools one by one; the rest are still downloaded.

The table is data: `crates/romwright-core/src/new_project/toolchains.json`
(embedded at build time, validated by a unit test: https/file URLs, 64-digit
sha256, known archive kind, license and provenance present). Pinned on
2026-10-11:

| id | pinned | license | integrity |
| --- | --- | --- | --- |
| `binutils-mips-ps2-decompals` | decompals/binutils-mips-ps2-decompals v0.10 (linux-x86-64, macos-arm64, windows-x86-64) | GPL (GNU binutils 2.40 + patches; GitHub reports GPL-2.0, binutils itself is GPL-3.0+) | release publishes no digests; sha256 pinned from the downloaded assets |
| `wibo` | decompals/wibo 1.2.0 (linux x86_64/i686, macOS) | MIT | GitHub asset digests, same as pinned |
| `objdiff-cli` | encounter/objdiff v3.6.1 (linux x86_64/aarch64, macOS, Windows) | Apache-2.0 | GitHub asset digests, same as pinned |
| `clang-22.1.8` | llvm/llvm-project `llvmorg-22.1.8`, `LLVM-22.1.8-Linux-X64`/`Linux-ARM64`/`macOS-ARM64` `.tar.xz` (1.9 GB, 1.8 GB, 1.5 GB), used by the non-matching scaffolds | Apache-2.0 with LLVM exception | GitHub asset digests, same as pinned; `build.py fetch` downloaded, verified and extracted it (Linux x86-64, 3.4 GB on disk) and the Switch scaffold compiled 40/40 with it |
| 34 compilers: `mwcps2-*` (2.3 to 3.0.1 b210), `ee-gcc2.9-*`, `ee-gcc2.95.*`, `ee-gcc2.96`, `ee-gcc3.2-*` | decompme/compilers GitHub release `compilers` (the tag is mutable, assets are replaced individually) | MWCC: proprietary (Metrowerks); ee-gcc: GCC for the Emotion Engine is GPL, bundled assemblers/libraries may be proprietary Sony/SN software | digests exist for 3 assets only; the rest are pinned by hashing the bytes seen on 2026-10-11 |
| `ido5.3`, `ido7.1` | decompals/ido-static-recomp v1.2 (linux x86-64/aarch64, macOS) | IDO is SGI proprietary; the recompilation is a derived binary | release publishes no digests; sha256 pinned from the downloaded assets |
| `gcc2.7.2kmc` + `binutils-mips-2.6`, `gcc2.8.1pm` + `binutils-papermario` | decompals/mips-gcc-2.7.2 and mips-binutils-2.6 `main`, pmret/gcc-papermario and binutils-papermario `master` (linux, macOS) | GPL (the KMC compiler `gcc2.7.2kmc` stands in for is proprietary) | no digests; pinned from the downloaded assets |
| `maspsx` | mkst/maspsx commit 423ffc6 (the commit decomp.me pins), source zip | MIT | GitHub source archive, pinned |
| `psyq3.3` .. `psyq4.6` (9) | mkst/esa release `psyq-binaries` | PSY-Q is proprietary (SN Systems / Sony) | no digests; pinned from the downloaded assets |
| `psp-gcc-1.7.1`, `mwccpsp-3.0.1-219` | decompme/compilers release `compilers` | GPL; Metrowerks is proprietary | the 1.7.1 asset publishes a digest (it is the one pinned); the tag is mutable |
| `dtk` | encounter/decomp-toolkit v1.8.4 (linux x86_64/aarch64, macOS x86_64/arm64, Windows x86_64) | MIT OR Apache-2.0 | GitHub asset digests, same as pinned |
| `sjiswrap` | encounter/sjiswrap v1.2.2 (32-bit Windows exe, run through wibo) | MIT OR Apache-2.0 | GitHub asset digest, same as pinned |
| `mwcc-gc-wii-20251118` | `https://files.decomp.dev/compilers_20251118.zip` (the bundle dtk-template fetches; 77 MB; only `GC/` and `Wii/` are extracted: GC/1.0 to GC/3.0a5.2, Wii/1.0 to Wii/1.7, each with `mwcceppc.exe`, `mwldeppc.exe`, `mwasmeppc.exe`) | Metrowerks CodeWarrior: proprietary | the file is named by date; sha256 pinned from the bytes seen on 2026-10-14 |

Provenance of the PS2 compilers: decomp.me hosts them in its compilers project
(`decompme/compilers`, no license file; each `platforms/ps2/<id>/Dockerfile` downloads the
asset). The `mwcps2-3.0.1b210-060308` archive's `mwccps2.exe` and `mwldps2.exe`
are byte-identical to the Persona 4 CI kit's. Some ee-gcc archives are Windows
executables (run through wibo), others 32-bit Linux ELF (`runtime: i386-linux`),
which need a 32-bit loader at `/lib/ld-linux.so.2` and fail without it; the
manifest records which. dtk-template's `files.decomp.dev/compilers_<tag>.zip`
(77 MB for `20251118`) holds `GC`, `Wii`, `X360` and `ProDG` and no PS2 compilers.

The compilers are proprietary or of unverified build provenance. The manifest records
where each came from; it grants no right to use it, and the generated README says so.

## Compiler detection

`Core`-independent API: `romwright_core::new_project::compiler::detect_ps2_compiler(&[u8])`
(CLI: `detect-compiler`). PS2 images are mixed (a Metrowerks game links Sony's
ee-gcc-built libraries; `gcc2_compiled.` appears in four of the five MWCC images), so
evidence comes from what the *linker* wrote: `.comment` (`MW MIPS C Compiler (x.y.z.w)` is
the Metrowerks linker's stamp, `GCC: (GNU) x.y.z` a GNU one), section vocabulary
(`.mwcats`, `main`+`heap`, `.relmain`, DWARF 1 `.debug`+`.line` for mwld; `.mdebug`,
`.vutext`, `.DVP.*`, `.lit4` for the Sony ee toolchain; `.sndata` for SN ProDG) and
runtime-helper symbols when a symbol table exists. The result is a family, a version
*class* (not a proven build), a confidence, the evidence, splat's `compiler:` value and a
default manifest compiler. Crt0 bytes, prologue idioms and `sq`/`sd` statistics were
measured and do not separate the families (every PS2 image shares Sony's crt0; `sd $ra`
appears in both), so they are not used.

Measured over the eight PS2 corpus games with a `truth/meta.json`
(`tests/m23-001_new_project_ps2.py`, report `benchmarks/reports/m23-001_compiler_detection.md`):

| | result |
| --- | --- |
| family (mwcc-ps2 / ee-gcc / sn-prodg) | **7/8** |
| lineage (Metrowerks vs GNU/SN) | **8/8** |
| version class (in-sample: the classes were chosen after seeing this corpus) | 7/8 |
| suggested manifest compiler names the meta version | 6/8 |
| supplementary (Capcom Fighting Evolution: mwcc; dungeon-game: GNU 3.2.2) | 2/2 |

The miss is Ratchet & Clank PAL: its game code is SN ProDG 3.01 but the executable is
laid out exactly like the NTSC build (EE GCC 2.95.2), with no `.sndata`, so the evidence
cannot tell them apart. God Hand's SN ProDG is found through `.sndata`. Version
evidence is thin: the MWCC stamp names the linker (`2.3.1.01`, `2.4.1.01`), so
`mwcc-2.4` covers 2.4 through 3.0.x; Dark Chronicle (3.0) therefore gets the 3.0.1 b210
default, and ee-gcc images carry a version string only when `.comment` survives (the
3.2.2 dungeon image). The README of every generated project says the version is a default
for its evidence class.

### GameCube and Wii

`romwright_core::new_project::gc_compiler::detect_gc_compiler` (CLI `detect-compiler` on a DOL or a
disc). A DOL has no `.comment` and no symbol table, and the one thing every game links, Nintendo's
SDK, is built by Nintendo with whatever CodeWarrior Nintendo then shipped, not the studio's.
The evidence is the console (`RVL_SDK`/`Revolution OS` strings, a `0x80004000` load address),
the SDK library banners with build dates (`<< Dolphin SDK - OS release build: Nov 26 2003 ... >>`) and
`MetroTRK for Revolution v0.N`; the answer is an era class with a default compiler directory
of the compilers bundle, a confidence and the evidence. Rules (in-sample: the thresholds were chosen
after seeing this corpus): GameCube, latest banner before 2002-06 `GC/1.2.5n`, to 2003-03 `GC/1.3.2`,
to 2004-03 `GC/2.6`, to 2004-08 `GC/1.3.2` (low), after that `GC/3.0a5`; no banner `GC/1.3.2` (low).
Wii, TRK 0.1 to 0.3 or SDK before 2009 `GC/3.0a5`, TRK 0.4 or SDK 2009 `Wii/1.3`, SDK 2010 or later
`Wii/1.5`.

Measured against the `linker_version` of each game's decompilation project (the repository's main
compiler; read as data from the repos named in each image's `truth/meta.json`; most games mix
versions per library, so this is the dominant one):

| image | detected | repo | |
| --- | --- | --- | --- |
| Pikmin 2 | GC/2.6 | GC/2.6 | exact |
| Super Mario Strikers | GC/1.3.2 | GC/1.3.2 | exact |
| Melee | GC/1.3.2 (no banner) | GC/1.3.2 | exact |
| Wind Waker | GC/1.3.2 | GC/1.3.2 | exact |
| Twilight Princess | GC/3.0a5 | GC/3.0a5 | exact |
| Mario Strikers Charged | GC/3.0a5 | GC/3.0a5 | exact |
| Super Mario Galaxy | GC/3.0a5 | GC/3.0a5 | exact |
| Skyward Sword | Wii/1.5 | Wii/1.5 | exact |
| Pikmin | GC/1.3.2 (no banner) | GC/1.2.5 | same line |
| Tiger Woods 2004 | GC/2.6 | GC/2.5 (the repo finds 2.5 to 2.7 identical) | same line |
| Pikmin 2 (Wii) | GC/3.0a5 | GC/3.0a5.2 | same line |
| Rock Band 3 | Wii/1.5 | Wii/1.3 | same line |
| Mario Party 4 | GC/1.3.2 (no banner) | GC/2.6 | miss |

8 of 13 are the repository's exact directory, 12 of 13 its generation. Animal Crossing's DOL has no
banners either (default `GC/1.3.2`; its repository links with `GC/2.6`). The bundle's other builds
(`GC/1.2.5n`, `GC/2.0`, ...) are what to try when a function will not match: the detector narrows
to an era, not a build, and the README of every project says so.

## Platform matrix

`new-project --list-platforms` prints the same data (`platforms.rs`). Licenses are
those GitHub reports for the repository unless stated; "none" means the repository has no
license file (do not assume it is free to redistribute).

| platform | status | toolkit | next steps |
| --- | --- | --- | --- |
| PS2 | **implemented** | splat 0.39.1 (MIT), decompals PS2 binutils (GPL), ninja; MWCC PS2 / ee-gcc | none; see above |
| GameCube, Wii | **implemented** | decomp-toolkit v1.8.4 (MIT OR Apache-2.0), dtk-template layout (CC0-1.0), ninja; MWCC GC/1.0 .. 3.0a5.2 and Wii/1.0 .. 1.7 (proprietary, wibo); objdiff | none for a DOL or a disc's boot DOL and RELs; Animal Crossing's DOL needs a hand-written dtk config (below); REL symbols come from dtk's analysis, not romwright's names |
| N64 | **implemented** | splat 0.39.1 (MIT), decompals MIPS binutils (GPL), ninja; IDO 5.3/7.1 (ido-static-recomp), GCC 2.7.2 / 2.8.1 | none for raw code; compressed segments and overlays stay binary pieces, `.data/.rodata/.bss` are not split from the code segment; see above |
| PSX | **implemented** | splat 0.39.1 (MIT), maspsx (MIT), decompals MIPS binutils (GPL), ninja; PSY-Q 3.3 - 4.6 `CC1PSX` (proprietary, wibo) | none for a PS-X EXE; discs and overlay modules (`BODYPROG.BIN`, `MAP*.BIN`) are separate files, not routed; the PSY-Q generation is a window default |
| PSP | **implemented** | splat 0.39.1 (MIT), decompals MIPS binutils (GPL), ninja; psp-gcc 1.7.1 (GPL, i386) / mwccpsp 3.0.1 (proprietary, wibo) | the retail PRX relocation tables are carried verbatim (a C unit that moves code would need them re-emitted: not implemented); Allegrex-only instructions assemble as raw words; no `~PSP`/`EBOOT.PBP` packing |
| GBA | **implemented** | romwright's ARM/Thumb `.s` emitter (splat has no ARM), Arm GNU Toolchain 13.3.rel1 binutils + cpp (GPL), agbcc (pret/agbcc release binary), ninja | none for code that is in the cartridge image; RAM-copied or unpacked code stays bytes; see above |
| NDS | **implemented** | dsd v0.12.1 + ds-rom v0.8.0 (MIT), mwccarm/mwldarm (proprietary) through wibo, objdiff; romwright's symbols merged into dsd's config | decrypted dumps of games without DS Protect rebuild to the retail sha1; an encrypted dump needs the ARM7 BIOS, a build whose DS Protect ranges are not encrypted (the corpus HeartGold, pret's own build) does not relink to its own bytes; the ARM7 program stays a binary; see above |
| 3DS, Switch, PS4, Vita, Xbox 360 | **implemented (non-matching)** | no byte-matching ecosystem: pinned clang 22.1.8 (Apache-2.0 + LLVM exception) compile check, objdiff-cli 3.6.1 (Apache-2.0) for 3DS, Switch and PS4 | no byte-identical build exists; Vita and Xbox 360 have no objdiff.json (ARMv7 refused by objdiff; no PowerPC backend); a bare 3DS `.code` has one region; see the section above |
| Windows PE (x86) | **per-function** (a scaffold: no whole-image rebuild) | reccmp-style units: romwright's C + the era's Visual C++ (`msvc4.2`/`6.0`/`7.0`/`7.1`/`8.0`, proprietary, wibo) + objdiff-cli 3.6.1; i386 COFF target objects of the retail bytes | PE32 only (no x86-64), no pinned MinGW GCC (clang compile check), `__thiscall`/C++ units, no sha1 gate; see the section above |
| PS3 | **implemented (non-matching)**, blocked on the corpus image | same, no objdiff.json (no PowerPC64 backend) | the only PS3 image on the hosts (`SW.BIN`, Persona 5) is an encrypted retail SELF and stops at `SELF metadata counts implausible` without the user's keys; the scaffold ran on a synthetic decrypted PowerPC64 ELF only |

The non-matching scaffold (3DS, Switch, PS3, PS4, Vita, Xbox 360) is described in its own section above; the
per-platform limits are in `platforms.rs` and `--list-platforms`.

## Limits

* PS2: only ELF executables (or a disc whose `SYSTEM.CNF` names one) are routed; IRX/IOP
  modules and overlays are not. N64: ROMs; PlayStation: a PS-X EXE (not a disc); PSP: a decrypted ELF
  (not an `EBOOT.PBP` or a `~PSP` image).
* The C swap needs whole-function replacements. Data the C object emits is not linked.
* Compiler flags default to `-O2`; calibrating them per unit is the user's job
  (`--cflags` for the project, `config/project.json` after).
* `ee-gcc` Linux builds need a 32-bit loader; the Windows builds run through wibo.
* splat takes 30-120 s per split; a swap re-splits (its cache is `.splache`).
* GameCube/Wii: Animal Crossing's DOL (GAFE01) is not splittable by stock dtk: its `.init` has no
  `_eti_init_info` where dtk looks, and its decompilation repository needs `symbols_known`, a custom
  `ldscript_template`, `common_start` and block/add-relocation lists; `new-project` stops at `dtk dol
  split` for it. Per-REL symbols come from dtk's analysis (romwright's names inside RELs are not
  exported), and on Twilight Princess about half of the RELs rebuild byte for byte (`ninja rels`
  says which; the others differ in one `.dtors` relocation). `match` and `swap` work on DOL
  functions only. The newer `mwldeppc.exe` builds crash under wibo on a `.comment` older than
  their own (the project writes the matching version, `gc::comment_version`).
