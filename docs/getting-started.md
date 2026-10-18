# Getting started

A walkthrough from a checkout to a decompiled function, using the fixture
binary committed in this repository. Every command below is executed by
`tests/m6-001_documented_workflow.py`, and every output line printed under a
command is matched against what the command actually prints — if this page
drifts from the tool, that gate fails.

`$PROJECT` is the project directory the walkthrough writes to; use any path,
for example `/tmp/romwright-demo`.

## What needs what

| Step | Needs |
|---|---|
| `import`, `functions`, `symbols`, `strings`, `xrefs`, `search`, `rename`, `bookmark`, `patch` | nothing beyond the built binary |
| `disasm`, `decompile`, `decompile-doc` | the pinned Ghidra **SLEIGH language data** (`build/ghidra`, extracted by `python setup.py`; `ROMWRIGHT_GHIDRA` or `~/ghidra_12.1.3_PUBLIC` also work); `decompile` and `decompile-doc` also the native decompiler (`native/build/ghidra_opt`, built by `setup.py` or `native/build_ghidra_opt.sh`) |
| `detect-compiler` | nothing beyond the built binary (it reads the image's bytes) |
| `new-project` | the SLEIGH data like `import` (it imports the image); `python3` for the repository's own scripts. romwright downloads no tool: the repository's `configure.py` fetches the pinned ones |
| `match` | the native decompiler, and the repository's compiler (installed by its `configure.py`, or a profile naming one you have) |
| anything with `--oracle` | a Java runtime and the Stage-1 bridge; used only to generate comparison oracles |

**No step starts a JVM** unless you pass `--oracle`. The native decompiler
reads SLEIGH language data as data; it does not run Ghidra.

Discovery uses the in-process SLEIGH decoder when the pinned install supplies
its language data, so an import made without the install recovers fewer
functions than one made with it — the decoder is what proves a byte pattern
is a function start. Both imports
are honest; the smaller one simply had less evidence.

## Build

From a fresh checkout, one command checks the prerequisites, downloads and
verifies the Ghidra 12.1.3 language data (into `build/ghidra`), builds
`native/build/ghidra_opt`, runs the `cargo build` below and decompiles the
fixture as a smoke test (`docs/environment.md`, "One command"). A release
archive needs none of this: unpack it and use `bin/romwright-cli`, which
finds everything relative to itself. `romwright-cli paths` prints where it
looks and whether each file exists.

<!-- not gated: builds native components and downloads Ghidra; the walkthrough below is what is gated -->
```sh
python setup.py        # python3 on Linux and macOS
```

The Rust part on its own:

```console
$ cargo build --release -p romwright-cli
```

## Import a binary

Import parses the image, discovers functions through flow, and writes facts
into a SQLite project. Nothing is invented: every fact carries its producing
pass as provenance.

```console
$ ./target/release/romwright-cli import tests/fixtures-src/tiny_bin --name tiny --project $PROJECT
imported tiny natively
```

## Read the program model

Functions, with entry, size and name:

```console
$ ./target/release/romwright-cli functions tiny --project $PROJECT
00400466      20  add
0040047a      43  main
```

Imported symbols, with the pass that recorded each one:

```console
$ ./target/release/romwright-cli symbols tiny --project $PROJECT
00402fd8  EXT       native-import  __libc_start_main
```

Strings, with their encoding:

```console
$ ./target/release/romwright-cli strings tiny --project $PROJECT
00401000  [ASCII]  /lib64/ld-linux-x86-64.so.2
```

References to an address, each with its kind and provenance:

```console
$ ./target/release/romwright-cli xrefs tiny --to 00400466 --project $PROJECT
004011a8 --DATA--> 00400466 [inferred; source=native-import:elf-unwind; confidence=unknown]
```

The same references, restricted to what the image itself declares. `--evidence`
takes `declared`, `decoded` or `inferred`, and the store applies it, so nothing
is fetched to be thrown away:

```console
$ ./target/release/romwright-cli xrefs tiny --to 00400466 --evidence declared --project $PROJECT
004011a8 --DATA--> 00400466 [inferred; source=native-import:elf-unwind; confidence=unknown]
```

A project can hold several images, and they overlap: `locate` names each
program mapping an address, and `--follow` prints what that image holds there.

<!-- not gated: the walkthrough imports one image, and the interesting answer
     needs two; `tests/m10-002_image_navigation.py` drives this command. -->

```sh
romwright-cli locate 00401000 --follow --project $PROJECT
```

Search names and symbols:

```console
$ ./target/release/romwright-cli search tiny add --project $PROJECT
00400466  [function]  add
-- 1 search hits
```

## Annotate

A rename is a durable fact, and `undo` reverses it:

```console
$ ./target/release/romwright-cli rename tiny 00400466 demo_add --project $PROJECT
renamed 00400466 -> demo_add
$ ./target/release/romwright-cli functions tiny --project $PROJECT
00400466      20  demo_add
$ ./target/release/romwright-cli undo tiny --project $PROJECT
undid rename seq 1 (00400466 -> add)
$ ./target/release/romwright-cli functions tiny --project $PROJECT
00400466      20  add
```

Bookmarks carry a label and an optional comment:

```console
$ ./target/release/romwright-cli bookmark tiny 00400466 hot checked --project $PROJECT
bookmarked 00400466 -> hot
$ ./target/release/romwright-cli bookmarks tiny --project $PROJECT
00400466  hot  checked
-- 1 bookmarks
```

## What the SLEIGH decoder adds

With the language data available the same import proves more: `printf`'s linkage
stub becomes a function, function extents come from flow rather than from the
next entry, and the call into `add` is recorded as a reference.

<!-- requires: sleigh -->

```console
$ ./target/release/romwright-cli import tests/fixtures-src/tiny_bin --name flowed --project $PROJECT
imported flowed natively (12 functions, x86:LE:64:default)
$ ./target/release/romwright-cli functions flowed --project $PROJECT
00400370       6  printf
$ ./target/release/romwright-cli xrefs flowed --to 00400466 --project $PROJECT
00400488 --UNCONDITIONAL_CALL--> 00400466 [inferred; source=native-import; confidence=unknown]
-- 2 xrefs
```

Without it, the same command reports eleven functions and one reference: less
evidence, and the store says so rather than guessing.

## Disassemble and decompile

These read SLEIGH language data from the pinned install; they still start no
JVM.

<!-- requires: sleigh -->

```console
$ ./target/release/romwright-cli disasm tests/fixtures-src/tiny_bin 00400466 -n 4
0x00400466: PUSH      RBP
0x00400467: MOV       RBP,RSP
$ ./target/release/romwright-cli decompile tests/fixtures-src/tiny_bin 00400466 --name tiny --project $PROJECT
int add(int param_1,int param_2)

{
  return param_2 + param_1;
}
```

`decompile-doc` prints the same function as a structured document — tokens
with their kinds, the recovered prototype, jump tables and storage — for a UI
or a script that needs more than text.

Three companion binaries disassemble coprocessor blobs without a
project: `gte_dump`, `rsp_dump` and `vu_dump` each take a raw binary
file and print one `mnemonic operands` line per instruction for the
PSX GTE, N64 RSP and PS2 VU macro sets respectively.

## Start a matching project

`new-project` turns a retail image into a repository to decompile it in, and
`match` searches the ways the decompiler can print one function for the C that
the repository's compiler turns into the retail bytes. Every platform romwright
imports has a plugin; the shapes are byte-matching (PlayStation 2, GameCube and
Wii, Nintendo 64, PlayStation, PSP, Game Boy Advance, Nintendo DS), non-matching
scaffold (3DS, Switch, PS3, PS4, Vita, Xbox 360) and per-function (Windows PE
x86); `docs/new-project.md` has one section per platform, `docs/pc-project.md`
the Windows PE fixtures and results, and `docs/match.md` what `match` varies and
measured.

```console
$ ./target/release/romwright-cli new-project --list-platforms
pe      Windows PE (x86)       Scaffold
ps2     PlayStation 2          Implemented
gba     Game Boy Advance       Implemented
3ds     Nintendo 3DS           Scaffold
```

`detect-compiler` names the compiler the image was built with and the evidence
(the fixture is a MinGW-built PE32):

```console
$ ./target/release/romwright-cli detect-compiler tests/fixtures-src/tiny_pe32.exe
platform:   Windows PE (i386)
compiler:   mingw-gcc-15 (Medium confidence)
```

The repository below is the PC shape, because it is the one whose compile
check needs no proprietary tool: `--toolchain` names a profile
(`{"clang": "clang"}`, here the host's clang) instead of the compiler the
manifest pins, and `--decompile none` writes no C yet. The fixture's functions
are the importer's, so the count depends on the SLEIGH data like the import
above. A byte-matching platform is the same two commands with a retail image
and, for the first run, `python3 configure.py` fetching the pinned tools
(sha256-checked; romwright ships none):

<!-- requires: sleigh -->

```console
$ ./target/release/romwright-cli new-project tests/fixtures-src/tiny_pe32.exe $PROJECT-repo --toolchain tests/fixtures-src/pe_clang_profile.json --decompile none
per-function PE project (131 functions
next: cd
```

`configure.py` writes the repository's build configuration, and `match` prints
the function in alternative ways (here `--budget 4` of them), compiles each with
the repository's compiler and scores it against the retail bytes. `match`
decompiles, so it needs the native decompiler like `decompile` does; the score
column is *equal instruction words* here, an objdiff percent when
`objdiff-cli` is installed, and says nothing about the original compiler:

<!-- requires: sleigh clang -->

```console
$ python3 $PROJECT-repo/configure.py
configured: clang-22.1.8 (clang)
$ ./target/release/romwright-cli match 0x00401420 --project $PROJECT-repo --budget 4
FUN_00401420 0x401420 (164 bytes)
best: default
```

`match --write` stores the best variant's C in the repository for
`configure.py swap` (byte-matching platforms) or `build.py` (PE) to build. The
desktop's Program setup panel (**Create project**) and Match panel do the same
from the open image (`docs/desktop.md`).

## Where the numbers live

Every gate writes a report under `benchmarks/reports/`, and the evidence index
([evidence.md](evidence.md)) is generated from those files. `STATUS.md` records the current
milestone and the next task. Nothing in either is written by hand except the
prose around the generated tables.
