# Getting started

A walkthrough from a checkout to a decompiled function, using the fixture
binary committed in this repository. Every command below is executed by
`tests/m6-001_documented_workflow.py`, and every output line printed under a
command is matched against what the command actually prints — if this page
drifts from the tool, that gate fails.

`$PROJECT` is the project directory the walkthrough writes to; use any path,
for example `/tmp/ventris-demo`.

## What needs what

| Step | Needs |
|---|---|
| `import`, `functions`, `symbols`, `strings`, `xrefs`, `search`, `rename`, `bookmark`, `patch` | nothing beyond the built binary |
| `disasm`, `decompile`, `decompile-doc` | the pinned Ghidra install for **SLEIGH language data** (`VENTRIS_GHIDRA`, default `~/ghidra_12.1.3_PUBLIC`) and the native console (`native/build_console.sh`) |
| anything with `--oracle` | a Java runtime and the Stage-1 bridge; used only to generate comparison oracles |

**No step starts a JVM** unless you pass `--oracle`. The native decompiler
reads SLEIGH language data as data; it does not run Ghidra.

Discovery uses the SLEIGH console when it is available, so an import made
without the pinned install recovers fewer functions than one made with it —
the console is what proves a byte pattern is a function start. Both imports
are honest; the smaller one simply had less evidence.

## Build

```console
$ cargo build --release -p lre-cli
```

## Import a binary

Import parses the image, discovers functions through flow, and writes facts
into a SQLite project. Nothing is invented: every fact carries its producing
pass as provenance.

```console
$ ./target/release/lre-cli import tests/fixtures-src/tiny_bin --name tiny --project $PROJECT
imported tiny natively
```

## Read the program model

Functions, with entry, size and name:

```console
$ ./target/release/lre-cli functions tiny --project $PROJECT
00400466      20  add
0040047a      43  main
```

Imported symbols, with the pass that recorded each one:

```console
$ ./target/release/lre-cli symbols tiny --project $PROJECT
00402fd8  EXT       native-import  __libc_start_main
```

Strings, with their encoding:

```console
$ ./target/release/lre-cli strings tiny --project $PROJECT
00401000  [ASCII]  /lib64/ld-linux-x86-64.so.2
```

References to an address, each with its kind and provenance:

```console
$ ./target/release/lre-cli xrefs tiny --to 00400466 --project $PROJECT
004011a8 --DATA--> 00400466 [inferred; source=native-import:elf-unwind; confidence=unknown]
```

The same references, restricted to what the image itself declares. `--evidence`
takes `declared`, `decoded` or `inferred`, and the store applies it, so nothing
is fetched to be thrown away:

```console
$ ./target/release/lre-cli xrefs tiny --to 00400466 --evidence declared --project $PROJECT
004011a8 --DATA--> 00400466 [inferred; source=native-import:elf-unwind; confidence=unknown]
```

Search names and symbols:

```console
$ ./target/release/lre-cli search tiny add --project $PROJECT
00400466  [function]  add
-- 1 search hits
```

## Annotate

A rename is a durable fact, and `undo` reverses it:

```console
$ ./target/release/lre-cli rename tiny 00400466 demo_add --project $PROJECT
renamed 00400466 -> demo_add
$ ./target/release/lre-cli functions tiny --project $PROJECT
00400466      20  demo_add
$ ./target/release/lre-cli undo tiny --project $PROJECT
undid rename seq 1 (00400466 -> add)
$ ./target/release/lre-cli functions tiny --project $PROJECT
00400466      20  add
```

Bookmarks carry a label and an optional comment:

```console
$ ./target/release/lre-cli bookmark tiny 00400466 hot checked --project $PROJECT
bookmarked 00400466 -> hot
$ ./target/release/lre-cli bookmarks tiny --project $PROJECT
00400466  hot  checked
-- 1 bookmarks
```

## What the SLEIGH console adds

With the console available the same import proves more: `printf`'s linkage
stub becomes a function, function extents come from flow rather than from the
next entry, and the call into `add` is recorded as a reference.

<!-- requires: sleigh -->

```console
$ ./target/release/lre-cli import tests/fixtures-src/tiny_bin --name flowed --project $PROJECT
imported flowed natively (12 functions, x86:LE:64:default)
$ ./target/release/lre-cli functions flowed --project $PROJECT
00400370       6  printf
$ ./target/release/lre-cli xrefs flowed --to 00400466 --project $PROJECT
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
$ ./target/release/lre-cli disasm tests/fixtures-src/tiny_bin 00400466 -n 4
0x00400466: PUSH      RBP
0x00400467: MOV       RBP,RSP
$ ./target/release/lre-cli decompile tests/fixtures-src/tiny_bin 00400466 --name tiny --project $PROJECT
int add(int param_1,int param_2){return param_2 + param_1;}
```

`decompile-doc` prints the same function as a structured document — tokens
with their kinds, the recovered prototype, jump tables and storage — for a UI
or a script that needs more than text.

## Where the numbers live

Every gate writes a report under `benchmarks/reports/`, and the README
evidence index is generated from those files. `STATUS.md` records the current
milestone and the next task. Nothing in either is written by hand except the
prose around the generated tables.
