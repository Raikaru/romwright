# Romwright

Romwright is a reverse-engineering tool for console games and Windows PC
games. It runs Ghidra's SLEIGH processor models and C++ decompiler natively, as
compiler technology, over a SQLite store that records where every fact came
from.

What it does:

- **Import** a retail image (ELF, DOL and discs, N64/GBA/NDS ROMs, PS-X EXE,
  PSP/PS3/Vita/3DS/Switch/Xbox 360 containers, PE) and find its functions,
  references, strings and types.
- **Decompile** to C meant to compile again with the game's own compiler.
- **`new-project`**: write a decompilation repository that builds with the
  game's compiler and checks every function against the retail bytes.
- **`match`**: search the ways one function can be printed for the C the
  repository's compiler turns into the retail bytes.
- A **desktop workstation** (Rust, egui/wgpu) over the same core, plus a
  versioned stdio/HTTP API and a Python SDK.

## Results

Measured against stock Ghidra 12.1.3 on the same images and the same symbol
truth (`STATUS.md`, "Finish gate"; the reports are listed in
[docs/evidence.md](docs/evidence.md)). Finding functions on 53 console games,
Romwright's recall is higher on 51 and tied on 2; its precision is higher on
15, tied on 36 and lower on 2. On 8 Windows PC fixtures its recall is higher
on all 8.

| Measurement | Romwright | Stock Ghidra |
|---|---|---|
| PS2 C, 200 matched Persona 4 functions: byte-exact | 56 | 7 |
| PS2 C, same 200: compiles | 196 | 109 |
| PS2 C, same 200: mean objdiff match | 78.0% | 37.1% |
| Peak memory, tiny ELF import (median) | 36,090 KiB | 423,274 KiB |

The import runs structural discovery tuned for compiled game code, which is
where its speed and memory come from
([docs/measurements.md](docs/measurements.md)).

## Platforms

| Platform | `new-project` writes |
|---|---|
| PlayStation 2 | splat repository; `ninja` rebuilds the retail ELF byte for byte |
| GameCube, Wii | decomp-toolkit repository (DOL and RELs), byte-identical rebuild |
| Nintendo 64, PlayStation, PSP | splat repository, byte-identical rebuild |
| Game Boy Advance, Nintendo DS | ARM/Thumb units (GBA) or a ds-decomp project (NDS), byte-identical rebuild |
| 3DS (armcc) | per-function matching repository built with Nintendo's armcc; `tools/relink.py` relinks the retail `.code` with GNU ld from the matched functions |
| Switch, PS3, PS4, Vita, Xbox 360 | C per function, target objects and an objdiff project |
| Windows PE (i386) | per-function repository built with the era's Visual C++ |

`--keys` takes your own keys for encrypted containers. Per platform:
[docs/new-project.md](docs/new-project.md); per input format:
[docs/support-matrix.md](docs/support-matrix.md).

## Quick start

Download a release, or build from source with one command.

**Download a release.** Take `romwright-<version>-<os>-<arch>.zip` (Windows) or
`.tar.gz` (Linux, macOS) from the
[releases page](https://github.com/Raikaru/romwright/releases), unpack it
anywhere, and run `bin/romwright-cli` (put `bin/` on `PATH` to run it from any
directory). The archive carries the worker, the patched decompiler, the
language specs and the Ghidra 12.1.3 language data, found relative to the
executable (`bin/romwright-cli paths` shows where).

**Or build from a source checkout, with one command:**

<!-- not gated: builds native components whose toolchains are host-specific; setup.py ends by decompiling tests/fixtures-src/tiny_bin and checking the output -->
```sh
python setup.py        # python3 on Linux and macOS; standard library only
```

`setup.py` checks the prerequisites and names what is missing and how to get it
(Rust via [rustup](https://rustup.rs); a C++11 compiler, `make`, zlib and `git`;
on Windows [MSYS2](https://www.msys2.org) MinGW64 with `mingw-w64-x86_64-gcc
mingw-w64-x86_64-make mingw-w64-x86_64-zlib`, and Git for Windows), downloads
the pinned Ghidra 12.1.3 release once (checksum-verified, cached, only its
language data kept in `build/ghidra`), builds `native/build/ghidra_opt` and
`cargo build --release -p romwright-cli -p romwright-worker`, then imports
`tests/fixtures-src/tiny_bin` and decompiles `00400466` as a smoke test. A rerun
skips what is done. The options and what is read where:
[docs/environment.md](docs/environment.md).

`romwright-cli import <binary>` imports natively; `--oracle` (with
`--ghidra DIR`) runs the Ghidra bridge to produce comparison oracles.

<!-- not gated: illustrates the surfaces documented and executed by docs/getting-started.md -->
```sh
./target/release/romwright-cli import game.elf --name game --project ./proj
./target/release/romwright-cli functions game --project ./proj
./target/release/romwright-cli decompile game.elf 00100008 --name game --project ./proj
```

A matching project, on the repository's PE32 fixture with clang as the
compile check (the same commands run in
[docs/getting-started.md](docs/getting-started.md)):

<!-- not gated: the same commands are executed on this fixture by docs/getting-started.md through tests/m6-001_documented_workflow.py -->
```sh
./target/release/romwright-cli new-project tests/fixtures-src/tiny_pe32.exe repo \
    --toolchain tests/fixtures-src/pe_clang_profile.json --decompile none
python3 repo/configure.py
./target/release/romwright-cli match 0x00401420 --project repo --budget 4
```

The byte-matching repositories fetch their pinned compilers with
`python3 configure.py` (or `build.py fetch`), checking every sha256. The
desktop (`romwright-desktop`) does the same from the open image: Program
setup > Create project, and the Match panel.

## Documentation

| Page | Covers |
|---|---|
| [getting-started.md](docs/getting-started.md) | build, import, read, annotate, decompile, start a matching project (executed by `tests/m6-001_documented_workflow.py`) |
| [overview.md](docs/overview.md) | architecture, repository layout, build, API and SDK, debugger, end-to-end CLI use |
| [new-project.md](docs/new-project.md), [match.md](docs/match.md), [pc-project.md](docs/pc-project.md) | projects per platform, the near-miss search, Windows PC games |
| [desktop.md](docs/desktop.md) | the desktop workstation, its panels and gates |
| [core-api.md](docs/core-api.md), [scripting.md](docs/scripting.md) | the stdio/HTTP API and the Python SDK |
| [releasing.md](docs/releasing.md) | build, package, SBOM, manifest, verify |
| [environment.md](docs/environment.md), [toolchains.md](docs/toolchains.md), [third-party.md](docs/third-party.md) | every `ROMWRIGHT_*` variable, user-owned toolchains, vendored sources and licences |
| [measurements.md](docs/measurements.md), [evidence.md](docs/evidence.md), [support-matrix.md](docs/support-matrix.md) | the measured gate claims, the index of every report, support per input format |
| [types-port.md](docs/types-port.md), [printer-ir.md](docs/printer-ir.md), [merge-port.md](docs/merge-port.md), [structs.md](docs/structs.md) | the decompiler's stage ports: types and symbol layout, the print tree, merge, struct recovery |
| [compiler-rules.md](docs/compiler-rules.md), [console-research.md](docs/console-research.md), [c-output-lanes.md](docs/c-output-lanes.md) | import precision rules, the console and PC measurements, the C-output lanes |
| [import-speed.md](docs/import-speed.md), [ownership.md](docs/ownership.md), [fact-pack.md](docs/fact-pack.md), [vsig.md](docs/vsig.md), [n64-segments.md](docs/n64-segments.md) | import speed, ownership, fact packs, signature databases, N64 segment layouts |
| [structuring-baseline.md](docs/structuring-baseline.md), [upstream-ghidra.md](docs/upstream-ghidra.md), [assumptions.md](docs/assumptions.md), [game-decomp-plan.md](docs/game-decomp-plan.md) | structuring baseline, the pinned Ghidra, standing assumptions, the decomp plan |

`STATUS.md` is the running log: every milestone, measurement and open item.

## Licence

Apache-2.0 ([LICENSE](LICENSE), [NOTICE](NOTICE)). Vendored Ghidra sources and
other third-party components: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
