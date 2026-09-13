# The desktop workstation

`desktop/romwright-qt` is a Qt 6 Widgets workstation over the same Core API the
CLI and scripts use. It links the core as a static Rust library, so a launched
window needs no helper process and no JVM.

## Build and package

Qt 6.4 or newer with the Widgets and Concurrent modules, CMake 3.21, a C++17
compiler, and `cargo` for the bridge library.

```console
$ cmake -S desktop/romwright-qt -B build/romwright-qt -DCMAKE_BUILD_TYPE=Release
$ cmake --build build/romwright-qt --config Release --target romwright-qt
$ cmake --build build/romwright-qt --config Release --target package
```

The `package` target writes a CPack `TGZ` named
`romwright-<version>-<system>-<machine>.tar.gz` beside the build tree. Extract it
anywhere; the archive carries the executable, and the executable carries the
core.

## Launch

<!-- not gated: opens a window against a user's own project; the packaged
     launch is gated offscreen by tests/m6-003_desktop_package.py -->

```sh
romwright-qt --project DIR --name PROGRAM --binary PATH
```

`--project` is the SQLite project the CLI writes; a program imported by
`romwright-cli import` opens directly. Panels read the store: functions, symbols,
references, strings, listing, graph, types, patches, bookmarks and jobs. Edits
go through the same journalled commands as the CLI, so `undo` reverses a rename
made in either.

Decoding and decompiling need SLEIGH language data from the pinned Ghidra
install, exactly as they do on the command line
(`docs/getting-started.md`). Everything that reads the store works without it.

## What the gate proves

`tests/m6-003_desktop_package.py` builds the archive with the three commands
above, extracts it into a clean prefix, and launches the *extracted* binary
offscreen with **every `ROMWRIGHT_*` variable removed**. The app then reports two
facts it measures itself:

| Metric | Meaning |
|---|---|
| `ui.install.prefix_ok` | the executable is not running from a build tree |
| `ui.install.store_only_ok` | the store-facing workflow completed with no `ROMWRIGHT_*` variable set |

Both are false when they should be: a build-tree binary reports
`prefix_ok: false`, and setting any `ROMWRIGHT_*` variable reports
`store_only_ok: false`.

The older `ui.install.ok` metric in `benchmarks/reports/ui-gate.json` is not
measured — the app reads it from `ROMWRIGHT_UI_INSTALL_OK`, which the harness
sets. It is left in place because changing a metric definition is reserved to
the human; `STATUS.md` records the proposal to retire it.

The gate reports the platform it ran on, so the evidence names its own
coverage: the CI `qt` job runs it on Linux, macOS and Windows, and a local run
covers only that machine.

## Filtering by evidence

The Xrefs dock carries an evidence selector: **All evidence**, `declared`,
`decoded` or `inferred`. The store applies the filter, so the row count is
the service's answer rather than a client-side pass over rows already
fetched. The UI gate records 13 declared of 19 rows on `libc`
(`ui.xrefs.declared_rows`, `ui.xrefs.rows`), and `tests/m9-004_filter_surfaces.py`
checks the window against the service at the address it opened.
