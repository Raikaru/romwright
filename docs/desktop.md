# The desktop workstation

`romwright-desktop` (`crates/romwright-desktop`) is the Romwright workstation:
an egui shell rendered by wgpu (Vulkan, Metal or DX12; no OpenGL), calling
`romwright_core::Core` directly on worker threads. It links the Core
statically and embeds its fonts, so a launched window needs no JVM and no
runtime data beside the `romwright-worker` it decompiles through.

## Build and package

A Rust toolchain of at least 1.95 (the egui/eframe minimum) is the only
requirement; there is no C++ toolchain or UI framework to install.

```console
$ cargo build --profile dist -p romwright-desktop -p romwright-worker -p romwright-cli
$ python3 packaging/package_desktop.py --output build/desktop-package
```

`package_desktop.py` runs the same `cargo build --profile dist` (the shipping
profile of `Cargo.toml`; pass `--no-build` to package
an existing one; it reads `$CARGO_TARGET_DIR` when set) and writes
`romwright-<version>-<system>-<machine>.tar.gz`. The archive holds one
top-level directory with `bin/romwright-desktop`, `bin/romwright-worker`,
`bin/romwright-cli`, and `share/doc/romwright/` carrying `LICENSE`, `NOTICE`,
`THIRD_PARTY_NOTICES.md` and the SIL OFL licences of the bundled Inter and
JetBrains Mono fonts. Extract it anywhere: the app finds the worker and the
CLI beside itself (the CLI is what **Create project** runs), the desktop
executable carries the core, and the CLI carries the `new-project` templates
and the tool manifest it writes into a repository. `docs/releasing.md` stages
the archive with the other release artifacts.

## Launch

<!-- not gated: opens a window against a user's own project; the packaged
     launch is gated offscreen by tests/m6-003_desktop_package.py -->

```sh
romwright-desktop --project DIR --program PROGRAM --binary PATH [--address HEX] [--theme NAME]
```

| Flag | Meaning |
|---|---|
| `-p`, `--project DIR` | SQLite project directory (default `.romwright`) |
| `-n`, `--program NAME` | program to open |
| `-b`, `--binary PATH` | binary path (the gate imports it) |
| `-a`, `--address HEX` | initial address for the listing, decompiler and references |
| `--theme NAME` | `system`, `dark`, `light` or `contrast` |
| `--gate`, `--store-only` | offscreen UI gate (below) |
| `--project-image IMAGE` | with `--gate`: also gate Program setup's new project and the Match panel on this image (below) |
| `--matching-gate CONFIG.json` | offscreen matching workflow gate (below) |
| `--screenshot PATH` | render offscreen until idle and write one PNG |
| `--panel ID` | with `--screenshot`: raise that panel first; repeatable |
| `--size WxH`, `--scale F` | offscreen size in points (default 1440x900) and pixels per point (default 1) |
| `--timeout SECONDS` | screenshot idle wait (default 120); matching gate limit (default 60) |

`--project` is the SQLite project the CLI writes; a program imported by
`romwright-cli import` opens directly. Panels read the store: Functions,
Listing, Decompiler, Graph, Xrefs, Facts (symbols, strings, search), Types,
Memory, Analyst (bookmarks and patches), Vtables, Jobs, Program setup and
Match, plus the Matching workspace. Edits go through the same journalled
commands as the CLI, so `undo` reverses a rename made in either.

Decoding and decompiling need SLEIGH language data from the pinned Ghidra
install, exactly as they do on the command line
(`docs/getting-started.md`). Everything that reads the store works without it.

### Themes and settings

The theme follows the system light/dark preference unless `--theme` or
**View → Theme** chooses `dark`, `light` or `contrast` (high contrast). Every
panel takes its colours, fonts and sizes from the shared theme. The theme,
recent projects and per-program dock layouts persist in
`$XDG_CONFIG_HOME/romwright/desktop.json` (`%APPDATA%` on Windows,
`~/.config` when neither is set). Contributors adding panels follow
`crates/romwright-desktop/PANELS.md`.

## Headless rendering

`--gate`, `--matching-gate` and `--screenshot` render the real window through
wgpu into an offscreen texture: no window, no display server. The app asks
for a hardware adapter first and falls back to the platform's software
adapter, so a machine without a GPU still renders:

| Platform | Software adapter |
|---|---|
| Linux | Mesa lavapipe (Vulkan), from `mesa-vulkan-drivers` |
| Windows | WARP through DX12, part of Windows |
| macOS | Metal (every supported Mac has a Metal device) |

Each headless mode prints the adapter it chose on stderr
(`ui gate: rendering offscreen on llvmpipe (LLVM ...) (Vulkan)` with
lavapipe). To force lavapipe on a machine that also has a GPU, point the
Vulkan loader at its manifest:

<!-- not gated: needs Mesa's lavapipe manifest at a distribution-specific
     path; CI runs the gate on a GPU-less runner instead -->

```sh
VK_DRIVER_FILES=/usr/share/vulkan/icd.d/lvp_icd.x86_64.json \
  romwright-desktop --screenshot shot.png --project DIR --program PROGRAM --theme dark
```

The gate renders and waits on a frame between every poll of the app, so
`ui.list.load_ms` and `ui.list.filter_ms` include about two frames each. On
WARP a 1440x900 frame is CPU rasterising and takes 100 ms or more, so
`tests/m6-003_desktop_package.py` holds a WARP run to 1500 ms for both and every
other adapter to the 500 ms and 100 ms thresholds; its header has the
measurements.

## The UI gate

`--gate` drives the real shell and panels and prints one
`{"metrics": {...}}` line, the format `benchmarks/ui_gate.py` parses: the
decompiler source and graph interaction checks (`ui.source.*` and the graph
selection/self-loop booleans), import, function list
load and filter, decompiler/listing sync, graph fetch/layout/paint, xrefs,
program switching, install and analysis metrics. `--store-only` stops after
the list and filter.

`benchmarks/ui_gate.py` runs it against `--app` (default
`$ROMWRIGHT_DESKTOP_APP`, then `$CARGO_TARGET_DIR/release/romwright-desktop`,
then `target/release/romwright-desktop`), aggregates `--runs` samples and
checks them against the frozen thresholds.
`tests/filter_latency.sh`, `tests/largest_graph_desktop.sh` and
`tests/package_install_smoke.sh` are focused wrappers over it.

### What the gate proves

`tests/m6-003_desktop_package.py` builds the archive with the packaging
command above, extracts it into a clean prefix, and launches the *extracted*
binary headless with **every `ROMWRIGHT_*` variable removed**. The app then
reports two facts it measures itself:

| Metric | Meaning |
|---|---|
| `ui.install.prefix_ok` | the executable is not running from a cargo build tree (no `.fingerprint`, `deps` + `build` or `CACHEDIR.TAG` beside it) |
| `ui.install.store_only_ok` | the store-facing workflow completed with no `ROMWRIGHT_*` variable set |

Both are false when they should be: a binary run from `target/release` reports
`prefix_ok: false`, and setting any `ROMWRIGHT_*` variable reports
`store_only_ok: false`.

The older `ui.install.ok` metric in `benchmarks/reports/ui-gate.json` is not
measured — the app reads it from `ROMWRIGHT_UI_INSTALL_OK`, which the harness
(`tests/package_install_smoke.sh`) sets. It is left in place because changing
a metric definition is reserved to the human; `STATUS.md` records the proposal
to retire it.

The gate reports the platform and the wgpu adapter it ran on, so the evidence
names its own coverage: the CI `desktop` job runs it on GitHub-hosted Linux,
macOS and Windows runners (Linux has no GPU and renders on lavapipe), and a
local run covers only that machine.

The same packaged gate also exercises source range selection/copy,
selected-symbol follow/rename, folding/reveal, read-only editing and exclusion
of inline hints from copied C. The `ui.source.*` booleans report those
observed behaviors.

Native analysis progress is a separate Linux corpus-job check
(`tests/m14-004_ui_progress.py`), with generated inputs and the patched native
engine built before launch. It does not run inside the portable package job,
which has no native corpus/runtime prerequisites.

### The project gate

`--gate --project-image IMAGE` extends the run with the two project
features. `IMAGE` is a Windows PE32 (`tests/fixtures-src/tiny_pe32.exe`): the
one retail-format image whose repository needs no downloaded toolchain to be
written. After the ordinary stages the gate imports it as a second program,
opens it, and drives the panels the way an analyst does:

1. **Program setup > Create project** runs `romwright-cli new-project` on the
   open image (the CLI beside the app, `$ROMWRIGHT_CLI` when set) and the gate
   reads back what the panel holds: `ui.new_project.ms`,
   `ui.new_project.files` (files written, not counting the retail copy and the
   store), `ui.new_project.readme`, `ui.new_project.config`
   (`config/project.json` exists), `ui.new_project.job_logged` (the Jobs panel
   shows the job as succeeded) and `ui.new_project.image`.
2. The Match panel takes the new repository as its root without being told
   (`ui.match.root_follows_project`). The repository is given the host's
   `clang` as its compile check (`config/toolchain.local.json`, then the
   repository's own `configure.py --no-fetch --compiler <clang id>`), the
   largest function is selected, and **Run match** is driven with a budget of
   6 variants. After three painted frames the gate counts what the table
   showed: `ui.match.rows`, `ui.match.rendered_rows` (must equal the rows),
   `ui.match.compiled_rows` (at least one), `ui.match.default_percent`,
   `ui.match.best_percent` (never below the default), `ui.match.decompiles`,
   `ui.match.compiles`, `ui.match.function` and `ui.match.ms`.

The gate fails, and names the check, when any of these is wrong. It needs the
pinned Ghidra install, the built decompiler worker, `python3` and `clang`
(`$CLANG` or `PATH`), so it is not part of the portable package job;
`tests/m6-007_desktop_projects.py` runs it from the extracted archive. The
clang compile check is the one docs/pc-project.md describes for an
unidentified PE: the percent column counts equal instruction words, not an
objdiff score, and says nothing about the retail compiler.

## New project and Match

**Program setup > New project** is `romwright-cli new-project` for the open
image. The fields are the output directory (a directory beside the project
store named for the program, until edited), an optional name, an optional
platform (`--platform`, for a container the magic does not identify) and the
`--decompile` selection, which defaults to `none` because the CLI's default for
the 3DS, Switch, PS3, PS4, Vita and Xbox 360 scaffold is a whole-image
decompile that takes hours. **Create project** runs as a job: the CLI's
progress lines are the Jobs panel's progress, Cancel stops the child process,
and the finished entry carries the CLI's summary and the next command to run
(`cd REPO && python3 configure.py && ninja` for the byte-matching platforms,
`python3 build.py` for the scaffold and PC repositories). The image is the
Binary field, which is the program's captured copy unless edited; the repository
is named after the program, not after the copy's content hash. Every platform
`new-project` supports is available here (docs/new-project.md); the
tools themselves are fetched by the repository's `configure.py`, never by the
app.

**Match** (View menu; `--panel match` for a screenshot) is `romwright-cli
match` for the function at the cursor (docs/match.md). It takes the repository
the last **Create project** wrote, or the parent of the open store when the app
was opened on a repository's own `.romwright`, and a variant budget (the CLI's
default). **Run match** prints the function in the bounded set of alternative
ways, compiles each with the repository's compiler and scores it against the
retail bytes, as a job with Cancel. The table is the CLI's: one row per
variant with the printed C's hash (`= #N` when it printed the same C as an
earlier row), the match percent, `yes`/`no` for an exact object, differing
bytes outside relocation fields, and the decompile and compile times; the best
row is starred, a variant that did not compile shows its first error in red,
and the footer repeats the CLI's summary line. **Copy C** (row menu) copies a
variant's source; **Write best** writes the best compiling variant to the
repository's `src/` (`match --write`) for `configure.py swap` to install. The
repository's tools must already be installed (`python3 configure.py`), as for
the CLI.

What the panels leave to the CLI: the scaffold platforms' `--keys` (your
console keys for an encrypted container), `--map` and `--raw/--language` (a flat
dump), `--fact-pack`, `--toolchain` profiles and `--cflags`, and the match
search's `--time` and `--plan`. **Create project** reports what the CLI wrote
and the next command; it never installs a tool, and `match` needs the tools
`configure.py` installs.

## Filtering by evidence

The Xrefs panel carries an evidence selector: **All evidence**, `declared`,
`decoded` or `inferred`. The store applies the filter, so the row count is
the service's answer rather than a client-side pass over rows already
fetched. The UI gate records 13 declared of 19 rows on `libc`
(`ui.xrefs.declared_rows`, `ui.xrefs.rows`), and `tests/m9-004_filter_surfaces.py`
checks the window against the service at the address it opened.

## Matching workstation

Choose the **Matching** workspace (`Ctrl+Shift+M`) after importing a program.
It replaces the analysis panes with a full-width, resizable source/evidence
split. Returning to **Analysis** restores its dock arrangement and active tabs.
**New** accepts the target symbol/object, source and user-owned compiler.
Include required headers; native and MWCC setup paths record compiler/version
evidence. **Setup** reveals advanced controls, including **Add profile** and
the typed JSON contracts described in [core-api.md](core-api.md#matching-workspaces).

1. **Compile & compare** (`Ctrl+Enter`) shows separate similarity, instruction,
   relocation, object and project evidence, opening **Compare** on success.
   The mismatch table gives testable hypotheses.
   Object offsets are not ROM addresses; filename-less source hints are not
   presented as reliable source links.
2. Select an expression or a builtin scalar type and **Search selection**, or
   supply **Explicit alternatives**. Set compilation and wall-clock budgets first. Search
   retains the baseline and each attempted immutable candidate; **Cancel**
   stops the owned compiler job.
3. **Pin selection** protects source bytes. Pins are UTF-8 byte ranges, so
   they stay correct across non-ASCII source. Clear pins explicitly to change
   protected text. Candidate selection and history provide reversible trials;
   unsaved edits must be saved or discarded before leaving them.
   Closing a window also offers **Save**, **Discard** and **Cancel**. Save
   waits for the immutable candidate to persist before closing.
4. **Calibrate** compares installed profiles on selected references and keeps
   ties. **Trial context** compares shared-header edits across candidates,
   showing improvements and regressions without changing global analysis.
5. In **Project patch**, bind a local tree, source mapping, actual
   build command and authorized output symbols. Preview the diff, verify the
   isolated baseline/candidate builds, then explicitly confirm application.
   Verification history remains available separately from standalone trials.
6. **Export** retains portable history but excludes private inputs and tools.
   **Import** asks for user-owned missing files and local tool paths. Imported
   trials are visibly unverified; replay before trusting them. A project
   imported without a local root cannot prepare or apply a patch.

Workspace, candidate, trial and project-check lists have continuation controls;
history is not limited to the first displayed page. Full evidence and tool
diagnostics remain available when a concise mismatch row is insufficient.
**History**, **Project patch** and **Diagnostics** share the evidence side;
the source editor stays visible while switching between them.

`--matching-gate CONFIG.json` drives the real workspace, dialogs, compiler and
project verifier through the whole workflow offscreen and writes the matching
workflow report (`elapsed_ms`, `mismatch_rows`, `history_rows` and the
workflow booleans); an optional `dialog_images` directory captures each
dialog it answers. The committed
`benchmarks/reports/matching-workflow.json` covers mismatch diagnosis, search,
Unicode pins, undo, calibration, context regression, verified source apply,
private export/import and exact replay; it was recorded on Linux before the
desktop moved to Rust and is not a cross-platform release or whole-game
matching claim.

## Workbench layout

The default workspace is arranged for side-by-side analysis:

- **Left:** function browser, with names given useful column width and the
  remaining columns available by horizontal scrolling.
- **Center:** disassembly, with byte/address columns fitted to the loaded
  instructions rather than a fixed wide blank gutter. **Bytes** toggles the
  byte column when more assembly space is needed.
- **Right:** tabbed decompiler and function graph.
- **Bottom:** xrefs and optional detail panes, including memory, jobs, types
  and analyst data. Matching has its own workspace rather than a bottom pane.

The top toolbar holds the **Analysis/Matching** modes, image selection,
address navigation, back/forward, decompile and refresh. Enter activates the
selected function or navigates the address field; `Alt+Left` and `Alt+Right`
traverse history. **Program setup** holds the project/binary and
rename/comment controls without a large form above the disassembly.

Listing selection keeps the loaded viewport stable. Home/End select its first
and last instructions; a single click selects a row, while a double click on
a hexadecimal operand follows it. Register names are not interpreted as
addresses. The current function is reflected in the browser and listing header.
Xrefs have incoming/outgoing counts and activate the row's address regardless
of which evidence column was clicked. Superseded filter, reference, listing
and decompiler responses cannot replace the current view.

Source-cursor and graph-node selections retain the installed decompilation.
Source selections settle before the listing and xrefs follow, instead of
queueing a request per keypress. The source view supports mouse/keyboard
range selection, word selection, Copy, PageUp/PageDown and Home/End.
Reverse synchronization does not replace an active text selection.

The source gutter shows line numbers and clickable fold markers.
`Ctrl+Shift+[` folds/unfolds the current block; `Ctrl+Shift+]` expands all.
Address navigation reveals enclosing folds. Known callee parameter declarations
appear as dim inline hints; the context menu can hide them, and Copy always
omits them. Unknown signatures do not receive invented parameter names.
`Ctrl+Enter` or `Ctrl+click` follows a function; `F2` renames it. These commands
also work on a selected function name. Double-click retains ordinary word
selection rather than opening a rename dialog.

The graph uses the active document's complete native `FunctionIr`, not a second
bounded disassembly request. Native block IDs preserve distinct blocks that
share an address, empty blocks, disconnected blocks and loops. Node addresses
are retained-operation navigation anchors, not claimed machine-code extents.
The title reports block/edge counts. Source and graph share one decompilation
per function; unavailable native IR is reported rather than replaced with an
incomplete graph.

The **Command palette** (`Ctrl+Shift+P`) filters the real menu actions and
supports keyboard activation. **Byte-pattern search** reads the committed
program image, accepts `??` wildcards, reports errors and empty results, and
explicitly caps the display at 256 matches. The Facts panel's **Search** tab
searches symbols, strings and comments.

Types' save/propagate controls write through the Core API; stack variables
have their own ordinal, independent of structure fields. Memory loads the
selected context when shown; the graph follows the active native document.
Superseded program/region/type/analyst/vtable results cannot replace a newer
request. Opening a project starts a separate window. Image switches use
captured project binaries and clear cross-program navigation history; editing
the setup fields alone does not change the active image.

The Jobs panel keeps a bounded completed log. **Dismiss** removes a log entry
only: native work continues. Matching's separate **Cancel** control cancels its
compiler job.

Saved layouts are preserved per program. Choose **View → Reset workbench
layout** to adopt the default arrangement. Individual panels can still be
shown, hidden, docked and resized through the View menu, which also raises
tabbed panels.

Function navigation separates the containing function from the instruction
cursor. Following an interior branch target preserves that function's source
and CFG instead of attempting to decompile the target as a new entry. The
function browser exposes the complete row count through bounded lazy pages;
address navigation locates its row under the active filter/sort. Fetching an
ordinary scroll page does not snap the browser back to the active function.

`package_desktop.py` builds the worker in the same `cargo build` as the app,
so a fresh desktop build does not launch an older-schema worker.

## Earlier workbench evidence

These reports were recorded on Linux before the desktop moved to Rust; they
describe the workflows the Rust panels reproduce, not runs of
`romwright-desktop`:
[`workbench-interactions.json`](../benchmarks/reports/workbench-interactions.json),
[`workbench-acceptance.json`](../benchmarks/reports/workbench-acceptance.json)
(repaired native failures, sustained two-function navigation, real MWCC
matching, secondary-pane/dialog checks and four layout/scale cases) and
[`workbench-quality.json`](../benchmarks/reports/workbench-quality.json)
(20 function switches and 2,220 source key events over 89.8 seconds with a
maximum 56 ms heartbeat gap). The native patch's compatibility boundary is
documented in
[upstream-ghidra.md](upstream-ghidra.md#romwright-native-compatibility-extensions).

Real MWCC `PADClamp` matches instructions and relocations. Whole-object
bytes remain different because the split target and compiler output carry
different object metadata; see [toolchains.md](toolchains.md#user-owned-matching-profiles).
Real Dolphin acceptance read two live memory pages over one connection, checked
the disc ID against independent image metadata, and returned to file mode.
Private game memory/source captures are not published. No cross-platform
certification or whole-game matching claim follows.
