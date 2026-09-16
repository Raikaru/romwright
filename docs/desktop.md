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
romwright-qt --project DIR --program PROGRAM --binary PATH
```

`--project` is the SQLite project the CLI writes; a program imported by
`romwright-cli import` opens directly. Panels read the store: functions, symbols,
references, strings, listing, graph, types, patches, bookmarks and jobs. Edits
go through the same journalled commands as the CLI, so `undo` reverses a rename
made in either.

Use `--program` (or `-n`), not `--name`: Qt's X11 argument handling consumes
`--name` before the application parser sees it. An optional `--address`
opens the initial listing, decompiler and references without another Go action.

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

The same packaged gate also exercises source range selection/copy, selected-symbol
follow/rename, folding/reveal, read-only editing and exclusion of inline hints
from copied C. The `ui.source.*` booleans report those observed behaviors.

Native analysis progress is a separate Linux corpus-job check, with generated
inputs, Qt and the patched native engine built before launch. It does not run
inside the portable package job, which has no native corpus/runtime prerequisites.

## Filtering by evidence

The Xrefs dock carries an evidence selector: **All evidence**, `declared`,
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
3. **Pin selection** protects source bytes. Pins remain correct across UTF-8
   source and Qt's UTF-16 editor offsets. Clear pins explicitly to change
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

The executable's `--matching-gate CONFIG.json` mode drives the real widgets,
dialogs, compiler and project verifier. The measured Linux run in
`benchmarks/reports/matching-workflow.json` covers mismatch diagnosis, search,
Unicode pins, undo, calibration, context regression, verified source apply,
private export/import and exact replay. This is local Qt runtime evidence,
not a cross-platform release or whole-game matching claim.

## Dark workbench layout

The default theme now styles the entire Qt application: menus, toolbars,
docks, tabs, tables, editors, dialogs and status bar share the analysis-view
palette. Existing light and high-contrast preferences remain supported.

The default workspace is arranged for side-by-side analysis:

- **Left:** function browser, with names given useful column width and the
  remaining columns available by horizontal scrolling.
- **Center:** disassembly, with byte/address columns fitted to the loaded
  instructions rather than a fixed wide blank gutter. **Bytes** toggles the
  byte column when more assembly space is needed.
- **Right:** tabbed decompiler and function graph.
- **Bottom:** xrefs and optional detail panes, including memory, jobs, types
  and analyst data. Matching has its own workspace rather than a bottom pane.

The top navigation toolbar holds **Analysis/Matching** modes, image selection,
address navigation, back/forward, decompile and refresh. Enter activates the
selected function or navigates the address field; `Alt+Left` and `Alt+Right`
traverse history. **Program setup** opens the project/binary and rename/comment
controls without leaving a large form above the disassembly.

Listing selection keeps the loaded viewport stable. Home/End select its first
and last instructions; a single click selects a row, while a double click on
a hexadecimal operand follows it. Register names are not interpreted as
addresses. The current function is reflected in the browser and listing header.
Xrefs have incoming/outgoing counts and activate the row's address regardless
of which evidence column was clicked. Superseded filter, reference, listing
and decompiler responses cannot replace the current view.

Source-cursor and graph-node selections retain the installed decompilation.
Rapid source selections coalesce listing/xref reads instead of queueing a
request per keypress. The native text editor supports mouse/keyboard range
selection, word selection, Copy, PageUp/PageDown and Home/End, with both
scrollbars. Reverse synchronization does not replace an active text selection.

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
The title reports block/edge counts. Source and graph share the revision-aware
document cache; unavailable native IR is reported rather than replaced with an
incomplete graph.

**Search → Command palette** (`Ctrl+Shift+P`) filters real menu actions and
supports keyboard activation. **Byte-pattern search** reads the committed
program image, accepts `??` wildcards, reports errors and empty results, and
explicitly caps the display at 256 matches. The Facts pane's **Search** tab
searches symbols, strings and comments.

Types' save/propagate controls write through the Core API; stack variables
have their own ordinal, independent of structure fields. The form scrolls
inside its dock. Memory loads the selected context when shown; the graph follows
the active native document. Superseded program/region/type/analyst/vtable results
cannot replace a newer request. Opening a project creates a separately bound window. Image switches
use captured project binaries and clear cross-program navigation history;
editing the setup fields alone does not change the active image.

The Jobs pane keeps a bounded completed log and opens full multiline details
on double-click. **Dismiss selected** removes a log entry only: native work
continues. Matching's separate **Cancel** control cancels its compiler job.

Saved layouts are preserved. Choose **View → Reset workbench layout** to
adopt the new arrangement in an existing project. Individual panes can still
be shown, hidden, floated and resized through the View menu.

Function navigation separates the containing function from the instruction
cursor. Following an interior branch target preserves that function's source
and CFG instead of attempting to decompile the target as a new entry. The
function browser exposes the complete row count through bounded lazy pages;
address navigation locates its row under the active filter/sort. Fetching an
ordinary scroll page does not snap the browser back to the active function.
The listing has horizontal scrolling, with operand hit testing accounting for
the scroll offset. View-menu actions raise tabified panes as well as showing
them.

Additional native Linux checks at 150% scaling exercised full-width address
entry, a horizontally scrolled branch operand, interior navigation, name-sort
and filter anchoring, and keyboard navigation to the final function page.
These checks do not establish other-platform behavior.

CMake builds the native Rust worker together with the Qt bridge so a fresh
desktop build does not accidentally launch an older-schema worker.

The original interaction evidence remains in
[`workbench-interactions.json`](../benchmarks/reports/workbench-interactions.json).
The follow-up
[`workbench-acceptance.json`](../benchmarks/reports/workbench-acceptance.json)
records the repaired native failures, sustained two-function navigation,
real MWCC matching, secondary-pane/dialog checks and four layout/scale cases.
The `ls` analysis gate now completes without the earlier control-flow-cut or
dynamic-hash errors. The native patch's compatibility boundary is documented
in [upstream-ghidra.md](upstream-ghidra.md#romwright-native-compatibility-extensions).

The follow-up quality evidence is
[`workbench-quality.json`](../benchmarks/reports/workbench-quality.json).
The earlier run's 531 ms maximum heartbeat gap led to profiling: parsing a
29.6 MB response alone occupied the GUI thread for 436 ms. Response parsing
and token/address projection now run off-thread. The follow-up exercised 20
function switches and 2,220 source key events over 89.8 seconds, with two native
decompilations and a maximum 56 ms heartbeat gap. This does not establish
IDA/Ghidra interaction parity or eliminate every possible UI stall.

Real MWCC `PADClamp` now matches instructions and relocations. Whole-object
bytes remain different because the split target and compiler output carry
different object metadata; see [toolchains.md](toolchains.md#user-owned-matching-profiles).
Real Dolphin acceptance read two live memory pages over one connection, checked
the disc ID against independent image metadata, and returned to file mode.
Private game memory/source captures are not published.

Evidence remains local Linux/Qt coverage. The existing CI matrix runs the
packaged source gate on Linux, Windows and macOS, but the updated Windows/macOS
binaries were not executed during this acceptance run. No cross-platform
certification or whole-game matching claim follows.
