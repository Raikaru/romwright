# Adding a panel to romwright-desktop

A panel is one dockable view. It owns its widgets and its data fetching, and it
never talks to another panel. The shell owns navigation, program switching,
commands, menus, docking, persistence and the job log.

## Register

1. Add `src/panels/<name>.rs` with a type implementing `panel::Panel`.
2. Add `pub mod <name>;` and one `Box::new(...)` line to `panels::builtin` in
   `src/panels/mod.rs`. Nothing else in the shell changes: the View menu,
   command palette, dock tab, layout persistence and event delivery all come
   from that list.

## The trait (`src/panel.rs`)

| Method | When | Rule |
|---|---|---|
| `id()` | always | Stable `&'static str`; saved layouts and `--panel` use it. Never rename. |
| `title()` | tab label | Short noun. |
| `placement()` | reset layout | `Left` (browser), `Center` (listing), `Right` (decompiler/graph), `Bottom` (details). |
| `open_by_default()` | reset layout | `false` = View menu only. |
| `on_event(&ShellEvent, cx)` | every broadcast, shown or hidden | React to `ProgramChanged`, `AddressChanged`, `FunctionChanged` (the decompile trigger), `Decompiled` (document, CFG and IR of the answered function), `RevisionChanged(Change)`, `Refresh`, `XrefsRequested` (requester raises the xrefs tab itself), `VtablesRequested`, `ProjectCreated` (Program setup wrote a `new-project` repository; the Match panel takes it as its root). |
| `poll(cx)` | every frame, shown or hidden | Poll your `Task`s here. |
| `ui(ui, cx)` | tab visible | Draw only; no blocking calls. |
| `busy()` | headless drivers | `true` while your requests are in flight. |
| `unsaved_work()` | program switch, window close | `Some(question)` while the panel holds work that is not saved; the shell then refuses program switches and offers Save / Discard / Cancel on close. |
| `save_work(cx)` / `discard_work(cx)` | close prompt | Start saving (the shell closes once you are idle with nothing unsaved) or drop the edits. |

`PanelContext` gives you `service`, the read-only `session` (project, program,
binary, cursor address, containing function, `gate`), the `theme`, and
`command(...)`/`navigate(...)`/`status(...)`/`error(...)`. Shell actions are
`Command`s (navigate, back/forward, rename, comment, undo, import, open/switch
program, raise a panel, refresh, decompile, broadcast an event, and
`Analyst(AnalystEdit)` to set/delete a bookmark or patch, answered with
`RevisionChanged(Change::Analyst)`). Use
`cx.has_panel(id)` before offering an affordance another panel answers.

The decompiler panel owns decompilation: on `FunctionChanged` it shows the
cached document or runs one `decompile` job through
`WorkerPoolManager::decompile_function` (the decompile post-processing every
frontend shares), then broadcasts `ShellEvent::Decompiled`
(entry, cursor, laid-out native CFG, function IR) so views like the graph
never decompile a second time. A panel that edits facts the decompiler reads
broadcasts `RevisionChanged(Change::Types)` (the decompiler drops its cache)
and queues `Command::Decompile` when the open function should refresh now.

New cross-panel notifications are new `ShellEvent` variants; new shell actions
are new `Command` variants. Both live in `panel.rs`, not in the shell.

Matching (`panels/matching.rs`) is a workspace, not a dock: the toolbar's
Analysis / Matching control (`Ctrl+Shift+M`, Matching menu, `--panel
matching`) replaces the dock area with the full-width matching panel and
leaves the analysis layout untouched for the way back. Its C source,
unified-diff and JSON layouts live in `panels/matching/text.rs`; the pin
wash is `warn` at low alpha.

## Calling the Core

Never call `romwright_core::Core` on the UI thread. Use `cx.service`
(`src/service.rs`), which owns the shared state (`Mutex<Core>` +
`Mutex<WorkerPoolManager>`, pool locked before Core):

- `request(|core| ...)` for short store reads (2-thread pool, Core mutex held).
- `request_pool(|core, pool| ...)` when you also need the worker pool counters.
- `job(label, |job| ...)` for anything long (decompile, analysis, matching):
  its own thread, an entry in the Jobs panel, progress via `job.progress(..)`,
  success text via `job.detail(..)`, cancellation via `job.check_cancelled()`
  or `job.execution_request(core, ...)` (which wires the Jobs panel's Cancel
  into the worker watchdog). Use `job.fork()` for a Core that does not hold
  the shared mutex; take `job.worker_pool()` before any Core lock.

Each call returns a `Task<T>`; keep it in an `Option` and use
`service::poll_slot`. Tag requests with a generation and drop superseded
answers (see `panels/functions.rs`, `panels/listing.rs`).

Work that is a CLI command or the `match` search lives in `src/projects.rs`:
`run_new_project` runs the sibling `romwright-cli new-project` as a child
process (stderr lines are the job's progress, Cancel kills the child) and
`run_match` is `romwright-cli match` as a library call returning the
`match_search::Report` that `panels/match_search.rs` tabulates. Program setup
(`panels/setup.rs`) and Match are the two callers; the gate drives both
(`gate/projects.rs`).

## Look and feel (required)

All colours, fonts and sizes come from `theme` and `widgets`; no hex literals,
`Color32::from_rgb`, ad-hoc font sizes or magic margins in panels.

- Colour tokens on `cx.theme`: neutrals `bg_app`, `bg_panel`, `bg_raised`,
  `bg_hover`, `bg_selected`, `bg_stripe`, `bg_code`, `border`, `border_strong`;
  text `text`, `text_muted`, `text_faint`; one accent `accent`,
  `accent_hover`, `on_accent`, `accent_soft`, `current_line`; state `ok`,
  `warn`, `error`.
- Syntax: `theme.syntax(Syntax::…)` with `Keyword, Type, Function, Address,
  Register, Constant, String, Comment, Warning, Mnemonic, Variable, Label,
  Punctuation, Dim, Plain`. The same kind is the same colour everywhere.
- Type scale: `theme::font(Type::Caption | Body | Strong | Title | Code |
  CodeSmall)`, `theme::code_bold()`. Inter for UI, JetBrains Mono for code.
- Spacing: `theme::space::{XXS, XS, SM, MD, LG, XL}` (4/8 grid);
  `theme::metrics::{ROW, CODE_ROW, RADIUS, RADIUS_SM, TAB_BAR, ...}`.
- Widgets (`src/widgets.rs`): `panel_header` (slim title bar with right-side
  controls), `primary_button` (one per region), `button`, `chip` (toggles),
  `segmented`, `icon_button` + `Icon`, `caption`, `truncated` (ellipsis plus
  full-text tooltip), `empty_state`, `loading`.
- Tables: use `src/table.rs` (`table::show`), which is the shared look:
  striped `metrics::ROW` rows with hover/selection, caption headers with
  `↑`/`↓` on sortable columns, right-aligned `Type::Code` addresses in
  `syntax_address` (`Column::address`, `Cell::address`), every cell through
  `widgets::truncated` (+ optional `Cell::tooltip`), ↑/↓/Enter navigation,
  double-click activation and a per-row context menu. Sort client-side with
  `table::sort_rows`/`text_order`/`address_order`; put counts in
  `table::with_footer`. Paged views fetch more when
  `TableResponse::last_visible` nears the end (see `panels/facts.rs`).
  Functions predates it and draws its own `TableBuilder` in the same style.
- Code views: classify with `code::highlight_instruction` or
  `code::decompiler_kind`, draw with `code::CodePainter` (gutter text dim,
  `current_line` + 2 px accent bar for the cursor row, `occurrence` set to the
  hovered or clicked word from `code::word_at` for the soft highlight).
- Painted canvases (`panels/graph.rs`, `panels/memory/hex.rs`): `bg_code`
  background, `bg_raised` gutters/cards, cursor in `current_line` + accent
  (`accent` stroke, `accent_soft` box). CFG edges: true `ok`, false `error`,
  jump `text_faint`, call `accent` dashed; card lift is the theme's
  `visuals.popup_shadow`, softened. Overlays (legend, minimap) sit on
  `bg_panel` pills with a `border` stroke. Fetch only while visible (call
  from `ui`, keep a pending target from `on_event`).
- Show `widgets::loading` while waiting and `widgets::empty_state` with one
  actionable sentence when there is nothing to show.

## Verify

`romwright-desktop --screenshot out.png --project P --program N --address A
[--panel <id>] [--theme dark|light]` renders offscreen through wgpu (no display)
and writes a PNG. Look at it in both themes.
