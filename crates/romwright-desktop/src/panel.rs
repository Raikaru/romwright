//! The panel contract: everything a dockable view needs from the shell, and
//! nothing more. See `PANELS.md` for the short version.
//!
//! A panel owns its widgets and its data fetching. It never talks to another
//! panel: it reacts to [`ShellEvent`]s the shell broadcasts to every
//! registered panel (shown or hidden), and asks for shell-level actions by
//! queueing [`Command`]s on its [`PanelContext`]. Register new panels in
//! `panels::builtin`.

use crate::service::CoreService;
use crate::theme::Theme;
use romwright_model::{Address, FunctionRow};
use std::any::Any;
use std::path::PathBuf;

/// Stable identifier: dock tab key, persisted layout entry and `--panel`
/// argument. Never rename one; saved layouts refer to it.
pub type PanelId = &'static str;

/// Where the default (reset) layout docks a panel; Qt `reset_layout`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Placement {
    /// Function browser column.
    Left,
    /// The main analysis view (listing).
    Center,
    /// Tabbed decompiler / graph column.
    Right,
    /// Tabbed detail strip: xrefs, memory, jobs, types, analyst...
    Bottom,
}

/// What the window is looking at. Read-only to panels; changed by the shell.
#[derive(Clone, Debug, Default)]
pub struct Session {
    pub project: PathBuf,
    /// Open program; empty before one is chosen.
    pub program: String,
    /// The program's captured binary (`<project>/artifacts/<digest>`).
    pub binary: PathBuf,
    /// Navigation cursor.
    pub address: Option<Address>,
    /// Function containing the cursor, when the store knows one.
    pub function: Option<FunctionRow>,
    /// The offscreen UI gate is driving the window: panels skip
    /// conveniences that would race its measurements (Qt `ROMWRIGHT_UI_GATE`).
    pub gate: bool,
}

/// Why facts changed under every view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    Rename,
    Comment,
    Undo,
    /// The background analysis pass finished.
    Analysis,
    /// A bookmark or patch was set or removed.
    Analyst,
    /// A type, field, prototype or stack variable was edited (Types panel).
    Types,
}

/// Broadcast to every registered panel, in registration order.
#[derive(Clone, Debug)]
pub enum ShellEvent {
    /// `session.program` / `session.binary` changed (or were reloaded):
    /// drop everything derived from the old program.
    ProgramChanged,
    /// The navigation cursor moved. `record` is false for history traversal
    /// and scroll-driven moves.
    AddressChanged { address: Address, record: bool },
    /// The shell resolved the function containing the cursor (`function_at`).
    /// This is the decompile trigger: Qt `MainWindow::decompile`. Re-sent by
    /// the toolbar's Decompile and after renames/undo.
    FunctionChanged { function: Option<FunctionRow>, cursor: Address },
    /// A journalled command or the analysis pass changed stored facts.
    RevisionChanged(Change),
    /// Toolbar Refresh: reload program-derived panels.
    Refresh,
    /// Someone asked to see references to an address (listing context menu).
    XrefsRequested(Address),
    /// Search ▸ Recover vtables: scan the open binary's data for vtables.
    VtablesRequested,
    /// Program setup wrote a `new-project` repository at `root`: the Match
    /// panel runs inside it.
    ProjectCreated { root: PathBuf },
    /// A decompile of `entry` answered (fresh or cached), after
    /// `FunctionChanged`. `graph` is the laid-out native CFG
    /// (`romwright_core::graph::native_layout`), computed once off the UI
    /// thread with `layout_ms` its cost; `None` when the IR is unavailable.
    Decompiled {
        entry: Address,
        cursor: Address,
        graph: Option<std::sync::Arc<romwright_core::graph::NativeGraph>>,
        layout_ms: f64,
        ir: Option<std::sync::Arc<romwright_model::function_ir::FunctionIr>>,
    },
}

/// Shell-level actions a panel may request; applied after the frame.
#[derive(Clone, Debug)]
pub enum Command {
    Navigate { address: Address, record: bool },
    Back,
    Forward,
    Status { text: String, error: bool },
    /// `name: None` opens the rename dialog.
    RenameFunction { address: Address, name: Option<String> },
    Comment { address: Address, kind: String, text: String },
    Undo,
    ImportNative { binary: PathBuf, name: String },
    OpenProgram(String),
    SwitchProgram(String),
    /// Show (if closed) and focus a panel's tab.
    Raise(PanelId),
    Refresh,
    /// Re-resolve the cursor's function and re-broadcast `FunctionChanged`.
    Decompile,
    Broadcast(ShellEvent),
    /// Store an analyst bookmark/patch change; answers with
    /// `RevisionChanged(Change::Analyst)`.
    Analyst(AnalystEdit),
}

/// One analyst-data mutation (Qt `AnalystDock::setBookmark`/`setPatch`).
#[derive(Clone, Debug)]
pub enum AnalystEdit {
    SetBookmark(romwright_model::BookmarkRow),
    DeleteBookmark(Address),
    SetPatch(romwright_model::PatchRow),
    DeletePatch(Address),
}

/// Per-call view of the shell handed to panel hooks.
pub struct PanelContext<'a> {
    pub service: &'a CoreService,
    pub session: &'a Session,
    pub theme: &'a Theme,
    registered: &'a [PanelId],
    commands: &'a mut Vec<Command>,
}

impl<'a> PanelContext<'a> {
    pub(crate) fn new(
        service: &'a CoreService,
        session: &'a Session,
        theme: &'a Theme,
        registered: &'a [PanelId],
        commands: &'a mut Vec<Command>,
    ) -> Self {
        Self { service, session, theme, registered, commands }
    }

    pub fn command(&mut self, command: Command) {
        self.commands.push(command);
    }

    pub fn navigate(&mut self, address: Address, record: bool) {
        self.command(Command::Navigate { address, record });
    }

    pub fn status(&mut self, text: impl Into<String>) {
        self.command(Command::Status { text: text.into(), error: false });
    }

    pub fn error(&mut self, text: impl Into<String>) {
        self.command(Command::Status { text: text.into(), error: true });
    }

    /// Whether a panel is registered, so optional cross-panel affordances
    /// (a "Show xrefs" menu item) appear only when something answers them.
    pub fn has_panel(&self, id: PanelId) -> bool {
        self.registered.contains(&id)
    }
}

/// One dockable view. `Any` lets the gate and screenshot driver reach a
/// concrete panel (`downcast_mut`) without the shell knowing its type.
pub trait Panel: Any {
    fn id(&self) -> PanelId;
    fn title(&self) -> String;
    fn placement(&self) -> Placement {
        Placement::Bottom
    }
    /// Whether the reset layout shows this panel (otherwise View menu only).
    fn open_by_default(&self) -> bool {
        true
    }
    /// Shell broadcasts; called for hidden panels too.
    fn on_event(&mut self, _event: &ShellEvent, _cx: &mut PanelContext<'_>) {}
    /// Once per frame before drawing, for every panel, shown or hidden:
    /// poll [`crate::service::Task`]s here so hidden panels stay current.
    fn poll(&mut self, _cx: &mut PanelContext<'_>) {}
    /// Draws the tab body. Only called while the tab is visible.
    fn ui(&mut self, ui: &mut egui::Ui, cx: &mut PanelContext<'_>);
    /// True while this panel waits on work it started; the screenshot and
    /// gate drivers wait for every panel to go idle.
    fn busy(&self) -> bool {
        false
    }
    /// The question to ask before this panel's state is thrown away (window
    /// close, program switch), when it holds work that is not saved. The
    /// shell then refuses program switches and offers Save / Discard /
    /// Cancel on close (Qt `MatchingDock::confirmClose`).
    fn unsaved_work(&self) -> Option<String> {
        None
    }
    /// Close prompt "Save": start saving; the shell closes once the panel
    /// is idle with nothing unsaved.
    fn save_work(&mut self, _cx: &mut PanelContext<'_>) {}
    /// Close prompt "Discard".
    fn discard_work(&mut self, _cx: &mut PanelContext<'_>) {}
}
