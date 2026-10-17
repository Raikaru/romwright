//! The window shell (Qt `MainWindow` + `main_window_commands.cpp`): menus,
//! toolbar, docking, status bar, navigation, program switching, journalled
//! commands and the background analysis pass. Panels plug in through
//! [`crate::panel`]; nothing here knows a concrete panel type.

use crate::address;
use crate::jobs::JobState;
use crate::nav::Navigation;
use crate::panel::{AnalystEdit, Change, Command, Panel, PanelContext, PanelId, Placement, Session, ShellEvent};
use crate::panels;
use crate::service::{CoreService, Task, poll_slot};
use crate::settings::Settings;
use crate::theme::{self, Theme, ThemeChoice, ThemeName, Type, font, metrics, space};
use crate::widgets::{self, Icon};
use egui::{Align, Align2, Color32, CornerRadius, Key, KeyboardShortcut, Layout, Modifiers, RichText, Sense, Stroke, vec2};
use egui_dock::{DockArea, DockState, NodeIndex, TabViewer};
use romwright_model::{Address, AnalysisStatus, FunctionRow, ProgramInput, ProgramRow, SearchHit};
use std::any::Any;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// How the window was launched.
#[derive(Clone, Debug)]
pub struct Options {
    pub project: PathBuf,
    pub program: String,
    pub binary: PathBuf,
    pub address: String,
    pub theme: Option<ThemeChoice>,
    /// Read/write user settings (theme, recent projects, layouts). Off for
    /// headless runs.
    pub persist: bool,
    /// The offscreen UI gate drives this window.
    pub gate: bool,
}

/// A journalled command or session action finished; what the shell does next.
enum Followup {
    Revision { program: String, change: Change, message: String },
    Switch { program: String, message: String },
    Imported { program: String, message: String },
}

struct Toast {
    text: String,
    state: JobState,
    created: Instant,
}

const TOAST_LIFETIME: Duration = Duration::from_secs(4);
const ANALYSIS_INTERVAL: Duration = Duration::from_millis(50);
const ANALYSIS_BUDGET: usize = 16;

#[derive(Default)]
struct Analysis {
    label: String,
    first: String,
    status: Option<(u64, Task<AnalysisStatus>)>,
    pass: Option<(u64, Task<AnalysisStatus>)>,
    next: Option<Instant>,
}

#[derive(Default)]
struct Palette {
    open: bool,
    filter: String,
    selected: usize,
}

#[derive(Default)]
struct ByteSearch {
    open: bool,
    pattern: String,
    status: String,
    results: Vec<Address>,
    task: Option<(u64, Task<Vec<SearchHit>>)>,
    generation: u64,
}

struct RenameDialog {
    address: Address,
    name: String,
}

#[derive(Default)]
struct OpenProjectDialog {
    open: bool,
    path: String,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Action {
    OpenProject,
    OpenRecent(usize),
    Quit,
    TogglePanel(usize),
    Theme(ThemeChoice),
    ResetLayout,
    CommandPalette,
    ByteSearch,
    RecoverVtables,
    Back,
    Forward,
    Decompile,
    Refresh,
    MatchingWorkspace,
}

struct ActionItem {
    menu: &'static str,
    label: String,
    action: Action,
    shortcut: Option<KeyboardShortcut>,
    enabled: bool,
    checked: Option<bool>,
}

const PALETTE_SHORTCUT: KeyboardShortcut = KeyboardShortcut::new(Modifiers::COMMAND.plus(Modifiers::SHIFT), Key::P);
const BACK_SHORTCUT: KeyboardShortcut = KeyboardShortcut::new(Modifiers::ALT, Key::ArrowLeft);
const FORWARD_SHORTCUT: KeyboardShortcut = KeyboardShortcut::new(Modifiers::ALT, Key::ArrowRight);
const QUIT_SHORTCUT: KeyboardShortcut = KeyboardShortcut::new(Modifiers::COMMAND, Key::Q);
const MATCHING_SHORTCUT: KeyboardShortcut = KeyboardShortcut::new(Modifiers::COMMAND.plus(Modifiers::SHIFT), Key::M);

pub struct DesktopApp {
    service: CoreService,
    session: Session,
    nav: Navigation,
    panels: Vec<Box<dyn Panel>>,
    ids: Vec<PanelId>,
    dock: DockState<String>,
    theme_choice: ThemeChoice,
    theme: Theme,
    applied: Option<ThemeName>,
    fonts_installed: bool,
    settings: Settings,
    persist: bool,
    status: (String, bool),
    toasts: Vec<Toast>,
    address_text: String,
    mode: usize,
    programs: Vec<ProgramRow>,
    programs_task: Option<Task<Vec<ProgramRow>>>,
    programs_listed: u64,
    switch: Option<(u64, String, Task<ProgramInput>)>,
    switch_generation: u64,
    lookup: Option<(u64, Address, Task<Option<FunctionRow>>)>,
    lookup_generation: u64,
    program_generation: u64,
    analysis: Analysis,
    followups: Vec<Task<Followup>>,
    commands: Vec<Command>,
    events: VecDeque<ShellEvent>,
    palette: Palette,
    byte_search: ByteSearch,
    rename: Option<RenameDialog>,
    open_project: OpenProjectDialog,
    active_tabs: Vec<String>,
    quit: bool,
    /// Close prompt text while a panel holds unsaved work (Save / Discard /
    /// Cancel), and whether a prompted save is settling before the close.
    close_prompt: Option<String>,
    closing: bool,
}

impl DesktopApp {
    pub fn new(options: Options) -> Self {
        let service = CoreService::open(&options.project);
        let mut settings = if options.persist { Settings::load() } else { Settings::default() };
        let theme_choice = options
            .theme
            .or_else(|| settings.theme.as_deref().and_then(ThemeChoice::parse))
            .unwrap_or(ThemeChoice::System);
        if options.persist {
            settings.remember_project(&options.project.display().to_string());
            let _ = settings.save();
        }
        let panels = panels::builtin(&options.program, &options.binary.display().to_string());
        let ids: Vec<PanelId> = panels.iter().map(|panel| panel.id()).collect();
        let session = Session {
            project: options.project.clone(),
            program: String::new(),
            binary: PathBuf::new(),
            address: None,
            function: None,
            gate: options.gate,
        };
        let mut app = Self {
            service,
            session,
            nav: Navigation::default(),
            dock: DockState::new(Vec::new()),
            panels,
            ids,
            theme: Theme::new(ThemeName::Dark),
            theme_choice,
            applied: None,
            fonts_installed: false,
            settings,
            persist: options.persist,
            status: (String::new(), false),
            toasts: Vec::new(),
            address_text: options.address.clone(),
            mode: 0,
            programs: Vec::new(),
            programs_task: None,
            programs_listed: 0,
            switch: None,
            switch_generation: 0,
            lookup: None,
            lookup_generation: 0,
            program_generation: 0,
            analysis: Analysis::default(),
            followups: Vec::new(),
            commands: Vec::new(),
            events: VecDeque::new(),
            palette: Palette::default(),
            byte_search: ByteSearch::default(),
            rename: None,
            open_project: OpenProjectDialog::default(),
            active_tabs: Vec::new(),
            quit: false,
            close_prompt: None,
            closing: false,
        };
        app.dock = app.restore_layout(&options.program);
        if let Some(error) = app.service.startup_error() {
            app.status = (error.to_string(), true);
            return app;
        }
        if options.gate {
            // The gate imports first, then opens the program itself.
        } else if !options.program.is_empty() {
            app.switch_program(&options.program);
        } else {
            app.status = ("Choose an image, or import a binary from Program setup.".into(), false);
        }
        if !options.gate {
            app.refresh_programs();
        }
        app
    }

    // ----- accessors for the headless drivers -------------------------------

    pub fn service(&self) -> &CoreService {
        &self.service
    }

    pub fn session(&self) -> &Session {
        &self.session
    }

    pub fn programs(&self) -> &[ProgramRow] {
        &self.programs
    }

    pub fn programs_listed(&self) -> u64 {
        self.programs_listed
    }

    pub fn analysis_label(&self) -> &str {
        &self.analysis.label
    }

    pub fn first_analysis(&self) -> &str {
        &self.analysis.first
    }

    pub fn set_theme(&mut self, choice: ThemeChoice) {
        self.theme_choice = choice;
        self.applied = None;
        if self.persist {
            self.settings.theme = Some(choice.key().to_string());
            let _ = self.settings.save();
        }
    }

    /// Runs `work` on a registered panel of concrete type `T` with a context.
    pub fn with_panel<T: Panel, R>(&mut self, id: PanelId, work: impl FnOnce(&mut T, &mut PanelContext<'_>) -> R) -> Option<R> {
        let panel = self.panels.iter_mut().find(|panel| panel.id() == id)?;
        let panel = (panel.as_mut() as &mut dyn Any).downcast_mut::<T>()?;
        let mut cx = PanelContext::new(&self.service, &self.session, &self.theme, &self.ids, &mut self.commands);
        Some(work(panel, &mut cx))
    }

    /// No request, job or panel fetch outstanding.
    pub fn idle(&self) -> bool {
        self.panels.iter().all(|panel| !panel.busy())
            && self.programs_task.is_none()
            && self.switch.is_none()
            && self.lookup.is_none()
            && self.followups.is_empty()
            && self.commands.is_empty()
            && self.events.is_empty()
            && self.service.jobs().running() == 0
    }

    /// Whether the background analysis pass still has work scheduled.
    pub fn analysing(&self) -> bool {
        self.analysis.next.is_some() || self.analysis.pass.is_some() || self.analysis.status.is_some()
    }

    pub fn quit_requested(&self) -> bool {
        self.quit
    }

    /// 0 = Analysis docks, 1 = the full-width Matching workspace (Qt
    /// `workspaceModes`; `showMatchingWorkspace`). The dock layout is kept
    /// untouched while Matching is shown, so Analysis comes back as it was.
    pub fn set_mode(&mut self, mode: usize) {
        self.mode = mode.min(1);
    }

    pub fn mode(&self) -> usize {
        self.mode
    }

    /// The first registered panel's unsaved-work question, if any.
    fn unsaved_work(&self) -> Option<String> {
        self.panels.iter().find_map(|panel| panel.unsaved_work())
    }

    /// Opens a program from the gate (Qt gate: `navigation.setProgram`,
    /// `functionsDock.setProgram`) with the binary it imported.
    pub fn open_imported(&mut self, program: &str, binary: PathBuf) {
        self.session.program = program.to_string();
        self.session.binary = binary;
        self.nav.reset();
        self.session.address = None;
        self.session.function = None;
        self.program_generation += 1;
        self.events.push_back(ShellEvent::ProgramChanged);
        self.pump();
    }

    /// Navigates as if the analyst had typed the address and pressed Go.
    pub fn navigate(&mut self, address: Address) {
        self.commands.push(Command::Navigate { address, record: true });
        self.pump();
    }

    pub fn raise(&mut self, id: PanelId) {
        self.raise_panel(id);
    }

    pub fn refresh_programs(&mut self) {
        self.programs_task = Some(self.service.request(|core| core.programs().map_err(|error| error.to_string())));
    }

    pub fn select_program_at(&mut self, index: usize) {
        if let Some(program) = self.programs.get(index).map(|row| row.program.clone()) {
            self.switch_program(&program);
        }
    }

    // ----- layout ---------------------------------------------------------

    fn default_layout(&self) -> DockState<String> {
        let group = |placement: Placement| -> Vec<String> {
            self.panels
                .iter()
                .filter(|panel| panel.placement() == placement && panel.open_by_default())
                .map(|panel| panel.id().to_string())
                .collect()
        };
        let (left, center, right, bottom) = (group(Placement::Left), group(Placement::Center), group(Placement::Right), group(Placement::Bottom));
        let mut dock = DockState::new(center);
        let surface = dock.main_surface_mut();
        let mut center_node = NodeIndex::root();
        if !left.is_empty() {
            // egui_dock applies the fraction to the left/top child, which
            // for split_left is the new (browser) node.
            center_node = surface.split_left(center_node, 0.23, left)[0];
        }
        if !bottom.is_empty() {
            center_node = surface.split_below(center_node, 0.74, bottom)[0];
        }
        if !right.is_empty() {
            // Qt gave the decompiler column more width than the listing
            // (`resizeDocks` 480 px of a 1024 px window).
            surface.split_right(center_node, 0.46, right);
        }
        dock
    }

    fn restore_layout(&self, program: &str) -> DockState<String> {
        let saved = self
            .settings
            .layouts
            .get(program)
            .and_then(|value| serde_json::from_value::<DockState<String>>(value.clone()).ok());
        let Some(mut dock) = saved else { return self.default_layout() };
        // Drop tabs whose panel no longer exists; never show a dead tab.
        let stale: Vec<_> = dock
            .iter_all_tabs()
            .filter(|(_, tab)| !self.ids.iter().any(|id| id == tab))
            .map(|(path, _)| path)
            .collect();
        for path in stale.into_iter().rev() {
            dock.remove_tab(path);
        }
        if dock.iter_all_tabs().next().is_none() { self.default_layout() } else { dock }
    }

    fn save_layout(&mut self) {
        if !self.persist {
            return;
        }
        if let Ok(value) = serde_json::to_value(&self.dock) {
            self.settings.layouts.insert(self.session.program.clone(), value);
            let _ = self.settings.save();
        }
    }

    fn panel_open(&self, id: PanelId) -> bool {
        self.dock.iter_all_tabs().any(|(_, tab)| tab == id)
    }

    fn raise_panel(&mut self, id: PanelId) {
        if !self.ids.contains(&id) {
            return;
        }
        if id == panels::matching::ID {
            // Matching is the full-width workspace, never a dock tab.
            self.set_mode(1);
            return;
        }
        if let Some(path) = self.dock.find_tab(&id.to_string()) {
            let _ = self.dock.set_active_tab(path);
            self.dock.set_focused_node_and_surface(path.node_path());
            return;
        }
        let placement = self.panels.iter().find(|panel| panel.id() == id).map(|panel| panel.placement());
        let sibling = self
            .panels
            .iter()
            .filter(|panel| Some(panel.placement()) == placement)
            .find_map(|panel| self.dock.find_tab(&panel.id().to_string()));
        match sibling {
            Some(path) => {
                self.dock.set_focused_node_and_surface(path.node_path());
                self.dock.push_to_focused_leaf(id.to_string());
            }
            None => self.dock.push_to_first_leaf(id.to_string()),
        }
    }

    fn toggle_panel(&mut self, index: usize) {
        let id = self.ids[index];
        if let Some(path) = self.dock.find_tab(&id.to_string()) {
            self.dock.remove_tab(path);
        } else {
            self.raise_panel(id);
        }
    }

    // ----- commands and events --------------------------------------------

    fn broadcast(&mut self, event: &ShellEvent) {
        let mut cx = PanelContext::new(&self.service, &self.session, &self.theme, &self.ids, &mut self.commands);
        for panel in &mut self.panels {
            panel.on_event(event, &mut cx);
        }
    }

    /// Applies queued commands and delivers queued events until both are
    /// empty (bounded so a feedback loop cannot hang the frame).
    fn pump(&mut self) {
        for _ in 0..64 {
            if let Some(event) = self.events.pop_front() {
                self.broadcast(&event);
                continue;
            }
            if self.commands.is_empty() {
                return;
            }
            let commands = std::mem::take(&mut self.commands);
            for command in commands {
                self.apply(command);
            }
        }
    }

    fn set_status(&mut self, text: impl Into<String>, error: bool) {
        self.status = (text.into(), error);
    }

    fn toast(&mut self, text: impl Into<String>, state: JobState) {
        self.toasts.push(Toast { text: text.into(), state, created: Instant::now() });
        if self.toasts.len() > 4 {
            self.toasts.remove(0);
        }
    }

    fn go_to(&mut self, address: Address, record: bool) {
        self.nav.go_to(address.clone(), record);
        self.after_move(address, record);
    }

    fn after_move(&mut self, address: Address, record: bool) {
        self.address_text = address::format(&address);
        self.session.address = Some(address.clone());
        self.events.push_back(ShellEvent::AddressChanged { address: address.clone(), record });
        self.lookup_function(address);
    }

    /// Qt `MainWindow::decompile`: resolve the containing function, then
    /// broadcast it (the decompile trigger).
    fn lookup_function(&mut self, address: Address) {
        self.lookup_generation += 1;
        if self.session.program.is_empty() {
            return;
        }
        let program = self.session.program.clone();
        let offset = address.offset;
        let task = self.service.request(move |core| core.function_at(&program, offset).map_err(|error| error.to_string()));
        self.lookup = Some((self.lookup_generation, address, task));
    }

    fn apply(&mut self, command: Command) {
        match command {
            Command::Navigate { address, record } => self.go_to(address, record),
            Command::Back => {
                if let Some(address) = self.nav.back() {
                    self.after_move(address, false);
                }
            }
            Command::Forward => {
                if let Some(address) = self.nav.forward() {
                    self.after_move(address, false);
                }
            }
            Command::Status { text, error } => self.set_status(text, error),
            Command::RenameFunction { address, name: None } => {
                let name = self.session.function.as_ref().map(|function| function.name.clone()).unwrap_or_default();
                self.rename = Some(RenameDialog { address, name });
            }
            Command::RenameFunction { address, name: Some(name) } => self.rename_function(address, name),
            Command::Comment { address, kind, text } => {
                let program = self.session.program.clone();
                let function = self.session.function.as_ref().map(|function| function.entry.clone());
                let label = format!("comment {}", address::format(&address));
                self.followups.push(self.service.job(label, move |job| {
                    let core = job.fork()?;
                    let function = function.unwrap_or_else(|| address.clone());
                    let kind = if kind.is_empty() { "eol".to_string() } else { kind };
                    core.comment_command(&program, &address, &function, &kind, &text).map_err(|error| error.to_string())?;
                    job.detail("comment applied");
                    Ok(Followup::Revision { program, change: Change::Comment, message: "Comment applied".into() })
                }));
            }
            Command::Undo => {
                let program = self.session.program.clone();
                self.followups.push(self.service.job("undo", move |job| {
                    let core = job.fork()?;
                    let message = core.undo_last(&program).map_err(|error| error.to_string())?;
                    job.detail(message.clone());
                    Ok(Followup::Revision { program, change: Change::Undo, message })
                }));
            }
            Command::ImportNative { binary, name } => {
                self.followups.push(self.service.job("native import", move |job| {
                    job.progress(format!("importing {}", binary.display()));
                    let core = job.fork()?;
                    core.import_native(&binary, &name).map_err(|error| error.to_string())?;
                    job.detail(format!("imported {name}"));
                    Ok(Followup::Imported { message: format!("Imported {name}"), program: name })
                }));
            }
            Command::OpenProgram(program) => {
                self.followups.push(self.service.job("open program", move |job| {
                    let core = job.fork()?;
                    core.open_program(&program).map_err(|error| error.to_string())?;
                    job.detail(format!("opened {program}"));
                    Ok(Followup::Switch { message: format!("Opened {program}"), program })
                }));
            }
            Command::SwitchProgram(program) => self.switch_program(&program),
            Command::Raise(id) => self.raise_panel(id),
            Command::Refresh => self.load_program_panels(true),
            Command::Decompile => {
                if let Some(address) = self.session.address.clone() {
                    self.lookup_function(address);
                }
            }
            Command::Broadcast(event) => self.events.push_back(event),
            Command::Analyst(edit) => {
                let program = self.session.program.clone();
                let label = match &edit {
                    AnalystEdit::SetBookmark(_) => "set bookmark",
                    AnalystEdit::DeleteBookmark(_) => "delete bookmark",
                    AnalystEdit::SetPatch(_) => "set patch",
                    AnalystEdit::DeletePatch(_) => "delete patch",
                };
                self.followups.push(self.service.job(label, move |job| {
                    let core = job.fork()?;
                    let message = match &edit {
                        AnalystEdit::SetBookmark(row) => core.set_bookmark(&program, row).map(|()| format!("Bookmarked {}", address::format(&row.address))),
                        AnalystEdit::DeleteBookmark(at) => core.delete_bookmark(&program, at).map(|()| format!("Removed bookmark {}", address::format(at))),
                        AnalystEdit::SetPatch(row) => core.set_patch(&program, row).map(|()| format!("Patch at {} committed", address::format(&row.address))),
                        AnalystEdit::DeletePatch(at) => core.delete_patch(&program, at).map(|()| format!("Removed patch {}", address::format(at))),
                    }
                    .map_err(|error| error.to_string())?;
                    job.detail(message.clone());
                    Ok(Followup::Revision { program, change: Change::Analyst, message })
                }));
            }
        }
    }

    fn rename_function(&mut self, address: Address, name: String) {
        let program = self.session.program.clone();
        let label = format!("rename {}", address::format(&address));
        self.followups.push(self.service.job(label, move |job| {
            let core = job.fork()?;
            // An interior cursor names its containing function.
            let entry = core
                .function_at(&program, address.offset)
                .map_err(|error| error.to_string())?
                .map(|function| function.entry)
                .unwrap_or(address);
            core.rename_command(&program, &entry, &name).map_err(|error| error.to_string())?;
            job.detail(format!("renamed to {name}"));
            Ok(Followup::Revision { program, change: Change::Rename, message: format!("Renamed to {name}") })
        }));
    }

    /// Qt `switchProgram`: resolve the captured binary, then reload panels.
    pub fn switch_program(&mut self, program: &str) {
        if program != self.session.program && self.unsaved_work().is_some() {
            // Qt `MatchingDock::setProgram` refuses to leave unsaved work.
            self.set_status("Save this immutable candidate or discard the editor change before switching context.", true);
            return;
        }
        self.switch_generation += 1;
        self.set_status(format!("Opening {program}…"), false);
        let name = program.to_string();
        let task = self.service.request(move |core| core.program_input(&name).map_err(|error| error.to_string()));
        self.switch = Some((self.switch_generation, program.to_string(), task));
    }

    fn switched(&mut self, program: String, input: ProgramInput) {
        let binary = self.session.project.join("artifacts").join(&input.binary_digest);
        let changed = self.session.program != program;
        if changed {
            self.save_layout();
            if !self.session.program.is_empty() {
                self.address_text.clear();
            }
            self.analysis = Analysis::default();
            self.nav.reset();
            self.session.address = None;
            self.session.function = None;
            if self.persist {
                self.dock = self.restore_layout(&program);
            }
        }
        self.program_generation += 1;
        self.session.program = program.clone();
        self.session.binary = binary;
        self.events.push_back(ShellEvent::ProgramChanged);
        self.load_program_panels(false);
        self.set_status(format!("Showing {program}"), false);
    }

    /// Qt `loadProgramPanels`: reopen at the typed address, refresh status.
    fn load_program_panels(&mut self, refresh: bool) {
        if refresh {
            self.events.push_back(ShellEvent::Refresh);
        }
        if let Some(address) = address::parse(&self.address_text) {
            let record = self.nav.address().is_none();
            self.go_to(address, record);
        }
        self.refresh_analysis_status();
    }

    fn refresh_analysis_status(&mut self) {
        if self.session.program.is_empty() {
            self.analysis = Analysis::default();
            return;
        }
        let program = self.session.program.clone();
        let task = self.service.request(move |core| core.analysis_status(&program).map_err(|error| error.to_string()));
        self.analysis.status = Some((self.program_generation, task));
    }

    fn analysis_text(status: &AnalysisStatus) -> String {
        if status.stale {
            format!("provisional: {} analysed, {} to go", status.analysed, status.seeded)
        } else {
            format!("analysed: {}", status.analysed)
        }
    }

    /// Polls shell-owned tasks; returns true when anything answered.
    fn poll_shell(&mut self) {
        for finished in self.service.jobs().take_finished() {
            let failed = finished.state == JobState::Failed;
            let detail = finished.detail.lines().next().unwrap_or("");
            self.set_status(format!("{}  ·  {detail}", finished.label.trim()), failed);
            if failed || finished.elapsed >= Duration::from_secs(1) {
                let verb = match finished.state {
                    JobState::Failed => "failed",
                    JobState::Cancelled => "cancelled",
                    _ => "finished",
                };
                self.toast(format!("{} {verb}", finished.label), finished.state);
            }
        }
        if let Some(result) = poll_slot(&mut self.programs_task) {
            match result {
                Ok(rows) => {
                    self.programs = rows;
                    if self.session.program.is_empty() && self.switch.is_none() && !self.session.gate
                        && let Some(first) = self.programs.first().map(|row| row.program.clone())
                    {
                        self.switch_program(&first);
                    }
                }
                Err(error) => self.set_status(error, true),
            }
            self.programs_listed += 1;
        }
        if let Some((generation, program, task)) = self.switch.take() {
            match task.poll() {
                None => self.switch = Some((generation, program, task)),
                Some(_) if generation != self.switch_generation => {}
                Some(Ok(input)) => self.switched(program, input),
                Some(Err(error)) => self.set_status(error, true),
            }
        }
        if let Some((generation, cursor, task)) = self.lookup.take() {
            match task.poll() {
                None => self.lookup = Some((generation, cursor, task)),
                Some(_) if generation != self.lookup_generation => {}
                Some(result) => {
                    let function = match result {
                        Ok(function) => function,
                        Err(error) => {
                            self.set_status(format!("Function lookup failed: {error}"), true);
                            None
                        }
                    };
                    self.session.function = function.clone();
                    self.events.push_back(ShellEvent::FunctionChanged { function, cursor });
                }
            }
        }
        let mut index = 0;
        while index < self.followups.len() {
            let Some(result) = self.followups[index].poll() else {
                index += 1;
                continue;
            };
            self.followups.remove(index);
            match result {
                Err(error) => self.toast(error, JobState::Failed),
                Ok(Followup::Revision { program, change, message }) => {
                    self.toast(message, JobState::Succeeded);
                    if program == self.session.program {
                        self.events.push_back(ShellEvent::RevisionChanged(change));
                        if matches!(change, Change::Rename | Change::Undo)
                            && let Some(address) = self.session.address.clone()
                        {
                            self.lookup_function(address);
                        }
                    }
                }
                Ok(Followup::Switch { program, message }) => {
                    self.toast(message, JobState::Succeeded);
                    self.switch_program(&program);
                }
                Ok(Followup::Imported { program, message }) => {
                    self.toast(message, JobState::Succeeded);
                    self.switch_program(&program);
                    self.refresh_programs();
                }
            }
        }
        self.poll_analysis();
        self.poll_byte_search();
        self.toasts.retain(|toast| toast.created.elapsed() < TOAST_LIFETIME);
    }

    fn poll_analysis(&mut self) {
        let generation = self.program_generation;
        let mut answered = None;
        if let Some((task_generation, task)) = self.analysis.status.take() {
            match task.poll() {
                None => self.analysis.status = Some((task_generation, task)),
                Some(result) if task_generation == generation => answered = Some((false, result)),
                Some(_) => {}
            }
        }
        if let Some((task_generation, task)) = self.analysis.pass.take() {
            match task.poll() {
                None => self.analysis.pass = Some((task_generation, task)),
                Some(result) if task_generation == generation => answered = Some((true, result)),
                Some(_) => {}
            }
        }
        if let Some((pass, result)) = answered {
            match result {
                Ok(status) => {
                    self.analysis.label = Self::analysis_text(&status);
                    if self.analysis.first.is_empty() {
                        self.analysis.first = self.analysis.label.clone();
                    }
                    if status.stale {
                        self.analysis.next = Some(Instant::now() + ANALYSIS_INTERVAL);
                    } else {
                        self.analysis.next = None;
                        if pass {
                            // The facts changed under every view: refresh once, at the end.
                            self.events.push_back(ShellEvent::RevisionChanged(Change::Analysis));
                        }
                    }
                }
                Err(error) => {
                    self.analysis.next = None;
                    if !pass {
                        self.analysis.label.clear();
                    }
                    if pass {
                        self.set_status(error, true);
                    }
                }
            }
        }
        if let Some(next) = self.analysis.next
            && Instant::now() >= next
            && self.analysis.pass.is_none()
        {
            self.analysis.next = None;
            if self.session.program.is_empty() || self.session.binary.as_os_str().is_empty() {
                return;
            }
            let program = self.session.program.clone();
            let binary = self.session.binary.clone();
            let task = self.service.background(move |job| {
                let core = job.fork()?;
                core.analyse_pending(&binary, &program, ANALYSIS_BUDGET).map_err(|error| error.to_string())
            });
            self.analysis.pass = Some((generation, task));
        }
    }

    fn poll_byte_search(&mut self) {
        let Some((generation, task)) = self.byte_search.task.take() else { return };
        match task.poll() {
            None => self.byte_search.task = Some((generation, task)),
            Some(_) if generation != self.byte_search.generation => {}
            Some(Err(error)) => self.byte_search.status = format!("Search failed: {error}"),
            Some(Ok(hits)) => {
                let total = hits.len();
                self.byte_search.results = hits.into_iter().take(256).filter_map(|hit| hit.address).collect();
                self.byte_search.status = if total > 256 {
                    "Showing the first 256 matches; refine the pattern.".into()
                } else {
                    format!("{total} matches. Activate a result to navigate.")
                };
            }
        }
    }

    fn poll_panels(&mut self) {
        let mut cx = PanelContext::new(&self.service, &self.session, &self.theme, &self.ids, &mut self.commands);
        for panel in &mut self.panels {
            panel.poll(&mut cx);
        }
    }

    /// One logic step without drawing: poll everything, apply commands.
    pub fn step(&mut self) {
        self.poll_shell();
        self.pump();
        self.poll_panels();
        self.pump();
    }

    // ----- actions ----------------------------------------------------------

    fn actions(&self) -> Vec<ActionItem> {
        let has_program = !self.session.program.is_empty();
        let mut items = vec![
            ActionItem { menu: "File", label: "Open project…".into(), action: Action::OpenProject, shortcut: None, enabled: true, checked: None },
        ];
        for (index, path) in self.settings.recent_projects.iter().enumerate() {
            items.push(ActionItem { menu: "File", label: format!("Open recent / {path}"), action: Action::OpenRecent(index), shortcut: None, enabled: true, checked: None });
        }
        items.push(ActionItem { menu: "File", label: "Quit".into(), action: Action::Quit, shortcut: Some(QUIT_SHORTCUT), enabled: true, checked: None });
        for (index, panel) in self.panels.iter().enumerate() {
            if panel.id() == panels::matching::ID {
                // Matching is a workspace mode, not a dock (Qt View menu).
                continue;
            }
            items.push(ActionItem {
                menu: "View",
                label: panel.title(),
                action: Action::TogglePanel(index),
                shortcut: None,
                enabled: true,
                checked: Some(self.panel_open(panel.id())),
            });
        }
        items.push(ActionItem { menu: "View", label: "Theme / Follow system".into(), action: Action::Theme(ThemeChoice::System), shortcut: None, enabled: true, checked: Some(self.theme_choice == ThemeChoice::System) });
        for name in ThemeName::ALL {
            items.push(ActionItem {
                menu: "View",
                label: format!("Theme / {}", name.label()),
                action: Action::Theme(ThemeChoice::Fixed(name)),
                shortcut: None,
                enabled: true,
                checked: Some(self.theme_choice == ThemeChoice::Fixed(name)),
            });
        }
        items.push(ActionItem { menu: "View", label: "Reset workbench layout".into(), action: Action::ResetLayout, shortcut: None, enabled: true, checked: None });
        items.push(ActionItem { menu: "Go", label: "Back".into(), action: Action::Back, shortcut: Some(BACK_SHORTCUT), enabled: self.nav.can_back(), checked: None });
        items.push(ActionItem { menu: "Go", label: "Forward".into(), action: Action::Forward, shortcut: Some(FORWARD_SHORTCUT), enabled: self.nav.can_forward(), checked: None });
        items.push(ActionItem { menu: "Go", label: "Decompile".into(), action: Action::Decompile, shortcut: None, enabled: self.session.address.is_some(), checked: None });
        items.push(ActionItem { menu: "Go", label: "Refresh".into(), action: Action::Refresh, shortcut: None, enabled: has_program, checked: None });
        items.push(ActionItem { menu: "Search", label: "Command palette".into(), action: Action::CommandPalette, shortcut: Some(PALETTE_SHORTCUT), enabled: true, checked: None });
        items.push(ActionItem { menu: "Search", label: "Byte-pattern search…".into(), action: Action::ByteSearch, shortcut: None, enabled: true, checked: None });
        items.push(ActionItem { menu: "Search", label: "Recover vtables".into(), action: Action::RecoverVtables, shortcut: None, enabled: !self.session.binary.as_os_str().is_empty(), checked: None });
        items.push(ActionItem { menu: "Matching", label: "Open matching workspace".into(), action: Action::MatchingWorkspace, shortcut: Some(MATCHING_SHORTCUT), enabled: true, checked: Some(self.mode == 1) });
        items
    }

    fn run(&mut self, action: Action) {
        match action {
            Action::OpenProject => self.open_project = OpenProjectDialog { open: true, path: self.session.project.display().to_string() },
            Action::OpenRecent(index) => {
                if let Some(path) = self.settings.recent_projects.get(index).cloned() {
                    self.launch_project(&path);
                }
            }
            Action::Quit => self.quit = true,
            Action::TogglePanel(index) => self.toggle_panel(index),
            Action::Theme(choice) => self.set_theme(choice),
            Action::ResetLayout => self.dock = self.default_layout(),
            Action::CommandPalette => self.palette = Palette { open: true, ..Palette::default() },
            Action::ByteSearch => self.byte_search.open = true,
            Action::RecoverVtables => {
                self.commands.push(Command::Broadcast(ShellEvent::VtablesRequested));
                self.commands.push(Command::Raise(panels::vtables::ID));
            }
            Action::Back => self.commands.push(Command::Back),
            Action::Forward => self.commands.push(Command::Forward),
            Action::Decompile => self.commands.push(Command::Decompile),
            Action::Refresh => self.commands.push(Command::Refresh),
            Action::MatchingWorkspace => self.set_mode(1),
        }
    }

    /// Opening a project creates a separately bound window: a new process.
    fn launch_project(&mut self, path: &str) {
        let result = std::env::current_exe().and_then(|exe| std::process::Command::new(exe).arg("--project").arg(path).spawn());
        match result {
            Ok(_) => self.set_status(format!("Opened {path} in a new window"), false),
            Err(error) => self.set_status(format!("Cannot open {path}: {error}"), true),
        }
    }

    // ----- drawing ----------------------------------------------------------

    /// Installs the bundled fonts. Must run before the first frame: egui
    /// binds fonts at the start of a pass, and every widget names them.
    pub fn prepare(&mut self, context: &egui::Context) {
        if !self.fonts_installed {
            theme::install_fonts(context);
            self.fonts_installed = true;
        }
        self.service.set_waker(context.clone());
    }

    fn ensure_style(&mut self, context: &egui::Context) {
        assert!(self.fonts_installed, "DesktopApp::prepare must run before the first frame");
        let name = self.theme_choice.resolve(context.system_theme());
        if self.applied != Some(name) {
            self.theme = Theme::new(name);
            self.theme.apply(context);
            self.applied = Some(name);
        }
    }

    /// Draws one frame. Shared by the native window and the offscreen driver.
    pub fn show(&mut self, ui: &mut egui::Ui) {
        let context = ui.ctx().clone();
        self.ensure_style(&context);
        self.step();
        self.shortcuts(&context);
        self.menu_bar(ui);
        self.toolbar(ui);
        self.status_bar(ui);
        self.dock_area(ui);
        self.dialogs(&context);
        self.paint_toasts(&context);
        self.pump();
        if !self.idle() || self.analysing() || !self.toasts.is_empty() {
            context.request_repaint_after(Duration::from_millis(30));
        }
    }

    fn shortcuts(&mut self, context: &egui::Context) {
        let pressed = context.input_mut(|input| {
            [PALETTE_SHORTCUT, BACK_SHORTCUT, FORWARD_SHORTCUT, QUIT_SHORTCUT, MATCHING_SHORTCUT].map(|shortcut| input.consume_shortcut(&shortcut))
        });
        let actions = [Action::CommandPalette, Action::Back, Action::Forward, Action::Quit, Action::MatchingWorkspace];
        for (pressed, action) in pressed.into_iter().zip(actions) {
            if pressed {
                self.run(action);
            }
        }
    }

    fn menu_bar(&mut self, ui: &mut egui::Ui) {
        let theme = self.theme.clone();
        let actions = self.actions();
        let mut chosen = None;
        egui::Panel::top("menu-bar")
            .frame(egui::Frame::new().fill(theme.bg_raised).inner_margin(egui::Margin::symmetric(space::SM as i8, space::XXS as i8)))
            .show_separator_line(false)
            .show(ui, |ui| {
                egui::MenuBar::new().ui(ui, |ui| {
                    for menu in ["File", "View", "Go", "Search", "Matching"] {
                        ui.menu_button(RichText::new(menu).font(font(Type::Body)).color(theme.text_muted), |ui| {
                            let mut last_group: Option<&str> = None;
                            for item in actions.iter().filter(|item| item.menu == menu) {
                                let (group, label) = item.label.split_once(" / ").map_or((None, item.label.as_str()), |(group, label)| (Some(group), label));
                                if group != last_group {
                                    ui.separator();
                                    if let Some(group) = group {
                                        widgets::caption(ui, &theme, group);
                                    }
                                    last_group = group;
                                }
                                let mut button = egui::Button::new(RichText::new(label).font(font(Type::Body)));
                                if let Some(checked) = item.checked {
                                    button = button.selected(checked);
                                }
                                if let Some(shortcut) = &item.shortcut {
                                    button = button.shortcut_text(ui.ctx().format_shortcut(shortcut));
                                }
                                if ui.add_enabled(item.enabled, button).clicked() {
                                    chosen = Some(item.action);
                                    ui.close();
                                }
                            }
                        });
                    }
                });
            });
        if let Some(action) = chosen {
            self.run(action);
        }
    }

    fn toolbar(&mut self, ui: &mut egui::Ui) {
        let theme = self.theme.clone();
        egui::Panel::top("toolbar")
            .exact_size(metrics::TOOLBAR)
            .frame(
                egui::Frame::new()
                    .fill(theme.bg_raised)
                    .inner_margin(egui::Margin::symmetric(space::MD as i8, 0))
                    .stroke(Stroke::NONE),
            )
            .show_separator_line(false)
            .show(ui, |ui| {
                let rect = ui.max_rect();
                ui.painter().hline(rect.x_range().expand(space::MD), rect.bottom(), Stroke::new(1.0, theme.border));
                ui.horizontal_centered(|ui| {
                    ui.spacing_mut().item_spacing.x = space::XS + 2.0;
                    let mut mode = self.mode;
                    if widgets::segmented(ui, &theme, &["Analysis", "Matching"], &mut mode, &[true, true]) {
                        self.set_mode(mode);
                    }
                    widgets::toolbar_separator(ui, &theme);
                    if widgets::icon_button(ui, &theme, Icon::Back, "Back  (Alt+Left)", self.nav.can_back()).clicked() {
                        self.commands.push(Command::Back);
                    }
                    if widgets::icon_button(ui, &theme, Icon::Forward, "Forward  (Alt+Right)", self.nav.can_forward()).clicked() {
                        self.commands.push(Command::Forward);
                    }
                    widgets::toolbar_separator(ui, &theme);
                    widgets::caption(ui, &theme, "Image");
                    let selected = self
                        .programs
                        .iter()
                        .find(|row| row.program == self.session.program)
                        .map(|row| format!("{}  ·  {}", row.program, row.language))
                        .unwrap_or_else(|| if self.session.program.is_empty() { "No image".into() } else { self.session.program.clone() });
                    let mut choice = None;
                    egui::ComboBox::from_id_salt("image-picker")
                        .width(240.0)
                        .height(28.0 * 12.0)
                        .selected_text(RichText::new(selected).font(font(Type::Body)))
                        .show_ui(ui, |ui| {
                            for (index, row) in self.programs.iter().enumerate() {
                                let label = RichText::new(format!("{}  ·  {}", row.program, row.language)).font(font(Type::Body));
                                if ui.selectable_label(row.program == self.session.program, label).clicked() {
                                    choice = Some(index);
                                }
                            }
                            if self.programs.is_empty() {
                                ui.label(RichText::new("No images in this project").color(theme.text_faint));
                            }
                        });
                    if let Some(index) = choice {
                        self.select_program_at(index);
                    }
                    widgets::toolbar_separator(ui, &theme);
                    widgets::caption(ui, &theme, "Address");
                    let char_width = ui.fonts_mut(|fonts| fonts.glyph_width(&font(Type::Code), '0'));
                    let response = ui.add(
                        egui::TextEdit::singleline(&mut self.address_text)
                            .font(font(Type::Code))
                            .hint_text(RichText::new("0x…").color(theme.text_faint))
                            .margin(egui::Margin::symmetric(space::SM as i8, space::XS as i8 + 1))
                            .desired_width(char_width * metrics::ADDRESS_CHARS),
                    )
                    .on_hover_text("Navigate to an address (Enter)");
                    let entered = response.lost_focus() && ui.input(|input| input.key_pressed(Key::Enter));
                    if widgets::button(ui, &theme, "Go", true).clicked() || entered {
                        self.go_to_text();
                    }
                    if widgets::primary_button(ui, &theme, "Decompile", !self.session.program.is_empty()).clicked() {
                        self.decompile_button();
                    }
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if widgets::button(ui, &theme, "Program setup", true).clicked() {
                            self.commands.push(Command::Raise(panels::setup::ID));
                        }
                        if widgets::icon_button(ui, &theme, Icon::Refresh, "Refresh program panels", !self.session.program.is_empty()).clicked() {
                            self.commands.push(Command::Refresh);
                        }
                        if widgets::icon_button(ui, &theme, Icon::Search, "Command palette  (Ctrl+Shift+P)", true).clicked() {
                            self.run(Action::CommandPalette);
                        }
                    });
                });
            });
    }

    fn go_to_text(&mut self) {
        match address::parse(&self.address_text) {
            Some(address) => self.commands.push(Command::Navigate { address, record: true }),
            None => self.set_status(format!("Not an address: {}", self.address_text.trim()), true),
        }
    }

    /// Qt: Decompile navigates first when the field names another address.
    fn decompile_button(&mut self) {
        match address::parse(&self.address_text) {
            Some(address) if Some(&address) != self.session.address.as_ref() => {
                self.commands.push(Command::Navigate { address, record: true })
            }
            Some(_) => self.commands.push(Command::Decompile),
            None => self.set_status(format!("Not an address: {}", self.address_text.trim()), true),
        }
    }

    fn status_bar(&mut self, ui: &mut egui::Ui) {
        let theme = self.theme.clone();
        let running: Vec<_> = self
            .service
            .jobs()
            .snapshot()
            .into_iter()
            .filter(|entry| entry.state == JobState::Running)
            .collect();
        egui::Panel::bottom("status-bar")
            .exact_size(metrics::STATUS_BAR)
            .frame(egui::Frame::new().fill(theme.bg_raised).inner_margin(egui::Margin::symmetric(space::MD as i8, 0)))
            .show_separator_line(false)
            .show(ui, |ui| {
                let rect = ui.max_rect();
                ui.painter().hline(rect.x_range().expand(space::MD), rect.top(), Stroke::new(1.0, theme.border));
                ui.horizontal_centered(|ui| {
                    let (text, error) = &self.status;
                    let color = if *error { theme.error } else { theme.text_muted };
                    if *error {
                        let (dot, _) = ui.allocate_exact_size(vec2(8.0, 8.0), Sense::hover());
                        ui.painter().circle_filled(dot.center(), 3.5, theme.error);
                    }
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if !self.analysis.label.is_empty() {
                            let stale = self.analysis.label.starts_with("provisional");
                            let color = if stale { theme.warn } else { theme.text_muted };
                            ui.label(RichText::new(&self.analysis.label).font(font(Type::Caption)).color(color));
                        }
                        if !running.is_empty() {
                            let label = running.last().map(|entry| entry.label.as_str()).unwrap_or("");
                            let text = if running.len() == 1 { label.to_string() } else { format!("{} jobs  ·  {label}", running.len()) };
                            ui.label(RichText::new(text).font(font(Type::Caption)).color(theme.text_muted));
                            ui.add(egui::Spinner::new().size(12.0).color(theme.accent));
                        }
                        ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                            widgets::truncated(ui, text.clone(), Type::Caption, color);
                        });
                    });
                });
            });
    }

    fn dock_area(&mut self, ui: &mut egui::Ui) {
        if self.mode == 1 {
            let mut cx = PanelContext::new(&self.service, &self.session, &self.theme, &self.ids, &mut self.commands);
            let theme = &self.theme;
            let panels = &mut self.panels;
            egui::CentralPanel::no_frame().frame(egui::Frame::new().fill(theme.bg_app)).show(ui, |ui| {
                if let Some(panel) = panels.iter_mut().find(|panel| panel.id() == panels::matching::ID) {
                    panel.ui(ui, &mut cx);
                }
            });
            return;
        }
        let style = self.theme.dock_style(ui.style());
        let mut viewer = Viewer {
            panels: &mut self.panels,
            cx: PanelContext::new(&self.service, &self.session, &self.theme, &self.ids, &mut self.commands),
            theme: &self.theme,
            active: &mut self.active_tabs,
            drawn: Vec::new(),
        };
        egui::CentralPanel::no_frame().show(ui, |ui| {
            DockArea::new(&mut self.dock)
                .style(style)
                .show_add_buttons(false)
                .show_leaf_collapse_buttons(false)
                .show_leaf_close_all_buttons(false)
                .show_inside(ui, &mut viewer);
        });
        let drawn = std::mem::take(&mut viewer.drawn);
        if *viewer.active != drawn {
            *viewer.active = drawn;
            ui.ctx().request_repaint();
        }
    }

    fn dialogs(&mut self, context: &egui::Context) {
        self.rename_dialog(context);
        self.palette_dialog(context);
        self.byte_search_dialog(context);
        self.open_project_dialog(context);
        self.close_dialog(context);
    }

    /// Qt `MainWindow::closeEvent` → `MatchingDock::confirmClose`.
    fn close_dialog(&mut self, context: &egui::Context) {
        let Some(question) = self.close_prompt.clone() else { return };
        let theme = self.theme.clone();
        let mut choice = None;
        let response = egui::Modal::new(egui::Id::new("unsaved-close")).show(context, |ui| {
            ui.set_width(460.0);
            ui.label(RichText::new("Unsaved matching candidate").font(font(Type::Title)).color(theme.text));
            ui.add_space(space::XS);
            ui.add(egui::Label::new(RichText::new(&question).font(font(Type::Body)).color(theme.text_muted)).wrap());
            ui.add_space(space::MD);
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if widgets::primary_button(ui, &theme, "Save", true).clicked() {
                    choice = Some(true);
                }
                if widgets::button(ui, &theme, "Discard", true).clicked() {
                    choice = Some(false);
                }
                ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                    if widgets::button(ui, &theme, "Cancel", true).clicked() {
                        choice = None;
                        self.close_prompt = None;
                    }
                });
            });
        });
        if response.should_close() {
            self.close_prompt = None;
        }
        let Some(save) = choice else { return };
        self.close_prompt = None;
        let mut cx = PanelContext::new(&self.service, &self.session, &self.theme, &self.ids, &mut self.commands);
        for panel in self.panels.iter_mut().filter(|panel| panel.unsaved_work().is_some()) {
            if save {
                panel.save_work(&mut cx);
            } else {
                panel.discard_work(&mut cx);
            }
        }
        // Save closes once the candidate persisted (Qt continuation).
        self.closing = save;
        self.quit = !save;
    }

    /// Window close or Quit: true when nothing unsaved stands in the way;
    /// otherwise the Save / Discard / Cancel prompt opens.
    fn may_close(&mut self) -> bool {
        match self.unsaved_work() {
            None => true,
            Some(question) => {
                self.close_prompt = Some(question);
                false
            }
        }
    }

    fn rename_dialog(&mut self, context: &egui::Context) {
        let Some(dialog) = &mut self.rename else { return };
        let theme = self.theme.clone();
        let mut submit = false;
        let mut cancel = false;
        let response = egui::Modal::new(egui::Id::new("rename-dialog")).show(context, |ui| {
            ui.set_width(380.0);
            ui.label(RichText::new("Rename function").font(font(Type::Title)).color(theme.text));
            ui.add_space(space::XS);
            widgets::caption(ui, &theme, &format!("at {}", address::format(&dialog.address)));
            ui.add_space(space::SM);
            let edit = ui.add(
                egui::TextEdit::singleline(&mut dialog.name)
                    .font(font(Type::Code))
                    .margin(egui::Margin::symmetric(space::SM as i8, space::XS as i8 + 1))
                    .desired_width(f32::INFINITY),
            );
            edit.request_focus();
            if ui.input(|input| input.key_pressed(Key::Enter)) {
                submit = true;
            }
            ui.add_space(space::MD);
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if widgets::primary_button(ui, &theme, "Rename", !dialog.name.trim().is_empty()).clicked() {
                    submit = true;
                }
                if widgets::button(ui, &theme, "Cancel", true).clicked() {
                    cancel = true;
                }
            });
        });
        if response.should_close() {
            cancel = true;
        }
        if submit && !dialog.name.trim().is_empty() {
            let (address, name) = (dialog.address.clone(), dialog.name.trim().to_string());
            self.rename = None;
            self.rename_function(address, name);
        } else if cancel {
            self.rename = None;
        }
    }

    fn palette_dialog(&mut self, context: &egui::Context) {
        if !self.palette.open {
            return;
        }
        let theme = self.theme.clone();
        let actions: Vec<ActionItem> = self
            .actions()
            .into_iter()
            .filter(|item| item.action != Action::CommandPalette)
            .collect();
        let needle = self.palette.filter.trim().to_lowercase();
        let matches: Vec<&ActionItem> = actions
            .iter()
            .filter(|item| format!("{} / {}", item.menu, item.label).to_lowercase().contains(&needle))
            .collect();
        let (up, down, enter) = context.input_mut(|input| {
            (
                input.consume_key(Modifiers::NONE, Key::ArrowUp),
                input.consume_key(Modifiers::NONE, Key::ArrowDown),
                input.consume_key(Modifiers::NONE, Key::Enter),
            )
        });
        if up {
            self.palette.selected = self.palette.selected.saturating_sub(1);
        }
        if down && self.palette.selected + 1 < matches.len() {
            self.palette.selected += 1;
        }
        self.palette.selected = self.palette.selected.min(matches.len().saturating_sub(1));
        let mut run = enter.then(|| matches.get(self.palette.selected).filter(|item| item.enabled).map(|item| item.action)).flatten();
        let response = egui::Modal::new(egui::Id::new("command-palette")).show(context, |ui| {
            ui.set_width(560.0);
            let edit = ui.add(
                egui::TextEdit::singleline(&mut self.palette.filter)
                    .hint_text(RichText::new("Find a command…").color(theme.text_faint))
                    .font(font(Type::Body))
                    .margin(egui::Margin::symmetric(space::SM as i8, space::SM as i8))
                    .desired_width(f32::INFINITY),
            );
            edit.request_focus();
            if edit.changed() {
                self.palette.selected = 0;
            }
            ui.add_space(space::XS);
            egui::ScrollArea::vertical().max_height(340.0).show(ui, |ui| {
                for (index, item) in matches.iter().enumerate() {
                    let (rect, response) = ui.allocate_exact_size(vec2(ui.available_width(), 30.0), Sense::click());
                    let selected = index == self.palette.selected;
                    if selected {
                        ui.painter().rect_filled(rect, CornerRadius::same(metrics::RADIUS), theme.bg_selected);
                        response.scroll_to_me(None);
                    } else if response.hovered() {
                        ui.painter().rect_filled(rect, CornerRadius::same(metrics::RADIUS), theme.bg_hover);
                    }
                    let color = if item.enabled { theme.text } else { theme.text_faint };
                    ui.painter().text(rect.left_center() + vec2(space::SM, 0.0), Align2::LEFT_CENTER, format!("{}  ›  {}", item.menu, item.label.replace(" / ", "  ›  ")), font(Type::Body), color);
                    if let Some(shortcut) = &item.shortcut {
                        ui.painter().text(rect.right_center() - vec2(space::SM, 0.0), Align2::RIGHT_CENTER, ui.ctx().format_shortcut(shortcut), font(Type::Caption), theme.text_faint);
                    }
                    if response.clicked() && item.enabled {
                        run = Some(item.action);
                    }
                }
                if matches.is_empty() {
                    ui.label(RichText::new("No matching commands.").color(theme.text_faint));
                }
            });
            ui.add_space(space::XS);
            widgets::caption(ui, &theme, "Enter runs the selected command  ·  Esc closes");
        });
        if response.should_close() {
            self.palette.open = false;
        }
        if let Some(action) = run {
            self.palette.open = false;
            self.run(action);
        }
    }

    fn byte_search_dialog(&mut self, context: &egui::Context) {
        if !self.byte_search.open {
            return;
        }
        let theme = self.theme.clone();
        let binary = self.session.binary.clone();
        let mut open = true;
        let mut navigate = None;
        let mut search = false;
        egui::Window::new(RichText::new("Byte-pattern search").font(font(Type::Title)))
            .id(egui::Id::new("byte-search"))
            .open(&mut open)
            .collapsible(false)
            .default_size([520.0, 420.0])
            .show(context, |ui| {
                ui.horizontal(|ui| {
                    let edit = ui.add(
                        egui::TextEdit::singleline(&mut self.byte_search.pattern)
                            .font(font(Type::Code))
                            .hint_text(RichText::new("48 8B ?? — ?? matches any byte").color(theme.text_faint))
                            .margin(egui::Margin::symmetric(space::SM as i8, space::XS as i8 + 1))
                            .desired_width(ui.available_width() - 90.0),
                    );
                    if edit.changed() {
                        self.byte_search.generation += 1;
                        self.byte_search.results.clear();
                        self.byte_search.status.clear();
                    }
                    let enabled = !binary.as_os_str().is_empty() && !self.byte_search.pattern.trim().is_empty() && self.byte_search.task.is_none();
                    let entered = edit.lost_focus() && ui.input(|input| input.key_pressed(Key::Enter));
                    if (widgets::primary_button(ui, &theme, "Search", enabled).clicked() || entered) && enabled {
                        search = true;
                    }
                });
                let status = if binary.as_os_str().is_empty() {
                    "Open a program with a binary before searching."
                } else if self.byte_search.task.is_some() {
                    "Searching…"
                } else if self.byte_search.status.is_empty() {
                    "Enter a pattern and press Enter to search mapped bytes."
                } else {
                    &self.byte_search.status
                };
                widgets::caption(ui, &theme, status);
                ui.separator();
                egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                    for address in &self.byte_search.results {
                        let text = RichText::new(address::format(address)).font(font(Type::Code)).color(theme.syntax_address);
                        if ui.selectable_label(false, text).double_clicked() {
                            navigate = Some(address.clone());
                        }
                    }
                });
            });
        if search {
            self.byte_search.generation += 1;
            let pattern = self.byte_search.pattern.trim().to_string();
            let task = self.service.request(move |core| core.search_bytes(&binary, &pattern, 257).map_err(|error| error.to_string()));
            self.byte_search.task = Some((self.byte_search.generation, task));
        }
        if let Some(address) = navigate {
            open = false;
            self.mode = 0;
            self.commands.push(Command::Navigate { address, record: true });
        }
        self.byte_search.open = open;
    }

    fn open_project_dialog(&mut self, context: &egui::Context) {
        if !self.open_project.open {
            return;
        }
        let theme = self.theme.clone();
        let mut launch = None;
        let mut close = false;
        let response = egui::Modal::new(egui::Id::new("open-project")).show(context, |ui| {
            ui.set_width(460.0);
            ui.label(RichText::new("Open project").font(font(Type::Title)).color(theme.text));
            widgets::caption(ui, &theme, "A project directory holding project.sqlite; it opens in a new window.");
            ui.add_space(space::SM);
            ui.add(
                egui::TextEdit::singleline(&mut self.open_project.path)
                    .font(font(Type::Code))
                    .margin(egui::Margin::symmetric(space::SM as i8, space::XS as i8 + 1))
                    .desired_width(f32::INFINITY),
            );
            ui.add_space(space::MD);
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if widgets::primary_button(ui, &theme, "Open", !self.open_project.path.trim().is_empty()).clicked() {
                    launch = Some(self.open_project.path.trim().to_string());
                }
                if widgets::button(ui, &theme, "Cancel", true).clicked() {
                    close = true;
                }
            });
        });
        if response.should_close() || close {
            self.open_project.open = false;
        }
        if let Some(path) = launch {
            self.open_project.open = false;
            self.launch_project(&path);
        }
    }

    fn paint_toasts(&mut self, context: &egui::Context) {
        if self.toasts.is_empty() {
            return;
        }
        let theme = &self.theme;
        egui::Area::new(egui::Id::new("toasts"))
            .anchor(Align2::RIGHT_BOTTOM, vec2(-space::LG, -(metrics::STATUS_BAR + space::LG)))
            .order(egui::Order::Foreground)
            .interactable(false)
            .show(context, |ui| {
                for toast in &self.toasts {
                    let age = toast.created.elapsed().as_secs_f32();
                    let fade = ((TOAST_LIFETIME.as_secs_f32() - age) / 0.4).clamp(0.0, 1.0);
                    let accent = match toast.state {
                        JobState::Failed => theme.error,
                        JobState::Cancelled => theme.text_faint,
                        _ => theme.ok,
                    };
                    egui::Frame::new()
                        .fill(theme.bg_raised.gamma_multiply(fade))
                        .stroke(Stroke::new(1.0, theme.border_strong.gamma_multiply(fade)))
                        .corner_radius(CornerRadius::same(metrics::RADIUS))
                        .inner_margin(egui::Margin::symmetric(space::MD as i8, space::SM as i8))
                        .shadow(egui::Shadow { offset: [0, 4], blur: 12, spread: 0, color: Color32::from_black_alpha((60.0 * fade) as u8) })
                        .show(ui, |ui| {
                            ui.set_max_width(320.0);
                            ui.horizontal(|ui| {
                                let (dot, _) = ui.allocate_exact_size(vec2(8.0, 14.0), Sense::hover());
                                ui.painter().circle_filled(dot.center(), 3.5, accent.gamma_multiply(fade));
                                ui.add(egui::Label::new(RichText::new(&toast.text).font(font(Type::Body)).color(theme.text.gamma_multiply(fade))).wrap());
                            });
                        });
                    ui.add_space(space::SM);
                }
            });
    }

    /// Saves the layout (window close).
    pub fn save(&mut self) {
        self.save_layout();
    }
}

struct Viewer<'a> {
    panels: &'a mut [Box<dyn Panel>],
    cx: PanelContext<'a>,
    theme: &'a Theme,
    /// Tabs whose body was drawn last frame, i.e. the active tab of each
    /// visible leaf; they get the accent underline.
    active: &'a mut Vec<String>,
    drawn: Vec<String>,
}

impl TabViewer for Viewer<'_> {
    type Tab = String;

    fn title(&mut self, tab: &mut String) -> egui::WidgetText {
        let title = self.panels.iter().find(|panel| panel.id() == tab).map(|panel| panel.title()).unwrap_or_else(|| tab.clone());
        RichText::new(title).font(font(Type::Strong)).into()
    }

    fn id(&mut self, tab: &mut String) -> egui::Id {
        egui::Id::new(("panel", tab.as_str()))
    }

    fn on_tab_button(&mut self, tab: &mut String, response: &egui::Response) {
        if self.active.contains(tab) {
            let painter = response.ctx.layer_painter(response.layer_id);
            let rect = response.rect;
            painter.hline((rect.left() + space::SM)..=(rect.right() - space::SM), rect.bottom() - 1.0, Stroke::new(2.0, self.theme.accent));
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, tab: &mut String) {
        self.drawn.push(tab.clone());
        if let Some(panel) = self.panels.iter_mut().find(|panel| panel.id() == tab) {
            panel.ui(ui, &mut self.cx);
        }
    }

    fn scroll_bars(&self, _tab: &String) -> [bool; 2] {
        [false, false]
    }
}

impl eframe::App for DesktopApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.show(ui);
        let requested = ui.ctx().input(|input| input.viewport().close_requested());
        if self.closing && self.panels.iter().all(|panel| !panel.busy()) {
            // A prompted save settled: close only if it left nothing unsaved
            // (a failed save stays open with its error, as in Qt).
            self.closing = false;
            self.quit = self.unsaved_work().is_none();
        }
        if requested || self.quit {
            let allowed = self.close_prompt.is_none() && !self.closing && self.may_close();
            if !allowed {
                self.quit = false;
                if requested {
                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::CancelClose);
                }
            } else if self.quit {
                ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
            }
        }
    }

    fn on_exit(&mut self) {
        self.save();
        self.service.shutdown();
    }
}
