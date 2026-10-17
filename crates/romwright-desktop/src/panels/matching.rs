//! Matching workspace (Qt `MatchingDock` + `matching_dock_dialogs.cpp`): pick
//! a workspace and an immutable candidate, edit its source, compile and
//! compare against the reference object, search selected expressions,
//! protect bytes with pins, calibrate toolchains, trial shared context, bind
//! a real project patch, and move workspaces between machines.
//!
//! Workspace management (`WorkspaceOperation`) runs on a forked Core off the
//! request mutex, like the bridge's `matching_workspace`. Compiler work
//! (`MatchingOperation`) is a logged job whose cancel token is the execution
//! request's, so the Jobs panel's and this panel's Cancel reach the worker
//! watchdog. The shell shows this panel as its own full-width workspace
//! (toolbar Analysis / Matching), never as a dock tab.

mod dialogs;
mod text;
mod view;

pub use dialogs::{Dialog, JsonPurpose, NewWorkspaceForm, PathPurpose};

use crate::panel::{Panel, PanelContext, PanelId, Placement, ShellEvent};
use crate::service::{JobContext, Task, TaskResult};
use romwright_core::Core;
use romwright_model::matching::{
    CalibrationResult, CandidateChange, ContextComparison, MatchDiagnosis, MatchingCandidate, MatchingOperation,
    MatchingWorkspace, MismatchEvidence, PatchVerification, ProjectPatch, SearchRequest, SourcePin, TrialBatch,
    TrialRecord, WorkspaceBundle, WorkspaceCreated, WorkspaceImport, WorkspaceSetup,
};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const ID: PanelId = "matching";

/// Page size of every continuation list (Qt `limit: 128`).
const PAGE: usize = 128;
/// Mismatch rows shown; full evidence stays in Diagnostics.
const MISMATCH_ROWS: usize = 512;
/// Workspace bundles larger than this are refused (Qt: 64 MiB).
const MAX_BUNDLE: u64 = 64 * 1024 * 1024;

/// Every button of the workspace. The UI and the gate both go through
/// [`MatchingPanel::enabled`] and [`MatchingPanel::trigger`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    RefreshWorkspaces,
    MoreWorkspaces,
    NewWorkspace,
    Import,
    Export,
    MoreCandidates,
    AddProfile,
    Calibrate,
    TrialContext,
    ExplicitSearch,
    Save,
    Discard,
    Pin,
    ClearPins,
    Run,
    Search,
    Cancel,
    RefreshHistory,
    MoreHistory,
    Checks,
    MoreChecks,
    BindProject,
    PreparePatch,
    Verify,
    Apply,
}

/// Right-hand evidence tabs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tab {
    Compare,
    History,
    Patch,
    Diagnostics,
}

impl Tab {
    pub const ALL: [Tab; 4] = [Tab::Compare, Tab::History, Tab::Patch, Tab::Diagnostics];

    fn label(self) -> &'static str {
        match self {
            Tab::Compare => "Compare",
            Tab::History => "History",
            Tab::Patch => "Project patch",
            Tab::Diagnostics => "Diagnostics",
        }
    }
}

/// A finished compiler job's typed answer.
#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum Outcome {
    Trial(TrialRecord),
    Batch(TrialBatch),
    Calibration(CalibrationResult),
    Context(Vec<ContextComparison>),
    Patch(ProjectPatch),
    Verification(PatchVerification),
}

/// What the panel did, for the matching gate (Qt `MatchingDock` signals).
#[derive(Clone, Debug)]
pub enum MatchingEvent {
    WorkspaceLoaded(u64),
    CandidateLoaded(u64),
    /// `statusRequested(message, true)`.
    Failed(String),
    /// `statusRequested(message, false)`.
    Status(String),
    /// `jobFinished(label, false, detail)`.
    JobFailed(String),
    /// `operationFinished(result)`.
    Operation(Box<Outcome>),
}

/// Whether the reference object came out of the trial.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectVerdict {
    NotBuilt,
    Exact(bool),
}

/// The evidence summary over the mismatch table (Qt `summary_`).
#[derive(Clone, Debug)]
pub struct Evidence {
    pub symbol: String,
    pub candidate: u64,
    pub similarity: Option<f64>,
    pub instructions: Option<bool>,
    pub relocations: Option<bool>,
    pub object: ObjectVerdict,
    pub project: Option<bool>,
}

/// One rendered history row (Qt `history_` cells).
#[derive(Clone, Debug)]
pub struct HistoryRow {
    pub cells: [String; 8],
    pub similarity: Option<f64>,
    pub exact: Option<bool>,
}

/// Editor work the next frame applies through egui's own text state, so
/// selection and undo are the editor's (Qt `QTextCursor`, `undo()`).
#[derive(Clone, Debug)]
enum EditorAction {
    Select(Range<usize>),
    Replace(String),
    Undo,
    /// A newly loaded text starts a fresh undo history (Qt `setPlainText`).
    Reset,
}

/// What to do with a workspace request's answer (Qt `ValueCallback`s).
enum Reply {
    Workspaces { after: u64 },
    Created,
    Load,
    Candidates { after: u64 },
    Candidate { ticket: u64 },
    Source { candidate: u64, file: String },
    Saved { text: String, then: Then },
    Accept,
    Trials { after: u64 },
    Checks { after: u64 },
    ProfileBase,
    ProjectBase,
    ProfileUpdated,
    ProjectUpdated,
    Exported,
    ImportRead,
    PrivateHashed,
    Imported,
}

enum Answer {
    Workspaces(Vec<MatchingWorkspace>),
    Created(Box<WorkspaceCreated>),
    Workspace(Box<MatchingWorkspace>),
    Candidates(Vec<MatchingCandidate>),
    Candidate(Box<MatchingCandidate>),
    Source(String),
    Trials(Vec<TrialRecord>),
    Checks(Vec<PatchVerification>),
    Bundle(Box<WorkspaceBundle>),
    Hashed(BTreeMap<String, String>),
    Done,
}

/// Continuation after the editor's text is saved as a candidate (Qt
/// `saveSource(continuation)`).
enum Then {
    Nothing,
    Run,
    Pin { clear: bool, selection: SourcePin },
    Search { selection: SourcePin },
    Calibrate,
    Explicit,
    PreparePatch,
}

struct Request {
    generation: u64,
    reply: Reply,
    task: Task<Answer>,
}

struct RunningJob {
    label: String,
    generation: u64,
    task: Task<Outcome>,
}

pub struct MatchingPanel {
    program: String,
    binary: PathBuf,
    workspaces: Vec<(u64, String)>,
    candidates: Vec<(u64, String)>,
    profiles: Vec<String>,
    profile: usize,
    files: Vec<String>,
    file: usize,
    workspace: Option<MatchingWorkspace>,
    candidate: Option<MatchingCandidate>,
    patch: Option<ProjectPatch>,
    patch_text: String,
    trials: Vec<TrialRecord>,
    history: Vec<HistoryRow>,
    history_selected: Option<usize>,
    checks: Vec<PatchVerification>,
    details: String,
    evidence: Option<Evidence>,
    note: Option<String>,
    mismatches: Vec<MismatchEvidence>,
    loaded_file: String,
    loaded_source: String,
    source: String,
    was_modified: bool,
    /// Selected characters of `source` (egui cursor indices).
    selection: Range<usize>,
    editor: Vec<EditorAction>,
    generation: u64,
    candidate_generation: u64,
    requests: Vec<Request>,
    job: Option<RunningJob>,
    state: String,
    state_error: bool,
    pub tab: Tab,
    /// Compilation budget (Qt `budget_`, 1..=4096).
    pub budget: usize,
    /// Wall-clock budget in seconds (Qt `seconds_`, 1..=3600).
    pub seconds: u64,
    setup_open: bool,
    dialog: Option<Dialog>,
    /// Bundle waiting for private inputs and bindings during import.
    import: Option<(WorkspaceBundle, BTreeSet<String>, BTreeMap<String, String>)>,
    record: bool,
    events: Vec<MatchingEvent>,
}

impl Default for MatchingPanel {
    fn default() -> Self {
        Self {
            program: String::new(),
            binary: PathBuf::new(),
            workspaces: Vec::new(),
            candidates: Vec::new(),
            profiles: Vec::new(),
            profile: 0,
            files: Vec::new(),
            file: 0,
            workspace: None,
            candidate: None,
            patch: None,
            patch_text: String::new(),
            trials: Vec::new(),
            history: Vec::new(),
            history_selected: None,
            checks: Vec::new(),
            details: String::new(),
            evidence: None,
            note: None,
            mismatches: Vec::new(),
            loaded_file: String::new(),
            loaded_source: String::new(),
            source: String::new(),
            was_modified: false,
            selection: 0..0,
            editor: Vec::new(),
            generation: 0,
            candidate_generation: 0,
            requests: Vec::new(),
            job: None,
            state: "No matching workspace selected.".into(),
            state_error: false,
            tab: Tab::Compare,
            budget: 12,
            seconds: 120,
            setup_open: false,
            dialog: None,
            import: None,
            record: false,
            events: Vec::new(),
        }
    }
}

// ----- helpers shared with the view and the gate ----------------------------

fn verdict(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "exact",
        Some(false) => "different",
        None => "unknown",
    }
}

fn object_verdict(trial: &TrialRecord) -> ObjectVerdict {
    if trial.candidate_digest.is_none() {
        ObjectVerdict::NotBuilt
    } else {
        ObjectVerdict::Exact(trial.diagnosis.exact_object_bytes)
    }
}

fn object_text(verdict_: ObjectVerdict) -> &'static str {
    match verdict_ {
        ObjectVerdict::NotBuilt => "not built",
        ObjectVerdict::Exact(exact) => verdict(Some(exact)),
    }
}

fn percent(value: Option<f64>) -> String {
    value.map_or_else(|| "unscored".into(), |value| format!("{value:.2}%"))
}

fn object_offset(value: Option<u64>) -> String {
    value.map(|value| format!("0x{value:x}")).unwrap_or_default()
}

fn candidate_label(candidate: &MatchingCandidate) -> String {
    format!("#{} {}", candidate.id, candidate.spec.label)
}

fn workspace_label(workspace: &MatchingWorkspace) -> String {
    format!("{} · {} (#{})", workspace.spec.name, workspace.spec.symbol, workspace.id)
}

fn status_text<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value).ok().and_then(|value| value.as_str().map(str::to_owned)).unwrap_or_default()
}

fn pretty<T: Serialize>(value: &T) -> String {
    serde_json::to_string_pretty(value).unwrap_or_default()
}

/// Byte offset of character `index` in `text` (the editor counts
/// characters, the store counts UTF-8 bytes).
pub fn byte_offset(text: &str, index: usize) -> usize {
    text.char_indices().nth(index).map_or(text.len(), |(offset, _)| offset)
}

/// Character index of byte `offset`, clamped to a boundary at or before it.
pub fn char_index(text: &str, offset: usize) -> usize {
    let mut offset = offset.min(text.len());
    while !text.is_char_boundary(offset) {
        offset -= 1;
    }
    text[..offset].chars().count()
}

fn history_row(trial: &TrialRecord) -> HistoryRow {
    let diagnosis = &trial.diagnosis;
    let provenance = if trial.imported { " · imported, unverified" } else { " · local" };
    HistoryRow {
        cells: [
            format!("{} / #{}", trial.id, trial.candidate),
            trial.profile.clone(),
            percent(diagnosis.similarity),
            verdict(diagnosis.exact_instructions).into(),
            verdict(diagnosis.exact_relocations).into(),
            object_text(object_verdict(trial)).into(),
            format!("{}{provenance}", status_text(&trial.status)),
            format!("{} ms", trial.elapsed_ms),
        ],
        similarity: diagnosis.similarity,
        exact: (trial.candidate_digest.is_some()).then_some(diagnosis.exact_object_bytes),
    }
}

/// `which`: the first executable named `name` on `PATH` (Qt
/// `QStandardPaths::findExecutable`).
fn find_executable(name: &str) -> String {
    std::env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| std::env::split_paths(&paths).collect::<Vec<_>>())
        .map(|directory| directory.join(name))
        .find(|path| path.is_file())
        .map(|path| path.display().to_string())
        .unwrap_or_default()
}

impl MatchingPanel {
    // ----- read-only state for the view and the gate --------------------------

    pub fn program(&self) -> &str {
        &self.program
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    /// The editor holds text that is not a saved candidate.
    pub fn modified(&self) -> bool {
        !self.loaded_file.is_empty() && self.source != self.loaded_source
    }

    pub fn candidate_id(&self) -> Option<u64> {
        self.candidate.as_ref().map(|candidate| candidate.id)
    }

    pub fn candidate_entries(&self) -> &[(u64, String)] {
        &self.candidates
    }

    pub fn files(&self) -> &[String] {
        &self.files
    }

    pub fn mismatch_rows(&self) -> usize {
        self.mismatches.len()
    }

    pub fn history_rows(&self) -> usize {
        self.history.len()
    }

    pub fn state(&self) -> (&str, bool) {
        (&self.state, self.state_error)
    }

    pub fn dialog(&mut self) -> Option<&mut Dialog> {
        self.dialog.as_mut()
    }

    pub fn has_dialog(&self) -> bool {
        self.dialog.is_some()
    }

    /// Text of every pin on the loaded file, in pin order.
    pub fn pinned_texts(&self) -> Vec<String> {
        if self.modified() {
            return Vec::new();
        }
        self.candidate
            .iter()
            .flat_map(|candidate| &candidate.spec.pins)
            .filter(|pin| pin.file == self.loaded_file)
            .filter_map(|pin| self.source.get(pin.start..pin.end).map(str::to_owned))
            .collect()
    }

    /// Starts recording [`MatchingEvent`]s for [`Self::take_events`].
    pub fn record_events(&mut self) {
        self.record = true;
    }

    pub fn take_events(&mut self) -> Vec<MatchingEvent> {
        std::mem::take(&mut self.events)
    }

    fn emit(&mut self, event: MatchingEvent) {
        if self.record {
            self.events.push(event);
        }
    }

    fn idle(&self) -> bool {
        self.job.is_none() && self.requests.is_empty()
    }

    fn source_ready(&self) -> bool {
        self.candidate.is_some()
            && !self.loaded_file.is_empty()
            && self.files.get(self.file).is_some_and(|file| *file == self.loaded_file)
    }

    /// The editor accepts typing (Qt `!source_->isReadOnly()`).
    pub fn editable(&self) -> bool {
        self.idle() && self.source_ready()
    }

    fn project_root(&self) -> Option<&str> {
        self.workspace
            .as_ref()?
            .spec
            .project
            .as_ref()?
            .root
            .as_deref()
            .filter(|root| !root.is_empty())
    }

    /// Qt `updateControls`.
    pub fn enabled(&self, action: Action) -> bool {
        let idle = self.idle();
        let run = idle && self.candidate.is_some() && !self.binary.as_os_str().is_empty();
        let verify = idle && self.patch.is_some() && !self.binary.as_os_str().is_empty();
        match action {
            Action::Save | Action::Discard => idle && self.source_ready() && self.modified(),
            Action::Run | Action::Search => run,
            Action::PreparePatch => run && self.project_root().is_some(),
            Action::Verify | Action::Apply => verify,
            Action::Cancel => self.job.is_some(),
            _ => idle && !self.program.is_empty(),
        }
    }

    fn profile_name(&self) -> String {
        self.profiles.get(self.profile).cloned().unwrap_or_default()
    }

    fn current_file(&self) -> String {
        self.files.get(self.file).cloned().unwrap_or_default()
    }

    /// The editor selection as UTF-8 byte offsets (Qt `selection()`).
    fn selected(&self) -> SourcePin {
        let start = byte_offset(&self.source, self.selection.start.min(self.selection.end));
        let end = byte_offset(&self.source, self.selection.start.max(self.selection.end));
        SourcePin { file: self.loaded_file.clone(), start, end }
    }

    fn selected_text(&self) -> String {
        let pin = self.selected();
        self.source.get(pin.start..pin.end).unwrap_or_default().to_string()
    }

    // ----- status ------------------------------------------------------------

    fn fail(&mut self, cx: &mut PanelContext<'_>, message: impl Into<String>) {
        let message = message.into();
        self.state = message.clone();
        self.state_error = true;
        cx.error(message.clone());
        self.emit(MatchingEvent::Failed(message));
    }

    fn inform(&mut self, text: impl Into<String>) {
        self.state = text.into();
        self.state_error = false;
    }

    /// Qt `canLeaveSource`.
    fn can_leave_source(&mut self, cx: &mut PanelContext<'_>) -> bool {
        if !self.modified() {
            return true;
        }
        self.fail(cx, "Save this immutable candidate or discard the editor change before switching context.");
        false
    }

    // ----- requests ----------------------------------------------------------

    /// Qt `workspaceRequest`: a forked Core so a slow setup (compiler
    /// version probes, import hashing) never holds the shared Core mutex.
    fn request(
        &mut self,
        cx: &mut PanelContext<'_>,
        reply: Reply,
        work: impl FnOnce(&Core, &str) -> Result<Answer, String> + Send + 'static,
    ) {
        if self.program.is_empty() {
            self.fail(cx, "Open a program first.");
            return;
        }
        let program = self.program.clone();
        let task = cx.service.background(move |job: &JobContext| {
            let core = job.fork()?;
            work(&core, &program)
        });
        self.requests.push(Request { generation: self.generation, reply, task });
    }

    fn reset(&mut self) {
        self.workspace = None;
        self.candidate = None;
        self.patch = None;
        self.patch_text.clear();
        self.candidates.clear();
        self.files.clear();
        self.file = 0;
        self.profiles.clear();
        self.profile = 0;
        self.source.clear();
        self.loaded_source.clear();
        self.loaded_file.clear();
        self.was_modified = false;
        self.selection = 0..0;
        self.editor.clear();
        self.history.clear();
        self.trials.clear();
        self.checks.clear();
        self.details.clear();
        self.mismatches.clear();
        self.evidence = None;
        self.note = None;
    }

    /// Qt `setProgram` (the shell refuses the switch first while the editor
    /// holds unsaved text, see [`Panel::unsaved_work`]).
    fn set_program(&mut self, cx: &mut PanelContext<'_>, program: &str, binary: &Path) {
        if program == self.program {
            self.binary = binary.to_path_buf();
            return;
        }
        if let Some(job) = self.job.take() {
            job.task.cancel();
        }
        self.generation += 1;
        self.candidate_generation += 1;
        self.requests.clear();
        self.program = program.to_string();
        self.binary = binary.to_path_buf();
        self.workspaces.clear();
        self.reset();
        self.dialog = None;
        self.import = None;
        self.inform(if program.is_empty() { "No matching workspace selected." } else { "Loading matching workspaces…" });
        self.refresh_workspaces(cx, 0);
    }

    fn refresh_workspaces(&mut self, cx: &mut PanelContext<'_>, after: u64) {
        if self.program.is_empty() {
            return;
        }
        self.request(cx, Reply::Workspaces { after }, move |core, program| {
            core.matching_workspaces(program, after, PAGE).map(Answer::Workspaces).map_err(|error| error.to_string())
        });
    }

    pub fn create_workspace(&mut self, cx: &mut PanelContext<'_>, setup: WorkspaceSetup) {
        if !self.can_leave_source(cx) {
            return;
        }
        self.request(cx, Reply::Created, move |core, program| {
            core.setup_matching_workspace(program, setup).map(|created| Answer::Created(Box::new(created))).map_err(|error| error.to_string())
        });
    }

    /// Qt `loadWorkspace`.
    pub fn load_workspace(&mut self, cx: &mut PanelContext<'_>, id: u64) {
        if id == 0 || !self.can_leave_source(cx) {
            return;
        }
        self.generation += 1;
        self.candidate_generation += 1;
        self.requests.clear();
        self.reset();
        self.request(cx, Reply::Load, move |core, program| {
            core.matching_workspace(program, id).map(|workspace| Answer::Workspace(Box::new(workspace))).map_err(|error| error.to_string())
        });
    }

    fn refresh_candidates(&mut self, cx: &mut PanelContext<'_>, after: u64) {
        let Some(workspace) = self.workspace.as_ref().map(|workspace| workspace.id) else { return };
        self.request(cx, Reply::Candidates { after }, move |core, program| {
            core.matching_candidates(program, workspace, after, PAGE).map(Answer::Candidates).map_err(|error| error.to_string())
        });
    }

    /// Qt `loadCandidate`.
    pub fn load_candidate(&mut self, cx: &mut PanelContext<'_>, id: u64) {
        if id == 0 || !self.can_leave_source(cx) {
            return;
        }
        self.candidate_generation += 1;
        let ticket = self.candidate_generation;
        self.request(cx, Reply::Candidate { ticket }, move |core, program| {
            core.matching_candidate(program, id).map(|candidate| Answer::Candidate(Box::new(candidate))).map_err(|error| error.to_string())
        });
    }

    fn add_candidate_entry(&mut self, candidate: &MatchingCandidate) {
        if !self.candidates.iter().any(|(id, _)| *id == candidate.id) {
            self.candidates.push((candidate.id, candidate_label(candidate)));
        }
    }

    /// Qt `acceptCandidate`.
    fn accept_candidate(&mut self, cx: &mut PanelContext<'_>, candidate: MatchingCandidate) {
        self.patch = None;
        self.patch_text.clear();
        self.add_candidate_entry(&candidate);
        let previous = self.current_file();
        self.files = candidate.spec.files.keys().cloned().collect();
        let primary = self.workspace.as_ref().map(|workspace| workspace.spec.source.clone()).unwrap_or_default();
        self.file = self
            .files
            .iter()
            .position(|file| *file == previous)
            .or_else(|| self.files.iter().position(|file| *file == primary))
            .unwrap_or(0);
        self.candidate = Some(candidate);
        self.load_source(cx);
    }

    /// Qt `loadSource`; also the file selector's `activated`.
    pub fn select_file(&mut self, cx: &mut PanelContext<'_>, index: usize) {
        if !self.can_leave_source(cx) {
            return;
        }
        if index < self.files.len() {
            self.file = index;
        }
        self.load_source(cx);
    }

    fn load_source(&mut self, cx: &mut PanelContext<'_>) {
        let Some(candidate) = self.candidate.as_ref().map(|candidate| candidate.id) else { return };
        let file = self.current_file();
        if file.is_empty() {
            return;
        }
        self.loaded_file.clear();
        self.loaded_source.clear();
        self.source.clear();
        self.was_modified = false;
        self.selection = 0..0;
        let wanted = file.clone();
        self.request(cx, Reply::Source { candidate, file }, move |core, program| {
            core.matching_source(program, candidate, &wanted).map(Answer::Source).map_err(|error| error.to_string())
        });
    }

    /// Qt `saveSource`: an unmodified editor continues at once.
    fn save_source(&mut self, cx: &mut PanelContext<'_>, then: Then) {
        let Some(candidate) = self.candidate.as_ref().map(|candidate| candidate.id) else {
            self.fail(cx, "Select a candidate.");
            return;
        };
        if !self.modified() {
            self.continue_with(cx, then);
            return;
        }
        let text = self.source.clone();
        let file = self.loaded_file.clone();
        let source = text.clone();
        self.request(cx, Reply::Saved { text, then }, move |core, program| {
            core.replace_matching_source(program, candidate, &file, &source, &format!("Edit {file}"))
                .map(|candidate| Answer::Candidate(Box::new(candidate)))
                .map_err(|error| error.to_string())
        });
    }

    fn discard_source(&mut self) {
        self.source = self.loaded_source.clone();
        self.reset_editor();
    }

    fn reset_editor(&mut self) {
        self.editor.clear();
        self.editor.push(EditorAction::Reset);
    }

    fn continue_with(&mut self, cx: &mut PanelContext<'_>, then: Then) {
        let Some(candidate) = self.candidate.clone() else { return };
        let profile = self.profile_name();
        match then {
            Then::Nothing => {}
            Then::Run => self.execute(cx, MatchingOperation::Trial { candidate: candidate.id, profile }),
            Then::Pin { clear, selection } => {
                let mut pins = if clear { Vec::new() } else { candidate.spec.pins.clone() };
                if !clear {
                    pins.push(selection);
                }
                let change = CandidateChange {
                    parent: candidate.id,
                    label: if clear { "Clear source pins" } else { "Pin source selection" }.into(),
                    edits: Vec::new(),
                    pins: Some(pins),
                };
                self.request(cx, Reply::Accept, move |core, program| {
                    core.change_matching_candidate(program, change).map(|candidate| Answer::Candidate(Box::new(candidate))).map_err(|error| error.to_string())
                });
            }
            Then::Search { selection } => {
                let request = SearchRequest {
                    candidate: candidate.id,
                    profile,
                    max_compilations: self.budget,
                    alternatives: Vec::new(),
                    expression: Some(selection),
                };
                self.execute(cx, MatchingOperation::Search { request });
            }
            Then::Calibrate => {
                let initial = json!({
                    "operation": "calibrate",
                    "candidates": [candidate.id],
                    "profiles": self.profiles,
                    "max_compilations": self.budget,
                });
                self.dialog = Some(Dialog::json(
                    "Calibrate actual toolchains",
                    "Choose known-reference candidate IDs and profile names. Every candidate/profile pair is compiled; equal scores remain tied, not identified as a unique compiler.",
                    &initial,
                    JsonPurpose::Operation,
                ));
            }
            Then::Explicit => {
                let selected = self.selected();
                let initial = json!({
                    "operation": "search",
                    "request": {
                        "candidate": candidate.id,
                        "profile": profile,
                        "max_compilations": self.budget,
                        "expression": null,
                        "alternatives": [[{
                            "file": self.loaded_file,
                            "start": selected.start,
                            "end": selected.end,
                            "replacement": self.selected_text(),
                            "reason": "Test this explicit alternative",
                        }]],
                    },
                });
                self.dialog = Some(Dialog::json(
                    "Bounded explicit candidate search",
                    "Each alternative is a separate array of UTF-8 source edits against the same immutable parent. Pins are enforced. Include the baseline in the compilation budget.",
                    &initial,
                    JsonPurpose::Operation,
                ));
            }
            Then::PreparePatch => self.execute(cx, MatchingOperation::PreparePatch { candidate: candidate.id, profile }),
        }
    }

    // ----- compiler jobs -----------------------------------------------------

    /// Qt `executeOperation`: one logged job per operation; its cancel token
    /// is the execution request's.
    pub fn execute(&mut self, cx: &mut PanelContext<'_>, operation: MatchingOperation) {
        if self.job.is_some() {
            self.fail(cx, "Wait for or cancel the active matching job.");
            return;
        }
        if self.binary.as_os_str().is_empty() {
            self.fail(cx, "Select the original imported binary for execution.");
            return;
        }
        let name = match &operation {
            MatchingOperation::Trial { .. } => "trial",
            MatchingOperation::Search { .. } => "search",
            MatchingOperation::Calibrate { .. } => "calibrate",
            MatchingOperation::Context { .. } => "context",
            MatchingOperation::PreparePatch { .. } => "prepare_patch",
            MatchingOperation::VerifyPatch { .. } => "verify_patch",
        };
        let label = format!("matching/{name}");
        self.inform(format!("{label} · running"));
        let (program, binary) = (self.program.clone(), self.binary.clone());
        let budget = Duration::from_secs(self.seconds);
        let task = cx.service.job(label.clone(), move |job| {
            job.progress("running");
            let core = job.fork()?;
            let request = job.execution_request(&core, &binary, &program, None, budget)?;
            let text = |error: romwright_core::CoreError| error.to_string();
            let outcome = match operation {
                MatchingOperation::Trial { candidate, profile } => {
                    Outcome::Trial(core.run_matching_candidate(&request, candidate, &profile).map_err(text)?)
                }
                MatchingOperation::Search { request: search } => {
                    Outcome::Batch(core.search_matching_candidates(&request, search).map_err(text)?)
                }
                MatchingOperation::Calibrate { candidates, profiles, max_compilations } => Outcome::Calibration(
                    core.calibrate_matching_profiles(&request, &candidates, &profiles, max_compilations).map_err(text)?,
                ),
                MatchingOperation::Context { request: context } => {
                    Outcome::Context(core.trial_matching_context(&request, context).map_err(text)?)
                }
                MatchingOperation::PreparePatch { candidate, profile } => {
                    Outcome::Patch(core.matching_project_patch(&request, candidate, &profile).map_err(text)?)
                }
                MatchingOperation::VerifyPatch { patch, apply } => {
                    Outcome::Verification(core.verify_matching_patch(&request, patch, apply).map_err(text)?)
                }
            };
            job.detail(match &outcome {
                Outcome::Batch(batch) => format!("{} compilations · {}", batch.compiler_invocations, batch.stopped),
                Outcome::Verification(check) if check.applied => "verified and applied".into(),
                Outcome::Verification(_) => "verified".into(),
                Outcome::Patch(patch) => format!("{} files", patch.files.len()),
                _ => "done".into(),
            });
            Ok(outcome)
        });
        self.job = Some(RunningJob { label, generation: self.generation, task });
    }

    /// Qt `cancelJob`.
    pub fn cancel_job(&mut self) {
        if let Some(job) = &self.job {
            job.task.cancel();
            self.inform("Cancellation requested; waiting for the running operation to settle.");
        }
    }

    fn finish_job(&mut self, cx: &mut PanelContext<'_>, label: String, result: TaskResult<Outcome>) {
        match result {
            Err(error) => {
                self.fail(cx, error.clone());
                self.emit(MatchingEvent::JobFailed(format!("{label}: {error}")));
            }
            Ok(outcome) => {
                self.render_result(&outcome);
                self.refresh_history(cx, 0);
                match &outcome {
                    Outcome::Batch(TrialBatch { best_candidate: Some(best), .. }) => self.load_candidate(cx, *best),
                    _ => self.refresh_candidates(cx, 0),
                }
                self.emit(MatchingEvent::Operation(Box::new(outcome)));
            }
        }
    }

    // ----- history -----------------------------------------------------------

    fn refresh_history(&mut self, cx: &mut PanelContext<'_>, after: u64) {
        let Some(workspace) = self.workspace.as_ref().map(|workspace| workspace.id) else { return };
        self.request(cx, Reply::Trials { after }, move |core, program| {
            core.matching_trials(program, workspace, after, PAGE).map(Answer::Trials).map_err(|error| error.to_string())
        });
    }

    fn refresh_checks(&mut self, cx: &mut PanelContext<'_>, after: u64) {
        let Some(workspace) = self.workspace.as_ref().map(|workspace| workspace.id) else { return };
        self.request(cx, Reply::Checks { after }, move |core, program| {
            core.matching_project_checks(program, workspace, after, PAGE).map(Answer::Checks).map_err(|error| error.to_string())
        });
    }

    /// History row activation (Qt `cellDoubleClicked`).
    pub fn open_trial(&mut self, cx: &mut PanelContext<'_>, row: usize) {
        let Some(trial) = self.trials.get(row).cloned() else { return };
        self.render_result(&Outcome::Trial(trial.clone()));
        self.load_candidate(cx, trial.candidate);
    }

    /// Qt `renderResult`.
    fn render_result(&mut self, outcome: &Outcome) {
        self.details = pretty(outcome);
        let mut trial: Option<TrialRecord> = None;
        let mut diagnosis: Option<MatchDiagnosis> = None;
        let mut patch_candidate = None;
        let mut project = None;
        match outcome {
            Outcome::Trial(record) => trial = Some(record.clone()),
            Outcome::Batch(batch) => {
                trial = batch
                    .trials
                    .iter()
                    .rev()
                    .find(|entry| Some(entry.candidate) == batch.best_candidate)
                    .or(batch.trials.last())
                    .cloned();
            }
            Outcome::Calibration(calibration) => trial = calibration.trials.last().cloned(),
            Outcome::Context(comparisons) => trial = comparisons.first().map(|comparison| comparison.trial.clone()),
            Outcome::Patch(patch) => {
                self.patch = Some(patch.clone());
                self.patch_text = patch.unified_diff.clone();
            }
            Outcome::Verification(check) => {
                self.patch = Some(check.patch.clone());
                self.patch_text = check.patch.unified_diff.clone();
                diagnosis = check.diagnosis.clone();
                patch_candidate = Some(check.patch.candidate);
                project = Some(check.project_exactness);
            }
        }
        if let Some(trial) = &trial {
            diagnosis = Some(trial.diagnosis.clone());
        }
        if let Some(diagnosis) = diagnosis {
            self.tab = Tab::Compare;
            let object = match (&trial, outcome) {
                (Some(trial), _) => object_verdict(trial),
                (None, Outcome::Verification(check)) if check.candidate_digest.is_some() => ObjectVerdict::Exact(diagnosis.exact_object_bytes),
                _ => ObjectVerdict::NotBuilt,
            };
            self.evidence = Some(Evidence {
                symbol: diagnosis.symbol.clone(),
                candidate: trial.as_ref().map(|trial| trial.candidate).or(patch_candidate).unwrap_or(0),
                similarity: diagnosis.similarity,
                instructions: diagnosis.exact_instructions,
                relocations: diagnosis.exact_relocations,
                object,
                project: project.flatten(),
            });
            self.note = None;
            self.mismatches = diagnosis.mismatches.into_iter().take(MISMATCH_ROWS).collect();
        }
        if let Outcome::Context(comparisons) = outcome {
            let changes: Vec<String> = comparisons
                .iter()
                .map(|comparison| {
                    format!(
                        "#{}: {} → {} ({} points)",
                        comparison.baseline.candidate,
                        percent(comparison.baseline.diagnosis.similarity),
                        percent(comparison.trial.diagnosis.similarity),
                        comparison.delta.map_or_else(|| "unknown".into(), |delta| format!("{delta:.2}")),
                    )
                })
                .collect();
            if !changes.is_empty() {
                self.note = Some(format!("Isolated context trials: {}. Mismatch table shows the first trial.", changes.join(" · ")));
            }
        }
        if let Outcome::Calibration(calibration) = outcome {
            let ranking: Vec<String> = calibration.ranking.iter().map(|(name, score)| format!("{name}: {}", percent(Some(*score)))).collect();
            self.note = Some(format!("Calibration evidence (ties retained): {}", ranking.join(" · ")));
        }
        match outcome {
            Outcome::Verification(check) => self.inform(if check.applied {
                "Reviewed source patch applied. Build outputs were not copied into the project."
            } else {
                "Verification recorded; no source applied. Inspect scope, build and regression evidence."
            }),
            Outcome::Batch(batch) => self.inform(format!(
                "{} compilations in {} ms; {}. Tested variants are not proofs of source-level equivalence.",
                batch.compiler_invocations, batch.elapsed_ms, batch.stopped
            )),
            _ => self.inform("Compilation finished; inspect the evidence."),
        }
        if matches!(outcome, Outcome::Patch(_)) {
            self.tab = Tab::Patch;
            self.inform("Source patch prepared. Review the complete diff, then verify the build.");
        }
    }

    // ----- actions -----------------------------------------------------------

    /// One click on `action`'s button.
    pub fn trigger(&mut self, cx: &mut PanelContext<'_>, action: Action) {
        if !self.enabled(action) {
            return;
        }
        match action {
            Action::RefreshWorkspaces => self.refresh_workspaces(cx, 0),
            Action::MoreWorkspaces => {
                if let Some((last, _)) = self.workspaces.last() {
                    let last = *last;
                    self.refresh_workspaces(cx, last);
                }
            }
            Action::NewWorkspace => {
                if self.can_leave_source(cx) {
                    self.dialog = Some(Dialog::NewWorkspace(NewWorkspaceForm::new(find_executable("clang"))));
                }
            }
            Action::Import => {
                if self.can_leave_source(cx) {
                    self.dialog = Some(Dialog::path("Import portable workspace", "A workspace JSON exported by Romwright (at most 64 MiB).", "", dialogs::PathPurpose::Import));
                }
            }
            Action::Export => {
                if self.workspace.is_some() {
                    self.dialog = Some(Dialog::path("Export portable matching workspace", "Private inputs and proprietary tool bytes stay excluded.", "", dialogs::PathPurpose::Export));
                }
            }
            Action::MoreCandidates => {
                if let Some((last, _)) = self.candidates.last() {
                    let last = *last;
                    self.refresh_candidates(cx, last);
                }
            }
            Action::AddProfile => self.show_workspace(cx, Reply::ProfileBase),
            Action::Calibrate => self.save_source(cx, Then::Calibrate),
            Action::TrialContext => self.trial_context(cx),
            Action::ExplicitSearch => self.save_source(cx, Then::Explicit),
            Action::Save => self.save_source(cx, Then::Nothing),
            Action::Discard => self.discard_source(),
            Action::Pin | Action::ClearPins => {
                let clear = action == Action::ClearPins;
                let selection = self.selected();
                if !clear && selection.start == selection.end {
                    self.fail(cx, "Select source bytes to protect.");
                    return;
                }
                self.save_source(cx, Then::Pin { clear, selection });
            }
            Action::Run => self.save_source(cx, Then::Run),
            Action::Search => {
                let selection = self.selected();
                if selection.start == selection.end {
                    self.fail(cx, "Select an expression or builtin scalar type for bounded search. Semantic equivalence is not assumed.");
                    return;
                }
                self.save_source(cx, Then::Search { selection });
            }
            Action::Cancel => self.cancel_job(),
            Action::RefreshHistory => self.refresh_history(cx, 0),
            Action::MoreHistory => {
                if let Some(last) = self.trials.last().map(|trial| trial.id) {
                    self.refresh_history(cx, last);
                }
            }
            Action::Checks => self.refresh_checks(cx, 0),
            Action::MoreChecks => {
                if let Some(last) = self.checks.last().map(|check| check.id) {
                    self.refresh_checks(cx, last);
                }
            }
            Action::BindProject => {
                if self.workspace.is_some() && self.can_leave_source(cx) {
                    self.show_workspace(cx, Reply::ProjectBase);
                }
            }
            Action::PreparePatch => self.save_source(cx, Then::PreparePatch),
            Action::Verify => self.verify_patch(cx, false),
            Action::Apply => {
                let root = self.project_root().unwrap_or_default().to_string();
                self.dialog = Some(Dialog::Confirm { root });
            }
        }
    }

    fn show_workspace(&mut self, cx: &mut PanelContext<'_>, reply: Reply) {
        let Some(id) = self.workspace.as_ref().map(|workspace| workspace.id) else { return };
        self.request(cx, reply, move |core, program| {
            core.matching_workspace(program, id).map(|workspace| Answer::Workspace(Box::new(workspace))).map_err(|error| error.to_string())
        });
    }

    fn update_workspace(&mut self, cx: &mut PanelContext<'_>, spec: Value, reply: Reply) {
        let Some(workspace) = self.workspace.as_ref() else { return };
        let (id, revision) = (workspace.id, workspace.revision);
        let spec = match serde_json::from_value(spec) {
            Ok(spec) => spec,
            Err(error) => {
                self.fail(cx, format!("invalid workspace spec: {error}"));
                return;
            }
        };
        self.request(cx, reply, move |core, program| {
            core.update_matching_workspace(program, id, revision, spec).map(|workspace| Answer::Workspace(Box::new(workspace))).map_err(|error| error.to_string())
        });
    }

    /// Qt `trialContext`.
    fn trial_context(&mut self, cx: &mut PanelContext<'_>) {
        let Some(candidate) = self.candidate.as_ref().map(|candidate| candidate.id) else { return };
        if !self.can_leave_source(cx) || self.loaded_file != self.current_file() {
            return;
        }
        let selected = self.selected();
        let initial = json!({
            "operation": "context",
            "request": {
                "candidates": [candidate],
                "profile": self.profile_name(),
                "max_compilations": self.budget,
                "edits": [{
                    "file": self.loaded_file,
                    "start": selected.start,
                    "end": selected.end,
                    "replacement": self.selected_text(),
                    "reason": "Trial a shared-context change",
                }],
            },
        });
        self.dialog = Some(Dialog::json(
            "Isolated shared-context trial",
            "Use candidate IDs sharing this context and UTF-8 byte edits. Each candidate gets a private fork and a real before/after build. No program types or global facts are published.",
            &initial,
            JsonPurpose::Operation,
        ));
    }

    fn verify_patch(&mut self, cx: &mut PanelContext<'_>, apply: bool) {
        if let Some(patch) = self.patch.clone() {
            self.execute(cx, MatchingOperation::VerifyPatch { patch, apply });
        }
    }

    /// Selects a candidate from the selector (Qt `candidates_` `activated`).
    pub fn select_candidate(&mut self, cx: &mut PanelContext<'_>, index: usize) {
        if let Some((id, _)) = self.candidates.get(index).cloned() {
            self.load_candidate(cx, id);
        }
    }

    pub fn select_profile(&mut self, index: usize) {
        if index < self.profiles.len() && index != self.profile {
            self.profile = index;
            self.patch = None;
            self.patch_text.clear();
        }
    }

    // ----- editor (applied by the next frame through egui's text state) --------

    /// Selects `start..end` (character indices) in the source editor.
    pub fn select_chars(&mut self, range: Range<usize>) {
        self.editor.push(EditorAction::Select(range));
    }

    /// Selects the first occurrence of `needle` after `prefix` in the editor.
    pub fn select_text(&mut self, prefix: &str, needle: &str) -> bool {
        let Some(at) = self.source.find(&format!("{prefix}{needle}")) else { return false };
        let start = char_index(&self.source, at + prefix.len());
        self.select_chars(start..start + needle.chars().count());
        true
    }

    /// Types `text` over the selection, as the analyst would.
    pub fn type_text(&mut self, text: &str) {
        self.editor.push(EditorAction::Replace(text.to_string()));
    }

    /// The editor's own undo (Ctrl+Z).
    pub fn undo(&mut self) {
        self.editor.push(EditorAction::Undo);
    }

    pub fn editor_pending(&self) -> bool {
        !self.editor.is_empty()
    }

    // ----- dialogs ------------------------------------------------------------

    pub fn reject_dialog(&mut self) {
        if let Some(Dialog::Json { back: Some(form), .. }) = self.dialog.take() {
            self.dialog = Some(Dialog::NewWorkspace(*form));
        }
        if self.dialog.is_none() {
            self.import = None;
        }
    }

    /// The dialog's OK / Yes. Invalid input keeps the dialog open with an
    /// error line, like Qt's warnings over the still-open dialog.
    pub fn accept_dialog(&mut self, cx: &mut PanelContext<'_>) {
        let Some(dialog) = self.dialog.take() else { return };
        match dialog {
            Dialog::NewWorkspace(mut form) => match form.build() {
                Ok(setup) => match serde_json::from_value::<WorkspaceSetup>(setup) {
                    Ok(setup) => self.create_workspace(cx, setup),
                    Err(error) => {
                        form.error = format!("Invalid setup: {error}");
                        self.dialog = Some(Dialog::NewWorkspace(form));
                    }
                },
                Err(error) => {
                    form.error = error;
                    self.dialog = Some(Dialog::NewWorkspace(form));
                }
            },
            Dialog::Json { title, explanation, text, purpose, back, .. } => {
                let value: Value = match serde_json::from_str(&text) {
                    Ok(value) => value,
                    Err(error) => {
                        self.dialog = Some(Dialog::Json { title, explanation, text, error: format!("Invalid JSON: {error}"), purpose, back });
                        return;
                    }
                };
                if let Err(error) = self.accept_json(cx, value, purpose.clone()) {
                    self.dialog = Some(Dialog::Json { title, explanation, text, error, purpose, back });
                }
            }
            Dialog::Path { purpose, path, title, explanation, second, .. } => {
                let path = path.trim().to_string();
                let second = second.map(|(label, value)| (label, value.trim().to_string()));
                if path.is_empty() || second.as_ref().is_some_and(|(_, value)| value.is_empty()) {
                    self.dialog = Some(Dialog::Path { purpose, path, title, explanation, second, error: "Fill in every field.".into() });
                    return;
                }
                self.accept_path(cx, purpose, path, second.map(|(_, value)| value));
            }
            Dialog::PrivateInputs { paths, .. } => {
                let paths: Vec<PathBuf> = paths.lines().map(str::trim).filter(|line| !line.is_empty()).map(PathBuf::from).collect();
                let missing = self.import.as_ref().map(|(_, missing, _)| missing.clone()).unwrap_or_default();
                self.request(cx, Reply::PrivateHashed, move |_, _| Ok(Answer::Hashed(hash_private_inputs(&paths, &missing))));
            }
            Dialog::Confirm { .. } => self.verify_patch(cx, true),
        }
    }

    fn accept_json(&mut self, cx: &mut PanelContext<'_>, value: Value, purpose: JsonPurpose) -> Result<(), String> {
        match purpose {
            JsonPurpose::Operation => {
                let operation: MatchingOperation = serde_json::from_value(value).map_err(|error| format!("Invalid operation: {error}"))?;
                self.execute(cx, operation);
            }
            JsonPurpose::Setup => {
                let setup: WorkspaceSetup = serde_json::from_value(value).map_err(|error| format!("Invalid setup: {error}"))?;
                self.create_workspace(cx, setup);
            }
            JsonPurpose::Profile { mut spec } => {
                if !value.is_object() {
                    return Err("A profile is a JSON object.".into());
                }
                if let Some(profiles) = spec.get_mut("profiles").and_then(Value::as_array_mut) {
                    profiles.push(value);
                }
                self.update_workspace(cx, spec, Reply::ProfileUpdated);
            }
            JsonPurpose::Project { mut spec } => {
                if !value.is_object() {
                    return Err("A project binding is a JSON object.".into());
                }
                spec["project"] = value;
                self.update_workspace(cx, spec, Reply::ProjectUpdated);
            }
            JsonPurpose::ImportBindings => {
                let Some((bundle, _, _)) = self.import.take() else { return Ok(()) };
                let mut request = value;
                if !request.is_object() {
                    return Err("Import bindings are a JSON object.".into());
                }
                request["bundle"] = serde_json::to_value(&bundle).map_err(|error| error.to_string())?;
                let import: WorkspaceImport = serde_json::from_value(request).map_err(|error| format!("Invalid bindings: {error}"))?;
                self.request(cx, Reply::Imported, move |core, program| {
                    core.import_matching_workspace(program, import).map(|created| Answer::Created(Box::new(created))).map_err(|error| error.to_string())
                });
            }
        }
        Ok(())
    }

    fn accept_path(&mut self, cx: &mut PanelContext<'_>, purpose: dialogs::PathPurpose, path: String, second: Option<String>) {
        match purpose {
            dialogs::PathPurpose::Export => {
                let Some(id) = self.workspace.as_ref().map(|workspace| workspace.id) else { return };
                self.request(cx, Reply::Exported, move |core, program| {
                    let bundle = core.export_matching_workspace(program, id).map_err(|error| error.to_string())?;
                    let bytes = serde_json::to_vec_pretty(&bundle).map_err(|error| error.to_string())?;
                    write_atomic(Path::new(&path), &bytes).map_err(|error| format!("Could not write workspace: {error}"))?;
                    Ok(Answer::Done)
                });
            }
            dialogs::PathPurpose::Import => {
                self.request(cx, Reply::ImportRead, move |_, _| {
                    let size = std::fs::metadata(&path).map(|metadata| metadata.len()).unwrap_or(u64::MAX);
                    let bytes = (size <= MAX_BUNDLE).then(|| std::fs::read(&path).ok()).flatten();
                    let bytes = bytes.ok_or("Workspace must be a readable JSON file of at most 64 MiB.")?;
                    let bundle: WorkspaceBundle = serde_json::from_slice(&bytes).map_err(|error| format!("Invalid workspace JSON: {error}"))?;
                    Ok(Answer::Bundle(Box::new(bundle)))
                });
            }
            dialogs::PathPurpose::ProjectRoot { mut spec } => {
                let output = second.unwrap_or_default();
                let source = spec["source"].clone();
                let symbol = spec["symbol"].as_str().unwrap_or_default().to_string();
                let mut sources = serde_json::Map::new();
                if let Some(name) = source.as_str() {
                    sources.insert(name.to_string(), source.clone());
                }
                let binding = json!({
                    "root": path,
                    "sources": sources,
                    "build": { "executable": "ninja", "arguments": [output], "environment": {} },
                    "objects": { symbol: output },
                    "linked_output": null,
                    "generated": [".ninja_log", ".ninja_deps"],
                });
                spec["project"] = binding.clone();
                self.dialog = Some(project_dialog(&binding, spec));
            }
        }
    }

    /// Missing digests in a bundle (Qt `importWorkspace` `require`).
    fn missing_inputs(bundle: &WorkspaceBundle) -> BTreeSet<String> {
        let mut missing = BTreeSet::new();
        let mut require = |digest: &str| {
            if !digest.is_empty() && !bundle.artifacts.contains_key(digest) {
                missing.insert(digest.to_string());
            }
        };
        require(&bundle.workspace.target.digest);
        for file in bundle.workspace.files.values() {
            require(&file.digest);
        }
        for candidate in &bundle.candidates {
            for file in candidate.spec.files.values() {
                require(&file.digest);
            }
        }
        missing
    }

    fn continue_import(&mut self) {
        let Some((_, missing, found)) = &self.import else { return };
        if missing.is_empty() {
            let initial = json!({
                "private_files": found,
                "compilers": {},
                "tools": {},
                "objdiff": null,
                "project_root": null,
            });
            self.dialog = Some(Dialog::json(
                "Local import bindings",
                "Map profile names to installed compiler/wrapper paths and declared tool names to local paths when needed. Imported results are unverified until rerun. Leave project_root null unless explicitly rebinding a real source tree.",
                &initial,
                JsonPurpose::ImportBindings,
            ));
        } else {
            self.dialog = Some(Dialog::PrivateInputs { missing: missing.iter().cloned().collect(), paths: String::new() });
        }
    }

    // ----- answers -----------------------------------------------------------

    fn answered(&mut self, cx: &mut PanelContext<'_>, reply: Reply, answer: Answer) {
        match (reply, answer) {
            (Reply::Workspaces { after }, Answer::Workspaces(rows)) => {
                if after == 0 {
                    self.workspaces.clear();
                }
                for workspace in &rows {
                    if !self.workspaces.iter().any(|(id, _)| *id == workspace.id) {
                        self.workspaces.push((workspace.id, workspace_label(workspace)));
                    }
                }
                if self.workspace.is_none() && self.requests.iter().all(|request| !matches!(request.reply, Reply::Load)) {
                    if let Some((first, _)) = self.workspaces.first().cloned() {
                        self.load_workspace(cx, first);
                    } else {
                        self.inform("No matching workspace yet. New… sets one up from a reference object, source and compiler.");
                    }
                }
            }
            (Reply::Created, Answer::Created(created)) => {
                let id = created.workspace.id;
                self.load_workspace(cx, id);
            }
            (Reply::Imported, Answer::Created(created)) => {
                let id = created.workspace.id;
                self.load_workspace(cx, id);
                cx.status("Workspace imported; imported trials stay unverified until rerun.");
            }
            (Reply::Load, Answer::Workspace(workspace)) => {
                let id = workspace.id;
                if !self.workspaces.iter().any(|(known, _)| *known == id) {
                    self.workspaces.push((id, workspace_label(&workspace)));
                }
                self.profiles = workspace.spec.profiles.iter().map(|profile| profile.name.clone()).collect();
                self.profile = 0;
                self.workspace = Some(*workspace);
                self.refresh_candidates(cx, 0);
                self.emit(MatchingEvent::WorkspaceLoaded(id));
            }
            (Reply::Candidates { after }, Answer::Candidates(rows)) => {
                if after == 0 {
                    self.candidates.clear();
                }
                for candidate in &rows {
                    self.add_candidate_entry(candidate);
                }
                if let Some(candidate) = self.candidate.clone() {
                    self.add_candidate_entry(&candidate);
                } else if let Some((first, _)) = self.candidates.first().cloned() {
                    self.load_candidate(cx, first);
                }
            }
            (Reply::Candidate { ticket }, Answer::Candidate(candidate)) => {
                if ticket != self.candidate_generation {
                    return;
                }
                if Some(candidate.workspace) != self.workspace.as_ref().map(|workspace| workspace.id) {
                    self.fail(cx, "Candidate belongs to another workspace.");
                    return;
                }
                self.accept_candidate(cx, *candidate);
                self.refresh_history(cx, 0);
            }
            (Reply::Source { candidate, file }, Answer::Source(text)) => {
                if self.candidate_id() != Some(candidate) || self.current_file() != file {
                    return;
                }
                self.loaded_file = file.clone();
                self.loaded_source = text.clone();
                self.source = text;
                self.was_modified = false;
                self.selection = 0..0;
                self.reset_editor();
                self.inform(format!("Candidate #{candidate} · {file}. Saves fork history; only Verify & apply writes project source."));
                self.emit(MatchingEvent::CandidateLoaded(candidate));
            }
            (Reply::Saved { text, then }, Answer::Candidate(candidate)) => {
                self.loaded_source = text;
                self.source = self.loaded_source.clone();
                self.was_modified = false;
                self.add_candidate_entry(&candidate);
                self.candidate = Some(*candidate);
                self.continue_with(cx, then);
            }
            (Reply::Accept, Answer::Candidate(candidate)) => self.accept_candidate(cx, *candidate),
            (Reply::Trials { after }, Answer::Trials(rows)) => {
                if after == 0 {
                    self.trials.clear();
                    self.history.clear();
                    self.history_selected = None;
                }
                self.history.extend(rows.iter().map(history_row));
                self.trials.extend(rows);
            }
            (Reply::Checks { after }, Answer::Checks(rows)) => {
                if after == 0 {
                    self.checks.clear();
                }
                self.checks.extend(rows);
                self.details = pretty(&self.checks);
                self.tab = Tab::Diagnostics;
                self.inform(format!("{} project checks loaded. More project checks continues the recorded history.", self.checks.len()));
            }
            (Reply::ProfileBase, Answer::Workspace(workspace)) => {
                let spec = serde_json::to_value(&workspace.spec).unwrap_or(Value::Null);
                let current = self.profile_name();
                let base = workspace
                    .spec
                    .profiles
                    .iter()
                    .find(|profile| profile.name == current)
                    .or(workspace.spec.profiles.first())
                    .cloned();
                self.workspace = Some(*workspace);
                let Some(mut profile) = base.and_then(|profile| serde_json::to_value(profile).ok()) else { return };
                profile["name"] = Value::String(format!("{}-variant", profile["name"].as_str().unwrap_or_default()));
                if let Some(object) = profile.as_object_mut() {
                    object.remove("compiler_digest");
                }
                if let Some(tools) = profile.get_mut("tools").and_then(Value::as_object_mut) {
                    for tool in tools.values_mut() {
                        tool["digest"] = Value::String(String::new());
                    }
                }
                self.dialog = Some(Dialog::json(
                    "Add immutable compiler profile",
                    "Use a new name. Existing profiles stay unchanged. Argument arrays preserve ordering; installed tools are pinned when saved.",
                    &profile,
                    JsonPurpose::Profile { spec },
                ));
            }
            (Reply::ProjectBase, Answer::Workspace(workspace)) => {
                let spec = serde_json::to_value(&workspace.spec).unwrap_or(Value::Null);
                let binding = workspace.spec.project.clone().filter(|binding| binding.root.is_some());
                self.workspace = Some(*workspace);
                match binding {
                    Some(binding) => {
                        let binding = serde_json::to_value(binding).unwrap_or(Value::Null);
                        self.dialog = Some(project_dialog(&binding, spec));
                    }
                    None => {
                        self.dialog = Some(Dialog::Path {
                            title: "Real project build root".into(),
                            explanation: "The local source tree whose build produces this function, and the project-relative object output containing it.".into(),
                            path: String::new(),
                            second: Some(("Fresh build output".into(), String::new())),
                            error: String::new(),
                            purpose: dialogs::PathPurpose::ProjectRoot { spec },
                        });
                    }
                }
            }
            (Reply::ProfileUpdated, Answer::Workspace(workspace)) => {
                self.profiles = workspace.spec.profiles.iter().map(|profile| profile.name.clone()).collect();
                self.profile = self.profiles.len().saturating_sub(1);
                self.workspace = Some(*workspace);
            }
            (Reply::ProjectUpdated, Answer::Workspace(workspace)) => {
                self.workspace = Some(*workspace);
                self.patch = None;
                self.patch_text.clear();
                self.inform("Project binding saved. Prepare a source patch to review it.");
            }
            (Reply::Exported, Answer::Done) => {
                let message = "Workspace exported; private inputs and proprietary tool bytes remain excluded.";
                self.inform(message);
                cx.status(message);
                self.emit(MatchingEvent::Status(message.into()));
            }
            (Reply::ImportRead, Answer::Bundle(bundle)) => {
                let missing = Self::missing_inputs(&bundle);
                self.import = Some((*bundle, missing, BTreeMap::new()));
                self.continue_import();
            }
            (Reply::PrivateHashed, Answer::Hashed(found)) => {
                if let Some((_, missing, known)) = &mut self.import {
                    for (digest, path) in found {
                        missing.remove(&digest);
                        known.insert(digest, path);
                    }
                }
                self.continue_import();
            }
            _ => {}
        }
    }

    fn poll_requests(&mut self, cx: &mut PanelContext<'_>) {
        let mut index = 0;
        while index < self.requests.len() {
            let Some(result) = self.requests[index].task.poll() else {
                index += 1;
                continue;
            };
            let request = self.requests.remove(index);
            if request.generation != self.generation {
                continue;
            }
            match result {
                Ok(answer) => self.answered(cx, request.reply, answer),
                Err(error) => {
                    if matches!(request.reply, Reply::PrivateHashed | Reply::ImportRead | Reply::Imported) {
                        self.import = None;
                    }
                    self.fail(cx, error);
                }
            }
        }
    }
}

/// Qt `configureProject`'s binding editor.
fn project_dialog(binding: &Value, spec: Value) -> Dialog {
    Dialog::json(
        "Bind a reviewable source patch",
        "Map workspace source/header files to real project paths. Name the actual build command and fresh outputs. objects authorizes individual function/data symbols, including reported anonymous-data ranges. generated never hides object changes. Optional linked_output is compared with the imported binary.",
        binding,
        JsonPurpose::Project { spec },
    )
}

/// Hashes user-chosen files (directories contribute their files) and keeps
/// those naming a missing digest (Qt: SHA-256 over each selected file).
fn hash_private_inputs(paths: &[PathBuf], missing: &BTreeSet<String>) -> BTreeMap<String, String> {
    let mut files = Vec::new();
    for path in paths {
        if path.is_dir() {
            if let Ok(entries) = std::fs::read_dir(path) {
                files.extend(entries.flatten().map(|entry| entry.path()).filter(|path| path.is_file()));
            }
        } else {
            files.push(path.clone());
        }
    }
    let mut found = BTreeMap::new();
    for file in files {
        if std::fs::metadata(&file).map_or(true, |metadata| metadata.len() > MAX_BUNDLE) {
            continue;
        }
        if let Some(digest) = romwright_core::import_cache::digest(&file)
            && missing.contains(&digest)
        {
            found.insert(digest, file.display().to_string());
        }
    }
    found
}

/// Qt `QSaveFile`: write beside, then rename over.
fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    std::fs::write(&temporary, bytes)?;
    std::fs::rename(&temporary, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&temporary);
    })
}

impl Panel for MatchingPanel {
    fn id(&self) -> PanelId {
        ID
    }

    fn title(&self) -> String {
        if self.program.is_empty() { "Matching".into() } else { format!("Matching — {}", self.program) }
    }

    fn placement(&self) -> Placement {
        Placement::Bottom
    }

    fn open_by_default(&self) -> bool {
        false
    }

    fn on_event(&mut self, event: &ShellEvent, cx: &mut PanelContext<'_>) {
        if let ShellEvent::ProgramChanged = event {
            let (program, binary) = (cx.session.program.clone(), cx.session.binary.clone());
            self.set_program(cx, &program, &binary);
        }
    }

    fn poll(&mut self, cx: &mut PanelContext<'_>) {
        self.poll_requests(cx);
        if let Some(job) = &self.job
            && let Some(result) = job.task.poll()
        {
            let job = self.job.take().expect("polled job");
            if job.generation == self.generation {
                self.finish_job(cx, job.label, result);
            }
        }
        let modified = self.modified();
        if modified != self.was_modified {
            // Qt `modificationChanged`: a stale patch preview is dropped.
            self.was_modified = modified;
            self.patch = None;
            self.patch_text.clear();
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, cx: &mut PanelContext<'_>) {
        view::show(self, ui, cx);
    }

    fn busy(&self) -> bool {
        !self.idle()
    }

    fn unsaved_work(&self) -> Option<String> {
        self.modified().then(|| "Save these source edits as an immutable candidate before closing? This does not modify project files.".to_string())
    }

    fn save_work(&mut self, cx: &mut PanelContext<'_>) {
        self.save_source(cx, Then::Nothing);
    }

    fn discard_work(&mut self, _cx: &mut PanelContext<'_>) {
        self.discard_source();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn editor_offsets_follow_utf8_bytes() {
        let text = "/* Ünï — */ x + 1";
        let start = text.find("1").unwrap();
        let index = char_index(text, start);
        assert_eq!(byte_offset(text, index), start);
        assert_eq!(&text[byte_offset(text, index)..byte_offset(text, index + 1)], "1");
        assert!(index < start, "multi-byte characters precede the literal");
    }

    #[test]
    fn verdicts_match_the_qt_wording() {
        assert_eq!(verdict(Some(true)), "exact");
        assert_eq!(verdict(Some(false)), "different");
        assert_eq!(verdict(None), "unknown");
        assert_eq!(percent(Some(80.0)), "80.00%");
        assert_eq!(percent(None), "unscored");
        assert_eq!(object_offset(Some(0x1a)), "0x1a");
    }
}
