//! `--matching-gate CONFIG.json` (Qt `matching_gate.cpp`): drives the real
//! matching workspace — its buttons, editor, dialogs, actual compiler and
//! project verifier — through the whole workflow, offscreen through wgpu.
//!
//! The configuration and the report are Qt's. Configuration keys: `name`,
//! `symbol`, `target`, `source`, `root`, `compiler` (the New-workspace
//! form), `project` (the binding that replaces the binding editor's JSON),
//! `bundle` (export/import path), `store` (the project directory, whose
//! `artifacts/` hold the private inputs), `apply_project`, `before_image`,
//! `after_image` and `report`. On success the indented report is written to
//! `report` and printed on stdout; any failure prints
//! `matching UI gate: <message>` on stderr and exits 1. Phase numbers match
//! the Qt gate so a timeout names the same step. An optional
//! `dialog_images` directory also receives `<phase>-<dialog>.png` of every
//! dialog as it opens and `25-patch.png` of the prepared source patch, for
//! visual review; the report is unchanged.

use crate::app::{DesktopApp, Options};
use crate::headless::Driver;
use crate::panel::PanelContext;
use crate::panels::matching::{self, Action, Dialog, JsonPurpose, MatchingEvent, MatchingPanel, Outcome, Tab};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

pub struct MatchingGateArgs {
    pub config: PathBuf,
    pub options: Options,
    pub width: u32,
    pub height: u32,
    pub scale: f32,
    /// Overall limit; `None` keeps the Qt gate's 60 seconds.
    pub timeout: Option<Duration>,
}

const TIMEOUT: Duration = Duration::from_secs(60);

struct Gate {
    config: Value,
    phase: u32,
    mismatch_rows: usize,
    pinned: u64,
    revision: u64,
    private_inputs: BTreeSet<String>,
    /// Phase-11 undo issued; checked once the editor applied it.
    undone: bool,
    /// A click to deliver once the editor applied the selection before it.
    deferred: Option<Action>,
    /// Screenshot to take after the next rendered frame, then the phase.
    capture: Option<(PathBuf, u32)>,
    /// The dialog kind accepted last frame; still open next frame = refused.
    accepted: Option<&'static str>,
    /// Dialog screenshot pending (`dialog_images`): path and frames to wait
    /// so the modal's fade-in has settled.
    dialog_shot: Option<(PathBuf, u8)>,
    shots: BTreeSet<(u32, &'static str)>,
    started: Instant,
    error: Option<String>,
}

fn dialog_kind(dialog: &Dialog) -> &'static str {
    match dialog {
        Dialog::NewWorkspace(_) => "new",
        Dialog::Json { .. } => "json",
        Dialog::Path { .. } => "path",
        Dialog::PrivateInputs { .. } => "private",
        Dialog::Confirm { .. } => "confirm",
    }
}

fn dialog_error(dialog: &Dialog) -> String {
    match dialog {
        Dialog::NewWorkspace(form) => form.error.clone(),
        Dialog::Json { error, .. } | Dialog::Path { error, .. } => error.clone(),
        _ => String::new(),
    }
}

impl Gate {
    fn text(&self, key: &str) -> String {
        self.config.get(key).and_then(Value::as_str).unwrap_or_default().to_string()
    }

    fn fail(&mut self, message: impl Into<String>) {
        if self.error.is_none() {
            self.error = Some(message.into());
        }
    }

    fn require(&mut self, ok: bool, message: &str) -> bool {
        if !ok {
            self.fail(message);
        }
        ok
    }

    /// Qt `candidateLoaded` handler.
    fn candidate_loaded(&mut self, panel: &MatchingPanel) {
        let source = panel.source();
        match self.phase {
            1 if source.contains("+ 2") => self.phase = 2,
            6 if source.contains("+ 1") => self.phase = 7,
            8 => {
                let pinned = panel.pinned_texts();
                if !self.require(pinned.first().is_some_and(|text| text == "1"), "UTF-8 pin did not select the correct UTF-16 source character") {
                    return;
                }
                self.pinned = panel.candidate_id().unwrap_or(0);
                self.phase = 9;
            }
            18 if source.contains("unsigned char") => self.phase = 19,
            33 => self.phase = 34,
            35 if source.contains("+ 1") => self.phase = 36,
            _ => {}
        }
    }

    /// Qt `statusRequested(message, true)` handler.
    fn failed(&mut self, panel: &MatchingPanel, message: String) {
        if self.phase == 10 {
            let kept = panel.modified() && panel.source().contains("+ 9") && panel.candidate_id() == Some(self.pinned);
            if self.require(kept, "Rejected pin edit changed immutable candidate state") {
                self.phase = 11;
            }
        } else {
            self.fail(message);
        }
    }

    /// Qt `operationFinished` handler.
    fn operation(&mut self, panel: &mut MatchingPanel, outcome: Outcome) {
        match (self.phase, outcome) {
            (3, Outcome::Trial(trial)) => {
                let visible = trial.diagnosis.similarity.is_some_and(|similarity| similarity < 100.0) && panel.mismatch_rows() > 0;
                if !self.require(visible, "Initial mismatch was not visible") {
                    return;
                }
                self.mismatch_rows = panel.mismatch_rows();
                self.revision = trial.run.as_ref().map_or(0, |run| run.record.revision);
                self.capture = Some((PathBuf::from(self.text("before_image")), 4));
            }
            (5, Outcome::Batch(batch)) => {
                if !self.require(batch.compiler_invocations == 2 && batch.best_candidate.is_some(), "Bounded search did not finish in two actual compilations") {
                    return;
                }
                if !self.require(batch.trials.last().is_some_and(|trial| trial.diagnosis.exact_object_bytes), "Search did not reach exact object bytes") {
                    return;
                }
                self.phase = 6;
            }
            (13, Outcome::Trial(trial)) => {
                if self.require(trial.candidate == self.pinned && trial.diagnosis.exact_object_bytes, "Reverted pinned candidate did not recompile exactly") {
                    self.phase = 14;
                }
            }
            (16, Outcome::Calibration(calibration)) => {
                let ok = calibration.ranking.len() == 1 && calibration.ranking[0].1 == 100.0;
                if self.require(ok, "Desktop calibration did not compile its selected reference") {
                    self.phase = 17;
                }
            }
            (20, Outcome::Context(comparisons)) => {
                let ok = comparisons.len() == 1
                    && comparisons[0].delta.is_some_and(|delta| delta < 0.0)
                    && panel.source().contains("unsigned char");
                if self.require(ok, "Context trial did not report the regression while preserving selected context") {
                    self.phase = 21;
                }
            }
            (24, Outcome::Patch(patch)) => {
                if self.require(!patch.unified_diff.is_empty(), "Real-project source preview is empty") {
                    self.phase = 25;
                    if let Some(directory) = self.config.get("dialog_images").and_then(Value::as_str) {
                        self.dialog_shot = Some((Path::new(directory).join("25-patch.png"), 4));
                    }
                }
            }
            (phase @ (26 | 28), Outcome::Verification(check)) => {
                let ok = check.baseline_build_succeeded
                    && check.build_succeeded
                    && check.original_inputs_unchanged
                    && check.diagnosis.as_ref().is_some_and(|diagnosis| diagnosis.exact_object_bytes)
                    && check.unexpected_symbols.is_empty()
                    && check.applied == (phase == 28);
                if self.require(ok, "Desktop real-project verification did not preserve its build/application contract") {
                    self.phase = if phase == 26 { 27 } else { 29 };
                }
            }
            (37, Outcome::Trial(trial)) => {
                let ok = trial.diagnosis.exact_object_bytes && !trial.imported && trial.run.as_ref().map(|run| run.record.revision) == Some(self.revision);
                if self.require(ok, "Imported source did not replay exactly without changing program facts") {
                    self.phase = 38;
                }
            }
            _ => {}
        }
    }

    /// Qt `handleModal`.
    fn modal(&mut self, panel: &mut MatchingPanel, cx: &mut PanelContext<'_>) {
        let phase = self.phase;
        let Some(dialog) = panel.dialog() else {
            self.accepted = None;
            return;
        };
        let kind = dialog_kind(dialog);
        if self.accepted == Some(kind) {
            let error = dialog_error(dialog);
            self.fail(if error.is_empty() { format!("the {kind} dialog stayed open at phase {phase}") } else { error });
            return;
        }
        if self.dialog_shot.is_some() {
            return;
        }
        if let Some(directory) = self.config.get("dialog_images").and_then(Value::as_str)
            && self.shots.insert((phase, kind))
        {
            self.dialog_shot = Some((Path::new(directory).join(format!("{phase:02}-{kind}.png")), 4));
            return;
        }
        let accept = match dialog {
            Dialog::Confirm { .. } if phase == 28 => true,
            Dialog::Confirm { root } => {
                let root = root.clone();
                self.fail(format!("unexpected confirmation for {root}"));
                return;
            }
            Dialog::NewWorkspace(form) if phase == 1 => {
                form.name = self.text("name");
                form.symbol = self.text("symbol");
                form.target = self.text("target");
                form.source = self.text("source");
                form.root = self.text("root");
                form.compiler = self.text("compiler");
                true
            }
            Dialog::Path { purpose, path, second, .. } => match purpose {
                matching::PathPurpose::ProjectRoot { .. } if phase == 22 => {
                    *path = self.text("root");
                    if let Some((_, output)) = second {
                        *output = "unit.o".into();
                    }
                    true
                }
                matching::PathPurpose::Export if phase == 30 => {
                    *path = self.text("bundle");
                    true
                }
                matching::PathPurpose::Import if phase == 32 => {
                    *path = self.text("bundle");
                    true
                }
                _ => false,
            },
            Dialog::PrivateInputs { paths, .. } if phase == 32 => {
                let artifacts = Path::new(&self.text("store")).join("artifacts");
                *paths = self.private_inputs.iter().map(|digest| artifacts.join(digest).display().to_string()).collect::<Vec<_>>().join("\n");
                true
            }
            Dialog::Json { text, purpose, .. } if matches!(phase, 16 | 20 | 22 | 32) => {
                let mut object: Value = serde_json::from_str(text).unwrap_or(Value::Null);
                match phase {
                    20 => object["request"]["edits"][0]["replacement"] = json!("unsigned int"),
                    22 if matches!(purpose, JsonPurpose::Project { .. }) => {
                        object = self.config.get("project").cloned().unwrap_or(Value::Null);
                        self.phase = 23;
                    }
                    32 if matches!(purpose, JsonPurpose::ImportBindings) => {
                        object["project_root"] = Value::Null;
                        self.phase = 33;
                    }
                    _ => {}
                }
                *text = serde_json::to_string_pretty(&object).unwrap_or_default();
                true
            }
            _ => false,
        };
        if accept {
            self.accepted = Some(kind);
            panel.accept_dialog(cx);
        }
    }

    /// Qt `inspectBundle`: private bytes and tools must stay out.
    fn inspect_bundle(&mut self) -> bool {
        let Ok(bytes) = std::fs::read(self.text("bundle")) else { return false };
        let bundle: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        let artifacts = bundle["artifacts"].as_object().cloned().unwrap_or_default();
        let mut inputs = vec![bundle["workspace"]["target"].clone()];
        for candidate in bundle["candidates"].as_array().into_iter().flatten() {
            inputs.extend(candidate["spec"]["files"].as_object().into_iter().flat_map(|files| files.values().cloned()));
        }
        for input in inputs {
            let digest = input["digest"].as_str().unwrap_or_default().to_string();
            let public = input["redistributable"].as_bool().unwrap_or(false);
            if !public && artifacts.contains_key(&digest) {
                self.fail("Desktop export included private bytes");
                return false;
            }
            if !artifacts.contains_key(&digest) {
                self.private_inputs.insert(digest);
            }
        }
        for profile in bundle["workspace"]["profiles"].as_array().into_iter().flatten() {
            let compiler = profile["compiler_digest"].as_str().unwrap_or_default();
            if !self.require(!artifacts.contains_key(compiler), "Desktop export included compiler bytes") {
                return false;
            }
            for tool in profile["tools"].as_object().into_iter().flat_map(|tools| tools.values()) {
                let digest = tool["digest"].as_str().unwrap_or_default();
                if !self.require(!artifacts.contains_key(digest), "Desktop export included a proprietary tool") {
                    return false;
                }
            }
        }
        self.error.is_none()
    }

    /// Qt `tick`. Returns the final report once phase 38 completes.
    fn tick(&mut self, panel: &mut MatchingPanel, cx: &mut PanelContext<'_>) -> Option<Value> {
        if panel.editor_pending() || self.capture.is_some() || self.dialog_shot.is_some() {
            return None;
        }
        if let Some(action) = self.deferred.take() {
            panel.trigger(cx, action);
            return None;
        }
        let on = |action| panel.enabled(action);
        match self.phase {
            0 if on(Action::NewWorkspace) => {
                self.phase = 1;
                panel.trigger(cx, Action::NewWorkspace);
            }
            2 if on(Action::Run) => {
                self.phase = 3;
                panel.trigger(cx, Action::Run);
            }
            4 if on(Action::Search) => {
                if !self.require(panel.select_text("+ ", "2"), "Literal selection is missing") {
                    return None;
                }
                panel.budget = 3;
                self.phase = 5;
                self.deferred = Some(Action::Search);
            }
            7 if on(Action::Pin) => {
                if !self.require(panel.select_text("+ ", "1"), "Literal selection is missing") {
                    return None;
                }
                self.phase = 8;
                self.deferred = Some(Action::Pin);
            }
            9 if panel.editable() => {
                if !self.require(panel.select_text("+ ", "1"), "Literal selection is missing") {
                    return None;
                }
                panel.type_text("9");
                self.phase = 10;
                self.deferred = Some(Action::Save);
            }
            11 if panel.editable() => {
                if !self.undone {
                    self.undone = true;
                    panel.undo();
                    return None;
                }
                if !self.require(!panel.modified() && panel.source().contains("+ 1"), "Editor undo did not restore the pinned source") {
                    return None;
                }
                self.phase = 12;
            }
            12 if on(Action::Run) => {
                self.phase = 13;
                panel.trigger(cx, Action::Run);
            }
            14 if on(Action::Run) => {
                if self.require(panel.history_rows() >= 4, "Actual trial history was not populated") {
                    self.phase = 15;
                }
            }
            15 if on(Action::Calibrate) => {
                self.phase = 16;
                panel.trigger(cx, Action::Calibrate);
            }
            17 if panel.editable() => {
                let Some(index) = panel.files().iter().position(|file| file == "types.h") else {
                    self.fail("Shared header is absent");
                    return None;
                };
                self.phase = 18;
                panel.select_file(cx, index);
            }
            19 if on(Action::TrialContext) => {
                let Some(start) = panel.source().find("unsigned char") else {
                    self.fail("Shared context type is absent");
                    return None;
                };
                let start = matching::char_index(panel.source(), start);
                panel.select_chars(start..start + 13);
                self.phase = 20;
                self.deferred = Some(Action::TrialContext);
            }
            21 if on(Action::BindProject) => {
                self.phase = 22;
                panel.trigger(cx, Action::BindProject);
            }
            23 if on(Action::PreparePatch) => {
                self.phase = 24;
                panel.trigger(cx, Action::PreparePatch);
            }
            25 if on(Action::Verify) => {
                self.phase = 26;
                panel.trigger(cx, Action::Verify);
            }
            27 if on(Action::Apply) => {
                if self.config.get("apply_project").and_then(Value::as_bool).unwrap_or(false) {
                    self.phase = 28;
                    panel.trigger(cx, Action::Apply);
                } else {
                    self.phase = 29;
                }
            }
            29 if on(Action::Export) => {
                self.phase = 30;
                panel.trigger(cx, Action::Export);
            }
            30 if on(Action::Export) && Path::new(&self.text("bundle")).exists() && !panel.has_dialog() => {
                if self.inspect_bundle() {
                    self.phase = 31;
                }
            }
            31 if on(Action::Import) => {
                self.phase = 32;
                panel.trigger(cx, Action::Import);
            }
            34 if on(Action::Run) => {
                if !self.require(!on(Action::PreparePatch), "Imported project was automatically rebound") {
                    return None;
                }
                let found = panel.candidate_entries().iter().rposition(|(_, label)| label.ends_with("Pin source selection"));
                let Some(found) = found else {
                    self.fail("Portable pinned candidate is absent");
                    return None;
                };
                self.phase = 35;
                panel.select_candidate(cx, found);
            }
            36 if on(Action::Run) => {
                self.phase = 37;
                panel.trigger(cx, Action::Run);
            }
            38 if on(Action::Run) => {
                panel.tab = Tab::History;
                return Some(json!({
                    "passed": true,
                    "elapsed_ms": self.started.elapsed().as_millis() as u64,
                    "mismatch_rows": self.mismatch_rows,
                    "search_compiler_invocations": 2,
                    "exact_object_recompiled": true,
                    "utf16_pin_correct": true,
                    "protected_edit_rejected": true,
                    "editor_undo_restored": true,
                    "history_rows": panel.history_rows(),
                    "calibration": true,
                    "isolated_context_regression": true,
                    "project_verified": true,
                    "project_applied": self.config.get("apply_project").cloned().unwrap_or(Value::Null),
                    "portable_private_inputs_excluded": true,
                    "portable_replay_exact": true,
                    "native_revision_unchanged": true,
                    "before_image": self.config.get("before_image").cloned().unwrap_or(Value::Null),
                    "after_image": self.config.get("after_image").cloned().unwrap_or(Value::Null),
                }));
            }
            _ => {}
        }
        None
    }
}

/// Qt `QJsonDocument::toJson(Indented)`: sorted keys, four-space indent.
fn indented(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    let formatter = serde_json::ser::PrettyFormatter::with_indent(b"    ");
    let mut serializer = serde_json::Serializer::with_formatter(&mut bytes, formatter);
    serde::Serialize::serialize(value, &mut serializer).expect("serializing JSON into memory");
    bytes.push(b'\n');
    bytes
}

fn failure(message: &str) -> ExitCode {
    eprintln!("matching UI gate: {message}");
    ExitCode::FAILURE
}

pub fn run(args: MatchingGateArgs) -> ExitCode {
    let config = match std::fs::read(&args.config) {
        Ok(bytes) => bytes,
        Err(_) => return failure("Cannot open gate configuration"),
    };
    let config: Value = match serde_json::from_slice(&config) {
        Ok(config @ Value::Object(_)) => config,
        _ => return failure("Invalid gate configuration"),
    };
    let timeout = args.timeout.unwrap_or(TIMEOUT);
    let mut options = args.options;
    options.persist = false;
    let mut driver = match Driver::new(args.width, args.height, args.scale) {
        Ok(driver) => driver,
        Err(error) => return failure(&error),
    };
    eprintln!("matching UI gate: rendering offscreen on {}", driver.offscreen.adapter);
    let mut app = DesktopApp::new(options);
    if let Some(error) = app.service().startup_error() {
        return failure(error);
    }
    app.set_mode(1);
    app.with_panel::<MatchingPanel, _>(matching::ID, |panel, _| panel.record_events());
    let mut gate = Gate {
        config,
        phase: 0,
        mismatch_rows: 0,
        pinned: 0,
        revision: 0,
        private_inputs: BTreeSet::new(),
        undone: false,
        deferred: None,
        capture: None,
        accepted: None,
        dialog_shot: None,
        shots: BTreeSet::new(),
        started: Instant::now(),
        error: None,
    };
    loop {
        driver.frame(&mut app);
        if let Some((path, next)) = gate.capture.take() {
            // The frame just rendered shows the state being recorded.
            match driver.save_png(&path) {
                Ok(()) => gate.phase = next,
                Err(_) => gate.fail(if next == 4 { "Could not save mismatch screenshot" } else { "Could not save history screenshot" }),
            }
        }
        match gate.dialog_shot.take() {
            Some((path, 0)) => {
                if let Err(error) = driver.save_png(&path) {
                    eprintln!("matching UI gate: dialog screenshot {}: {error}", path.display());
                }
            }
            Some((path, frames)) => gate.dialog_shot = Some((path, frames - 1)),
            None => {}
        }
        let report = app
            .with_panel::<MatchingPanel, _>(matching::ID, |panel, cx| {
                for event in panel.take_events() {
                    match event {
                        MatchingEvent::CandidateLoaded(_) => gate.candidate_loaded(panel),
                        MatchingEvent::Failed(message) => gate.failed(panel, message),
                        MatchingEvent::JobFailed(message) => gate.fail(message),
                        MatchingEvent::Operation(outcome) => gate.operation(panel, *outcome),
                        MatchingEvent::WorkspaceLoaded(_) | MatchingEvent::Status(_) => {}
                    }
                    if gate.error.is_some() {
                        return None;
                    }
                }
                gate.modal(panel, cx);
                if gate.error.is_some() { None } else { gate.tick(panel, cx) }
            })
            .flatten();
        if let Some(error) = gate.error.take() {
            return failure(&error);
        }
        if let Some(report) = report {
            // Render the History tab before capturing it.
            for _ in 0..3 {
                driver.frame(&mut app);
            }
            if driver.save_png(Path::new(&gate.text("after_image"))).is_err() {
                return failure("Could not save history screenshot");
            }
            let bytes = indented(&report);
            if write_report(Path::new(&gate.text("report")), &bytes).is_err() {
                return failure("Could not write UI gate report");
            }
            print!("{}", String::from_utf8_lossy(&bytes));
            return ExitCode::SUCCESS;
        }
        if gate.started.elapsed() > timeout {
            return failure(&format!("Matching desktop gate timed out at phase {}", gate.phase));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Qt `QSaveFile`: the report appears whole or not at all.
fn write_report(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    std::fs::write(&temporary, bytes)?;
    std::fs::rename(&temporary, path)
}
