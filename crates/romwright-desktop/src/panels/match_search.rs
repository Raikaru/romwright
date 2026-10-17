//! Match (`romwright-cli match`, docs/match.md): for the selected function of
//! a `new-project` repository, print it in the bounded set of alternative
//! ways, compile each with the repository's pinned compiler and score the
//! object against the retail bytes. The table is the CLI's: one row per
//! variant, the best marked, exact rows in the accent colour.
//!
//! This is the near-miss search over a repository, not the Matching
//! workspace (`panels/matching.rs`), which is the source/compiler workbench.

use crate::address;
use crate::panel::{Command, Panel, PanelContext, PanelId, ShellEvent};
use crate::projects::{self, MatchOutcome, MatchRequest};
use crate::service::{Task, poll_slot};
use crate::table::{self, Cell, Column, Sort, Width};
use crate::theme::{Type, font, space};
use crate::widgets;
use egui::RichText;
use romwright_core::match_search::{Row, Stop};
use romwright_core::match_search::plan::DEFAULT_BUDGET;
use romwright_model::FunctionRow;
use std::path::PathBuf;

pub const ID: PanelId = "match";

const COLUMNS: [Column; 8] = [
    Column::new("#", Width::Exact(44.0)).right().unsorted(),
    Column::new("Variant", Width::Initial(280.0)).unsorted(),
    Column::new("C", Width::Exact(96.0)).unsorted(),
    Column::new("Match %", Width::Exact(84.0)).right().unsorted(),
    Column::new("Exact", Width::Exact(56.0)).unsorted(),
    Column::new("Bytes", Width::Initial(96.0)).right().unsorted(),
    Column::new("Decompile", Width::Exact(84.0)).right().unsorted(),
    Column::new("Compile", Width::Remainder).right().unsorted(),
];

/// Seconds after which no further variant starts (the CLI's `--time` default).
const TIME_LIMIT: u64 = 600;

pub struct MatchPanel {
    /// The `new-project` repository (the directory with `config/project.json`).
    root: String,
    budget: String,
    /// The function the shell resolved at the cursor.
    function: Option<FunctionRow>,
    task: Option<Task<MatchOutcome>>,
    writing: Option<Task<PathBuf>>,
    outcome: Option<MatchOutcome>,
    error: Option<String>,
    written: Option<PathBuf>,
    sort: Sort,
    selected: Option<usize>,
    runs: u64,
    /// Rows the last frame handed to the table.
    rendered: usize,
}

impl Default for MatchPanel {
    fn default() -> Self {
        Self {
            root: String::new(),
            budget: DEFAULT_BUDGET.to_string(),
            function: None,
            task: None,
            writing: None,
            outcome: None,
            error: None,
            written: None,
            sort: Sort::default(),
            selected: None,
            runs: 0,
            rendered: 0,
        }
    }
}

impl MatchPanel {
    /// Points the panel at a repository (what `new-project` just wrote, or
    /// what the open project's store sits in).
    pub fn set_root(&mut self, root: String) {
        self.root = root;
    }

    /// The repository the panel runs in.
    pub fn root(&self) -> &str {
        &self.root
    }

    /// Variants besides the stock one.
    pub fn set_budget(&mut self, budget: String) {
        self.budget = budget;
    }

    /// The function the shell last resolved at the cursor.
    pub fn function(&self) -> Option<&FunctionRow> {
        self.function.as_ref()
    }

    /// Runs completed (answered or failed) since the window opened.
    pub fn runs_finished(&self) -> u64 {
        self.runs
    }

    pub fn outcome(&self) -> Option<&MatchOutcome> {
        self.outcome.as_ref()
    }

    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// Variant rows the table showed on the last frame.
    pub fn rendered_rows(&self) -> usize {
        self.rendered
    }

    /// `match` on the function the cursor is in.
    pub fn run(&mut self, cx: &mut PanelContext<'_>) {
        match self.function.clone() {
            Some(function) => self.run_function(cx, &function),
            None => cx.error("Match needs a selected function: pick one in Functions or the Listing"),
        }
    }

    pub fn run_function(&mut self, cx: &mut PanelContext<'_>, function: &FunctionRow) {
        let root = self.root.trim();
        if root.is_empty() {
            cx.error("Match needs the repository `new-project` wrote");
            return;
        }
        let Ok(budget) = self.budget.trim().parse::<usize>() else {
            cx.error("Match budget is a number of variants");
            return;
        };
        let request = MatchRequest { root: PathBuf::from(root), entry: function.entry.offset, budget, seconds: TIME_LIMIT };
        let (name, entry) = (function.name.clone(), function.entry.offset);
        self.outcome = None;
        self.error = None;
        self.written = None;
        self.selected = None;
        self.function = Some(function.clone());
        self.task = Some(cx.service.job(format!("match {name}"), move |job| {
            job.progress(format!("match {name} {entry:#x}"));
            let outcome = projects::run_match(job, &request)?;
            let best = outcome.report.best_row();
            job.detail(format!(
                "{name}: best {} {:.3}%{} of {} variants",
                best.variant,
                best.score.as_ref().map_or(0.0, |score| score.percent),
                if best.score.as_ref().is_some_and(|score| score.exact) { " exact" } else { "" },
                outcome.report.rows.len()
            ));
            Ok(outcome)
        }));
    }

    /// `match --write`: the best compiling variant's C into the repository.
    fn write_best(&mut self, cx: &mut PanelContext<'_>) {
        let Some(outcome) = &self.outcome else { return };
        let best = outcome.report.best_row();
        let Some(text) = best.text.clone().filter(|_| best.score.as_ref().is_some_and(|score| score.compiled)) else {
            cx.error("No variant compiled; nothing to write");
            return;
        };
        let (root, entry) = (PathBuf::from(self.root.trim()), outcome.entry);
        self.writing = Some(cx.service.job("match write", move |job| {
            let path = projects::write_best(&root, entry, &text)?;
            job.detail(format!("wrote {}", path.display()));
            Ok(path)
        }));
    }

    fn can_write(&self) -> bool {
        self.writing.is_none()
            && self.outcome.as_ref().is_some_and(|outcome| {
                let best = outcome.report.best_row();
                best.text.is_some() && best.score.as_ref().is_some_and(|score| score.compiled)
            })
    }

    fn summary(outcome: &MatchOutcome) -> String {
        let report = &outcome.report;
        let best = report.best_row();
        let stop = match report.stop {
            Stop::Exact => "stopped at an exact variant",
            Stop::Exhausted => "every planned variant tried",
            Stop::Budget => "stopped at the variant budget",
            Stop::Time => "stopped at the time limit",
        };
        format!(
            "{} {:#x} ({} bytes)  ·  {} {}  ·  best {} {:.3}%{} (default {:.3}%)  ·  {} decompiles, {} compiles, {:.1}s  ·  {stop}",
            outcome.name,
            outcome.entry,
            outcome.size,
            outcome.compiler,
            outcome.cflags,
            best.variant,
            best.score.as_ref().map_or(0.0, |score| score.percent),
            if best.score.as_ref().is_some_and(|score| score.exact) { " exact" } else { "" },
            report.rows[0].score.as_ref().map_or(0.0, |score| score.percent),
            report.decompiles,
            report.compiles,
            report.elapsed_ms as f64 / 1000.0,
        )
    }

    fn cell(theme: &crate::theme::Theme, outcome: &MatchOutcome, index: usize, column: usize) -> Cell {
        let row: &Row = &outcome.report.rows[index];
        let score = row.score.as_ref();
        let compiled = score.is_some_and(|score| score.compiled);
        match column {
            0 => Cell::code(format!("{}{index}", if index == outcome.report.best { "*" } else { "" }), theme.accent),
            1 => Cell::text(theme, row.variant.as_str()),
            2 => match (row.same_as, row.text_hash.as_deref()) {
                (Some(earlier), _) => Cell::code(format!("= #{earlier}"), theme.text_faint).tooltip("printed the same C as that row; not compiled again"),
                (None, Some(hash)) => Cell::code(&hash[..hash.len().min(8)], theme.text_muted),
                (None, None) => Cell::code("-", theme.text_faint),
            },
            3 if compiled => Cell::code(format!("{:.3}", score.map_or(0.0, |score| score.percent)), theme.text),
            4 if compiled => {
                let exact = score.is_some_and(|score| score.exact);
                Cell::code(if exact { "yes" } else { "no" }, if exact { theme.ok } else { theme.text_muted })
            }
            5 if compiled => {
                let score = score.expect("compiled rows have a score");
                Cell::code(score.byte_diffs.map_or_else(|| format!("size {}", score.size.unwrap_or(0)), |diffs| diffs.to_string()), theme.text_muted)
            }
            6 => Cell::code(format!("{:.1}s", row.decompile_ms as f64 / 1000.0), theme.text_faint),
            7 => Cell::code(format!("{:.1}s", row.compile_ms as f64 / 1000.0), theme.text_faint),
            _ => {
                // Not compiled: the reason, in the Match % column's place.
                let reason = score.and_then(|score| score.error.clone()).or_else(|| row.error.clone()).unwrap_or_default();
                let first = reason.lines().next().unwrap_or("").to_string();
                match column {
                    3 => Cell::code("-", theme.text_faint),
                    4 => Cell::code("-", theme.text_faint),
                    _ => Cell::new(first.clone(), Type::CodeSmall, theme.error).tooltip(reason),
                }
            }
        }
    }
}

impl Panel for MatchPanel {
    fn id(&self) -> PanelId {
        ID
    }

    fn title(&self) -> String {
        "Match".into()
    }

    fn open_by_default(&self) -> bool {
        false
    }

    fn on_event(&mut self, event: &ShellEvent, cx: &mut PanelContext<'_>) {
        match event {
            ShellEvent::ProgramChanged => {
                self.function = None;
                // A project opened from a repository's own store: its parent is the repository.
                let store = &cx.session.project;
                if self.root.is_empty()
                    && let Some(parent) = store.parent().filter(|_| store.file_name().is_some_and(|name| name == ".romwright"))
                    && parent.join("config/project.json").is_file()
                {
                    self.root = parent.display().to_string();
                }
            }
            ShellEvent::FunctionChanged { function, .. } => self.function = function.clone(),
            ShellEvent::ProjectCreated { root } => self.root = root.display().to_string(),
            _ => {}
        }
    }

    fn poll(&mut self, cx: &mut PanelContext<'_>) {
        if let Some(result) = poll_slot(&mut self.task) {
            self.runs += 1;
            match result {
                Ok(outcome) => {
                    cx.status(format!("Match {}: {} variants", outcome.name, outcome.report.rows.len()));
                    cx.command(Command::Raise(ID));
                    self.outcome = Some(outcome);
                }
                Err(error) => {
                    cx.error(format!("Match: {error}"));
                    self.error = Some(error);
                }
            }
        }
        if let Some(result) = poll_slot(&mut self.writing) {
            match result {
                Ok(path) => {
                    cx.status(format!("Wrote {}", path.display()));
                    self.written = Some(path);
                }
                Err(error) => cx.error(format!("Match write: {error}")),
            }
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, cx: &mut PanelContext<'_>) {
        let theme = cx.theme;
        let running = self.task.is_some();
        let mut run = false;
        let mut write = false;
        let title = match &self.function {
            Some(function) => format!("Match  ·  {} {}  ·  {} bytes", function.name, address::format(&function.entry), function.size),
            None => "Match".to_string(),
        };
        widgets::panel_header(ui, theme, &title, |ui| {
            write = widgets::button(ui, theme, "Write best", self.can_write()).on_hover_text("Write the best compiling variant to src/ (match --write)").clicked();
            run = widgets::primary_button(ui, theme, "Run match", self.function.is_some() && !self.root.trim().is_empty() && !running).clicked();
        });
        egui::Frame::new().inner_margin(egui::Margin::symmetric(space::MD as i8, space::SM as i8)).show(ui, |ui| {
            ui.horizontal(|ui| {
                widgets::caption(ui, theme, "Repository");
                ui.add(
                    egui::TextEdit::singleline(&mut self.root)
                        .hint_text(RichText::new("a `romwright-cli new-project` repository").color(theme.text_faint))
                        .font(font(Type::Body))
                        .desired_width(ui.available_width() - 160.0),
                );
                widgets::caption(ui, theme, "Budget");
                ui.add(egui::TextEdit::singleline(&mut self.budget).font(font(Type::Body)).desired_width(48.0));
            });
        });
        if run {
            self.run(cx);
        }
        if write {
            self.write_best(cx);
        }
        self.rendered = 0;
        if running {
            widgets::loading(ui, theme, "Printing, compiling and scoring variants…");
            return;
        }
        if let Some(error) = &self.error {
            widgets::empty_state(ui, theme, "Match failed", error);
            return;
        }
        let Some(outcome) = &self.outcome else {
            let detail = if cx.session.program.is_empty() {
                "Open a program imported from a new-project repository."
            } else if self.function.is_none() {
                "Select a function in Functions or the Listing, then Run match."
            } else {
                "Run match prints the function in alternative ways and scores each against the retail bytes."
            };
            widgets::empty_state(ui, theme, "No match run yet", detail);
            return;
        };
        self.rendered = outcome.report.rows.len();
        let mut footer = format!("{}  ·  metric: {}", Self::summary(outcome), outcome.metric);
        if let Some(path) = &self.written {
            footer.push_str(&format!("  ·  wrote {}", path.display()));
        }
        let mut copy = None;
        table::with_footer(ui, theme, &footer, |ui| {
            ui.add_space(space::XXS);
            table::show(
                ui,
                theme,
                "match-table",
                &COLUMNS,
                &mut self.sort,
                outcome.report.rows.len(),
                &mut self.selected,
                &mut |index, column| Self::cell(theme, outcome, index, column),
                &mut |ui, index| {
                    if outcome.report.rows[index].text.is_some() && ui.button("Copy C").clicked() {
                        copy = outcome.report.rows[index].text.clone();
                        ui.close();
                    }
                },
            )
        });
        if let Some(text) = copy {
            ui.ctx().copy_text(text);
            cx.status("Copied the variant's C");
        }
    }

    fn busy(&self) -> bool {
        self.task.is_some() || self.writing.is_some()
    }
}
