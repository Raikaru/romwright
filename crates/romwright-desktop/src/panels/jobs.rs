//! Jobs (Qt `JobsDock`): the bounded log of long-running work with live
//! progress, Cancel for running jobs, full details on double-click, and the
//! supervised worker pool's counters (`WorkerPoolManager::jobs_page`).

use crate::jobs::{JobEntry, JobId, JobState};
use crate::panel::{Panel, PanelContext, PanelId, Placement};
use crate::service::{Task, poll_slot};
use crate::theme::{Type, font, metrics, space};
use crate::widgets::{self, Icon};
use egui::{Align, CornerRadius, Layout, RichText, Sense, vec2};
use romwright_worker_client::JobsPage;

pub const ID: PanelId = "jobs";

#[derive(Default)]
pub struct JobsPanel {
    pool: Option<Task<JobsPage>>,
    summary: String,
    summary_error: bool,
    seen_finished: Option<u64>,
    selected: Option<JobId>,
    details: Option<JobEntry>,
}

impl JobsPanel {
    fn refresh_pool(&mut self, cx: &PanelContext<'_>) {
        if self.pool.is_some() {
            return;
        }
        self.pool = Some(cx.service.request_pool(|core, pool| {
            Ok(pool.jobs_page(core.runtime_config().worker_memory_cap, 0, 64))
        }));
    }

    fn summarize(page: &JobsPage) -> String {
        let pool = &page.pool;
        let cap = if pool.memory_cap_bytes == 0 {
            "unlimited".to_string()
        } else {
            format!("{} MiB", pool.memory_cap_bytes / (1024 * 1024))
        };
        let mut summary = format!(
            "Worker pool  ·  {} idle  ·  {} busy  ·  {} restarts  ·  cap {cap} ({} hits)",
            pool.idle_workers, pool.busy_workers, pool.restarts, pool.memory_cap_hits
        );
        if let Some(failure) = page.rows.iter().rev().find(|row| row.state == romwright_worker_client::JobState::Failed) {
            summary.push_str(&format!("\nLast failure: {} — {}", failure.operation, failure.detail));
        }
        summary
    }
}

impl Panel for JobsPanel {
    fn id(&self) -> PanelId {
        ID
    }

    fn title(&self) -> String {
        "Jobs".into()
    }

    fn placement(&self) -> Placement {
        Placement::Bottom
    }

    fn poll(&mut self, cx: &mut PanelContext<'_>) {
        let finished = cx.service.jobs().finished();
        if self.seen_finished != Some(finished) {
            self.seen_finished = Some(finished);
            self.refresh_pool(cx);
        }
        match poll_slot(&mut self.pool) {
            Some(Ok(page)) => {
                self.summary = Self::summarize(&page);
                self.summary_error = false;
            }
            Some(Err(error)) => {
                self.summary = format!("Worker pool unavailable: {error}");
                self.summary_error = true;
            }
            None => {}
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, cx: &mut PanelContext<'_>) {
        let theme = cx.theme;
        let board = cx.service.jobs();
        let entries = board.snapshot();
        egui::Frame::new()
            .inner_margin(egui::Margin::symmetric(space::MD as i8, space::SM as i8))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    let color = if self.summary_error { theme.error } else { theme.text_muted };
                    let summary = if self.summary.is_empty() { "Worker pool  ·  no decompile jobs yet" } else { &self.summary };
                    ui.add(egui::Label::new(RichText::new(summary).font(font(Type::Caption)).color(color)).wrap());
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        let enabled = self.selected.is_some();
                        if widgets::button(ui, theme, "Dismiss", enabled)
                            .on_hover_text("Remove this log entry; native work continues.")
                            .clicked()
                            && let Some(id) = self.selected.take()
                        {
                            board.dismiss(id);
                        }
                    });
                });
            });
        ui.painter().hline(ui.max_rect().x_range(), ui.cursor().top(), egui::Stroke::new(1.0, theme.border));
        if entries.is_empty() {
            widgets::empty_state(ui, theme, "No jobs yet", "Imports, listings, decompiles and analysis passes appear here.");
            return;
        }
        let mut open = None;
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .stick_to_bottom(true)
            .show_rows(ui, metrics::ROW, entries.len(), |ui, range| {
                for entry in &entries[range] {
                    let (rect, response) = ui.allocate_exact_size(vec2(ui.available_width(), metrics::ROW), Sense::click());
                    let selected = self.selected == Some(entry.id);
                    if selected {
                        ui.painter().rect_filled(rect, CornerRadius::ZERO, theme.bg_selected);
                    } else if response.hovered() {
                        ui.painter().rect_filled(rect, CornerRadius::ZERO, theme.bg_hover);
                    }
                    let mut child = ui.new_child(
                        egui::UiBuilder::new()
                            .max_rect(rect.shrink2(vec2(space::MD, 0.0)))
                            .layout(Layout::left_to_right(Align::Center)),
                    );
                    let (icon_color, text) = match entry.state {
                        JobState::Running => (theme.warn, if entry.progress.is_empty() { String::new() } else { entry.progress.clone() }),
                        JobState::Succeeded => (theme.ok, entry.detail.clone()),
                        JobState::Failed => (theme.error, entry.detail.clone()),
                        JobState::Cancelled => (theme.text_faint, entry.detail.clone()),
                    };
                    let (icon_rect, _) = child.allocate_exact_size(vec2(16.0, 16.0), Sense::hover());
                    match entry.state {
                        JobState::Running => {
                            child.put(icon_rect, egui::Spinner::new().size(12.0).color(icon_color));
                        }
                        JobState::Succeeded => widgets::paint_icon(child.painter(), icon_rect, Icon::Check, icon_color),
                        JobState::Failed | JobState::Cancelled => widgets::paint_icon(child.painter(), icon_rect, Icon::Cross, icon_color),
                    }
                    child.label(RichText::new(entry.label.trim()).font(font(Type::Strong)).color(theme.text));
                    child.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if let Some(elapsed) = entry.elapsed {
                            ui.label(RichText::new(format!("{:.0} ms", elapsed.as_secs_f64() * 1000.0)).font(font(Type::CodeSmall)).color(theme.text_faint));
                        } else if entry.cancel_requested() {
                            ui.label(RichText::new("cancelling…").font(font(Type::Caption)).color(theme.text_faint));
                        } else if widgets::icon_button(ui, theme, Icon::Close, "Cancel this job", true).clicked() {
                            board.cancel(entry.id);
                        }
                        ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                            let first_line = text.lines().next().unwrap_or("");
                            widgets::truncated(ui, first_line, Type::Body, theme.text_muted);
                        });
                    });
                    if response.clicked() {
                        self.selected = Some(entry.id);
                    }
                    if response.double_clicked() && entry.state != JobState::Running {
                        open = Some(entry.clone());
                    }
                }
            });
        if open.is_some() {
            self.details = open;
        }
        if let Some(entry) = &self.details {
            let mut keep = true;
            egui::Window::new(entry.label.clone())
                .id(egui::Id::new("job-details"))
                .open(&mut keep)
                .collapsible(false)
                .resizable(true)
                .default_width(560.0)
                .show(ui.ctx(), |ui| {
                    egui::ScrollArea::vertical().max_height(360.0).show(ui, |ui| {
                        ui.add(egui::Label::new(RichText::new(&entry.detail).font(font(Type::Code)).color(theme.text)).selectable(true));
                    });
                });
            if !keep {
                self.details = None;
            }
        }
    }

    fn busy(&self) -> bool {
        self.pool.is_some()
    }
}
