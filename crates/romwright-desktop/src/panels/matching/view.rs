//! Drawing for the matching workspace. Layout follows the Qt dock (context
//! bar, optional setup strip, source | evidence split, state line) with the
//! controls grouped where they act: candidate actions under the editor,
//! project actions over the patch, history paging over the history.

use super::dialogs::{self, Choice, Dialog, JsonPurpose};
use super::text;
use super::{Action, Evidence, MatchingPanel, ObjectVerdict, Tab, byte_offset, object_offset, object_text, percent, verdict};
use crate::panel::PanelContext;
use crate::table;
use crate::theme::{self, Syntax, Theme, Type, font, metrics, space};
use crate::widgets::{self, Icon};
use egui::text::{CCursor, CCursorRange};
use egui::text_edit::TextEditState;
use egui::{Align, Color32, CornerRadius, Key, KeyboardShortcut, Layout, Modifiers, RichText, Sense, Stroke, Ui, vec2};

const RUN_SHORTCUT: KeyboardShortcut = KeyboardShortcut::new(Modifiers::COMMAND, Key::Enter);
const EDITOR: &str = "matching-source-editor";

fn editor_id() -> egui::Id {
    egui::Id::new(EDITOR)
}

/// A labelled verdict: coloured dot plus text, on a soft pill.
fn verdict_pill(ui: &mut Ui, theme: &Theme, label: &str, value: Option<bool>, text: &str) {
    let color = match value {
        Some(true) => theme.ok,
        Some(false) => theme.error,
        None => theme.text_faint,
    };
    egui::Frame::new()
        .fill(theme.bg_raised)
        .stroke(Stroke::new(1.0, theme.border))
        .corner_radius(CornerRadius::same(metrics::RADIUS))
        .inner_margin(egui::Margin::symmetric(space::SM as i8, space::XS as i8))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = space::XS + 2.0;
                let (dot, _) = ui.allocate_exact_size(vec2(8.0, 14.0), Sense::hover());
                ui.painter().circle_filled(dot.center(), 3.5, color);
                ui.label(RichText::new(label).font(font(Type::Caption)).color(theme.text_muted));
                ui.label(RichText::new(text).font(font(Type::Strong)).color(theme.text));
            });
        });
}

fn similarity_color(theme: &Theme, value: Option<f64>) -> Color32 {
    match value {
        Some(value) if value >= 100.0 => theme.ok,
        Some(value) if value >= 50.0 => theme.warn,
        Some(_) => theme.error,
        None => theme.text_faint,
    }
}

/// Thin horizontal meter (similarity).
fn meter(ui: &mut Ui, theme: &Theme, value: Option<f64>) {
    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), 6.0), Sense::hover());
    ui.painter().rect_filled(rect, CornerRadius::same(3), theme.bg_hover);
    if let Some(value) = value {
        let mut fill = rect;
        fill.set_width(rect.width() * (value / 100.0).clamp(0.0, 1.0) as f32);
        ui.painter().rect_filled(fill, CornerRadius::same(3), similarity_color(theme, Some(value)));
    }
}

fn click(ui: &mut Ui, theme: &Theme, panel: &MatchingPanel, label: &str, action: Action, actions: &mut Vec<Action>) {
    if widgets::button(ui, theme, label, panel.enabled(action)).clicked() {
        actions.push(action);
    }
}

fn combo(ui: &mut Ui, id: &str, width: f32, enabled: bool, selected: &str, entries: &[String], current: Option<usize>) -> Option<usize> {
    let mut chosen = None;
    ui.add_enabled_ui(enabled, |ui| {
        egui::ComboBox::from_id_salt(id)
            .width(width)
            .height(28.0 * 12.0)
            .selected_text(RichText::new(selected).font(font(Type::Body)))
            .show_ui(ui, |ui| {
                for (index, entry) in entries.iter().enumerate() {
                    if ui.selectable_label(current == Some(index), RichText::new(entry).font(font(Type::Body))).clicked() {
                        chosen = Some(index);
                    }
                }
            });
    });
    chosen
}

pub(super) fn show(panel: &mut MatchingPanel, ui: &mut Ui, cx: &mut PanelContext<'_>) {
    let theme = cx.theme.clone();
    let mut actions = Vec::new();
    if ui.input_mut(|input| input.consume_shortcut(&RUN_SHORTCUT)) {
        actions.push(Action::Run);
    }
    egui::Panel::top("matching-context")
        .frame(egui::Frame::new().fill(theme.bg_panel).inner_margin(egui::Margin::symmetric(space::MD as i8, space::SM as i8)))
        .show_separator_line(false)
        .show(ui, |ui| {
            let rect = ui.max_rect();
            ui.painter().hline(rect.x_range().expand(space::MD), rect.bottom() + space::SM, Stroke::new(1.0, theme.border));
            context_bar(panel, ui, cx, &theme, &mut actions);
        });
    if panel.setup_open {
        egui::Panel::top("matching-setup")
            .frame(egui::Frame::new().fill(theme.bg_raised).inner_margin(egui::Margin::symmetric(space::MD as i8, space::SM as i8)))
            .show_separator_line(false)
            .show(ui, |ui| {
                let rect = ui.max_rect();
                ui.painter().hline(rect.x_range().expand(space::MD), rect.bottom() + space::SM, Stroke::new(1.0, theme.border));
                setup_strip(panel, ui, &theme, &mut actions);
            });
    }
    egui::Panel::bottom("matching-state")
        .exact_size(metrics::STATUS_BAR + 2.0)
        .frame(egui::Frame::new().fill(theme.bg_panel).inner_margin(egui::Margin::symmetric(space::MD as i8, 0)))
        .show_separator_line(false)
        .show(ui, |ui| {
            let rect = ui.max_rect();
            ui.painter().hline(rect.x_range().expand(space::MD), rect.top(), Stroke::new(1.0, theme.border));
            ui.horizontal_centered(|ui| {
                let (text, error) = panel.state();
                let color = if error { theme.error } else { theme.text_muted };
                let (dot, _) = ui.allocate_exact_size(vec2(8.0, 8.0), Sense::hover());
                let dot_color = if error {
                    theme.error
                } else if panel.job.is_some() {
                    theme.accent
                } else {
                    theme.ok
                };
                ui.painter().circle_filled(dot.center(), 3.5, dot_color);
                widgets::truncated(ui, text.to_string(), Type::Caption, color);
            });
        });
    let available = ui.available_width();
    egui::Panel::left("matching-source")
        .resizable(true)
        .default_size((available * 0.5).max(360.0))
        .size_range(320.0..=(available - 320.0).max(320.0))
        .frame(egui::Frame::new().fill(theme.bg_app))
        .show_separator_line(true)
        .show(ui, |ui| source_side(panel, ui, cx, &theme, &mut actions));
    egui::CentralPanel::no_frame().show(ui, |ui| evidence_side(panel, ui, cx, &theme, &mut actions));
    for action in actions {
        panel.trigger(cx, action);
    }
    if let Some(dialog) = &mut panel.dialog {
        match dialogs::show(dialog, ui.ctx(), &theme) {
            Choice::None => {}
            Choice::Accept => panel.accept_dialog(cx),
            Choice::Reject => panel.reject_dialog(),
            Choice::Advanced => {
                if let Some(Dialog::NewWorkspace(form)) = &mut panel.dialog {
                    match form.build() {
                        Ok(setup) => {
                            let form = Box::new(form.clone());
                            let mut json = Dialog::json(
                                "Complete workspace setup",
                                "Exact source/context inputs, named tool requirements and complete argument arrays. Redistributable defaults to false.",
                                &setup,
                                JsonPurpose::Setup,
                            );
                            if let Dialog::Json { back, .. } = &mut json {
                                *back = Some(form);
                            }
                            panel.dialog = Some(json);
                        }
                        Err(error) => form.error = error,
                    }
                }
            }
        }
    }
}

fn context_bar(panel: &mut MatchingPanel, ui: &mut Ui, cx: &mut PanelContext<'_>, theme: &Theme, actions: &mut Vec<Action>) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = space::XS + 2.0;
        let enabled = panel.enabled(Action::RefreshWorkspaces);
        widgets::caption(ui, theme, "Workspace");
        let current = panel.workspace.as_ref().and_then(|workspace| panel.workspaces.iter().position(|(id, _)| *id == workspace.id));
        let selected = current.map(|index| panel.workspaces[index].1.clone()).unwrap_or_else(|| "No workspace".into());
        let labels: Vec<String> = panel.workspaces.iter().map(|(_, label)| label.clone()).collect();
        if let Some(index) = combo(ui, "matching-workspace", 260.0, enabled, &selected, &labels, current) {
            let id = panel.workspaces[index].0;
            panel.load_workspace(cx, id);
        }
        ui.add_space(space::SM);
        widgets::caption(ui, theme, "Candidate");
        let current = panel.candidate_id().and_then(|id| panel.candidates.iter().position(|(known, _)| *known == id));
        let selected = current.map(|index| panel.candidates[index].1.clone()).unwrap_or_else(|| "No candidate".into());
        let labels: Vec<String> = panel.candidates.iter().map(|(_, label)| label.clone()).collect();
        if let Some(index) = combo(ui, "matching-candidate", 260.0, enabled, &selected, &labels, current) {
            panel.select_candidate(cx, index);
        }
        click(ui, theme, panel, "New…", Action::NewWorkspace, actions);
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if widgets::chip(ui, theme, "Setup", panel.setup_open)
                .on_hover_text("Workspace transfer, toolchain calibration and search limits")
                .clicked()
            {
                panel.setup_open = !panel.setup_open;
            }
            if let Some(job) = &panel.job {
                if widgets::button(ui, theme, "Cancel", true).clicked() {
                    actions.push(Action::Cancel);
                }
                ui.label(RichText::new(&job.label).font(font(Type::Caption)).color(theme.text_muted));
                ui.add(egui::Spinner::new().size(14.0).color(theme.accent));
            } else if !panel.requests.is_empty() {
                ui.add(egui::Spinner::new().size(14.0).color(theme.text_faint));
            }
        });
    });
}

fn setup_strip(panel: &mut MatchingPanel, ui: &mut Ui, theme: &Theme, actions: &mut Vec<Action>) {
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing = vec2(space::XS + 2.0, space::XS + 2.0);
        widgets::caption(ui, theme, "Workspaces");
        click(ui, theme, panel, "Refresh", Action::RefreshWorkspaces, actions);
        click(ui, theme, panel, "More workspaces", Action::MoreWorkspaces, actions);
        click(ui, theme, panel, "More candidates", Action::MoreCandidates, actions);
        click(ui, theme, panel, "Import…", Action::Import, actions);
        click(ui, theme, panel, "Export…", Action::Export, actions);
        widgets::toolbar_separator(ui, theme);
        widgets::caption(ui, theme, "Toolchain");
        click(ui, theme, panel, "Add profile…", Action::AddProfile, actions);
        click(ui, theme, panel, "Calibrate…", Action::Calibrate, actions);
        click(ui, theme, panel, "Trial context…", Action::TrialContext, actions);
        click(ui, theme, panel, "Explicit alternatives…", Action::ExplicitSearch, actions);
        widgets::toolbar_separator(ui, theme);
        widgets::caption(ui, theme, "Compilation budget");
        let idle = panel.enabled(Action::RefreshWorkspaces);
        ui.add_enabled(idle, egui::DragValue::new(&mut panel.budget).range(1..=4096));
        widgets::caption(ui, theme, "Wall clock");
        ui.add_enabled(idle, egui::DragValue::new(&mut panel.seconds).range(1..=3600).suffix(" s"));
    });
}

fn source_side(panel: &mut MatchingPanel, ui: &mut Ui, cx: &mut PanelContext<'_>, theme: &Theme, actions: &mut Vec<Action>) {
    egui::Panel::top("matching-source-head")
        .frame(egui::Frame::new().fill(theme.bg_panel).inner_margin(egui::Margin::symmetric(space::MD as i8, space::XS as i8 + 2)))
        .show_separator_line(false)
        .show(ui, |ui| {
            let rect = ui.max_rect();
            ui.painter().hline(rect.x_range().expand(space::MD), rect.bottom() + space::XS + 2.0, Stroke::new(1.0, theme.border));
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = space::XS + 2.0;
                let enabled = panel.enabled(Action::RefreshWorkspaces);
                let selected = panel.files.get(panel.file).cloned().unwrap_or_else(|| "No source".into());
                let files = panel.files.clone();
                if let Some(index) = combo(ui, "matching-file", 180.0, enabled, &selected, &files, Some(panel.file)) {
                    panel.select_file(cx, index);
                }
                if panel.modified() {
                    let (dot, _) = ui.allocate_exact_size(vec2(10.0, 10.0), Sense::hover());
                    ui.painter().circle_filled(dot.center(), 3.5, theme.warn);
                    widgets::caption(ui, theme, "unsaved");
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let profiles = panel.profiles.clone();
                    let selected = profiles.get(panel.profile).cloned().unwrap_or_else(|| "No profile".into());
                    if let Some(index) = combo(ui, "matching-profile", 120.0, enabled, &selected, &profiles, Some(panel.profile)) {
                        panel.select_profile(index);
                    }
                    widgets::caption(ui, theme, "Toolchain");
                    widgets::toolbar_separator(ui, theme);
                    if widgets::button(ui, theme, "Save", panel.enabled(Action::Save))
                        .on_hover_text("Create an immutable candidate. This does not write project source files.")
                        .clicked()
                    {
                        actions.push(Action::Save);
                    }
                    if widgets::button(ui, theme, "Discard", panel.enabled(Action::Discard)).on_hover_text("Discard unsaved source edits").clicked() {
                        actions.push(Action::Discard);
                    }
                });
            });
        });
    egui::Panel::bottom("matching-source-foot")
        .frame(egui::Frame::new().fill(theme.bg_panel).inner_margin(egui::Margin::symmetric(space::MD as i8, space::XS as i8 + 2)))
        .show_separator_line(false)
        .show(ui, |ui| {
            let rect = ui.max_rect();
            ui.painter().hline(rect.x_range().expand(space::MD), rect.top() - space::XS - 2.0, Stroke::new(1.0, theme.border));
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = space::XS + 2.0;
                click(ui, theme, panel, "Pin selection", Action::Pin, actions);
                click(ui, theme, panel, "Clear pins", Action::ClearPins, actions);
                let pins = panel.candidate.as_ref().map_or(0, |candidate| candidate.spec.pins.len());
                let (dot, _) = ui.allocate_exact_size(vec2(8.0, 8.0), Sense::hover());
                ui.painter().circle_filled(dot.center(), 3.0, if pins > 0 { theme.warn } else { theme.text_faint });
                let suffix = if panel.modified() { " · checked on save" } else { "" };
                widgets::caption(ui, theme, &format!("{pins} pin{}{suffix}", if pins == 1 { "" } else { "s" }));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if widgets::primary_button(ui, theme, "Compile & compare", panel.enabled(Action::Run))
                        .on_hover_text("Save a candidate and compile against the reference (Ctrl+Enter)")
                        .clicked()
                    {
                        actions.push(Action::Run);
                    }
                    click(ui, theme, panel, "Search selection", Action::Search, actions);
                });
            });
        });
    egui::CentralPanel::no_frame().show(ui, |ui| editor(panel, ui, theme));
}

/// Applies queued editor work through egui's text state (selection, typed
/// replacement, undo), so the gate and the analyst share one editor.
fn apply_editor_actions(panel: &mut MatchingPanel, context: &egui::Context) {
    if panel.editor.is_empty() {
        return;
    }
    let mut state = TextEditState::load(context, editor_id()).unwrap_or_default();
    for action in std::mem::take(&mut panel.editor) {
        match action {
            super::EditorAction::Select(range) => {
                state.cursor.set_char_range(Some(CCursorRange::two(CCursor::new(range.start), CCursor::new(range.end))));
                panel.selection = range;
            }
            super::EditorAction::Replace(text) => {
                if !panel.editable() {
                    continue;
                }
                let range = state.cursor.char_range().unwrap_or_else(|| CCursorRange::one(CCursor::new(panel.selection.end)));
                let [start, end] = range.sorted_cursors();
                // Typing always leaves an undo point first, as the editor
                // does when it has keyboard focus.
                let mut undoer = state.undoer();
                undoer.add_undo(&(range, panel.source.clone()));
                state.set_undoer(undoer);
                let (from, to) = (byte_offset(&panel.source, start.index.0), byte_offset(&panel.source, end.index.0));
                panel.source.replace_range(from..to, &text);
                let caret = start.index.0 + text.chars().count();
                state.cursor.set_char_range(Some(CCursorRange::one(CCursor::new(caret))));
                panel.selection = caret..caret;
            }
            super::EditorAction::Undo => {
                let current = (state.cursor.char_range().unwrap_or_default(), panel.source.clone());
                let mut undoer = state.undoer();
                if let Some((range, text)) = undoer.undo(&current).cloned() {
                    panel.source = text;
                    state.cursor.set_char_range(Some(range));
                    panel.selection = range.as_sorted_char_range().start.0..range.as_sorted_char_range().end.0;
                }
                state.set_undoer(undoer);
            }
            super::EditorAction::Reset => {
                state.clear_undoer();
                state.cursor.set_char_range(None);
            }
        }
    }
    state.store(context, editor_id());
}

fn editor(panel: &mut MatchingPanel, ui: &mut Ui, theme: &Theme) {
    apply_editor_actions(panel, ui.ctx());
    if panel.candidate.is_none() {
        if panel.workspaces.is_empty() && panel.requests.is_empty() && !panel.program.is_empty() {
            widgets::empty_state(ui, theme, "No matching workspace", "New… sets one up from a reference object, its source and a compiler.");
        } else if panel.program.is_empty() {
            widgets::empty_state(ui, theme, "No program", "Open a program, then choose or create a matching workspace.");
        } else {
            widgets::loading(ui, theme, "Loading candidate…");
        }
        return;
    }
    if panel.loaded_file.is_empty() {
        widgets::loading(ui, theme, "Loading source…");
        return;
    }
    let editable = panel.editable();
    let pins: Vec<std::ops::Range<usize>> = if panel.modified() {
        Vec::new()
    } else {
        panel
            .candidate
            .iter()
            .flat_map(|candidate| &candidate.spec.pins)
            .filter(|pin| pin.file == panel.loaded_file)
            .map(|pin| pin.start..pin.end)
            .collect()
    };
    let code_font = font(Type::Code);
    let gutter_font = font(Type::CodeSmall);
    let row_height = ui.fonts_mut(|fonts| fonts.row_height(&code_font));
    let char_width = ui.fonts_mut(|fonts| fonts.glyph_width(&gutter_font, '0'));
    let lines = panel.source.lines().count().max(1);
    let gutter = char_width * (lines.to_string().len().max(3) as f32) + 2.0 * space::MD;
    egui::Frame::new().fill(theme.bg_code).show(ui, |ui| {
        ui.set_min_size(ui.available_size());
        egui::ScrollArea::both().id_salt("matching-source-scroll").auto_shrink([false, false]).show(ui, |ui| {
            ui.horizontal_top(|ui| {
                ui.spacing_mut().item_spacing.x = 0.0;
                let (gutter_rect, _) = ui.allocate_exact_size(vec2(gutter, lines as f32 * row_height + 2.0 * space::SM), Sense::hover());
                let background = ui.painter().add(egui::Shape::Noop);
                let theme_for_layout = theme.clone();
                let mut layouter = move |ui: &Ui, buffer: &dyn egui::TextBuffer, _wrap: f32| {
                    let job = text::source_job(buffer.as_str(), &theme_for_layout, &pins);
                    ui.fonts_mut(|fonts| fonts.layout_job(job))
                };
                let output = if editable {
                    source_edit(egui::TextEdit::multiline(&mut panel.source), lines).layouter(&mut layouter).show(ui)
                } else {
                    // Read-only but selectable (Qt `setReadOnly`).
                    let mut text = panel.source.as_str();
                    source_edit(egui::TextEdit::multiline(&mut text), lines).layouter(&mut layouter).show(ui)
                };
                if let Some(range) = output.cursor_range {
                    let range = range.as_sorted_char_range();
                    panel.selection = range.start.0..range.end.0;
                }
                // No wrapping: one galley row per source line.
                let cursor_row = output
                    .cursor_range
                    .map(|range| panel.source.chars().take(range.primary.index.0).filter(|character| *character == '\n').count());
                let painter = ui.painter();
                let width = ui.clip_rect().right() - gutter_rect.left();
                for (index, row) in output.galley.rows.iter().enumerate() {
                    let top = output.galley_pos.y + row.pos.y;
                    let number_y = top + row.rect().height() / 2.0;
                    let current = cursor_row == Some(index) && output.response.has_focus();
                    if current {
                        let line = egui::Rect::from_min_size(egui::pos2(gutter_rect.left(), top), vec2(width, row.rect().height()));
                        painter.set(background, egui::Shape::rect_filled(line, CornerRadius::ZERO, theme.current_line));
                        painter.vline(gutter_rect.left() + 1.0, line.y_range(), Stroke::new(2.0, theme.accent));
                    }
                    let color = if current { theme.text_muted } else { theme.syntax(Syntax::Dim) };
                    painter.text(
                        egui::pos2(gutter_rect.right() - space::MD, number_y),
                        egui::Align2::RIGHT_CENTER,
                        (index + 1).to_string(),
                        gutter_font.clone(),
                        color,
                    );
                }
            });
        });
    });
}

fn source_edit(edit: egui::TextEdit<'_>, lines: usize) -> egui::TextEdit<'_> {
    edit.id(editor_id())
        .code_editor()
        .frame(egui::Frame::NONE)
        .margin(egui::Margin::symmetric(space::SM as i8, space::SM as i8))
        .desired_width(f32::INFINITY)
        .desired_rows(lines)
        .lock_focus(true)
}

fn evidence_side(panel: &mut MatchingPanel, ui: &mut Ui, cx: &mut PanelContext<'_>, theme: &Theme, actions: &mut Vec<Action>) {
    egui::Panel::top("matching-tabs")
        .frame(egui::Frame::new().fill(theme.bg_panel).inner_margin(egui::Margin::symmetric(space::MD as i8, space::XS as i8 + 2)))
        .show_separator_line(false)
        .show(ui, |ui| {
            let rect = ui.max_rect();
            ui.painter().hline(rect.x_range().expand(space::MD), rect.bottom() + space::XS + 2.0, Stroke::new(1.0, theme.border));
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = space::XS + 2.0;
                let labels = Tab::ALL.map(Tab::label);
                let mut index = Tab::ALL.iter().position(|tab| *tab == panel.tab).unwrap_or(0);
                if widgets::segmented(ui, theme, &labels, &mut index, &[true; 4]) {
                    panel.tab = Tab::ALL[index];
                }
                if panel.tab == Tab::History {
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if widgets::icon_button(ui, theme, Icon::Refresh, "Refresh history", panel.enabled(Action::RefreshHistory)).clicked() {
                            actions.push(Action::RefreshHistory);
                        }
                    });
                }
            });
        });
    let frame = egui::Frame::new().fill(theme.bg_app).inner_margin(egui::Margin::same(space::MD as i8));
    egui::CentralPanel::no_frame().frame(frame).show(ui, |ui| match panel.tab {
        Tab::Compare => compare(panel, ui, theme),
        Tab::History => {
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing = vec2(space::XS + 2.0, space::XS + 2.0);
                click(ui, theme, panel, "More history", Action::MoreHistory, actions);
                widgets::toolbar_separator(ui, theme);
                click(ui, theme, panel, "Project check history", Action::Checks, actions);
                click(ui, theme, panel, "More project checks", Action::MoreChecks, actions);
            });
            ui.add_space(space::SM);
            history(panel, ui, cx, theme);
        }
        Tab::Patch => {
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing = vec2(space::XS + 2.0, space::XS + 2.0);
                click(ui, theme, panel, "Bind real project…", Action::BindProject, actions);
                click(ui, theme, panel, "Prepare source patch", Action::PreparePatch, actions);
                click(ui, theme, panel, "Verify build", Action::Verify, actions);
                if widgets::primary_button(ui, theme, "Verify & apply…", panel.enabled(Action::Apply)).clicked() {
                    actions.push(Action::Apply);
                }
            });
            ui.add_space(space::SM);
            patch(panel, ui, theme);
        }
        Tab::Diagnostics => code_view(ui, theme, "matching-details", &panel.details, text::json_job, "No diagnostics yet", "Run an operation or load project checks to see the full evidence."),
    });
}

fn card(ui: &mut Ui, theme: &Theme, add: impl FnOnce(&mut Ui)) {
    egui::Frame::new()
        .fill(theme.bg_panel)
        .stroke(Stroke::new(1.0, theme.border))
        .corner_radius(CornerRadius::same(metrics::RADIUS + 2))
        .inner_margin(egui::Margin::same(space::MD as i8))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui);
        });
}

fn scorecard(ui: &mut Ui, theme: &Theme, evidence: &Evidence, note: Option<&str>) {
    card(ui, theme, |ui| {
        ui.horizontal(|ui| {
            ui.label(RichText::new(&evidence.symbol).font(theme::code_bold()).color(theme.syntax(Syntax::Function)));
            widgets::caption(ui, theme, &format!("candidate #{}", evidence.candidate));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.label(RichText::new(percent(evidence.similarity)).font(font(Type::Title)).color(similarity_color(theme, evidence.similarity)));
                widgets::caption(ui, theme, "similarity");
            });
        });
        ui.add_space(space::SM);
        meter(ui, theme, evidence.similarity);
        ui.add_space(space::SM);
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing = vec2(space::SM, space::XS);
            verdict_pill(ui, theme, "Instructions", evidence.instructions, verdict(evidence.instructions));
            verdict_pill(ui, theme, "Relocations", evidence.relocations, verdict(evidence.relocations));
            let object = match evidence.object {
                ObjectVerdict::NotBuilt => None,
                ObjectVerdict::Exact(exact) => Some(exact),
            };
            verdict_pill(ui, theme, "Object", object, object_text(evidence.object));
            verdict_pill(ui, theme, "Project", evidence.project, verdict(evidence.project));
        });
        if let Some(note) = note {
            ui.add_space(space::SM);
            ui.add(egui::Label::new(RichText::new(note).font(font(Type::Body)).color(theme.text_muted)).wrap());
        }
    });
}

fn compare(panel: &mut MatchingPanel, ui: &mut Ui, theme: &Theme) {
    let Some(evidence) = panel.evidence.clone() else {
        if let Some(note) = &panel.note {
            card(ui, theme, |ui| {
                ui.add(egui::Label::new(RichText::new(note).font(font(Type::Body)).color(theme.text_muted)).wrap());
            });
            return;
        }
        widgets::empty_state(ui, theme, "Compile a candidate to collect evidence.", "Ctrl+Enter saves the editor as a candidate and compiles it against the reference object.");
        return;
    };
    scorecard(ui, theme, &evidence, panel.note.as_deref());
    ui.add_space(space::SM);
    widgets::caption(ui, theme, "Addresses below are object offsets, not ROM addresses. Source lines without filenames are hints only.");
    ui.add_space(space::XS);
    if panel.mismatches.is_empty() {
        let exact = evidence.object == ObjectVerdict::Exact(true);
        let (title, detail) = if exact {
            ("No mismatches", "The candidate's object bytes equal the reference.")
        } else {
            ("No mismatch rows", "The comparison reported no instruction-level differences; see Diagnostics for the full evidence.")
        };
        widgets::empty_state(ui, theme, title, detail);
        return;
    }
    let code = font(Type::CodeSmall);
    let side = |ui: &mut Ui, label: &str, offset: Option<u64>, instruction: &str| {
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = space::SM;
            widgets::caption(ui, theme, label);
            ui.label(RichText::new(object_offset(offset)).font(code.clone()).color(theme.syntax_address));
            let instruction = if instruction.is_empty() { "—" } else { instruction };
            ui.add(egui::Label::new(text::instruction_job(instruction, theme)).truncate()).on_hover_text(instruction);
        });
    };
    egui::ScrollArea::vertical().id_salt("matching-mismatches").auto_shrink([false, false]).show(ui, |ui| {
        for mismatch in &panel.mismatches {
            egui::Frame::new()
                .fill(theme.bg_panel)
                .stroke(Stroke::new(1.0, theme.border))
                .corner_radius(CornerRadius::same(metrics::RADIUS))
                .inner_margin(egui::Margin::symmetric(space::MD as i8, space::SM as i8))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        let category = super::status_text(&mismatch.category).replace('_', " ");
                        egui::Frame::new()
                            .fill(theme.warn.gamma_multiply(0.14))
                            .corner_radius(CornerRadius::same(metrics::RADIUS_SM))
                            .inner_margin(egui::Margin::symmetric(space::SM as i8, space::XXS as i8))
                            .show(ui, |ui| {
                                ui.label(RichText::new(category).font(font(Type::Caption)).color(theme.warn));
                            });
                        if let Some(line) = mismatch.source_line {
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                widgets::caption(ui, theme, &format!("source line {line} (file unknown)"));
                            });
                        }
                    });
                    ui.add_space(space::XS);
                    ui.columns(2, |columns| {
                        side(&mut columns[0], "REFERENCE", mismatch.target_address, &mismatch.target);
                        side(&mut columns[1], "CANDIDATE", mismatch.candidate_address, &mismatch.candidate);
                    });
                    if !mismatch.hypothesis.is_empty() {
                        ui.add_space(space::XS);
                        ui.add(egui::Label::new(RichText::new(&mismatch.hypothesis).font(font(Type::Body)).color(theme.text_muted)).wrap());
                    }
                });
            ui.add_space(space::SM);
        }
    });
}

const HISTORY_COLUMNS: [table::Column; 8] = [
    table::Column::new("Trial / candidate", table::Width::Initial(84.0)).unsorted(),
    table::Column::new("Profile", table::Width::Initial(60.0)).unsorted(),
    table::Column::new("Similarity", table::Width::Initial(72.0)).right().unsorted(),
    table::Column::new("Instructions", table::Width::Initial(72.0)).unsorted(),
    table::Column::new("Relocations", table::Width::Initial(72.0)).unsorted(),
    table::Column::new("Object", table::Width::Initial(64.0)).unsorted(),
    table::Column::new("Status / provenance", table::Width::Remainder).unsorted(),
    table::Column::new("Time", table::Width::Exact(68.0)).right().unsorted(),
];

fn history(panel: &mut MatchingPanel, ui: &mut Ui, cx: &mut PanelContext<'_>, theme: &Theme) {
    if panel.history.is_empty() {
        widgets::empty_state(ui, theme, "No trials yet", "Every compilation is recorded here; double-click a trial to reopen its candidate.");
        return;
    }
    let rows = &panel.history;
    let footer = format!("{} trials  ·  double-click reopens a trial's candidate and evidence", rows.len());
    let mut sort = table::Sort::default();
    let selected = &mut panel.history_selected;
    let response = table::with_footer(ui, theme, &footer, |ui| {
        table::show(
            ui,
            theme,
            "matching-history",
            &HISTORY_COLUMNS,
            &mut sort,
            rows.len(),
            selected,
            &mut |row, column| {
                let entry = &rows[row];
                let text = entry.cells[column].clone();
                let color = match column {
                    2 => similarity_color(theme, entry.similarity),
                    3..=5 => match text.as_str() {
                        "exact" => theme.ok,
                        "different" => theme.error,
                        _ => theme.text_faint,
                    },
                    6 if text.contains("unverified") => theme.warn,
                    7 => theme.text_muted,
                    _ => theme.text,
                };
                let kind = if matches!(column, 0 | 2 | 7) { Type::Code } else { Type::Body };
                table::Cell::new(text, kind, color)
            },
            &mut |_, _| {},
        )
    });
    if let Some(index) = response.activated {
        panel.open_trial(cx, index);
    }
}

fn patch(panel: &mut MatchingPanel, ui: &mut Ui, theme: &Theme) {
    match panel.project_root() {
        Some(root) => {
            widgets::caption(ui, theme, &format!("Project root  ·  {root}"));
        }
        None => {
            widgets::caption(ui, theme, "No real project bound. Bind project… maps workspace files to a local tree and its build.");
        }
    }
    ui.add_space(space::XS);
    let detail = if panel.project_root().is_some() {
        "Prepare patch previews the candidate as a reviewable diff against the bound project."
    } else {
        "Bind a real project first; imported workspaces stay unbound until you choose a local root."
    };
    code_view(ui, theme, "matching-patch", &panel.patch_text, text::diff_job, "No source patch prepared", detail);
}

/// A read-only, selectable code view with a custom layout.
fn code_view(
    ui: &mut Ui,
    theme: &Theme,
    id: &str,
    content: &str,
    layout: fn(&str, &Theme) -> egui::text::LayoutJob,
    empty_title: &str,
    empty_detail: &str,
) {
    if content.is_empty() {
        widgets::empty_state(ui, theme, empty_title, empty_detail);
        return;
    }
    egui::Frame::new()
        .fill(theme.bg_code)
        .stroke(Stroke::new(1.0, theme.border))
        .corner_radius(CornerRadius::same(metrics::RADIUS))
        .show(ui, |ui| {
            ui.set_min_size(ui.available_size());
            egui::ScrollArea::both().id_salt(id).auto_shrink([false, false]).show(ui, |ui| {
                let theme = theme.clone();
                let mut layouter = move |ui: &Ui, buffer: &dyn egui::TextBuffer, _wrap: f32| ui.fonts_mut(|fonts| fonts.layout_job(layout(buffer.as_str(), &theme)));
                ui.add(
                    egui::TextEdit::multiline(&mut &*content)
                        .id_salt(id)
                        .code_editor()
                        .frame(egui::Frame::NONE)
                        .margin(egui::Margin::same(space::SM as i8))
                        .desired_width(f32::INFINITY)
                        .layouter(&mut layouter),
                );
            });
        });
}
