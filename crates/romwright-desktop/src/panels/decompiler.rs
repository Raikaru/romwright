//! Decompiler (Qt `DecompilerDock`/`DecompilerView` + `MainWindow::decompile`
//! and `decompileFunction`): decompiles the cursor's function through the
//! warm worker pool as a cancellable job, caches documents per
//! program + entry, and paints the token stream with the shared highlighter.
//!
//! The view is read-only source: click/drag/Shift+arrows select, Ctrl+C
//! copies without argument hints, Ctrl+click / Ctrl+Enter follow a callee,
//! F2 renames it, Ctrl+Shift+[ / ] fold and expand brace blocks. Moving the
//! cursor onto an addressed token navigates the other views after a 75 ms
//! pause (Qt's selection timer), and their moves highlight and reveal the
//! matching tokens here.

mod source;
mod tokens;

use crate::address;
use crate::code::{self, CodePainter};
use crate::panel::{Command, Panel, PanelContext, PanelId, Placement, ShellEvent};
use crate::service::{Task, poll_slot};
use crate::theme::{Syntax, Type, font, metrics, space};
use crate::widgets::{self, Icon};
use egui::{CornerRadius, Event, Key, Modifiers, Rect, Sense, Stroke, pos2, vec2};
use romwright_core::graph::NativeGraph;
use romwright_model::function_ir::FunctionIr;
use romwright_model::{Address, FunctionRow};
use source::{Action, SourceView};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokens::{Kind, Token};

pub const ID: PanelId = "decompiler";
/// Qt `selection_timer_`: source cursor moves settle before other views follow.
const SELECTION_DELAY: Duration = Duration::from_millis(75);
/// Decompile budget per function (Qt bridge `decompile_doc`).
const BUDGET: Duration = Duration::from_secs(60);
/// Documents kept per window; Qt's cache was a cost-bounded `QCache`.
const CACHE_ENTRIES: usize = 48;
const MARGIN: f32 = space::SM;
const FOLD_ZONE: f32 = 16.0;

/// One decompiled function as shown: tokens plus the native CFG the graph
/// panel lays out from.
struct Document {
    tokens: Vec<Token>,
    graph: Option<Arc<NativeGraph>>,
    layout_ms: f64,
    ir: Option<Arc<FunctionIr>>,
}

type CacheKey = (String, Address);

struct Load {
    generation: u64,
    key: CacheKey,
    cursor: Address,
    task: Task<Document>,
}

pub struct DecompilerPanel {
    view: SourceView,
    cache: HashMap<CacheKey, Arc<Document>>,
    order: VecDeque<CacheKey>,
    displayed: Option<CacheKey>,
    load: Option<Load>,
    generation: u64,
    /// Shown instead of source: (title, detail).
    message: (String, String),
    function: Option<FunctionRow>,
    pending_navigation: Option<(Address, bool, Instant)>,
    occurrence_click: Option<String>,
    documents: u64,
    /// Per-frame scratch: visible line numbers and one line's spans.
    rows: Vec<usize>,
    spans: Vec<code::Span>,
}

impl Default for DecompilerPanel {
    fn default() -> Self {
        Self {
            view: SourceView::default(),
            cache: HashMap::new(),
            order: VecDeque::new(),
            displayed: None,
            load: None,
            generation: 0,
            message: ("Nothing to decompile".into(), "Select an address to decompile.".into()),
            function: None,
            pending_navigation: None,
            occurrence_click: None,
            documents: 0,
            rows: Vec::new(),
            spans: Vec::new(),
        }
    }
}

impl DecompilerPanel {
    /// Documents installed so far (gate: the decompiler answered).
    pub fn documents_loaded(&self) -> u64 {
        self.documents
    }

    pub fn source(&self) -> &str {
        self.view.text()
    }

    /// Reverse sync from the navigation cursor: highlight and reveal.
    pub fn set_address(&mut self, _cx: &mut PanelContext<'_>, address: &Address) {
        self.view.set_address(address);
    }

    fn set_pending(&mut self, title: impl Into<String>, detail: impl Into<String>) {
        self.displayed = None;
        self.view.set_tokens(Vec::new());
        self.message = (title.into(), detail.into());
    }

    fn clear_cache(&mut self) {
        self.cache.clear();
        self.order.clear();
    }

    /// Shows `entry`'s document from the cache or decompiles it (Qt
    /// `decompileFunction`); the cursor is highlighted once it is shown.
    pub fn decompile(&mut self, cx: &mut PanelContext<'_>, entry: Address, cursor: Address) {
        self.generation += 1;
        self.load = None;
        let key = (cx.session.program.clone(), entry.clone());
        if let Some(document) = self.cache.get(&key).cloned() {
            self.install(cx, key, &document, &cursor);
            return;
        }
        let stale = self.displayed.as_ref() == Some(&key);
        if !stale {
            self.set_pending("Decompiling…", address::format(&entry));
        }
        let (binary, program) = (cx.session.binary.clone(), cx.session.program.clone());
        let task_entry = entry.clone();
        let task = cx.service.job(format!("decompile {}", address::format(&entry)), move |job| {
            job.progress("waiting for the decompiler worker");
            let mut pool = job.worker_pool()?;
            let core = job.fork()?;
            let request = job.execution_request(&core, &binary, &program, None, BUDGET)?;
            job.progress(format!("decompiling {}", address::format(&task_entry)));
            let function = pool.decompile_function(&core, &request, &task_entry).map_err(|error| error.to_string())?;
            drop(pool);
            let tokens = tokens::from_document(&function.doc, &function.call_signatures, function.function_entry.as_ref());
            job.detail(format!("{} tokens, revision {}", tokens.len(), function.doc.revision));
            Ok(Document {
                tokens,
                graph: function.graph.map(Arc::new),
                layout_ms: function.layout_ms,
                ir: function.doc.function_ir.map(Arc::new),
            })
        });
        self.load = Some(Load { generation: self.generation, key, cursor, task });
    }

    fn install(&mut self, cx: &mut PanelContext<'_>, key: CacheKey, document: &Document, cursor: &Address) {
        if self.displayed.as_ref() != Some(&key) {
            self.view.set_tokens(document.tokens.clone());
            self.occurrence_click = None;
            self.documents += 1;
        }
        self.view.set_address(cursor);
        cx.command(Command::Broadcast(ShellEvent::Decompiled {
            entry: key.1.clone(),
            cursor: cursor.clone(),
            graph: document.graph.clone(),
            layout_ms: document.layout_ms,
            ir: document.ir.clone(),
        }));
        self.displayed = Some(key);
    }

    fn remember(&mut self, key: CacheKey, document: Arc<Document>) {
        if self.cache.insert(key.clone(), document).is_none() {
            self.order.push_back(key);
        }
        while self.order.len() > CACHE_ENTRIES {
            if let Some(oldest) = self.order.pop_front() {
                self.cache.remove(&oldest);
            }
        }
    }

    fn function_changed(&mut self, cx: &mut PanelContext<'_>, function: Option<&FunctionRow>, cursor: &Address) {
        self.function = function.cloned();
        match function {
            Some(function) => self.decompile(cx, function.entry.clone(), cursor.clone()),
            None => {
                self.generation += 1;
                self.load = None;
                self.set_pending("No function here", format!("No known function contains {}.", address::format(cursor)));
            }
        }
    }

    fn reload(&mut self, cx: &mut PanelContext<'_>) {
        if let Some(key) = self.displayed.clone() {
            self.cache.remove(&key);
            self.order.retain(|entry| entry != &key);
        }
        cx.command(Command::Decompile);
    }

    fn apply(&mut self, cx: &mut PanelContext<'_>, ui: &egui::Ui, action: Action) {
        match action {
            Action::Follow(target) => cx.navigate(target, true),
            Action::Rename(target, _) => cx.command(Command::RenameFunction { address: target, name: None }),
            Action::Copy(text) => ui.ctx().copy_text(text),
        }
    }

    fn header(&mut self, ui: &mut egui::Ui, cx: &mut PanelContext<'_>) {
        let theme = cx.theme;
        let title = match &self.function {
            Some(function) => format!("DECOMPILER  ·  {}", function.name),
            None => "DECOMPILER".into(),
        };
        let (mut hints, mut unfold, mut reload) = (false, false, false);
        let has_source = !self.view.is_empty();
        let refreshing = self.load.is_some() && has_source;
        widgets::panel_header(ui, theme, &title, |ui| {
            if widgets::chip(ui, theme, "Reload", false).on_hover_text("Decompile this function again").clicked() {
                reload = true;
            }
            if widgets::chip(ui, theme, "Unfold", false).on_hover_text("Expand all folded blocks  (Ctrl+Shift+])").clicked() {
                unfold = true;
            }
            if widgets::chip(ui, theme, "Hints", self.view.hints_visible())
                .on_hover_text("Stored parameter declarations before call arguments; never copied")
                .clicked()
            {
                hints = true;
            }
            if refreshing {
                ui.add(egui::Spinner::new().size(12.0).color(theme.accent));
            }
        });
        if hints {
            self.view.set_hints_visible(!self.view.hints_visible());
        }
        if unfold && has_source {
            self.view.expand_all();
        }
        if reload {
            self.reload(cx);
        }
    }

    fn canvas(&mut self, ui: &mut egui::Ui, cx: &mut PanelContext<'_>) {
        let theme = cx.theme;
        let code_font = font(Type::Code);
        let char_width = ui.fonts_mut(|fonts| fonts.glyph_width(&code_font, '0'));
        let row_height = metrics::CODE_ROW;
        let digits = self.view.line_count().to_string().len().max(2);
        let gutter_width = MARGIN + digits as f32 * char_width + space::SM + FOLD_ZONE;
        let text_offset = gutter_width + space::MD;
        let mut visible = std::mem::take(&mut self.rows);
        visible.clear();
        visible.extend_from_slice(self.view.visible_lines());
        let content = vec2(
            text_offset + (self.view.longest_line() + 6) as f32 * char_width,
            visible.len() as f32 * row_height + 2.0 * MARGIN,
        );
        let page = ((ui.available_height() - 2.0 * MARGIN) / row_height).floor().max(1.0) as usize;
        let indent_unit = self.view.indent_unit();
        let id = ui.id().with("decompiler-canvas");
        let before = self.view.current_address().cloned();
        let cursor_before = (self.view.cursor(), self.view.selection());
        let mut record = false;
        let mut actions = Vec::new();
        let mut hover_token: Option<(String, Option<Address>)> = None;
        let mut context_menu = false;
        let output = egui::ScrollArea::both()
            .id_salt("decompiler-scroll")
            .auto_shrink([false, false])
            .show_viewport(ui, |ui, viewport| {
                let (rect, _) = ui.allocate_exact_size(content.max(ui.available_size()), Sense::hover());
                let response = ui.interact(rect, id, Sense::click_and_drag());
                let clip = ui.clip_rect();
                let text_left = rect.left() + text_offset;
                let gutter_right = clip.left() + gutter_width;
                let row_top = |index: usize| rect.top() + MARGIN + index as f32 * row_height;
                // Pointer → (visible row, line, column rounded to a caret gap).
                let hit = |pos: egui::Pos2, round: bool| -> Option<(usize, usize)> {
                    if visible.is_empty() {
                        return None;
                    }
                    let index = (((pos.y - rect.top() - MARGIN) / row_height).floor().max(0.0) as usize).min(visible.len() - 1);
                    let columns = (pos.x - text_left) / char_width;
                    let column = if round { (columns + 0.5).floor() } else { columns.floor() }.max(0.0) as usize;
                    Some((visible[index], column))
                };
                if self.view.take_reveal() {
                    let line = self.view.cursor_line();
                    if let Ok(index) = visible.binary_search(&line) {
                        let x = text_left + self.view.column_of(self.view.cursor()) as f32 * char_width;
                        let target = Rect::from_min_size(pos2(x - 4.0 * char_width, row_top(index)), vec2(8.0 * char_width, row_height));
                        ui.scroll_to_rect(target.expand2(vec2(0.0, row_height)), None);
                    }
                }

                // Pointer input.
                let modifiers = ui.input(|input| input.modifiers);
                let pointer = response.hover_pos();
                let in_gutter = |pos: egui::Pos2| pos.x < gutter_right;
                if let Some(pos) = pointer.filter(|pos| !in_gutter(*pos))
                    && let Some((line, column)) = hit(pos, false)
                {
                    let text = self.view.line(line);
                    let local = self.view.position(line, column) - self.view.line_range(line).start;
                    if column < text.chars().count() {
                        hover_token = code::word_at(text, local).map(|range| (text[range].to_string(), None));
                        let token = self.view.token_at(self.view.line_range(line).start + local);
                        if let Some(token) = token.filter(|token| token.function_target.is_some()) {
                            hover_token = Some((token.text.clone(), token.function_target.clone()));
                        }
                    }
                }
                if response.is_pointer_button_down_on() || response.clicked() || response.secondary_clicked() {
                    response.request_focus();
                }
                let pressed = ui.input(|input| input.pointer.primary_pressed());
                if pressed
                    && response.hovered()
                    && let Some(pos) = pointer.filter(|pos| !in_gutter(*pos))
                    && let Some((line, column)) = hit(pos, true)
                {
                    self.view.set_cursor(self.view.position(line, column), modifiers.shift);
                    record = true;
                }
                if response.dragged_by(egui::PointerButton::Primary)
                    && let Some(pos) = response.interact_pointer_pos().filter(|pos| !in_gutter(*pos))
                    && let Some((line, column)) = hit(pos, true)
                {
                    self.view.set_cursor(self.view.position(line, column), true);
                }
                if let Some(pos) = response.interact_pointer_pos() {
                    if response.double_clicked() && !in_gutter(pos) {
                        if let Some((line, column)) = hit(pos, false) {
                            self.view.select_word(self.view.position(line, column));
                        }
                    } else if response.clicked() {
                        if in_gutter(pos) {
                            if let Some((line, _)) = hit(pos, false) {
                                if pos.x >= gutter_right - FOLD_ZONE - space::XS && self.view.fold_end(line).is_some() {
                                    self.view.toggle_fold(line);
                                } else {
                                    self.view.select_line(line);
                                    record = true;
                                }
                            }
                        } else {
                            self.occurrence_click = hover_token.as_ref().map(|(word, _)| word.clone());
                            if modifiers.command && let Some((target, _)) = self.view.follow_target() {
                                actions.push(Action::Follow(target));
                            }
                        }
                    } else if response.secondary_clicked() && !in_gutter(pos) {
                        if self.view.selection().is_none()
                            && let Some((line, column)) = hit(pos, true)
                        {
                            self.view.set_cursor(self.view.position(line, column), false);
                        }
                        context_menu = true;
                    }
                }

                // Paint.
                let painter = ui.painter_at(clip);
                let text_painter = ui.painter_at(Rect::from_min_max(pos2(gutter_right, clip.top()), clip.max));
                let occurrence = hover_token.as_ref().map(|(word, _)| word.clone()).or_else(|| self.occurrence_click.clone());
                let code_painter = CodePainter {
                    painter: &text_painter,
                    theme,
                    font: code_font.clone(),
                    char_width,
                    row_height,
                    occurrence: occurrence.as_deref(),
                };
                let cursor_line = self.view.cursor_line();
                let selection = self.view.selection();
                let highlighted = self.view.highlighted();
                let first = ((viewport.min.y - MARGIN) / row_height).floor().max(0.0) as usize;
                let last = (((viewport.max.y - MARGIN) / row_height).ceil().max(0.0) as usize + 1).min(visible.len());
                let hovered_line = pointer.and_then(|pos| hit(pos, false)).map(|(line, _)| line);
                let column_x = |line_text: &str, byte: usize| text_left + line_text[..byte].chars().count() as f32 * char_width;
                for (index, &line) in visible.iter().enumerate().take(last).skip(first) {
                    let y = row_top(index);
                    let full = Rect::from_min_size(pos2(clip.left(), y), vec2(clip.width(), row_height));
                    let range = self.view.line_range(line);
                    let text = self.view.line(line);
                    if line == cursor_line {
                        painter.rect_filled(full, CornerRadius::ZERO, theme.current_line);
                        painter.rect_filled(Rect::from_min_size(full.min, vec2(2.0, row_height)), CornerRadius::ZERO, theme.accent);
                    }
                    // Selection, including the line break when it continues.
                    if let Some(selected) = &selection
                        && selected.start <= range.end
                        && selected.end > range.start
                    {
                        let start = selected.start.max(range.start) - range.start;
                        let end = selected.end.min(range.end) - range.start;
                        let mut right = column_x(text, end);
                        if selected.end > range.end {
                            right += char_width;
                        }
                        let band = Rect::from_min_max(pos2(column_x(text, start), y + 1.0), pos2(right, y + row_height - 1.0));
                        text_painter.rect_filled(band, CornerRadius::same(metrics::RADIUS_SM), theme.bg_selected);
                    }
                    // Indent guides.
                    let leading = text.len() - text.trim_start_matches(' ').len();
                    if leading < text.len() {
                        for level in 0..(leading / indent_unit).min(self.view.depth(line)) {
                            let x = text_left + (level * indent_unit) as f32 * char_width + 0.5 * char_width;
                            text_painter.vline(x, y..=y + row_height, Stroke::new(1.0, theme.border));
                        }
                    }
                    // Tokens tied to the synced address.
                    for synced in highlighted.iter().filter(|synced| synced.start >= range.start && synced.end <= range.end) {
                        let (start, end) = (synced.start - range.start, synced.end - range.start);
                        let band = Rect::from_min_max(pos2(column_x(text, start) - 1.0, y + 2.0), pos2(column_x(text, end) + 1.0, y + row_height - 2.0));
                        text_painter.rect_filled(band, CornerRadius::same(metrics::RADIUS_SM), theme.current_line);
                        text_painter.hline(band.x_range(), band.bottom(), Stroke::new(1.0, theme.accent));
                    }
                    let mut spans = std::mem::take(&mut self.spans);
                    spans.clear();
                    for (span, token) in self.view.line_spans(line) {
                        if token.kind == Kind::Hint {
                            let trimmed = token.text.trim_end().len();
                            let pill = Rect::from_min_max(
                                pos2(column_x(text, span.start) - 1.0, y + 3.0),
                                pos2(column_x(text, span.start + trimmed) + 2.0, y + row_height - 3.0),
                            );
                            text_painter.rect_filled(pill, CornerRadius::same(metrics::RADIUS_SM), theme.bg_hover);
                        }
                        if token.kind == Kind::Function
                            && modifiers.command
                            && hovered_line == Some(line)
                            && hover_token.as_ref().is_some_and(|(word, target)| target.is_some() && *word == token.text)
                        {
                            let underline = y + row_height - 3.0;
                            text_painter.hline(column_x(text, span.start)..=column_x(text, span.end), underline, Stroke::new(1.0, theme.syntax_function));
                        }
                        spans.push(code::Span { range: span, kind: token.syntax() });
                    }
                    code_painter.spans(pos2(text_left, y), text, &spans);
                    self.spans = spans;
                    if self.view.is_folded(line) {
                        let x = column_x(text, text.len()) + char_width;
                        let closing = self.view.fold_end(line).map(|end| self.view.line(end).trim().to_string()).unwrap_or_default();
                        let label = format!("⋯ {closing}");
                        let width = label.chars().count() as f32 * char_width;
                        let pill = Rect::from_min_size(pos2(x - 3.0, y + 2.0), vec2(width + 6.0, row_height - 4.0));
                        text_painter.rect(pill, CornerRadius::same(metrics::RADIUS_SM), theme.bg_raised, Stroke::new(1.0, theme.border), egui::StrokeKind::Inside);
                        code_painter.text(pos2(x, y), &label, Syntax::Dim);
                    }
                    // Sticky gutter: line number and fold chevron.
                    let gutter = Rect::from_min_max(pos2(clip.left(), y), pos2(gutter_right, y + row_height));
                    painter.rect_filled(gutter, CornerRadius::ZERO, if line == cursor_line { theme.current_line } else { theme.bg_code });
                    let number_color = if line == cursor_line { theme.text_muted } else { theme.text_faint };
                    painter.text(
                        pos2(gutter_right - FOLD_ZONE - space::XS, y + row_height / 2.0),
                        egui::Align2::RIGHT_CENTER,
                        (line + 1).to_string(),
                        font(Type::CodeSmall),
                        number_color,
                    );
                    if self.view.fold_end(line).is_some() {
                        let folded = self.view.is_folded(line);
                        let show = folded || hovered_line.is_some() || line == cursor_line;
                        if show {
                            let icon = Rect::from_center_size(pos2(gutter_right - FOLD_ZONE / 2.0, y + row_height / 2.0), vec2(12.0, 12.0));
                            let color = if folded { theme.accent } else { theme.text_faint };
                            widgets::paint_icon(&painter, icon, if folded { Icon::Forward } else { Icon::Down }, color);
                        }
                    }
                }
                // Gutter background above/below the rows and its divider.
                let top = Rect::from_min_max(clip.min, pos2(gutter_right, row_top(first)));
                painter.rect_filled(top, CornerRadius::ZERO, theme.bg_code);
                let bottom = Rect::from_min_max(pos2(clip.left(), row_top(last)), pos2(gutter_right, clip.bottom()));
                painter.rect_filled(bottom, CornerRadius::ZERO, theme.bg_code);
                painter.vline(gutter_right, clip.y_range(), Stroke::new(1.0, theme.border));
                response
            });
        let response = output.inner;
        self.rows = visible;
        if response.hovered() {
            let pointer_on_link = modifiers_command(ui) && hover_token.as_ref().is_some_and(|(_, target)| target.is_some());
            if pointer_on_link {
                ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
            } else {
                ui.ctx().set_cursor_icon(egui::CursorIcon::Text);
            }
        }
        if let Some((name, Some(target))) = &hover_token {
            response.clone().on_hover_ui_at_pointer(|ui| {
                ui.label(egui::RichText::new(format!("{name}  ·  {}", address::format(target))).font(font(Type::Code)).color(theme.syntax_function));
                widgets::caption(ui, theme, "Ctrl+click to open  ·  F2 to rename");
            });
        }

        // Keyboard: Qt DecompilerView bindings; text input is ignored.
        if response.has_focus() {
            let events = ui.input(|input| input.events.clone());
            for event in &events {
                if let Some(action) = self.view.handle_event(event, page) {
                    actions.push(action);
                }
            }
            ui.memory_mut(|memory| {
                memory.set_focus_lock_filter(response.id, egui::EventFilter { vertical_arrows: true, horizontal_arrows: true, escape: false, tab: false })
            });
        }

        if context_menu || response.context_menu_opened() {
            let follow = self.view.follow_target();
            let has_selection = self.view.selection().is_some();
            let hints = self.view.hints_visible();
            let mut menu = None;
            response.context_menu(|ui| {
                let mut item = |ui: &mut egui::Ui, label: &str, shortcut: &str, enabled: bool, choice: MenuChoice| {
                    let button = egui::Button::new(label).shortcut_text(shortcut);
                    if ui.add_enabled(enabled, button).clicked() {
                        menu = Some(choice);
                        ui.close();
                    }
                };
                item(ui, "Copy", "Ctrl+C", has_selection, MenuChoice::Copy);
                item(ui, "Select all", "Ctrl+A", true, MenuChoice::SelectAll);
                ui.separator();
                item(ui, "Follow function", "Ctrl+Enter", follow.is_some(), MenuChoice::Follow);
                item(ui, "Rename function…", "F2", follow.is_some(), MenuChoice::Rename);
                ui.separator();
                item(ui, "Fold current block", "Ctrl+Shift+[", true, MenuChoice::Fold);
                item(ui, "Expand all blocks", "Ctrl+Shift+]", true, MenuChoice::Expand);
                item(ui, if hints { "Hide argument hints" } else { "Show argument hints" }, "", true, MenuChoice::Hints);
            });
            match menu {
                Some(MenuChoice::Copy) => actions.extend(self.view.copy_selection().map(Action::Copy)),
                Some(MenuChoice::SelectAll) => self.view.select_all(),
                Some(MenuChoice::Follow) => actions.extend(follow.map(|(target, _)| Action::Follow(target))),
                Some(MenuChoice::Rename) => actions.extend(follow.map(|(target, name)| Action::Rename(target, name))),
                Some(MenuChoice::Fold) => self.view.fold_current(),
                Some(MenuChoice::Expand) => self.view.expand_all(),
                Some(MenuChoice::Hints) => self.view.set_hints_visible(!hints),
                None => {}
            }
        }
        for action in actions {
            self.apply(cx, ui, action);
        }

        // Cursor moved by the analyst: navigate the other views once it
        // settles (Qt `addressSelected` + 75 ms selection timer).
        let moved = (self.view.cursor(), self.view.selection()) != cursor_before;
        if moved && self.view.selection().is_none() {
            let after = self.view.current_address().cloned();
            if let Some(address) = after
                && (record || Some(&address) != before.as_ref() || cx.session.address.as_ref() != Some(&address))
            {
                self.pending_navigation = Some((address, record, Instant::now()));
            }
        }
        if let Some((_, _, since)) = &self.pending_navigation {
            ui.ctx().request_repaint_after(SELECTION_DELAY.saturating_sub(since.elapsed()));
        }
    }
}

#[derive(Clone, Copy)]
enum MenuChoice {
    Copy,
    SelectAll,
    Follow,
    Rename,
    Fold,
    Expand,
    Hints,
}

fn modifiers_command(ui: &egui::Ui) -> bool {
    ui.input(|input| input.modifiers.command)
}

impl Panel for DecompilerPanel {
    fn id(&self) -> PanelId {
        ID
    }

    fn title(&self) -> String {
        "Decompiler".into()
    }

    fn placement(&self) -> Placement {
        Placement::Right
    }

    fn on_event(&mut self, event: &ShellEvent, cx: &mut PanelContext<'_>) {
        match event {
            ShellEvent::ProgramChanged | ShellEvent::Refresh => {
                self.clear_cache();
                self.generation += 1;
                self.load = None;
                self.function = None;
                self.pending_navigation = None;
                self.set_pending("Nothing to decompile", "Select an address to decompile.");
            }
            ShellEvent::AddressChanged { address, .. } => self.view.set_address(address),
            ShellEvent::FunctionChanged { function, cursor } => self.function_changed(cx, function.as_ref(), cursor),
            ShellEvent::RevisionChanged(_) => self.clear_cache(),
            _ => {}
        }
    }

    fn poll(&mut self, cx: &mut PanelContext<'_>) {
        if let Some((address, record, since)) = &self.pending_navigation
            && since.elapsed() >= SELECTION_DELAY
        {
            let (address, record) = (address.clone(), *record);
            self.pending_navigation = None;
            if record || cx.session.address.as_ref() != Some(&address) {
                cx.navigate(address, record);
            }
        }
        let Some(load) = self.load.take() else { return };
        let mut slot = Some(load.task);
        match poll_slot(&mut slot) {
            None => {
                self.load = slot.map(|task| Load { task, ..load });
            }
            Some(_) if load.generation != self.generation => {}
            Some(Err(error)) => {
                let first = error.lines().next().unwrap_or("").to_string();
                self.set_pending("Decompilation failed", first);
                cx.error(format!("Decompilation failed: {error}"));
            }
            Some(Ok(document)) => {
                let document = Arc::new(document);
                self.remember(load.key.clone(), Arc::clone(&document));
                self.displayed = None;
                self.install(cx, load.key, &document, &load.cursor);
            }
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, cx: &mut PanelContext<'_>) {
        self.header(ui, cx);
        let theme = cx.theme;
        let canvas = ui.available_rect_before_wrap();
        ui.painter().rect_filled(canvas, CornerRadius::ZERO, theme.bg_code);
        if self.view.is_empty() {
            if self.load.is_some() {
                widgets::loading(ui, theme, &format!("{}  {}", self.message.0, self.message.1));
            } else if cx.session.program.is_empty() {
                widgets::empty_state(ui, theme, "No program open", "Choose an image in the toolbar to decompile its functions.");
            } else {
                widgets::empty_state(ui, theme, &self.message.0, &self.message.1);
            }
            return;
        }
        self.canvas(ui, cx);
    }

    fn busy(&self) -> bool {
        self.load.is_some()
    }
}

// ----- UI gate --------------------------------------------------------------

fn key(key: Key, modifiers: Modifiers) -> Event {
    Event::Key { key, physical_key: None, pressed: true, repeat: false, modifiers }
}

fn expect(condition: bool, what: &str) -> Result<(), String> {
    if condition { Ok(()) } else { Err(format!("source interaction failed: {what}")) }
}

/// Headless replay of the Qt gate's `sourceInteractions` on the real source
/// model: hint-free selection copy, keyboard selection, follow/rename on a
/// callee, folding with reverse sync, the hints toggle and read-only input.
/// `Ok` backs `ui.source.{selection_copy, hints_excluded_from_copy,
/// follow_rename, fold_reverse_sync, read_only}`.
pub fn source_interactions() -> Result<(), String> {
    let token = |text: &str, kind: Kind, address: Option<u64>, target: Option<u64>, parameters: &[&str]| Token {
        address: address.map(Address::ram),
        function_target: target.map(Address::ram),
        parameters: parameters.iter().map(|parameter| parameter.to_string()).collect(),
        ..Token::new(text, kind)
    };
    let tokens = vec![
        token("int ", Kind::Code(Syntax::Type), None, None, &[]),
        token("sample", Kind::Function, Some(0x10), Some(0x10), &[]),
        token("() {", Kind::Syntax, None, None, &[]),
        Token::line_break(4),
        token("use", Kind::Function, Some(0x14), Some(0x20), &["int count"]),
        token("(", Kind::Syntax, None, None, &[]),
        token("42", Kind::Code(Syntax::Constant), Some(0x14), None, &[]),
        token("); /* } */", Kind::Syntax, None, None, &[]),
        Token::line_break(0),
        token("}", Kind::Syntax, None, None, &[]),
        Token::line_break(0),
    ];
    let original = "int sample() {\n    use(42); /* } */\n}\n";
    let mut view = SourceView::default();
    view.set_tokens(tokens::with_argument_hints(tokens));
    expect(view.text() != original, "argument hints are shown")?;
    view.select_all();
    expect(view.handle_event(&Event::Copy, 10) == Some(Action::Copy(original.into())), "select-all copy omits hints")?;
    let at = view.text().find("42").ok_or("missing constant")?;
    view.set_cursor(at, false);
    let shift_right = key(Key::ArrowRight, Modifiers::SHIFT);
    view.handle_event(&shift_right, 10);
    view.handle_event(&shift_right, 10);
    expect(view.handle_event(&key(Key::C, Modifiers::COMMAND), 10) == Some(Action::Copy("42".into())), "Shift+Right selection copy")?;
    view.set_address(&Address::ram(0x10));
    expect(view.selected_text() == "42", "reverse sync keeps the analyst's selection")?;
    let at = view.text().find("use").ok_or("missing call")?;
    view.select_word(at);
    let follow = view.handle_event(&key(Key::Enter, Modifiers::COMMAND), 10);
    let rename = view.handle_event(&key(Key::F2, Modifiers::NONE), 10);
    expect(follow == Some(Action::Follow(Address::ram(0x20))), "Ctrl+Enter follows the callee")?;
    expect(matches!(rename, Some(Action::Rename(target, _)) if target == Address::ram(0x20)), "F2 renames the callee")?;
    view.set_cursor(0, false);
    view.handle_event(&key(Key::OpenBracket, Modifiers::COMMAND | Modifiers::SHIFT), 10);
    expect(!view.is_line_visible(1), "Ctrl+Shift+[ folds the block")?;
    view.set_address(&Address::ram(0x14));
    expect(view.is_line_visible(1) && view.current_address() == Some(&Address::ram(0x14)), "reverse sync unfolds and moves the cursor")?;
    view.set_hints_visible(false);
    expect(view.text() == original, "hints toggle off")?;
    for event in [Event::Text("x".into()), Event::Paste("y".into()), key(Key::Backspace, Modifiers::NONE), key(Key::Delete, Modifiers::NONE)] {
        view.handle_event(&event, 10);
    }
    expect(view.text() == original, "typing never edits the source")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn source_interactions_pass() {
        super::source_interactions().unwrap();
    }
}
