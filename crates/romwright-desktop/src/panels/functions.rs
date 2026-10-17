//! Functions browser (Qt `FunctionsDock` + `FunctionTableModel`): a paged,
//! server-filtered, server-sorted view over `Core::functions_page`. Rows are
//! fetched in 256-row pages as the table scrolls and at most eight pages are
//! kept; the full list is never materialised.

use crate::address;
use crate::panel::{Change, Command, Panel, PanelContext, PanelId, Placement, ShellEvent};
use crate::service::Task;
use crate::theme::{Type, font, metrics, space};
use crate::widgets;
use egui::{Align, Key, Layout, RichText, Sense};
use egui_extras::{Column, TableBuilder};
use romwright_model::{Address, FunctionRow, Page};
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

pub const ID: PanelId = "functions";
const PAGE: u64 = 256;
const CACHED_PAGES: usize = 8;
const COLUMNS: [&str; 4] = ["Address", "Name", "Size", "Signature"];
const SORT_KEYS: [&str; 3] = ["entry", "name", "size"];
const ADDRESS_WIDTH: f32 = 88.0;

struct PageRequest {
    generation: u64,
    seek: u64,
    offset: u64,
    anchor: Option<Address>,
    task: Task<Page<FunctionRow>>,
}

pub struct FunctionsPanel {
    program: String,
    filter_text: String,
    filter: String,
    filter_edited: Option<Instant>,
    /// Debounce between typing and the request (250 ms; the gate uses 0).
    pub filter_delay: Duration,
    sort_column: usize,
    ascending: bool,
    total: u64,
    revision: u64,
    pages: HashMap<u64, Vec<FunctionRow>>,
    recent: VecDeque<u64>,
    pending: HashSet<u64>,
    failed: HashSet<u64>,
    requests: Vec<PageRequest>,
    anchor: Option<Address>,
    pending_anchor: Option<Address>,
    anchor_row: Option<u64>,
    anchor_resolved: bool,
    anchor_reveal: bool,
    generation: u64,
    seek_generation: u64,
    function: Option<Address>,
    selected: Option<u64>,
    /// Row to bring into view, retried for a few frames: the table's
    /// scroll extent is only known after it has laid out once.
    scroll_to: Option<(u64, u8)>,
    refreshes: u64,
}

impl Default for FunctionsPanel {
    fn default() -> Self {
        Self {
            program: String::new(),
            filter_text: String::new(),
            filter: String::new(),
            filter_edited: None,
            filter_delay: Duration::from_millis(250),
            sort_column: 0,
            ascending: true,
            total: 0,
            revision: 0,
            pages: HashMap::new(),
            recent: VecDeque::new(),
            pending: HashSet::new(),
            failed: HashSet::new(),
            requests: Vec::new(),
            anchor: None,
            pending_anchor: None,
            anchor_row: None,
            anchor_resolved: false,
            anchor_reveal: false,
            generation: 0,
            seek_generation: 0,
            function: None,
            selected: None,
            scroll_to: None,
            refreshes: 0,
        }
    }
}

impl FunctionsPanel {
    /// Rows the store reports under the active filter.
    pub fn total(&self) -> u64 {
        self.total
    }

    /// Completed page answers so far (Qt `refreshed` signal count).
    pub fn refreshes(&self) -> u64 {
        self.refreshes
    }

    pub fn set_program(&mut self, cx: &PanelContext<'_>, program: &str) {
        if self.program != program {
            self.anchor = None;
        }
        self.program = program.to_string();
        self.refresh(cx, false);
    }

    /// Applies a filter now (typing goes through the debounce).
    pub fn set_filter(&mut self, cx: &PanelContext<'_>, filter: &str) {
        self.filter_text = filter.to_string();
        self.filter_edited = None;
        if self.filter == filter {
            return;
        }
        self.filter = filter.to_string();
        self.refresh(cx, true);
    }

    fn sort(&mut self, cx: &PanelContext<'_>, column: usize) {
        if column >= SORT_KEYS.len() {
            return;
        }
        if self.sort_column == column {
            self.ascending = !self.ascending;
        } else {
            self.sort_column = column;
            self.ascending = true;
        }
        self.refresh(cx, true);
    }

    fn refresh(&mut self, cx: &PanelContext<'_>, reveal: bool) {
        self.generation += 1;
        self.seek_generation += 1;
        self.pages.clear();
        self.recent.clear();
        self.pending.clear();
        self.failed.clear();
        self.requests.clear();
        self.pending_anchor = None;
        self.anchor_resolved = false;
        self.anchor_row = None;
        self.total = 0;
        self.revision = 0;
        self.selected = None;
        let anchor = self.anchor.clone();
        self.request_page(cx, 0, anchor, reveal);
    }

    fn request_page(&mut self, cx: &PanelContext<'_>, offset: u64, anchor: Option<Address>, reveal: bool) {
        if self.program.is_empty() {
            return;
        }
        match &anchor {
            None => {
                if self.pages.contains_key(&offset) || self.pending.contains(&offset) || self.failed.contains(&offset) {
                    return;
                }
                self.pending.insert(offset);
            }
            Some(anchor) => {
                if self.pending_anchor.as_ref() == Some(anchor) {
                    self.anchor_reveal |= reveal;
                    return;
                }
                self.pending_anchor = Some(anchor.clone());
                self.anchor_reveal = reveal;
            }
        }
        let program = self.program.clone();
        let filter = (!self.filter.is_empty()).then(|| self.filter.clone());
        let sort = format!("{}:{}", SORT_KEYS[self.sort_column], if self.ascending { "asc" } else { "desc" });
        let seek = anchor.as_ref().map(|address| address.offset);
        let task = cx.service.request(move |core| {
            core.functions_page(&program, offset, PAGE, filter.as_deref(), Some(&sort), seek)
                .map_err(|error| error.to_string())
        });
        self.requests.push(PageRequest {
            generation: self.generation,
            seek: self.seek_generation,
            offset,
            anchor,
            task,
        });
    }

    fn cached_row(&mut self, row: u64) -> Option<&FunctionRow> {
        let offset = row / PAGE * PAGE;
        if !self.pages.get(&offset).is_some_and(|page| ((row - offset) as usize) < page.len()) {
            return None;
        }
        self.touch(offset);
        self.pages.get(&offset).and_then(|page| page.get((row - offset) as usize))
    }

    fn cached_address(&mut self, address: &Address) -> Option<u64> {
        let found = self.pages.iter().find_map(|(offset, page)| {
            page.iter()
                .position(|row| &row.entry == address)
                .map(|index| (*offset, offset + index as u64))
        });
        found.map(|(offset, row)| {
            self.touch(offset);
            row
        })
    }

    fn touch(&mut self, offset: u64) {
        if self.recent.back() == Some(&offset) {
            return;
        }
        self.recent.retain(|page| *page != offset);
        self.recent.push_back(offset);
    }

    fn seek_address(&mut self, cx: &PanelContext<'_>, address: Option<Address>, reveal: bool) {
        if self.anchor != address {
            self.anchor = address.clone();
            self.anchor_resolved = false;
            self.anchor_row = None;
            self.pending_anchor = None;
            self.seek_generation += 1;
        }
        let Some(address) = address else {
            self.resolved(None, None, reveal);
            return;
        };
        if !self.anchor_resolved {
            self.anchor_row = self.cached_address(&address);
            self.anchor_resolved = self.anchor_row.is_some();
        }
        if self.anchor_resolved {
            self.resolved(Some(&address), self.anchor_row, reveal);
            return;
        }
        self.request_page(cx, 0, Some(address), reveal);
    }

    /// Qt `addressResolved`: select the containing function's row when the
    /// answer is for the function the window is in.
    fn resolved(&mut self, address: Option<&Address>, row: Option<u64>, reveal: bool) {
        if address != self.function.as_ref() {
            return;
        }
        self.selected = row;
        if reveal {
            self.scroll_to = row.map(|row| (row, 3));
        }
    }

    fn set_function(&mut self, cx: &PanelContext<'_>, function: Option<&FunctionRow>) {
        let entry = function.map(|function| function.entry.clone());
        if self.function != entry {
            self.selected = None;
        }
        self.function = entry.clone();
        self.seek_address(cx, entry, true);
    }

    fn answer(&mut self, cx: &mut PanelContext<'_>, request: PageRequest, result: Result<Page<FunctionRow>, String>) {
        if request.generation != self.generation
            || (request.anchor.is_some() && request.seek != self.seek_generation)
        {
            return;
        }
        match &request.anchor {
            None => {
                self.pending.remove(&request.offset);
            }
            Some(_) => self.pending_anchor = None,
        }
        let page = match result {
            Ok(page) => page,
            Err(error) => {
                match &request.anchor {
                    None => {
                        self.failed.insert(request.offset);
                    }
                    Some(anchor) => {
                        let reveal = self.anchor_reveal;
                        self.resolved(Some(anchor), None, reveal);
                    }
                }
                cx.error(error);
                return;
            }
        };
        let changed = self.revision != 0 && self.revision != page.revision;
        if changed {
            self.generation += 1;
            self.pages.clear();
            self.recent.clear();
            self.pending.clear();
            self.failed.clear();
            self.requests.clear();
            self.pending_anchor = None;
            self.anchor_resolved = false;
            self.anchor_row = None;
        }
        self.total = page.total.unwrap_or(page.offset + page.rows.len() as u64);
        self.revision = page.revision;
        self.pages.insert(page.offset, page.rows);
        self.touch(page.offset);
        while self.recent.len() > CACHED_PAGES {
            if let Some(evicted) = self.recent.pop_front() {
                self.pages.remove(&evicted);
            }
        }
        if let Some(anchor) = &request.anchor {
            self.anchor_row = self.cached_address(anchor);
            self.anchor_resolved = true;
            let reveal = self.anchor_reveal;
            self.resolved(Some(anchor), self.anchor_row, reveal);
        } else if changed && self.anchor.is_some() {
            let anchor = self.anchor.clone();
            self.seek_address(cx, anchor, false);
        }
        self.refreshes += 1;
        // An opened program with no cursor starts at its first function.
        if !cx.session.gate && cx.session.address.is_none() && self.total > 0
            && let Some(first) = self.cached_row(0).map(|row| row.entry.clone())
        {
            cx.navigate(first, true);
        }
    }

    fn activate(&mut self, cx: &mut PanelContext<'_>, row: u64) {
        if let Some(entry) = self.cached_row(row).map(|row| row.entry.clone()) {
            cx.navigate(entry, true);
        }
    }

    fn table(&mut self, ui: &mut egui::Ui, cx: &mut PanelContext<'_>, visible_width: f32) {
        let theme = cx.theme;
        // Address + name fill the visible width; size and signature are
        // reached by scrolling right (Qt: names get useful width first).
        let spacing = ui.spacing().item_spacing.x;
        let name_width = (visible_width - ADDRESS_WIDTH - 2.0 * spacing).max(140.0);
        let row_count = usize::try_from(self.total).unwrap_or(usize::MAX);
        let focus_id = ui.id().with("functions-focus");
        let has_focus = ui.memory(|memory| memory.has_focus(focus_id));
        if has_focus && row_count > 0 {
            let (up, down, enter, rename) = ui.input(|input| {
                (input.key_pressed(Key::ArrowUp), input.key_pressed(Key::ArrowDown), input.key_pressed(Key::Enter), input.key_pressed(Key::F2))
            });
            let current = self.selected.unwrap_or(0);
            if up {
                self.selected = Some(current.saturating_sub(1));
                self.scroll_to = self.selected.map(|row| (row, 1));
            }
            if down {
                self.selected = Some((current + 1).min(self.total - 1));
                self.scroll_to = self.selected.map(|row| (row, 1));
            }
            if enter && let Some(row) = self.selected {
                self.activate(cx, row);
            }
            if rename && let Some(entry) = self.selected.and_then(|row| self.cached_row(row)).map(|row| row.entry.clone()) {
                cx.command(Command::RenameFunction { address: entry, name: None });
            }
        }
        let mut builder = TableBuilder::new(ui)
            .vscroll(true)
            .id_salt("functions-table")
            .striped(true)
            .sense(Sense::click())
            .auto_shrink([false, false])
            .cell_layout(Layout::left_to_right(Align::Center))
            .column(Column::exact(ADDRESS_WIDTH).clip(true))
            .column(Column::exact(name_width).clip(true))
            .column(Column::initial(64.0).at_least(40.0).resizable(true).clip(true))
            .column(Column::initial(320.0).at_least(80.0).resizable(true).clip(true));
        if let Some((row, frames)) = self.scroll_to.take() {
            builder = builder.scroll_to_row(usize::try_from(row).unwrap_or(usize::MAX), Some(Align::Center));
            self.scroll_to = frames.checked_sub(1).filter(|left| *left > 0).map(|left| (row, left));
        }
        let mut sort_clicked = None;
        let mut clicked = None;
        let mut activated = None;
        let mut renamed = None;
        let mut needed = Vec::new();
        builder
            .header(26.0, |mut header| {
                for (index, title) in COLUMNS.iter().enumerate() {
                    header.col(|ui| {
                        let sortable = index < SORT_KEYS.len();
                        let arrow = if sortable && self.sort_column == index {
                            if self.ascending { " ↑" } else { " ↓" }
                        } else {
                            ""
                        };
                        let active = sortable && self.sort_column == index;
                        let text = RichText::new(format!("{title}{arrow}"))
                            .font(font(Type::Caption))
                            .color(if active { theme.text } else { theme.text_muted });
                        let layout = if index == 0 || index == 2 { Layout::right_to_left(Align::Center) } else { Layout::left_to_right(Align::Center) };
                        ui.with_layout(layout, |ui| {
                            ui.add_space(space::XS);
                            let response = ui.add(egui::Label::new(text).sense(if sortable { Sense::click() } else { Sense::hover() }).truncate());
                            if sortable && response.clicked() {
                                sort_clicked = Some(index);
                            }
                            if sortable {
                                response.on_hover_cursor(egui::CursorIcon::PointingHand);
                            }
                        });
                    });
                }
            })
            .body(|body| {
                body.rows(metrics::ROW, row_count, |mut row| {
                    let index = row.index() as u64;
                    row.set_selected(self.selected == Some(index));
                    let offset = index / PAGE * PAGE;
                    let cached = self.cached_row(index).cloned();
                    match cached {
                        Some(function) => {
                            let entry = address::format(&function.entry);
                            row.col(|ui| {
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    ui.add_space(space::XS);
                                    widgets::truncated(ui, entry, Type::Code, theme.syntax_address);
                                });
                            });
                            row.col(|ui| {
                                ui.add_space(space::XS);
                                widgets::truncated(ui, &function.name, Type::Body, theme.text);
                            });
                            row.col(|ui| {
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    ui.add_space(space::XS);
                                    widgets::truncated(ui, function.size.to_string(), Type::CodeSmall, theme.text_muted);
                                });
                            });
                            row.col(|ui| {
                                ui.add_space(space::XS);
                                let signature = function.signature.as_deref().unwrap_or("");
                                widgets::truncated(ui, signature, Type::CodeSmall, theme.text_muted);
                            });
                        }
                        None => {
                            let failed = self.failed.contains(&offset);
                            if !failed {
                                needed.push(offset);
                            }
                            row.col(|_| {});
                            row.col(|ui| {
                                ui.add_space(space::XS);
                                let text = if failed { "Page unavailable" } else { "Loading…" };
                                ui.label(RichText::new(text).font(font(Type::Body)).color(theme.text_faint));
                            });
                            row.col(|_| {});
                            row.col(|_| {});
                        }
                    }
                    let response = row.response();
                    if response.clicked() {
                        clicked = Some(index);
                    }
                    if response.double_clicked() {
                        activated = Some(index);
                    }
                    response.context_menu(|ui| {
                        if ui.button("Go to function").clicked() {
                            activated = Some(index);
                            ui.close();
                        }
                        if ui.button("Rename…").clicked() {
                            renamed = Some(index);
                            ui.close();
                        }
                    });
                });
            });
        for offset in needed {
            self.request_page(cx, offset, None, false);
        }
        if let Some(column) = sort_clicked {
            self.sort(cx, column);
        }
        if let Some(row) = clicked {
            self.selected = Some(row);
            ui.memory_mut(|memory| memory.request_focus(focus_id));
        }
        if let Some(row) = activated {
            self.selected = Some(row);
            self.activate(cx, row);
        }
        if let Some(entry) = renamed.and_then(|row| self.cached_row(row)).map(|row| row.entry.clone()) {
            cx.command(Command::RenameFunction { address: entry, name: None });
        }
        if has_focus {
            ui.memory_mut(|memory| {
                memory.set_focus_lock_filter(focus_id, egui::EventFilter { vertical_arrows: true, ..Default::default() })
            });
        }
    }
}

impl Panel for FunctionsPanel {
    fn id(&self) -> PanelId {
        ID
    }

    fn title(&self) -> String {
        "Functions".into()
    }

    fn placement(&self) -> Placement {
        Placement::Left
    }

    fn on_event(&mut self, event: &ShellEvent, cx: &mut PanelContext<'_>) {
        match event {
            ShellEvent::ProgramChanged => {
                let program = cx.session.program.clone();
                self.function = None;
                self.set_program(cx, &program);
            }
            ShellEvent::FunctionChanged { function, .. } => self.set_function(cx, function.as_ref()),
            ShellEvent::RevisionChanged(Change::Rename | Change::Undo | Change::Analysis) | ShellEvent::Refresh => {
                self.refresh(cx, false)
            }
            _ => {}
        }
    }

    fn poll(&mut self, cx: &mut PanelContext<'_>) {
        if let Some(edited) = self.filter_edited
            && edited.elapsed() >= self.filter_delay
        {
            let filter = self.filter_text.clone();
            self.set_filter(cx, &filter);
        }
        let mut index = 0;
        while index < self.requests.len() {
            match self.requests[index].task.poll() {
                Some(result) => {
                    let request = self.requests.remove(index);
                    self.answer(cx, request, result);
                }
                None => index += 1,
            }
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, cx: &mut PanelContext<'_>) {
        let theme = cx.theme;
        egui::Frame::new()
            .inner_margin(egui::Margin::symmetric(space::SM as i8, space::SM as i8))
            .show(ui, |ui| {
                let response = ui.add(
                    egui::TextEdit::singleline(&mut self.filter_text)
                        .hint_text(RichText::new("Filter  ·  substring, or re: for regex").color(theme.text_faint))
                        .font(font(Type::Body))
                        .margin(egui::Margin::symmetric(space::SM as i8, space::XS as i8 + 1))
                        .desired_width(f32::INFINITY),
                );
                if response.changed() {
                    self.filter_edited = Some(Instant::now());
                }
            });
        ui.painter().hline(ui.max_rect().x_range(), ui.cursor().top(), egui::Stroke::new(1.0, theme.border));
        if self.program.is_empty() {
            widgets::empty_state(ui, theme, "No program open", "Choose an image in the toolbar, or import one from Program setup.");
            return;
        }
        if self.total == 0 {
            if self.requests.is_empty() {
                let detail = if self.filter.is_empty() { "The store holds no functions for this program." } else { "No function name matches the filter." };
                widgets::empty_state(ui, theme, "No functions", detail);
            } else {
                widgets::loading(ui, theme, "Loading functions…");
            }
            return;
        }
        let footer = 22.0;
        let table_height = (ui.available_height() - footer).max(0.0);
        // Names keep their width; the other columns scroll horizontally.
        let visible_width = ui.available_width();
        ui.allocate_ui(egui::vec2(visible_width, table_height), |ui| {
            egui::ScrollArea::horizontal()
                .id_salt("functions-h")
                .auto_shrink([false, false])
                .show(ui, |ui| self.table(ui, cx, visible_width));
        });
        let (rect, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), footer), Sense::hover());
        ui.painter().hline(rect.x_range(), rect.top(), egui::Stroke::new(1.0, theme.border));
        ui.painter().text(
            rect.left_center() + egui::vec2(space::SM, 0.0),
            egui::Align2::LEFT_CENTER,
            format!("{} functions  ·  revision {}", self.total, self.revision),
            font(Type::Caption),
            theme.text_faint,
        );
        let _ = ui.cursor();
    }

    fn busy(&self) -> bool {
        !self.requests.is_empty() || self.filter_edited.is_some()
    }
}
