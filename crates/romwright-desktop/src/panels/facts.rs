//! Symbols, strings and fact search (Qt `FactsDock` + `StringsTableModel`).
//!
//! Symbols and strings are paged from the store (`Core::symbols_page`,
//! `Core::strings_page`, 256 rows a page, in address order) and fetched as
//! the table scrolls toward the last loaded row, like Qt's
//! `canFetchMore`/`fetchMore`. Search runs `Core::search` on Enter and shows
//! the first 256 hits, sortable by any column.

use crate::address;
use crate::panel::{Change, Command, Panel, PanelContext, PanelId, ShellEvent};
use crate::service::Task;
use crate::table::{self, Cell, Column, Sort, Width};
use crate::theme::{Theme, Type, font, space};
use crate::widgets;
use egui::{Key, RichText};
use romwright_core::Core;
use romwright_model::{Address, Page, SearchHit, StringRow, SymbolRow};

pub const ID: PanelId = "facts";
const PAGE: u64 = 256;
/// Search hits per query (Qt `limit: 256`).
const SEARCH_LIMIT: u64 = 256;
/// Fetch the next page once the table shows a row this close to the end.
const PREFETCH: usize = 32;
const TABS: [&str; 3] = ["Symbols", "Strings", "Search"];

const SYMBOL_COLUMNS: [Column; 4] = [
    Column::address("Address").unsorted(),
    Column::new("Name", Width::Initial(260.0)).unsorted(),
    Column::new("Source", Width::Initial(120.0)).unsorted(),
    Column::new("External", Width::Remainder).unsorted(),
];
const STRING_COLUMNS: [Column; 3] = [
    Column::address("Address").unsorted(),
    Column::new("Kind", Width::Exact(96.0)).unsorted(),
    Column::new("Value", Width::Remainder).unsorted(),
];
const SEARCH_COLUMNS: [Column; 4] = [
    Column::address("Address"),
    Column::new("Kind", Width::Exact(96.0)),
    Column::new("Name", Width::Initial(240.0)),
    Column::new("Context", Width::Remainder),
];

/// An incrementally fetched, server-ordered list.
struct Paged<T> {
    rows: Vec<T>,
    total: u64,
    generation: u64,
    task: Option<(u64, Task<Page<T>>)>,
    error: Option<String>,
    answered: bool,
    selected: Option<usize>,
    sort: Sort,
}

impl<T> Default for Paged<T> {
    fn default() -> Self {
        Self { rows: Vec::new(), total: 0, generation: 0, task: None, error: None, answered: false, selected: None, sort: Sort::default() }
    }
}

impl<T: Send + 'static> Paged<T> {
    fn reset(&mut self) {
        self.generation += 1;
        self.rows.clear();
        self.total = 0;
        self.task = None;
        self.error = None;
        self.answered = false;
        self.selected = None;
    }

    fn can_fetch_more(&self) -> bool {
        self.task.is_none() && self.error.is_none() && (self.rows.len() as u64) < self.total
    }

    fn fetch(&mut self, cx: &PanelContext<'_>, page: fn(&Core, &str, u64) -> romwright_core::Result<Page<T>>) {
        let program = cx.session.program.clone();
        if self.task.is_some() || program.is_empty() {
            return;
        }
        let offset = self.rows.len() as u64;
        self.task = Some((self.generation, cx.service.request(move |core| page(core, &program, offset).map_err(|error| error.to_string()))));
    }

    fn poll(&mut self, cx: &mut PanelContext<'_>, what: &str) {
        let Some((generation, task)) = self.task.as_ref() else { return };
        let Some(result) = task.poll() else { return };
        let current = *generation == self.generation;
        self.task = None;
        if !current {
            return;
        }
        match result {
            Ok(page) => {
                self.answered = true;
                self.total = page.total.unwrap_or(page.offset + page.rows.len() as u64);
                if page.offset == self.rows.len() as u64 {
                    self.rows.extend(page.rows);
                }
            }
            Err(error) => {
                cx.error(format!("{what}: {error}"));
                self.error = Some(error);
            }
        }
    }
}

fn symbols_page(core: &Core, program: &str, offset: u64) -> romwright_core::Result<Page<SymbolRow>> {
    core.symbols_page(program, offset, PAGE, None)
}

fn strings_page(core: &Core, program: &str, offset: u64) -> romwright_core::Result<Page<StringRow>> {
    core.strings_page(program, offset, PAGE)
}

#[derive(Default)]
pub struct FactsPanel {
    program: String,
    tab: usize,
    symbols: Paged<SymbolRow>,
    strings: Paged<StringRow>,
    term: String,
    searched: String,
    search_generation: u64,
    search_task: Option<(u64, Task<Vec<SearchHit>>)>,
    hits: Vec<SearchHit>,
    search_status: String,
    search_selected: Option<usize>,
    search_sort: Sort,
}

impl FactsPanel {
    /// Shows one tab: 0 symbols, 1 strings, 2 search.
    pub fn set_tab(&mut self, tab: usize) {
        self.tab = tab.min(TABS.len() - 1);
    }

    /// Qt `loadFacts`: reload symbols and strings, then run `term` if any.
    pub fn load(&mut self, cx: &PanelContext<'_>, term: &str) {
        self.program = cx.session.program.clone();
        self.symbols.reset();
        self.strings.reset();
        self.term = term.to_string();
        self.search_generation += 1;
        self.search_task = None;
        self.hits.clear();
        self.searched.clear();
        self.search_selected = None;
        self.search_status = "Enter a search term.".into();
        if self.program.is_empty() {
            return;
        }
        self.symbols.fetch(cx, symbols_page);
        self.strings.fetch(cx, strings_page);
        if !term.trim().is_empty() {
            self.search(cx);
        }
    }

    /// Qt `searchFacts`.
    pub fn search(&mut self, cx: &PanelContext<'_>) {
        let term = self.term.trim().to_string();
        self.search_generation += 1;
        self.hits.clear();
        self.search_selected = None;
        self.search_task = None;
        if self.program.is_empty() || term.is_empty() {
            self.search_status = if self.program.is_empty() { "Open a program first." } else { "Enter a search term." }.into();
            return;
        }
        self.search_status = "Searching…".into();
        self.searched = term.clone();
        let program = self.program.clone();
        let task = cx.service.request(move |core| core.search(&program, &term, SEARCH_LIMIT).map_err(|error| error.to_string()));
        self.search_task = Some((self.search_generation, task));
    }

    fn sort_hits(&mut self) {
        table::sort_rows(&mut self.hits, self.search_sort, |a, b, column| match column {
            0 => match (&a.address, &b.address) {
                (Some(a), Some(b)) => table::address_order(a, b),
                (a, b) => a.is_some().cmp(&b.is_some()),
            },
            1 => a.kind.cmp(&b.kind),
            2 => table::text_order(&a.name, &b.name),
            _ => table::text_order(&a.context, &b.context),
        });
    }

    fn tab_label(&self, index: usize) -> String {
        let count = match index {
            0 => self.symbols.answered.then_some(self.symbols.total),
            1 => self.strings.answered.then_some(self.strings.total),
            _ => (!self.searched.is_empty() && self.search_task.is_none()).then_some(self.hits.len() as u64),
        };
        match count {
            Some(count) => format!("{}  {count}", TABS[index]),
            None => TABS[index].to_string(),
        }
    }

    fn symbols_ui(&mut self, ui: &mut egui::Ui, cx: &mut PanelContext<'_>) {
        let theme = cx.theme;
        let paged = &mut self.symbols;
        if !paged.answered {
            return state(ui, theme, paged.error.as_deref(), "Loading symbols…");
        }
        if paged.rows.is_empty() {
            return widgets::empty_state(ui, theme, "No symbols", "The store holds no symbols for this program.");
        }
        let footer = footer_text(paged.rows.len(), paged.total, "symbols", paged.task.is_some());
        let rows = &paged.rows;
        let mut navigate = None;
        let mut xrefs = None;
        let response = table::with_footer(ui, theme, &footer, |ui| {
            table::show(
                ui,
                theme,
                "facts-symbols",
                &SYMBOL_COLUMNS,
                &mut paged.sort,
                rows.len(),
                &mut paged.selected,
                &mut |index, column| {
                    let row = &rows[index];
                    match column {
                        0 => Cell::address(theme, &row.address),
                        1 => Cell::new(row.name.as_str(), Type::Body, if row.external { theme.syntax_type } else { theme.syntax_function }),
                        2 => Cell::code(row.source.as_str(), theme.text_muted),
                        _ => if row.external { Cell::new("external", Type::Caption, theme.warn) } else { Cell::new("—", Type::Caption, theme.text_faint) },
                    }
                },
                &mut |ui, index| row_menu(ui, &rows[index].address, &mut navigate, &mut xrefs),
            )
        });
        if let Some(index) = response.activated {
            navigate = paged.rows.get(index).map(|row| row.address.clone());
        }
        if response.last_visible.is_some_and(|last| last + PREFETCH >= paged.rows.len()) && paged.can_fetch_more() {
            paged.fetch(cx, symbols_page);
        }
        finish(cx, navigate, xrefs);
    }

    fn strings_ui(&mut self, ui: &mut egui::Ui, cx: &mut PanelContext<'_>) {
        let theme = cx.theme;
        let paged = &mut self.strings;
        if !paged.answered {
            return state(ui, theme, paged.error.as_deref(), "Loading strings…");
        }
        if paged.rows.is_empty() {
            return widgets::empty_state(ui, theme, "No strings", "Analysis found no strings in this program.");
        }
        let footer = footer_text(paged.rows.len(), paged.total, "strings", paged.task.is_some());
        let rows = &paged.rows;
        let mut navigate = None;
        let mut xrefs = None;
        let response = table::with_footer(ui, theme, &footer, |ui| {
            table::show(
                ui,
                theme,
                "facts-strings",
                &STRING_COLUMNS,
                &mut paged.sort,
                rows.len(),
                &mut paged.selected,
                &mut |index, column| {
                    let row = &rows[index];
                    match column {
                        0 => Cell::address(theme, &row.address),
                        1 => Cell::code(row.kind.as_str(), theme.text_muted),
                        _ => Cell::new(format!("\"{}\"", row.value.escape_debug()), Type::Code, theme.syntax_string),
                    }
                },
                &mut |ui, index| row_menu(ui, &rows[index].address, &mut navigate, &mut xrefs),
            )
        });
        if let Some(index) = response.activated {
            navigate = paged.rows.get(index).map(|row| row.address.clone());
        }
        // Qt: a click on a string shows its references without moving the cursor.
        if let Some(index) = response.clicked
            && xrefs.is_none()
            && let Some(row) = paged.rows.get(index) {
                cx.command(Command::Broadcast(ShellEvent::XrefsRequested(row.address.clone())));
            }
        if response.last_visible.is_some_and(|last| last + PREFETCH >= paged.rows.len()) && paged.can_fetch_more() {
            paged.fetch(cx, strings_page);
        }
        finish(cx, navigate, xrefs);
    }

    fn search_ui(&mut self, ui: &mut egui::Ui, cx: &mut PanelContext<'_>) {
        let theme = cx.theme;
        let mut run = false;
        egui::Frame::new().inner_margin(egui::Margin::symmetric(space::SM as i8, space::SM as i8)).show(ui, |ui| {
            ui.horizontal(|ui| {
                let button_width = 84.0;
                let response = ui.add(
                    egui::TextEdit::singleline(&mut self.term)
                        .hint_text(RichText::new("Search symbols, strings and comments").color(theme.text_faint))
                        .font(font(Type::Body))
                        .margin(egui::Margin::symmetric(space::SM as i8, space::XS as i8 + 1))
                        .desired_width((ui.available_width() - button_width - space::SM).max(120.0)),
                );
                if response.changed() {
                    // Qt `textEdited`: drop stale results until Enter.
                    self.search_generation += 1;
                    self.search_task = None;
                    self.hits.clear();
                    self.searched.clear();
                    self.search_selected = None;
                    self.search_status = "Press Enter to search.".into();
                }
                let entered = response.lost_focus() && ui.input(|input| input.key_pressed(Key::Enter));
                if widgets::primary_button(ui, theme, "Search", !self.program.is_empty()).clicked() || entered {
                    run = true;
                }
            });
            ui.add_space(space::XXS);
            widgets::caption(ui, theme, &self.search_status);
        });
        ui.painter().hline(ui.max_rect().x_range(), ui.cursor().top(), egui::Stroke::new(1.0, theme.border));
        if run {
            self.search(cx);
        }
        if self.search_task.is_some() {
            return widgets::loading(ui, theme, "Searching…");
        }
        if self.hits.is_empty() {
            let (title, detail) = if self.searched.is_empty() {
                ("Search facts", "Type a name, string or comment text and press Enter.")
            } else {
                ("No matches", "Nothing in symbols, strings or comments contains that text.")
            };
            return widgets::empty_state(ui, theme, title, detail);
        }
        let hits = &self.hits;
        let mut navigate = None;
        let mut xrefs = None;
        let response = table::show(
            ui,
            theme,
            "facts-search",
            &SEARCH_COLUMNS,
            &mut self.search_sort,
            hits.len(),
            &mut self.search_selected,
            &mut |index, column| {
                let hit = &hits[index];
                match column {
                    0 => match &hit.address {
                        Some(at) => Cell::address(theme, at),
                        None => Cell::new("—", Type::Code, theme.text_faint),
                    },
                    1 => Cell::code(hit.kind.as_str(), theme.text_muted),
                    2 => Cell::text(theme, hit.name.as_str()),
                    _ => Cell::muted(theme, hit.context.as_str()),
                }
            },
            &mut |ui, index| {
                if let Some(at) = &hits[index].address {
                    row_menu(ui, at, &mut navigate, &mut xrefs);
                }
            },
        );
        if response.sort_changed {
            self.search_selected = None;
            self.sort_hits();
        }
        if let Some(index) = response.activated {
            navigate = self.hits.get(index).and_then(|hit| hit.address.clone());
        }
        finish(cx, navigate, xrefs);
    }
}

fn state(ui: &mut egui::Ui, theme: &Theme, error: Option<&str>, loading: &str) {
    match error {
        Some(error) => widgets::empty_state(ui, theme, "Unavailable", error),
        None => widgets::loading(ui, theme, loading),
    }
}

fn footer_text(loaded: usize, total: u64, noun: &str, fetching: bool) -> String {
    if loaded as u64 >= total {
        format!("{total} {noun}  ·  double-click to go to one")
    } else {
        format!("{loaded} of {total} {noun} loaded{}", if fetching { "  ·  fetching…" } else { "  ·  scroll for more" })
    }
}

fn row_menu(ui: &mut egui::Ui, at: &Address, navigate: &mut Option<Address>, xrefs: &mut Option<Address>) {
    if ui.button(format!("Go to {}", address::format(at))).clicked() {
        *navigate = Some(at.clone());
        ui.close();
    }
    if ui.button("Show xrefs").clicked() {
        *xrefs = Some(at.clone());
        ui.close();
    }
    if ui.button("Copy address").clicked() {
        ui.ctx().copy_text(address::format(at));
        ui.close();
    }
}

fn finish(cx: &mut PanelContext<'_>, navigate: Option<Address>, xrefs: Option<Address>) {
    if let Some(at) = navigate {
        cx.navigate(at, true);
    }
    if let Some(at) = xrefs {
        cx.command(Command::Broadcast(ShellEvent::XrefsRequested(at)));
        cx.command(Command::Raise(crate::panels::xrefs::ID));
    }
}

impl Panel for FactsPanel {
    fn id(&self) -> PanelId {
        ID
    }

    fn title(&self) -> String {
        "Facts".into()
    }

    fn on_event(&mut self, event: &ShellEvent, cx: &mut PanelContext<'_>) {
        match event {
            ShellEvent::ProgramChanged => self.load(cx, ""),
            ShellEvent::RevisionChanged(Change::Rename | Change::Undo | Change::Analysis | Change::Comment) | ShellEvent::Refresh => {
                let term = self.searched.clone();
                self.load(cx, &term);
            }
            _ => {}
        }
    }

    fn poll(&mut self, cx: &mut PanelContext<'_>) {
        self.symbols.poll(cx, "Symbols");
        self.strings.poll(cx, "Strings");
        if let Some((generation, task)) = &self.search_task
            && let Some(result) = task.poll()
        {
            let current = *generation == self.search_generation;
            self.search_task = None;
            if current {
                match result {
                    Ok(hits) => {
                        self.search_status = if hits.len() as u64 == SEARCH_LIMIT {
                            format!("Showing the first {SEARCH_LIMIT} matches; refine the search.")
                        } else {
                            format!("{} matches for “{}”", hits.len(), self.searched)
                        };
                        self.hits = hits;
                        self.sort_hits();
                    }
                    Err(error) => {
                        cx.error(format!("Search: {error}"));
                        self.search_status = error;
                    }
                }
            }
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, cx: &mut PanelContext<'_>) {
        let theme = cx.theme;
        let labels: Vec<String> = (0..TABS.len()).map(|index| self.tab_label(index)).collect();
        let labels: Vec<&str> = labels.iter().map(String::as_str).collect();
        egui::Frame::new().inner_margin(egui::Margin::symmetric(space::SM as i8, space::XS as i8 + 2)).show(ui, |ui| {
            ui.horizontal(|ui| {
                widgets::segmented(ui, theme, &labels, &mut self.tab, &[]);
            });
        });
        ui.painter().hline(ui.max_rect().x_range(), ui.cursor().top(), egui::Stroke::new(1.0, theme.border));
        if self.program.is_empty() {
            return widgets::empty_state(ui, theme, "No program open", "Choose an image in the toolbar to browse its symbols and strings.");
        }
        match self.tab {
            0 => self.symbols_ui(ui, cx),
            1 => self.strings_ui(ui, cx),
            _ => self.search_ui(ui, cx),
        }
    }

    fn busy(&self) -> bool {
        self.symbols.task.is_some() || self.strings.task.is_some() || self.search_task.is_some()
    }
}
