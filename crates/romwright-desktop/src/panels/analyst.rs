//! Analyst data (Qt `AnalystDock`): bookmarks and byte patches, listed from
//! the store and edited through the shell's [`Command::Analyst`] so every
//! change lands as a job and broadcasts `RevisionChanged(Change::Analyst)`.

use crate::address;
use crate::panel::{AnalystEdit, Change, Command, Panel, PanelContext, PanelId, ShellEvent};
use crate::service::Task;
use crate::table::{self, Cell, Column, Sort, Width};
use crate::theme::{Theme, Type, font, space};
use crate::widgets;
use egui::{Key, RichText};
use romwright_model::{Address, BookmarkRow, PatchRow};

pub const ID: PanelId = "analyst";
const TABS: [&str; 2] = ["Bookmarks", "Patches"];
const BOOKMARK_COLUMNS: [Column; 3] = [
    Column::address("Address"),
    Column::new("Label", Width::Initial(200.0)),
    Column::new("Comment", Width::Remainder),
];
const PATCH_COLUMNS: [Column; 4] = [
    Column::address("Address"),
    Column::new("Original", Width::Initial(180.0)),
    Column::new("Patched", Width::Initial(180.0)),
    Column::new("State", Width::Remainder),
];

/// Hex as an analyst types it: `90 90`, `9090`, `0x90,0x90`.
pub fn parse_bytes(text: &str) -> Option<Vec<u8>> {
    let mut digits = String::new();
    for token in text.split(|c: char| c.is_whitespace() || c == ',') {
        let token = token.strip_prefix("0x").or_else(|| token.strip_prefix("0X")).unwrap_or(token);
        if token.len() % 2 == 1 {
            digits.push('0');
        }
        digits.push_str(token);
    }
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    (0..digits.len()).step_by(2).map(|at| u8::from_str_radix(&digits[at..at + 2], 16).ok()).collect()
}

/// `90 90 c3` (Qt `bytesText`).
pub fn format_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect::<Vec<_>>().join(" ")
}

/// The add/edit form under the tab strip.
#[derive(Default)]
struct Form {
    open: bool,
    /// Editing the row at this address (its address is fixed).
    editing: Option<Address>,
    address: String,
    first: String,
    second: String,
    error: Option<String>,
}

#[derive(Default)]
pub struct AnalystPanel {
    program: String,
    tab: usize,
    generation: u64,
    bookmarks: Vec<BookmarkRow>,
    patches: Vec<PatchRow>,
    bookmarks_task: Option<(u64, Task<Vec<BookmarkRow>>)>,
    patches_task: Option<(u64, Task<Vec<PatchRow>>)>,
    answered: [bool; 2],
    errors: [Option<String>; 2],
    selected: [Option<usize>; 2],
    sorts: [Sort; 2],
    form: Form,
}

impl AnalystPanel {
    /// Shows one tab: 0 bookmarks, 1 patches.
    pub fn set_tab(&mut self, tab: usize) {
        let tab = tab.min(TABS.len() - 1);
        if tab != self.tab {
            self.tab = tab;
            self.form = Form::default();
        }
    }

    /// Qt `loadAnalystData`.
    pub fn load(&mut self, cx: &PanelContext<'_>) {
        self.generation += 1;
        self.program = cx.session.program.clone();
        self.answered = [false; 2];
        self.errors = [None, None];
        self.selected = [None; 2];
        if self.program.is_empty() {
            self.bookmarks.clear();
            self.patches.clear();
            self.bookmarks_task = None;
            self.patches_task = None;
            return;
        }
        let program = self.program.clone();
        self.bookmarks_task = Some((self.generation, cx.service.request(move |core| core.bookmarks(&program).map_err(|error| error.to_string()))));
        let program = self.program.clone();
        self.patches_task = Some((self.generation, cx.service.request(move |core| core.patches(&program).map_err(|error| error.to_string()))));
    }

    fn sort(&mut self, tab: usize) {
        match tab {
            0 => table::sort_rows(&mut self.bookmarks, self.sorts[0], |a, b, column| match column {
                0 => table::address_order(&a.address, &b.address),
                1 => table::text_order(&a.label, &b.label),
                _ => table::text_order(&a.comment, &b.comment),
            }),
            _ => table::sort_rows(&mut self.patches, self.sorts[1], |a, b, column| match column {
                0 => table::address_order(&a.address, &b.address),
                1 => a.original.cmp(&b.original),
                2 => a.patched.cmp(&b.patched),
                _ => b.enabled.cmp(&a.enabled),
            }),
        }
    }

    /// Opens the add form (`None`, prefilled with the cursor) or the edit
    /// form for row `editing` of the current tab.
    pub fn open_form(&mut self, cx: &PanelContext<'_>, editing: Option<usize>) {
        let cursor = cx.session.address.as_ref().map(address::format).unwrap_or_default();
        self.form = match (self.tab, editing) {
            (0, Some(index)) => match self.bookmarks.get(index) {
                Some(row) => Form { open: true, editing: Some(row.address.clone()), address: address::format(&row.address), first: row.label.clone(), second: row.comment.clone(), error: None },
                None => return,
            },
            (_, Some(index)) => match self.patches.get(index) {
                Some(row) => Form {
                    open: true,
                    editing: Some(row.address.clone()),
                    address: address::format(&row.address),
                    first: format_bytes(&row.original),
                    second: format_bytes(&row.patched),
                    error: None,
                },
                None => return,
            },
            (_, None) => Form { open: true, address: cursor, ..Form::default() },
        };
    }

    fn submit(&mut self, cx: &mut PanelContext<'_>) {
        let form = &mut self.form;
        let Some(at) = form.editing.clone().or_else(|| address::parse(&form.address)) else {
            form.error = Some("Enter an address such as 0x401000.".into());
            return;
        };
        let edit = if self.tab == 0 {
            if form.first.trim().is_empty() {
                form.error = Some("A bookmark needs a label.".into());
                return;
            }
            AnalystEdit::SetBookmark(BookmarkRow { address: at, label: form.first.trim().to_string(), comment: form.second.trim().to_string() })
        } else {
            let (Some(original), Some(patched)) = (parse_bytes(&form.first), parse_bytes(&form.second)) else {
                form.error = Some("Original and patched bytes are hex, such as 74 05.".into());
                return;
            };
            if original.len() != patched.len() {
                form.error = Some(format!("Original has {} bytes but patched has {}.", original.len(), patched.len()));
                return;
            }
            let enabled = self.patches.iter().find(|row| row.address == at).is_none_or(|row| row.enabled);
            AnalystEdit::SetPatch(PatchRow { address: at, original, patched, enabled })
        };
        cx.command(Command::Analyst(edit));
        self.form = Form::default();
    }

    fn form_ui(&mut self, ui: &mut egui::Ui, cx: &mut PanelContext<'_>) {
        let theme = cx.theme;
        let bookmarks = self.tab == 0;
        let mut save = false;
        let mut cancel = false;
        egui::Frame::new()
            .fill(theme.bg_raised)
            .inner_margin(egui::Margin::symmetric(space::MD as i8, space::SM as i8))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                let form = &mut self.form;
                let (first, second) = if bookmarks { ("Label", "Comment") } else { ("Original", "Patched") };
                let mut entered = false;
                ui.horizontal(|ui| {
                    let mut field = |ui: &mut egui::Ui, caption: &str, text: &mut String, width: f32, code: bool, enabled: bool| {
                        ui.vertical(|ui| {
                            widgets::caption(ui, theme, caption);
                            let edit = egui::TextEdit::singleline(text)
                                .font(font(if code { Type::Code } else { Type::Body }))
                                .margin(egui::Margin::symmetric(space::SM as i8, space::XS as i8 + 1))
                                .desired_width(width);
                            let response = ui.add_enabled(enabled, edit);
                            entered |= response.lost_focus() && ui.input(|input| input.key_pressed(Key::Enter));
                        });
                    };
                    let editing = form.editing.is_none();
                    field(ui, "Address", &mut form.address, 120.0, true, editing);
                    let wide = ((ui.available_width() - 200.0) / 2.0).max(120.0);
                    field(ui, first, &mut form.first, wide, !bookmarks, true);
                    field(ui, second, &mut form.second, wide, !bookmarks, true);
                    ui.vertical(|ui| {
                        widgets::caption(ui, theme, " ");
                        ui.horizontal(|ui| {
                            save = widgets::primary_button(ui, theme, "Save", true).clicked();
                            cancel = widgets::button(ui, theme, "Cancel", true).clicked();
                        });
                    });
                });
                save |= entered;
                if let Some(error) = &form.error {
                    ui.label(RichText::new(error).font(font(Type::Caption)).color(theme.error));
                }
            });
        ui.painter().hline(ui.max_rect().x_range(), ui.cursor().top(), egui::Stroke::new(1.0, theme.border));
        if cancel {
            self.form = Form::default();
        } else if save {
            self.submit(cx);
        }
    }

    fn table_ui(&mut self, ui: &mut egui::Ui, cx: &mut PanelContext<'_>) {
        let theme = cx.theme;
        let tab = self.tab;
        let mut navigate = None;
        let mut edit = None;
        let mut command = None;
        let footer;
        let response = if tab == 0 {
            let rows = &self.bookmarks;
            footer = format!("{} bookmarks  ·  double-click to go to one", rows.len());
            table::with_footer(ui, theme, &footer, |ui| {
                table::show(
                    ui,
                    theme,
                    "analyst-bookmarks",
                    &BOOKMARK_COLUMNS,
                    &mut self.sorts[0],
                    rows.len(),
                    &mut self.selected[0],
                    &mut |index, column| {
                        let row = &rows[index];
                        match column {
                            0 => Cell::address(theme, &row.address),
                            1 => Cell::new(row.label.as_str(), Type::Strong, theme.syntax_label),
                            _ => Cell::new(row.comment.as_str(), Type::Body, theme.syntax_comment),
                        }
                    },
                    &mut |ui, index| {
                        let row = &rows[index];
                        if ui.button(format!("Go to {}", address::format(&row.address))).clicked() {
                            navigate = Some(row.address.clone());
                            ui.close();
                        }
                        if ui.button("Edit…").clicked() {
                            edit = Some(index);
                            ui.close();
                        }
                        if ui.button("Delete bookmark").clicked() {
                            command = Some(AnalystEdit::DeleteBookmark(row.address.clone()));
                            ui.close();
                        }
                    },
                )
            })
        } else {
            let rows = &self.patches;
            let enabled = rows.iter().filter(|row| row.enabled).count();
            footer = format!("{} patches  ·  {enabled} enabled", rows.len());
            table::with_footer(ui, theme, &footer, |ui| {
                table::show(
                    ui,
                    theme,
                    "analyst-patches",
                    &PATCH_COLUMNS,
                    &mut self.sorts[1],
                    rows.len(),
                    &mut self.selected[1],
                    &mut |index, column| {
                        let row = &rows[index];
                        match column {
                            0 => Cell::address(theme, &row.address),
                            1 => Cell::code(format_bytes(&row.original), theme.syntax_dim),
                            2 => Cell::code(format_bytes(&row.patched), theme.syntax_constant),
                            _ if row.enabled => Cell::new("enabled", Type::Caption, theme.ok),
                            _ => Cell::new("disabled", Type::Caption, theme.text_faint),
                        }
                    },
                    &mut |ui, index| {
                        let row = &rows[index];
                        if ui.button(format!("Go to {}", address::format(&row.address))).clicked() {
                            navigate = Some(row.address.clone());
                            ui.close();
                        }
                        if ui.button(if row.enabled { "Disable" } else { "Enable" }).clicked() {
                            command = Some(AnalystEdit::SetPatch(PatchRow { enabled: !row.enabled, ..row.clone() }));
                            ui.close();
                        }
                        if ui.button("Edit…").clicked() {
                            edit = Some(index);
                            ui.close();
                        }
                        if ui.button("Delete patch").clicked() {
                            command = Some(AnalystEdit::DeletePatch(row.address.clone()));
                            ui.close();
                        }
                    },
                )
            })
        };
        if response.sort_changed {
            self.selected[tab] = None;
            self.sort(tab);
        }
        if let Some(index) = response.activated {
            navigate = if tab == 0 { self.bookmarks.get(index).map(|row| row.address.clone()) } else { self.patches.get(index).map(|row| row.address.clone()) };
        }
        if let Some(index) = edit {
            self.open_form(cx, Some(index));
        }
        if let Some(command) = command {
            cx.command(Command::Analyst(command));
        }
        if let Some(at) = navigate {
            cx.navigate(at, true);
        }
    }
}

fn empty(ui: &mut egui::Ui, theme: &Theme, tab: usize) {
    if tab == 0 {
        widgets::empty_state(ui, theme, "No bookmarks", "Add bookmark marks the cursor address with a label and a note.");
    } else {
        widgets::empty_state(ui, theme, "No patches", "Add patch records replacement bytes at an address; the image is not modified.");
    }
}

impl Panel for AnalystPanel {
    fn id(&self) -> PanelId {
        ID
    }

    fn title(&self) -> String {
        "Analyst".into()
    }

    fn on_event(&mut self, event: &ShellEvent, cx: &mut PanelContext<'_>) {
        match event {
            ShellEvent::ProgramChanged => {
                self.form = Form::default();
                self.load(cx);
            }
            ShellEvent::RevisionChanged(Change::Analyst | Change::Undo) | ShellEvent::Refresh => self.load(cx),
            _ => {}
        }
    }

    fn poll(&mut self, cx: &mut PanelContext<'_>) {
        if let Some((generation, task)) = &self.bookmarks_task
            && let Some(result) = task.poll()
        {
            let current = *generation == self.generation;
            self.bookmarks_task = None;
            if current {
                self.answered[0] = true;
                match result {
                    Ok(rows) => {
                        self.bookmarks = rows;
                        self.sort(0);
                    }
                    Err(error) => {
                        cx.error(format!("Bookmarks: {error}"));
                        self.errors[0] = Some(error);
                    }
                }
            }
        }
        if let Some((generation, task)) = &self.patches_task
            && let Some(result) = task.poll()
        {
            let current = *generation == self.generation;
            self.patches_task = None;
            if current {
                self.answered[1] = true;
                match result {
                    Ok(rows) => {
                        self.patches = rows;
                        self.sort(1);
                    }
                    Err(error) => {
                        cx.error(format!("Patches: {error}"));
                        self.errors[1] = Some(error);
                    }
                }
            }
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, cx: &mut PanelContext<'_>) {
        let theme = cx.theme;
        let counts = [self.bookmarks.len(), self.patches.len()];
        let labels: Vec<String> = (0..2)
            .map(|index| if self.answered[index] { format!("{}  {}", TABS[index], counts[index]) } else { TABS[index].to_string() })
            .collect();
        let has_program = !self.program.is_empty();
        let mut tab = self.tab;
        let mut add = false;
        egui::Frame::new().inner_margin(egui::Margin::symmetric(space::SM as i8, space::XS as i8 + 2)).show(ui, |ui| {
            ui.horizontal(|ui| {
                widgets::segmented(ui, theme, &[labels[0].as_str(), labels[1].as_str()], &mut tab, &[]);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let label = if tab == 0 { "Add bookmark" } else { "Add patch" };
                    add = widgets::button(ui, theme, label, has_program && !self.form.open).clicked();
                });
            });
        });
        ui.painter().hline(ui.max_rect().x_range(), ui.cursor().top(), egui::Stroke::new(1.0, theme.border));
        self.set_tab(tab);
        if add {
            self.open_form(cx, None);
        }
        if !has_program {
            return widgets::empty_state(ui, theme, "No program open", "Choose an image in the toolbar to see its bookmarks and patches.");
        }
        if self.form.open {
            self.form_ui(ui, cx);
        }
        if !self.answered[self.tab] {
            return widgets::loading(ui, theme, "Loading…");
        }
        if let Some(error) = &self.errors[self.tab] {
            return widgets::empty_state(ui, theme, "Unavailable", error);
        }
        if counts[self.tab] == 0 {
            if !self.form.open {
                empty(ui, theme, self.tab);
            }
            return;
        }
        self.table_ui(ui, cx);
    }

    fn busy(&self) -> bool {
        self.bookmarks_task.is_some() || self.patches_task.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_hex_forms_analysts_type() {
        assert_eq!(parse_bytes("90 90"), Some(vec![0x90, 0x90]));
        assert_eq!(parse_bytes("74eb"), Some(vec![0x74, 0xeb]));
        assert_eq!(parse_bytes("0x74,0x5"), Some(vec![0x74, 0x05]));
        assert_eq!(parse_bytes(""), None);
        assert_eq!(parse_bytes("zz"), None);
        assert_eq!(format_bytes(&[0x90, 0x0c]), "90 0c");
    }
}
