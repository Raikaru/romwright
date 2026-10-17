//! The one data-table look every list panel shares (Functions sets the
//! style): caption headers with `↑`/`↓` sort arrows, zebra rows of
//! [`metrics::ROW`], hover and selection highlight, monospace right-aligned
//! addresses, every cell ellipsized with its full text on hover, keyboard
//! row navigation (↑/↓, Enter) and a per-row context menu.
//!
//! Rows are supplied in display order by index; a panel that sorts on the
//! client keeps its own `Vec` sorted with [`sort_rows`] whenever
//! [`TableResponse::sort_changed`] fires.

use crate::address;
use crate::theme::{Theme, Type, font, metrics, space};
use crate::widgets;
use egui::{Align, Color32, Key, Layout, RichText, Sense, Ui};
use egui_extras::{Column as ExtraColumn, TableBuilder};
use romwright_model::Address;
use std::cmp::Ordering;

/// Width of an address column (`0x` + 9 hex digits in `Type::Code`; longer
/// addresses ellipsize with the full text on hover).
pub const ADDRESS_WIDTH: f32 = 100.0;
const HEADER: f32 = 26.0;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Width {
    /// Fixed width.
    Exact(f32),
    /// User-resizable, starting at this width.
    Initial(f32),
    /// Whatever is left (last column).
    Remainder,
}

#[derive(Clone, Copy, Debug)]
pub struct Column {
    pub title: &'static str,
    pub width: Width,
    /// Right-aligned (addresses, counts).
    pub right: bool,
    pub sortable: bool,
}

impl Column {
    pub const fn new(title: &'static str, width: Width) -> Self {
        Self { title, width, right: false, sortable: true }
    }

    /// Address column: fixed, right-aligned, sortable.
    pub const fn address(title: &'static str) -> Self {
        Self { title, width: Width::Exact(ADDRESS_WIDTH), right: true, sortable: true }
    }

    pub const fn right(mut self) -> Self {
        self.right = true;
        self
    }

    pub const fn unsorted(mut self) -> Self {
        self.sortable = false;
        self
    }
}

/// What one cell shows.
#[derive(Clone, Debug)]
pub struct Cell {
    pub text: String,
    pub kind: Type,
    pub color: Color32,
    /// Extra hover text (the full text is always shown when truncated).
    pub tooltip: Option<String>,
}

impl Cell {
    pub fn new(text: impl Into<String>, kind: Type, color: Color32) -> Self {
        Self { text: text.into(), kind, color, tooltip: None }
    }

    /// Body text in the primary text colour.
    pub fn text(theme: &Theme, text: impl Into<String>) -> Self {
        Self::new(text, Type::Body, theme.text)
    }

    /// Secondary body text.
    pub fn muted(theme: &Theme, text: impl Into<String>) -> Self {
        Self::new(text, Type::Body, theme.text_muted)
    }

    /// Monospace address in the address syntax colour.
    pub fn address(theme: &Theme, address: &Address) -> Self {
        Self::new(address::format(address), Type::Code, theme.syntax_address)
    }

    /// Dense monospace (bytes, counts, kinds).
    pub fn code(text: impl Into<String>, color: Color32) -> Self {
        Self::new(text, Type::CodeSmall, color)
    }

    pub fn tooltip(mut self, text: impl Into<String>) -> Self {
        self.tooltip = Some(text.into());
        self
    }
}

/// Client-side sort state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sort {
    pub column: Option<usize>,
    pub ascending: bool,
}

impl Default for Sort {
    fn default() -> Self {
        Self { column: None, ascending: true }
    }
}

impl Sort {
    pub fn by(column: usize) -> Self {
        Self { column: Some(column), ascending: true }
    }

    fn click(&mut self, column: usize) {
        if self.column == Some(column) {
            self.ascending = !self.ascending;
        } else {
            self.column = Some(column);
            self.ascending = true;
        }
    }
}

/// Stable sort of `rows` by the active column; `compare(a, b, column)` gives
/// the ascending order of one column.
pub fn sort_rows<T>(rows: &mut [T], sort: Sort, compare: impl Fn(&T, &T, usize) -> Ordering) {
    let Some(column) = sort.column else { return };
    rows.sort_by(|a, b| {
        let order = compare(a, b, column);
        if sort.ascending { order } else { order.reverse() }
    });
}

/// Case-insensitive text order for sort comparators.
pub fn text_order(a: &str, b: &str) -> Ordering {
    a.chars().flat_map(char::to_lowercase).cmp(b.chars().flat_map(char::to_lowercase))
}

/// Address order for sort comparators: offset, then space.
pub fn address_order(a: &Address, b: &Address) -> Ordering {
    a.offset.cmp(&b.offset).then_with(|| {
        if a.space == b.space { Ordering::Equal } else { address::format(a).cmp(&address::format(b)) }
    })
}

/// What happened in the table this frame.
#[derive(Default)]
pub struct TableResponse {
    /// The sort changed: re-sort the rows.
    pub sort_changed: bool,
    /// Double-clicked or Enter on a row.
    pub activated: Option<usize>,
    /// Single-clicked (selection already updated).
    pub clicked: Option<usize>,
    /// The last row index the body laid out (incremental fetching).
    pub last_visible: Option<usize>,
}

/// Draws the table filling the available space.
///
/// `cell(row, column)` supplies display text; `menu(ui, row)` fills the
/// row's context menu (return without adding items for none).
// The table's inputs are a UI handle, its data model and two callbacks.
#[allow(clippy::too_many_arguments)]
pub fn show(
    ui: &mut Ui,
    theme: &Theme,
    id_salt: &str,
    columns: &[Column],
    sort: &mut Sort,
    rows: usize,
    selected: &mut Option<usize>,
    cell: &mut dyn FnMut(usize, usize) -> Cell,
    menu: &mut dyn FnMut(&mut Ui, usize),
) -> TableResponse {
    let mut out = TableResponse::default();
    let focus_id = ui.id().with((id_salt, "focus"));
    let has_focus = ui.memory(|memory| memory.has_focus(focus_id));
    let mut scroll_to = None;
    if has_focus && rows > 0 {
        let (up, down, enter) = ui.input(|input| {
            (input.key_pressed(Key::ArrowUp), input.key_pressed(Key::ArrowDown), input.key_pressed(Key::Enter))
        });
        let current = selected.unwrap_or(0);
        if up {
            *selected = Some(current.saturating_sub(1));
            scroll_to = *selected;
        }
        if down {
            *selected = Some(if selected.is_some() { (current + 1).min(rows - 1) } else { 0 });
            scroll_to = *selected;
        }
        if enter {
            out.activated = *selected;
        }
    }
    let mut builder = TableBuilder::new(ui)
        .id_salt(id_salt)
        .vscroll(true)
        .striped(true)
        .sense(Sense::click())
        .auto_shrink([false, false])
        // Fill exactly the space given, however short the dock (egui_extras
        // defaults to at least 200 px, which pushes footers out of view).
        .min_scrolled_height(0.0)
        .max_scroll_height(f32::INFINITY)
        .cell_layout(Layout::left_to_right(Align::Center));
    for column in columns {
        builder = builder.column(match column.width {
            Width::Exact(width) => ExtraColumn::exact(width).clip(true),
            Width::Initial(width) => ExtraColumn::initial(width).at_least(40.0).resizable(true).clip(true),
            Width::Remainder => ExtraColumn::remainder().at_least(80.0).clip(true),
        });
    }
    if let Some(row) = scroll_to {
        builder = builder.scroll_to_row(row, None);
    }
    let mut sort_clicked = None;
    let mut clicked = None;
    builder
        .header(HEADER, |mut header| {
            for (index, column) in columns.iter().enumerate() {
                header.col(|ui| {
                    let active = column.sortable && sort.column == Some(index);
                    let arrow = if active { if sort.ascending { " ↑" } else { " ↓" } } else { "" };
                    let text = RichText::new(format!("{}{arrow}", column.title))
                        .font(font(Type::Caption))
                        .color(if active { theme.text } else { theme.text_muted });
                    let layout = if column.right { Layout::right_to_left(Align::Center) } else { Layout::left_to_right(Align::Center) };
                    ui.with_layout(layout, |ui| {
                        ui.add_space(space::XS);
                        let sense = if column.sortable { Sense::click() } else { Sense::hover() };
                        let response = ui.add(egui::Label::new(text).sense(sense).truncate());
                        if column.sortable {
                            if response.clicked() {
                                sort_clicked = Some(index);
                            }
                            response.on_hover_cursor(egui::CursorIcon::PointingHand);
                        }
                    });
                });
            }
        })
        .body(|body| {
            body.rows(metrics::ROW, rows, |mut row| {
                let index = row.index();
                out.last_visible = Some(out.last_visible.map_or(index, |last| last.max(index)));
                row.set_selected(*selected == Some(index));
                for (column_index, column) in columns.iter().enumerate() {
                    let content = cell(index, column_index);
                    row.col(|ui| {
                        let draw = |ui: &mut Ui| {
                            ui.add_space(space::XS);
                            let response = widgets::truncated(ui, content.text.as_str(), content.kind, content.color);
                            if let Some(tooltip) = &content.tooltip {
                                response.on_hover_text(tooltip.as_str());
                            }
                        };
                        if column.right {
                            ui.with_layout(Layout::right_to_left(Align::Center), draw);
                        } else {
                            draw(ui);
                        }
                    });
                }
                let response = row.response();
                if response.clicked() {
                    clicked = Some(index);
                }
                if response.double_clicked() {
                    out.activated = Some(index);
                }
                response.context_menu(|ui| {
                    *selected = Some(index);
                    menu(ui, index);
                });
            });
        });
    if let Some(column) = sort_clicked {
        sort.click(column);
        out.sort_changed = true;
    }
    if let Some(row) = clicked {
        *selected = Some(row);
        out.clicked = Some(row);
        ui.memory_mut(|memory| memory.request_focus(focus_id));
    }
    if has_focus {
        ui.memory_mut(|memory| {
            memory.set_focus_lock_filter(focus_id, egui::EventFilter { vertical_arrows: true, ..Default::default() })
        });
    }
    out
}

/// A thin footer line under a table: caption text, top border.
pub fn footer(ui: &mut Ui, theme: &Theme, text: &str) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), FOOTER), Sense::hover());
    ui.painter().hline(rect.x_range(), rect.top(), egui::Stroke::new(1.0, theme.border));
    ui.painter().text(
        rect.left_center() + egui::vec2(space::SM, 0.0),
        egui::Align2::LEFT_CENTER,
        text,
        font(Type::Caption),
        theme.text_faint,
    );
}

/// Height [`footer`] takes; reserve it before laying out the table.
pub const FOOTER: f32 = 22.0;

/// Lays a table out in the space above a [`footer`].
pub fn with_footer<R>(ui: &mut Ui, theme: &Theme, footer_text: &str, table: impl FnOnce(&mut Ui) -> R) -> R {
    let height = (ui.available_height() - FOOTER).max(0.0);
    let width = ui.available_width();
    let result = ui.allocate_ui(egui::vec2(width, height), table).inner;
    footer(ui, theme, footer_text);
    result
}
