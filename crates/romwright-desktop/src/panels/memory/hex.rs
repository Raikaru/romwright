//! Hex canvas (Qt `HexCanvas`): a painted view over one fetched window of
//! bytes, sixteen per row with offset, hex and ASCII columns. The cursor byte
//! is the navigation address; little-endian qwords that point into a mapped
//! region are drawn as links and follow on click.

use crate::theme::{Syntax, Theme, Type, font, metrics, space};
use egui::{Align2, CornerRadius, Key, Pos2, Rect, Sense, Stroke, pos2, vec2};
use romwright_model::MemoryRegion;
use std::ops::Range;

pub const BYTES_PER_ROW: u64 = 16;
const MARGIN: f32 = space::SM;

/// One fetched window: rows start at `base` (16-aligned); `bytes` cover
/// `data` (a sub-range when the window straddles a region edge).
#[derive(Default)]
pub struct HexWindow {
    pub base: u64,
    pub data: Range<u64>,
    pub bytes: Vec<u8>,
    pub live: bool,
}

impl HexWindow {
    fn rows(&self) -> u64 {
        self.data.end.saturating_sub(self.base).div_ceil(BYTES_PER_ROW)
    }

    fn byte(&self, address: u64) -> Option<u8> {
        self.data.contains(&address).then(|| self.bytes[(address - self.data.start) as usize])
    }

    pub fn contains(&self, address: u64) -> bool {
        self.data.contains(&address)
    }
}

/// What the canvas asks of its panel.
pub enum HexAction {
    Navigate { address: u64, record: bool },
    /// The view scrolled to the window edge: fetch around `address`.
    Window(u64),
}

#[derive(Default)]
pub struct HexView {
    pub window: HexWindow,
    pub cursor: Option<u64>,
    first_row: u64,
    reveal: bool,
    /// Address to keep mid-view after a scroll-driven window fetch.
    anchor: Option<u64>,
}

/// The qword starting at `address` when it lands inside a region.
fn pointer(window: &HexWindow, regions: &[MemoryRegion], address: u64) -> Option<u64> {
    let mut value = 0u64;
    for index in (0..8).rev() {
        value = value << 8 | u64::from(window.byte(address + index)?);
    }
    regions
        .iter()
        .any(|region| value >= region.start.offset && value - region.start.offset < region.size)
        .then_some(value)
}

impl HexView {
    /// Installs a window; with `anchor` the view keeps that address in the
    /// middle (scrolling), otherwise it reveals the cursor.
    pub fn set_window(&mut self, window: HexWindow, anchor: Option<u64>) {
        self.window = window;
        self.first_row = 0;
        self.reveal = anchor.is_none();
        self.anchor = anchor;
    }

    pub fn clear(&mut self) {
        self.set_window(HexWindow::default(), None);
    }

    /// Moves the cursor; `false` when the address is outside the window.
    pub fn set_cursor(&mut self, address: Option<u64>) -> bool {
        self.cursor = address;
        self.reveal = true;
        address.is_none_or(|address| self.window.contains(address))
    }

    fn row_of(&self, address: u64) -> u64 {
        (address - self.window.base) / BYTES_PER_ROW
    }

    pub fn show(&mut self, ui: &mut egui::Ui, theme: &Theme, regions: &[MemoryRegion]) -> Option<HexAction> {
        let rect = ui.available_rect_before_wrap();
        ui.allocate_rect(rect, Sense::hover());
        let response = ui.interact(rect, ui.id().with("hex-canvas"), Sense::click());
        let painter = ui.painter_at(rect);
        painter.rect_filled(rect, CornerRadius::ZERO, theme.bg_code);
        let code = font(Type::Code);
        let char_width = ui.fonts_mut(|fonts| fonts.glyph_width(&code, '0'));
        let row_height = metrics::CODE_ROW;
        let rows = self.window.rows();
        let header_height = row_height;
        let visible = (((rect.height() - header_height - 2.0 * MARGIN) / row_height).floor().max(1.0)) as u64;
        let max_first = rows.saturating_sub(visible);
        if let Some(anchor) = self.anchor.take().filter(|anchor| self.window.contains(*anchor)) {
            self.reveal = false;
            self.first_row = self.row_of(anchor).saturating_sub(visible / 2);
        } else if self.reveal {
            self.reveal = false;
            if let Some(cursor) = self.cursor.filter(|cursor| self.window.contains(*cursor)) {
                let row = self.row_of(cursor);
                if row < self.first_row || row >= self.first_row + visible {
                    self.first_row = row.saturating_sub(visible / 3);
                }
            }
        }
        let mut action = None;

        // Wheel scrolls three rows; at the window edge it asks for more.
        if response.hovered() {
            let notches: f32 = ui.input(|input| {
                input
                    .raw
                    .events
                    .iter()
                    .filter_map(|event| match event {
                        egui::Event::MouseWheel { unit, delta, .. } => Some(match unit {
                            egui::MouseWheelUnit::Line => delta.y,
                            _ => delta.y / metrics::CODE_ROW,
                        }),
                        _ => None,
                    })
                    .sum()
            });
            if notches != 0.0 {
                let delta = (-notches * 3.0).round() as i64;
                let target = self.first_row as i64 + delta;
                if target < 0 && self.window.base > 0 && rows > 0 {
                    action = Some(HexAction::Window(self.window.base));
                } else if target > max_first as i64 && rows > 0 {
                    action = Some(HexAction::Window(self.window.data.end));
                }
                self.first_row = target.clamp(0, max_first as i64) as u64;
            }
        }
        self.first_row = self.first_row.min(max_first);

        // Columns.
        let digits = format!("{:x}", self.window.data.end.max(1)).len().max(8);
        let offset_x = rect.left() + MARGIN;
        let gutter_right = offset_x + (digits + 2) as f32 * char_width + space::SM;
        let hex_x = gutter_right + space::MD;
        let column_x = |column: u64| hex_x + (column * 3 + u64::from(column >= 8)) as f32 * char_width;
        let ascii_x = column_x(BYTES_PER_ROW) + space::LG;
        let top = rect.top() + MARGIN + header_height;

        painter.rect_filled(Rect::from_min_max(rect.min, pos2(gutter_right, rect.bottom())), CornerRadius::ZERO, theme.bg_raised);
        painter.vline(gutter_right, rect.y_range(), Stroke::new(1.0, theme.border));
        // Column header.
        let header_y = rect.top() + MARGIN + header_height / 2.0;
        let caption = font(Type::Caption);
        painter.text(pos2(offset_x, header_y), Align2::LEFT_CENTER, "Offset", caption.clone(), theme.text_faint);
        for column in 0..BYTES_PER_ROW {
            painter.text(pos2(column_x(column), header_y), Align2::LEFT_CENTER, format!("{column:02x}"), font(Type::CodeSmall), theme.text_faint);
        }
        painter.text(pos2(ascii_x, header_y), Align2::LEFT_CENTER, "ASCII", caption.clone(), theme.text_faint);
        let source = if self.window.live { "LIVE" } else { "FILE" };
        let badge = painter.layout_no_wrap(source.into(), caption, if self.window.live { theme.on_accent } else { theme.text_muted });
        let badge_rect = Rect::from_min_size(
            pos2(rect.right() - MARGIN - badge.size().x - 2.0 * space::SM, header_y - badge.size().y / 2.0 - space::XXS),
            badge.size() + vec2(2.0 * space::SM, 2.0 * space::XXS),
        );
        painter.rect(
            badge_rect,
            CornerRadius::same(metrics::RADIUS_SM),
            if self.window.live { theme.accent } else { theme.bg_raised },
            Stroke::new(1.0, if self.window.live { theme.accent } else { theme.border }),
            egui::StrokeKind::Inside,
        );
        painter.galley(badge_rect.min + vec2(space::SM, space::XXS), badge, theme.text_muted);
        painter.hline(rect.x_range(), top - space::XS, Stroke::new(1.0, theme.border));

        // Hit testing.
        let hit = |pos: Pos2| -> Option<u64> {
            if pos.y < top {
                return None;
            }
            let row = self.first_row + ((pos.y - top) / row_height) as u64;
            if row >= rows {
                return None;
            }
            let column = (0..BYTES_PER_ROW).find(|&column| {
                let x = column_x(column);
                pos.x >= x - char_width / 2.0 && pos.x < x + 2.5 * char_width
            });
            let column = column.or_else(|| {
                let local = pos.x - ascii_x;
                (local >= 0.0 && local < BYTES_PER_ROW as f32 * char_width).then(|| (local / char_width) as u64)
            });
            let address = self.window.base + row * BYTES_PER_ROW + column.unwrap_or(0);
            self.window.contains(address).then_some(address)
        };
        let hover = response.hover_pos().and_then(hit);
        let pointer_at = |address: u64| {
            let qword = address - (address - self.window.base) % 8;
            pointer(&self.window, regions, qword)
        };
        if let Some(address) = hover
            && let Some(target) = pointer_at(address)
        {
            response.clone().on_hover_text(format!("Pointer to 0x{target:x}: click to follow"));
        }

        // Rows.
        let code_small = font(Type::CodeSmall);
        let mut ascii = String::with_capacity(BYTES_PER_ROW as usize);
        for row in self.first_row..rows.min(self.first_row + visible) {
            let y = top + (row - self.first_row) as f32 * row_height;
            let line = Rect::from_min_size(pos2(rect.left(), y), vec2(rect.width(), row_height));
            let row_start = self.window.base + row * BYTES_PER_ROW;
            let cursor_row = self.cursor.is_some_and(|cursor| cursor >= row_start && cursor < row_start + BYTES_PER_ROW);
            if cursor_row {
                painter.rect_filled(line, CornerRadius::ZERO, theme.current_line);
                painter.rect_filled(Rect::from_min_size(line.min, vec2(2.0, row_height)), CornerRadius::ZERO, theme.accent);
            } else if hover.is_some_and(|address| address >= row_start && address < row_start + BYTES_PER_ROW) {
                painter.rect_filled(line, CornerRadius::ZERO, theme.bg_stripe);
            }
            let mid = y + row_height / 2.0;
            painter.text(
                pos2(offset_x, mid),
                Align2::LEFT_CENTER,
                format!("0x{row_start:0digits$x}"),
                code.clone(),
                if cursor_row { theme.syntax_address } else { theme.text_faint },
            );
            ascii.clear();
            let mut column = 0;
            while column < BYTES_PER_ROW {
                let address = row_start + column;
                let Some(byte) = self.window.byte(address) else {
                    ascii.push(' ');
                    column += 1;
                    continue;
                };
                if column % 8 == 0
                    && let Some(_target) = pointer(&self.window, regions, address)
                {
                    // A pointer qword: one link spanning eight bytes.
                    let start = column_x(column) - char_width / 2.0;
                    let end = column_x(column + 7) + 2.5 * char_width;
                    let link = Rect::from_min_max(pos2(start, y + 2.0), pos2(end, y + row_height - 2.0));
                    let hovered = hover.is_some_and(|hovered| hovered >= address && hovered < address + 8);
                    painter.rect_filled(link, CornerRadius::same(metrics::RADIUS_SM), if hovered { theme.accent_soft } else { theme.bg_stripe });
                    for offset in 0..8 {
                        let value = self.window.byte(address + offset).unwrap_or(0);
                        painter.text(pos2(column_x(column + offset), mid), Align2::LEFT_CENTER, format!("{value:02x}"), code.clone(), theme.syntax_function);
                        ascii.push(printable(value));
                    }
                    painter.hline(start + char_width / 2.0..=end - char_width / 2.0, y + row_height - 3.0, Stroke::new(1.0, theme.syntax_function.gamma_multiply(0.6)));
                    column += 8;
                    continue;
                }
                let color = match byte {
                    0 => theme.syntax(Syntax::Dim),
                    0x20..0x7f => theme.syntax(Syntax::String),
                    0xff => theme.syntax(Syntax::Constant),
                    _ => theme.syntax(Syntax::Plain),
                };
                painter.text(pos2(column_x(column), mid), Align2::LEFT_CENTER, format!("{byte:02x}"), code.clone(), color);
                ascii.push(printable(byte));
                column += 1;
            }
            // Cursor byte: boxed in both columns.
            if cursor_row && let Some(cursor) = self.cursor.filter(|cursor| self.window.contains(*cursor)) {
                let column = cursor - row_start;
                let cell = Rect::from_min_size(pos2(column_x(column) - char_width / 2.0, y + 1.0), vec2(3.0 * char_width, row_height - 2.0));
                painter.rect(cell, CornerRadius::same(metrics::RADIUS_SM), theme.accent_soft, Stroke::new(1.0, theme.accent), egui::StrokeKind::Inside);
                let ascii_cell = Rect::from_min_size(pos2(ascii_x + column as f32 * char_width, y + 1.0), vec2(char_width, row_height - 2.0));
                painter.rect(ascii_cell, CornerRadius::ZERO, theme.accent_soft, Stroke::new(1.0, theme.accent), egui::StrokeKind::Inside);
            }
            painter.text(pos2(ascii_x, mid), Align2::LEFT_CENTER, &ascii, code_small.clone(), theme.text_muted);
        }

        // Clicks: pointers follow, any other byte becomes the cursor.
        if response.clicked() {
            response.request_focus();
            if let Some(address) = response.interact_pointer_pos().and_then(hit) {
                let target = pointer_at(address).unwrap_or(address);
                self.cursor = Some(address);
                action = Some(HexAction::Navigate { address: target, record: true });
            }
        }
        // Keyboard: arrows move by byte / row, pages by screen.
        if response.has_focus()
            && let Some(cursor) = self.cursor
        {
            let page = (visible.saturating_sub(1).max(1) * BYTES_PER_ROW) as i64;
            let row = BYTES_PER_ROW as i64;
            let delta: i64 = ui.input(|input| {
                [(Key::ArrowLeft, -1), (Key::ArrowRight, 1), (Key::ArrowUp, -row), (Key::ArrowDown, row), (Key::PageUp, -page), (Key::PageDown, page)]
                    .into_iter()
                    .filter(|(key, _)| input.key_pressed(*key))
                    .map(|(_, delta)| delta)
                    .sum()
            });
            if delta != 0 {
                let target = cursor.saturating_add_signed(delta);
                self.cursor = Some(target);
                self.reveal = true;
                action = Some(HexAction::Navigate { address: target, record: true });
            }
            ui.memory_mut(|memory| {
                memory.set_focus_lock_filter(response.id, egui::EventFilter { vertical_arrows: true, horizontal_arrows: true, escape: false, tab: false })
            });
        }
        action
    }
}

fn printable(byte: u8) -> char {
    if (0x20..0x7f).contains(&byte) { byte as char } else { '·' }
}
