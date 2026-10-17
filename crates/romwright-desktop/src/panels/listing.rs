//! Disassembly listing (Qt `ListingCanvas` + `MainWindow::loadListingAt`): a
//! painted, virtualised view over one `Core::listing_window` of rows. The
//! cursor is the navigation address; moving past the loaded window fetches
//! a new one around it.

use crate::address;
use crate::code::{self, CodePainter};
use crate::panel::{Change, Command, Panel, PanelContext, PanelId, Placement, ShellEvent};
use crate::service::{Task, poll_slot};
use crate::theme::{Syntax, Type, code_bold, font, metrics, space};
use crate::widgets;
use egui::{CornerRadius, Key, Rect, Sense, Stroke, pos2, vec2};
use romwright_model::{Address, FunctionRow, ListingRow, ListingRowKind, ListingWindow};

pub const ID: PanelId = "listing";
const WINDOW_ROWS: u32 = 128;
const MARGIN: f32 = space::SM;
const XREFS_PANEL: PanelId = "xrefs";

fn selectable(row: &ListingRow) -> bool {
    matches!(row.kind, ListingRowKind::Instruction | ListingRowKind::Data | ListingRowKind::Label)
}

pub struct ListingPanel {
    rows: Vec<ListingRow>,
    spans: Vec<Vec<code::Span>>,
    cursor: Option<usize>,
    first_visible: usize,
    requested: Option<Address>,
    empty_message: String,
    bytes_visible: bool,
    address_columns: usize,
    byte_columns: usize,
    content_width: f32,
    scroll_x: f32,
    set_scroll_x: Option<f32>,
    heading: String,
    load: Option<(u64, Address, Task<ListingWindow>)>,
    generation: u64,
    occurrence_click: Option<String>,
    loaded: u64,
    pending_reveal: bool,
}

impl Default for ListingPanel {
    fn default() -> Self {
        Self {
            rows: Vec::new(),
            spans: Vec::new(),
            cursor: None,
            first_visible: 0,
            requested: None,
            empty_message: "No listing loaded".into(),
            bytes_visible: true,
            address_columns: 10,
            byte_columns: 0,
            content_width: 0.0,
            scroll_x: 0.0,
            set_scroll_x: None,
            heading: "DISASSEMBLY".into(),
            load: None,
            generation: 0,
            occurrence_click: None,
            loaded: 0,
            pending_reveal: false,
        }
    }
}

impl ListingPanel {
    /// Count of windows installed (gate: the listing answered).
    pub fn windows_loaded(&self) -> u64 {
        self.loaded
    }

    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    pub fn cursor_address(&self) -> Option<&Address> {
        self.cursor.map(|index| &self.rows[index].address)
    }

    fn set_window(&mut self, rows: Vec<ListingRow>, empty_message: String) {
        self.empty_message = if rows.is_empty() { empty_message } else { String::new() };
        self.cursor = None;
        self.first_visible = 0;
        self.address_columns = rows.iter().map(|row| address::format(&row.address).len()).max().unwrap_or(0).max(10);
        self.byte_columns = rows.iter().map(|row| row.bytes.len()).max().unwrap_or(0);
        self.spans = rows
            .iter()
            .map(|row| match row.kind {
                ListingRowKind::Instruction => code::highlight_instruction(&row.text),
                _ => Vec::new(),
            })
            .collect();
        self.rows = rows;
        self.content_width = 0.0;
    }

    fn clear(&mut self) {
        self.requested = None;
        self.load = None;
        self.generation += 1;
        self.set_window(Vec::new(), "No listing loaded".into());
    }

    /// Highlights the row at `address`, or asks for a window around it.
    pub fn set_address(&mut self, cx: &PanelContext<'_>, address: &Address) {
        for pass in 0..2 {
            if let Some(index) = self.rows.iter().position(|row| {
                &row.address == address && (pass == 1 || row.kind == ListingRowKind::Instruction)
            }) {
                self.cursor = Some(index);
                self.requested = None;
                self.pending_reveal = true;
                return;
            }
        }
        self.cursor = None;
        if self.requested.as_ref() != Some(address) {
            self.requested = Some(address.clone());
            self.load_at(cx, address.clone());
        }
    }

    pub fn load_at(&mut self, cx: &PanelContext<'_>, start: Address) {
        self.generation += 1;
        let binary = cx.session.binary.clone();
        if binary.as_os_str().is_empty() {
            return;
        }
        self.set_window(Vec::new(), format!("Loading listing at {}…", address::format(&start)));
        let label = format!("listing {}", address::format(&start));
        let task_start = start.clone();
        let task = cx.service.job(label, move |job| {
            let core = job.fork()?;
            let window = core
                .listing_window(&binary, &task_start, WINDOW_ROWS, 0.25)
                .map_err(|error| error.to_string())?;
            job.detail(format!("{} rows", window.rows.len()));
            Ok(window)
        });
        self.load = Some((self.generation, start, task));
    }

    fn function_changed(&mut self, function: Option<&FunctionRow>, cursor: &Address) {
        self.heading = match function {
            Some(function) => {
                let mut name = function.name.clone();
                if function.entry.space == cursor.space && cursor.offset > function.entry.offset {
                    name.push_str(&format!("+0x{:x}", cursor.offset - function.entry.offset));
                }
                format!("DISASSEMBLY  ·  {name}")
            }
            None => format!("DISASSEMBLY  ·  {}", address::format(cursor)),
        };
        if let Some(function) = function {
            for row in &mut self.rows {
                if row.kind == ListingRowKind::FunctionHeader && row.address == function.entry {
                    row.text = function.name.clone();
                }
            }
        }
    }

    fn move_cursor(&mut self, cx: &mut PanelContext<'_>, delta: isize, record: bool, visible: usize) {
        if self.rows.is_empty() || delta == 0 {
            return;
        }
        let direction = delta.signum();
        let mut target: isize = match self.cursor {
            Some(cursor) => cursor as isize,
            None if direction > 0 => -1,
            None => self.rows.len() as isize,
        };
        for _ in 0..delta.unsigned_abs() {
            let mut next = target;
            loop {
                next += direction;
                if next < 0 || next >= self.rows.len() as isize || selectable(&self.rows[next as usize]) {
                    break;
                }
            }
            if next < 0 || next >= self.rows.len() as isize {
                break;
            }
            target = next;
        }
        if target < 0 || target >= self.rows.len() as isize || Some(target as usize) == self.cursor {
            return;
        }
        let index = target as usize;
        self.cursor = Some(index);
        self.pending_reveal = true;
        cx.navigate(self.rows[index].address.clone(), record);
        // Refill forward; moving up keeps the rows above the cursor.
        if self.rows.len() > visible && index > self.rows.len() - visible {
            let start = self.rows[index].address.clone();
            self.load_at(cx, start);
        }
    }

    fn header(&mut self, ui: &mut egui::Ui, cx: &mut PanelContext<'_>) {
        let theme = cx.theme;
        let mut reload = false;
        let mut xrefs = false;
        let show_xrefs = cx.has_panel(XREFS_PANEL);
        widgets::panel_header(ui, theme, &self.heading, |ui| {
            if show_xrefs && widgets::chip(ui, theme, "Xrefs", false).on_hover_text("Show references to the cursor").clicked() {
                xrefs = true;
            }
            if widgets::chip(ui, theme, "Reload", false).on_hover_text("Reload the listing at the cursor").clicked() {
                reload = true;
            }
            if widgets::chip(ui, theme, "Bytes", self.bytes_visible)
                .on_hover_text("Show instruction bytes beside the assembly")
                .clicked()
            {
                self.bytes_visible = !self.bytes_visible;
                self.content_width = 0.0;
            }
        });
        if reload && let Some(address) = cx.session.address.clone() {
            self.load_at(cx, address);
        }
        if xrefs && let Some(address) = cx.session.address.clone() {
            cx.command(Command::Broadcast(ShellEvent::XrefsRequested(address)));
            cx.command(Command::Raise(XREFS_PANEL));
        }
    }

    fn text_start(&self, char_width: f32) -> f32 {
        let gutter = MARGIN + self.address_columns as f32 * char_width + space::LG;
        if self.bytes_visible {
            gutter + (self.byte_columns as f32 + 2.0) * char_width
        } else {
            gutter
        }
    }

    fn canvas(&mut self, ui: &mut egui::Ui, cx: &mut PanelContext<'_>) {
        let theme = cx.theme;
        let code_font = font(Type::Code);
        let char_width = ui.fonts_mut(|fonts| fonts.glyph_width(&code_font, '0'));
        let row_height = metrics::CODE_ROW;
        let viewport = ui.available_rect_before_wrap();
        let visible = (((viewport.height() - 2.0 * MARGIN) / row_height).floor().max(0.0)) as usize;
        let text_start = self.text_start(char_width);
        if self.content_width == 0.0 {
            self.content_width = self
                .rows
                .iter()
                .map(|row| text_start + row.text.chars().count() as f32 * char_width + 4.0 * char_width)
                .fold(0.0, f32::max)
                + MARGIN;
        }
        let id = ui.id().with("listing-canvas");
        let mut scroll = egui::ScrollArea::horizontal().id_salt("listing-h").auto_shrink([false, false]);
        if let Some(offset) = self.set_scroll_x.take() {
            scroll = scroll.horizontal_scroll_offset(offset);
        }
        let mut clicked_row = None;
        let mut double_clicked = None;
        let mut context_row = None;
        let mut hover_word = None;
        let output = scroll.show(ui, |ui| {
            let width = self.content_width.max(viewport.width());
            let (rect, _) = ui.allocate_exact_size(vec2(width, viewport.height()), Sense::hover());
            let response = ui.interact(rect, id, Sense::click());
            let painter = ui.painter_at(ui.clip_rect());
            // Gutter.
            let gutter_right = rect.left() + MARGIN + self.address_columns as f32 * char_width + space::SM;
            painter.rect_filled(Rect::from_min_max(rect.min, pos2(gutter_right, rect.bottom())), CornerRadius::ZERO, theme.bg_raised);
            painter.vline(gutter_right, rect.y_range(), Stroke::new(1.0, theme.border));
            if self.pending_reveal {
                self.reveal(visible);
            }
            let pointer = response.hover_pos();
            let row_at = |y: f32| -> Option<usize> {
                let local = y - rect.top() - MARGIN;
                (local >= 0.0).then(|| self.first_visible + (local / row_height) as usize)
            };
            if let Some(pos) = pointer
                && let Some(index) = row_at(pos.y).filter(|index| *index < self.rows.len())
                && pos.x >= rect.left() + text_start
            {
                let column = ((pos.x - rect.left() - text_start) / char_width) as usize;
                hover_word = code::word_at(&self.rows[index].text, column).map(|range| self.rows[index].text[range].to_string());
            }
            let occurrence = hover_word.clone().or_else(|| self.occurrence_click.clone());
            let code_painter = CodePainter {
                painter: &painter,
                theme,
                font: code_font.clone(),
                char_width,
                row_height,
                occurrence: occurrence.as_deref(),
            };
            let clip = ui.clip_rect();
            let mut y = rect.top() + MARGIN;
            for index in self.first_visible..self.rows.len().min(self.first_visible + visible) {
                let row = &self.rows[index];
                let line = Rect::from_min_size(pos2(clip.left(), y), vec2(clip.width(), row_height));
                if Some(index) == self.cursor {
                    painter.rect_filled(line, CornerRadius::ZERO, theme.current_line);
                    painter.rect_filled(Rect::from_min_size(line.min, vec2(2.0, row_height)), CornerRadius::ZERO, theme.accent);
                } else if pointer.is_some_and(|pos| line.contains(pos)) && selectable(row) {
                    painter.rect_filled(line, CornerRadius::ZERO, theme.bg_stripe);
                }
                let left = rect.left() + MARGIN;
                match row.kind {
                    ListingRowKind::FunctionHeader => {
                        if index > self.first_visible {
                            painter.hline(rect.x_range(), y + 1.0, Stroke::new(1.0, theme.border));
                        }
                        painter.text(
                            pos2(left, y + row_height / 2.0),
                            egui::Align2::LEFT_CENTER,
                            &row.text,
                            code_bold(),
                            theme.syntax_function,
                        );
                        let name_width = row.text.chars().count() as f32 * char_width;
                        code_painter.text(pos2(left + name_width + char_width, y), &format!("@ {}", address::format(&row.address)), Syntax::Dim);
                    }
                    ListingRowKind::BbSeparator => {
                        let mid = y + row_height / 2.0;
                        let label = format!("block {}", address::format(&row.address));
                        let label_x = rect.left() + text_start;
                        let label_rect = painter.text(pos2(label_x, mid), egui::Align2::LEFT_CENTER, &label, font(Type::Caption), theme.text_faint);
                        painter.hline((label_rect.right() + space::SM)..=clip.right(), mid, Stroke::new(1.0, theme.border));
                    }
                    _ => {
                        let text_x = rect.left() + text_start;
                        let address_text = address::format(&row.address);
                        let address_x = left + (self.address_columns - address_text.len()) as f32 * char_width;
                        let address_color = if Some(index) == self.cursor { theme.syntax_address } else { theme.text_faint };
                        code_painter.text_colored(pos2(address_x, y), &address_text, address_color);
                        if self.bytes_visible {
                            code_painter.text(pos2(left + self.address_columns as f32 * char_width + space::LG, y), &row.bytes, Syntax::Dim);
                        }
                        match row.kind {
                            ListingRowKind::Label => code_painter.text(pos2(text_x, y), &format!("{}:", row.text), Syntax::Label),
                            ListingRowKind::Data => code_painter.text(pos2(text_x, y), &row.text, Syntax::Constant),
                            _ => code_painter.spans(pos2(text_x, y), &row.text, &self.spans[index]),
                        }
                    }
                }
                y += row_height;
            }
            if response.clicked() || response.double_clicked() || response.secondary_clicked() {
                response.request_focus();
            }
            if let Some(pos) = response.interact_pointer_pos() {
                let index = row_at(pos.y).filter(|index| *index < self.rows.len());
                if response.double_clicked() {
                    double_clicked = index.zip(Some(pos.x - rect.left()));
                } else if response.clicked() {
                    clicked_row = index;
                } else if response.secondary_clicked() {
                    context_row = index;
                }
            }
            response
        });
        self.scroll_x = output.state.offset.x;
        let response = output.inner;
        // Keyboard: Qt ListingCanvas bindings.
        if response.has_focus() {
            let page = visible.saturating_sub(1).max(1) as isize;
            let len = self.rows.len() as isize;
            let keys = ui.input(|input| {
                [
                    (Key::ArrowUp, -1),
                    (Key::ArrowDown, 1),
                    (Key::PageUp, -page),
                    (Key::PageDown, page),
                    (Key::Home, -len),
                    (Key::End, len),
                ]
                .into_iter()
                .filter(|(key, _)| input.key_pressed(*key))
                .map(|(_, delta)| delta)
                .collect::<Vec<_>>()
            });
            for delta in keys {
                self.move_cursor(cx, delta, true, visible);
            }
            let (left, right, escape, back, forward) = ui.input(|input| {
                (
                    input.key_pressed(Key::ArrowLeft),
                    input.key_pressed(Key::ArrowRight),
                    input.key_pressed(Key::Escape),
                    input.modifiers.command && input.key_pressed(Key::OpenBracket),
                    input.modifiers.command && input.key_pressed(Key::CloseBracket),
                )
            });
            if left {
                self.set_scroll_x = Some((self.scroll_x - 3.0 * char_width).max(0.0));
            }
            if right {
                self.set_scroll_x = Some(self.scroll_x + 3.0 * char_width);
            }
            if escape || back {
                cx.command(Command::Back);
            }
            if forward {
                cx.command(Command::Forward);
            }
            ui.memory_mut(|memory| {
                memory.set_focus_lock_filter(response.id, egui::EventFilter { vertical_arrows: true, horizontal_arrows: true, escape: true, tab: false })
            });
        }
        // Wheel moves the cursor three rows without recording history.
        if response.hovered() {
            let (notches, shift) = ui.input(|input| {
                let notches: f32 = input
                    .raw
                    .events
                    .iter()
                    .filter_map(|event| match event {
                        egui::Event::MouseWheel { delta, .. } => Some(delta.y),
                        _ => None,
                    })
                    .sum();
                (notches, input.modifiers.shift)
            });
            if notches != 0.0 && !shift {
                self.move_cursor(cx, if notches > 0.0 { -3 } else { 3 }, false, visible);
            }
        }
        if let Some(index) = clicked_row {
            if selectable(&self.rows[index]) {
                self.cursor = Some(index);
                cx.navigate(self.rows[index].address.clone(), true);
            }
            self.occurrence_click = hover_word.clone();
        }
        if let Some((index, x)) = double_clicked {
            // Follow a hexadecimal operand; registers never read as addresses.
            let text_start = self.text_start(char_width);
            if x >= text_start {
                let column = ((x - text_start) / char_width) as usize;
                let text = &self.rows[index].text;
                if let Some(range) = code::word_at(text, column)
                    && text[range.clone()].starts_with("0x")
                    && let Some(target) = address::parse(&text[range])
                {
                    cx.navigate(target, true);
                }
            }
        }
        if let Some(index) = context_row {
            self.cursor = Some(index);
        }
        let cursor_address = self.cursor.map(|index| self.rows[index].address.clone());
        if let Some(address) = cursor_address {
            let show_xrefs = cx.has_panel(XREFS_PANEL);
            let mut commands = Vec::new();
            response.context_menu(|ui| {
                if ui.button("Rename function…").clicked() {
                    commands.push(Command::RenameFunction { address: address.clone(), name: None });
                    ui.close();
                }
                if show_xrefs && ui.button("Show xrefs").clicked() {
                    commands.push(Command::Broadcast(ShellEvent::XrefsRequested(address.clone())));
                    commands.push(Command::Raise(XREFS_PANEL));
                    ui.close();
                }
                if ui.button("Decompile here").clicked() {
                    commands.push(Command::Navigate { address: address.clone(), record: true });
                    ui.close();
                }
            });
            for command in commands {
                cx.command(command);
            }
        }
    }

    fn reveal(&mut self, visible: usize) {
        self.pending_reveal = false;
        let Some(cursor) = self.cursor else { return };
        if cursor < self.first_visible {
            self.first_visible = cursor;
        } else if visible > 0 && cursor >= self.first_visible + visible {
            self.first_visible = cursor + 1 - visible;
        }
    }
}

impl Panel for ListingPanel {
    fn id(&self) -> PanelId {
        ID
    }

    fn title(&self) -> String {
        "Listing".into()
    }

    fn placement(&self) -> Placement {
        Placement::Center
    }

    fn on_event(&mut self, event: &ShellEvent, cx: &mut PanelContext<'_>) {
        match event {
            ShellEvent::ProgramChanged | ShellEvent::Refresh => {
                self.clear();
                self.heading = "DISASSEMBLY".into();
                if let Some(address) = cx.session.address.clone() {
                    self.set_address(cx, &address);
                }
            }
            ShellEvent::AddressChanged { address, .. } => self.set_address(cx, address),
            ShellEvent::FunctionChanged { function, cursor } => self.function_changed(function.as_ref(), cursor),
            ShellEvent::RevisionChanged(Change::Comment | Change::Undo) => {
                if let Some(address) = cx.session.address.clone() {
                    self.load_at(cx, address);
                }
            }
            _ => {}
        }
    }

    fn poll(&mut self, cx: &mut PanelContext<'_>) {
        let Some((generation, start, _)) = &self.load else { return };
        let (generation, start) = (*generation, start.clone());
        let mut slot = self.load.take().map(|(_, _, task)| task);
        match poll_slot(&mut slot) {
            None => self.load = slot.map(|task| (generation, start, task)),
            Some(_) if generation != self.generation => {}
            Some(Err(error)) => {
                self.set_window(Vec::new(), format!("Listing failed at {}:\n{error}", address::format(&start)));
            }
            Some(Ok(window)) => {
                self.set_window(window.rows, format!("No instructions at {}", address::format(&start)));
                self.loaded += 1;
                if let Some(address) = cx.session.address.clone() {
                    self.requested = Some(address.clone());
                    self.set_address(cx, &address);
                } else {
                    self.set_address(cx, &start);
                }
            }
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, cx: &mut PanelContext<'_>) {
        self.header(ui, cx);
        let theme = cx.theme;
        let canvas = ui.available_rect_before_wrap();
        ui.painter().rect_filled(canvas, CornerRadius::ZERO, theme.bg_code);
        if self.rows.is_empty() {
            if self.load.is_some() {
                widgets::loading(ui, theme, &self.empty_message);
            } else if cx.session.program.is_empty() {
                widgets::empty_state(ui, theme, "No program open", "Choose an image in the toolbar to see its disassembly.");
            } else {
                let (title, detail) = self.empty_message.split_once('\n').unwrap_or((&self.empty_message, ""));
                widgets::empty_state(ui, theme, title, detail);
            }
            return;
        }
        self.canvas(ui, cx);
    }

    fn busy(&self) -> bool {
        self.load.is_some()
    }
}
