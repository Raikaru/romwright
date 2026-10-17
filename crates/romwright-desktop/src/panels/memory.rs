//! Memory map and hex view (Qt `MemoryDock` + `HexCanvas`): the program's
//! `Core::memory_regions` beside a hex window read from the captured binary
//! (`Core::mem_native`) or a live target (`Core::read_memory_live`, Dolphin's
//! GDB stub). Nothing is fetched until the tab is shown; the hex cursor is
//! the navigation address.

mod hex;

use crate::address;
use crate::panel::{Panel, PanelContext, PanelId, ShellEvent};
use crate::service::{Task, poll_slot};
use crate::table::{self, Cell, Column, Sort, Width};
use crate::theme::{Type, font, metrics};
use crate::widgets;
use egui::{Align, CornerRadius, Layout, Sense, Stroke, pos2};
use hex::{BYTES_PER_ROW, HexAction, HexView, HexWindow};
use romwright_model::{Address, AddressSpace, MemoryRegion};

pub const ID: PanelId = "memory";
/// Bytes per fetched window (Qt requested 4096).
const WINDOW: u64 = 4096;
/// Bytes kept before the target so the view can scroll up.
const LEAD: u64 = 1024;
const DEFAULT_ENDPOINT: &str = "127.0.0.1:24689";
const COLUMNS: [Column; 5] = [
    Column::new("Name", Width::Initial(120.0)),
    Column::address("Start"),
    Column::new("Size", Width::Initial(84.0)).right(),
    Column::new("Perms", Width::Initial(52.0)),
    Column::new("Source", Width::Remainder),
];
/// Side-by-side map and hex from this width; stacked below it.
const SPLIT_WIDTH: f32 = 980.0;

struct HexLoad {
    generation: u64,
    target: u64,
    scroll: bool,
    task: Task<HexWindow>,
}

pub struct MemoryPanel {
    regions: Vec<MemoryRegion>,
    sort: Sort,
    /// Row of the region holding the cursor (or the user's pick).
    selected: Option<usize>,
    regions_stale: bool,
    regions_load: Option<(u64, Task<Vec<MemoryRegion>>)>,
    regions_message: String,
    hex: HexView,
    /// Address whose window is wanted (fetched while the tab is visible).
    hex_target: Option<u64>,
    hex_load: Option<HexLoad>,
    /// A scroll fetch that failed (end of readable bytes): not retried.
    scroll_dead: Option<u64>,
    hex_message: String,
    live: bool,
    endpoint: String,
    generation: u64,
    hex_generation: u64,
}

impl Default for MemoryPanel {
    fn default() -> Self {
        Self {
            regions: Vec::new(),
            sort: Sort::by(1),
            selected: None,
            regions_stale: true,
            regions_load: None,
            regions_message: String::new(),
            hex: HexView::default(),
            hex_target: None,
            hex_load: None,
            scroll_dead: None,
            hex_message: String::new(),
            live: false,
            endpoint: DEFAULT_ENDPOINT.into(),
            generation: 0,
            hex_generation: 0,
        }
    }
}

fn ram(address: &Address) -> Option<u64> {
    (address.space == AddressSpace::Ram).then_some(address.offset)
}

fn region_end(region: &MemoryRegion) -> u64 {
    region.start.offset.saturating_add(region.size)
}

/// Reads the window around `target`. File reads try the full window, then
/// the part inside the region holding `target`, then from `target` itself
/// (a read across unmapped bytes fails); live reads are taken as asked.
fn read_window(
    core: &romwright_core::Core,
    binary: &std::path::Path,
    regions: &[MemoryRegion],
    target: u64,
    live: Option<&str>,
) -> Result<HexWindow, String> {
    let aligned = target - target % BYTES_PER_ROW;
    let start = aligned.saturating_sub(LEAD);
    let end = start.saturating_add(WINDOW);
    if let Some(endpoint) = live {
        let bytes = core.read_memory_live(endpoint, start, WINDOW as usize).map_err(|error| error.to_string())?;
        return Ok(HexWindow { base: start, data: start..start + bytes.len() as u64, bytes, live: true });
    }
    let mut attempts = vec![(start, end)];
    if let Some(region) = regions
        .iter()
        .find(|region| region.start.space == AddressSpace::Ram && target >= region.start.offset && target < region_end(region))
    {
        attempts.push((start.max(region.start.offset), end.min(region_end(region))));
        attempts.push((target, end.min(region_end(region))));
    }
    attempts.push((target, target.saturating_add(BYTES_PER_ROW)));
    let mut failure = String::new();
    for (low, high) in attempts {
        match core.mem_native(binary, low, (high - low) as usize) {
            Ok(bytes) => {
                return Ok(HexWindow { base: low - low % BYTES_PER_ROW, data: low..low + bytes.len() as u64, bytes, live: false });
            }
            Err(error) => failure = error.to_string(),
        }
    }
    Err(failure)
}

impl MemoryPanel {
    fn sort(&mut self) {
        table::sort_rows(&mut self.regions, self.sort, |a, b, column| match column {
            0 => table::text_order(&a.name, &b.name),
            2 => a.size.cmp(&b.size),
            3 => a.permissions.cmp(&b.permissions),
            4 => table::text_order(&a.source, &b.source),
            _ => table::address_order(&a.start, &b.start),
        });
        self.select_cursor_region();
    }

    fn select_cursor_region(&mut self) {
        let Some(cursor) = self.hex.cursor else { return };
        if let Some(row) = self
            .regions
            .iter()
            .position(|region| region.start.space == AddressSpace::Ram && cursor >= region.start.offset && cursor < region_end(region))
        {
            self.selected = Some(row);
        }
    }

    fn reset(&mut self, cx: &PanelContext<'_>) {
        self.generation += 1;
        self.hex_generation += 1;
        self.regions.clear();
        self.selected = None;
        self.regions_load = None;
        self.regions_stale = true;
        self.regions_message.clear();
        self.hex.clear();
        self.hex_load = None;
        self.hex_message.clear();
        self.hex.cursor = cx.session.address.as_ref().and_then(ram);
        self.hex_target = self.hex.cursor;
    }

    fn load_regions(&mut self, cx: &PanelContext<'_>) {
        self.regions_stale = false;
        let program = cx.session.program.clone();
        if program.is_empty() {
            return;
        }
        self.regions_message = "Loading the memory map…".into();
        let task = cx.service.request(move |core| core.memory_regions(&program).map_err(|error| error.to_string()));
        self.regions_load = Some((self.generation, task));
    }

    /// Fetches the window around `target`; `scroll` keeps the view where the
    /// user scrolled instead of jumping back to the cursor.
    fn load_hex(&mut self, cx: &PanelContext<'_>, target: u64, scroll: bool) {
        self.hex_target = None;
        self.hex_generation += 1;
        let binary = cx.session.binary.clone();
        if !self.live && binary.as_os_str().is_empty() {
            return;
        }
        let regions = self.regions.clone();
        let live = self.live.then(|| self.endpoint.trim().to_string());
        self.hex_message = format!("Reading {}…", address::format(&Address::ram(target)));
        let task = cx.service.job(format!("hex 0x{target:x}"), move |job| {
            let window = job.with_core(|core| read_window(core, &binary, &regions, target, live.as_deref()))??;
            job.detail(format!("{}: {} bytes", if window.live { "live" } else { "file" }, window.bytes.len()));
            Ok(window)
        });
        self.hex_load = Some(HexLoad { generation: self.hex_generation, target, scroll, task });
    }

    fn header(&mut self, ui: &mut egui::Ui, cx: &mut PanelContext<'_>) {
        let theme = cx.theme;
        let heading = if self.regions.is_empty() {
            "MEMORY".to_string()
        } else {
            format!("MEMORY  ·  {} regions", self.regions.len())
        };
        let (mut reload, mut toggled, mut endpoint_done) = (false, false, false);
        widgets::panel_header(ui, theme, &heading, |ui| {
            if widgets::chip(ui, theme, "Reload", false).on_hover_text("Reload the memory map and window").clicked() {
                reload = true;
            }
            if self.live {
                let edit = ui.add(
                    egui::TextEdit::singleline(&mut self.endpoint)
                        .font(font(Type::Code))
                        .hint_text("Dolphin GDB endpoint")
                        .desired_width(160.0),
                );
                endpoint_done = edit.lost_focus();
            }
            if widgets::chip(ui, theme, "Live target", self.live)
                .on_hover_text("Read bytes from a running target through Dolphin's GDB stub")
                .clicked()
            {
                self.live = !self.live;
                toggled = true;
            }
        });
        if reload {
            self.reset(cx);
        } else if toggled || endpoint_done {
            let target = self.hex.cursor.or(Some(self.hex.window.data.start)).filter(|_| !self.hex.window.bytes.is_empty() || self.hex.cursor.is_some());
            if let Some(target) = target {
                self.hex.clear();
                self.load_hex(cx, target, false);
            }
        }
    }

    fn regions_table(&mut self, ui: &mut egui::Ui, cx: &mut PanelContext<'_>) {
        let theme = cx.theme;
        if self.regions.is_empty() {
            ui.painter().rect_filled(ui.available_rect_before_wrap(), CornerRadius::ZERO, theme.bg_panel);
            if self.regions_load.is_some() {
                widgets::loading(ui, theme, &self.regions_message);
            } else if cx.session.program.is_empty() {
                widgets::empty_state(ui, theme, "No program open", "Choose an image in the toolbar to see its memory map.");
            } else if self.regions_message.is_empty() {
                widgets::empty_state(ui, theme, "No memory regions", "This program's import recorded no mapped regions.");
            } else {
                let (title, detail) = self.regions_message.split_once('\n').unwrap_or((&self.regions_message, ""));
                widgets::empty_state(ui, theme, title, detail);
            }
            return;
        }
        let footer = format!("{} regions  ·  double-click to go to one", self.regions.len());
        let regions = &self.regions;
        let mut navigate = None;
        let response = table::with_footer(ui, theme, &footer, |ui| {
            table::show(
                ui,
                theme,
                "memory-regions",
                &COLUMNS,
                &mut self.sort,
                regions.len(),
                &mut self.selected,
                &mut |index, column| {
                    let region = &regions[index];
                    match column {
                        0 => Cell::text(theme, region.name.as_str()),
                        1 => Cell::address(theme, &region.start),
                        2 => Cell::code(format!("0x{:x}", region.size), theme.text_muted).tooltip(format!("{} bytes", region.size)),
                        3 => Cell::new(
                            region.permissions.as_str(),
                            Type::Code,
                            if region.permissions.contains('x') { theme.syntax_keyword } else { theme.text_muted },
                        ),
                        _ => Cell::muted(theme, region.source.as_str()),
                    }
                },
                &mut |ui, index| {
                    let start = &regions[index].start;
                    if ui.button(format!("Go to {}", address::format(start))).clicked() {
                        navigate = Some(start.clone());
                        ui.close();
                    }
                },
            )
        });
        if let Some(index) = response.activated {
            navigate = Some(self.regions[index].start.clone());
        }
        if response.sort_changed {
            self.sort();
        }
        if let Some(start) = navigate {
            cx.navigate(start, true);
        }
    }

    fn hex_view(&mut self, ui: &mut egui::Ui, cx: &mut PanelContext<'_>) {
        let theme = cx.theme;
        if self.hex.window.bytes.is_empty() {
            ui.painter().rect_filled(ui.available_rect_before_wrap(), CornerRadius::ZERO, theme.bg_code);
            if self.hex_load.is_some() {
                widgets::loading(ui, theme, &self.hex_message);
            } else if self.hex_message.is_empty() {
                widgets::empty_state(ui, theme, "No bytes loaded", "Navigate to an address or pick a region to read its bytes.");
            } else {
                let (title, detail) = self.hex_message.split_once('\n').unwrap_or((&self.hex_message, ""));
                widgets::empty_state(ui, theme, title, detail);
            }
            return;
        }
        match self.hex.show(ui, theme, &self.regions) {
            Some(HexAction::Navigate { address, record }) => cx.navigate(Address::ram(address), record),
            Some(HexAction::Window(address)) if self.hex_load.is_none() && self.scroll_dead != Some(address) => {
                self.load_hex(cx, address, true)
            }
            _ => {}
        }
    }
}

impl Panel for MemoryPanel {
    fn id(&self) -> PanelId {
        ID
    }

    fn title(&self) -> String {
        "Memory".into()
    }

    fn on_event(&mut self, event: &ShellEvent, cx: &mut PanelContext<'_>) {
        match event {
            ShellEvent::ProgramChanged | ShellEvent::Refresh => self.reset(cx),
            ShellEvent::AddressChanged { address, .. } => {
                let target = ram(address);
                if !self.hex.set_cursor(target) {
                    self.hex_target = target;
                }
                self.select_cursor_region();
            }
            _ => {}
        }
    }

    fn poll(&mut self, cx: &mut PanelContext<'_>) {
        if let Some((generation, _)) = &self.regions_load {
            let generation = *generation;
            let mut slot = self.regions_load.take().map(|(_, task)| task);
            match poll_slot(&mut slot) {
                None => self.regions_load = slot.map(|task| (generation, task)),
                Some(_) if generation != self.generation => {}
                Some(Err(error)) => self.regions_message = format!("Memory map failed\n{error}"),
                Some(Ok(regions)) => {
                    self.regions = regions;
                    self.regions_message.clear();
                    self.sort();
                    // Qt: the window opens at the cursor, else the first region.
                    if self.hex_target.is_none() && self.hex.window.bytes.is_empty() && self.hex_load.is_none() {
                        self.hex_target = cx
                            .session
                            .address
                            .as_ref()
                            .and_then(ram)
                            .or_else(|| self.regions.iter().find(|region| region.start.space == AddressSpace::Ram).map(|region| region.start.offset));
                    }
                }
            }
        }
        if let Some(answer) = self.hex_load.as_ref().and_then(|load| load.task.poll())
            && let Some(load) = self.hex_load.take()
            && load.generation == self.hex_generation
        {
            match answer {
                // Scrolling past the readable bytes keeps the current window.
                Err(_) if load.scroll => {
                    self.hex_message.clear();
                    self.scroll_dead = Some(load.target);
                }
                Err(error) => {
                    self.hex.clear();
                    self.hex_message = format!("Cannot read 0x{:x}\n{error}", load.target);
                }
                Ok(window) => {
                    self.hex_message.clear();
                    self.scroll_dead = None;
                    self.hex.set_window(window, load.scroll.then_some(load.target));
                }
            }
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, cx: &mut PanelContext<'_>) {
        // Loads when shown.
        if self.regions_stale && self.regions_load.is_none() {
            self.load_regions(cx);
        }
        if self.regions_load.is_none()
            && self.hex_load.is_none()
            && let Some(target) = self.hex_target
        {
            self.load_hex(cx, target, false);
        }
        self.header(ui, cx);
        let theme = cx.theme;
        let rect = ui.available_rect_before_wrap();
        ui.allocate_rect(rect, Sense::hover());
        let side_by_side = rect.width() >= SPLIT_WIDTH;
        let (map, hex) = if side_by_side {
            let split = (rect.width() * 0.4).clamp(380.0, 560.0);
            rect.split_left_right_at_x(rect.left() + split)
        } else {
            rect.split_top_bottom_at_y(rect.top() + (rect.height() * 0.4).max(metrics::ROW * 4.0))
        };
        let mut map_ui = ui.new_child(egui::UiBuilder::new().max_rect(map).layout(Layout::top_down(Align::Min)));
        map_ui.set_clip_rect(map);
        self.regions_table(&mut map_ui, cx);
        let separator = if side_by_side {
            [pos2(hex.left(), hex.top()), pos2(hex.left(), hex.bottom())]
        } else {
            [pos2(hex.left(), hex.top()), pos2(hex.right(), hex.top())]
        };
        let mut hex_ui = ui.new_child(egui::UiBuilder::new().max_rect(hex.shrink2(egui::vec2(0.5, 0.5))).layout(Layout::top_down(Align::Min)));
        hex_ui.set_clip_rect(hex);
        self.hex_view(&mut hex_ui, cx);
        ui.painter().line_segment(separator, Stroke::new(1.0, theme.border));
    }

    fn busy(&self) -> bool {
        self.regions_load.is_some() || self.hex_load.is_some()
    }
}
