//! Cross references at the cursor (Qt `XrefsDock`): `Core::xrefs_page` in
//! both directions, an evidence-kind filter, and for every row the shared
//! sentence saying what proved it (`FactProvenance::explanation`).
//!
//! The gate reads [`XrefsPanel::rendered_rows`] / [`XrefsPanel::unexplained_rows`]
//! after [`XrefsPanel::loads_finished`] moves, exactly as Qt's gate runner read
//! `renderedRows`/`unexplainedRows` on `loadFinished`.

use crate::address;
use crate::panel::{Change, Panel, PanelContext, PanelId, ShellEvent};
use crate::service::{Task, poll_slot};
use crate::table::{self, Cell, Column, Sort, Width};
use crate::theme::{Theme, Type, font, space};
use crate::widgets;
use egui::{Layout, RichText};
use romwright_model::provenance::EvidenceKind;
use romwright_model::{Address, Page, XrefRow};

pub const ID: PanelId = "xrefs";
/// Rows fetched per direction (Qt `limit: 256`).
const LIMIT: u64 = 256;
const EVIDENCE: [(&str, &str); 4] = [("All", ""), ("Declared", "declared"), ("Decoded", "decoded"), ("Inferred", "inferred")];
const COLUMNS: [Column; 6] = [
    Column::address("Address"),
    Column::new("Function", Width::Initial(160.0)),
    Column::new("Kind", Width::Initial(150.0)),
    Column::address("Target"),
    Column::new("Basis", Width::Exact(72.0)),
    Column::new("Evidence", Width::Remainder),
];

#[derive(Default)]
struct Side {
    rows: Vec<XrefRow>,
    total: u64,
    task: Option<Task<Page<XrefRow>>>,
    error: Option<String>,
    sort: Sort,
    selected: Option<usize>,
}

impl Side {
    fn reset(&mut self) {
        self.rows.clear();
        self.total = 0;
        self.task = None;
        self.error = None;
        self.selected = None;
    }

    fn sort(&mut self) {
        table::sort_rows(&mut self.rows, self.sort, |a, b, column| match column {
            0 => table::address_order(&a.from, &b.from),
            1 => table::text_order(a.function.as_deref().unwrap_or(""), b.function.as_deref().unwrap_or("")),
            2 => a.kind.cmp(&b.kind),
            3 => table::address_order(&a.to, &b.to),
            4 => basis(a).cmp(basis(b)),
            _ => sentence(a).cmp(sentence(b)),
        });
    }
}

fn basis(row: &XrefRow) -> &'static str {
    row.provenance.evidence().map_or("", EvidenceKind::as_str)
}

fn sentence(row: &XrefRow) -> &str {
    row.provenance.explanation().unwrap_or(&row.provenance.source)
}

fn basis_color(theme: &Theme, kind: Option<EvidenceKind>) -> egui::Color32 {
    match kind {
        Some(EvidenceKind::Declared) => theme.ok,
        Some(EvidenceKind::Decoded) => theme.accent,
        Some(EvidenceKind::Inferred) => theme.warn,
        None => theme.text_faint,
    }
}

#[derive(Default)]
pub struct XrefsPanel {
    program: String,
    address: Option<Address>,
    evidence: String,
    /// 0 = incoming, 1 = outgoing.
    tab: usize,
    sides: [Side; 2],
    generation: u64,
    pending: u8,
    rendered_rows: usize,
    unexplained_rows: usize,
    loads_finished: u64,
}

impl XrefsPanel {
    /// Rows the last load put in both tables (Qt `renderedRows`).
    pub fn rendered_rows(&self) -> usize {
        self.rendered_rows
    }

    /// Rows among them with no evidence sentence (Qt `unexplainedRows`).
    pub fn unexplained_rows(&self) -> usize {
        self.unexplained_rows
    }

    /// Completed loads (both directions answered): Qt `loadFinished` count.
    pub fn loads_finished(&self) -> u64 {
        self.loads_finished
    }

    /// Selects an evidence kind (`""` = all) and reloads when it changed
    /// (Qt `setEvidence`).
    pub fn set_evidence(&mut self, cx: &PanelContext<'_>, kind: &str) {
        if self.evidence == kind {
            return;
        }
        self.evidence = kind.to_string();
        if let Some(address) = self.address.clone() {
            self.load_xrefs(cx, &address);
        }
    }

    /// Loads references to and from `address` in the open program
    /// (Qt `loadXrefs`).
    pub fn load_xrefs(&mut self, cx: &PanelContext<'_>, address: &Address) {
        self.generation += 1;
        for side in &mut self.sides {
            side.reset();
        }
        self.program = cx.session.program.clone();
        self.address = Some(address.clone());
        self.rendered_rows = 0;
        self.unexplained_rows = 0;
        self.pending = 0;
        if self.program.is_empty() {
            return;
        }
        self.pending = 2;
        let evidence = EvidenceKind::parse(&self.evidence);
        for (index, side) in self.sides.iter_mut().enumerate() {
            let incoming = index == 0;
            let (program, address) = (self.program.clone(), address.clone());
            side.task = Some(cx.service.request(move |core| {
                core.xrefs_page(&program, &address, incoming, 0, LIMIT, evidence).map_err(|error| error.to_string())
            }));
        }
    }

    fn clear(&mut self) {
        self.generation += 1;
        self.program.clear();
        self.address = None;
        self.pending = 0;
        for side in &mut self.sides {
            side.reset();
        }
    }

    fn reload(&mut self, cx: &PanelContext<'_>) {
        if let Some(address) = self.address.clone() {
            self.load_xrefs(cx, &address);
        }
    }

    fn tab_label(&self, index: usize) -> String {
        let side = &self.sides[index];
        let name = if index == 0 { "Incoming" } else { "Outgoing" };
        if side.task.is_some() {
            format!("{name} …")
        } else if side.error.is_some() {
            format!("{name}  ·  failed")
        } else if self.address.is_some() {
            format!("{name}  {}", side.total)
        } else {
            name.to_string()
        }
    }

    fn toolbar(&mut self, ui: &mut egui::Ui, cx: &mut PanelContext<'_>) {
        let theme = cx.theme;
        let mut tab = self.tab;
        let labels = [self.tab_label(0), self.tab_label(1)];
        let mut evidence = EVIDENCE.iter().position(|(_, key)| *key == self.evidence).unwrap_or(0);
        let mut changed = None;
        egui::Frame::new().inner_margin(egui::Margin::symmetric(space::SM as i8, space::XS as i8 + 2)).show(ui, |ui| {
            ui.horizontal(|ui| {
                widgets::segmented(ui, theme, &[labels[0].as_str(), labels[1].as_str()], &mut tab, &[]);
                widgets::toolbar_separator(ui, theme);
                widgets::caption(ui, theme, "Evidence");
                let names: Vec<&str> = EVIDENCE.iter().map(|(name, _)| *name).collect();
                if widgets::segmented(ui, theme, &names, &mut evidence, &[]) {
                    changed = Some(EVIDENCE[evidence].1);
                }
                if let Some(address) = &self.address {
                    ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(RichText::new(address::format(address)).font(font(Type::Code)).color(theme.syntax_address));
                        widgets::caption(ui, theme, "References at");
                    });
                }
            });
        });
        ui.painter().hline(ui.max_rect().x_range(), ui.cursor().top(), egui::Stroke::new(1.0, theme.border));
        self.tab = tab;
        if let Some(kind) = changed {
            self.set_evidence(cx, kind);
        }
    }
}

/// The selected row's evidence in full: kind, class and sentence.
fn detail(ui: &mut egui::Ui, theme: &Theme, row: &XrefRow) {
    let provenance = &row.provenance;
    egui::Frame::new()
        .fill(theme.bg_raised)
        .inner_margin(egui::Margin::symmetric(space::MD as i8, space::SM as i8))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                let kind = provenance.evidence();
                ui.label(RichText::new(kind.map_or("unclassified", EvidenceKind::as_str)).font(font(Type::Caption)).color(basis_color(theme, kind)));
                ui.label(RichText::new(&provenance.source).font(font(Type::CodeSmall)).color(theme.text_muted));
                if let Some(confidence) = provenance.confidence {
                    widgets::caption(ui, theme, &format!("confidence {confidence:.2}"));
                }
            });
            let text = provenance.explanation().unwrap_or("Nothing in the provenance table explains this source.");
            ui.add(egui::Label::new(RichText::new(text).font(font(Type::Body)).color(theme.text)).wrap());
        });
}

impl Panel for XrefsPanel {
    fn id(&self) -> PanelId {
        ID
    }

    fn title(&self) -> String {
        "Xrefs".into()
    }

    fn on_event(&mut self, event: &ShellEvent, cx: &mut PanelContext<'_>) {
        match event {
            ShellEvent::ProgramChanged => self.clear(),
            ShellEvent::AddressChanged { address, .. } => {
                if self.address.as_ref() != Some(address) || self.program != cx.session.program {
                    self.load_xrefs(cx, address);
                }
            }
            // The requester raises the tab when it wants it shown (Qt: a
            // string click fills the dock without raising it).
            ShellEvent::XrefsRequested(address) => self.load_xrefs(cx, address),
            ShellEvent::RevisionChanged(Change::Rename | Change::Undo | Change::Analysis) | ShellEvent::Refresh => self.reload(cx),
            _ => {}
        }
    }

    fn poll(&mut self, cx: &mut PanelContext<'_>) {
        for index in 0..2 {
            let Some(result) = poll_slot(&mut self.sides[index].task) else { continue };
            match result {
                Ok(page) => {
                    self.rendered_rows += page.rows.len();
                    self.unexplained_rows += page.rows.iter().filter(|row| row.provenance.explanation().is_none()).count();
                    let side = &mut self.sides[index];
                    side.total = page.total.unwrap_or(page.rows.len() as u64);
                    side.rows = page.rows;
                    side.sort();
                }
                Err(error) => {
                    cx.error(format!("Xrefs: {error}"));
                    self.sides[index].error = Some(error);
                }
            }
            self.pending = self.pending.saturating_sub(1);
            if self.pending == 0 {
                self.loads_finished += 1;
            }
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, cx: &mut PanelContext<'_>) {
        let theme = cx.theme;
        self.toolbar(ui, cx);
        if cx.session.program.is_empty() {
            widgets::empty_state(ui, theme, "No program open", "Choose an image in the toolbar to see its references.");
            return;
        }
        if self.address.is_none() {
            widgets::empty_state(ui, theme, "No address", "Navigate to an address, or pick Show xrefs in the listing.");
            return;
        }
        let incoming = self.tab == 0;
        let side = &mut self.sides[self.tab];
        if side.task.is_some() {
            widgets::loading(ui, theme, "Loading references…");
            return;
        }
        if let Some(error) = &side.error {
            widgets::empty_state(ui, theme, "References unavailable", error);
            return;
        }
        if side.rows.is_empty() {
            let filter = EVIDENCE.iter().find(|(_, key)| *key == self.evidence).map_or("", |(name, _)| name);
            let detail = if self.evidence.is_empty() {
                if incoming { "Nothing in the store refers to this address." } else { "This address refers to nothing the store knows." }
            } else {
                "No reference of that evidence kind; choose All to see every reference."
            };
            let title = if self.evidence.is_empty() { "No references".to_string() } else { format!("No {} references", filter.to_lowercase()) };
            widgets::empty_state(ui, theme, &title, detail);
            return;
        }
        let shown = side.rows.len() as u64;
        let footer = if side.total > shown {
            format!("{} of {} references  ·  first {LIMIT} shown", shown, side.total)
        } else {
            format!("{shown} references  ·  double-click to go to the {}", if incoming { "referring address" } else { "target" })
        };
        let selected_row = side.selected.and_then(|index| side.rows.get(index)).cloned();
        let detail_height = if selected_row.is_some() { 76.0 } else { 0.0 };
        let mut navigate = None;
        let mut requested = None;
        let response = table::with_footer(ui, theme, &footer, |ui| {
            let height = (ui.available_height() - detail_height).max(0.0);
            let width = ui.available_width();
            let response = ui
                .allocate_ui(egui::vec2(width, height), |ui| {
                    let rows = &side.rows;
                    table::show(
                        ui,
                        theme,
                        if incoming { "xrefs-in" } else { "xrefs-out" },
                        &COLUMNS,
                        &mut side.sort,
                        rows.len(),
                        &mut side.selected,
                        &mut |index, column| {
                            let row = &rows[index];
                            match column {
                                0 => Cell::address(theme, &row.from),
                                1 => match &row.function {
                                    Some(name) => Cell::new(name.as_str(), Type::Body, theme.syntax_function),
                                    None => Cell::new("—", Type::Body, theme.text_faint),
                                },
                                2 => Cell::code(row.kind.as_str(), theme.text_muted),
                                3 => Cell::address(theme, &row.to),
                                4 => {
                                    let kind = row.provenance.evidence();
                                    Cell::new(kind.map_or("—", EvidenceKind::as_str), Type::Caption, basis_color(theme, kind))
                                }
                                _ => {
                                    let provenance = &row.provenance;
                                    let tooltip = match provenance.evidence() {
                                        Some(kind) => format!("{} [{}]", provenance.source, kind.as_str()),
                                        None => provenance.source.clone(),
                                    };
                                    match provenance.explanation() {
                                        Some(text) => Cell::muted(theme, text),
                                        None => Cell::new(provenance.source.as_str(), Type::CodeSmall, theme.warn),
                                    }
                                    .tooltip(tooltip)
                                }
                            }
                        },
                        &mut |ui, index| {
                            let row = &rows[index];
                            if ui.button(format!("Go to source  {}", address::format(&row.from))).clicked() {
                                navigate = Some(row.from.clone());
                                ui.close();
                            }
                            if ui.button(format!("Go to target  {}", address::format(&row.to))).clicked() {
                                navigate = Some(row.to.clone());
                                ui.close();
                            }
                            let other = if incoming { &row.from } else { &row.to };
                            if ui.button(format!("Show xrefs of {}", address::format(other))).clicked() {
                                requested = Some(other.clone());
                                ui.close();
                            }
                            if ui.button("Copy address").clicked() {
                                ui.ctx().copy_text(address::format(other));
                                ui.close();
                            }
                        },
                    )
                })
                .inner;
            if let Some(row) = &selected_row {
                detail(ui, theme, row);
            }
            response
        });
        let side = &mut self.sides[self.tab];
        if response.sort_changed {
            side.selected = None;
            side.sort();
        }
        if let Some(index) = response.activated
            && let Some(row) = side.rows.get(index)
        {
            navigate = Some(if incoming { row.from.clone() } else { row.to.clone() });
        }
        if let Some(address) = navigate {
            cx.navigate(address, true);
        }
        if let Some(address) = requested {
            self.load_xrefs(cx, &address);
        }
    }

    fn busy(&self) -> bool {
        self.pending > 0
    }
}
