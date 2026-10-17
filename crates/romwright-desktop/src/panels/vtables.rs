//! Recovered vtables (Qt `VtablesDock`): Search ▸ Recover vtables runs
//! `Core::recover_vtables` over the open binary's data as a job and lists
//! every run of code pointers it found.

use crate::address;
use crate::panel::{Command, Panel, PanelContext, PanelId, ShellEvent};
use crate::service::{Task, poll_slot};
use crate::table::{self, Cell, Column, Sort, Width};
use crate::theme::{Type, space};
use crate::widgets;
use romwright_model::Address;
use serde_json::Value;

pub const ID: PanelId = "vtables";
/// Vtables per recovery (Qt `limit: 512`).
const LIMIT: u64 = 512;
const COLUMNS: [Column; 3] = [
    Column::address("Address"),
    Column::new("Entries", Width::Exact(72.0)).right(),
    Column::new("Targets", Width::Remainder),
];

struct Vtable {
    address: Address,
    targets: Vec<Address>,
    /// `targets` joined for display, built once.
    text: String,
}

/// `{"address": "<hex>", "targets": ["<hex>", ...]}` as `Core::recover_vtables`
/// answers it.
fn parse(value: &Value) -> Option<Vtable> {
    let hex = |value: &Value| value.as_str().and_then(|text| u64::from_str_radix(text, 16).ok()).map(Address::ram);
    let address = hex(value.get("address")?)?;
    let targets: Vec<Address> = value.get("targets")?.as_array()?.iter().filter_map(hex).collect();
    let text = targets.iter().map(address::format).collect::<Vec<_>>().join(", ");
    Some(Vtable { address, targets, text })
}

#[derive(Default)]
pub struct VtablesPanel {
    rows: Vec<Vtable>,
    task: Option<Task<Vec<Vtable>>>,
    /// A recovery answered for the open binary.
    recovered: bool,
    error: Option<String>,
    sort: Sort,
    selected: Option<usize>,
}

impl VtablesPanel {
    /// Rows the last recovery produced.
    pub fn rows(&self) -> usize {
        self.rows.len()
    }

    /// Qt `recoverVtables`: scan the session's binary.
    pub fn recover(&mut self, cx: &mut PanelContext<'_>) {
        self.clear();
        let binary = cx.session.binary.clone();
        if binary.as_os_str().is_empty() {
            cx.error("Recover vtables needs an open program with a captured binary");
            return;
        }
        self.task = Some(cx.service.job("vtable recovery", move |job| {
            job.progress(format!("scanning {}", binary.display()));
            let core = job.fork()?;
            let values = core.recover_vtables(&binary, LIMIT).map_err(|error| error.to_string())?;
            let rows: Vec<Vtable> = values.iter().filter_map(parse).collect();
            job.detail(format!("{} vtables recovered", rows.len()));
            Ok(rows)
        }));
    }

    fn clear(&mut self) {
        self.rows.clear();
        self.task = None;
        self.recovered = false;
        self.error = None;
        self.selected = None;
    }

    fn sort(&mut self) {
        table::sort_rows(&mut self.rows, self.sort, |a, b, column| match column {
            0 => table::address_order(&a.address, &b.address),
            1 => a.targets.len().cmp(&b.targets.len()),
            _ => a.text.cmp(&b.text),
        });
    }
}

impl Panel for VtablesPanel {
    fn id(&self) -> PanelId {
        ID
    }

    fn title(&self) -> String {
        "Vtables".into()
    }

    fn open_by_default(&self) -> bool {
        false
    }

    fn on_event(&mut self, event: &ShellEvent, cx: &mut PanelContext<'_>) {
        match event {
            ShellEvent::ProgramChanged => self.clear(),
            ShellEvent::VtablesRequested => self.recover(cx),
            _ => {}
        }
    }

    fn poll(&mut self, cx: &mut PanelContext<'_>) {
        let Some(result) = poll_slot(&mut self.task) else { return };
        match result {
            Ok(rows) => {
                self.rows = rows;
                self.recovered = true;
                self.sort();
                cx.status(format!("{} vtables recovered", self.rows.len()));
                cx.command(Command::Raise(ID));
            }
            Err(error) => {
                cx.error(format!("Vtable recovery: {error}"));
                self.error = Some(error);
            }
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, cx: &mut PanelContext<'_>) {
        let theme = cx.theme;
        let has_binary = !cx.session.binary.as_os_str().is_empty();
        let running = self.task.is_some();
        let mut recover = false;
        let binary = cx.session.binary.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default();
        let title = if self.recovered { format!("Recovered from {binary}") } else { "Vtables".to_string() };
        widgets::panel_header(ui, theme, &title, |ui| {
            let label = if self.recovered { "Recover again" } else { "Recover vtables" };
            recover = widgets::button(ui, theme, label, has_binary && !running).clicked();
        });
        if recover {
            self.recover(cx);
        }
        if cx.session.program.is_empty() {
            widgets::empty_state(ui, theme, "No program open", "Choose an image in the toolbar first.");
            return;
        }
        if self.task.is_some() {
            widgets::loading(ui, theme, "Scanning data for tables of code pointers…");
            return;
        }
        if let Some(error) = &self.error {
            widgets::empty_state(ui, theme, "Recovery failed", error);
            return;
        }
        if !self.recovered {
            widgets::empty_state(ui, theme, "Not scanned yet", "Search ▸ Recover vtables scans the binary's data for runs of code pointers.");
            return;
        }
        if self.rows.is_empty() {
            widgets::empty_state(ui, theme, "No vtables", "No run of three or more code pointers was found in the image's data.");
            return;
        }
        let footer = if self.rows.len() as u64 >= LIMIT {
            format!("First {LIMIT} vtables  ·  double-click to go to a table")
        } else {
            format!("{} vtables  ·  double-click to go to a table", self.rows.len())
        };
        let rows = &self.rows;
        let mut navigate = None;
        let response = table::with_footer(ui, theme, &footer, |ui| {
            ui.add_space(space::XXS);
            table::show(
                ui,
                theme,
                "vtables-table",
                &COLUMNS,
                &mut self.sort,
                rows.len(),
                &mut self.selected,
                &mut |index, column| {
                    let row = &rows[index];
                    match column {
                        0 => Cell::address(theme, &row.address),
                        1 => Cell::code(row.targets.len().to_string(), theme.syntax_constant),
                        _ => Cell::new(row.text.as_str(), Type::CodeSmall, theme.text_muted),
                    }
                },
                &mut |ui, index| {
                    let row = &rows[index];
                    if ui.button(format!("Go to table  {}", address::format(&row.address))).clicked() {
                        navigate = Some(row.address.clone());
                        ui.close();
                    }
                    ui.menu_button("Go to entry", |ui| {
                        for (slot, target) in row.targets.iter().enumerate() {
                            if ui.button(format!("[{slot}]  {}", address::format(target))).clicked() {
                                navigate = Some(target.clone());
                                ui.close();
                            }
                        }
                    });
                },
            )
        });
        if response.sort_changed {
            self.selected = None;
            self.sort();
        }
        if let Some(index) = response.activated
            && let Some(row) = self.rows.get(index)
        {
            navigate = Some(row.address.clone());
        }
        if let Some(address) = navigate {
            cx.navigate(address, true);
        }
    }

    fn busy(&self) -> bool {
        self.task.is_some()
    }
}
