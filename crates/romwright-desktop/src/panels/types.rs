//! Types and prototypes (Qt `TypesDock`): the program's type definitions,
//! composite fields, function prototypes, recovered stack variables and the
//! type dependency graph, each with its editor. Saving a prototype
//! re-decompiles the current function; every save broadcasts
//! `RevisionChanged(Change::Types)` so derived views drop stale documents.

use crate::address;
use crate::panel::{Change, Command, Panel, PanelContext, PanelId, ShellEvent};
use crate::service::{Task, poll_slot};
use crate::table::{self, Cell, Column, Sort, Width};
use crate::theme::{Theme, Type, font, space};
use crate::widgets;
use egui::{Key, RichText};
use romwright_model::{
    Address, FactKind, FactProvenance, FunctionRow, PrimitiveKind, PrototypeRow, StackVariableRow, TypeDefRow, TypeFieldRow,
    TypeLinkRow,
};

pub const ID: PanelId = "types";
const TABS: [&str; 5] = ["Types", "Fields", "Prototypes", "Stack", "Graph"];
const EDITOR_WIDTH: f32 = 300.0;
const PRIMITIVES: [Option<PrimitiveKind>; 6] = [
    None,
    Some(PrimitiveKind::SignedInteger),
    Some(PrimitiveKind::UnsignedInteger),
    Some(PrimitiveKind::Float),
    Some(PrimitiveKind::Boolean),
    Some(PrimitiveKind::Void),
];
const TYPE_COLUMNS: [Column; 9] = [
    Column::new("Name", Width::Initial(180.0)),
    Column::new("Kind", Width::Initial(80.0)),
    Column::new("Definition", Width::Initial(240.0)),
    Column::new("Size", Width::Exact(56.0)).right(),
    Column::new("Align", Width::Exact(56.0)).right(),
    Column::new("Base", Width::Initial(110.0)),
    Column::new("Primitive", Width::Initial(120.0)),
    Column::new("Elements", Width::Exact(72.0)).right(),
    Column::new("Provenance", Width::Remainder),
];
const FIELD_COLUMNS: [Column; 6] = [
    Column::new("Type", Width::Initial(160.0)),
    Column::new("#", Width::Exact(44.0)).right(),
    Column::new("Field", Width::Initial(160.0)),
    Column::new("Offset", Width::Exact(72.0)).right(),
    Column::new("Size", Width::Exact(56.0)).right(),
    Column::new("Type ref", Width::Remainder),
];
const PROTOTYPE_COLUMNS: [Column; 5] = [
    Column::address("Function"),
    Column::new("Signature", Width::Initial(380.0)),
    Column::new("Convention", Width::Initial(110.0)),
    Column::new("Return", Width::Initial(110.0)),
    Column::new("Source", Width::Remainder),
];
const STACK_COLUMNS: [Column; 7] = [
    Column::address("Function"),
    Column::new("#", Width::Exact(44.0)).right(),
    Column::new("Name", Width::Initial(150.0)),
    Column::new("Storage", Width::Initial(120.0)),
    Column::new("Type", Width::Initial(140.0)),
    Column::new("Offset", Width::Exact(72.0)).right(),
    Column::new("Size", Width::Remainder),
];
const LINK_COLUMNS: [Column; 4] = [
    Column::new("Source", Width::Initial(180.0)),
    Column::new("Target", Width::Initial(180.0)),
    Column::new("Kind", Width::Initial(110.0)),
    Column::new("Provenance", Width::Remainder),
];

/// Everything the panel lists, read in one store pass.
#[derive(Default)]
struct Lists {
    types: Vec<TypeDefRow>,
    fields: Vec<TypeFieldRow>,
    prototypes: Vec<PrototypeRow>,
    stack: Vec<StackVariableRow>,
    links: Vec<TypeLinkRow>,
    nodes: usize,
}

/// Editor text, one block per tab (Qt's grid of line edits).
struct Form {
    name: String,
    kind: String,
    definition: String,
    size: String,
    alignment: String,
    base: String,
    primitive: usize,
    elements: String,
    field_type: String,
    field_ordinal: String,
    field_name: String,
    field_offset: String,
    field_size: String,
    field_ref: String,
    function: String,
    signature: String,
    convention: String,
    stack_name: String,
    stack_ordinal: String,
    stack_storage: String,
    stack_type: String,
    stack_offset: String,
    stack_size: String,
    error: Option<String>,
}

impl Default for Form {
    fn default() -> Self {
        Self {
            name: String::new(),
            kind: "struct".into(),
            definition: String::new(),
            size: String::new(),
            alignment: String::new(),
            base: String::new(),
            primitive: 0,
            elements: String::new(),
            field_type: String::new(),
            field_ordinal: "0".into(),
            field_name: String::new(),
            field_offset: "0".into(),
            field_size: String::new(),
            field_ref: String::new(),
            function: String::new(),
            signature: String::new(),
            convention: String::new(),
            stack_name: String::new(),
            stack_ordinal: "0".into(),
            stack_storage: String::new(),
            stack_type: String::new(),
            stack_offset: String::new(),
            stack_size: String::new(),
            error: None,
        }
    }
}

/// One store write.
enum Edit {
    Type(TypeDefRow),
    Field(TypeFieldRow),
    Prototype(PrototypeRow),
    Stack(StackVariableRow),
    Propagate,
}

#[derive(Default)]
pub struct TypesPanel {
    program: String,
    function: Option<FunctionRow>,
    tab: usize,
    /// The analyst picked a tab; otherwise the first non-empty one opens.
    tab_chosen: bool,
    lists: Lists,
    /// Stack rows shown (all, or the current function's).
    stack_view: Vec<usize>,
    only_current: bool,
    generation: u64,
    load: Option<(u64, Task<Lists>)>,
    answered: bool,
    error: Option<String>,
    saves: Vec<(String, Task<String>)>,
    selected: [Option<usize>; 5],
    sorts: [Sort; 5],
    form: Form,
}

/// `12`, `0x10`, `-0x18`; empty is `None`.
fn integer(text: &str) -> Result<Option<i64>, String> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(None);
    }
    let (negative, digits) = match text.strip_prefix('-') {
        Some(rest) => (true, rest.trim()),
        None => (false, text),
    };
    let value = match digits.strip_prefix("0x").or_else(|| digits.strip_prefix("0X")) {
        Some(hex) => i64::from_str_radix(hex, 16),
        None => digits.parse::<i64>(),
    }
    .map_err(|_| format!("{text:?} is not a number"))?;
    Ok(Some(if negative { -value } else { value }))
}

fn unsigned(text: &str, what: &str) -> Result<Option<u64>, String> {
    integer(text)?.map(|value| u64::try_from(value).map_err(|_| format!("{what} cannot be negative"))).transpose()
}

fn required<T>(value: Option<T>, what: &str) -> Result<T, String> {
    value.ok_or_else(|| format!("{what} is required"))
}

fn optional_text(text: &str) -> Option<String> {
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_string())
}

fn number(value: Option<u64>) -> String {
    value.map(|value| value.to_string()).unwrap_or_default()
}

fn primitive_label(kind: Option<PrimitiveKind>) -> &'static str {
    kind.map_or("unknown", PrimitiveKind::as_str)
}

fn provenance_label(provenance: &FactProvenance) -> String {
    let kind = match provenance.kind {
        FactKind::Asserted => "asserted",
        FactKind::Inferred => "inferred",
    };
    match provenance.confidence {
        Some(confidence) => format!("{kind} · {} · {:.0}%", provenance.source, confidence * 100.0),
        None if provenance.source.is_empty() => kind.to_string(),
        None => format!("{kind} · {}", provenance.source),
    }
}

impl TypesPanel {
    pub fn set_tab(&mut self, tab: usize) {
        self.tab = tab.min(TABS.len() - 1);
        self.tab_chosen = true;
    }

    fn load(&mut self, cx: &mut PanelContext<'_>) {
        self.program = cx.session.program.clone();
        self.generation += 1;
        self.load = None;
        if self.program.is_empty() {
            self.lists = Lists::default();
            self.answered = false;
            return;
        }
        let program = self.program.clone();
        let task = cx.service.job("types", move |job| {
            let core = job.fork()?;
            let text = |error: romwright_core::CoreError| error.to_string();
            let (nodes, links) = core.type_graph(&program).map_err(text)?;
            let lists = Lists {
                types: core.type_defs(&program).map_err(text)?,
                fields: core.type_fields(&program, None).map_err(text)?,
                prototypes: core.prototypes(&program).map_err(text)?,
                stack: core.stack_variables(&program, None).map_err(text)?,
                links,
                nodes: nodes.len(),
            };
            job.detail(format!(
                "{} types, {} fields, {} prototypes, {} stack variables, {} type links",
                lists.types.len(),
                lists.fields.len(),
                lists.prototypes.len(),
                lists.stack.len(),
                lists.links.len()
            ));
            Ok(lists)
        });
        self.load = Some((self.generation, task));
    }

    fn sort(&mut self, tab: usize) {
        let sort = self.sorts[tab];
        let text = table::text_order;
        match tab {
            0 => table::sort_rows(&mut self.lists.types, sort, |a, b, column| match column {
                0 => text(&a.name, &b.name),
                1 => text(&a.kind, &b.kind),
                2 => text(&a.definition, &b.definition),
                3 => a.size.cmp(&b.size),
                4 => a.alignment.cmp(&b.alignment),
                5 => a.base_type.cmp(&b.base_type),
                6 => primitive_label(a.primitive).cmp(primitive_label(b.primitive)),
                7 => a.element_count.cmp(&b.element_count),
                _ => text(&a.provenance, &b.provenance),
            }),
            1 => table::sort_rows(&mut self.lists.fields, sort, |a, b, column| match column {
                0 => text(&a.type_name, &b.type_name).then(a.ordinal.cmp(&b.ordinal)),
                1 => a.ordinal.cmp(&b.ordinal),
                2 => text(&a.field_name, &b.field_name),
                3 => a.offset.cmp(&b.offset),
                4 => a.size.cmp(&b.size),
                _ => a.type_ref.cmp(&b.type_ref),
            }),
            2 => table::sort_rows(&mut self.lists.prototypes, sort, |a, b, column| match column {
                0 => table::address_order(&a.function, &b.function),
                1 => text(&a.signature, &b.signature),
                2 => a.calling_convention.cmp(&b.calling_convention),
                3 => a.return_type.cmp(&b.return_type),
                _ => provenance_label(&a.provenance).cmp(&provenance_label(&b.provenance)),
            }),
            3 => {
                table::sort_rows(&mut self.lists.stack, sort, |a, b, column| match column {
                    0 => table::address_order(&a.function, &b.function).then(a.ordinal.cmp(&b.ordinal)),
                    1 => a.ordinal.cmp(&b.ordinal),
                    2 => text(&a.name, &b.name),
                    3 => text(&a.storage, &b.storage),
                    4 => a.type_name.cmp(&b.type_name),
                    5 => a.offset.cmp(&b.offset),
                    _ => a.size.cmp(&b.size),
                });
                self.filter_stack();
            }
            _ => table::sort_rows(&mut self.lists.links, sort, |a, b, column| match column {
                0 => text(&a.source, &b.source),
                1 => text(&a.target, &b.target),
                2 => text(&a.kind, &b.kind),
                _ => text(&a.provenance, &b.provenance),
            }),
        }
    }

    fn filter_stack(&mut self) {
        let function = self.only_current.then(|| self.function.as_ref().map(|function| &function.entry)).flatten();
        self.stack_view = (0..self.lists.stack.len())
            .filter(|index| function.is_none_or(|entry| &self.lists.stack[*index].function == entry))
            .collect();
        self.selected[3] = None;
    }

    fn current_function_text(&self) -> String {
        self.function.as_ref().map(|function| address::format(&function.entry)).unwrap_or_default()
    }

    /// Fills the editor from a clicked row (Qt had no row → editor link;
    /// re-typing a row to edit it was the only way).
    fn edit_row(&mut self, tab: usize, index: usize) {
        let form = &mut self.form;
        form.error = None;
        match tab {
            0 => {
                let row = &self.lists.types[index];
                form.name = row.name.clone();
                form.kind = row.kind.clone();
                form.definition = row.definition.clone();
                form.size = number(row.size);
                form.alignment = number(row.alignment);
                form.base = row.base_type.clone().unwrap_or_default();
                form.primitive = PRIMITIVES.iter().position(|kind| *kind == row.primitive).unwrap_or(0);
                form.elements = number(row.element_count);
            }
            1 => {
                let row = &self.lists.fields[index];
                form.field_type = row.type_name.clone();
                form.field_ordinal = row.ordinal.to_string();
                form.field_name = row.field_name.clone();
                form.field_offset = format!("0x{:x}", row.offset);
                form.field_size = number(row.size);
                form.field_ref = row.type_ref.clone().unwrap_or_default();
            }
            2 => {
                let row = &self.lists.prototypes[index];
                form.function = address::format(&row.function);
                form.signature = row.signature.clone();
                form.convention = row.calling_convention.clone().unwrap_or_default();
            }
            3 => {
                let row = &self.lists.stack[self.stack_view[index]];
                form.function = address::format(&row.function);
                form.stack_ordinal = row.ordinal.to_string();
                form.stack_name = row.name.clone();
                form.stack_storage = row.storage.clone();
                form.stack_type = row.type_name.clone().unwrap_or_default();
                form.stack_offset = row.offset.map(|offset| if offset < 0 { format!("-0x{:x}", offset.unsigned_abs()) } else { format!("0x{offset:x}") }).unwrap_or_default();
                form.stack_size = number(row.size);
            }
            _ => {}
        }
    }

    fn function_address(&self) -> Result<Address, String> {
        let text = if self.form.function.trim().is_empty() { self.current_function_text() } else { self.form.function.clone() };
        if text.trim().is_empty() {
            return Err("No function: move the cursor into a function first".into());
        }
        address::parse(&text).ok_or_else(|| format!("{text:?} is not an address"))
    }

    fn build(&self, tab: usize) -> Result<Edit, String> {
        let form = &self.form;
        match tab {
            0 => {
                let name = required(optional_text(&form.name), "Type name")?;
                Ok(Edit::Type(TypeDefRow {
                    name,
                    kind: form.kind.trim().to_string(),
                    definition: form.definition.trim().to_string(),
                    size: unsigned(&form.size, "Size")?,
                    alignment: unsigned(&form.alignment, "Alignment")?,
                    base_type: optional_text(&form.base),
                    provenance: "ui".into(),
                    primitive: PRIMITIVES[form.primitive],
                    element_count: unsigned(&form.elements, "Elements")?,
                }))
            }
            1 => {
                let type_name = required(optional_text(&form.field_type), "Type name")?;
                let field_name = required(optional_text(&form.field_name), "Field name")?;
                let ordinal = required(unsigned(&form.field_ordinal, "Ordinal")?, "Ordinal")?;
                Ok(Edit::Field(TypeFieldRow {
                    type_name,
                    ordinal: u32::try_from(ordinal).map_err(|_| "Ordinal is too large".to_string())?,
                    field_name,
                    offset: required(unsigned(&form.field_offset, "Offset")?, "Offset")?,
                    size: unsigned(&form.field_size, "Size")?,
                    type_ref: optional_text(&form.field_ref),
                }))
            }
            2 => Ok(Edit::Prototype(PrototypeRow {
                function: self.function_address()?,
                signature: required(optional_text(&form.signature), "Signature")?,
                calling_convention: optional_text(&form.convention),
                return_type: None,
                provenance: FactProvenance { kind: FactKind::Asserted, source: "ui".into(), confidence: None },
            })),
            3 => {
                let ordinal = required(unsigned(&form.stack_ordinal, "Ordinal")?, "Ordinal")?;
                Ok(Edit::Stack(StackVariableRow {
                    function: self.function_address()?,
                    ordinal: u32::try_from(ordinal).map_err(|_| "Ordinal is too large".to_string())?,
                    name: required(optional_text(&form.stack_name), "Name")?,
                    storage: form.stack_storage.trim().to_string(),
                    type_name: optional_text(&form.stack_type),
                    offset: integer(&form.stack_offset)?,
                    size: unsigned(&form.stack_size, "Size")?,
                }))
            }
            _ => Ok(Edit::Propagate),
        }
    }

    fn save(&mut self, cx: &mut PanelContext<'_>, edit: Edit) {
        let program = self.program.clone();
        let (label, kind) = match &edit {
            Edit::Type(_) => ("save type", "type"),
            Edit::Field(_) => ("save type field", "field"),
            Edit::Prototype(_) => ("save prototype", "prototype"),
            Edit::Stack(_) => ("save stack variable", "stack"),
            Edit::Propagate => ("propagate types", "propagate"),
        };
        let task = cx.service.job(label, move |job| {
            let core = job.fork()?;
            let text = |error: romwright_core::CoreError| error.to_string();
            let detail = match edit {
                Edit::Type(row) => core.set_type_def(&program, &row).map(|()| format!("type {} saved", row.name)),
                Edit::Field(row) => core.set_type_field(&program, &row).map(|()| format!("field {}.{} saved", row.type_name, row.field_name)),
                Edit::Prototype(row) => core.set_prototype(&program, &row).map(|()| format!("prototype saved; decompiling {}", address::format(&row.function))),
                Edit::Stack(row) => core.set_stack_variable(&program, &row).map(|()| format!("stack variable {} saved", row.name)),
                Edit::Propagate => core.propagate_type_links(&program).map(|links| format!("{} type links", links.len())),
            }
            .map_err(text)?;
            job.detail(detail.clone());
            Ok(detail)
        });
        self.saves.push((kind.to_string(), task));
    }

    fn submit(&mut self, cx: &mut PanelContext<'_>) {
        match self.build(self.tab) {
            Ok(edit) => {
                self.form.error = None;
                self.save(cx, edit);
            }
            Err(error) => self.form.error = Some(error),
        }
    }

    fn toolbar(&mut self, ui: &mut egui::Ui, cx: &mut PanelContext<'_>) {
        let theme = cx.theme;
        let counts = [
            self.lists.types.len(),
            self.lists.fields.len(),
            self.lists.prototypes.len(),
            self.lists.stack.len(),
            self.lists.links.len(),
        ];
        let labels: Vec<String> = TABS
            .iter()
            .zip(counts)
            .map(|(tab, count)| if self.answered { format!("{tab}  {count}") } else { (*tab).to_string() })
            .collect();
        let label_refs: Vec<&str> = labels.iter().map(String::as_str).collect();
        let mut tab = self.tab;
        let mut propagate = false;
        let mut reload = false;
        let busy = !self.saves.is_empty();
        let has_program = !self.program.is_empty();
        egui::Frame::new().inner_margin(egui::Margin::symmetric(space::SM as i8, space::XS as i8 + 2)).show(ui, |ui| {
            ui.horizontal(|ui| {
                widgets::segmented(ui, theme, &label_refs, &mut tab, &[]);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    reload = widgets::icon_button(ui, theme, widgets::Icon::Refresh, "Reload types", has_program).clicked();
                    propagate = widgets::button(ui, theme, "Propagate types", has_program && !busy)
                        .on_hover_text("Close the type-link graph transitively; propagated links are marked")
                        .clicked();
                    if busy || self.load.is_some() {
                        ui.add(egui::Spinner::new().size(14.0).color(theme.accent));
                    }
                });
            });
        });
        ui.painter().hline(ui.max_rect().x_range(), ui.cursor().top(), egui::Stroke::new(1.0, theme.border));
        if tab != self.tab {
            self.tab = tab;
            self.tab_chosen = true;
            self.form.error = None;
        }
        if propagate {
            self.save(cx, Edit::Propagate);
        }
        if reload {
            self.load(cx);
        }
    }

    fn editor(&mut self, ui: &mut egui::Ui, cx: &mut PanelContext<'_>) {
        let theme = cx.theme;
        let tab = self.tab;
        let current = self.current_function_text();
        let mut save = false;
        egui::ScrollArea::vertical().id_salt("types-editor").auto_shrink([false, false]).show(ui, |ui| {
            egui::Frame::new().inner_margin(egui::Margin::same(space::MD as i8)).show(ui, |ui| {
                ui.set_width(ui.available_width());
                let (title, detail) = match tab {
                    0 => ("Type definition", "Upserts by name."),
                    1 => ("Composite field", "Upserts by type and ordinal."),
                    2 => ("Function prototype", "Saving re-decompiles the function."),
                    3 => ("Stack variable", "Upserts by function and ordinal."),
                    _ => ("Type graph", ""),
                };
                ui.label(RichText::new(title).font(font(Type::Strong)).color(theme.text));
                if !detail.is_empty() {
                    widgets::caption(ui, theme, detail);
                }
                ui.add_space(space::SM);
                let form = &mut self.form;
                let mut entered = false;
                let mut field = |ui: &mut egui::Ui, label: &str, value: &mut String, hint: &str, code: bool| {
                    widgets::caption(ui, theme, label);
                    let response = ui.add(
                        egui::TextEdit::singleline(value)
                            .hint_text(RichText::new(hint).color(theme.text_faint))
                            .font(font(if code { Type::Code } else { Type::Body }))
                            .margin(egui::Margin::symmetric(space::SM as i8, space::XS as i8 + 1))
                            .desired_width(f32::INFINITY),
                    );
                    entered |= response.lost_focus() && ui.input(|input| input.key_pressed(Key::Enter));
                    ui.add_space(space::XS);
                };
                let pair = |ui: &mut egui::Ui, add: &mut dyn FnMut(&mut egui::Ui, usize)| {
                    ui.columns(2, |columns| {
                        for (index, column) in columns.iter_mut().enumerate() {
                            add(column, index);
                        }
                    });
                };
                match tab {
                    0 => {
                        field(ui, "Name", &mut form.name, "struct_name", true);
                        pair(ui, &mut |ui, index| match index {
                            0 => field(ui, "Kind", &mut form.kind, "struct", false),
                            _ => field(ui, "Base type", &mut form.base, "none", true),
                        });
                        field(ui, "Definition", &mut form.definition, "struct { int a; }", true);
                        pair(ui, &mut |ui, index| match index {
                            0 => field(ui, "Size", &mut form.size, "unknown", true),
                            _ => field(ui, "Alignment", &mut form.alignment, "unknown", true),
                        });
                        let mut primitive = form.primitive;
                        let mut elements = std::mem::take(&mut form.elements);
                        pair(ui, &mut |ui, index| match index {
                            0 => {
                                widgets::caption(ui, theme, "Primitive");
                                egui::ComboBox::from_id_salt("types-primitive")
                                    .width(ui.available_width())
                                    .selected_text(primitive_label(PRIMITIVES[primitive]))
                                    .show_ui(ui, |ui| {
                                        for (choice, kind) in PRIMITIVES.iter().enumerate() {
                                            ui.selectable_value(&mut primitive, choice, primitive_label(*kind));
                                        }
                                    });
                            }
                            _ => field(ui, "Elements", &mut elements, "unknown", true),
                        });
                        form.primitive = primitive;
                        form.elements = elements;
                    }
                    1 => {
                        field(ui, "Type", &mut form.field_type, "struct_name", true);
                        pair(ui, &mut |ui, index| match index {
                            0 => field(ui, "Ordinal", &mut form.field_ordinal, "0", true),
                            _ => field(ui, "Name", &mut form.field_name, "field", true),
                        });
                        pair(ui, &mut |ui, index| match index {
                            0 => field(ui, "Offset", &mut form.field_offset, "0x0", true),
                            _ => field(ui, "Size", &mut form.field_size, "unknown", true),
                        });
                        field(ui, "Type ref", &mut form.field_ref, "int", true);
                    }
                    2 => {
                        field(ui, "Function", &mut form.function, if current.is_empty() { "address" } else { current.as_str() }, true);
                        field(ui, "Signature", &mut form.signature, "int f(int a, char *b)", true);
                        field(ui, "Calling convention", &mut form.convention, "default", true);
                    }
                    3 => {
                        field(ui, "Function", &mut form.function, if current.is_empty() { "address" } else { current.as_str() }, true);
                        pair(ui, &mut |ui, index| match index {
                            0 => field(ui, "Name", &mut form.stack_name, "local_10", true),
                            _ => field(ui, "Ordinal", &mut form.stack_ordinal, "0", true),
                        });
                        pair(ui, &mut |ui, index| match index {
                            0 => field(ui, "Storage", &mut form.stack_storage, "stack", true),
                            _ => field(ui, "Type", &mut form.stack_type, "int", true),
                        });
                        pair(ui, &mut |ui, index| match index {
                            0 => field(ui, "Offset", &mut form.stack_offset, "-0x10", true),
                            _ => field(ui, "Size", &mut form.stack_size, "4", true),
                        });
                    }
                    _ => {
                        let nodes = self.lists.nodes;
                        let propagated = self.lists.links.iter().filter(|link| link.provenance == "type-propagation").count();
                        ui.label(RichText::new(format!("{nodes} types  ·  {} links  ·  {propagated} propagated", self.lists.links.len())).font(font(Type::Body)).color(theme.text_muted));
                        ui.add_space(space::SM);
                        widgets::caption(ui, theme, "Propagate types adds transitive links A → C for every A → B → C; propagated links are marked type-propagation.");
                    }
                }
                save = entered;
                if tab < 4 {
                    ui.add_space(space::SM);
                    let label = ["Save type", "Save field", "Save prototype", "Save stack variable"][tab];
                    ui.horizontal(|ui| {
                        save |= widgets::primary_button(ui, theme, label, !self.program.is_empty()).clicked();
                        if widgets::button(ui, theme, "Clear", true).clicked() {
                            let keep = std::mem::take(&mut self.form.function);
                            self.form = Form::default();
                            if tab >= 2 {
                                self.form.function = keep;
                            }
                        }
                    });
                }
                if let Some(error) = &self.form.error {
                    ui.add_space(space::XS);
                    ui.label(RichText::new(error).font(font(Type::Caption)).color(theme.error));
                }
            });
        });
        if save {
            self.submit(cx);
        }
    }

    fn table_ui(&mut self, ui: &mut egui::Ui, cx: &mut PanelContext<'_>) {
        let theme = cx.theme;
        let tab = self.tab;
        let lists = &self.lists;
        let mut navigate = None;
        let syntax = |kind| theme.syntax(kind);
        use crate::theme::Syntax;
        let (footer, columns, rows): (String, &[Column], usize) = match tab {
            0 => (format!("{} types", lists.types.len()), &TYPE_COLUMNS, lists.types.len()),
            1 => (format!("{} fields", lists.fields.len()), &FIELD_COLUMNS, lists.fields.len()),
            2 => (format!("{} prototypes  ·  double-click to go to a function", lists.prototypes.len()), &PROTOTYPE_COLUMNS, lists.prototypes.len()),
            3 => {
                let scope = match (&self.function, self.only_current) {
                    (Some(function), true) => format!("in {}", function.name),
                    _ => "in all functions".into(),
                };
                (format!("{} stack variables {scope}", self.stack_view.len()), &STACK_COLUMNS, self.stack_view.len())
            }
            _ => (format!("{} type links", lists.links.len()), &LINK_COLUMNS, lists.links.len()),
        };
        let stack_view = &self.stack_view;
        let response = table::with_footer(ui, theme, &footer, |ui| {
            if rows == 0 {
                let (title, detail) = match tab {
                    0 => ("No types", "Save type adds a named definition."),
                    1 => ("No fields", "Save field adds a member to a composite type."),
                    2 => ("No prototypes", "Save prototype asserts a function's signature."),
                    3 => ("No stack variables", "This function has no recovered stack variables."),
                    _ => ("No type links", "Type links come from importers and propagation."),
                };
                widgets::empty_state(ui, theme, title, detail);
                return table::TableResponse::default();
            }
            table::show(
                ui,
                theme,
                &format!("types-table-{tab}"),
                columns,
                &mut self.sorts[tab],
                rows,
                &mut self.selected[tab],
                &mut |index, column| match tab {
                    0 => {
                        let row = &lists.types[index];
                        match column {
                            0 => Cell::new(row.name.as_str(), Type::Code, syntax(Syntax::Type)),
                            1 => Cell::muted(theme, row.kind.as_str()),
                            2 => Cell::code(row.definition.as_str(), theme.text),
                            3 => Cell::code(number(row.size), syntax(Syntax::Constant)),
                            4 => Cell::code(number(row.alignment), syntax(Syntax::Constant)),
                            5 => Cell::code(row.base_type.clone().unwrap_or_default(), syntax(Syntax::Type)),
                            6 => Cell::muted(theme, primitive_label(row.primitive)),
                            7 => Cell::code(number(row.element_count), syntax(Syntax::Constant)),
                            _ => Cell::new(row.provenance.as_str(), Type::Caption, theme.text_faint),
                        }
                    }
                    1 => {
                        let row = &lists.fields[index];
                        match column {
                            0 => Cell::new(row.type_name.as_str(), Type::Code, syntax(Syntax::Type)),
                            1 => Cell::code(row.ordinal.to_string(), theme.text_faint),
                            2 => Cell::new(row.field_name.as_str(), Type::Code, syntax(Syntax::Variable)),
                            3 => Cell::code(format!("0x{:x}", row.offset), syntax(Syntax::Constant)),
                            4 => Cell::code(number(row.size), syntax(Syntax::Constant)),
                            _ => Cell::code(row.type_ref.clone().unwrap_or_default(), syntax(Syntax::Type)),
                        }
                    }
                    2 => {
                        let row = &lists.prototypes[index];
                        match column {
                            0 => Cell::address(theme, &row.function),
                            1 => Cell::new(row.signature.as_str(), Type::Code, theme.text),
                            2 => Cell::code(row.calling_convention.clone().unwrap_or_default(), syntax(Syntax::Keyword)),
                            3 => Cell::code(row.return_type.clone().unwrap_or_default(), syntax(Syntax::Type)),
                            _ => Cell::new(provenance_label(&row.provenance), Type::Caption, theme.text_faint)
                                .tooltip(row.provenance.explanation().unwrap_or_default()),
                        }
                    }
                    3 => {
                        let row = &lists.stack[stack_view[index]];
                        match column {
                            0 => Cell::address(theme, &row.function),
                            1 => Cell::code(row.ordinal.to_string(), theme.text_faint),
                            2 => Cell::new(row.name.as_str(), Type::Code, syntax(Syntax::Variable)),
                            3 => Cell::code(row.storage.as_str(), syntax(Syntax::Register)),
                            4 => Cell::code(row.type_name.clone().unwrap_or_default(), syntax(Syntax::Type)),
                            5 => Cell::code(
                                row.offset.map(|offset| if offset < 0 { format!("-0x{:x}", offset.unsigned_abs()) } else { format!("0x{offset:x}") }).unwrap_or_default(),
                                syntax(Syntax::Constant),
                            ),
                            _ => Cell::code(number(row.size), syntax(Syntax::Constant)),
                        }
                    }
                    _ => {
                        let row = &lists.links[index];
                        match column {
                            0 => Cell::new(row.source.as_str(), Type::Code, syntax(Syntax::Type)),
                            1 => Cell::new(row.target.as_str(), Type::Code, syntax(Syntax::Type)),
                            2 => Cell::muted(theme, row.kind.as_str()),
                            _ => Cell::new(row.provenance.as_str(), Type::Caption, theme.text_faint),
                        }
                    }
                },
                &mut |ui, index| {
                    let function = match tab {
                        2 => Some(&lists.prototypes[index].function),
                        3 => Some(&lists.stack[stack_view[index]].function),
                        _ => None,
                    };
                    if let Some(function) = function
                        && ui.button(format!("Go to {}", address::format(function))).clicked()
                    {
                        navigate = Some(function.clone());
                        ui.close();
                    }
                },
            )
        });
        if response.sort_changed {
            self.selected[tab] = None;
            self.sort(tab);
        }
        if let Some(index) = response.clicked {
            self.edit_row(tab, index);
        }
        if let Some(index) = response.activated {
            navigate = match tab {
                2 => self.lists.prototypes.get(index).map(|row| row.function.clone()),
                3 => self.stack_view.get(index).map(|row| self.lists.stack[*row].function.clone()),
                _ => None,
            };
        }
        if let Some(at) = navigate {
            cx.navigate(at, true);
        }
    }

    fn scope_bar(&mut self, ui: &mut egui::Ui, theme: &Theme) {
        if self.tab != 3 {
            return;
        }
        let Some(function) = &self.function else { return };
        let name = function.name.clone();
        let mut toggle = false;
        egui::Frame::new().inner_margin(egui::Margin::symmetric(space::SM as i8, space::XS as i8)).show(ui, |ui| {
            ui.horizontal(|ui| {
                toggle = widgets::chip(ui, theme, &format!("Only {name}"), self.only_current).clicked();
            });
        });
        if toggle {
            self.only_current = !self.only_current;
            self.filter_stack();
        }
    }
}

impl Panel for TypesPanel {
    fn id(&self) -> PanelId {
        ID
    }

    fn title(&self) -> String {
        "Types".into()
    }

    fn open_by_default(&self) -> bool {
        false
    }

    fn on_event(&mut self, event: &ShellEvent, cx: &mut PanelContext<'_>) {
        match event {
            ShellEvent::ProgramChanged => {
                self.form = Form::default();
                self.function = None;
                self.only_current = true;
                self.tab_chosen = false;
                self.answered = false;
                self.selected = [None; 5];
                self.load(cx);
            }
            ShellEvent::FunctionChanged { function, .. } => {
                if function.as_ref().map(|row| &row.entry) != self.function.as_ref().map(|row| &row.entry) {
                    self.function = function.clone();
                    self.form.function.clear();
                    self.filter_stack();
                }
            }
            ShellEvent::RevisionChanged(Change::Types | Change::Undo | Change::Analysis) | ShellEvent::Refresh => self.load(cx),
            _ => {}
        }
    }

    fn poll(&mut self, cx: &mut PanelContext<'_>) {
        if let Some((generation, _)) = &self.load {
            let generation = *generation;
            let mut slot = self.load.take().map(|(_, task)| task);
            match poll_slot(&mut slot) {
                None => self.load = slot.map(|task| (generation, task)),
                Some(_) if generation != self.generation => {}
                Some(Ok(lists)) => {
                    self.lists = lists;
                    if !self.tab_chosen && !self.answered {
                        let lists = &self.lists;
                        let counts = [lists.types.len(), lists.fields.len(), lists.prototypes.len(), lists.stack.len(), lists.links.len()];
                        self.tab = counts.iter().position(|count| *count > 0).unwrap_or(0);
                    }
                    self.answered = true;
                    self.error = None;
                    for tab in 0..TABS.len() {
                        self.sort(tab);
                    }
                    self.filter_stack();
                    self.selected = [None; 5];
                }
                Some(Err(error)) => {
                    cx.error(format!("Types: {error}"));
                    self.error = Some(error);
                    self.answered = true;
                }
            }
        }
        let mut index = 0;
        while index < self.saves.len() {
            let Some(result) = self.saves[index].1.poll() else {
                index += 1;
                continue;
            };
            let (kind, _) = self.saves.remove(index);
            match result {
                Ok(detail) => {
                    cx.status(detail);
                    cx.command(Command::Broadcast(ShellEvent::RevisionChanged(Change::Types)));
                    if kind == "prototype" {
                        cx.command(Command::Decompile);
                    }
                }
                Err(error) => {
                    self.form.error = Some(error.clone());
                    cx.error(error);
                }
            }
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, cx: &mut PanelContext<'_>) {
        let theme = cx.theme;
        self.toolbar(ui, cx);
        if self.program.is_empty() {
            return widgets::empty_state(ui, theme, "No program open", "Choose an image in the toolbar to see its types and prototypes.");
        }
        if !self.answered {
            return widgets::loading(ui, theme, "Loading types…");
        }
        if let Some(error) = &self.error {
            return widgets::empty_state(ui, theme, "Types unavailable", error);
        }
        let rect = ui.available_rect_before_wrap();
        let editor_width = EDITOR_WIDTH.min(rect.width() * 0.45);
        let split = rect.right() - editor_width;
        let table_rect = egui::Rect::from_min_max(rect.min, egui::pos2(split, rect.bottom()));
        let editor_rect = egui::Rect::from_min_max(egui::pos2(split, rect.top()), rect.max);
        ui.painter().rect_filled(editor_rect, egui::CornerRadius::ZERO, theme.bg_raised);
        ui.painter().vline(split, rect.y_range(), egui::Stroke::new(1.0, theme.border));
        let mut table_ui = ui.new_child(egui::UiBuilder::new().max_rect(table_rect).layout(egui::Layout::top_down(egui::Align::Min)));
        self.scope_bar(&mut table_ui, theme);
        self.table_ui(&mut table_ui, cx);
        let mut editor_ui = ui.new_child(egui::UiBuilder::new().max_rect(editor_rect.shrink2(egui::vec2(1.0, 0.0))).layout(egui::Layout::top_down(egui::Align::Min)));
        self.editor(&mut editor_ui, cx);
        ui.allocate_rect(rect, egui::Sense::hover());
    }

    fn busy(&self) -> bool {
        self.load.is_some() || !self.saves.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_accept_decimal_hex_and_negative_offsets() {
        assert_eq!(integer(""), Ok(None));
        assert_eq!(integer("12"), Ok(Some(12)));
        assert_eq!(integer("0x10"), Ok(Some(16)));
        assert_eq!(integer("-0x18"), Ok(Some(-24)));
        assert!(integer("ten").is_err());
        assert!(unsigned("-1", "Size").is_err());
    }

    #[test]
    fn prototype_requires_a_function() {
        let mut panel = TypesPanel::default();
        panel.form.signature = "int f(void)".into();
        assert!(panel.build(2).is_err());
        panel.form.function = "0x401000".into();
        match panel.build(2) {
            Ok(Edit::Prototype(row)) => assert_eq!(row.function, Address::ram(0x401000)),
            _ => panic!("expected a prototype"),
        }
    }
}
