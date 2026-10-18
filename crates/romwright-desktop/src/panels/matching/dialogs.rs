//! Matching dialogs (Qt `matching_dock_dialogs.cpp`): the new-workspace
//! form, the typed JSON contract editor every advanced operation shares,
//! path prompts (in place of native file pickers), private-input selection
//! for imports, and the apply confirmation.

use crate::theme::{Theme, Type, font, space};
use crate::widgets;
use egui::{Align, Layout, RichText};
use serde_json::{Value, json};
use std::path::Path;

/// Where an accepted JSON editor sends its value.
#[derive(Clone, Debug)]
pub enum JsonPurpose {
    /// A complete `MatchingOperation` (calibrate, context, explicit search).
    Operation,
    /// A complete `WorkspaceSetup` ("Use complete setup JSON…").
    Setup,
    /// A new profile appended to `spec.profiles`.
    Profile { spec: Value },
    /// The project binding stored as `spec.project`.
    Project { spec: Value },
    /// Import bindings around the bundle being imported.
    ImportBindings,
}

#[derive(Clone, Debug)]
pub enum PathPurpose {
    Export,
    Import,
    /// Project root plus the fresh build output (Qt directory picker, then
    /// `QInputDialog`).
    ProjectRoot { spec: Value },
}

#[derive(Clone, Debug)]
pub enum Dialog {
    NewWorkspace(NewWorkspaceForm),
    Json {
        title: String,
        explanation: String,
        text: String,
        error: String,
        purpose: JsonPurpose,
        /// The form to return to on Cancel (advanced setup).
        back: Option<Box<NewWorkspaceForm>>,
    },
    Path {
        title: String,
        explanation: String,
        path: String,
        /// An optional second field: (label, value).
        second: Option<(String, String)>,
        error: String,
        purpose: PathPurpose,
    },
    /// Digests a bundle needs but does not carry; paths are one per line
    /// (directories contribute their files).
    PrivateInputs { missing: Vec<String>, paths: String },
    /// "Verify & apply" confirmation naming the project root.
    Confirm { root: String },
}

impl Dialog {
    pub fn json(title: &str, explanation: &str, initial: &Value, purpose: JsonPurpose) -> Self {
        Dialog::Json {
            title: title.into(),
            explanation: explanation.into(),
            text: serde_json::to_string_pretty(initial).unwrap_or_default(),
            error: String::new(),
            purpose,
            back: None,
        }
    }

    pub fn path(title: &str, explanation: &str, path: &str, purpose: PathPurpose) -> Self {
        Dialog::Path { title: title.into(), explanation: explanation.into(), path: path.into(), second: None, error: String::new(), purpose }
    }

    /// The JSON editor's text (Qt `matchingJsonEditor`).
    pub fn json_text(&mut self) -> Option<&mut String> {
        match self {
            Dialog::Json { text, .. } => Some(text),
            _ => None,
        }
    }
}

/// Qt `createWorkspaceDialog` fields.
#[derive(Clone, Debug)]
pub struct NewWorkspaceForm {
    pub name: String,
    pub symbol: String,
    pub target: String,
    pub source: String,
    pub root: String,
    /// 0 = Clang / GCC, 1 = MWCC through a user-owned wrapper.
    pub preset: usize,
    pub compiler: String,
    pub wrapped: String,
    pub flags: String,
    pub public_source: bool,
    pub public_target: bool,
    pub error: String,
}

const PRESETS: [&str; 2] = ["Clang / GCC", "MWCC through a user-owned wrapper"];
const SOURCE_PATTERNS: [&str; 9] = ["h", "hpp", "hxx", "hh", "inc", "c", "cc", "cpp", "cxx"];
const MAX_INPUTS: usize = 4096;

fn file_input(path: &str, public_bytes: bool) -> Value {
    json!({ "kind": "path", "path": path, "redistributable": public_bytes })
}

fn collect_sources(root: &Path, directory: &Path, files: &mut serde_json::Map<String, Value>) -> Result<(), String> {
    let entries = std::fs::read_dir(directory).map_err(|error| format!("Cannot read {}: {error}", directory.display()))?;
    let mut entries: Vec<_> = entries.flatten().collect();
    entries.sort_by_key(|entry| entry.path());
    for entry in entries {
        let path = entry.path();
        let kind = entry.file_type().map_err(|error| error.to_string())?;
        if kind.is_symlink() {
            continue;
        }
        if kind.is_dir() {
            collect_sources(root, &path, files)?;
        } else if path.extension().and_then(|extension| extension.to_str()).is_some_and(|extension| SOURCE_PATTERNS.contains(&extension)) {
            let relative = path.strip_prefix(root).map_err(|error| error.to_string())?;
            files.insert(portable_name(relative), file_input(&path.display().to_string(), false));
            if files.len() > MAX_INPUTS {
                return Err("Too many inputs: choose a smaller root or an explicit setup JSON (maximum 4096 files).".into());
            }
        }
    }
    Ok(())
}

fn absolute(path: &str) -> std::path::PathBuf {
    let path = Path::new(path);
    if path.is_absolute() { path.to_path_buf() } else { std::env::current_dir().unwrap_or_default().join(path) }
}

/// A project-relative file name as a workspace setup spells it: components
/// joined with `/` on every platform (a Windows path would give `include\types.h`).
fn portable_name(relative: &Path) -> String {
    relative.components().map(|part| part.as_os_str().to_string_lossy()).collect::<Vec<_>>().join("/")
}

impl NewWorkspaceForm {
    pub fn new(clang: String) -> Self {
        Self {
            name: String::new(),
            symbol: String::new(),
            target: String::new(),
            source: String::new(),
            root: String::new(),
            preset: 0,
            compiler: clang,
            wrapped: String::new(),
            flags: "[\"-O2\"]".into(),
            public_source: false,
            public_target: false,
            error: String::new(),
        }
    }

    fn set_preset(&mut self, preset: usize) {
        self.preset = preset;
        self.compiler = super::find_executable(if preset == 1 { "wibo" } else { "clang" });
        self.flags = if preset == 1 {
            "[\"-nodefaults\",\"-proc\",\"gekko\",\"-O4,p\",\"-nosyspath\"]".into()
        } else {
            "[\"-O2\"]".into()
        };
    }

    /// Qt `build_setup`: the `WorkspaceSetup` JSON, or the warning text.
    pub fn build(&self) -> Result<Value, String> {
        if self.name.trim().is_empty() || self.symbol.trim().is_empty() || self.target.is_empty() || self.source.is_empty() || self.compiler.is_empty() {
            return Err("Name, linker symbol, source, reference object and compiler are required.".into());
        }
        let flags: Value = serde_json::from_str(&self.flags).map_err(|_| "Invalid flags: use a JSON array of individual argument strings.".to_string())?;
        let Some(flags) = flags.as_array() else {
            return Err("Invalid flags: use a JSON array of individual argument strings.".into());
        };
        if flags.iter().any(|flag| !flag.is_string()) {
            return Err("Invalid flag: each argument must be a string.".into());
        }
        if self.preset == 1 && self.wrapped.is_empty() {
            return Err("Missing tool: choose the user-owned MWCC executable.".into());
        }
        let source_path = absolute(&self.source);
        let mut source_name = source_path.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default();
        let mut files = serde_json::Map::new();
        if !self.root.is_empty() {
            let root = absolute(&self.root);
            source_name = portable_name(
                source_path
                    .strip_prefix(&root)
                    .map_err(|_| "Source outside root: choose a root containing the primary source.".to_string())?,
            );
            collect_sources(&root, &root, &mut files)?;
        }
        files.insert(source_name.clone(), file_input(&source_path.display().to_string(), self.public_source));
        let mut arguments = Vec::new();
        let mut tools = serde_json::Map::new();
        let version = if self.wrapped.is_empty() {
            json!(["--version"])
        } else {
            arguments.push(json!("{tool:compiler}"));
            tools.insert("compiler".into(), json!({ "path": self.wrapped, "digest": "" }));
            json!(["{tool:compiler}", "-version"])
        };
        arguments.extend(flags.iter().cloned());
        arguments.extend(["-c", "{source}", "-o", "{output}"].map(Value::from));
        Ok(json!({
            "name": self.name,
            "symbol": self.symbol,
            "source": source_name,
            "files": files,
            "target": file_input(&self.target, self.public_target),
            "profiles": [{
                "name": "default",
                "recipe": { "compiler": self.compiler, "arguments": [], "environment": {} },
                "compile_arguments": arguments,
                "version_arguments": version,
                "tools": tools,
            }],
        }))
    }
}

/// What the analyst did in a dialog this frame.
pub enum Choice {
    None,
    Accept,
    Reject,
    /// New-workspace form: "Use complete setup JSON…".
    Advanced,
}

fn field(ui: &mut egui::Ui, theme: &Theme, label: &str, value: &mut String, hint: &str) {
    widgets::caption(ui, theme, label);
    ui.add(
        egui::TextEdit::singleline(value)
            .font(font(Type::Code))
            .hint_text(RichText::new(hint).color(theme.text_faint))
            .margin(egui::Margin::symmetric(space::SM as i8, space::XS as i8 + 1))
            .desired_width(f32::INFINITY),
    );
    ui.end_row();
}

fn heading(ui: &mut egui::Ui, theme: &Theme, title: &str, explanation: &str) {
    ui.label(RichText::new(title).font(font(Type::Title)).color(theme.text));
    if !explanation.is_empty() {
        ui.add_space(space::XS);
        ui.add(egui::Label::new(RichText::new(explanation).font(font(Type::Body)).color(theme.text_muted)).wrap());
    }
    ui.add_space(space::MD);
}

fn error_line(ui: &mut egui::Ui, theme: &Theme, error: &str) {
    if !error.is_empty() {
        ui.add_space(space::XS);
        ui.add(egui::Label::new(RichText::new(error).font(font(Type::Body)).color(theme.error)).wrap());
    }
}

/// OK/Cancel row, right-aligned; `extra` adds left-side controls.
fn buttons(ui: &mut egui::Ui, theme: &Theme, ok: &str, enabled: bool, choice: &mut Choice, extra: impl FnOnce(&mut egui::Ui, &mut Choice)) {
    ui.add_space(space::MD);
    ui.horizontal(|ui| {
        extra(ui, choice);
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if widgets::primary_button(ui, theme, ok, enabled).clicked() {
                *choice = Choice::Accept;
            }
            if widgets::button(ui, theme, "Cancel", true).clicked() {
                *choice = Choice::Reject;
            }
        });
    });
}

/// Draws `dialog` as a modal and returns what the analyst chose.
pub fn show(dialog: &mut Dialog, context: &egui::Context, theme: &Theme) -> Choice {
    let mut choice = Choice::None;
    let id = egui::Id::new("matching-dialog");
    let response = egui::Modal::new(id).show(context, |ui| match dialog {
        Dialog::NewWorkspace(form) => {
            ui.set_width(720.0);
            heading(ui, theme, "New matching workspace", "");
            egui::Grid::new("matching-setup").num_columns(2).spacing([space::MD, space::SM]).show(ui, |ui| {
                field(ui, theme, "Workspace name", &mut form.name, "e.g. player update");
                field(ui, theme, "Exact object/linker symbol", &mut form.symbol, "symbol as the object names it");
                field(ui, theme, "Reference object", &mut form.target, "/path/to/reference.o");
                field(ui, theme, "Candidate source", &mut form.source, "/path/to/unit.c");
                field(ui, theme, "Source/header root (optional)", &mut form.root, "directory captured with relative paths");
                widgets::caption(ui, theme, "Invocation shape");
                let mut preset = form.preset;
                egui::ComboBox::from_id_salt("matching-preset")
                    .width(320.0)
                    .selected_text(RichText::new(PRESETS[preset]).font(font(Type::Body)))
                    .show_ui(ui, |ui| {
                        for (index, label) in PRESETS.iter().enumerate() {
                            ui.selectable_value(&mut preset, index, RichText::new(*label).font(font(Type::Body)));
                        }
                    });
                if preset != form.preset {
                    form.set_preset(preset);
                }
                ui.end_row();
                field(ui, theme, "Compiler / wrapper", &mut form.compiler, "executable path");
                field(ui, theme, "Wrapped compiler executable", &mut form.wrapped, "MWCC only: the user-owned mwcceppc.exe");
                widgets::caption(ui, theme, "Compiler flags (JSON argv)");
                ui.add(
                    egui::TextEdit::multiline(&mut form.flags)
                        .font(font(Type::Code))
                        .desired_rows(2)
                        .margin(egui::Margin::symmetric(space::SM as i8, space::XS as i8 + 1))
                        .desired_width(f32::INFINITY),
                );
                ui.end_row();
                ui.label("");
                ui.vertical(|ui| {
                    ui.checkbox(&mut form.public_source, RichText::new("I may redistribute this source file").font(font(Type::Body)));
                    ui.checkbox(&mut form.public_target, RichText::new("I may redistribute this reference object").font(font(Type::Body)));
                });
                ui.end_row();
            });
            ui.add_space(space::SM);
            ui.add(
                egui::Label::new(
                    RichText::new(
                        "Headers stay private. Compiler/wrapper binaries are never bundled. The optional root captures C/C++ headers and sources with their relative paths; add other inputs through a workspace setup JSON when needed.",
                    )
                    .font(font(Type::Caption))
                    .color(theme.text_faint),
                )
                .wrap(),
            );
            error_line(ui, theme, &form.error);
            buttons(ui, theme, "Create", true, &mut choice, |ui, choice| {
                if widgets::button(ui, theme, "Use complete setup JSON…", true).clicked() {
                    *choice = Choice::Advanced;
                }
            });
        }
        Dialog::Json { title, explanation, text, error, .. } => {
            ui.set_width(820.0);
            heading(ui, theme, title, explanation);
            egui::Frame::new()
                .fill(theme.bg_code)
                .stroke(egui::Stroke::new(1.0, theme.border))
                .corner_radius(egui::CornerRadius::same(crate::theme::metrics::RADIUS))
                .inner_margin(egui::Margin::same(space::XS as i8))
                .show(ui, |ui| {
                    egui::ScrollArea::both().max_height(420.0).auto_shrink([false, true]).show(ui, |ui| {
                        let theme = theme.clone();
                        let mut layouter = move |ui: &egui::Ui, buffer: &dyn egui::TextBuffer, _wrap: f32| {
                            let job = super::text::json_job(buffer.as_str(), &theme);
                            ui.fonts_mut(|fonts| fonts.layout_job(job))
                        };
                        ui.add(
                            egui::TextEdit::multiline(text)
                                .code_editor()
                                .frame(egui::Frame::NONE)
                                .desired_rows(18)
                                .desired_width(f32::INFINITY)
                                .layouter(&mut layouter),
                        );
                    });
                });
            error_line(ui, theme, error);
            buttons(ui, theme, "OK", true, &mut choice, |_, _| {});
        }
        Dialog::Path { title, explanation, path, second, error, purpose } => {
            ui.set_width(560.0);
            heading(ui, theme, title, explanation);
            let (label, hint) = match purpose {
                PathPurpose::Export => ("Save as", "/path/to/workspace.json"),
                PathPurpose::Import => ("Workspace file", "/path/to/workspace.json"),
                PathPurpose::ProjectRoot { .. } => ("Project root", "/path/to/project"),
            };
            egui::Grid::new("matching-path").num_columns(2).spacing([space::MD, space::SM]).show(ui, |ui| {
                field(ui, theme, label, path, hint);
                if let Some((label, value)) = second {
                    field(ui, theme, label, value, "project-relative object, e.g. build/unit.o");
                }
            });
            error_line(ui, theme, error);
            buttons(ui, theme, "OK", true, &mut choice, |_, _| {});
        }
        Dialog::PrivateInputs { missing, paths } => {
            ui.set_width(640.0);
            heading(
                ui,
                theme,
                &format!("Select user-owned private inputs ({} digests missing)", missing.len()),
                "The bundle names these inputs without carrying their bytes. List local files (one per line, or a directory to search); only files whose SHA-256 matches a missing digest are used.",
            );
            egui::ScrollArea::vertical().max_height(120.0).show(ui, |ui| {
                for digest in missing.iter() {
                    ui.label(RichText::new(digest).font(font(Type::CodeSmall)).color(theme.text_muted));
                }
            });
            ui.add_space(space::SM);
            ui.add(
                egui::TextEdit::multiline(paths)
                    .font(font(Type::Code))
                    .desired_rows(5)
                    .hint_text(RichText::new("/path/to/private/unit.c").color(theme.text_faint))
                    .desired_width(f32::INFINITY),
            );
            buttons(ui, theme, "Use these files", !paths.trim().is_empty(), &mut choice, |_, _| {});
        }
        Dialog::Confirm { root } => {
            ui.set_width(520.0);
            heading(
                ui,
                theme,
                "Verify and apply reviewed source",
                &format!(
                    "Rebuild the baseline and candidate in isolation, check regressions and scope, then apply only the reviewed source patch to:\n{root}\n\nBuild outputs are not copied back. Review the complete diff first."
                ),
            );
            buttons(ui, theme, "Verify & apply", true, &mut choice, |_, _| {});
        }
    });
    if matches!(choice, Choice::None) && response.should_close() {
        choice = Choice::Reject;
    }
    choice
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_builds_the_qt_setup_shape() {
        let directory = std::env::temp_dir().join(format!("romwright-matching-form-{}", std::process::id()));
        std::fs::create_dir_all(directory.join("include")).unwrap();
        std::fs::write(directory.join("unit.c"), "int f(void){return 1;}").unwrap();
        std::fs::write(directory.join("include/types.h"), "typedef int s32;").unwrap();
        std::fs::write(directory.join("notes.txt"), "ignored").unwrap();
        let mut form = NewWorkspaceForm::new("/usr/bin/clang".into());
        assert!(form.build().is_err(), "required fields are enforced");
        form.name = "w".into();
        form.symbol = "f".into();
        form.target = "/tmp/target.o".into();
        form.source = directory.join("unit.c").display().to_string();
        form.root = directory.display().to_string();
        let setup = form.build().unwrap();
        assert_eq!(setup["source"], "unit.c");
        let files = setup["files"].as_object().unwrap();
        assert!(files.contains_key("include/types.h") && files.contains_key("unit.c") && !files.contains_key("notes.txt"));
        assert_eq!(setup["profiles"][0]["compile_arguments"], json!(["-O2", "-c", "{source}", "-o", "{output}"]));
        assert_eq!(setup["profiles"][0]["version_arguments"], json!(["--version"]));
        serde_json::from_value::<romwright_model::matching::WorkspaceSetup>(setup).unwrap();
        form.flags = "[1]".into();
        assert!(form.build().is_err(), "non-string flags are refused");
        let _ = std::fs::remove_dir_all(directory);
    }
}
