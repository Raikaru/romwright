//! Program setup (Qt "Program & annotations" dock): project/program/binary,
//! native import, open-by-name, `new-project` for the open image, and the
//! rename/comment/undo commands for the cursor. Editing these fields alone
//! never changes the active image.

use crate::address;
use crate::panel::{Command, Panel, PanelContext, PanelId, Placement, ShellEvent};
use crate::projects::{self, NewProjectReport, NewProjectRequest};
use crate::service::{Task, poll_slot};
use crate::theme::{Type, font, space};
use crate::widgets;
use egui::RichText;
use std::path::PathBuf;

pub const ID: PanelId = "setup";

#[derive(Default)]
pub struct SetupPanel {
    program: String,
    binary: String,
    name: String,
    comment: String,
    kind: String,
    /// `new-project`: the repository to write, its `--name`, `--platform` and `--decompile`.
    outdir: String,
    /// The default `outdir` last derived from the open program.
    derived_outdir: String,
    project_name: String,
    platform: String,
    decompile: String,
    creating: Option<Task<NewProjectReport>>,
    created: Option<Result<NewProjectReport, String>>,
    creations: u64,
}

impl SetupPanel {
    pub fn new(program: &str, binary: &str) -> Self {
        Self {
            program: program.to_string(),
            binary: binary.to_string(),
            kind: "eol".into(),
            decompile: "none".into(),
            ..Self::default()
        }
    }

    /// `new-project` has answered (written or failed) this many times.
    pub fn creations_finished(&self) -> u64 {
        self.creations
    }

    /// The last `new-project` answer.
    pub fn last_creation(&self) -> Option<&Result<NewProjectReport, String>> {
        self.created.as_ref()
    }

    pub fn set_outdir(&mut self, outdir: String) {
        self.outdir = outdir;
    }

    /// `new-project` on the image in the Binary field (the open program's
    /// binary unless edited), written to the Output directory.
    pub fn create_project(&mut self, cx: &mut PanelContext<'_>) {
        let image = PathBuf::from(self.binary.trim());
        let outdir = PathBuf::from(self.outdir.trim());
        if image.as_os_str().is_empty() || outdir.as_os_str().is_empty() {
            cx.error("New project needs an image and an output directory");
            return;
        }
        let request = NewProjectRequest {
            image,
            program: cx.session.program.clone(),
            outdir,
            name: self.project_name.clone(),
            platform: self.platform.clone(),
            decompile: self.decompile.clone(),
            staging: cx.session.project.join("staging"),
        };
        self.created = None;
        self.creating = Some(cx.service.job("new project", move |job| {
            let report = projects::run_new_project(job, &request)?;
            job.detail(format!("{}\n{}", report.summary, report.next));
            Ok(report)
        }));
    }
}

fn field(ui: &mut egui::Ui, theme: &crate::theme::Theme, label: &str, value: &mut String, hint: &str, editable: bool) {
    widgets::caption(ui, theme, label);
    ui.add_enabled(
        editable,
        egui::TextEdit::singleline(value)
            .hint_text(RichText::new(hint).color(theme.text_faint))
            .font(font(Type::Body))
            .margin(egui::Margin::symmetric(space::SM as i8, space::XS as i8 + 1))
            .desired_width(f32::INFINITY),
    );
    ui.end_row();
}

impl Panel for SetupPanel {
    fn id(&self) -> PanelId {
        ID
    }

    fn title(&self) -> String {
        "Program setup".into()
    }

    fn placement(&self) -> Placement {
        Placement::Bottom
    }

    fn open_by_default(&self) -> bool {
        false
    }

    fn on_event(&mut self, event: &ShellEvent, cx: &mut PanelContext<'_>) {
        if let ShellEvent::ProgramChanged = event {
            self.program = cx.session.program.clone();
            self.binary = cx.session.binary.display().to_string();
            // A directory beside the project store named for the program, replaced
            // while the field still holds the previous program's default.
            if !cx.session.program.is_empty() && (self.outdir.is_empty() || self.outdir == self.derived_outdir) {
                let parent = cx.session.project.parent().map(PathBuf::from).unwrap_or_default();
                self.derived_outdir = parent.join(format!("{}-project", cx.session.program)).display().to_string();
                self.outdir = self.derived_outdir.clone();
            }
        }
    }

    fn poll(&mut self, cx: &mut PanelContext<'_>) {
        let Some(result) = poll_slot(&mut self.creating) else { return };
        self.creations += 1;
        match &result {
            Ok(report) => {
                cx.status(format!("New project written to {}", report.outdir.display()));
                cx.command(Command::Broadcast(ShellEvent::ProjectCreated { root: report.outdir.clone() }));
            }
            Err(error) => cx.error(format!("New project: {error}")),
        }
        self.created = Some(result);
    }

    fn busy(&self) -> bool {
        self.creating.is_some()
    }

    fn ui(&mut self, ui: &mut egui::Ui, cx: &mut PanelContext<'_>) {
        let theme = cx.theme;
        let cursor = cx.session.address.clone();
        let mut create = false;
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            egui::Frame::new().inner_margin(egui::Margin::same(space::LG as i8)).show(ui, |ui| {
                egui::Grid::new("setup-grid")
                    .num_columns(2)
                    .spacing([space::MD, space::SM])
                    .min_col_width(84.0)
                    .striped(false)
                    .show(ui, |ui| {
                        let mut project = cx.session.project.display().to_string();
                        field(ui, theme, "Project", &mut project, "", false);
                        field(ui, theme, "Program", &mut self.program, "name", true);
                        field(ui, theme, "Binary", &mut self.binary, "path to a binary to import", true);
                        ui.label("");
                        ui.horizontal(|ui| {
                            if widgets::primary_button(ui, theme, "Import native", !self.binary.trim().is_empty() && !self.program.trim().is_empty()).clicked() {
                                cx.command(Command::ImportNative {
                                    binary: PathBuf::from(self.binary.trim()),
                                    name: self.program.trim().to_string(),
                                });
                            }
                            if widgets::button(ui, theme, "Open program", !self.program.trim().is_empty()).clicked() {
                                cx.command(Command::OpenProgram(self.program.trim().to_string()));
                            }
                        });
                        ui.end_row();
                    });
                ui.add_space(space::LG);
                ui.label(RichText::new("New project  ·  from the Binary above").font(font(Type::Strong)).color(theme.text));
                ui.add_space(space::SM);
                egui::Grid::new("new-project-grid")
                    .num_columns(2)
                    .spacing([space::MD, space::SM])
                    .min_col_width(84.0)
                    .striped(false)
                    .show(ui, |ui| {
                        field(ui, theme, "Output", &mut self.outdir, "directory the repository is written to", true);
                        field(ui, theme, "Name", &mut self.project_name, "optional project name", true);
                        field(ui, theme, "Platform", &mut self.platform, "detected from the image; 3ds, switch, ps3, ps4, vita, x360... to force", true);
                        field(ui, theme, "Decompile", &mut self.decompile, "none, all, first:N or ADDR,ADDR", true);
                        ui.label("");
                        let enabled = self.creating.is_none() && !self.binary.trim().is_empty() && !self.outdir.trim().is_empty();
                        create = widgets::primary_button(ui, theme, "Create project", enabled)
                            .on_hover_text("romwright-cli new-project: a repository of retail-matching units (or the non-matching scaffold)")
                            .clicked();
                        ui.end_row();
                    });
                match (&self.creating, &self.created) {
                    (Some(_), _) => {
                        ui.add_space(space::SM);
                        ui.label(RichText::new("Importing and writing the repository…").font(font(Type::Caption)).color(theme.text_muted));
                    }
                    (None, Some(Ok(report))) => {
                        ui.add_space(space::SM);
                        ui.add(egui::Label::new(RichText::new(format!("{}\n{}", report.summary, report.next)).font(font(Type::CodeSmall)).color(theme.text_muted)).selectable(true));
                    }
                    (None, Some(Err(error))) => {
                        ui.add_space(space::SM);
                        ui.add(egui::Label::new(RichText::new(error).font(font(Type::CodeSmall)).color(theme.error)).selectable(true));
                    }
                    (None, None) => {}
                }
                ui.add_space(space::LG);
                let target = cursor.as_ref().map(address::format).unwrap_or_else(|| "no cursor".into());
                ui.label(RichText::new(format!("Annotate  ·  {target}")).font(font(Type::Strong)).color(theme.text));
                ui.add_space(space::SM);
                egui::Grid::new("annotate-grid")
                    .num_columns(2)
                    .spacing([space::MD, space::SM])
                    .min_col_width(84.0)
                    .striped(false)
                    .show(ui, |ui| {
                        field(ui, theme, "Rename", &mut self.name, "new function name", true);
                        ui.label("");
                        ui.horizontal(|ui| {
                            let enabled = cursor.is_some() && !self.name.trim().is_empty();
                            if widgets::button(ui, theme, "Apply rename", enabled).clicked()
                                && let Some(address) = cursor.clone()
                            {
                                cx.command(Command::RenameFunction { address, name: Some(self.name.trim().to_string()) });
                            }
                            if widgets::button(ui, theme, "Undo", !cx.session.program.is_empty()).clicked() {
                                cx.command(Command::Undo);
                            }
                        });
                        ui.end_row();
                        field(ui, theme, "Comment", &mut self.comment, "comment text", true);
                        field(ui, theme, "Kind", &mut self.kind, "eol, pre, post, plate", true);
                        ui.label("");
                        if widgets::button(ui, theme, "Apply comment", cursor.is_some()).clicked()
                            && let Some(address) = cursor.clone()
                        {
                            cx.command(Command::Comment { address, kind: self.kind.trim().to_string(), text: self.comment.clone() });
                        }
                        ui.end_row();
                    });
            });
        });
        if create {
            self.create_project(cx);
        }
    }
}
