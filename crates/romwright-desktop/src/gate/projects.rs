//! `--gate --project-image IMAGE`: the two project features of the shell.
//!
//! The image (a Windows PE32 such as `tests/fixtures-src/tiny_pe32.exe`: the
//! one retail-format image whose `new-project` needs no downloaded
//! toolchain to be written) is imported as a second program and opened like
//! an analyst would: Program setup's **Create project** runs
//! `romwright-cli new-project` on the open image and writes the repository
//! (`ui.new_project.*`); the repository is then given the host's `clang` as
//! its compile check (its own `configure.py --no-fetch` with a
//! `toolchain.local.json` profile, the way docs/pc-project.md describes) and
//! the Match panel runs `match` on the largest function of the open program,
//! showing the variant table (`ui.match.*`). Every metric is read back from
//! the panels' own state after the frames that paint it, not from the job.

use crate::app::DesktopApp;
use crate::headless::Driver;
use crate::panels::{match_search, setup};
use crate::service::Task;
use romwright_model::{FunctionRow, Page};
use serde_json::{Map, Value, json};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

/// Variants besides the stock one: enough for a table, short for a gate.
const BUDGET: &str = "6";

enum Step {
    Import(Task<()>),
    Switch,
    Create { base: u64 },
    Largest(Task<Page<FunctionRow>>),
    Select(FunctionRow),
    Match { base: u64 },
}

pub struct ProjectsGate {
    program: String,
    outdir: PathBuf,
    step: Step,
    started: Instant,
}

fn ms(started: Instant) -> Value {
    json!(started.elapsed().as_secs_f64() * 1000.0)
}

/// The host compiler the repository's compile check uses: `$CLANG`, else the first `clang` on `PATH`.
fn find_clang() -> Result<PathBuf, String> {
    if let Some(path) = std::env::var_os("CLANG").map(PathBuf::from).filter(|path| path.is_file()) {
        return Ok(path);
    }
    let name = format!("clang{}", std::env::consts::EXE_SUFFIX);
    std::env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| std::env::split_paths(&paths).collect::<Vec<_>>())
        .map(|directory| directory.join(&name))
        .find(|candidate| candidate.is_file())
        .ok_or_else(|| "the project gate compiles with the host's clang: set CLANG or put clang on PATH".to_string())
}

/// `python3 configure.py --no-fetch` with `clang` as the compiler: writes `build/config.json`.
fn configure(outdir: &Path) -> Result<(), String> {
    let clang = find_clang()?;
    let manifest: Value = serde_json::from_str(
        &std::fs::read_to_string(outdir.join("config/toolchain.json")).map_err(|error| format!("config/toolchain.json: {error}"))?,
    )
    .map_err(|error| format!("config/toolchain.json: {error}"))?;
    let tool = manifest["tools"]
        .as_array()
        .and_then(|tools| tools.iter().filter_map(|tool| tool["id"].as_str()).find(|id| id.starts_with("clang")))
        .ok_or("config/toolchain.json pins no clang")?
        .to_string();
    std::fs::write(outdir.join("config/toolchain.local.json"), json!({ "clang": clang }).to_string())
        .map_err(|error| format!("config/toolchain.local.json: {error}"))?;
    let output = Command::new("python3")
        .args(["configure.py", "--no-fetch", "--compiler", &tool])
        .current_dir(outdir)
        .output()
        .map_err(|error| format!("python3 configure.py: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!("configure.py failed ({}): {}", output.status, String::from_utf8_lossy(&output.stderr).trim()))
    }
}

impl ProjectsGate {
    /// Imports `image` as its own program.
    pub fn start(app: &mut DesktopApp, image: PathBuf) -> Self {
        let program = "project_image".to_string();
        let outdir = app.session().project.with_file_name("project-image-repository");
        let binary = image;
        let name = program.clone();
        let step = Step::Import(app.service().job("native import", move |job| {
            let core = job.fork()?;
            core.import_native(&binary, &name).map(drop).map_err(|error| error.to_string())
        }));
        Self { program, outdir, step, started: Instant::now() }
    }

    /// Advances one poll; `Some` ends the gate.
    pub fn step(&mut self, app: &mut DesktopApp, driver: &mut Driver, metrics: &mut Map<String, Value>) -> Option<Result<(), String>> {
        let step = std::mem::replace(&mut self.step, Step::Switch);
        self.step = match step {
            Step::Import(task) => match task.poll() {
                None => Step::Import(task),
                Some(Err(error)) => return Some(Err(format!("project image import: {error}"))),
                Some(Ok(())) => {
                    app.switch_program(&self.program);
                    Step::Switch
                }
            },
            Step::Switch => {
                let session = app.session();
                if session.program == self.program && !session.binary.as_os_str().is_empty() {
                    // The open image: the Binary field holds the program's artifact copy.
                    let outdir = self.outdir.display().to_string();
                    let base = app.with_panel::<setup::SetupPanel, _>(setup::ID, |panel, cx| {
                        panel.set_outdir(outdir);
                        let base = panel.creations_finished();
                        panel.create_project(cx);
                        base
                    });
                    self.started = Instant::now();
                    match base {
                        Some(base) => Step::Create { base },
                        None => return Some(Err("program setup panel is not registered".into())),
                    }
                } else {
                    Step::Switch
                }
            }
            Step::Create { base } => {
                let answered = app.with_panel::<setup::SetupPanel, _>(setup::ID, |panel, _| {
                    (panel.creations_finished() > base).then(|| panel.last_creation().cloned())
                });
                match answered.flatten() {
                    None => Step::Create { base },
                    Some(None) => return Some(Err("new project answered without a result".into())),
                    Some(Some(Err(error))) => return Some(Err(format!("new project: {error}"))),
                    Some(Some(Ok(report))) => {
                        let readme = report.outdir.join("README.md").is_file();
                        let project = report.outdir.join("config/project.json").is_file();
                        let logged = app.service().jobs().snapshot().iter().any(|entry| entry.label == "new project" && entry.state == crate::jobs::JobState::Succeeded);
                        metrics.insert("ui.new_project.ms".into(), ms(self.started));
                        metrics.insert("ui.new_project.files".into(), json!(report.files));
                        metrics.insert("ui.new_project.readme".into(), json!(readme));
                        metrics.insert("ui.new_project.config".into(), json!(project));
                        metrics.insert("ui.new_project.job_logged".into(), json!(logged));
                        // The repository is named for the program, not for the artifact copy's content hash.
                        let recorded = std::fs::read_to_string(report.outdir.join("config/project.json"))
                            .ok()
                            .and_then(|text| serde_json::from_str::<Value>(&text).ok())
                            .and_then(|project| project["image"]["file"].as_str().map(str::to_string));
                        metrics.insert("ui.new_project.image".into(), json!(recorded));
                        if recorded.as_deref() != Some(self.program.as_str()) {
                            return Some(Err(format!("the repository recorded the image as {recorded:?}, not {:?}", self.program)));
                        }
                        if !(readme && project && logged && report.files > 0) {
                            return Some(Err("new project did not leave a repository".into()));
                        }
                        // The panel the repository was written for follows it.
                        driver.frame(app);
                        let follows = app
                            .with_panel::<match_search::MatchPanel, _>(match_search::ID, |panel, _| panel.root() == self.outdir.display().to_string())
                            .unwrap_or(false);
                        metrics.insert("ui.match.root_follows_project".into(), json!(follows));
                        if !follows {
                            return Some(Err("the Match panel did not take the new repository as its root".into()));
                        }
                        if let Err(error) = configure(&report.outdir) {
                            return Some(Err(error));
                        }
                        let program = self.program.clone();
                        Step::Largest(app.service().request(move |core| {
                            core.functions_page(&program, 0, 1, None, Some("size:desc"), None).map_err(|error| error.to_string())
                        }))
                    }
                }
            }
            Step::Largest(task) => match task.poll() {
                None => Step::Largest(task),
                Some(Err(error)) => return Some(Err(error)),
                Some(Ok(page)) => match page.rows.into_iter().next() {
                    None => return Some(Err("the project image has no functions".into())),
                    Some(function) => {
                        app.navigate(function.entry.clone());
                        Step::Select(function)
                    }
                },
            },
            Step::Select(function) => {
                // The shell resolves the function at the cursor and tells the panel.
                let selected = app
                    .with_panel::<match_search::MatchPanel, _>(match_search::ID, |panel, _| panel.function().is_some_and(|selected| selected.entry == function.entry))
                    .unwrap_or(false);
                if selected {
                    app.raise(match_search::ID);
                    self.started = Instant::now();
                    let base = app.with_panel::<match_search::MatchPanel, _>(match_search::ID, |panel, cx| {
                        panel.set_budget(BUDGET.into());
                        let base = panel.runs_finished();
                        panel.run(cx);
                        base
                    });
                    match base {
                        Some(base) => Step::Match { base },
                        None => return Some(Err("match panel is not registered".into())),
                    }
                } else {
                    Step::Select(function)
                }
            }
            Step::Match { base } => {
                let finished = app.with_panel::<match_search::MatchPanel, _>(match_search::ID, |panel, _| panel.runs_finished() > base).unwrap_or(false);
                if !finished {
                    self.step = Step::Match { base };
                    return None;
                }
                // Paint the table, then count what it showed.
                for _ in 0..3 {
                    driver.frame(app);
                }
                let elapsed = ms(self.started);
                let read = app.with_panel::<match_search::MatchPanel, _>(match_search::ID, |panel, _| {
                    panel.outcome().map(|outcome| {
                        let rows = &outcome.report.rows;
                        let best = outcome.report.best_row();
                        (
                            rows.len(),
                            rows.iter().filter(|row| row.score.as_ref().is_some_and(|score| score.compiled)).count(),
                            rows[0].score.as_ref().map_or(0.0, |score| score.percent),
                            best.score.as_ref().map_or(0.0, |score| score.percent),
                            outcome.name.clone(),
                            outcome.report.decompiles,
                            outcome.report.compiles,
                            panel.rendered_rows(),
                        )
                    })
                    .ok_or_else(|| panel.error().unwrap_or("no result").to_string())
                });
                match read {
                    Some(Ok((rows, compiled, default_percent, best_percent, function, decompiles, compiles, rendered))) => {
                        metrics.insert("ui.match.ms".into(), elapsed);
                        metrics.insert("ui.match.function".into(), json!(function));
                        metrics.insert("ui.match.rows".into(), json!(rows));
                        metrics.insert("ui.match.rendered_rows".into(), json!(rendered));
                        metrics.insert("ui.match.compiled_rows".into(), json!(compiled));
                        metrics.insert("ui.match.default_percent".into(), json!(default_percent));
                        metrics.insert("ui.match.best_percent".into(), json!(best_percent));
                        metrics.insert("ui.match.decompiles".into(), json!(decompiles));
                        metrics.insert("ui.match.compiles".into(), json!(compiles));
                        if rows < 2 || compiled == 0 || rendered != rows || best_percent < default_percent {
                            return Some(Err(format!("match table is wrong: {rows} rows, {compiled} compiled, {rendered} painted, best {best_percent} against default {default_percent}")));
                        }
                        return Some(Ok(()));
                    }
                    Some(Err(error)) => return Some(Err(format!("match: {error}"))),
                    None => return Some(Err("match panel is not registered".into())),
                }
            }
        };
        None
    }
}
