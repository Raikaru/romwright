//! `--gate`: the offscreen UI gate (Qt `GateRunner`), rendering every frame
//! through wgpu into an offscreen texture. It drives the real shell and
//! panels and prints one `{"metrics": {...}}` line on stdout, the contract
//! `benchmarks/ui_gate.py`, `tests/m6-003_desktop_package.py` and
//! `tests/m14-004_ui_progress.py` parse.
//!
//! Same order as Qt: the headless source and graph interaction checks
//! (`ui.source.*`, `ui.graph.{distinct_block_selection,empty_block_selection,
//! selection_reset,self_loop_visible}`), import, `ui.list.load_ms`,
//! `ui.list.filter_ms` (store-only runs stop here with `ui.install.prefix_ok`
//! and `ui.install.store_only_ok`), the largest function decompiled with its
//! listing for `ui.sync_ms`, `ui.graph.fetch_ms` / `ui.graph.paint_ms` (the
//! graph panel prints the `BRIDGE-GRAPH` layout line `ui_gate.py` turns into
//! `ui.graph.layout_ms`), `ui.xrefs.{rows,unexplained,address,declared_rows}`,
//! `ui.programs`, `ui.programs_switch_functions`, `ui.install.ok` and
//! `ui.analysis.*`. With `--project-image` the run ends with the project
//! features ([`projects`]: `ui.new_project.*` and `ui.match.*`).
//! `--matching-gate` lives in [`matching`].

pub mod matching;
pub mod projects;

use crate::app::{DesktopApp, Options};
use crate::headless::Driver;
use crate::panels::{decompiler, functions, graph, listing, xrefs};
use crate::service::Task;
use romwright_model::{Address, AnalysisStatus, FunctionRow, Page};
use serde_json::{Map, Value, json};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

enum Stage {
    Import(Task<()>),
    LoadingList { base: u64 },
    Filtering { base: u64 },
    Clearing { base: u64 },
    Largest(Task<Page<FunctionRow>>),
    Decompile { documents: u64, windows: u64, address: Address },
    Graph { base: u64, address: Address },
    Xrefs { base: u64, address: Address },
    Declared { base: u64 },
    Programs { base: u64 },
    Switch { base: u64, deadline: Instant },
    Analysis { task: Option<Task<AnalysisStatus>>, polls: u32, next: Instant },
    Projects(projects::ProjectsGate),
    Done(Result<(), String>),
}

pub struct GateArgs {
    pub options: Options,
    pub store_only: bool,
    pub screenshot: Option<PathBuf>,
    pub width: u32,
    pub height: u32,
    pub scale: f32,
    /// `--project-image`: also gate Program setup's new project and the Match panel on this image.
    pub project_image: Option<PathBuf>,
}

fn ms(started: Instant) -> Value {
    json!(started.elapsed().as_secs_f64() * 1000.0)
}

/// A cargo build tree, not an installed layout: the executable sits beside
/// cargo's own bookkeeping (`.fingerprint`, `deps`) or under `CACHEDIR.TAG`.
fn build_tree(executable: &Path) -> bool {
    let Some(directory) = executable.parent() else { return false };
    directory.join(".fingerprint").is_dir()
        || directory.join("deps").is_dir() && directory.join("build").is_dir()
        || directory.join("CACHEDIR.TAG").is_file()
        || directory.parent().is_some_and(|parent| parent.join("CACHEDIR.TAG").is_file())
}

pub fn run(args: GateArgs) -> ExitCode {
    let GateArgs { mut options, store_only, screenshot, width, height, scale, project_image } = args;
    options.gate = true;
    options.persist = false;
    let program = options.program.clone();
    let binary = options.binary.clone();
    let mut metrics = Map::new();
    if program.is_empty() || binary.as_os_str().is_empty() {
        return finish(&metrics, Err("gate requires --binary and --program".into()));
    }
    let mut driver = match Driver::new(width, height, scale) {
        Ok(driver) => driver,
        Err(error) => return finish(&metrics, Err(error)),
    };
    eprintln!("ui gate: rendering offscreen on {}", driver.offscreen.adapter);
    let mut app = DesktopApp::new(options);
    if let Some(error) = app.service().startup_error() {
        return finish(&metrics, Err(error.to_string()));
    }
    // Qt runs the source and graph interaction checks before importing.
    if let Err(error) = decompiler::source_interactions() {
        eprintln!("ui gate: {error}");
        return finish(&metrics, Err("Source interaction gate failed".into()));
    }
    for key in ["selection_copy", "hints_excluded_from_copy", "follow_rename", "fold_reverse_sync", "read_only"] {
        metrics.insert(format!("ui.source.{key}"), json!(true));
    }
    if let Err(error) = graph::graph_interactions() {
        eprintln!("ui gate: {error}");
        return finish(&metrics, Err("Graph interaction gate failed".into()));
    }
    for key in ["distinct_block_selection", "empty_block_selection", "selection_reset", "self_loop_visible"] {
        metrics.insert(format!("ui.graph.{key}"), json!(true));
    }
    let load_only = std::env::var_os("ROMWRIGHT_UI_LOAD_ONLY").is_some();
    // `ROMWRIGHT_UI_LOAD_ONLY` takes the large-image path: map, show the
    // loader's answer, analyse in the background.
    let (import_program, import_binary) = (program.clone(), binary.clone());
    let mut stage = Stage::Import(app.service().job("native import", move |job| {
        let core = job.fork()?;
        if load_only {
            core.load_program(&import_binary, &import_program).map(drop).map_err(|error| error.to_string())
        } else {
            core.import_native(&import_binary, &import_program).map(drop).map_err(|error| error.to_string())
        }
    }));
    let mut started = Instant::now();
    let deadline = Instant::now() + Duration::from_secs(900);
    let refreshes = |app: &mut DesktopApp| app.with_panel::<functions::FunctionsPanel, _>(functions::ID, |panel, _| panel.refreshes()).unwrap_or(0);
    loop {
        driver.frame(&mut app);
        if Instant::now() > deadline {
            stage = Stage::Done(Err("gate timed out".into()));
        }
        stage = match stage {
            Stage::Import(task) => match task.poll() {
                None => Stage::Import(task),
                Some(Err(error)) => Stage::Done(Err(error)),
                Some(Ok(())) => {
                    app.with_panel::<functions::FunctionsPanel, _>(functions::ID, |panel, _| panel.filter_delay = Duration::ZERO);
                    let base = refreshes(&mut app);
                    started = Instant::now();
                    app.open_imported(&program, binary.clone());
                    Stage::LoadingList { base }
                }
            },
            Stage::LoadingList { base } if refreshes(&mut app) > base => {
                metrics.insert("ui.list.load_ms".into(), ms(started));
                let base = refreshes(&mut app);
                started = Instant::now();
                app.with_panel::<functions::FunctionsPanel, _>(functions::ID, |panel, cx| panel.set_filter(cx, "FUN_"));
                Stage::Filtering { base }
            }
            Stage::Filtering { base } if refreshes(&mut app) > base => {
                metrics.insert("ui.list.filter_ms".into(), ms(started));
                let base = refreshes(&mut app);
                app.with_panel::<functions::FunctionsPanel, _>(functions::ID, |panel, cx| panel.set_filter(cx, ""));
                Stage::Clearing { base }
            }
            Stage::Clearing { base } if refreshes(&mut app) > base => {
                if store_only {
                    let executable = std::env::current_exe().unwrap_or_default();
                    metrics.insert("ui.install.prefix_ok".into(), json!(!build_tree(&executable)));
                    let configured = std::env::vars_os().any(|(name, _)| name.to_string_lossy().starts_with("ROMWRIGHT_"));
                    metrics.insert("ui.install.store_only_ok".into(), json!(!configured));
                    Stage::Done(Ok(()))
                } else {
                    let program = program.clone();
                    Stage::Largest(app.service().request(move |core| {
                        core.functions_page(&program, 0, 1, None, Some("size:desc"), None).map_err(|error| error.to_string())
                    }))
                }
            }
            Stage::Largest(task) => match task.poll() {
                None => Stage::Largest(task),
                Some(Err(error)) => Stage::Done(Err(error)),
                Some(Ok(page)) => match page.rows.into_iter().next() {
                    None => Stage::Done(Err("gate found no functions".into())),
                    Some(function) => {
                        // Qt `startDecompile`: the document and the listing
                        // window for the same function, then the cursor sync.
                        let address = function.entry;
                        let documents = app.with_panel::<decompiler::DecompilerPanel, _>(decompiler::ID, |panel, cx| {
                            let base = panel.documents_loaded();
                            panel.decompile(cx, address.clone(), address.clone());
                            base
                        });
                        let windows = app.with_panel::<listing::ListingPanel, _>(listing::ID, |panel, cx| {
                            let base = panel.windows_loaded();
                            panel.load_at(cx, address.clone());
                            base
                        });
                        match (documents, windows) {
                            (Some(documents), Some(windows)) => Stage::Decompile { documents, windows, address },
                            _ => Stage::Done(Err("decompiler or listing panel is not registered".into())),
                        }
                    }
                },
            },
            Stage::Decompile { documents, windows, address } => {
                let decompiled = app.with_panel::<decompiler::DecompilerPanel, _>(decompiler::ID, |panel, _| {
                    (panel.documents_loaded() > documents, crate::panel::Panel::busy(panel))
                });
                let listed = app
                    .with_panel::<listing::ListingPanel, _>(listing::ID, |panel, _| panel.windows_loaded() > windows && !crate::panel::Panel::busy(panel))
                    .unwrap_or(false);
                match decompiled {
                    Some((false, false)) => Stage::Done(Err(format!("decompile of {} failed", crate::address::format(&address)))),
                    Some((true, _)) if listed => {
                        // Both views hold their rows: time the cursor sync
                        // on both and the repaint that shows it.
                        started = Instant::now();
                        app.with_panel::<decompiler::DecompilerPanel, _>(decompiler::ID, |panel, cx| panel.set_address(cx, &address));
                        app.with_panel::<listing::ListingPanel, _>(listing::ID, |panel, cx| panel.set_address(cx, &address));
                        driver.frame(&mut app);
                        metrics.insert("ui.sync_ms".into(), ms(started));
                        // Qt `startGraph`: raise the tab so the paint is real.
                        app.raise(graph::ID);
                        let base = app.with_panel::<graph::GraphPanel, _>(graph::ID, |panel, cx| {
                            let base = panel.graphs_loaded();
                            panel.load_graph(cx, &address);
                            base
                        });
                        match base {
                            Some(base) => Stage::Graph { base, address },
                            None => Stage::Done(Err("graph panel is not registered".into())),
                        }
                    }
                    _ => Stage::Decompile { documents, windows, address },
                }
            }
            Stage::Graph { base, address } => {
                let answered = app.with_panel::<graph::GraphPanel, _>(graph::ID, |panel, _| {
                    (panel.graphs_loaded() > base).then(|| ((panel.last_fetch_ms(), panel.last_layout_ms()), panel.view().is_empty()))
                });
                match answered.flatten() {
                    None => Stage::Graph { base, address },
                    Some(((None, _), _)) | Some((_, true)) => Stage::Done(Err(format!("function graph of {} failed", crate::address::format(&address)))),
                    Some(((Some(fetch), layout), false)) => {
                        metrics.insert("ui.graph.fetch_ms".into(), json!(fetch));
                        // Same number `ui_gate.py` reads from `BRIDGE-GRAPH`.
                        if let Some(layout) = layout {
                            metrics.insert("ui.graph.layout_ms".into(), json!(layout));
                        }
                        started = Instant::now();
                        driver.frame(&mut app);
                        metrics.insert("ui.graph.paint_ms".into(), ms(started));
                        // Qt `startXrefs`: what the table holds once both
                        // requests answered, not what was sent.
                        let base = app.with_panel::<xrefs::XrefsPanel, _>(xrefs::ID, |panel, cx| {
                            panel.load_xrefs(cx, &address);
                            panel.loads_finished()
                        });
                        match base {
                            Some(base) => Stage::Xrefs { base, address },
                            None => Stage::Done(Err("xrefs panel is not registered".into())),
                        }
                    }
                }
            }
            Stage::Xrefs { base, address } => {
                let rows = app.with_panel::<xrefs::XrefsPanel, _>(xrefs::ID, |panel, _| {
                    (panel.loads_finished() > base).then(|| (panel.rendered_rows(), panel.unexplained_rows(), panel.loads_finished()))
                });
                match rows.flatten() {
                    None => Stage::Xrefs { base, address },
                    Some((rows, unexplained, finished)) => {
                        metrics.insert("ui.xrefs.rows".into(), json!(rows));
                        metrics.insert("ui.xrefs.unexplained".into(), json!(unexplained));
                        metrics.insert("ui.xrefs.address".into(), json!(address.offset as f64));
                        app.with_panel::<xrefs::XrefsPanel, _>(xrefs::ID, |panel, cx| panel.set_evidence(cx, "declared"));
                        Stage::Declared { base: finished }
                    }
                }
            }
            Stage::Declared { base } => {
                let rows = app.with_panel::<xrefs::XrefsPanel, _>(xrefs::ID, |panel, _| (panel.loads_finished() > base).then(|| panel.rendered_rows()));
                match rows.flatten() {
                    None => Stage::Declared { base },
                    Some(rows) => {
                        metrics.insert("ui.xrefs.declared_rows".into(), json!(rows));
                        let base = app.programs_listed();
                        app.refresh_programs();
                        Stage::Programs { base }
                    }
                }
            }
            Stage::Programs { base } if app.programs_listed() > base => {
                let count = app.programs().len();
                metrics.insert("ui.programs".into(), json!(count));
                if count == 0 {
                    finish_switch(&mut metrics, 0);
                    Stage::Analysis { task: None, polls: 0, next: Instant::now() }
                } else {
                    let base = refreshes(&mut app);
                    app.select_program_at(count - 1);
                    Stage::Switch { base, deadline: Instant::now() + Duration::from_secs(2) }
                }
            }
            Stage::Switch { base, deadline } => {
                let total = app.with_panel::<functions::FunctionsPanel, _>(functions::ID, |panel, _| panel.total()).unwrap_or(0);
                if refreshes(&mut app) > base || Instant::now() > deadline {
                    finish_switch(&mut metrics, total);
                    Stage::Analysis { task: None, polls: 0, next: Instant::now() }
                } else {
                    Stage::Switch { base, deadline }
                }
            }
            Stage::Analysis { task: None, polls, next } if Instant::now() >= next => {
                let program = app.session().program.clone();
                let task = app.service().request(move |core| core.analysis_status(&program).map_err(|error| error.to_string()));
                Stage::Analysis { task: Some(task), polls, next }
            }
            Stage::Analysis { task: Some(task), polls, next } => match task.poll() {
                None => Stage::Analysis { task: Some(task), polls, next },
                Some(result) => {
                    let status = result.ok();
                    let stale = status.as_ref().is_some_and(|status| status.stale);
                    metrics.insert("ui.analysis.stale".into(), json!(stale));
                    metrics.insert("ui.analysis.analysed".into(), json!(status.as_ref().map_or(0, |status| status.analysed)));
                    metrics.insert("ui.analysis.seeded".into(), json!(status.as_ref().map_or(0, |status| status.seeded)));
                    metrics.insert("ui.analysis".into(), json!(app.analysis_label()));
                    metrics.insert("ui.analysis.first".into(), json!(app.first_analysis()));
                    metrics.insert("ui.analysis.polls".into(), json!(polls));
                    // 600 polls at 50 ms: long enough for a corpus image,
                    // short enough that a stuck pass fails instead of hangs.
                    if load_only && stale && polls < 600 {
                        Stage::Analysis { task: None, polls: polls + 1, next: Instant::now() + Duration::from_millis(50) }
                    } else {
                        match &project_image {
                            Some(image) => Stage::Projects(projects::ProjectsGate::start(&mut app, image.clone())),
                            None => Stage::Done(Ok(())),
                        }
                    }
                }
            },
            Stage::Projects(mut gate) => match gate.step(&mut app, &mut driver, &mut metrics) {
                Some(result) => Stage::Done(result),
                None => Stage::Projects(gate),
            },
            Stage::Done(result) => {
                if let Some(path) = &screenshot {
                    for _ in 0..3 {
                        driver.frame(&mut app);
                    }
                    if let Err(error) = driver.save_png(path) {
                        eprintln!("ui gate: screenshot failed: {error}");
                    }
                }
                drop(app);
                return finish(&metrics, result);
            }
            waiting => {
                std::thread::sleep(Duration::from_millis(1));
                waiting
            }
        };
    }
}

fn finish_switch(metrics: &mut Map<String, Value>, functions: u64) {
    metrics.insert("ui.programs_switch_functions".into(), json!(functions));
    metrics.insert("ui.install.ok".into(), json!(std::env::var_os("ROMWRIGHT_UI_INSTALL_OK").is_some()));
}

fn finish(metrics: &Map<String, Value>, result: Result<(), String>) -> ExitCode {
    println!("{}", json!({ "metrics": metrics }));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(detail) => {
            eprintln!("ui gate failed: {detail}");
            ExitCode::FAILURE
        }
    }
}
