//! `romwright-desktop`: the pure-Rust Romwright workstation (egui shell,
//! wgpu renderer): `--project`, `--program`/`-n`, `--binary`, `--address`,
//! the offscreen `--gate` / `--store-only` / `--matching-gate` modes, and
//! `--screenshot PATH` for one offscreen frame.

use romwright_desktop::app::{DesktopApp, Options};
use romwright_desktop::{gate, headless, panels, theme};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};
use theme::ThemeChoice;

const USAGE: &str = "\
Usage: romwright-desktop [OPTIONS]

  -p, --project DIR        SQLite project directory (default .romwright)
  -n, --program NAME       program to open
  -b, --binary PATH        binary path (gate: the image to import)
  -a, --address HEX        initial address (default 00400466)
      --theme NAME         system, dark, light or contrast
      --gate               run the offscreen UI gate, print metrics JSON, exit
      --store-only         gate the store-facing workflow only
      --project-image IMG  (gate) also gate Program setup's new project and the
                           Match panel on this image (a Windows PE32)
      --matching-gate CFG  drive the matching workspace through matching_gate's
                           workflow, write and print its report
      --screenshot PATH    render offscreen until idle, write a PNG, exit
      --panel ID           (screenshot) raise this panel first; repeatable
      --size WxH           offscreen size in points (default 1440x900)
      --scale F            offscreen pixels per point (default 1)
      --timeout SECONDS    screenshot idle wait (default 120); matching gate
                           limit (default 60)
  -h, --help               show this help";

struct Args {
    options: Options,
    gate: bool,
    matching_gate: Option<PathBuf>,
    store_only: bool,
    project_image: Option<PathBuf>,
    screenshot: Option<PathBuf>,
    panels: Vec<String>,
    width: u32,
    height: u32,
    scale: f32,
    timeout: Option<Duration>,
}

fn parse_args() -> Result<Option<Args>, String> {
    let mut args = Args {
        options: Options {
            project: PathBuf::from(".romwright"),
            program: String::new(),
            binary: PathBuf::new(),
            address: "00400466".into(),
            theme: None,
            persist: true,
            gate: false,
        },
        gate: false,
        matching_gate: None,
        store_only: false,
        project_image: None,
        screenshot: None,
        panels: Vec::new(),
        width: 1440,
        height: 900,
        scale: 1.0,
        timeout: None,
    };
    let mut input = std::env::args().skip(1);
    while let Some(argument) = input.next() {
        let (flag, inline) = match argument.split_once('=') {
            Some((flag, value)) if flag.starts_with("--") => (flag.to_string(), Some(value.to_string())),
            _ => (argument.clone(), None),
        };
        let mut value = || inline.clone().or_else(|| input.next()).ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "-h" | "--help" => return Ok(None),
            "-p" | "--project" => args.options.project = PathBuf::from(value()?),
            "-n" | "--program" => args.options.program = value()?,
            "-b" | "--binary" => args.options.binary = PathBuf::from(value()?),
            "-a" | "--address" => args.options.address = value()?,
            "--theme" => {
                let name = value()?;
                args.options.theme = Some(ThemeChoice::parse(&name).ok_or_else(|| format!("unknown theme {name:?}"))?);
            }
            "--gate" => args.gate = true,
            "--store-only" => args.store_only = true,
            "--project-image" => args.project_image = Some(PathBuf::from(value()?)),
            "--matching-gate" => args.matching_gate = Some(PathBuf::from(value()?)),
            "--screenshot" => args.screenshot = Some(PathBuf::from(value()?)),
            "--panel" => args.panels.push(value()?),
            "--size" => {
                let size = value()?;
                let (width, height) = size
                    .split_once('x')
                    .and_then(|(width, height)| Some((width.parse().ok()?, height.parse().ok()?)))
                    .filter(|(width, height): &(u32, u32)| *width >= 320 && *height >= 240 && *width <= 8192 && *height <= 8192)
                    .ok_or_else(|| format!("--size wants WxH between 320x240 and 8192x8192, not {size:?}"))?;
                args.width = width;
                args.height = height;
            }
            "--scale" => {
                let scale = value()?;
                args.scale = scale.parse().ok().filter(|scale: &f32| (0.5..=4.0).contains(scale)).ok_or_else(|| format!("--scale wants 0.5..4, not {scale:?}"))?;
            }
            "--timeout" => {
                let seconds = value()?;
                args.timeout = Some(Duration::from_secs(seconds.parse().map_err(|_| format!("--timeout wants seconds, not {seconds:?}"))?));
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    Ok(Some(args))
}

fn screenshot(args: Args, path: PathBuf) -> ExitCode {
    let mut options = args.options;
    options.persist = false;
    let mut driver = match headless::Driver::new(args.width, args.height, args.scale) {
        Ok(driver) => driver,
        Err(error) => {
            eprintln!("screenshot: {error}");
            return ExitCode::FAILURE;
        }
    };
    eprintln!("screenshot: rendering offscreen on {}", driver.offscreen.adapter);
    let mut app = DesktopApp::new(options);
    let started = Instant::now();
    let mut idle_frames = 0;
    let mut raised = false;
    while idle_frames < 3 {
        driver.frame(&mut app);
        if !raised && started.elapsed() > Duration::from_millis(100) {
            for id in &args.panels {
                if let Some(id) = panels::builtin("", "").iter().map(|panel| panel.id()).find(|known| known == id) {
                    app.raise(id);
                } else {
                    eprintln!("screenshot: unknown panel {id:?}");
                }
            }
            raised = true;
        }
        idle_frames = if raised && app.idle() { idle_frames + 1 } else { 0 };
        let timeout = args.timeout.unwrap_or(Duration::from_secs(120));
        if started.elapsed() > timeout {
            eprintln!("screenshot: still busy after {timeout:?}; capturing anyway");
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    // Let animations (tab underline, fades) settle.
    for _ in 0..3 {
        driver.frame(&mut app);
    }
    match driver.save_png(&path) {
        Ok(()) => {
            println!("{}", path.display());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("screenshot: {error}");
            ExitCode::FAILURE
        }
    }
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(Some(args)) => args,
        Ok(None) => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(error) => {
            eprintln!("romwright-desktop: {error}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    if let Some(config) = args.matching_gate {
        return gate::matching::run(gate::matching::MatchingGateArgs {
            config,
            options: args.options,
            width: args.width,
            height: args.height,
            scale: args.scale,
            timeout: args.timeout,
        });
    }
    if args.gate {
        return gate::run(gate::GateArgs {
            options: args.options,
            store_only: args.store_only,
            screenshot: args.screenshot,
            width: args.width,
            height: args.height,
            scale: args.scale,
            project_image: args.project_image,
        });
    }
    if let Some(path) = args.screenshot.clone() {
        return screenshot(args, path);
    }
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Romwright")
            .with_app_id("romwright")
            .with_inner_size([1440.0, 920.0])
            .with_min_inner_size([800.0, 520.0]),
        ..Default::default()
    };
    let app_options = args.options;
    match eframe::run_native("Romwright", options, Box::new(move |creation| {
        let mut app = DesktopApp::new(app_options);
        app.prepare(&creation.egui_ctx);
        Ok(Box::new(app))
    })) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("romwright-desktop: {error}");
            ExitCode::FAILURE
        }
    }
}
