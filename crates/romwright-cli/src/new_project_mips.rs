//! `new-project` for the MIPS platforms romwright splits with splat besides the
//! PlayStation 2: Nintendo 64, PlayStation (PS-X EXE) and PSP. Included by
//! `new_project.rs`; see docs/new-project.md.

use super::{program_name, Manifest};
use crate::{flag, has_flag};
use romwright_core::new_project::{self, mips::Inputs, n64, psp, psx};
use romwright_core::Core;
use std::path::{Path, PathBuf};

pub fn run(args: &[String], platform: &str, image_path: &Path, image_name: &str, outdir: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut image_name = image_name.to_string();
    let dump_sha1 = romwright_core::export::sha1_hex(bytes);
    // N64: any dump order is normalised to big-endian `.z64` before the import.
    let (bytes, order): (Vec<u8>, &'static str) = if platform == "n64" {
        let (z64, order) = n64::to_z64(bytes).ok_or("this is not a Nintendo 64 ROM (no PI configuration word in any dump byte order)")?;
        if order != "z64" {
            image_name = format!("{}.z64", Path::new(&image_name).file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "rom".into()));
            eprintln!("{}: {order} byte order; normalised to .z64 as {image_name}", image_path.display());
        }
        (z64, order)
    } else {
        (bytes.to_vec(), "z64")
    };

    let project_name = flag(args, "--name").unwrap_or_else(|| {
        Path::new(&image_name).file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "game".into())
    });
    let program = program_name(&project_name);
    let manifest = match flag(args, "--manifest") {
        Some(path) => Manifest::parse(&std::fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?).map_err(|e| format!("{path}: {e}"))?,
        None => Manifest::builtin(),
    };
    let profile = match flag(args, "--toolchain") {
        Some(path) => {
            let text = std::fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?;
            serde_json::from_str::<serde_json::Value>(&text).map_err(|e| format!("{path}: not JSON: {e}"))?;
            Some(text)
        }
        None => None,
    };

    let orig = outdir.join("orig").join(&image_name);
    std::fs::create_dir_all(orig.parent().unwrap()).map_err(|e| e.to_string())?;
    std::fs::write(&orig, &bytes).map_err(|e| format!("{}: {e}", orig.display()))?;

    let store = outdir.join(".romwright");
    let core = Core::open(&store).map_err(|e| e.to_string())?;
    let keys = romwright_core::native::keys::KeyStore::load_all(&[]).map_err(|e| e.to_string())?;
    let pack = flag(args, "--fact-pack").map(PathBuf::from);
    let (stored, _, facts_reports) = core
        .import_native_with_facts(&orig, &program, &[], true, None, None, &keys, pack.as_deref())
        .map_err(|e| e.to_string())?;
    // N64 overlays are programs of their own (`<name>.main`, `<name>.ovl_*`); the main one is first.
    let summary = stored.first().ok_or("import produced no program")?;
    eprintln!("imported {} ({} functions, {}; {} program(s) in the store)", summary.program, summary.functions, summary.language, stored.len());
    for report in &facts_reports {
        eprintln!("fact pack: {}: {} matched, {} renamed, {} prototypes", report.program, report.matched, report.renamed, report.prototypes);
    }
    let export = core.export_facts(&summary.program).map_err(|e| e.to_string())?;
    let prototypes: Vec<(u64, String)> = core
        .prototypes(&summary.program)
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|row| (row.function.offset, row.signature))
        .collect();

    let compiler_flag = flag(args, "--compiler");
    let inputs = Inputs {
        image: &bytes,
        image_name: &image_name,
        project_name: &project_name,
        facts: &export,
        prototypes: &prototypes,
        manifest: &manifest,
        compiler_id: compiler_flag.as_deref(),
        cflags: flag(args, "--cflags").map(|f| f.split_whitespace().map(str::to_string).collect()),
        profile: profile.as_deref(),
        romwright_version: env!("CARGO_PKG_VERSION"),
    };
    let (mut files, report) = match platform {
        "psx" => psx::plan(&inputs)?,
        "psp" => psp::plan(&inputs)?,
        "n64" => {
            let mappings = romwright_core::native::load_native_mappings(&orig).map_err(|e| e.to_string())?;
            let backing = romwright_core::export::file_backing(&mappings, &bytes);
            n64::plan(&inputs, &n64::N64Source { order, dump_sha1: &dump_sha1, backing: &backing })?
        }
        other => return Err(format!("platform `{other}` is not a MIPS splat platform")),
    };
    // The store program the match search opens (N64 names its main program `<name>.main`).
    for file in files.iter_mut().filter(|f| f.path == "config/project.json") {
        let mut value: serde_json::Value = serde_json::from_slice(&file.bytes).map_err(|e| e.to_string())?;
        value["image"]["program"] = serde_json::json!(summary.program);
        file.bytes = (serde_json::to_string_pretty(&value).map_err(|e| e.to_string())? + "\n").into_bytes();
    }
    new_project::write_files(outdir, &files).map_err(|e| format!("{}: {e}", outdir.display()))?;

    let mut decompiled = 0usize;
    if let Some(selection) = flag(args, "--decompile").filter(|s| s != "none") {
        let target = outdir.join("decompiled");
        std::fs::create_dir_all(&target).map_err(|e| e.to_string())?;
        let options = romwright_core::emit_m2c::M2cOptions {
            budget: flag(args, "--budget-ms")
                .map(|v| v.parse::<u64>().map_err(|e| e.to_string()))
                .transpose()?
                .map(std::time::Duration::from_millis),
            ..Default::default()
        };
        let entries: Vec<Option<u64>> = if selection == "all" {
            vec![None]
        } else {
            selection
                .split(',')
                .map(|a| u64::from_str_radix(a.trim().trim_start_matches("0x"), 16).map(Some).map_err(|e| format!("--decompile {a}: {e}")))
                .collect::<Result<_, _>>()?
        };
        for entry in entries {
            core.export_m2c(&orig, &summary.program, &target, None, entry, &options).map_err(|e| format!("decompile {entry:?}: {e}"))?;
        }
        decompiled = std::fs::read_dir(&target).map(|d| d.count()).unwrap_or(0);
    }

    if has_flag(args, "--json") {
        let mut value = serde_json::to_value(&report).map_err(|e| e.to_string())?;
        value["outdir"] = serde_json::json!(outdir);
        value["decompiled_files"] = serde_json::json!(decompiled);
        println!("{}", serde_json::to_string_pretty(&value).map_err(|e| e.to_string())?);
    } else {
        println!(
            "wrote {}: {} {} ({}, {:?}), {} functions as asm units, {} binary units, {} symbols, {} prototypes ({} skipped), splat `{}`, compiler `{}`",
            outdir.display(),
            report.platform,
            report.detection.family,
            report.detection.version,
            report.detection.confidence,
            report.asm_units,
            report.bin_units,
            report.symbols,
            report.prototypes_emitted,
            report.prototypes_skipped,
            report.detection.splat_compiler,
            report.compiler_tool
        );
        for note in &report.notes {
            println!("note: {note}");
        }
        println!("next: cd {} && python3 -m pip install -r requirements.txt && python3 configure.py && ninja", outdir.display());
    }
    Ok(())
}
