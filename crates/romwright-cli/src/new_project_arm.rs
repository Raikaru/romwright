//! `new-project` for the ARM platforms romwright builds without splat: Game Boy
//! Advance (GNU as/ld units) and Nintendo DS (ds-decomp). Included by
//! `new_project.rs`; see docs/new-project.md.

use super::{program_name, Manifest};
use crate::{flag, has_flag};
use romwright_core::new_project::{self, gba, nds};
use romwright_core::Core;
use std::path::{Path, PathBuf};

pub fn run(args: &[String], platform: &str, image_path: &Path, image_name: &str, outdir: &Path, bytes: &[u8]) -> Result<(), String> {
    let project_name = flag(args, "--name").unwrap_or_else(|| {
        Path::new(image_name).file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "game".into())
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

    // The retail image goes into orig/ (user-owned bytes, ignored by git).
    let orig = outdir.join("orig").join(image_name);
    std::fs::create_dir_all(orig.parent().unwrap()).map_err(|e| e.to_string())?;
    if std::fs::canonicalize(image_path).ok() != std::fs::canonicalize(&orig).ok() {
        std::fs::write(&orig, bytes).map_err(|e| format!("{}: {e}", orig.display()))?;
    }

    let store = outdir.join(".romwright");
    let core = Core::open(&store).map_err(|e| e.to_string())?;
    let keys = romwright_core::native::keys::KeyStore::load_all(&[]).map_err(|e| e.to_string())?;
    let pack = flag(args, "--fact-pack").map(PathBuf::from);
    let (stored, _, facts_reports) = core
        .import_native_with_facts(&orig, &program, &[], true, None, None, &keys, pack.as_deref())
        .map_err(|e| e.to_string())?;
    // Overlays are programs of their own; the main one is first.
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

    let (files, summary_line, next) = match platform {
        "gba" => {
            let compiler = flag(args, "--compiler");
            let (files, report) = gba::plan(&gba::GbaInputs {
                image: bytes,
                image_name,
                project_name: &project_name,
                program: &summary.program,
                facts: &export,
                prototypes: &prototypes,
                manifest: &manifest,
                compiler_id: compiler.as_deref(),
                cflags: flag(args, "--cflags").map(|f| f.split_whitespace().map(str::to_string).collect()),
                profile: profile.as_deref(),
                romwright_version: env!("CARGO_PKG_VERSION"),
            })?;
            let line = if has_flag(args, "--json") {
                serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
            } else {
                format!(
                    "wrote {}: gba {} ({:?}), {} functions as asm units ({} Thumb, {} ARM), {} binary units, {} symbols, {} prototypes ({} skipped), compiler `{}`",
                    outdir.display(),
                    report.detection.family,
                    report.detection.confidence,
                    report.asm_units,
                    report.thumb_functions,
                    report.arm_functions,
                    report.bin_units,
                    report.symbols,
                    report.prototypes_emitted,
                    report.prototypes_skipped,
                    report.compiler_tool
                )
            };
            (files, line, "python3 -m pip install -r requirements.txt && python3 configure.py && ninja")
        }
        "nds" => {
            // Every program of the ROM: the ARM9 (with its autoloads), the ARM7 and one program per overlay.
            let mut all = Vec::new();
            for stored_program in &stored {
                let facts = core.export_facts(&stored_program.program).map_err(|e| e.to_string())?;
                let protos: Vec<(u64, String)> = core
                    .prototypes(&stored_program.program)
                    .map_err(|e| e.to_string())?
                    .into_iter()
                    .map(|row| (row.function.offset, row.signature))
                    .collect();
                all.push((stored_program.program.clone(), facts, protos));
            }
            let programs: Vec<nds::NdsProgram> =
                all.iter().map(|(name, facts, protos)| nds::NdsProgram { program: name, facts, prototypes: protos }).collect();
            let compiler = flag(args, "--compiler");
            let (files, report) = nds::plan(&nds::NdsInputs {
                image: bytes,
                image_name,
                project_name: &project_name,
                program: &summary.program,
                programs: &programs,
                manifest: &manifest,
                compiler_id: compiler.as_deref(),
                cflags: flag(args, "--cflags").map(|f| f.split_whitespace().map(str::to_string).collect()),
                profile: profile.as_deref(),
                romwright_version: env!("CARGO_PKG_VERSION"),
            })?;
            let line = if has_flag(args, "--json") {
                serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
            } else {
                format!(
                    "wrote {}: nds {} ({:?}), {} modules, {} ARM9 + {} overlay + {} ARM7 functions, {} symbols, {} prototypes ({} skipped), compiler `{}`",
                    outdir.display(),
                    report.detection.family,
                    report.detection.confidence,
                    report.modules,
                    report.arm9_functions,
                    report.overlay_functions,
                    report.arm7_functions,
                    report.symbols,
                    report.prototypes_emitted,
                    report.prototypes_skipped,
                    report.compiler_tool
                )
            };
            (files, line, "python3 -m pip install -r requirements.txt && python3 configure.py && ninja")
        }
        other => return Err(format!("platform `{other}` is not an ARM platform new-project builds")),
    };
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

    println!("{summary_line}");
    if !has_flag(args, "--json") {
        if decompiled > 0 {
            println!("{decompiled} reference C file(s) in decompiled/");
        }
        println!("next: cd {} && {next}", outdir.display());
    }
    Ok(())
}
