//! `romwright-cli new-project` and `detect-compiler`.
//!
//!   new-project <image> <outdir> [--name NAME] [--toolchain PROFILE.json] [--manifest FILE]
//!               [--compiler ID] [--cflags "FLAGS"] [--decompile all|ADDR,ADDR] [--fact-pack PACK]
//!               [--budget-ms N] [--json]
//!   new-project --list-platforms [--json]
//!   detect-compiler <image> [--json]
//!
//! Thin delegates to `romwright_core::new_project`; see docs/new-project.md.

use super::{flag, has_flag};
use romwright_core::new_project::{self, compiler, manifest::Manifest, platforms, ps2};
use romwright_core::Core;
use std::path::{Path, PathBuf};

#[path = "new_project_scaffold.rs"]
mod scaffold_cli;
#[path = "new_project_mips.rs"]
mod mips_cli;
#[path = "new_project_gc.rs"]
mod gc_cli;
#[path = "new_project_arm.rs"]
mod arm_cli;
#[path = "new_project_pe.rs"]
mod pe_cli;

pub fn run(args: &[String]) -> Result<(), String> {
    match args[1].as_str() {
        "detect-compiler" => detect(args),
        _ if has_flag(args, "--list-platforms") => list_platforms(args),
        _ => new_project(args),
    }
}

fn detect(args: &[String]) -> Result<(), String> {
    let image = args.get(2).ok_or("detect-compiler needs an image")?;
    let bytes = std::fs::read(image).map_err(|e| format!("{image}: {e}"))?;
    // N64, PlayStation and PSP images: the MIPS detectors (new_project/detect.rs).
    if let Some(platform) = new_project::detect_mips_platform(&bytes) {
        let found = match platform {
            "n64" => {
                let (z64, _) = new_project::n64::to_z64(&bytes).ok_or("not a Nintendo 64 ROM")?;
                // Without the layout the whole ROM after the boot code is read; compressed noise only lowers the counts.
                new_project::detect::detect_n64(&z64, &[(0x1000, z64.len() as u64 - 0x1000)])
            }
            "psx" => new_project::detect::detect_psx(&bytes),
            _ => new_project::detect::detect_psp(&bytes),
        };
        if has_flag(args, "--json") {
            println!("{}", serde_json::to_string_pretty(&found).map_err(|e| e.to_string())?);
        } else {
            println!("platform    {platform}");
            println!("family      {}", found.family);
            println!("version     {}", if found.version.is_empty() { "-" } else { &found.version });
            println!("confidence  {:?}", found.confidence);
            println!("splat       {}", found.splat_compiler);
            println!("tool        {}", found.suggested_tool);
            for line in &found.evidence {
                println!("  - {line}");
            }
        }
        return Ok(());
    }
    // A Windows x86 PE: the importer's compiler detector on the image's own headers.
    if let Some(Ok(_)) = new_project::pe::detect_platform(&bytes) {
        let found = new_project::pe::detect_image_compiler(&bytes);
        if has_flag(args, "--json") {
            println!("{}", serde_json::to_string_pretty(&found).map_err(|e| e.to_string())?);
        } else {
            println!("platform:   Windows PE (i386)");
            println!("compiler:   {} ({:?} confidence)", found.id, found.confidence);
            for line in &found.evidence {
                println!("  - {line}");
            }
            if let Some(tool) = new_project::pe::msvc_for(&found.id) {
                println!("suggested:  {} (pinned in the manifest){}", tool.0, if tool.1.is_empty() { String::new() } else { format!("; {}", tool.1) });
            }
        }
        return Ok(());
    }
    // A GBA or Nintendo DS ROM (new_project/gba.rs, nds.rs).
    if let Some(platform) = new_project::detect_arm_platform(&bytes) {
        let (value, family, version, confidence, tool, evidence) = if platform == "gba" {
            let found = new_project::gba::detect_gba_compiler(&bytes);
            (serde_json::to_value(&found).map_err(|e| e.to_string())?, found.family.to_string(), found.version.clone(), format!("{:?}", found.confidence), found.suggested_tool.to_string(), found.evidence.clone())
        } else {
            let found = new_project::nds::detect_nds_compiler(&bytes);
            let tool = format!("{} (mwccarm/{})", found.suggested_tool, found.mw_version);
            (serde_json::to_value(&found).map_err(|e| e.to_string())?, found.family.to_string(), found.version.clone(), format!("{:?}", found.confidence), tool, found.evidence.clone())
        };
        if has_flag(args, "--json") {
            println!("{}", serde_json::to_string_pretty(&value).map_err(|e| e.to_string())?);
        } else {
            println!("platform    {platform}");
            println!("family      {family}");
            println!("version     {}", if version.is_empty() { "-" } else { &version });
            println!("confidence  {confidence}");
            println!("tool        {tool}");
            for line in &evidence {
                println!("  - {line}");
            }
        }
        return Ok(());
    }
    // A GameCube/Wii disc or DOL: the Metrowerks era class.
    if let Some(found) = new_project::gc::detect_image_compiler(&bytes) {
        let found = found.map_err(|e| format!("{image}: {e}"))?;
        if has_flag(args, "--json") {
            println!("{}", serde_json::to_string_pretty(&found).map_err(|e| e.to_string())?);
        } else {
            println!("family      {}", found.family);
            println!("class       {}", found.version_class);
            println!("confidence  {:?}", found.confidence);
            println!("tool        {}", found.mw_version);
            for line in &found.evidence {
                println!("  - {line}");
            }
        }
        return Ok(());
    }
    let found = compiler::detect_ps2_compiler(&bytes);
    if has_flag(args, "--json") {
        println!("{}", serde_json::to_string_pretty(&found).map_err(|e| e.to_string())?);
    } else {
        println!("family      {}", found.family.id());
        println!("version     {}", if found.version.is_empty() { "-" } else { &found.version });
        println!("confidence  {:?}", found.confidence);
        println!("splat       {}", found.splat_compiler);
        println!("tool        {}", found.suggested_tool);
        for line in &found.evidence {
            println!("  - {line}");
        }
    }
    Ok(())
}

fn list_platforms(args: &[String]) -> Result<(), String> {
    if has_flag(args, "--json") {
        println!("{}", serde_json::to_string_pretty(platforms::PLATFORMS).map_err(|e| e.to_string())?);
        return Ok(());
    }
    for platform in platforms::PLATFORMS {
        println!("{:<7} {:<22} {:?}", platform.id, platform.name, platform.status);
        println!("        {}", platform.toolkit);
        for need in platform.needs {
            println!("        - {need}");
        }
    }
    Ok(())
}

/// A program name the store and file names accept.
fn program_name(stem: &str) -> String {
    stem.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect()
}

fn new_project(args: &[String]) -> Result<(), String> {
    let image_arg = args.get(2).ok_or("new-project needs an image and an outdir")?;
    let outdir = PathBuf::from(args.get(3).ok_or("new-project needs an outdir")?);
    let mut image_path = PathBuf::from(image_arg);
    let mut bytes = std::fs::read(&image_path).map_err(|e| format!("{image_arg}: {e}"))?;
    let mut image_name = image_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .ok_or("the image has no file name")?;

    // A disc image: take the boot executable SYSTEM.CNF names.
    if let Some((name, elf)) = new_project::iso::boot_executable(&bytes)? {
        eprintln!("{image_arg}: ISO9660 disc image; using its boot executable {name} ({} bytes)", elf.len());
        let staged = outdir.join("orig").join(&name);
        std::fs::create_dir_all(staged.parent().unwrap()).map_err(|e| e.to_string())?;
        std::fs::write(&staged, &elf).map_err(|e| format!("{}: {e}", staged.display()))?;
        image_path = staged;
        image_name = name;
        bytes = elf;
    }

    // A Windows executable: i386 PE projects are per-function (new_project_pe.rs); a PE32+ is refused with the reason.
    let pe = match new_project::pe::detect_platform(&bytes) {
        Some(Err(reason)) if flag(args, "--platform").is_none() => return Err(format!("{image_arg}: {reason}")),
        Some(Ok(id)) => Some(id),
        _ => None,
    };
    let platform = flag(args, "--platform").unwrap_or_else(|| {
        if let Some(id) = pe {
            id.into()
        } else if new_project::looks_like_ps2_elf(&bytes) {
            "ps2".into()
        } else if let Some(mips) = new_project::detect_mips_platform(&bytes) {
            mips.into()
        } else if let Some(arm) = new_project::detect_arm_platform(&bytes) {
            arm.into()
        } else if let Some(gc) = new_project::gc::detect_platform(&bytes) {
            gc.into()
        } else {
            new_project::scaffold::detect_platform(&bytes).map(str::to_string).unwrap_or_else(|| "unknown".into())
        }
    });
    // Nintendo 64, PlayStation, PSP: splat repositories (new_project_mips.rs).
    if matches!(platform.as_str(), "n64" | "psx" | "psp") {
        return mips_cli::run(args, &platform, &image_path, &image_name, &outdir, &bytes);
    }
    // Game Boy Advance, Nintendo DS: GNU as/ld units and ds-decomp (new_project_arm.rs).
    if matches!(platform.as_str(), "gba" | "nds") {
        return arm_cli::run(args, &platform, &image_path, &image_name, &outdir, &bytes);
    }
    // Windows PE (i386): per-function projects with the era's Visual C++ (new_project_pe.rs).
    if platform == "pe" {
        return pe_cli::run(args, &image_path, &image_name, &outdir, &bytes);
    }
    // GameCube and Wii: decomp-toolkit repositories (new_project_gc.rs).
    if matches!(platform.as_str(), "gc" | "wii") {
        return gc_cli::run(args, &platform, &image_path, &image_name, &outdir, &bytes);
    }
    // 3DS, Switch, PS3, PS4, Vita, Xbox 360: the non-matching scaffold.
    if new_project::scaffold::target(&platform).is_some() {
        return scaffold_cli::run(args, &platform, &image_path, &image_name, &outdir, &bytes);
    }
    if platform != "ps2" {
        let ids: Vec<&str> = platforms::PLATFORMS.iter().map(|row| row.id).collect();
        return Err(if platform == "unknown" {
            format!("new-project: the platform of this image was not recognised; pass --platform ID (one of: {})", ids.join(", "))
        } else {
            format!("new-project: `{platform}` is not a platform with a plugin (one of: {})", ids.join(", "))
        });
    }

    let project_name = flag(args, "--name").unwrap_or_else(|| {
        Path::new(&image_name).file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "game".into())
    });
    let program = program_name(&project_name);
    let manifest = match flag(args, "--manifest") {
        Some(path) => {
            Manifest::parse(&std::fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?)
                .map_err(|e| format!("{path}: {e}"))?
        }
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
    let orig = outdir.join("orig").join(&image_name);
    std::fs::create_dir_all(orig.parent().unwrap()).map_err(|e| e.to_string())?;
    if std::fs::canonicalize(&image_path).ok() != std::fs::canonicalize(&orig).ok() {
        std::fs::write(&orig, &bytes).map_err(|e| format!("{}: {e}", orig.display()))?;
    }

    // Import: functions, symbols and prototypes come from the store.
    let store = outdir.join(".romwright");
    let core = Core::open(&store).map_err(|e| e.to_string())?;
    let keys = romwright_core::native::keys::KeyStore::load_all(&[]).map_err(|e| e.to_string())?;
    let pack = flag(args, "--fact-pack").map(PathBuf::from);
    let (stored, _, facts_reports) = core
        .import_native_with_facts(&orig, &program, &[], true, None, None, &keys, pack.as_deref())
        .map_err(|e| e.to_string())?;
    let summary = stored.first().ok_or("import produced no program")?;
    eprintln!("imported {} ({} functions, {})", summary.program, summary.functions, summary.language);
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

    let version = env!("CARGO_PKG_VERSION");
    let (files, report) = ps2::plan(&ps2::Ps2Inputs {
        image: &bytes,
        image_name: &image_name,
        project_name: &project_name,
        facts: &export,
        prototypes: &prototypes,
        manifest: &manifest,
        compiler_id: flag(args, "--compiler").as_deref(),
        cflags: flag(args, "--cflags").map(|f| f.split_whitespace().map(str::to_string).collect()),
        profile: profile.as_deref(),
        romwright_version: version,
    })?;
    new_project::write_files(&outdir, &files).map_err(|e| format!("{}: {e}", outdir.display()))?;

    // Optional non-matching reference C, kept out of the build.
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
                .map(|a| {
                    u64::from_str_radix(a.trim().trim_start_matches("0x"), 16)
                        .map(Some)
                        .map_err(|e| format!("--decompile {a}: {e}"))
                })
                .collect::<Result<_, _>>()?
        };
        for entry in entries {
            core.export_m2c(&orig, &summary.program, &target, None, entry, &options)
                .map_err(|e| format!("decompile {entry:?}: {e}"))?;
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
            "wrote {}: {} ({}, {:?}), {} functions as asm units, {} binary units, {} symbols, {} prototypes ({} skipped), splat `{}`, compiler `{}`",
            outdir.display(),
            report.detection.family.id(),
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
        println!("next: cd {} && python3 -m pip install -r requirements.txt && python3 configure.py && ninja", outdir.display());
    }
    Ok(())
}
