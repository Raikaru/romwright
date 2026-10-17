//! `new-project` for 32-bit Windows executables: imports the PE, decompiles, and writes the per-function repository of
//! `romwright_core::new_project::pe` (docs/new-project.md, "Windows PE").
//!
//! Flags beyond the common ones: `--compiler ID` (a manifest compiler: `msvc4.2`, `msvc6.0`, `msvc7.0`, `msvc7.1`,
//! `msvc8.0`; the importer's verdict when absent), `--cflags "FLAGS"` (cl flags), `--decompile all|first:N|ADDR,ADDR|none`.

use super::{flag, has_flag};
use romwright_core::native::linkmap::SplitExtent;
use romwright_core::new_project::{self, manifest::Manifest, pe, scaffold};
use romwright_core::session::ProgramImage;
use romwright_core::Core;
use std::collections::HashMap;
use std::path::Path;

enum Selection {
    All,
    First(usize),
    Addresses(Vec<u64>),
}

fn selection(args: &[String]) -> Result<Selection, String> {
    match flag(args, "--decompile").as_deref() {
        None | Some("all") => Ok(Selection::All),
        Some("none") => Ok(Selection::Addresses(Vec::new())),
        Some(first) if first.starts_with("first:") => first[6..].parse::<usize>().map(Selection::First).map_err(|e| format!("--decompile {first}: {e}")),
        Some(list) => list
            .split(',')
            .map(|a| u64::from_str_radix(a.trim().trim_start_matches("0x"), 16).map_err(|e| format!("--decompile {a}: {e}")))
            .collect::<Result<Vec<_>, _>>()
            .map(Selection::Addresses),
    }
}

fn extent(unit: &scaffold::Unit) -> SplitExtent {
    SplitExtent { tu: unit.tu.clone(), start: unit.address, end: unit.address + 1, name: String::new(), kind: "code".into() }
}

pub fn run(args: &[String], image_path: &Path, image_name: &str, outdir: &Path, bytes: &[u8]) -> Result<(), String> {
    let project_name = flag(args, "--name").unwrap_or_else(|| {
        Path::new(image_name).file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "game".into())
    });
    let program: String = project_name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect();
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
    let started = std::time::Instant::now();
    let (stored, _, reports) = core
        .import_native_with_facts(&orig, &program, &[], true, None, None, &keys, flag(args, "--fact-pack").map(std::path::PathBuf::from).as_deref())
        .map_err(|e| e.to_string())?;
    let summary = stored.first().ok_or("import produced no program")?;
    eprintln!("imported {} ({} functions, {})", summary.program, summary.functions, summary.language);
    for report in &reports {
        eprintln!("fact pack: {}: {} matched, {} renamed, {} prototypes", report.program, report.matched, report.renamed, report.prototypes);
    }
    eprintln!("import: {:.1}s", started.elapsed().as_secs_f64());

    let facts = core.pe_facts(&summary.program).map_err(|e| e.to_string())?;
    let request = core
        .execution_request(&orig, &summary.program, None, std::time::Duration::from_secs(600))
        .map_err(|e| e.to_string())?;
    let image = ProgramImage::open_input(&request.project_dir, &request.input).map_err(|e| e.to_string())?;
    let mapped_sha256 = {
        let mut regions: Vec<_> = image.regions().to_vec();
        regions.sort_by_key(|r| r.vaddr);
        let mut all = Vec::new();
        for region in &regions {
            if let Some(chunk) = image.read(region.vaddr, region.file_size) {
                all.extend_from_slice(&chunk);
            }
        }
        scaffold::sha256_hex(&all)
    };
    let detected = if facts.scaffold.facts.compiler.is_empty() { "unknown".to_string() } else { facts.scaffold.facts.compiler.clone() };
    let compiler = pe::compiler_for(
        &detected,
        flag(args, "--compiler").as_deref(),
        flag(args, "--cflags").map(|f| f.split_whitespace().map(str::to_string).collect()),
        &manifest,
    )?;
    eprintln!("compiler: {} ({})", compiler.tool, compiler.why);
    let reader = move |address: u64, size: usize| image.read(address, size as u64);
    let inputs = pe::PeInputs {
        image_name,
        project_name: &project_name,
        image_sha256: scaffold::sha256_hex(bytes),
        image_size: bytes.len() as u64,
        program: summary.program.clone(),
        facts: &facts,
        code: &reader,
        mapped_sha256,
        detected,
        compiler,
        manifest: &manifest,
        profile: profile.as_deref(),
        romwright_version: env!("CARGO_PKG_VERSION"),
    };
    let units = pe::layout(&inputs);

    // Decompile into a scratch directory; plan() wraps each file into src/.
    let scratch = store.join("m2c");
    let _ = std::fs::remove_dir_all(&scratch);
    // a whole-image export outlives the 60 s interactive default
    let options = romwright_core::emit_m2c::M2cOptions {
        budget: Some(std::time::Duration::from_millis(
            flag(args, "--budget-ms").map(|v| v.parse::<u64>().map_err(|e| e.to_string())).transpose()?.unwrap_or(3_600_000),
        )),
        ..Default::default()
    };
    let chosen = selection(args)?;
    let started = std::time::Instant::now();
    let mut refused = 0usize;
    let addresses: Vec<u64> = match &chosen {
        Selection::All => Vec::new(),
        Selection::First(count) => units.iter().take(*count).map(|u| u.address).collect(),
        Selection::Addresses(list) => list.clone(),
    };
    let mut one_by_one = |addresses: &[u64]| {
        for address in addresses {
            let Some(unit) = units.iter().find(|u| u.address == *address) else { continue };
            if let Err(error) = core.export_m2c(&orig, &summary.program, &scratch, Some(&[extent(unit)]), Some(*address), &options) {
                eprintln!("warning: no C for {address:#x}: {error}");
                refused += 1;
            }
        }
    };
    match &chosen {
        Selection::Addresses(list) if list.is_empty() => {}
        Selection::All => {
            let splits: Vec<SplitExtent> = units.iter().map(extent).collect();
            if let Err(error) = core.export_m2c(&orig, &summary.program, &scratch, Some(&splits), None, &options) {
                // The batch publishes nothing when any function fails: redo it function by function.
                eprintln!("warning: batch decompile failed ({error}); retrying function by function");
                let all: Vec<u64> = units.iter().map(|u| u.address).collect();
                one_by_one(&all);
            }
        }
        _ => one_by_one(&addresses),
    }
    let mut sources: HashMap<String, String> = HashMap::new();
    for unit in &units {
        if let Ok(text) = std::fs::read_to_string(scaffold::exported_source(&scratch, unit)) {
            sources.insert(unit.tu.clone(), text);
        }
    }
    eprintln!("decompile: {} function(s) in {:.1}s ({refused} refused by the decompiler)", sources.len(), started.elapsed().as_secs_f64());
    let _ = std::fs::remove_dir_all(&scratch);

    let (files, report) = pe::plan(&inputs, &units, &sources)?;
    new_project::write_files(outdir, &files).map_err(|e| format!("{}: {e}", outdir.display()))?;

    if has_flag(args, "--json") {
        let mut value = serde_json::to_value(&report).map_err(|e| e.to_string())?;
        value["outdir"] = serde_json::json!(outdir);
        println!("{}", serde_json::to_string_pretty(&value).map_err(|e| e.to_string())?);
    } else {
        println!(
            "wrote {}: per-function PE project ({} functions, {} sources, {} target objects with {} call and {} data relocations, {} objdiff units, {} symbols, {} prototypes ({} skipped)), compiler `{}` ({}), detected `{}`",
            outdir.display(),
            report.functions,
            report.sources,
            report.target_objects,
            report.call_relocations,
            report.data_relocations,
            report.objdiff_units,
            report.symbols,
            report.prototypes_emitted,
            report.prototypes_skipped,
            report.compiler,
            report.compiler_family,
            report.detected
        );
        println!("next: cd {} && python3 configure.py && python3 build.py && python3 build.py report", outdir.display());
    }
    Ok(())
}
