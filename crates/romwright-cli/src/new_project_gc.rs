//! `new-project` for GameCube and Wii: a disc image (ISO, CISO, RVZ, WIA, WBFS,
//! Wii ISO) or a bare DOL in, a decomp-toolkit repository out. Included by
//! `new_project.rs`; see docs/new-project.md.

use super::{program_name, Manifest};
use crate::{flag, has_flag};
use romwright_core::new_project::{self, gc};
use romwright_core::Core;
use std::path::{Path, PathBuf};

/// A file name safe inside `orig/`.
fn safe_name(name: &str) -> String {
    name.chars().map(|c| if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') { c } else { '_' }).collect()
}

pub fn run(args: &[String], _platform: &str, image_path: &Path, image_name: &str, outdir: &Path, bytes: &[u8]) -> Result<(), String> {
    let (dol, rels, version, title, disc_note): (Vec<u8>, Vec<gc::DiscRelFile>, String, String, String) = match gc::extract_disc(bytes) {
        Some(Ok(files)) => {
            for note in &files.notes {
                eprintln!("warning: {note}");
            }
            let note = format!(
                "{} disc {} (game id {}, \"{}\"): boot DOL {} bytes, {} REL(s)",
                if files.wii { "Wii" } else { "GameCube" },
                image_path.display(),
                files.game_id,
                files.title,
                files.dol.len(),
                files.rels.len()
            );
            let version = if files.game_id.is_empty() { "GAME".to_string() } else { safe_name(&files.game_id) };
            (files.dol, files.rels, version, files.title, note)
        }
        Some(Err(error)) => return Err(format!("{}: {error}", image_path.display())),
        None => {
            let stem = Path::new(image_name).file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "game".into());
            let version = flag(args, "--version")
                .or_else(|| flag(args, "--name"))
                .map(|v| safe_name(&v).to_ascii_uppercase())
                .unwrap_or_else(|| safe_name(&stem).to_ascii_uppercase());
            (bytes.to_vec(), Vec::new(), version, String::new(), format!("DOL {} ({} bytes)", image_path.display(), bytes.len()))
        }
    };
    eprintln!("{disc_note}");
    let project_name = flag(args, "--name").unwrap_or_else(|| {
        if title.is_empty() { version.clone() } else { title.clone() }
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

    // The retail files go into orig/ (user-owned bytes, ignored by git).
    let orig = outdir.join("orig").join(&version);
    let dol_path = orig.join("sys").join("main.dol");
    std::fs::create_dir_all(dol_path.parent().unwrap()).map_err(|e| e.to_string())?;
    std::fs::write(&dol_path, &dol).map_err(|e| format!("{}: {e}", dol_path.display()))?;
    let mut modules = Vec::new();
    let mut taken = std::collections::HashSet::new();
    let mut seen = std::collections::HashSet::new();
    for rel in &rels {
        // The same file in two archives is one module (romwright's loader does the same).
        if !seen.insert((rel.name.clone(), romwright_core::export::sha1_hex(&rel.bytes))) {
            continue;
        }
        let mut name = safe_name(&rel.name);
        if !taken.insert(name.clone()) {
            let mut n = 2;
            while !taken.insert(format!("{name}_{n}")) {
                n += 1;
            }
            name = format!("{name}_{n}");
        }
        let path = orig.join("rels").join(format!("{name}.rel"));
        std::fs::create_dir_all(path.parent().unwrap()).map_err(|e| e.to_string())?;
        std::fs::write(&path, &rel.bytes).map_err(|e| format!("{}: {e}", path.display()))?;
        modules.push(gc::GcModule {
            rel_path: format!("orig/{version}/rels/{name}.rel"),
            linked: new_project::rel_layout::has_code(&rel.bytes),
            module_id: rel.bytes.get(..4).map_or(0, |b| u32::from_be_bytes([b[0], b[1], b[2], b[3]])),
            name,
            sha1: romwright_core::export::sha1_hex(&rel.bytes),
            symbols_txt: String::new(),
            splits_txt: new_project::rel_layout::rel_sections_block(&rel.bytes),
        });
    }

    // Modules that share an id are overlays. When another module relocates against that id, dtk
    // cannot tell which alternative is meant ("Couldn't find module N symbol"): the one that stays
    // resident is linked and the others are copied from the retail files. As the disc importer
    // decides it (`native/rel.rs`), the resident one is the file whose archive or directory holds
    // the most RELs.
    let referenced: std::collections::HashSet<u32> = rels.iter().flat_map(|rel| new_project::rel_layout::imported_modules(&rel.bytes)).collect();
    let mut per_container = std::collections::HashMap::<&str, usize>::new();
    for rel in &rels {
        *per_container.entry(rel.container.as_str()).or_default() += 1;
    }
    let container_size = |name: &str| rels.iter().find(|r| safe_name(&r.name) == name).map_or(0, |r| per_container[r.container.as_str()]);
    let mut resident: std::collections::HashMap<u32, (usize, String)> = std::collections::HashMap::new();
    for module in modules.iter().filter(|m| m.linked && referenced.contains(&m.module_id)) {
        let size = container_size(&module.name);
        let best = resident.entry(module.module_id).or_insert((size, module.name.clone()));
        if size > best.0 {
            *best = (size, module.name.clone());
        }
    }
    for module in modules.iter_mut().filter(|m| m.linked) {
        if let Some((_, name)) = resident.get(&module.module_id) {
            module.linked = *name == module.name;
        }
    }

    // Import the DOL: functions, symbols and prototypes come from the store.
    let store = outdir.join(".romwright");
    let core = Core::open(&store).map_err(|e| e.to_string())?;
    let keys = romwright_core::native::keys::KeyStore::load_all(&[]).map_err(|e| e.to_string())?;
    let pack = flag(args, "--fact-pack").map(PathBuf::from);
    let (stored, _, facts_reports) = core
        .import_native_with_facts(&dol_path, &program, &[], true, None, None, &keys, pack.as_deref())
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

    let (files, report) = gc::plan(&gc::GcInputs {
        dol: &dol,
        version: &version,
        project_name: &project_name,
        title: &title,
        facts: &export,
        prototypes: &prototypes,
        modules: &modules,
        manifest: &manifest,
        mw_version: flag(args, "--compiler").as_deref(),
        cflags: flag(args, "--cflags").map(|f| {
            // One flag per entry, as dtk-template writes them (`-O4,p`, `-proc gekko`).
            let mut flags: Vec<String> = Vec::new();
            for word in f.split_whitespace() {
                match flags.last_mut() {
                    Some(last) if !word.starts_with('-') || last.as_str() == "-i" || last.as_str() == "-ir" => {
                        last.push(' ');
                        last.push_str(word);
                    }
                    _ => flags.push(word.to_string()),
                }
            }
            flags
        }),
        profile: profile.as_deref(),
        romwright_version: env!("CARGO_PKG_VERSION"),
    })?;
    new_project::write_files(outdir, &files).map_err(|e| format!("{}: {e}", outdir.display()))?;

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
                .map(|a| u64::from_str_radix(a.trim().trim_start_matches("0x"), 16).map(Some).map_err(|e| format!("--decompile {a}: {e}")))
                .collect::<Result<_, _>>()?
        };
        for entry in entries {
            core.export_m2c(&dol_path, &summary.program, &target, None, entry, &options).map_err(|e| format!("decompile {entry:?}: {e}"))?;
        }
        decompiled = std::fs::read_dir(&target).map(|d| d.count()).unwrap_or(0);
    }

    if has_flag(args, "--json") {
        let mut value = serde_json::to_value(&report).map_err(|e| e.to_string())?;
        value["outdir"] = serde_json::json!(outdir);
        value["version"] = serde_json::json!(version);
        value["decompiled_files"] = serde_json::json!(decompiled);
        println!("{}", serde_json::to_string_pretty(&value).map_err(|e| e.to_string())?);
    } else {
        println!(
            "wrote {}: {} {} ({:?} confidence), {} sections ({}), {} functions, {} symbols ({} functions dtk cannot represent skipped), {} REL module(s), {} prototypes ({} skipped), compiler `{}`",
            outdir.display(),
            report.detection.family,
            report.detection.version_class,
            report.detection.confidence,
            report.sections,
            if report.sections_from_tables { "from the .init tables" } else { "from the DOL header" },
            report.functions,
            report.symbols,
            report.functions_skipped,
            report.modules,
            report.prototypes_emitted,
            report.prototypes_skipped,
            report.mw_version
        );
        println!("next: cd {} && python3 -m pip install -r requirements.txt && python3 configure.py && ninja", outdir.display());
    }
    Ok(())
}
