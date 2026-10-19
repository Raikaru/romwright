//! `new-project` for the platforms without a byte-matching ecosystem (3DS,
//! Switch, PS3, PS4, Vita, Xbox 360): imports the image, decompiles, and
//! writes the non-matching scaffold of `romwright_core::new_project::scaffold`.
//!
//! Extra flags over the PS2 path: `--keys FILE...` (user keys for the
//! container loaders; used in memory, never written), `--map FILE` (a linker
//! map or BINMAP naming the image's symbols), `--raw BASE --language ID` (a
//! flat dump, e.g. a 3DS ExeFS `.code`), `--compiler ID [--cflags FLAGS]` (a
//! retail compiler from the manifest, 3DS armcc, instead of the clang compile
//! check). `--decompile` takes `all` (the default), `first:N` (the first N
//! functions of each module by address), `ADDR,ADDR` or `none`; `--jobs N`
//! decompiles on N workers at once (default: the host's cores, at most 16).
//! `--tus FILE` places functions in folders named after their original source
//! files (`src/<module>/<file>/<function>.c`), one objdiff progress category each.
//! `--names FILE` (`ADDR NAME` lines) renames functions the analysis found and
//! seeds nothing, unlike `--map`. `--prototypes FILE|none` types the functions whose
//! (final) names a library table declares; the 3DS defaults to the CTR SDK's table.

use super::{flag, has_flag};
use romwright_core::native::linkmap::SplitExtent;
use romwright_core::new_project::{self, manifest::Manifest, scaffold};
use romwright_core::session::ProgramImage;
use romwright_core::Core;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// Reads `size` bytes at a virtual address of one image.
type Reader<'a> = Box<dyn Fn(u64, usize) -> Option<Vec<u8>> + 'a>;

fn hex_flag(args: &[String], name: &str) -> Result<Option<u64>, String> {
    flag(args, name)
        .map(|value| u64::from_str_radix(value.trim_start_matches("0x"), 16).map_err(|e| format!("{name} {value}: {e}")))
        .transpose()
}

/// What `--decompile` asks for.
enum Selection {
    All,
    /// The first N functions of each module, by address.
    First(usize),
    Addresses(Vec<u64>),
}

fn selection(args: &[String]) -> Result<Selection, String> {
    match flag(args, "--decompile").as_deref() {
        None | Some("all") => Ok(Selection::All),
        Some("none") => Ok(Selection::Addresses(Vec::new())),
        Some(first) if first.starts_with("first:") => first[6..]
            .parse::<usize>()
            .map(Selection::First)
            .map_err(|e| format!("--decompile {first}: {e}")),
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

/// `--tus FILE`: `{"units": [{"module", "address", "tu"}, ...]}`, each function
/// placed in its original source file (a relative path without extension).
fn source_files(path: &str) -> Result<HashMap<(String, u64), String>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let document: serde_json::Value = serde_json::from_str(&text).map_err(|e| format!("{path}: not JSON: {e}"))?;
    let units = document["units"].as_array().ok_or_else(|| format!("{path}: no `units` array"))?;
    let mut files = HashMap::new();
    for (index, unit) in units.iter().enumerate() {
        let field = |name: &str| unit[name].as_str().ok_or_else(|| format!("{path}: units[{index}] has no `{name}`"));
        let (module, address, file) = (field("module")?, field("address")?, field("tu")?);
        let address = u64::from_str_radix(address.trim_start_matches("0x"), 16)
            .map_err(|e| format!("{path}: units[{index}] address {address}: {e}"))?;
        if !scaffold::valid_file_path(file) {
            return Err(format!("{path}: units[{index}] file {file:?} is not a relative path of plain names"));
        }
        files.insert((module.to_string(), address), file.to_string());
    }
    Ok(files)
}

/// `--names FILE`: `ADDR NAME` per line (`#` comments). Unlike `--map`, which
/// seeds the analysis with every row (and so changes which functions it finds),
/// these only rename functions an unnamed import finds.
fn names_file(path: &str) -> Result<Vec<(u64, String)>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let mut names = Vec::new();
    for (number, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut words = line.split_whitespace();
        let (Some(address), Some(name), None) = (words.next(), words.next(), words.next()) else {
            return Err(format!("{path}:{}: expected `ADDR NAME`", number + 1));
        };
        let address = u64::from_str_radix(address.trim_start_matches("0x"), 16)
            .map_err(|e| format!("{path}:{}: address {address}: {e}", number + 1))?;
        names.push((address, name.to_string()));
    }
    Ok(names)
}

/// Functions per decompile batch: one worker start serves this many, and a
/// batch the decompiler refuses is redone function by function.
const BATCH: usize = 48;

/// Decompiles `units` of `program` into `scratch` on `jobs` threads, each with
/// its own store connection and worker, `BATCH` functions per call. Returns
/// how many functions the decompiler refused.
///
/// The threads use forks of `core`: their own connection, but one parsed image
/// (the emitter reads machine code from it) instead of one per thread.
fn decompile_parallel(
    core: &Core,
    orig: &Path,
    program: &str,
    scratch: &Path,
    units: &[&scaffold::Unit],
    options: &romwright_core::emit_m2c::M2cOptions,
    per_function: std::time::Duration,
    jobs: usize,
) -> Result<usize, String> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let batches: Vec<&[&scaffold::Unit]> = units.chunks(BATCH).collect();
    let next = AtomicUsize::new(0);
    let (done, refused) = (AtomicUsize::new(0), AtomicUsize::new(0));
    let total = units.len();
    let forks: Vec<Core> = (0..jobs.clamp(1, batches.len().max(1)))
        .map(|_| core.fork().map_err(|e| e.to_string()))
        .collect::<Result<_, _>>()?;
    std::thread::scope(|scope| -> Result<(), String> {
        let workers: Vec<_> = forks
            .into_iter()
            .map(|core| {
                let (next, done, refused, batches) = (&next, &done, &refused, &batches);
                scope.spawn(move || -> Result<(), String> {
                    loop {
                        let index = next.fetch_add(1, Ordering::Relaxed);
                        let Some(batch) = batches.get(index) else { return Ok(()) };
                        let splits: Vec<SplitExtent> = batch.iter().map(|u| extent(u)).collect();
                        let entries: Vec<u64> = batch.iter().map(|u| u.address).collect();
                        let budgeted = romwright_core::emit_m2c::M2cOptions {
                            budget: Some(per_function * entries.len() as u32),
                            ..options.clone()
                        };
                        if core.export_m2c_entries(orig, program, scratch, Some(&splits), Some(&entries), &budgeted).is_err() {
                            // The batch publishes nothing when any function fails: redo it
                            // function by function, skipping (and counting) the refusals.
                            let single = romwright_core::emit_m2c::M2cOptions { budget: Some(per_function), ..options.clone() };
                            for unit in batch.iter() {
                                if let Err(error) = core.export_m2c(orig, program, scratch, Some(&[extent(unit)]), Some(unit.address), &single) {
                                    eprintln!("warning: {program}: no C for {:#x}: {error}", unit.address);
                                    refused.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }
                        let finished = done.fetch_add(batch.len(), Ordering::Relaxed) + batch.len();
                        if total > BATCH {
                            eprintln!("decompile: {finished}/{total}");
                        }
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().map_err(|_| "a decompile thread panicked".to_string())??;
        }
        Ok(())
    })?;
    Ok(refused.into_inner())
}

pub fn run(args: &[String], platform: &str, image_path: &Path, image_name: &str, outdir: &Path, bytes: &[u8]) -> Result<(), String> {
    let target = scaffold::target(platform).ok_or_else(|| format!("`{platform}` has no scaffold target"))?;
    let project_name = flag(args, "--name").unwrap_or_else(|| {
        Path::new(image_name).file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "game".into())
    });
    let program: String = project_name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect();
    let manifest = match flag(args, "--manifest") {
        Some(path) => {
            Manifest::parse(&std::fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?).map_err(|e| format!("{path}: {e}"))?
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
    let compiler = scaffold::compiler_for(
        target,
        flag(args, "--compiler").as_deref(),
        flag(args, "--cflags").map(|f| f.split_whitespace().map(str::to_string).collect()),
        &manifest,
    )?;
    let files = match flag(args, "--tus") {
        Some(path) => source_files(&path)?,
        None => HashMap::new(),
    };

    // The retail image goes into orig/ (user-owned bytes, ignored by git).
    let orig = outdir.join("orig").join(image_name);
    std::fs::create_dir_all(orig.parent().unwrap()).map_err(|e| e.to_string())?;
    if std::fs::canonicalize(image_path).ok() != std::fs::canonicalize(&orig).ok() {
        std::fs::copy(image_path, &orig).map_err(|e| format!("{}: {e}", orig.display()))?;
    }

    // Keys are the user's: loaded for this process only.
    let key_paths: Vec<PathBuf> = args
        .iter()
        .skip_while(|a| a.as_str() != "--keys")
        .skip(1)
        .take_while(|a| !a.starts_with("--"))
        .map(PathBuf::from)
        .collect();
    let keys = romwright_core::native::keys::KeyStore::load_all(&key_paths).map_err(|e| e.to_string())?;
    let raw = match hex_flag(args, "--raw")? {
        Some(base) => Some((base, flag(args, "--language").ok_or("--raw needs --language (e.g. ARM:LE:32:v6)")?)),
        None => None,
    };
    let map = flag(args, "--map").map(PathBuf::from);

    let store = outdir.join(".romwright");
    let core = Core::open(&store).map_err(|e| e.to_string())?;
    let started = std::time::Instant::now();
    let (stored, _, reports) = core
        .import_native_with_facts(
            &orig,
            &program,
            &[],
            true,
            map.as_deref(),
            raw.as_ref().map(|(base, language)| (*base, language.as_str())),
            &keys,
            flag(args, "--fact-pack").map(PathBuf::from).as_deref(),
        )
        .map_err(|e| e.to_string())?;
    if stored.is_empty() {
        return Err("import produced no program".into());
    }
    for summary in &stored {
        eprintln!("imported {} ({} functions, {})", summary.program, summary.functions, summary.language);
    }
    for report in &reports {
        eprintln!("fact pack: {}: {} matched, {} renamed, {} prototypes", report.program, report.matched, report.renamed, report.prototypes);
    }
    eprintln!("import: {:.1}s", started.elapsed().as_secs_f64());
    if let Some(path) = flag(args, "--names") {
        let wanted = names_file(&path)?;
        for summary in &stored {
            let entries: HashSet<u64> = core
                .export_facts(&summary.program)
                .map_err(|e| e.to_string())?
                .functions
                .iter()
                .map(|f| f.entry.offset)
                .collect();
            let mut renamed = 0;
            for (address, name) in &wanted {
                if entries.contains(address) {
                    core.rename_command(&summary.program, &romwright_model::Address::ram(*address), name)
                        .map_err(|e| format!("{path}: {address:#x} {name}: {e}"))?;
                    renamed += 1;
                }
            }
            eprintln!("names: {}: {renamed} of {} renamed, {} name no function entry", summary.program, wanted.len(), wanted.len() - renamed);
        }
    }
    // Declarations by name, now that the names are final: `--prototypes FILE` (a library table, the
    // format of `oracle/library-prototypes-v1/`), else the platform's own table (the 3DS: the CTR SDK's),
    // `--prototypes none` for neither.
    let table = match flag(args, "--prototypes").as_deref() {
        Some("none") => None,
        Some(path) => Some((PathBuf::from(path), "library-prototypes:file")),
        None => core.platform_prototype_table(target.id),
    };
    if let Some((path, source)) = table {
        for summary in &stored {
            let report = core
                .apply_named_prototypes(&summary.program, &path, source)
                .map_err(|e| format!("{}: {e}", path.display()))?;
            eprintln!(
                "prototypes: {}: {} applied ({} named by the table, {} already typed, {} with types the language lacks) from {}",
                summary.program, report.applied, report.named, report.held, report.unrepresentable, path.display()
            );
        }
    }

    // Facts and the retail bytes of every program.
    let mut facts = Vec::new();
    let mut images = Vec::new();
    for summary in &stored {
        facts.push(core.scaffold_facts(&summary.program).map_err(|e| e.to_string())?);
        let request = core
            .execution_request(&orig, &summary.program, None, std::time::Duration::from_secs(600))
            .map_err(|e| e.to_string())?;
        images.push(ProgramImage::open_input(&request.project_dir, &request.input).map_err(|e| e.to_string())?);
    }
    let mapped_hash = |image: &ProgramImage| {
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
    let mut module_ids: Vec<String> = Vec::new();
    for summary in &stored {
        let suffix = summary.program.strip_prefix(&format!("{program}.")).unwrap_or("");
        let mut id: String = suffix.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect();
        if id.is_empty() {
            id = "main".into();
        }
        if module_ids.contains(&id) {
            id = format!("{id}_{}", module_ids.len());
        }
        module_ids.push(id);
    }
    let single_build_id = if stored.len() == 1 { scaffold::nso_build_id(bytes) } else { None };
    let readers: Vec<Reader<'_>> = images
        .iter()
        .map(|image| Box::new(move |address: u64, size: usize| image.read(address, size as u64)) as Reader<'_>)
        .collect();
    let modules: Vec<scaffold::ModuleInput> = stored
        .iter()
        .enumerate()
        .map(|(index, summary)| scaffold::ModuleInput {
            id: module_ids[index].clone(),
            program: summary.program.clone(),
            facts: &facts[index],
            code: readers[index].as_ref(),
            build_id: single_build_id.clone(),
            mapped_sha256: mapped_hash(&images[index]),
        })
        .collect();
    let inputs = scaffold::ScaffoldInputs {
        target,
        image_name,
        project_name: &project_name,
        // The retail file itself, streamed: `bytes` may be only its program view.
        image_sha256: romwright_core::import_cache::digest(image_path).ok_or_else(|| format!("{}: unreadable", image_path.display()))?,
        image_size: std::fs::metadata(image_path).map_err(|e| e.to_string())?.len(),
        modules,
        manifest: &manifest,
        profile: profile.as_deref(),
        files: &files,
        compiler,
        romwright_version: env!("CARGO_PKG_VERSION"),
    };
    let units = scaffold::layout(&inputs);

    // Decompile into a scratch directory; plan() wraps each file into src/.
    let scratch = store.join("m2c");
    let _ = std::fs::remove_dir_all(&scratch);
    // armcc rejects what clang accepts of the decompiler's text: `conform` spells it the way armcc takes
    let options = romwright_core::emit_m2c::M2cOptions { strict_c: inputs.compiler.retail(), ..Default::default() };
    // `--budget-ms` bounds each function; a batch gets the sum of its functions'.
    let per_function = flag(args, "--budget-ms")
        .map(|v| v.parse::<u64>().map_err(|e| e.to_string()))
        .transpose()?
        .map_or(romwright_core::exec::DEFAULT_BUDGET, std::time::Duration::from_millis);
    let jobs = match flag(args, "--jobs") {
        Some(value) => value.parse::<usize>().map_err(|e| format!("--jobs {value}: {e}"))?.max(1),
        None => std::thread::available_parallelism().map_or(1, |n| n.get()).min(16),
    };
    let chosen = selection(args)?;
    let started = std::time::Instant::now();
    let mut exported: usize = 0;
    let mut refused: usize = 0;
    for (index, summary) in stored.iter().enumerate() {
        let module_units: Vec<&scaffold::Unit> = units.iter().filter(|u| u.module == index).collect();
        let selected: Vec<&scaffold::Unit> = match &chosen {
            Selection::All => module_units,
            Selection::First(count) => module_units.into_iter().take(*count).collect(),
            Selection::Addresses(list) => module_units.into_iter().filter(|u| list.contains(&u.address)).collect(),
        };
        if selected.is_empty() {
            continue;
        }
        refused += decompile_parallel(&core, &orig, &summary.program, &scratch, &selected, &options, per_function, jobs)?;
    }
    let mut sources: HashMap<String, String> = HashMap::new();
    for unit in &units {
        if let Ok(text) = std::fs::read_to_string(scaffold::exported_source(&scratch, unit)) {
            sources.insert(unit.tu.clone(), text);
            exported += 1;
        }
    }
    eprintln!("decompile: {exported} function(s) in {:.1}s ({refused} refused by the decompiler)", started.elapsed().as_secs_f64());
    let _ = std::fs::remove_dir_all(&scratch);

    let (files, report) = scaffold::plan(&inputs, &units, &sources)?;
    new_project::write_files(outdir, &files).map_err(|e| format!("{}: {e}", outdir.display()))?;

    if has_flag(args, "--json") {
        let mut value = serde_json::to_value(&report).map_err(|e| e.to_string())?;
        value["outdir"] = serde_json::json!(outdir);
        println!("{}", serde_json::to_string_pretty(&value).map_err(|e| e.to_string())?);
    } else {
        println!(
            "wrote {}: {} for {} ({} module(s)), {} function(s), {} source(s), {} target object(s) ({} relocations), {} objdiff unit(s), {} symbols, {} prototypes ({} skipped), compiler {}",
            outdir.display(),
            if inputs.compiler.retail() { "per-function matching project" } else { "non-matching scaffold" },
            target.name,
            report.modules,
            report.functions,
            report.sources,
            report.target_objects,
            report.relocated_calls,
            report.objdiff_units,
            report.symbols,
            report.prototypes_emitted,
            report.prototypes_skipped,
            if inputs.compiler.retail() { format!("{} ({})", inputs.compiler.tool, inputs.compiler.flags.join(" ")) } else { format!("{} --target={}", inputs.compiler.tool, report.triple) }
        );
        println!("next: cd {} && python3 build.py", outdir.display());
    }
    Ok(())
}
