//! lre-cli: scriptable automation over the Core API (spec 17.1).
//!
//! End-to-end sequence proven by this binary:
//!   lre-cli import <binary> [--project DIR] [--no-analysis] [--no-analysis]
//!   lre-cli open <program> [--project DIR]
//!   lre-cli functions <program> [--project DIR]
//!   lre-cli diff <program> --reference DIR [--apply] [--json]
//!   lre-cli symbols <program>
//!   lre-cli xrefs <program> --to|--from <address>
//!   lre-cli rename <program> <address> <name>
//!   lre-cli decompile <program> <address>   (bridge required)
//!   lre-cli disasm <program> <address> [-n N]
//!   lre-cli open <program>                  (store-only reopen: no JVM)
//!
//! The native commands (`import`, `mem`, `disasm`,
//! `decompile`) are thin delegates to Core — the same methods a GUI
//! consumes — so no consumer has to re-implement the spawn logic.

use lre_core::{bridge::Bridge, Core};
use std::path::{Path, PathBuf};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        usage();
    }
    let code = run(&args);
    std::process::exit(code);
}

fn usage() {
    eprintln!(
        "usage:
  lre-cli import <binary> [--name NAME] [--signatures DB[,DB]] [--timings] [--project DIR]
  lre-cli decompile <binary> <address> [--name NAME] [--project DIR] [--base HEX]
  lre-cli decompile-batch <binary> <addr,addr,...> [--name NAME] [--project DIR] [--base HEX]
  lre-cli decompile-doc <binary> <address> [--name NAME] [--project DIR] [--base HEX]
  lre-cli disasm <binary> <address> [-n N]
  lre-cli architectures [--project DIR]   (uses VENTRIS_GHIDRA)
  lre-cli open <program> [--project DIR]
  lre-cli functions <program> [--offset N] [--limit N] [--filter TEXT] [--project DIR]
  lre-cli analyse-function <binary> <program> <address> [--project DIR] [--json]
  lre-cli structure <binary> <program> <addr[,addr...]> [--project DIR] [--json]
  lre-cli infer-types <binary> <program> <addr[,addr...]> [--project DIR] [--json]
  lre-cli detect-functions <binary> <program> [--unit N] [--whole-range] [--project DIR] [--json]
  lre-cli status <program> [--project DIR] [--json]
  lre-cli analyse-pending <binary> <program> [--budget N] [--project DIR] [--json]
  lre-cli diff <program> --reference DIR [--reference-name N] [--apply] [--matcher nap|greedy] [--no-semantic]
  lre-cli index-semantics <binary> <program> [--project DIR]
  lre-cli symbols <program> [--project DIR]
  lre-cli xrefs <program> [--to HEX | --from HEX] [--project DIR] [--evidence KIND]
  lre-cli comments <program> [--project DIR]
  lre-cli comment <program> <address> <text> [--function HEX] [--project DIR]
  lre-cli types <program> [--project DIR]
  lre-cli undo <program> [--project DIR]
  lre-cli strings <program> [--project DIR]
  lre-cli search <program> <term> [--limit N] [--project DIR]
  lre-cli graph <program> [--largest --binary BINARY] [--project DIR]
  lre-cli memory-regions <program> [--project DIR]
  lre-cli programs [--project DIR]
  lre-cli locate <address-hex> [--follow] [--project DIR]
  lre-cli bookmarks <program> [--project DIR]
  lre-cli bookmark <program> <address> <label> [comment] [--project DIR]
  lre-cli patches <program> [--project DIR]
  lre-cli patch <program> <address> <original-hex> <patched-hex> [--disabled] [--project DIR]
  lre-cli rename <program> <address> <new-name> [--project DIR]
  lre-cli signatures build --archive A --package P --license L --out DB [--report R] [--min-bytes N]
  lre-cli signatures info --db DB
  lre-cli mem <binary> <vaddr-hex> [size]
  lre-cli provenance [<program>] [--project DIR] [--json]

oracle generation only (launches the Stage-1 Java bridge):
  lre-cli import <binary> --oracle [--name NAME] [--project DIR] [--ghidra DIR]
  lre-cli decompile <program> <address> --oracle [--ghidra DIR]
  lre-cli decompile-batch <program> <addr,addr,...> --oracle [--ghidra DIR]
  lre-cli disasm <program> <address> --oracle [-n N] [--ghidra DIR]
  lre-cli dump-specs <program> --oracle --out <dir> [--ghidra DIR]"
        );
    std::process::exit(2);
}


fn parse_bytes(value: &str) -> Result<Vec<u8>, String> {
    let value = value.trim_start_matches("0x");
    if value.len() % 2 != 0 {
        return Err(format!("hex byte string has odd length: {value}"));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|e| e.to_string())?;
            u8::from_str_radix(text, 16).map_err(|e| format!("bad byte {text}: {e}"))
        })
        .collect()
}

fn hex_bytes(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn project_dir(args: &[String]) -> PathBuf {
    flag(args, "--project")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".lre"))
}

/// Launch the bridge JVM against the pinned install.
/// True when a bare flag is present.
fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|argument| argument == flag)
}

fn launch_bridge(args: &[String]) -> Result<Bridge, String> {
    let install = ghidra_dir(args);
    let classpath = find_ghidra_classpath(&install)?;
    let project = project_dir(args).join("bridge-projects");
    Bridge::launch(
        &PathBuf::from("java"),
        &classpath,
        &install,
        &project,
        &jvm_opens(),
    )
    .map_err(|e| e.to_string())
}

fn ghidra_dir(args: &[String]) -> PathBuf {
    flag(args, "--ghidra")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::var("VENTRIS_GHIDRA")
                .unwrap_or_else(|_| {
                    format!(
                        "{}/ghidra_12.1.3_PUBLIC",
                        std::env::var("HOME").unwrap_or_default()
                    )
                })
                .into()
        })
}

fn jvm_opens() -> Vec<String> {
    let mut options: Vec<String> = [
        "--add-opens=java.base/java.lang=ALL-UNNAMED",
        "--add-opens=java.base/java.lang.invoke=ALL-UNNAMED",
        "--add-opens=java.base/java.lang.ref=ALL-UNNAMED",
        "--add-opens=java.base/java.util=ALL-UNNAMED",
        "--add-opens=java.base/java.io=ALL-UNNAMED",
        "--add-opens=java.desktop/java.awt=ALL-UNNAMED",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    // A JVM default heap is not enough for every loader the install carries:
    // the Game Boy Advance loader maps the console's whole address space, and
    // stock `analyzeHeadless` needs its heap raised past the 2G default before
    // a 420-byte cartridge will import. The bridge is the oracle, so it gets
    // the ceiling that makes the oracle able to answer.
    let heap = std::env::var("VENTRIS_BRIDGE_MAXMEM").unwrap_or_else(|_| "8g".into());
    options.push(format!("-Xmx{heap}"));
    options
}

/// Builds the classpath from every runtime jar of the install.
fn find_ghidra_classpath(install: &Path) -> Result<String, String> {
    let pattern = install.join("Ghidra");
    let mut jars = Vec::new();
    collect_jars(&pattern, &mut jars)
        .map_err(|e| format!("classpath scan failed: {e}"))?;
    // Installed extensions are modules like any other: their jars carry
    // loaders (a GameCube DOL, a Game Boy Advance cartridge) and languages
    // (`r5900`) that the install's own opinion data already points at.
    // Dropping them left the oracle unable to load exactly the containers the
    // corpus is made of, which then read as "no such loader exists".
    jars.retain(|p| !p.to_string_lossy().contains("src.zip"));
    if jars.is_empty() {
        return Err(format!("no Ghidra jars under {}", install.display()));
    }
    let service = service_jar();
    jars.push(service);
    Ok(jars
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect::<Vec<_>>()
        .join(":"))
}

fn service_jar() -> PathBuf {
    // The service jar lives next to the crate; resolve from the executable's
    // build location via env override first.
    std::env::var_os("VENTRIS_SERVICE_JAR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("service/build/ventris-service.jar"))
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from("service/build/ventris-service.jar"))
}

fn collect_jars(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    if dir.is_file() {
        if dir.extension().map(|e| e == "jar").unwrap_or(false) {
            out.push(dir.to_path_buf());
        }
        return Ok(());
    }
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if name == "Extension" || name.ends_with("-src.zip") {
            continue;
        }
        if path.is_dir() {
            collect_jars(&path, out)?;
        } else if name.ends_with(".jar") {
            out.push(path);
        }
    }
    Ok(())
}

fn run(args: &[String]) -> i32 {
    match run_inner(args) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

/// Signature databases are plain files: no project store is opened for them.
fn signatures(args: &[String]) -> Result<(), String> {
    let action = args.get(2).map(String::as_str);
    match action {
        Some("build") => {
            let archive = flag(args, "--archive").ok_or("signatures build needs --archive")?;
            let package = flag(args, "--package").ok_or("signatures build needs --package")?;
            let license = flag(args, "--license").ok_or("signatures build needs --license")?;
            let out = flag(args, "--out").ok_or("signatures build needs --out")?;
            let min_compared = match flag(args, "--min-bytes") {
                Some(value) => value.parse().map_err(|_| "--min-bytes needs a number")?,
                None => lre_sig::build::MIN_COMPARED,
            };
            let bytes = std::fs::read(&archive).map_err(|error| format!("{archive}: {error}"))?;
            let (database, report) = lre_sig::from_archive(
                &bytes,
                &package,
                &license,
                min_compared,
                // One project-wide answer: the install's own opinion data,
                // queried exactly as an import queries it (lre-core).
                &|machine, big_endian, class64, flags| {
                    let install = lre_core::session::RuntimeConfig::from_env().ghidra_install;
                    lre_core::opinion::elf_selection(
                        &install,
                        lre_core::opinion::ElfMachine {
                            machine,
                            flags,
                            bits: if class64 { 64 } else { 32 },
                            big_endian,
                        },
                    )
                    .ok()
                    .map(|selection| selection.language)
                },
            )
            .map_err(|error| error.to_string())?;
            let encoded = database.encode();
            std::fs::write(&out, &encoded).map_err(|error| format!("{out}: {error}"))?;
            let summary = serde_json::json!({
                "archive": archive,
                "package": package,
                "license": license,
                "language": report.language,
                "members": report.members,
                "functions": report.functions,
                "records": report.records,
                "skipped": report.skipped,
                "min_compared_bytes": min_compared,
                "database": out,
                "database_bytes": encoded.len(),
            });
            if let Some(path) = flag(args, "--report") {
                std::fs::write(&path, serde_json::to_string_pretty(&summary).unwrap() + "\n")
                    .map_err(|error| format!("{path}: {error}"))?;
            }
            println!("{summary}");
            Ok(())
        }
        Some("info") => {
            let path = flag(args, "--db").ok_or("signatures info needs --db")?;
            let bytes = std::fs::read(&path).map_err(|error| format!("{path}: {error}"))?;
            let database = lre_sig::SignatureDb::decode(&bytes).map_err(|e| e.to_string())?;
            let records = database.signatures();
            let mut languages: Vec<_> =
                records.iter().map(|record| record.language.clone()).collect();
            languages.sort();
            languages.dedup();
            let mut packages: Vec<_> =
                records.iter().map(|record| record.package.clone()).collect();
            packages.sort();
            packages.dedup();
            let mut licenses: Vec<_> =
                records.iter().map(|record| record.license.clone()).collect();
            licenses.sort();
            licenses.dedup();
            println!(
                "{}",
                serde_json::json!({
                    "database": path,
                    "database_bytes": bytes.len(),
                    "records": records.len(),
                    "languages": languages,
                    "packages": packages,
                    "licenses": licenses,
                    "compared_bytes_min": records.iter()
                        .map(|record| record.compared_bytes()).min(),
                    "compared_bytes_total": records.iter()
                        .map(|record| record.compared_bytes()).sum::<usize>(),
                })
            );
            Ok(())
        }
        _ => Err("signatures needs `build` or `info`".into()),
    }
}

fn run_inner(args: &[String]) -> Result<(), String> {
    if args[1] == "signatures" {
        return signatures(args);
    }
    let core = Core::open(&project_dir(args)).map_err(|e| e.to_string())?;
    let cmd = args[1].as_str();
    match cmd {
        // The user path is native. `--oracle` is the only way to the Stage-1
        // Java bridge, which exists to produce oracles, not to serve users.
        "import" if !has_flag(args, "--oracle") => {
            let binary = args
                .get(2)
                .ok_or("import needs a binary path")?
                .clone();
            let program = flag(args, "--name")
                .unwrap_or_else(|| {
                    Path::new(&binary)
                        .file_name()
                        .map(|s| s.to_string_lossy().into_owned())
                        .unwrap_or_else(|| "program".into())
                });
            let databases: Vec<PathBuf> = flag(args, "--signatures")
                .into_iter()
                .flat_map(|value| {
                    value
                        .split(',')
                        .filter(|part| !part.is_empty())
                        .map(PathBuf::from)
                        .collect::<Vec<_>>()
                })
                .collect();
            let map: Option<PathBuf> = flag(args, "--map").map(PathBuf::from);
            // `--raw BASE --language ID`: a flat dump has no container to
            // sniff, so the caller supplies where it loads and what runs it.
            let raw = match flag(args, "--raw") {
                Some(base) => {
                    let base = u64::from_str_radix(
                        base.trim_start_matches("0x"),
                        16,
                    )
                    .map_err(|e| format!("--raw base: {e}"))?;
                    let language = flag(args, "--language")
                        .ok_or("--raw needs --language (e.g. ARM:LE:32:v6)")?;
                    Some((base, language))
                }
                None => None,
            };
            let started = std::time::Instant::now();
            let (stored, signatures) = core
                .import_native_with_signatures(
                    Path::new(&binary),
                    &program,
                    &databases,
                    !has_flag(args, "--no-analysis"),
                    map.as_deref(),
                    raw.as_ref().map(|(base, language)| (*base, language.as_str())),
                )
                .map_err(|e| e.to_string())?;
            let total = started.elapsed().as_secs_f64();
            // A container stores one program per processor; print each, so
            // nothing about what was imported is left implicit.
            for summary in &stored {
                println!(
                    "imported {} natively ({} functions, {})",
                    summary.program, summary.functions, summary.language
                );
            }
            let summary = stored
                .first()
                .ok_or_else(|| "import produced no program".to_string())?;
            if let Some(report) = signatures {
                println!(
                    "signatures: {} records, {} matched, {} renamed, {} conflicts",
                    report.records, report.matched, report.renamed, report.conflicts
                );
            }
            // Measured phases, for budget gates. Reporting a budget without
            // these numbers is how a threshold stops meaning anything.
            if has_flag(args, "--timings") {
                // One key per phase, summed over the rounds that ran it: a
                // phase measured four times used to print four identical
                // keys, and every JSON reader kept only the last, which is
                // how a 57 s switch round was read as 5.6 s.
                let mut totals: std::collections::BTreeMap<&str, f64> =
                    std::collections::BTreeMap::new();
                for phase in &summary.phases {
                    *totals.entry(phase.phase.as_str()).or_default() += phase.seconds;
                }
                let phases = totals
                    .iter()
                    .map(|(name, seconds)| format!("\"{name}\":{seconds:.6}"))
                    .collect::<Vec<_>>()
                    .join(",");
                let flow = summary.flow.map_or_else(
                    || "null".to_string(),
                    |flow| {
                        // `rounds` is part of the measurement: every phase
                        // timing above is a sum over them.
                        format!(
                            "{{\"requests\":{},\"instructions\":{},\"rounds\":{}}}",
                            flow.requests, flow.instructions, flow.rounds
                        )
                    },
                );
                // Why console-driven discovery did not run, when it did not:
                // a silent fallback to pointer-only seeds is what hid a whole
                // architecture's flow (m11-002).
                let patterns = summary
                    .patterns
                    .as_ref()
                    .map(|stats| {
                        format!(
                            ",\"patterns\":{}",
                            serde_json::to_string(stats).unwrap_or_default()
                        )
                    })
                    .unwrap_or_default();
                let refused = match summary.references_refused {
                    0 => String::new(),
                    count => format!(",\"references_refused\":{count}"),
                };
                let note = summary
                    .discovery_note
                    .as_deref()
                    .map(|note| format!(",\"discovery_note\":{}", serde_json::json!(note)))
                    .unwrap_or_default();
                println!(
                    "TIMINGS {{\"total\":{total:.6},\"functions\":{},\"shards\":{},\"flow\":{flow},\"phases\":{{{phases}}}{patterns}{refused}{note}}}",
                    summary.functions,
                    core.runtime_config().console_shards
                );
            }
        }
        // `export-symbols <program> [--format dtk|splat] [--splits FILE]`:
        // the store's own symbol list in a decomp project's grammar, so a
        // Ventris session hands dtk/splat the names it recovered rather
        // than making the project re-derive them. `--splits` supplies the
        // project's splits.txt so exported rows carry real section names;
        // without it the section column is the coarse `.text`/`.data`
        // split the store can defend.
        "export-symbols" => {
            let program = args.get(2).ok_or("export-symbols needs a program")?;
            let format = flag(args, "--format").unwrap_or_else(|| "dtk".into());
            let splits = flag(args, "--splits")
                .map(|path| {
                    std::fs::read_to_string(&path)
                        .map(|text| lre_core::native::linkmap::parse_splits(&text))
                        .map_err(|e| format!("{path}: {e}"))
                })
                .transpose()?
                .unwrap_or_default();
            let functions = core.functions(program).map_err(|e| e.to_string())?;
            let symbols = core.symbols(program).map_err(|e| e.to_string())?;
            let data_definitions =
                core.data_definitions(program).map_err(|e| e.to_string())?;
            let regions = core.memory_regions(program).map_err(|e| e.to_string())?;
            // Symbols outside every splits extent (unsplit TUs, gaps) still
            // need their real section name: name each memory region after the
            // splits extent covering most of it, so `.rodata` symbols don't
            // fall back to `.data` and corrupt dtk's section extents.
            let mut region_names: Vec<(u64, u64, String)> = Vec::new();
            for region in &regions {
                let start = region.start.offset;
                let end = start.saturating_add(region.size);
                let name = splits
                    .iter()
                    .filter(|extent| extent.start < end && extent.end > start)
                    .max_by_key(|extent| {
                        extent.end.min(end).saturating_sub(extent.start.max(start))
                    })
                    .map(|extent| extent.name.clone());
                if let Some(name) = name {
                    region_names.push((start, end, name));
                }
            }
            let section_of = |address: u64| -> &str {
                if let Some(name) =
                    lre_core::native::linkmap::section_at(&splits, address)
                {
                    return name;
                }
                region_names
                    .iter()
                    .find(|(start, end, _)| address >= *start && address < *end)
                    .map(|(_, _, name)| name.as_str())
                    .unwrap_or(".data")
            };
            let mut rows: Vec<String> = Vec::new();
            for function in &functions {
                let address = function.entry.offset;
                let section = section_of(address);
                match format.as_str() {
                    "splat" => rows.push(format!("{address:#x} {};", function.name)),
                    _ => rows.push(format!(
                        "{} = {section}:{address:#x}; // type:function size:{:#x} scope:global",
                        function.name, function.size
                    )),
                }
            }
            for symbol in &symbols {
                if symbol.external {
                    continue;
                }
                let address = symbol.address.offset;
                let section = section_of(address);
                // dtk types an unsized object `Unknown` and `dol diff`
                // rejects it; the data-definition table holds the size
                // the import recorded.
                let size = data_definitions
                    .iter()
                    .find(|row| row.address.offset == address)
                    .map(|row| row.size)
                    .unwrap_or(0);
                match format.as_str() {
                    "splat" => rows.push(format!("{address:#x} {};", symbol.name)),
                    _ => rows.push(format!(
                        "{} = {section}:{address:#x}; // type:object size:{size:#x} scope:global",
                        symbol.name
                    )),
                }
            }
            for row in &rows {
                println!("{row}");
            }
        }
        // `export-dtk <program> <outdir> [--splits FILE]`: write a dtk
        // project skeleton — config.yml, symbols.txt, splits.txt — from
        // the store. With --splits the section names are the project's
        // real ones; without it each memory region becomes a section
        // named after the region.
        "export-dtk" => {
            let program = args.get(2).ok_or("export-dtk needs a program")?;
            let outdir = Path::new(args.get(3).ok_or("export-dtk needs an outdir")?);
            std::fs::create_dir_all(outdir).map_err(|e| e.to_string())?;
            let splits_path = flag(args, "--splits");
            let splits = splits_path
                .as_ref()
                .map(|path| {
                    std::fs::read_to_string(path)
                        .map(|text| lre_core::native::linkmap::parse_splits(&text))
                        .map_err(|e| format!("{path}: {e}"))
                })
                .transpose()?
                .unwrap_or_default();
            let functions = core.functions(program).map_err(|e| e.to_string())?;
            let symbols = core.symbols(program).map_err(|e| e.to_string())?;
            let data_definitions =
                core.data_definitions(program).map_err(|e| e.to_string())?;
            let regions = core.memory_regions(program).map_err(|e| e.to_string())?;

            // splits.txt: when the project's own file was given, copy it
            // through; otherwise emit one extent per memory region.
            let splits_text = if let Some(path) = &splits_path {
                std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?
            } else {
                let mut text = String::from("Sections:\n");
                for region in &regions {
                    let kind = if region.permissions.contains('x') {
                        "code"
                    } else if region.permissions.contains('w') {
                        "data"
                    } else {
                        "rodata"
                    };
                    text.push_str(&format!("\t{} type:{kind} align:4\n", region.name));
                }
                text.push_str(&format!("{program}:\n"));
                for region in &regions {
                    text.push_str(&format!(
                        "\t{} start:{:#x} end:{:#x}\n",
                        region.name,
                        region.start.offset,
                        region.start.offset + region.size
                    ));
                }
                text
            };
            std::fs::write(outdir.join("splits.txt"), &splits_text)
                .map_err(|e| e.to_string())?;

            // Section names for symbols: splits extents first, then the
            // containing region's dominant extent name, then the region
            // name itself.
            let mut region_names: Vec<(u64, u64, String)> = Vec::new();
            for region in &regions {
                let start = region.start.offset;
                let end = start.saturating_add(region.size);
                let name = splits
                    .iter()
                    .filter(|extent| extent.start < end && extent.end > start)
                    .max_by_key(|extent| {
                        extent.end.min(end).saturating_sub(extent.start.max(start))
                    })
                    .map(|extent| extent.name.clone())
                    .unwrap_or_else(|| region.name.clone());
                region_names.push((start, end, name));
            }
            let section_of = |address: u64| -> &str {
                if let Some(name) =
                    lre_core::native::linkmap::section_at(&splits, address)
                {
                    return name;
                }
                region_names
                    .iter()
                    .find(|(start, end, _)| address >= *start && address < *end)
                    .map(|(_, _, name)| name.as_str())
                    .unwrap_or(".data")
            };
            let mut symbols_text = String::new();
            for function in &functions {
                let address = function.entry.offset;
                symbols_text.push_str(&format!(
                    "{} = {}:{address:#x}; // type:function size:{:#x} scope:global\n",
                    function.name,
                    section_of(address),
                    function.size
                ));
            }
            for symbol in &symbols {
                if symbol.external {
                    continue;
                }
                let address = symbol.address.offset;
                let size = data_definitions
                    .iter()
                    .find(|row| row.address.offset == address)
                    .map(|row| row.size)
                    .unwrap_or(0);
                symbols_text.push_str(&format!(
                    "{} = {}:{address:#x}; // type:object size:{size:#x} scope:global\n",
                    symbol.name,
                    section_of(address)
                ));
            }
            std::fs::write(outdir.join("symbols.txt"), &symbols_text)
                .map_err(|e| e.to_string())?;
            std::fs::write(
                outdir.join("config.yml"),
                format!(
                    "name: {program}\nobject: {program}\n\
                     symbols: symbols.txt\nsplits: splits.txt\n"
                ),
            )
            .map_err(|e| e.to_string())?;
            println!(
                "wrote {} ({} functions, {} symbols)",
                outdir.display(),
                functions.len(),
                symbols.len()
            );
        }
        // `export-splat <program> <outdir>`: write a splat skeleton —
        // <program>.yaml + symbol_addrs.txt — from the store. Segments
        // come from memory regions; symbols from functions+symbols.
        "export-splat" => {
            let program = args.get(2).ok_or("export-splat needs a program")?;
            let outdir = Path::new(args.get(3).ok_or("export-splat needs an outdir")?);
            std::fs::create_dir_all(outdir).map_err(|e| e.to_string())?;
            let functions = core.functions(program).map_err(|e| e.to_string())?;
            let symbols = core.symbols(program).map_err(|e| e.to_string())?;
            let regions = core.memory_regions(program).map_err(|e| e.to_string())?;
            let mut yaml = format!(
                "options:\n  platform: gc_wii\n  basename: {program}\n  \
                 base_path: .\n  target_path: {program}\n  asm_path: asm\n  \
                 src_path: src\n  build_path: build\n  compiler: GC/1.2.5\n  \
                 symbol_addrs_path: symbol_addrs.txt\n  \
                 undefined_syms_auto_path: undefined_syms_auto.txt\n\
                 segments:\n"
            );
            for region in &regions {
                let kind = if region.permissions.contains('x') {
                    "code"
                } else if region.permissions.contains('w') {
                    "data"
                } else {
                    "rodata"
                };
                yaml.push_str(&format!(
                    "  - name: {}\n    type: {kind}\n    vram: {:#x}\n    \
                     start: {:#x}\n    files: []\n",
                    region.name,
                    region.start.offset,
                    region.start.offset
                ));
            }
            std::fs::write(outdir.join(format!("{program}.yaml")), &yaml)
                .map_err(|e| e.to_string())?;
            let mut addrs = String::new();
            for function in &functions {
                addrs.push_str(&format!("{:#x} {};\n", function.entry.offset, function.name));
            }
            for symbol in &symbols {
                if !symbol.external {
                    addrs.push_str(&format!("{:#x} {};\n", symbol.address.offset, symbol.name));
                }
            }
            std::fs::write(outdir.join("symbol_addrs.txt"), &addrs)
                .map_err(|e| e.to_string())?;
            println!(
                "wrote {} ({} segments, {} symbols)",
                outdir.display(),
                regions.len(),
                functions.len() + symbols.len()
            );
        }
        // `export-objdiff <program> <outdir> --splits FILE`: write an
        // objdiff.json whose units are the splits.txt TUs, each carrying
        // the store's functions that fall inside its extents. objdiff
        // matches functions by symbol name within a unit, so the unit
        // list is the interop surface.
        "export-objdiff" => {
            let program = args.get(2).ok_or("export-objdiff needs a program")?;
            let outdir = Path::new(args.get(3).ok_or("export-objdiff needs an outdir")?);
            let splits_path = flag(args, "--splits")
                .ok_or("export-objdiff needs --splits <splits.txt>")?;
            let splits = lre_core::native::linkmap::parse_splits(
                &std::fs::read_to_string(&splits_path)
                    .map_err(|e| format!("{splits_path}: {e}"))?,
            );
            std::fs::create_dir_all(outdir).map_err(|e| e.to_string())?;
            let functions = core.functions(program).map_err(|e| e.to_string())?;

            // Group extents by TU; a unit's address range is the union
            // of its extents, its functions the store rows inside them.
            let mut tus: Vec<(String, Vec<&lre_core::native::linkmap::SplitExtent>)> =
                Vec::new();
            for extent in &splits {
                if let Some((_, list)) =
                    tus.iter_mut().find(|(name, _)| *name == extent.tu)
                {
                    list.push(extent);
                } else {
                    tus.push((extent.tu.clone(), vec![extent]));
                }
            }
            let mut units = Vec::new();
            for (tu, extents) in &tus {
                if tu.is_empty() {
                    continue;
                }
                let stem = tu.trim_end_matches(".c").trim_end_matches(".cpp");
                let fns: Vec<serde_json::Value> = functions
                    .iter()
                    .filter(|f| {
                        extents.iter().any(|e| {
                            f.entry.offset >= e.start && f.entry.offset < e.end
                        })
                    })
                    .map(|f| {
                        serde_json::json!({
                            "name": f.name,
                            "vram": format!("{:#x}", f.entry.offset),
                            "size": f.size,
                        })
                    })
                    .collect();
                units.push(serde_json::json!({
                    "name": format!("{program}/{stem}"),
                    "target_path": format!("build/{stem}.o"),
                    "base_path": format!("build/{stem}.o"),
                    "metadata": {
                        "auto_generated": false,
                        "source_path": tu,
                        "functions": fns,
                    }
                }));
            }
            let doc = serde_json::json!({
                "min_version": "2.0.0-beta.5",
                "custom_make": "ninja",
                "build_target": false,
                "units": units,
            });
            std::fs::write(
                outdir.join("objdiff.json"),
                serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
            println!(
                "wrote {} ({} units)",
                outdir.join("objdiff.json").display(),
                units.len()
            );
        }
        // `export-scratch <program> <addr> <binary> [--compiler ID]
        // [--c-flags FLAGS]`: emit a decomp.me scratch payload —
        // target_asm.s (the function's disassembly), ctx.c (context
        // stub), scratch.json (metadata). The POST to decomp.me is the
        // caller's; we produce the payload it accepts.
        "export-scratch" => {
            let program = args.get(2).ok_or("export-scratch needs a program")?;
            let addr = args.get(3).ok_or("export-scratch needs a vaddr")?;
            let binary = args.get(4).ok_or("export-scratch needs a binary")?;
            let outdir = flag(args, "--out").unwrap_or_else(|| "scratch".into());
            let compiler = flag(args, "--compiler")
                .unwrap_or_else(|| "mwcc_233_163".into());
            let c_flags = flag(args, "--c-flags")
                .unwrap_or_else(|| "-O4,p -nodefaults -proc gekko".into());
            let address = u64::from_str_radix(addr.trim_start_matches("0x"), 16)
                .map_err(|e| e.to_string())?;
            let functions = core.functions(program).map_err(|e| e.to_string())?;
            let function = functions
                .iter()
                .find(|f| f.entry.offset == address)
                .ok_or_else(|| format!("no function at {addr}"))?;
            // PPC is fixed-width: size/4 instructions exactly.
            let count = (function.size / 4).max(1) as u32;
            let asm = core
                .disasm_native(Path::new(binary), &format!("{:#x}", address), count)
                .map_err(|e| e.to_string())?;
            std::fs::create_dir_all(&outdir).map_err(|e| e.to_string())?;
            std::fs::write(format!("{outdir}/target_asm.s"), &asm)
                .map_err(|e| e.to_string())?;
            std::fs::write(
                format!("{outdir}/ctx.c"),
                format!("/* context for {} */\n", function.name),
            )
            .map_err(|e| e.to_string())?;
            let doc = serde_json::json!({
                "name": function.name,
                "compiler": compiler,
                "c_flags": c_flags,
                "target_asm": asm,
                "context": format!("/* context for {} */", function.name),
                "diff_label": function.name,
            });
            std::fs::write(
                format!("{outdir}/scratch.json"),
                serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
            println!(
                "wrote {outdir}/ ({} bytes asm, {} insns)",
                asm.len(),
                count
            );
        }
        // `objdiff-report <report.json> [--frogress URL]`: roll up an
        // objdiff-cli `report generate` JSON into per-function match-% and
        // project totals; optionally POST the frogress-shaped payload.
        // The report's units carry func_units with fuzzy_match_percent;
        // we flatten to one row per function and aggregate.
        "objdiff-report" => {
            let path = args.get(2).ok_or("objdiff-report needs a report.json")?;
            let text = std::fs::read_to_string(path)
                .map_err(|e| format!("{path}: {e}"))?;
            let report: serde_json::Value = serde_json::from_str(&text)
                .map_err(|e| format!("{path}: {e}"))?;
            let units = report["units"].as_array()
                .ok_or("report has no units array")?;
            let mut rows: Vec<serde_json::Value> = Vec::new();
            let mut total_code = 0u64;
            let mut matched_code = 0u64;
            let mut complete_code = 0u64;
            for unit in units {
                let unit_name = unit["name"].as_str().unwrap_or("");
                let funcs = unit["func_units"].as_object();
                if let Some(funcs) = funcs {
                    for (key, f) in funcs {
                        let name = f["name"].as_str().unwrap_or(key);
                        let fuzzy = f["fuzzy_match_percent"].as_f64().unwrap_or(0.0);
                        let matched = f["matched_code"].as_u64().unwrap_or(0);
                        let total = f["total_code"].as_u64().unwrap_or(0);
                        let complete = f["complete_code"].as_u64().unwrap_or(0);
                        total_code += total;
                        matched_code += matched;
                        complete_code += complete;
                        rows.push(serde_json::json!({
                            "unit": unit_name,
                            "function": name,
                            "fuzzy_match_percent": fuzzy,
                            "matched_code": matched,
                            "total_code": total,
                            "complete_code": complete,
                        }));
                    }
                }
            }
            let matched_pct = if total_code > 0 {
                (matched_code as f64 / total_code as f64) * 100.0
            } else { 0.0 };
            let complete_pct = if total_code > 0 {
                (complete_code as f64 / total_code as f64) * 100.0
            } else { 0.0 };
            let out = serde_json::json!({
                "functions": rows,
                "measures": {
                    "total_code": total_code,
                    "matched_code": matched_code,
                    "matched_code_percent": matched_pct,
                    "complete_code": complete_code,
                    "complete_code_percent": complete_pct,
                    "total_units": units.len(),
                    "total_functions": rows.len(),
                }
            });
            if let Some(out_path) = flag(args, "--frogress") {
                // frogress payload: {project, version, measures:{...}} —
                // written to a file for the caller to POST (matches the
                // export-scratch pattern: we produce the payload, the
                // caller owns the network).
                let payload = serde_json::json!({
                    "project": report["project"].as_str().unwrap_or("ventris"),
                    "version": report["version"].as_str().unwrap_or(""),
                    "measures": out["measures"],
                });
                std::fs::write(&out_path, serde_json::to_string_pretty(&payload)
                    .map_err(|e| e.to_string())?)
                    .map_err(|e| format!("{out_path}: {e}"))?;
                println!("wrote frogress payload {out_path}");
            }
            println!("{}", serde_json::to_string_pretty(&out).map_err(|e| e.to_string())?);
        }
        // `import-score <program> <addr> <score.json>`: record a
        // decomp.me compile score against a function. Accepts either a
        // decomp.me `GET /api/scratch/<slug>` response ({slug, name,
        // score, match_override}) or a local {function, score} file.
        // The score lands as a comment on the function so the store
        // carries the match state a project can roll up.
        "import-score" => {
            let program = args.get(2).ok_or("import-score needs a program")?;
            let addr = args.get(3).ok_or("import-score needs a vaddr")?;
            let path = args.get(4).ok_or("import-score needs a score.json")?;
            let address = u64::from_str_radix(addr.trim_start_matches("0x"), 16)
                .map_err(|e| e.to_string())?;
            let text = std::fs::read_to_string(path)
                .map_err(|e| format!("{path}: {e}"))?;
            let doc: serde_json::Value = serde_json::from_str(&text)
                .map_err(|e| format!("{path}: {e}"))?;
            // decomp.me shape: score is a number; match_override flags a
            // manually-forced match. Local shape: {function, score}.
            let score = doc["score"].as_f64()
                .or_else(|| doc["match_percent"].as_f64())
                .ok_or("score.json has no score/match_percent")?;
            let name = doc["name"].as_str()
                .or_else(|| doc["function"].as_str())
                .unwrap_or("");
            let slug = doc["slug"].as_str().unwrap_or("");
            let functions = core.functions(program).map_err(|e| e.to_string())?;
            let function = functions
                .iter()
                .find(|f| f.entry.offset == address)
                .ok_or_else(|| format!("no function at {addr}"))?;
            let body = format!(
                "decomp.me score: {:.2}% (slug={}, name={}, match_override={})",
                score, slug, name,
                doc["match_override"].as_bool().unwrap_or(false)
            );
            core.comment_command(
                program,
                &function.entry,
                &function.entry,
                "eol",
                &body,
            ).map_err(|e| e.to_string())?;
            println!("recorded score {:.2}% on {} ({})", score, function.name, addr);
        }
        // `import-trace <program> <trace.csv>`: ingest an emulator trace
        // — one `addr,kind[,thread]` row per event, kind in
        // exec|call|read|write|bp — into trace_events, then mark every
        // function whose entry an exec/call/bp event names as traced.
        "import-trace" => {
            let program = args.get(2).ok_or("import-trace needs a program")?;
            let path = args.get(3).ok_or("import-trace needs a trace file")?;
            let text = std::fs::read_to_string(path)
                .map_err(|e| format!("{path}: {e}"))?;
            let db = core.store_handle().map_err(|e| e.to_string())?;
            let id = db.program_id(program).map_err(|e| e.to_string())?;
            let mut events = 0u64;
            let mut hit_entries: Vec<String> = Vec::new();
            for raw in text.lines() {
                let line = raw.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let mut fields = line.split(',');
                let Some(addr_field) = fields.next() else { continue };
                let Some(kind) = fields.next() else { continue };
                let thread = fields.next().unwrap_or("").trim();
                let address = u64::from_str_radix(
                    addr_field.trim().trim_start_matches("0x"),
                    16,
                );
                let Ok(address) = address else { continue };
                let kind = kind.trim();
                let event = lre_model::TraceEvent {
                    sequence: 0,
                    at: String::new(),
                    thread: thread.to_string(),
                    address: Some(lre_model::Address::ram(address)),
                    kind: kind.to_string(),
                    payload: String::new(),
                    provenance: "import-trace".into(),
                };
                db.append_trace_event(id, &event).map_err(|e| e.to_string())?;
                events += 1;
                if matches!(kind, "exec" | "call" | "bp") {
                    hit_entries.push(format!("{address:08x}"));
                }
            }
            let marked = db
                .mark_traced(id, &hit_entries)
                .map_err(|e| e.to_string())?;
            println!(
                "imported {events} trace events, {} functions traced",
                marked.len()
            );
        }
        "mem" => {
            let binary = args.get(2).ok_or("mem needs a binary path")?.clone();
            let vaddr = u64::from_str_radix(
                args.get(3).ok_or("mem needs a vaddr (hex)")?,
                16,
            )
            .map_err(|e| e.to_string())?;
            let size: usize = args
                .get(4)
                .and_then(|s| s.parse().ok())
                .unwrap_or(32);
            let bytes = core
                .mem_native(Path::new(&binary), vaddr, size)
                .map_err(|e| e.to_string())?;
            for b in &bytes {
                print!("{b:02x} ");
            }
            println!();
        }
        "byte-scan" => {
            let binary = args.get(2).ok_or("byte-scan needs a binary path")?.clone();
            let vaddr = u64::from_str_radix(
                args.get(3)
                    .ok_or("byte-scan needs a vaddr (hex)")?
                    .trim()
                    .trim_start_matches("0x"),
                16,
            )
            .map_err(|e| e.to_string())?;
            let size: usize = args
                .get(4)
                .and_then(|s| s.parse().ok())
                .ok_or("byte-scan needs a byte size")?;
            let ask: Vec<u64> = args
                .iter()
                .find_map(|a| a.strip_prefix("--ask="))
                .map(|list| {
                    list.split(',')
                        .filter_map(|h| u64::from_str_radix(h.trim().trim_start_matches("0x"), 16).ok())
                        .collect()
                })
                .unwrap_or_default();
            let (digest, flows, ms, decoded, answered) = core
                .byte_scan(Path::new(&binary), vaddr, size, &ask)
                .map_err(|e| e.to_string())?;
            if has_flag(args, "--json") {
                let asked: Vec<serde_json::Value> = answered
                    .iter()
                    .map(|(a, l, f)| {
                        serde_json::json!({"address": a, "len": l, "flow": f})
                    })
                    .collect();
                println!(
                    "{}",
                    serde_json::json!({
                        "vaddr": vaddr,
                        "size": size,
                        "ms": ms,
                        "digest": digest,
                        "flows": flows.to_vec(),
                        "decoded": decoded,
                        "asked": asked,
                    })
                );
            } else {
                println!("sweep {size} bytes at {vaddr:#x}: {ms}ms digest {digest} decoded {decoded}");
                println!("flows: Next={} Call={} Jump={} Jcc={} IndCall={} Ind={} Stop={} Bad={}",
                    flows[0], flows[1], flows[2], flows[3], flows[4], flows[5], flows[6], flows[7]);
                for (address, len, flow) in &answered {
                    println!("{address:#x}: len {len} flow {flow}");
                }
            }
        }
        "disasm" if !has_flag(args, "--oracle") => {
            let binary = args.get(2).ok_or("disasm needs a binary path")?.clone();
            let addr = args.get(3).ok_or("disasm needs a vaddr (hex)")?.clone();
            let n: u32 = flag(args, "-n").and_then(|v| v.parse().ok()).unwrap_or(8);
            let text = core
                .disasm_native(Path::new(&binary), &addr, n)
                .map_err(|e| e.to_string())?;
            println!("{text}");
        }
        "decompile" if !has_flag(args, "--oracle") => {
            let binary = args
                .get(2)
                .ok_or("decompile needs a binary path")?
                .clone();
            let address = args
                .get(3)
                .ok_or("decompile needs a vaddr (hex)")?
                .clone();
            let program = flag(args, "--name").unwrap_or_else(|| {
                Path::new(&binary)
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "program".into())
            });
            let base = flag(args, "--base")
                .and_then(|b| u64::from_str_radix(b.trim_start_matches("0x"), 16).ok());
            let code = core
                .decompile_native(
                    Path::new(&binary),
                    &address,
                    &program,
                    base,
                )
                .map_err(|e| e.to_string())?;
            print!("{code}");
        }
        "decompile-batch" if !has_flag(args, "--oracle") => {
            let binary = args
                .get(2)
                .ok_or("decompile-batch needs a binary path")?
                .clone();
            let addresses: Vec<String> = args
                .get(3)
                .ok_or("decompile-batch needs a comma-separated address list")?
                .split(',')
                .filter(|item| !item.trim().is_empty())
                .map(|item| item.trim().to_string())
                .collect();
            let program = flag(args, "--name").unwrap_or_else(|| {
                Path::new(&binary)
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "program".into())
            });
            let base = flag(args, "--base")
                .and_then(|b| u64::from_str_radix(b.trim_start_matches("0x"), 16).ok());
            let answers = core
                .decompile_native_batch(Path::new(&binary), &addresses, &program, base)
                .map_err(|e| e.to_string())?;
            println!(
                "{}",
                serde_json::to_string(&answers).map_err(|e| e.to_string())?
            );
        }
        "decompile-doc" => {
            let binary = args
                .get(2)
                .ok_or("decompile-doc needs a binary path")?
                .clone();
            let address_arg = args
                .get(3)
                .ok_or("decompile-doc needs a vaddr (hex)")?
                .clone();
            let address = lre_model::Address::parse_ram_hex(&address_arg)
                .ok_or_else(|| format!("bad address: {address_arg}"))?;
            let program = flag(args, "--name").unwrap_or_else(|| {
                Path::new(&binary)
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "program".into())
            });
            let base = flag(args, "--base")
                .and_then(|b| u64::from_str_radix(b.trim_start_matches("0x"), 16).ok());
            let doc = core
                .decompile_native_doc(Path::new(&binary), &address, &program, base)
                .map_err(|e| e.to_string())?;
            println!(
                "{}",
                serde_json::to_string(&doc).map_err(|e| e.to_string())?
            );
        }
        "architectures" => {
            for architecture in core.architectures().map_err(|e| e.to_string())? {
                println!(
                    "{}\t{}\t{}\t{}\t{}",
                    architecture.id,
                    architecture.processor,
                    architecture.endian,
                    architecture.bits.map_or_else(|| "?".into(), |bits| bits.to_string()),
                    architecture.sla_count
                );
            }
        }
        "import" => {
            let binary = args
                .get(2)
                .ok_or("import --oracle needs a binary path")?
                .clone();
            let name = flag(args, "--name");
            let mut bridge = launch_bridge(args)?;
            let summary = core
                .import_program(&mut bridge, "main", Path::new(&binary), name.as_deref())
                .map_err(|e| e.to_string())?;
            println!(
                "imported {} ({} functions, {})",
                summary.program, summary.functions, summary.language
            );
            bridge.shutdown().map_err(|e| e.to_string())?;
        }
        "open" => {
            let program = args.get(2).ok_or("open needs a program name")?.clone();
            let summary = core.open_program(&program).map_err(|e| e.to_string())?;
            println!(
                "reopened {} ({} functions, {})",
                summary.program, summary.functions, summary.language
            );
        }
        "diff" => {
            // Whole-program structural diff: name the target program in this
            // project, and the project holding the reference program.
            let target = args.get(2).ok_or("diff needs a target program name")?.clone();
            let reference_project = flag(args, "--reference")
                .ok_or("diff needs --reference <project dir>")?;
            let reference = flag(args, "--reference-name");
            let mut options = lre_diff::Options::default();
            if let Some(value) = flag(args, "--min-score").and_then(|v| v.parse().ok()) {
                options.min_score = value;
            }
            if let Some(value) = flag(args, "--lambda").and_then(|v| v.parse().ok()) {
                options.lambda = value;
            }
            if let Some(value) = flag(args, "--candidates").and_then(|v| v.parse().ok()) {
                options.candidates = value;
            }
            options.matcher = match flag(args, "--matcher").as_deref() {
                None | Some("nap") => lre_diff::Matcher::Nap,
                Some("greedy") => lre_diff::Matcher::Greedy,
                Some(other) => return Err(format!("unknown matcher: {other}")),
            };
            if has_flag(args, "--no-semantic") {
                options.semantic = false;
            }
            let report = core
                .diff_program(
                    &target,
                    Path::new(&reference_project),
                    reference.as_deref(),
                    &options,
                    has_flag(args, "--apply"),
                )
                .map_err(|e| e.to_string())?;
            if has_flag(args, "--json") {
                println!(
                    "{}",
                    serde_json::to_string(&report).map_err(|e| e.to_string())?
                );
            } else {
                for row in &report.matches {
                    println!(
                        "{}  {}  {:.3}  {:?}  {} -> {}",
                        row.reference, row.target, row.score, row.evidence,
                        row.reference_name, row.target_name
                    );
                }
                println!(
                    "-- matched {} of {} target functions against {} reference functions ({} anchors); {} names {}",
                    report.matches.len(),
                    report.target_functions,
                    report.reference_functions,
                    report.anchors,
                    report.names.len(),
                    if has_flag(args, "--apply") { "applied" } else { "portable" }
                );
            }
        }
        "index-semantics" => {
            // BSim-style data-flow signatures for one program, from the
            // binary it was imported from: p-code needs a loaded console,
            // which the store does not keep. The diff reads these when the
            // semantic class is on and ignores them with --no-semantic.
            let binary = args.get(2).ok_or("index-semantics needs a binary")?.clone();
            let program = args
                .get(3)
                .ok_or("index-semantics needs a program name")?
                .clone();
            let indexed = core
                .index_semantics(Path::new(&binary), &program)
                .map_err(|e| e.to_string())?;
            println!("indexed {indexed} semantic signatures for {program}");
        }
        "functions" => {
            let program = args.get(2).ok_or("functions needs a program name")?.clone();
            let offset: u64 = flag(args, "--offset").and_then(|v| v.parse().ok()).unwrap_or(0);
            let limit: u64 = flag(args, "--limit").and_then(|v| v.parse().ok()).unwrap_or(0);
            let filter = flag(args, "--filter");
            let sort = flag(args, "--sort");
            let rows = if limit > 0 {
                let page = core
                    .functions_page(&program, offset, limit, filter.as_deref(), sort.as_deref())
                    .map_err(|e| e.to_string())?;
                println!("-- paged {}..{} of {:?} (rev {})", page.offset, page.offset + page.rows.len() as u64, page.total, page.revision);
                page.rows
            } else {
                core.functions(&program).map_err(|e| e.to_string())?
            };
            for f in &rows {
                // A convention is a fact about the function: show it where
                // the function is listed, not only in decompiled text.
                match f.calling_convention.as_deref() {
                    Some(model) => {
                        println!("{}  {:6}  {}  [{model}]", f.entry, f.size, f.name)
                    }
                    None => println!("{}  {:6}  {}", f.entry, f.size, f.name),
                }
            }
            if limit == 0 {
                println!("-- {} functions", rows.len());
            }
        }
        "status" => {
            let program = args.get(2).ok_or("status needs a program name")?.clone();
            let status = core.analysis_status(&program).map_err(|e| e.to_string())?;
            if has_flag(args, "--json") {
                println!(
                    "{}",
                    serde_json::to_string(&status).map_err(|e| e.to_string())?
                );
            } else {
                println!(
                    "{}  rev {}  {} functions: {} analysed, {} seeded, {} undecodable{}",
                    status.program,
                    status.revision,
                    status.functions,
                    status.analysed,
                    status.seeded,
                    status.undecodable,
                    if status.stale { " (provisional)" } else { "" }
                );
            }
        }
        "analyse-pending" => {
            let binary = args.get(2).ok_or("analyse-pending needs a binary")?.clone();
            let program = args
                .get(3)
                .ok_or("analyse-pending needs a program name")?
                .clone();
            let budget: usize = flag(args, "--budget")
                .and_then(|value| value.parse().ok())
                .unwrap_or(64);
            let status = core
                .analyse_pending(Path::new(&binary), &program, budget)
                .map_err(|e| e.to_string())?;
            if has_flag(args, "--json") {
                println!(
                    "{}",
                    serde_json::to_string(&status).map_err(|e| e.to_string())?
                );
            } else {
                println!(
                    "{}  rev {}  {} analysed, {} seeded left",
                    status.program, status.revision, status.analysed, status.seeded
                );
            }
        }
        "detect-functions" => {
            let binary = args.get(2).ok_or("detect-functions needs a binary")?.clone();
            let program = args
                .get(3)
                .ok_or("detect-functions needs a program name")?
                .clone();
            let unit: u64 = flag(args, "--unit")
                .and_then(|value| value.parse().ok())
                .unwrap_or(1);
            let found = core
                .detect_functions_cfg(
                    Path::new(&binary),
                    &program,
                    unit,
                    has_flag(args, "--whole-range"),
                )
                .map_err(|e| e.to_string())?;
            if has_flag(args, "--json") {
                println!("{found}");
            } else {
                println!(
                    "{} candidates from {} blocks in {} components ({} bytes swept, {:.2}s)",
                    found["entries"].as_array().map(Vec::len).unwrap_or(0),
                    found["blocks"],
                    found["components"],
                    found["swept_bytes"],
                    found["seconds"].as_f64().unwrap_or(0.0)
                );
            }
        }
        "infer-types" => {
            let binary = args.get(2).ok_or("infer-types needs a binary")?.clone();
            let program = args.get(3).ok_or("infer-types needs a program name")?.clone();
            let entries = args
                .get(4)
                .ok_or("infer-types needs one or more addresses")?
                .split(',')
                .map(|address| {
                    u64::from_str_radix(address.trim().trim_start_matches("0x"), 16)
                        .map(lre_model::Address::ram)
                        .map_err(|_| format!("not an address: {address}"))
                })
                .collect::<Result<Vec<_>, String>>()?;
            let rows = core
                .infer_types(Path::new(&binary), &program, &entries)
                .map_err(|e| e.to_string())?;
            for row in &rows {
                if has_flag(args, "--json") {
                    println!("{row}");
                } else {
                    println!(
                        "{}  {} ({}) -> {}",
                        row["entry"].as_str().unwrap_or("?"),
                        row["model"].as_str().unwrap_or("?"),
                        row["parameters"]
                            .as_array()
                            .map(|all| all
                                .iter()
                                .filter_map(|value| value.as_str())
                                .collect::<Vec<_>>()
                                .join(", "))
                            .unwrap_or_default(),
                        row["returns"].as_str().unwrap_or("?")
                    );
                }
            }
        }
        "prune-indirect-calls" => {
            let binary = args.get(2).ok_or("prune-indirect-calls needs a binary")?.clone();
            let program = args.get(3).ok_or("prune-indirect-calls needs a program name")?.clone();
            let entry = args
                .get(4)
                .ok_or("prune-indirect-calls needs a function entry")?
                .trim()
                .trim_start_matches("0x");
            let entry = u64::from_str_radix(entry, 16)
                .map(lre_model::Address::ram)
                .map_err(|_| format!("not an address: {entry}"))?;
            let rows = core
                .prune_indirect_calls(Path::new(&binary), &program, &entry)
                .map_err(|e| e.to_string())?;
            for row in &rows {
                if has_flag(args, "--json") {
                    println!("{row}");
                } else {
                    println!(
                        "{}  kept {} of {}",
                        row["site"].as_str().unwrap_or("?"),
                        row["kept"].as_array().map(|a| a.len()).unwrap_or(0),
                        row["candidates"].as_array().map(|a| a.len()).unwrap_or(0),
                    );
                }
            }
        }
        "structure" => {
            let binary = args.get(2).ok_or("structure needs a binary")?.clone();
            let program = args.get(3).ok_or("structure needs a program name")?.clone();
            let entries = args
                .get(4)
                .ok_or("structure needs one or more addresses")?
                .split(',')
                .map(|address| {
                    u64::from_str_radix(address.trim().trim_start_matches("0x"), 16)
                        .map(lre_model::Address::ram)
                        .map_err(|_| format!("not an address: {address}"))
                })
                .collect::<Result<Vec<_>, String>>()?;
            let answers = core
                .structure_functions(Path::new(&binary), &program, &entries)
                .map_err(|e| e.to_string())?;
            if has_flag(args, "--json") {
                for answer in &answers {
                    println!("{answer}");
                }
            } else {
                for answer in &answers {
                    println!(
                        "{}  gotos {}  {}",
                        answer["id"].as_str().unwrap_or("?"),
                        answer["gotos"],
                        answer["kinds"]
                    );
                }
            }
        }
        "analyse-function" => {
            let binary = args.get(2).ok_or("analyse-function needs a binary")?.clone();
            let program = args
                .get(3)
                .ok_or("analyse-function needs a program name")?
                .clone();
            let address = args
                .get(4)
                .ok_or("analyse-function needs an address")?
                .clone();
            let entry = lre_model::Address::ram(
                u64::from_str_radix(address.trim_start_matches("0x"), 16)
                    .map_err(|_| format!("not an address: {address}"))?,
            );
            let done = core
                .analyse_function(Path::new(&binary), &program, &entry)
                .map_err(|e| e.to_string())?;
            if has_flag(args, "--json") {
                println!(
                    "{}",
                    serde_json::to_string(&done).map_err(|e| e.to_string())?
                );
            } else {
                println!(
                    "{} {} bytes, {} instructions, {} xrefs, {} calls ({}, {:.3}s)",
                    done.entry,
                    done.size,
                    done.instructions,
                    done.xrefs,
                    done.calls.len(),
                    if done.reused { "reused" } else { &done.state },
                    done.seconds
                );
            }
        }
        "comments" => {
            let program = args.get(2).ok_or("comments needs a program name")?.clone();
            let rows = core.comments(&program).map_err(|e| e.to_string())?;
            for c in &rows {
                println!("{}  [{:5}]  {}", c.address, c.kind, c.text);
            }
            println!("-- {} comments", rows.len());
        }
        "types" => {
            let program = args.get(2).ok_or("types needs a program name")?.clone();
            let rows = core.datatypes(&program).map_err(|e| e.to_string())?;
            for t in &rows {
                println!("{}  {}", t.name, t.definition);
            }
            println!("-- {} types", rows.len());
        }
        "symbols" => {
            let program = args.get(2).ok_or("symbols needs a program name")?.clone();
            let rows = core.symbols(&program).map_err(|e| e.to_string())?;
            for s in &rows {
                println!(
                    "{}  {:8}  {}  {}",
                    s.address,
                    if s.external { "EXT" } else { "LOC" },
                    s.source,
                    s.name
                );
            }
            println!("-- {} symbols", rows.len());
        }
        "strings" => {
            let program = args.get(2).ok_or("strings needs a program name")?.clone();
            let rows = core.strings(&program).map_err(|e| e.to_string())?;
            for row in &rows {
                println!("{}  [{}]  {}", row.address, row.kind, row.value);
            }
            println!("-- {} strings", rows.len());
        }
        "search" => {
            let program = args.get(2).ok_or("search needs a program name")?.clone();
            let term = args.get(3).ok_or("search needs a term")?.clone();
            let limit = flag(args, "--limit")
                .and_then(|value| value.parse().ok())
                .unwrap_or(256);
            let rows = core.search(&program, &term, limit).map_err(|e| e.to_string())?;
            for row in &rows {
                let address = row
                    .address
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "-".into());
                println!("{address}  [{}]  {}  {}", row.kind, row.name, row.context);
            }
            println!("-- {} search hits", rows.len());
        }
        "graph" => {
            let program = args.get(2).ok_or("graph needs a program name")?.clone();
            let is_largest = args.iter().any(|a| a == "--largest");
            if is_largest {
                let binary_arg = flag(args, "--binary")
                    .ok_or("graph --largest requires --binary <path>")?;
                let binary_path = Path::new(&binary_arg);
                let mut functions = core.functions(&program).map_err(|e| e.to_string())?;
                functions.sort_by(|a, b| b.size.cmp(&a.size));
                let mut best: Option<(usize, String, String, serde_json::Value)> = None;
                for f in functions {
                    let addr_hex = format!("{:x}", f.entry.offset);
                    if let Ok(graph_json) = core.function_bb_graph(binary_path, &addr_hex) {
                        let blocks = graph_json
                            .get("nodes")
                            .and_then(|n| n.as_array())
                            .map(|a| a.len())
                            .unwrap_or(0);
                        let better = best.as_ref().map(|(count, _, _, _)| blocks > *count).unwrap_or(true);
                        if better {
                            best = Some((blocks, f.name.clone(), f.entry.to_string(), graph_json));
                        }
                        if blocks >= 200 {
                            break;
                        }
                    }
                }
                let (blocks, name, address, graph) = best
                    .ok_or_else(|| format!("no recoverable basic-block graph for program {program}"))?;
                let out = serde_json::json!({
                    "program": program,
                    "name": name,
                    "address": address,
                    "blocks": blocks,
                    "graph": graph,
                });
                println!("{out}");
            } else {
                let (nodes, edges) = core.function_graph(&program).map_err(|e| e.to_string())?;
                for node in &nodes {
                    println!("node {} {}", node.address, node.name);
                }
                for edge in &edges {
                    println!("edge {} --{}--> {}", edge.from, edge.kind, edge.to);
                }
                println!("-- {} nodes, {} edges", nodes.len(), edges.len());
            }
        }
        "provenance" => {
            // Every fact names the pass that produced it; this prints what
            // those names mean. With a program, only the classes it holds.
            let program = args.get(2).filter(|value| !value.starts_with("--")).cloned();
            let held: Option<std::collections::BTreeSet<String>> = match &program {
                Some(program) => {
                    let mut names = std::collections::BTreeSet::new();
                    for row in core.xrefs(program).map_err(|e| e.to_string())? {
                        names.insert(row.provenance.source.clone());
                    }
                    for row in core.symbols(program).map_err(|e| e.to_string())? {
                        names.insert(row.source.clone());
                    }
                    Some(names)
                }
                None => None,
            };
            let rows: Vec<_> = lre_model::provenance::CLASSES
                .iter()
                .filter(|entry| held.as_ref().is_none_or(|held| held.contains(entry.source)))
                .collect();
            if has_flag(args, "--json") {
                let payload: Vec<_> = rows
                    .iter()
                    .map(|entry| {
                        serde_json::json!({
                            "source": entry.source,
                            "explanation": entry.explanation,
                            "evidence": entry.evidence.as_str(),
                            "derives_confidence": entry.derives_confidence,
                        })
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&payload).map_err(|e| e.to_string())?);
            } else {
                for entry in &rows {
                    println!("{} [{}]\n    {}", entry.source, entry.evidence.as_str(),
                             entry.explanation);
                }
                println!("-- {} provenance classes", rows.len());
            }
            if let Some(held) = held {
                let unexplained: Vec<_> = held
                    .iter()
                    .filter(|name| lre_model::provenance::explain(name).is_none())
                    .collect();
                if !unexplained.is_empty() {
                    return Err(format!("provenance with no explanation: {unexplained:?}"));
                }
            }
        }
        "programs" => {
            // What this project holds: a project is not one image, and a DS
            // pair or an executable with overlays is the ordinary case.
            let rows = core.programs().map_err(|e| e.to_string())?;
            for row in &rows {
                println!(
                    "{}  {}  {} functions  revision {}",
                    row.program, row.language, row.functions, row.revision
                );
            }
            println!("-- {} programs", rows.len());
        }
        "locate" => {
            let address_arg = args.get(2).ok_or("locate needs an address")?;
            let address = lre_model::Address::parse_ram_hex(address_arg)
                .ok_or_else(|| format!("bad address: {address_arg}"))?;
            let rows = core.locate(&address).map_err(|e| e.to_string())?;
            let follow = has_flag(args, "--follow");
            for row in &rows {
                println!(
                    "{}  {}  {} {:#x}+{:#x} {}  {}",
                    row.program,
                    row.language,
                    row.region.name,
                    row.region.start.offset,
                    row.region.size,
                    row.region.permissions,
                    row.function.as_deref().unwrap_or("-")
                );
                if !follow {
                    continue;
                }
                // What that image holds there: images overlap, so these facts
                // belong to the program on the line above, not to the address.
                let symbols = core
                    .symbols(&row.program)
                    .map_err(|e| e.to_string())?
                    .iter()
                    .filter(|symbol| symbol.address == address)
                    .count();
                let to = core
                    .xrefs_to(&row.program, &address)
                    .map_err(|e| e.to_string())?
                    .len();
                let from = core
                    .xrefs_from(&row.program, &address)
                    .map_err(|e| e.to_string())?
                    .len();
                println!(
                    "    follow {} function={} symbols={symbols} xrefs_to={to} \
                     xrefs_from={from}",
                    row.program,
                    row.function.as_deref().unwrap_or("-")
                );
            }
            println!("-- {} programs map {}", rows.len(), address);
        }
        "memory-regions" => {
            let program = args.get(2).ok_or("memory-regions needs a program name")?.clone();
            let rows = core.memory_regions(&program).map_err(|e| e.to_string())?;
            for row in &rows {
                println!(
                    "{}  {:#x}  {:#x}  {}  {}",
                    row.name, row.start.offset, row.size, row.permissions, row.source
                );
            }
            println!("-- {} memory regions", rows.len());
        }
        "bookmarks" => {
            let program = args.get(2).ok_or("bookmarks needs a program name")?.clone();
            let rows = core.bookmarks(&program).map_err(|e| e.to_string())?;
            for row in &rows {
                println!("{}  {}  {}", row.address, row.label, row.comment);
            }
            println!("-- {} bookmarks", rows.len());
        }
        "bookmark" => {
            let program = args.get(2).ok_or("bookmark needs a program name")?.clone();
            let address_arg = args.get(3).ok_or("bookmark needs an address")?.clone();
            let label = args.get(4).ok_or("bookmark needs a label")?.clone();
            let comment = args
                .get(5)
                .filter(|value| !value.starts_with("--"))
                .cloned()
                .unwrap_or_default();
            let address = lre_model::Address::parse_ram_hex(&address_arg)
                .ok_or_else(|| format!("bad address: {address_arg}"))?;
            core.set_bookmark(
                &program,
                &lre_model::BookmarkRow {
                    address: address.clone(),
                    label: label.clone(),
                    comment,
                },
            )
            .map_err(|e| e.to_string())?;
            println!("bookmarked {} -> {}", address, label);
        }
        "patches" => {
            let program = args.get(2).ok_or("patches needs a program name")?.clone();
            let rows = core.patches(&program).map_err(|e| e.to_string())?;
            for row in &rows {
                println!(
                    "{}  {} -> {}  {}",
                    row.address,
                    hex_bytes(&row.original),
                    hex_bytes(&row.patched),
                    if row.enabled { "enabled" } else { "disabled" }
                );
            }
            println!("-- {} patches", rows.len());
        }
        "patch" => {
            let program = args.get(2).ok_or("patch needs a program name")?.clone();
            let address_arg = args.get(3).ok_or("patch needs an address")?.clone();
            let original = args.get(4).ok_or("patch needs original bytes")?.clone();
            let patched = args.get(5).ok_or("patch needs patched bytes")?.clone();
            let address = lre_model::Address::parse_ram_hex(&address_arg)
                .ok_or_else(|| format!("bad address: {address_arg}"))?;
            core.set_patch(
                &program,
                &lre_model::PatchRow {
                    address: address.clone(),
                    original: parse_bytes(&original)?,
                    patched: parse_bytes(&patched)?,
                    enabled: !args.iter().any(|value| value == "--disabled"),
                },
            )
            .map_err(|e| e.to_string())?;
            println!("patched {}", address);
        }
        "xrefs" => {
            let program = args.get(2).ok_or("xrefs needs a program name")?.clone();

            let addr_arg = flag(args, "--to").or_else(|| flag(args, "--from"));
            // The store filters by the kind of evidence a fact rests on, so an
            // audit asks for what it wants rather than printing everything and
            // grepping. Unknown kinds are refused, never silently ignored.
            let evidence = match flag(args, "--evidence") {
                Some(text) => Some(
                    lre_model::provenance::EvidenceKind::parse(&text).ok_or_else(|| {
                        format!("bad evidence kind: {text} (declared, decoded or inferred)")
                    })?,
                ),
                None => None,
            };
            let rows = match (addr_arg, evidence) {
                (Some(addr_str), _) => {
                    let address = lre_model::Address::parse_ram_hex(&addr_str)
                        .ok_or_else(|| format!("bad address: {addr_str}"))?;
                    let incoming = args.iter().any(|a| a == "--to");
                    core.xrefs_page(
                        &program, &address, incoming, 0, u64::from(u32::MAX), evidence,
                    )
                    .map(|page| page.rows)
                    .map_err(|e| e.to_string())?
                }
                // Filtering the whole program has no window to page, and
                // pretending otherwise would answer a question not asked.
                (None, Some(kind)) => {
                    return Err(format!(
                        "--evidence {} needs --to or --from",
                        kind.as_str()
                    ))
                }
                (None, None) => core.xrefs(&program).map_err(|e| e.to_string())?,
            };
            for r in &rows {
                let ownership = match r.provenance.kind {
                    lre_model::FactKind::Inferred => "inferred",
                    lre_model::FactKind::Asserted => "asserted",
                };
                let source = if r.provenance.source.is_empty() {
                    "unknown"
                } else {
                    r.provenance.source.as_str()
                };
                match r.provenance.confidence {
                    Some(confidence) => println!(
                        "{} --{}--> {} [{ownership}; source={source}; confidence={confidence}]",
                        r.from, r.kind, r.to
                    ),
                    None => println!(
                        "{} --{}--> {} [{ownership}; source={source}; confidence=unknown]",
                        r.from, r.kind, r.to
                    ),
                }
            }
            println!("-- {} xrefs", rows.len());
        }
        "rename" => {
            let program = args.get(2).ok_or("rename needs a program name")?.clone();
            let addr_arg = args.get(3).ok_or("rename needs an address")?.clone();
            let name = args.get(4).ok_or("rename needs a new name")?.clone();
            let address = lre_model::Address::parse_ram_hex(&addr_arg)
                .ok_or_else(|| format!("bad address: {addr_arg}"))?;
            core.rename_command(&program, &address, &name)
                .map_err(|e| e.to_string())?;
            println!("renamed {} -> {}", address, name);
        }
        "comment" => {
            let program = args.get(2).ok_or("comment needs a program name")?.clone();
            let address_arg = args.get(3).ok_or("comment needs an address")?.clone();
            let text = args.get(4).ok_or("comment needs comment text")?.clone();
            let address = lre_model::Address::parse_ram_hex(&address_arg)
                .ok_or_else(|| format!("bad address: {address_arg}"))?;
            let function = flag(args, "--function")
                .map(|value| {
                    lre_model::Address::parse_ram_hex(&value)
                        .ok_or_else(|| format!("bad function address: {value}"))
                })
                .transpose()?
                .unwrap_or_else(|| address.clone());
            let kind = flag(args, "--kind").unwrap_or_else(|| "eol".into());
            core.comment_command(&program, &address, &function, &kind, &text)
                .map_err(|e| e.to_string())?;
            println!("commented {} [{}]", address, kind);
        }
        "undo" => {
            let program = args.get(2).ok_or("undo needs a program name")?.clone();
            let what = core.undo_last(&program).map_err(|e| e.to_string())?;
            println!("{what}");
        }
        "dump-specs" if has_flag(args, "--oracle") => {
            let program = args.get(2).ok_or("dump-specs needs a program name")?.clone();
            let out = flag(args, "--out").ok_or("dump-specs needs --out DIR")?;
            let mut bridge = launch_bridge(args)?;
            let session = format!("cli-{program}");
            bridge
                .open(&session, &program)
                .map_err(|e| e.to_string())?;
            bridge
                .dump_specs(&session, &out)
                .map_err(|e| e.to_string())?;
            println!("specs written to {out}");
            bridge.shutdown().map_err(|e| e.to_string())?;
        }
        "decompile-batch" => {
            let program = args
                .get(2)
                .ok_or("--oracle needs a program name")?
                .clone();
            let addresses: Vec<String> = args
                .get(3)
                .ok_or("--oracle needs a comma-separated address list")?
                .split(',')
                .filter(|item| !item.trim().is_empty())
                .map(|item| item.trim().to_string())
                .collect();
            let mut bridge = launch_bridge(args)?;
            let session = format!("cli-{program}");
            bridge.open(&session, &program).map_err(|e| e.to_string())?;
            // One JVM launch and one analysis for the whole batch: the bridge
            // session is what makes a corpus-wide comparison affordable.
            let mut answers = std::collections::BTreeMap::new();
            for address in &addresses {
                let code = core
                    .decompile(&mut bridge, &session, address)
                    .map_err(|e| e.to_string())?;
                let offset = u64::from_str_radix(address.trim_start_matches("0x"), 16)
                    .map_err(|e| e.to_string())?;
                answers.insert(format!("{offset:08x}"), code);
            }
            println!(
                "{}",
                serde_json::to_string(&answers).map_err(|e| e.to_string())?
            );
            bridge.shutdown().map_err(|e| e.to_string())?;
        }
        "decompile" | "disasm" => {
            let program = args
                .get(2)
                .ok_or("--oracle needs a program name")?
                .clone();
            let address = args.get(3).ok_or("--oracle needs an address")?.clone();
            let mut bridge = launch_bridge(args)?;
            let session = format!("cli-{program}");
            bridge
                .open(&session, &program)
                .map_err(|e| e.to_string())?;
            if cmd == "decompile" {
                let code = core
                    .decompile(&mut bridge, &session, &address)
                    .map_err(|e| e.to_string())?;
                println!("{code}");
            } else {
                let n: u32 = flag(args, "-n").and_then(|v| v.parse().ok()).unwrap_or(32);
                let rows = core
                    .disassemble(&mut bridge, &session, &address, n)
                    .map_err(|e| e.to_string())?;
                for r in &rows {
                    println!("{}  {}", r.address, r.text);
                }
            }
            bridge.shutdown().map_err(|e| e.to_string())?;
        }
        _ => return Err(format!("unknown command: {cmd}")),
    }
    Ok(())
}
