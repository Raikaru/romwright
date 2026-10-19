//! romwright-cli: scriptable automation over the Core API (spec 17.1).
//!
//! End-to-end sequence proven by this binary:
//!   romwright-cli import <binary> [--project DIR] [--no-analysis] [--no-analysis]
//!   romwright-cli open <program> [--project DIR]
//!   romwright-cli functions <program> [--project DIR]
//!   romwright-cli diff <program> --reference DIR [--apply] [--json]
//!   romwright-cli symbols <program>
//!   romwright-cli xrefs <program> --to|--from <address>
//!   romwright-cli rename <program> <address> <name>
//!   romwright-cli decompile <program> <address>   (bridge required)
//!   romwright-cli disasm <program> <address> [-n N]
//!   romwright-cli open <program>                  (store-only reopen: no JVM)
//!
//! The native commands (`import`, `mem`, `disasm`,
//! `decompile`) are thin delegates to Core — the same methods a GUI
//! consumes — so no consumer has to re-implement the spawn logic.

use romwright_core::{Core, bridge::Bridge};
use std::path::{Path, PathBuf};
mod compiler_rules;
mod facts;
mod match_cmd;
mod new_project;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if matches!(args.get(1).map(String::as_str), Some("help" | "-h" | "--help")) {
        println!("{USAGE}");
        return;
    }
    if args.len() < 2 {
        usage();
    }
    let code = run(&args);
    std::process::exit(code);
}

const USAGE: &str = "usage:
  romwright-cli import <binary> [--name NAME] [--signatures DB[,DB]] [--timings] [--project DIR]
  romwright-cli import ... [--compiler ID]   (record this compiler id, e.g. mwcc-ps2, ee-gcc-2.9x, ido, agbcc, instead of detecting one; ROMWRIGHT_COMPILER likewise)
  romwright-cli import ... [--fact-pack PACK]   (else ROMWRIGHT_FACT_PACK, else $XDG_DATA_HOME/romwright/fact-pack.sqlite; ROMWRIGHT_NO_FACT_PACK=1 disables)
  romwright-cli facts add-donor --pack PACK --project DIR --program NAME --truth TSV --donor JSON [--prototypes TSV]
  romwright-cli facts set-meta --pack PACK KEY VALUE   (KEY: gate_short_body | gate_min_donors)
  romwright-cli facts apply --project DIR --program NAME [--pack PACK] [--exclude GAME]... [--scan] [--json]
  romwright-cli decompile <binary> <address> [--name NAME] [--project DIR] [--base HEX]
  romwright-cli decompile-batch <binary> <addr,addr,...> [--name NAME] [--project DIR] [--base HEX]
  romwright-cli decompile-doc <binary> <address> [--name NAME] [--project DIR] [--base HEX]
  romwright-cli disasm <binary> <address> [-n N]
  romwright-cli architectures [--project DIR]   (uses ROMWRIGHT_GHIDRA)
  romwright-cli paths   (where the decompiler, worker, specs, library prototypes and Ghidra data are looked for, and whether each exists; docs/environment.md)
  romwright-cli open <program> [--project DIR]
  romwright-cli functions <program> [--offset N] [--limit N] [--filter TEXT] [--project DIR]
  romwright-cli analyse-function <binary> <program> <address> [--project DIR] [--json]
  romwright-cli structure <binary> <program> <addr[,addr...]> [--project DIR] [--json]
  romwright-cli infer-types <binary> <program> <addr[,addr...]> [--project DIR] [--json]
  romwright-cli detect-functions <binary> <program> [--unit N] [--whole-range] [--project DIR] [--json]
  romwright-cli status <program> [--project DIR] [--json]
  romwright-cli analyse-pending <binary> <program> [--budget N] [--project DIR] [--json]
  romwright-cli diff <program> --reference DIR [--reference-name N] [--apply] [--matcher nap|greedy] [--no-semantic]
  romwright-cli index-semantics <binary> <program> [--project DIR]
  romwright-cli symbols <program> [--project DIR]
  romwright-cli xrefs <program> [--to HEX | --from HEX] [--project DIR] [--evidence KIND]
  romwright-cli evidence <program> <address> [--json] [--project DIR]   (why one function exists: the rule that claimed it, its symbol, what reaches it)
  romwright-cli comments <program> [--project DIR]
  romwright-cli comment <program> <address> <text> [--function HEX] [--project DIR]
  romwright-cli types <program> [--project DIR]
  romwright-cli undo <program> [--project DIR]
  romwright-cli strings <program> [--project DIR]
  romwright-cli search <program> <term> [--limit N] [--project DIR]
  romwright-cli graph <program> [--largest --binary BINARY] [--project DIR]
  romwright-cli memory-regions <program> [--project DIR]
  romwright-cli programs [--project DIR]
  romwright-cli locate <address-hex> [--follow] [--project DIR]
  romwright-cli bookmarks <program> [--project DIR]
  romwright-cli bookmark <program> <address> <label> [comment] [--project DIR]
  romwright-cli patches <program> [--project DIR]
  romwright-cli patch <program> <address> <original-hex> <patched-hex> [--disabled] [--project DIR]
  romwright-cli rename <program> <address> <new-name> [--project DIR]
  romwright-cli assert-prototypes <program> <protos.json|-> [--source NAME] [--project DIR]
  romwright-cli assert-names <program> <names.json|-> [--project DIR]
  romwright-cli signatures build --archive A --package P --license L --out DB [--report R] [--min-bytes N]
  romwright-cli signatures info --db DB
  romwright-cli mem <binary> <vaddr-hex> [size]
  romwright-cli provenance [<program>] [--project DIR] [--json]
  romwright-cli matching-workspace <program> <request.json|-> [--project DIR]
  romwright-cli matching-run <binary> <program> <request.json|-> [--budget-ms N] [--base HEX] [--project DIR]
  romwright-cli export-c <binary> <program> <outdir> [--address HEX] [--splits FILE] [--transforms LIST] [--budget-ms N] [--context HEADER] [--project DIR]
  romwright-cli export-scratch <program> <address> <binary> --compiler ID --c-flags FLAGS [--target-object FILE] [--context FILE] [--out DIR] [--project DIR]
  romwright-cli export-dtk <program> <outdir> [--splits FILE] [--project DIR]
  romwright-cli export-objdiff <program> <outdir> --splits <splits.txt> --target-root DIR [--base-root DIR] [--source-root DIR] [--complete all|UNIT,UNIT] [--dtk-config config.json] [--project DIR]
  romwright-cli export-splat <program> <outdir> [--binary FILE] [--project DIR]
  romwright-cli new-project <image> <outdir> [--name NAME] [--platform ID] [--toolchain PROFILE.json] [--manifest FILE] [--compiler ID] [--cflags FLAGS] [--decompile all|first:N|ADDR,ADDR|none] [--fact-pack PACK] [--keys FILE...] [--map FILE] [--names FILE] [--prototypes FILE|none] [--json]   (--list-platforms: what each platform needs; docs/new-project.md)
  romwright-cli detect-compiler <image> [--json]
  romwright-cli match <name|0xADDR> [--project REPO] [--budget N] [--time SECS] [--write] [--json]   (inside a new-project repository: near-miss search over printing variants, scored with the repo's compiler; docs/match.md)
  romwright-cli compiler-rules [--json]   (the embedded compiler rules and their switch state; ROMWRIGHT_NO_COMPILER_RULES=1, ROMWRIGHT_COMPILER_RULES_DISABLE=id,id, ROMWRIGHT_COMPILER_RULES_ENABLE=id,id)
  romwright-cli export-symbols <program> [--project DIR]
  romwright-cli byte-scan <binary> <vaddr-hex> [--project DIR]
  romwright-cli import-score <program> <vaddr> <score.json> [--project DIR]
  romwright-cli import-trace <program> <trace-file> [--project DIR]
  romwright-cli match-source <program> <target-object> <source-C> --recipe <recipe.json> [--project DIR]
  romwright-cli matching-runs <program> [--after ID] [--limit N] [--project DIR]
  romwright-cli objdiff-report <report.json> [--previous PREV.json] [--frogress OUT] [--project DIR]
  romwright-cli oracle-signatures <program> [--project DIR]
  romwright-cli prune-indirect-calls <binary> <program> [--project DIR]

oracle generation only (launches the Stage-1 Java bridge):
  romwright-cli import <binary> --oracle [--name NAME] [--project DIR] [--ghidra DIR]
  romwright-cli decompile <program> <address> --oracle [--ghidra DIR]
  romwright-cli decompile-batch <program> <addr,addr,...> --oracle [--ghidra DIR]
  romwright-cli disasm <program> <address> --oracle [-n N] [--ghidra DIR]
  romwright-cli dump-specs <program> --oracle --out <dir> [--ghidra DIR]
  romwright-cli lint-specs [--ghidra DIR]   (validate every language module's spec files)
  romwright-cli ir-dump <binary> <addr,addr,...> [--base HEX]   (typed IR / normalized p-code)";

fn usage() {
    eprintln!("{USAGE}");
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
        .unwrap_or_else(|| PathBuf::from(".romwright"))
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
        .unwrap_or_else(romwright_core::native_runtime::ghidra_dir)
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
    let heap = std::env::var("ROMWRIGHT_BRIDGE_MAXMEM").unwrap_or_else(|_| "8g".into());
    options.push(format!("-Xmx{heap}"));
    options
}

/// Builds the classpath from every runtime jar of the install.
fn find_ghidra_classpath(install: &Path) -> Result<String, String> {
    let pattern = install.join("Ghidra");
    let mut jars = Vec::new();
    collect_jars(&pattern, &mut jars).map_err(|e| format!("classpath scan failed: {e}"))?;
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
    std::env::var_os("ROMWRIGHT_SERVICE_JAR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("service/build/romwright-service.jar"))
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from("service/build/romwright-service.jar"))
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
                None => romwright_sig::build::MIN_COMPARED,
            };
            let bytes = std::fs::read(&archive).map_err(|error| format!("{archive}: {error}"))?;
            let (database, report) = romwright_sig::from_archive(
                &bytes,
                &package,
                &license,
                min_compared,
                // One project-wide answer: the install's own opinion data,
                // queried exactly as an import queries it (romwright-core).
                &|machine, big_endian, class64, flags| {
                    let install = romwright_core::session::RuntimeConfig::from_env().ghidra_install;
                    romwright_core::opinion::elf_selection(
                        &install,
                        romwright_core::opinion::ElfMachine {
                            machine,
                            flags,
                            bits: if class64 { 64 } else { 32 },
                            big_endian,
                            e_type: 0,
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
                std::fs::write(
                    &path,
                    serde_json::to_string_pretty(&summary).unwrap() + "\n",
                )
                .map_err(|error| format!("{path}: {error}"))?;
            }
            println!("{summary}");
            Ok(())
        }
        Some("info") => {
            let path = flag(args, "--db").ok_or("signatures info needs --db")?;
            let bytes = std::fs::read(&path).map_err(|error| format!("{path}: {error}"))?;
            let database = romwright_sig::SignatureDb::decode(&bytes).map_err(|e| e.to_string())?;
            let records = database.signatures();
            let mut languages: Vec<_> = records
                .iter()
                .map(|record| record.language.clone())
                .collect();
            languages.sort();
            languages.dedup();
            let mut packages: Vec<_> = records
                .iter()
                .map(|record| record.package.clone())
                .collect();
            packages.sort();
            packages.dedup();
            let mut licenses: Vec<_> = records
                .iter()
                .map(|record| record.license.clone())
                .collect();
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
    if args[1] == "facts" && args.get(2).map(String::as_str) == Some("set-meta") {
        return facts::set_meta(args);
    }
    if args[1] == "compiler-rules" {
        return compiler_rules::run(args);
    }
    if args[1] == "paths" {
        let config = romwright_core::session::RuntimeConfig::from_env();
        for (name, path) in [
            ("worker", &config.worker_path),
            ("decompiler", &config.decompiler_path),
            ("specs", &config.spec_root),
            ("library-prototypes", &config.library_prototypes),
            ("ghidra", &config.ghidra_install),
        ] {
            let state = if path.exists() { "found" } else { "missing" };
            println!("{name}\t{state}\t{}", path.display());
        }
        return Ok(());
    }
    if matches!(args[1].as_str(), "new-project" | "detect-compiler") {
        return new_project::run(args);
    }
    if args[1] == "match" {
        return match_cmd::run(args);
    }
    let cmd = args[1].as_str();
    // `import --compiler ID` records that compiler id instead of detecting
    // one (the oracle import's `--compiler` names a Ghidra compiler spec).
    let mut config = romwright_core::session::RuntimeConfig::from_env();
    if cmd == "import" && !has_flag(args, "--oracle") {
        if let Some(id) = flag(args, "--compiler") {
            config.compiler = Some(id);
        }
    }
    let core = Core::open_with_config(&project_dir(args), config).map_err(|e| e.to_string())?;
    match cmd {
        // The user path is native. `--oracle` is the only way to the Stage-1
        // Java bridge, which exists to produce oracles, not to serve users.
        "import" if !has_flag(args, "--oracle") => {
            let binary = args.get(2).ok_or("import needs a binary path")?.clone();
            let program = flag(args, "--name").unwrap_or_else(|| {
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
                    let base = u64::from_str_radix(base.trim_start_matches("0x"), 16)
                        .map_err(|e| format!("--raw base: {e}"))?;
                    let language = flag(args, "--language")
                        .ok_or("--raw needs --language (e.g. ARM:LE:32:v6)")?;
                    Some((base, language))
                }
                None => None,
            };
            // User-supplied console keys: each `--keys <file>` is a
            // prod.keys/keys.txt/aes_keys.txt named-hex file or a raw
            // .rap/.klic blob. They reach the console loaders through the
            // KeyStore; absent keys leave the loaders' key-gap errors as-is.
            let key_paths: Vec<std::path::PathBuf> = args
                .iter()
                .skip_while(|a| a.as_str() != "--keys")
                .skip(1)
                .take_while(|a| !a.starts_with("--"))
                .map(std::path::PathBuf::from)
                .collect();
            let keys = romwright_core::native::keys::KeyStore::load_all(&key_paths)
                .map_err(|e| e.to_string())?;
            let started = std::time::Instant::now();
            let fact_pack = flag(args, "--fact-pack").map(PathBuf::from);
            let (stored, signatures, facts) = core
                .import_native_with_facts(
                    Path::new(&binary),
                    &program,
                    &databases,
                    !has_flag(args, "--no-analysis"),
                    map.as_deref(),
                    raw.as_ref()
                        .map(|(base, language)| (*base, language.as_str())),
                    &keys,
                    fact_pack.as_deref(),
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
                report_diagnostics(summary);
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
            for report in &facts {
                println!(
                    "fact pack: {}: {} matched, {} renamed, {} kept, {} abstained, {} gated, {} prototypes",
                    report.program, report.matched, report.renamed, report.kept_name, report.abstained, report.gated, report.prototypes
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
                let switch = summary
                    .switch
                    .as_ref()
                    .map(|stats| {
                        format!(
                            ",\"switch_stats\":{}",
                            serde_json::to_string(stats).unwrap_or_default()
                        )
                    })
                    .unwrap_or_default();
                let note = if summary.diagnostics.is_empty() {
                    String::new()
                } else {
                    format!(
                        ",\"diagnostics\":{}",
                        serde_json::to_string(&summary.diagnostics).unwrap_or_default()
                    )
                };
                println!(
                    "TIMINGS {{\"total\":{total:.6},\"functions\":{},\"shards\":{},\"flow\":{flow},\"phases\":{{{phases}}}{patterns}{refused}{note}{switch}}}",
                    summary.functions,
                    core.runtime_config().console_shards
                );
                // Every program's own phases, in import order: a container of
                // many programs spends its time per program, and the line
                // above shows only the first.
                for each in &stored {
                    let mut sums: std::collections::BTreeMap<&str, f64> =
                        std::collections::BTreeMap::new();
                    for phase in &each.phases {
                        *sums.entry(phase.phase.as_str()).or_default() += phase.seconds;
                    }
                    let phases = sums
                        .iter()
                        .map(|(name, seconds)| format!("\"{name}\":{seconds:.6}"))
                        .collect::<Vec<_>>()
                        .join(",");
                    println!(
                        "PROGRAM {{\"program\":\"{}\",\"functions\":{},\"phases\":{{{phases}}}}}",
                        each.program, each.functions
                    );
                }
                // Process-wide sums over every thread (decoder construction,
                // the switch stage's setup and workers): they exceed wall time.
                let tally = romwright_core::native::tally::drain()
                    .iter()
                    .map(|(name, seconds)| format!("\"{name}\":{seconds:.6}"))
                    .collect::<Vec<_>>()
                    .join(",");
                println!("TALLY {{{tally}}}");
            }
        }
        // `export-symbols <program> [--format dtk|splat] [--splits FILE]`:
        // the store's own symbol list in a decomp project's grammar, so a
        // Romwright session hands dtk/splat the names it recovered rather
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
                        .map(|text| romwright_core::native::linkmap::parse_splits(&text))
                        .map_err(|e| format!("{path}: {e}"))
                })
                .transpose()?
                .unwrap_or_default();
            let facts = core.export_facts(program).map_err(|e| e.to_string())?;
            match format.as_str() {
                "splat" => print!("{}", romwright_core::export::splat_symbol_addrs(&facts).0),
                _ => {
                    for row in &romwright_core::export::dtk_symbols(&facts, &splits, true).rows {
                        println!("{row}");
                    }
                }
            }
        }
        // `export-dtk <program> <outdir> [--splits FILE]`: write a dtk
        // project skeleton — config.yml, symbols.txt, splits.txt — from
        // the store. With --splits the project's own file passes through
        // and names its sections; without it `Sections:` lists the
        // image's sections under dtk's names (`.init`, `.text`, ...) in
        // order. Functions dtk cannot represent (unaligned PowerPC
        // entries) are left out and counted.
        "export-dtk" => {
            let program = args.get(2).ok_or("export-dtk needs a program")?;
            let outdir = Path::new(args.get(3).ok_or("export-dtk needs an outdir")?);
            std::fs::create_dir_all(outdir).map_err(|e| e.to_string())?;
            let splits_text = flag(args, "--splits")
                .map(|path| std::fs::read_to_string(&path).map_err(|e| format!("{path}: {e}")))
                .transpose()?;
            let facts = core.export_facts(program).map_err(|e| e.to_string())?;
            let export = romwright_core::export::export_dtk(&facts, splits_text.as_deref());
            for (name, text) in [
                ("splits.txt", &export.splits_txt),
                ("symbols.txt", &export.symbols_txt),
                ("config.yml", &export.config_yml),
            ] {
                std::fs::write(outdir.join(name), text).map_err(|e| format!("{name}: {e}"))?;
            }
            println!(
                "wrote {} ({} functions, {} data symbols, {} functions dtk cannot represent skipped)",
                outdir.display(),
                export.symbols.functions,
                export.symbols.objects,
                export.symbols.rejected.len()
            );
        }
        // `export-splat <program> <outdir> [--binary FILE]`: write a splat
        // config — <program>.yaml + symbol_addrs.txt — from the store.
        // splat's segment `start` is a file offset, so the binary the
        // program was imported from (`--binary`, else the recorded source
        // path) is read for where each region sits in it. Platforms splat
        // cannot disassemble are declared `is_unsupported_platform` with
        // `bin` segments.
        "export-splat" => {
            let program = args.get(2).ok_or("export-splat needs a program")?;
            let outdir = Path::new(args.get(3).ok_or("export-splat needs an outdir")?);
            std::fs::create_dir_all(outdir).map_err(|e| e.to_string())?;
            let facts = core.export_facts(program).map_err(|e| e.to_string())?;
            let binary = flag(args, "--binary")
                .or_else(|| facts.source_path.clone())
                .ok_or("export-splat needs --binary FILE: the store does not record where the program was imported from")?;
            let binary = std::fs::canonicalize(&binary).map_err(|e| format!("{binary}: {e}"))?;
            let file = std::fs::read(&binary).map_err(|e| format!("{}: {e}", binary.display()))?;
            let mappings = romwright_core::native::load_native_mappings(&binary)
                .map_err(|e| format!("{}: {e} (pass --binary <the imported image>)", binary.display()))?;
            let backing = romwright_core::export::file_backing(&mappings, &file);
            let export = romwright_core::export::export_splat(
                &facts,
                &backing,
                &binary.to_string_lossy(),
                Some(&romwright_core::export::sha1_hex(&file)),
            )?;
            std::fs::write(outdir.join(format!("{program}.yaml")), &export.yaml)
                .map_err(|e| e.to_string())?;
            std::fs::write(outdir.join("symbol_addrs.txt"), &export.symbol_addrs)
                .map_err(|e| e.to_string())?;
            println!(
                "wrote {} (platform {}{}, {} segments, {} symbols)",
                outdir.display(),
                export.platform,
                if export.supported { "" } else { ", unsupported by splat 0.39.1" },
                export.segments,
                export.symbols
            );
        }
        // `export-objdiff <program> <outdir> --splits FILE --target-root DIR
        // [--base-root DIR] [--source-root DIR] [--complete all|UNIT,UNIT]
        // [--dtk-config build/<ver>/config.json]`: write an objdiff.json
        // whose units are the splits.txt TUs, each carrying the store's
        // functions that fall inside its extents. objdiff matches functions
        // by symbol name within a unit, so the unit list is the interop
        // surface. `--source-root` prefixes each unit's source_path;
        // `--complete` names the units linked into the verified build
        // (objdiff's `complete`; default none); `--dtk-config` adds the
        // target-only units dtk generated for the gaps between TUs.
        "export-objdiff" => {
            let program = args.get(2).ok_or("export-objdiff needs a program")?;
            let outdir = Path::new(args.get(3).ok_or("export-objdiff needs an outdir")?);
            let splits_path =
                flag(args, "--splits").ok_or("export-objdiff needs --splits <splits.txt>")?;
            let target_root =
                flag(args, "--target-root").ok_or("export-objdiff needs --target-root")?;
            let base_root = flag(args, "--base-root").unwrap_or_else(|| "build".into());
            let splits = romwright_core::native::linkmap::parse_splits(
                &std::fs::read_to_string(&splits_path).map_err(|e| e.to_string())?,
            );
            let options = romwright_core::export::ObjdiffOptions {
                source_root: flag(args, "--source-root").unwrap_or_default(),
                complete: match flag(args, "--complete").as_deref() {
                    None | Some("none") => romwright_core::export::Complete::None,
                    Some("all") => romwright_core::export::Complete::All,
                    Some(list) => romwright_core::export::Complete::Units(
                        list.split(',').map(str::to_string).collect(),
                    ),
                },
                auto_units: match flag(args, "--dtk-config") {
                    Some(path) => romwright_core::export::dtk_auto_units(
                        &std::fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?,
                    )
                    .map_err(|e| format!("{path}: {e}"))?,
                    None => Vec::new(),
                },
            };
            let report = core
                .export_objdiff(
                    program,
                    outdir,
                    &splits,
                    Path::new(&target_root),
                    Path::new(&base_root),
                    &options,
                )
                .map_err(|e| e.to_string())?;
            println!("{report}");
        }
        "matching-workspace" => {
            let program = args.get(2).ok_or("matching-workspace needs a program")?;
            let path = args.get(3).ok_or("matching-workspace needs a workspace-operation JSON file or -")?;
            let operation = matching_request_json(path)?;
            let result = core.run_matching_workspace_operation(program, operation).map_err(|error| error.to_string())?;
            println!("{}", serde_json::to_string_pretty(&result).map_err(|error| error.to_string())?);
        }
        "matching-run" => {
            let binary = args.get(2).ok_or("matching-run needs a binary")?;
            let program = args.get(3).ok_or("matching-run needs a program")?;
            let path = args.get(4).ok_or("matching-run needs a matching-operation JSON file or -")?;
            let operation = matching_request_json(path)?;
            let milliseconds = flag(args, "--budget-ms").map(|value| value.parse::<u64>().map_err(|error| error.to_string())).transpose()?.unwrap_or(120_000);
            let base = flag(args, "--base").map(|value| u64::from_str_radix(value.trim_start_matches("0x"), 16).map_err(|error| error.to_string())).transpose()?;
            let request = core.execution_request(Path::new(binary), program, base, std::time::Duration::from_millis(milliseconds)).map_err(|error| error.to_string())?;
            let result = core.run_matching_operation(&request, operation).map_err(|error| error.to_string())?;
            println!("{}", serde_json::to_string_pretty(&result).map_err(|error| error.to_string())?);
        }
        // `export-c <binary> <program> <outdir> [--splits splits.txt]`:
        // decompile every function and write m2c-shaped C — the source
        // tree `export-objdiff`'s project compiles. With --splits the
        // functions group into one <tu>.c per translation unit so the
        // files line up with objdiff's target/base objects; without it,
        // one <name>.c per function.
        "export-c" => {
            let binary = args.get(2).ok_or("export-c needs a binary")?.clone();
            let program = args.get(3).ok_or("export-c needs a program")?.clone();
            let outdir = Path::new(args.get(4).ok_or("export-c needs an outdir")?);
            let splits = flag(args, "--splits")
                .map(
                    |p| -> Result<Vec<romwright_core::native::linkmap::SplitExtent>, String> {
                        let text = std::fs::read_to_string(&p).map_err(|e| format!("{p}: {e}"))?;
                        Ok(romwright_core::native::linkmap::parse_splits(&text))
                    },
                )
                .transpose()?;
            // `--transforms a,b,c` overrides the default pipeline so a
            // transform's effect can be measured against a baseline; an
            // empty list (`--transforms ""`) runs no transforms.
            let mut opts = romwright_core::emit_m2c::M2cOptions::default();
            if let Some(list) = flag(args, "--transforms") {
                opts.transforms = if list.trim().is_empty() {
                    Vec::new()
                } else {
                    list.split(',').map(|s| s.trim().to_string()).collect()
                };
            }
            // `--budget-ms N`: a whole-program export outlives the 60 s
            // interactive default.
            opts.budget = flag(args, "--budget-ms")
                .map(|value| value.parse::<u64>().map_err(|error| error.to_string()))
                .transpose()?
                .map(std::time::Duration::from_millis);
            // `--context HEADER`: declarations the project already has are
            // not repeated (with the types the decompiler recovered) in the export.
            if let Some(path) = flag(args, "--context") {
                let header = std::fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?;
                opts.declared = romwright_core::emit_m2c::declared_names(&header);
                opts.context = header;
            }
            let entry = flag(args, "--address").map(|address| {
                u64::from_str_radix(address.trim_start_matches("0x"), 16)
                    .map_err(|error| format!("invalid function address: {error}"))
            }).transpose()?;
            let report = core
                .export_m2c(
                    Path::new(&binary),
                    &program,
                    outdir,
                    splits.as_deref(),
                    entry,
                    &opts,
                )
                .map_err(|e| e.to_string())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
            );
        }
        "export-scratch" => {
            let program = args.get(2).ok_or("export-scratch needs a program")?;
            let addr = args.get(3).ok_or("export-scratch needs a vaddr")?;
            let binary = args.get(4).ok_or("export-scratch needs a binary")?;
            let outdir = flag(args, "--out").unwrap_or_else(|| "scratch".into());
            let compiler = flag(args, "--compiler").ok_or("export-scratch needs --compiler ID")?;
            let compiler_flags = flag(args, "--c-flags").ok_or("export-scratch needs --c-flags FLAGS (an explicitly empty value is allowed)")?;
            let target = flag(args, "--target-object");
            let context = flag(args, "--context");
            let address = u64::from_str_radix(addr.trim_start_matches("0x"), 16)
                .map_err(|e| e.to_string())?;
            let options = romwright_core::matching::ScratchExportOptions {
                compiler: &compiler,
                compiler_flags: &compiler_flags,
                target_object: target.as_deref().map(Path::new),
                context: context.as_deref().map(Path::new),
            };
            let report = core.export_scratch(Path::new(binary), program, address, Path::new(&outdir), &options)
                .map_err(|error| error.to_string())?;
            println!("{}", serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?);
        }
        "match-source" => {
            let program = args.get(2).ok_or("match-source needs a program")?;
            let target = Path::new(args.get(3).ok_or("match-source needs a target object")?);
            let source = Path::new(args.get(4).ok_or("match-source needs source C")?);
            let recipe_path =
                flag(args, "--recipe").ok_or("match-source needs --recipe <recipe.json>")?;
            let recipe = serde_json::from_slice(
                &std::fs::read(recipe_path).map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
            let context = flag(args, "--context");
            let budget = flag(args, "--budget-ms")
                .map(|value| value.parse::<u64>())
                .transpose()
                .map_err(|error| error.to_string())?
                .unwrap_or(60000);
            let input = core
                .program_input(program)
                .map_err(|error| error.to_string())?;
            let request = core
                .execution_request(
                    Path::new(&input.source_path),
                    program,
                    None,
                    std::time::Duration::from_millis(budget),
                )
                .map_err(|error| error.to_string())?;
            let prepared = Core::prepare_matching(
                &request,
                target,
                source,
                context.as_deref().map(Path::new),
                recipe,
            )
            .map_err(|error| error.to_string())?;
            let run = core
                .run_matching(&request, &prepared)
                .map_err(|error| error.to_string())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&run).map_err(|error| error.to_string())?
            );
        }
        "matching-runs" => {
            let program = args.get(2).ok_or("matching-runs needs a program")?;
            let after = flag(args, "--after")
                .map(|value| value.parse::<u64>())
                .transpose()
                .map_err(|error| error.to_string())?
                .unwrap_or(0);
            let limit = flag(args, "--limit")
                .map(|value| value.parse::<usize>())
                .transpose()
                .map_err(|error| error.to_string())?
                .unwrap_or(64);
            let runs = core
                .matching_runs(program, after, limit)
                .map_err(|error| error.to_string())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&runs).map_err(|error| error.to_string())?
            );
        }
        // `objdiff-report <report.json> [--previous PREV.json] [--frogress OUT]`:
        // roll an `objdiff-cli report generate` JSON up into per-function
        // rows and project totals (checked against objdiff's own
        // `measures`); with --previous, also the `report changes` delta
        // between the two reports. The report's units carry `functions`
        // rows with fuzzy_match_percent; counters are JSON strings.
        "objdiff-report" => {
            let read_report = |path: &str| -> Result<serde_json::Value, String> {
                let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
                serde_json::from_str(&text).map_err(|e| format!("{path}: {e}"))
            };
            let path = args.get(2).ok_or("objdiff-report needs a report.json")?;
            let report = read_report(path)?;
            let mut out = romwright_core::export::objdiff_rollup(&report)?;
            if let Some(previous) = flag(args, "--previous") {
                out["changes"] =
                    romwright_core::export::objdiff_changes(&read_report(&previous)?, &report)?;
            }
            if let Some(out_path) = flag(args, "--frogress") {
                // frogress payload: {project, version, measures:{...}} —
                // written to a file for the caller to POST (matches the
                // export-scratch pattern: we produce the payload, the
                // caller owns the network).
                let payload = serde_json::json!({
                    "project": report["project"].as_str().unwrap_or("romwright"),
                    "version": report["version"].as_str().unwrap_or(""),
                    "measures": out["measures"],
                });
                std::fs::write(
                    &out_path,
                    serde_json::to_string_pretty(&payload).map_err(|e| e.to_string())?,
                )
                .map_err(|e| format!("{out_path}: {e}"))?;
                println!("wrote frogress payload {out_path}");
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&out).map_err(|e| e.to_string())?
            );
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
            let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
            let doc: serde_json::Value =
                serde_json::from_str(&text).map_err(|e| format!("{path}: {e}"))?;
            // decomp.me shape: score is a number; match_override flags a
            // manually-forced match. Local shape: {function, score}.
            let score = doc["score"]
                .as_f64()
                .or_else(|| doc["match_percent"].as_f64())
                .ok_or("score.json has no score/match_percent")?;
            let name = doc["name"]
                .as_str()
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
                score,
                slug,
                name,
                doc["match_override"].as_bool().unwrap_or(false)
            );
            core.comment_command(program, &function.entry, &function.entry, "eol", &body)
                .map_err(|e| e.to_string())?;
            println!(
                "recorded score {:.2}% on {} ({})",
                score, function.name, addr
            );
        }
        // `import-trace <program> <trace.csv>`: ingest an emulator trace
        // — one `addr,kind[,thread]` row per event, kind in
        // exec|call|read|write|bp — into trace_events, then mark every
        // function whose entry an exec/call/bp event names as traced.
        "import-trace" => {
            let program = args.get(2).ok_or("import-trace needs a program")?;
            let path = args.get(3).ok_or("import-trace needs a trace file")?;
            let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
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
                let Some(addr_field) = fields.next() else {
                    continue;
                };
                let Some(kind) = fields.next() else { continue };
                let thread = fields.next().unwrap_or("").trim();
                let address = u64::from_str_radix(addr_field.trim().trim_start_matches("0x"), 16);
                let Ok(address) = address else { continue };
                let kind = kind.trim();
                let event = romwright_model::TraceEvent {
                    sequence: 0,
                    at: String::new(),
                    thread: thread.to_string(),
                    address: Some(romwright_model::Address::ram(address)),
                    kind: kind.to_string(),
                    payload: String::new(),
                    provenance: "import-trace".into(),
                };
                db.append_trace_event(id, &event)
                    .map_err(|e| e.to_string())?;
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
            let vaddr = u64::from_str_radix(args.get(3).ok_or("mem needs a vaddr (hex)")?, 16)
                .map_err(|e| e.to_string())?;
            let size: usize = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(32);
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
                        .filter_map(|h| {
                            u64::from_str_radix(h.trim().trim_start_matches("0x"), 16).ok()
                        })
                        .collect()
                })
                .unwrap_or_default();
            let (digest, flows, ms, decoded, answered) = core
                .byte_scan(Path::new(&binary), vaddr, size, &ask)
                .map_err(|e| e.to_string())?;
            if has_flag(args, "--json") {
                let asked: Vec<serde_json::Value> = answered
                    .iter()
                    .map(|(a, l, f)| serde_json::json!({"address": a, "len": l, "flow": f}))
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
                println!(
                    "sweep {size} bytes at {vaddr:#x}: {ms}ms digest {digest} decoded {decoded}"
                );
                println!(
                    "flows: Next={} Call={} Jump={} Jcc={} IndCall={} Ind={} Stop={} Bad={}",
                    flows[0], flows[1], flows[2], flows[3], flows[4], flows[5], flows[6], flows[7]
                );
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
        "ir-dump" => {
            // Print the typed IR (normalized p-code) for a comma-separated
            // address list — the form analyses consume, not the raw strings.
            let binary = args.get(2).ok_or("ir-dump needs a binary path")?.clone();
            let addresses: Vec<u64> = args
                .get(3)
                .ok_or("ir-dump needs a comma-separated address list")?
                .split(',')
                .filter_map(|a| u64::from_str_radix(a.trim().trim_start_matches("0x"), 16).ok())
                .collect();
            let irs = core
                .ir_native(Path::new(&binary), &addresses)
                .map_err(|e| e.to_string())?;
            for ir in &irs {
                let failed = ir.error.as_deref().map(|error| format!(" error={error}")).unwrap_or_default();
                println!("{:#x} (len {}){failed}", ir.address, ir.length);
                for op in &ir.ops {
                    let ins: Vec<String> = op
                        .inputs
                        .iter()
                        .map(|v| format!("{}:{:x}:{}", v.space, v.offset, v.size))
                        .collect();
                    let out = op
                        .output
                        .as_ref()
                        .map(|v| format!("{}:{:x}:{}", v.space, v.offset, v.size))
                        .unwrap_or_else(|| "-".into());
                    println!("  {} {} <- {}", op.opcode.name(), out, ins.join(", "));
                }
            }
        }
        "decompile" if !has_flag(args, "--oracle") => {
            let binary = args.get(2).ok_or("decompile needs a binary path")?.clone();
            let address = args.get(3).ok_or("decompile needs a vaddr (hex)")?.clone();
            let program = flag(args, "--name").unwrap_or_else(|| {
                Path::new(&binary)
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "program".into())
            });
            let base = flag(args, "--base")
                .and_then(|b| u64::from_str_radix(b.trim_start_matches("0x"), 16).ok());
            let code = core
                .decompile_native(Path::new(&binary), &address, &program, base)
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
            let address = romwright_model::Address::parse_ram_hex(&address_arg)
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
                    architecture
                        .bits
                        .map_or_else(|| "?".into(), |bits| bits.to_string()),
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
            let language = flag(args, "--language");
            let compiler = flag(args, "--compiler");
            let mut bridge = launch_bridge(args)?;
            let summary = core
                .import_program_as(
                    &mut bridge,
                    "main",
                    Path::new(&binary),
                    name.as_deref(),
                    language.as_deref(),
                    compiler.as_deref(),
                )
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
            let target = args
                .get(2)
                .ok_or("diff needs a target program name")?
                .clone();
            let reference_project =
                flag(args, "--reference").ok_or("diff needs --reference <project dir>")?;
            let reference = flag(args, "--reference-name");
            let mut options = romwright_diff::Options::default();
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
                None | Some("nap") => romwright_diff::Matcher::Nap,
                Some("greedy") => romwright_diff::Matcher::Greedy,
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
            for warning in &report.warnings {
                eprintln!("warning: {warning}");
            }
            if has_flag(args, "--json") {
                println!(
                    "{}",
                    serde_json::to_string(&report).map_err(|e| e.to_string())?
                );
            } else {
                for row in &report.matches {
                    println!(
                        "{}  {}  {:.3}  {:?} ({:?})  {} -> {}",
                        row.reference,
                        row.target,
                        row.score,
                        row.evidence,
                        row.confidence,
                        row.reference_name,
                        row.target_name
                    );
                }
                let mut by_confidence = std::collections::BTreeMap::new();
                for row in &report.matches {
                    *by_confidence.entry(format!("{:?}", row.confidence).to_lowercase()).or_insert(0usize) += 1;
                }
                println!(
                    "-- confidence: {}",
                    by_confidence
                        .iter()
                        .map(|(label, count)| format!("{count} {label}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                println!(
                    "-- matched {} of {} target functions against {} reference functions ({} anchors); {} names {}",
                    report.matches.len(),
                    report.target_functions,
                    report.reference_functions,
                    report.anchors,
                    report.names.len(),
                    if has_flag(args, "--apply") {
                        "applied"
                    } else {
                        "portable"
                    }
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
            let offset: u64 = flag(args, "--offset")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            let limit: u64 = flag(args, "--limit")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            let filter = flag(args, "--filter");
            let sort = flag(args, "--sort");
            let page = core
                .functions_page(
                    &program,
                    offset,
                    if limit == 0 { i64::MAX as u64 } else { limit },
                    filter.as_deref(),
                    sort.as_deref(),
                    None,
                )
                .map_err(|e| e.to_string())?;
            if limit > 0 {
                println!(
                    "-- paged {}..{} of {:?} (rev {})",
                    page.offset,
                    page.offset + page.rows.len() as u64,
                    page.total,
                    page.revision
                );
            }
            let rows = page.rows;
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
        "facts" => facts::run(&core, args)?,
        "oracle-signatures" => {
            // Dump the oracle's recovered signatures as JSON — the head-to-head
            // type gate scores these against DWARF truth.
            let program = args
                .get(2)
                .ok_or("oracle-signatures needs a program name")?
                .clone();
            let mut bridge = launch_bridge(args)?;
            let session = format!("cli-{program}");
            bridge.open(&session, &program).map_err(|e| e.to_string())?;
            let sigs = bridge
                .oracle_signatures(&session)
                .map_err(|e| e.to_string())?;
            let out: Vec<serde_json::Value> = sigs
                .iter()
                .map(|s| {
                    serde_json::json!({
                        "entry": s.entry,
                        "signature": s.signature,
                        "return_type": s.return_type,
                        "signature_source": s.signature_source,
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::to_string(&out).map_err(|e| e.to_string())?
            );
            bridge.shutdown().map_err(|e| e.to_string())?;
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
            let binary = args
                .get(2)
                .ok_or("detect-functions needs a binary")?
                .clone();
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
            let program = args
                .get(3)
                .ok_or("infer-types needs a program name")?
                .clone();
            let entries = args
                .get(4)
                .ok_or("infer-types needs one or more addresses")?
                .split(',')
                .map(|address| {
                    u64::from_str_radix(address.trim().trim_start_matches("0x"), 16)
                        .map(romwright_model::Address::ram)
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
            let binary = args
                .get(2)
                .ok_or("prune-indirect-calls needs a binary")?
                .clone();
            let program = args
                .get(3)
                .ok_or("prune-indirect-calls needs a program name")?
                .clone();
            let entry = args
                .get(4)
                .ok_or("prune-indirect-calls needs a function entry")?
                .trim()
                .trim_start_matches("0x");
            let entry = u64::from_str_radix(entry, 16)
                .map(romwright_model::Address::ram)
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
                        .map(romwright_model::Address::ram)
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
            let binary = args
                .get(2)
                .ok_or("analyse-function needs a binary")?
                .clone();
            let program = args
                .get(3)
                .ok_or("analyse-function needs a program name")?
                .clone();
            let address = args
                .get(4)
                .ok_or("analyse-function needs an address")?
                .clone();
            let entry = romwright_model::Address::ram(
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
        // A matching-decompilation project knows the exact signature and name
        // of every function it has already matched byte-for-byte. Feeding
        // those back is the cheapest accuracy win available: recovered types
        // propagate through call sites, and `export-c` stops emitting
        // "Supplied declaration required" for callees the project has
        // already proven. Both commands take one JSON array on a path or
        // stdin and mark what they write as ASSERTED, so no later inference
        // round can overwrite a fact the project proved.
        "assert-prototypes" => {
            let program = args.get(2).ok_or("assert-prototypes needs a program name")?.clone();
            let path = args
                .get(3)
                .ok_or("assert-prototypes needs a prototypes JSON file or -")?;
            let text = read_json_argument(path)?;
            #[derive(serde::Deserialize)]
            struct Supplied {
                function: String,
                signature: String,
                #[serde(default)]
                calling_convention: Option<String>,
                #[serde(default)]
                return_type: Option<String>,
            }
            let supplied: Vec<Supplied> =
                serde_json::from_str(&text).map_err(|error| error.to_string())?;
            let source = flag(args, "--source").unwrap_or_else(|| "project".to_string());
            let (mut applied, mut skipped) = (0usize, 0usize);
            for row in &supplied {
                let Some(address) = romwright_model::Address::parse_ram_hex(&row.function) else {
                    return Err(format!("bad address: {}", row.function));
                };
                let prototype = romwright_model::PrototypeRow {
                    function: address,
                    signature: row.signature.clone(),
                    calling_convention: row.calling_convention.clone(),
                    return_type: row.return_type.clone(),
                    provenance: romwright_model::FactProvenance {
                        kind: romwright_model::FactKind::Asserted,
                        source: source.clone(),
                        confidence: Some(1.0),
                    },
                };
                match core.set_prototype(&program, &prototype) {
                    Ok(()) => applied += 1,
                    Err(_) => skipped += 1,
                }
            }
            println!("asserted {applied} prototypes, skipped {skipped}");
        }
        "assert-names" => {
            let program = args.get(2).ok_or("assert-names needs a program name")?.clone();
            let path = args.get(3).ok_or("assert-names needs a names JSON file or -")?;
            let text = read_json_argument(path)?;
            #[derive(serde::Deserialize)]
            struct Supplied {
                function: String,
                name: String,
            }
            let supplied: Vec<Supplied> =
                serde_json::from_str(&text).map_err(|error| error.to_string())?;
            let (mut applied, mut skipped) = (0usize, 0usize);
            for row in &supplied {
                let Some(address) = romwright_model::Address::parse_ram_hex(&row.function) else {
                    return Err(format!("bad address: {}", row.function));
                };
                match core.rename_command(&program, &address, &row.name) {
                    Ok(()) => applied += 1,
                    Err(_) => skipped += 1,
                }
            }
            println!("renamed {applied} functions, skipped {skipped}");
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
            let rows = core
                .search(&program, &term, limit)
                .map_err(|e| e.to_string())?;
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
                let binary_arg =
                    flag(args, "--binary").ok_or("graph --largest requires --binary <path>")?;
                let binary_path = Path::new(&binary_arg);
                let mut functions = core.functions(&program).map_err(|e| e.to_string())?;
                functions.sort_by(|a, b| b.size.cmp(&a.size));
                let mut best: Option<(usize, String, String, serde_json::Value)> = None;
                for f in functions {
                    let addr_hex = format!("{:x}", f.entry.offset);
                    if let Ok(graph_json) = core.function_bb_graph(&program, binary_path, &addr_hex) {
                        let blocks = graph_json
                            .get("nodes")
                            .and_then(|n| n.as_array())
                            .map(|a| a.len())
                            .unwrap_or(0);
                        let better = best
                            .as_ref()
                            .map(|(count, _, _, _)| blocks > *count)
                            .unwrap_or(true);
                        if better {
                            best = Some((blocks, f.name.clone(), f.entry.to_string(), graph_json));
                        }
                        if blocks >= 200 {
                            break;
                        }
                    }
                }
                let (blocks, name, address, graph) = best.ok_or_else(|| {
                    format!("no recoverable basic-block graph for program {program}")
                })?;
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
        "evidence" => {
            // Why one function exists: the rule that claimed it, the image's
            // own name for it, what reaches it, and what analysis did.
            let program = args.get(2).ok_or("evidence needs a program name")?.clone();
            let address = args.get(3).ok_or("evidence needs an address")?;
            let offset = u64::from_str_radix(address.trim().trim_start_matches("0x"), 16)
                .map_err(|_| format!("not an address: {address}"))?;
            let evidence = core
                .function_evidence(&program, offset)
                .map_err(|e| e.to_string())?
                .ok_or_else(|| format!("no function covers {offset:#x} in {program}"))?;
            if has_flag(args, "--json") {
                println!("{}", serde_json::to_string_pretty(&evidence).map_err(|e| e.to_string())?);
            } else {
                println!(
                    "{} at {} ({} bytes): {:?}, claimed by {}, analysis {}",
                    evidence.name,
                    evidence.entry,
                    evidence.size,
                    evidence.standing,
                    evidence.producer,
                    evidence.analysis_state.as_deref().unwrap_or("unknown")
                );
                if let Some((name, source)) = &evidence.symbol {
                    println!("  symbol {name} ({source})");
                }
                for group in &evidence.incoming {
                    let from: Vec<String> = group.from.iter().map(ToString::to_string).collect();
                    println!(
                        "  {} {} from {} [{}], e.g. {}",
                        group.count,
                        group.kind,
                        group.source,
                        group.evidence.as_deref().unwrap_or("unclassified"),
                        from.join(", ")
                    );
                }
                if let Some(thunk) = &evidence.thunk {
                    println!("  thunk to {} ({})", thunk.thunked, thunk.provenance.source);
                }
                for signature in &evidence.signatures {
                    println!(
                        "  signature {} from {} ({:.2})",
                        signature.name, signature.package, signature.confidence
                    );
                }
                if evidence.traced {
                    println!("  covered by an emulator trace");
                }
            }
        }
        "provenance" => {
            // Every fact names the pass that produced it; this prints what
            // those names mean. With a program, only the classes it holds.
            let program = args
                .get(2)
                .filter(|value| !value.starts_with("--"))
                .cloned();
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
            let rows: Vec<_> = romwright_model::provenance::CLASSES
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
                println!(
                    "{}",
                    serde_json::to_string_pretty(&payload).map_err(|e| e.to_string())?
                );
            } else {
                for entry in &rows {
                    println!(
                        "{} [{}]\n    {}",
                        entry.source,
                        entry.evidence.as_str(),
                        entry.explanation
                    );
                }
                println!("-- {} provenance classes", rows.len());
            }
            if let Some(held) = held {
                let unexplained: Vec<_> = held
                    .iter()
                    .filter(|name| romwright_model::provenance::explain(name).is_none())
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
            let address = romwright_model::Address::parse_ram_hex(address_arg)
                .ok_or_else(|| format!("bad address: {address_arg}"))?;
            let rows = core.locate(&address).map_err(|e| e.to_string())?;
            let follow = has_flag(args, "--follow");
            let mut followed = std::collections::BTreeSet::new();
            for row in &rows {
                // Overlays share address windows, so the module the address
                // is in is part of the answer, not a detail of it.
                let module = match (&row.module, row.module_id) {
                    (Some(name), Some(id)) => format!("  module={name}#{id}"),
                    _ => String::new(),
                };
                println!(
                    "{}  {}  {} {:#x}+{:#x} {}  {}{module}",
                    row.program,
                    row.language,
                    row.region.name,
                    row.region.start.offset,
                    row.region.size,
                    row.region.permissions,
                    row.function.as_deref().unwrap_or("-")
                );
                // One follow block per program: its facts do not depend on
                // which of its modules the address was in.
                if !follow || !followed.insert(row.program.clone()) {
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
            let programs = rows.iter().map(|row| &row.program).collect::<std::collections::BTreeSet<_>>();
            println!("-- {} programs map {}", programs.len(), address);
        }
        "memory-regions" => {
            let program = args
                .get(2)
                .ok_or("memory-regions needs a program name")?
                .clone();
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
            let address = romwright_model::Address::parse_ram_hex(&address_arg)
                .ok_or_else(|| format!("bad address: {address_arg}"))?;
            core.set_bookmark(
                &program,
                &romwright_model::BookmarkRow {
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
            let address = romwright_model::Address::parse_ram_hex(&address_arg)
                .ok_or_else(|| format!("bad address: {address_arg}"))?;
            core.set_patch(
                &program,
                &romwright_model::PatchRow {
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
                    romwright_model::provenance::EvidenceKind::parse(&text).ok_or_else(|| {
                        format!("bad evidence kind: {text} (declared, decoded or inferred)")
                    })?,
                ),
                None => None,
            };
            let rows = match (addr_arg, evidence) {
                (Some(addr_str), _) => {
                    let address = romwright_model::Address::parse_ram_hex(&addr_str)
                        .ok_or_else(|| format!("bad address: {addr_str}"))?;
                    let incoming = args.iter().any(|a| a == "--to");
                    core.xrefs_page(
                        &program,
                        &address,
                        incoming,
                        0,
                        u64::from(u32::MAX),
                        evidence,
                    )
                    .map(|page| page.rows)
                    .map_err(|e| e.to_string())?
                }
                // Filtering the whole program has no window to page, and
                // pretending otherwise would answer a question not asked.
                (None, Some(kind)) => {
                    return Err(format!("--evidence {} needs --to or --from", kind.as_str()));
                }
                (None, None) => core.xrefs(&program).map_err(|e| e.to_string())?,
            };
            for r in &rows {
                let ownership = match r.provenance.kind {
                    romwright_model::FactKind::Inferred => "inferred",
                    romwright_model::FactKind::Asserted => "asserted",
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
            let address = romwright_model::Address::parse_ram_hex(&addr_arg)
                .ok_or_else(|| format!("bad address: {addr_arg}"))?;
            core.rename_command(&program, &address, &name)
                .map_err(|e| e.to_string())?;
            println!("renamed {} -> {}", address, name);
        }
        "comment" => {
            let program = args.get(2).ok_or("comment needs a program name")?.clone();
            let address_arg = args.get(3).ok_or("comment needs an address")?.clone();
            let text = args.get(4).ok_or("comment needs comment text")?.clone();
            let address = romwright_model::Address::parse_ram_hex(&address_arg)
                .ok_or_else(|| format!("bad address: {address_arg}"))?;
            let function = flag(args, "--function")
                .map(|value| {
                    romwright_model::Address::parse_ram_hex(&value)
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
            let program = args
                .get(2)
                .ok_or("dump-specs needs a program name")?
                .clone();
            let out = flag(args, "--out").ok_or("dump-specs needs --out DIR")?;
            let mut bridge = launch_bridge(args)?;
            let session = format!("cli-{program}");
            bridge.open(&session, &program).map_err(|e| e.to_string())?;
            bridge
                .dump_specs(&session, &out)
                .map_err(|e| e.to_string())?;
            println!("specs written to {out}");
            bridge.shutdown().map_err(|e| e.to_string())?;
        }
        "lint-specs" => {
            // A stricter spec compiler: validate every language module under
            // the install and report the defect classes that produce a bad
            // spec bundle (unknown opinion attributes, missing/stub .sla,
            // cspec schema drift). Exit non-zero when any error fires.
            let install = flag(args, "--ghidra")
                .map(PathBuf::from)
                .unwrap_or_else(romwright_core::native_runtime::ghidra_dir);
            let findings = romwright_core::speclint::lint_install(&install);
            let mut errors = 0usize;
            for f in &findings {
                if f.severity == romwright_core::speclint::Severity::Error {
                    errors += 1;
                }
                println!(
                    "{}: {}: {}: {}",
                    f.severity,
                    f.rule,
                    f.path.display(),
                    f.message
                );
            }
            println!("{} finding(s), {} error(s)", findings.len(), errors);
            if errors > 0 {
                return Err(format!("lint-specs: {errors} error(s)"));
            }
        }
        "decompile-batch" => {
            let program = args.get(2).ok_or("--oracle needs a program name")?.clone();
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
            let program = args.get(2).ok_or("--oracle needs a program name")?.clone();
            let address = args.get(3).ok_or("--oracle needs an address")?.clone();
            let mut bridge = launch_bridge(args)?;
            let session = format!("cli-{program}");
            bridge.open(&session, &program).map_err(|e| e.to_string())?;
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

fn matching_request_json<T: serde::de::DeserializeOwned>(path: &str) -> Result<T, String> {
    use std::io::Read;
    let mut bytes = Vec::new();
    if path == "-" {
        std::io::stdin().lock().take(64 * 1024 * 1024 + 1).read_to_end(&mut bytes)
    } else {
        std::fs::File::open(path).map_err(|error| error.to_string())?
            .take(64 * 1024 * 1024 + 1).read_to_end(&mut bytes)
    }.map_err(|error| error.to_string())?;
    if bytes.len() > 64 * 1024 * 1024 { return Err("matching request exceeds 64 MiB".into()); }
    serde_json::from_slice(&bytes).map_err(|error| format!("invalid matching request: {error}"))
}

/// Reads a JSON argument from a path or stdin, with the same 64 MiB ceiling
/// the matching requests use.
fn read_json_argument(path: &str) -> Result<String, String> {
    use std::io::Read;
    let mut bytes = Vec::new();
    if path == "-" {
        std::io::stdin().lock().take(64 * 1024 * 1024 + 1).read_to_end(&mut bytes)
    } else {
        std::fs::File::open(path)
            .map_err(|error| format!("{path}: {error}"))?
            .take(64 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
    }
    .map_err(|error| error.to_string())?;
    if bytes.len() > 64 * 1024 * 1024 {
        return Err("supplied JSON exceeds 64 MiB".into());
    }
    String::from_utf8(bytes).map_err(|error| error.to_string())
}

/// Says on stderr what an import could not do: one line per severity with a
/// few examples, and whether the result is reusable. A degraded stage used
/// to leave only a JSON field under `--timings`, and a failure that kept an
/// image out of the import cache left nothing at all.
fn report_diagnostics(summary: &romwright_model::ProgramSummary) {
    use romwright_model::DiagnosticSeverity;
    const SHOWN: usize = 5;
    for (severity, label) in [
        (DiagnosticSeverity::Degraded, "degraded"),
        (DiagnosticSeverity::Partial, "partial"),
        (DiagnosticSeverity::Info, "note"),
    ] {
        let rows: Vec<_> = summary
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.severity == severity)
            .collect();
        if rows.is_empty() {
            continue;
        }
        eprintln!("{label}: {} ({})", rows.len(), summary.program);
        for row in rows.iter().take(SHOWN) {
            let first = row.message.lines().next().unwrap_or_default();
            eprintln!("  [{}] {first}", row.stage);
        }
        if rows.len() > SHOWN {
            eprintln!("  ... {} more", rows.len() - SHOWN);
        }
    }
    if summary
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.severity == DiagnosticSeverity::Degraded)
    {
        eprintln!(
            "{}: analysis incomplete; this import is not cached and will run again",
            summary.program
        );
    }
}
