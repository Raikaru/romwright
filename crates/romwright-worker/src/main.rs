//! The native decompiler worker (Stage 3 shell).
//!
//! Spawns the pinned `ghidra_opt` binary, speaks the burst/packed protocol
//! on its stdio, and answers its program queries from the project store
//! (`romwright-db`) plus the selected immutable program input. This is the
//! no-JVM replacement for the Stage-1 bridge, per ADR-0001.

use std::io::Write;
use std::path::Path;

/// Decompiles stored program functions using the supplied native specification bundle.
///
/// Usage:
///   romwright-worker <ghidra_opt> <lang-dir|auto> <program> <addr-hex>... [--project DIR]
///                    [--switches | --printer-diff]
///
/// The language dir must contain the four spec documents (`dump_specs`
/// output) plus registers.txt; `auto` resolves the program's own bundle and
/// SLEIGH as the CLI does. The program and its functions come from the
/// project store so the worker is the store-backed no-JVM decompiler.
/// `--printer-diff` compares the Rust C printer against PrintC per address.
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 5 {
        eprintln!(
            "usage: romwright-worker <ghidra_opt> <lang-dir|auto> <program> <addr-hex>... [--project DIR] [--switches|--printer-diff]"
        );
        std::process::exit(2);
    }
    let project = std::env::args()
        .position(|a| a == "--project")
        .and_then(|i| std::env::args().nth(i + 1))
        .unwrap_or_else(|| ".romwright".into());
    // Every positional after the program name is an address: one decompiler
    // launch answers a whole batch, which is what makes comparing a 400-row
    // corpus variant affordable (m4-022).
    let addresses: Vec<String> = args[4..]
        .iter()
        .take_while(|argument| !argument.starts_with("--"))
        .cloned()
        .collect();
    // Structuring takes graphs on stdin instead of addresses: it needs the
    // language and the image, not the store's facts.
    let outcome = if args.iter().any(|argument| argument == "--structure") {
        run_structure(&args[1], &args[2], &args[3], &project)
    } else if args.iter().any(|argument| argument == "--printer-diff") {
        run_printer_diff(&args[1], &args[2], &args[3], &addresses, &project)
    } else {
        run(
            &args[1], &args[2], &args[3], &addresses, &project,
            args.iter().any(|argument| argument == "--switches"),
        )
    };
    if let Err(e) = outcome {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn program_input(
    db: &romwright_db::ProjectDb,
    program: romwright_model::ProgramId,
) -> romwright_worker::Result<romwright_model::ProgramInput> {
    match std::env::var("ROMWRIGHT_PROGRAM_INPUT") {
        Ok(record) => serde_json::from_str(&record).map_err(|error| {
            romwright_worker::WorkerError::Setup(format!("captured input: {error}"))
        }),
        Err(std::env::VarError::NotPresent) => Ok(db.program_input(program)?),
        Err(error) => Err(romwright_worker::WorkerError::Setup(error.to_string())),
    }
}

/// The specification bundle and decompiler environment for `program`.
///
/// A `lang_dir` of `auto` resolves the program's SLEIGH and specification
/// bundle as the CLI does (`language_decompile_config`); otherwise
/// `lang_dir` is the bundle and the caller provides `ROMWRIGHT_SLA` and
/// `ROMWRIGHT_LANGUAGE*` in the environment.
fn resolve_language(
    db: &romwright_db::ProjectDb,
    program: romwright_model::ProgramId,
    lang_dir: &str,
) -> romwright_worker::Result<(std::path::PathBuf, Vec<(&'static str, std::ffi::OsString)>)> {
    if lang_dir != "auto" {
        return Ok((std::path::PathBuf::from(lang_dir), Vec::new()));
    }
    let language = db.program_language(program)?;
    let cfg = romwright_core::session::RuntimeConfig::from_env();
    let (sla, specs, language_dir, language) =
        romwright_core::native_runtime::language_decompile_config(&cfg, &language).map_err(
            |error| romwright_worker::WorkerError::Setup(format!("language {language}: {error}")),
        )?;
    Ok((
        specs,
        vec![
            ("ROMWRIGHT_SLA", sla.into_os_string()),
            ("ROMWRIGHT_LANGUAGE_DIR", language_dir.into_os_string()),
            ("ROMWRIGHT_LANGUAGE", language.into()),
        ],
    ))
}

/// The printer differential (benchmarks/printer_diff.py): decompiles each
/// address once, prints the exported printer IR with the Rust printer
/// without structuring models ([`romwright_worker::printc::reference`]), and
/// compares it against PrintC's markup from the same Funcdata.
/// Answers one JSON line per address. `lang_dir` as in [`resolve_language`].
fn run_printer_diff(
    ghidra_opt: &str,
    lang_dir: &str,
    program: &str,
    addresses: &[String],
    project: &str,
) -> romwright_worker::Result<()> {
    use romwright_worker::WorkerError;
    let timeout = std::env::var("WORKER_DECOMPILE_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(romwright_core::exec::DEFAULT_BUDGET.as_secs());
    let db = romwright_worker::open_store(Path::new(project))?;
    let pid = db.program_id(program)?;
    let input = program_input(&db, pid)?;
    let (specs_dir, environment) = resolve_language(&db, pid, lang_dir)?;
    let mut provider = romwright_worker::ProgramProvider::from_store(
        Path::new(project),
        &input,
        &specs_dir,
        &db,
        pid,
        false,
    )?;
    let specs = romwright_worker::specs::load_program_specs(&mut provider, &specs_dir, &db, pid)?;
    let function_shell = provider.function_shell()?;
    let launch = |provider: &mut romwright_worker::ProgramProvider| {
        let mut command = std::process::Command::new(ghidra_opt);
        command.envs(environment.iter().map(|(key, value)| (key, value)));
        let mut worker = romwright_worker::NativeWorker::launch(command)?;
        worker.register_program_with_shell(
            provider,
            &specs.0,
            &specs.1,
            &specs.2,
            &specs.3,
            &function_shell,
        )?;
        Ok::<_, WorkerError>(worker)
    };
    let ram = provider.ram_space_index as u32;
    let mut worker = launch(&mut provider)?;
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    for address in addresses {
        let offset = u64::from_str_radix(address.trim_start_matches("0x"), 16)
            .map_err(|e| WorkerError::Setup(e.to_string()))?;
        let deadline = (timeout > 0)
            .then(|| std::time::Instant::now() + std::time::Duration::from_secs(timeout));
        let raw = worker.within_deadline(deadline, |worker| {
            worker.prepare_function(&mut provider, offset)?;
            worker.set_action(&mut provider, "decompile", "")?;
            worker.decompile_at(&mut provider, ram, offset)
        });
        let report = match raw {
            Ok(raw) => compare_printers(&raw, u64::from(ram)),
            Err(error) => {
                serde_json::json!({ "status": "decompile-error", "detail": error.to_string() })
            }
        };
        let flushed = worker.within_deadline(deadline, |worker| worker.flush_native(&mut provider));
        if flushed.is_err() {
            worker = launch(&mut provider)?;
        }
        let mut line = serde_json::json!({ "address": format!("{offset:08x}") });
        if let (Some(line), serde_json::Value::Object(report)) = (line.as_object_mut(), report) {
            line.extend(report);
        }
        writeln!(stdout, "{line}")?;
        stdout.flush()?;
    }
    Ok(())
}

/// Classifies the first difference between PrintC's and the Rust printer's
/// markup for one response.
fn compare_printers(raw: &[u8], ram: u64) -> serde_json::Value {
    use romwright_model::TokenKind;
    let sections = match romwright_worker::printc::sections(raw) {
        Ok(sections) => sections,
        Err(error) => {
            return serde_json::json!({ "status": "error", "category": "document", "detail": error });
        }
    };
    let (Some(stock), Some(blob)) = (sections.markup, sections.printer_ir) else {
        return serde_json::json!({ "status": "error", "category": "missing-output",
            "detail": format!("markup: {}, printer IR: {}", sections.markup.is_some(), sections.printer_ir.is_some()) });
    };
    let (ours, expressions) = match romwright_worker::printc::reference_with_stats(blob) {
        Ok(rendered) => rendered,
        Err(error) => {
            return serde_json::json!({ "status": "error", "category": "render", "detail": error });
        }
    };
    let expected = romwright_worker::decode_tokens_with_ram_space(stock, Some(ram));
    let actual = romwright_worker::decode_tokens_with_ram_space(&ours, Some(ram));
    let base = serde_json::json!({ "stock_bytes": stock.len(), "rust_bytes": ours.len(), "tokens": expected.len(),
        "expressions": expressions });
    let report = |status: &str, category: &str, detail: String| {
        let mut value = base.clone();
        if let Some(object) = value.as_object_mut() {
            object.insert("status".into(), status.into());
            object.insert("category".into(), category.into());
            object.insert("detail".into(), detail.into());
        }
        value
    };
    if stock == ours.as_slice() {
        return report("identical", "identical", String::new());
    }
    let as_json =
        |tokens: &[romwright_model::DecompToken]| serde_json::to_value(tokens).unwrap_or_default();
    if as_json(&expected) == as_json(&actual) {
        return report(
            "different",
            "markup-only",
            "tokens equal, packed bytes differ".into(),
        );
    }
    let lines = |tokens: &[romwright_model::DecompToken], breaks: bool| {
        let mut lines = vec![String::new()];
        for token in tokens {
            if token.kind == TokenKind::Break {
                if breaks {
                    lines.push(" ".repeat(token.indent.unwrap_or(0).max(0) as usize));
                }
            } else if let Some(line) = lines.last_mut() {
                line.push_str(&token.text);
            }
        }
        lines
    };
    let first_difference = |left: &[String], right: &[String]| {
        let index = left
            .iter()
            .zip(right)
            .position(|(a, b)| a != b)
            .unwrap_or(left.len().min(right.len()));
        format!(
            "line {index}: printc {:?} | rust {:?}",
            left.get(index).map(String::as_str).unwrap_or("<end>"),
            right.get(index).map(String::as_str).unwrap_or("<end>")
        )
    };
    let (stock_lines, rust_lines) = (lines(&expected, true), lines(&actual, true));
    if stock_lines == rust_lines {
        let index = expected
            .iter()
            .zip(&actual)
            .position(|(a, b)| serde_json::to_value(a).ok() != serde_json::to_value(b).ok())
            .unwrap_or(0);
        return report(
            "different",
            "token-links",
            format!("token {index}: {:?}", expected.get(index).map(|t| &t.text)),
        );
    }
    if lines(&expected, false) == lines(&actual, false) {
        return report(
            "different",
            "line-breaks",
            first_difference(&stock_lines, &rust_lines),
        );
    }
    report(
        "different",
        "text",
        first_difference(&stock_lines, &rust_lines),
    )
}

/// Structures control-flow graphs read from stdin, one JSON object per line:
/// `{"id":"...","blocks":[<start address>,...],"edges":[[from,to],...]}`.
///
/// Answers one JSON object per request with the hierarchy the decompiler's
/// own `structureGraph` produced, the count of blocks by kind, and the number
/// of unstructured jumps in it. No decompilation happens: the command takes a
/// graph and returns its structure, which is what makes our own structuring
/// comparable on identical input.
fn run_structure(
    ghidra_opt: &str,
    lang_dir: &str,
    program: &str,
    project: &str,
) -> romwright_worker::Result<()> {
    use std::io::BufRead as _;
    let db = romwright_worker::open_store(Path::new(project))?;
    let input = program_input(&db, db.program_id(program)?)?;
    let mut provider = romwright_worker::ProgramProvider::new(
        romwright_worker::BinaryBacking::from_input(Path::new(project), &input)?,
        Vec::new(),
    );
    provider.load_language_info(Path::new(lang_dir))?;
    let specs = romwright_worker::load_specs(Path::new(lang_dir))?;
    provider.core_types = romwright_worker::parse_core_types(&specs.3);
    let mut worker =
        romwright_worker::NativeWorker::launch(std::process::Command::new(ghidra_opt))?;
    let function_shell = provider.function_shell()?;
    worker.register_program_with_shell(
        &mut provider,
        &specs.0,
        &specs.1,
        &specs.2,
        &specs.3,
        &function_shell,
    )?;
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let line = line.map_err(|error| romwright_worker::WorkerError::Setup(error.to_string()))?;
        if line.trim().is_empty() {
            continue;
        }
        #[derive(serde::Deserialize)]
        struct Request {
            #[serde(default)]
            id: String,
            blocks: Vec<u64>,
            edges: Vec<(usize, usize)>,
        }
        let request: Request = serde_json::from_str(&line)
            .map_err(|error| romwright_worker::WorkerError::Setup(error.to_string()))?;
        let graph = romwright_worker::structure::ControlFlow {
            blocks: request.blocks,
            edges: request.edges,
        };
        let answer = match worker.structure_graph(&mut provider, &graph) {
            Ok(tree) => serde_json::json!({
                "id": request.id,
                "gotos": tree.gotos(),
                "breaks_and_continues": tree.breaks_and_continues(),
                "kinds": tree.kinds(),
                "tree": tree,
            }),
            Err(error) => serde_json::json!({
                "id": request.id,
                "error": error.to_string(),
            }),
        };
        println!("{answer}");
    }
    Ok(())
}

fn run(
    ghidra_opt: &str,
    lang_dir: &str,
    program: &str,
    addresses: &[String],
    project: &str,
    switches: bool,
) -> romwright_worker::Result<()> {
    // Ordinary decompilation shares one deadline; switch batches isolate functions.
    let timeout = std::env::var("WORKER_DECOMPILE_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(romwright_core::exec::DEFAULT_BUDGET.as_secs());
    let deadline =
        (timeout > 0).then(|| std::time::Instant::now() + std::time::Duration::from_secs(timeout));
    let checkpoint = || {
        if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
            Err(romwright_worker::WorkerError::Timeout(timeout))
        } else {
            Ok(())
        }
    };
    let db = romwright_worker::open_store(Path::new(project))?;
    let pid = db.program_id(program)?;
    let input = program_input(&db, pid)?;
    let (specs_dir, environment) = resolve_language(&db, pid, lang_dir)?;
    let decompiler = || {
        let mut command = std::process::Command::new(ghidra_opt);
        command.envs(environment.iter().map(|(key, value)| (key, value)));
        command
    };
    let mut provider = romwright_worker::ProgramProvider::from_store(
        Path::new(project),
        &input,
        &specs_dir,
        &db,
        pid,
        false,
    )?;
    if switches {
        // Switch recovery asks the decompiler what it recovers by itself; the
        // tables it is asked for are not fed back to it.
        provider.stored_switch_mode = romwright_worker::provider::StoredSwitches::Off;
    }

    let offsets = addresses
        .iter()
        .map(|address| {
            u64::from_str_radix(address.trim_start_matches("0x"), 16)
                .map_err(|e| romwright_worker::WorkerError::Setup(e.to_string()))
        })
        .collect::<romwright_worker::Result<Vec<u64>>>()?;
    let Some(&offset) = offsets.first() else {
        return Err(romwright_worker::WorkerError::Setup(
            "no address to decompile".into(),
        ));
    };
    let specs = romwright_worker::specs::load_program_specs(&mut provider, &specs_dir, &db, pid)?;
    let mut worker = romwright_worker::NativeWorker::launch(decompiler())?;
    let function_shell = provider.function_shell()?;
    worker.within_deadline(deadline, |worker| {
        worker.register_program_with_shell(
            &mut provider,
            &specs.0,
            &specs.1,
            &specs.2,
            &specs.3,
            &function_shell,
        )
    })?;
    let ram = provider.ram_space_index as u32;
    if switches {
        worker.within_deadline(deadline, |worker| {
            worker.configure_switch_recovery(&mut provider)
        })?;
        let mut restart = false;
        let stdout = std::io::stdout();
        let mut stdout = stdout.lock();
        for offset in offsets {
            let deadline = (timeout > 0)
                .then(|| std::time::Instant::now() + std::time::Duration::from_secs(timeout));
            if restart {
                worker = romwright_worker::NativeWorker::launch(decompiler())?;
                worker.within_deadline(deadline, |worker| {
                    worker.register_program_with_shell(
                        &mut provider,
                        &specs.0,
                        &specs.1,
                        &specs.2,
                        &specs.3,
                        &function_shell,
                    )?;
                    worker.configure_switch_recovery(&mut provider)
                })?;
            }
            let result = worker.within_deadline(deadline, |worker| {
                worker.prepare_function(&mut provider, offset)?;
                let raw = worker.decompile_at(&mut provider, ram, offset)?;
                let decoded = romwright_worker::doc::decode_document_with_ram_space(
                    &raw,
                    Some(u64::from(ram)),
                );
                decoded.jump_tables.ok_or_else(|| {
                    romwright_worker::WorkerError::Protocol(
                        "switch response has no complete function".into(),
                    )
                })
            });
            // Never retry the failed function, or discard a completed table
            // because clearing the session for the next function failed.
            restart = result.is_err()
                || worker
                    .within_deadline(deadline, |worker| worker.flush_native(&mut provider))
                    .is_err();
            // The wall-clock guard is the one failure that depends on the
            // host's load, so the client is told which one it was.
            let wall_clock = matches!(result, Err(romwright_worker::WorkerError::Timeout(_)));
            let result = result.map_err(|error| error.to_string());
            let response =
                serde_json::json!({ "address": offset, "result": result, "wall_clock": wall_clock });
            writeln!(stdout, "{response}")?;
            stdout.flush()?;
        }
        return Ok(());
    }
    let ir_passes = match std::env::var("ROMWRIGHT_IR_PASSES") {
        Ok(value) => romwright_core::func_ir::parse_pass_names(&value),
        Err(std::env::VarError::NotPresent) => romwright_core::func_ir::default_pass_names(),
        Err(error) => return Err(romwright_worker::WorkerError::Setup(error.to_string())),
    };
    // A batch answers every address from one launch, in one JSON object; a
    // single address keeps the plain-text answer every existing caller reads.
    if offsets.len() > 1 {
        let structured = std::env::var_os("WORKER_STRUCTURED").is_some();
        // The simplification style a caller asks for; `decompile` is what a
        // reader wants, `normalize` is what a switch-recovery pass needs
        // (jump tables are recovered while flow is built, before either).
        let action = std::env::var("WORKER_ACTION").unwrap_or_else(|_| "decompile".to_string());
        let mut answers = serde_json::Map::new();
        for offset in offsets {
            // One function's failure is that function's answer, not the
            // batch's. A real image branches into memory it never maps -- a
            // Nintendo 64 boot segment jumps past RDRAM -- and the decompiler
            // raises for the address it cannot read. Ghidra's client keeps its
            // session and reports the one function as undecompiled, so the
            // batch omits the key and every other address still answers.
            let decoded = match worker.within_deadline(deadline, |worker| {
                worker.prepare_function(&mut provider, offset)?;
                worker.set_action(&mut provider, &action, "")?;
                let raw = worker.decompile_at(&mut provider, ram, offset)?;
                let passes = if action == "decompile" {
                    ir_passes.as_slice()
                } else {
                    &[]
                };
                worker.finalize_document(&mut provider, &raw, ram, offset, passes, deadline, None)
            }) {
                Ok(decoded) => decoded,
                Err(error) => {
                    checkpoint()?;
                    eprintln!("warning: {offset:08x}: {error}");
                    // The exception leaves the session's per-function state
                    // behind; if it cannot be cleared the process is gone and
                    // a fresh one takes over the rest of the batch.
                    if worker
                        .within_deadline(deadline, |worker| worker.flush_native(&mut provider))
                        .is_err()
                    {
                        checkpoint()?;
                        worker = romwright_worker::NativeWorker::launch(decompiler())?;
                        worker.within_deadline(deadline, |worker| {
                            worker.register_program_with_shell(
                                &mut provider,
                                &specs.0,
                                &specs.1,
                                &specs.2,
                                &specs.3,
                                &function_shell,
                            )
                        })?;
                    }
                    continue;
                }
            };
            let doc = romwright_model::DecompDoc {
                tokens: decoded.tokens,
                prototype: decoded.prototype,
                call_prototypes: decoded.call_prototypes,
                call_targets: decoded.call_targets,
                jump_tables: decoded.jump_tables,
                address: romwright_model::Address::ram(offset),
                revision: 0,
                storage: decoded.storage,
                function_ir: decoded.function_ir,
            };
            let value = if structured {
                serde_json::to_value(&doc).map_err(|e| {
                    romwright_worker::WorkerError::Setup(format!("encode document: {e}"))
                })?
            } else {
                serde_json::Value::String(romwright_core::emit_m2c::render_doc_text(&doc))
            };
            worker.within_deadline(deadline, |worker| worker.flush_native(&mut provider))?;
            answers.insert(format!("{offset:08x}"), value);
        }
        checkpoint()?;
        println!(
            "{}",
            serde_json::to_string(&serde_json::Value::Object(answers))
                .map_err(|e| romwright_worker::WorkerError::Setup(format!("encode batch: {e}")))?
        );
        return Ok(());
    }
    let decoded = worker.within_deadline(deadline, |worker| {
        worker.prepare_function(&mut provider, offset)?;
        let action = std::env::var("WORKER_ACTION").unwrap_or_else(|_| "decompile".to_string());
        worker.set_action(&mut provider, &action, "")?;
        let raw = worker.decompile_at(&mut provider, ram, offset)?;
        let passes = if action == "decompile" {
            ir_passes.as_slice()
        } else {
            &[]
        };
        worker.finalize_document(&mut provider, &raw, ram, offset, passes, deadline, None)
    })?;
    let doc = romwright_model::DecompDoc {
        tokens: decoded.tokens,
        prototype: decoded.prototype,
        call_prototypes: decoded.call_prototypes,
        call_targets: decoded.call_targets,
        jump_tables: decoded.jump_tables,
        address: romwright_model::Address::ram(offset),
        revision: 0,
        storage: decoded.storage,
        function_ir: decoded.function_ir,
    };
    checkpoint()?;
    if std::env::var_os("WORKER_STRUCTURED").is_some() {
        println!(
            "{}",
            serde_json::to_string(&doc).map_err(|e| romwright_worker::WorkerError::Setup(
                format!("encode document: {e}")
            ))?
        );
        return Ok(());
    }
    let c_text = romwright_core::emit_m2c::render_doc_text(&doc);
    if std::env::var_os("WORKER_DUMP").is_some() {
        let mut f = std::fs::File::create("/tmp/ctext_dump.txt").unwrap();
        let _ = f.write_all(c_text.as_bytes());
    }
    println!("{c_text}");
    Ok(())
}
