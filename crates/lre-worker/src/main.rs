//! The native decompiler worker (Stage 3 shell).
//!
//! Spawns the pinned `ghidra_opt` binary, speaks the burst/packed protocol
//! on its stdio, and answers its program queries from the project store
//! (`lre-db`) plus the raw binary via a read-only file mapping. This is the
//! no-JVM replacement for the Stage-1 bridge, per ADR-0001.

use std::io::Write;
use std::path::Path;

/// the spec dir, and decompiles one function of a program in the store.
///
/// Usage:
///   lre-worker <ghidra_opt> <lang-dir> <binary> <program> <addr-hex> [--project DIR]
///
/// The language dir must contain the four spec documents (`dump_specs`
/// output) plus registers.txt; the program and its functions come from the
/// project store so the worker is the store-backed no-JVM decompiler.
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 6 {
        eprintln!(
            "usage: lre-worker <ghidra_opt> <lang-dir> <binary> <program> <addr-hex> [--project DIR] [--base HEX]"
        );
        std::process::exit(2);
    }
    let project = std::env::args()
        .position(|a| a == "--project")
        .and_then(|i| std::env::args().nth(i + 1))
        .unwrap_or_else(|| ".lre".into());
    let base = std::env::args()
        .position(|a| a == "--base")
        .and_then(|i| std::env::args().nth(i + 1))
        .and_then(|v| u64::from_str_radix(v.trim_start_matches("0x"), 16).ok())
        .unwrap_or(0x400000);
    if let Err(e) = run(
        &args[1], &args[2], &args[3], &args[4], &args[5], &project, base,
    ) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run(
    ghidra_opt: &str,
    lang_dir: &str,
    binary: &str,
    program: &str,
    addr: &str,
    project: &str,
    base: u64,
) -> lre_worker::Result<()> {
    let mut provider = lre_worker::ProgramProvider::new(
        lre_worker::BinaryBacking::from_file(Path::new(binary), base)?,
        Vec::new(),
    );
    provider.load_language_info(Path::new(lang_dir))?;

    // Function entries from the project store.
    let db = lre_worker::open_store(Path::new(project))?;
    let pid = db.program_id(program)?;
    for f in db.functions(pid)? {
        let off = f.entry.offset;
        provider.functions.push(off);
        provider
            .function_names
            .insert(off, lre_worker::c_identifier(&f.name));
        provider.function_sizes.insert(off, f.size as u64);
    }
    for symbol in db.symbols(pid)? {
        let rendered = lre_worker::c_identifier(&symbol.name);
        provider
            .symbol_names
            .entry(symbol.address.offset)
            .or_insert_with(|| rendered.clone());
        if symbol.external {
            provider
                .external_names
                .insert(symbol.address.offset, rendered);
        }
    }
    for comment in db.comments(pid)? {
        provider
            .comments
            .entry(comment.function.offset)
            .or_default()
            .push((comment.address.offset, comment.kind, comment.text));
    }
    for datatype in db.datatypes(pid)? {
        provider
            .datatypes
            .insert(datatype.name, datatype.definition);
    }
    for prototype in db.prototypes(pid)? {
        if !prototype.signature.is_empty() {
            provider
                .prototypes
                .insert(prototype.function.offset, prototype);
        }
    }
    for string in db
        .strings(pid)?
        .into_iter()
        .filter(|string| string.address.space == lre_model::AddressSpace::Ram)
    {
        provider.strings.insert(string.address.offset, string.value);
    }
    // Locations a stored data reference names and nothing else describes:
    // the dynamic-label case (`SymbolUtilities.getDynamicName`).
    // A thunk's jump transfers control the way a call does. The store proves
    // both halves: the thunk row names entry and destination, and the xref
    // row names the instruction that performs the transfer.
    for region in db.memory_regions(pid)? {
        if region.start.space == lre_model::AddressSpace::Ram
            && !region.permissions.contains('w')
            && region.size > 0
        {
            provider
                .read_only
                .push((region.start.offset, region.start.offset + region.size));
        }
    }
    for region in db.memory_regions(pid)? {
        if region.start.space == lre_model::AddressSpace::Ram
            && region.permissions.contains('x')
            && region.size > 0
        {
            provider
                .executable
                .push((region.start.offset, region.start.offset + region.size));
        }
    }
    for row in db.data_definitions(pid)? {
        if row.address.space == lre_model::AddressSpace::Ram && row.size > 0 {
            provider
                .data_definitions
                .insert(row.address.offset, (row.data_type, row.size));
        }
    }
    // A stub's transfer is recorded as a flow override by the importer, which
    // is where the branch instruction is known; nothing is derived here.
    // Instruction flow the store corrects: each override belongs to the
    // function that contains it, which is how the decompiler keys them.
    for row in db.flow_overrides(pid)? {
        if row.address.space != lre_model::AddressSpace::Ram || row.kind != "callreturn" {
            continue;
        }
        let address = row.address.offset;
        let Some(index) = provider
            .functions
            .iter()
            .rposition(|entry| *entry <= address)
        else {
            continue;
        };
        let entry = provider.functions[index];
        let span = provider
            .function_sizes
            .get(&entry)
            .copied()
            .filter(|size| *size > 0)
            .unwrap_or_else(|| {
                provider
                    .functions
                    .get(index + 1)
                    .map_or(u64::MAX, |next| *next)
                    .saturating_sub(entry)
            });
        if address < entry.saturating_add(span) {
            provider
                .call_return_branches
                .entry(entry)
                .or_default()
                .push(address);
        }
    }
    for target in db.data_reference_targets(pid)? {
        if target.space == lre_model::AddressSpace::Ram {
            provider.data_targets.insert(target.offset);
        }
    }
    provider.load_call_edges(&db, pid)?;
    provider.load_return_behaviors(&db, pid, false)?;
    provider.load_calling_conventions(&db, pid)?;

    let offset = u64::from_str_radix(addr.trim_start_matches("0x"), 16)
        .map_err(|e| lre_worker::WorkerError::Setup(e.to_string()))?;
    let specs = lre_worker::load_specs(Path::new(lang_dir))?;
    provider.core_types = lre_worker::parse_core_types(&specs.3);
    let mut worker = lre_worker::NativeWorker::launch(std::process::Command::new(ghidra_opt))?;
    let function_shell = provider.function_shell()?;
    worker.register_program_with_shell(
        &mut provider,
        &specs.0,
        &specs.1,
        &specs.2,
        &specs.3,
        &function_shell,
    )?;
    worker.prepare_function(&mut provider, offset)?;
    worker.set_action(&mut provider, "decompile", "")?;
    let ram = provider.ram_space_index as u32;
    let raw = worker.decompile_at(&mut provider, ram, offset)?;
    // The packed response is the source of truth for both structured tokens
    // and rendered compatibility text. `decode_tokens_with_ram_space` follows
    // PackedDecode.java and preserves token metadata; concatenation is only
    // the legacy CLI presentation boundary.
    if std::env::var_os("WORKER_STRUCTURED").is_some() {
        let decoded = lre_worker::decode_document_with_ram_space(&raw, Some(ram as u64));
        let doc = lre_model::DecompDoc {
            tokens: decoded.tokens,
            prototype: decoded.prototype,
            jump_tables: decoded.jump_tables,
            address: lre_model::Address::ram(offset),
            revision: 0,
            storage: decoded.storage,
        };
        println!(
            "{}",
            serde_json::to_string(&doc)
                .map_err(|e| lre_worker::WorkerError::Setup(format!("encode document: {e}")))?
        );
        return Ok(());
    }
    let tokens = lre_worker::decode_tokens_with_ram_space(&raw, Some(ram as u64));
    let c_text: String = tokens.iter().map(|token| token.text.as_str()).collect();
    if std::env::var_os("WORKER_DUMP").is_some() {
        let mut f = std::fs::File::create("/tmp/ctext_dump.txt").unwrap();
        let _ = f.write_all(c_text.as_bytes());
    }
    println!("{c_text}");
    Ok(())
}