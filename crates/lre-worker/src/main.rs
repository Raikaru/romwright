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
            "usage: lre-worker <ghidra_opt> <lang-dir> <binary> <program> <addr-hex>... [--project DIR] [--base HEX]"
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
    // Every positional after the program name is an address: one decompiler
    // launch answers a whole batch, which is what makes comparing a 400-row
    // corpus variant affordable (m4-022).
    let addresses: Vec<String> = args[5..]
        .iter()
        .take_while(|argument| !argument.starts_with("--"))
        .cloned()
        .collect();
    if let Err(e) = run(
        &args[1], &args[2], &args[3], &args[4], &addresses, &project, base,
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
    addresses: &[String],
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
    let held = db.symbols(pid)?;
    // Stock applies a demangled name as the *primary* symbol at its address
    // (`DemangledAddressTable.applyTo`, :86, through
    // `DemangledObject.applyDemangledName`, :551-554), and the primary is the
    // name a decompiler prints. Which is why `_ZTIi` prints as `typeinfo`.
    let primary: std::collections::HashMap<u64, String> = held
        .iter()
        .filter(|symbol| symbol.source == lre_core::native::DEMANGLE_SOURCE)
        .map(|symbol| (symbol.address.offset, lre_worker::c_identifier(&symbol.name)))
        .collect();
    // A demangled name is applied inside the namespace the mangled name
    // names -- `typeinfo` in `int` -- and the decompiler prints a symbol
    // outside the global scope scope-qualified. The namespace is re-derived
    // from the mangled name beside it, so one demangler answers both.
    // Scope ids share one space with the function ids this session hands out
    // in mapped-symbol answers (`index + 1`), and a collision makes the
    // decompiler reuse the function's scope instead of asking for the
    // namespace's path (`ScopeGhidra::reresolveScope`,
    // database_ghidra.cc:48-61). Namespaces get their own high range.
    const NAMESPACE_BASE: u64 = 1 << 48;
    let mut next_namespace = NAMESPACE_BASE;
    for symbol in &held {
        if !primary.contains_key(&symbol.address.offset) {
            continue;
        }
        if let Some(demangled) = lre_core::demangle::demangle(&symbol.name) {
            if !demangled.namespace.is_empty() {
                next_namespace += 1;
                provider.namespaces.insert(
                    symbol.address.offset,
                    (next_namespace, lre_worker::c_identifier(&demangled.namespace)),
                );
            }
        }
    }
    for symbol in &held {
        if symbol.source == lre_core::native::DYNAMIC_LABEL_SOURCE
            && symbol.address.space == lre_model::AddressSpace::Ram
        {
            provider
                .tag_names
                .insert(symbol.address.offset, lre_worker::c_identifier(&symbol.name));
        }
    }
    // Which name an address answers with, in the order stock's primary symbol
    // resolves: the demangled name first (it is applied primary,
    // `DemangledAddressTable.applyTo`, :86), then a name the image gives the
    // object, then the dynamic table's label -- which the pinned install keeps
    // non-primary wherever something else names the address (measured at
    // `_DT_INIT`) -- and last the import a linkage slot resolves to, which
    // stock keeps in its EXTERNAL block rather than at the slot.
    let rank = |symbol: &lre_model::SymbolRow| match symbol.source.as_str() {
        _ if primary.contains_key(&symbol.address.offset) => 0,
        lre_core::native::DYNAMIC_LABEL_SOURCE => 2,
        _ if symbol.external => 3,
        _ => 1,
    };
    let mut ordered: Vec<&lre_model::SymbolRow> = held.iter().collect();
    ordered.sort_by_key(|symbol| rank(symbol));
    for symbol in ordered {
        let rendered = primary
            .get(&symbol.address.offset)
            .cloned()
            .unwrap_or_else(|| lre_worker::c_identifier(&symbol.name));
        provider
            .symbol_names
            .entry(symbol.address.offset)
            .or_insert_with(|| rendered.clone());
        if symbol.external {
            provider
                .external_names
                .entry(symbol.address.offset)
                .or_insert(rendered);
        }
    }
    for comment in db.comments(pid)? {
        provider
            .comments
            .entry(comment.function.offset)
            .or_default()
            .push((comment.address.offset, comment.kind, comment.text));
    }
    // A protected call site is a fact with a range and a handler; the comment
    // is its rendering, and it is Ghidra's: `GccExceptionAnalyzer` writes
    // exactly this PRE comment at the range's first address (m4-024).
    for site in db.exception_sites(pid)? {
        provider
            .comments
            .entry(site.function.offset)
            .or_default()
            .push((
                site.start.offset,
                "pre".to_string(),
                format!(
                    "try {{ // try from {:08x} to {:08x} has its CatchHandler @ {:08x}",
                    site.start.offset, site.end.offset, site.landing_pad.offset
                ),
            ));
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
    // A pointer's label names its referent, so a pointer-typed slot's target
    // has to travel with it. Which rule typed the slot does not matter: what
    // the label needs is the address the slot holds (m4-027).
    for xref in db.xrefs(pid)? {
        let pointer = matches!(
            provider.data_definitions.get(&xref.from.offset),
            Some((kind, _)) if kind == "pointer"
        );
        if pointer
            && xref.kind == "DATA"
            && xref.from.space == lre_model::AddressSpace::Ram
            && xref.to.space == lre_model::AddressSpace::Ram
        {
            provider.pointer_targets.insert(xref.from.offset, xref.to.offset);
        }
    }
    provider.load_call_edges(&db, pid)?;
    provider.load_return_behaviors(&db, pid, false)?;
    provider.load_calling_conventions(&db, pid)?;

    let offsets = addresses
        .iter()
        .map(|address| {
            u64::from_str_radix(address.trim_start_matches("0x"), 16)
                .map_err(|e| lre_worker::WorkerError::Setup(e.to_string()))
        })
        .collect::<lre_worker::Result<Vec<u64>>>()?;
    let Some(&offset) = offsets.first() else {
        return Err(lre_worker::WorkerError::Setup("no address to decompile".into()));
    };
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
    let ram = provider.ram_space_index as u32;
    // A batch answers every address from one launch, in one JSON object; a
    // single address keeps the plain-text answer every existing caller reads.
    if offsets.len() > 1 {
        let structured = std::env::var_os("WORKER_STRUCTURED").is_some();
        let mut answers = serde_json::Map::new();
        for offset in offsets {
            worker.prepare_function(&mut provider, offset)?;
            worker.set_action(&mut provider, "decompile", "")?;
            let raw = worker.decompile_at(&mut provider, ram, offset)?;
            // One launch, many functions: the decompiler's per-function
            // caches have to be cleared between them exactly as Ghidra's
            // client clears them.
            worker.flush_native(&mut provider)?;
            let value = if structured {
                let decoded = lre_worker::decode_document_with_ram_space(&raw, Some(ram as u64));
                serde_json::to_value(lre_model::DecompDoc {
                    tokens: decoded.tokens,
                    prototype: decoded.prototype,
                    jump_tables: decoded.jump_tables,
                    address: lre_model::Address::ram(offset),
                    revision: 0,
                    storage: decoded.storage,
                })
                .map_err(|e| lre_worker::WorkerError::Setup(format!("encode document: {e}")))?
            } else {
                let tokens = lre_worker::decode_tokens_with_ram_space(&raw, Some(ram as u64));
                serde_json::Value::String(
                    tokens.iter().map(|token| token.text.as_str()).collect::<String>(),
                )
            };
            answers.insert(format!("{offset:08x}"), value);
        }
        println!(
            "{}",
            serde_json::to_string(&serde_json::Value::Object(answers))
                .map_err(|e| lre_worker::WorkerError::Setup(format!("encode batch: {e}")))?
        );
        return Ok(());
    }
    worker.prepare_function(&mut provider, offset)?;
    worker.set_action(&mut provider, "decompile", "")?;
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