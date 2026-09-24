use super::*;

/// Writes a native import into the store, returning the summary.
/// Ghidra's own name for the model the operating system enters a process
/// with (`ElfProgramBuilder.PROCESS_ENTRY_CALLING_CONVENTION_NAME`, :67).
pub const PROCESS_ENTRY_MODEL: &str = "processEntry";
/// The rule that proved it: an ABI-reserved entry point, not an analysis.
pub const ENTRY_CONVENTION_SOURCE: &str = "native-import:entry-convention";
/// A name the dynamic table itself carries.
pub const DYNAMIC_LABEL_SOURCE: &str = "native-import:dynamic-tag";
/// A branch that leaves its function for another function's entry.
pub const SHARED_RETURN_SOURCE: &str = "native-analysis:shared-return";
/// How wide the access that reached a location was.
pub const DATA_WIDTH_SOURCE: &str = "native-analysis:data-width";
/// A word an initializer array proves holds a code address.
pub const ELF_POINTER_SOURCE: &str = "native-import:elf-pointer";

/// A referenced word whose bytes are a function's entry.
pub const DATA_POINTER_SOURCE: &str = "native-analysis:data-pointer";

/// A word inside a `.got` section, which the ELF loader types as a pointer.
pub const ELF_GOT_SOURCE: &str = "native-import:elf-got";

/// The name a mangled name was mangled from, applied beside it.
pub const DEMANGLE_SOURCE: &str = "native-analysis:demangle";

/// The size and name an ELF `OBJECT` symbol declares for the object it
/// names: sizes ride inferred data definitions, names ride symbols.
pub const ELF_OBJECT_SOURCE: &str = "native-import:elf-object";

/// A linkage slot whose relocation names a function: the loader will write a
/// code address into it.
pub const ELF_LINKAGE_SOURCE: &str = "native-import:elf-linkage";
/// An object the dynamic linker copies into the image, named by the
/// relocation that copies it.
pub const ELF_COPY_SOURCE: &str = "native-import:elf-copy";

/// A call site `.gcc_except_table` declares protected, with its handler.
pub const ELF_EXCEPTION_SOURCE: &str = "native-import:elf-exception";

/// The process-entry model when the language declares one, and nothing when
/// it does not -- Ghidra catches the same failure and skips silently
/// (`processEntryPoints`, :666-672). An undeclared name would be worse than
/// none: the decompiler answers an unrecognized model with a placeholder
/// that has no parameter storage at all (`fspec.cc:4695-4698`).
pub fn declared_entry_model(
    cfg: &crate::session::RuntimeConfig,
    language: &str,
) -> Option<&'static str> {
    let (_, specs, _, _) = crate::native_runtime::language_decompile_config(cfg, language).ok()?;
    let cspec = std::fs::read_to_string(specs.join("cspec.xml")).ok()?;
    crate::register_params::declares_model(&cspec, PROCESS_ENTRY_MODEL)
        .then_some(PROCESS_ENTRY_MODEL)
}

/// Whether a const-seeded entry's body swallows a better-evidenced one.
/// Two functions cannot share code (m8-002); strict containment only --
/// an abutting neighbour (start == end) is a correct boundary, not an
/// overlap. Sizes of 0 read as 1, matching the stored rows.
/// Whether `entry` opens the way ARM code opens, in either instruction set:
/// Thumb `push` or `push.w`, `bx lr` or a PC-relative literal load; ARM
/// `stmdb sp!` with `lr`, `bx lr` or a PC-relative `ldr`.
fn opens_like_arm_code(imp: &NativeImport, entry: u64) -> bool {
    let read = |count: usize| {
        imp.mappings.iter().find_map(|mapping| {
            let offset = usize::try_from(entry.checked_sub(mapping.vaddr)?).ok()?;
            mapping.bytes.get(offset..offset.checked_add(count)?).map(<[u8]>::to_vec)
        })
    };
    let thumb = read(2).is_some_and(|b| {
        let half = u16::from_le_bytes([b[0], b[1]]);
        // Thumb-2 `push.w`/`stmdb sp!` opens with 0xe92d: the Vita compiler's
        // frame, where agbcc's is the 16-bit `push`.
        half & 0xfe00 == 0xb400 || half == 0x4770 || half >> 11 == 0b01001 || half == 0xe92d
    });
    let arm = read(4).is_some_and(|b| {
        let word = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        word & 0xffff_4000 == 0xe92d_4000 || word == 0xe12f_ff1e || word & 0x0f7f_0000 == 0x051f_0000
    });
    thumb || arm
}

/// Functions only a call claims that neither open like code nor are called
/// from anything trusted. Trust starts at functions that open like code or
/// that the image itself names (`anchored`), and flows forward along direct
/// calls into call-only functions.
fn untrusted_call_chains(
    imp: &NativeImport,
    functions: &[NativeFunction],
    only_called: impl Fn(u64) -> bool,
    anchored: impl Fn(u64) -> bool,
) -> std::collections::HashSet<u64> {
    let mut bodies: Vec<(u64, u64)> = functions
        .iter()
        .map(|function| (function.entry, function.entry + function.size.max(1)))
        .collect();
    bodies.sort_unstable();
    let owner = |address: u64| {
        let index = bodies.partition_point(|&(start, _)| start <= address);
        index
            .checked_sub(1)
            .filter(|&i| address < bodies[i].1)
            .map(|i| bodies[i].0)
    };
    let mut callees: std::collections::HashMap<u64, Vec<u64>> = std::collections::HashMap::new();
    for xref in imp.xrefs.iter().filter(|xref| xref.kind.contains("CALL")) {
        if let Some(caller) = owner(xref.from) {
            callees.entry(caller).or_default().push(xref.to & !1);
        }
    }
    let mut trusted: std::collections::HashSet<u64> = functions
        .iter()
        .map(|function| function.entry)
        .filter(|&entry| anchored(entry) || opens_like_arm_code(imp, entry))
        .collect();
    let mut pending: Vec<u64> = trusted.iter().copied().collect();
    while let Some(caller) = pending.pop() {
        for &callee in callees.get(&caller).map(Vec::as_slice).unwrap_or(&[]) {
            if only_called(callee) && trusted.insert(callee) {
                pending.push(callee);
            }
        }
    }
    functions
        .iter()
        .map(|function| function.entry)
        .filter(|&entry| only_called(entry) && !trusted.contains(&entry))
        .collect()
}

pub(super) fn const_entry_swallowed(entry: u64, size: u64, stronger: &[u64]) -> bool {
    stronger
        .iter()
        .any(|&other| entry < other && other < entry + size.max(1))
}

pub fn store_import(
    db: &ProjectDb,
    program: &str,
    imp: &NativeImport,
    entry_model: Option<&str>,
) -> Result<ProgramSummary> {
    db.invalidate_program_input(program)?;
    let mut functions = imp.functions.clone();
    functions.sort_by_key(|f| f.entry);
    // Fill sizes from the next function's entry only where none was proven.
    // A proven one-byte body is a fact, not a placeholder: overwriting it with
    // the distance to the next entry made a one-instruction CRT stub own a
    // kilobyte of unrelated code.
    for i in 0..functions.len() {
        if functions[i].size == 0 {
            let end = functions
                .get(i + 1)
                .map(|n| n.entry)
                .unwrap_or(functions[i].entry + 16);
            functions[i].size = end.saturating_sub(functions[i].entry).max(1);
        }
    }
    let pid = db.upsert_program(program, &imp.language, &native_provenance())?;
    // Publish the loader identity with the program itself: a native worker
    // reopening this store must see the same immutable input the import
    // analysed, so its answers are reproducible from the store alone.
    if let Some((_, input)) = imp.input_context.as_deref() {
        db.set_program_input(pid, input)?;
    }
    if let Some(toolchain) = &imp.toolchain {
        db.set_program_compiler(pid, toolchain)?;
    }
    // DOL toolchain: the mwcc runtime symbols are the fingerprint, and
    // they arrive via --map after dol::import returns — so detection
    // runs here, not in the loader.
    if imp.toolchain.is_none() && imp.format.eq_ignore_ascii_case("dol") {
        let mwcc = imp.functions.iter().any(|f| {
            matches!(
                f.name.as_str(),
                "__init_registers" | "__start" | "__ppc_eabi_init"
            )
        });
        if mwcc {
            db.set_program_compiler(pid, "mwcc")?;
        }
    }
    let mut regions = imp
        .mappings
        .iter()
        .enumerate()
        .map(|(index, mapping)| MemoryRegion {
            name: match imp.mapping_names.get(index) {
                Some(name) => format!("{}:{name}", imp.format.to_ascii_lowercase()),
                None => format!("{}:{index}", imp.format.to_ascii_lowercase()),
            },
            start: romwright_model::Address::ram(mapping.vaddr),
            size: mapping.size,
            permissions: mapping_permissions(mapping.flags),
            source: "native-import".into(),
        })
        .collect::<Vec<_>>();
    // Every mapped region is a module the program loads: DOL sections,
    // ELF segments, REL images. `locate` names the module an address
    // belongs to from these rows.
    for region in &regions {
        db.insert_module(
            pid,
            &romwright_model::ModuleRow {
                module_id: 0,
                program: program.to_string(),
                name: region.name.clone(),
                kind: if region.permissions.contains('x') {
                    "code".into()
                } else {
                    "data".into()
                },
                file_id: String::new(),
                load_vaddr: region.start.clone(),
                size: region.size,
                file_off: 0,
                resident: true,
            },
        )?;
    }
    // A platform's own map: declared, byte-less, and named by the platform.
    regions.extend(imp.declared_regions.iter().map(|region| MemoryRegion {
        name: format!("{}:{}", imp.format.to_ascii_lowercase(), region.name),
        start: romwright_model::Address::ram(region.vaddr),
        size: region.size,
        permissions: mapping_permissions(region.flags),
        source: "native-import:platform-map".into(),
    }));
    db.replace_memory_regions(pid, &regions)?;
    let swept_strings = strings::discover(imp);
    db.replace_strings(
        pid,
        imp.string_tables
            .iter()
            .flat_map(|table| &table.strings)
            .chain(&swept_strings),
    )?;
    // Say what produced these rows. A loader-only import declares seeds that
    // nobody has walked; demand-driven analysis upgrades them one at a time.
    // And say *which pass* claimed each entry. One recall number over six
    // producers cannot tell you which of them is carrying it, or which one
    // to fix when it drops; the classes are derived here, in one place,
    // from the evidence each pass already recorded.
    let called: std::collections::HashSet<u64> = imp
        .xrefs
        .iter()
        .filter(|xref| xref.kind.contains("CALL"))
        .map(|xref| xref.to)
        .collect();
    let patterned: std::collections::HashSet<u64> = imp
        .pattern_labels
        .iter()
        .map(|(address, _)| *address)
        .chain(imp.pattern_starts.iter().copied())
        .collect();
    let thunked: std::collections::HashSet<u64> =
        imp.thunks.iter().map(|thunk| thunk.entry).collect();
    let pointed: std::collections::HashSet<u64> = imp
        .pointer_slots
        .iter()
        .chain(imp.initializer_slots.iter())
        .map(|(_, target)| *target)
        .collect();
    let declared: std::collections::HashSet<u64> = imp.symbol_named.iter().copied().collect();
    let consted: std::collections::HashSet<u64> = imp.const_data_starts.iter().copied().collect();
    // A const-seeded entry whose body swallows better-evidenced entries is
    // a mid-body label mistaken for a start (libc: one swallowed 37
    // symtab functions into a 7KB body). Two functions cannot share code
    // (m8-002); retract the const entry, keep what it covered. Only the
    // const class retracts: other producers' overlaps are pre-existing
    // behavior this rule must not relitigate. A const-seeded entry the
    // analysis itself reached as data is the same mistake from the other
    // side: a counter the propagation proved constant is not a callback
    // (N64 8008fa74: seeding it coined _FUN_ over the known DAT_ and the
    // decompiler rendered the overlap warning). Access wins over seeding.
    // A seed with no callers and no out-edges never participated in flow
    // as code -- measured and rejected 2026-09-11: the clause retracted
    // the real leaf restorer __restore_rt on libc (recall 1.0 -> 0.9997)
    // for a 3-entry cosmetic gain on one ROM. A taken address with no
    // edges is indistinguishable from a quiet leaf at store time.
    {
        // Pattern evidence is an accepted start, not a match: the console
        // labels every match of a labelled pattern, and those it refused
        // (offcuts inside a body decoded later) retracted the real
        // function around them (swkotor2 0x727010, over four refused
        // matches). A start the guard-clause merge absorbed is its
        // owner's code, not evidence either.
        let accepted_patterns: Vec<u64> = imp
            .pattern_starts
            .iter()
            .copied()
            .filter(|address| !imp.absorbed_starts.contains(address))
            .collect();
        let stronger: Vec<u64> = thunked
            .iter()
            .chain(declared.iter())
            .chain(accepted_patterns.iter())
            .chain(pointed.iter())
            .chain(called.iter())
            .copied()
            .collect();
        let accessed: std::collections::HashSet<u64> = imp
            .reference_widths
            .iter()
            .map(|(address, _)| *address)
            .collect();
        // A const seed that starts inside an instruction the walk decoded
        // is an operand, not code. On the Mac KOTOR II slice (full symbol
        // table) this retracts 1,578 unnamed const seeds and no named
        // function; a linear sweep puts 1,442 of them mid-instruction. Each
        // cut the function it sat in short at the next-entry boundary.
        let mut decoded: Vec<(u64, u64)> = imp
            .flow_shapes
            .iter()
            .map(|shape| (shape.address, shape.address + u64::from(shape.length)))
            .collect();
        decoded.sort_unstable();
        decoded.dedup();
        let mid_instruction = |entry: u64| {
            let index = decoded.partition_point(|&(start, _)| start < entry);
            index
                .checked_sub(1)
                .is_some_and(|i| decoded[i].0 < entry && entry < decoded[i].1)
        };
        // Inside a symbol's declared extent is inside that function, however
        // short its proven body: libc `printf_positional` declares 9,174
        // bytes and proves 2,316, and constant propagation seeded four of its
        // jump targets past that as 6-11 KB "functions".
        let inside_declared = |entry: u64| {
            let index = imp.symbol_extents.partition_point(|&(start, _)| start < entry);
            index
                .checked_sub(1)
                .is_some_and(|i| entry < imp.symbol_extents[i].1)
        };
        functions.retain(|f| {
            !(consted.contains(&f.entry)
                && (const_entry_swallowed(f.entry, f.size, &stronger)
                    || accessed.contains(&f.entry)
                    || mid_instruction(f.entry)
                    || (!declared.contains(&f.entry) && inside_declared(f.entry))))
        });
        // On an interworking ARM image whose data shares the executable
        // window, a direct call decoded from data names data too, and each
        // such "function" calls more of it. A function only a call claims is
        // kept when it opens like a function, or when something that does
        // calls it; trust flows along calls from there. On pokeemerald this
        // retracts 377 of 548 call-only functions in the data region and 3
        // real ones.
        if crate::native::low_bit_code_mode(&imp.language) && imp.language.starts_with("ARM") {
            let only_called = |entry: u64| {
                called.contains(&entry)
                    && !declared.contains(&entry)
                    && !patterned.contains(&entry)
                    && !pointed.contains(&entry)
                    && !consted.contains(&entry)
                    && !thunked.contains(&entry)
            };
            let anchored = |entry: u64| declared.contains(&entry) || pointed.contains(&entry);
            let retract = untrusted_call_chains(imp, &functions, only_called, anchored);
            functions.retain(|f| !retract.contains(&f.entry));
        }
    }
    let rows: Vec<FunctionRow> = functions
        .iter()
        .map(|f| FunctionRow {
            entry: romwright_model::Address::ram(f.entry),
            name: f.name.clone(),
            size: f.size.max(1),
            signature: None,
            traced: false,
            calling_convention: None,
        })
        .collect();
    db.replace_functions(pid, &rows)?;
    db.set_all_analysis_states(pid, if imp.analysed { "batch" } else { "seeded" })?;
    let producers: Vec<(String, String)> = rows
        .iter()
        .map(|row| {
            let entry = row.entry.offset;
            // Most specific evidence first: a linkage stub is a stub even
            // when something calls it, and a symbol is the image's own word.
            let producer = if thunked.contains(&entry) {
                "thunk"
            } else if declared.contains(&entry) {
                "symbol"
            } else if patterned.contains(&entry) {
                "pattern"
            } else if pointed.contains(&entry) {
                "pointer"
            } else if consted.contains(&entry) {
                "const"
            } else if called.contains(&entry) {
                "call"
            } else {
                "flow"
            };
            (row.entry.to_string(), producer.to_string())
        })
        .collect();
    db.set_producers(pid, &producers)?;
    // Structural measurements of each body, taken while it was decoded:
    // instruction and basic-block counts, intra-function edges, and digests
    // of the bytes and of the decoded shape. `romwright-diff` matches programs on
    // these; nothing else reads them, and nothing re-reads the image to get
    // them.
    // Features must reference stored functions: retracted const seeds stay
    // in `imp` (one function set feeds the rest of the pipeline) but their
    // rows never reach the table, so their measurements must not either.
    let stored: std::collections::HashSet<u64> = rows.iter().map(|row| row.entry.offset).collect();
    let mut measured = features::measure(imp);
    measured.retain(|feature| stored.contains(&feature.function.offset));
    db.replace_function_features(pid, &measured)?;
    // The frame each function's own stack accesses describe, so the worker
    // can hand the decompiler the same declared locals stock's does.
    db.replace_stack_variables(pid, &imp.stack_variables)?;
    // The instruction set at every point discovery settled: a mapping symbol,
    // a pattern's declared mode, a computed target's low bit, and each
    // entry's decoded mode. The last value written for an address wins, in
    // the order discovery settled them.
    // `TMode` (ARM) and `ISA_MODE` (MIPS) are the bit each language aliases
    // as `LowBitCodeMode` (ARM.sinc:90-93, mips.sinc:416-417); one name per
    // address keeps the last value written the one that applies.
    let mut contexts: Vec<(romwright_model::Address, String, u64)> = imp
        .contexts
        .iter()
        .map(|context| {
            let name = match context.name.as_str() {
                "TMode" | "ISA_MODE" => "LowBitCodeMode".to_string(),
                other => other.to_string(),
            };
            (
                romwright_model::Address::ram(context.address),
                name,
                context.value,
            )
        })
        .collect();
    // Store each function's entry value, not merely each range's first address.
    // The console takes the same facts directly from `register_contexts`.
    contexts.extend(
        sda_decode_points(&imp.register_contexts, &imp.functions)
            .into_iter()
            .map(|(address, name, value)| (romwright_model::Address::ram(address), name, value)),
    );
    db.replace_decode_contexts(pid, &contexts)?;
    // Refresh this loader's facts without discarding symbols from other owners.
    let mut symbols = db.symbols(pid)?;
    symbols.retain(|symbol| symbol.source != "native-import");
    symbols.retain(|symbol| symbol.source != DYNAMIC_LABEL_SOURCE);
    symbols.extend(
        imp.externals
            .iter()
            .filter(|(entry, _)| *entry != 0)
            .map(|(entry, name)| romwright_model::SymbolRow {
                name: name.clone(),
                address: romwright_model::Address::ram(*entry),
                external: true,
                source: "native-import".into(),
            }),
    );
    // An object a COPY relocation brings in *is* the named object: the
    // dynamic linker copies the library's definition into this slot, so the
    // slot carries that name (`R_*_COPY`; stock records the same symbol from
    // the same relocation).
    symbols.retain(|symbol| symbol.source != ELF_COPY_SOURCE);
    let copied: Vec<romwright_model::SymbolRow> = imp
        .named_relocations
        .iter()
        .filter(|relocation| relocation.copies && relocation.address != 0)
        .map(|relocation| romwright_model::SymbolRow {
            name: relocation.symbol.clone(),
            address: romwright_model::Address::ram(relocation.address),
            external: false,
            source: ELF_COPY_SOURCE.into(),
        })
        .collect();
    let already: std::collections::HashSet<u64> = symbols
        .iter()
        .filter(|symbol| symbol.address.space == romwright_model::AddressSpace::Ram)
        .map(|symbol| symbol.address.offset)
        .collect();
    symbols.extend(
        copied
            .into_iter()
            .filter(|row| !already.contains(&row.address.offset)),
    );
    // A name the image's own dynamic table proves. Ghidra applies it beside
    // whatever else names the address rather than instead of it: at a
    // `DT_INIT` target the pinned install holds both the function `_DT_INIT`
    // and the label `__DT_INIT` (measured on `powerpc_plain_o0`, `10010588`),
    // and at a `DT_PLTGOT` target that is also the first PLT slot it holds
    // only the label -- the import the slot resolves to lives in its EXTERNAL
    // block (`ElfProgramBuilder.markupDynamicTable`, :2691-2773).
    symbols.extend(
        imp.dynamic_labels
            .iter()
            .map(|(address, name)| romwright_model::SymbolRow {
                name: name.clone(),
                address: romwright_model::Address::ram(*address),
                external: false,
                source: DYNAMIC_LABEL_SOURCE.into(),
            }),
    );
    // A name an ELF symbol table gives an object: stock defines data under
    // that name (`ElfProgramBuilder.processSymbols`, :1703-1706), so the
    // name travels with the size -- sizes ride `ELF_OBJECT_SOURCE` data
    // definitions below, names ride the same source here, ranked just under
    // primary symbols so a function or dynamic label at the same address
    // keeps its spelling.
    symbols.retain(|symbol| symbol.source != ELF_OBJECT_SOURCE);
    symbols.extend(
        imp.object_names
            .iter()
            .filter(|(address, _)| *address != 0)
            .map(|(address, name)| romwright_model::SymbolRow {
                name: name.clone(),
                address: romwright_model::Address::ram(*address),
                external: false,
                source: ELF_OBJECT_SOURCE.into(),
            }),
    );
    // A mangled name also carries the name it was mangled from. Stock's
    // demangler applies that name as a *second* symbol at the same address,
    // with `SourceType.ANALYSIS`, and makes it primary
    // (`DemangledAddressTable.applyTo`, :74-90;
    // `DemangledObject.applyDemangledName`, :527-555) -- so the mangled name
    // stays as evidence and the derived name is what a decompiler prints.
    symbols.retain(|symbol| symbol.source != DEMANGLE_SOURCE);
    let derived: Vec<romwright_model::SymbolRow> = symbols
        .iter()
        .filter(|symbol| symbol.address.space == romwright_model::AddressSpace::Ram)
        .filter_map(|symbol| {
            let demangled = crate::demangle::demangle(&symbol.name)?;
            Some(romwright_model::SymbolRow {
                name: demangled.name,
                address: symbol.address.clone(),
                external: symbol.external,
                source: DEMANGLE_SOURCE.into(),
            })
        })
        .collect();
    symbols.extend(derived);
    db.replace_symbols(pid, &symbols)?;
    let xrows: Vec<XrefRow> = imp
        .xrefs
        .iter()
        .map(|x| XrefRow {
            from: romwright_model::Address::ram(x.from),
            to: romwright_model::Address::ram(x.to),
            kind: x.kind.clone(),
            // Containment resolves at query time from the function table.
            function: None,
            provenance: romwright_model::FactProvenance {
                kind: romwright_model::FactKind::Inferred,
                source: if x.provenance.is_empty() {
                    "native-import".into()
                } else {
                    x.provenance.clone()
                },
                confidence: None,
            },
        })
        .collect();
    db.replace_xrefs(pid, &xrows)?;
    db.replace_import_diagnostics(pid, &imp.diagnostics)?;
    // Cross-module references: an xref whose src and dst live in
    // different modules is a module_xrefs row.
    let module_rows = db.modules(pid)?;
    if module_rows.len() > 1 {
        let module_of = |address: u64| -> Option<&romwright_model::ModuleRow> {
            module_rows
                .iter()
                .find(|m| m.load_vaddr.offset <= address && address - m.load_vaddr.offset < m.size)
        };
        // One row per distinct reference: discovery rounds re-append the
        // same xref, and each copy used to become its own row.
        let mut seen: std::collections::HashSet<(u64, u64)> = std::collections::HashSet::new();
        let mut rows: Vec<romwright_model::ModuleXrefRow> = Vec::new();
        for x in &imp.xrefs {
            let (Some(from), Some(to)) = (module_of(x.from), module_of(x.to)) else {
                continue;
            };
            if from.module_id != to.module_id && seen.insert((x.from, x.to)) {
                rows.push(romwright_model::ModuleXrefRow {
                    module_id: from.module_id,
                    from_addr: romwright_model::Address::ram(x.from),
                    to_module_id: Some(to.module_id),
                    to_addr: romwright_model::Address::ram(x.to),
                    to_external: String::new(),
                    kind: "call".into(),
                });
            }
        }
        db.insert_module_xrefs(&rows)?;
    }
    // Each rule owns its rows: the ABI-reserved slot and a stub's own branch
    // are different evidence for the same kind of correction.
    for source in [PLT_HEADER_SOURCE, THUNK_SOURCE, SHARED_RETURN_SOURCE] {
        let overrides: Vec<romwright_model::FlowOverrideRow> = imp
            .flow_overrides
            .iter()
            .filter(|(_, rule)| *rule == source)
            .map(|(address, rule)| romwright_model::FlowOverrideRow {
                address: romwright_model::Address::ram(*address),
                kind: "callreturn".into(),
                provenance: romwright_model::FactProvenance {
                    kind: romwright_model::FactKind::Inferred,
                    source: (*rule).into(),
                    confidence: None,
                },
            })
            .collect();
        db.replace_inferred_flow_overrides(pid, source, &overrides)?;
    }
    let tagged: std::collections::HashSet<u64> = imp
        .dynamic_labels
        .iter()
        .map(|(address, _)| *address)
        .collect();
    // What the *image* declares a slot points at, which is the only thing that
    // justifies typing one more strongly than stock -- whose loader types
    // every word it marks up a plain pointer
    // (`ElfDefaultGotPltMarkup.createPointer`, :562-585). Two declarations
    // qualify: a linkage relocation for a function, and an initializer array,
    // which the ABI defines as an array of function pointers and whose entries
    // this loader has already confirmed decode as code. A word that merely
    // *happens* to hold a function's entry -- a `.got` word, a referenced word
    // (m4-027) -- is a coincidence, not a declaration, and keeps the plain
    // pointer both stores give it.
    let linkage_declared: std::collections::HashSet<u64> = imp
        .function_slots
        .iter()
        .map(|(address, _)| *address)
        .collect();
    let array_declared: std::collections::HashSet<u64> = imp
        .initializer_slots
        .iter()
        .map(|(address, _)| *address)
        .collect();
    let pointee = |address: u64| -> String {
        // An initializer array's entries are function pointers by definition,
        // including the first one, which `DT_INIT_ARRAY` also names. A linkage
        // slot the dynamic table names is different: `DT_PLTGOT` on PowerPC is
        // the ABI's reserved table head as well as the first jump slot, and
        // stock types that word a plain pointer (m4-029).
        let declared = array_declared.contains(&address)
            || (linkage_declared.contains(&address) && !tagged.contains(&address));
        if declared {
            "code-pointer".into()
        } else {
            "pointer".into()
        }
    };
    let definitions: Vec<romwright_model::DataDefinitionRow> = imp
        .plt_reserved_slots
        .iter()
        .filter(|(address, _)| {
            // A word the ABI reserves holds no code address -- unless a
            // relocation names a function for it, which makes it a linkage
            // slot whatever its position in the table.
            !imp.function_slots.iter().any(|(slot, _)| slot == address)
        })
        .map(|(address, width)| romwright_model::DataDefinitionRow {
            address: romwright_model::Address::ram(*address),
            data_type: pointee(*address),
            size: *width,
            provenance: romwright_model::FactProvenance {
                kind: romwright_model::FactKind::Inferred,
                source: PLT_RESERVED_SOURCE.into(),
                confidence: None,
            },
        })
        .collect();
    db.replace_inferred_data_definitions(pid, PLT_RESERVED_SOURCE, &definitions)?;
    // A linkage slot whose relocation names a function: the loader writes a
    // code address there, which is the only fact that justifies typing a slot
    // more strongly than stock, whose loader types every marked-up word a
    // plain pointer (`ElfDefaultGotPltMarkup.createPointer`, :562-585). A word
    // the dynamic table names is that table's own datum even when a linkage
    // relocation lands on it (m4-029), so it keeps the weaker type.
    let mut linkage: Vec<romwright_model::DataDefinitionRow> = imp
        .function_slots
        .iter()
        .filter(|(address, _)| !tagged.contains(address))
        .map(|(address, width)| romwright_model::DataDefinitionRow {
            address: romwright_model::Address::ram(*address),
            data_type: pointee(*address),
            size: *width,
            provenance: romwright_model::FactProvenance {
                kind: romwright_model::FactKind::Inferred,
                source: ELF_LINKAGE_SOURCE.into(),
                confidence: None,
            },
        })
        .collect();
    linkage.sort_by_key(|row| row.address.offset);
    linkage.dedup_by_key(|row| row.address.offset);
    db.replace_inferred_data_definitions(pid, ELF_LINKAGE_SOURCE, &linkage)?;
    // The size an ELF symbol declares for an object, applied as the undefined
    // data Ghidra applies: one `undefinedN` up to eight bytes, an array of
    // `undefined1` beyond that (`Undefined.getUndefinedDataType`, :47-55,
    // called from `allocateUndefinedSymbolData`, :1358-1381). An object wider
    // than a word is why stock prints `int::typeinfo` and not
    // `&int::typeinfo`: the '&' is dropped for an array
    // (`PrintC`, printc.cc:1082-1090).
    let mut objects: Vec<romwright_model::DataDefinitionRow> = imp
        .object_sizes
        .iter()
        .map(|(address, size)| romwright_model::DataDefinitionRow {
            address: romwright_model::Address::ram(*address),
            data_type: if *size > 8 {
                "undefined1[]".into()
            } else {
                "undefined".into()
            },
            size: *size,
            provenance: romwright_model::FactProvenance {
                kind: romwright_model::FactKind::Inferred,
                source: ELF_OBJECT_SOURCE.into(),
                confidence: None,
            },
        })
        .collect();
    objects.sort_by_key(|row| row.address.offset);
    objects.dedup_by_key(|row| row.address.offset);
    db.replace_inferred_data_definitions(pid, ELF_OBJECT_SOURCE, &objects)?;
    // A location another rule types keeps that type; this rule only says how
    // wide the access that reached it was.
    let mut widths: Vec<romwright_model::DataDefinitionRow> = imp
        .reference_widths
        .iter()
        .filter(|(address, _)| {
            !imp.plt_reserved_slots
                .iter()
                .any(|(slot, _)| slot == address)
                && !imp.pointer_slots.iter().any(|(slot, _)| slot == address)
                && !imp.got_slots.iter().any(|(slot, _)| slot == address)
                && !imp.object_sizes.iter().any(|(slot, _)| slot == address)
                && !imp.function_slots.iter().any(|(slot, _)| slot == address)
        })
        .map(|(address, width)| romwright_model::DataDefinitionRow {
            address: romwright_model::Address::ram(*address),
            data_type: "undefined".into(),
            size: *width,
            provenance: romwright_model::FactProvenance {
                kind: romwright_model::FactKind::Inferred,
                source: DATA_WIDTH_SOURCE.into(),
                confidence: None,
            },
        })
        .collect();
    widths.sort_by_key(|row| row.address.offset);
    widths.dedup_by_key(|row| row.address.offset);
    db.replace_inferred_data_definitions(pid, DATA_WIDTH_SOURCE, &widths)?;
    let mut slots: Vec<romwright_model::DataDefinitionRow> = imp
        .initializer_slots
        .iter()
        .map(|(address, width)| romwright_model::DataDefinitionRow {
            address: romwright_model::Address::ram(*address),
            data_type: pointee(*address),
            size: *width,
            provenance: romwright_model::FactProvenance {
                kind: romwright_model::FactKind::Inferred,
                source: ELF_POINTER_SOURCE.into(),
                confidence: None,
            },
        })
        .collect();
    slots.sort_by_key(|row| row.address.offset);
    slots.dedup_by_key(|row| row.address.offset);
    db.replace_inferred_data_definitions(pid, ELF_POINTER_SOURCE, &slots)?;
    let mut pointers: Vec<romwright_model::DataDefinitionRow> = imp
        .pointer_slots
        .iter()
        .map(|(address, width)| romwright_model::DataDefinitionRow {
            address: romwright_model::Address::ram(*address),
            data_type: pointee(*address),
            size: *width,
            provenance: romwright_model::FactProvenance {
                kind: romwright_model::FactKind::Inferred,
                source: DATA_POINTER_SOURCE.into(),
                confidence: None,
            },
        })
        .collect();
    pointers.sort_by_key(|row| row.address.offset);
    pointers.dedup_by_key(|row| row.address.offset);
    db.replace_inferred_data_definitions(pid, DATA_POINTER_SOURCE, &pointers)?;
    let mut got: Vec<romwright_model::DataDefinitionRow> = imp
        .got_slots
        .iter()
        .filter(|(address, _)| {
            // `.got` is walked at load time, before the pass that reads a
            // word and finds a function's entry in it (m4-027); that pass's
            // fact is the stronger one.
            !imp.pointer_slots.iter().any(|(slot, _)| slot == address)
                && !imp.function_slots.iter().any(|(slot, _)| slot == address)
        })
        .map(|(address, width)| romwright_model::DataDefinitionRow {
            address: romwright_model::Address::ram(*address),
            data_type: pointee(*address),
            size: *width,
            provenance: romwright_model::FactProvenance {
                kind: romwright_model::FactKind::Inferred,
                source: ELF_GOT_SOURCE.into(),
                confidence: None,
            },
        })
        .collect();
    got.sort_by_key(|row| row.address.offset);
    got.dedup_by_key(|row| row.address.offset);
    db.replace_inferred_data_definitions(pid, ELF_GOT_SOURCE, &got)?;
    // The rule owns its rows: re-importing an image the rule no longer covers
    // clears the fact, and an assertion over it is left alone.
    let conventions: Vec<romwright_model::CallingConventionRow> = imp
        .process_entry
        .zip(entry_model)
        .map(|(entry, model)| romwright_model::CallingConventionRow {
            function: romwright_model::Address::ram(entry),
            convention: model.to_string(),
            provenance: romwright_model::FactProvenance {
                kind: romwright_model::FactKind::Inferred,
                source: ENTRY_CONVENTION_SOURCE.into(),
                confidence: None,
            },
        })
        .into_iter()
        .collect();
    db.replace_inferred_calling_conventions(pid, ENTRY_CONVENTION_SOURCE, &conventions)?;
    // The image's own exception tables: a range and the handler it enters,
    // not a rendering. The worker turns them into the comment Ghidra's
    // analyzer writes (m4-024).
    let sites: Vec<romwright_model::ExceptionSiteRow> = imp
        .exception_sites
        .iter()
        .map(|site| romwright_model::ExceptionSiteRow {
            function: romwright_model::Address::ram(site.function),
            start: romwright_model::Address::ram(site.start),
            end: romwright_model::Address::ram(site.end),
            landing_pad: romwright_model::Address::ram(site.landing_pad),
            provenance: romwright_model::FactProvenance {
                kind: romwright_model::FactKind::Asserted,
                source: ELF_EXCEPTION_SOURCE.into(),
                confidence: None,
            },
        })
        .collect();
    db.replace_exception_sites(pid, ELF_EXCEPTION_SOURCE, &sites)?;
    apply_library_prototypes(db, pid, imp)?;
    // A name on Ghidra's own pinned list is a declared exit: without the fact
    // the decompiler walks past the call and takes the next function's body
    // with it.
    for function in &imp.functions {
        if crate::nonreturn::known_no_return(&imp.format, &function.name) {
            db.set_return_behavior(
                pid,
                &romwright_model::ReturnBehaviorRow {
                    function: romwright_model::Address::ram(function.entry),
                    no_return: true,
                    provenance: romwright_model::FactProvenance {
                        kind: romwright_model::FactKind::Inferred,
                        source: KNOWN_NAME_SOURCE.into(),
                        confidence: None,
                    },
                },
            )?;
        }
    }
    // Each rule owns its rows, so one pass never deletes another's facts.
    for source in [THUNK_SOURCE] {
        let thunks: Vec<romwright_model::ThunkRow> = imp
            .thunks
            .iter()
            .filter(|thunk| thunk.source == source)
            .map(|thunk| romwright_model::ThunkRow {
                function: romwright_model::Address::ram(thunk.entry),
                thunked: romwright_model::Address::ram(thunk.destination),
                kind: thunk.kind,
                provenance: romwright_model::FactProvenance {
                    kind: romwright_model::FactKind::Inferred,
                    source: source.into(),
                    confidence: None,
                },
            })
            .collect();
        db.replace_inferred_thunks(pid, source, &thunks)?;
    }
    // Itanium class facts come from the image's own relocations and data, so
    // the loader can publish them without a console or a worker.
    let recovery = crate::rtti::recover(imp);
    db.replace_inferred_classes(pid, recovery.source, &recovery.classes)?;
    Ok(ProgramSummary {
        program: program.to_string(),
        functions: functions.len() as u64,
        language: imp.language.clone(),
        compiler: imp.toolchain.clone().unwrap_or_default(),
        phases: imp.phases.clone(),
        flow: imp.flow,
        patterns: imp.patterns_seen.clone(),
        references_refused: imp.references_refused,
        diagnostics: imp.diagnostics.clone(),
        switch: Some(romwright_model::SwitchStats {
            vsa_resolved: imp.switch_vsa_resolved as u64,
            vsa_refused: imp.switch_vsa_refused as u64,
            decompiler_skipped: imp.switch_decompiler_skipped as u64,
        }),
    })
}

fn mapping_permissions(flags: u64) -> String {
    let (read, write, execute) = (flags & 0x2 != 0, flags & 0x1 != 0, flags & 0x4 != 0);
    format!(
        "{}{}{}",
        if read { "r" } else { "-" },
        if write { "w" } else { "-" },
        if execute { "x" } else { "-" }
    )
}

/// Types the imports the pinned C library archive declares.
///
/// The name has to come from the image: an external symbol, or a stub the
/// linkage pass named after the slot it reads. A name the archive omits, or one
/// whose declared types the decompiler does not have, stays untyped.
fn apply_library_prototypes(
    db: &ProjectDb,
    pid: romwright_model::ProgramId,
    imp: &NativeImport,
) -> Result<()> {
    let Some(table) = crate::library_types::load(&imp.cfg.library_prototypes) else {
        return Ok(());
    };
    let imports: std::collections::HashSet<&str> = imp
        .externals
        .iter()
        .map(|(_, name)| name.as_str())
        .collect();
    let named: Vec<(u64, &str)> = imp
        .functions
        .iter()
        .filter(|function| imports.contains(function.name.as_str()))
        .map(|function| (function.entry, function.name.as_str()))
        .collect();
    // What this language's own core-type document declares decides which
    // declarations can be applied: the parser resolves nothing else, and one
    // unresolvable name fails the whole decompile (m4-022).
    let Ok((_, specs, _, _)) =
        crate::native_runtime::language_decompile_config(&imp.cfg, &imp.language)
    else {
        return Ok(());
    };
    let Some(mut known_types) = crate::library_types::core_type_names(&specs) else {
        return Ok(());
    };
    // Plus the base types the compiler spec declares a width for: the
    // decompiler asks the worker for a name it does not hold, and the worker
    // answers from the same document (m4-025).
    known_types.extend(crate::library_types::language_base_types(&specs).into_keys());
    let applied = crate::library_types::declared_for(&table, named, &known_types);
    if applied.is_empty() {
        return Ok(());
    }
    let rows: Vec<romwright_model::PrototypeRow> = applied
        .iter()
        .map(
            |(address, signature, declaration)| romwright_model::PrototypeRow {
                function: romwright_model::Address::ram(*address),
                signature: signature.clone(),
                calling_convention: None,
                return_type: Some(declaration.return_type.clone()),
                provenance: romwright_model::FactProvenance {
                    kind: romwright_model::FactKind::Inferred,
                    source: crate::library_types::SOURCE.into(),
                    confidence: None,
                },
            },
        )
        .collect();
    let revision = db.revision(pid)?;
    db.merge_inferred_prototypes(pid, revision, &rows)?;
    Ok(())
}
