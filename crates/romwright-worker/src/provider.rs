//! Program-provider callbacks.
//!
//! While a command (e.g. `decompileAt`) runs, the pinned decompiler issues
//! *queries* on the same stdio pair (burst 0x04 … 0x05), and our answers
//! (0x08 … 0x09) are its only view of the program — this is exactly what
//! `ArchitectureGhidra` does on the Java side. Each callback mirrors one
//! query function from ghidra_arch.cc.
use crate::wire::{self, burst, encode_burst, encode_string_stream};
use crate::{NativeWorker, Result, WorkerError};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Shared loader-backed bytes, including load bias, relocations and BSS.
#[derive(Clone)]
pub struct BinaryBacking {
    image: Arc<romwright_core::session::ProgramImage>,
}

impl BinaryBacking {
    pub fn from_file(path: &Path, program: Option<&str>, raw_base: u64) -> Result<Self> {
        let image =
            romwright_core::session::ProgramImage::open_for_program(path, program, Some(raw_base))
                .map_err(|e| WorkerError::Setup(e.to_string()))?;
        Ok(Self {
            image: Arc::new(image),
        })
    }

    pub fn from_input(project: &Path, input: &romwright_model::ProgramInput) -> Result<Self> {
        let image = romwright_core::session::ProgramImage::open_input(project, input)
            .map_err(|error| WorkerError::Setup(error.to_string()))?;
        Ok(Self {
            image: Arc::new(image),
        })
    }

    /// One past the highest mapped address, zero for an empty image.
    pub fn image_end(&self) -> u64 {
        self.image
            .regions()
            .iter()
            .map(|region| region.vaddr.saturating_add(region.size))
            .max()
            .unwrap_or(0)
    }

    pub fn read(&self, vaddr: u64, size: u64) -> Option<Vec<u8>> {
        // DecompileCallback.getBytes returns a zero-initialized buffer after
        // a valid short read; an unmapped initial address is still an error.
        let region_at = |address| {
            self.image
                .regions()
                .iter()
                .find(|r| address >= r.vaddr && address - r.vaddr < r.size)
        };
        region_at(vaddr)?;
        let mut bytes = vec![0; usize::try_from(size).ok()?];
        let mut copied = 0usize;
        while copied < bytes.len() {
            let at = vaddr.checked_add(copied as u64)?;
            let Some(region) = region_at(at) else {
                break;
            };
            let available = usize::try_from(region.size - (at - region.vaddr)).ok()?;
            let count = available.min(bytes.len() - copied);
            self.image
                .read_into(at, &mut bytes[copied..copied + count])?;
            copied += count;
        }
        Some(bytes)
    }
}

/// A snapshot of program facts served to native callbacks. Missing facts stay
/// unknown; durable ownership remains in the project store.
pub struct ProgramProvider {
    pub backing: BinaryBacking,
    /// Function entry addresses, sorted.
    pub functions: Vec<u64>,
    /// Entry address -> name (from the store; used by getMappedSymbols).
    pub function_names: HashMap<u64, String>,
    /// Entry address -> byte size (from the store).
    pub function_sizes: HashMap<u64, u64>,
    /// Full-body signature identities bound to this immutable program input.
    pub verified_helpers: HashMap<u64, String>,
    /// Symbol names at arbitrary addresses, including imported labels.
    pub symbol_names: HashMap<u64, String>,
    /// Function-address to comments exported from the durable store.
    pub comments: HashMap<u64, Vec<(u64, String, String)>>,
    /// Data-type name to a human-readable definition.
    pub datatypes: HashMap<String, String>,
    /// External address/name pairs used by getExternalRef.
    pub external_names: HashMap<u64, String>,
    /// String data indexed by address for getStringData.
    pub strings: HashMap<u64, String>,
    /// Addresses a stored data reference names, with no other fact: the
    /// dynamic-label case Ghidra composes on demand rather than storing
    /// (`SymbolUtilities.getDynamicName`).
    pub data_targets: HashSet<u64>,
    /// Pointer slot -> the address its bytes hold. Ghidra names a pointer
    /// after its referent, so the label needs the target, not just the slot
    /// (`PointerDataType.getLabelString`, :192-238).
    pub pointer_targets: HashMap<u64, u64>,
    /// Addresses the image's own dynamic table names, and the name it gives
    /// them (`__DT_PLTGOT`, ...). Stock holds these as real symbols, so an
    /// address that has one is never given a composed label
    /// (`ElfProgramBuilder.markupDynamicTable`, :2691-2773).
    pub tag_names: HashMap<u64, String>,
    /// Address -> the namespace its symbol lives in, and the id this session
    /// gave that namespace. A symbol outside the global scope is printed
    /// scope-qualified (`PrintC::pushSymbolScope`, printc.cc:202-231), which
    /// is how `_ZTIi` prints as `int::typeinfo`.
    pub namespaces: HashMap<u64, (u64, String)>,
    /// Entry address -> stored prototype, including its assertion status.
    pub prototypes: HashMap<u64, romwright_model::PrototypeRow>,
    /// RAM entries with a stored non-returning fact.
    pub non_returning: HashSet<u64>,
    /// Declared stack locals per function entry: (name, offset, size,
    /// type name), the frame the store recovered or was told.
    pub stack_frames: HashMap<u64, Vec<(String, i64, u64, Option<String>)>>,
    /// RAM call edges ordered by source/destination offset.
    pub call_edges: Vec<(romwright_model::Address, romwright_model::Address)>,
    /// Track which space index `ram` occupies once the tspec registers it.
    pub ram_space_index: i64,
    /// Register space index from the tspec (x86-64: 4).
    pub register_space_index: i64,
    /// Mapped ranges the image marks unwritable, from the store's own map.
    pub read_only: Vec<(u64, u64)>,
    /// Locations the store types, address -> (type name, width).
    pub data_definitions: BTreeMap<u64, (String, u64)>,
    /// Function entry -> branch instructions the store proves transfer
    /// control the way a call does (a thunk's jump).
    pub call_return_branches: HashMap<u64, Vec<u64>>,
    /// Core type name -> (id, size) from the language's `coretypes.xml`.
    /// A type the language does not define is never referenced.
    pub core_types: HashMap<String, (u64, u64)>,
    /// C base types the language's compiler spec declares a width for. The
    /// decompiler's C parser asks the client for a type name it does not
    /// already hold (`TypeFactoryGhidra::findById`), and on a 32-bit language
    /// `long` is exactly such a name (m4-025).
    pub base_types: std::collections::BTreeMap<String, romwright_core::library_types::BaseType>,
    /// Pointer width in bytes, from the language's tspec.
    pub pointer_size: u64,
    /// Struct layouts the store holds and `ROMWRIGHT_STRUCTS` lets the
    /// decompiler see (`struct_types`), and whether they were checked against
    /// this language's types yet.
    pub structs: crate::struct_types::Layouts,
    pub structs_checked: bool,
    /// Executable address ranges, from the store's memory regions: an unnamed
    /// address in one of them is code, and Ghidra's label for code is `LAB_`
    /// (`SymbolUtilities.DEFAULT_SYMBOL_PREFIX`, :49-53).
    pub executable: Vec<(u64, u64)>,
    /// Register name -> (offset, size) from registers.txt (register space).
    pub registers: HashMap<String, (u64, u64)>,
    /// Function entry -> the model the store holds for it. Only models the
    /// loaded compiler spec declares reach the decompiler: an unrecognized
    /// name becomes a placeholder with no parameter storage at all
    /// (`Architecture::createUnknownModel`, fspec.cc:4695-4698).
    pub conventions: HashMap<u64, String>,
    /// Prototype model names the loaded cspec declares.
    pub declared_models: HashSet<String>,
    /// Call-fixup target name -> fixup name, from the loaded cspec. Ghidra's
    /// own installer builds the same map and sets the fixup on any function
    /// whose name is a target (`CallFixupAnalyzer.getTargetFixupMap`, :436-459).
    pub call_fixups: HashMap<String, String>,
    /// (Function entry, register name) -> the loader-established value that
    /// register holds there (`romwright_core::native::STORED_BASE_REGISTERS`):
    /// PowerPC EABI small-data-area bases (`_SDA_BASE_` in `r13`,
    /// `_SDA2_BASE_` in `r2` on 32-bit) and the MIPS/R5900 global pointer
    /// `gp` of non-PIC images. Discovery stores one point per function; the
    /// decompiler reads them through `getTrackedRegisters` the same way it
    /// reads MIPS `t9` (which needs no table: the value is the entry address
    /// by convention).
    pub tracked_values: HashMap<(u64, String), u64>,
    /// The dispatch tables the import stored, `(BRANCHIND address, targets)`
    /// sorted by branch, targets sorted and distinct. The decompiler is handed
    /// them as the authoritative address table of that branch, in every
    /// function whose flow reaches it (`ROMWRIGHT_STORED_SWITCHES`,
    /// `StoredSwitches`).
    pub stored_switches: Vec<(u64, Vec<u64>)>,
    /// What the decompiler does with `stored_switches`.
    pub stored_switch_mode: StoredSwitches,
}

/// What the decompiler does with the dispatch tables the import stored
/// (`ROMWRIGHT_STORED_SWITCHES=off|observe|apply`, default `apply`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum StoredSwitches {
    /// The decompiler recovers every table itself (`jumptable.cc` only).
    Off,
    /// The decompiler recovers the table itself and reports whether it agrees
    /// with the stored one; its own table stands.
    Observe,
    /// The stored table is the authority: `jumptable.cc` still runs for the
    /// normalization, guards and case values, and what it recovered is
    /// replaced when it differs from the stored table.
    #[default]
    Apply,
}

impl StoredSwitches {
    pub fn from_env() -> Result<Self> {
        match std::env::var("ROMWRIGHT_STORED_SWITCHES") {
            Ok(value) => match value.as_str() {
                "off" => Ok(Self::Off),
                "observe" => Ok(Self::Observe),
                "apply" => Ok(Self::Apply),
                other => Err(WorkerError::Setup(format!(
                    "ROMWRIGHT_STORED_SWITCHES={other}: expected off, observe or apply"
                ))),
            },
            Err(std::env::VarError::NotPresent) => Ok(Self::default()),
            Err(error) => Err(WorkerError::Setup(error.to_string())),
        }
    }
}

impl ProgramProvider {
    /// The values a processor's ABI puts in registers on entry to the
    /// function containing `address`, each with that register's storage.
    /// MIPS is the conventional case: `t9` holds the callee's own entry
    /// address. The stored cases are the PowerPC EABI `r13`/`r2`
    /// small-data-area bases and the MIPS `gp`, recorded at the containing entry.
    pub fn entry_registers(&self, address: u64) -> Vec<(u64, (u64, u64))> {
        let mut out = Vec::new();
        if let Some(storage) = self.registers.get("t9") {
            if storage.1 != 0 && storage.1 <= 8 {
                if let Some(entry) = self.function_containing(address) {
                    out.push((entry, *storage));
                }
            }
        }
        if let Some(entry) = self.function_containing(address) {
            for name in romwright_core::native::STORED_BASE_REGISTERS {
                if let (Some(&value), Some(&storage)) = (
                    self.tracked_values.get(&(entry, name.to_string())),
                    self.registers.get(name),
                ) {
                    if storage.1 != 0 && storage.1 <= 8 {
                        out.push((value, storage));
                    }
                }
            }
        }
        out
    }

    /// The entry of the function whose recorded extent holds `address`.
    pub fn function_containing(&self, address: u64) -> Option<u64> {
        let index = self.functions.partition_point(|entry| *entry <= address);
        let entry = *self.functions.get(index.checked_sub(1)?)?;
        let size = self.function_sizes.get(&entry).copied().unwrap_or(1).max(1);
        (address < entry.saturating_add(size)).then_some(entry)
    }

    pub fn new(backing: BinaryBacking, functions: Vec<u64>) -> Self {
        let mut functions = functions;
        functions.sort_unstable();
        Self {
            backing,
            functions,
            function_names: HashMap::new(),
            function_sizes: HashMap::new(),
            verified_helpers: HashMap::new(),
            symbol_names: HashMap::new(),
            comments: HashMap::new(),
            datatypes: HashMap::new(),
            external_names: HashMap::new(),
            strings: HashMap::new(),
            data_targets: HashSet::new(),
            pointer_targets: HashMap::new(),
            tag_names: HashMap::new(),
            namespaces: HashMap::new(),
            prototypes: HashMap::new(),
            non_returning: HashSet::new(),
            stack_frames: HashMap::new(),
            call_edges: Vec::new(),
            ram_space_index: 3,
            register_space_index: 4,
            read_only: Vec::new(),
            executable: Vec::new(),
            data_definitions: BTreeMap::new(),
            call_return_branches: HashMap::new(),
            stored_switches: Vec::new(),
            stored_switch_mode: StoredSwitches::default(),
            core_types: HashMap::new(),
            base_types: std::collections::BTreeMap::new(),
            pointer_size: 8,
            structs: crate::struct_types::Layouts::default(),
            structs_checked: false,
            registers: HashMap::new(),
            conventions: HashMap::new(),
            declared_models: HashSet::new(),
            call_fixups: HashMap::new(),
            tracked_values: HashMap::new(),
        }
    }

    /// Materializes the resolved image and one set of store facts for every
    /// native frontend; transport choices cannot change decompiler inputs.
    pub fn from_store(
        project: &std::path::Path,
        input: &romwright_model::ProgramInput,
        specs: &std::path::Path,
        db: &romwright_db::ProjectDb,
        pid: romwright_model::ProgramId,
        asserted_returns_only: bool,
    ) -> Result<Self> {
        let mut provider = Self::new(BinaryBacking::from_input(project, input)?, Vec::new());
        provider.load_language_info(specs)?;
        // Function entries from the project store.
        let stored_functions = db.functions(pid)?;
        let held = db.symbols(pid)?;
        // CodeWarrior-mangled names print as the name they encode
        // (`UberBond_Update`); the mangled name stays the function's linkage
        // name in the store. One pass names functions and data symbols so a
        // shared `Class::name` is disambiguated across both.
        let printed = {
            let mut seen = std::collections::HashSet::new();
            let names = stored_functions
                .iter()
                .map(|f| (f.entry.offset, f.name.as_str()))
                .chain(
                    held.iter()
                        .filter(|symbol| {
                            symbol.address.space == romwright_model::AddressSpace::Ram
                                && symbol.source != romwright_core::native::DEMANGLE_SOURCE
                                && symbol.source
                                    != romwright_core::qualified_prototypes::mangled::DISPLAY_SOURCE
                        })
                        .map(|symbol| (symbol.address.offset, symbol.name.as_str())),
                )
                .filter(|(offset, name)| seen.insert((*offset, *name)));
            romwright_core::qualified_prototypes::mangled::print_names(names)
        };
        for f in stored_functions {
            let off = f.entry.offset;
            provider.functions.push(off);
            provider.function_names.insert(
                off,
                printed
                    .get(&off)
                    .cloned()
                    .unwrap_or_else(|| crate::c_identifier(&f.name)),
            );
            provider.function_sizes.insert(off, f.size as u64);
        }
        // Stock applies a demangled name as the *primary* symbol at its address
        // (`DemangledAddressTable.applyTo`, :86, through
        // `DemangledObject.applyDemangledName`, :551-554), and the primary is the
        // name a decompiler prints. Which is why `_ZTIi` prints as `typeinfo`.
        let mut primary: std::collections::HashMap<u64, String> = held
            .iter()
            .filter(|symbol| symbol.source == romwright_core::native::DEMANGLE_SOURCE)
            .map(|symbol| (symbol.address.offset, crate::c_identifier(&symbol.name)))
            .collect();
        for (address, name) in &printed {
            primary.entry(*address).or_insert_with(|| name.clone());
        }
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
            if let Some(demangled) = romwright_core::demangle::demangle(&symbol.name) {
                if !demangled.namespace.is_empty() {
                    next_namespace += 1;
                    provider.namespaces.insert(
                        symbol.address.offset,
                        (next_namespace, crate::c_identifier(&demangled.namespace)),
                    );
                }
            }
        }
        for symbol in &held {
            if symbol.source == romwright_core::native::DYNAMIC_LABEL_SOURCE
                && symbol.address.space == romwright_model::AddressSpace::Ram
            {
                provider
                    .tag_names
                    .insert(symbol.address.offset, crate::c_identifier(&symbol.name));
            }
        }
        // Which name an address answers with, in the order stock's primary symbol
        // resolves: the demangled name first (it is applied primary,
        // `DemangledAddressTable.applyTo`, :86), then a name the image gives the
        // object, then the dynamic table's label -- which the pinned install keeps
        // non-primary wherever something else names the address (measured at
        // `_DT_INIT`) -- and last the import a linkage slot resolves to, which
        // stock keeps in its EXTERNAL block rather than at the slot.
        let rank = |symbol: &romwright_model::SymbolRow| match symbol.source.as_str() {
            _ if primary.contains_key(&symbol.address.offset) => 0,
            romwright_core::native::DYNAMIC_LABEL_SOURCE => 2,
            _ if symbol.external => 3,
            _ => 1,
        };
        let mut ordered: Vec<&romwright_model::SymbolRow> = held.iter().collect();
        ordered.sort_by_key(|symbol| rank(symbol));
        for symbol in ordered {
            let rendered = primary
                .get(&symbol.address.offset)
                .cloned()
                .unwrap_or_else(|| crate::c_identifier(&symbol.name));
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
        provider.structs = crate::struct_types::Layouts::load(
            db,
            pid,
            romwright_model::structs::StructMode::from_env(),
        )?;
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
            .filter(|string| string.address.space == romwright_model::AddressSpace::Ram)
        {
            provider.strings.insert(string.address.offset, string.value);
        }
        // Locations a stored data reference names and nothing else describes:
        // the dynamic-label case (`SymbolUtilities.getDynamicName`).
        // A thunk's jump transfers control the way a call does. The store proves
        // both halves: the thunk row names entry and destination, and the xref
        // row names the instruction that performs the transfer.
        for region in db.memory_regions(pid)? {
            if region.start.space == romwright_model::AddressSpace::Ram
                && !region.permissions.contains('w')
                && region.size > 0
            {
                provider
                    .read_only
                    .push((region.start.offset, region.start.offset + region.size));
            }
        }
        for region in db.memory_regions(pid)? {
            if region.start.space == romwright_model::AddressSpace::Ram
                && region.permissions.contains('x')
                && region.size > 0
            {
                provider
                    .executable
                    .push((region.start.offset, region.start.offset + region.size));
            }
        }
        let mut definitions = Vec::new();
        for row in db.data_definitions(pid)? {
            if row.address.space == romwright_model::AddressSpace::Ram && row.size > 0 {
                provider
                    .data_definitions
                    .insert(row.address.offset, (row.data_type.clone(), row.size));
                definitions.push((row.address.offset, row.data_type, row.size, row.provenance.source));
            }
        }
        // A stub's transfer is recorded as a flow override by the importer, which
        // is where the branch instruction is known; nothing is derived here.
        // Instruction flow the store corrects: each override belongs to the
        // function that contains it, which is how the decompiler keys them.
        for row in db.flow_overrides(pid)? {
            if row.address.space != romwright_model::AddressSpace::Ram || row.kind != "callreturn" {
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
            if target.space == romwright_model::AddressSpace::Ram {
                provider.data_targets.insert(target.offset);
            }
        }
        // A pointer's label names its referent, so a pointer-typed slot's target
        // has to travel with it. Which rule typed the slot does not matter: what
        // the label needs is the address the slot holds (m4-027).
        let mut address_taken = std::collections::BTreeSet::new();
        for xref in db.xrefs(pid)? {
            if xref.kind == "DATA" && xref.to.space == romwright_model::AddressSpace::Ram {
                address_taken.insert(xref.to.offset);
            }
            let pointer = matches!(
                provider.data_definitions.get(&xref.from.offset),
                Some((kind, _)) if kind == "pointer" || kind == "code-pointer"
            );
            if pointer
                && xref.kind == "DATA"
                && xref.from.space == romwright_model::AddressSpace::Ram
                && xref.to.space == romwright_model::AddressSpace::Ram
            {
                provider
                    .pointer_targets
                    .insert(xref.from.offset, xref.to.offset);
            }
        }
        provider.data_definitions = crate::layout::globals(
            definitions,
            |address| provider.strings.contains_key(&address) || provider.functions.binary_search(&address).is_ok(),
            |start, end| address_taken.range(start..end).next().is_some(),
        );
        provider.stored_switch_mode = StoredSwitches::from_env()?;
        // The dispatch tables the import recovered: a branch the switch stage
        // gave COMPUTED_JUMP edges to, and every COMPUTED_JUMP edge it has. An
        // edge another pass laid first (the console's constant propagation
        // resolving one slot) is the same (from, to, kind) fact and keeps that
        // pass's provenance, so the switch provenance alone misses its target.
        let xrefs = db.xrefs(pid)?;
        let computed = |xref: &romwright_model::XrefRow| {
            xref.kind == "COMPUTED_JUMP"
                && xref.from.space == romwright_model::AddressSpace::Ram
                && xref.to.space == romwright_model::AddressSpace::Ram
        };
        let switch_branches: std::collections::HashSet<u64> = xrefs
            .iter()
            .filter(|xref| {
                computed(xref) && xref.provenance.source == romwright_core::native::SWITCH_PROVENANCE
            })
            .map(|xref| xref.from.offset)
            .collect();
        let mut tables: std::collections::BTreeMap<u64, Vec<u64>> = Default::default();
        for xref in xrefs.iter().filter(|xref| computed(xref)) {
            if switch_branches.contains(&xref.from.offset) {
                tables.entry(xref.from.offset).or_default().push(xref.to.offset);
            }
        }
        for (branch, mut targets) in tables {
            targets.sort_unstable();
            targets.dedup();
            provider.stored_switches.push((branch, targets));
        }
        provider.load_call_edges(db, pid)?;
        provider.load_return_behaviors(db, pid, asserted_returns_only)?;
        provider.load_stack_frames(db, pid)?;
        provider.load_calling_conventions(db, pid)?;
        for row in db.signature_matches(pid)? {
            let address = row.function.offset;
            if row.function.space == romwright_model::AddressSpace::Ram
                && row.input.as_ref() == Some(input)
                && row.confidence == 1.0
                && provider.function_sizes.get(&address) == Some(&row.compared_bytes)
                && provider.function_names.get(&address) == Some(&row.name)
                && !provider.non_returning.contains(&address)
                && romwright_core::func_ir::helper_semantics(&row.name).is_some()
            {
                provider.verified_helpers.insert(address, row.name);
            }
        }
        Ok(provider)
    }

    pub fn load_call_edges(
        &mut self,
        db: &romwright_db::ProjectDb,
        program: romwright_model::ProgramId,
    ) -> Result<()> {
        self.call_edges = db.call_edges(program)?;
        self.call_edges.retain(|(from, to)| {
            from.space == romwright_model::AddressSpace::Ram
                && to.space == romwright_model::AddressSpace::Ram
        });
        Ok(())
    }

    /// The stack frame the store holds for each function, as the decompiler
    /// will be handed it: Ghidra's client sends every variable of the
    /// function's frame in `<localdb>` (`LocalSymbolMap.grabFromFunction`).
    pub fn load_stack_frames(
        &mut self,
        db: &romwright_db::ProjectDb,
        pid: romwright_model::ProgramId,
    ) -> Result<()> {
        let rows = db
            .stack_variables(pid, None)
            .map_err(|e| WorkerError::Setup(format!("stack variables: {e}")))?;
        for row in rows {
            let (Some(offset), Some(size)) = (row.offset, row.size) else {
                continue;
            };
            if size == 0 || size > 8 {
                continue;
            }
            self.stack_frames
                .entry(row.function.offset)
                .or_default()
                .push((row.name, offset, size, row.type_name));
        }
        Ok(())
    }

    /// The function's declared locals in wire form. A local is typed with
    /// the core type its row names when this language carries that type at
    /// the row's width (a debug stream's `int`); any other row is typed
    /// `undefined<size>`, and a width the language has no undefined type
    /// for is left out rather than mistyped.
    pub fn stack_locals(&self, entry: u64) -> Vec<(String, u64, u64, String, u64)> {
        let mask = if self.pointer_size >= 8 {
            u64::MAX
        } else {
            (1u64 << (self.pointer_size * 8)) - 1
        };
        self.stack_frames
            .get(&entry)
            .map(|frame| {
                frame
                    .iter()
                    .filter_map(|(name, offset, size, declared)| {
                        let named = declared
                            .as_deref()
                            .and_then(|n| self.core_types.get(n).map(|&(id, width)| (n, id, width)))
                            .filter(|&(_, _, width)| width == *size);
                        let (type_name, type_id) = match named {
                            Some((n, id, _)) => (n.to_string(), id),
                            None => {
                                let undefined = format!("undefined{size}");
                                let (id, _) = self.core_types.get(&undefined).copied()?;
                                (undefined, id)
                            }
                        };
                        Some((
                            name.clone(),
                            (*offset as u64) & mask,
                            *size,
                            type_name,
                            type_id,
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn load_return_behaviors(
        &mut self,
        db: &romwright_db::ProjectDb,
        program: romwright_model::ProgramId,
        asserted_only: bool,
    ) -> Result<()> {
        self.non_returning = db
            .return_behaviors(program)?
            .into_iter()
            .filter(|row| {
                !asserted_only || row.provenance.kind == romwright_model::FactKind::Asserted
            })
            .filter_map(|row| {
                (row.function.space == romwright_model::AddressSpace::Ram && row.no_return)
                    .then_some(row.function.offset)
            })
            .collect();
        Ok(())
    }

    /// Loads the convention facts, keeping only models the language declares
    /// -- the same silent skip Ghidra performs when a compiler spec has no
    /// such prototype (`ElfProgramBuilder.processEntryPoints`, :666-672).
    pub fn load_calling_conventions(
        &mut self,
        db: &romwright_db::ProjectDb,
        program: romwright_model::ProgramId,
    ) -> Result<()> {
        self.conventions = db
            .calling_conventions(program)?
            .into_iter()
            .filter(|row| row.function.space == romwright_model::AddressSpace::Ram)
            .filter(|row| self.declared_models.contains(&row.convention))
            .map(|row| (row.function.offset, row.convention))
            .collect();
        Ok(())
    }

    /// The model to send for a function, if the store holds one.
    pub fn convention(&self, vaddr: u64) -> Option<&str> {
        self.conventions.get(&vaddr).map(String::as_str)
    }

    /// The name Ghidra composes a pointer label from: the referent's symbol
    /// with its address suffix stripped
    /// (`PointerDataType.getLabelString` :229-231 calls
    /// `SymbolUtilities.getCleanSymbolName`, :950-972, which removes a
    /// trailing `_<address>` only when the whole name is exactly base plus
    /// that address). A default name therefore contributes its prefix -- a
    /// slot holding `FUN_00401570` is labelled `PTR_FUN_<slot>` -- and a real
    /// name contributes itself.
    pub fn pointer_referent(&self, vaddr: u64) -> Option<String> {
        let target = *self.pointer_targets.get(&vaddr)?;
        let name = self
            .function_names
            .get(&target)
            .or_else(|| self.symbol_names.get(&target))?;
        Some(clean_symbol_name(name, target))
    }

    /// The compiler spec's call fixup for a function, by name. Ghidra tries
    /// the name, then one and two leading underscores
    /// (`CallFixupAnalyzer.getCallFixupNameForFunction`, :200-222). Names are
    /// compared as C identifiers on both sides, since that is the form the
    /// store's names reach the decompiler in.
    pub fn call_fixup(&self, vaddr: u64) -> Option<&str> {
        let name = self.function_names.get(&vaddr)?;
        ["", "_", "__"]
            .iter()
            .find_map(|prefix| self.call_fixups.get(&format!("{prefix}{name}")))
            .map(String::as_str)
    }

    /// Preloads all known functions so stored callee signatures can be applied
    /// before the first caller is analyzed.
    pub fn function_shell(&self) -> Result<Vec<u8>> {
        let entries = self
            .functions
            .iter()
            .map(|offset| {
                let name = self.function_names.get(offset).ok_or_else(|| {
                    WorkerError::Setup(format!("function {offset:#x} has no stored name"))
                })?;
                let size = self.function_sizes.get(offset).ok_or_else(|| {
                    WorkerError::Setup(format!("function {offset:#x} has no stored extent"))
                })?;
                Ok((*offset, name.as_str(), *size))
            })
            .collect::<Result<Vec<_>>>()?;
        let fixups: HashMap<u64, String> = self
            .functions
            .iter()
            .filter_map(|offset| {
                self.call_fixup(*offset)
                    .map(|name| (*offset, name.to_string()))
            })
            .collect();
        Ok(NativeWorker::encode_function_shell_doc(
            self.ram_space_index as u32,
            &entries,
            &self.non_returning,
            &self.conventions,
            &fixups,
            &self.call_return_branches,
            &self.stored_switches_for_decompiler(),
            self.stored_switch_mode == StoredSwitches::Apply,
            |entry| self.stack_locals(entry),
        ))
    }

    /// The stored tables the decompiler is handed: none when the mode is off.
    pub fn stored_switches_for_decompiler(&self) -> Vec<(u64, Vec<u64>)> {
        if self.stored_switch_mode == StoredSwitches::Off {
            Vec::new()
        } else {
            self.stored_switches.clone()
        }
    }

    /// Name of the function at `vaddr`, if known.
    pub fn function_name(&self, vaddr: u64) -> Option<String> {
        self.function_names.get(&vaddr).cloned()
    }

    /// Loads registers.txt (name<TAB>offset<TAB>size), the ram/register space
    /// indices from the tspec, and the prototype models the cspec declares —
    /// the files `dump_specs` writes.
    pub fn load_language_info(&mut self, lang_dir: &Path) -> Result<()> {
        // The C base types this language declares a width for. Every path
        // that loads language facts needs them, not just the CLI: the
        // decompiler asks whichever provider is answering for a type name it
        // does not hold, and an unanswered `long` fails the whole decompile
        // (m4-025).
        self.base_types = romwright_core::library_types::language_base_types(lang_dir);
        let regs = std::fs::read_to_string(lang_dir.join("registers.txt"))
            .map_err(|e| WorkerError::Setup(format!("registers.txt: {e}")))?;
        for line in regs.lines() {
            let mut it = line.split('\t');
            if let (Some(name), Some(off), Some(sz)) = (it.next(), it.next(), it.next()) {
                if let (Ok(off), Ok(sz)) = (off.parse::<u64>(), sz.parse::<u64>()) {
                    self.registers.insert(name.to_string(), (off, sz));
                }
            }
        }
        let tspec = std::fs::read_to_string(lang_dir.join("tspec.xml"))
            .map_err(|e| WorkerError::Setup(format!("tspec.xml: {e}")))?;
        // The address space the decompiler reads through is the language's
        // *default* space, named in `<spaces defaultspace="...">`. Most
        // languages call it `ram`; the 6502 family calls it `RAM`, and a
        // hardcoded lowercase name made those tspecs unloadable.
        let ram_name = default_space_name(&tspec).unwrap_or_else(|| "ram".to_string());
        self.ram_space_index = find_space_index(&tspec, &ram_name)
            .ok_or_else(|| WorkerError::Setup("tspec has no ram space".into()))?;
        self.register_space_index = find_space_index(&tspec, "register")
            .ok_or_else(|| WorkerError::Setup("tspec has no register space".into()))?;
        // A pointer is as wide as the space it addresses: `<space name="ram"
        // size="4">` on a 32-bit language. Assuming eight made the decompiler
        // carve four bytes out of every typed slot it was handed.
        self.pointer_size = find_space_attribute(&tspec, &ram_name, "size")
            .and_then(|size| size.parse().ok())
            .ok_or_else(|| WorkerError::Setup("tspec ram space has no size".into()))?;
        // Which models exist at all. A convention the store holds but this
        // language never declared must not be sent: the decompiler answers an
        // unrecognized name with a placeholder model
        // (`createUnknownModel`, fspec.cc:4695-4698), which is worse than the
        // default it would otherwise use.
        let cspec = std::fs::read_to_string(lang_dir.join("cspec.xml"))
            .map_err(|e| WorkerError::Setup(format!("cspec.xml: {e}")))?;
        self.declared_models = prototype_models(&cspec);
        self.call_fixups = call_fixup_targets(&cspec);
        Ok(())
    }
}

/// Call-fixup targets a compiler spec declares, as a map from the target
/// name to the fixup's own name. A fixup carries one or more
/// `<target name="..."/>` children, and the decompiler compiles the `<pcode>`
/// body itself in this build (`PcodeInjectLibrarySleigh`), so only the name
/// has to travel. Target names are stored as C identifiers, the form a name
/// reaches the decompiler in (`__i686.get_pc_thunk.bx` cannot be printed).
pub(crate) fn call_fixup_targets(cspec: &str) -> HashMap<String, String> {
    let mut found = HashMap::new();
    let mut rest = cspec;
    while let Some(pos) = rest.find("<callfixup ") {
        let body = &rest[pos..];
        rest = &body[1..];
        let end = body.find("</callfixup>").unwrap_or(body.len());
        let element = &body[..end];
        let Some(header_end) = element.find('>') else {
            continue;
        };
        let Some(name) = tag_name(&element[..header_end]) else {
            continue;
        };
        let mut targets = &element[header_end..];
        while let Some(at) = targets.find("<target ") {
            let tag = &targets[at..];
            targets = &tag[1..];
            let Some(tag_end) = tag.find('>') else { break };
            if let Some(target) = tag_name(&tag[..tag_end]) {
                found.insert(crate::c_identifier(&target), name.clone());
            }
        }
    }
    found
}

/// The `name="..."` of one start tag.
fn tag_name(header: &str) -> Option<String> {
    let start = header.find("name=\"")? + 6;
    let value = &header[start..];
    value.find('"').map(|close| value[..close].to_string())
}

/// The names of `<prototype name="...">` elements a compiler spec declares.
/// A `<prototype>` inside `<callfixup>` or a comment does not exist here:
/// only start tags carrying a name, which is what `CompilerSpec` registers.
pub(crate) fn prototype_models(cspec: &str) -> HashSet<String> {
    let mut found = HashSet::new();
    let mut rest = cspec;
    while let Some(pos) = rest.find("<prototype ") {
        let tag = &rest[pos..];
        rest = &tag[1..];
        let Some(end) = tag.find('>') else { break };
        let header = &tag[..end];
        if let Some(name) = tag_name(header) {
            found.insert(name);
        }
    }
    found
}

/// Extracts one attribute from the `<space name="NAME"` start tag in a tspec.
fn find_space_attribute(tspec: &str, name: &str, attribute: &str) -> Option<String> {
    let mut rest = tspec;
    let needle = format!("{attribute}=\"");
    while let Some(pos) = rest.find("<space ") {
        let tag = &rest[pos..];
        let end = tag.find('>')?;
        let start_tag = &tag[..end];
        if start_tag.contains(&format!("name=\"{name}\"")) {
            if let Some(index) = start_tag.find(&needle) {
                let after = &start_tag[index + needle.len()..];
                return after.find('"').map(|j| after[..j].to_string());
            }
        }
        rest = &tag[end..];
    }
    None
}

/// The `defaultspace` attribute of the `<spaces>` element — the name of the
/// address space the decompiler treats as memory. `ram` on most languages,
/// `RAM` on the 6502 family.
fn default_space_name(tspec: &str) -> Option<String> {
    let pos = tspec.find("<spaces ")?;
    let tag = &tspec[pos..];
    let end = tag.find('>')?;
    let start_tag = &tag[..end];
    let i = start_tag.find("defaultspace=\"")?;
    let after = &start_tag[i + 14..];
    let j = after.find('"')?;
    Some(after[..j].to_string())
}

/// Extracts `index="N"` from the `<space name="NAME"` start tag in a tspec.
fn find_space_index(tspec: &str, name: &str) -> Option<i64> {
    let mut rest = tspec;
    while let Some(pos) = rest.find("<space ") {
        let tag = &rest[pos..];
        let end = tag.find('>')?;
        let start_tag = &tag[..end];
        let has_name = start_tag.contains(&format!("name=\"{name}\""));
        let has_index = start_tag.find("index=\"").and_then(|i| {
            let after = &start_tag[i + 7..];
            after.find('"').map(|j| after[..j].to_string())
        });
        if let (Some(i), true) = (has_index, has_name) {
            return i.parse().ok();
        }
        rest = &tag[end..];
    }
    None
}

impl NativeWorker {
    /// Drives one full command lifecycle, answering every query the
    /// decompiler interleaves. Returns the command's own response text.
    pub fn run_command(
        &mut self,
        provider: &mut ProgramProvider,
        command: &str,
        params: &[&[u8]],
    ) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        encode_burst(&mut buf, burst::COMMAND_OPEN);
        encode_string_stream(&mut buf, command.as_bytes());
        for p in params {
            encode_string_stream(&mut buf, p);
        }
        encode_burst(&mut buf, burst::COMMAND_CLOSE);
        self.write_frame(&buf)?;

        // The C++ writes the 0x06 header first (doit, ghidra_process.cc:138),
        // then interleaves program queries while rawAction runs, then the
        // result stream, the warnings frame, and the 0x07 closer. Queries
        // may arrive between 0x06 and the result, so stay in the loop.
        let mut in_response = false;
        loop {
            let code = self.next_burst()?;
            if code == burst::QUERY_OPEN {
                self.answer_query(provider)?;
                continue;
            }
            match code {
                burst::RESPONSE_OPEN => in_response = true,
                0x0e if in_response => {
                    let text = self.read_string_payload(provider)?;
                    // sendResult then writes the warnings frame (raw text
                    // between 0x10 and 0x11), and the caller the 0x07 closer
                    // (ghidra_process.cc:146-149, 489).
                    self.expect_burst(0x10)?;
                    let warnings = self.read_until(0x11)?;
                    self.expect_burst(burst::RESPONSE_CLOSE)?;
                    // `doit` catches a failed `ghidra->init()` and still
                    // sends an id (ghidra_process.cc:137-156, 187-200): the
                    // slot it names was never filled, and every later
                    // command fails with "No architecture registered".
                    // Registration's own error is the one to report.
                    if command == "registerProgram" {
                        let warnings = String::from_utf8_lossy(&warnings);
                        if let Some(error) = warnings.lines().find(|line| {
                            ["Low-level Error:", "Recoverable Error:", "Marshaling error:"]
                                .iter()
                                .any(|prefix| line.starts_with(prefix))
                        }) {
                            return Err(WorkerError::Decompiler(format!(
                                "registerProgram failed: {}",
                                error.trim()
                            )));
                        }
                    }
                    return Ok(text);
                }
                0x10 if in_response => {
                    // A diagnostic-only reply is not a packed document.
                    // Void commands may return an empty warnings frame.
                    let warnings = self.read_until(0x11)?;
                    self.expect_burst(burst::RESPONSE_CLOSE)?;
                    if warnings.is_empty() {
                        return Ok(Vec::new());
                    }
                    return Err(WorkerError::Decompiler(
                        String::from_utf8_lossy(&warnings).trim().to_owned(),
                    ));
                }
                burst::EXCEP_OPEN => {
                    let tp = self.read_string_stream()?;
                    let msg = self.read_string_stream()?;
                    let _ = self.expect_burst(burst::EXCEP_CLOSE)?;
                    return Err(WorkerError::Decompiler(format!(
                        "{}: {}",
                        String::from_utf8_lossy(&tp),
                        String::from_utf8_lossy(&msg)
                    )));
                }
                other => {
                    return Err(WorkerError::Protocol(format!(
                        "unexpected burst 0x{other:x} in command stream"
                    )));
                }
            }
        }
    }

    /// Dispatches one query by its packed root element id (the C++ writes
    /// the query as a packed command element; the id table is ghidra_arch
    /// .cc:30-48). Answers are 0x08..0x09 frames; an unanswered query hangs
    /// the decompiler, so unknown ids abort loudly.
    pub(crate) fn answer_query(&mut self, provider: &mut ProgramProvider) -> Result<()> {
        let payload = self.read_string_stream()?;
        let id = decode_root_element_id(&payload)
            .ok_or_else(|| WorkerError::Protocol("query payload has no element".into()))?;
        self.expect_burst(burst::QUERY_CLOSE)?;
        match id {
            wire::query::GETBYTES => self.answer_getbytes(provider, &payload),
            wire::query::GETMAPPEDSYMBOLS => self.answer_getmappedsymbols(provider, &payload),
            wire::query::GETREGISTER => self.answer_getregister(provider, &payload),
            wire::query::GETREGISTERNAME => self.answer_getregistername(provider, &payload),
            wire::query::GETCODELABEL => self.answer_code_label(provider, &payload),
            wire::query::GETSTRINGDATA => self.answer_string_data(provider, &payload),
            wire::query::GETCOMMENTS => self.answer_comments(provider, &payload),
            wire::query::GETDATATYPE => self.answer_datatype(provider, &payload),
            wire::query::GETEXTERNALREF => self.answer_external_ref(provider, &payload),
            wire::query::ISNAMEUSED => self.answer_name_used(provider, &payload),
            wire::query::GETNAMESPACEPATH => self.answer_namespace_path(provider, &payload),
            // These callbacks have no durable facts in the current model.
            // An empty response is the protocol's defined "unknown" value,
            // not a hang or a fabricated fallback.
            wire::query::GETCALLFIXUP
            | wire::query::GETCALLMECH
            | wire::query::GETCALLOTHERFIXUP
            | wire::query::GETCPOOLREF
            | wire::query::GETPCODE
            | wire::query::GETPCODEEXECUTABLE => self.answer_empty(),
            wire::query::GETUSEROPNAME => self.answer_str(""),
            crate::printc::query::QUERY_ID => self.answer_structure(&payload),
            wire::query::GETTRACKEDREGISTERS => self.answer_tracked_pointset(provider, &payload),
            other => {
                let msg = format!("romwright-worker: unsupported query id {other}");
                let mut buf = Vec::new();
                encode_burst(&mut buf, burst::EXCEP_OPEN);
                encode_string_stream(&mut buf, msg.as_bytes());
                encode_burst(&mut buf, burst::EXCEP_CLOSE);
                self.write_frame(&buf)?;
                Ok(())
            }
        }
    }

    /// The structuring query (native/romwright_structure.hh): `ghidra_opt`
    /// sends the control-flow graph it is decompiling and the worker's
    /// structurer answers which return-block edges are `goto`s.
    fn answer_structure(&mut self, payload: &[u8]) -> Result<()> {
        let answer = find_bytes_attribute(payload, 1)
            .ok_or_else(|| "structuring query has no content".to_string())
            .and_then(|content| crate::printc::query::answer(&content));
        let mut buf = Vec::new();
        match answer {
            Ok(bytes) => {
                encode_burst(&mut buf, burst::QRESPONSE_OPEN);
                encode_string_stream(&mut buf, &bytes);
                encode_burst(&mut buf, burst::QRESPONSE_CLOSE);
            }
            Err(message) => {
                encode_burst(&mut buf, burst::EXCEP_OPEN);
                encode_string_stream(&mut buf, format!("romwright-worker: {message}").as_bytes());
                encode_burst(&mut buf, burst::EXCEP_CLOSE);
            }
        }
        self.write_frame(&buf)?;
        Ok(())
    }

    /// getBytes (ghidra_arch.cc `ArchitectureGhidra::getBytes`): the query
    /// carries a packed `<addr>`; the answer is a byte stream with each
    /// byte encoded as two nibble chars biased by 'A', or an exception
    /// burst for unmapped memory.
    fn answer_getbytes(&mut self, provider: &mut ProgramProvider, payload: &[u8]) -> Result<()> {
        let (_space, vaddr, size) = decode_addr_element(payload)
            .ok_or_else(|| WorkerError::Protocol("bad packed <addr>".into()))?;

        let mut buf = Vec::new();
        match provider.backing.read(vaddr, size) {
            Some(bytes) => {
                encode_burst(&mut buf, burst::QRESPONSE_OPEN);
                encode_burst(&mut buf, burst::BYTESTREAM_OPEN);
                for byte in &bytes {
                    buf.extend_from_slice(&[(byte >> 4) + b'A', (byte & 0xf) + b'A']);
                }
                encode_burst(&mut buf, burst::BYTESTREAM_CLOSE);
                encode_burst(&mut buf, burst::QRESPONSE_CLOSE);
            }
            None => {
                encode_burst(&mut buf, burst::EXCEP_OPEN);
                // JavaError carries TWO string streams (type, message);
                // passJavaException writes both (ghidra_arch.cc:241-246).
                encode_string_stream(&mut buf, b"DataUnavailError");
                encode_string_stream(
                    &mut buf,
                    format!("GHIDRA has no data in the loadimage at {vaddr:#x}").as_bytes(),
                );
                encode_burst(&mut buf, burst::EXCEP_CLOSE);
            }
        }
        self.write_frame(&buf)?;
        Ok(())
    }

    /// Boolean query response (getIsNameUsed readBoolStream): a string
    /// stream with "t" or "f".
    fn answer_bool(&mut self, value: bool) -> Result<()> {
        let mut buf = Vec::new();
        encode_burst(&mut buf, burst::QRESPONSE_OPEN);
        encode_string_stream(&mut buf, if value { b"t" } else { b"f" });
        encode_burst(&mut buf, burst::QRESPONSE_CLOSE);
        self.write_frame(&buf)?;
        Ok(())
    }

    /// String query response (getCodeLabel, getUserOpName).
    fn answer_str(&mut self, value: &str) -> Result<()> {
        let mut buf = Vec::new();
        encode_burst(&mut buf, burst::QRESPONSE_OPEN);
        encode_string_stream(&mut buf, value.as_bytes());
        encode_burst(&mut buf, burst::QRESPONSE_CLOSE);
        self.write_frame(&buf)?;
        Ok(())
    }

    /// `<tracked_pointset>` for getTrackedRegisters: the register values that
    /// hold at an address.
    ///
    /// MIPS calling code leaves a function's own address in `t9`, and every
    /// position-independent load inside the function is written relative to
    /// it. Ghidra tracks that: `MipsAddressAnalyzer` ships with "Assume T9 set
    /// to Function entry" on and writes `t9 = entry` into the program context
    /// (`unknownValue`, 462-504), which is what its decompiler then reads
    /// through `getTrackedRegisters`. Without the value a `lw` through `t9`
    /// decompiles as `in_t9 + offset` instead of the pointer it is.
    fn answer_tracked_pointset(
        &mut self,
        provider: &mut ProgramProvider,
        payload: &[u8],
    ) -> Result<()> {
        let mut el = Vec::new();
        wire::encode_header(&mut el, wire::ELEMENT_START, wire::elem::TRACKED_POINTSET);
        if let Some((space, offset, _)) = decode_addr_element(payload) {
            if space == provider.ram_space_index {
                for (register, (reg_offset, reg_size)) in provider.entry_registers(offset) {
                    wire::encode_header(&mut el, wire::ELEMENT_START, wire::elem::SET);
                    wire::encode_attribute(
                        &mut el,
                        wire::attr::SPACE,
                        wire::attr_type::SPACE,
                        provider.register_space_index as u64,
                    );
                    wire::encode_attribute(
                        &mut el,
                        wire::attr::OFFSET,
                        wire::attr_type::UNSIGNED_INT,
                        reg_offset,
                    );
                    wire::encode_attribute(
                        &mut el,
                        wire::attr::SIZE,
                        wire::attr_type::POSITIVE_INT,
                        reg_size,
                    );
                    wire::encode_attribute(
                        &mut el,
                        wire::attr::TRACKED_VALUE,
                        wire::attr_type::UNSIGNED_INT,
                        register,
                    );
                    wire::encode_header(&mut el, wire::ELEMENT_END, wire::elem::SET);
                }
            }
        }
        wire::encode_header(&mut el, wire::ELEMENT_END, wire::elem::TRACKED_POINTSET);
        let mut buf = Vec::new();
        encode_burst(&mut buf, burst::QRESPONSE_OPEN);
        encode_string_stream(&mut buf, &el);
        encode_burst(&mut buf, burst::QRESPONSE_CLOSE);
        self.write_frame(&buf)?;
        Ok(())
    }

    /// Empty query response: open immediately closed. The query payload
    /// was already consumed by answer_query, so no drain is needed.
    fn answer_empty(&mut self) -> Result<()> {
        let mut buf = Vec::new();
        encode_burst(&mut buf, burst::QRESPONSE_OPEN);
        encode_burst(&mut buf, burst::QRESPONSE_CLOSE);
        self.write_frame(&buf)?;
        Ok(())
    }

    /// Resolves labels from durable symbols and function names.
    /// getCodeLabel (`DecompileCallback.getCodeLabel`, :429-441) answers the
    /// primary symbol at a branch target. Ghidra's flow analysis leaves a
    /// reference on every branch target, so an instruction inside a
    /// function body with no real symbol carries the dynamic label
    /// `SymbolUtilities.getDynamicInstructionName` builds: `LAB_` and the
    /// address (:584-607). A function entry keeps its own name.
    fn answer_code_label(&mut self, provider: &mut ProgramProvider, payload: &[u8]) -> Result<()> {
        let (_, address, _) = decode_addr_element(payload)
            .ok_or_else(|| WorkerError::Protocol("bad getCodeLabel address".into()))?;
        let dynamic;
        let name = match provider
            .symbol_names
            .get(&address)
            .or_else(|| provider.function_names.get(&address))
        {
            Some(name) => name.as_str(),
            None if provider.function_containing(address).is_some() => {
                dynamic = format!("LAB_{address:08x}");
                dynamic.as_str()
            }
            None => "",
        };
        self.answer_str(name)
    }

    /// Answers `isNameUsed` from all durable function and symbol names.
    /// getNamespacePath (`ArchitectureGhidra::getNamespacePath`,
    /// ghidra_arch.cc:608-622): the query carries a namespace id and the
    /// answer is the path from the root scope down to it. An id this session
    /// did not hand out gets the bare root, which is what a client that keeps
    /// every symbol global answers.
    fn answer_namespace_path(
        &mut self,
        provider: &mut ProgramProvider,
        payload: &[u8],
    ) -> Result<()> {
        let wanted =
            u64::try_from(find_numeric_attribute(payload, wire::attr::ID).unwrap_or_default())
                .unwrap_or(0);
        let components: Vec<(u64, String)> = provider
            .namespaces
            .values()
            .find(|(id, _)| *id == wanted)
            .map(|(id, name)| vec![(*id, name.clone())])
            .unwrap_or_default();
        let mut doc = Vec::new();
        wire::encode_namespace_path(&mut doc, &components);
        let mut buf = Vec::new();
        encode_burst(&mut buf, burst::QRESPONSE_OPEN);
        encode_string_stream(&mut buf, &doc);
        encode_burst(&mut buf, burst::QRESPONSE_CLOSE);
        self.write_frame(&buf)
    }

    /// isNameUsed (`ArchitectureGhidra::isNameUsed`, ghidra_arch.cc:624-645):
    /// the query names a symbol and the two ends of a namespace path, and the
    /// answer says whether a symbol of that name lives anywhere along it.
    /// Ghidra skips symbols in the global scope outright -- "common case we
    /// know can't match anything in path" (`DecompileCallback.isNameUsed`,
    /// :491-533) -- so a global name never makes a namespace refuse a symbol.
    /// Answering otherwise loses the symbol: `ScopeGhidraNamespace::isNameUsed`
    /// (database_ghidra.cc:373-381) asks this before every insertion.
    fn answer_name_used(&mut self, provider: &mut ProgramProvider, payload: &[u8]) -> Result<()> {
        let name = find_name_attribute(payload).unwrap_or_default();
        let start =
            u64::try_from(find_numeric_attribute(payload, wire::attr::FIRST).unwrap_or_default())
                .unwrap_or(0);
        // Every namespace this session hands out is a child of the global
        // scope, so the path from one is that namespace alone.
        let used = start != 0
            && provider.namespaces.iter().any(|(address, (id, _))| {
                *id == start && provider.symbol_names.get(address) == Some(&name)
            });
        self.answer_bool(used)
    }

    /// Returns UTF-8 string bytes using the exact A-biased byte-stream shape
    /// consumed by ArchitectureGhidra::getStringData.
    fn answer_string_data(&mut self, provider: &mut ProgramProvider, payload: &[u8]) -> Result<()> {
        let (space, address, _) = decode_addr_element(payload)
            .ok_or_else(|| WorkerError::Protocol("bad getStringData address".into()))?;
        let max_chars = find_numeric_attribute(payload, wire::attr::MAXSIZE)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or_else(|| WorkerError::Protocol("bad getStringData character limit".into()))?;
        let value = if space == provider.ram_space_index {
            provider.strings.get(&address).map(String::as_str)
        } else {
            None
        };
        let mut buf = Vec::new();
        wire::encode_string_data_response(&mut buf, value, max_chars);
        self.write_frame(&buf)
    }

    /// Encodes store comments in the packed `<commentdb>` form consumed by
    /// CommentDatabaseInternal::decode.
    fn answer_comments(&mut self, provider: &mut ProgramProvider, payload: &[u8]) -> Result<()> {
        let (_, function, _) = decode_addr_element(payload)
            .ok_or_else(|| WorkerError::Protocol("bad getComments address".into()))?;
        let mut doc = Vec::new();
        wire::encode_header(&mut doc, wire::ELEMENT_START, wire::elem::COMMENTDB);
        for (address, kind, text) in provider.comments.get(&function).into_iter().flatten() {
            wire::encode_header(&mut doc, wire::ELEMENT_START, wire::elem::COMMENT);
            wire::encode_string_attribute(
                &mut doc,
                wire::attr::TYPE,
                comment_type_name(kind).as_bytes(),
            );
            wire::encode_addr_element(&mut doc, provider.ram_space_index as u32, function);
            wire::encode_addr_element(&mut doc, provider.ram_space_index as u32, *address);
            wire::encode_header(&mut doc, wire::ELEMENT_START, wire::elem::TEXT);
            wire::encode_string_attribute(&mut doc, wire::attr::CONTENT, text.as_bytes());
            wire::encode_header(&mut doc, wire::ELEMENT_END, wire::elem::TEXT);
            wire::encode_header(&mut doc, wire::ELEMENT_END, wire::elem::COMMENT);
        }
        wire::encode_header(&mut doc, wire::ELEMENT_END, wire::elem::COMMENTDB);
        let mut buf = Vec::new();
        encode_burst(&mut buf, burst::QRESPONSE_OPEN);
        encode_string_stream(&mut buf, &doc);
        encode_burst(&mut buf, burst::QRESPONSE_CLOSE);
        self.write_frame(&buf)
    }

    /// Encodes a conservative basic datatype response. The durable type
    /// definition is intentionally retained as store text; the decompiler
    /// needs the name/size/metatype wire fields to continue safely.
    fn answer_datatype(&mut self, provider: &mut ProgramProvider, payload: &[u8]) -> Result<()> {
        let name = find_name_attribute(payload).unwrap_or_default();
        let mut buf = Vec::new();
        encode_burst(&mut buf, burst::QRESPONSE_OPEN);
        // A base type the language declares a width for. The id is left out
        // on purpose: `Datatype::decodeBasic` derives `hashName(name)` when
        // none is given (`type.cc`:698-700), which is the same id the
        // decompiler would have used for a type of its own.
        if let Some(base) = provider
            .base_types
            .get(&name)
            .filter(|_| !provider.core_types.contains_key(&name))
        {
            let mut doc = Vec::new();
            wire::encode_header(&mut doc, wire::ELEMENT_START, wire::elem::TYPE);
            wire::encode_string_attribute(&mut doc, wire::attr::NAME, name.as_bytes());
            wire::encode_attribute(
                &mut doc,
                wire::attr::SIZE,
                wire::attr_type::POSITIVE_INT,
                u64::from(base.size),
            );
            wire::encode_string_attribute(&mut doc, wire::attr::METATYPE, base.metatype.as_bytes());
            wire::encode_header(&mut doc, wire::ELEMENT_END, wire::elem::TYPE);
            encode_string_stream(&mut buf, &doc);
            encode_burst(&mut buf, burst::QRESPONSE_CLOSE);
            return self.write_frame(&buf);
        }
        if let Some(doc) = provider.struct_datatype(&name) {
            encode_string_stream(&mut buf, &doc);
            encode_burst(&mut buf, burst::QRESPONSE_CLOSE);
            return self.write_frame(&buf);
        }
        if provider.datatypes.contains_key(&name) {
            let mut doc = Vec::new();
            wire::encode_header(&mut doc, wire::ELEMENT_START, wire::elem::TYPE);
            wire::encode_string_attribute(&mut doc, wire::attr::NAME, name.as_bytes());
            wire::encode_attribute(&mut doc, wire::attr::ID, wire::attr_type::UNSIGNED_INT, 1);
            wire::encode_attribute(&mut doc, wire::attr::SIZE, wire::attr_type::POSITIVE_INT, 1);
            wire::encode_string_attribute(
                &mut doc,
                wire::attr::METATYPE,
                datatype_metatype(
                    provider
                        .datatypes
                        .get(&name)
                        .map(String::as_str)
                        .unwrap_or(""),
                )
                .as_bytes(),
            );
            wire::encode_header(&mut doc, wire::ELEMENT_END, wire::elem::TYPE);
            encode_string_stream(&mut buf, &doc);
        }
        encode_burst(&mut buf, burst::QRESPONSE_CLOSE);
        self.write_frame(&buf)
    }

    /// Resolves imported addresses to an external-reference symbol.
    fn answer_external_ref(
        &mut self,
        provider: &mut ProgramProvider,
        payload: &[u8],
    ) -> Result<()> {
        let (_, address, _) = decode_addr_element(payload)
            .ok_or_else(|| WorkerError::Protocol("bad getExternalRef address".into()))?;
        let mut buf = Vec::new();
        encode_burst(&mut buf, burst::QRESPONSE_OPEN);
        if let Some(name) = provider.external_names.get(&address) {
            let mut doc = Vec::new();
            wire::encode_header(&mut doc, wire::ELEMENT_START, wire::elem::EXTERNREFSYMBOL);
            wire::encode_string_attribute(&mut doc, wire::attr::NAME, name.as_bytes());
            wire::encode_addr_element(&mut doc, provider.ram_space_index as u32, address);
            wire::encode_header(&mut doc, wire::ELEMENT_END, wire::elem::EXTERNREFSYMBOL);
            encode_string_stream(&mut buf, &doc);
        }
        encode_burst(&mut buf, burst::QRESPONSE_CLOSE);
        self.write_frame(&buf)
    }

    fn answer_getmappedsymbols(
        &mut self,
        provider: &mut ProgramProvider,
        payload: &[u8],
    ) -> Result<()> {
        let (space, vaddr, _size) = decode_addr_element(payload)
            .ok_or_else(|| WorkerError::Protocol("bad packed <addr>".into()))?;
        let mut buf = Vec::new();
        encode_burst(&mut buf, burst::QRESPONSE_OPEN);
        if space == provider.ram_space_index {
            if let Ok(index) = provider.functions.binary_search(&vaddr) {
                let name = provider
                    .function_name(vaddr)
                    .unwrap_or_else(|| format!("FUN_{vaddr:x}"));
                let size = provider.function_sizes.get(&vaddr).copied().unwrap_or(8);
                let mut doc = Vec::new();
                wire::encode_header(&mut doc, wire::ELEMENT_START, wire::elem::DOC);
                wire::encode_attribute(&mut doc, wire::attr::ID, wire::attr_type::UNSIGNED_INT, 0);
                wire::encode_header(&mut doc, wire::ELEMENT_START, wire::elem::MAPSYM);
                let branches = provider
                    .call_return_branches
                    .get(&vaddr)
                    .cloned()
                    .unwrap_or_default();
                let owned = provider.stack_locals(vaddr);
                let locals: Vec<wire::StackLocal> = owned
                    .iter()
                    .map(
                        |(name, offset, size, type_name, type_id)| wire::StackLocal {
                            name,
                            offset: *offset,
                            size: *size,
                            type_name,
                            type_id: *type_id,
                        },
                    )
                    .collect();
                wire::encode_function_element(
                    &mut doc,
                    space as u32,
                    index as u64 + 1,
                    vaddr,
                    &name,
                    size,
                    provider.non_returning.contains(&vaddr),
                    provider.convention(vaddr),
                    provider.call_fixup(vaddr),
                    &branches,
                    &locals,
                );
                wire::encode_addr_element_size(&mut doc, space as u32, vaddr, size);
                wire::encode_header(&mut doc, wire::ELEMENT_START, wire::elem::RANGELIST);
                wire::encode_header(&mut doc, wire::ELEMENT_END, wire::elem::RANGELIST);
                wire::encode_header(&mut doc, wire::ELEMENT_END, wire::elem::MAPSYM);
                wire::encode_header(&mut doc, wire::ELEMENT_END, wire::elem::DOC);
                encode_string_stream(&mut buf, &doc);
            } else {
                // Not a function: the store may still hold a fact about this
                // location, and Ghidra composes the label for it on demand
                // (`DecompileCallback.encodeData`, DecompileCallback.java:835-855)
                // rather than storing one.
                // A cold query can first touch an interior field. Return its
                // containing data object, not an unrelated address-named word.
                let vaddr = provider.data_definitions.range(..=vaddr).next_back()
                    .filter(|(start, (_, size))| vaddr - **start < *size)
                    .map_or(vaddr, |(start, _)| *start);
                let mut doc = Vec::new();
                let core = |name: &str| provider.core_types.get(name).copied();
                // Every mapped-symbol answer carries the namespace of the
                // symbol it describes (`DecompileCallback.encodeData`, :852,
                // and `encodeLabel`, :874), and a symbol outside the global
                // scope prints scope-qualified.
                let namespace = provider
                    .namespaces
                    .get(&vaddr)
                    .map(|(id, _)| *id)
                    .unwrap_or(0);
                let read_only = provider
                    .read_only
                    .iter()
                    .any(|(start, end)| *start <= vaddr && vaddr < *end);
                if let (Some(text), Some((char_id, _))) =
                    (provider.strings.get(&vaddr), core("char"))
                {
                    // A string is `char[len + 1]`: the stored value excludes
                    // the terminator the image carries.
                    let count = text.len() as u64 + 1;
                    let name = string_label(text, vaddr);
                    open_document_in(&mut doc, namespace);
                    wire::encode_data_symbol(
                        &mut doc,
                        space as u32,
                        vaddr,
                        &name,
                        read_only,
                        |out| wire::encode_array_type(out, ("char", char_id), 1, count),
                    );
                    close_document(&mut doc);
                } else if let (true, Some((code_id, _))) = (
                    provider.external_names.contains_key(&vaddr)
                        || matches!(
                            provider.data_definitions.get(&vaddr),
                            Some((kind, _)) if kind == "pointer" || kind == "code-pointer"
                        ),
                    core("code"),
                ) {
                    // A slot holding a code pointer. Ghidra's label is
                    // `PTR_<target name>_<address>` when the target has a
                    // name and `PTR_<address>` when it does not
                    // (`PointerDataType.getLabelString`, :212-238, and
                    // `getDynamicDataName`, SymbolUtilities.java:541-544).
                    // A label is composed only where stock has no symbol; the
                    // dynamic table's own name is a symbol, so it is sent as
                    // it stands. On PowerPC `DT_PLTGOT` is the first PLT slot,
                    // which is why stock prints `__DT_PLTGOT` there and not
                    // the import the slot resolves to.
                    let name = match provider.tag_names.get(&vaddr) {
                        Some(tag) => tag.clone(),
                        None => match provider.external_names.get(&vaddr) {
                            Some(target) => format!("PTR_{target}_{vaddr:08x}"),
                            None => match provider.pointer_referent(vaddr) {
                                Some(referent) => format!("PTR_{referent}_{vaddr:08x}"),
                                None => format!("PTR_{vaddr:08x}"),
                            },
                        },
                    };
                    let size = provider
                        .data_definitions
                        .get(&vaddr)
                        .map(|(_, width)| *width)
                        .unwrap_or(provider.pointer_size);
                    // What the slot points at, as the store holds it: a
                    // linkage slot resolves to code, but the word the dynamic
                    // table names is the ABI's own reserved datum -- stock
                    // types it a plain pointer (`dataAt=pointer` at
                    // `1003074c` on `powerpc_plain_o0`), which is why its call
                    // through it carries a `(code *)` cast.
                    // What the slot points at, as the store proves it: only a
                    // slot the image declares holds a function address is
                    // typed `code *`. Everything else is a plain pointer,
                    // which is the type stock gives every word it marks up
                    // (`ElfDefaultGotPltMarkup.createPointer`, :562-585).
                    let proven_code = matches!(
                        provider.data_definitions.get(&vaddr),
                        Some((kind, _)) if kind == "code-pointer"
                    );

                    open_document_in(&mut doc, namespace);
                    wire::encode_data_symbol(
                        &mut doc,
                        space as u32,
                        vaddr,
                        &name,
                        read_only,
                        |out| {
                            if proven_code {
                                wire::encode_pointer_type(out, ("code", code_id), size)
                            } else {
                                // Stock's plain pointer points at the type the
                                // decompiler registers for itself, which is
                                // what makes its text read `undefined *`.
                                wire::encode_pointer_to(out, size, |out| {
                                    wire::encode_basic_type(out, "undefined", "unknown", 1)
                                })
                            }
                        },
                    );
                    close_document(&mut doc);
                } else if let Some((width, count, (element, element_id))) = provider
                    .data_definitions
                    .get(&vaddr)
                    .and_then(|(kind, size)| {
                        let width = crate::layout::element_width(kind)?;
                        let name = format!("undefined{width}");
                        Some((width, size / width, (name.clone(), core(&name)?.0)))
                    })
                {
                    // An object wider than a word: Ghidra applies the size the
                    // ELF symbol declares as an array of `undefined1`
                    // (`Undefined.getUndefinedDataType`, :51-53), and the C
                    // printer drops the '&' in front of an array
                    // (printc.cc:1082-1090).
                    let name = provider
                        .symbol_names
                        .get(&vaddr)
                        .cloned()
                        .unwrap_or_else(|| format!("DAT_{vaddr:08x}"));
                    open_document_in(&mut doc, namespace);
                    wire::encode_data_symbol(
                        &mut doc,
                        space as u32,
                        vaddr,
                        &name,
                        read_only,
                        |out| wire::encode_array_type(out, (element.as_str(), element_id), width, count),
                    );
                    close_document(&mut doc);
                } else if let (Some(width), Some((type_id, _))) = (
                    provider
                        .data_definitions
                        .get(&vaddr)
                        .filter(|(kind, _)| kind == "undefined")
                        .map(|(_, width)| *width),
                    provider
                        .data_definitions
                        .get(&vaddr)
                        .filter(|(kind, _)| kind == "undefined")
                        .and_then(|(_, width)| core(&format!("undefined{width}"))),
                ) {
                    // A location of known width and unknown contents. Ghidra
                    // answers a referenced location with the *data* defined
                    // there, and its analyzers define it as wide as the access
                    // (`DecompileCallback.encodeData`, :835-855). A symbol
                    // narrower than the access makes the decompiler warn that
                    // a global overlaps it (`Funcdata::checkGlobals`,
                    // funcdata_varnode.cc:1742).
                    let name = provider
                        .symbol_names
                        .get(&vaddr)
                        .cloned()
                        .unwrap_or_else(|| format!("DAT_{vaddr:08x}"));
                    open_document_in(&mut doc, namespace);
                    wire::encode_data_symbol(
                        &mut doc,
                        space as u32,
                        vaddr,
                        &name,
                        read_only,
                        |out| wire::encode_typeref(out, &format!("undefined{width}"), type_id),
                    );
                    close_document(&mut doc);
                } else if provider.data_targets.contains(&vaddr) {
                    // Only a reference: a name, with no claim about width or
                    // type. Ghidra sends the same shape for a symbol that is
                    // not defined data, and its own analyzers are what turn
                    // such a location into typed data.
                    // `LAB_` for an address in executable memory, `DAT_`
                    // otherwise: Ghidra's two default prefixes
                    // (`SymbolUtilities`, :49-53).
                    let code = provider
                        .executable
                        .iter()
                        .any(|(start, end)| *start <= vaddr && vaddr < *end);
                    let name = provider
                        .symbol_names
                        .get(&vaddr)
                        .cloned()
                        .unwrap_or_else(|| {
                            let prefix = if code { "LAB" } else { "DAT" };
                            format!("{prefix}_{vaddr:08x}")
                        });
                    open_document_in(&mut doc, namespace);
                    wire::encode_label_symbol(&mut doc, space as u32, vaddr, &name, read_only);
                    close_document(&mut doc);
                }
                if doc.is_empty() {
                    wire::encode_hole(&mut doc, space as u32, vaddr, read_only);
                }
                encode_string_stream(&mut buf, &doc);
            }
        }
        encode_burst(&mut buf, burst::QRESPONSE_CLOSE);
        self.write_frame(&buf)
    }

    /// getRegister (ArchitectureGhidra::getRegister): the answer is a
    /// packed `<addr>` in the register space (encodeRegister in Java); an
    /// unknown register is an exception, matching the Java client.
    fn answer_getregister(&mut self, provider: &mut ProgramProvider, payload: &[u8]) -> Result<()> {
        let name = find_name_attribute(payload)
            .ok_or_else(|| WorkerError::Protocol("getregister without name".into()))?;
        let mut buf = Vec::new();
        match provider.registers.get(&name) {
            Some((off, sz)) => {
                encode_burst(&mut buf, burst::QRESPONSE_OPEN);
                let mut addr = Vec::new();
                wire::encode_addr_element_size(
                    &mut addr,
                    provider.register_space_index as u32,
                    *off,
                    *sz,
                );
                encode_string_stream(&mut buf, &addr);
                encode_burst(&mut buf, burst::QRESPONSE_CLOSE);
            }
            None => {
                encode_burst(&mut buf, burst::EXCEP_OPEN);
                encode_string_stream(&mut buf, b"RuntimeException");
                encode_string_stream(&mut buf, format!("No Register Defined: {name}").as_bytes());
                encode_burst(&mut buf, burst::EXCEP_CLOSE);
            }
        }
        self.write_frame(&buf)?;
        Ok(())
    }

    /// getRegisterName (ArchitectureGhidra::getRegisterName): answer is a
    /// plain string (the Java handler writeString(res)); empty when the
    /// storage maps no register.
    fn answer_getregistername(
        &mut self,
        provider: &mut ProgramProvider,
        payload: &[u8],
    ) -> Result<()> {
        let (_space, off, sz) = decode_addr_element(payload)
            .ok_or_else(|| WorkerError::Protocol("bad packed <addr>".into()))?;
        let mut buf = Vec::new();
        encode_burst(&mut buf, burst::QRESPONSE_OPEN);
        let found = provider
            .registers
            .iter()
            .find(|(_, (o, s))| *o == off && *s == sz)
            .map(|(n, _)| n.as_str())
            .unwrap_or("");
        encode_string_stream(&mut buf, found.as_bytes());
        encode_burst(&mut buf, burst::QRESPONSE_CLOSE);
        self.write_frame(&buf)?;
        Ok(())
    }
}

/// The query payloads wrap the addr inside a command element, so the walk
/// also handles element-start/end headers with the extension byte (ids
/// above 0x1f, per PackedEncode::writeHeader, marshal.hh:661).
pub fn decode_addr_element(data: &[u8]) -> Option<(i64, u64, u64)> {
    let result = decode_addr_element_inner(data);
    if result.is_none() && std::env::var_os("ROMWRIGHT_TRACE_ADDR").is_some() {
        eprintln!(
            "trace: decode_addr_element failed on {} bytes: {}",
            data.len(),
            data.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")
        );
    }
    result
}

fn decode_addr_element_inner(data: &[u8]) -> Option<(i64, u64, u64)> {
    let mut pos = 0usize;
    let mut space: Option<i64> = None;
    let mut offset: Option<u64> = None;
    let mut size: Option<u64> = None;
    let mut depth = 0usize;

    while pos < data.len() {
        let header = data[pos];
        pos += 1;
        match header & wire::HEADER_MASK_EQ {
            h if h == wire::ELEMENT_START_EQ => {
                if header & 0x20 != 0 {
                    pos += 1; // extension byte
                }
                depth += 1;
            }
            h if h == wire::ELEMENT_END_EQ => {
                if header & 0x20 != 0 {
                    pos += 1; // extension byte
                }
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    break;
                }
            }
            h if h == wire::ATTRIBUTE_EQ => {
                let (aid, ty) = decode_attr_header(header, data, &mut pos)?;
                let value = decode_attr_value(data, ty, &mut pos)?;
                if ty >> 4 == wire::attr_type::STRING {
                    pos = pos.checked_add(usize::try_from(value).ok()?)?;
                    if pos > data.len() {
                        return None;
                    }
                    continue;
                }
                match (aid, ty >> 4) {
                    (wire::attr::SPACE, wire::attr_type::SPACE) => space = Some(value as i64),
                    // A special space (stack, join, fspec, iop, spacebase) is
                    // named by the length nibble, not by an index into the
                    // program's space table. Give it a negative identity so it
                    // can never compare equal to `ram_space_index`, which is
                    // what every caller tests.
                    (wire::attr::SPACE, wire::attr_type::SPECIAL_SPACE) => {
                        space = Some(-1 - value as i64)
                    }
                    (wire::attr::OFFSET, wire::attr_type::UNSIGNED_INT) => {
                        if offset.is_none() {
                            offset = Some(value);
                        } else if size.is_none() {
                            size = Some(value);
                        }
                    }
                    (wire::attr::SIZE, _) => size = Some(value),
                    _ => {}
                }
            }
            _ => return None,
        }
    }
    Some((space?, offset?, size.unwrap_or(0)))
}

/// Completes an attribute whose header byte is already consumed: reads the
/// extension byte if set, then the type byte. Returns (attr id, type byte).
fn decode_attr_header(header: u8, data: &[u8], pos: &mut usize) -> Option<(u32, u8)> {
    let mut id = (header & 0x1f) as u32;
    if header & 0x20 != 0 {
        id = (id << 7) | (data.get(*pos).copied()? & 0x7f) as u32;
        *pos += 1;
    }
    // Attribute headers carry a type byte; element headers do not.
    let ty = data.get(*pos).copied()?;
    *pos += 1;
    Some((id, ty))
}

/// Decodes the 7-bit-groups integer value (may be zero groups).
fn decode_int_value(data: &[u8], start: usize, pos: &mut usize, groups: usize) -> Option<u64> {
    let mut value = 0u64;
    let mut p = start;
    for _ in 0..groups {
        value = (value << 7) | (data.get(p).copied()? & 0x7f) as u64;
        p += 1;
    }
    *pos = p;
    Some(value)
}

/// Decodes an attribute's value and advances past whatever payload it owns.
///
/// Two type codes carry their value in the type byte's low nibble and are
/// followed by NO payload groups: `BOOLEAN` (marshal.cc
/// `PackedEncode::writeBool` writes `(TYPECODE_BOOLEAN << 4) | val`) and
/// `SPECIAL_SPACE` (`PackedEncode::writeSpace` writes
/// `(TYPECODE_SPECIALSPACE << 4) | code` for the stack, join, fspec, iop and
/// spacebase spaces). Reading `ty & 0xf` groups for those consumes the next
/// attribute's header bytes instead, and because integer payload bytes all
/// have bit 0x80 set, the walk then reads one as an element-end or attribute
/// header and desynchronises for the rest of the element. That is what made
/// every query carrying a stack or spacebase address fail as
/// "bad packed <addr>".
fn decode_attr_value(data: &[u8], ty: u8, pos: &mut usize) -> Option<u64> {
    match ty >> 4 {
        wire::attr_type::BOOLEAN | wire::attr_type::SPECIAL_SPACE => Some((ty & 0xf) as u64),
        _ => decode_int_value(data, *pos, pos, (ty & 0xf) as usize),
    }
}

/// Reads the root element id of a packed payload (with extension byte).
pub fn decode_root_element_id(data: &[u8]) -> Option<u32> {
    let header = data.first().copied()?;
    if header & wire::HEADER_MASK_EQ != wire::ELEMENT_START_EQ {
        return None;
    }
    let mut id = (header & 0x1f) as u32;
    if header & 0x20 != 0 {
        id = (id << 7) | (data.get(1).copied()? & 0x7f) as u32;
    }
    Some(id)
}

/// Returns the byte offset where the raw C text starts inside the result.
///
/// DecompileAt::rawAction writes the packed `<doc>` and, inside its
/// element, the printer's C output as raw bytes (ghidra_process.cc:330-332,
/// 173-175). The doc's packed children end before the C text, so the first
/// byte inside the doc that is not a packed header/attribute starts the C.
/// Returns `None` only when no doc/child structure was found.
pub fn packed_element_span(data: &[u8]) -> Option<usize> {
    let mut pos = 0usize;
    let mut depth = 0usize;
    let mut first_elem = false;
    let mut fail_point = None;
    while pos < data.len() {
        let header = data[pos];
        pos += 1;
        match header & wire::HEADER_MASK_EQ {
            h if h == wire::ELEMENT_START_EQ => {
                if header & 0x20 != 0 {
                    pos += 1;
                }
                depth += 1;
                first_elem = true;
            }
            h if h == wire::ELEMENT_END_EQ => {
                if header & 0x20 != 0 {
                    pos += 1;
                }
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(pos);
                }
            }
            h if h == wire::ATTRIBUTE_EQ => {
                let (aid, ty) = decode_attr_header(header, data, &mut pos)?;
                let v = decode_attr_value(data, ty, &mut pos)?;
                if ty >> 4 == wire::attr_type::STRING {
                    pos = pos.checked_add(v as usize)?;
                }
                let _ = aid;
            }
            _ => {
                // Non-packed byte at the (in)side of the doc: the printer's
                // raw C output starts here. Only meaningful once at least
                // one element was seen; otherwise this is not a result doc.
                if first_elem && fail_point.is_none() {
                    fail_point = Some(pos - 1);
                }
                return fail_point.or(Some(pos - 1));
            }
        }
    }
    None
}

/// Finds the raw bytes of the string attribute with the given id.
pub fn find_bytes_attribute(data: &[u8], target: u32) -> Option<Vec<u8>> {
    let mut pos = 0usize;
    while pos < data.len() {
        let header = data[pos];
        pos += 1;
        match header & wire::HEADER_MASK_EQ {
            h if h == wire::ELEMENT_START_EQ || h == wire::ELEMENT_END_EQ => {
                if header & 0x20 != 0 {
                    pos = pos.checked_add(1)?;
                }
            }
            h if h == wire::ATTRIBUTE_EQ => {
                let (id, ty) = decode_attr_header(header, data, &mut pos)?;
                let value = decode_attr_value(data, ty, &mut pos)?;
                if ty >> 4 == wire::attr_type::STRING {
                    let end = pos.checked_add(usize::try_from(value).ok()?)?;
                    if id == target {
                        return Some(data.get(pos..end)?.to_vec());
                    }
                    pos = end;
                }
            }
            _ => return None,
        }
    }
    None
}

/// Finds the string attribute with the given id (e.g. the getregister name).
pub fn find_name_attribute(data: &[u8]) -> Option<String> {
    let mut pos = 0usize;
    let mut name: Option<String> = None;
    while pos < data.len() {
        let header = data[pos];
        pos += 1;
        match header & wire::HEADER_MASK_EQ {
            h if h == wire::ELEMENT_START_EQ => {
                if header & 0x20 != 0 {
                    pos += 1;
                }
            }
            h if h == wire::ELEMENT_END_EQ => {
                if header & 0x20 != 0 {
                    pos += 1;
                }
            }
            h if h == wire::ATTRIBUTE_EQ => {
                if pos >= data.len() {
                    return None;
                }
                let (aid, ty) = decode_attr_header(header, data, &mut pos)?;
                // Every attribute's payload has to be stepped over, not just
                // the one being looked for: integer payload bytes all have bit
                // 0x80 set, so a skipped payload is read back as an element or
                // attribute header and the walk desynchronises.
                let value = decode_attr_value(data, ty, &mut pos)?;
                if ty >> 4 == wire::attr_type::STRING {
                    let end = pos.checked_add(usize::try_from(value).ok()?)?;
                    if aid == wire::attr::NAME {
                        let raw = data.get(pos..end)?.to_vec();
                        name = Some(String::from_utf8_lossy(&raw).into_owned());
                    }
                    pos = end;
                }
            }
            _ => return None,
        }
    }
    name
}

/// Finds a numeric packed attribute without assuming it is the first one.
pub fn find_numeric_attribute(data: &[u8], target: u32) -> Option<i64> {
    let mut pos = 0usize;
    while pos < data.len() {
        let header = data[pos];
        pos += 1;
        match header & wire::HEADER_MASK_EQ {
            h if h == wire::ELEMENT_START_EQ || h == wire::ELEMENT_END_EQ => {
                if header & 0x20 != 0 {
                    pos = pos.checked_add(1)?;
                }
            }
            h if h == wire::ATTRIBUTE_EQ => {
                let (id, ty) = decode_attr_header(header, data, &mut pos)?;
                let value = decode_attr_value(data, ty, &mut pos)?;
                if ty >> 4 == wire::attr_type::STRING {
                    pos = pos.checked_add(usize::try_from(value).ok()?)?;
                    continue;
                }
                if id == target {
                    return match ty >> 4 {
                        wire::attr_type::NEGATIVE_INT => Some(-(value as i64)),
                        _ => i64::try_from(value).ok(),
                    };
                }
            }
            _ => return None,
        }
    }
    None
}

/// A name the C the decompiler emits can carry.
///
/// The store keeps what the image declared -- Ghidra's own x86 pattern file
/// labels a stub `__i686.get_pc_thunk.bx` -- but a `.` printed into C is a
/// member access, not part of an identifier. Characters a symbol cannot carry
/// become underscores, which is what Ghidra's own applied name looks like
/// (`SymbolUtilities.replaceInvalidChars` with `USE_UNDERSCORES`,
/// SymbolUtilities.java:401-419).
pub fn c_identifier(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// The language's core types, as `coretypes.xml` declares them: the ids the
/// decompiler resolves `<typeref>` by (`TypeFactory::decodeType`,
/// type.cc:4643-4664) come from that file, not from the name.
pub fn parse_core_types(xml: &str) -> HashMap<String, (u64, u64)> {
    let mut types = HashMap::new();
    for element in xml.split("<type ").skip(1) {
        let attribute = |key: &str| -> Option<&str> {
            let start = element.find(&format!("{key}=\""))? + key.len() + 2;
            let end = element[start..].find('"')? + start;
            Some(&element[start..end])
        };
        let (Some(name), Some(size), Some(id)) =
            (attribute("name"), attribute("size"), attribute("id"))
        else {
            continue;
        };
        let id = u64::from_str_radix(id.trim_start_matches("0x"), 16);
        if let (Ok(size), Ok(id)) = (size.parse::<u64>(), id) {
            types.insert(name.to_string(), (id, size));
        }
    }
    types
}

/// `<doc id="0">` wraps every query answer the C++ scope decodes
/// (`ScopeGhidra::processResult`).
/// The `<doc id=...>` a mapped-symbol answer carries is the id of the
/// namespace the symbol lives in (`DecompileCallback.encodeResult`, :807-826);
/// zero is the global scope.
fn open_document_in(out: &mut Vec<u8>, namespace: u64) {
    wire::encode_header(out, wire::ELEMENT_START, wire::elem::DOC);
    wire::encode_attribute(
        out,
        wire::attr::ID,
        wire::attr_type::UNSIGNED_INT,
        namespace,
    );
}

fn close_document(out: &mut Vec<u8>) {
    wire::encode_header(out, wire::ELEMENT_END, wire::elem::DOC);
}

/// Ghidra's label for string data: the `s` prefix its string types report
/// (`SymbolUtilities.getDynamicDataTypePrefixes`, SymbolUtilities.java:105),
/// an abbreviation of the content, then the address (`getDynamicDataName`,
/// :541-544). Characters a symbol name cannot carry become underscores, as
/// `SymbolUtilities.replaceInvalidChars` does.
fn string_label(text: &str, address: u64) -> String {
    let mut body = String::new();
    for ch in text.chars().take(20) {
        if ch.is_ascii_alphanumeric() {
            body.push(ch);
        } else {
            body.push('_');
        }
    }
    format!("s_{body}_{address:08x}")
}

/// Ghidra's own mapping from a listing comment type to the decompiler's
/// property name (`DecompileCallback.encodeCommentsType`:576-595): EOL is
/// `user1`, PRE is `user2`, POST is `user3` and PLATE is `header`. The
/// difference is load-bearing -- the decompiler's default body mask is
/// `user2 | warning` (`printlanguage.cc`:586), so a PRE comment sent as
/// `header` is silently dropped from the function body (m4-024).
fn comment_type_name(kind: &str) -> &'static str {
    match kind.to_ascii_lowercase().as_str() {
        "eol" | "user1" => "user1",
        "pre" | "user2" => "user2",
        "post" | "user3" => "user3",
        "header" | "plate" => "header",
        "warning" => "warning",
        "warningheader" => "warningheader",
        _ => "user1",
    }
}

fn datatype_metatype(definition: &str) -> &'static str {
    let definition = definition.to_ascii_lowercase();
    if definition.contains("struct") {
        "struct"
    } else if definition.contains("union") {
        "union"
    } else if definition.contains("enum") {
        "enum_int"
    } else if definition.contains("float") {
        "float"
    } else if definition.contains("bool") {
        "bool"
    } else {
        "int"
    }
}

/// Path helper for the pinned language tree (spike layout).
pub fn spec_dir(root: &Path) -> PathBuf {
    root.join("Ghidra/Processors/x86/data/languages")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_types_come_from_the_shipped_spec_with_their_ids() {
        let xml = std::fs::read_to_string("../../native/specs/coretypes.xml")
            .expect("the shipped x86-64 core types");
        let types = parse_core_types(&xml);
        // The decompiler resolves `<typeref>` by id; a parser that lost the
        // id would silently make every data symbol unresolvable.
        assert_eq!(types.get("code"), Some(&(0xe000000000000001, 1)));
        assert_eq!(types.get("char").map(|(_, size)| *size), Some(1));
        assert_eq!(types.get("undefined8").map(|(_, size)| *size), Some(8));
        assert!(types.get("char").unwrap().0 != 0);
    }

    #[test]
    fn string_query_decodes_address_after_datatype_name() {
        let mut payload = Vec::new();
        wire::encode_header(
            &mut payload,
            wire::ELEMENT_START,
            wire::query::GETSTRINGDATA,
        );
        wire::encode_attribute(
            &mut payload,
            wire::attr::MAXSIZE,
            wire::attr_type::POSITIVE_INT,
            64,
        );
        wire::encode_string_attribute(&mut payload, wire::attr::TYPE, b"char");
        wire::encode_attribute(
            &mut payload,
            wire::attr::ID,
            wire::attr_type::UNSIGNED_INT,
            0,
        );
        wire::encode_addr_element(&mut payload, 3, 0x401178);
        wire::encode_header(&mut payload, wire::ELEMENT_END, wire::query::GETSTRINGDATA);
        assert_eq!(decode_addr_element(&payload), Some((3, 0x401178, 0)));
    }

    /// `PackedEncode::writeSpace` puts a special space's code in the type
    /// byte's low nibble and writes no payload. Reading that nibble as a
    /// group count swallows the following attribute's header, and because
    /// every integer payload byte has bit 0x80 set the walk then reads one
    /// as an element-end and gives up. This is the exact 15-byte query the
    /// decompiler sends for a stack address; 158 of 197 Persona 4 functions
    /// failed to decompile on it.
    #[test]
    fn special_space_address_decodes_without_a_payload() {
        let payload: [u8; 15] = [
            0x61, 0xf9, // <getmappedsymbols> (extended element id)
            0x4b, // <addr>
            0xd4, 0x64, // space attribute, SPECIAL_SPACE code 4 (spacebase)
            0xd0, 0x45, 0x8f, 0xff, 0xfe, 0x8a, 0x84, // offset, 5 groups
            0x8b, // </addr>
            0xa1, 0xf9, // </getmappedsymbols>
        ];
        let (space, offset, size) = decode_addr_element(&payload).expect("special-space addr");
        assert_eq!(offset, 0xffff8504);
        assert_eq!(size, 0);
        // Special spaces are not indices into the program's space table, so
        // they must never collide with a real one.
        assert!(space < 0, "special space {space} must not look like a real index");
    }

    /// `PackedEncode::writeBool` encodes the value in the length nibble and
    /// writes no payload either, so a `true` used to consume the next byte.
    #[test]
    fn boolean_attribute_carries_no_payload() {
        let mut payload = Vec::new();
        wire::encode_header(&mut payload, wire::ELEMENT_START, wire::elem::ADDR);
        wire::encode_header(&mut payload, wire::ATTRIBUTE, wire::attr::READONLY);
        payload.push((wire::attr_type::BOOLEAN << 4) | 1);
        wire::encode_attribute(&mut payload, wire::attr::SPACE, wire::attr_type::SPACE, 3);
        wire::encode_attribute(
            &mut payload,
            wire::attr::OFFSET,
            wire::attr_type::UNSIGNED_INT,
            0x401178,
        );
        wire::encode_header(&mut payload, wire::ELEMENT_END, wire::elem::ADDR);
        assert_eq!(decode_addr_element(&payload), Some((3, 0x401178, 0)));
    }

    /// `find_numeric_attribute` has to step over every attribute's payload,
    /// not just the one it wants, or it desynchronises before reaching a
    /// target that is not first.
    #[test]
    fn numeric_attribute_is_found_after_a_string_and_a_bool() {
        let mut payload = Vec::new();
        wire::encode_header(&mut payload, wire::ELEMENT_START, wire::elem::ADDR);
        wire::encode_string_attribute(&mut payload, wire::attr::NAME, b"stackframe");
        wire::encode_header(&mut payload, wire::ATTRIBUTE, wire::attr::READONLY);
        payload.push((wire::attr_type::BOOLEAN << 4) | 1);
        wire::encode_attribute(&mut payload, wire::attr::SIZE, wire::attr_type::POSITIVE_INT, 48);
        wire::encode_header(&mut payload, wire::ELEMENT_END, wire::elem::ADDR);
        assert_eq!(find_numeric_attribute(&payload, wire::attr::SIZE), Some(48));
        assert_eq!(find_name_attribute(&payload).as_deref(), Some("stackframe"));
    }
}

/// Strips the address suffix a dynamic name carries, exactly as Ghidra's
/// `SymbolUtilities.getCleanSymbolName` (:950-972) does: the name is split at
/// its last `_` and the tail must be the symbol's own address rendered the way
/// the store renders it, or the name is returned untouched.
fn clean_symbol_name(name: &str, address: u64) -> String {
    match name.rsplit_once('_') {
        Some((base, tail)) if !base.is_empty() && tail == format!("{address:08x}") => {
            base.to_string()
        }
        _ => name.to_string(),
    }
}
