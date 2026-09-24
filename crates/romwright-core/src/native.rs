//! Native (no-JVM) ELF/PE/DOL import: parse headers, derive the memory map,
//! discover functions from symbols and entry-point call walking, and extract
//! direct xrefs. Facts land in the same project.sqlite tables the bridge
//! import fills, with provenance `native-import`.
//!
//! Design notes:
//! - ELF64 import selects a Ghidra language from `e_machine` for the
//!   architectures currently represented in the catalog; PE supports PE32+ (x86-64) and PE32 (i386).
//! - Structural ELF facts (mappings, symbols, entry point) are architecture
//!   independent. Discovery uses the selected SLEIGH language and the generic
//!   worklist; without a console, ELF/PE retain structural facts only.
use romwright_db::ProjectDb;
use std::collections::HashSet;
use std::path::Path;
mod discovery;
pub(crate) mod dol;
mod gba;
mod n64;
mod nds;
pub mod nds_overlays;
mod psx;
pub(crate) use discovery::BRANCH_PROVENANCE;
pub(crate) mod binmap;
pub(crate) mod containers;
pub(crate) mod crypto;
mod elf_exception;
mod elf_image;
mod elf_pointers;
mod elf_unwind;
mod features;
pub(crate) mod gameboy;
pub(crate) mod genesis;
pub(crate) mod irx;
mod iso9660;
pub mod keys;
mod kirk;
mod kirk_tables;
pub mod linkmap;
mod mdebug;
pub(crate) mod macho;
pub mod n64_overlays;
pub(crate) mod nes;
pub mod nid;
pub(crate) mod nonreturn;
mod nso;
mod pe_roots;
mod pe_unwind;
pub(crate) mod ps3;
pub(crate) mod psp;
pub mod psx_overlays;
pub(crate) mod rel;
mod sce;
pub(crate) mod sja;
pub(crate) mod snes;
mod strings;
pub(crate) mod switch;
pub(crate) mod threeds;
pub(crate) mod vita;
pub(crate) mod vsa;
pub(crate) mod wii;
pub(crate) mod xbox_3ds;
pub(crate) mod xex;
mod elf;
mod pe;
mod references;
mod store;
mod switch_tables;
use romwright_model::{FunctionRow, MemoryRegion, ProgramSummary, Provenance, XrefRow};
pub use elf::{elf_image_base, import_elf};
pub(crate) use elf::ElfSection;
use elf::{elf_bases, import_elf32, parse_elf32_sections};
pub use pe::{import_pe, pe_image_base};
pub use references::close_call_targets;
use references::infer_data_references;
pub use store::{
    DATA_POINTER_SOURCE, DATA_WIDTH_SOURCE, DEMANGLE_SOURCE, DYNAMIC_LABEL_SOURCE,
    ELF_COPY_SOURCE, ELF_EXCEPTION_SOURCE, ELF_GOT_SOURCE, ELF_LINKAGE_SOURCE, ELF_OBJECT_SOURCE,
    ELF_POINTER_SOURCE, ENTRY_CONVENTION_SOURCE, PROCESS_ENTRY_MODEL, SHARED_RETURN_SOURCE,
    declared_entry_model, store_import,
};
pub(crate) use switch_tables::scratch_root;
use switch_tables::{
    ScratchDir, demote_case_blocks, recover_switch_tables, recover_switch_tables_native,
    switch_candidates,
};
/// Errors from a native import.
#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error("{0}")]
    Bad(String),
    #[error("store: {0}")]
    Store(#[from] romwright_db::DbError),
}

pub type Result<T> = std::result::Result<T, ImportError>;

pub fn native_provenance() -> Provenance {
    Provenance {
        producer: "native-import".into(),
        upstream_version: "12.1.3".into(),
    }
}

/// One loaded code/data range in memory (vaddr..vaddr+size).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mapping {
    pub vaddr: u64,
    pub size: u64,
    /// File offset of the mapping's first byte (ELF: section offset; PE:
    /// section raw offset — the RVA-to-file translation the worker uses).
    pub file_off: u64,
    /// Low bits encode write (1), read (2), execute (4) for every format.
    /// Additional ELF SHF_* attributes are retained above those bits.
    pub flags: u64,
    /// Raw bytes of the mapping.
    pub bytes: Vec<u8>,
}

/// A context register value the image declares at an address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeContext {
    /// Context register name, as the language declares it (`TMode`).
    pub name: String,
    /// Address the value applies from.
    pub address: u64,
    /// The value itself.
    pub value: u64,
}

/// A discovered function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeFunction {
    pub entry: u64,
    pub name: String,
    pub size: u64,
}

/// A discovered xref (direct call or branch).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeXref {
    pub from: u64,
    pub to: u64,
    pub kind: String,
    pub provenance: String,
}

impl NativeXref {
    pub fn new(from: u64, to: u64, kind: impl Into<String>) -> Self {
        Self {
            from,
            to,
            kind: kind.into(),
            provenance: "native-import".into(),
        }
    }

    pub fn with_provenance(
        from: u64,
        to: u64,
        kind: impl Into<String>,
        provenance: impl Into<String>,
    ) -> Self {
        Self {
            from,
            to,
            kind: kind.into(),
            provenance: provenance.into(),
        }
    }
}

/// A loader-applied word, retained for mmap-backed memory consumers.
#[derive(Debug, Clone, Copy)]
pub struct MemoryRelocation {
    pub address: u64,
    pub(crate) bytes: [u8; 8],
    pub(crate) width: usize,
}

/// Loader-established register value over an instruction-address range.
#[derive(Debug, Clone)]
pub struct NativeRegisterContext {
    pub start: u64,
    pub end: u64,
    pub register: String,
    pub value: u64,
}

/// Loader-defined string table, including non-loaded metadata address spaces.
#[derive(Debug)]
pub struct NativeStringTable {
    pub address: romwright_model::Address,
    pub size: u64,
    pub strings: Vec<romwright_model::StringRow>,
}

/// Single owner name for flow-proven thunk facts and their jump xrefs.
pub const THUNK_SOURCE: &str = "native-import:thunk";
/// Provenance of a jump-to-case reference the decompiler's table recovery proved.
pub const SWITCH_PROVENANCE: &str = "native-import:switch";
/// The PLT header's jump reads `DT_PLTGOT + 2 * pointer size`, which the
/// System V ABI reserves for the dynamic linker's resolver.
pub const PLT_HEADER_SOURCE: &str = "native-import:plt-header";
/// The same reservation types the three words themselves: each is a pointer.
pub const PLT_RESERVED_SOURCE: &str = "native-import:plt-reserved";
/// A name on the pinned list of functions Ghidra ships as non-returning.
pub const KNOWN_NAME_SOURCE: &str = "native-import:known-name";

/// A loader-bound data relocation that names a symbol: `copies` marks the
/// COPY form, where the loader duplicates the symbol's bytes at `address`.
#[derive(Clone, Debug)]
pub struct NamedRelocation {
    pub address: u64,
    pub symbol: String,
    pub addend: u64,
    pub copies: bool,
}

/// A function whose whole body transfers to one proven destination.
#[derive(Clone, Copy, Debug)]
pub struct NativeThunk {
    pub entry: u64,
    /// Thunked function entry, or the imported slot for linkage stubs.
    pub destination: u64,
    pub kind: romwright_model::ThunkKind,
    /// The rule that proved this transfer; each becomes its own provenance so
    /// a consumer can tell flow evidence from an ABI-declared slot.
    pub source: &'static str,
}

/// One instruction as the walk decoded it, addresses aside from its own
/// direct branch target left out: the shape a diff can compare.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FlowShape {
    pub address: u64,
    pub length: u8,
    pub kind: crate::native_runtime::FlowKind,
    pub conditional: bool,
    pub target: Option<u64>,
}

impl NativeImport {
    /// Records one thing the import could not do.
    pub(crate) fn diagnose(
        &mut self,
        severity: romwright_model::DiagnosticSeverity,
        stage: &str,
        message: impl Into<String>,
    ) {
        self.diagnostics.push(romwright_model::ImportDiagnostic {
            severity,
            stage: stage.to_string(),
            message: message.into(),
        });
    }

    /// Whether any stage fell short for reasons outside the inputs.
    pub(crate) fn degraded(&self) -> bool {
        self.diagnostics
            .iter()
            .any(|diagnostic| diagnostic.severity == romwright_model::DiagnosticSeverity::Degraded)
    }
}

/// Parsed image and transient loader/discovery evidence.
#[derive(Debug, Default)]
pub struct NativeImport {
    /// Captured loader identity available to analysis-time worker staging.
    pub input_context: Option<std::sync::Arc<(std::path::PathBuf, romwright_model::ProgramInput)>>,
    pub mappings: Vec<Mapping>,
    pub string_tables: Vec<NativeStringTable>,
    pub functions: Vec<NativeFunction>,
    pub xrefs: Vec<NativeXref>,
    /// Unconditional direct branches seen by flow, kept so the pass that
    /// records transfers out of a function can run after every pass that
    /// can still create one.
    pub branch_transfers: Vec<(u64, u64)>,
    pub externals: Vec<(u64, String)>,
    /// Proven ifunc pointer slots and their in-image resolvers.
    pub ifunc_slots: Vec<(u64, u64)>,
    /// Loader-bound data relocations that name a symbol.
    pub named_relocations: Vec<NamedRelocation>,
    /// Flow-proven thunk entries and their destinations.
    pub thunks: Vec<NativeThunk>,
    /// `DT_PLTGOT + 2 * pointer size`: the slot the System V ABI reserves for
    /// the dynamic linker's resolver, which the PLT header jumps through.
    pub plt_resolver_slot: Option<u64>,
    /// The `DT_PLTGOT` words the ABI reserves, each holding a pointer, with
    /// the image's pointer width.
    pub plt_reserved_slots: Vec<(u64, u64)>,
    /// Instructions whose transfer the image's own structure proves behaves
    /// like a call, with the rule that proved each.
    pub flow_overrides: Vec<(u64, &'static str)>,
    /// Indirect transfers the flow walk decoded, sorted: a rule that needs the
    /// branch rather than the load it follows reads these.
    pub indirect_transfers: Vec<u64>,
    /// Every decoded indirect jump, whatever the image's linkage: the
    /// instructions a switch round asks the decompiler about.
    pub indirect_jumps: Vec<u64>,
    /// Jump tables the decompiler recovered at an indirect branch, keyed by
    /// the branch: the case targets discovery walks from it, as Ghidra's
    /// `DecompilerSwitchAnalyzer` lays references on the jump and
    /// disassembles them.
    pub switch_tables: std::collections::HashMap<u64, Vec<u64>>,
    /// Indirect jumps the decompiler was already asked about, with the size
    /// of the function that held each at the time: Ghidra runs its switch
    /// analyzer again on a function whose body changed, and so does this.
    pub switch_asked: std::collections::HashMap<u64, u64>,
    /// Entries an earlier discovery run created as ordinary functions; a
    /// later run does not turn one into a thunk, as `CreateFunctionCmd`
    /// decides thunk-ness only when it creates the function.
    pub thunk_settled: std::collections::HashSet<u64>,
    /// Address ranges the last walk decoded, merged and sorted.
    pub decoded_ranges: Vec<(u64, u64)>,
    /// Every instruction a walk decoded, kept across discovery rounds: a
    /// round re-walks from all seeds, and Ghidra's own analysis never
    /// disassembles an instruction twice. A mode context added after a
    /// round drops what it could re-mode (`flow_cache_contexts`).
    pub flow_cache: std::collections::BTreeMap<u64, crate::native_runtime::FlowResult>,
    /// How many of `contexts` the cached results were decoded under.
    pub flow_cache_contexts: usize,
    /// The contexts the walk that filled `flow_cache` set as it went; a
    /// later walk setting one it did not drops what that context re-modes.
    pub flow_cache_walk_contexts: Vec<NativeContext>,
    /// Dispatches value-set analysis resolved, and refused, over every
    /// round: the measurement that says whether the decompiler is still
    /// needed in the switch round at all.
    pub switch_vsa_resolved: usize,
    pub switch_vsa_refused: usize,
    /// Decompiler-round owners skipped by the owner budget, recorded
    /// rather than silently dropped: bounding wall time must not
    /// masquerade as coverage.
    pub switch_decompiler_skipped: usize,
    /// Entries the walk has started from, over every round.
    pub walk_entries: std::collections::HashSet<u64>,
    /// The decoded shape of every instruction the walk read: address, byte
    /// length, flow kind, whether the flow is conditional, and the single
    /// direct target when it has one. This is what the structural features
    /// (`romwright_model::FunctionFeatureRow`) are counted from; a switch jump's
    /// many targets are not here, they are the `switch_tables` fact.
    pub flow_shapes: Vec<FlowShape>,
    /// Computed-call targets the propagation reached with the low address
    /// bit set, aligned: on a low-bit-mode language each is decoded in the
    /// alternate instruction set from then on.
    pub computed_mode_targets: Vec<u64>,
    /// The stack frame the propagation recovered per function: every slot a
    /// load or store reached through the stack pointer, merged where
    /// accesses overlap, named as Ghidra's stack analyzer names them.
    pub stack_variables: Vec<romwright_model::StackVariableRow>,
    /// Initializer-array words, with their width: each holds a code address,
    /// proved by the array it belongs to.
    pub initializer_slots: Vec<(u64, u64)>,
    /// Referenced words whose bytes are a function's entry, with their width.
    pub pointer_slots: Vec<(u64, u64)>,
    /// Words inside a `.got` section, with their width.
    pub got_slots: Vec<(u64, u64)>,
    /// Addresses an ELF `OBJECT` symbol declares, with the size it declares.
    pub object_sizes: Vec<(u64, u64)>,
    /// Names an ELF `OBJECT` symbol declares, keyed by the address. Sizes
    /// travel in `object_sizes`; names travel here so data definitions can
    /// print them instead of `DAT_` defaults.
    pub object_names: Vec<(u64, String)>,
    /// Linkage slots whose relocation names a function, with their width.
    pub function_slots: Vec<(u64, u64)>,
    /// Entries whose name came from the image's own symbol table. Ghidra's
    /// loader leaves such a function's name alone and only marks it an entry
    /// point (`ElfProgramBuilder.createEntryFunction`, :790-794).
    pub symbol_named: Vec<u64>,
    /// `[start, end)` of every symbol-table function the image gives a size,
    /// sorted: the image's own word that the range is one function.
    pub symbol_extents: Vec<(u64, u64)>,
    /// How wide the widest proven access to a location is, by address. A
    /// location whose address is only taken proves no width and is absent.
    pub reference_widths: Vec<(u64, u64)>,
    /// Branches an unconditional-jump-to-a-function-entry rule proved to be
    /// calls that return, keyed by the branching instruction. Recorded by
    /// `record_branch_transfers`, applied once every rule that owns an
    /// override has run.
    pub shared_return_branches: Vec<u64>,
    /// Addresses the dynamic table names, labelled as Ghidra labels them:
    /// `__DT_<TAG>` for every ADDRESS-valued tag with a nonzero value, and
    /// `_DYNAMIC` for the table itself
    /// (`ElfProgramBuilder.markupDynamicTable`, :2691-2723, and
    /// `addDynamicMemoryReference`, :2753-2773). A label is only applied
    /// where nothing else names the address, which is Ghidra's own guard.
    pub dynamic_labels: Vec<(u64, String)>,
    /// The address the operating system enters the process at, when the ABI
    /// says the platform's process-entry model applies to it: `e_entry` of an
    /// executable or shared object whose OS ABI is Linux or unspecified
    /// (`ElfProgramBuilder.processEntryPoints`, :655-673). The language
    /// decides whether such a model exists; the image decides the address.
    pub process_entry: Option<u64>,
    /// Relocation code targets to be verified as candidate function entries.
    pub reloc_candidates: Vec<u64>,
    /// Untrusted data pointers; never functions until flow confirms them.
    pub pointer_candidates: Vec<u64>,
    /// Set when no data section held pointers to scan: code and data share
    /// executable segments (Sony's `main`/`heap` layout), so tables live in
    /// the bytes of code mappings discovery did not decode.
    pub code_holds_data: bool,
    /// The image ships without relocations, so a code address stored in its
    /// data is visible only as a word: XEX, whose PE image has its base
    /// relocations stripped at link time.
    pub unrelocated_data_pointers: bool,
    /// Entries the gap rule seeded (`mips_gap_starts`), over every round.
    pub gap_starts: std::collections::HashSet<u64>,
    /// Entries seeded from code pointers stored in tables or data words,
    /// over every round: a handler reached through such a table is also a
    /// computed-jump target, and stays a function when case labels go.
    pub table_seeds: std::collections::HashSet<u64>,
    /// Other images of the same container call into this one: a DS
    /// overlay's program holds only the overlay, so a static-module
    /// function only overlays call is found through their calls. Such an
    /// image is discovered after its siblings and seeded from them.
    pub sibling_call_host: bool,
    /// Loader-declared initializer entry points, also requiring valid flow.
    pub initializer_candidates: Vec<u64>,
    /// Names an initializer array gives its targets: the array names the
    /// prefix, the slot's position names the index.
    pub initializer_labels: Vec<(u64, String)>,
    /// Names the pinned patterns give the starts they proved.
    pub pattern_labels: Vec<(u64, String)>,
    /// Starts the pattern search produced: addresses its `collect` accepted
    /// as candidates, not every rule match (most matches are refused on
    /// prerequisites). Labels alone cannot say this -- only a subset of
    /// rules carry a `<funcstart label=>`.
    pub pattern_starts: Vec<u64>,
    /// Pattern starts the guard-clause merge folded into the function
    /// above them. Durable across discovery rounds, which refresh
    /// `pattern_labels`: an absorbed start is no evidence of a function.
    pub absorbed_starts: std::collections::HashSet<u64>,
    /// Reference facts of the last discovery round, per function range,
    /// with the digest of the round-level inputs they were inferred under.
    /// See `infer_data_references`.
    /// Keyed by range, with the digest of the decode contexts covering it
    /// (`ContextPoints::covering`).
    pub reference_memo: std::collections::HashMap<(u64, u64), (u64, Vec<crate::native_runtime::ReferenceFact>)>,
    pub reference_memo_inputs: Option<u64>,
    /// Starts this rule seeded from constant-propagated DATA facts: the
    /// only evidence that names the seeding pass, so the producer column
    /// credits discovery's source instead of the walk that followed it.
    pub const_data_starts: Vec<u64>,
    /// Untrusted PLT entries: loaded address and maximum entry width.
    pub plt_candidates: Vec<(u64, u64)>,
    pub relocations: Vec<MemoryRelocation>,
    pub register_contexts: Vec<NativeRegisterContext>,
    /// Loader-enabled register propagation across calls during reference analysis.
    pub reference_call_register: Option<&'static str>,
    /// ELF section-address code roots and exclusive bounds, not function seeds.
    pub reference_roots: Vec<(u64, u64)>,
    pub format: String,
    /// Ghidra-compatible language id. For a format whose header names a
    /// machine this is selected from the install's own opinion data
    /// (`opinion::elf_selection`), which is why it is empty until a caller
    /// with a configured install fills it in; a container that declares its
    /// own language sets it at parse time.
    pub language: String,
    /// Loader-selected base compiler specification; absent for raw/default images.
    pub compiler: Option<String>,
    /// Toolchain that produced the image, detected from the image's own
    /// markers (ELF `.comment`, PE Rich header, DOL mwcc runtime symbols).
    /// Distinct from `compiler`: that is the SLEIGH spec, this is the
    /// producing toolchain.
    pub toolchain: Option<String>,
    /// What an ELF header said about its machine: the primary and secondary
    /// keys the install's opinion data is queried with.
    pub elf_machine: Option<crate::opinion::ElfMachine>,
    /// Call sites `.gcc_except_table` declares protected, with the handler
    /// each one branches to.
    pub exception_sites: Vec<elf_exception::ExceptionSite>,
    /// Runtime configuration used to reach the SLEIGH console/worker.
    pub cfg: crate::session::RuntimeConfig,
    /// Path to the binary used for console-driven x86 flow.
    pub binary: std::path::PathBuf,
    /// Measured wall time of each completed import phase.
    pub phases: Vec<romwright_model::PhaseTiming>,
    /// Regions the platform defines but the image does not contain, such as
    /// a console's RAM and IO windows. Declared for the store; never given
    /// invented bytes, so discovery cannot walk into them.
    pub declared_regions: Vec<DeclaredRegion>,
    /// Names for the leading mappings, when the platform names them. A
    /// cartridge has one window called ROM, not one called `0`.
    pub mapping_names: Vec<String>,
    /// Console request accounting for the flow phase, when it ran.
    pub flow: Option<romwright_model::FlowStats>,
    /// Pattern accounting for the pattern phase, when it ran.
    pub patterns_seen: Option<romwright_model::PatternStats>,
    /// Reference ranges the console refused, counted so the loss is reported.
    pub references_refused: u64,
    /// Processor mode values the image itself declares, applied to a console
    /// before anything decodes: ARM marks Thumb code with the low bit of a
    /// function address and with `$t`/`$a` mapping symbols
    /// (`ARM_ElfExtension.creatingFunction`, 116-140, and
    /// `evaluateElfSymbol`, 142-209).
    pub contexts: Vec<NativeContext>,
    /// What this import could not do, graded by how much it matters. A
    /// silent fallback to pointer-only seeds is how a MIPS image came back
    /// with a third of its functions and no complaint (m11-002); a single
    /// note slot also let one stage overwrite another's.
    pub diagnostics: Vec<romwright_model::ImportDiagnostic>,
    /// True when discovery walked this image, as opposed to the loader
    /// simply declaring what the file says about itself.
    pub analysed: bool,
}
/// One platform-defined region with no bytes in the image.
#[derive(Debug, Clone)]
pub struct DeclaredRegion {
    pub name: String,
    pub vaddr: u64,
    pub size: u64,
    /// ELF SHF-style bits, as `Mapping::flags`.
    pub flags: u64,
}

/// The bytes of `[off, off+len)` the file holds. A range that runs past
/// the end of the file keeps the part that is there and says what was cut:
/// taking nothing -- a missing section read as zeros -- is how a
/// truncated image used to import without a word.
fn file_bytes<'a>(
    data: &'a [u8],
    off: u64,
    len: u64,
    what: impl FnOnce() -> String,
    notes: &mut Vec<romwright_model::ImportDiagnostic>,
) -> &'a [u8] {
    let start = usize::try_from(off).unwrap_or(usize::MAX).min(data.len());
    let end = usize::try_from(off.saturating_add(len)).unwrap_or(usize::MAX).min(data.len());
    let present = &data[start..end];
    if (present.len() as u64) < len {
        notes.push(romwright_model::ImportDiagnostic {
            severity: romwright_model::DiagnosticSeverity::Partial,
            stage: "load".into(),
            message: format!("{} runs past the end of the file: {} of {len} bytes present", what(), present.len()),
        });
    }
    present
}

fn err<T>(msg: impl Into<String>) -> Result<T> {
    Err(ImportError::Bad(msg.into()))
}

fn u16_at(b: &[u8], o: usize) -> Result<u16> {
    b.get(o..o + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .ok_or(ImportError::Bad("truncated".into()))
}
fn u32_at(b: &[u8], o: usize) -> Result<u32> {
    b.get(o..o + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or(ImportError::Bad("truncated".into()))
}
fn u64_at(b: &[u8], o: usize) -> Result<u64> {
    b.get(o..o + 8)
        .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
        .ok_or(ImportError::Bad("truncated".into()))
}
fn u16_be_at(b: &[u8], o: usize) -> Result<u16> {
    b.get(o..o + 2)
        .map(|s| u16::from_be_bytes([s[0], s[1]]))
        .ok_or(ImportError::Bad("truncated".into()))
}
fn u32_be_at(b: &[u8], o: usize) -> Result<u32> {
    b.get(o..o + 4)
        .map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or(ImportError::Bad("truncated".into()))
}
fn u64_be_at(b: &[u8], o: usize) -> Result<u64> {
    b.get(o..o + 8)
        .map(|s| u64::from_be_bytes(s.try_into().unwrap()))
        .ok_or(ImportError::Bad("truncated".into()))
}

// ---- ELF32 ----------------------------------------------------------------

/// Returns the executable (code) ranges of the import, for seed filtering.
///
/// Only the bytes the image actually carries are code: a section's virtual
/// extent can outrun its file contents, and Ghidra searches loaded *and
/// initialized* memory (`Memory::getLoadedAndInitializedAddressSet`). The
/// console agrees by construction -- its load image raises `DataUnavailError`
/// for an address it was never given bytes for.
pub fn code_ranges(imp: &NativeImport) -> Vec<(u64, u64)> {
    imp.mappings
        .iter()
        .filter(|m| m.flags & 0x4 != 0)
        .filter_map(|m| {
            let length = (m.bytes.len() as u64).min(m.size);
            (length > 0).then_some((m.vaddr, m.vaddr + length))
        })
        .collect()
}

/// Finds a known external name for a function entry, if any (PLT/GOT named
/// stubs; FUN_<hex> otherwise).
pub fn extern_name(imp: &NativeImport, entry: u64) -> Option<String> {
    imp.externals
        .iter()
        .find(|(a, n)| *a == entry && !n.is_empty())
        .map(|(_, n)| n.clone())
}

pub(crate) fn parse_native(data: &[u8]) -> Result<NativeImport> {
    if data.starts_with(b"\x7fELF") && irx::is_irx(data) {
        irx::import(data)
    } else if data.starts_with(b"\x7fELF") {
        import_elf(data)
    } else if data.starts_with(b"MZ") {
        import_pe(data)
    } else if n64::is_rom(data) || n64::is_swapped_dump(data) {
        // A swapped dump is recognised only to refuse it by name.
        n64::import(data)
    } else if nso::is_module(data) {
        nso::import(data)
    } else if psx::is_executable(data) {
        psx::import(data)
    } else if gba::is_cartridge(data) {
        gba::import(data)
    } else if nds::is_cartridge(data) {
        // A container holds one image per processor; a single-image caller
        // gets the one the console boots.
        nds::import(data)?
            .into_iter()
            .next()
            .map(|(_, import)| import)
            .ok_or_else(|| ImportError::Bad("empty Nintendo DS container".into()))
    } else if xex::is_xex(data) {
        xex::import(data)
    } else if rel::is_rel(data) {
        rel::import(data)
    } else if nes::is_rom(data) {
        nes::import(data)
    } else if gameboy::is_rom(data) {
        gameboy::import(data)
    } else if snes::is_rom(data) {
        snes::import(data)
    } else if genesis::is_rom(data) {
        genesis::import(data)
    } else if macho::is_macho(data) {
        macho::import(data)
    } else {
        dol::import(data)
    }
}

/// Every image a container carries, each with the suffix that names it.
/// A single-image file yields one entry with an empty suffix, so callers do
/// not special-case formats.
pub(crate) fn parse_container(data: &[u8]) -> Result<Vec<(String, NativeImport)>> {
    parse_container_with(data, &keys::KeyStore::empty())
}

/// `parse_container` with a user-supplied key store: the console loaders
/// that can use a dumped key (Switch NCA/XCI, 3DS slot-key content, PS3
/// NPDRM/RAP, Vita klic) read it from `keys`; an absent key leaves the
/// loader's existing key-gap error unchanged. PSP KIRK needs no dumped key:
/// its tables are public constants embedded in the loader.
pub(crate) fn parse_container_with(
    data: &[u8],
    keys: &keys::KeyStore,
) -> Result<Vec<(String, NativeImport)>> {
    if iso9660::is_iso(data) {
        return iso9660::import(data);
    }
    if nds::is_cartridge(data) {
        return nds::import(data);
    }
    if let Some(result) = containers::import(data) {
        return result;
    }
    if let Some(result) = wii::import(data) {
        return result;
    }
    if let Some(result) = switch::import_with(data, keys) {
        return result;
    }
    // 3DS NCCH/NCSD/CIA before xbox_3ds: threeds implements them where
    // xbox_3ds only refuses. xbox_3ds still owns XEX/XBE.
    if let Some(result) = threeds::import_with(data, keys) {
        return result;
    }
    // Vita before PS3: both use the `SCE\0` magic, but Vita's little-endian
    // version-3/type-1 header would misparse under PS3's big-endian layout.
    if let Some(result) = vita::import_with(data, keys) {
        return result;
    }
    if let Some(result) = ps3::import_with(data, keys) {
        return result;
    }
    if let Some(result) = psp::import_with(data, keys) {
        return result;
    }
    if let Some(result) = xbox_3ds::import(data) {
        return result;
    }
    Ok(vec![(String::new(), parse_native(data)?)])
}

/// Loads `<binary>` mappings without running discovery or sweep passes.
pub fn load_native_mappings(binary: &Path) -> Result<Vec<Mapping>> {
    let data = std::fs::read(binary)
        .map_err(|e| ImportError::Bad(format!("{}: {e}", binary.display())))?;
    let imp = parse_native(&data)?;
    Ok(imp.mappings)
}

/// Records one measured phase on the import.
fn phase(imp: &mut NativeImport, name: &str, started: std::time::Instant) {
    imp.phases.push(romwright_model::PhaseTiming {
        phase: name.to_string(),
        seconds: started.elapsed().as_secs_f64(),
    });
}

/// Loads every image `<binary>` carries, closing each one's seeds through
/// SLEIGH flow with that image's own language.
/// Fills in the language and compiler spec for an image whose header names a
/// machine, from the install the configuration points at.
///
/// A container that declares its own language (GBA, N64, DOL) has already
/// answered and is left alone: `elf_machine` is what says "ask the opinion
/// data".
pub fn select_language(imp: &mut NativeImport, cfg: &crate::session::RuntimeConfig) -> Result<()> {
    let Some(machine) = imp.elf_machine else {
        return Ok(());
    };
    let selection = crate::opinion::elf_selection(&cfg.ghidra_install, machine)
        .map_err(|e| ImportError::Bad(e.to_string()))?;
    imp.language = selection.language;
    imp.compiler = Some(selection.compiler);
    Ok(())
}

pub fn load_container(binary: &Path) -> Result<Vec<(String, NativeImport)>> {
    let data = std::fs::read(binary).map_err(|error| ImportError::Bad(error.to_string()))?;
    load_container_with(
        binary,
        &data,
        true,
        None,
        None,
        &keys::KeyStore::empty(),
        &crate::session::RuntimeConfig::from_env(),
    )
}

/// Parse captured bytes with explicit raw-image metadata and key material.
pub(crate) fn parse_image_input(
    data: &[u8],
    raw: Option<(u64, &str)>,
    keys: &keys::KeyStore,
) -> Result<Vec<(String, NativeImport)>> {
    let Some((base, language)) = raw else {
        return parse_container_with(data, keys);
    };
    base.checked_add(data.len() as u64)
        .ok_or_else(|| ImportError::Bad("raw image address overflow".into()))?;
    Ok(vec![(
        String::new(),
        NativeImport {
            mappings: vec![Mapping {
                vaddr: base,
                size: data.len() as u64,
                file_off: 0,
                flags: 7,
                bytes: data.to_vec(),
            }],
            format: "raw".into(),
            language: language.to_string(),
            process_entry: Some(base),
            functions: vec![NativeFunction {
                entry: base,
                name: "entry".into(),
                size: 1,
            }],
            ..Default::default()
        },
    )])
}

/// Loads every image a container carries, running discovery only when asked.
///
/// Without discovery this is the loader's own answer: mapped bytes, declared
/// regions, relocations, and whatever the image says about itself -- its
/// symbol table above all. That is a parse, not a walk, so it returns in
/// seconds on an image whose full analysis takes minutes, which is what an
/// interactive session needs before it can show anything at all.
pub fn load_container_with(
    binary: &Path,
    data: &[u8],
    analyse: bool,
    map: Option<&Path>,
    raw: Option<(u64, &str)>,
    keys: &keys::KeyStore,
    config: &crate::session::RuntimeConfig,
) -> Result<Vec<(String, NativeImport)>> {
    let parse_started = std::time::Instant::now();
    let images = parse_image_input(data, raw, keys)?;
    // A linker MAP is the image's own symbol table from the other side:
    // read once, applied to every image it names an address in, before
    // discovery so a seeded entry is walked rather than coined. Binary
    // BINMAP blobs (Vita) sniff first; everything else is a text grammar.
    let map_bytes = match map {
        Some(path) => Some(
            std::fs::read(path)
                .map_err(|e| ImportError::Bad(format!("{}: {e}", path.display())))?,
        ),
        None => None,
    };
    let bin_map = map_bytes.as_deref().and_then(binmap::parse);
    let sym_map = if bin_map.is_none() {
        map_bytes.as_deref().and_then(linkmap::parse_sym)
    } else {
        None
    };
    let cw_map = match (bin_map.is_some() || sym_map.is_some(), &map_bytes) {
        (true, _) => None,
        (false, Some(bytes)) => Some(linkmap::parse(
            std::str::from_utf8(bytes)
                .map_err(|_| ImportError::Bad("map is neither BINMAP nor text".into()))?,
        )),
        (false, None) => None,
    };
    // Direct native callers get the same captured-input contract as Core.
    // Core supplies its durable context after the loader-only phase instead.
    let captured = if analyse {
        let scratch = ScratchDir::new("romwright-input").ok_or_else(|| {
            ImportError::Bad("native analysis has no input scratch directory".into())
        })?;
        let (_, input) = crate::inputs::capture(
            &scratch.path,
            binary,
            data.to_vec().into(),
            map_bytes.as_ref().map(|bytes| bytes.clone().into()),
            raw,
            keys,
        )
        .map_err(|error| ImportError::Bad(error.to_string()))?;
        Some((scratch, input))
    } else {
        None
    };
    let canonical = binary
        .canonicalize()
        .unwrap_or_else(|_| binary.to_path_buf());
    let mut loaded = Vec::with_capacity(images.len());
    for (suffix, mut imp) in images {
        if let Some((scratch, input)) = &captured {
            let mut input = input.clone();
            input.image_selector = suffix.clone();
            imp.input_context = Some(std::sync::Arc::new((scratch.path.clone(), input)));
        }
        imp.binary = canonical.clone();
        imp.cfg = config.clone();
        let cfg = imp.cfg.clone();
        select_language(&mut imp, &cfg)?;
        imp.cfg.adopt_language(&imp.language);
        if let Some(cw_map) = &cw_map {
            linkmap::apply_to_import(&mut imp, cw_map);
        }
        if let Some(sym_map) = &sym_map {
            linkmap::apply_to_import(&mut imp, sym_map);
        }
        if let Some(bin_map) = &bin_map {
            binmap::apply_to_import(&mut imp, bin_map);
        }
        phase(&mut imp, "parse", parse_started);
        imp.analysed = analyse;
        if analyse {
            discover(&mut imp)?;
            imp.input_context = None;
        } else {
            imp.diagnose(romwright_model::DiagnosticSeverity::Info, "load", "loaded without analysis: functions are the image's own symbols");
        }
        loaded.push((suffix, imp));
    }
    Ok(loaded)
}

/// The context field the pinned languages alias to the instruction-set mode
/// a code address carries in its low bit: ARM declares
/// `LowBitCodeMode = (0,0)` beside `TMode` (ARM.sinc:90-93), MIPS declares
/// `LowBitCodeMode = (1,1)` beside `ISA_MODE` (mips.sinc:416-417). Ghidra
/// keys the rule on a register of exactly this name
/// (`PseudoDisassembler.setTargetContextForDisassembly`,
/// `LOW_BIT_CODE_MODE_REGISTER_NAME`); no other pinned language declares it.
pub(crate) fn low_bit_code_mode(language: &str) -> bool {
    language.starts_with("ARM:") || language.starts_with("MIPS:")
}

/// Code pointers stored as tables in executable bytes discovery has not
/// decoded, for images whose code segments also carry their data. Only runs
/// of two or more aligned words that each name an address in code count: a
/// single word that happens to equal a code address is no table -- except on
/// ARM, where an odd word is a Thumb entry by its own low bit. A target
/// inside code already decoded is a case label or interior address, not an
/// entry, and is skipped. Candidates still face flow validation. Measured on
/// PS2 Capcom Fighting Evolution: 1,679 of 2,199 missed functions had their
/// address stored in `main`, the one segment code and data share.
fn code_pointer_tables(imp: &NativeImport) -> Vec<u64> {
    if !imp.code_holds_data {
        return Vec::new();
    }
    let be = imp.language.contains(":BE:");
    let arm = imp.language.starts_with("ARM");
    // Owned code is the bodies of functions that exist now, not every byte
    // ever decoded: walks from retracted junk entries decode data too, and
    // on Capcom that hid nearly every table.
    let mut bodies: Vec<(u64, u64)> = imp
        .functions
        .iter()
        .filter(|function| function.size > 1)
        .map(|function| (function.entry, function.entry + function.size))
        .collect();
    bodies.sort_unstable();
    let decoded = |address: u64| {
        let index = bodies.partition_point(|&(start, _)| start <= address);
        bodies[..index].iter().rev().take(8).any(|&(_, end)| address < end)
    };
    let code: Vec<(u64, u64)> = imp
        .mappings
        .iter()
        .filter(|mapping| mapping.flags & 4 != 0)
        .map(|mapping| (mapping.vaddr, mapping.vaddr + mapping.size))
        .collect();
    let in_code = |address: u64| code.iter().any(|&(lo, hi)| lo <= address && address < hi);
    let known: std::collections::HashSet<u64> = imp.functions.iter().map(|f| f.entry).collect();
    let mut found = Vec::new();
    for mapping in imp.mappings.iter().filter(|mapping| mapping.flags & 4 != 0) {
        let mut run: Vec<u64> = Vec::new();
        let flush = |run: &mut Vec<u64>, found: &mut Vec<u64>| {
            if run.len() >= 2 {
                found.extend(run.iter().copied());
            }
            run.clear();
        };
        let start = (mapping.vaddr + 3) & !3;
        let mut address = start;
        while address + 4 <= mapping.vaddr + mapping.bytes.len() as u64 {
            if decoded(address) {
                flush(&mut run, &mut found);
                address += 4;
                continue;
            }
            let at = (address - mapping.vaddr) as usize;
            let raw: [u8; 4] = mapping.bytes[at..at + 4].try_into().expect("four bytes");
            let word = u64::from(if be { u32::from_be_bytes(raw) } else { u32::from_le_bytes(raw) });
            let target = if arm { word & !1 } else { word };
            // On ARM the Thumb bit is the evidence a lone word lacks: data
            // is at even addresses, so an odd word naming code is a Thumb
            // entry, table or not. Vita NFS: 4,921 such words outside every
            // body, 4,892 of them functions its map names.
            if arm {
                if word & 1 != 0 && in_code(target) {
                    found.push(target);
                }
                address += 4;
                continue;
            }
            let aligned = target % 4 == 0;
            if word != 0 && aligned && in_code(target) {
                run.push(target);
            } else {
                flush(&mut run, &mut found);
            }
            address += 4;
        }
        flush(&mut run, &mut found);
    }
    found.retain(|target| {
        !known.contains(target)
            && !decoded(*target)
            && if arm { !thumb1(&imp.language) || thumb1_table_entry(imp, *target) } else { mips_function_evidence(imp, *target, be) }
    });
    found.sort_unstable();
    found.dedup();
    found
}

/// Code addresses stored as words in an unrelocated image's data mappings,
/// outside every current body and not yet an entry: vtables, script-command
/// tables and callback arrays. Measured on Black Ops 2 (XEX): 544 such words
/// in `.rdata` and 659 more in `.data`, every one a function its map names,
/// and 1,203 of the 1,677 functions the exception directory and calls
/// missed. A word inside a body is a case label or return address, never
/// taken.
fn data_code_pointers(imp: &NativeImport) -> Vec<u64> {
    if !imp.unrelocated_data_pointers {
        return Vec::new();
    }
    let be = imp.language.contains(":BE:");
    let mut bodies: Vec<(u64, u64)> = imp
        .functions
        .iter()
        .filter(|function| function.size > 1)
        .map(|function| (function.entry, function.entry + function.size))
        .collect();
    bodies.sort_unstable();
    let owned = |address: u64| {
        let index = bodies.partition_point(|&(start, _)| start <= address);
        bodies[..index].iter().rev().take(8).any(|&(_, end)| address < end)
    };
    let code: Vec<(u64, u64)> = imp
        .mappings
        .iter()
        .filter(|mapping| mapping.flags & 4 != 0)
        .map(|mapping| (mapping.vaddr, mapping.vaddr + mapping.size))
        .collect();
    let in_code = |address: u64| code.iter().any(|&(lo, hi)| lo <= address && address < hi);
    let known: std::collections::HashSet<u64> = imp.functions.iter().map(|f| f.entry).collect();
    let mut found: Vec<u64> = imp
        .mappings
        .iter()
        .filter(|mapping| mapping.flags & 4 == 0)
        .flat_map(|mapping| {
            let skip = ((4 - mapping.vaddr % 4) % 4) as usize;
            mapping.bytes.get(skip..).unwrap_or(&[]).chunks_exact(4).map(move |raw| {
                let raw: [u8; 4] = raw.try_into().expect("four bytes");
                u64::from(if be { u32::from_be_bytes(raw) } else { u32::from_le_bytes(raw) })
            })
        })
        .filter(|&target| target % 4 == 0 && in_code(target) && !known.contains(&target) && !owned(target))
        .collect();
    found.sort_unstable();
    found.dedup();
    found
}

/// The first code after each body, on MIPS: skipping zero padding, the next
/// word before the following entry that opens a frame or reaches `jr ra`
/// soon. Code nothing calls or points at -- dead library code, callbacks
/// reached through registers -- still sits between the functions that are
/// found. PS2 dungeon_game: 97 such starts, 84 of them functions its symbol
/// table names, against 153 functions nothing references at all. Only a
/// body that ends on a jump and its delay slot has a gap after it; a start
/// whose body never decodes is retracted after the last round.
fn mips_gap_starts(imp: &NativeImport) -> Vec<u64> {
    if !mips_language(&imp.language) {
        return Vec::new();
    }
    let be = imp.language.contains(":BE:");
    let mut bodies: Vec<(u64, u64)> = imp
        .functions
        .iter()
        .map(|function| (function.entry, function.entry + function.size.max(1)))
        .collect();
    bodies.sort_unstable();
    let word = |address: u64| -> Option<u32> {
        imp.mappings.iter().filter(|mapping| mapping.flags & 4 != 0).find_map(|mapping| {
            let at = usize::try_from(address.checked_sub(mapping.vaddr)?).ok()?;
            let raw: [u8; 4] = mapping.bytes.get(at..at + 4)?.try_into().ok()?;
            Some(if be { u32::from_be_bytes(raw) } else { u32::from_le_bytes(raw) })
        })
    };
    let cases: std::collections::HashSet<u64> =
        imp.switch_tables.values().flat_map(|targets| targets.iter().copied()).collect();
    let mut found = Vec::new();
    // A body that stops without a terminal instruction stopped for another
    // reason, and what follows is its own code: `_Z7do_worki` in the mipsel
    // corpus proves 64 of its 108 bytes, and its continuation is no start.
    // MIPS ends on a jump and its delay slot: `jr ra`, `j`, or `b`. A `jr`
    // through any other register is a dispatch whose table went unresolved,
    // and what follows it is the cases (dungeon_game `graph_vram_size`: nine
    // case blocks coined as functions).
    let terminal = |end: u64| {
        word(end.wrapping_sub(8)).is_some_and(|w| w == 0x03e0_0008 || w >> 26 == 2 || w >> 16 == 0x1000)
    };
    for pair in bodies.windows(2) {
        let (_, end) = pair[0];
        let (next, _) = pair[1];
        if !terminal(end) {
            continue;
        }
        let mut address = (end + 3) & !3;
        while address < next && word(address) == Some(0) {
            address += 4;
        }
        if address < next
            && !cases.contains(&address)
            && word(address).is_some()
            && mips_function_evidence(imp, address, be)
        {
            found.push(address);
        }
    }
    found
}

fn mips_language(language: &str) -> bool {
    ["MIPS", "r5900", "PSX", "Allegrex"].iter().any(|family| language.starts_with(family))
}

/// Code evidence for a table target on MIPS: a stack-frame prologue
/// (`addiu sp, sp, -N`), or a start that is not text or zero with a
/// `jr ra` within 64 instructions. A segment that holds code and data also
/// holds tables of string and data pointers; on PS2 Capcom Fighting
/// Evolution this rule kept 1,306 real functions against 105 others,
/// where "points into code" alone took 1,624 against 1,924. Other
/// architectures have no measured rule, and take nothing.
fn mips_function_evidence(imp: &NativeImport, target: u64, be: bool) -> bool {
    if !mips_language(&imp.language) {
        return false;
    }
    let word = |address: u64| -> Option<u32> {
        imp.mappings.iter().find_map(|mapping| {
            let at = usize::try_from(address.checked_sub(mapping.vaddr)?).ok()?;
            let raw: [u8; 4] = mapping.bytes.get(at..at + 4)?.try_into().ok()?;
            Some(if be { u32::from_be_bytes(raw) } else { u32::from_le_bytes(raw) })
        })
    };
    let Some(first) = word(target) else {
        return false;
    };
    if first >> 16 == 0x27bd && first & 0x8000 != 0 {
        return true;
    }
    let bytes = if be { first.to_be_bytes() } else { first.to_le_bytes() };
    if first == 0 || bytes.iter().all(|&byte| (32..127).contains(&byte)) {
        return false;
    }
    (0..64).any(|index| word(target + 4 * index) == Some(0x03e0_0008))
}

// Code addresses the propagation proved hold constants.
//
// A constant-propagated DATA value into executable code is usually a
// callback -- or `main` handed to `__libc_start_main`, which arrives no
// other way (mipsel_many_o2: 7 of 401 without this rule, all 401 with
// `main` seeded). No other pass proposes these, so without this rule
// they stay invisible no matter how long the walk runs. Flow
// confirmation still applies downstream; this only seeds.
//
// The use must materialize the address, not compare against it: on libc
// the unfiltered rule seeded 20 uncalled orphans from comparison
// immediates (`CMP EDI, <code>`, padding decoding past the target).
// The p-code of the using instruction says which (opcodes, not
// mnemonics, so one predicate covers every language); unknown shapes
// stay allowed and the spurious floors judge.
fn const_data_use_denied(ops: &[String]) -> bool {
    ops.iter().any(|op| {
        matches!(
            op.as_str(),
            "INT_EQUAL"
                | "INT_NOTEQUAL"
                | "INT_LESS"
                | "INT_SLESS"
                | "INT_LESSEQUAL"
                | "INT_SLESSEQUAL"
                | "INT_CARRY"
                | "INT_SCARRY"
                | "INT_SBORROW"
        ) || op.starts_with("BOOL_")
            || op.starts_with("FLOAT_")
    })
}
fn const_data_targets(
    import: &mut NativeImport,
    session: &mut crate::native_runtime::ConsoleSession,
) -> Vec<u64> {
    let entries: std::collections::HashSet<u64> = import
        .functions
        .iter()
        .map(|function| function.entry)
        .collect();
    let in_code = |address: u64| {
        import.mappings.iter().any(|mapping| {
            mapping.flags & 4 != 0
                && address >= mapping.vaddr
                && address - mapping.vaddr < mapping.size
        })
    };
    // Lift only what can become a seed: most const facts point at data.
    // One batch per round; facts the console cannot lift stay allowed
    // (recall-preserving: an unknown use seeds, the spurious floors judge).
    let mut froms: Vec<u64> = import
        .xrefs
        .iter()
        .filter(|xref| {
            xref.kind == "DATA" && xref.provenance == "native-analysis:constant-propagation"
        })
        .filter(|xref| !entries.contains(&xref.to) && in_code(xref.to))
        .map(|xref| xref.from)
        .collect();
    froms.sort_unstable();
    froms.dedup();
    let mut uses: std::collections::HashMap<u64, Vec<String>> = std::collections::HashMap::new();
    if let Ok(lifted) = session.pcode_batch(&froms) {
        for instruction in lifted {
            uses.insert(
                instruction.address,
                instruction.ops.iter().map(|op| op.opcode.clone()).collect(),
            );
        }
    }
    // On a low-bit-mode language the low bit of a DATA value is the
    // instruction-set mode, not address: 0x02000ca5 *is* the 0x02000ca4
    // entry, and coining it as a one-byte function truncates the walk
    // through the real one (m5-013 NitroMain). Align before the
    // membership check, and record the mode the way computed targets do
    // so a genuinely new Thumb callback still decodes Thumb.
    // On ARM the bit is also the code/data discriminator: data addresses
    // are always even, so an even DATA value in executable mapping is
    // usually data the module shares its mapping with (NDS ARM9: 320
    // even-coined const entries, 211 spurious vs 2/256 odd). MIPS keeps
    // even targets: mipsel_many_o2's 401 callbacks are MIPS32 (even)
    // and its ELF sections already separate code from data.
    let mode = low_bit_code_mode(&import.language);
    let arm = import.language.starts_with("ARM:");
    let mut targets: Vec<u64> = import
        .xrefs
        .iter()
        .filter(|xref| {
            xref.kind == "DATA" && xref.provenance == "native-analysis:constant-propagation"
        })
        .filter(|xref| !arm || xref.to & 1 != 0)
        .filter(|xref| !arm || thumb_start_evidence(import, xref.to & !1))
        // The same for MIPS, whose code and data can share a segment too:
        // on PS2 Capcom Fighting Evolution 47 of 1,016 const-seeded entries
        // were functions; this keeps 41 of them and 8 of the rest.
        .filter(|xref| {
            !mips_language(&import.language)
                || mips_function_evidence(import, xref.to, import.language.contains(":BE:"))
        })
        .filter(|xref| {
            uses.get(&xref.from)
                .is_none_or(|ops| !const_data_use_denied(ops))
        })
        .map(|xref| xref.to)
        .map(|target| if mode { target & !1 } else { target })
        .filter(|&target| !entries.contains(&target) && in_code(target))
        .collect();
    targets.sort_unstable();
    targets.dedup();
    if mode {
        for xref in import.xrefs.iter() {
            if xref.kind == "DATA"
                && xref.provenance == "native-analysis:constant-propagation"
                && xref.to & 1 != 0
                && targets.contains(&(xref.to & !1))
            {
                import.computed_mode_targets.push(xref.to & !1);
            }
        }
    }
    targets
}
/// Whether the halfword at a Thumb constant's target opens a function the
/// way Thumb code does: a `push` (with or without `lr`), a leaf's `bx lr`, or
/// a PC-relative literal load. An odd constant is also any pointer to data
/// at an odd address -- byte strings, graphics -- and on a cartridge whose
/// data shares the executable window those decode as Thumb too. Measured on
/// pokeemerald: of 878 real functions seeded this way, 849 open like this;
/// of 316 seeded in the data region, 3 do. Each junk seed also rooted a chain
/// of calls through more data (1,912 further invented functions).
fn thumb_start_evidence(import: &NativeImport, target: u64) -> bool {
    thumb_halfword(import, target)
        .is_some_and(|first| first & 0xfe00 == 0xb400 || first == 0x4770 || first >> 11 == 0b01001)
}

fn thumb_halfword(import: &NativeImport, target: u64) -> Option<u16> {
    import.mappings.iter().find_map(|mapping| {
        let offset = usize::try_from(target.checked_sub(mapping.vaddr)?).ok()?;
        let bytes = mapping.bytes.get(offset..offset.checked_add(2)?)?;
        Some(u16::from_le_bytes([bytes[0], bytes[1]]))
    })
}

/// Languages whose Thumb is 16-bit only (ARMv4T, ARMv5T): no Thumb-2 wide
/// encodings, so the first halfword alone is the first instruction.
fn thumb1(language: &str) -> bool {
    language.starts_with("ARM:") && (language.ends_with(":v4t") || language.ends_with(":v5t"))
}

/// Whether a Thumb-1 table target is a function entry: it opens like one
/// and it follows the end of something else. An odd word also points at
/// byte-aligned data -- event-script bytecode, text -- whose bytes decode as
/// Thumb too.
///
/// Opening: the start evidence above, or a first instruction that sets up
/// an argument or a local (a `mov`, `cmp` or `add` immediate, a
/// three-operand add or subtract, an `ldr`/`ldrb`/`ldrh` immediate). Data
/// opens with shifts (a zero halfword is `lsl r0, r0, #0`), ALU and
/// high-register operations, stores and branches instead.
///
/// Following an end: the halfword before is a `pop {.., pc}`, a `bx`/`blx`
/// register, an unconditional `b`, or a `nop`; or, on a word boundary, zero
/// padding or the high half of a literal-pool pointer into the image or a
/// declared region. Script bytecode carries unaligned pointers of its own.
///
/// Of what the rule added without this filter, pokeemerald keeps 1,695 of
/// the 1,704 functions its symbols name against 192
/// of 1,455 others (script bytecode and data); the pokeheartgold ARM9
/// keeps 765 of 778 against 2 of 52. Thumb-2 code opens with wide encodings
/// this does not read; there (Vita NFS) the words need no filter: 11,323 of
/// 11,453 name functions.
fn thumb1_table_entry(import: &NativeImport, target: u64) -> bool {
    let Some(first) = thumb_halfword(import, target) else {
        return false;
    };
    let opens = thumb_start_evidence(import, target)
        || matches!(first >> 11, 0b00011 | 0b00100 | 0b00101 | 0b00110 | 0b01101 | 0b01111 | 0b10001);
    let Some(before) = target.checked_sub(2).and_then(|at| thumb_halfword(import, at)) else {
        return false;
    };
    let ends = before & 0xff00 == 0xbd00
        || before & 0xff87 == 0x4700
        || before >> 11 == 0b11100
        || before == 0x46c0;
    let pointer_high = |half: u16| {
        let low = u64::from(half) << 16;
        let high = low | 0xffff;
        let overlaps = |vaddr: u64, size: u64| vaddr <= high && low < vaddr.saturating_add(size);
        import.mappings.iter().any(|mapping| overlaps(mapping.vaddr, mapping.size))
            || import.declared_regions.iter().any(|region| overlaps(region.vaddr, region.size))
    };
    let aligned_end = target % 4 == 0 && (before == 0 || pointer_high(before));
    opens && (ends || aligned_end)
}

// Destinations of stub-shaped unconditional jumps. A body that is only a
// jump is a thunk even when its destination returns normally (Ghidra's
// getSimpleFlow makes no noreturn distinction); the destination becomes a
// seed and flow confirmation decides it. A jump terminating a substantial
// body is a tail call, not a stub, and stays parked (m5-007: neither tool
// promotes the stock-missing leaf). Stub means tiny with exactly one jump
// and no calls; the bound is arbitrary and the spurious floors judge it.
fn stub_jump_seeds(import: &NativeImport) -> Vec<(u64, u64)> {
    const STUB_BODY_MAX: u64 = 32;
    let in_code = |address: u64| {
        import.mappings.iter().any(|mapping| {
            mapping.flags & 4 != 0
                && address >= mapping.vaddr
                && address - mapping.vaddr < mapping.size
        })
    };
    // One from-ordered index: a linear scan per function is O(F*X), the
    // shape that never converged at FFXV scale. Range queries per body.
    // Thunk membership and entryhood likewise come from sets, not scans.
    let mut by_from: Vec<usize> = (0..import.xrefs.len()).collect();
    by_from.sort_unstable_by_key(|&index| import.xrefs[index].from);
    let thunked: std::collections::HashSet<u64> =
        import.thunks.iter().map(|thunk| thunk.entry).collect();
    let known: std::collections::HashSet<u64> = import
        .functions
        .iter()
        .map(|function| function.entry)
        .collect();
    let mut out = Vec::new();
    for function in import.functions.iter() {
        if function.size > STUB_BODY_MAX {
            continue;
        }
        if thunked.contains(&function.entry) {
            continue;
        }
        let end = function.entry + function.size.max(1);
        let lo = by_from.partition_point(|&index| import.xrefs[index].from < function.entry);
        let hi = by_from.partition_point(|&index| import.xrefs[index].from < end);
        let mut jumps = Vec::new();
        let mut calls = 0u32;
        for &index in &by_from[lo..hi] {
            let xref = &import.xrefs[index];
            if xref.kind == "UNCONDITIONAL_JUMP" {
                jumps.push(xref.to);
            } else if xref.kind.contains("CALL") {
                calls += 1;
            }
        }
        if jumps.len() != 1 || calls != 0 {
            continue;
        }
        let destination = jumps[0];
        if !in_code(destination) || known.contains(&destination) {
            continue;
        }
        out.push((function.entry, destination));
    }
    out
}

/// Function starts the propagation proved by resolving a call or branch
/// through a register, that no pass has created yet. Ghidra creates these
/// from the reference the constant-propagation analyzer lays down
/// (`ConstantPropagationContextEvaluator.evaluateDestination`, then
/// disassembly and function creation follow the reference); a target with
/// the low bit set on a low-bit-mode language is decoded in that mode from
/// then on (`setTargetContextForDisassembly`: clear the bit, set the mode).
fn computed_flow_targets(import: &mut NativeImport) -> Vec<u64> {
    let entries: std::collections::HashSet<u64> = import
        .functions
        .iter()
        .map(|function| function.entry)
        .collect();
    let in_code = |address: u64| {
        import.mappings.iter().any(|mapping| {
            mapping.flags & 4 != 0
                && address >= mapping.vaddr
                && address - mapping.vaddr < mapping.size
        })
    };
    let mut targets: Vec<u64> = import
        .xrefs
        .iter()
        .filter(|xref| xref.kind == "COMPUTED_CALL")
        .map(|xref| xref.to)
        .filter(|&target| !entries.contains(&target) && in_code(target))
        .collect();
    targets.sort_unstable();
    targets.dedup();
    targets
}

/// Seeds `host` with the calls its already-discovered `siblings` make into
/// its code: a direct call is as good a function start there as it is in
/// the caller's own image. Only siblings in the host's language count (a
/// DS ARM7 shares main RAM but not the ARM9's instruction set). Where the
/// language switches modes by the low bit, the target's mode is read from
/// the call itself, and a call whose encoding does not reach its recorded
/// target seeds nothing: flow records no context for a `bl` that keeps
/// its caller's mode, and a Thumb start seeded without one decodes as ARM.
/// On Pokemon HeartGold, 731 ARM9 functions only overlays call.
pub(crate) fn seed_from_siblings(host: &mut NativeImport, siblings: &[&NativeImport]) {
    let executable = |address: u64| {
        host.mappings
            .iter()
            .any(|m| m.flags & 4 != 0 && address >= m.vaddr && address - m.vaddr < m.size)
    };
    let modes = low_bit_code_mode(&host.language);
    let mut known: std::collections::HashSet<u64> = host.functions.iter().map(|f| f.entry).collect();
    let mut seeds = Vec::new();
    for sibling in siblings.iter().filter(|sibling| sibling.language == host.language) {
        for xref in &sibling.xrefs {
            if xref.kind != "UNCONDITIONAL_CALL" || !executable(xref.to) || known.contains(&xref.to) {
                continue;
            }
            let mode = if modes {
                match arm_call_target_mode(sibling, xref.from, xref.to) {
                    Some(mode) => Some(mode),
                    None => continue,
                }
            } else {
                None
            };
            known.insert(xref.to);
            seeds.push((xref.to, mode));
        }
    }
    for (entry, mode) in seeds {
        if let Some(value) = mode {
            host.contexts.push(NativeContext { name: "LowBitCodeMode".into(), address: entry, value });
        }
        host.functions.push(NativeFunction { entry, name: format!("FUN_{entry:08x}"), size: 1 });
    }
}

/// The mode (`1` Thumb, `0` ARM) a direct call at `from` enters `to` in,
/// from the call's own encoding: a Thumb `bl` pair or an ARM `bl` keeps
/// the caller's mode, the `blx` forms switch it. Each reading is accepted
/// only if its computed target is `to` (ARM ARM, A8.8.25 BL, BLX
/// (immediate)), which also decides between the two readings.
fn arm_call_target_mode(image: &NativeImport, from: u64, to: u64) -> Option<u64> {
    let big = image.language.contains(":BE:");
    let bytes = |at: u64, count: usize| -> Option<&[u8]> {
        image.mappings.iter().find_map(|m| {
            let offset = usize::try_from(at.checked_sub(m.vaddr)?).ok()?;
            m.bytes.get(offset..offset.checked_add(count)?)
        })
    };
    let half = |at: u64| {
        bytes(at, 2).map(|b| if big { u16::from_be_bytes([b[0], b[1]]) } else { u16::from_le_bytes([b[0], b[1]]) })
    };
    let signed = |value: u32, bits: u32| i64::from(((value << (32 - bits)) as i32) >> (32 - bits));
    if let (Some(high), Some(low)) = (half(from), half(from + 2)) {
        if high & 0xf800 == 0xf000 && matches!(low & 0xf800, 0xf800 | 0xe800) {
            let offset = (signed(u32::from(high & 0x7ff), 11) << 12) + i64::from(low & 0x7ff) * 2;
            let target = (from as i64 + 4 + offset) as u64;
            if low & 0xf800 == 0xf800 && target == to {
                return Some(1);
            }
            if low & 0xf800 == 0xe800 && target & !3 == to {
                return Some(0);
            }
        }
    }
    if from % 4 == 0 {
        let word = bytes(from, 4).map(|b| {
            let b = [b[0], b[1], b[2], b[3]];
            if big { u32::from_be_bytes(b) } else { u32::from_le_bytes(b) }
        })?;
        let offset = signed(word & 0x00ff_ffff, 24) * 4;
        let target = (from as i64 + 8 + offset) as u64;
        if word >> 25 == 0x7d && target + u64::from((word >> 24) & 1) * 2 == to {
            return Some(1);
        }
        if word & 0x0f00_0000 == 0x0b00_0000 && word >> 28 != 0xf && target == to {
            return Some(0);
        }
    }
    None
}

/// Runs discovery and reference inference for one loaded image.
pub(crate) fn discover(imp: &mut NativeImport) -> Result<()> {
    let discovery_started = std::time::Instant::now();
    let mut ran = if imp.format == "dol" {
        discovery::discover_mapped(imp)?;
        true
    } else {
        elf_pointers::confirm_initializers(imp);
        discovery::discover_seeded(imp)
    };
    phase(imp, "discovery", discovery_started);
    // Ghidra's analysis is a loop: a reference the propagation lays down on a
    // computed call is disassembled and made a function, whose own code the
    // propagation then walks. The round repeats while it creates something,
    // bounded because each round re-walks the image. Three rounds reached
    // every computed target on a DS ARM9 module whose crt0 enters the game
    // through `bx r1`.
    // Every phase timing is a sum over rounds, so the count is part of the
    // measurement: without it a per-pass budget reads a four-round total as
    // one pass. The walk rewrites the flow stats each round, so the count is
    // applied after the loop.
    let mut rounds_run = 0u64;
    for round in 0..4 {
        if !std::mem::take(&mut ran) {
            break;
        }
        rounds_run = round as u64 + 1;
        // The reference pass reads bytes through a console that has decoded
        // nothing but what the recorded contexts say. The discovery console
        // has probed thousands of candidates by now, and every probe wrote
        // the mode switches its bytes carried into that console's one
        // context database (SLEIGH `globalset`), so crt0 of a DS ROM read as
        // Thumb there and yielded no references at all.
        let console_started = std::time::Instant::now();
        let references_started = std::time::Instant::now();
        let mut session = match crate::native_runtime::ConsoleSession::new(&imp.cfg) {
            Ok(session) => session,
            Err(error) => {
                imp.diagnose(romwright_model::DiagnosticSeverity::Degraded, "references", format!("reference console did not start: {error}"));
                break;
            }
        };
        if let Err(error) = session.load_mapped(imp) {
            imp.diagnose(romwright_model::DiagnosticSeverity::Degraded, "references", format!("reference console did not load the image: {error}"));
            break;
        }
        let shards = crate::native_runtime::ConsoleSession::open_image_shards(
            imp,
            imp.cfg.console_shards.max(1) - 1,
        );
        phase(imp, "console", console_started);
        let references_only = std::time::Instant::now();
        seed_mips_entry_register(imp);
        infer_data_references(imp, &mut session, shards)?;
        phase(imp, "references-only", references_only);
        phase(imp, "references", references_started);
        if round == 3 {
            break;
        }
        let targets = computed_flow_targets(imp);
        let callbacks = const_data_targets(imp, &mut session);
        let stubs = stub_jump_seeds(imp);
        let mut tables_in_code = code_pointer_tables(imp);
        tables_in_code.extend(data_code_pointers(imp));
        imp.table_seeds.extend(tables_in_code.iter().copied());
        let gaps = mips_gap_starts(imp);
        imp.gap_starts.extend(gaps.iter().copied());
        tables_in_code.extend(gaps);
        tables_in_code.sort_unstable();
        tables_in_code.dedup();
        // Value-set analysis over p-code answers most dispatches without the
        // decompiler; the decompiler path is what a body this cannot follow
        // falls back to (and the accelerator can be switched off entirely,
        // which is how the two are measured against each other).
        let switch_started = std::time::Instant::now();
        let candidates = switch_candidates(imp);
        if std::env::var_os("ROMWRIGHT_TRACE_VSA").is_some() {
            eprintln!(
                "switch round {round}: candidates={} indirect_jumps={} asked={} known_tables={}",
                candidates.len(),
                imp.indirect_jumps.len(),
                imp.switch_asked.len(),
                imp.switch_tables.len()
            );
        }
        let mut tables = 0;
        let mut remaining = candidates.iter().map(|&(branch, _, _)| branch).count();
        if imp.cfg.switch_vsa && !candidates.is_empty() {
            let (added, unresolved) = recover_switch_tables_native(imp, &mut session, &candidates);
            tables += added;
            remaining = unresolved.len();
            // Only the branches value-set analysis could not follow are
            // asked again, so the decompiler sees the residue and nothing
            // more.
            for &(branch, _, _) in &candidates {
                if !unresolved.contains(&branch) {
                    continue;
                }
                imp.switch_asked.remove(&branch);
            }
            imp.switch_vsa_resolved += added;
            imp.switch_vsa_refused += unresolved.len();
        } else {
            for &(branch, _, _) in &candidates {
                imp.switch_asked.remove(&branch);
            }
        }
        phase(imp, "switch-vsa", switch_started);
        if remaining > 0 && imp.cfg.switch_decompiler {
            tables += recover_switch_tables(imp);
        } else if tables > 0 {
            demote_case_blocks(imp);
        }
        if targets.is_empty()
            && tables == 0
            && callbacks.is_empty()
            && stubs.is_empty()
            && tables_in_code.is_empty()
        {
            break;
        }
        let mode = low_bit_code_mode(&imp.language);
        for &target in targets.iter().chain(callbacks.iter()) {
            if mode {
                // The reference kept the aligned address; the mode it carried
                // is the call's own fact. A caller whose register held an
                // even address leaves the context as it was, as Ghidra does.
                if imp.computed_mode_targets.contains(&target) {
                    imp.contexts.push(NativeContext {
                        name: "LowBitCodeMode".into(),
                        address: target,
                        value: 1,
                    });
                }
            }
            imp.functions.push(NativeFunction {
                entry: target,
                name: format!("FUN_{target:08x}"),
                size: 1,
            });
        }
        for &(entry, destination) in &stubs {
            imp.thunks.push(NativeThunk {
                entry,
                destination,
                kind: romwright_model::ThunkKind::Direct,
                source: crate::native::THUNK_SOURCE,
            });
            imp.functions.push(NativeFunction {
                entry: destination,
                name: format!("FUN_{destination:08x}"),
                size: 1,
            });
        }
        // Table targets are seeded like computed-call targets: two or more
        // adjacent code pointers are stronger evidence than one relocation,
        // and the candidate veto would drop them for bytes a walk from a
        // since-retracted entry once decoded.
        let thumb_tables = imp.language.starts_with("ARM") && imp.code_holds_data;
        for &target in &tables_in_code {
            // An ARM table target came from an odd word: it is Thumb code.
            if thumb_tables {
                imp.contexts.push(NativeContext {
                    name: "LowBitCodeMode".into(),
                    address: target,
                    value: 1,
                });
            }
            imp.functions.push(NativeFunction {
                entry: target,
                name: format!("FUN_{target:08x}"),
                size: 1,
            });
        }
        imp.const_data_starts.extend(callbacks.iter().copied());
        let again = std::time::Instant::now();
        ran = discovery::discover_seeded(imp);
        phase(imp, "discovery", again);
    }
    if let Some(flow) = imp.flow.as_mut() {
        flow.rounds = rounds_run;
    }
    // Only a later round's walk reads it.
    imp.flow_cache = std::collections::BTreeMap::new();
    imp.flow_cache_walk_contexts = Vec::new();
    // A gap seed is forced, not validated (the candidate veto rejects gap
    // bytes a junk walk once decoded: Capcom lost 1.8 points of recall that
    // way), so one whose body never decoded (still the forced seed's
    // placeholder size of 1) is retracted here: undecodable
    // padding before `.init` (mipsel corpus 0x20a94) is not a function.
    if !imp.gap_starts.is_empty() {
        let gaps = std::mem::take(&mut imp.gap_starts);
        imp.functions.retain(|function| !(gaps.contains(&function.entry) && function.size <= 1));
    }
    // A pointer candidate the walk re-validates in a later round comes back
    // as a function after its table demoted it (dungeon_game: its `.rodata`
    // jump tables read as code pointers), and no round after the last table
    // demotes again. Table-seeded handlers are spared: Capcom's are also
    // computed-jump targets.
    if !imp.switch_tables.is_empty() {
        let spared = std::mem::take(&mut imp.table_seeds);
        switch_tables::demote_case_blocks_among(imp, Some(&spared));
        imp.table_seeds = spared;
    }
    // Whether a branch target is a function can only be answered once every
    // pass that creates one has run.
    let tail_started = std::time::Instant::now();
    discovery::record_branch_transfers(imp);
    // The instruction that reads the resolver slot only exists once reference
    // inference has run, so this rule reads its facts, not discovery's seeds.
    discovery::record_plt_header_flow(imp);
    // Last, so a rule that owns an instruction's override keeps it: Ghidra
    // skips an instruction that already carries one
    // (`SharedReturnAnalysisCmd.processFunctionJumpReferences`, :417-419).
    discovery::apply_shared_returns(imp);
    name_linkage_stubs(imp);
    apply_initializer_labels(imp);
    apply_pattern_labels(imp);
    // A word a reference landed on, whose bytes are a function's entry: the
    // references have to exist first, which is why this is not a loader pass
    // (m4-027).
    elf_pointers::confirm_referenced_pointers(imp);
    // Counted by the last reference round, which re-asks every range.
    if imp.references_refused > 0 {
        let refused = imp.references_refused;
        imp.diagnose(
            romwright_model::DiagnosticSeverity::Partial,
            "references",
            format!("{refused} function ranges the console could not decode for references"),
        );
    }
    phase(imp, "settle", tail_started);
    Ok(())
}

/// Gives a pattern-proven start the name its pattern carries.
///
/// The label comes from the `<funcstart label=...>` attribute of the pattern
/// that matched at that address in the pinned install, which the console
/// already uses to install a call fixup there. A body is required, so a label
/// never names bytes nothing proved, and only a generated name is replaced.
fn apply_pattern_labels(imp: &mut NativeImport) {
    let labels = std::mem::take(&mut imp.pattern_labels);
    for (address, label) in &labels {
        if let Some(function) = imp.functions.iter_mut().find(|function| {
            function.entry == *address && function.size > 1 && function.name.starts_with("FUN_")
        }) {
            function.name = label.clone();
        }
    }
    imp.pattern_labels = labels;
}

/// Gives an initializer-array target the name its array gives it.
///
/// Only a generated name is replaced. Ghidra does the same: a function that a
/// symbol already named keeps that name and merely becomes an entry point
/// (`ElfProgramBuilder.createEntryFunction:779-802`).
fn apply_initializer_labels(imp: &mut NativeImport) {
    let labels = std::mem::take(&mut imp.initializer_labels);
    for (target, label) in &labels {
        if let Some(function) = imp
            .functions
            .iter_mut()
            .find(|function| function.entry == *target && function.name.starts_with("FUN_"))
        {
            function.name = label.clone();
        }
    }
    imp.initializer_labels = labels;
}

/// Gives a stub the import name its own resolved slot proved.
///
/// The evidence is the one that produced the linkage thunk: the stub reads an
/// imported slot, and that slot names a symbol. Only a generated name is
/// replaced, so a name that came from a symbol or from the section table
/// stands. Stock Ghidra names the same stubs from the same relocation.
fn name_linkage_stubs(imp: &mut NativeImport) {
    if imp.thunks.is_empty() {
        return;
    }
    let named: std::collections::HashMap<u64, &str> = imp
        .externals
        .iter()
        .map(|(address, name)| (*address, name.as_str()))
        .collect();
    let proven: Vec<(u64, String)> = imp
        .thunks
        .iter()
        .filter(|thunk| thunk.kind == romwright_model::ThunkKind::Linkage)
        .filter_map(|thunk| {
            named
                .get(&thunk.entry)
                .or_else(|| named.get(&thunk.destination))
                .map(|name| (thunk.entry, (*name).to_owned()))
        })
        .collect();
    for (entry, name) in proven {
        if let Some(function) = imp
            .functions
            .iter_mut()
            .find(|function| function.entry == entry && function.name.starts_with("FUN_"))
        {
            function.name = name;
        }
    }
}

/// Loads `<binary>` natively and closes its seeds through SLEIGH flow.
pub fn load_native(binary: &Path) -> Result<NativeImport> {
    let data = std::fs::read(binary)
        .map_err(|e| ImportError::Bad(format!("{}: {e}", binary.display())))?;
    let mut images = load_container_with(
        binary,
        &data,
        true,
        None,
        None,
        &keys::KeyStore::empty(),
        &crate::session::RuntimeConfig::from_env(),
    )?;
    if images.len() != 1 {
        return Err(ImportError::Bad(
            "native load requires exactly one selected image; use Core for containers".into(),
        ));
    }
    Ok(images.pop().expect("one image").1)
}

/// MIPS calling code leaves a function's own address in `t9`, and every
/// position-independent load inside it is written relative to that register.
/// Ghidra assumes it: `MipsAddressAnalyzer` ships with "Assume T9 set to
/// Function entry" **on**, and sets `t9` to the entry address the first time
/// propagation meets it unset (`unknownValue`, 462-504). Without the
/// assumption a `lw` through `t9` stays symbolic -- stock prints
/// `PTR___gmon_start___000407a0` where we printed `in_t9 + 0x200d0`.
fn seed_mips_entry_register(imp: &mut NativeImport) {
    if !imp.language.starts_with("MIPS:") {
        return;
    }
    let seeds: Vec<NativeRegisterContext> = imp
        .functions
        .iter()
        .filter_map(|function| {
            let end = function.entry.checked_add(function.size.max(1))?;
            Some(NativeRegisterContext {
                start: function.entry,
                end,
                register: "t9".into(),
                value: function.entry,
            })
        })
        .collect();
    imp.register_contexts.extend(seeds);
}
/// Small-data-area bases for PowerPC EABI, seeded as loader-established
/// register ranges so every consumer takes them through the register
/// channel: the console's reference pass folds `r13`-/`r2`-relative access
/// during discovery (data xrefs to SDA globals), and the store funnels one
/// point per range into decode contexts for the worker's tracked sets.
/// This mirrors `PowerPC_ElfRelocationContext.getBaseOffset`: the
/// `_SDA_BASE_`/`_SDA2_BASE_` ABS symbol when the image declares one, else
/// the start of the `.sdata`/`.sbss` (respectively `.sdata2`/`.sbss2`)
/// range -- the midpoint when that range exceeds 15 bits. Values are
/// image-global; one range per function matches the `t9` seed shape.
/// Register values must never ride `imp.contexts`: the console and the
/// raw-SLEIGH spec resolve those rows as context *variables*, and a real
/// register is rejected by both.
pub(crate) fn seed_ppc_sda_registers(
    machine: u16,
    abs: &[(String, u64)],
    sections: &[ElfSection],
    functions: &[NativeFunction],
    register_contexts: &mut Vec<NativeRegisterContext>,
) {
    // EM_PPC (20) and EM_PPC64 (21): `PowerPC:BE:32:default` and 64-bit
    // siblings, the only loaders that reach this seeder.
    if machine != 20 && machine != 21 {
        return;
    }
    let find = |names: &[&str]| {
        abs.iter()
            .find_map(|(name, value)| names.contains(&name.as_str()).then_some(*value))
    };
    // Least start of the named blocks, or nothing when none is present.
    // Past fifteen bits half the range no longer reaches both ends from
    // one base, so the aligned midpoint becomes the base instead.
    let block_base = |names: &[&str]| {
        let mut first = u64::MAX;
        let mut last = 0u64;
        for section in sections
            .iter()
            .filter(|section| names.contains(&section.name.as_str()))
        {
            first = first.min(section.addr);
            last = last.max(section.addr.saturating_add(section.size));
        }
        if first == u64::MAX {
            return None;
        }
        let span = last.saturating_sub(first);
        if span > 0x7fff {
            Some(first.wrapping_add((span / 2) & !0x0f))
        } else {
            Some(first)
        }
    };
    // A zero ABS is the linker leaving the slot: stock only establishes
    // a base while processing an SDA-relative relocation, so zero falls
    // through to sections (and to nothing when those are absent).
    let abs_base = |names: &[&str]| find(names).filter(|value| *value != 0);
    // Section convention is 32-bit EABI only: on 64-bit `r2` is the TOC
    // pointer and `r13` the thread pointer, and `.sdata` commonly exists.
    // A declared ABS symbol still wins at any width.
    let conventional = |names: &[&str]| (machine == 20).then(|| block_base(names)).flatten();
    let r13 = abs_base(&["_SDA_BASE_"]).or_else(|| conventional(&[".sdata", ".sbss"]));
    let r2 = abs_base(&["_SDA2_BASE_"]).or_else(|| conventional(&[".sdata2", ".sbss2"]));
    for (register, value) in [("r13", r13), ("r2", r2)]
        .into_iter()
        .filter_map(|(r, v)| v.map(|v| (r, v)))
    {
        register_contexts.extend(functions.iter().filter_map(|function| {
            Some(NativeRegisterContext {
                start: function.entry,
                end: function.entry.checked_add(function.size.max(1))?,
                register: register.into(),
                value,
            })
        }));
    }
}

/// Expand SDA register ranges at every recovered function entry. The console
/// consumes the full ranges; the worker's tracked-register callback is keyed
/// by entry, including functions discovered after the loader established them.
pub(crate) fn sda_decode_points(
    register_contexts: &[NativeRegisterContext],
    functions: &[NativeFunction],
) -> Vec<(u64, String, u64)> {
    let mut entries: Vec<_> = functions.iter().map(|function| function.entry).collect();
    entries.sort_unstable();
    entries.dedup();
    let mut points = std::collections::BTreeMap::new();
    for context in register_contexts.iter()
        .filter(|context| context.register == "r13" || context.register == "r2")
    {
        let first = entries.partition_point(|entry| *entry < context.start);
        for &entry in entries[first..].iter().take_while(|entry| **entry < context.end) {
            points.insert((entry, context.register.as_str()), context.value);
        }
    }
    points.into_iter().map(|((entry, register), value)| (entry, register.to_string(), value)).collect()
}

/// Decoded/function extents indexed for containment tests: a linear scan
/// per candidate is O(extents) each, which never converges when both
/// number in the hundreds of thousands. Any extent covering an address
/// starts within the widest extent before it, so the window query answers
/// exactly what the scan did.
pub struct ExtentIndex {
    starts: std::collections::BTreeMap<u64, u64>,
    max_len: u64,
}

impl ExtentIndex {
    pub fn build(extents: &[(u64, u64)]) -> Self {
        let mut starts = std::collections::BTreeMap::new();
        let mut max_len = 0u64;
        for &(start, size) in extents {
            // Same start decoded twice keeps the widest: one start means
            // the widest covers the union exactly.
            starts
                .entry(start)
                .and_modify(|kept: &mut u64| *kept = (*kept).max(size))
                .or_insert(size);
            max_len = max_len.max(size);
        }
        ExtentIndex { starts, max_len }
    }
    pub fn insert(&mut self, start: u64, size: u64) {
        self.starts
            .entry(start)
            .and_modify(|kept: &mut u64| *kept = (*kept).max(size))
            .or_insert(size);
        self.max_len = self.max_len.max(size);
    }

    pub fn contains(&self, address: u64) -> bool {
        let from = address.saturating_sub(self.max_len);
        self.starts
            .range(from..address)
            .any(|(&start, &size)| address - start < size)
    }
}

/// Context for candidate pre-pass confirmation.
pub struct CandidateFilterContext<'a> {
    pub mappings: &'a [Mapping],
    pub known_extents: ExtentIndex,
    pub initial_seeds: &'a HashSet<u64>,
}

/// Rejects non-code and owned bytes before requesting SLEIGH evidence.
pub fn candidate_address_is_valid(cand: u64, ctx: &CandidateFilterContext) -> bool {
    ctx.mappings.iter().any(|mapping| {
        mapping.flags & 0x4 != 0 && cand >= mapping.vaddr && cand - mapping.vaddr < mapping.size
    }) && !ctx.known_extents.contains(cand)
}

/// Confirms an address-qualified candidate without copying its flow response.
pub fn candidate_flow_is_valid(
    cand: u64,
    ctx: &CandidateFilterContext,
    info: &crate::native_runtime::FlowResult,
) -> bool {
    use crate::native_runtime::FlowKind;
    info.address == cand
        && info.length != 0
        && !matches!(info.kind, FlowKind::Bad | FlowKind::Unimpl)
        && (info.kind != FlowKind::Fallthrough
            || !info
                .fallthrough
                .is_some_and(|fall| ctx.initial_seeds.contains(&fall)))
}

#[cfg(test)]
mod tests;
