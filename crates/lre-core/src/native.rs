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
use lre_db::ProjectDb;
use std::collections::HashSet;
use std::path::Path;
mod gba;
mod n64;
mod nds;
mod psx;
pub(crate) mod dol;
mod discovery;
mod features;
mod nso;
pub(crate) mod vsa;
mod elf_exception;
mod elf_pointers;
mod elf_unwind;
mod elf_image;
mod pe_roots;
mod pe_unwind;
mod strings;
pub(crate) mod nonreturn;
use lre_model::{
    FunctionRow, MemoryRegion, Provenance, ProgramSummary, XrefRow,
};
/// Errors from a native import.
#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error("{0}")]
    Bad(String),
    #[error("store: {0}")]
    Store(#[from] lre_db::DbError),
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

    pub fn with_provenance(from: u64, to: u64, kind: impl Into<String>, provenance: impl Into<String>) -> Self {
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
    pub address: lre_model::Address,
    pub size: u64,
    pub strings: Vec<lre_model::StringRow>,
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
    pub kind: lre_model::ThunkKind,
    /// The rule that proved this transfer; each becomes its own provenance so
    /// a consumer can tell flow evidence from an ABI-declared slot.
    pub source: &'static str,
}

/// One instruction as the walk decoded it, addresses aside from its own
/// direct branch target left out: the shape a diff can compare.
#[derive(Clone, Copy, Debug)]
pub struct FlowShape {
    pub address: u64,
    pub length: u8,
    pub kind: crate::native_runtime::FlowKind,
    pub conditional: bool,
    pub target: Option<u64>,
}

/// Parsed image and transient loader/discovery evidence.
#[derive(Debug, Default)]
pub struct NativeImport {
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
    /// Dispatches value-set analysis resolved, and refused, over every
    /// round: the measurement that says whether the decompiler is still
    /// needed in the switch round at all.
    pub switch_vsa_resolved: usize,
    pub switch_vsa_refused: usize,
    /// The decoded shape of every instruction the walk read: address, byte
    /// length, flow kind, whether the flow is conditional, and the single
    /// direct target when it has one. This is what the structural features
    /// (`lre_model::FunctionFeatureRow`) are counted from; a switch jump's
    /// many targets are not here, they are the `switch_tables` fact.
    pub flow_shapes: Vec<FlowShape>,
    /// Computed-call targets the propagation reached with the low address
    /// bit set, aligned: on a low-bit-mode language each is decoded in the
    /// alternate instruction set from then on.
    pub computed_mode_targets: Vec<u64>,
    /// The stack frame the propagation recovered per function: every slot a
    /// load or store reached through the stack pointer, merged where
    /// accesses overlap, named as Ghidra's stack analyzer names them.
    pub stack_variables: Vec<lre_model::StackVariableRow>,
    /// Initializer-array words, with their width: each holds a code address,
    /// proved by the array it belongs to.
    pub initializer_slots: Vec<(u64, u64)>,
    /// Referenced words whose bytes are a function's entry, with their width.
    pub pointer_slots: Vec<(u64, u64)>,
    /// Words inside a `.got` section, with their width.
    pub got_slots: Vec<(u64, u64)>,
    /// Addresses an ELF `OBJECT` symbol declares, with the size it declares.
    pub object_sizes: Vec<(u64, u64)>,
    /// Linkage slots whose relocation names a function, with their width.
    pub function_slots: Vec<(u64, u64)>,
    /// Entries whose name came from the image's own symbol table. Ghidra's
    /// loader leaves such a function's name alone and only marks it an entry
    /// point (`ElfProgramBuilder.createEntryFunction`, :790-794).
    pub symbol_named: Vec<u64>,
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
    /// Loader-declared initializer entry points, also requiring valid flow.
    pub initializer_candidates: Vec<u64>,
    /// Names an initializer array gives its targets: the array names the
    /// prefix, the slot's position names the index.
    pub initializer_labels: Vec<(u64, String)>,
    /// Names the pinned patterns give the starts they proved.
    pub pattern_labels: Vec<(u64, String)>,
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
    pub phases: Vec<lre_model::PhaseTiming>,
    /// Regions the platform defines but the image does not contain, such as
    /// a console's RAM and IO windows. Declared for the store; never given
    /// invented bytes, so discovery cannot walk into them.
    pub declared_regions: Vec<DeclaredRegion>,
    /// Names for the leading mappings, when the platform names them. A
    /// cartridge has one window called ROM, not one called `0`.
    pub mapping_names: Vec<String>,
    /// Console request accounting for the flow phase, when it ran.
    pub flow: Option<lre_model::FlowStats>,
    /// Pattern accounting for the pattern phase, when it ran.
    pub patterns_seen: Option<lre_model::PatternStats>,
    /// Reference ranges the console refused, counted so the loss is reported.
    pub references_refused: u64,
    /// Processor mode values the image itself declares, applied to a console
    /// before anything decodes: ARM marks Thumb code with the low bit of a
    /// function address and with `$t`/`$a` mapping symbols
    /// (`ARM_ElfExtension.creatingFunction`, 116-140, and
    /// `evaluateElfSymbol`, 142-209).
    pub contexts: Vec<NativeContext>,
    /// Why console-driven discovery was not used, when it was not. A silent
    /// fallback to pointer-only seeds is how a MIPS image came back with a
    /// third of its functions and no complaint (m11-002).
    pub discovery_note: Option<String>,
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

// ---- ELF32 ----------------------------------------------------------------

/// ELF32 section parse (40-byte Shdr), either endianness.
fn parse_elf32_sections(data: &[u8], be: bool) -> Result<(Vec<ElfSection>, Vec<u8>)> {
    let rd32 = |o: usize| -> Result<u32> {
        if be {
            u32_be_at(data, o)
        } else {
            u32_at(data, o)
        }
    };
    let rd16 = |o: usize| -> Result<u16> {
        if be {
            u16_be_at(data, o)
        } else {
            u16_at(data, o)
        }
    };
    let shentsize = rd16(46)? as usize;
    let shnum = rd16(48)? as usize;
    let shoff = rd32(32)? as usize;
    let shstrndx = rd16(50)? as usize;
    if shoff == 0 || shnum == 0 {
        return err("ELF32 has no section headers");
    }
    let mut sections = Vec::new();
    for i in 0..shnum {
        let hdr = shoff + i * shentsize;
        if hdr + 40 > data.len() {
            break;
        }
        sections.push(ElfSection {
            name: String::new(),
            typ: rd32(hdr + 4)?,
            flags: rd32(hdr + 8)? as u64,
            addr: rd32(hdr + 12)? as u64,
            off: rd32(hdr + 16)? as u64,
            size: rd32(hdr + 20)? as u64,
            link: rd32(hdr + 24)?,
            entry_size: rd32(hdr + 36)? as u64,
        });
    }
    // shstrtab content for names.
    let mut shstr = Vec::new();
    if let Some(s) = sections.get(shstrndx) {
        shstr = data
            .get(s.off as usize..s.off as usize + s.size as usize)
            .unwrap_or(&[])
            .to_vec();
    }
    // Names: re-walk with stored offsets (Shdr sh_name at +0).
    let mut name_offs = Vec::new();
    for i in 0..sections.len() {
        name_offs.push(rd32(shoff + i * shentsize)? as usize);
    }
    for (section, name_off) in sections.iter_mut().zip(name_offs) {
        section.name = shstr
            .get(name_off..)
            .and_then(|r| r.split(|c| *c == 0).next())
            .map(|r| String::from_utf8_lossy(r).into_owned())
            .unwrap_or_default();
    }
    Ok((sections, shstr))
}

/// ELF32 import (Phase 4 target: GameCube PowerPC BE, PS2 MIPS BE).
/// Symbols use 16-byte Elf32_Sym entries. Relative relocations, pointers,
/// unwind indexes and linkage metadata share the ELF64 implementation.
fn import_elf32(data: &[u8], be: bool) -> Result<NativeImport> {
    let rd32 = |o: usize| -> Result<u32> {
        if be {
            u32_be_at(data, o)
        } else {
            u32_at(data, o)
        }
    };
    let rd16 = |o: usize| -> Result<u16> {
        if be {
            u16_be_at(data, o)
        } else {
            u16_at(data, o)
        }
    };
    let elf_machine = crate::opinion::ElfMachine {
        machine: rd16(18)?,
        flags: rd32(36)?,
        bits: 32,
        big_endian: be,
    };
    let entry = rd32(24)? as u64;
    let process_entry = elf_process_entry(data, entry, rd16(16)?);
    let (mut sections, _shstr) = parse_elf32_sections(data, be)?;

    let mut mappings = Vec::new();
    for s in sections.iter() {
        if s.flags & 0x2 == 0 || s.size == 0 {
            continue;
        }
        let b = if s.typ == 8 { &[] } else {
            data.get(s.off as usize..s.off as usize + s.size as usize).unwrap_or(&[])
        };
        mappings.push(Mapping {
            vaddr: s.addr,
            size: s.size,
            file_off: s.off,
            flags: s.flags,
            bytes: b.to_vec(),
        });
    }
    if mappings.is_empty() {
        return err("ELF has no allocated sections");
    }

    let mut functions = Vec::new();
    let mut symbol_functions: std::collections::HashMap<u64, (u8, String, u64)> =
        std::collections::HashMap::new();
    let mut externals = Vec::new();
    let mut object_sizes: Vec<(u64, u64)> = Vec::new();
    let mut contexts: Vec<NativeContext> = Vec::new();
    // SHT_SYMTAB (2) and SHT_DYNSYM (11): 16-byte Elf32_Sym.
    for s in sections.iter().filter(|s| s.typ == 2 || s.typ == 11) {
        let strtab = sections
            .get(s.link as usize)
            .map(|t| {
                data.get(t.off as usize..t.off as usize + t.size as usize)
                    .unwrap_or(&[])
                    .to_vec()
            })
            .unwrap_or_default();
        let count = s.size as usize / 16;
        for i in 0..count {
            let hdr = s.off as usize + i * 16;
            if hdr + 16 > data.len() {
                break;
            }
            let name_off = rd32(hdr)? as usize;
            let info = data[hdr + 12];
            let shndx = rd16(hdr + 14)?;
            let value = rd32(hdr + 4)? as u64;
            let size = rd32(hdr + 8)? as u64;
            let name = strtab
                .get(name_off..)
                .and_then(|r| r.split(|c| *c == 0).next())
                .map(|r| String::from_utf8_lossy(r).into_owned())
                .unwrap_or_default();
            let typ = info & 0xf;
            // ARM tags Thumb code with the low bit of a function's address and
            // with `$t`/`$a` mapping symbols. The address is the aligned one;
            // the bit is a mode declaration, not part of it
            // (`ARM_ElfExtension`, 116-209).
            let arm = elf_machine.machine == 0x28;
            if arm {
                if name == "$t" || name.starts_with("$t.") {
                    contexts.push(NativeContext { name: "TMode".into(), address: value, value: 1 });
                } else if name == "$a" || name.starts_with("$a.") {
                    contexts.push(NativeContext { name: "TMode".into(), address: value, value: 0 });
                }
            }
            let (value, thumb) = if arm && typ == 2 && value & 1 != 0 {
                (value & !1, true)
            } else {
                (value, false)
            };
            if typ == 2 && shndx != 0 && value != 0 && !name.is_empty() {
                if thumb {
                    contexts.push(NativeContext { name: "TMode".into(), address: value, value: 1 });
                }
                let rank = symbol_rank(info, &name);
                let slot = symbol_functions.entry(value).or_insert((rank, name.clone(), size.max(1)));
                if rank < slot.0 {
                    *slot = (rank, name.clone(), size.max(1));
                }
            }
            // STT_OBJECT with a size and an address: Ghidra defines undefined
            // data of exactly that size there
            // (`ElfProgramBuilder.processSymbols`, :1703-1706, and
            // `allocateUndefinedSymbolData`, :1358-1381).
            if typ == 1 && shndx != 0 && value != 0 && size > 0 {
                object_sizes.push((value, size));
            }
            if shndx == 0 && !name.is_empty() {
                externals.push((0, name.clone()));
            }
        }
    }
    let symbol_named: Vec<u64> = symbol_functions.keys().copied().collect();
    functions.extend(
        symbol_functions
            .into_iter()
            .map(|(entry, (_, name, size))| NativeFunction { entry, name, size }),
    );
    collect_elf_section_starts(&sections, &mut functions);
    functions.sort_by_key(|f| f.entry);
    let mut import = NativeImport {
        process_entry,
        symbol_named,
        format: "elf32".into(),
        elf_machine: Some(elf_machine),
        mappings,
        functions,
        xrefs: Vec::new(),
        externals,
        object_sizes,
        contexts,
        ..Default::default()
    };
    elf_image::prepare(data, &mut sections, &mut import, 4, be)?;
    elf_pointers::collect(data, &sections, &mut import, 4, be)?;
    elf_pointers::collect_got(data, &sections, &mut import, 4, be)?;
    elf_unwind::collect(data, &sections, &mut import, 4, be);
    elf_exception::collect(data, &sections, &mut import, 4, be);
    Ok(import)
}

// ---- ELF64 ----------------------------------------------------------------

struct ElfSection {
    name: String,
    typ: u32,
    flags: u64,
    addr: u64,
    off: u64,
    size: u64,
    link: u32,
    entry_size: u64,
}

fn collect_elf_section_starts(sections: &[ElfSection], functions: &mut Vec<NativeFunction>) {
    for s in sections {
        if s.flags & 4 == 0 || s.size == 0 || s.addr == 0 || functions.iter().any(|f| f.entry == s.addr) {
            continue;
        }
        let (name, size) = match s.name.as_str() {
            ".init" => ("_init", s.size),
            ".fini" => ("_fini", s.size),
            ".plt" => ("_plt", 1),
            _ => continue,
        };
        functions.push(NativeFunction { entry: s.addr, name: name.into(), size });
    }
}

fn parse_elf_sections(data: &[u8]) -> Result<(Vec<ElfSection>, Vec<u8>)> {
    let shentsize = u16_at(data, 58)? as usize;
    let shnum = u16_at(data, 60)? as usize;
    let shoff = u64_at(data, 40)? as usize;
    let shstrndx = u16_at(data, 62)? as usize;
    let mut sections = Vec::new();
    for i in 0..shnum {
        let hdr = shoff + i * shentsize;
        sections.push(ElfSection {
            name: String::new(),
            typ: u32_at(data, hdr + 4)?,
            flags: u64_at(data, hdr + 8)?,
            addr: u64_at(data, hdr + 16)?,
            off: u64_at(data, hdr + 24)?,
            size: u64_at(data, hdr + 32)?,
            link: u32_at(data, hdr + 40)?,
            entry_size: u64_at(data, hdr + 56)?,
        });
    }
    // fetch shstrtab content
    let shstr = {
        let hdr = shoff + shstrndx * shentsize;
        let off = u64_at(data, hdr + 24)? as usize;
        let sz = u64_at(data, hdr + 32)? as usize;
        data.get(off..off + sz).unwrap_or(&[]).to_vec()
    };
    // names assigned from shstrtab after fetching; store raw offsets
    let mut name_offs = Vec::new();
    for i in 0..shnum {
        let hdr = shoff + i * shentsize;
        name_offs.push(u32_at(data, hdr)? as usize);
    }
    for (s, no) in sections.iter_mut().zip(name_offs) {
        s.name = shstr
            .get(no..)
            .and_then(|r| r.split(|c| *c == 0).next())
            .map(|r| String::from_utf8_lossy(r).into_owned())
            .unwrap_or_default();
    }
    Ok((sections, shstr))
}

/// Ghidra's rule, verbatim: `e_entry` of an executable (`ET_EXEC`) or shared
/// object (`ET_DYN`) whose `e_ident[EI_OSABI]` is `ELFOSABI_LINUX` or
/// `ELFOSABI_NONE` -- the latter meaning "no ABI-specific extensions", which
/// also stands for unspecified (`ElfProgramBuilder.processEntryPoints`,
/// :655-673, with `ElfConstants`).
fn elf_process_entry(data: &[u8], entry: u64, e_type: u16) -> Option<u64> {
    let linux_or_unspecified = matches!(data.get(7), Some(0 | 3));
    (entry != 0 && matches!(e_type, 2 | 3) && linux_or_unspecified).then_some(entry)
}


/// ELF64 parse. Returns (mappings, functions from symtab + entry, externals).
/// ELF symbol preference for one address: exported before local, and an
/// unversioned name before its `name@@VERSION` alias. Ghidra's analyzers read
/// the primary symbol, so an internal alias must not shadow the public name.
fn symbol_rank(info: u8, name: &str) -> u8 {
    let local = info >> 4 == 0;
    let versioned = name.contains('@');
    (u8::from(local) << 1) | u8::from(versioned)
}

pub fn import_elf(data: &[u8]) -> Result<NativeImport> {
    if data.get(0..4) != Some(b"\x7fELF") {
        return err("not an ELF");
    }
    // A magic-only (or truncated) file must error, not panic on indexing.
    if data.len() < 6 {
        return err("truncated ELF header");
    }
    if data[4] == 1 {
        // ELF32: GameCube/PS2-class images (PowerPC/MIPS, either endian).
        return import_elf32(data, data[5] == 2);
    }
    if data[4] != 2 || data[5] != 1 {
        return err("ELF64 little-endian expected");
    }
    let elf_machine = crate::opinion::ElfMachine {
        machine: u16_at(data, 18)?,
        flags: u32_at(data, 48)?,
        bits: 64,
        big_endian: false,
    };
    let entry = u64_at(data, 24)?;
    let process_entry = elf_process_entry(data, entry, u16_at(data, 16)?);
    let (mut sections, _shstr) = parse_elf_sections(data)?;

    // Mappings: SHF_ALLOC sections carrying file bytes (SHT_PROGBITS etc).
    let mut mappings = Vec::new();
    for s in sections.iter() {
        if s.flags & 0x2 == 0 || s.size == 0 {
            continue;
        }
        let b = if s.typ == 8 { &[] } else {
            data.get(s.off as usize..s.off as usize + s.size as usize).unwrap_or(&[])
        };
        mappings.push(Mapping {
            vaddr: s.addr,
            size: s.size,
            file_off: s.off,
            flags: s.flags,
            bytes: b.to_vec(),
        });
    }
    if mappings.is_empty() {
        return err("ELF has no allocated sections");
    }

    // Symbols: the SHT_SYMTAB (type 2) and its sh_link strtab.
    let mut functions = Vec::new();
    let mut symbol_functions: std::collections::HashMap<u64, (u8, String, u64)> =
        std::collections::HashMap::new();
    let mut externals = Vec::new();
    let mut object_sizes: Vec<(u64, u64)> = Vec::new();
    for s in sections.iter() {
        if s.typ != 2 {
            continue;
        }
        let strtab = sections
            .get(s.link as usize)
            .map(|t| {
                data.get(t.off as usize..t.off as usize + t.size as usize)
                    .unwrap_or(&[])
                    .to_vec()
            })
            .unwrap_or_default();
        let count = s.size as usize / 24;
        for i in 0..count {
            let hdr = s.off as usize + i * 24;
            if hdr + 24 > data.len() {
                break;
            }
            let name_off = u32_at(data, hdr)? as usize;
            let info = data[hdr + 4];
            // ELF64_Sym: st_name(0,4) st_info(4) st_other(5) st_shndx(6,2)
            // st_value(8,8) st_size(16,8)
            let value = u64_at(data, hdr + 8)?;
            let size = u64_at(data, hdr + 16)?;
            let name = strtab
                .get(name_off..)
                .and_then(|r| r.split(|c| *c == 0).next())
                .map(|r| String::from_utf8_lossy(r).into_owned())
                .unwrap_or_default();
            let typ = info & 0xf;
            if typ == 2 && value != 0 && !name.is_empty() {
                let rank = symbol_rank(info, &name);
                let slot = symbol_functions.entry(value).or_insert((rank, name.clone(), size.max(1)));
                if rank < slot.0 {
                    *slot = (rank, name.clone(), size.max(1));
                }
            }
            if typ == 1 && value != 0 && size > 0 {
                object_sizes.push((value, size));
            }
            if value == 0 && typ == 1 && !name.is_empty() {
                externals.push((0, name));
            }
        }
    }
    // Undefined dynamic symbols; elf_image collects their loaded relocation slots.
    for s in sections.iter().filter(|s| s.typ == 11) {
        let strtab = sections
            .get(s.link as usize)
            .map(|t| {
                data.get(t.off as usize..t.off as usize + t.size as usize)
                    .unwrap_or(&[])
                    .to_vec()
            })
            .unwrap_or_default();
        let count = s.size as usize / 24;
        for i in 0..count {
            let hdr = s.off as usize + i * 24;
            if hdr + 24 > data.len() {
                break;
            }
            let name_off = u32_at(data, hdr)? as usize;
            let info = data[hdr + 4];
            let shndx = u16_at(data, hdr + 6)?;
            let value = u64_at(data, hdr + 8)?;
            let size = u64_at(data, hdr + 16)?;
            let name = strtab
                .get(name_off..)
                .and_then(|r| r.split(|c| *c == 0).next())
                .map(|r| String::from_utf8_lossy(r).into_owned())
                .unwrap_or_default();
            // A copy-relocated object is *defined* in the executable's own
            // dynamic table, with the size the library declares.
            if info & 0xf == 1 && shndx != 0 && value != 0 && size > 0 {
                object_sizes.push((value, size));
            }
            if !name.is_empty() && shndx == 0 {
                externals.push((0, name));
            }
        }
    }
    let symbol_named: Vec<u64> = symbol_functions.keys().copied().collect();
    functions.extend(
        symbol_functions
            .into_iter()
            .map(|(entry, (_, name, size))| NativeFunction { entry, name, size }),
    );
    collect_elf_section_starts(&sections, &mut functions);
    functions.sort_by_key(|f| f.entry);
    functions.dedup_by_key(|f| f.entry);
    let mut import = NativeImport {
        mappings,
        functions,
        externals,
        object_sizes,
        process_entry,
        symbol_named,
        format: "ELF".into(),
        elf_machine: Some(elf_machine),
        ..Default::default()
    };
    elf_image::prepare(data, &mut sections, &mut import, 8, false)?;
    elf_pointers::collect(data, &sections, &mut import, 8, false)?;
    elf_pointers::collect_got(data, &sections, &mut import, 8, false)?;
    elf_unwind::collect(data, &sections, &mut import, 8, false);
    elf_exception::collect(data, &sections, &mut import, 8, false);
    Ok(import)
}

pub fn import_pe(data: &[u8]) -> Result<NativeImport> {
    if data.get(0..2) != Some(b"MZ") {
        return err("not a PE");
    }
    let pe_off = u32_at(data, 0x3c)? as usize;
    if data.get(pe_off..pe_off + 4) != Some(b"PE\0\0") {
        return err("missing PE signature");
    }
    let machine = u16_at(data, pe_off + 4)?;
    let (is_64, language) = match machine {
        0x8664 => (true, "x86:LE:64:default"),
        0x014c => (false, "x86:LE:32:default"),
        other => return err(format!("unsupported PE machine {other:#x} (AMD64 0x8664 or i386 0x14c expected)")),
    };
    let num_sections = u16_at(data, pe_off + 6)? as usize;
    let opt_size = u16_at(data, pe_off + 20)? as usize;
    let opt = pe_off + 24;
    if opt + opt_size > data.len() {
        return err("PE optional header truncated");
    }
    let magic = u16_at(data, opt)?;

    // Exception directory (index 3) carries RUNTIME_FUNCTION bounds, but only
    // the AMD64 records have the layout the unwind pass reads.
    let (entry_rva, image_base, reloc_dir_offset, unwind_dir_offset, export_dir_offset,
         import_dir_offset, tls_dir_offset) = match (machine, magic) {
        (0x8664, 0x20b) => {
            if opt_size < 112 {
                return err(format!("PE32+ optional header size {opt_size} too small (>= 112 expected)"));
            }
            let entry_rva = u32_at(data, opt + 16)? as u64;
            let image_base = u64_at(data, opt + 24)?;
            let num_rva_sizes = u32_at(data, opt + 108)? as usize;
            let reloc_offset = if num_rva_sizes > 5 && opt_size >= 160 {
                Some(opt + 152)
            } else {
                None
            };
            let unwind_offset = if num_rva_sizes > 3 && opt_size >= 144 {
                Some(opt + 136)
            } else {
                None
            };
            let export_offset = (num_rva_sizes > 0 && opt_size >= 120).then_some(opt + 112);
            let import_offset = (num_rva_sizes > 1 && opt_size >= 128).then_some(opt + 120);
            let tls_offset = (num_rva_sizes > 9 && opt_size >= 192).then_some(opt + 184);
            (entry_rva, image_base, reloc_offset, unwind_offset, export_offset,
             import_offset, tls_offset)
        }
        (0x014c, 0x10b) => {
            if opt_size < 96 {
                return err(format!("PE32 optional header size {opt_size} too small (>= 96 expected)"));
            }
            let entry_rva = u32_at(data, opt + 16)? as u64;
            let image_base = u32_at(data, opt + 28)? as u64;
            let num_rva_sizes = u32_at(data, opt + 92)? as usize;
            let reloc_offset = if num_rva_sizes > 5 && opt_size >= 144 {
                Some(opt + 136)
            } else {
                None
            };
            let export_offset = (num_rva_sizes > 0 && opt_size >= 104).then_some(opt + 96);
            let import_offset = (num_rva_sizes > 1 && opt_size >= 112).then_some(opt + 104);
            let tls_offset = (num_rva_sizes > 9 && opt_size >= 176).then_some(opt + 168);
            (entry_rva, image_base, reloc_offset, None, export_offset, import_offset,
             tls_offset)
        }
        (0x8664, other) => {
            return err(format!("PE AMD64 requires PE32+ optional header magic 0x20b, got {other:#x}"));
        }
        (0x014c, other) => {
            return err(format!("PE i386 requires PE32 optional header magic 0x10b, got {other:#x}"));
        }
        (other, _) => {
            return err(format!("unsupported PE machine {other:#x} (AMD64 0x8664 or i386 0x14c expected)"));
        }
    };
    let sec_table = opt + opt_size;
    if sec_table + num_sections * 40 > data.len() {
        return err("PE section table truncated");
    }
    let mut mappings = Vec::new();
    // The unwind pass needs the same section spans, so they share one shape.
    use pe_unwind::Span;
    let mut raw_sections = Vec::new();
    for i in 0..num_sections {
        let o = sec_table + i * 40;
        let vaddr = u32_at(data, o + 12)? as u64;
        let size = u32_at(data, o + 8)? as usize;
        let raw = u32_at(data, o + 20)? as usize;
        let raw_size = u32_at(data, o + 16)? as usize;
        if size == 0 {
            continue;
        }
        raw_sections.push(Span {
            vaddr,
            vsize: size,
            raw_off: raw,
        });
        let mut bytes = data.get(raw..raw + raw_size).unwrap_or(&[]).to_vec();
        bytes.resize(size, 0);
        let sflags = u32_at(data, o + 36)? as u64; // section characteristics
        let flags = (u64::from(sflags & 0x20000000 != 0) << 2)
            | (u64::from(sflags & 0x40000000 != 0) << 1)
            | u64::from(sflags & 0x80000000 != 0);
        mappings.push(Mapping {
            vaddr: image_base + vaddr,
            size: size as u64,
            file_off: raw as u64,
            flags,
            bytes,
        });
    }
    if mappings.is_empty() {
        return err("PE has no sections");
    }
    let mut functions = vec![NativeFunction {
        entry: image_base + entry_rva,
        name: "_entry".into(),
        size: 1,
    }];

    // Parse base relocations from Data Directory 5 (.reloc)
    let (reloc_dir_rva, reloc_dir_size) = if let Some(offset) = reloc_dir_offset {
        let rva = u32_at(data, offset).unwrap_or(0) as u64;
        let size = u32_at(data, offset + 4).unwrap_or(0) as usize;
        (rva, size)
    } else {
        (0, 0)
    };

    let reloc_raw_data: Option<&[u8]> = if reloc_dir_rva > 0 && reloc_dir_size > 0 {
        raw_sections.iter().find_map(|s| {
            if reloc_dir_rva >= s.vaddr && reloc_dir_rva < s.vaddr + s.vsize as u64 {
                let off = s.raw_off + (reloc_dir_rva - s.vaddr) as usize;
                data.get(off..off + reloc_dir_size)
            } else {
                None
            }
        })
    } else {
        None
    };

    let mut reloc_candidates: Vec<u64> = Vec::new();
    let mut xrefs: Vec<NativeXref> = Vec::new();
    if let Some(reloc_bytes) = reloc_raw_data {
        let mut pos = 0usize;
        while pos + 8 <= reloc_bytes.len() {
            let page_rva = match u32_at(reloc_bytes, pos) {
                Ok(v) => v as u64,
                Err(_) => break,
            };
            let block_size = match u32_at(reloc_bytes, pos + 4) {
                Ok(v) => v as usize,
                Err(_) => break,
            };
            if block_size < 8 || pos + block_size > reloc_bytes.len() {
                break;
            }
            let entry_count = (block_size - 8) / 2;
            for i in 0..entry_count {
                let entry = match u16_at(reloc_bytes, pos + 8 + i * 2) {
                    Ok(v) => v,
                    Err(_) => break,
                };
                let r_type = entry >> 12;
                let r_offset = (entry & 0x0fff) as u64;
                let target_rva = page_rva + r_offset;
                let loc = image_base + target_rva;

                if let Some(m) = mappings.iter().find(|m| loc >= m.vaddr && loc < m.vaddr + m.size) {
                    let off = (loc - m.vaddr) as usize;
                    match r_type {
                        10 => { // IMAGE_REL_BASED_DIR64
                            if off + 8 <= m.bytes.len() {
                                let ptr = u64::from_le_bytes(m.bytes[off..off + 8].try_into().unwrap());
                                let in_mem = mappings.iter().any(|cm| ptr >= cm.vaddr && ptr < cm.vaddr + cm.size);
                                if in_mem {
                                    xrefs.push(NativeXref::with_provenance(
                                        loc,
                                        ptr,
                                        "DATA",
                                        "native-import:pe-reloc",
                                    ));
                                }
                                let in_code = mappings.iter().any(|cm| {
                                    cm.flags & 0x4 != 0 && ptr >= cm.vaddr && ptr < cm.vaddr + cm.size
                                });
                                if in_code {
                                    reloc_candidates.push(ptr);
                                }
                            }
                        }
                        3 => { // IMAGE_REL_BASED_HIGHLOW
                            if off + 4 <= m.bytes.len() {
                                let ptr = u32::from_le_bytes(m.bytes[off..off + 4].try_into().unwrap()) as u64;
                                let in_mem = mappings.iter().any(|cm| ptr >= cm.vaddr && ptr < cm.vaddr + cm.size);
                                if in_mem {
                                    xrefs.push(NativeXref::with_provenance(
                                        loc,
                                        ptr,
                                        "DATA",
                                        "native-import:pe-reloc",
                                    ));
                                }
                                let in_code = mappings.iter().any(|cm| {
                                    cm.flags & 0x4 != 0 && ptr >= cm.vaddr && ptr < cm.vaddr + cm.size
                                });
                                if in_code {
                                    reloc_candidates.push(ptr);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            pos += block_size;
        }
    }

    functions.sort_by_key(|f| f.entry);
    functions.dedup_by_key(|f| f.entry);
    let mut import = NativeImport {
        mappings,
        functions,
        xrefs,
        externals: Vec::new(),
        reloc_candidates,
        format: "PE".into(),
        language: language.into(),
        ..Default::default()
    };
    let directory = |offset: Option<usize>| {
        offset.map_or((0, 0), |at| {
            (
                u32_at(data, at).unwrap_or(0) as u64,
                u32_at(data, at + 4).unwrap_or(0) as usize,
            )
        })
    };
    let (unwind_rva, unwind_size) = directory(unwind_dir_offset);
    pe_unwind::collect(data, &raw_sections, &mut import, image_base, unwind_rva, unwind_size);
    let (export_rva, export_size) = directory(export_dir_offset);
    pe_roots::collect_exports(data, &raw_sections, &mut import, image_base, export_rva, export_size);
    let (import_rva, import_size) = directory(import_dir_offset);
    pe_roots::collect_imports(
        data,
        &raw_sections,
        &mut import,
        image_base,
        import_rva,
        import_size,
        if is_64 { 8 } else { 4 },
    );
    let (tls_rva, tls_size) = directory(tls_dir_offset);
    pe_roots::collect_tls(
        data,
        &raw_sections,
        &mut import,
        image_base,
        tls_rva,
        tls_size,
        if is_64 { 8 } else { 4 },
    );
    import.functions.sort_by_key(|f| f.entry);
    import.functions.dedup_by_key(|f| f.entry);
    Ok(import)
}
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

/// Image base of a PE binary (the optional-header `ImageBase` field:
/// `e_lfanew + 24` (optional header start) `+ 24`), or `None` when `data`
/// is not a PE32+ with a parseable header. Used to default `--base` for
/// the worker: PE addresses are RVA-based, so byte resolution falls back
/// to `vaddr - base` when no section mapping covers a request.
pub fn pe_image_base(data: &[u8]) -> Option<u64> {
    if data.get(0..2) != Some(b"MZ") {
        return None;
    }
    let pe_off = u32_at(data, 0x3c).ok()? as usize;
    if data.get(pe_off..pe_off + 4) != Some(b"PE\0\0") {
        return None;
    }
    let opt = pe_off + 24;
    let magic = u16_at(data, opt).ok()?;
    if magic == 0x10b {
        u32_at(data, opt + 28).ok().map(|b| b as u64)
    } else if magic == 0x20b {
        u64_at(data, opt + 24).ok()
    } else {
        None
    }
}

/// Returns the preferred image base for an ELF image.
/// For ET_EXEC (fixed base), returns 0.
/// For ET_DYN (PIE / shared library), returns the minimum PT_LOAD vaddr
/// or 0x100000 (64-bit) / 0x10000 (32-bit), matching Ghidra's default.
pub fn elf_image_base(data: &[u8]) -> Option<u64> {
    elf_bases(data).map(|(base, _)| base)
}

// Preferred image base and relocation delta are distinct for prelinked images.
fn elf_bases(data: &[u8]) -> Option<(u64, u64)> {
    if data.get(0..4) != Some(b"\x7fELF") || data.len() < 18 {
        return None;
    }
    let is_64 = data.get(4).copied() == Some(2);
    let is_be = data.get(5).copied() == Some(2);
    let e_type = if is_be {
        u16_be_at(data, 16).ok()?
    } else {
        u16_at(data, 16).ok()?
    };
    if e_type != 3 {
        // ET_EXEC or other non-DYN: base is already fixed in the headers.
        return Some((0, 0));
    }
    // ET_DYN: find minimum PT_LOAD vaddr from program headers if any non-zero.
    let (phoff, phentsize, phnum) = if is_64 {
        let off = u64_at(data, 32).ok()? as usize;
        let esz = u16_at(data, 54).ok()? as usize;
        let num = u16_at(data, 56).ok()? as usize;
        (off, esz, num)
    } else {
        let off = if is_be { u32_be_at(data, 28).ok()? } else { u32_at(data, 28).ok()? } as usize;
        let esz = if is_be { u16_be_at(data, 42).ok()? } else { u16_at(data, 42).ok()? } as usize;
        let num = if is_be { u16_be_at(data, 44).ok()? } else { u16_at(data, 44).ok()? } as usize;
        (off, esz, num)
    };
    let mut min_vaddr = u64::MAX;
    for i in 0..phnum {
        let hdr = phoff.checked_add(i.checked_mul(phentsize)?)?;
        if hdr.checked_add(if is_64 { 56 } else { 32 })? > data.len() {
            break;
        }
        let p_type = if is_be { u32_be_at(data, hdr).ok()? } else { u32_at(data, hdr).ok()? };
        if p_type == 1 {
            // PT_LOAD
            let p_vaddr = if is_64 {
                u64_at(data, hdr + 16).ok()?
            } else if is_be {
                u32_be_at(data, hdr + 8).ok()? as u64
            } else {
                u32_at(data, hdr + 8).ok()? as u64
            };
            if p_vaddr < min_vaddr {
                min_vaddr = p_vaddr;
            }
        }
    }
    if min_vaddr != u64::MAX && min_vaddr != 0 {
        Some((min_vaddr, 0))
    } else if is_64 {
        Some((0x100000, 0x100000))
    } else {
        Some((0x10000, 0x10000))
    }
}

pub(crate) fn parse_native(data: &[u8]) -> Result<NativeImport> {
    if data.starts_with(b"\x7fELF") {
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
    } else {
        dol::import(data)
    }
}

/// Every image a container carries, each with the suffix that names it.
/// A single-image file yields one entry with an empty suffix, so callers do
/// not special-case formats.
pub(crate) fn parse_container(data: &[u8]) -> Result<Vec<(String, NativeImport)>> {
    if nds::is_cartridge(data) {
        return nds::import(data);
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
    imp.phases.push(lre_model::PhaseTiming {
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
    let parse_started = std::time::Instant::now();
    let data = std::fs::read(binary)
        .map_err(|e| ImportError::Bad(format!("{}: {e}", binary.display())))?;
    let images = parse_container(&data)?;
    let canonical = binary.canonicalize().unwrap_or_else(|_| binary.to_path_buf());
    let mut loaded = Vec::with_capacity(images.len());
    for (suffix, mut imp) in images {
        imp.binary = canonical.clone();
        imp.cfg = crate::session::RuntimeConfig::from_env();
        let cfg = imp.cfg.clone();
        select_language(&mut imp, &cfg)?;
        imp.cfg.adopt_language(&imp.language);
        phase(&mut imp, "parse", parse_started);
        discover(&mut imp)?;
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
fn low_bit_code_mode(language: &str) -> bool {
    language.starts_with("ARM:") || language.starts_with("MIPS:")
}

/// Function starts the propagation proved by resolving a call or branch
/// through a register, that no pass has created yet. Ghidra creates these
/// from the reference the constant-propagation analyzer lays down
/// (`ConstantPropagationContextEvaluator.evaluateDestination`, then
/// disassembly and function creation follow the reference); a target with
/// the low bit set on a low-bit-mode language is decoded in that mode from
/// then on (`setTargetContextForDisassembly`: clear the bit, set the mode).
fn computed_flow_targets(import: &mut NativeImport) -> Vec<u64> {
    let entries: std::collections::HashSet<u64> =
        import.functions.iter().map(|function| function.entry).collect();
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


/// Ghidra's `DecompilerSwitchAnalyzer` runs the decompiler on every function
/// holding an indirect jump, lays a reference from the jump to each table
/// entry it recovers, and disassembles them; the case bodies then reach the
/// calls the walk stopped short of. The decompile worker reads the program
/// from a store, so the image is stored to a scratch project first. Returns
/// the number of tables this round added; a branch already holding one is
/// not asked again.
/// A process-unique scratch directory removed on drop.
struct ScratchDir {
    path: std::path::PathBuf,
}

impl ScratchDir {
    fn new(prefix: &str) -> Option<Self> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_nanos();
        let path = std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&path).ok()?;
        Some(Self { path })
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// The image, as the value-set analysis reads it.
struct ImageView<'a> {
    imp: &'a NativeImport,
    big_endian: bool,
}

impl vsa::Image for ImageView<'_> {
    fn read(&self, address: u64, size: u32) -> Option<u64> {
        if size == 0 || size > 8 {
            return None;
        }
        let mapping = self.imp.mappings.iter().find(|mapping| {
            address >= mapping.vaddr && address + u64::from(size) <= mapping.vaddr + mapping.size
        })?;
        let offset = usize::try_from(address - mapping.vaddr).ok()?;
        let bytes = mapping.bytes.get(offset..offset + size as usize)?;
        let mut value = 0u64;
        if self.big_endian {
            for byte in bytes {
                value = (value << 8) | u64::from(*byte);
            }
        } else {
            for (index, byte) in bytes.iter().enumerate() {
                value |= u64::from(*byte) << (index * 8);
            }
        }
        Some(value)
    }

    fn executable(&self, address: u64) -> bool {
        self.imp.mappings.iter().any(|mapping| {
            mapping.flags & 4 != 0
                && address >= mapping.vaddr
                && address < mapping.vaddr + mapping.size
        })
    }

    fn big_endian(&self) -> bool {
        self.big_endian
    }
}

/// The straight-line window ending at `branch`, and the blocks that can
/// reach it, which is where a guard lives.
///
/// Ghidra takes the path out of the SSA form it has already built
/// (`JumpBasic::findDeterminingVarnodes`) and the range out of the blocks
/// that dominate the dispatch (`JumpBasic::analyzeGuards`). There is no SSA
/// here, so the window is the branch's own basic block -- Ghidra's own
/// definition, a run of instructions nothing jumps into
/// (`BasicBlockModel.hasEndOfBlockFlow`) -- and the guard region is the
/// blocks that actually branch or fall into it. Taking the two positionally
/// preceding blocks instead found a guard for 15 of 132 dispatches on libc:
/// a dispatch block is usually jumped to, not fallen into.
fn switch_window(
    imp: &NativeImport,
    branch: u64,
    entry: u64,
    end: u64,
) -> (Vec<u64>, Vec<Vec<u64>>) {
    let shapes: Vec<&FlowShape> = imp
        .flow_shapes
        .iter()
        .filter(|shape| shape.address >= entry && shape.address < end)
        .collect();
    if shapes.is_empty() || !shapes.iter().any(|shape| shape.address == branch) {
        return (Vec::new(), Vec::new());
    }
    let ends_block = |kind: crate::native_runtime::FlowKind| {
        matches!(
            kind,
            crate::native_runtime::FlowKind::Branch
                | crate::native_runtime::FlowKind::CBranch
                | crate::native_runtime::FlowKind::BranchInd
                | crate::native_runtime::FlowKind::Return
        )
    };
    let mut leaders: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    leaders.insert(entry);
    for shape in &shapes {
        if let Some(target) = shape.target {
            if target >= entry && target < end {
                leaders.insert(target);
            }
        }
        if ends_block(shape.kind) {
            let next = shape.address + u64::from(shape.length);
            if next < end {
                leaders.insert(next);
            }
        }
    }
    let leader_of = |address: u64| {
        leaders
            .range(..=address)
            .next_back()
            .copied()
            .unwrap_or(entry)
    };
    let dispatch = leader_of(branch);
    // Predecessors: a block whose last instruction branches to the dispatch,
    // and the block that falls into it.
    let mut predecessors: Vec<u64> = Vec::new();
    for shape in &shapes {
        let reaches = shape.target == Some(dispatch)
            || (!ends_block(shape.kind)
                && shape.address + u64::from(shape.length) == dispatch)
            || (matches!(shape.kind, crate::native_runtime::FlowKind::CBranch)
                && shape.address + u64::from(shape.length) == dispatch);
        if reaches {
            let block = leader_of(shape.address);
            if block != dispatch && !predecessors.contains(&block) {
                predecessors.push(block);
            }
        }
    }
    predecessors.sort_unstable();
    let window: Vec<u64> = shapes
        .iter()
        .filter(|shape| shape.address >= dispatch && shape.address <= branch)
        .map(|shape| shape.address)
        .collect();
    // Each predecessor block on its own: a guard is read by running the
    // block that states it, and one block's call must not clear the index
    // another block compares.
    let mut guard: Vec<Vec<u64>> = Vec::new();
    for &block in predecessors.iter().take(4) {
        let block_end = leaders
            .range((std::ops::Bound::Excluded(block), std::ops::Bound::Unbounded))
            .next()
            .copied()
            .unwrap_or(end);
        let addresses: Vec<u64> = shapes
            .iter()
            .filter(|shape| shape.address >= block && shape.address < block_end)
            .map(|shape| shape.address)
            .collect();
        if !addresses.is_empty() {
            guard.push(addresses);
        }
    }
    (window, guard)
}

/// Recovers tables with value-set analysis over p-code, no decompiler.
///
/// Returns the branches it could not resolve, which the decompiler path then
/// gets, so a body this cannot follow is still recovered.
fn recover_switch_tables_native(
    imp: &mut NativeImport,
    session: &mut crate::native_runtime::ConsoleSession,
    branches: &[(u64, u64, u64)],
) -> (usize, Vec<u64>) {
    // The language id names the endianness in its second field
    // (`PowerPC:BE:32:default`), which is how every other reader here takes
    // it.
    let big_endian = imp
        .language
        .split(':')
        .nth(1)
        .is_some_and(|field| field.eq_ignore_ascii_case("BE"));
    let mut resolved = Vec::new();
    let mut unresolved = Vec::new();
    let mut refusals = vsa::Refusals::default();
    let mut no_window = 0usize;
    let mut undecodable = 0usize;
    for &(branch, entry, end) in branches {
        let (window_addresses, guard_addresses) = switch_window(imp, branch, entry, end);
        if window_addresses.is_empty() {
            no_window += 1;
            unresolved.push(branch);
            continue;
        }
        // One request for both regions: the guard's constants come from the
        // blocks before the dispatch, and only the dispatch block is
        // emulated.
        let mut addresses: Vec<u64> = guard_addresses.iter().flatten().copied().collect();
        addresses.extend(window_addresses.iter().copied());
        let decoded = match session.pcode_batch(&addresses) {
            Ok(decoded) => decoded,
            Err(_) => {
                unresolved.push(branch);
                continue;
            }
        };
        if decoded.iter().any(|instruction| instruction.error.is_some()) {
            undecodable += 1;
            unresolved.push(branch);
            continue;
        }
        // Split the one answer back into the blocks it was asked for.
        let mut cursor = 0usize;
        let mut guard: Vec<Vec<crate::native_runtime::PcodeInstruction>> = Vec::new();
        for block in &guard_addresses {
            let end = (cursor + block.len()).min(decoded.len());
            guard.push(decoded[cursor..end].to_vec());
            cursor = end;
        }
        let window = &decoded[cursor.min(decoded.len())..];
        if std::env::var("VENTRIS_TRACE_VSA_AT")
            .ok()
            .and_then(|value| u64::from_str_radix(value.trim_start_matches("0x"), 16).ok())
            == Some(branch)
        {
            eprintln!(
                "VSA at {branch:#x}: guard {:x?} window {:x?}",
                guard.iter().map(|block| block.iter().map(|i| i.address).collect::<Vec<_>>()).collect::<Vec<_>>(),
                window.iter().map(|i| i.address).collect::<Vec<_>>(),
            );
            for instruction in window {
                for op in &instruction.ops {
                    eprintln!(
                        "  {:#x} {} {:?} <- {:?}",
                        instruction.address,
                        op.opcode,
                        op.output.as_ref().map(|v| format!("{}:{:x}:{}", v.space, v.offset, v.size)),
                        op.inputs
                            .iter()
                            .map(|v| format!("{}:{:x}:{}", v.space, v.offset, v.size))
                            .collect::<Vec<_>>()
                    );
                }
            }
        }
        let table = {
            let view = ImageView { imp, big_endian };
            vsa::recover(
                &view,
                branch,
                &guard,
                window,
                imp.cfg.switch_vsa_unguarded,
                &mut refusals,
            )
        };
        match table {
            Some(table) => resolved.push(table),
            None => unresolved.push(branch),
        }
    }
    if std::env::var_os("VENTRIS_TRACE_VSA").is_some() {
        eprintln!(
            "VSA candidates={} resolved={} no_window={no_window} undecodable={undecodable} \
             no_live_in={} no_strided_load={} too_few_targets={} unmodelled={}",
            branches.len(),
            resolved.len(),
            refusals.no_live_in,
            refusals.no_strided_load,
            refusals.too_few_targets,
            refusals.unmodelled,
        );
    }
    let mut added = 0;
    for table in resolved {
        let mut targets = table.targets;
        targets.sort_unstable();
        targets.dedup();
        for &target in &targets {
            imp.xrefs.push(NativeXref::with_provenance(
                table.branch,
                target,
                "COMPUTED_JUMP",
                SWITCH_PROVENANCE,
            ));
        }
        let reaches_new = targets.iter().any(|&target| {
            let index = imp.decoded_ranges.partition_point(|&(start, _)| start <= target);
            !index
                .checked_sub(1)
                .is_some_and(|i| target < imp.decoded_ranges[i].1)
        });
        if imp.switch_tables.insert(table.branch, targets).is_none() && reaches_new {
            added += 1;
        }
    }
    (added, unresolved)
}

/// Indirect jumps whose table is not known yet, with the extent of the
/// function that owns each: the candidates both switch paths work from.
///
/// A jump whose transfer the image's structure already proved -- a linkage
/// stub through an import slot, a thunk -- is not a switch;
/// `DecompilerSwitchAnalyzer.findLocations` skips an instruction whose flow
/// is overridden or already referenced (:398-431).
fn switch_candidates(imp: &mut NativeImport) -> Vec<(u64, u64, u64)> {
    let extents: Vec<(u64, u64)> = imp
        .functions
        .iter()
        .filter(|function| function.size > 1)
        .map(|function| (function.entry, function.entry + function.size))
        .collect();
    let resolved: std::collections::HashSet<u64> = imp
        .flow_overrides
        .iter()
        .map(|&(address, _)| address)
        .chain(
            imp.xrefs
                .iter()
                .filter(|xref| xref.kind == "COMPUTED_JUMP")
                .map(|xref| xref.from),
        )
        .collect();
    let thunk_entries: std::collections::HashSet<u64> =
        imp.thunks.iter().map(|thunk| thunk.entry).collect();
    let mut out = Vec::new();
    for &branch in &imp.indirect_jumps {
        if imp.switch_tables.contains_key(&branch) || resolved.contains(&branch) {
            continue;
        }
        let Some(&(entry, end)) = extents
            .iter()
            .find(|&&(start, end)| start <= branch && branch < end)
        else {
            continue;
        };
        if thunk_entries.contains(&entry) {
            continue;
        }
        if imp.switch_asked.insert(branch, end - entry) != Some(end - entry) {
            out.push((branch, entry, end));
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

fn recover_switch_tables(imp: &mut NativeImport) -> usize {
    let extents: Vec<(u64, u64)> = imp
        .functions
        .iter()
        .filter(|function| function.size > 1)
        .map(|function| (function.entry, function.entry + function.size))
        .collect();
    let owner = |address: u64| {
        extents
            .iter()
            .find(|&&(start, end)| start <= address && address < end)
            .map(|&(start, end)| (start, end - start))
    };
    let started = std::time::Instant::now();
    // A jump whose transfer the image's structure already proved -- a
    // linkage stub through an import slot, a thunk -- is not a switch;
    // `DecompilerSwitchAnalyzer.findLocations` skips an instruction whose
    // flow is overridden or already referenced (:398-431).
    let resolved: std::collections::HashSet<u64> = imp
        .flow_overrides
        .iter()
        .map(|&(address, _)| address)
        .chain(imp.xrefs.iter().filter(|xref| xref.kind == "COMPUTED_JUMP").map(|xref| xref.from))
        .collect();
    let thunk_entries: std::collections::HashSet<u64> =
        imp.thunks.iter().map(|thunk| thunk.entry).collect();
    let mut owners: Vec<u64> = Vec::new();
    for &branch in &imp.indirect_jumps {
        if imp.switch_tables.contains_key(&branch) || resolved.contains(&branch) {
            continue;
        }
        let Some((entry, size)) = owner(branch) else {
            continue;
        };
        if thunk_entries.contains(&entry) {
            continue;
        }
        if imp.switch_asked.insert(branch, size) != Some(size) {
            owners.push(entry);
        }
    }
    owners.sort_unstable();
    owners.dedup();
    if owners.is_empty() {
        phase(imp, "switch", started);
        return 0;
    }
    let scratch = ScratchDir::new("ventris-switch");
    let Some(scratch) = scratch else {
        imp.discovery_note = Some("switch recovery has no scratch dir".into());
        return 0;
    };
    let program = "switch-recovery";
    let stored = ProjectDb::open(&scratch.path.join("project.sqlite"))
        .map_err(|error| error.to_string())
        .and_then(|db| {
            store_import(&db, program, imp, declared_entry_model(&imp.cfg, &imp.language))
                .map_err(|error| error.to_string())
        });
    if let Err(error) = stored {
        imp.discovery_note = Some(format!("switch recovery could not store the image: {error}"));
        return 0;
    }
    let addresses: Vec<String> = owners.iter().map(|entry| format!("{entry:#x}")).collect();
    // One worker per chunk, as many at once as the host has cores: the
    // decompiles are independent and each worker loads the language once.
    let lanes = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .clamp(1, 8);
    let chunk_size = addresses.len().div_ceil(lanes).clamp(1, 256);
    let chunks: Vec<&[String]> = addresses.chunks(chunk_size).collect();
    // Each lane reads its own copy of the store: the worker opens it for
    // writing, and two on one file lock each other out.
    let mut lane_dirs = Vec::with_capacity(chunks.len());
    for index in 0..chunks.len() {
        let lane = scratch.path.join(format!("lane-{index}"));
        if let Err(error) = std::fs::create_dir_all(&lane).and_then(|_| {
            std::fs::copy(scratch.path.join("project.sqlite"), lane.join("project.sqlite"))
        }) {
            imp.discovery_note = Some(format!("switch recovery could not copy the store: {error}"));
            return 0;
        }
        lane_dirs.push(lane);
    }
    let outcomes: Vec<Result<std::collections::BTreeMap<String, lre_model::DecompDoc>>> =
        std::thread::scope(|scope| {
            let handles: Vec<_> = chunks
                .iter()
                .zip(lane_dirs.iter())
                .map(|(chunk, project)| {
                    let cfg = &imp.cfg;
                    let binary = &imp.binary;
                    scope.spawn(move || {
                        crate::native_runtime::decompile_native_docs(
                            cfg, binary, chunk, program, project, None,
                        )
                        .map_err(|error| ImportError::Bad(error.to_string()))
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| {
                    handle
                        .join()
                        .unwrap_or_else(|_| Err(ImportError::Bad("switch worker panicked".into())))
                })
                .collect()
        });
    let mut added = 0;
    for outcome in outcomes {
        let docs = match outcome {
            Ok(docs) => docs,
            Err(error) => {
                imp.discovery_note = Some(format!("switch recovery decompile failed: {error}"));
                continue;
            }
        };
        for doc in docs.values() {
            for table in doc.jump_tables.iter().flatten() {
                if table.branch.space != lre_model::AddressSpace::Ram {
                    continue;
                }
                let mut targets: Vec<u64> = table
                    .targets
                    .iter()
                    .filter(|target| target.space == lre_model::AddressSpace::Ram)
                    .map(|target| target.offset)
                    .collect();
                targets.sort_unstable();
                targets.dedup();
                if targets.is_empty() {
                    continue;
                }
                // The reference Ghidra's switch analyzer lays from the jump
                // to each case (`COMPUTED_JUMP`), before the pattern analyzer
                // runs: a case label is owned by flow from then on
                // (`checkAlreadyInFunctionAbove`, 514-527).
                for &target in &targets {
                    imp.xrefs.push(NativeXref::with_provenance(
                        table.branch.offset,
                        target,
                        "COMPUTED_JUMP",
                        SWITCH_PROVENANCE,
                    ));
                }
                // A table whose every case the walk already decoded changes
                // no body; only one reaching bytes nothing read is a reason
                // to walk again.
                let reaches_new = targets.iter().any(|&target| {
                    let index = imp.decoded_ranges.partition_point(|&(start, _)| start <= target);
                    !index
                        .checked_sub(1)
                        .is_some_and(|i| target < imp.decoded_ranges[i].1)
                });
                if imp.switch_tables.insert(table.branch.offset, targets).is_none() && reaches_new {
                    added += 1;
                }
            }
        }
    }
    if added > 0 {
        demote_case_blocks(imp);
    }
    phase(imp, "switch", started);
    added
}

/// Ghidra recovers a jump's table at `CODE_ANALYSIS`, before the pattern
/// analyzer's delayed creator runs at `DATA_ANALYSIS.after()` and finds the
/// case block already inside a function (`PossibleDelayedFunctionCreator`,
/// 1001-1012). Here the patterns ran a round earlier, so a function whose
/// only evidence is a pattern match at a case target is withdrawn; the next
/// walk gives the block to the function that jumps to it. A target anything
/// calls or points at keeps its function.
fn demote_case_blocks(imp: &mut NativeImport) {
    let targets: std::collections::HashSet<u64> = imp
        .switch_tables
        .values()
        .flat_map(|targets| targets.iter().copied())
        .collect();
    let evidenced: std::collections::HashSet<u64> = imp
        .xrefs
        .iter()
        .filter(|xref| xref.kind.ends_with("CALL") || xref.kind == "DATA")
        .map(|xref| xref.to)
        .collect();
    imp.functions.retain(|function| {
        !(targets.contains(&function.entry)
            && function.name.starts_with("FUN_")
            && !evidenced.contains(&function.entry))
    });
}

/// Runs discovery and reference inference for one loaded image.
fn discover(imp: &mut NativeImport) -> Result<()> {
    let discovery_started = std::time::Instant::now();
    let mut lanes = if imp.format == "dol" {
        Some(discovery::discover_mapped(imp)?)
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
    for round in 0..4 {
        if lanes.take().is_none() {
            break;
        }
        // The reference pass reads bytes through a console that has decoded
        // nothing but what the recorded contexts say. The discovery console
        // has probed thousands of candidates by now, and every probe wrote
        // the mode switches its bytes carried into that console's one
        // context database (SLEIGH `globalset`), so crt0 of a DS ROM read as
        // Thumb there and yielded no references at all.
        let references_started = std::time::Instant::now();
        let mut session = match crate::native_runtime::ConsoleSession::new(&imp.cfg) {
            Ok(session) => session,
            Err(error) => {
                imp.discovery_note = Some(format!("reference console did not start: {error}"));
                break;
            }
        };
        if let Err(error) = session.load_mapped(imp) {
            imp.discovery_note = Some(format!("reference console did not load the image: {error}"));
            break;
        }
        let shards = crate::native_runtime::ConsoleSession::open_image_shards(
            imp,
            imp.cfg.console_shards.max(1) - 1,
        );
        seed_mips_entry_register(imp);
        infer_data_references(imp, &mut session, shards)?;
        phase(imp, "references", references_started);
        if round == 3 {
            break;
        }
        let targets = computed_flow_targets(imp);
        // Value-set analysis over p-code answers most dispatches without the
        // decompiler; the decompiler path is what a body this cannot follow
        // falls back to (and the accelerator can be switched off entirely,
        // which is how the two are measured against each other).
        let switch_started = std::time::Instant::now();
        let candidates = switch_candidates(imp);
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
        if targets.is_empty() && tables == 0 {
            break;
        }
        let mode = low_bit_code_mode(&imp.language);
        for &target in &targets {
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
        let again = std::time::Instant::now();
        lanes = discovery::discover_seeded(imp);
        phase(imp, "discovery", again);
    }
    // Whether a branch target is a function can only be answered once every
    // pass that creates one has run.
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
        .filter(|thunk| thunk.kind == lre_model::ThunkKind::Linkage)
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
    let parse_started = std::time::Instant::now();
    let data = std::fs::read(binary)
        .map_err(|e| ImportError::Bad(format!("{}: {e}", binary.display())))?;
    let mut imp = parse_native(&data)?;
    imp.binary = binary.canonicalize().unwrap_or_else(|_| binary.to_path_buf());
    imp.cfg = crate::session::RuntimeConfig::from_env();
    let cfg = imp.cfg.clone();
    select_language(&mut imp, &cfg)?;
    imp.cfg.adopt_language(&imp.language);
    phase(&mut imp, "parse", parse_started);
    discover(&mut imp)?;
    Ok(imp)
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

/// One console reference query. ConstantPropagationAnalyzer's default trusts
/// initial writable values; this inferred-reference policy does not change
/// strict constant queries. A root or stripped entry that does not decode
/// contributes no references and must not abort the whole image's import.
fn query_references(
    session: &mut crate::native_runtime::ConsoleSession,
    start: u64,
    end: u64,
    mappings: &[Mapping],
    refused: &std::sync::atomic::AtomicU64,
) -> Result<Option<Vec<crate::native_runtime::ReferenceFact>>> {
    match session.optional_references(start, end, mappings, true) {
        Ok(facts) => Ok(facts),
        // One range the console cannot answer costs that range's references,
        // never the image. A 53 MB game executable always holds bytes that
        // are not instructions; the count is reported so the loss stays
        // visible instead of being swallowed.
        Err(_) => {
            refused.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(None)
        }
    }
}

/// One lane of a sharded round: claim ranges until the round is drained.
fn claim_references(
    session: &mut crate::native_runtime::ConsoleSession,
    ranges: &[(usize, u64, u64)],
    cursor: &std::sync::atomic::AtomicUsize,
    mappings: &[Mapping],
    refused: &std::sync::atomic::AtomicU64,
) -> Result<Vec<(usize, Vec<crate::native_runtime::ReferenceFact>)>> {
    let mut facts = Vec::new();
    loop {
        let next = cursor.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let Some(&(index, start, end)) = ranges.get(next) else {
            return Ok(facts);
        };
        if let Some(found) = query_references(session, start, end, mappings, refused)? {
            facts.push((index, found));
        }
    }
}

/// The address width the language id declares (`ARM:LE:32:v5t`), which is
/// the width a stack offset travels in.
fn language_pointer_bits(language: &str) -> u32 {
    language
        .split(':')
        .nth(2)
        .and_then(|bits| bits.parse().ok())
        .unwrap_or(64)
}

fn sign_extend(value: u64, bits: u32) -> i64 {
    if bits == 0 || bits >= 64 {
        return value as i64;
    }
    let shift = 64 - bits;
    (((value << shift) as i64) >> shift)
}

/// Ghidra's stack analyzer, from the accesses one function makes through
/// its stack pointer (`NewFunctionStackAnalysisCmd`): an offset outside
/// `[-64K, 2048]` is refused (`defineFuncVariable`), every referenced slot
/// becomes a variable sized by its access, overlapping slots merge into one
/// spanning them all (`accumulateVariable`), and -- with the analyzer's
/// default of creating locals but not parameters -- only offsets below the
/// parameter area become variables. The name is
/// `SymbolUtilities.getDefaultLocalName`: `local_` and the offset's
/// magnitude in hex; the type is `undefined<size>`.
fn stack_frame(function: u64, accesses: &[(i64, u32)]) -> Vec<lre_model::StackVariableRow> {
    let mut slots: Vec<(i64, i64)> = accesses
        .iter()
        .filter(|&&(offset, size)| {
            size > 0 && (-(64 * 1024)..=2048).contains(&offset) && offset < 0
        })
        .map(|&(offset, size)| (offset, offset + size as i64))
        .collect();
    slots.sort_unstable();
    let mut merged: Vec<(i64, i64)> = Vec::new();
    for (start, end) in slots {
        match merged.last_mut() {
            Some(last) if start < last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    merged
        .into_iter()
        .enumerate()
        .map(|(ordinal, (start, end))| {
            let size = (end - start) as u64;
            lre_model::StackVariableRow {
                function: lre_model::Address::ram(function),
                ordinal: ordinal as u32,
                name: format!("local_{:x}", -start),
                storage: format!("Stack[-0x{:x}]:{size}", -start),
                type_name: Some(format!("undefined{size}")),
                offset: Some(start),
                size: Some(size),
            }
        })
        .collect()
}

fn infer_data_references(
    import: &mut NativeImport,
    session: &mut crate::native_runtime::ConsoleSession,
    lanes: Vec<crate::native_runtime::ConsoleSession>,
) -> Result<()> {
    use crate::native_runtime::ReferenceKind;
    session.prepare_reference_context(import)
        .map_err(|error| ImportError::Bad(format!("reference context: {error}")))?;
    let functions = import.functions.iter().filter(|function| function.size > 1).map(|function| {
        function.entry.checked_add(function.size)
            .map(|end| (function.entry, end))
            .ok_or_else(|| ImportError::Bad("reference function range overflows".into()))
    });
    let roots = import.reference_roots.iter()
        .filter(|&&(start, _)| !import.functions.iter()
            .any(|function| function.entry == start && function.size > 1))
        .copied();
    // Ranges the console could not answer. Counted, not hidden.
    let refused = std::sync::atomic::AtomicU64::new(0);
    let mut work = functions
        .map(|range| range.map(|(start, end)| (start, end, Vec::new(), true)))
        .collect::<Result<Vec<_>>>()?;
    let function_count = work.len();
    for (start, end) in roots {
        work.push((start, end, Vec::new(), true));
    }
    let mut pending: Vec<usize> = (0..work.len()).collect();
    // One console per hardware thread: the per-function cost is the console
    // lifting that function, so the pass scales with processes, not with
    // fewer requests. Shards start from the round's context and never read
    // one discovered inside it, so their facts equal a single session's.
    // Discovery already opened these consoles on this image; they only need
    // this pass's context, not another startup.
    let mut shards = lanes;
    let mut prepared = false;
    let shard_target = import.cfg.console_shards.max(1);
    loop {
        let batch = std::mem::take(&mut pending);
        for &index in &batch {
            work[index].3 = false;
        }
        let ranges: Vec<(usize, u64, u64)> = batch
            .iter()
            .map(|&index| (index, work[index].0, work[index].1))
            .collect();
        let wanted = shard_target.min(ranges.len()).saturating_sub(1);
        shards.truncate(wanted);
        if !prepared && !shards.is_empty() {
            let spec = session.reference_shard_spec();
            // A shard is an optimization: one that cannot take the context is
            // dropped, and the pass stays correct on the remaining lanes.
            shards.retain_mut(|shard| shard.prepare_as_reference_shard(&spec, import).is_ok());
            prepared = true;
        }
        if shards.len() < wanted {
            let spec = session.reference_shard_spec();
            let mut opened =
                crate::native_runtime::ConsoleSession::open_image_shards(import, wanted - shards.len());
            opened.retain_mut(|shard| shard.prepare_as_reference_shard(&spec, import).is_ok());
            shards.extend(opened);
        }
        let keep = session.reference_contexts().len();
        let mut results: Vec<(usize, Vec<crate::native_runtime::ReferenceFact>)> = Vec::new();
        let mut discovered: Vec<NativeRegisterContext> = Vec::new();
        if shards.is_empty() || ranges.len() < 2 {
            for &(index, start, end) in &ranges {
                if let Some(facts) =
                    query_references(session, start, end, &import.mappings, &refused)?
                {
                    results.push((index, facts));
                }
            }
        } else {
            let mappings = &import.mappings;
            for shard in shards.iter_mut() {
                shard.sync_reference_context(session.reference_contexts());
            }
            // Function cost varies by orders of magnitude, so lanes claim the
            // next range instead of taking a fixed stride: one huge function
            // must not decide the round's wall time.
            let cursor = std::sync::atomic::AtomicUsize::new(0);
            let outcome: Result<Vec<_>> = std::thread::scope(|scope| {
                let mut handles = Vec::with_capacity(shards.len());
                for shard in shards.iter_mut() {
                    let ranges = &ranges;
                    let cursor = &cursor;
                    let refused = &refused;
                    handles.push(scope.spawn(move || {
                        claim_references(shard, ranges, cursor, mappings, refused)
                    }));
                }
                let mut collected =
                    vec![claim_references(session, &ranges, &cursor, mappings, &refused)?];
                for handle in handles {
                    collected.push(handle.join().unwrap_or_else(|_| {
                        Err(ImportError::Bad("reference shard panicked".into()))
                    })?);
                }
                Ok(collected)
            });
            for lane in outcome? {
                results.extend(lane);
            }
            for shard in shards.iter_mut() {
                discovered.extend(shard.drain_discovered_contexts(keep));
            }
        }
        for (index, facts) in results {
            let known = &mut work[index].2;
            if known.is_empty() {
                *known = facts;
            } else {
                known.extend(facts);
                known.sort_unstable_by_key(|fact| (fact.from, fact.to, fact.kind as u8));
                known.dedup();
            }
        }
        // Finish local evidence before applying this round's call context.
        // Shard order must not decide the context list, so merge sorted.
        discovered.extend(session.drain_discovered_contexts(keep));
        discovered.sort_by(|left, right| {
            (left.start, left.end, &left.register, left.value)
                .cmp(&(right.start, right.end, &right.register, right.value))
        });
        discovered.dedup_by(|left, right| {
            left.start == right.start
                && left.end == right.end
                && left.register == right.register
                && left.value == right.value
        });
        let mut targets = session.adopt_reference_contexts(discovered);
        targets.sort_unstable();
        targets.dedup();
        for target in targets {
            if let Some(next) = work.iter().position(|item| item.0 == target) {
                if !work[next].3 {
                    work[next].3 = true;
                    pending.push(next);
                }
            }
        }
        if pending.is_empty() {
            break;
        }
    }
    // Propagated caller context can resolve a linkage whose base register was
    // unknown during discovery. Require the existing pure-linkage proof and
    // one consistent imported read slot within that exact instruction extent.
    let imported: std::collections::HashMap<_, _> = import.externals.iter()
        .filter(|(address, _)| *address != 0)
        .map(|(address, name)| (*address, name.as_str()))
        .collect();
    let candidates: Vec<_> = work[..function_count].iter().enumerate()
        .filter(|(_, (start, _, facts, _))| {
            !imported.contains_key(start) && facts.iter()
                .any(|fact| fact.kind == ReferenceKind::Read && imported.contains_key(&fact.to))
        })
        .map(|(index, _)| index)
        .collect();
    let mut linked = Vec::new();
    let mut thunked: Vec<NativeThunk> = Vec::new();
    let mut addresses = Vec::with_capacity(candidates.len().min(1024));
    for chunk in candidates.chunks(1024) {
        addresses.clear();
        addresses.extend(chunk.iter().map(|&index| work[index].0));
        let shapes = session.linkage_batch(&addresses)
            .map_err(|error| ImportError::Bad(format!("propagated linkage: {error}")))?;
        for (&index, shape) in chunk.iter().zip(shapes) {
            let (start, end, facts, _) = &work[index];
            let Some(limit) = start.checked_add(shape.length as u64)
                .filter(|limit| shape.length != 0 && *limit <= *end) else {
                continue;
            };
            let mut slot = None;
            let mut consistent = true;
            for fact in facts.iter().filter(|fact| {
                fact.kind == ReferenceKind::Read && *start <= fact.from && fact.from < limit
            }) {
                if !imported.contains_key(&fact.to)
                    || slot.is_some_and(|previous| previous != fact.to)
                    || shape.slot.is_some_and(|resolved| resolved != fact.to)
                {
                    consistent = false;
                    break;
                }
                slot = Some(fact.to);
            }
            if consistent && let Some((slot, name)) = slot.zip(slot.and_then(|slot| imported.get(&slot))) {
                linked.push((*start, (*name).to_owned()));
                // The slot that names this stub is the destination it reaches,
                // so the stub is a linkage thunk. Stock Ghidra converts the
                // function it already created (CreateThunkFunctionCmd); the
                // slot is the address the stub's own instructions read.
                if !import.thunks.iter().any(|thunk| thunk.entry == *start) {
                    thunked.push(NativeThunk {
                        entry: *start,
                        destination: slot,
                        kind: lre_model::ThunkKind::Linkage,
                        source: crate::native::THUNK_SOURCE,
                    });
                }
            }
        }
    }
    import.externals.extend(linked);
    import.thunks.extend(thunked);
    // Context adds precise accesses; existing speculative DATA remains evidence.
    // Publish no partial pass if any query fails.
    let pointer_bits = language_pointer_bits(&import.language);
    // A pass covers every function, and a later round covers them again with
    // more of the image known: the frames are this pass's, not a sum.
    import.stack_variables.clear();
    for (index, (start, _, facts, _)) in work.into_iter().enumerate() {
        // The frame this function's own accesses describe. Roots that are
        // not functions carry no frame.
        if index < function_count {
            let accesses: Vec<(i64, u32)> = facts
                .iter()
                .filter(|fact| fact.kind == ReferenceKind::Stack)
                .map(|fact| (sign_extend(fact.to, pointer_bits), fact.size))
                .collect();
            import
                .stack_variables
                .extend(stack_frame(start, &accesses));
        }
        let facts: Vec<crate::native_runtime::ReferenceFact> = facts
            .into_iter()
            .filter(|fact| fact.kind != ReferenceKind::Stack)
            .collect();
        // The width of an access is a fact about the location, not about the
        // instruction: stock defines data of the access size at every
        // referenced location, which is what keeps a wider read from
        // overlapping a one-byte symbol.
        for fact in &facts {
            if fact.size == 0
                || fact.size > 8
                || matches!(
                    fact.kind,
                    ReferenceKind::Data | ReferenceKind::ComputedCall | ReferenceKind::ComputedJump
                )
            {
                continue;
            }
            match import
                .reference_widths
                .iter_mut()
                .find(|(address, _)| *address == fact.to)
            {
                Some((_, width)) => *width = (*width).max(fact.size as u64),
                None => import.reference_widths.push((fact.to, fact.size as u64)),
            }
        }
        if low_bit_code_mode(&import.language) {
            for fact in &facts {
                if fact.kind == ReferenceKind::ComputedCall && fact.to & 1 != 0 {
                    import.computed_mode_targets.push(fact.to & !1);
                }
            }
        }
        let mode = low_bit_code_mode(&import.language);
        import.xrefs.extend(facts.into_iter().map(|fact| {
            // The reference lands where the flow does; on a language that
            // carries the instruction-set mode in the low bit, that bit is a
            // mode, not part of the address, and the mode is recorded
            // separately (`computed_mode_targets`).
            let aligned = if mode { fact.to & !1 } else { fact.to };
            let (kind, to) = match fact.kind {
                ReferenceKind::Read => ("READ", fact.to),
                ReferenceKind::Write => ("WRITE", fact.to),
                ReferenceKind::ReadWrite => ("READ_WRITE", fact.to),
                ReferenceKind::Data => ("DATA", fact.to),
                ReferenceKind::ComputedCall => ("COMPUTED_CALL", aligned),
                ReferenceKind::ComputedJump => ("COMPUTED_JUMP", aligned),
                ReferenceKind::Stack => unreachable!("stack facts were taken out above"),
            };
            NativeXref::with_provenance(fact.from, to, kind, "native-analysis:constant-propagation")
        }));
    }
    import.references_refused = refused.load(std::sync::atomic::Ordering::Relaxed);
    Ok(())
}


/// Adds FUN_<hex> functions for every xref target inside a code mapping
/// (the direct-call closure; mirrors Ghidra's FUN_ naming).
pub fn close_call_targets(imp: &mut NativeImport) {
    for x in &imp.xrefs {
        if !x.kind.contains("CALL") {
            continue;
        }
        let in_code = imp
            .mappings
            .iter()
            .any(|m| m.flags & 0x4 != 0 && x.to >= m.vaddr && x.to < m.vaddr + m.size);
        if !in_code || imp.functions.iter().any(|f| f.entry == x.to) {
            continue;
        }
        imp.functions.push(NativeFunction {
            entry: x.to,
            name: format!("FUN_{:08x}", x.to),
            size: 1,
        });
    }
    imp.functions.sort_by_key(|f| f.entry);
    imp.functions.dedup_by_key(|f| f.entry);
}

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

/// The size an ELF `OBJECT` symbol declares for the object it names.
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
pub fn declared_entry_model(cfg: &crate::session::RuntimeConfig, language: &str) -> Option<&'static str> {
    let (_, specs, _, _) = crate::native_runtime::language_decompile_config(cfg, language).ok()?;
    let cspec = std::fs::read_to_string(specs.join("cspec.xml")).ok()?;
    crate::register_params::declares_model(&cspec, PROCESS_ENTRY_MODEL)
        .then_some(PROCESS_ENTRY_MODEL)
}

pub fn store_import(
    db: &ProjectDb,
    program: &str,
    imp: &NativeImport,
    entry_model: Option<&str>,
) -> Result<ProgramSummary> {
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
    let mut regions = imp
        .mappings
        .iter()
        .enumerate()
        .map(|(index, mapping)| MemoryRegion {
            name: match imp.mapping_names.get(index) {
                Some(name) => format!("{}:{name}", imp.format.to_ascii_lowercase()),
                None => format!("{}:{index}", imp.format.to_ascii_lowercase()),
            },
            start: lre_model::Address::ram(mapping.vaddr),
            size: mapping.size,
            permissions: mapping_permissions(mapping.flags),
            source: "native-import".into(),
        })
        .collect::<Vec<_>>();
    // A platform's own map: declared, byte-less, and named by the platform.
    regions.extend(imp.declared_regions.iter().map(|region| MemoryRegion {
        name: format!("{}:{}", imp.format.to_ascii_lowercase(), region.name),
        start: lre_model::Address::ram(region.vaddr),
        size: region.size,
        permissions: mapping_permissions(region.flags),
        source: "native-import:platform-map".into(),
    }));
    db.replace_memory_regions(pid, &regions)?;
    let swept_strings = strings::discover(imp);
    db.replace_strings(pid, imp.string_tables.iter().flat_map(|table| &table.strings)
        .chain(&swept_strings))?;
    let rows: Vec<FunctionRow> = functions
        .iter()
        .map(|f| FunctionRow {
            entry: lre_model::Address::ram(f.entry),
            name: f.name.clone(),
            size: f.size.max(1),
            signature: None,
            calling_convention: None,
        })
        .collect();
    db.replace_functions(pid, &rows)?;
    // Structural measurements of each body, taken while it was decoded:
    // instruction and basic-block counts, intra-function edges, and digests
    // of the bytes and of the decoded shape. `lre-diff` matches programs on
    // these; nothing else reads them, and nothing re-reads the image to get
    // them.
    db.replace_function_features(pid, &features::measure(imp))?;
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
    let contexts: Vec<(lre_model::Address, String, u64)> = imp
        .contexts
        .iter()
        .map(|context| {
            let name = match context.name.as_str() {
                "TMode" | "ISA_MODE" => "LowBitCodeMode".to_string(),
                other => other.to_string(),
            };
            (lre_model::Address::ram(context.address), name, context.value)
        })
        .collect();
    db.replace_decode_contexts(pid, &contexts)?;
    // Refresh this loader's facts without discarding symbols from other owners.
    let mut symbols = db.symbols(pid)?;
    symbols.retain(|symbol| symbol.source != "native-import");
    symbols.retain(|symbol| symbol.source != DYNAMIC_LABEL_SOURCE);
    symbols.extend(
        imp.externals.iter().filter(|(entry, _)| *entry != 0)
            .map(|(entry, name)| lre_model::SymbolRow {
                name: name.clone(),
                address: lre_model::Address::ram(*entry),
                external: true,
                source: "native-import".into(),
            }),
    );
    // An object a COPY relocation brings in *is* the named object: the
    // dynamic linker copies the library's definition into this slot, so the
    // slot carries that name (`R_*_COPY`; stock records the same symbol from
    // the same relocation).
    symbols.retain(|symbol| symbol.source != ELF_COPY_SOURCE);
    let copied: Vec<lre_model::SymbolRow> = imp
        .named_relocations
        .iter()
        .filter(|relocation| relocation.copies && relocation.address != 0)
        .map(|relocation| lre_model::SymbolRow {
            name: relocation.symbol.clone(),
            address: lre_model::Address::ram(relocation.address),
            external: false,
            source: ELF_COPY_SOURCE.into(),
        })
        .collect();
    let already: std::collections::HashSet<u64> = symbols
        .iter()
        .filter(|symbol| symbol.address.space == lre_model::AddressSpace::Ram)
        .map(|symbol| symbol.address.offset)
        .collect();
    symbols.extend(copied.into_iter().filter(|row| !already.contains(&row.address.offset)));
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
            .map(|(address, name)| lre_model::SymbolRow {
                name: name.clone(),
                address: lre_model::Address::ram(*address),
                external: false,
                source: DYNAMIC_LABEL_SOURCE.into(),
            }),
    );
    // A mangled name also carries the name it was mangled from. Stock's
    // demangler applies that name as a *second* symbol at the same address,
    // with `SourceType.ANALYSIS`, and makes it primary
    // (`DemangledAddressTable.applyTo`, :74-90;
    // `DemangledObject.applyDemangledName`, :527-555) -- so the mangled name
    // stays as evidence and the derived name is what a decompiler prints.
    symbols.retain(|symbol| symbol.source != DEMANGLE_SOURCE);
    let derived: Vec<lre_model::SymbolRow> = symbols
        .iter()
        .filter(|symbol| symbol.address.space == lre_model::AddressSpace::Ram)
        .filter_map(|symbol| {
            let demangled = crate::demangle::demangle(&symbol.name)?;
            Some(lre_model::SymbolRow {
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
            from: lre_model::Address::ram(x.from),
            to: lre_model::Address::ram(x.to),
            kind: x.kind.clone(),
            // Containment resolves at query time from the function table.
            function: None,
            provenance: lre_model::FactProvenance {
                kind: lre_model::FactKind::Inferred,
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
    // Each rule owns its rows: the ABI-reserved slot and a stub's own branch
    // are different evidence for the same kind of correction.
    for source in [PLT_HEADER_SOURCE, THUNK_SOURCE, SHARED_RETURN_SOURCE] {
        let overrides: Vec<lre_model::FlowOverrideRow> = imp
            .flow_overrides
            .iter()
            .filter(|(_, rule)| *rule == source)
            .map(|(address, rule)| lre_model::FlowOverrideRow {
                address: lre_model::Address::ram(*address),
                kind: "callreturn".into(),
                provenance: lre_model::FactProvenance {
                    kind: lre_model::FactKind::Inferred,
                    source: (*rule).into(),
                    confidence: None,
                },
            })
            .collect();
        db.replace_inferred_flow_overrides(pid, source, &overrides)?;
    }
    let tagged: std::collections::HashSet<u64> =
        imp.dynamic_labels.iter().map(|(address, _)| *address).collect();
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
    let linkage_declared: std::collections::HashSet<u64> =
        imp.function_slots.iter().map(|(address, _)| *address).collect();
    let array_declared: std::collections::HashSet<u64> =
        imp.initializer_slots.iter().map(|(address, _)| *address).collect();
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
    let definitions: Vec<lre_model::DataDefinitionRow> = imp
        .plt_reserved_slots
        .iter()
        .filter(|(address, _)| {
            // A word the ABI reserves holds no code address -- unless a
            // relocation names a function for it, which makes it a linkage
            // slot whatever its position in the table.
            !imp.function_slots.iter().any(|(slot, _)| slot == address)
        })
        .map(|(address, width)| lre_model::DataDefinitionRow {
            address: lre_model::Address::ram(*address),
            data_type: pointee(*address),
            size: *width,
            provenance: lre_model::FactProvenance {
                kind: lre_model::FactKind::Inferred,
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
    let mut linkage: Vec<lre_model::DataDefinitionRow> = imp
        .function_slots
        .iter()
        .filter(|(address, _)| !tagged.contains(address))
        .map(|(address, width)| lre_model::DataDefinitionRow {
            address: lre_model::Address::ram(*address),
            data_type: pointee(*address),
            size: *width,
            provenance: lre_model::FactProvenance {
                kind: lre_model::FactKind::Inferred,
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
    let mut objects: Vec<lre_model::DataDefinitionRow> = imp
        .object_sizes
        .iter()
        .map(|(address, size)| lre_model::DataDefinitionRow {
            address: lre_model::Address::ram(*address),
            data_type: if *size > 8 { "undefined1[]".into() } else { "undefined".into() },
            size: *size,
            provenance: lre_model::FactProvenance {
                kind: lre_model::FactKind::Inferred,
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
    let mut widths: Vec<lre_model::DataDefinitionRow> = imp
        .reference_widths
        .iter()
        .filter(|(address, _)| {
            !imp.plt_reserved_slots.iter().any(|(slot, _)| slot == address)
                && !imp.pointer_slots.iter().any(|(slot, _)| slot == address)
                && !imp.got_slots.iter().any(|(slot, _)| slot == address)
                && !imp.object_sizes.iter().any(|(slot, _)| slot == address)
                && !imp.function_slots.iter().any(|(slot, _)| slot == address)
        })
        .map(|(address, width)| lre_model::DataDefinitionRow {
            address: lre_model::Address::ram(*address),
            data_type: "undefined".into(),
            size: *width,
            provenance: lre_model::FactProvenance {
                kind: lre_model::FactKind::Inferred,
                source: DATA_WIDTH_SOURCE.into(),
                confidence: None,
            },
        })
        .collect();
    widths.sort_by_key(|row| row.address.offset);
    widths.dedup_by_key(|row| row.address.offset);
    db.replace_inferred_data_definitions(pid, DATA_WIDTH_SOURCE, &widths)?;
    let mut slots: Vec<lre_model::DataDefinitionRow> = imp
        .initializer_slots
        .iter()
        .map(|(address, width)| lre_model::DataDefinitionRow {
            address: lre_model::Address::ram(*address),
            data_type: pointee(*address),
            size: *width,
            provenance: lre_model::FactProvenance {
                kind: lre_model::FactKind::Inferred,
                source: ELF_POINTER_SOURCE.into(),
                confidence: None,
            },
        })
        .collect();
    slots.sort_by_key(|row| row.address.offset);
    slots.dedup_by_key(|row| row.address.offset);
    db.replace_inferred_data_definitions(pid, ELF_POINTER_SOURCE, &slots)?;
    let mut pointers: Vec<lre_model::DataDefinitionRow> = imp
        .pointer_slots
        .iter()
        .map(|(address, width)| lre_model::DataDefinitionRow {
            address: lre_model::Address::ram(*address),
            data_type: pointee(*address),
            size: *width,
            provenance: lre_model::FactProvenance {
                kind: lre_model::FactKind::Inferred,
                source: DATA_POINTER_SOURCE.into(),
                confidence: None,
            },
        })
        .collect();
    pointers.sort_by_key(|row| row.address.offset);
    pointers.dedup_by_key(|row| row.address.offset);
    db.replace_inferred_data_definitions(pid, DATA_POINTER_SOURCE, &pointers)?;
    let mut got: Vec<lre_model::DataDefinitionRow> = imp
        .got_slots
        .iter()
        .filter(|(address, _)| {
            // `.got` is walked at load time, before the pass that reads a
            // word and finds a function's entry in it (m4-027); that pass's
            // fact is the stronger one.
            !imp.pointer_slots.iter().any(|(slot, _)| slot == address)
                && !imp.function_slots.iter().any(|(slot, _)| slot == address)
        })
        .map(|(address, width)| lre_model::DataDefinitionRow {
            address: lre_model::Address::ram(*address),
            data_type: pointee(*address),
            size: *width,
            provenance: lre_model::FactProvenance {
                kind: lre_model::FactKind::Inferred,
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
    let conventions: Vec<lre_model::CallingConventionRow> = imp
        .process_entry
        .zip(entry_model)
        .map(|(entry, model)| lre_model::CallingConventionRow {
            function: lre_model::Address::ram(entry),
            convention: model.to_string(),
            provenance: lre_model::FactProvenance {
                kind: lre_model::FactKind::Inferred,
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
    let sites: Vec<lre_model::ExceptionSiteRow> = imp
        .exception_sites
        .iter()
        .map(|site| lre_model::ExceptionSiteRow {
            function: lre_model::Address::ram(site.function),
            start: lre_model::Address::ram(site.start),
            end: lre_model::Address::ram(site.end),
            landing_pad: lre_model::Address::ram(site.landing_pad),
            provenance: lre_model::FactProvenance {
                kind: lre_model::FactKind::Asserted,
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
                &lre_model::ReturnBehaviorRow {
                    function: lre_model::Address::ram(function.entry),
                    no_return: true,
                    provenance: lre_model::FactProvenance {
                        kind: lre_model::FactKind::Inferred,
                        source: KNOWN_NAME_SOURCE.into(),
                        confidence: None,
                    },
                },
            )?;
        }
    }
    // Each rule owns its rows, so one pass never deletes another's facts.
    for source in [THUNK_SOURCE] {
        let thunks: Vec<lre_model::ThunkRow> = imp
            .thunks
            .iter()
            .filter(|thunk| thunk.source == source)
            .map(|thunk| lre_model::ThunkRow {
                function: lre_model::Address::ram(thunk.entry),
                thunked: lre_model::Address::ram(thunk.destination),
                kind: thunk.kind,
                provenance: lre_model::FactProvenance {
                    kind: lre_model::FactKind::Inferred,
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
        phases: imp.phases.clone(),
        flow: imp.flow,
        patterns: imp.patterns_seen.clone(),
        references_refused: imp.references_refused,
        discovery_note: imp.discovery_note.clone(),
        switch: Some(lre_model::SwitchStats {
            vsa_resolved: imp.switch_vsa_resolved as u64,
            vsa_refused: imp.switch_vsa_refused as u64,
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


/// Context for candidate pre-pass confirmation.
pub struct CandidateFilterContext<'a> {
    pub mappings: &'a [Mapping],
    pub known_extents: &'a [(u64, u64)],
    pub initial_seeds: &'a HashSet<u64>,
}

/// Rejects non-code and owned bytes before requesting SLEIGH evidence.
pub fn candidate_address_is_valid(cand: u64, ctx: &CandidateFilterContext) -> bool {
    ctx.mappings.iter().any(|mapping| {
        mapping.flags & 0x4 != 0 && cand >= mapping.vaddr && cand - mapping.vaddr < mapping.size
    }) && !ctx
        .known_extents
        .iter()
        .any(|&(entry, size)| cand > entry && cand - entry < size)
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
mod tests {
    use super::*;
    use super::discovery::flow_discover_with_provider;
    #[test]
    fn elf_data_pointer_waits_for_flow_and_walks_indirect_call_fallthrough() {
        use crate::native_runtime::{FlowKind, FlowResult};
        let mut bytes = vec![0; 0x300];
        bytes[..6].copy_from_slice(b"\x7fELF\x02\x01");
        for (offset, value) in [(16, 2_u16), (18, 0x3e), (58, 64), (60, 4), (62, 3)] {
            bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        }
        for (offset, value) in [(24, 0x1000_u64), (40, 0x200),
                                (0x248, 6), (0x250, 0x1000), (0x258, 0x100), (0x260, 0x80),
                                (0x288, 3), (0x290, 0x2000), (0x298, 0x180), (0x2a0, 16),
                                (0x2d8, 0x1a0), (0x2e0, 13),
                                (0x180, 0x1020), (0x188, 0x1030)] {
            bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        for (offset, value) in [(0x240, 1_u32), (0x244, 1), (0x280, 7), (0x284, 1), (0x2c4, 3)] {
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        bytes[0x100..0x180].fill(1);
        bytes[0x1a0..0x1ad].copy_from_slice(b"\0.text\0.data\0");
        let mut imp = import_elf(&bytes).unwrap();
        assert!(!imp.functions.iter().any(|f| f.entry == 0x1020));
        flow_discover_with_provider(&mut imp, |_| Vec::new());
        assert!(!imp.functions.iter().any(|f| f.entry == 0x1020));
        flow_discover_with_provider(&mut imp, |addresses| addresses.iter().map(|&address| {
            let (kind, fallthrough, targets) = match address {
                0x1020 => (FlowKind::CallInd, Some(0x1024), vec![]),
                0x1024 => (FlowKind::Call, Some(0x1028), vec![0x1040]),
                0x1030 => (FlowKind::Bad, None, vec![]),
                _ => (FlowKind::Return, None, vec![]),
            };
            FlowResult { terminal: kind == FlowKind::Return, conditional: false, return_op: kind == FlowKind::Return, delay_slots: Vec::new(), no_op: false, pure_jump: false, address, length: 4, fallthrough, targets, kind, mode: None, target_modes: Vec::new() }
        }).collect());
        assert!(imp.functions.iter().any(|f| f.entry == 0x1020));
        assert!(imp.functions.iter().any(|f| f.entry == 0x1040),
                "pointer-rooted traversal must continue after an indirect call");
        assert!(!imp.functions.iter().any(|f| f.entry == 0x1030));
        assert!(imp.xrefs.iter().any(|x| x.from == 0x2000 && x.to == 0x1020
                && x.kind == "DATA" && x.provenance == "native-import:elf-pointer"));
    }

    #[test]
    fn distant_branch_does_not_claim_unvisited_gap() {
        use crate::native_runtime::{FlowKind, FlowResult};
        let mut imp = NativeImport {
            mappings: vec![Mapping {
                vaddr: 0x1000, size: 0x2010, file_off: 0, flags: 6,
                bytes: vec![0x90; 0x2010],
            }],
            functions: vec![NativeFunction { entry: 0x1000, name: "entry".into(), size: 1 }],
            reloc_candidates: vec![0x2000, 0x3001],
            ..Default::default()
        };
        flow_discover_with_provider(&mut imp, |addresses| addresses.iter().map(|&address| {
            FlowResult { terminal: address != 0x1000, conditional: false, return_op: address != 0x1000, delay_slots: Vec::new(), no_op: false, pure_jump: false, address, length: 4, fallthrough: None,
            targets: if address == 0x1000 { vec![0x3000] } else { vec![] },
            kind: if address == 0x1000 { FlowKind::Branch } else { FlowKind::Return },
            mode: None, target_modes: Vec::new(),
            }
        }).collect());
        assert!(imp.functions.iter().any(|f| f.entry == 0x2000),
                "a distant branch must not suppress a function in the unvisited gap");
        assert!(!imp.functions.iter().any(|f| f.entry == 0x3001),
                "an instruction-interior pointer must still be rejected");
    }



    #[test]
    fn an_elf_records_the_machine_it_names_and_selects_no_language_alone() {
        // The machine and flags an ELF header names are facts of the file;
        // which language answers for them is the install's decision, made by
        // `opinion::elf_selection` and tested against the pinned tree there.
        // A parse on its own selects nothing, so no caller can inherit a
        // language that no install agreed to.
        let mut bytes = elf32_with_pltgot(16);
        bytes[36..40].copy_from_slice(&0x0580_0000u32.to_le_bytes()); // e_flags
        let import = import_elf(&bytes).unwrap();
        assert_eq!(
            import.elf_machine,
            Some(crate::opinion::ElfMachine {
                machine: 3,
                flags: 0x0580_0000,
                bits: 32,
                big_endian: false,
            })
        );
        assert!(import.language.is_empty() && import.compiler.is_none());

        // With an install, the same bytes are answered from its data.
        let cfg = crate::session::RuntimeConfig::from_env();
        let mut selected = import;
        if cfg.ghidra_install.join("Ghidra/Processors").is_dir() {
            select_language(&mut selected, &cfg).unwrap();
            assert_eq!(selected.language, "x86:LE:32:default");
            assert_eq!(selected.compiler.as_deref(), Some("gcc"));
        }
        // A machine no install declares is refused rather than guessed.
        let mut unknown = selected;
        unknown.elf_machine = Some(crate::opinion::ElfMachine {
            machine: 0xfffe,
            flags: 0,
            bits: 32,
            big_endian: false,
        });
        assert!(select_language(&mut unknown, &cfg).is_err());
    }

    #[test]
    fn elf32_startup_section_seeds() {
        for be in [false, true] {
            let word = |v: u32| if be { v.to_be_bytes() } else { v.to_le_bytes() };
            let half = |v: u16| if be { v.to_be_bytes() } else { v.to_le_bytes() };
            let mut data = vec![0u8; 0x400];
            data[..6].copy_from_slice(if be { b"\x7fELF\x01\x02" } else { b"\x7fELF\x01\x01" });
            for (offset, value) in [(16, 2), (18, if be { 20 } else { 3 }),
                                    (46, 40), (48, 5), (50, 4)] {
                data[offset..offset + 2].copy_from_slice(&half(value));
            }
            data[32..36].copy_from_slice(&word(0x100));
            let names = b"\0.init\0.fini\0.plt\0.shstrtab\0";
            data[0x300..0x300 + names.len()].copy_from_slice(names);
            for (index, name, typ, flags, addr, offset, size) in [
                (1usize, 1, 1, 6, 0x1000, 0x340, 16),
                (2, 7, 1, 6, 0x2000, 0x350, 16),
                (3, 13, 1, 6, 0x3000, 0x360, 32),
                (4, 18, 3, 0, 0, 0x300, names.len() as u32),
            ] {
                let start = 0x100 + index * 40;
                for (field, value) in [name, typ, flags, addr, offset, size].into_iter().enumerate() {
                    data[start + field * 4..start + field * 4 + 4].copy_from_slice(&word(value));
                }
            }
            let import = import_elf(&data).unwrap();
            let entries: Vec<_> = import.functions.iter().map(|f| (f.entry, f.name.as_str())).collect();
            assert_eq!(entries, [(0x1000, "_init"), (0x2000, "_fini"), (0x3000, "_plt")],
                       "stripped ELF32 must retain loader-declared executable starts");
            // Section names alone do not make data executable.
            for index in 1..=3 {
                let flags = 0x100 + index * 40 + 8;
                data[flags..flags + 4].copy_from_slice(&word(2));
            }
            assert!(import_elf(&data).unwrap().functions.is_empty());
        }
    }

    #[test]
    fn elf_load_populates_functions() {
        // Build a tiny synthetic ELF64 with one symtab entry.
        let mut b = vec![0u8; 0x1000];
        b[0..4].copy_from_slice(b"\x7fELF");
        b[4] = 2;
        b[5] = 1;
        b[18..20].copy_from_slice(&0x3eu16.to_le_bytes());
        // e_entry
        b[24..32].copy_from_slice(&0x401000u64.to_le_bytes());
        // ehdr: e_shoff (0x200), e_shentsize (64), e_shnum (4),
        // e_shstrndx (3)
        b[40..48].copy_from_slice(&0x200u64.to_le_bytes());
        b[58..60].copy_from_slice(&64u16.to_le_bytes());
        b[60..62].copy_from_slice(&4u16.to_le_bytes());
        b[62..64].copy_from_slice(&3u16.to_le_bytes());
        // section 0 null; section 1 .text; section 2 .symtab; section 3 .strtab
        for (o, typ, flags, addr, off, size, link) in [
            (0x200usize, 0u32, 0u64, 0u64, 0u64, 0u64, 0u32),
            (0x240, 1, 0x2, 0x401000, 0x300, 0x10, 0), // .text
            (0x280, 2, 0, 0, 0x400, 24, 3), // .symtab -> .strtab
            (0x2c0, 3, 0, 0, 0x380, 8, 0), // .strtab
        ] {
            b[o..o + 4].copy_from_slice(&0u32.to_le_bytes());
            b[o + 4..o + 8].copy_from_slice(&typ.to_le_bytes());
            b[o + 8..o + 16].copy_from_slice(&flags.to_le_bytes());
            b[o + 16..o + 24].copy_from_slice(&addr.to_le_bytes());
            b[o + 24..o + 32].copy_from_slice(&off.to_le_bytes());
            b[o + 32..o + 40].copy_from_slice(&size.to_le_bytes());
            b[o + 40..o + 44].copy_from_slice(&link.to_le_bytes());
        }
        b[0x380] = 0;
        b[0x381..0x381 + 4].copy_from_slice(b"add\0");
        // symtab entry: st_name=1, info=0x12 (STT_FUNC|STB_GLOBAL),
        // st_size=4, st_value=0x401000
        b[0x400..0x404].copy_from_slice(&1u32.to_le_bytes());
        b[0x404] = 0x12;
        b[0x408..0x410].copy_from_slice(&0x401000u64.to_le_bytes());
        b[0x410..0x418].copy_from_slice(&4u64.to_le_bytes());
        // shstrtab for names: .text\0.symtab\0.strtab\0
        {
            let shstr = b".text\0.symtab\0.strtab\0";
            b[0x800..0x800 + shstr.len()].copy_from_slice(shstr);
        }
        // set section name offsets
        for (o, off) in [(0x240usize, 1usize), (0x280, 7), (0x2c0, 14)] {
            b[o..o + 4].copy_from_slice(&(off as u32).to_le_bytes());
        }
        let mut imp = import_elf(&b).unwrap();
        let f = imp.functions.iter().find(|f| f.name == "add").unwrap();
        assert_eq!(f.entry, 0x401000);
        assert_eq!(f.size, 4);
        assert_eq!(imp.mappings[0].vaddr, 0x401000);
        let cfg = crate::session::RuntimeConfig::from_env();
        if cfg.ghidra_install.join("Ghidra/Processors").is_dir() {
            select_language(&mut imp, &cfg).unwrap();
            assert_eq!(imp.language, "x86:LE:64:default");
        }
    }

    #[test]
    fn exported_symbol_names_win_over_internal_aliases() {
        // Three FUNC symbols share one address, as glibc does for `abort`:
        // a LOCAL alias, a versioned export, and the plain export.
        let mut b = vec![0u8; 0x1000];
        b[0..4].copy_from_slice(b"\x7fELF");
        b[4] = 2;
        b[5] = 1;
        b[18..20].copy_from_slice(&0x3eu16.to_le_bytes());
        b[24..32].copy_from_slice(&0x401000u64.to_le_bytes());
        b[40..48].copy_from_slice(&0x200u64.to_le_bytes());
        b[58..60].copy_from_slice(&64u16.to_le_bytes());
        b[60..62].copy_from_slice(&4u16.to_le_bytes());
        b[62..64].copy_from_slice(&3u16.to_le_bytes());
        for (o, typ, flags, addr, off, size, link) in [
            (0x200usize, 0u32, 0u64, 0u64, 0u64, 0u64, 0u32),
            (0x240, 1, 0x2, 0x401000, 0x300, 0x10, 0),
            (0x280, 2, 0, 0, 0x400, 72, 3),
            (0x2c0, 3, 0, 0, 0x380, 40, 0),
        ] {
            b[o..o + 4].copy_from_slice(&0u32.to_le_bytes());
            b[o + 4..o + 8].copy_from_slice(&typ.to_le_bytes());
            b[o + 8..o + 16].copy_from_slice(&flags.to_le_bytes());
            b[o + 16..o + 24].copy_from_slice(&addr.to_le_bytes());
            b[o + 24..o + 32].copy_from_slice(&off.to_le_bytes());
            b[o + 32..o + 40].copy_from_slice(&size.to_le_bytes());
            b[o + 40..o + 44].copy_from_slice(&link.to_le_bytes());
        }
        let strtab = b"\0__GI_abort\0abort@@GLIBC_2.2.5\0abort\0";
        b[0x380..0x380 + strtab.len()].copy_from_slice(strtab);
        // st_info: 0x02 = LOCAL FUNC, 0x12 = GLOBAL FUNC.
        for (index, (name_off, info)) in [(1u32, 0x02u8), (12, 0x12), (31, 0x12)]
            .into_iter()
            .enumerate()
        {
            let o = 0x400 + index * 24;
            b[o..o + 4].copy_from_slice(&name_off.to_le_bytes());
            b[o + 4] = info;
            b[o + 8..o + 16].copy_from_slice(&0x401000u64.to_le_bytes());
            b[o + 16..o + 24].copy_from_slice(&8u64.to_le_bytes());
        }
        let shstr = b".text\0.symtab\0.strtab\0";
        b[0x800..0x800 + shstr.len()].copy_from_slice(shstr);
        for (o, off) in [(0x240usize, 1usize), (0x280, 7), (0x2c0, 14)] {
            b[o..o + 4].copy_from_slice(&(off as u32).to_le_bytes());
        }
        let functions = import_elf(&b).unwrap().functions;
        let named: Vec<_> = functions
            .iter()
            .filter(|f| f.entry == 0x401000)
            .map(|f| f.name.as_str())
            .collect();
        assert_eq!(
            named, ["abort"],
            "an internal alias must not shadow the exported name a name list matches"
        );
    }

    #[test]
    fn pe_memory_regions_preserve_section_permissions() {
        // Section flags: READ (0x40000000) alone must NOT be executable.
        let mut b = vec![0u8; 0x200];
        b[0..2].copy_from_slice(b"MZ");
        b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        b[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        b[0x86..0x88].copy_from_slice(&1u16.to_le_bytes()); // 1 section
        b[0x94..0x96].copy_from_slice(&0xf0u16.to_le_bytes()); // opt size
        b[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes()); // PE32+ magic
        b[0xb0..0xb8].copy_from_slice(&0x140000000u64.to_le_bytes()); // ImageBase at opt + 24
        let sec = 0x80 + 24 + 0xf0;
        b[sec + 8..sec + 12].copy_from_slice(&0x1000u32.to_le_bytes()); // vsize
        b[sec + 16..sec + 20].copy_from_slice(&0x200u32.to_le_bytes()); // raw size
        b[sec + 20..sec + 24].copy_from_slice(&0x100u32.to_le_bytes()); // raw ptr
        b[sec + 36..sec + 40].copy_from_slice(&0x40000000u32.to_le_bytes()); // READ only
        let imp = import_pe(&b).unwrap();
        let db = ProjectDb::open_in_memory().unwrap();
        let pid = db.upsert_program("pe", &imp.language, &native_provenance()).unwrap();
        store_import(&db, "pe", &imp, None).unwrap();
        assert_eq!(db.memory_regions(pid).unwrap()[0].permissions, "r--");
        // Executable, writable code retains all three permissions.
        b[sec + 36..sec + 40].copy_from_slice(&0xe0000000u32.to_le_bytes());
        let imp = import_pe(&b).unwrap();
        store_import(&db, "pe", &imp, None).unwrap();
        assert_eq!(db.memory_regions(pid).unwrap()[0].permissions, "rwx");
    }

    #[test]
    fn truncated_elf_magic_errors_not_panics() {
        assert!(import_elf(b"\x7fELF").is_err());
        assert!(import_elf(b"\x7fELF\x02\x01").is_err());
        assert!(import_elf(b"\x7fELF\x02\x01\x00\x00").is_err());
    }

    #[test]
    fn malformed_inputs_never_panic() {
        // Deterministic PRNG (xorshift64) fuzz smoke: truncated headers,
        // magic-only files, and arbitrary byte soups must return typed
        // errors (or a parse) — never panic or OOM (review QA-002).
        let mut state: u64 = 0x9e3779b97f4a7c15;
        let mut rand = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for len in 1..=64usize {
            for _ in 0..64 {
                let mut bytes = vec![0u8; len];
                for b in bytes.iter_mut() {
                    *b = (rand() & 0xff) as u8;
                }
                let _ = import_elf(&bytes);
                let _ = import_pe(&bytes);
                if len >= 4 {
                    let _ = crate::disasm::decode(&bytes, 0x400000);
                }
                // magic-only truncated variants
                let _ = import_elf(&b"\x7fELF"[..len.min(4)]);
                let _ = import_pe(&b"MZ"[..len.min(2)]);
            }
        }
        // Structured but corrupted: valid ELF header with bogus section
        // table offsets/counts.
        let mut b = vec![0u8; 0x100];
        b[0..4].copy_from_slice(b"\x7fELF");
        b[4] = 2;
        b[5] = 1;
        b[40..48].copy_from_slice(&(0x100000000u64).to_le_bytes()); // absurd shoff
        b[58..60].copy_from_slice(&0xffffu16.to_le_bytes()); // shentsize
        b[60..62].copy_from_slice(&0xffffu16.to_le_bytes()); // shnum
        let _ = import_elf(&b);
    }

    #[test]
    fn pe_image_base_reads_header_field() {
        // Minimal MZ + PE signature + optional header carrying ImageBase.
        let mut b = vec![0u8; 0x100];
        b[0..2].copy_from_slice(b"MZ");
        b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        b[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes()); // PE32+ magic
        b[0xb0..0xb8].copy_from_slice(&0x140000000u64.to_le_bytes());
        assert_eq!(pe_image_base(&b), Some(0x140000000));
        assert_eq!(pe_image_base(b"\x7fELF"), None);
    }
    #[test]
    fn regression_candidates_inside_known_bodies_are_rejected() {
        let mut imp = NativeImport {
            mappings: vec![Mapping {
                vaddr: 0x1000,
                size: 0x100,
                file_off: 0,
                flags: 0x4,
                bytes: vec![0x90; 0x100],
            }],
            functions: vec![NativeFunction {
                entry: 0x1000,
                name: "known_outer".into(),
                size: 0x80, // covers 0x1000..0x1080
            }],
            reloc_candidates: vec![0x1040], // strictly inside known_outer
            format: "ELF".into(),
            language: "x86:LE:64:default".into(),
            ..Default::default()
        };
        flow_discover_with_provider(&mut imp, |addresses| addresses.iter().map(|&address| {
            crate::native_runtime::FlowResult { terminal: true, conditional: false, return_op: true, delay_slots: Vec::new(), no_op: false, address, length: 1, fallthrough: None,
                targets: vec![], kind: crate::native_runtime::FlowKind::Return, pure_jump: false,
                mode: None, target_modes: Vec::new(),
            }
        }).collect());
        assert!(!imp.functions.iter().any(|f| f.entry == 0x1040));
    }

    #[test]
    fn regression_console_absence_does_not_promote_unconfirmed_candidates() {
        let mut imp = NativeImport {
            mappings: vec![Mapping {
                vaddr: 0x1000,
                size: 0x200,
                file_off: 0,
                flags: 0x4,
                bytes: vec![0x90; 0x200],
            }],
            functions: vec![NativeFunction {
                entry: 0x1000,
                name: "root".into(),
                size: 0x10,
            }],
            reloc_candidates: vec![0x1100],
            cfg: crate::session::RuntimeConfig {
                console_path: Some(std::path::PathBuf::from("/nonexistent/decomp_native")),
                ..Default::default()
            },
            format: "ELF".into(),
            language: "x86:LE:64:default".into(),
            ..Default::default()
        };
        drop(discovery::discover_seeded(&mut imp));
        // Unconfirmed candidate 0x1100 must NOT be promoted when console is absent/failing
        assert_eq!(imp.functions.len(), 1);
        assert_eq!(imp.functions[0].entry, 0x1000);
    }

    #[test]
    fn regression_invalid_relocation_target_is_not_promoted() {
        let mut imp = NativeImport {
            mappings: vec![Mapping {
                vaddr: 0x1000,
                size: 0x100,
                file_off: 0,
                flags: 0x4,
                bytes: vec![0x90; 0x100],
            }],
            functions: vec![NativeFunction {
                entry: 0x1000,
                name: "entry".into(),
                size: 0x10,
            }],
            reloc_candidates: vec![0x99999], // out of bounds / non-code
            format: "ELF".into(),
            language: "x86:LE:64:default".into(),
            ..Default::default()
        };
        flow_discover_with_provider(&mut imp, |addresses| addresses.iter().map(|&address| {
            crate::native_runtime::FlowResult { terminal: true, conditional: false, return_op: true, delay_slots: Vec::new(), no_op: false, address, length: 1, fallthrough: None,
                targets: vec![], kind: crate::native_runtime::FlowKind::Return, pure_jump: false,
                mode: None, target_modes: Vec::new(),
            }
        }).collect());
        assert!(!imp.functions.iter().any(|f| f.entry == 0x99999));
    }
    #[test]
    fn test_filter_candidate_rejects_internal_even_with_valid_flow() {
        use crate::native_runtime::FlowResult;
        let mappings = vec![Mapping {
            vaddr: 0x1000,
            size: 0x100,
            file_off: 0,
            flags: 0x4,
            bytes: vec![0x90; 0x100],
        }];
        let extents = vec![(0x1000, 0x50)]; // 0x1000..0x1050
        let initial_seeds = HashSet::from([0x1000]);
        let ctx = CandidateFilterContext {
            mappings: &mappings,
            known_extents: &extents,
            initial_seeds: &initial_seeds,
        };

        // Candidate 0x1020 is internal to 0x1000..0x1050.
        let result = candidate_address_is_valid(0x1020, &ctx)
            && candidate_flow_is_valid(
                0x1020,
                &ctx,
                &FlowResult {
                    terminal: false,
                    conditional: false,
                    return_op: false,
                    delay_slots: Vec::new(),
                    no_op: false,
                    pure_jump: false,
                    address: 0x1020,
                    length: 4,
                    fallthrough: Some(0x1024),
                    targets: Vec::new(),
                    kind: crate::native_runtime::FlowKind::Fallthrough,
            mode: None, target_modes: Vec::new(),
                },
            );
        assert!(
            !result,
            "candidate inside known function must be rejected even with valid flow"
        );
    }

    #[test]
    fn test_filter_candidate_rejects_out_of_code_even_with_valid_flow() {
        use crate::native_runtime::FlowResult;
        let mappings = vec![
            Mapping {
                vaddr: 0x1000,
                size: 0x100,
                file_off: 0,
                flags: 0x4, // executable
                bytes: vec![0x90; 0x100],
            },
            Mapping {
                vaddr: 0x2000,
                size: 0x100,
                file_off: 0x100,
                flags: 0x2, // non-executable data
                bytes: vec![0x00; 0x100],
            },
        ];
        let extents = vec![(0x1000, 0x20)];
        let initial_seeds = HashSet::from([0x1000]);
        let ctx = CandidateFilterContext {
            mappings: &mappings,
            known_extents: &extents,
            initial_seeds: &initial_seeds,
        };

        // Candidate 0x2050 is in a data mapping despite its valid instruction.
        let result = candidate_address_is_valid(0x2050, &ctx)
            && candidate_flow_is_valid(
                0x2050,
                &ctx,
                &FlowResult {
                    terminal: false,
                    conditional: false,
                    return_op: false,
                    delay_slots: Vec::new(),
                    no_op: false,
                    pure_jump: false,
                    address: 0x2050,
                    length: 4,
                    fallthrough: Some(0x2054),
                    targets: Vec::new(),
                    kind: crate::native_runtime::FlowKind::Fallthrough,
            mode: None, target_modes: Vec::new(),
                },
            );
        assert!(
            !result,
            "candidate outside executable mapping must be rejected even with valid flow"
        );
    }

    #[test]
    fn test_pe_data_to_data_relocation_recorded_in_xrefs() {
        // Build mock PE with .text (code) and .data (data) sections.
        // Relocation in .data points to .data (data-to-data).
        let mut b = vec![0u8; 0x400];
        b[0..2].copy_from_slice(b"MZ");
        b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        b[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes()); // AMD64
        b[0x86..0x88].copy_from_slice(&3u16.to_le_bytes()); // 3 sections (.text, .data, .reloc)
        b[0x94..0x96].copy_from_slice(&0xf0u16.to_le_bytes()); // opt size
        b[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes()); // PE32+
        b[0xb0..0xb8].copy_from_slice(&0x140000000u64.to_le_bytes()); // ImageBase at opt + 24
        // NumberOfRvaAndSizes at opt + 108: 16 directories
        b[0x98 + 108..0x98 + 112].copy_from_slice(&16u32.to_le_bytes());
        // Directory 5 (.reloc) at opt + 152:
        b[0x98 + 152..0x98 + 156].copy_from_slice(&0x3000u32.to_le_bytes()); // RVA
        b[0x98 + 156..0x98 + 160].copy_from_slice(&16u32.to_le_bytes()); // Size 16
        let sec = 0x80 + 24 + 0xf0;
        // Sec 0: .text (RVA 0x1000, size 0x1000, raw 0x100, raw_sz 0x100, flags 0x60000020 code)
        b[sec..sec + 5].copy_from_slice(b".text");
        b[sec + 8..sec + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        b[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        b[sec + 16..sec + 20].copy_from_slice(&0x100u32.to_le_bytes());
        b[sec + 20..sec + 24].copy_from_slice(&0x100u32.to_le_bytes());
        b[sec + 36..sec + 40].copy_from_slice(&0x60000020u32.to_le_bytes());

        // Sec 1: .data (RVA 0x2000, size 0x1000, raw 0x200, raw_sz 0x100, flags 0xc0000040 data)
        let sec1 = sec + 40;
        b[sec1..sec1 + 5].copy_from_slice(b".data");
        b[sec1 + 8..sec1 + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        b[sec1 + 12..sec1 + 16].copy_from_slice(&0x2000u32.to_le_bytes());
        b[sec1 + 16..sec1 + 20].copy_from_slice(&0x100u32.to_le_bytes());
        b[sec1 + 20..sec1 + 24].copy_from_slice(&0x200u32.to_le_bytes());
        b[sec1 + 36..sec1 + 40].copy_from_slice(&0xc0000040u32.to_le_bytes());
        // Put a pointer at raw 0x200 (RVA 0x2000) pointing to .data at 0x140002080 (data-to-data)
        b[0x200..0x208].copy_from_slice(&0x140002080u64.to_le_bytes());

        // Sec 2: .reloc (RVA 0x3000, size 0x1000, raw 0x300, raw_sz 0x100, flags 0x42000040)
        let sec2 = sec + 80;
        b[sec2..sec2 + 6].copy_from_slice(b".reloc");
        b[sec2 + 8..sec2 + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        b[sec2 + 12..sec2 + 16].copy_from_slice(&0x3000u32.to_le_bytes());
        b[sec2 + 16..sec2 + 20].copy_from_slice(&16u32.to_le_bytes());
        b[sec2 + 20..sec2 + 24].copy_from_slice(&0x300u32.to_le_bytes());
        b[sec2 + 36..sec2 + 40].copy_from_slice(&0x42000040u32.to_le_bytes());
        // Relocation block at 0x300:
        b[0x300..0x304].copy_from_slice(&0x2000u32.to_le_bytes()); // page RVA 0x2000
        b[0x304..0x308].copy_from_slice(&12u32.to_le_bytes()); // block size 12 (8 header + 2*2 entries)
        let entry0: u16 = (10 << 12) | 0; // DIR64 at off 0
        b[0x308..0x30a].copy_from_slice(&entry0.to_le_bytes());
        b[0x30a..0x30c].copy_from_slice(&0u16.to_le_bytes()); // padding

        let imp = import_pe(&b).unwrap();
        // 1. Data-to-data relocation must be emitted as DATA xref with pe-reloc provenance
        let xref = imp.xrefs.iter().find(|x| x.from == 0x140002000 && x.to == 0x140002080);
        assert!(xref.is_some(), "data-to-data relocation must be present in xrefs");
        assert_eq!(xref.unwrap().kind, "DATA");
        assert_eq!(xref.unwrap().provenance, "native-import:pe-reloc");

        // 2. Data-to-data relocation must NOT be promoted as a function candidate
        assert!(!imp.reloc_candidates.contains(&0x140002080), "data-to-data relocation must not be a function candidate");
    }

    #[test]
    fn test_pe32_fixture_import_and_discovery() {
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let path = manifest_dir.join("../../tests/fixtures-src/tiny_pe32.exe");
        assert!(path.is_file(), "committed fixture must exist at {}", path.display());
        let imp = load_native(&path).expect("tiny_pe32 must load cleanly");
        assert_eq!(imp.format, "PE");
        assert_eq!(imp.language, "x86:LE:32:default");
        assert_eq!(pe_image_base(&std::fs::read(&path).unwrap()), Some(0x400000));
        assert!(imp.functions.iter().any(|f| f.entry == 0x401400));
        assert!(imp.xrefs.iter().any(|x| x.provenance == "native-import:pe-reloc"));
        if crate::native_runtime::find_console(&imp.cfg).is_ok() {
            assert!(imp.functions.len() >= 10, "console discovery should find >= 10 functions, got {}", imp.functions.len());
        } else {
            assert!(!imp.functions.is_empty(), "entry function must be present");
        }
    }

    #[test]
    fn test_relocation_only_code_function_is_promoted() {
        use crate::native_runtime::{FlowKind, FlowResult};
        // Setup:
        // func_root at 0x1000 has normal instruction-sized flow:
        // 0x1000: push rbp (len 1, fall 0x1001)
        // 0x1001: mov rbp, rsp (len 3, fall 0x1004)
        // 0x1004: ret (len 1, Return) -> proven extent 0x1000..0x1005 (size 5).
        //
        // Relocation candidate 0x1040 is in the gap outside func_root's extent:
        // 0x1040: push rbp (len 1, fall 0x1041)
        // 0x1041: mov rbp, rsp (len 3, fall 0x1044) -> reaches 0x1044 via Fallthrough!
        // 0x1044: call 0x1080 (len 5, Call target 0x1080, fall 0x1049)
        // 0x1049: ret (len 1, Return)
        //
        // Candidate 0x1044 is reached through fallthrough from 0x1040 (internal target!).
        // Candidate 0x1080 is reached through Call (call target!).
        //
        // Assert:
        // 1. Relocation-only code function at 0x1040 IS PROMOTED to imp.functions.
        // 2. Call target 0x1080 REMAINS a separate function in imp.functions.
        // 3. Internal candidate 0x1044 reached through fallthrough is merged/dropped!
        let mut imp = NativeImport {
            mappings: vec![Mapping {
                vaddr: 0x1000,
                size: 0x200,
                file_off: 0,
                flags: 0x4, // executable
                bytes: vec![0x90; 0x200],
            }],
            functions: vec![NativeFunction {
                entry: 0x1000,
                name: "func_root".into(),
                size: 5, // 0x1000..0x1005
            }],
            reloc_candidates: vec![0x1040, 0x1044, 0x1080],
            format: "ELF".into(),
            language: "x86:LE:64:default".into(),
            ..Default::default()
        };

        flow_discover_with_provider(&mut imp, |chunk| {
            chunk.iter().map(|&addr| {
                match addr {
                    0x1000 => FlowResult { terminal: false, conditional: false, return_op: false, delay_slots: Vec::new(), no_op: false, pure_jump: false, address: 0x1000,
                    length: 1,
                    fallthrough: Some(0x1001),
                    targets: Vec::new(),
                    kind: FlowKind::Fallthrough,
                    mode: None, target_modes: Vec::new(), },
                    0x1001 => FlowResult { terminal: false, conditional: false, return_op: false, delay_slots: Vec::new(), no_op: false, pure_jump: false, address: 0x1001,
                    length: 3,
                    fallthrough: Some(0x1004),
                    targets: Vec::new(),
                    kind: FlowKind::Fallthrough,
                    mode: None, target_modes: Vec::new(), },
                    0x1004 => FlowResult { terminal: true, conditional: false, return_op: true, delay_slots: Vec::new(), no_op: false, pure_jump: false, address: 0x1004,
                    length: 1,
                    fallthrough: None,
                    targets: Vec::new(),
                    kind: FlowKind::Return,
                    mode: None, target_modes: Vec::new(), },
                    0x1040 => FlowResult { terminal: false, conditional: false, return_op: false, delay_slots: Vec::new(), no_op: false, pure_jump: false, address: 0x1040,
                    length: 1,
                    fallthrough: Some(0x1041),
                    targets: Vec::new(),
                    kind: FlowKind::Fallthrough,
                    mode: None, target_modes: Vec::new(), },
                    0x1041 => FlowResult { terminal: false, conditional: false, return_op: false, delay_slots: Vec::new(), no_op: false, pure_jump: false, address: 0x1041,
                    length: 3,
                    fallthrough: Some(0x1044),
                    targets: Vec::new(),
                    kind: FlowKind::Fallthrough,
                    mode: None, target_modes: Vec::new(), },
                    0x1044 => FlowResult { terminal: false, conditional: false, return_op: false, delay_slots: Vec::new(), no_op: false, pure_jump: false, address: 0x1044,
                    length: 5,
                    fallthrough: Some(0x1049),
                    targets: vec![0x1080],
                    kind: FlowKind::Call,
                    mode: None, target_modes: Vec::new(), },
                    0x1049 => FlowResult { terminal: true, conditional: false, return_op: true, delay_slots: Vec::new(), no_op: false, pure_jump: false, address: 0x1049,
                    length: 1,
                    fallthrough: None,
                    targets: Vec::new(),
                    kind: FlowKind::Return,
                    mode: None, target_modes: Vec::new(), },
                    0x1080 => FlowResult { terminal: true, conditional: false, return_op: true, delay_slots: Vec::new(), no_op: false, pure_jump: false, address: 0x1080,
                    length: 1,
                    fallthrough: None,
                    targets: Vec::new(),
                    kind: FlowKind::Return,
                    mode: None, target_modes: Vec::new(), },
                    other => FlowResult { terminal: true, conditional: false, return_op: true, delay_slots: Vec::new(), no_op: false, pure_jump: false, address: other,
                    length: 1,
                    fallthrough: None,
                    targets: Vec::new(),
                    kind: FlowKind::Return,
                    mode: None, target_modes: Vec::new(), },
                }
            }).collect()
        });

        // 1. Relocation-only code function at 0x1040 outside func_root's extent IS PROMOTED
        assert!(imp.functions.iter().any(|f| f.entry == 0x1040), "0x1040 must be promoted to a function");

        // 2. Call target 0x1080 remains a separate function
        assert!(imp.functions.iter().any(|f| f.entry == 0x1080), "call target 0x1080 must remain a separate function");

        // 3. Internal candidate 0x1044 reached through fallthrough from 0x1040 is merged/dropped
        assert!(!imp.functions.iter().any(|f| f.entry == 0x1044), "internal candidate 0x1044 reached via fallthrough must be merged/dropped");

        // 4. Function size of 0x1040 covers the full span 0x1040..0x104a (size 0xa)
        let f_1040 = imp.functions.iter().find(|f| f.entry == 0x1040).expect("0x1040 must be present");
        assert_eq!(f_1040.size, 0xa, "0x1040 function size must be 0xa (0x1040..0x104a)");
    }
    #[test]
    fn regression_load_native_pe32_data_to_data_relocation_never_becomes_function() {
        let mut b = vec![0u8; 0x600];
        b[0..2].copy_from_slice(b"MZ");
        b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        b[0x84..0x86].copy_from_slice(&0x014cu16.to_le_bytes()); // i386
        b[0x86..0x88].copy_from_slice(&3u16.to_le_bytes()); // 3 sections
        b[0x94..0x96].copy_from_slice(&0xe0u16.to_le_bytes()); // opt size 224
        let opt = 0x98;
        b[opt..opt + 2].copy_from_slice(&0x10bu16.to_le_bytes()); // PE32 magic
        b[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // entry RVA
        b[opt + 28..opt + 32].copy_from_slice(&0x400000u32.to_le_bytes()); // image base
        // NumberOfRvaAndSizes at opt + 92: 16 directories
        b[opt + 92..opt + 96].copy_from_slice(&16u32.to_le_bytes());
        // Relocation directory at opt + 136: RVA 0x3000, size 16
        b[opt + 136..opt + 140].copy_from_slice(&0x3000u32.to_le_bytes());
        b[opt + 140..opt + 144].copy_from_slice(&16u32.to_le_bytes());

        let sec = opt + 0xe0; // 0x178
        // Sec 0: .text (RVA 0x1000, size 0x1000, raw 0x200, raw_sz 0x100, exec)
        b[sec..sec + 5].copy_from_slice(b".text");
        b[sec + 8..sec + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        b[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        b[sec + 16..sec + 20].copy_from_slice(&0x100u32.to_le_bytes());
        b[sec + 20..sec + 24].copy_from_slice(&0x200u32.to_le_bytes());
        b[sec + 36..sec + 40].copy_from_slice(&0x60000020u32.to_le_bytes());
        b[0x200] = 0xc3; // ret at 0x401000

        // Sec 1: .data (RVA 0x2000, size 0x1000, raw 0x300, raw_sz 0x100, data)
        let sec1 = sec + 40;
        b[sec1..sec1 + 5].copy_from_slice(b".data");
        b[sec1 + 8..sec1 + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        b[sec1 + 12..sec1 + 16].copy_from_slice(&0x2000u32.to_le_bytes());
        b[sec1 + 16..sec1 + 20].copy_from_slice(&0x100u32.to_le_bytes());
        b[sec1 + 20..sec1 + 24].copy_from_slice(&0x300u32.to_le_bytes());
        b[sec1 + 36..sec1 + 40].copy_from_slice(&0xc0000040u32.to_le_bytes());
        // Put a 32-bit pointer at raw 0x300 (0x402000) pointing to 0x402080 (in .data)
        b[0x300..0x304].copy_from_slice(&0x402080u32.to_le_bytes());

        // Sec 2: .reloc (RVA 0x3000, size 0x1000, raw 0x400, raw_sz 0x100, reloc)
        let sec2 = sec + 80;
        b[sec2..sec2 + 6].copy_from_slice(b".reloc");
        b[sec2 + 8..sec2 + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        b[sec2 + 12..sec2 + 16].copy_from_slice(&0x3000u32.to_le_bytes());
        b[sec2 + 16..sec2 + 20].copy_from_slice(&16u32.to_le_bytes());
        b[sec2 + 20..sec2 + 24].copy_from_slice(&0x400u32.to_le_bytes());
        b[sec2 + 36..sec2 + 40].copy_from_slice(&0x42000040u32.to_le_bytes());
        // Relocation block at 0x400: page RVA 0x2000, block size 12
        b[0x400..0x404].copy_from_slice(&0x2000u32.to_le_bytes());
        b[0x404..0x408].copy_from_slice(&12u32.to_le_bytes());
        let entry0: u16 = (3 << 12) | 0; // HIGHLOW at offset 0
        b[0x408..0x40a].copy_from_slice(&entry0.to_le_bytes());

        let tmp_dir = std::env::temp_dir();
        let tmp_path = tmp_dir.join("test_pe32_data_reloc_regression.exe");
        std::fs::write(&tmp_path, &b).expect("write temp pe32");

        let imp = load_native(&tmp_path).expect("load_native must succeed on valid PE32");
        let _ = std::fs::remove_file(&tmp_path);

        assert_eq!(imp.format, "PE");
        assert_eq!(imp.language, "x86:LE:32:default");
        assert!(imp.functions.iter().any(|f| f.entry == 0x401000));

        // Proves data-to-data relocation remains an xref with pe-reloc provenance
        let xref = imp.xrefs.iter().find(|x| x.from == 0x402000 && x.to == 0x402080);
        assert!(xref.is_some(), "data-to-data relocation must be recorded in xrefs");
        assert_eq!(xref.unwrap().kind, "DATA");
        assert_eq!(xref.unwrap().provenance, "native-import:pe-reloc");

        // Proves data-to-data relocation target and source NEVER become functions
        assert!(
            !imp.functions.iter().any(|f| f.entry == 0x402080),
            "data-to-data relocation target must never become a function"
        );
        assert!(
            !imp.functions.iter().any(|f| f.entry == 0x402000),
            "data relocation source must never become a function"
        );
    }

    #[test]
    fn regression_pe_truncated_optional_header_returns_error() {
        let mut b = vec![0u8; 0x100];
        b[0..2].copy_from_slice(b"MZ");
        b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        b[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes()); // AMD64
        b[0x94..0x96].copy_from_slice(&0x200u16.to_le_bytes()); // opt_size claims 0x200 (past 0x100 len)
        let res = import_pe(&b);
        assert!(res.is_err(), "truncated optional header must return Err");

        // Also test opt_size too small for PE32+ (e.g. 50 < 160)
        let mut b2 = vec![0u8; 0x200];
        b2[0..2].copy_from_slice(b"MZ");
        b2[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        b2[0x80..0x84].copy_from_slice(b"PE\0\0");
        b2[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        b2[0x94..0x96].copy_from_slice(&50u16.to_le_bytes()); // opt_size 50
        b2[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes()); // magic 0x20b
        let res2 = import_pe(&b2);
        assert!(res2.is_err(), "undersized PE32+ optional header must return Err");

        // Also test opt_size too small for PE32 (e.g. 40 < 96)
        let mut b3 = vec![0u8; 0x200];
        b3[0..2].copy_from_slice(b"MZ");
        b3[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        b3[0x80..0x84].copy_from_slice(b"PE\0\0");
        b3[0x84..0x86].copy_from_slice(&0x014cu16.to_le_bytes()); // i386
        b3[0x94..0x96].copy_from_slice(&40u16.to_le_bytes()); // opt_size 40 < 96
        b3[0x98..0x9a].copy_from_slice(&0x10bu16.to_le_bytes()); // magic 0x10b
        let res3 = import_pe(&b3);
        assert!(res3.is_err(), "undersized PE32 optional header must return Err");
    }
    #[test]
    fn regression_pe_truncated_section_table_returns_error() {
        let mut b = vec![0u8; 0x200];
        b[0..2].copy_from_slice(b"MZ");
        b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        b[0x84..0x86].copy_from_slice(&0x014cu16.to_le_bytes()); // i386
        b[0x86..0x88].copy_from_slice(&50u16.to_le_bytes()); // 50 sections * 40 = 2000 bytes (past 0x200 len)
        b[0x94..0x96].copy_from_slice(&0xe0u16.to_le_bytes()); // opt_size 224
        let opt = 0x98;
        b[opt..opt + 2].copy_from_slice(&0x10bu16.to_le_bytes());
        let res = import_pe(&b);
        assert!(res.is_err(), "truncated section table must return Err");
    }
    #[test]
    fn negative_test_reloc_section_ignored_when_directory_5_absent() {
        let mut b = vec![0u8; 0x600];
        b[0..2].copy_from_slice(b"MZ");
        b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        let pe_off = 0x80;
        b[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
        b[pe_off + 4..pe_off + 6].copy_from_slice(&0x8664u16.to_le_bytes()); // AMD64
        b[pe_off + 6..pe_off + 8].copy_from_slice(&2u16.to_le_bytes()); // 2 sections (.text, .reloc)
        b[pe_off + 20..pe_off + 22].copy_from_slice(&0xf0u16.to_le_bytes()); // opt size 240
        let opt = pe_off + 24; // 0x98
        b[opt..opt + 2].copy_from_slice(&0x20bu16.to_le_bytes()); // PE32+
        b[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // entry RVA
        // Explicit ImageBase (0x140000000) at opt + 24:
        b[opt + 24..opt + 32].copy_from_slice(&0x140000000u64.to_le_bytes());
        // NumberOfRvaAndSizes at opt + 108 = 0 (Directory 5 ABSENT!)
        b[opt + 108..opt + 112].copy_from_slice(&0u32.to_le_bytes());

        let sec = opt + 0xf0; // 0x98 + 0xf0 = 0x188
        // Section table: 2 sections * 40 bytes = 80 bytes (0x188..0x1d8)
        // Sec 0: .text
        b[sec..sec + 5].copy_from_slice(b".text");
        b[sec + 8..sec + 12].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualSize
        b[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
        b[sec + 16..sec + 20].copy_from_slice(&0x100u32.to_le_bytes()); // SizeOfRawData
        b[sec + 20..sec + 24].copy_from_slice(&0x200u32.to_le_bytes()); // PointerToRawData (after section table ends at 0x1d8)
        b[sec + 36..sec + 40].copy_from_slice(&0x60000020u32.to_le_bytes()); // CODE | EXECUTE | READ

        // Sec 1: .reloc with valid relocation block bytes, but Directory 5 is ABSENT
        let sec1 = sec + 40; // 0x1b0
        b[sec1..sec1 + 6].copy_from_slice(b".reloc");
        b[sec1 + 8..sec1 + 12].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualSize
        b[sec1 + 12..sec1 + 16].copy_from_slice(&0x2000u32.to_le_bytes()); // VirtualAddress
        b[sec1 + 16..sec1 + 20].copy_from_slice(&0x100u32.to_le_bytes()); // SizeOfRawData
        b[sec1 + 20..sec1 + 24].copy_from_slice(&0x300u32.to_le_bytes()); // PointerToRawData (after .text raw data)
        b[sec1 + 36..sec1 + 40].copy_from_slice(&0x42000040u32.to_le_bytes()); // INITIALIZED_DATA | DISCARDABLE | READ

        // Put mapped executable pointer at relocation location in .text raw data (raw 0x200, RVA 0x1000):
        // Relocated pointer 0x140001050 lands inside executable mapping (ImageBase 0x140000000 + RVA 0x1000..0x2000)
        b[0x200..0x208].copy_from_slice(&0x140001050u64.to_le_bytes());

        // Put valid relocation block in .reloc raw data (raw 0x300):
        b[0x300..0x304].copy_from_slice(&0x1000u32.to_le_bytes()); // Page RVA
        b[0x304..0x308].copy_from_slice(&12u32.to_le_bytes()); // Block Size
        let entry0: u16 = (10 << 12) | 0; // DIR64 at offset 0
        b[0x308..0x30a].copy_from_slice(&entry0.to_le_bytes());

        let imp = import_pe(&b).expect("PE must parse cleanly");
        // Directory 5 is absent, so .reloc section MUST BE IGNORED
        assert!(imp.xrefs.is_empty(), "xrefs must be empty when directory 5 is absent");
        assert!(imp.reloc_candidates.is_empty(), "reloc_candidates must be empty when directory 5 is absent");
    }

    #[test]
    fn a_mode_declaration_never_takes_the_console_down() {
        // These are ARM instructions. Read in Thumb mode -- which a `$t`
        // symbol or a pattern's `setcontext` can ask for at any address --
        // they drove the constructor walk past the parser's fixed 75 states
        // (sleigh.cc:457), and indexing past the end killed the console
        // mid-import. Out of states is a decode failure, not a crash.
        use crate::native_runtime::{ConsoleSession, FlowKind, find_console};
        let mut cfg = crate::session::RuntimeConfig::from_env();
        cfg.language_id = "ARM:LE:32:v8".into();
        cfg.language_dir = cfg.ghidra_install.join("Ghidra/Processors/ARM/data/languages");
        if find_console(&cfg).is_err() {
            eprintln!("SKIP: SLEIGH console not available");
            return;
        }
        let import = NativeImport {
            language: cfg.language_id.clone(),
            compiler: Some("default".into()),
            format: "elf32".into(),
            cfg: cfg.clone(),
            mappings: vec![Mapping {
                vaddr: 0x1000,
                size: 24,
                file_off: 0,
                flags: 6,
                bytes: vec![
                    0x02, 0x8b, 0x2d, 0xed, 0x00, 0x8a, 0xb7, 0xee, 0x24, 0xd0, 0x4d, 0xe2,
                    0x00, 0x70, 0xa0, 0xe1, 0x10, 0x60, 0x8d, 0xe2, 0x0d, 0x50, 0xa0, 0xe1,
                ],
            }],
            contexts: vec![NativeContext {
                name: "TMode".into(),
                address: 0x1002,
                value: 1,
            }],
            ..Default::default()
        };
        let mut session = ConsoleSession::new(&cfg).unwrap();
        session.load_mapped(&import).unwrap();
        let flows = session
            .flow_batch(&[0x1002, 0x1004])
            .expect("the console must answer, not die");
        assert_eq!(flows.len(), 2, "one answer per address");
        assert_eq!(flows[0].kind, FlowKind::Bad, "no Thumb instruction there");
    }

    #[test]
    fn pattern_search_reads_only_the_bytes_the_image_carries() {
        // A PS2 executable's last code section declares more virtual size than
        // it carries bytes for. The old range asked the console to search
        // addresses the load image never received, `loadFill` raised
        // DataUnavailError, the whole pattern search failed, and the import
        // kept one function out of 8794.
        use crate::native_runtime::{ConsoleSession, find_console};
        let mut cfg = crate::session::RuntimeConfig::from_env();
        cfg.language_id = "MIPS:LE:32:default".into();
        cfg.language_dir = cfg.ghidra_install.join("Ghidra/Processors/MIPS/data/languages");
        if find_console(&cfg).is_err() {
            eprintln!("SKIP: SLEIGH console not available");
            return;
        }
        let import = NativeImport {
            language: cfg.language_id.clone(),
            compiler: Some("default".into()),
            format: "elf".into(),
            cfg: cfg.clone(),
            mappings: vec![Mapping {
                vaddr: 0x1000,
                // Sixteen bytes of virtual extent, eight bytes of content.
                size: 16,
                file_off: 0,
                flags: 6,
                bytes: vec![0, 0, 0, 0, 0x08, 0x00, 0xe0, 0x03],
            }],
            ..Default::default()
        };
        let ranges = code_ranges(&import);
        assert_eq!(ranges, vec![(0x1000, 0x1008)], "ranges stop at the bytes");
        let mut session = ConsoleSession::new(&cfg).unwrap();
        session.load_mapped(&import).unwrap();
        session
            .function_patterns(&ranges)
            .expect("a byte-backed range is searchable");
    }

    #[test]
    fn flow_batch_answers_every_address_it_is_asked() {
        // One undecodable address used to discard the rest of the command line,
        // so a batch came back short and discovery fell back to pointer-only
        // seeds: MIPS lost half its functions to a delay slot at a mapping's
        // end (sleigh.cc:385) and to addresses the image does not cover
        // (loadimage_xml.cc:236).
        use crate::native_runtime::{ConsoleSession, FlowKind, find_console};
        let mut cfg = crate::session::RuntimeConfig::from_env();
        cfg.language_id = "MIPS:LE:32:default".into();
        cfg.language_dir = cfg.ghidra_install.join("Ghidra/Processors/MIPS/data/languages");
        if find_console(&cfg).is_err() {
            eprintln!("SKIP: SLEIGH console not available");
            return;
        }
        let import = NativeImport {
            language: cfg.language_id.clone(),
            compiler: Some("default".into()),
            format: "elf".into(),
            cfg: cfg.clone(),
            mappings: vec![Mapping {
                vaddr: 0x1000,
                size: 16,
                file_off: 0,
                flags: 6,
                // Sixteen bytes of real MIPS text. Read at 0x1002 they are a
                // branch-likely whose delay slot never reaches the pcode
                // state, so SleighBuilder::delaySlot raises a plain
                // LowlevelError (sleigh.cc:385) rather than BadDataError.
                bytes: vec![
                    0x82, 0x05, 0x0e, 0x46, 0x03, 0x52, 0x0c, 0x46,
                    0x00, 0x45, 0x1a, 0x46, 0xda, 0x00, 0x04, 0x0c,
                ],
            }],
            ..Default::default()
        };
        let mut session = ConsoleSession::new(&cfg).unwrap();
        session.load_mapped(&import).unwrap();
        let asked = [0x1002u64, 0x1004, 0x9000];
        let flows = session.flow_batch(&asked).expect("batch must not fail");
        assert_eq!(
            flows.iter().map(|flow| flow.address).collect::<Vec<_>>(),
            asked,
            "one answer per requested address, in order"
        );
        assert_eq!(flows[0].kind, FlowKind::Bad, "branch whose delay slot cannot be cached");
        assert_eq!(flows[1].kind, FlowKind::Fallthrough, "the aligned instruction still decodes");
        assert_eq!(flows[2].kind, FlowKind::Bad, "address the image does not map");
    }

    #[test]
    fn references_apply_pc_helper_fixups() {
        use crate::native_runtime::{ConsoleSession, find_console};
        let mut cfg = crate::session::RuntimeConfig::from_env();
        cfg.language_id = "x86:LE:32:default".into();
        cfg.language_dir = cfg.ghidra_install.join("Ghidra/Processors/x86/data/languages");
        if find_console(&cfg).is_err() {
            eprintln!("SKIP: SLEIGH console not available");
            return;
        }
        let mut import = NativeImport {
            language: cfg.language_id.clone(), compiler: Some("gcc".into()),
            format: "elf".into(), cfg: cfg.clone(),
            functions: vec![
                NativeFunction { entry: 0x1000, size: 14, name: "FUN_1000".into() },
                NativeFunction { entry: 0x1100, size: 4, name: "FUN_1100".into() },
            ],
            mappings: vec![
                Mapping {
                    vaddr: 0x1000, size: 14, file_off: 0, flags: 6,
                    bytes: vec![
                        0xe8, 0xfb, 0, 0, 0, // call 0x1100
                        0x8d, 0x83, 0xfb, 0x2f, 0, 0, // lea eax,[ebx+0x2ffb]
                        0x31, 0xc0, 0xc3, // discard address; ret
                    ],
                },
                Mapping {
                    vaddr: 0x1100, size: 4, file_off: 0, flags: 6,
                    bytes: vec![0x8b, 0x1c, 0x24, 0xc3], // mov ebx,[esp]; ret
                },
                Mapping {
                    vaddr: 0x4000, size: 16, file_off: 0, flags: 3, bytes: vec![0; 16],
                },
            ],
            ..Default::default()
        };
        let mut session = ConsoleSession::new(&cfg).unwrap();
        session.load_mapped(&import).unwrap();
        infer_data_references(&mut import, &mut session, Vec::new()).unwrap();
        let refs: Vec<_> = import.xrefs.iter()
            .map(|xref| (xref.from, xref.to, xref.kind.as_str())).collect();
        assert_eq!(refs, vec![(0x1005, 0x4000, "DATA")],
            "a recognized helper supplies the caller PC for address formation");

        import.xrefs.clear();
        import.mappings[0].bytes = vec![
            0x83, 0xe4, 0xf0, // and esp,-16
            0xe8, 0xf8, 0, 0, 0, // call 0x1100
            0x8d, 0x83, 0xf8, 0x2f, 0, 0, // lea eax,[ebx+0x2ff8]
            0x31, 0xc0, 0xc3,
        ];
        import.mappings[0].size = 17;
        import.functions[0].size = 17;
        let mut session = ConsoleSession::new(&cfg).unwrap();
        session.load_mapped(&import).unwrap();
        infer_data_references(&mut import, &mut session, Vec::new()).unwrap();
        let refs: Vec<_> = import.xrefs.iter()
            .map(|xref| (xref.from, xref.to, xref.kind.as_str())).collect();
        assert_eq!(refs, vec![(0x1008, 0x4000, "DATA")],
            "stack realignment must retain a usable frame for the helper");

        import.xrefs.clear();
        import.functions.truncate(1);
        let mut session = ConsoleSession::new(&cfg).unwrap();
        session.load_mapped(&import).unwrap();
        infer_data_references(&mut import, &mut session, Vec::new()).unwrap();
        assert!(import.xrefs.is_empty(), "a pattern alone cannot establish a function");

        import.functions.push(NativeFunction {
            entry: 0x1100, size: 5, name: "FUN_1100".into(),
        });
        import.mappings[1].bytes = vec![0x8b, 0x5c, 0x24, 4, 0xc3]; // reads argument, not PC
        import.mappings[1].size = 5;
        let mut session = ConsoleSession::new(&cfg).unwrap();
        session.load_mapped(&import).unwrap();
        infer_data_references(&mut import, &mut session, Vec::new()).unwrap();
        assert!(import.xrefs.is_empty(), "ordinary calls retain unknown register context");

        import.mappings[0].bytes = vec![
            0xc7, 0x04, 0x24, 0, 0x40, 0, 0, // mov dword [esp],0x4000
            0x89, 0xe1, // mov ecx,esp
            0x83, 0xe4, 0xf0, // and esp,-16
            0x8b, 0x04, 0x24, // mov eax,[esp]: old slot may not alias
            0x29, 0xe1, // sub ecx,esp: old pointer may not equal new pointer
            0x81, 0xc1, 0x08, 0x40, 0, 0, // add ecx,0x4008
            0xc3,
        ];
        import.mappings[0].size = import.mappings[0].bytes.len() as u64;
        let mut session = ConsoleSession::new(&cfg).unwrap();
        session.load_mapped(&import).unwrap();
        let facts = session.constants(
            0x1000, 0x1000 + import.mappings[0].size, &import.mappings, false,
        ).unwrap();
        assert!(facts.iter().all(|fact| fact.pc < 0x1009),
            "realignment must not produce constants from stale frame aliases: {facts:?}");
    }

    #[test]
    fn inferred_references_use_writable_image_values() {
        use crate::native_runtime::{ConsoleSession, find_console};
        let mut cfg = crate::session::RuntimeConfig::from_env();
        cfg.language_id = "x86:LE:64:default".into();
        cfg.language_dir = cfg.ghidra_install.join("Ghidra/Processors/x86/data/languages");
        if find_console(&cfg).is_err() {
            eprintln!("SKIP: SLEIGH console not available");
            return;
        }
        let mut import = NativeImport {
            language: cfg.language_id.clone(), compiler: Some("gcc".into()),
            format: "elf".into(), cfg: cfg.clone(),
            functions: vec![NativeFunction { entry: 0x1000, size: 14, name: "FUN_1000".into() }],
            mappings: vec![
                Mapping {
                    vaddr: 0x1000, size: 14, file_off: 0, flags: 6,
                    bytes: vec![
                        0x48, 0x8b, 0x04, 0x25, 0, 0x30, 0, 0, // mov rax,[0x3000]
                        0x48, 0x8b, 0x08, // mov rcx,[rax]
                        0x31, 0xc0, 0xc3,
                    ],
                },
                Mapping {
                    vaddr: 0x3000, size: 8, file_off: 0, flags: 3,
                    bytes: 0x4000u64.to_le_bytes().to_vec(),
                },
                Mapping {
                    vaddr: 0x4000, size: 16, file_off: 0, flags: 3, bytes: vec![0; 16],
                },
            ],
            ..Default::default()
        };
        let mut session = ConsoleSession::new(&cfg).unwrap();
        session.load_mapped(&import).unwrap();
        infer_data_references(&mut import, &mut session, Vec::new()).unwrap();
        let refs: Vec<_> = import.xrefs.iter()
            .map(|xref| (xref.from, xref.to, xref.kind.as_str())).collect();
        assert_eq!(refs, vec![(0x1000, 0x3000, "READ"), (0x1008, 0x4000, "READ")],
            "reference inference follows the selected analyzer's writable-image policy");
        let strict = session.constants(0x1000, 0x100e, &import.mappings, false).unwrap();
        assert!(strict.iter().all(|fact| fact.value != 0x4000),
            "strict constant queries must not inherit reference-inference heuristics: {strict:?}");
    }

    #[test]
    #[test]
    fn pattern_labels_need_a_body_and_a_generated_name() {
        let mut imp = NativeImport {
            functions: vec![
                NativeFunction { entry: 0x1000, size: 4, name: "FUN_00001000".into() },
                NativeFunction { entry: 0x1004, size: 4, name: "frame_dummy".into() },
                // A one-byte stub is an address, not a proven body.
                NativeFunction { entry: 0x1008, size: 1, name: "FUN_00001008".into() },
            ],
            pattern_labels: vec![
                (0x1000, "__i686.get_pc_thunk.bx".into()),
                (0x1004, "__i686.get_pc_thunk.ax".into()),
                (0x1008, "__i686.get_pc_thunk.cx".into()),
                (0x100c, "__i686.get_pc_thunk.dx".into()),
            ],
            ..Default::default()
        };
        apply_pattern_labels(&mut imp);
        assert_eq!(
            imp.functions
                .iter()
                .map(|function| (function.entry, function.name.clone()))
                .collect::<Vec<_>>(),
            vec![
                (0x1000, "__i686.get_pc_thunk.bx".to_string()),
                (0x1004, "frame_dummy".to_string()),
                (0x1008, "FUN_00001008".to_string()),
            ]
        );
    }

    #[test]
    fn initializer_labels_replace_only_generated_names() {
        let mut imp = NativeImport {
            functions: vec![
                NativeFunction { entry: 0x1000, size: 4, name: "FUN_00001000".into() },
                NativeFunction { entry: 0x1004, size: 4, name: "frame_dummy".into() },
            ],
            initializer_labels: vec![
                (0x1000, "_INIT_0".into()),
                (0x1004, "_INIT_1".into()),
                // No function there: a label for nothing is dropped.
                (0x1008, "_FINI_0".into()),
            ],
            ..Default::default()
        };
        apply_initializer_labels(&mut imp);
        assert_eq!(
            imp.functions
                .iter()
                .map(|function| (function.entry, function.name.clone()))
                .collect::<Vec<_>>(),
            vec![
                (0x1000, "_INIT_0".to_string()),
                (0x1004, "frame_dummy".to_string()),
            ]
        );
    }

    #[test]
    fn linkage_naming_replaces_only_generated_names() {
        let mut imp = NativeImport {
            functions: vec![
                NativeFunction { entry: 0x1000, size: 4, name: "FUN_00001000".into() },
                NativeFunction { entry: 0x1100, size: 4, name: "_init".into() },
                NativeFunction { entry: 0x1200, size: 4, name: "FUN_00001200".into() },
            ],
            externals: vec![
                (0x1000, "printf".into()),
                (0x1100, "__cxa_finalize".into()),
            ],
            thunks: vec![
                NativeThunk { entry: 0x1000, destination: 0x2000,
                              kind: lre_model::ThunkKind::Linkage, source: THUNK_SOURCE },
                NativeThunk { entry: 0x1100, destination: 0x2008,
                              kind: lre_model::ThunkKind::Linkage, source: THUNK_SOURCE },
                // A direct thunk carries no import evidence, so no name.
                NativeThunk { entry: 0x1200, destination: 0x1000,
                              kind: lre_model::ThunkKind::Direct, source: THUNK_SOURCE },
            ],
            ..Default::default()
        };
        name_linkage_stubs(&mut imp);
        assert_eq!(
            imp.functions
                .iter()
                .map(|function| (function.entry, function.name.clone()))
                .collect::<Vec<_>>(),
            vec![
                (0x1000, "printf".to_string()),
                // A section-derived name stands: it is evidence of its own.
                (0x1100, "_init".to_string()),
                (0x1200, "FUN_00001200".to_string()),
            ]
        );
    }

    /// The index comes from the slot's position and the prefix from the array
    /// the slot belongs to; nothing here is guessed.
    #[test]
    fn initializer_arrays_name_their_targets_by_index() {
        let mut bytes = vec![0u8; 0x300];
        bytes[..7].copy_from_slice(b"\x7fELF\x01\x01\x01");
        for (offset, value) in [(16, 2u16), (18, 3), (40, 52), (42, 32), (44, 3),
            (46, 40), (48, 5), (50, 4)] {
            bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        }
        for (offset, value) in [(20, 1u32), (24, 0x1000), (28, 52), (32, 0x200)] {
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        for (index, header) in [
            // code, data holding the arrays, and the dynamic table
            [1u32, 0x100, 0x1000, 0x1000, 0x20, 0x20, 5, 1],
            [1, 0x120, 0x3000, 0x3000, 0x10, 0x10, 6, 1],
            [2, 0x140, 0x3100, 0x3100, 0x28, 0x28, 6, 4],
        ].iter().enumerate() {
            for (field, value) in header.iter().enumerate() {
                let offset = 52 + index * 32 + field * 4;
                bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            }
        }
        // Two init entries and one fini entry, pointing into the code segment.
        for (index, target) in [0x1000u32, 0x1004, 0x1008].iter().enumerate() {
            let offset = 0x120 + index * 4;
            bytes[offset..offset + 4].copy_from_slice(&target.to_le_bytes());
        }
        for (index, (tag, value)) in [(25u32, 0x3000u32), (27, 8), (26, 0x3008), (28, 4)]
            .iter()
            .enumerate()
        {
            let offset = 0x140 + index * 8;
            bytes[offset..offset + 4].copy_from_slice(&tag.to_le_bytes());
            bytes[offset + 4..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        let names = b"\0.text\0.init_array\0.fini_array\0.shstrtab\0";
        bytes[0x180..0x180 + names.len()].copy_from_slice(names);
        for (index, header) in [
            [1u32, 1, 6, 0x1000, 0x100, 0x20, 0, 0, 1, 0],
            [7, 14, 3, 0x3000, 0x120, 8, 0, 0, 4, 0],
            [19, 15, 3, 0x3008, 0x128, 4, 0, 0, 4, 0],
            [31, 3, 0, 0, 0x180, names.len() as u32, 0, 0, 1, 0],
        ].iter().enumerate() {
            for (field, value) in header.iter().enumerate() {
                let offset = 0x200 + (index + 1) * 40 + field * 4;
                bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            }
        }
        let import = import_elf(&bytes).expect("elf");
        let base = import.mappings.iter().map(|mapping| mapping.vaddr).min().unwrap();
        let bias = base - 0x1000;
        assert_eq!(
            import.initializer_labels,
            vec![
                (0x1000 + bias, "_INIT_0".to_string()),
                (0x1004 + bias, "_INIT_1".to_string()),
                (0x1008 + bias, "_FINI_0".to_string()),
            ]
        );
    }

    /// A 32-bit ELF whose `.dynamic` declares `DT_PLTGOT = 0x3000`, with a
    /// `.got` section of `got_size` bytes at that address and a two-slot PLT
    /// read at 0x1000. The GOT section size is the parameter because the ABI's
    /// three reserved words only exist where the object has room for them.
    fn elf32_with_pltgot(got_size: u32) -> Vec<u8> {
        let mut bytes = vec![0u8; 0x300];
        bytes[..7].copy_from_slice(b"\x7fELF\x01\x01\x01");
        for (offset, value) in [(16, 2u16), (18, 3), (40, 52), (42, 32), (44, 3),
            (46, 40), (48, 5), (50, 4)] {
            bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        }
        for (offset, value) in [(20, 1u32), (24, 0x1000), (28, 52), (32, 0x200)] {
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        for (index, header) in [
            [1u32, 0x100, 0x1000, 0x1000, 6, 6, 5, 1],
            [1, 0x120, 0x3000, 0x3000, 0x30, 0x30, 6, 1],
            [2, 0x140, 0x3020, 0x3020, 16, 16, 6, 4],
        ].iter().enumerate() {
            for (field, value) in header.iter().enumerate() {
                let offset = 52 + index * 32 + field * 4;
                bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            }
        }
        bytes[0x100..0x106].copy_from_slice(&[0x8b, 0x43, 4, 0xff, 0x63, 8]);
        bytes[0x140..0x144].copy_from_slice(&3u32.to_le_bytes()); // DT_PLTGOT
        bytes[0x144..0x148].copy_from_slice(&0x3000u32.to_le_bytes());
        let names = b"\0.plt\0.got\0.dynamic\0.shstrtab\0.text\0";
        bytes[0x180..0x180 + names.len()].copy_from_slice(names);
        for (index, header) in [
            [1u32, 1, 6, 0x1000, 0x100, 6, 0, 0, 1, 0],
            [6, 1, 3, 0x3000, 0x120, got_size, 0, 0, 4, 0],
            [11, 6, 3, 0x3020, 0x140, 16, 0, 0, 4, 8],
            [20, 3, 0, 0, 0x180, names.len() as u32, 0, 0, 1, 0],
        ].iter().enumerate() {
            for (field, value) in header.iter().enumerate() {
                let offset = 0x200 + (index + 1) * 40 + field * 4;
                bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            }
        }
        bytes
    }

    #[test]
    fn reserved_words_stop_at_the_object_that_holds_them() {
        // `powerpc_many_o2`'s `.plt` is two words long, so the address the
        // third reserved word would occupy belongs to `.bss` -- the guard byte
        // `_FINI_0` reads. Typing it as a resolver pointer and treating its
        // readers as PLT headers truncated that function to `halt_baddata()`
        // (m4-022).
        let import = import_elf(&elf32_with_pltgot(16)).unwrap();
        assert_eq!(
            import.plt_reserved_slots,
            vec![(0x3000, 4), (0x3004, 4), (0x3008, 4)],
            "a GOT with room for three words reserves three"
        );
        assert_eq!(import.plt_resolver_slot, Some(0x3008));

        let import = import_elf(&elf32_with_pltgot(8)).unwrap();
        assert_eq!(
            import.plt_reserved_slots,
            vec![(0x3000, 4), (0x3004, 4)],
            "a two-word GOT reserves two, and the third address is not ours"
        );
        assert_eq!(import.plt_resolver_slot, None);
    }

    fn elf_plt_register_context_is_scoped() {
        use crate::native_runtime::find_console;
        let mut cfg = crate::session::RuntimeConfig::from_env();
        cfg.language_id = "x86:LE:32:default".into();
        cfg.language_dir = cfg.ghidra_install.join("Ghidra/Processors/x86/data/languages");
        if find_console(&cfg).is_err() {
            eprintln!("SKIP: SLEIGH console not available");
            return;
        }
        let mut bytes = elf32_with_pltgot(16);
        let analyze = |bytes: &[u8]| {
            let mut import = import_elf(bytes).unwrap();
            import.cfg = cfg.clone();
            select_language(&mut import, &cfg).unwrap();
            let mut session = discovery::discover_seeded(&mut import).unwrap().session;
            import.xrefs.clear();
            infer_data_references(&mut import, &mut session, Vec::new()).unwrap();
            let strict = session.constants(0x1000, 0x1006, &import.mappings, false).unwrap();
            assert!(strict.is_empty(), "reference-only context must not seed strict queries: {strict:?}");
            import.xrefs.into_iter().map(|xref| (xref.from, xref.to, xref.kind))
                .collect::<Vec<_>>()
        };
        assert_eq!(analyze(&bytes), vec![(0x1000, 0x3004, "READ".into()),
            (0x1003, 0x3008, "READ".into())],
            "ELF PLT references use the loader-declared GOT register context");
        bytes[0x140..0x144].fill(0);
        assert!(analyze(&bytes).is_empty(), "a GOT section cannot substitute for DT_PLTGOT");
        bytes[0x140..0x144].copy_from_slice(&3u32.to_le_bytes());
        bytes[0x228..0x22c].copy_from_slice(&30u32.to_le_bytes()); // rename .plt to .text
        assert!(analyze(&bytes).is_empty(), "PLT register context must not leak into ordinary code");
    }

    #[test]
    fn powerpc_pic_context_follows_calls_not_unrelated_functions() {
        use crate::native_runtime::{ConsoleSession, find_console};
        let mut cfg = crate::session::RuntimeConfig::from_env();
        cfg.language_id = "PowerPC:BE:32:default".into();
        cfg.language_dir = cfg.ghidra_install.join("Ghidra/Processors/PowerPC/data/languages");
        if find_console(&cfg).is_err() {
            eprintln!("SKIP: SLEIGH console not available");
            return;
        }
        let mut bytes = vec![0u8; 0x500];
        bytes[..7].copy_from_slice(b"\x7fELF\x01\x02\x01");
        for (offset, value) in [(16, 2u16), (18, 20), (40, 52), (42, 32), (44, 3),
            (46, 40), (48, 5), (50, 4)] {
            bytes[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
        }
        for (offset, value) in [(20, 1u32), (24, 0x1100), (28, 52), (32, 0x400)] {
            bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        }
        for (index, header) in [
            [1u32, 0x100, 0x1000, 0x1000, 0x208, 0x208, 5, 4],
            [1, 0x320, 0x3000, 0x3000, 0x20, 0x20, 6, 4],
            [2, 0x330, 0x3010, 0x3010, 16, 16, 6, 4],
        ].iter().enumerate() {
            for (field, value) in header.iter().enumerate() {
                let offset = 52 + index * 32 + field * 4;
                bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
            }
        }
        for (offset, instruction) in [
            (0x100, 0x807e0004u32), (0x104, 0x4e800020), // lwz r3,4(r30); blr
            (0x200, 0x3fc00000), (0x204, 0x63de3000), // lis/ori r30,0x3000
            (0x208, 0x4bfffef9), (0x20c, 0x4e800020), // bl 0x1000; blr
            (0x300, 0x807e0008), (0x304, 0x4e800020), // uncalled load
            (0x330, 0x70000000), (0x334, 0x3000), // DT_PPC_GOT
        ] {
            bytes[offset..offset + 4].copy_from_slice(&instruction.to_be_bytes());
        }
        let names = b"\0.text\0.got\0.dynamic\0.shstrtab\0";
        bytes[0x360..0x360 + names.len()].copy_from_slice(names);
        for (index, header) in [
            [1u32, 1, 6, 0x1000, 0x100, 0x208, 0, 0, 4, 0],
            [7, 1, 3, 0x3000, 0x320, 16, 0, 0, 4, 0],
            [12, 6, 3, 0x3010, 0x330, 16, 0, 0, 4, 8],
            [21, 3, 0, 0, 0x360, names.len() as u32, 0, 0, 1, 0],
        ].iter().enumerate() {
            for (field, value) in header.iter().enumerate() {
                let offset = 0x400 + (index + 1) * 40 + field * 4;
                bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
            }
        }
        let analyze = |bytes: &[u8], caller_first: bool| {
            let mut import = import_elf(bytes).unwrap();
            import.cfg = cfg.clone();
            select_language(&mut import, &cfg).unwrap();
            import.functions = [(0x1000, 8), (0x1100, 16), (0x1200, 8)].into_iter()
                .map(|(entry, size)| NativeFunction { entry, size, name: format!("FUN_{entry:x}") })
                .collect();
            if caller_first { import.functions.swap(0, 1); }
            let mut session = ConsoleSession::new(&cfg).unwrap();
            session.load_mapped(&import).unwrap();
            infer_data_references(&mut import, &mut session, Vec::new()).unwrap();
            assert!(session.constants(0x1000, 0x1008, &import.mappings, false).unwrap().is_empty(),
                "call-derived reference context must not enter strict constant queries");
            let mut data = Vec::new();
            let reads = import.xrefs.into_iter().filter_map(|xref| {
                if xref.kind == "DATA" { data.push((xref.from, xref.to)); }
                (xref.kind == "READ").then_some((xref.from, xref.to))
            }).collect::<Vec<_>>();
            (reads, data)
        };
        assert_eq!(analyze(&bytes, false).0, vec![(0x1000, 0x3004)],
            "only the called function inherits the actual r30 value, independent of query order");
        bytes[0x330..0x334].fill(0);
        assert!(analyze(&bytes, false).0.is_empty(), "a GOT section alone cannot enable r30 propagation");
        bytes[0x330..0x334].copy_from_slice(&0x70000000u32.to_be_bytes());
        for offset in [0x200, 0x204] {
            bytes[offset..offset + 4].copy_from_slice(&0x60000000u32.to_be_bytes()); // nop
        }
        assert!(analyze(&bytes, false).0.is_empty(), "unknown caller values must not invent a GOT context");
        bytes[0x200..0x204].copy_from_slice(&0x3fc00000u32.to_be_bytes()); // lis r30,0
        bytes[0x100..0x104].copy_from_slice(&0x807e3004u32.to_be_bytes()); // lwz r3,0x3004(r30)
        assert!(analyze(&bytes, false).0.is_empty(), "zero is not an established PIC register context");
        bytes[0x204..0x208].copy_from_slice(&0x63de0004u32.to_be_bytes()); // ori r30,r30,4
        let (reads, data) = analyze(&bytes, false);
        assert_eq!(reads, vec![(0x1000, 0x3008)], "use the actual caller value, not DT_PPC_GOT");
        assert!(data.contains(&(0x1000, 0x3004)),
            "call context adds precise accesses without erasing speculative offset DATA");
        assert_eq!(analyze(&bytes, true), (reads, data),
            "caller-first scheduling must retain the same local and contextual evidence");
    }

    #[test]
    fn elf_linkage_references_do_not_require_functions() {
        use crate::native_runtime::{find_console, ConsoleSession};
        let mut cfg = crate::session::RuntimeConfig::from_env();
        cfg.language_id = "PowerPC:BE:32:default".into();
        cfg.language_dir = cfg.ghidra_install.join("Ghidra/Processors/PowerPC/data/languages");
        if find_console(&cfg).is_err() {
            eprintln!("SKIP: SLEIGH console not available");
            return;
        }
        let code = [
            0x3d, 0x60, 0, 0, 0x81, 0x6b, 0x30, 4, // lis r11,0; lwz r11,0x3004(r11)
            0x7d, 0x69, 3, 0xa6, 0x4e, 0x80, 4, 0x20, // mtctr r11; bctr
            0x48, 0, 0, 8, 0x60, 0, 0, 0, // disconnected resolver: b next; nop
            0x3d, 0x80, 0, 0, 0x80, 0x0c, 0x30, 8, // lis r12,0; lwz r0,0x3008(r12)
            0x4e, 0x80, 0, 0x20, // blr
        ];
        let mut bytes = vec![0u8; 0x2a0];
        bytes[..7].copy_from_slice(b"\x7fELF\x01\x02\x01");
        for (offset, value) in [(16, 2u16), (18, 20), (40, 52), (42, 32), (44, 2),
            (46, 40), (48, 4), (50, 3)] {
            bytes[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
        }
        for (offset, value) in [(20, 1u32), (24, 0x1000), (28, 52), (32, 0x200)] {
            bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        }
        for (index, header) in [
            [1u32, 0x100, 0x1000, 0x1000, code.len() as u32, code.len() as u32, 5, 4],
            [1, 0x140, 0x3000, 0x3000, 16, 16, 6, 4],
        ].iter().enumerate() {
            for (field, value) in header.iter().enumerate() {
                let offset = 52 + index * 32 + field * 4;
                bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
            }
        }
        bytes[0x100..0x100 + code.len()].copy_from_slice(&code);
        let names = b"\0.glink\0.data\0.shstrtab\0.text\0";
        bytes[0x180..0x180 + names.len()].copy_from_slice(names);
        for (index, header) in [
            [1u32, 1, 6, 0x1000, 0x100, code.len() as u32, 0, 0, 4, 0],
            [8, 1, 3, 0x3000, 0x140, 16, 0, 0, 4, 0],
            [14, 3, 0, 0, 0x180, names.len() as u32, 0, 0, 1, 0],
        ].iter().enumerate() {
            for (field, value) in header.iter().enumerate() {
                let offset = 0x200 + (index + 1) * 40 + field * 4;
                bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
            }
        }
        let analyze = |bytes: &[u8]| {
            let mut import = import_elf(bytes).unwrap();
            import.cfg = cfg.clone();
            select_language(&mut import, &cfg).unwrap();
            import.functions.clear();
            import.xrefs.clear();
            let mut session = ConsoleSession::new(&cfg).unwrap();
            session.load_mapped(&import).unwrap();
            infer_data_references(&mut import, &mut session, Vec::new()).unwrap();
            assert!(import.functions.is_empty(), "reference coverage must not manufacture functions");
            import.xrefs.into_iter().map(|xref| (xref.from, xref.to, xref.kind))
                .collect::<Vec<_>>()
        };
        let expected = vec![(0x1004, 0x3004, "READ".into())];
        assert_eq!(analyze(&bytes), expected,
            "follow the section-address code root, not unseeded disconnected bytes");
        bytes[0x230..0x234].copy_from_slice(&2u32.to_be_bytes());
        assert!(analyze(&bytes).is_empty(), "non-executable linkage data is not code");
        bytes[0x230..0x234].copy_from_slice(&6u32.to_be_bytes());
        bytes[0x228..0x22c].copy_from_slice(&24u32.to_be_bytes());
        assert_eq!(analyze(&bytes), expected, "section-address evidence is independent of its name");
    }

    #[test]
    fn an_undecodable_code_root_does_not_abort_reference_inference() {
        use crate::native_runtime::{ConsoleSession, find_console};
        let mut cfg = crate::session::RuntimeConfig::from_env();
        cfg.language_id = "x86:LE:64:default".into();
        cfg.language_dir = cfg.ghidra_install.join("Ghidra/Processors/x86/data/languages");
        if find_console(&cfg).is_err() {
            eprintln!("SKIP: SLEIGH console not available");
            return;
        }
        let mut bytes = vec![
            // 0x1000: an ELF header start, exactly how a section root can land
            // on bytes that never decode as code.
            0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00,
            // 0x1008: mov rax,[rip+0x1ff1]; ret
            0x48, 0x8b, 0x05, 0xf1, 0x1f, 0x00, 0x00, 0xc3,
        ];
        bytes.resize(0x20, 0);
        let mut import = NativeImport {
            cfg: cfg.clone(),
            language: cfg.language_id.clone(),
            format: "elf32".into(),
            mappings: vec![
                Mapping { vaddr: 0x1000, size: 0x20, file_off: 0, flags: 6, bytes },
                Mapping { vaddr: 0x3000, size: 8, file_off: 0, flags: 2, bytes: vec![0; 8] },
            ],
            reference_roots: vec![(0x1000, 0x1008), (0x1008, 0x1010)],
            ..Default::default()
        };
        let mut session = ConsoleSession::new(&cfg).unwrap();
        session.load_mapped(&import).unwrap();
        assert!(
            session
                .optional_references(0x1000, 0x1008, &import.mappings, true)
                .unwrap()
                .is_none(),
            "the console must refuse the undecodable root instead of answering"
        );
        infer_data_references(&mut import, &mut session, Vec::new()).unwrap();
        assert_eq!(
            import
                .xrefs
                .iter()
                .map(|xref| (xref.from, xref.to, xref.kind.clone()))
                .collect::<Vec<_>>(),
            vec![(0x1008, 0x3000, "READ".into())],
            "the decodable root still contributes its reference"
        );
    }


    #[test]
    fn data_string_sweep_decodes_utf8_and_utf16() {
        for (language, big_endian) in [
            ("x86:LE:64:default", false), ("PowerPC:BE:32:default", true),
        ] {
            let wide = |value: &str| {
                value.encode_utf16().chain(std::iter::once(0))
                    .flat_map(|unit| if big_endian { unit.to_be_bytes() } else { unit.to_le_bytes() })
                    .collect::<Vec<_>>()
            };
            let mappings = [
                (0x3000, 2, b"word\0".to_vec()),
                (0x3100, 2, "café\0".as_bytes().to_vec()),
                (0x3200, 2, wide("wide text")),
                (0x3300, 2, wide("A😀BC")),
                (0x3400, 2, "猫猫猫\0".as_bytes().to_vec()),
                (0x3500, 2, wide("😀😀")),
                (0x1000, 6, b"CODE\0".to_vec()),
            ].into_iter().map(|(vaddr, flags, bytes)| Mapping {
                vaddr, size: bytes.len() as u64, file_off: 0, flags, bytes,
            }).collect();
            let import = NativeImport { language: language.into(), mappings, ..Default::default() };
            let mut strings: Vec<_> = strings::discover(&import).into_iter()
                .map(|row| (row.address.offset, row.value)).collect();
            strings.sort_unstable();
            assert_eq!(strings, vec![
                (0x3000, "word".into()), (0x3100, "café".into()),
                (0x3200, "wide text".into()), (0x3300, "A😀BC".into()),
            ], "decode data strings in {language}; count characters, not encoded bytes or code units");
        }
    }
}

/// Types the imports the pinned C library archive declares.
///
/// The name has to come from the image: an external symbol, or a stub the
/// linkage pass named after the slot it reads. A name the archive omits, or one
/// whose declared types the decompiler does not have, stays untyped.
fn apply_library_prototypes(
    db: &ProjectDb,
    pid: lre_model::ProgramId,
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
    let rows: Vec<lre_model::PrototypeRow> = applied
        .iter()
        .map(|(address, signature, declaration)| lre_model::PrototypeRow {
            function: lre_model::Address::ram(*address),
            signature: signature.clone(),
            calling_convention: None,
            return_type: Some(declaration.return_type.clone()),
            provenance: lre_model::FactProvenance {
                kind: lre_model::FactKind::Inferred,
                source: crate::library_types::SOURCE.into(),
                confidence: None,
            },
        })
        .collect();
    let revision = db.revision(pid)?;
    db.merge_inferred_prototypes(pid, revision, &rows)?;
    Ok(())
}
