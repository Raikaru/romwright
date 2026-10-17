//! GameCube/Wii REL loader (P3.1): the relocatable module a disc carries
//! beside the boot DOL. A REL is a header, a section table, relocation
//! streams and an import table; the console's linker (`OSLink`) places the
//! sections, then patches the relocations against the main DOL (module 0)
//! and against the REL itself.
//!
//! Format reference: the REL layout and relocation semantics as implemented
//! by decomp-toolkit (`src/util/rel.rs`, `src/cmd/rel.rs`; MIT OR Apache-2.0,
//! Copyright encounter) and documented by the GC/Wii homebrew community.
//! Independent implementation; no upstream code copied. Header (big-endian):
//!
//! ```text
//!   0x00 u32 module id (0 is the DOL)      0x30 u8  prolog section
//!   0x04 u32 next module   (0 on disc)     0x31 u8  epilog section
//!   0x08 u32 previous module (0 on disc)   0x32 u8  unresolved section
//!   0x0c u32 section count                 0x33 u8  bss section (0 on disc)
//!   0x10 u32 section table offset          0x34 u32 prolog offset
//!   0x14 u32 name offset                   0x38 u32 epilog offset
//!   0x18 u32 name size                     0x3c u32 unresolved offset
//!   0x1c u32 version (1..=3)               0x40 u32 alignment      (v2+)
//!   0x20 u32 bss size                      0x44 u32 bss alignment  (v2+)
//!   0x24 u32 relocation stream offset      0x48 u32 fix size       (v3)
//!   0x28 u32 import table offset
//!   0x2c u32 import table size
//! ```
//!
//! Section table entry (8 bytes): `offset | exec`, `size`; offset 0 with a
//! size is the bss. Import table entry (8 bytes): target module id, offset
//! of that module's relocation stream. A stream is 8-byte records
//! `{u16 offset, u8 type, u8 section, u32 addend}` read until
//! `R_DOLPHIN_END`; `offset` advances the place within the current source
//! section, `R_DOLPHIN_SECTION` switches that section and resets the place,
//! `R_DOLPHIN_NOP` only advances. For a target in module 0 `addend` is an
//! absolute address; otherwise it is an offset into `section` of the target
//! module.
//!
//! **Placement.** A REL has no addresses of its own: the game's heap decides
//! at run time. Following `dtk rel merge`, the modules of a disc are placed in
//! module-id order, one section after another from `dol::rel_base`, each
//! section starting on a 32-byte boundary, so the DOL and every REL are
//! one program in one address space and a relocation is an ordinary
//! cross-module reference. A REL imported on its own (no DOL beside it) puts
//! section `i` at `0x8000_0000 + i * 0x1000_0000`; its relocations against
//! module 0 still apply, since their addends are absolute. RELs of a disc that
//! share a module id are alternatives the game pages into one place; each is a
//! program of its own, placed alone from the same base (`attach`).

use super::{
    err, ImportError, Mapping, NativeFunction, NativeImport, NativeModule, NativeRegisterContext,
    NativeXref, Result,
};

const R_PPC_NONE: u8 = 0;
const R_PPC_ADDR32: u8 = 1;
const R_PPC_ADDR24: u8 = 2;
const R_PPC_ADDR16: u8 = 3;
const R_PPC_ADDR16_LO: u8 = 4;
const R_PPC_ADDR16_HI: u8 = 5;
const R_PPC_ADDR16_HA: u8 = 6;
const R_PPC_ADDR14: u8 = 7;
const R_PPC_ADDR14_BRTAKEN: u8 = 8;
const R_PPC_ADDR14_BRNTAKEN: u8 = 9;
const R_PPC_REL24: u8 = 10;
const R_PPC_REL14: u8 = 11;
const R_PPC_REL14_BRTAKEN: u8 = 12;
const R_PPC_REL14_BRNTAKEN: u8 = 13;
const R_DOLPHIN_NOP: u8 = 201;
const R_DOLPHIN_SECTION: u8 = 202;
const R_DOLPHIN_END: u8 = 203;
const R_DOLPHIN_MRKREF: u8 = 204;

/// Provenance of the data references a relocation table adds.
const RELOC_SOURCE: &str = "native-import:rel-reloc";
/// Standalone placement: section `i` at `BASE + i * STRIDE`.
const WINDOW_BASE: u64 = 0x8000_0000;
const WINDOW_STRIDE: u64 = 0x1000_0000;
/// How far apart modules' sections may be and still be one 32-bit space.
const ADDRESS_LIMIT: u64 = 0x1_0000_0000;

fn u32_be(data: &[u8], off: usize) -> Result<u32> {
    off.checked_add(4)
        .and_then(|end| data.get(off..end))
        .map(|b| u32::from_be_bytes(b.try_into().unwrap()))
        .ok_or_else(|| ImportError::Bad("truncated REL field".into()))
}

fn align32(value: u64) -> u64 {
    (value + 31) & !31
}

/// The header size of a REL format version, or `None` for an unknown one.
fn header_size(version: u32) -> Option<usize> {
    match version {
        1 => Some(0x40),
        2 => Some(0x48),
        3 => Some(0x4c),
        _ => None,
    }
}

/// One entry of the section table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Section {
    /// File offset of the bytes; 0 with a nonzero size is the bss.
    pub file_off: u32,
    pub size: u32,
    pub exec: bool,
}

impl Section {
    fn is_bss(&self) -> bool {
        self.file_off == 0 && self.size != 0
    }
}

/// One relocation record, with the stream state (source section, place)
/// already resolved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Reloc {
    /// Module the relocation targets (its import-table entry).
    pub module: u32,
    /// Section of this REL holding the place, and the place's offset in it.
    pub source: u8,
    pub offset: u32,
    pub kind: u8,
    /// Section of `module` the target lies in; unused when `module` is 0.
    pub target: u8,
    pub addend: u32,
}

/// A parsed REL: header, section table, and every relocation.
pub(crate) struct Rel<'a> {
    data: &'a [u8],
    pub module_id: u32,
    pub sections: Vec<Section>,
    pub relocs: Vec<Reloc>,
    /// `(section, offset)` of `_prolog`, `_epilog`, `_unresolved`.
    pub entries: [Option<(u8, u32)>; 3],
}

struct Header {
    module_id: u32,
    section_count: usize,
    section_off: usize,
    bss_size: u32,
    rel_off: usize,
    imp_off: usize,
    imp_size: usize,
    entries: [Option<(u8, u32)>; 3],
}

fn header(data: &[u8]) -> Result<Header> {
    let version = u32_be(data, 0x1c)?;
    let size = header_size(version)
        .ok_or_else(|| ImportError::Bad(format!("unsupported REL version {version}")))?;
    if data.len() < size {
        return err("truncated REL header");
    }
    // The links the console fills in are zero on disc, and so is the bss
    // section index: a header that says otherwise is not a REL on disc.
    if u32_be(data, 0x04)? != 0 || u32_be(data, 0x08)? != 0 || data[0x33] != 0 {
        return err("REL runtime link fields are not zero");
    }
    let section_count = u32_be(data, 0x0c)? as usize;
    let section_off = u32_be(data, 0x10)? as usize;
    let imp_off = u32_be(data, 0x28)? as usize;
    let imp_size = u32_be(data, 0x2c)? as usize;
    let rel_off = u32_be(data, 0x24)? as usize;
    if !(1..=256).contains(&section_count)
        || section_off < size
        || section_off.saturating_add(section_count * 8) > data.len()
        || imp_off.saturating_add(imp_size) > data.len()
        || !imp_size.is_multiple_of(8)
        || rel_off > data.len()
    {
        return err("REL tables lie outside the file");
    }
    let entry = |section_at: usize, offset_at: usize| -> Result<Option<(u8, u32)>> {
        let section = data[section_at];
        Ok((section != 0).then_some((section, u32_be(data, offset_at)?)))
    };
    Ok(Header {
        module_id: u32_be(data, 0x00)?,
        section_count,
        section_off,
        bss_size: u32_be(data, 0x20)?,
        rel_off,
        imp_off,
        imp_size,
        entries: [entry(0x30, 0x34)?, entry(0x31, 0x38)?, entry(0x32, 0x3c)?],
    })
}

/// True when the image is a REL: a header whose version, link fields, section
/// table and import table are all consistent with the file.
pub(crate) fn is_rel(data: &[u8]) -> bool {
    header(data).is_ok()
}

impl<'a> Rel<'a> {
    pub(crate) fn parse(data: &'a [u8]) -> Result<Self> {
        let head = header(data)?;
        let mut sections = Vec::with_capacity(head.section_count);
        for index in 0..head.section_count {
            let at = head.section_off + index * 8;
            let raw = u32_be(data, at)?;
            sections.push(Section {
                file_off: raw & !1,
                size: u32_be(data, at + 4)?,
                exec: raw & 1 != 0,
            });
        }
        for section in &sections {
            if section.size != 0 && !section.is_bss() {
                let end = u64::from(section.file_off) + u64::from(section.size);
                if end > data.len() as u64 {
                    return err("REL section outside file");
                }
            }
        }
        // The header's bss size is the one bss section's size, as decomp-toolkit
        // requires; a table that disagrees was not written by a linker.
        let bss: u64 = sections.iter().filter(|s| s.is_bss()).map(|s| u64::from(s.size)).sum();
        if bss != u64::from(head.bss_size) {
            return err("REL bss size does not match its section table");
        }
        let relocs = relocations(data, &head)?;
        Ok(Self {
            data,
            module_id: head.module_id,
            sections,
            relocs,
            entries: head.entries,
        })
    }

    /// The initialized bytes of section `index`; empty for bss.
    fn bytes(&self, index: usize) -> &'a [u8] {
        let section = &self.sections[index];
        if section.is_bss() {
            return &[];
        }
        &self.data[section.file_off as usize..(section.file_off + section.size) as usize]
    }
}

/// Walks every import's relocation stream.
fn relocations(data: &[u8], head: &Header) -> Result<Vec<Reloc>> {
    let mut out = Vec::new();
    for import in 0..head.imp_size / 8 {
        let module = u32_be(data, head.imp_off + import * 8)?;
        let mut at = u32_be(data, head.imp_off + import * 8 + 4)? as usize;
        if import == 0 && at != head.rel_off {
            return err("REL first import does not start the relocation stream");
        }
        let (mut source, mut place) = (0u8, 0u32);
        loop {
            let record = at
                .checked_add(8)
                .and_then(|end| data.get(at..end))
                .ok_or_else(|| ImportError::Bad("REL relocation stream runs past the file".into()))?;
            at += 8;
            let offset = u32::from(u16::from_be_bytes([record[0], record[1]]));
            let (kind, target) = (record[2], record[3]);
            let addend = u32::from_be_bytes(record[4..8].try_into().unwrap());
            match kind {
                R_DOLPHIN_END => break,
                R_DOLPHIN_SECTION => {
                    source = target;
                    place = 0;
                    continue;
                }
                _ => place = place.wrapping_add(offset),
            }
            if matches!(kind, R_DOLPHIN_NOP | R_DOLPHIN_MRKREF | R_PPC_NONE) {
                continue;
            }
            out.push(Reloc { module, source, offset: place, kind, target, addend });
        }
    }
    Ok(out)
}

/// A relocation's patch to the place's bytes.
enum Patch {
    Word(u32),
    Half(u16),
}

/// The patch relocation `kind` makes, given the word at the place, the
/// target address `s` (symbol plus addend) and the place's own address `p`.
/// Semantics follow the ELF PowerPC psABI the console's linker implements:
/// the `LO`/`HI`/`HA` forms write the halfword, the branch forms keep the
/// opcode, `AA` and `LK` bits, and `REL` forms are checked to reach.
fn patch(kind: u8, word: u32, s: u32, p: u32) -> Option<Patch> {
    let displacement = s.wrapping_sub(p) as i32;
    let taken = 0x0020_0000;
    Some(match kind {
        R_PPC_ADDR32 => Patch::Word(s),
        R_PPC_ADDR24 => Patch::Word(word & 0xfc00_0003 | s & 0x03ff_fffc),
        R_PPC_ADDR16 | R_PPC_ADDR16_LO => Patch::Half(s as u16),
        R_PPC_ADDR16_HI => Patch::Half((s >> 16) as u16),
        R_PPC_ADDR16_HA => Patch::Half(((s >> 16) + (s >> 15 & 1)) as u16),
        R_PPC_ADDR14 => Patch::Word(word & 0xffff_0003 | s & 0xfffc),
        R_PPC_ADDR14_BRTAKEN => Patch::Word(word & 0xffdf_0003 | s & 0xfffc | taken),
        R_PPC_ADDR14_BRNTAKEN => Patch::Word(word & 0xffdf_0003 | s & 0xfffc),
        R_PPC_REL24 if (-0x200_0000..0x200_0000).contains(&displacement) => {
            Patch::Word(word & 0xfc00_0003 | displacement as u32 & 0x03ff_fffc)
        }
        R_PPC_REL14 if (-0x8000..0x8000).contains(&displacement) => {
            Patch::Word(word & 0xffff_0003 | displacement as u32 & 0xfffc)
        }
        R_PPC_REL14_BRTAKEN if (-0x8000..0x8000).contains(&displacement) => {
            Patch::Word(word & 0xffdf_0003 | displacement as u32 & 0xfffc | taken)
        }
        R_PPC_REL14_BRNTAKEN if (-0x8000..0x8000).contains(&displacement) => {
            Patch::Word(word & 0xffdf_0003 | displacement as u32 & 0xfffc)
        }
        _ => return None,
    })
}

/// What linking a set of RELs did, reported as one diagnostic.
#[derive(Default, Debug, PartialEq, Eq)]
pub(crate) struct LinkStats {
    pub applied: usize,
    /// Relocations against a module that is not loaded.
    pub unresolved: usize,
    /// Relocations whose place lies in the bss or outside its section.
    pub misplaced: usize,
    /// REL24/REL14 relocations that cannot reach their target.
    pub out_of_range: usize,
    /// Relocation types the format defines no meaning for.
    pub unknown: usize,
    /// Relocation counts by type, for `cross_module` and the report.
    pub by_kind: std::collections::BTreeMap<u8, usize>,
}

/// Section base addresses for a set of RELs placed one after another from
/// `start`: modules in id order as given, sections in table order, each on
/// a 32-byte boundary. Empty sections have no address.
fn place_sequential(rels: &[Rel], start: u64) -> Result<Vec<Vec<Option<u64>>>> {
    let mut at = align32(start);
    let mut out = Vec::with_capacity(rels.len());
    for rel in rels {
        let mut bases = Vec::with_capacity(rel.sections.len());
        for section in &rel.sections {
            if section.size == 0 {
                bases.push(None);
                continue;
            }
            bases.push(Some(at));
            at = align32(at + u64::from(section.size));
            if at > ADDRESS_LIMIT {
                return err("REL sections do not fit in a 32-bit address space");
            }
        }
        out.push(bases);
    }
    Ok(out)
}

/// Standalone placement: section `i` in its own window.
fn place_windows(rel: &Rel) -> Result<Vec<Option<u64>>> {
    rel.sections
        .iter()
        .enumerate()
        .map(|(index, section)| {
            if section.size == 0 {
                return Ok(None);
            }
            let base = WINDOW_BASE + index as u64 * WINDOW_STRIDE;
            if base + u64::from(section.size) > ADDRESS_LIMIT {
                return err("REL has too many sections for standalone placement");
            }
            Ok(Some(base))
        })
        .collect()
}

/// A linked REL: where its sections went.
pub(crate) struct Linked {
    /// First mapping of this REL in `NativeImport::mappings`, and how many.
    pub first_mapping: usize,
    pub mappings: usize,
    pub module: NativeModule,
}

/// Adds `rels` to `imp`: their sections as mappings at `bases`, every
/// relocation applied to the bytes, and the seeds and references the
/// relocations and header prove. `names` labels each module (the file stem
/// on the disc). `imp` may already hold the DOL. A relocation against a
/// module not in `rels` asks `outside` for the target section's address
/// (an overlay's imports of the modules that stay resident).
fn link(
    imp: &mut NativeImport,
    rels: &[Rel],
    bases: &[Vec<Option<u64>>],
    names: &[(String, String, u64)],
    outside: &dyn Fn(u32, u8) -> Option<u64>,
) -> Result<(Vec<Linked>, LinkStats)> {
    let mut stats = LinkStats::default();
    let mut linked = Vec::with_capacity(rels.len());
    // First, every section becomes a mapping, so a relocation can patch
    // whichever module's bytes it lands in.
    let mut slots: Vec<Vec<Option<usize>>> = Vec::with_capacity(rels.len());
    for (rel_index, rel) in rels.iter().enumerate() {
        let first = imp.mappings.len();
        let mut slot = vec![None; rel.sections.len()];
        let (mut low, mut high) = (u64::MAX, 0u64);
        for (index, section) in rel.sections.iter().enumerate() {
            let Some(base) = bases[rel_index][index] else { continue };
            slot[index] = Some(imp.mappings.len());
            imp.mappings.push(Mapping {
                vaddr: base,
                size: u64::from(section.size),
                file_off: u64::from(section.file_off),
                flags: if section.exec { 6 } else { 3 },
                bytes: rel.bytes(index).to_vec(),
            });
            imp.mapping_names
                .resize(imp.mappings.len() - 1, String::new());
            imp.mapping_names
                .push(format!("rel{}.sec{index}", rel.module_id));
            low = low.min(base);
            high = high.max(base + u64::from(section.size));
        }
        if first == imp.mappings.len() {
            return err("REL carries no sections");
        }
        let (name, file_id, file_off) = &names[rel_index];
        linked.push(Linked {
            first_mapping: first,
            mappings: imp.mappings.len() - first,
            module: NativeModule {
                name: name.clone(),
                kind: "rel".into(),
                file_id: file_id.clone(),
                load_vaddr: low,
                size: high - low,
                file_off: *file_off,
            },
        });
        slots.push(slot);
    }
    let base_of = |module: u32, section: u8| -> Option<u64> {
        match rels.iter().position(|rel| rel.module_id == module) {
            Some(index) => bases[index].get(usize::from(section)).copied().flatten(),
            None => outside(module, section),
        }
    };
    for (rel_index, rel) in rels.iter().enumerate() {
        for reloc in &rel.relocs {
            *stats.by_kind.entry(reloc.kind).or_default() += 1;
            let target = if reloc.module == 0 {
                Some(u64::from(reloc.addend))
            } else {
                base_of(reloc.module, reloc.target).map(|base| base + u64::from(reloc.addend))
            };
            let Some(target) = target else {
                stats.unresolved += 1;
                continue;
            };
            let section = usize::from(reloc.source);
            let (Some(Some(slot)), Some(base)) = (
                slots[rel_index].get(section),
                bases[rel_index].get(section).copied().flatten(),
            ) else {
                stats.misplaced += 1;
                continue;
            };
            let width = if matches!(
                reloc.kind,
                R_PPC_ADDR16 | R_PPC_ADDR16_LO | R_PPC_ADDR16_HI | R_PPC_ADDR16_HA
            ) {
                2
            } else {
                4
            };
            let place = base + u64::from(reloc.offset);
            let mapping = &mut imp.mappings[*slot];
            let at = reloc.offset as usize;
            let Some(bytes) = at
                .checked_add(width)
                .and_then(|end| mapping.bytes.get_mut(at..end))
            else {
                stats.misplaced += 1;
                continue;
            };
            let word = if width == 4 {
                u32::from_be_bytes(bytes.try_into().unwrap())
            } else {
                0
            };
            let known = (R_PPC_ADDR32..=R_PPC_REL14_BRNTAKEN).contains(&reloc.kind);
            match patch(reloc.kind, word, target as u32, place as u32) {
                Some(Patch::Word(value)) => bytes.copy_from_slice(&value.to_be_bytes()),
                Some(Patch::Half(value)) => bytes.copy_from_slice(&value.to_be_bytes()),
                None if known => {
                    stats.out_of_range += 1;
                    continue;
                }
                None => {
                    stats.unknown += 1;
                    continue;
                }
            }
            stats.applied += 1;
            if reloc.kind == R_PPC_ADDR32 {
                imp.xrefs.push(NativeXref::with_provenance(place, target, "DATA", RELOC_SOURCE));
            }
        }
    }
    // Seeds: the header's entry points, and every code address a relocation
    // names. Each still faces flow validation like any relocation candidate.
    for (rel_index, rel) in rels.iter().enumerate() {
        for (entry, name) in rel.entries.iter().zip(["_prolog", "_epilog", "_unresolved"]) {
            let Some((section, offset)) = *entry else { continue };
            if let Some(base) = bases[rel_index].get(usize::from(section)).copied().flatten() {
                imp.functions.push(NativeFunction {
                    entry: base + u64::from(offset),
                    name: name.into(),
                    size: 1,
                });
            }
        }
    }
    let executable: Vec<(u64, u64)> = imp
        .mappings
        .iter()
        .filter(|mapping| mapping.flags & 4 != 0)
        .map(|mapping| (mapping.vaddr, mapping.vaddr + mapping.size))
        .collect();
    let in_code = |address: u64| executable.iter().any(|&(lo, hi)| address >= lo && address < hi);
    for rel in rels.iter() {
        for reloc in &rel.relocs {
            if !matches!(reloc.kind, R_PPC_ADDR32 | R_PPC_REL24 | R_PPC_REL14) {
                continue;
            }
            let target = if reloc.module == 0 {
                Some(u64::from(reloc.addend))
            } else {
                base_of(reloc.module, reloc.target).map(|base| base + u64::from(reloc.addend))
            };
            // A branch relocation names a function entry (or a case label
            // the flow walk will refuse); a data word names one only when it
            // is a function pointer. Both are candidates, never conclusions.
            if let Some(target) = target.filter(|target| in_code(*target) && target % 4 == 0) {
                // A REL24 against the REL's own code from its own code is
                // already a call the flow walk follows; the candidate list
                // is for what nothing else reaches.
                let own_code = reloc.module == rel.module_id && reloc.kind != R_PPC_ADDR32;
                if !own_code {
                    imp.reloc_candidates.push(target);
                }
            }
        }
    }
    imp.reloc_candidates.sort_unstable();
    imp.reloc_candidates.dedup();
    Ok((linked, stats))
}

fn describe(stats: &LinkStats, rels: usize) -> String {
    let kinds: Vec<String> = stats
        .by_kind
        .iter()
        .map(|(kind, count)| format!("{kind}:{count}"))
        .collect();
    format!(
        "{rels} REL module(s): {} relocations applied, {} against modules not loaded, \
         {} out of range, {} misplaced, {} of unknown type; by type {}",
        stats.applied,
        stats.unresolved,
        stats.out_of_range,
        stats.misplaced,
        stats.unknown,
        kinds.join(" ")
    )
}

/// Standalone REL import: no DOL beside it, sections in their own windows.
pub(crate) fn import(data: &[u8]) -> Result<NativeImport> {
    let rel = Rel::parse(data)?;
    let bases = vec![place_windows(&rel)?];
    let mut imp = NativeImport::default();
    let name = format!("rel{}", rel.module_id);
    let (_, stats) = link(
        &mut imp,
        std::slice::from_ref(&rel),
        &bases,
        &[(name, String::new(), 0)],
        &|_, _| None,
    )?;
    // Standalone, the windows are not memory the REL occupies together, so
    // each section stays its own module row (the store's default).
    imp.mapping_names.clear();
    imp.format = "REL".into();
    imp.language = "PowerPC:BE:32:Gekko_Broadway".into();
    imp.diagnose(
        romwright_model::DiagnosticSeverity::Info,
        "rel",
        describe(&stats, 1),
    );
    Ok(imp)
}

/// One REL a disc carries, with the names its module row takes.
pub(crate) struct DiscRel {
    pub name: String,
    pub file_id: String,
    /// The archive or directory the file was read from: what its siblings
    /// of one set share.
    pub container: String,
    /// Where the file's stored bytes begin in the disc image.
    pub file_off: u64,
    pub bytes: Vec<u8>,
}

/// A parsed REL and the disc entry it was read from.
type RelEntry<'a> = (Rel<'a>, &'a DiscRel);

/// Sorts parsed RELs into the modules that stay resident (merged into the
/// DOL's program, in module-id order) and the alternatives that share an id
/// (programs of their own), and counts the alternatives per id.
///
/// A module id names one module in a running game, so a group of files with
/// one id holds either copies, or alternatives paged into the same place, or
/// a game's module and a stub of it for another mode. In order:
/// 1. byte-identical files of one name are one module (the copy in the
///    container with the most RELs is kept, so a loose copy of an archive's
///    member does not displace it);
/// 2. a file is the resident one of its id when its container -- the archive
///    or the directory it was read from -- holds more RELs than every other
///    file's of that id and it is the only one of its id there: Skyward
///    Sword's `rels.arc` (636 RELs) beside seven stubs in
///    `sys/mpls_movie/rels`;
/// 3. otherwise none is, and every file of the id is an alternative: Mario
///    Party 4's `dll` directory holds 99 RELs of module id 1 or 2.
fn split_by_module_id<'a>(
    parsed: Vec<RelEntry<'a>>,
    copies: &mut Vec<String>,
) -> (Vec<RelEntry<'a>>, Vec<RelEntry<'a>>, std::collections::HashMap<u32, usize>) {
    use std::collections::HashMap;
    let mut in_container: HashMap<&str, usize> = HashMap::new();
    for (_, item) in &parsed {
        *in_container.entry(item.container.as_str()).or_default() += 1;
    }
    let mut groups: std::collections::BTreeMap<u32, Vec<(Rel<'a>, &'a DiscRel)>> = std::collections::BTreeMap::new();
    for entry in parsed {
        groups.entry(entry.0.module_id).or_default().push(entry);
    }
    let (mut resident, mut overlays) = (Vec::new(), Vec::new());
    let mut alternatives = HashMap::new();
    for (id, mut group) in groups {
        // Largest container first; the disc's own order within one.
        group.sort_by_key(|(_, item)| std::cmp::Reverse(in_container[item.container.as_str()]));
        let mut distinct: Vec<(Rel<'a>, &'a DiscRel)> = Vec::with_capacity(group.len());
        for entry in group {
            // A copy is the same module under the same name; two differently
            // named files that happen to hold the same bytes (Mario Party 4's
            // empty minigame DLLs) are two modules.
            let twin = distinct
                .iter()
                .find(|(_, first)| first.name.eq_ignore_ascii_case(&entry.1.name) && first.bytes == entry.1.bytes);
            match twin {
                Some((_, first)) => copies.push(format!("{} is identical to {}", entry.1.file_id, first.file_id)),
                None => distinct.push(entry),
            }
        }
        let size = |entry: &(Rel<'a>, &'a DiscRel)| in_container[entry.1.container.as_str()];
        let stays = distinct.len() == 1
            || (size(&distinct[0]) > size(&distinct[1])
                && distinct[1..].iter().all(|other| other.1.container != distinct[0].1.container));
        if distinct.len() > 1 {
            alternatives.insert(id, distinct.len());
        }
        if stays {
            let mut members = distinct.into_iter();
            resident.push(members.next().expect("a group is never empty"));
            overlays.extend(members);
        } else {
            overlays.extend(distinct);
        }
    }
    (resident, overlays, alternatives)
}

/// Imports a DOL with the RELs of its disc placed beside it, as programs.
///
/// A REL has no address of its own, and the console's loader (`OSLink`) puts
/// each module wherever the heap has room, so the RELs of a disc are placed
/// the way `dtk rel merge` does: in module-id order after the DOL, every
/// relocation applied, and the DOL and each REL their own `modules` rows so
/// a reference between them is a `module_xrefs` row. That is the first
/// program (`dol` is the loaded DOL import, consumed).
///
/// Module ids name a module in a *running* game, so two RELs of one id are
/// never loaded together. When they are alternatives paged into the same
/// place (Mario Party 4's minigame and board DLLs are all module 1 or 2),
/// merging them would stack code that never coexists and make one id mean
/// several modules, so each such REL is a program of its own, named after the
/// file, placed from the same base the merged modules start at and sharing
/// its addresses with its siblings the way DS and N64 overlays do. Which
/// file of an id stays resident, if any, is `split_by_module_id`'s decision.
/// An overlay's relocations against module 0 apply exactly as in the merged
/// program, and those against a module that stays resident resolve to that
/// module's place in the main program.
///
/// The first program is the DOL's, with the empty suffix when there are no
/// overlay programs and `main` when there are, so every program of a
/// container selects by a suffix of its own.
pub(crate) fn attach(
    mut dol: NativeImport,
    dol_id: &str,
    dol_file_off: u64,
    rels: &[DiscRel],
) -> Result<Vec<(String, NativeImport)>> {
    if rels.is_empty() {
        return Ok(vec![(String::new(), dol)]);
    }
    let mut parsed: Vec<(Rel, &DiscRel)> = Vec::with_capacity(rels.len());
    let mut skipped = Vec::new();
    for item in rels {
        match Rel::parse(&item.bytes) {
            Ok(rel) if rel.module_id == 0 => {
                skipped.push(format!("{}: module id 0 is the DOL", item.file_id));
            }
            Ok(rel) => parsed.push((rel, item)),
            Err(error) => skipped.push(format!("{}: {error}", item.file_id)),
        }
    }
    let note_skipped = |imp: &mut NativeImport, skipped: Vec<String>| {
        for reason in skipped {
            imp.diagnose(
                romwright_model::DiagnosticSeverity::Partial,
                "rel",
                format!("REL skipped: {reason}"),
            );
        }
    };
    if parsed.is_empty() {
        note_skipped(&mut dol, skipped);
        return Ok(vec![(String::new(), dol)]);
    }
    let mut copies = Vec::new();
    let (resident, overlays, alternatives) = split_by_module_id(parsed, &mut copies);
    let dol_low = dol.mappings.iter().map(|m| m.vaddr).min().unwrap_or(0);
    let dol_high = dol.mappings.iter().map(|m| m.vaddr + m.size).max().unwrap_or(0);
    let base = super::dol::rel_base(&dol);
    let small_data = super::dol::sda_bases(&dol);
    let language = dol.language.clone();
    // The DOL's mappings keep their default names.
    let dol_count = dol.mappings.len();
    dol.mapping_names = (0..dol_count).map(|index| index.to_string()).collect();
    // REL code addresses its data through the DOL's small-data bases.
    let small_data_contexts = |imp: &mut NativeImport, linked: &Linked| {
        let Some([r2, r13]) = small_data else { return };
        for mapping in &imp.mappings[linked.first_mapping..linked.first_mapping + linked.mappings] {
            if mapping.flags & 4 == 0 {
                continue;
            }
            for (register, value) in [("r2", r2), ("r13", r13)] {
                imp.register_contexts.push(NativeRegisterContext {
                    start: mapping.vaddr,
                    end: mapping.vaddr + mapping.size,
                    register: register.into(),
                    value: u64::from(value),
                });
            }
        }
    };
    dol.modules.push(NativeModule {
        name: "main.dol".into(),
        kind: "dol".into(),
        file_id: dol_id.into(),
        load_vaddr: dol_low,
        size: dol_high - dol_low,
        file_off: dol_file_off,
    });
    let (set, items): (Vec<Rel>, Vec<&DiscRel>) = resident.into_iter().unzip();
    let bases = place_sequential(&set, base)?;
    if !set.is_empty() {
        let names: Vec<(String, String, u64)> = items
            .iter()
            .map(|item| (item.name.clone(), item.file_id.clone(), item.file_off))
            .collect();
        let (linked, stats) = link(&mut dol, &set, &bases, &names, &|_, _| None)?;
        for linked in &linked {
            dol.modules.push(linked.module.clone());
            small_data_contexts(&mut dol, linked);
        }
        dol.diagnose(
            romwright_model::DiagnosticSeverity::Info,
            "rel",
            describe(&stats, set.len()),
        );
    }
    // Each alternative is its own program, from the same base.
    let outside = |module: u32, section: u8| -> Option<u64> {
        let index = set.iter().position(|rel| rel.module_id == module)?;
        bases[index].get(usize::from(section)).copied().flatten()
    };
    let mut programs: Vec<(String, NativeImport)> = Vec::with_capacity(overlays.len() + 1);
    // A stub of a resident module keeps the file's name in its module row but
    // not as a program name: that name is the resident module's.
    let mut taken: std::collections::HashSet<String> = std::collections::HashSet::from(["main".to_string()]);
    taken.extend(items.iter().map(|item| item.name.clone()));
    for (rel, item) in &overlays {
        let alone = place_sequential(std::slice::from_ref(rel), base)?;
        let mut imp = NativeImport {
            format: "dol".into(),
            language: language.clone(),
            ..Default::default()
        };
        let names = [(item.name.clone(), item.file_id.clone(), item.file_off)];
        let (linked, stats) = link(&mut imp, std::slice::from_ref(rel), &alone, &names, &outside)?;
        imp.modules.push(linked[0].module.clone());
        small_data_contexts(&mut imp, &linked[0]);
        let alternatives = alternatives[&rel.module_id];
        imp.diagnose(
            romwright_model::DiagnosticSeverity::Info,
            "rel",
            format!(
                "overlay program: module id {} is shared by {alternatives} REL files, so each is placed alone from {base:#x}; {}",
                rel.module_id,
                describe(&stats, 1)
            ),
        );
        // A program's name is its file's, made unique when two files of
        // different folders share it.
        let mut suffix = item.name.clone();
        if !taken.insert(suffix.clone()) {
            suffix = format!("{}_{}", item.name, rel.module_id);
            let mut copy = 2;
            while !taken.insert(suffix.clone()) {
                suffix = format!("{}_{}_{copy}", item.name, rel.module_id);
                copy += 1;
            }
        }
        programs.push((suffix, imp));
    }
    if !programs.is_empty() {
        dol.sibling_call_host = true;
        dol.diagnose(
            romwright_model::DiagnosticSeverity::Info,
            "rel",
            format!(
                "{} REL file(s) share a module id with another and are overlay programs of their own (alternatives paged into one place), not merged",
                programs.len()
            ),
        );
    }
    note_skipped(&mut dol, skipped);
    for copy in copies {
        dol.diagnose(
            romwright_model::DiagnosticSeverity::Info,
            "rel",
            format!("REL copy not linked again: {copy}"),
        );
    }
    let first = if programs.is_empty() { String::new() } else { "main".to_string() };
    programs.insert(0, (first, dol));
    Ok(programs)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn be(out: &mut Vec<u8>, value: u32) {
        out.extend_from_slice(&value.to_be_bytes());
    }

    /// One relocation record `{offset, type, section, addend}`.
    fn record(offset: u16, kind: u8, section: u8, addend: u32) -> [u8; 8] {
        let mut out = [0u8; 8];
        out[0..2].copy_from_slice(&offset.to_be_bytes());
        out[2] = kind;
        out[3] = section;
        out[4..8].copy_from_slice(&addend.to_be_bytes());
        out
    }

    /// A version-2 REL: section 1 `.text` (exec), section 2 `.data`, section
    /// 3 a bss of 0x40; `_prolog` at text+0x10. `streams` is
    /// `(target module, records)` per import, in table order.
    fn build(module_id: u32, text: &[u8], data: &[u8], streams: &[(u32, Vec<[u8; 8]>)]) -> Vec<u8> {
        let sections_at = 0x48usize;
        let text_at = sections_at + 4 * 8;
        let data_at = text_at + text.len();
        let rel_at = data_at + data.len();
        let mut stream_bytes = Vec::new();
        let mut imports = Vec::new();
        for (module, records) in streams {
            imports.push((*module, rel_at + stream_bytes.len()));
            for r in records {
                stream_bytes.extend_from_slice(r);
            }
            stream_bytes.extend_from_slice(&record(0, R_DOLPHIN_END, 0, 0));
        }
        let imp_at = rel_at + stream_bytes.len();
        let mut out = Vec::new();
        for value in [
            module_id, 0, 0, 4, sections_at as u32, 0, 0, 2, 0x40,
            rel_at as u32, imp_at as u32, (imports.len() * 8) as u32,
        ] {
            be(&mut out, value);
        }
        out.extend_from_slice(&[1, 0, 0, 0]);
        for value in [0x10, 0, 0, 4, 8] {
            be(&mut out, value);
        }
        assert_eq!(out.len(), sections_at);
        for value in [
            0, 0,
            (text_at | 1) as u32, text.len() as u32,
            data_at as u32, data.len() as u32,
            0, 0x40,
        ] {
            be(&mut out, value);
        }
        out.extend_from_slice(text);
        out.extend_from_slice(data);
        out.extend_from_slice(&stream_bytes);
        for (module, at) in imports {
            be(&mut out, module);
            be(&mut out, at as u32);
        }
        out
    }

    /// A REL of module `id` whose data word at +4 holds the address of
    /// `(module, text + addend)` for each import given (one word per import
    /// stream, so tests pass at most one).
    pub(crate) fn module_importing(id: u32, imports: &[(u32, u32)]) -> Vec<u8> {
        let streams: Vec<(u32, Vec<[u8; 8]>)> = imports
            .iter()
            .map(|&(module, addend)| {
                (module, vec![record(0, R_DOLPHIN_SECTION, 2, 0), record(4, R_PPC_ADDR32, 1, addend)])
            })
            .collect();
        build(id, &[0; 0x20], &[0; 8], &streams)
    }

    fn word(bytes: &[u8], at: usize) -> u32 {
        u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap())
    }

    fn applied(kind: u8, before: u32, target: u32, place: u32) -> Option<u32> {
        match patch(kind, before, target, place)? {
            Patch::Word(value) => Some(value),
            Patch::Half(value) => Some(u32::from(value)),
        }
    }

    #[test]
    fn every_relocation_type_patches_as_the_psabi_says() {
        let s = 0x8123_8000;
        let p = 0x8000_1000;
        let near = p + 0x400;
        // (type, word at the place, target, expected word or halfword)
        let cases: [(u8, u32, u32, u32); 13] = [
            (R_PPC_ADDR32, 0xdead_beef, s, 0x8123_8000),
            (R_PPC_ADDR24, 0x4800_0001, s, 0x4923_8001),
            (R_PPC_ADDR14, 0x4082_0000, s, 0x4082_8000),
            (R_PPC_ADDR14_BRTAKEN, 0x4082_0000, s, 0x40a2_8000),
            (R_PPC_ADDR14_BRNTAKEN, 0x40a2_0000, s, 0x4082_8000),
            (R_PPC_REL24, 0x4800_0001, near, 0x4800_0401),
            (R_PPC_REL14, 0x4182_0000, near, 0x4182_0400),
            (R_PPC_REL14_BRTAKEN, 0x4182_0000, near, 0x41a2_0400),
            (R_PPC_REL14_BRNTAKEN, 0x41a2_0000, near, 0x4182_0400),
            (R_PPC_ADDR16, 0, s, 0x8000),
            (R_PPC_ADDR16_LO, 0, s, 0x8000),
            (R_PPC_ADDR16_HI, 0, s, 0x8123),
            // The low half is negative as a signed value, so HA rounds up.
            (R_PPC_ADDR16_HA, 0, s, 0x8124),
        ];
        for (kind, before, target, want) in cases {
            assert_eq!(applied(kind, before, target, p), Some(want), "type {kind}");
        }
        // A positive low half does not round.
        assert_eq!(applied(R_PPC_ADDR16_HA, 0, 0x8123_7fff, p), Some(0x8123));
        // A backwards branch keeps its sign bits inside the field.
        assert_eq!(applied(R_PPC_REL24, 0x4800_0001, p - 0x10, p), Some(0x4bff_fff1));
        // REL24 reaches +-32 MiB, REL14 +-32 KiB; one past is refused.
        assert!(applied(R_PPC_REL24, 0x4800_0001, p + 0x200_0000, p).is_none());
        assert!(applied(R_PPC_REL24, 0x4800_0001, p - 0x200_0000, p).is_some());
        assert!(applied(R_PPC_REL14, 0x4182_0000, p + 0x8000, p).is_none());
        assert!(applied(R_PPC_REL14, 0x4182_0000, p - 0x8000, p).is_some());
        assert!(applied(R_PPC_NONE, 0, s, p).is_none());
    }

    #[test]
    fn streams_accumulate_offsets_switch_sections_and_stop_at_end() {
        let own = vec![
            record(0, R_DOLPHIN_SECTION, 1, 0),
            record(4, R_PPC_REL24, 0, 0x8000_2000),
            record(0x10, R_PPC_ADDR16_HA, 2, 8),
            record(2, R_PPC_ADDR16_LO, 2, 8),
            record(0, R_DOLPHIN_SECTION, 2, 0),
            record(8, R_PPC_ADDR32, 1, 0x10),
        ];
        let dol = vec![
            record(0, R_DOLPHIN_SECTION, 1, 0),
            // NOP and MRKREF only advance the place.
            record(0xffff, R_DOLPHIN_NOP, 0, 0),
            record(4, R_DOLPHIN_MRKREF, 0, 0),
            record(0x18, R_PPC_REL24, 0, 0x8000_3000),
        ];
        let image = build(5, &[0; 0x20], &[0; 0x10], &[(5, own), (0, dol)]);
        let rel = Rel::parse(&image).unwrap();
        assert_eq!(rel.module_id, 5);
        // Section 0 is null, 3 is the 0x40-byte bss.
        assert_eq!(rel.sections.len(), 4);
        assert_eq!((rel.sections[3].file_off, rel.sections[3].size), (0, 0x40));
        assert_eq!(rel.entries, [Some((1, 0x10)), None, None]);
        let got: Vec<(u32, u8, u32, u8, u32)> = rel
            .relocs
            .iter()
            .map(|r| (r.module, r.source, r.offset, r.kind, r.addend))
            .collect();
        assert_eq!(
            got,
            [
                (5, 1, 4, R_PPC_REL24, 0x8000_2000),
                (5, 1, 0x14, R_PPC_ADDR16_HA, 8),
                (5, 1, 0x16, R_PPC_ADDR16_LO, 8),
                (5, 2, 8, R_PPC_ADDR32, 0x10),
                (0, 1, 0xffff + 4 + 0x18, R_PPC_REL24, 0x8000_3000),
            ]
        );
    }

    #[test]
    fn link_places_sections_and_patches_self_and_dol_targets() {
        let mut text = vec![0u8; 0x40];
        text[4..8].copy_from_slice(&0x4800_0001u32.to_be_bytes()); // bl
        text[0x10..0x14].copy_from_slice(&0x3c60_0000u32.to_be_bytes()); // lis
        text[0x14..0x18].copy_from_slice(&0x3863_0000u32.to_be_bytes()); // addi
        let to_dol = vec![
            record(0, R_DOLPHIN_SECTION, 1, 0),
            record(4, R_PPC_REL24, 0, 0x8000_3100),
        ];
        let to_self = vec![
            record(0, R_DOLPHIN_SECTION, 1, 0),
            record(0x12, R_PPC_ADDR16_HA, 2, 8),
            record(4, R_PPC_ADDR16_LO, 2, 8),
            record(0, R_DOLPHIN_SECTION, 2, 0),
            record(4, R_PPC_ADDR32, 1, 0x20),
        ];
        let image = build(1, &text, &[0; 0x10], &[(0, to_dol), (1, to_self)]);
        let rel = Rel::parse(&image).unwrap();
        let bases = place_sequential(std::slice::from_ref(&rel), 0x8021_e720).unwrap();
        // Text, data, bss each on the next 32-byte boundary.
        assert_eq!(bases[0], [None, Some(0x8021_e720), Some(0x8021_e760), Some(0x8021_e780)]);
        let mut imp = NativeImport::default();
        let names = [("m".to_string(), "m.rel".to_string(), 0x1234)];
        let (linked, stats) = link(&mut imp, std::slice::from_ref(&rel), &bases, &names, &|_, _| None).unwrap();
        assert_eq!((stats.applied, stats.unresolved, stats.out_of_range, stats.misplaced), (4, 0, 0, 0));
        assert_eq!(linked[0].module.load_vaddr, 0x8021_e720);
        assert_eq!(linked[0].module.size, 0xa0);
        assert_eq!(linked[0].module.file_off, 0x1234);
        let text = &imp.mappings[0].bytes;
        // `bl` to the DOL's absolute address, relative to the place.
        assert_eq!(word(text, 4), 0x4800_0001 | 0x8000_3100u32.wrapping_sub(0x8021_e724) & 0x03ff_fffc);
        // The lis/addi pair that loads the address of data+8 (0x8021e768):
        // HA is 0x8021 + 1 because the low half 0xe768 is negative signed.
        assert_eq!(&text[0x12..0x14], &[0x80, 0x22]);
        assert_eq!(&text[0x16..0x18], &[0xe7, 0x68]);
        // The data word holds the address of text+0x20, recorded as a data
        // reference carrying the relocation's provenance.
        assert_eq!(word(&imp.mappings[1].bytes, 4), 0x8021_e740);
        assert_eq!(imp.xrefs.len(), 1);
        assert_eq!((imp.xrefs[0].from, imp.xrefs[0].to), (0x8021_e764, 0x8021_e740));
        assert_eq!(imp.xrefs[0].provenance, RELOC_SOURCE);
        // The bss is zero-fill and `_prolog` seeds a function.
        assert!(imp.mappings[2].bytes.is_empty());
        assert_eq!(imp.functions[0].entry, 0x8021_e730);
        assert_eq!(imp.functions[0].name, "_prolog");
        // The DOL target is outside every mapping here; the data word names
        // code nothing else reaches.
        assert_eq!(imp.reloc_candidates, [0x8021_e740]);
    }

    #[test]
    fn unresolvable_unreachable_and_misplaced_relocations_are_counted_not_applied() {
        let to_dol = vec![
            record(0, R_DOLPHIN_SECTION, 1, 0),
            record(0, R_PPC_REL24, 0, 0x9000_0000), // beyond +-32 MiB of the place
        ];
        let to_self = vec![
            record(0, R_DOLPHIN_SECTION, 1, 0),
            record(4, R_PPC_ADDR32, 1, 0),
            record(0, R_DOLPHIN_SECTION, 3, 0), // the bss holds no bytes
            record(0, R_PPC_ADDR32, 1, 0),
            record(0, R_DOLPHIN_SECTION, 1, 0),
            record(0x10, 77, 1, 0), // no such type
        ];
        let elsewhere = vec![record(0, R_DOLPHIN_SECTION, 1, 0), record(8, R_PPC_ADDR32, 1, 0)];
        let image = build(1, &[0; 0x20], &[0; 8], &[(0, to_dol), (1, to_self), (9, elsewhere)]);
        let rel = Rel::parse(&image).unwrap();
        let bases = place_sequential(std::slice::from_ref(&rel), 0x8000_0000).unwrap();
        let mut imp = NativeImport::default();
        let names = [("m".to_string(), String::new(), 0)];
        let (_, stats) = link(&mut imp, std::slice::from_ref(&rel), &bases, &names, &|_, _| None).unwrap();
        assert_eq!(
            (stats.applied, stats.out_of_range, stats.misplaced, stats.unresolved, stats.unknown),
            (1, 1, 1, 1, 1)
        );
        // The `bl` slot the table could not reach stays untouched.
        assert_eq!(word(&imp.mappings[0].bytes, 0), 0);
        assert_eq!(word(&imp.mappings[0].bytes, 4), 0x8000_0000);
    }

    #[test]
    fn relocations_resolve_across_rels_by_module_id() {
        let into_b = vec![record(0, R_DOLPHIN_SECTION, 2, 0), record(4, R_PPC_ADDR32, 1, 0x10)];
        let a = build(1, &[0; 0x20], &[0; 8], &[(2, into_b)]);
        let b = build(2, &[0; 0x20], &[0; 8], &[]);
        let rels = [Rel::parse(&a).unwrap(), Rel::parse(&b).unwrap()];
        let bases = place_sequential(&rels, 0x8100_0000).unwrap();
        let names = [("a".to_string(), String::new(), 0), ("b".to_string(), String::new(), 0)];
        let mut imp = NativeImport::default();
        let (_, stats) = link(&mut imp, &rels, &bases, &names, &|_, _| None).unwrap();
        assert_eq!(stats.applied, 1);
        // a's data word names b's text + 0x10.
        assert_eq!(word(&imp.mappings[1].bytes, 4), (bases[1][1].unwrap() + 0x10) as u32);
        // Alone, a's import of module 2 cannot resolve.
        let mut alone = NativeImport::default();
        let (_, stats) = link(&mut alone, &rels[..1], &bases[..1], &names[..1], &|_, _| None).unwrap();
        assert_eq!((stats.applied, stats.unresolved), (0, 1));
    }

    #[test]
    fn standalone_import_keeps_section_windows_and_applies_dol_relocations() {
        let mut text = vec![0u8; 8];
        text[0..4].copy_from_slice(&0x4800_0001u32.to_be_bytes());
        let stream = vec![record(0, R_DOLPHIN_SECTION, 1, 0), record(0, R_PPC_REL24, 0, 0x9000_0100)];
        let image = build(3, &text, &[0xde, 0xad, 0xbe, 0xef], &[(0, stream)]);
        assert!(is_rel(&image));
        let imp = import(&image).unwrap();
        let starts: Vec<u64> = imp.mappings.iter().map(|m| m.vaddr).collect();
        assert_eq!(starts, [0x9000_0000, 0xa000_0000, 0xb000_0000]);
        assert_eq!(word(&imp.mappings[0].bytes, 0), 0x4800_0101);
        assert_eq!(imp.mappings[1].bytes, [0xde, 0xad, 0xbe, 0xef]);
        assert!(imp.modules.is_empty());
    }

    #[test]
    fn malformed_rels_are_refused_by_name() {
        let good = build(1, &[0; 8], &[0; 4], &[(0, vec![record(0, R_DOLPHIN_SECTION, 1, 0)])]);
        assert!(is_rel(&good));
        // A DOL is not a REL.
        let mut dol = vec![0u8; 0x100];
        dol[0..4].copy_from_slice(&0x100u32.to_be_bytes());
        assert!(!is_rel(&dol));
        // A section past the end of the file: recognised, refused on parse.
        let mut bad = good.clone();
        bad[0x48 + 8 + 4..0x48 + 8 + 8].copy_from_slice(&0x1000_0000u32.to_be_bytes());
        assert!(is_rel(&bad));
        assert!(Rel::parse(&bad).err().unwrap().to_string().contains("REL section outside file"));
        // A version this loader has no header size for.
        let mut bad = good.clone();
        bad[0x1c..0x20].copy_from_slice(&9u32.to_be_bytes());
        assert!(!is_rel(&bad));
        // Runtime link fields set: a loaded module, not a file.
        let mut bad = good.clone();
        bad[0x04..0x08].copy_from_slice(&1u32.to_be_bytes());
        assert!(!is_rel(&bad));
        // A header bss size the section table does not carry.
        let mut bad = good.clone();
        bad[0x20..0x24].copy_from_slice(&0x10u32.to_be_bytes());
        assert!(Rel::parse(&bad).err().unwrap().to_string().contains("bss size"));
        // Truncated.
        assert!(!is_rel(&good[..0x30]));
        // A relocation stream that never reaches END runs off the file.
        let mut endless = good.clone();
        let at = endless.len() - 8;
        endless[0x24..0x28].copy_from_slice(&(at as u32).to_be_bytes());
        endless[at + 4..at + 8].copy_from_slice(&(at as u32).to_be_bytes());
        assert!(Rel::parse(&endless).is_err());
    }
}
