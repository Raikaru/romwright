//! MIPS `.debug` (SHT_MIPS_DEBUG) readers: the debug stream a PS2-era
//! toolchain leaves beside the ELF symbol table.
//!
//! Two formats share the section name, sniffed by content:
//!
//! * **ECOFF/mdebug** (MIPS/SGI toolchain): an HDRR symbolic header whose
//!   fields are absolute file offsets into FDR file descriptors, PDR
//!   procedure descriptors, SYMR local symbols, AUX entries, string
//!   spaces, and EXTR external symbols. Layouts follow binutils
//!   `include/coff/sym.h` and `include/coff/mips.h`; semantics (the
//!   `stEnd` size indirection, the stripped-file external lookup, the
//!   packed line stream) follow gdb `mdebugread.c`.
//! * **Metrowerks DWARF 1** ("MW MIPS C Compiler"): a flat DIE stream
//!   whose `length` field includes itself and whose attribute codes pack
//!   `(attribute << 4) | form`. SLUS_209.50 carries this shape; its
//!   sibling `.line` section is a separate per-function line table this
//!   reader does not need for symbol recovery.
//!
//! Both readers recover procedure entries: address, name, size. The
//! DWARF 1 reader (`dwarf1`) also recovers each subprogram's return type,
//! parameters, locals and the type graph behind them, and turns the
//! prototypes whose types the decompiler can spell into `DebugPrototype`s.
//! The ECOFF reader recovers procedures only. Line programs are not read.

mod dwarf1;

use super::{ElfSection, NativeFunction};
pub(crate) use dwarf1::{DebugLocal, DebugPrototype};

/// SHT_MIPS_DEBUG: the section type both formats arrive under.
const SHT_MIPS_DEBUG: u32 = 0x7000_0005;

/// ECOFF symbolic-header magics (`magicSym`, `magicSym2` in
/// `include/coff/symconst.h`), read in the image's own endianness.
const ECOFF_MAGIC: [u16; 2] = [0x7009, 0x1992];

/// ECOFF symbol types (`st*`, `include/coff/symconst.h`).
const ECOFF_ST_PROC: u32 = 6;
const ECOFF_ST_END: u32 = 8;
const ECOFF_ST_STATIC_PROC: u32 = 14;
/// ECOFF storage classes (`sc*`).
const ECOFF_SC_TEXT: u32 = 1;
/// `indexNil`: a SYMR whose index field names no aux entry.
const ECOFF_INDEX_NIL: u32 = 0x000f_ffff;

/// On-disk record sizes for 32-bit ECOFF (`*_ext` in `include/coff/mips.h`).
const ECOFF_HDRR_SIZE: usize = 96;
const ECOFF_FDR_SIZE: usize = 72;
const ECOFF_PDR_SIZE: usize = 52;
const ECOFF_SYMR_SIZE: usize = 12;
const ECOFF_EXTR_SIZE: usize = 16;
const ECOFF_AUX_SIZE: usize = 4;

/// What an image's `.debug` stream declares, whatever format it is.
#[derive(Debug, Default)]
pub(crate) struct DebugInfo {
    pub functions: Vec<NativeFunction>,
    /// Prototypes the stream states, by entry, for functions whose every
    /// type has a C spelling. Only the DWARF 1 reader produces these.
    pub prototypes: Vec<DebugPrototype>,
    /// Scalar stack locals the stream places, entry-relative, for functions
    /// whose prologue frame size the code states. DWARF 1 only.
    pub locals: Vec<DebugLocal>,
    /// Struct layouts the stream states (`native-import:debug-info`); the
    /// prototypes above name the structs they point at. DWARF 1 only.
    pub structs: Vec<romwright_model::structs::StructLayout>,
}

/// Functions and prototypes the image's `.debug` stream declares.
///
/// `be` is the ELF's endianness; the ECOFF reader reads its scalar fields
/// in it (the Metrowerks stream is little-endian, as the MIPS targets that
/// use it are). Returns nothing when no debug section exists or the
/// section's content matches neither grammar.
pub(crate) fn collect(data: &[u8], sections: &[ElfSection], be: bool) -> DebugInfo {
    let mut info = DebugInfo::default();
    for section in sections {
        if section.typ != SHT_MIPS_DEBUG || section.size == 0 {
            continue;
        }
        let start = section.off as usize;
        let Some(blob) = data.get(start..start.saturating_add(section.size as usize)) else {
            continue;
        };
        if blob.len() < 6 {
            continue;
        }
        let magic = if be {
            u16::from_be_bytes([blob[0], blob[1]])
        } else {
            u16::from_le_bytes([blob[0], blob[1]])
        };
        if ECOFF_MAGIC.contains(&magic) && blob.len() >= ECOFF_HDRR_SIZE {
            info.functions.extend(ecoff_functions(data, section.off, be));
        } else if u16::from_le_bytes([blob[4], blob[5]]) == dwarf1::TAG_COMPILE_UNIT {
            let stream = dwarf1::Dwarf1::parse(blob);
            let functions = stream.functions();
            let function_names: std::collections::BTreeSet<&str> =
                functions.iter().map(|f| f.name.as_str()).collect();
            let structs = stream.structs(&function_names);
            info.prototypes.extend(stream.prototypes_named(&structs.names));
            info.structs.extend(structs.layouts);
            info.functions.extend(functions.iter().cloned());
            for subprogram in &stream.subprograms {
                let code = code_at(data, sections, subprogram.entry, MIPS_PROLOGUE_BYTES);
                if let Some(frame) = code.and_then(|code| mips_frame_size(code, be)) {
                    info.locals.extend(stream.stack_locals(subprogram, frame));
                }
            }
        }
    }
    info.functions.sort_by_key(|f| f.entry);
    info.functions.dedup_by_key(|f| f.entry);
    info.prototypes.sort_by_key(|p| p.entry);
    info.prototypes.dedup_by_key(|p| p.entry);
    info.locals.sort_by_key(|l| (l.entry, l.offset));
    info.locals.dedup_by_key(|l| (l.entry, l.offset));
    info.structs.sort_by(|a, b| a.name.cmp(&b.name));
    info.structs.dedup_by(|a, b| a.name == b.name);
    info
}

/// How many bytes of a function's start the frame-size decode reads: the
/// prologue's `addiu sp` sits among the first instructions.
const MIPS_PROLOGUE_BYTES: usize = 64;

/// The file bytes of an allocated executable section at a virtual address.
fn code_at<'a>(data: &'a [u8], sections: &[ElfSection], address: u64, len: usize) -> Option<&'a [u8]> {
    let section = sections.iter().find(|s| {
        s.flags & 0x2 != 0 && s.flags & 0x4 != 0 && s.typ != 8 && s.addr <= address && address < s.addr + s.size
    })?;
    let start = section.off.checked_add(address - section.addr)? as usize;
    let end = (start + len).min(section.off as usize + section.size as usize);
    data.get(start..end)
}

/// The bytes a MIPS prologue subtracts from the stack pointer: the first
/// `addiu sp, sp, -N` or `daddiu sp, sp, -N` among the leading instructions
/// (opcodes 0x09/0x19, rs = rt = 29). `None` for a frameless function.
fn mips_frame_size(code: &[u8], be: bool) -> Option<u64> {
    code.as_chunks::<4>().0.iter().find_map(|word| {
        let word = if be {
            u32::from_be_bytes([word[0], word[1], word[2], word[3]])
        } else {
            u32::from_le_bytes([word[0], word[1], word[2], word[3]])
        };
        let immediate = word as u16;
        (matches!(word >> 16, 0x27bd | 0x67bd) && immediate & 0x8000 != 0)
            .then(|| u64::from(0x1_0000 - u32::from(immediate)))
    })
}

/// The stack variables an import holds, with the debug stream's locals laid
/// over them. A debug local replaces every propagated slot it overlaps (the
/// stack analyzer names slots by access, the compiler named this one) and
/// takes the name the source gave it, made unique within the function. Its
/// row says where it came from in `storage` (`...:debug-info`) and carries
/// its C type name so a core type can be applied. Ordinals are renumbered
/// per function in offset order.
pub(crate) fn merge_debug_locals(
    existing: &[romwright_model::StackVariableRow],
    locals: &[DebugLocal],
) -> Vec<romwright_model::StackVariableRow> {
    use romwright_model::{Address, StackVariableRow};
    use std::collections::{BTreeMap, HashSet};
    let mut by_function: BTreeMap<u64, Vec<StackVariableRow>> = BTreeMap::new();
    for row in existing {
        by_function.entry(row.function.offset).or_default().push(row.clone());
    }
    let mut debug: BTreeMap<u64, Vec<&DebugLocal>> = BTreeMap::new();
    for local in locals {
        debug.entry(local.entry).or_default().push(local);
    }
    for (entry, locals) in debug {
        let rows = by_function.entry(entry).or_default();
        let mut used: HashSet<String> = rows.iter().map(|r| r.name.clone()).collect();
        for local in locals {
            let (start, end) = (local.offset, local.offset + local.size as i64);
            rows.retain(|r| match (r.offset, r.size) {
                (Some(o), Some(s)) => o + s as i64 <= start || o >= end,
                _ => true,
            });
            let base = sanitize_identifier(&local.name);
            let mut name = base.clone();
            let mut n = 1;
            while !used.insert(name.clone()) {
                n += 1;
                name = format!("{base}_{n}");
            }
            rows.push(StackVariableRow {
                function: Address::ram(entry),
                ordinal: 0,
                name,
                storage: format!("Stack[-0x{:x}]:{}:debug-info", -local.offset, local.size),
                type_name: Some(
                    local.c_type.clone().unwrap_or_else(|| format!("undefined{}", local.size)),
                ),
                offset: Some(local.offset),
                size: Some(local.size),
            });
        }
    }
    let mut out = Vec::with_capacity(existing.len() + locals.len());
    for (_, mut rows) in by_function {
        rows.sort_by_key(|r| r.offset.unwrap_or(i64::MAX));
        for (ordinal, mut row) in rows.into_iter().enumerate() {
            row.ordinal = ordinal as u32;
            out.push(row);
        }
    }
    out
}

/// A C identifier from a debug name: other characters become `_`, an empty
/// or digit-leading name gains a `local_` prefix.
fn sanitize_identifier(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' })
        .collect();
    if cleaned.is_empty() || cleaned.starts_with(|c: char| c.is_ascii_digit()) {
        format!("local_{cleaned}")
    } else {
        cleaned
    }
}

// ---- ECOFF / mdebug ---------------------------------------------------------

/// One decoded SYMR: name index, value, type, storage class, aux index.
#[derive(Debug, Clone, Copy)]
struct EcoffSym {
    iss: u32,
    value: u32,
    st: u32,
    sc: u32,
    index: u32,
}

/// One decoded FDR: the fields procedure recovery reads.
#[derive(Debug, Clone, Copy)]
struct EcoffFdr {
    /// -1 marks a file linked `-x`: its PDRs index the external table.
    rss: i32,
    iss_base: u32,
    isym_base: u32,
    iaux_base: u32,
    ipd_first: u32,
    cpd: u32,
    cb_line_offset: u32,
    cb_line: u32,
    /// The compile host's endianness for this file's aux entries.
    aux_big_endian: bool,
}

/// One decoded PDR.
#[derive(Debug, Clone, Copy)]
struct EcoffPdr {
    adr: u32,
    isym: i32,
    iline: i32,
    ln_low: i32,
    ln_high: i32,
    cb_line_offset: u32,
}

/// ECOFF HDRR fields, as absolute file offsets and counts.
#[derive(Debug, Clone, Copy)]
struct EcoffHeader {
    cb_line: u32,
    cb_line_offset: u32,
    ipd_max: u32,
    cb_pd_offset: u32,
    isym_max: u32,
    cb_sym_offset: u32,
    iaux_max: u32,
    cb_aux_offset: u32,
    iss_max: u32,
    cb_ss_offset: u32,
    iss_ext_max: u32,
    cb_ss_ext_offset: u32,
    ifd_max: u32,
    cb_fd_offset: u32,
    iext_max: u32,
    cb_ext_offset: u32,
}

struct Reader<'a> {
    data: &'a [u8],
    be: bool,
}

impl Reader<'_> {
    fn u16(&self, off: u64) -> Option<u16> {
        let b = self.data.get(off as usize..off as usize + 2)?;
        Some(if self.be {
            u16::from_be_bytes([b[0], b[1]])
        } else {
            u16::from_le_bytes([b[0], b[1]])
        })
    }
    fn u32(&self, off: u64) -> Option<u32> {
        let b = self.data.get(off as usize..off as usize + 4)?;
        Some(if self.be {
            u32::from_be_bytes([b[0], b[1], b[2], b[3]])
        } else {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        })
    }
    fn i32(&self, off: u64) -> Option<i32> {
        self.u32(off).map(|v| v as i32)
    }
    /// A NUL-terminated string in a string space.
    fn string(&self, base: u64, iss: u32) -> Option<String> {
        let start = base.checked_add(iss as u64)? as usize;
        let rest = self.data.get(start..)?;
        let end = rest.iter().position(|c| *c == 0).unwrap_or(rest.len());
        let name = String::from_utf8_lossy(&rest[..end]).into_owned();
        if name.is_empty() {
            None
        } else {
            Some(name)
        }
    }
}

/// Reads one SYMR: iss, value, then the packed `st:6, sc:5, reserved:1,
/// index:20` word (`ecoff_swap_sym_in` decodes the same bit positions).
fn ecoff_sym(r: &Reader, off: u64) -> Option<EcoffSym> {
    let iss = r.u32(off)?;
    let value = r.u32(off + 4)?;
    let bits = r.u32(off + 8)?;
    Some(EcoffSym {
        iss,
        value,
        st: bits & 0x3f,
        sc: (bits >> 6) & 0x1f,
        index: (bits >> 12) & 0xf_ffff,
    })
}

/// Reads one FDR. The flags word's `fBigendian` bit sits at 0x80 of
/// `f_bits1` little-endian, 0x01 big-endian (`FDR_BITS1_FBIGENDIAN_*`).
fn ecoff_fdr(r: &Reader, off: u64) -> Option<EcoffFdr> {
    let flags = r.u32(off + 60)?;
    let aux_big_endian = if r.be { flags & 1 != 0 } else { flags & 0x80 != 0 };
    Some(EcoffFdr {
        rss: r.i32(off + 4)?,
        iss_base: r.u32(off + 8)?,
        isym_base: r.u32(off + 16)?,
        iaux_base: r.u32(off + 44)?,
        ipd_first: r.u16(off + 40)? as u32,
        cpd: r.u16(off + 42)? as u32,
        cb_line_offset: r.u32(off + 64)?,
        cb_line: r.u32(off + 68)?,
        aux_big_endian,
    })
}

fn ecoff_pdr(r: &Reader, off: u64) -> Option<EcoffPdr> {
    Some(EcoffPdr {
        adr: r.u32(off)?,
        isym: r.i32(off + 4)?,
        iline: r.i32(off + 8)?,
        ln_low: r.i32(off + 40)?,
        ln_high: r.i32(off + 44)?,
        cb_line_offset: r.u32(off + 48)?,
    })
}

/// Reads one EXTR: a flags/ifd word then a SYMR.
fn ecoff_extr(r: &Reader, off: u64) -> Option<(i32, EcoffSym)> {
    let ifd = r.i32(off + 2)?;
    let asym = ecoff_sym(r, off + 4)?;
    Some((ifd, asym))
}

/// A procedure's byte size from its packed line stream: each entry's low
/// nibble counts instructions minus one, so the stream's total is the
/// instruction count (`parse_lines`, gdb `mdebugread.c`). `line_base` is
/// the file offset of the line section's first byte; `start`/`end` are
/// the procedure's byte range within it.
fn ecoff_line_size(data: &[u8], line_base: u64, start: u64, end: u64) -> Option<u64> {
    if end <= start {
        return None;
    }
    let base = line_base.checked_add(start)? as usize;
    let halt = line_base.checked_add(end)? as usize;
    let bytes = data.get(base..halt.min(data.len()))?;
    let mut words = 0u64;
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        i += 1;
        // A delta nibble of -8 escapes to a 16-bit delta.
        if b >> 4 == 8 {
            i += 2;
        }
        words += (b & 0x0f) as u64 + 1;
    }
    if i > bytes.len() {
        return None;
    }
    Some(words * 4)
}

/// Parses an ECOFF/mdebug `.debug` section. `section_off` is the HDRR's
/// file offset; every offset the HDRR carries is itself a file offset
/// (bfd seeks to them directly), which is how `.line` lives in its own
/// section.
fn ecoff_functions(data: &[u8], section_off: u64, be: bool) -> Vec<NativeFunction> {
    let r = Reader { data, be };
    let h = section_off;
    let hdr = EcoffHeader {
        cb_line: r.u32(h + 8).unwrap_or(0),
        cb_line_offset: r.u32(h + 12).unwrap_or(0),
        ipd_max: r.u32(h + 24).unwrap_or(0) as u32,
        cb_pd_offset: r.u32(h + 28).unwrap_or(0),
        isym_max: r.u32(h + 32).unwrap_or(0) as u32,
        cb_sym_offset: r.u32(h + 36).unwrap_or(0),
        iaux_max: r.u32(h + 48).unwrap_or(0) as u32,
        cb_aux_offset: r.u32(h + 52).unwrap_or(0),
        iss_max: r.u32(h + 56).unwrap_or(0) as u32,
        cb_ss_offset: r.u32(h + 60).unwrap_or(0),
        iss_ext_max: r.u32(h + 64).unwrap_or(0) as u32,
        cb_ss_ext_offset: r.u32(h + 68).unwrap_or(0),
        ifd_max: r.u32(h + 72).unwrap_or(0) as u32,
        cb_fd_offset: r.u32(h + 76).unwrap_or(0),
        iext_max: r.u32(h + 88).unwrap_or(0) as u32,
        cb_ext_offset: r.u32(h + 92).unwrap_or(0),
    };
    // Bounds-check every table before trusting a count.
    let sane = |off: u32, count: u32, size: usize| -> bool {
        (off as u64)
            .checked_add(count as u64 * size as u64)
            .map(|end| end <= data.len() as u64)
            .unwrap_or(false)
    };
    if !sane(hdr.cb_pd_offset, hdr.ipd_max, ECOFF_PDR_SIZE)
        || !sane(hdr.cb_sym_offset, hdr.isym_max, ECOFF_SYMR_SIZE)
        || !sane(hdr.cb_aux_offset, hdr.iaux_max, ECOFF_AUX_SIZE)
        || !sane(hdr.cb_ss_offset, hdr.iss_max, 1)
        || !sane(hdr.cb_ss_ext_offset, hdr.iss_ext_max, 1)
        || !sane(hdr.cb_fd_offset, hdr.ifd_max, ECOFF_FDR_SIZE)
        || !sane(hdr.cb_ext_offset, hdr.iext_max, ECOFF_EXTR_SIZE)
        || !sane(hdr.cb_line_offset, hdr.cb_line, 1)
    {
        return Vec::new();
    }

    let mut functions: std::collections::BTreeMap<u64, NativeFunction> =
        std::collections::BTreeMap::new();

    // Procedures: one PDR per text label, grouped by file. The PDR's
    // `isym` is file-relative into the local symbol table when the file
    // kept symbols, or an index into the external table when it was
    // linked -x (`parse_procedure`, gdb `mdebugread.c`).
    for ifd in 0..hdr.ifd_max {
        let Some(fdr) = ecoff_fdr(&r, hdr.cb_fd_offset as u64 + ifd as u64 * ECOFF_FDR_SIZE as u64)
        else {
            continue;
        };
        for j in 0..fdr.cpd {
            let pdr_off = hdr.cb_pd_offset as u64
                + (fdr.ipd_first as u64 + j as u64) * ECOFF_PDR_SIZE as u64;
            let Some(pdr) = ecoff_pdr(&r, pdr_off) else {
                continue;
            };
            if pdr.isym < 0 {
                continue;
            }
            let (name, sym_index, sym_adr) = if fdr.rss == -1 {
                // Stripped file: `isym` indexes the external table, whose
                // names live in the external string space.
                let Some((_, ext)) =
                    ecoff_extr(&r, hdr.cb_ext_offset as u64 + pdr.isym as u64 * ECOFF_EXTR_SIZE as u64)
                else {
                    continue;
                };
                let Some(name) = r.string(hdr.cb_ss_ext_offset as u64, ext.iss) else {
                    continue;
                };
                (name, None, ext.value)
            } else {
                let sym_off = hdr.cb_sym_offset as u64
                    + (fdr.isym_base as u64 + pdr.isym as u64) * ECOFF_SYMR_SIZE as u64;
                let Some(sym) = ecoff_sym(&r, sym_off) else {
                    continue;
                };
                // Only procedure symbols name a function body; a PDR can
                // also point at a plain label.
                if sym.st != ECOFF_ST_PROC && sym.st != ECOFF_ST_STATIC_PROC {
                    continue;
                }
                let Some(name) = r.string(
                    hdr.cb_ss_offset as u64 + fdr.iss_base as u64,
                    sym.iss,
                ) else {
                    continue;
                };
                (name, Some(sym), sym.value)
            };
            let entry = if pdr.adr != 0 { pdr.adr } else { sym_adr } as u64;
            if entry == 0 {
                continue;
            }
            // Size: the procedure's stEnd symbol carries the byte length
            // as its value, found through the proc's aux entry
            // (`fh->isymBase + isym - 1`, mdebugread.c). Failing that, the
            // packed line stream counts the procedure's instructions.
            let mut size = sym_index
                .and_then(|sym| {
                    if sym.index == ECOFF_INDEX_NIL
                        || fdr.iaux_base as u64 + sym.index as u64 >= hdr.iaux_max as u64
                    {
                        return None;
                    }
                    let aux_off = hdr.cb_aux_offset as u64
                        + (fdr.iaux_base as u64 + sym.index as u64) * ECOFF_AUX_SIZE as u64;
                    let aux = Reader { data, be: fdr.aux_big_endian }.u32(aux_off)?;
                    let end_off = hdr.cb_sym_offset as u64
                        + (fdr.isym_base as u64 + aux as u64).saturating_sub(1)
                            * ECOFF_SYMR_SIZE as u64;
                    let end = ecoff_sym(&r, end_off)?;
                    (end.st == ECOFF_ST_END).then_some(end.value as u64)
                })
                .unwrap_or(0);
            if size == 0 {
                let next = if j + 1 < fdr.cpd {
                    ecoff_pdr(&r, pdr_off + ECOFF_PDR_SIZE as u64).map(|n| n.cb_line_offset)
                } else {
                    Some(fdr.cb_line)
                };
                if pdr.iline >= 0 && pdr.ln_low != -1 && pdr.ln_high != -1 {
                    if let Some(next) = next {
                        size = ecoff_line_size(
                            data,
                            hdr.cb_line_offset as u64 + fdr.cb_line_offset as u64,
                            pdr.cb_line_offset as u64,
                            next as u64,
                        )
                        .unwrap_or(0);
                    }
                }
            }
            functions
                .entry(entry)
                .or_insert(NativeFunction { entry, name, size });
        }
    }

    // External text procedures the PDR table does not reach: an stProc /
    // stStaticProc / stGlobal with scText names code (`mdebugread.c`
    // records them as minimal symbols).
    for i in 0..hdr.iext_max {
        let Some((_, ext)) =
            ecoff_extr(&r, hdr.cb_ext_offset as u64 + i as u64 * ECOFF_EXTR_SIZE as u64)
        else {
            continue;
        };
        if ext.sc != ECOFF_SC_TEXT
            || !matches!(ext.st, ECOFF_ST_PROC | ECOFF_ST_STATIC_PROC | 1)
            || ext.value == 0
        {
            continue;
        }
        let Some(name) = r.string(hdr.cb_ss_ext_offset as u64, ext.iss) else {
            continue;
        };
        functions
            .entry(ext.value as u64)
            .or_insert(NativeFunction { entry: ext.value as u64, name, size: 0 });
    }

    functions.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn section(name: &str, off: u64, size: u64) -> ElfSection {
        ElfSection {
            name: name.into(),
            typ: SHT_MIPS_DEBUG,
            flags: 0,
            addr: 0,
            off,
            size,
            link: 0,
            entry_size: 0,
        }
    }

    /// A synthetic ECOFF .debug blob: one file, three PDRs. `func_a`
    /// sizes through its stEnd aux indirection; `func_b` has no aux and
    /// sizes from its packed line stream; the third PDR points at a
    /// label and must not produce a function.
    fn ecoff_blob() -> Vec<u8> {
        let mut b = vec![0u8; 0x400];
        let put32 = |b: &mut [u8], o: usize, v: u32| b[o..o + 4].copy_from_slice(&v.to_le_bytes());
        let put16 = |b: &mut [u8], o: usize, v: u16| b[o..o + 2].copy_from_slice(&v.to_le_bytes());
        // HDRR at 0.
        put16(&mut b, 0, 0x7009);
        put32(&mut b, 8, 4); // cbLine
        put32(&mut b, 12, 0x300); // cbLineOffset
        put32(&mut b, 24, 3); // ipdMax
        put32(&mut b, 28, 0x100); // cbPdOffset
        put32(&mut b, 32, 4); // isymMax
        put32(&mut b, 36, 0x1a0); // cbSymOffset
        put32(&mut b, 48, 1); // iauxMax
        put32(&mut b, 52, 0x1e0); // cbAuxOffset
        put32(&mut b, 56, 32); // issMax
        put32(&mut b, 60, 0x200); // cbSsOffset
        put32(&mut b, 64, 16); // issExtMax
        put32(&mut b, 68, 0x240); // cbSsExtOffset
        put32(&mut b, 72, 1); // ifdMax
        put32(&mut b, 76, 0x280); // cbFdOffset
        put32(&mut b, 88, 1); // iextMax
        put32(&mut b, 92, 0x2e0); // cbExtOffset
        // PDRs at 0x100: func_a, func_b, then one pointing at a label.
        put32(&mut b, 0x100, 0x1000); // adr
        put32(&mut b, 0x104, 0); // isym -> sym[0]
        put32(&mut b, 0x108, 0); // iline
        put32(&mut b, 0x128, 1); // lnLow
        put32(&mut b, 0x12c, 10); // lnHigh
        put32(&mut b, 0x130, 0); // cbLineOffset
        put32(&mut b, 0x134, 0x1080); // func_b adr
        put32(&mut b, 0x138, 2); // isym -> sym[2]
        put32(&mut b, 0x13c, 0); // iline
        put32(&mut b, 0x15c, 1); // lnLow
        put32(&mut b, 0x160, 5); // lnHigh
        put32(&mut b, 0x164, 0); // cbLineOffset: stream [0, next)
        put32(&mut b, 0x168, 0x10c0); // label adr
        put32(&mut b, 0x16c, 3); // isym -> sym[3] (stLabel)
        put32(&mut b, 0x170, 0); // iline
        put32(&mut b, 0x190, 1); // lnLow
        put32(&mut b, 0x194, 5); // lnHigh
        put32(&mut b, 0x198, 4); // cbLineOffset: end of func_b's stream
        // SYMRs at 0x1a0: stProc func_a (index -> aux 0), stEnd (size
        // 0x80), stProc func_b (indexNil), a stray stLabel.
        let sym = |b: &mut [u8], o: usize, iss: u32, value: u32, st: u32, sc: u32, index: u32| {
            put32(b, o, iss);
            put32(b, o + 4, value);
            put32(b, o + 8, st | (sc << 6) | (index << 12));
        };
        sym(&mut b, 0x1a0, 0, 0x1000, ECOFF_ST_PROC, ECOFF_SC_TEXT, 0);
        sym(&mut b, 0x1ac, 0, 0x80, ECOFF_ST_END, ECOFF_SC_TEXT, ECOFF_INDEX_NIL);
        sym(&mut b, 0x1b8, 7, 0x1080, ECOFF_ST_PROC, ECOFF_SC_TEXT, ECOFF_INDEX_NIL);
        sym(&mut b, 0x1c4, 15, 0x10c0, 5, ECOFF_SC_TEXT, ECOFF_INDEX_NIL);
        // AUX at 0x1e0: isym 2 -> sym[1] (the stEnd).
        put32(&mut b, 0x1e0, 2);
        // Local strings at 0x200: "func_a\0func_b\0label_x\0".
        b[0x200..0x207].copy_from_slice(b"func_a\0");
        b[0x207..0x20e].copy_from_slice(b"func_b\0");
        b[0x20f..0x217].copy_from_slice(b"label_x\0");
        // External strings at 0x240: "ext_proc\0".
        b[0x240..0x249].copy_from_slice(b"ext_proc\0");
        // FDR at 0x280 (72 bytes -> ends 0x2c8).
        put32(&mut b, 0x280, 0x1000); // adr
        put32(&mut b, 0x284, 0); // rss (named file)
        put32(&mut b, 0x288, 0); // issBase
        put32(&mut b, 0x290, 0); // isymBase
        put16(&mut b, 0x2a8, 0); // ipdFirst
        put16(&mut b, 0x2aa, 3); // cpd
        put32(&mut b, 0x2ac, 0); // iauxBase
        put32(&mut b, 0x2c0, 0); // cbLineOffset
        put32(&mut b, 0x2c4, 4); // cbLine
        // EXTR at 0x2e0: ifd 0, stProc scText ext_proc at 0x2000.
        put16(&mut b, 0x2e2, 0); // ifd
        sym(&mut b, 0x2e4, 0, 0x2000, ECOFF_ST_PROC, ECOFF_SC_TEXT, ECOFF_INDEX_NIL);
        // Line stream at 0x300: four entries of (delta<<4)|count, each
        // counting 1 instruction -> func_b is 4 words = 0x10 bytes.
        b[0x300..0x304].copy_from_slice(&[0x00, 0x10, 0x10, 0x10]);
        b
    }

    #[test]
    fn mdebug_ecoff_recovers_procedures() {
        let blob = ecoff_blob();
        let sections = vec![section(".debug", 0, blob.len() as u64)];
        let functions = collect(&blob, &sections, false).functions;
        let by_name: std::collections::HashMap<&str, &NativeFunction> =
            functions.iter().map(|f| (f.name.as_str(), f)).collect();
        assert_eq!(by_name["func_a"].entry, 0x1000);
        assert_eq!(by_name["func_a"].size, 0x80, "stEnd aux indirection");
        assert_eq!(by_name["func_b"].entry, 0x1080);
        assert_eq!(by_name["func_b"].size, 0x10, "line-stream instruction count");
        assert_eq!(by_name["ext_proc"].entry, 0x2000);
        // A PDR pointing at a label is not a function.
        assert!(!by_name.contains_key("label_x"));
    }

    /// A synthetic Metrowerks DWARF 1 stream: a compile unit, one named
    /// subroutine, one unnamed, a null entry, then a second unit.
    fn dwarf1_blob() -> Vec<u8> {
        let mut b = Vec::new();
        let entry = |b: &mut Vec<u8>, tag: u16, attrs: &[(u16, Vec<u8>)]| {
            let mut body = tag.to_le_bytes().to_vec();
            for (code, value) in attrs {
                body.extend_from_slice(&code.to_le_bytes());
                body.extend_from_slice(value);
            }
            let length = (body.len() + 4) as u32;
            b.extend_from_slice(&length.to_le_bytes());
            b.extend_from_slice(&body);
        };
        let s = |code: u16, text: &str| -> (u16, Vec<u8>) {
            let mut v = text.as_bytes().to_vec();
            v.push(0);
            (code, v)
        };
        let a4 = |code: u16, v: u32| (code, v.to_le_bytes().to_vec());
        // Compile unit: sibling, language, producer, name.
        let cu = s(0x0258, "MW MIPS C Compiler");
        let cn = s(0x0038, "E:\\jam\\x.c");
        entry(&mut b, dwarf1::TAG_COMPILE_UNIT, &[
            a4(0x0012, 0),
            a4(0x0136, 1),
            cu,
            cn,
        ]);
        // Named subroutine: sibling, low_pc, high_pc, name.
        let n1 = s(0x0038, "pl2d_jump_rate");
        entry(&mut b, dwarf1::TAG_GLOBAL_SUBROUTINE, &[
            a4(0x0012, 0),
            a4(0x0111, 0x1299a0),
            a4(0x0121, 0x1299dc),
            n1,
        ]);
        // Unnamed subroutine: low_pc only.
        entry(&mut b, dwarf1::TAG_SUBROUTINE, &[a4(0x0111, 0x140000)]);
        // Null entry, then a second unit so the walk continues past it.
        b.extend_from_slice(&4u32.to_le_bytes());
        entry(&mut b, dwarf1::TAG_COMPILE_UNIT, &[a4(0x0136, 1)]);
        b
    }

    #[test]
    fn mdebug_dwarf1_recovers_subroutines() {
        let blob = dwarf1_blob();
        let sections = vec![section(".debug", 0, blob.len() as u64)];
        let functions = collect(&blob, &sections, false).functions;
        assert_eq!(functions.len(), 2);
        assert_eq!(functions[0].entry, 0x1299a0);
        assert_eq!(functions[0].name, "pl2d_jump_rate");
        assert_eq!(functions[0].size, 0x3c);
        assert_eq!(functions[1].entry, 0x140000);
        assert_eq!(functions[1].name, "FUN_00140000");
        assert_eq!(functions[1].size, 0);
    }

    #[test]
    fn a_mips_prologue_states_the_frame_size() {
        let words: [u32; 4] = [0x3c1c0000, 0x279c0000, 0x27bdffd0, 0xafbf002c];
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        assert_eq!(mips_frame_size(&bytes, false), Some(0x30));
        let big: Vec<u8> = words.iter().flat_map(|w| w.to_be_bytes()).collect();
        assert_eq!(mips_frame_size(&big, true), Some(0x30));
        // daddiu sp, sp, -0x100
        assert_eq!(mips_frame_size(&0x67bdff00u32.to_le_bytes(), false), Some(0x100));
        // A leaf: no stack adjustment, and a positive immediate is no frame.
        assert_eq!(mips_frame_size(&0x03e00008u32.to_le_bytes(), false), None);
        assert_eq!(mips_frame_size(&0x27bd0030u32.to_le_bytes(), false), None);
    }

    #[test]
    fn debug_locals_replace_the_slots_they_overlap_and_keep_the_rest() {
        use romwright_model::{Address, StackVariableRow};
        let row = |function: u64, ordinal: u32, offset: i64, size: u64| StackVariableRow {
            function: Address::ram(function),
            ordinal,
            name: format!("local_{:x}", -offset),
            storage: format!("Stack[-0x{:x}]:{size}", -offset),
            type_name: Some(format!("undefined{size}")),
            offset: Some(offset),
            size: Some(size),
        };
        let existing = vec![row(0x2000, 0, -0x30, 8), row(0x2000, 1, -0x10, 4), row(0x3000, 0, -8, 4)];
        let local = |name: &str, offset: i64, size: u64| DebugLocal {
            entry: 0x2000,
            name: name.into(),
            c_type: Some("int".into()),
            size,
            offset,
        };
        // `count` overlaps the 8-byte slot at -0x30; `local_10` is a name the
        // debug stream also uses, so the second one is made unique.
        let merged = merge_debug_locals(
            &existing,
            &[local("count", -0x2c, 4), local("local_10", -0x20, 4), local("9bad name", -0x18, 4)],
        );
        let of = |entry: u64| -> Vec<(u32, String, i64, String)> {
            merged
                .iter()
                .filter(|r| r.function.offset == entry)
                .map(|r| (r.ordinal, r.name.clone(), r.offset.unwrap(), r.storage.clone()))
                .collect()
        };
        assert_eq!(
            of(0x2000),
            [
                (0, "count".to_string(), -0x2c, "Stack[-0x2c]:4:debug-info".to_string()),
                (1, "local_10_2".to_string(), -0x20, "Stack[-0x20]:4:debug-info".to_string()),
                (2, "local_9bad_name".to_string(), -0x18, "Stack[-0x18]:4:debug-info".to_string()),
                (3, "local_10".to_string(), -0x10, "Stack[-0x10]:4".to_string()),
            ]
        );
        // Another function is untouched.
        assert_eq!(of(0x3000).len(), 1);
        assert_eq!(merged.iter().find(|r| r.name == "count").unwrap().type_name.as_deref(), Some("int"));
    }

    #[test]
    fn mdebug_ignores_other_sections() {
        let blob = dwarf1_blob();
        // A PROGBITS .debug (DWARF2+ style) is not this reader's grammar.
        let mut s = section(".debug", 0, blob.len() as u64);
        s.typ = 1;
        assert!(collect(&blob, &[s], false).functions.is_empty());
        // A MIPS_DEBUG section that is neither grammar yields nothing.
        let junk = vec![0xabu8; 64];
        let s = section(".line", 0, 64);
        assert!(collect(&junk, &[s], false).functions.is_empty());
    }
}
