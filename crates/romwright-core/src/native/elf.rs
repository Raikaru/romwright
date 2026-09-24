use super::*;

/// ELF32 section parse (40-byte Shdr), either endianness.
pub(super) fn parse_elf32_sections(data: &[u8], be: bool) -> Result<(Vec<ElfSection>, Vec<u8>)> {
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
    // No section table: SCE ELFs (Vita `e_type` 0xfe00) ship program
    // headers only. Returning empty hands the mapping work to the PT_LOAD
    // path in `import_elf32`, which is what Ghidra does when
    // `elf.getSectionHeaderCount() == 0` (`ElfProgramBuilder.
    // processProgramHeaders`, :3192-3225).
    if shoff == 0 || shnum == 0 {
        return Ok((Vec::new(), Vec::new()));
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
pub(super) fn import_elf32(data: &[u8], be: bool) -> Result<NativeImport> {
    let mut notes: Vec<romwright_model::ImportDiagnostic> = Vec::new();
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
        e_type: rd16(16)?,
    };
    let entry = rd32(24)? as u64;
    let process_entry = elf_process_entry(data, entry, rd16(16)?);
    let (mut sections, _shstr) = parse_elf32_sections(data, be)?;

    let mut mappings = Vec::new();
    if sections.is_empty() {
        // Sectionless image (SCE ELF): the PT_LOAD program headers are the
        // memory map. `complete_load_segments` covers each segment to
        // p_memsz, file bytes to p_filesz and the bss tail empty — the same
        // shape the section path produces for SHT_NOBITS.
        elf_image::complete_load_segments(data, &mut mappings, 4, be, 0)?;
    }
    for s in sections.iter() {
        if s.flags & 0x2 == 0 || s.size == 0 {
            continue;
        }
        let b = if s.typ == 8 {
            &[]
        } else {
            file_bytes(data, s.off, s.size, || format!("section {}", s.name), &mut notes)
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
    let mut object_names: Vec<(u64, String)> = Vec::new();
    let mut abs_symbols: Vec<(String, u64)> = Vec::new();
    let mut contexts: Vec<NativeContext> = Vec::new();
    // SHT_SYMTAB (2) and SHT_DYNSYM (11): 16-byte Elf32_Sym.
    for s in sections.iter().filter(|s| s.typ == 2 || s.typ == 11) {
        let strtab = sections
            .get(s.link as usize)
            .map(|t| {
                file_bytes(data, t.off, t.size, || format!("string table {}", t.name), &mut notes)
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
                    contexts.push(NativeContext {
                        name: "TMode".into(),
                        address: value,
                        value: 1,
                    });
                } else if name == "$a" || name.starts_with("$a.") {
                    contexts.push(NativeContext {
                        name: "TMode".into(),
                        address: value,
                        value: 0,
                    });
                }
            }
            let (value, thumb) = if arm && typ == 2 && value & 1 != 0 {
                (value & !1, true)
            } else {
                (value, false)
            };
            if typ == 2 && shndx != 0 && !name.is_empty() {
                if thumb {
                    contexts.push(NativeContext {
                        name: "TMode".into(),
                        address: value,
                        value: 1,
                    });
                }
                let rank = symbol_rank(info, &name);
                let slot =
                    symbol_functions
                        .entry(value)
                        .or_insert((rank, name.clone(), size.max(1)));
                if rank < slot.0 {
                    *slot = (rank, name.clone(), size.max(1));
                }
            }
            // STT_OBJECT with a size and an address: Ghidra defines undefined
            // data of exactly that size there
            // (`ElfProgramBuilder.processSymbols`, :1703-1706, and
            // `allocateUndefinedSymbolData`, :1358-1381).
            if typ == 1 && shndx != 0 && size > 0 {
                object_sizes.push((value, size));
                if !name.is_empty() {
                    object_names.push((value, name.clone()));
                }
            }
            // Absolute symbols carry loader-established values (`_SDA_BASE_`
            // on PowerPC); nothing else in the loops wants them.
            if shndx == 0xfff1 && !name.is_empty() {
                abs_symbols.push((name.clone(), value));
            }
            if shndx == 0 && !name.is_empty() {
                externals.push((0, name.clone()));
            }
        }
    }
    // A MIPS .debug stream (ECOFF mdebug or Metrowerks DWARF 1) names
    // procedures the symtab may have stripped. The symtab's spelling
    // wins where both exist; debug info only adds coverage.
    let mdebug_started = std::time::Instant::now();
    let mdebug_functions = mdebug::collect(data, &sections, be);
    for f in &mdebug_functions {
        symbol_functions
            .entry(f.entry)
            .or_insert((u8::MAX, f.name.clone(), f.size.max(1)));
    }
    let symbol_named: Vec<u64> = symbol_functions.keys().copied().collect();
    let symbol_extents = declared_extents(&symbol_functions);
    functions.extend(
        symbol_functions
            .into_iter()
            .map(|(entry, (_, name, size))| NativeFunction { entry, name, size }),
    );
    collect_elf_section_starts(&sections, &mut functions);
    functions.sort_by_key(|f| f.entry);
    let mut register_contexts = Vec::new();
    seed_ppc_sda_registers(
        elf_machine.machine,
        &abs_symbols,
        &sections,
        &functions,
        &mut register_contexts,
    );
    let mut import = NativeImport {
        diagnostics: notes,
        process_entry,
        symbol_named,
        symbol_extents,
        format: "elf32".into(),
        elf_machine: Some(elf_machine),
        mappings,
        functions,
        xrefs: Vec::new(),
        externals,
        object_sizes,
        object_names,
        contexts,
        register_contexts,
        ..Default::default()
    };
    import.toolchain = detect_toolchain(data, &sections);
    if !mdebug_functions.is_empty() {
        phase(&mut import, "mdebug", mdebug_started);
    }
    elf_image::prepare(data, &mut sections, &mut import, 4, be)?;
    let bias = elf_bases(data).map(|(_, bias)| bias).unwrap_or(0);
    elf_pointers::collect(data, &sections, &mut import, 4, be, bias)?;
    elf_pointers::collect_got(data, &sections, &mut import, 4, be, bias)?;
    elf_unwind::collect(data, &sections, &mut import, 4, be);
    elf_exception::collect(data, &sections, &mut import, 4, be);
    sce::collect(data, be, rd16(16)?, entry, &mut import)?;
    Ok(import)
}

// ---- ELF64 ----------------------------------------------------------------

pub(crate) struct ElfSection {
    pub(super) name: String,
    pub(super) typ: u32,
    pub(super) flags: u64,
    pub(super) addr: u64,
    pub(super) off: u64,
    pub(super) size: u64,
    pub(super) link: u32,
    pub(super) entry_size: u64,
}

fn collect_elf_section_starts(sections: &[ElfSection], functions: &mut Vec<NativeFunction>) {
    for s in sections {
        if s.flags & 4 == 0
            || s.size == 0
            || s.addr == 0
            || functions.iter().any(|f| f.entry == s.addr)
        {
            continue;
        }
        let (name, size) = match s.name.as_str() {
            ".init" => ("_init", s.size),
            ".fini" => ("_fini", s.size),
            ".plt" => ("_plt", 1),
            _ => continue,
        };
        functions.push(NativeFunction {
            entry: s.addr,
            name: name.into(),
            size,
        });
    }
}

fn parse_elf_sections(data: &[u8], be: bool) -> Result<(Vec<ElfSection>, Vec<u8>)> {
    let rd16 = |o: usize| -> Result<u16> {
        if be {
            u16_be_at(data, o)
        } else {
            u16_at(data, o)
        }
    };
    let rd32 = |o: usize| -> Result<u32> {
        if be {
            u32_be_at(data, o)
        } else {
            u32_at(data, o)
        }
    };
    let rd64 = |o: usize| -> Result<u64> {
        if be {
            u64_be_at(data, o)
        } else {
            u64_at(data, o)
        }
    };
    let shentsize = rd16(58)? as usize;
    let shnum = rd16(60)? as usize;
    let shoff = rd64(40)? as usize;
    let shstrndx = rd16(62)? as usize;
    let mut sections = Vec::new();
    for i in 0..shnum {
        let hdr = shoff + i * shentsize;
        sections.push(ElfSection {
            name: String::new(),
            typ: rd32(hdr + 4)?,
            flags: rd64(hdr + 8)?,
            addr: rd64(hdr + 16)?,
            off: rd64(hdr + 24)?,
            size: rd64(hdr + 32)?,
            link: rd32(hdr + 40)?,
            entry_size: rd64(hdr + 56)?,
        });
    }
    // fetch shstrtab content
    let shstr = {
        let hdr = shoff + shstrndx * shentsize;
        let off = rd64(hdr + 24)? as usize;
        let sz = rd64(hdr + 32)? as usize;
        data.get(off..off + sz).unwrap_or(&[]).to_vec()
    };
    // names assigned from shstrtab after fetching; store raw offsets
    let mut name_offs = Vec::new();
    for i in 0..shnum {
        let hdr = shoff + i * shentsize;
        name_offs.push(rd32(hdr)? as usize);
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

/// Detect the producing toolchain from the image's own markers.
/// ELF: the `.comment` section's `GCC: (GNU) x.y.z` / `clang version`
/// strings. PE: the linker major.minor in the optional header (MSVC
/// linkers stamp it; 14.x = MSVC 2015+). DOL: the mwcc runtime symbols
/// (`__init_registers`, `__start`, `__ppc_eabi_init`) every CodeWarrior
/// GC/Wii binary carries.
/// Sorted `[start, end)` extents of the sized symbol-table functions.
fn declared_extents(symbols: &std::collections::HashMap<u64, (u8, String, u64)>) -> Vec<(u64, u64)> {
    let mut extents: Vec<(u64, u64)> = symbols
        .iter()
        .filter(|(_, (_, _, size))| *size > 1)
        .map(|(&entry, (_, _, size))| (entry, entry.saturating_add(*size)))
        .collect();
    extents.sort_unstable();
    extents
}

fn detect_toolchain(data: &[u8], sections: &[ElfSection]) -> Option<String> {
    // ELF .comment.
    for section in sections {
        if section.name == ".comment" && section.size > 0 {
            let off = section.off as usize;
            let end = (off + section.size as usize).min(data.len());
            let text = String::from_utf8_lossy(&data[off..end]);
            for chunk in text.split('\0') {
                let chunk = chunk.trim();
                if let Some(version) = chunk.strip_prefix("GCC: (GNU) ") {
                    return Some(format!("gcc {}", version.trim()));
                }
                if let Some(version) = chunk.strip_prefix("GCC: ") {
                    return Some(format!("gcc {}", version.trim()));
                }
                if let Some(version) = chunk.strip_prefix("clang version ") {
                    return Some(format!("clang {}", version.trim()));
                }
            }
        }
    }
    // DOL detection lives in store_import: the mwcc runtime symbols it
    // keys on arrive via --map, which applies after dol::import returns.
    None
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
    let mut notes: Vec<romwright_model::ImportDiagnostic> = Vec::new();
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
    if data[4] != 2 || !matches!(data[5], 1 | 2) {
        return err("ELF64 expected");
    }
    let be = data[5] == 2;
    let rd16 = |o: usize| -> Result<u16> {
        if be {
            u16_be_at(data, o)
        } else {
            u16_at(data, o)
        }
    };
    let rd32 = |o: usize| -> Result<u32> {
        if be {
            u32_be_at(data, o)
        } else {
            u32_at(data, o)
        }
    };
    let rd64 = |o: usize| -> Result<u64> {
        if be {
            u64_be_at(data, o)
        } else {
            u64_at(data, o)
        }
    };
    let elf_machine = crate::opinion::ElfMachine {
        machine: rd16(18)?,
        flags: rd32(48)?,
        bits: 64,
        big_endian: be,
        e_type: rd16(16)?,
    };
    let entry = rd64(24)?;
    let process_entry = elf_process_entry(data, entry, rd16(16)?);
    let (mut sections, _shstr) = parse_elf_sections(data, be)?;

    // Mappings: SHF_ALLOC sections carrying file bytes (SHT_PROGBITS etc).
    let mut mappings = Vec::new();
    for s in sections.iter() {
        if s.flags & 0x2 == 0 || s.size == 0 {
            continue;
        }
        let b = if s.typ == 8 {
            &[]
        } else {
            file_bytes(data, s.off, s.size, || format!("section {}", s.name), &mut notes)
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

    // PPC64 function descriptors: a function symbol's `st_value` names a
    // `.opd` entry `{func_ptr, toc_ptr}`, not the code. Ghidra's
    // `PowerPC64_ElfExtension.processOPDSection`/`markupDescriptorEntry`
    // (:449-647) reads each descriptor, creates the function at `func_ptr`,
    // and sets `r2 = toc_ptr` over the function's range. We mirror that:
    // `opd` maps a descriptor vaddr to `(func_ptr, toc_ptr)` so the symtab
    // loop below can remap `value` to the real entry and seed the TOC.
    // `.opd` is a non-executable data section; a stripped image has no name,
    // so fall back to the section `e_entry` lands in (Ghidra :458-475).
    let opd: std::collections::HashMap<u64, (u64, u64)> = if elf_machine.machine == 21 {
        let opd_section = sections.iter().find(|s| s.name == ".opd").or_else(|| {
            sections.iter().find(|s| {
                s.flags & 0x2 != 0
                    && s.flags & 0x4 == 0
                    && entry >= s.addr
                    && entry < s.addr + s.size
            })
        });
        let mut map = std::collections::HashMap::new();
        if let Some(s) = opd_section {
            let base = s.off as usize;
            let count = (s.size as usize) / 16;
            for i in 0..count {
                let o = base + i * 16;
                if o + 16 > data.len() {
                    break;
                }
                let func = rd64(o)?;
                let toc = rd64(o + 8)?;
                if func != 0 {
                    map.insert(s.addr + (i * 16) as u64, (func, toc));
                }
            }
        }
        map
    } else {
        std::collections::HashMap::new()
    };
    // TOC values to seed as `r2` register contexts, keyed by function entry.
    let mut opd_toc: Vec<(u64, u64)> = Vec::new();

    // Symbols: the SHT_SYMTAB (type 2) and its sh_link strtab.
    let mut functions = Vec::new();
    let mut symbol_functions: std::collections::HashMap<u64, (u8, String, u64)> =
        std::collections::HashMap::new();
    let mut externals = Vec::new();
    let mut object_sizes: Vec<(u64, u64)> = Vec::new();
    let mut object_names: Vec<(u64, String)> = Vec::new();
    let mut abs_symbols: Vec<(String, u64)> = Vec::new();
    for s in sections.iter() {
        if s.typ != 2 {
            continue;
        }
        let strtab = sections
            .get(s.link as usize)
            .map(|t| {
                file_bytes(data, t.off, t.size, || format!("string table {}", t.name), &mut notes)
                    .to_vec()
            })
            .unwrap_or_default();
        let count = s.size as usize / 24;
        for i in 0..count {
            let hdr = s.off as usize + i * 24;
            if hdr + 24 > data.len() {
                break;
            }
            let name_off = rd32(hdr)? as usize;
            let info = data[hdr + 4];
            // ELF64_Sym: st_name(0,4) st_info(4) st_other(5) st_shndx(6,2)
            // st_value(8,8) st_size(16,8)
            let value = rd64(hdr + 8)?;
            let shndx = rd16(hdr + 6)?;
            let size = rd64(hdr + 16)?;
            let name = strtab
                .get(name_off..)
                .and_then(|r| r.split(|c| *c == 0).next())
                .map(|r| String::from_utf8_lossy(r).into_owned())
                .unwrap_or_default();
            let typ = info & 0xf;
            // PPC64: `value` may be a `.opd` descriptor; the real entry is
            // `func_ptr` and `toc_ptr` becomes the function's `r2` context.
            let (entry_addr, toc) = opd
                .get(&value)
                .map(|&(func, toc)| (func, Some(toc)))
                .unwrap_or((value, None));
            if let Some(toc) = toc {
                opd_toc.push((entry_addr, toc));
            }
            if typ == 2 && shndx != 0 && !name.is_empty() {
                let rank = symbol_rank(info, &name);
                let slot =
                    symbol_functions
                        .entry(entry_addr)
                        .or_insert((rank, name.clone(), size.max(1)));
                if rank < slot.0 {
                    *slot = (rank, name.clone(), size.max(1));
                }
            }
            if typ == 1 && shndx != 0 && size > 0 {
                object_sizes.push((value, size));
                if !name.is_empty() {
                    object_names.push((value, name.clone()));
                }
            }
            if shndx == 0xfff1 && !name.is_empty() {
                abs_symbols.push((name.clone(), value));
            }
            if shndx == 0 && !name.is_empty() {
                externals.push((0, name));
            }
        }
    }
    // Dynamic symbols: undefined entries name externals (elf_image collects
    // their loaded relocation slots); defined functions fill addresses the
    // symtab never named.
    let symtab_named: std::collections::HashSet<u64> = symbol_functions.keys().copied().collect();
    for s in sections.iter().filter(|s| s.typ == 11) {
        let strtab = sections
            .get(s.link as usize)
            .map(|t| {
                file_bytes(data, t.off, t.size, || format!("string table {}", t.name), &mut notes)
                    .to_vec()
            })
            .unwrap_or_default();
        let count = s.size as usize / 24;
        for i in 0..count {
            let hdr = s.off as usize + i * 24;
            if hdr + 24 > data.len() {
                break;
            }
            let name_off = rd32(hdr)? as usize;
            let info = data[hdr + 4];
            let shndx = rd16(hdr + 6)?;
            let value = rd64(hdr + 8)?;
            let size = rd64(hdr + 16)?;
            let name = strtab
                .get(name_off..)
                .and_then(|r| r.split(|c| *c == 0).next())
                .map(|r| String::from_utf8_lossy(r).into_owned())
                .unwrap_or_default();
            // PPC64: a defined dynamic function's `value` may be a `.opd`
            // descriptor; remap to `func_ptr` and seed `r2 = toc_ptr`.
            let (entry_addr, toc) = opd
                .get(&value)
                .map(|&(func, toc)| (func, Some(toc)))
                .unwrap_or((value, None));
            if let Some(toc) = toc {
                opd_toc.push((entry_addr, toc));
            }
            // A copy-relocated object is *defined* in the executable's own
            // dynamic table, with the size the library declares.
            if info & 0xf == 1 && shndx != 0 && size > 0 {
                object_sizes.push((value, size));
            }
            // A defined dynamic function names what the stripped symtab no
            // longer can. Addresses the symtab loop already named keep its
            // spelling; among dynsym spellings of one address the rank
            // decides, as in the symtab loop, so an unversioned name beats
            // `name@@VERSION`.
            if info & 0xf == 2 && shndx != 0 && !name.is_empty() {
                let rank = symbol_rank(info, &name);
                let slot =
                    symbol_functions
                        .entry(entry_addr)
                        .or_insert((rank, name.clone(), size.max(1)));
                if !symtab_named.contains(&entry_addr) && rank < slot.0 {
                    *slot = (rank, name.clone(), size.max(1));
                }
            }
            if !name.is_empty() && shndx == 0 {
                externals.push((0, name));
            }
        }
    }
    // A MIPS .debug stream (ECOFF mdebug or Metrowerks DWARF 1) names
    // procedures the symtab may have stripped. The symtab's spelling
    // wins where both exist; debug info only adds coverage.
    let mdebug_started = std::time::Instant::now();
    let mdebug_functions = mdebug::collect(data, &sections, be);
    for f in &mdebug_functions {
        symbol_functions
            .entry(f.entry)
            .or_insert((u8::MAX, f.name.clone(), f.size.max(1)));
    }
    let symbol_named: Vec<u64> = symbol_functions.keys().copied().collect();
    let symbol_extents = declared_extents(&symbol_functions);
    functions.extend(
        symbol_functions
            .into_iter()
            .map(|(entry, (_, name, size))| NativeFunction { entry, name, size }),
    );
    collect_elf_section_starts(&sections, &mut functions);
    functions.sort_by_key(|f| f.entry);
    functions.dedup_by_key(|f| f.entry);
    let contexts = Vec::new();
    let mut register_contexts = Vec::new();
    seed_ppc_sda_registers(
        elf_machine.machine,
        &abs_symbols,
        &sections,
        &functions,
        &mut register_contexts,
    );
    // PPC64 OPD: each descriptor's `toc_ptr` is the function's `r2` value.
    // Ghidra sets it over the function's range (markupDescriptorEntry
    // :636-644); we seed one range per function the descriptor named.
    for (entry_addr, toc) in &opd_toc {
        let end = functions
            .iter()
            .find(|f| f.entry == *entry_addr)
            .map(|f| f.entry + f.size.max(1))
            .unwrap_or(*entry_addr + 1);
        register_contexts.push(NativeRegisterContext {
            start: *entry_addr,
            end,
            register: "r2".into(),
            value: *toc,
        });
    }
    let mut import = NativeImport {
        diagnostics: notes,
        mappings,
        functions,
        externals,
        object_sizes,
        process_entry,
        object_names,
        contexts,
        register_contexts,
        symbol_named,
        symbol_extents,
        format: "ELF".into(),
        elf_machine: Some(elf_machine),
        ..Default::default()
    };
    if !mdebug_functions.is_empty() {
        phase(&mut import, "mdebug", mdebug_started);
    }
    import.toolchain = detect_toolchain(data, &sections);
    elf_image::prepare(data, &mut sections, &mut import, 8, be)?;
    let bias = elf_bases(data).map(|(_, bias)| bias).unwrap_or(0);
    elf_pointers::collect(data, &sections, &mut import, 8, be, bias)?;
    elf_pointers::collect_got(data, &sections, &mut import, 8, be, bias)?;
    elf_unwind::collect(data, &sections, &mut import, 8, be);
    elf_exception::collect(data, &sections, &mut import, 8, be);
    Ok(import)
}

/// Returns the preferred image base for an ELF image.
/// For ET_EXEC (fixed base), returns 0.
/// For ET_DYN (PIE / shared library), returns the minimum PT_LOAD vaddr
/// or 0x100000 (64-bit) / 0x10000 (32-bit), matching Ghidra's default.
pub fn elf_image_base(data: &[u8]) -> Option<u64> {
    elf_bases(data).map(|(base, _)| base)
}

// Preferred image base and relocation delta are distinct for prelinked images.
pub(super) fn elf_bases(data: &[u8]) -> Option<(u64, u64)> {
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
        let off = if is_be {
            u64_be_at(data, 32).ok()?
        } else {
            u64_at(data, 32).ok()?
        } as usize;
        let esz = if is_be {
            u16_be_at(data, 54).ok()?
        } else {
            u16_at(data, 54).ok()?
        } as usize;
        let num = if is_be {
            u16_be_at(data, 56).ok()?
        } else {
            u16_at(data, 56).ok()?
        } as usize;
        (off, esz, num)
    } else {
        let off = if is_be {
            u32_be_at(data, 28).ok()?
        } else {
            u32_at(data, 28).ok()?
        } as usize;
        let esz = if is_be {
            u16_be_at(data, 42).ok()?
        } else {
            u16_at(data, 42).ok()?
        } as usize;
        let num = if is_be {
            u16_be_at(data, 44).ok()?
        } else {
            u16_at(data, 44).ok()?
        } as usize;
        (off, esz, num)
    };
    let mut min_vaddr = u64::MAX;
    for i in 0..phnum {
        let hdr = phoff.checked_add(i.checked_mul(phentsize)?)?;
        if hdr.checked_add(if is_64 { 56 } else { 32 })? > data.len() {
            break;
        }
        let p_type = if is_be {
            u32_be_at(data, hdr).ok()?
        } else {
            u32_at(data, hdr).ok()?
        };
        if p_type == 1 {
            // PT_LOAD
            let p_vaddr = if is_64 {
                if is_be {
                    u64_be_at(data, hdr + 16).ok()?
                } else {
                    u64_at(data, hdr + 16).ok()?
                }
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
