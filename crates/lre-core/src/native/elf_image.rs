//! ELF load bias and relative relocations, before discovery or memory reads.
//! REL/RELA/RELR layouts and R_*_RELATIVE numbers follow the public elf.h ABI.
use super::{ElfSection, ImportError, MemoryRelocation, NativeImport, NativeXref, Result};
use std::collections::HashMap;

fn bad(message: &str) -> ImportError {
    ImportError::Bad(message.into())
}

fn word(data: &[u8], offset: usize, width: usize, be: bool) -> Result<u64> {
    let end = offset
        .checked_add(width)
        .ok_or_else(|| bad("ELF word overflow"))?;
    let bytes = data
        .get(offset..end)
        .ok_or_else(|| bad("truncated ELF relocation"))?;
    Ok(bytes.iter().enumerate().fold(0, |value, (i, byte)| {
        value | (*byte as u64) << (8 * if be { width - 1 - i } else { i })
    }))
}

fn collect_string_tables(data: &[u8], sections: &[ElfSection], import: &mut NativeImport) -> Result<()> {
    for section in sections.iter().filter(|section| section.typ == 3 && section.size != 0) {
        let start = usize::try_from(section.off).map_err(|_| bad("ELF string table offset overflow"))?;
        let size = usize::try_from(section.size).map_err(|_| bad("ELF string table size overflow"))?;
        let bytes = data.get(start..start.checked_add(size).ok_or_else(|| bad("ELF string table overflow"))?)
            .ok_or_else(|| bad("truncated ELF string table"))?;
        section.addr.checked_add(section.size).ok_or_else(|| bad("ELF string table address overflow"))?;
        let address = lre_model::Address {
            space: if section.flags & 2 != 0 { lre_model::AddressSpace::Ram }
                else { lre_model::AddressSpace::Other(section.name.clone()) },
            offset: section.addr,
        };
        let mut strings = Vec::new();
        // ElfProgramBuilder.markupStringTable skips the initial empty entry
        // and declares each subsequent string as StringUTF8DataType.
        let mut begin = 1;
        for (end, &byte) in bytes.iter().enumerate().skip(1) {
            if byte != 0 { continue; }
            let value = String::from_utf8_lossy(&bytes[begin..end]);
            if value.chars().count() >= 4 {
                strings.push(lre_model::StringRow {
                    address: lre_model::Address { space: address.space.clone(), offset: address.offset + begin as u64 },
                    value: value.into_owned(), kind: "UTF-8".into(),
                });
            }
            begin = end + 1;
        }
        import.string_tables.push(super::NativeStringTable { address, size: section.size, strings });
    }
    Ok(())
}

pub(super) fn prepare(
    data: &[u8],
    sections: &mut [ElfSection],
    import: &mut NativeImport,
    width: usize,
    be: bool,
) -> Result<()> {
    let (_, bias) = super::elf_bases(data).ok_or_else(|| bad("invalid ELF image base"))?;
    let rebase = |address: u64| {
        address
            .checked_add(bias)
            .ok_or_else(|| bad("ELF address overflow"))
    };
    for mapping in &mut import.mappings {
        mapping.vaddr = rebase(mapping.vaddr)?;
        let end = mapping
            .vaddr
            .checked_add(mapping.size)
            .ok_or_else(|| bad("ELF mapping overflow"))?;
        if width == 4 && end > 1u64 << 32 {
            return Err(bad("ELF32 mapping exceeds address space"));
        }
    }
    for function in &mut import.functions {
        function.entry = rebase(function.entry)?;
    }
    for (address, _) in &mut import.externals {
        if *address != 0 {
            *address = rebase(*address)?;
        }
    }
    for section in sections.iter_mut().filter(|s| s.flags & 2 != 0) {
        section.addr = rebase(section.addr)?;
    }
    complete_load_segments(data, import, width, be, bias)?;
    collect_string_tables(data, sections, import)?;
    let machine = word(data, 18, 2, be)?;
    if machine == 20 && width == 4 && dynamic_value(data, width, be, 0x70000000)?.is_some() {
        import.reference_call_register = Some("r30"); // DT_PPC_GOT: old ELF32 PIC ABI.
    }
    let linkage_types = match machine {
        3 | 62 => [6, 7],
        20 | 21 => [20, 21],
        183 => [1025, 1026],
        40 => [21, 22],
        8 => [51, 127],
        243 => [0, 5],
        _ => [0, 0],
    }; // Public elf.h: GLOB_DAT / JUMP_SLOT, not arbitrary symbol relocations.
    let relative_type = match machine {
        3 | 62 => Some(8),   // i386 / x86-64
        20 | 21 => Some(22), // PowerPC / PowerPC64
        183 => Some(1027),   // AArch64
        243 => Some(3),      // RISC-V
        _ => None,
    };
    // Public elf.h STT_GNU_IFUNC relocations: the addend is the in-image
    // resolver, so the slot has a proven local destination and no import name.
    let irelative_type = match machine {
        3 => Some(42),
        62 => Some(37),
        20 | 21 => Some(248),
        183 => Some(1032),
        40 => Some(160),
        243 => Some(58),
        _ => None,
    };
    // Public elf.h: a loader-copied object (COPY) and a word-sized absolute
    // binding. Both name a symbol at a data address, which is how the Itanium
    // ABI ties a type_info to its `__cxxabiv1` vtable.
    let copy_type = match machine {
        3 | 62 => Some(5),
        20 | 21 => Some(19),
        183 => Some(1024),
        40 => Some(20),
        _ => None,
    };
    let absolute_type = match machine {
        3 | 20 | 21 | 40 => Some(1),
        62 => Some(1),
        183 => Some(257),
        243 => Some(2),
        _ => None,
    };
    for section in sections
        .iter()
        .filter(|s| matches!(s.typ, 4 | 9 | 19) && s.size != 0)
    {
        let start =
            usize::try_from(section.off).map_err(|_| bad("ELF relocation offset overflow"))?;
        let size =
            usize::try_from(section.size).map_err(|_| bad("ELF relocation size overflow"))?;
        let bytes = data
            .get(
                start
                    ..start
                        .checked_add(size)
                        .ok_or_else(|| bad("ELF relocation overflow"))?,
            )
            .ok_or_else(|| bad("truncated ELF relocation section"))?;
        let stride = width
            * match section.typ {
                4 => 3,
                9 => 2,
                _ => 1,
            };
        if bytes.len() % stride != 0 {
            return Err(bad("partial ELF relocation record"));
        }
        let mut next = None;
        for record in bytes.chunks_exact(stride) {
            let place = word(record, 0, width, be)?;
            if section.typ == 19 {
                if place & 1 == 0 {
                    apply(import, rebase(place)?, None, bias, width, be)?;
                    next = Some(
                        place
                            .checked_add(width as u64)
                            .ok_or_else(|| bad("RELR cursor overflow"))?,
                    );
                } else {
                    let cursor = next.ok_or_else(|| bad("RELR bitmap without address"))?;
                    for bit in 1..width * 8 {
                        if place & (1u64 << bit) != 0 {
                            let at = cursor
                                .checked_add(((bit - 1) * width) as u64)
                                .ok_or_else(|| bad("RELR bitmap overflow"))?;
                            apply(import, rebase(at)?, None, bias, width, be)?;
                        }
                    }
                    next = Some(
                        cursor
                            .checked_add(((width * 8 - 1) * width) as u64)
                            .ok_or_else(|| bad("RELR cursor overflow"))?,
                    );
                }
            } else {
                let info = word(record, width, width, be)?;
                let typ = info & if width == 8 { 0xffffffff } else { 0xff };
                if typ != 0 && linkage_types.contains(&typ) {
                    let index = info >> if width == 8 { 32 } else { 8 };
                    if let Some(name) =
                        external_name(data, sections, section.link, index, width, be)?
                    {
                        let address = rebase(place)?;
                        if !import.mappings.iter().any(|m| {
                            m.size >= width as u64
                                && address >= m.vaddr
                                && address - m.vaddr <= m.size - width as u64
                        }) {
                            return Err(bad("ELF external relocation place is unmapped"));
                        }
                        import
                            .externals
                            .push((address, String::from_utf8_lossy(name).into_owned()));
                    }
                }
                if copy_type == Some(typ)
                    || absolute_type == Some(typ)
                    || linkage_types.contains(&typ)
                {
                    let index = info >> if width == 8 { 32 } else { 8 };
                    if let Some(name) =
                        relocation_symbol(data, sections, section.link, index, width, be)?
                    {
                        let address = rebase(place)?;
                        let addend = if section.typ == 4 {
                            word(record, 2 * width, width, be)?
                        } else {
                            // REL keeps the addend in place; read the loaded word.
                            import
                                .mappings
                                .iter()
                                .find_map(|mapping| {
                                    let offset = address.checked_sub(mapping.vaddr)? as usize;
                                    let bytes = mapping.bytes.get(offset..offset + width)?;
                                    Some(word(bytes, 0, width, be))
                                })
                                .transpose()?
                                .unwrap_or(0)
                        };
                        import.named_relocations.push(crate::native::NamedRelocation {
                            address,
                            symbol: String::from_utf8_lossy(name).into_owned(),
                            addend,
                            copies: copy_type == Some(typ),
                        });
                    }
                }
                if irelative_type == Some(typ) && section.typ == 4 {
                    let slot = rebase(place)?;
                    let resolver = rebase(word(record, 2 * width, width, be)?)?;
                    let slot_mapped = import.mappings.iter().any(|m| {
                        m.size >= width as u64
                            && slot >= m.vaddr
                            && slot - m.vaddr <= m.size - width as u64
                    });
                    let resolves_code = import.mappings.iter().any(|m| {
                        m.flags & 4 != 0 && resolver >= m.vaddr && resolver - m.vaddr < m.size
                    });
                    if slot_mapped && resolves_code {
                        import.ifunc_slots.push((slot, resolver));
                    }
                }
                if relative_type != Some(typ) {
                    continue;
                }
                let addend = if section.typ == 4 {
                    Some(word(record, 2 * width, width, be)?)
                } else {
                    None
                };
                apply(import, rebase(place)?, addend, bias, width, be)?;
            }
        }
    }
    import.relocations.sort_by_key(|r| r.address);
    if import
        .relocations
        .windows(2)
        .any(|pair| pair[1].address - pair[0].address < width as u64)
    {
        return Err(bad("overlapping ELF relative relocations"));
    }
    import.externals.sort();
    import.externals.dedup();
    import.ifunc_slots.sort_unstable();
    import.ifunc_slots.dedup();
    collect_plt_candidates(sections, import, machine, width as u64);
    collect_initializer_labels(data, import, width, be, bias)?;
    if machine == 3 && width == 4 {
        collect_x86_plt_context(data, sections, import, bias, be)?;
    }
    // ElfProgramBuilder.markupSectionHeaders references each loaded sh_addr.
    // An executable section start is a code root, not a function or a sweep.
    for section in sections.iter().filter(|section| {
        section.typ == 1 && section.flags & 6 == 6 && section.size != 0
    }) {
        let end = section.addr.checked_add(section.size)
            .ok_or_else(|| bad("ELF section code range overflow"))?;
        import.reference_roots.push((section.addr, end));
    }
    Ok(())
}

fn program_headers(data: &[u8], width: usize, be: bool) -> Result<std::slice::ChunksExact<'_, u8>> {
    let (offset_at, size_at, count_at, minimum) =
        if width == 4 { (28, 42, 44, 32) } else { (32, 54, 56, 56) };
    let offset = usize::try_from(word(data, offset_at, width, be)?)
        .map_err(|_| bad("ELF program-header offset overflow"))?;
    let stride = word(data, size_at, 2, be)? as usize;
    let count = word(data, count_at, 2, be)? as usize;
    if count == 0 {
        return Ok(data[..0].chunks_exact(minimum));
    }
    if stride < minimum {
        return Err(bad("undersized ELF program header"));
    }
    let end = count.checked_mul(stride).and_then(|size| offset.checked_add(size))
        .ok_or_else(|| bad("ELF program-header range overflow"))?;
    Ok(data.get(offset..end).ok_or_else(|| bad("truncated ELF program headers"))?.chunks_exact(stride))
}

fn complete_load_segments(
    data: &[u8], import: &mut NativeImport, width: usize, be: bool, bias: u64,
) -> Result<()> {
    import.mappings.sort_unstable_by_key(|mapping| mapping.vaddr);
    for header in program_headers(data, width, be)? {
        if word(header, 0, 4, be)? != 1 { // PT_LOAD
            continue;
        }
        let offset = word(header, if width == 4 { 4 } else { 8 }, width, be)?;
        let start = word(header, if width == 4 { 8 } else { 16 }, width, be)?
            .checked_add(bias).ok_or_else(|| bad("ELF segment address overflow"))?;
        let filesz = word(header, if width == 4 { 16 } else { 32 }, width, be)?;
        let memsz = word(header, if width == 4 { 20 } else { 40 }, width, be)?;
        let permissions = word(header, if width == 4 { 24 } else { 4 }, 4, be)?;
        let end = start.checked_add(memsz).ok_or_else(|| bad("ELF segment range overflow"))?;
        if filesz > memsz || (width == 4 && end > 1u64 << 32) {
            return Err(bad("invalid ELF segment memory range"));
        }
        let file_end = offset.checked_add(filesz).ok_or_else(|| bad("ELF segment file overflow"))?;
        let file_bytes = usize::try_from(offset).ok().zip(usize::try_from(file_end).ok())
            .and_then(|(begin, end)| data.get(begin..end))
            .ok_or_else(|| bad("truncated ELF load segment"))?;
        let flags = ((permissions & 2) >> 1) | ((permissions & 4) >> 1) | ((permissions & 1) << 2);
        let mut gaps = Vec::new();
        let mut add_gap = |begin: u64, end: u64| -> Result<()> {
            let relative = begin - start;
            let initialized_start = relative.min(filesz) as usize;
            let initialized_end = (end - start).min(filesz) as usize;
            gaps.push(super::Mapping {
                vaddr: begin, size: end - begin,
                file_off: offset.checked_add(relative).ok_or_else(|| bad("ELF segment offset overflow"))?,
                flags, bytes: file_bytes[initialized_start..initialized_end].to_vec(),
            });
            Ok(())
        };
        let mut cursor = start;
        for mapping in &import.mappings {
            if mapping.vaddr >= end { break; }
            let mapped_end = mapping.vaddr.checked_add(mapping.size)
                .ok_or_else(|| bad("ELF mapping overflow"))?;
            if mapped_end <= cursor { continue; }
            if mapping.vaddr > cursor { add_gap(cursor, mapping.vaddr)?; }
            cursor = mapped_end.min(end);
        }
        if cursor < end { add_gap(cursor, end)?; }
        import.mappings.extend(gaps);
        import.mappings.sort_unstable_by_key(|mapping| mapping.vaddr);
    }
    Ok(())
}

fn dynamic_value(data: &[u8], width: usize, be: bool, wanted: u64) -> Result<Option<u64>> {
    for header in program_headers(data, width, be)? {
        if word(header, 0, 4, be)? != 2 { // PT_DYNAMIC
            continue;
        }
        let start = word(header, if width == 4 { 4 } else { 8 }, width, be)?;
        let size = word(header, if width == 4 { 16 } else { 32 }, width, be)?;
        let end = start.checked_add(size).ok_or_else(|| bad("ELF dynamic range overflow"))?;
        let bytes = usize::try_from(start).ok().zip(usize::try_from(end).ok())
            .and_then(|(start, end)| data.get(start..end))
            .ok_or_else(|| bad("ELF dynamic table outside file"))?;
        if bytes.len() % (2 * width) != 0 {
            return Err(bad("partial ELF dynamic record"));
        }
        for entry in bytes.chunks_exact(2 * width) {
            let tag = word(entry, 0, width, be)?;
            if tag == 0 {
                break;
            }
            if tag == wanted {
                return Ok(Some(word(entry, width, width, be)?));
            }
        }
    }
    Ok(None)
}

/// Names the targets of the dynamic initializer arrays.
///
/// Ghidra `ElfProgramBuilder.createDynamicEntryPoints` (lines 690-750) names
/// the target of `DT_INIT_ARRAY[i]` `_INIT_<i>`, and the other two arrays
/// `_PREINIT_<i>` and `_FINI_<i>`. Both parts are read, never guessed: the
/// array's base and size come from the dynamic table, the target from the
/// slot's own word or from the relocation applied to that slot, and the index
/// from the slot's position in the array. A zero slot names nothing.
fn collect_initializer_labels(
    data: &[u8],
    import: &mut NativeImport,
    width: usize,
    be: bool,
    bias: u64,
) -> Result<()> {
    // Public elf.h tag numbers.
    const ARRAYS: [(u64, u64, &str); 3] = [
        (25, 27, "_INIT_"),
        (32, 33, "_PREINIT_"),
        (26, 28, "_FINI_"),
    ];
    let relocated: HashMap<u64, u64> = import
        .xrefs
        .iter()
        .filter(|xref| xref.provenance == "native-import:elf-reloc")
        .map(|xref| (xref.from, xref.to))
        .collect();
    let word_at = |import: &NativeImport, address: u64| -> Option<u64> {
        let mapping = import.mappings.iter().find(|mapping| {
            address >= mapping.vaddr && address - mapping.vaddr < mapping.size
        })?;
        let offset = usize::try_from(address - mapping.vaddr).ok()?;
        let bytes = mapping.bytes.get(offset..offset.checked_add(width)?)?;
        Some(match (width, be) {
            (4, false) => u32::from_le_bytes(bytes.try_into().ok()?) as u64,
            (4, true) => u32::from_be_bytes(bytes.try_into().ok()?) as u64,
            (8, false) => u64::from_le_bytes(bytes.try_into().ok()?),
            (8, true) => u64::from_be_bytes(bytes.try_into().ok()?),
            _ => return None,
        })
    };
    let mut labels = Vec::new();
    for (array_tag, size_tag, prefix) in ARRAYS {
        let Some(base) = dynamic_value(data, width, be, array_tag)? else {
            continue;
        };
        let Some(size) = dynamic_value(data, width, be, size_tag)?
            .filter(|size| *size != 0)
        else {
            continue;
        };
        let base = base
            .checked_add(bias)
            .ok_or_else(|| bad("ELF initializer array address overflow"))?;
        for index in 0..size / width as u64 {
            let slot = base
                .checked_add(index * width as u64)
                .ok_or_else(|| bad("ELF initializer slot address overflow"))?;
            // A relocated slot holds its target already rebased; a plain word
            // holds a link-time address.
            let target = match relocated.get(&slot) {
                Some(target) => *target,
                None => match word_at(import, slot).filter(|word| *word != 0) {
                    Some(word) => word
                        .checked_add(bias)
                        .ok_or_else(|| bad("ELF initializer target overflow"))?,
                    None => continue,
                },
            };
            let executable = import.mappings.iter().any(|mapping| {
                mapping.flags & 4 != 0
                    && target >= mapping.vaddr
                    && target - mapping.vaddr < mapping.size
            });
            if executable {
                labels.push((target, format!("{prefix}{index}")));
            }
        }
    }
    import.initializer_labels.extend(labels);
    Ok(())
}

fn collect_x86_plt_context(
    data: &[u8], sections: &[ElfSection], import: &mut NativeImport, bias: u64, be: bool,
) -> Result<()> {
    // X86_32_ElfExtension.processX86PltSections (Ghidra 12.1.3).
    let Some(got) = dynamic_value(data, 4, be, 3)? else { return Ok(()); }; // DT_PLTGOT
    let value = got.checked_add(bias).filter(|value| *value <= u32::MAX as u64)
        .ok_or_else(|| bad("ELF32 GOT context overflows address space"))?;
    for section in sections.iter().filter(|section| {
        section.flags & 6 == 6 && section.size != 0
            && (section.name == ".plt" || section.name.starts_with(".plt."))
    }) {
        let end = section.addr.checked_add(section.size)
            .ok_or_else(|| bad("ELF PLT context range overflows"))?;
        import.register_contexts.push(super::NativeRegisterContext {
            start: section.addr, end, register: "EBX".into(), value,
        });
    }
    Ok(())
}

fn collect_plt_candidates(
    sections: &[ElfSection],
    import: &mut NativeImport,
    machine: u64,
    word_width: u64,
) {
    if !import.externals.iter().any(|(address, _)| *address != 0) {
        return;
    }
    for section in sections
        .iter()
        .filter(|section| section.flags & 6 == 6 && section.typ == 1)
    {
        let default_width = match (machine, section.name.as_str()) {
            (3 | 62, ".plt" | ".plt.sec") | (183, ".plt") => 16,
            (3 | 62, ".plt.got") => 8,
            _ => continue,
        };
        if section.entry_size == 0 {
            // Only infer a canonical linker layout when its relocation count
            // accounts for the whole table. Do not split unknown BTI/PAC layouts.
            let header = match (machine, section.name.as_str()) {
                (183, ".plt") => 32,
                (_, ".plt") => 16,
                (_, ".plt.sec") => 0,
                _ => continue,
            };
            let count = sections
                .iter()
                .filter(|rel| {
                    matches!(
                        (rel.typ, rel.name.as_str()),
                        (4, ".rela.plt") | (9, ".rel.plt")
                    )
                })
                .try_fold(0u64, |count, rel| {
                    count.checked_add(rel.size / (word_width * if rel.typ == 4 { 3 } else { 2 }))
                });
            if count
                .filter(|count| *count != 0)
                .and_then(|count| count.checked_mul(default_width))
                .and_then(|size| size.checked_add(header))
                != Some(section.size)
            {
                continue;
            }
        }
        let width = if section.entry_size == 0 {
            default_width
        } else {
            section.entry_size
        };
        if !(8..=64).contains(&width) || section.size % width != 0 {
            continue;
        }
        let Some(mapping) = import
            .mappings
            .iter()
            .find(|mapping| mapping.vaddr == section.addr)
        else {
            continue;
        };
        if section.size > mapping.bytes.len() as u64 {
            continue;
        }
        import
            .plt_candidates
            .extend((0..section.size / width).map(|index| (section.addr + index * width, width)));
    }
}

/// Name of the symbol a relocation binds, whatever its type or definition:
/// data relocations name defined objects, which import naming rejects.
fn relocation_symbol<'a>(
    data: &'a [u8],
    sections: &[ElfSection],
    link: u32,
    index: u64,
    width: usize,
    be: bool,
) -> Result<Option<&'a [u8]>> {
    // A data relocation may sit in a file with no symbol table we can read;
    // then it simply carries no name. Import naming keeps its strict check.
    let Some((symbols, _)) = symbol_record(data, sections, link, index, width, false)? else {
        return Ok(None);
    };
    symbol_name(data, sections, symbols, index, width, be)
}

/// Import names only: an undefined NOTYPE or FUNC symbol.
fn external_name<'a>(
    data: &'a [u8],
    sections: &[ElfSection],
    link: u32,
    index: u64,
    width: usize,
    be: bool,
) -> Result<Option<&'a [u8]>> {
    let Some((symbols, symbol)) = symbol_record(data, sections, link, index, width, true)? else {
        return Ok(None);
    };
    let info = symbol[if width == 8 { 4 } else { 12 }];
    if word(symbol, if width == 8 { 6 } else { 14 }, 2, be)? != 0 || !matches!(info & 15, 0 | 2) {
        return Ok(None);
    }
    symbol_name(data, sections, symbols, index, width, be)
}

/// Locates one dynamic symbol table entry, bounds-checked.
fn symbol_record<'a>(
    data: &'a [u8],
    sections: &'a [ElfSection],
    link: u32,
    index: u64,
    width: usize,
    required: bool,
) -> Result<Option<(&'a ElfSection, &'a [u8])>> {
    if index == 0 {
        return Ok(None);
    }
    // SHT_SYMTAB and SHT_DYNSYM share the entry layout.
    let symbols = match sections.get(link as usize).filter(|s| matches!(s.typ, 2 | 11)) {
        Some(symbols) => symbols,
        None if required => {
            return Err(bad("ELF external relocation has no dynamic symbol table"));
        }
        None => return Ok(None),
    };
    let stride = if width == 8 { 24 } else { 16 };
    let relative = index
        .checked_mul(stride)
        .ok_or_else(|| bad("ELF symbol index overflow"))?;
    if relative
        .checked_add(stride)
        .is_none_or(|end| end > symbols.size)
    {
        return Err(bad("ELF relocation symbol index is out of bounds"));
    }
    let start = usize::try_from(
        symbols
            .off
            .checked_add(relative)
            .ok_or_else(|| bad("ELF symbol offset overflow"))?,
    )
    .map_err(|_| bad("ELF symbol offset overflow"))?;
    let symbol = data
        .get(
            start
                ..start
                    .checked_add(stride as usize)
                    .ok_or_else(|| bad("ELF symbol overflow"))?,
        )
        .ok_or_else(|| bad("truncated ELF dynamic symbol"))?;
    Ok(Some((symbols, symbol)))
}

fn symbol_name<'a>(
    data: &'a [u8],
    sections: &[ElfSection],
    symbols: &ElfSection,
    index: u64,
    width: usize,
    be: bool,
) -> Result<Option<&'a [u8]>> {
    let stride = if width == 8 { 24 } else { 16 };
    let start = usize::try_from(symbols.off + index * stride)
        .map_err(|_| bad("ELF symbol offset overflow"))?;
    let symbol = data
        .get(start..start + stride as usize)
        .ok_or_else(|| bad("truncated ELF dynamic symbol"))?;
    let strings = sections
        .get(symbols.link as usize)
        .filter(|s| s.typ == 3)
        .ok_or_else(|| bad("ELF dynamic symbol has no string table"))?;
    let offset = word(symbol, 0, 4, be)?;
    if offset >= strings.size {
        return Err(bad("ELF symbol name is out of bounds"));
    }
    let start = usize::try_from(
        strings
            .off
            .checked_add(offset)
            .ok_or_else(|| bad("ELF string offset overflow"))?,
    )
    .map_err(|_| bad("ELF string offset overflow"))?;
    let end = usize::try_from(
        strings
            .off
            .checked_add(strings.size)
            .ok_or_else(|| bad("ELF string table overflow"))?,
    )
    .map_err(|_| bad("ELF string table overflow"))?;
    let bytes = data
        .get(start..end)
        .ok_or_else(|| bad("truncated ELF string table"))?;
    let end = bytes
        .iter()
        .position(|&byte| byte == 0)
        .ok_or_else(|| bad("unterminated ELF symbol name"))?;
    Ok((end != 0).then_some(&bytes[..end]))
}

fn apply(
    import: &mut NativeImport,
    address: u64,
    addend: Option<u64>,
    bias: u64,
    width: usize,
    be: bool,
) -> Result<()> {
    let mapping = import
        .mappings
        .iter_mut()
        .find(|m| {
            address >= m.vaddr
                && address - m.vaddr <= m.size.saturating_sub(width as u64)
                && m.size >= width as u64
        })
        .ok_or_else(|| bad("ELF relocation place is unmapped"))?;
    let offset = usize::try_from(address - mapping.vaddr)
        .map_err(|_| bad("ELF relocation offset overflow"))?;
    let addend = match addend {
        Some(value) => value,
        None if mapping.bytes.is_empty() => 0, // SHT_NOBITS
        None => word(&mapping.bytes, offset, width, be)?,
    };
    // Word-sized modular arithmetic also preserves zero and negative addends.
    let mut value = bias.wrapping_add(addend);
    if width == 4 {
        value &= u32::MAX as u64;
    }
    let mut bytes = [0; 8];
    for (i, byte) in bytes[..width].iter_mut().enumerate() {
        *byte = (value >> (8 * if be { width - 1 - i } else { i })) as u8;
    }
    if !mapping.bytes.is_empty() {
        mapping
            .bytes
            .get_mut(offset..offset + width)
            .ok_or_else(|| bad("truncated ELF relocation place"))?
            .copy_from_slice(&bytes[..width]);
    }
    import.relocations.push(MemoryRelocation {
        address,
        bytes,
        width,
    });
    import.xrefs.push(NativeXref::with_provenance(
        address,
        value,
        "DATA",
        "native-import:elf-reloc",
    ));
    if import
        .mappings
        .iter()
        .any(|m| m.flags & 4 != 0 && value >= m.vaddr && value - m.vaddr < m.size)
    {
        import.reloc_candidates.push(value);
    }
    Ok(())
}
