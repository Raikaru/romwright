use super::*;

pub(in crate::native) mod x86_conventions;
pub(in crate::native) mod x86_operands;
pub(in crate::native) mod local_calls;
pub(in crate::native) mod x86_fill;

/// What discovery calls, under names that say what it is for: the PE fill-start rule and the operand-based data rules.
pub(in crate::native) mod fill {
    pub(in crate::native) use super::x86_fill::{starts, PASSES};
}
pub(in crate::native) mod operand_hooks {
    pub(in crate::native) use super::x86_operands::dense_table_targets;
    pub(in crate::native) use super::x86_operands::memory_operand_only_targets as memory_only_targets;
}

/// The import-table slots whose calls are `__stdcall` (Win32 imports; see `pe_roots::stdcall_import_slots`).
pub fn stdcall_import_slots(data: &[u8]) -> std::collections::BTreeSet<u64> {
    pe_roots::stdcall_import_slots(data)
}

pub fn import_pe(data: &[u8]) -> Result<NativeImport> {
    let mut notes: Vec<romwright_model::ImportDiagnostic> = Vec::new();
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
        other => {
            return err(format!(
                "unsupported PE machine {other:#x} (AMD64 0x8664 or i386 0x14c expected)"
            ));
        }
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
    let (
        entry_rva,
        image_base,
        reloc_dir_offset,
        unwind_dir_offset,
        export_dir_offset,
        import_dir_offset,
        tls_dir_offset,
    ) = match (machine, magic) {
        (0x8664, 0x20b) => {
            if opt_size < 112 {
                return err(format!(
                    "PE32+ optional header size {opt_size} too small (>= 112 expected)"
                ));
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
            (
                entry_rva,
                image_base,
                reloc_offset,
                unwind_offset,
                export_offset,
                import_offset,
                tls_offset,
            )
        }
        (0x014c, 0x10b) => {
            if opt_size < 96 {
                return err(format!(
                    "PE32 optional header size {opt_size} too small (>= 96 expected)"
                ));
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
            (
                entry_rva,
                image_base,
                reloc_offset,
                None,
                export_offset,
                import_offset,
                tls_offset,
            )
        }
        (0x8664, other) => {
            return err(format!(
                "PE AMD64 requires PE32+ optional header magic 0x20b, got {other:#x}"
            ));
        }
        (0x014c, other) => {
            return err(format!(
                "PE i386 requires PE32 optional header magic 0x10b, got {other:#x}"
            ));
        }
        (other, _) => {
            return err(format!(
                "unsupported PE machine {other:#x} (AMD64 0x8664 or i386 0x14c expected)"
            ));
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
        let mut bytes = file_bytes(
            data,
            raw as u64,
            raw_size as u64,
            || format!("PE section at {vaddr:#x}"),
            &mut notes,
        )
        .to_vec();
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

                if let Some(m) = mappings
                    .iter()
                    .find(|m| loc >= m.vaddr && loc < m.vaddr + m.size)
                {
                    let off = (loc - m.vaddr) as usize;
                    match r_type {
                        10 => {
                            // IMAGE_REL_BASED_DIR64
                            if off + 8 <= m.bytes.len() {
                                let ptr =
                                    u64::from_le_bytes(m.bytes[off..off + 8].try_into().unwrap());
                                let in_mem = mappings
                                    .iter()
                                    .any(|cm| ptr >= cm.vaddr && ptr < cm.vaddr + cm.size);
                                if in_mem {
                                    xrefs.push(NativeXref::with_provenance(
                                        loc,
                                        ptr,
                                        "DATA",
                                        "native-import:pe-reloc",
                                    ));
                                }
                                let in_code = mappings.iter().any(|cm| {
                                    cm.flags & 0x4 != 0
                                        && ptr >= cm.vaddr
                                        && ptr < cm.vaddr + cm.size
                                });
                                if in_code {
                                    reloc_candidates.push(ptr);
                                }
                            }
                        }
                        3 => {
                            // IMAGE_REL_BASED_HIGHLOW
                            if off + 4 <= m.bytes.len() {
                                let ptr =
                                    u32::from_le_bytes(m.bytes[off..off + 4].try_into().unwrap())
                                        as u64;
                                let in_mem = mappings
                                    .iter()
                                    .any(|cm| ptr >= cm.vaddr && ptr < cm.vaddr + cm.size);
                                if in_mem {
                                    xrefs.push(NativeXref::with_provenance(
                                        loc,
                                        ptr,
                                        "DATA",
                                        "native-import:pe-reloc",
                                    ));
                                }
                                let in_code = mappings.iter().any(|cm| {
                                    cm.flags & 0x4 != 0
                                        && ptr >= cm.vaddr
                                        && ptr < cm.vaddr + cm.size
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
        diagnostics: notes,
        mappings,
        functions,
        xrefs,
        externals: Vec::new(),
        reloc_candidates,
        format: "PE".into(),
        language: language.into(),
        ..Default::default()
    };
    // What the compiler detector reads (`compiler::detect::pe_x86_image`).
    import.image_facts.pe_linker = data.get(opt + 2..opt + 4).map(|version| (version[0], version[1]));
    import.image_facts.pe_rich = crate::compiler::detect::find(&data[..pe_off.min(data.len())], b"Rich").is_some();
    import.image_facts.pe_gcc_stamp = crate::compiler::detect::gcc_stamp_text(data);
    import.image_facts.pe_comp_ids = crate::compiler::detect::rich_comp_ids(&data[..pe_off.min(data.len())]);
    import.image_facts.pe_crt_dll = crate::compiler::detect::crt_dll_name(data);
    let directory = |offset: Option<usize>| {
        offset.map_or((0, 0), |at| {
            (
                u32_at(data, at).unwrap_or(0) as u64,
                u32_at(data, at + 4).unwrap_or(0) as usize,
            )
        })
    };
    let (unwind_rva, unwind_size) = directory(unwind_dir_offset);
    pe_unwind::collect(
        data,
        &raw_sections,
        &mut import,
        image_base,
        unwind_rva,
        unwind_size,
    );
    let (export_rva, export_size) = directory(export_dir_offset);
    pe_roots::collect_exports(
        data,
        &raw_sections,
        &mut import,
        image_base,
        export_rva,
        export_size,
    );
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
    pe_roots::collect_import_stubs(data, &raw_sections, &mut import, image_base, is_64);
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

/// A PE's import address table is written by the loader: each slot holds the imported function's address, not the
/// image's own bytes (the bytes on disk are the hint/name RVAs the loader consumes). A decompiler that read the slot as
/// the constant it holds would fold `call [slot]` into a call to that RVA. The slots are therefore carved out of the
/// read-only section regions into their own writable ones, the way the loader's write makes them behave.
pub(in crate::native) fn carve_import_slots(
    regions: Vec<romwright_model::MemoryRegion>,
    slots: &[(u64, String)],
    width: u64,
) -> Vec<romwright_model::MemoryRegion> {
    // `ROMWRIGHT_PE_IAT_REGIONS=off` leaves the table in its read-only section
    if std::env::var("ROMWRIGHT_PE_IAT_REGIONS").is_ok_and(|v| v == "off") {
        return regions;
    }
    let mut starts: Vec<u64> = slots.iter().map(|(address, _)| *address).filter(|a| *a != 0).collect();
    starts.sort_unstable();
    starts.dedup();
    // a run is consecutive slots
    let mut runs: Vec<(u64, u64)> = Vec::new();
    for start in starts {
        match runs.last_mut() {
            Some((_, end)) if start <= *end => *end = start + width,
            _ => runs.push((start, start + width)),
        }
    }
    let mut out = Vec::with_capacity(regions.len() + runs.len());
    for region in regions {
        let (lo, hi) = (region.start.offset, region.start.offset + region.size);
        let inside: Vec<(u64, u64)> = if region.permissions.contains('w') {
            Vec::new()
        } else {
            runs.iter().copied().filter(|&(start, end)| start >= lo && end <= hi).collect()
        };
        if inside.is_empty() {
            out.push(region);
            continue;
        }
        let mut at = lo;
        for (start, end) in inside {
            if start > at {
                out.push(romwright_model::MemoryRegion { start: romwright_model::Address::ram(at), size: start - at, ..region.clone() });
            }
            out.push(romwright_model::MemoryRegion {
                name: format!("{}:iat", region.name),
                start: romwright_model::Address::ram(start),
                size: end - start,
                permissions: region.permissions.chars().enumerate().map(|(i, c)| if i == 1 { 'w' } else { c }).collect(),
                ..region.clone()
            });
            at = end;
        }
        if hi > at {
            out.push(romwright_model::MemoryRegion { start: romwright_model::Address::ram(at), size: hi - at, ..region.clone() });
        }
    }
    out
}

#[cfg(test)]
mod iat_tests {
    use super::*;

    fn region(name: &str, start: u64, size: u64, permissions: &str) -> romwright_model::MemoryRegion {
        romwright_model::MemoryRegion {
            name: name.into(),
            start: romwright_model::Address::ram(start),
            size,
            permissions: permissions.into(),
            source: "native-import".into(),
        }
    }

    #[test]
    fn the_import_address_table_becomes_its_own_writable_region() {
        let regions = vec![region("pe:.text", 0x1000, 0x1000, "r-x"), region("pe:.rdata", 0x2000, 0x1000, "r--")];
        // two DLLs' tables: slots at 0x2100 and 0x2104, and one at 0x2110
        let slots = vec![(0x2100, "A".to_string()), (0x2104, "B".to_string()), (0x2110, "C".to_string())];
        let out = carve_import_slots(regions, &slots, 4);
        let shape: Vec<_> = out.iter().map(|r| (r.name.as_str(), r.start.offset, r.size, r.permissions.as_str())).collect();
        assert_eq!(
            shape,
            vec![
                ("pe:.text", 0x1000, 0x1000, "r-x"),
                ("pe:.rdata", 0x2000, 0x100, "r--"),
                ("pe:.rdata:iat", 0x2100, 0x8, "rw-"),
                ("pe:.rdata", 0x2108, 0x8, "r--"),
                ("pe:.rdata:iat", 0x2110, 0x4, "rw-"),
                ("pe:.rdata", 0x2114, 0xeec, "r--"),
            ]
        );
        // a writable section is left alone
        let data = carve_import_slots(vec![region("pe:.data", 0x2000, 0x1000, "rw-")], &slots, 4);
        assert_eq!(data.len(), 1);
    }
}
