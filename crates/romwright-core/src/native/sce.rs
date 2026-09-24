//! SCE module metadata for PS Vita ELFs (`e_type` 0xfe00, `ET_SCE_EXEC`).
//!
//! Stock Ghidra ships no SCE loader extension; the layout here follows
//! vita-toolchain's `sce-elf-defs.h` / `sce-elf.c`, which is the format's
//! reference implementation:
//!
//! * `e_entry` is not a code address: `(segndx & 3) << 30 | segoffset`
//!   locates `sce_module_info` inside its PT_LOAD segment
//!   (`sce_elf_write_module_info`, sce-elf.c:1108).
//! * `sce_module_info` carries *segment offsets* for `export_top`,
//!   `export_end`, `import_top`, `import_end`, `module_start`,
//!   `module_stop` (CONVERTOFFSET, sce-elf.c:617) — resolved against the
//!   segment `e_entry` names.
//! * `sce_module_exports` / `sce_module_imports` entries carry absolute
//!   vaddrs for their name, NID table and entry table pointers
//!   (SETLOCALPTR / `vita_elf_host_to_vaddr`, sce-elf.c:900-950).
//! * Export NIDs are the module's public face: `module_start`,
//!   `module_stop`, `module_exit`, `module_info`, `module_proc_param`
//!   have fixed NIDs (sce-elf.h:29-35). Import NIDs name the stub the
//!   kernel patches; without a NID database they seed as
//!   `sce_import_<lib>_<nid>` and a BINMAP (`--map`) renames them.

use super::{ImportError, NativeContext, NativeFunction, NativeImport, Result};

fn bad(message: &str) -> ImportError {
    ImportError::Bad(message.into())
}

/// `e_type` for a Vita module image (ET_SCE_EXEC in vita-toolchain).
const ET_SCE_EXEC: u16 = 0xfe00;

/// Fixed NIDs of the main module export (vita-toolchain sce-elf.h:29-35).
pub(super) const MODULE_NIDS: &[(u32, &str)] = &[
    (0x935cd196, "module_start"),
    (0x79f8e492, "module_stop"),
    (0x913482a9, "module_exit"),
    (0x5c424d40, "module_bootstart"),
    (0x6c2224ba, "module_info"),
    (0x70fba1e7, "module_proc_param"),
    (0x936c8a78, "module_sdk_version"),
];

fn module_nid_name(nid: u32) -> Option<&'static str> {
    MODULE_NIDS.iter().find(|(n, _)| *n == nid).map(|(_, name)| *name)
}

/// One PT_LOAD program header, the fields SCE resolution needs.
struct LoadSegment {
    offset: u64,
    vaddr: u64,
    filesz: u64,
    memsz: u64,
    exec: bool,
}

fn load_segments(data: &[u8], be: bool) -> Result<Vec<LoadSegment>> {
    let mut segments = Vec::new();
    for header in super::elf_image::program_headers(data, 4, be)? {
        if super::elf_image::word(header, 0, 4, be)? != 1 {
            continue;
        }
        let permissions = super::elf_image::word(header, 24, 4, be)?;
        segments.push(LoadSegment {
            offset: super::elf_image::word(header, 4, 4, be)?,
            vaddr: super::elf_image::word(header, 8, 4, be)?,
            filesz: super::elf_image::word(header, 16, 4, be)?,
            memsz: super::elf_image::word(header, 20, 4, be)?,
            exec: permissions & 1 != 0,
        });
    }
    Ok(segments)
}

fn u16_at(data: &[u8], offset: usize, be: bool) -> Result<u16> {
    let end = offset.checked_add(2).ok_or_else(|| bad("SCE field overflow"))?;
    let bytes = data.get(offset..end).ok_or_else(|| bad("truncated SCE table"))?;
    Ok(if be {
        u16::from_be_bytes([bytes[0], bytes[1]])
    } else {
        u16::from_le_bytes([bytes[0], bytes[1]])
    })
}

fn u32_at(data: &[u8], offset: usize, be: bool) -> Result<u32> {
    let end = offset.checked_add(4).ok_or_else(|| bad("SCE field overflow"))?;
    let bytes = data.get(offset..end).ok_or_else(|| bad("truncated SCE table"))?;
    Ok(if be {
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    } else {
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    })
}

fn cstr_at(data: &[u8], offset: usize) -> String {
    data.get(offset..)
        .and_then(|rest| rest.split(|byte| *byte == 0).next())
        .map(|raw| String::from_utf8_lossy(raw).into_owned())
        .unwrap_or_default()
}

/// A vaddr inside a PT_LOAD's file-backed extent, as a file offset.
fn vaddr_to_file(segments: &[LoadSegment], vaddr: u64) -> Option<usize> {
    let segment = segments
        .iter()
        .find(|segment| vaddr >= segment.vaddr && vaddr - segment.vaddr < segment.filesz)?;
    usize::try_from(segment.offset + (vaddr - segment.vaddr)).ok()
}

/// A segment offset inside `segment`, as a file offset.
fn segoff_to_file(segment: &LoadSegment, segoff: u64) -> Option<usize> {
    if segoff >= segment.filesz {
        return None;
    }
    usize::try_from(segment.offset + segoff).ok()
}

/// Seed a named function entry, Thumb context included: Vita modules are
/// Thumb-only, and the export/import tables tag code entries with the low
/// bit exactly like ELF `st_value` does.
fn seed_function(
    import: &mut NativeImport,
    entry: u64,
    name: String,
    seeded: &mut std::collections::HashSet<u64>,
) {
    let entry = entry & !1;
    if entry == 0 || !seeded.insert(entry) {
        return;
    }
    import.contexts.push(NativeContext {
        name: "TMode".into(),
        address: entry,
        value: 1,
    });
    import.functions.push(NativeFunction {
        entry,
        name,
        size: 1,
    });
    if !import.symbol_named.contains(&entry) {
        import.symbol_named.push(entry);
    }
}

/// Parse `sce_module_info` and its export/import tables into the import.
/// Returns without error on anything that fails the format's own sanity
/// checks: a malformed SCE block must not sink an otherwise loadable ELF.
pub(super) fn collect(data: &[u8], be: bool, e_type: u16, e_entry: u64, import: &mut NativeImport) -> Result<()> {
    if e_type != ET_SCE_EXEC {
        return Ok(());
    }
    let segments = load_segments(data, be)?;
    let segndx = (e_entry >> 30) as usize;
    let segoff = e_entry & 0x3fffffff;
    let Some(segment) = segments.get(segndx) else {
        return Ok(());
    };
    let Some(info_off) = segoff_to_file(segment, segoff) else {
        return Ok(());
    };
    // sce_module_info: u16 attributes, u16 version, char name[27], u8 type,
    // then u32 fields. The name is the strongest format proof available.
    let name = cstr_at(data, info_off + 4);
    if name.len() > 26
        || name.is_empty()
        || !name.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
    {
        return Ok(());
    }
    let field = |index: usize| -> Result<u32> { u32_at(data, info_off + 32 + index * 4, be) };
    let export_top = field(1)? as u64;
    let export_end = field(2)? as u64;
    let import_top = field(3)? as u64;
    let import_end = field(4)? as u64;
    let module_start = field(9)? as u64;
    let module_stop = field(10)? as u64;
    if export_end < export_top || import_end < import_top {
        return Ok(());
    }
    let seg_vaddr = |segoff: u64| segment.vaddr + segoff;

    let mut seeded: std::collections::HashSet<u64> =
        import.functions.iter().map(|f| f.entry).collect();

    // module_start/module_stop are the process entry points of a module;
    // 0xffffffff marks them absent (sce-elf.c:851-858).
    if module_start != 0xffff_ffff && module_start < segment.memsz {
        import.process_entry = Some(seg_vaddr(module_start) & !1);
        seed_function(import, seg_vaddr(module_start), "module_start".into(), &mut seeded);
    }
    if module_stop != 0xffff_ffff && module_stop < segment.memsz {
        seed_function(import, seg_vaddr(module_stop), "module_stop".into(), &mut seeded);
    }


    // Export table: 0x20-byte sce_module_exports entries.
    let mut cursor = export_top;
    while cursor + 0x20 <= export_end {
        let Some(off) = segoff_to_file(segment, cursor) else {
            break;
        };
        let size = u16_at(data, off, be)? as u64;
        if size < 0x20 {
            break;
        }
        let num_funcs = u16_at(data, off + 6, be)? as u64;
        let num_vars = u32_at(data, off + 8, be)? as u64;
        let num_tls = u32_at(data, off + 12, be)? as u64;
        let nid_table = u32_at(data, off + 24, be)? as u64;
        let entry_table = u32_at(data, off + 28, be)? as u64;
        let total = num_funcs + num_vars + num_tls;
        if total > 0x10000 {
            break;
        }
        if let (Some(nids_off), Some(entries_off)) = (
            vaddr_to_file(&segments, nid_table),
            vaddr_to_file(&segments, entry_table),
        ) {
            for i in 0..total {
                let nid = u32_at(data, nids_off + (i * 4) as usize, be)?;
                let entry = u32_at(data, entries_off + (i * 4) as usize, be)? as u64;
                if entry == 0 {
                    continue;
                }
                let known = module_nid_name(nid);
                if i < num_funcs {
                    let name = known
                        .map(str::to_owned)
                        .unwrap_or_else(|| format!("sce_export_{nid:08x}"));
                    seed_function(import, entry, name, &mut seeded);
                } else {
                    // Variable exports name data, not code.
                    let name = known
                        .map(str::to_owned)
                        .unwrap_or_else(|| format!("sce_export_{nid:08x}"));
                    let address = entry & !1;
                    import.object_names.push((address, name));
                }
            }
        }
        cursor += size;
    }

    // Import table: 0x34-byte (or short 0x24) sce_module_imports entries.
    // Each function NID pairs with the stub the kernel patches; the stub
    // is a function in this image and an external symbol by name.
    let mut cursor = import_top;
    while cursor + 0x24 <= import_end {
        let Some(off) = segoff_to_file(segment, cursor) else {
            break;
        };
        let size = u16_at(data, off, be)? as u64;
        if !matches!(size, 0x24 | 0x34) {
            break;
        }
        let num_funcs = u16_at(data, off + 6, be)? as u64;
        let num_vars = u16_at(data, off + 8, be)? as u64;
        let (libname_vaddr, func_nid_table, func_entry_table, var_nid_table, var_entry_table) =
            if size == 0x34 {
                (
                    u32_at(data, off + 20, be)? as u64,
                    u32_at(data, off + 28, be)? as u64,
                    u32_at(data, off + 32, be)? as u64,
                    u32_at(data, off + 36, be)? as u64,
                    u32_at(data, off + 40, be)? as u64,
                )
            } else {
                (
                    u32_at(data, off + 16, be)? as u64,
                    u32_at(data, off + 20, be)? as u64,
                    u32_at(data, off + 24, be)? as u64,
                    u32_at(data, off + 28, be)? as u64,
                    u32_at(data, off + 32, be)? as u64,
                )
            };
        let libname = if libname_vaddr != 0 {
            vaddr_to_file(&segments, libname_vaddr)
                .map(|o| cstr_at(data, o))
                .unwrap_or_default()
        } else {
            String::new()
        };
        if num_funcs > 0x4000 || num_vars > 0x4000 {
            break;
        }
        if let (Some(nids_off), Some(entries_off)) = (
            vaddr_to_file(&segments, func_nid_table),
            vaddr_to_file(&segments, func_entry_table),
        ) {
            for i in 0..num_funcs as usize {
                let nid = u32_at(data, nids_off + i * 4, be)?;
                let stub = u32_at(data, entries_off + i * 4, be)? as u64 & !1;
                if stub == 0 {
                    continue;
                }
                let name = if libname.is_empty() {
                    format!("sce_import_{nid:08x}")
                } else {
                    format!("sce_import_{libname}_{nid:08x}")
                };
                seed_function(import, stub, name.clone(), &mut seeded);
                import.externals.push((stub, name));
            }
        }
        if let (Some(nids_off), Some(entries_off)) = (
            vaddr_to_file(&segments, var_nid_table),
            vaddr_to_file(&segments, var_entry_table),
        ) {
            for i in 0..num_vars as usize {
                let nid = u32_at(data, nids_off + i * 4, be)?;
                let slot = u32_at(data, entries_off + i * 4, be)? as u64;
                if slot == 0 {
                    continue;
                }
                let name = if libname.is_empty() {
                    format!("sce_import_var_{nid:08x}")
                } else {
                    format!("sce_import_var_{libname}_{nid:08x}")
                };
                import.externals.push((slot, name));
            }
        }
        cursor += size;
    }

    // Every PT_LOAD with the execute bit is Thumb code on Vita: declare it
    // once at each segment start so discovery never tries ARM there.
    for segment in &segments {
        if segment.exec && segment.memsz != 0 {
            import.contexts.push(NativeContext {
                name: "TMode".into(),
                address: segment.vaddr,
                value: 1,
            });
        }
    }
    import.functions.sort_by_key(|f| f.entry);
    Ok(())
}

#[cfg(test)]
mod tests {
    /// A minimal sectionless SCE ELF32: one PT_LOAD at 0x81000000 holding
    /// `sce_module_info` (e_entry = its segment offset), one export entry
    /// naming module_start, and one SceLibc import with one function NID.
    fn sce_elf() -> Vec<u8> {
        const BASE: u32 = 0x8100_0000;
        const SEG_OFF: usize = 0x100;
        const INFO: usize = SEG_OFF + 0x40; // module_info file offset
        const EXPORT: usize = SEG_OFF + 0xa0;
        const IMPORT: usize = SEG_OFF + 0xc0;
        const NIDTAB: usize = SEG_OFF + 0x100;
        const ENTTAB: usize = SEG_OFF + 0x110;
        const FNID: usize = SEG_OFF + 0x120;
        const FSTUB: usize = SEG_OFF + 0x130;
        const LIBNAME: usize = SEG_OFF + 0x140;
        const START: usize = SEG_OFF + 0x160; // module_start code
        let mut data = vec![0u8; SEG_OFF + 0x200];
        // ELF header: ELF32 LE, e_type 0xfe00, ARM, e_entry = segndx 0 |
        // segoffset of module_info.
        data[..4].copy_from_slice(b"\x7fELF");
        data[4] = 1;
        data[5] = 1;
        data[6] = 1;
        data[16..18].copy_from_slice(&0xfe00u16.to_le_bytes());
        data[18..20].copy_from_slice(&40u16.to_le_bytes()); // EM_ARM
        data[24..28].copy_from_slice(&((INFO - SEG_OFF) as u32).to_le_bytes());
        data[28..32].copy_from_slice(&52u32.to_le_bytes()); // e_phoff
        data[40..42].copy_from_slice(&52u16.to_le_bytes()); // e_ehsize
        data[42..44].copy_from_slice(&32u16.to_le_bytes()); // e_phentsize
        data[44..46].copy_from_slice(&1u16.to_le_bytes()); // e_phnum
        // PT_LOAD: offset SEG_OFF, vaddr BASE, filesz = memsz = 0x200, R E.
        let ph = 52;
        data[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes());
        data[ph + 4..ph + 8].copy_from_slice(&(SEG_OFF as u32).to_le_bytes());
        data[ph + 8..ph + 12].copy_from_slice(&BASE.to_le_bytes());
        data[ph + 16..ph + 20].copy_from_slice(&0x200u32.to_le_bytes());
        data[ph + 20..ph + 24].copy_from_slice(&0x200u32.to_le_bytes());
        data[ph + 24..ph + 28].copy_from_slice(&5u32.to_le_bytes());
        // sce_module_info: version 0x0101, name, type 6, export/import
        // ranges as segment offsets, module_start segoffset.
        data[INFO + 2..INFO + 4].copy_from_slice(&0x0101u16.to_le_bytes());
        data[INFO + 4..INFO + 4 + 9].copy_from_slice(b"TestMod\0\0");
        data[INFO + 31] = 6;
        let put = |off: usize, value: u32, data: &mut [u8]| {
            data[off..off + 4].copy_from_slice(&value.to_le_bytes());
        };
        put(INFO + 36, (EXPORT - SEG_OFF) as u32, &mut data); // export_top
        put(INFO + 40, (EXPORT + 0x20 - SEG_OFF) as u32, &mut data); // export_end
        put(INFO + 44, (IMPORT - SEG_OFF) as u32, &mut data); // import_top
        put(INFO + 48, (IMPORT + 0x34 - SEG_OFF) as u32, &mut data); // import_end
        put(INFO + 52, 0x11223344, &mut data); // module_nid
        put(INFO + 68, (START - SEG_OFF) as u32 | 1, &mut data); // module_start
        put(INFO + 72, 0xffff_ffff, &mut data); // module_stop absent
        // sce_module_exports: size 0x20, flags 0x8000, 1 func + 1 var.
        data[EXPORT..EXPORT + 2].copy_from_slice(&0x20u16.to_le_bytes());
        data[EXPORT + 6..EXPORT + 8].copy_from_slice(&1u16.to_le_bytes());
        put(EXPORT + 8, 1, &mut data); // num_syms_vars
        put(EXPORT + 24, BASE + (NIDTAB - SEG_OFF) as u32, &mut data);
        put(EXPORT + 28, BASE + (ENTTAB - SEG_OFF) as u32, &mut data);
        put(NIDTAB, 0x935c_d196, &mut data); // module_start NID
        put(NIDTAB + 4, 0x6c22_24ba, &mut data); // module_info NID
        put(ENTTAB, BASE + (START - SEG_OFF) as u32 | 1, &mut data);
        put(ENTTAB + 4, BASE + (INFO - SEG_OFF) as u32, &mut data);
        // sce_module_imports: size 0x34, 1 func, libname "SceLibc".
        data[IMPORT..IMPORT + 2].copy_from_slice(&0x34u16.to_le_bytes());
        data[IMPORT + 2..IMPORT + 4].copy_from_slice(&1u16.to_le_bytes());
        data[IMPORT + 6..IMPORT + 8].copy_from_slice(&1u16.to_le_bytes());
        put(IMPORT + 20, BASE + (LIBNAME - SEG_OFF) as u32, &mut data);
        put(IMPORT + 28, BASE + (FNID - SEG_OFF) as u32, &mut data);
        put(IMPORT + 32, BASE + (FSTUB - SEG_OFF) as u32, &mut data);
        put(FNID, 0x0056_061b, &mut data); // ldexp's NID
        put(FSTUB, BASE + (SEG_OFF + 0x180 - SEG_OFF) as u32, &mut data);
        data[LIBNAME..LIBNAME + 8].copy_from_slice(b"SceLibc\0");
        data
    }

    #[test]
    fn sce_module_tables_seed_named_entries() {
        let import = crate::native::import_elf(&sce_elf()).expect("sce elf");
        assert_eq!(import.format, "elf32");
        assert_eq!(import.process_entry, Some(0x8100_0160));
        let names: std::collections::HashMap<u64, &str> = import
            .functions
            .iter()
            .map(|f| (f.entry, f.name.as_str()))
            .collect();
        assert_eq!(names.get(&0x8100_0160), Some(&"module_start"));
        assert_eq!(
            names.get(&0x8100_0180),
            Some(&"sce_import_SceLibc_0056061b")
        );
        assert!(import
            .externals
            .iter()
            .any(|(slot, name)| *slot == 0x8100_0180
                && name == "sce_import_SceLibc_0056061b"));
        assert!(import
            .object_names
            .iter()
            .any(|(address, name)| *address == 0x8100_0040 && name == "module_info"));
        assert!(import
            .contexts
            .iter()
            .any(|c| c.name == "TMode" && c.address == 0x8100_0000 && c.value == 1));
    }

    #[test]
    fn non_sce_etypes_are_untouched() {
        let mut data = sce_elf();
        data[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        let import = crate::native::import_elf(&data).expect("elf");
        assert!(import.functions.is_empty());
        assert_eq!(import.process_entry, Some(0x40));
    }
}
