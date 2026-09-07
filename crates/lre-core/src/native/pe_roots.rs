//! PE directories that name what the loader will fill in: TLS callbacks,
//! exports, and imports.
//!
//! Rules and layouts from the pinned Ghidra sources (Apache-2.0):
//!
//! * `TLSDirectory` reads `AddressOfCallBacks` as the fourth pointer-sized
//!   field, and `TLSDataDirectory.markup` walks at most 20 slots, stops at the
//!   first null and makes each callback an external entry point. The array
//!   holds **virtual addresses**, so a slot's RVA is `value - image_base`.
//! * `ExportDataDirectory.parse` skips `AddressOfFunctions` slots holding RVA
//!   0 -- gaps in the ordinal space -- and marks an RVA that lands *inside*
//!   the export directory as a forwarder: those bytes are a string naming
//!   another library, not code. `PeLoader.processExports` gives every other
//!   export its exported name and makes it an entry point.
use super::{NativeFunction, NativeImport, NativeXref};
use super::pe_unwind::Span;

const MAX_CALLBACKS: usize = 20;

fn file_offset(spans: &[Span], rva: u64) -> Option<usize> {
    spans.iter().find_map(|span| {
        (rva >= span.vaddr && rva - span.vaddr < span.vsize as u64)
            .then(|| span.raw_off.checked_add((rva - span.vaddr) as usize))
            .flatten()
    })
}

fn word(data: &[u8], offset: usize, width: usize) -> Option<u64> {
    let bytes = data.get(offset..offset.checked_add(width)?)?;
    Some(match width {
        8 => u64::from_le_bytes(bytes.try_into().ok()?),
        4 => u64::from(u32::from_le_bytes(bytes.try_into().ok()?)),
        2 => u64::from(u16::from_le_bytes(bytes.try_into().ok()?)),
        _ => return None,
    })
}

fn in_code(import: &NativeImport, address: u64) -> bool {
    import
        .mappings
        .iter()
        .any(|m| m.flags & 4 != 0 && address >= m.vaddr && address - m.vaddr < m.size)
}

fn promote(import: &mut NativeImport, entry: u64, source: u64, name: Option<String>,
           provenance: &'static str) {
    if !in_code(import, entry) {
        return;
    }
    match import.functions.iter_mut().find(|f| f.entry == entry) {
        Some(existing) => {
            // A declared name outranks a generated one; a proven name stands.
            if let Some(name) = name {
                if existing.name.starts_with("FUN_") {
                    existing.name = name;
                }
            }
        }
        None => import.functions.push(NativeFunction {
            entry,
            name: name.unwrap_or_else(|| format!("FUN_{entry:08x}")),
            size: 1,
        }),
    }
    // The slot is relocated too, so a `pe-reloc` reference already says "a
    // pointer lives here". The directory says what the pointer *is*, which is
    // the more specific fact: upgrade rather than duplicate.
    match import
        .xrefs
        .iter_mut()
        .find(|x| x.from == source && x.to == entry)
    {
        Some(existing) => existing.provenance = provenance.into(),
        None => import
            .xrefs
            .push(NativeXref::with_provenance(source, entry, "DATA", provenance)),
    }
}

/// TLS callbacks: `AddressOfCallBacks` is a null-terminated array of VAs.
pub(super) fn collect_tls(
    data: &[u8],
    spans: &[Span],
    import: &mut NativeImport,
    image_base: u64,
    dir_rva: u64,
    dir_size: usize,
    width: usize,
) {
    if dir_rva == 0 || dir_size < 4 * width {
        return;
    }
    let Some(directory) = file_offset(spans, dir_rva) else { return };
    let Some(callbacks_va) = word(data, directory + 3 * width, width) else { return };
    if callbacks_va < image_base {
        return;
    }
    for index in 0..MAX_CALLBACKS {
        let slot_rva = callbacks_va - image_base + (index * width) as u64;
        let Some(slot) = file_offset(spans, slot_rva) else { break };
        let Some(callback) = word(data, slot, width) else { break };
        if callback == 0 {
            break;
        }
        promote(import, callback, image_base + slot_rva, None, "native-import:pe-tls");
    }
}

/// Exports: every non-forwarded `AddressOfFunctions` slot, with its name.
pub(super) fn collect_exports(
    data: &[u8],
    spans: &[Span],
    import: &mut NativeImport,
    image_base: u64,
    dir_rva: u64,
    dir_size: usize,
) {
    if dir_rva == 0 || dir_size < 40 {
        return;
    }
    let Some(header) = file_offset(spans, dir_rva) else { return };
    let read = |offset: usize| word(data, header + offset, 4).map(|value| value as u32);
    let (Some(ordinal_base), Some(count), Some(name_count),
         Some(functions_rva), Some(names_rva), Some(ordinals_rva)) =
        (read(16), read(20), read(24), read(28), read(32), read(36)) else { return };
    let _ = ordinal_base;
    // A count larger than the file cannot be a table; refuse rather than guess.
    if count == 0 || count as usize > data.len() / 4 {
        return;
    }
    let Some(functions) = file_offset(spans, u64::from(functions_rva)) else { return };
    let names = file_offset(spans, u64::from(names_rva));
    let ordinals = file_offset(spans, u64::from(ordinals_rva));
    for index in 0..count as usize {
        let Some(function_rva) = word(data, functions + index * 4, 4) else { break };
        if function_rva == 0 {
            continue; // a gap in the ordinal space
        }
        if function_rva >= dir_rva && function_rva < dir_rva + dir_size as u64 {
            continue; // a forwarder: those bytes are a library name, not code
        }
        let mut name = None;
        if let (Some(names), Some(ordinals)) = (names, ordinals) {
            for position in 0..name_count as usize {
                let Some(ordinal) = word(data, ordinals + position * 2, 2) else { break };
                if ordinal as usize != index {
                    continue;
                }
                let Some(name_rva) = word(data, names + position * 4, 4) else { break };
                if let Some(offset) = file_offset(spans, name_rva) {
                    let bytes = &data[offset..];
                    let end = bytes.iter().position(|&byte| byte == 0).unwrap_or(0);
                    if end > 0 && end < 256 {
                        if let Ok(text) = std::str::from_utf8(&bytes[..end]) {
                            name = Some(text.to_owned());
                        }
                    }
                }
                break;
            }
        }
        promote(
            import,
            image_base + function_rva,
            image_base + u64::from(functions_rva) + (index * 4) as u64,
            name,
            "native-import:pe-export",
        );
    }
}

/// Imports: one external symbol per IAT slot, named as the image imports it.
///
/// From `ImportDataDirectory.parse`, `ImportDescriptor` and `ThunkData`:
/// descriptors are 20 bytes and end when `OriginalFirstThunk` and `FirstThunk`
/// are both zero; the name table is `OriginalFirstThunk` when it maps and
/// `FirstThunk` otherwise; the walk ends at the first zero entry; a thunk with
/// the ordinal flag set imports by ordinal (`Ordinal_<n>`), and otherwise its
/// value is an RVA to `IMAGE_IMPORT_BY_NAME`, whose name follows a two-byte
/// hint. The address an import occupies is its IAT slot, and that slot holds a
/// pointer -- never code.
pub(super) fn collect_imports(
    data: &[u8],
    spans: &[Span],
    import: &mut NativeImport,
    image_base: u64,
    dir_rva: u64,
    dir_size: usize,
    width: usize,
) {
    const DESCRIPTOR: usize = 20;
    // Ghidra's MAX_SANE_COUNT: a table larger than this is corruption.
    const MAX_SANE: usize = 0x2000;
    if dir_rva == 0 || dir_size < DESCRIPTOR {
        return;
    }
    let ordinal_flag = 1u64 << (width * 8 - 1);
    for index in 0..dir_size / DESCRIPTOR {
        let Some(descriptor) = file_offset(spans, dir_rva + (index * DESCRIPTOR) as u64)
        else { break };
        let (Some(original), Some(name_rva), Some(first)) = (
            word(data, descriptor, 4),
            word(data, descriptor + 12, 4),
            word(data, descriptor + 16, 4),
        ) else { break };
        if original == 0 && first == 0 {
            break;
        }
        let names_rva = if original != 0 && file_offset(spans, original).is_some() {
            original
        } else {
            first
        };
        let _ = name_rva; // the library name is not part of the store's model
        for slot in 0..MAX_SANE {
            let Some(entry) = file_offset(spans, names_rva + (slot * width) as u64)
            else { break };
            let Some(value) = word(data, entry, width) else { break };
            if value == 0 {
                break;
            }
            let name = if value & ordinal_flag != 0 {
                format!("Ordinal_{}", value & 0xffff)
            } else {
                // IMAGE_IMPORT_BY_NAME: a two-byte hint, then the name.
                let Some(offset) = file_offset(spans, value + 2) else { continue };
                let bytes = &data[offset..];
                let end = bytes.iter().position(|&byte| byte == 0).unwrap_or(0);
                if end == 0 || end > 256 {
                    continue;
                }
                match std::str::from_utf8(&bytes[..end]) {
                    Ok(text) => text.to_owned(),
                    Err(_) => continue,
                }
            };
            let address = image_base + first + (slot * width) as u64;
            if !import.externals.iter().any(|(at, _)| *at == address) {
                import.externals.push((address, name));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::Mapping;

    fn image() -> (Vec<u8>, Vec<Span>, NativeImport) {
        let mut data = vec![0u8; 0x600];
        let spans = vec![
            Span { vaddr: 0x1000, vsize: 0x100, raw_off: 0x200 }, // .text
            Span { vaddr: 0x2000, vsize: 0x200, raw_off: 0x300 }, // .rdata
        ];
        data[0x200..0x300].fill(0x90);
        let import = NativeImport {
            mappings: vec![Mapping {
                vaddr: 0x400000 + 0x1000,
                size: 0x100,
                file_off: 0x200,
                flags: 0x4,
                bytes: vec![0x90; 0x100],
            }],
            ..Default::default()
        };
        (data, spans, import)
    }

    fn put32(data: &mut [u8], rva: u64, spans: &[Span], value: u32) {
        let offset = file_offset(spans, rva).unwrap();
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn tls_callbacks_stop_at_the_null_terminator() {
        let (mut data, spans, mut import) = image();
        // TLS directory at RVA 0x2000: callbacks VA at 0x400000 + 0x2100.
        put32(&mut data, 0x200c, &spans, 0x402100);
        put32(&mut data, 0x2100, &spans, 0x401010);
        put32(&mut data, 0x2104, &spans, 0x401020);
        put32(&mut data, 0x2108, &spans, 0); // terminator
        put32(&mut data, 0x210c, &spans, 0x401030); // past the terminator
        collect_tls(&data, &spans, &mut import, 0x400000, 0x2000, 24, 4);

        assert_eq!(
            import.functions.iter().map(|f| f.entry).collect::<Vec<_>>(),
            vec![0x401010, 0x401020]
        );
        assert!(import
            .xrefs
            .iter()
            .all(|x| x.provenance == "native-import:pe-tls" && x.kind == "DATA"));
        assert_eq!(import.xrefs[0].from, 0x402100);
    }

    #[test]
    fn exports_carry_their_name_and_skip_gaps_and_forwarders() {
        let (mut data, spans, mut import) = image();
        // Export directory at RVA 0x2000, size 0x80: three slots plus a gap.
        put32(&mut data, 0x2010, &spans, 1); // Base
        put32(&mut data, 0x2014, &spans, 4); // NumberOfFunctions
        put32(&mut data, 0x2018, &spans, 1); // NumberOfNames
        put32(&mut data, 0x201c, &spans, 0x2100); // AddressOfFunctions
        put32(&mut data, 0x2020, &spans, 0x2140); // AddressOfNames
        put32(&mut data, 0x2024, &spans, 0x2150); // AddressOfNameOrdinals
        put32(&mut data, 0x2100, &spans, 0x1040); // exported code
        put32(&mut data, 0x2104, &spans, 0); // gap in the ordinal space
        put32(&mut data, 0x2108, &spans, 0x2060); // forwarder: inside the directory
        put32(&mut data, 0x210c, &spans, 0x1080); // exported code, unnamed
        put32(&mut data, 0x2140, &spans, 0x2160); // name RVA for ordinal 0
        let ordinals = file_offset(&spans, 0x2150).unwrap();
        data[ordinals..ordinals + 2].copy_from_slice(&0u16.to_le_bytes());
        let name = file_offset(&spans, 0x2160).unwrap();
        data[name..name + 5].copy_from_slice(b"boot\0");
        collect_exports(&data, &spans, &mut import, 0x400000, 0x2000, 0x80);

        assert_eq!(
            import
                .functions
                .iter()
                .map(|f| (f.entry, f.name.clone()))
                .collect::<Vec<_>>(),
            vec![
                (0x401040, "boot".to_owned()),
                (0x401080, "FUN_00401080".to_owned())
            ]
        );
        assert!(import
            .xrefs
            .iter()
            .all(|x| x.provenance == "native-import:pe-export"));
        assert_eq!(import.xrefs[0].from, 0x402100);
        assert_eq!(import.xrefs[1].from, 0x40210c);
    }

    #[test]
    fn imports_name_their_iat_slots_by_name_and_by_ordinal() {
        let (mut data, spans, mut import) = image();
        // One descriptor at RVA 0x2000: INT at 0x2100, IAT at 0x2120.
        put32(&mut data, 0x2000, &spans, 0x2100); // OriginalFirstThunk
        put32(&mut data, 0x2004, &spans, 0); // TimeDateStamp: not bound
        put32(&mut data, 0x200c, &spans, 0x2180); // Name
        put32(&mut data, 0x2010, &spans, 0x2120); // FirstThunk
        put32(&mut data, 0x2100, &spans, 0x21a0); // by name
        put32(&mut data, 0x2104, &spans, 0x8000_0007); // by ordinal 7
        put32(&mut data, 0x2108, &spans, 0); // terminator
        let name = file_offset(&spans, 0x21a0).unwrap();
        data[name..name + 2].copy_from_slice(&9u16.to_le_bytes()); // hint
        data[name + 2..name + 8].copy_from_slice(b"Sleep\0");
        collect_imports(&data, &spans, &mut import, 0x400000, 0x2000, 40, 4);

        assert_eq!(
            import.externals,
            vec![
                (0x402120, "Sleep".to_owned()),
                (0x402124, "Ordinal_7".to_owned())
            ]
        );
        // A slot holds a pointer, so nothing is promoted to code.
        assert!(import.functions.is_empty());
    }

    #[test]
    fn directories_outside_the_image_and_absurd_counts_are_refused() {
        let (mut data, spans, mut import) = image();
        collect_tls(&data, &spans, &mut import, 0x400000, 0x9000, 24, 4);
        collect_exports(&data, &spans, &mut import, 0x400000, 0x9000, 0x80);
        assert!(import.functions.is_empty() && import.xrefs.is_empty());

        // A callback array below the image base is not an address array.
        put32(&mut data, 0x200c, &spans, 0x40);
        collect_tls(&data, &spans, &mut import, 0x400000, 0x2000, 24, 4);
        assert!(import.functions.is_empty());

        // A function count larger than the file cannot be a table.
        put32(&mut data, 0x2014, &spans, 0xffff_ffff);
        put32(&mut data, 0x201c, &spans, 0x2100);
        collect_exports(&data, &spans, &mut import, 0x400000, 0x2000, 0x80);
        assert!(import.functions.is_empty());
    }
}
