//! PE directories that declare code no call reaches: TLS callbacks and
//! exports.
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
