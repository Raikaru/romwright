//! PE exception directory function starts: `IMAGE_DIRECTORY_ENTRY_EXCEPTION`
//! records the bounds of every function the compiler gave unwind data, which
//! is how a stripped PE32+ names functions no call reaches.
//!
//! Layout and promotion rule from the pinned Ghidra sources (Apache-2.0):
//! `ImageRuntimeFunctionEntries_X86` reads 12-byte `RUNTIME_FUNCTION`
//! records (`BeginAddress`, `EndAddress`, `UnwindInfoAddressOrData`) and marks
//! a function at `ImageBase + BeginAddress` when
//! `beginAddress != 0 && (unwindInfo == null || !unwindInfo.hasChainedUnwindInfo())`.
//! `PEx64UnwindInfo` splits the first byte into `version = b & 0x7` and
//! `flags = (b >> 3) & 0x1f`, with `UNW_FLAG_CHAININFO = 0x4`: a chained record
//! describes a fragment of another function, not a function of its own.
use super::{NativeFunction, NativeImport, NativeXref};

const ENTRY_SIZE: usize = 0x0C;
const UNW_FLAG_CHAININFO: u8 = 0x4;

/// A section as the PE loader sees it: where it lands and where its bytes are.
pub(super) struct Span {
    pub vaddr: u64,
    pub vsize: usize,
    pub raw_off: usize,
}

fn file_offset(spans: &[Span], rva: u64) -> Option<usize> {
    spans.iter().find_map(|span| {
        (rva >= span.vaddr && rva - span.vaddr < span.vsize as u64)
            .then(|| span.raw_off.checked_add((rva - span.vaddr) as usize))
            .flatten()
    })
}

fn u32_le(data: &[u8], offset: usize) -> Option<u32> {
    data.get(offset..offset + 4)
        .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
}

/// Promote every non-chained `RUNTIME_FUNCTION` start that lands in code.
pub(super) fn collect(
    data: &[u8],
    spans: &[Span],
    import: &mut NativeImport,
    image_base: u64,
    dir_rva: u64,
    dir_size: usize,
) {
    if dir_rva == 0 || dir_size < ENTRY_SIZE {
        return;
    }
    let Some(table) = file_offset(spans, dir_rva) else { return };
    for index in 0..dir_size / ENTRY_SIZE {
        let record = table + index * ENTRY_SIZE;
        let Some(begin) = u32_le(data, record) else { break };
        let Some(unwind) = u32_le(data, record + 8) else { break };
        if begin == 0 {
            continue;
        }
        // A chained record continues a function that already has a start.
        if unwind != 0 {
            if let Some(flags) = file_offset(spans, u64::from(unwind))
                .and_then(|offset| data.get(offset).copied())
                .map(|split| (split >> 3) & 0x1f)
            {
                if flags & UNW_FLAG_CHAININFO != 0 {
                    continue;
                }
            }
        }
        let entry = image_base.wrapping_add(u64::from(begin));
        if !import
            .mappings
            .iter()
            .any(|m| m.flags & 4 != 0 && entry >= m.vaddr && entry - m.vaddr < m.size)
        {
            continue;
        }
        if !import.functions.iter().any(|f| f.entry == entry) {
            import.functions.push(NativeFunction {
                entry,
                name: format!("FUN_{entry:08x}"),
                size: 1,
            });
        }
        let source = image_base.wrapping_add(dir_rva).wrapping_add((index * ENTRY_SIZE) as u64);
        import
            .xrefs
            .push(NativeXref::with_provenance(source, entry, "DATA", "native-import:pe-unwind"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::Mapping;

    fn image(code_size: usize) -> (Vec<u8>, Vec<Span>, NativeImport) {
        let mut data = vec![0u8; 0x400];
        // .text at RVA 0x1000 from file offset 0x200, .pdata at 0x2000 from 0x300.
        let spans = vec![
            Span { vaddr: 0x1000, vsize: code_size, raw_off: 0x200 },
            Span { vaddr: 0x2000, vsize: 0x100, raw_off: 0x300 },
        ];
        data[0x200..0x210].fill(0x90);
        let import = NativeImport {
            mappings: vec![Mapping {
                vaddr: 0x140001000,
                size: code_size as u64,
                file_off: 0x200,
                flags: 0x4,
                bytes: vec![0x90; code_size],
            }],
            ..Default::default()
        };
        (data, spans, import)
    }

    fn write_record(data: &mut [u8], slot: usize, begin: u32, end: u32, unwind: u32) {
        let at = 0x300 + slot * ENTRY_SIZE;
        data[at..at + 4].copy_from_slice(&begin.to_le_bytes());
        data[at + 4..at + 8].copy_from_slice(&end.to_le_bytes());
        data[at + 8..at + 12].copy_from_slice(&unwind.to_le_bytes());
    }

    #[test]
    fn promotes_plain_records_and_skips_chained_fragments() {
        let (mut data, spans, mut import) = image(0x100);
        // Unwind info at RVA 0x2080: version 1, no flags -> a real function.
        data[0x380] = 0x01;
        // Unwind info at RVA 0x2090: UNW_FLAG_CHAININFO -> a fragment.
        data[0x390] = 0x01 | (u8::from(UNW_FLAG_CHAININFO) << 3);
        write_record(&mut data, 0, 0x1000, 0x1010, 0x2080);
        write_record(&mut data, 1, 0x1020, 0x1030, 0x2090);
        write_record(&mut data, 2, 0x1040, 0x1050, 0); // no unwind data: still a function
        write_record(&mut data, 3, 0, 0, 0); // padding record
        collect(&data, &spans, &mut import, 0x140000000, 0x2000, 4 * ENTRY_SIZE);

        let entries: Vec<u64> = import.functions.iter().map(|f| f.entry).collect();
        assert_eq!(entries, vec![0x140001000, 0x140001040]);
        assert!(import
            .xrefs
            .iter()
            .all(|x| x.provenance == "native-import:pe-unwind" && x.kind == "DATA"));
        assert_eq!(import.xrefs.len(), 2);
        // The reference is the record that proved it, not the function itself.
        assert_eq!(import.xrefs[0].from, 0x140002000);
        assert_eq!(import.xrefs[1].from, 0x140002000 + 2 * ENTRY_SIZE as u64);
    }

    #[test]
    fn ignores_records_outside_code_and_unreadable_tables() {
        let (mut data, spans, mut import) = image(0x100);
        write_record(&mut data, 0, 0x9000, 0x9010, 0); // outside every mapping
        collect(&data, &spans, &mut import, 0x140000000, 0x2000, ENTRY_SIZE);
        assert!(import.functions.is_empty() && import.xrefs.is_empty());

        // A directory the section table cannot resolve yields nothing.
        collect(&data, &spans, &mut import, 0x140000000, 0x7000, 4 * ENTRY_SIZE);
        assert!(import.functions.is_empty());

        // A size smaller than one record is not a table.
        write_record(&mut data, 0, 0x1000, 0x1010, 0);
        collect(&data, &spans, &mut import, 0x140000000, 0x2000, 4);
        assert!(import.functions.is_empty());
    }

    #[test]
    fn truncated_table_stops_at_the_last_whole_record() {
        let (mut data, spans, mut import) = image(0x100);
        write_record(&mut data, 0, 0x1000, 0x1010, 0);
        // Claim far more records than the file holds.
        collect(&data, &spans, &mut import, 0x140000000, 0x2000, 0x4000);
        assert_eq!(import.functions.len(), 1);
    }
}
