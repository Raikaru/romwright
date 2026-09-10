//! Nintendo Switch NSO0 modules.
//!
//! An NSO is three segments -- text, rodata, data -- each optionally
//! LZ4-block-compressed, with a header that says where each one goes in
//! memory (switchbrew "NSO"). Nothing in the file is an ELF, but the module
//! carries ELF machinery inside it: a `MOD0` header whose second word the
//! text segment's second word points at, and through it a standard ELF64
//! dynamic table with `DT_SYMTAB`, `DT_STRTAB`, `DT_RELA` and friends. So a
//! retail module usually still names its own functions.
//!
//! The layout facts here are the loader's, checked against the Ghidra
//! extension that already reads this format (Adubbz, `Ghidra-Switch-Loader`,
//! ISC; `NSO0Header.readHeader`, `NSO0Adapter.read`, `MOD0Adapter.getMOD0`
//! and `ElfCompatibilityProvider.getSymbolTable`) so an import lands at the
//! same addresses the oracle's does:
//!
//! - the image is assembled as one buffer of `data.memory_offset +
//!   data.size` bytes with each segment written at its memory offset;
//! - the module is mapped at `0x71_0000_0000` for AArch64, which is where
//!   `SwitchLoader.load` puts a 64-bit module;
//! - the `MOD0` offset is the unsigned word at text offset 4;
//! - the symbol table's length comes from `nchain` in `DT_HASH`, or from the
//!   string table's start when the symbol table precedes it.

use std::collections::HashMap;

use super::{
    DeclaredRegion, Mapping, MemoryRelocation, NamedRelocation, NativeFunction, NativeImport,
    Result,
};

/// Where a 64-bit module is mapped (`SwitchLoader.load`).
const BASE: u64 = 0x71_0000_0000;
/// Header length up to and including the compressed sizes.
const HEADER_LEN: usize = 0x6C;
/// `flags` bit 7: the segments are ZBIC-compressed rather than LZ4, which is
/// a different codec and is refused by name rather than mis-decoded.
const FLAG_ZBIC: u32 = 0x80;

/// One segment as the header describes it.
#[derive(Clone, Copy, Debug)]
struct Segment {
    file_offset: u32,
    memory_offset: u32,
    size: u32,
    compressed_size: u32,
    compressed: bool,
}

fn word(data: &[u8], offset: usize) -> Option<u32> {
    data.get(offset..offset + 4)
        .map(|bytes| u32::from_le_bytes(bytes.try_into().expect("four bytes")))
}

fn quad(data: &[u8], offset: usize) -> Option<u64> {
    data.get(offset..offset + 8)
        .map(|bytes| u64::from_le_bytes(bytes.try_into().expect("eight bytes")))
}

/// The three segment headers, when `data` starts with an NSO0 header.
fn header(data: &[u8]) -> Option<[Segment; 3]> {
    if data.len() < HEADER_LEN || !data.starts_with(b"NSO0") {
        return None;
    }
    let flags = word(data, 0x0C)?;
    let mut segments = [Segment {
        file_offset: 0,
        memory_offset: 0,
        size: 0,
        compressed_size: 0,
        compressed: false,
    }; 3];
    // text at 0x10, rodata at 0x20, data at 0x30; compressed sizes at 0x60.
    for (index, at) in [0x10usize, 0x20, 0x30].into_iter().enumerate() {
        segments[index] = Segment {
            file_offset: word(data, at)?,
            memory_offset: word(data, at + 4)?,
            size: word(data, at + 8)?,
            compressed_size: word(data, 0x60 + index * 4)?,
            compressed: flags & (1 << index) != 0,
        };
    }
    Some(segments)
}

/// True when `data` is an NSO0 module this loader can assemble.
pub(crate) fn is_module(data: &[u8]) -> bool {
    let Some(segments) = header(data) else {
        return false;
    };
    // Every segment must lie inside the file and inside a plausible image.
    segments.iter().all(|segment| {
        let stored = if segment.compressed {
            segment.compressed_size
        } else {
            segment.size
        } as usize;
        u64::from(segment.memory_offset) + u64::from(segment.size) < u64::from(u32::MAX)
            && segment.file_offset as usize + stored <= data.len()
    }) && segments[2].memory_offset >= segments[0].memory_offset
}

/// Decompresses one LZ4 block into `out_len` bytes.
///
/// The block format is a sequence of sequences: a token byte whose high
/// nibble is the literal length and whose low nibble is the match length,
/// each extended by 255-valued bytes when the nibble is 15; the literals;
/// then a little-endian 16-bit match offset, counted back from the current
/// output position, with the match length biased by 4 (LZ4 block format
/// specification, "Sequence"). A truncated or out-of-range block is refused
/// rather than partially applied.
fn lz4_block(input: &[u8], out_len: usize) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(out_len);
    let mut cursor = 0usize;
    while cursor < input.len() {
        let token = *input.get(cursor)?;
        cursor += 1;
        let mut literals = usize::from(token >> 4);
        if literals == 15 {
            loop {
                let extra = *input.get(cursor)?;
                cursor += 1;
                literals += usize::from(extra);
                if extra != 0xFF {
                    break;
                }
            }
        }
        if literals > 0 {
            let end = cursor.checked_add(literals)?;
            out.extend_from_slice(input.get(cursor..end)?);
            cursor = end;
        }
        if out.len() >= out_len {
            break;
        }
        // The last sequence carries literals only; its offset field is
        // absent, which is what ends the block.
        if cursor + 2 > input.len() {
            break;
        }
        let offset = usize::from(u16::from_le_bytes([input[cursor], input[cursor + 1]]));
        cursor += 2;
        if offset == 0 || offset > out.len() {
            return None;
        }
        let mut length = usize::from(token & 0x0F);
        if length == 15 {
            loop {
                let extra = *input.get(cursor)?;
                cursor += 1;
                length += usize::from(extra);
                if extra != 0xFF {
                    break;
                }
            }
        }
        length += 4;
        // Matches may overlap their own output, so the copy is byte at a
        // time: this is the run-length case the format relies on.
        let mut from = out.len() - offset;
        for _ in 0..length {
            let byte = out[from];
            out.push(byte);
            from += 1;
        }
    }
    (out.len() == out_len).then_some(out)
}

/// Assembles the module image: every segment decompressed and placed at its
/// memory offset, `bss` left as the zeroes the buffer already holds.
fn assemble(data: &[u8], segments: &[Segment; 3]) -> Result<Vec<u8>> {
    let end = segments[2]
        .memory_offset
        .checked_add(segments[2].size)
        .ok_or_else(|| super::ImportError::Bad("NSO image overflows".into()))?
        as usize;
    let mut image = vec![0u8; end];
    for segment in segments {
        let stored = if segment.compressed {
            segment.compressed_size
        } else {
            segment.size
        } as usize;
        let from = segment.file_offset as usize;
        let bytes = data
            .get(from..from + stored)
            .ok_or_else(|| super::ImportError::Bad("truncated NSO segment".into()))?;
        let decompressed = if segment.compressed {
            lz4_block(bytes, segment.size as usize).ok_or_else(|| {
                super::ImportError::Bad(format!(
                    "NSO segment at {:#x} did not decompress to {} bytes",
                    segment.file_offset, segment.size
                ))
            })?
        } else {
            bytes.to_vec()
        };
        let at = segment.memory_offset as usize;
        image
            .get_mut(at..at + decompressed.len())
            .ok_or_else(|| super::ImportError::Bad("NSO segment outside the image".into()))?
            .copy_from_slice(&decompressed);
    }
    Ok(image)
}

/// The dynamic table the module carries, as tag -> value.
fn dynamic(image: &[u8], text_offset: u32) -> Option<HashMap<u64, u64>> {
    let mod0 = word(image, text_offset as usize + 4)? as usize;
    if image.get(mod0..mod0 + 4)? != b"MOD0" {
        return None;
    }
    // Every MOD0 field is relative to the header itself.
    let dynamic_offset = mod0.checked_add(word(image, mod0 + 4)? as usize)?;
    let mut tags = HashMap::new();
    let mut cursor = dynamic_offset;
    loop {
        let tag = quad(image, cursor)?;
        let value = quad(image, cursor + 8)?;
        if tag == 0 {
            break;
        }
        tags.entry(tag).or_insert(value);
        cursor += 16;
    }
    Some(tags)
}

/// ELF64 dynamic tags this loader reads.
mod tag {
    pub const HASH: u64 = 4;
    pub const STRTAB: u64 = 5;
    pub const SYMTAB: u64 = 6;
    pub const RELA: u64 = 7;
    pub const RELASZ: u64 = 8;
    pub const SYMENT: u64 = 11;
    pub const PLTRELSZ: u64 = 2;
    pub const JMPREL: u64 = 23;
}

/// `R_AARCH64_RELATIVE`: the place holds an image-relative address that the
/// loader biases by the load address (AArch64 ELF ABI, "Dynamic
/// relocations").
const R_AARCH64_RELATIVE: u32 = 1027;
const R_AARCH64_GLOB_DAT: u32 = 1025;
const R_AARCH64_JUMP_SLOT: u32 = 1026;
const R_AARCH64_ABS64: u32 = 257;

/// Loads an NSO0 module: segments assembled at their mapped base, the
/// module's own symbols as named functions, and its relocations applied.
pub(crate) fn import(data: &[u8]) -> Result<NativeImport> {
    let Some(segments) = header(data) else {
        return super::err("not an NSO0 module");
    };
    let flags = word(data, 0x0C).unwrap_or(0);
    if flags & FLAG_ZBIC != 0 {
        return super::err("NSO0 module is ZBIC-compressed, which this loader cannot decode");
    }
    let mut image = assemble(data, &segments)?;
    let bss_size = u64::from(word(data, 0x3C).unwrap_or(0));

    let mut import = NativeImport {
        format: "nso".into(),
        // A 64-bit module is AArch64; a 32-bit one is mapped elsewhere by
        // the platform and is not accepted here.
        language: "AARCH64:LE:64:v8A".into(),
        ..Default::default()
    };

    let tags = dynamic(&image, segments[0].memory_offset);
    // Relocations are applied to the assembled image before it is mapped, so
    // every pointer the discovery pass reads is the value the console would
    // see.
    let mut relocations: Vec<MemoryRelocation> = Vec::new();
    let mut named: Vec<NamedRelocation> = Vec::new();
    let mut externals: Vec<(u64, String)> = Vec::new();
    let mut functions: Vec<NativeFunction> = Vec::new();
    let mut symbol_named: Vec<u64> = Vec::new();

    if let Some(tags) = tags.as_ref() {
        let symbols = symbol_table(&image, tags);
        for (offset, name, size, is_function) in &symbols {
            let address = BASE + offset;
            if *is_function && *offset != 0 {
                functions.push(NativeFunction {
                    entry: address,
                    name: name.clone(),
                    size: *size,
                });
                symbol_named.push(address);
            }
        }
        apply_relocations(
            &mut image,
            tags,
            &symbols,
            &mut relocations,
            &mut named,
            &mut externals,
        );
    } else {
        import.discovery_note = Some("NSO0 module carries no MOD0 dynamic table".into());
    }

    // One mapping per segment, with the permissions the platform gives it.
    let names = ["text", "rodata", "data"];
    for (index, segment) in segments.iter().enumerate() {
        let at = segment.memory_offset as usize;
        let bytes = image
            .get(at..at + segment.size as usize)
            .unwrap_or_default()
            .to_vec();
        if bytes.is_empty() {
            continue;
        }
        import.mappings.push(Mapping {
            vaddr: BASE + u64::from(segment.memory_offset),
            size: u64::from(segment.size),
            file_off: u64::from(segment.file_offset),
            // read+execute for text, read for rodata, read+write for data
            flags: match index {
                0 => 0x6,
                1 => 0x2,
                _ => 0x3,
            },
            bytes,
        });
        import.mapping_names.push(names[index].into());
    }
    if bss_size > 0 {
        let bss = BASE
            + u64::from(segments[2].memory_offset)
            + u64::from(segments[2].size);
        import.declared_regions.push(DeclaredRegion {
            name: "bss".into(),
            vaddr: bss,
            size: bss_size,
            flags: 0x3,
        });
    }
    import.functions = functions;
    import.symbol_named = symbol_named;
    import.relocations = relocations;
    import.named_relocations = named;
    import.externals = externals;
    Ok(import)
}

/// Every symbol the module's own `.dynsym` holds, as
/// `(image offset, name, size, is a function)`.
///
/// The length of the table is not stated anywhere: it comes from `nchain` in
/// `DT_HASH`, or, when the module has no hash table, from the string table
/// following the symbol table -- exactly the two cases
/// `ElfCompatibilityProvider.getSymbolTable` handles (:157-172).
fn symbol_table(image: &[u8], tags: &HashMap<u64, u64>) -> Vec<(u64, String, u64, bool)> {
    let Some(&symtab) = tags.get(&tag::SYMTAB) else {
        return Vec::new();
    };
    let Some(&strtab) = tags.get(&tag::STRTAB) else {
        return Vec::new();
    };
    let entry_size = tags.get(&tag::SYMENT).copied().unwrap_or(24).max(24);
    let count = match tags.get(&tag::HASH) {
        Some(&hash) => word(image, hash as usize + 4).map_or(0, u64::from),
        None if symtab < strtab => (strtab - symtab) / entry_size,
        None => 0,
    };
    let mut out = Vec::with_capacity(count as usize);
    for index in 0..count {
        let at = (symtab + index * entry_size) as usize;
        let Some(name_offset) = word(image, at) else {
            break;
        };
        let info = match image.get(at + 4) {
            Some(&info) => info,
            None => break,
        };
        let Some(value) = quad(image, at + 8) else {
            break;
        };
        let size = quad(image, at + 16).unwrap_or(0);
        let name = string_at(image, strtab as usize + name_offset as usize);
        if name.is_empty() {
            continue;
        }
        // STT_FUNC is the low nibble of `st_info`.
        out.push((value, name, size, info & 0xF == 2));
    }
    out
}

fn string_at(image: &[u8], offset: usize) -> String {
    let end = image[offset.min(image.len())..]
        .iter()
        .position(|byte| *byte == 0)
        .map_or(offset, |length| offset + length);
    String::from_utf8_lossy(image.get(offset..end).unwrap_or_default()).into_owned()
}

/// Applies `DT_RELA` and `DT_JMPREL`, recording each place the way the ELF
/// loader records it so the passes that read relocated words see the same
/// facts on both formats.
fn apply_relocations(
    image: &mut Vec<u8>,
    tags: &HashMap<u64, u64>,
    symbols: &[(u64, String, u64, bool)],
    relocations: &mut Vec<MemoryRelocation>,
    named: &mut Vec<NamedRelocation>,
    externals: &mut Vec<(u64, String)>,
) {
    for (table, size) in [
        (tags.get(&tag::RELA), tags.get(&tag::RELASZ)),
        (tags.get(&tag::JMPREL), tags.get(&tag::PLTRELSZ)),
    ] {
        let (Some(&table), Some(&size)) = (table, size) else {
            continue;
        };
        let mut cursor = table as usize;
        let end = (table + size) as usize;
        while cursor + 24 <= end {
            let Some(place) = quad(image, cursor) else {
                break;
            };
            let Some(info) = quad(image, cursor + 8) else {
                break;
            };
            let addend = quad(image, cursor + 16).unwrap_or(0);
            cursor += 24;
            let kind = (info & 0xFFFF_FFFF) as u32;
            let symbol = (info >> 32) as usize;
            let at = place as usize;
            match kind {
                R_AARCH64_RELATIVE => {
                    let value = BASE.wrapping_add(addend);
                    if let Some(slot) = image.get_mut(at..at + 8) {
                        slot.copy_from_slice(&value.to_le_bytes());
                    }
                    relocations.push(MemoryRelocation {
                        address: BASE + place,
                        bytes: value.to_le_bytes(),
                        width: 8,
                    });
                }
                R_AARCH64_GLOB_DAT | R_AARCH64_JUMP_SLOT | R_AARCH64_ABS64 => {
                    let Some((value, name, _, _)) = symbols.get(symbol) else {
                        continue;
                    };
                    named.push(NamedRelocation {
                        address: BASE + place,
                        symbol: name.clone(),
                        addend,
                        copies: false,
                    });
                    if *value == 0 {
                        // An undefined symbol: the slot names an import.
                        externals.push((BASE + place, name.clone()));
                    } else {
                        let resolved = BASE + value + addend;
                        if let Some(slot) = image.get_mut(at..at + 8) {
                            slot.copy_from_slice(&resolved.to_le_bytes());
                        }
                        relocations.push(MemoryRelocation {
                            address: BASE + place,
                            bytes: resolved.to_le_bytes(),
                            width: 8,
                        });
                    }
                }
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// LZ4-compresses `bytes` in the trivial way: one sequence of literals,
    /// which is a valid block and exercises the decoder's literal path.
    fn literals_only(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let length = bytes.len();
        if length < 15 {
            out.push((length as u8) << 4);
        } else {
            out.push(0xF0);
            let mut remaining = length - 15;
            while remaining >= 255 {
                out.push(0xFF);
                remaining -= 255;
            }
            out.push(remaining as u8);
        }
        out.extend_from_slice(bytes);
        out
    }

    #[test]
    fn it_decompresses_literals_and_overlapping_matches() {
        assert_eq!(
            lz4_block(&literals_only(b"abcdefghijklmnopqrst"), 20).as_deref(),
            Some(&b"abcdefghijklmnopqrst"[..])
        );
        // One literal `a`, then a match of length 5 at offset 1: the run-
        // length case, where the match reads bytes it is still writing.
        let block = vec![0x11, b'a', 0x01, 0x00];
        assert_eq!(lz4_block(&block, 6).as_deref(), Some(&b"aaaaaa"[..]));
    }

    #[test]
    fn a_block_that_does_not_fill_the_output_is_refused() {
        assert_eq!(lz4_block(&literals_only(b"abc"), 8), None);
        // An offset past the start of the output is refused rather than
        // reading outside the buffer.
        assert_eq!(lz4_block(&[0x01, b'a', 0x10, 0x00], 8), None);
    }

    /// A module with one uncompressed text segment, a MOD0 header, a dynamic
    /// table, one hash table, one string table and one FUNC symbol.
    fn module() -> Vec<u8> {
        let mut text = vec![0u8; 0x200];
        // MOD0 at text offset 0x40, named by the word at text offset 4.
        text[4..8].copy_from_slice(&0x40u32.to_le_bytes());
        text[0x40..0x44].copy_from_slice(b"MOD0");
        // dynamic at MOD0 + 0x40 = 0x80
        text[0x44..0x48].copy_from_slice(&0x40u32.to_le_bytes());
        let mut dynamic = Vec::new();
        for (tag, value) in [
            (tag::SYMTAB, 0x100u64),
            (tag::STRTAB, 0x140),
            (tag::SYMENT, 24),
            (tag::HASH, 0x180),
            (0u64, 0),
        ] {
            dynamic.extend_from_slice(&tag.to_le_bytes());
            dynamic.extend_from_slice(&value.to_le_bytes());
        }
        text[0x80..0x80 + dynamic.len()].copy_from_slice(&dynamic);
        // One symbol at index 1: name offset 1, STT_FUNC, value 0x10, size 8.
        let symbol = 0x100 + 24;
        text[symbol..symbol + 4].copy_from_slice(&1u32.to_le_bytes());
        text[symbol + 4] = 2;
        text[symbol + 8..symbol + 16].copy_from_slice(&0x10u64.to_le_bytes());
        text[symbol + 16..symbol + 24].copy_from_slice(&8u64.to_le_bytes());
        text[0x141..0x146].copy_from_slice(b"main\0");
        // DT_HASH: nbucket, nchain -- two symbols, the null one and `main`.
        text[0x184..0x188].copy_from_slice(&2u32.to_le_bytes());

        let mut file = vec![0u8; 0x100];
        file[..4].copy_from_slice(b"NSO0");
        for (index, at) in [0x10usize, 0x20, 0x30].into_iter().enumerate() {
            let (file_offset, memory_offset, size) = match index {
                0 => (0x100u32, 0u32, text.len() as u32),
                1 => (0x100 + text.len() as u32, text.len() as u32, 0x10),
                _ => (
                    0x100 + text.len() as u32 + 0x10,
                    text.len() as u32 + 0x10,
                    0x10,
                ),
            };
            file[at..at + 4].copy_from_slice(&file_offset.to_le_bytes());
            file[at + 4..at + 8].copy_from_slice(&memory_offset.to_le_bytes());
            file[at + 8..at + 12].copy_from_slice(&size.to_le_bytes());
        }
        file.extend_from_slice(&text);
        file.extend_from_slice(&[0u8; 0x20]);
        file
    }

    #[test]
    fn it_reads_the_modules_own_symbols() {
        let data = module();
        assert!(is_module(&data));
        let import = import(&data).expect("module");
        assert_eq!(import.language, "AARCH64:LE:64:v8A");
        assert_eq!(
            import
                .functions
                .iter()
                .map(|f| (f.entry, f.name.as_str(), f.size))
                .collect::<Vec<_>>(),
            vec![(BASE + 0x10, "main", 8)],
        );
        // The text segment is mapped at the base, executable.
        assert_eq!(import.mappings[0].vaddr, BASE);
        assert_eq!(import.mappings[0].flags, 0x6);
        assert!(import.symbol_named.contains(&(BASE + 0x10)));
    }

    #[test]
    fn a_file_that_is_not_a_module_is_declined() {
        assert!(!is_module(b"MZ\x90\x00"));
        assert!(!is_module(&[]));
        // Right magic, segment past the end of the file.
        let mut truncated = module();
        truncated[0x18..0x1C].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        assert!(!is_module(&truncated));
    }
}
