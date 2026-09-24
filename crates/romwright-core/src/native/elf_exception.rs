//! The try ranges `.gcc_except_table` declares, read through `.eh_frame`.
//!
//! Ghidra's `GccExceptionAnalyzer` walks each function's LSDA call-site table
//! and marks every call site that has a landing pad. The path to that table is
//! the CIE's augmentation string: `L` declares the encoding of the FDE's LSDA
//! pointer, `R` the encoding of the FDE's own code pointers, `P` a personality
//! routine whose pointer has to be stepped over first (LSB DWARF extensions;
//! `ExceptionHandlerFrameHeader`, `CieSource` and `DwarfEHDataDecodeFormat` in
//! the pinned tree).
//!
//! Two rules are Ghidra's, verified against the pinned sources rather than
//! remembered:
//!
//! * an omitted `@LPStart` (`DW_EH_PE_omit`, `0xff`) means the call sites and
//!   landing pads are relative to the function the FDE describes
//!   (`LSDAHeader.createLPStartPointer`: `lpStartAddr = region.getRangeStart()`);
//! * a record's range is `[lpStart + position, lpStart + position + length - 1]`
//!   and its handler is `lpStart + landingPadOffset`, with a zero offset
//!   meaning "no handler" -- the analyzer marks nothing for those
//!   (`LSDACallSiteRecord.create`, `GccExceptionAnalyzer.processCallSiteRecord`).

use super::elf_unwind::decode;
use super::{ElfSection, NativeImport};

/// One call site the image declares as protected, with its handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExceptionSite {
    /// Entry of the function the FDE describes.
    pub function: u64,
    /// First address of the protected range.
    pub start: u64,
    /// Last address of the protected range, inclusive.
    pub end: u64,
    /// The handler the call site branches to when it throws.
    pub landing_pad: u64,
}

/// `DW_EH_PE_omit`: the encoding that says "this pointer is not here".
const OMIT: u8 = 0xff;

/// One CIE's answers to the two questions an FDE asks of it.
#[derive(Debug, Clone, Copy)]
struct Cie {
    /// Encoding of the FDE's `initial_location`/`address_range`.
    pointer: u8,
    /// Encoding of the FDE's LSDA pointer, or `OMIT`.
    lsda: u8,
    /// Whether the augmentation data block is present (`z`).
    sized: bool,
}

/// Reads an unsigned LEB128 without consulting an encoding byte.
fn uleb(bytes: &[u8], cursor: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    let mut shift = 0;
    loop {
        let byte = *bytes.get(*cursor)?;
        *cursor += 1;
        value |= u64::from(byte & 0x7f).checked_shl(shift)?;
        if byte & 0x80 == 0 {
            return Some(value);
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
}

/// Skips a signed LEB128; only its length matters here.
fn sleb(bytes: &[u8], cursor: &mut usize) -> Option<()> {
    loop {
        let byte = *bytes.get(*cursor)?;
        *cursor += 1;
        if byte & 0x80 == 0 {
            return Some(());
        }
    }
}

/// Steps over one encoded pointer without resolving it.
///
/// The personality routine's pointer only has to be *skipped*, and its
/// encoding is routinely one no reader needs to follow: AArch64 builds encode
/// it `DW_EH_PE_indirect|pcrel|sdata8` (`0x9b`), which cannot be decoded to an
/// address without reading the slot it points at. Refusing to decode it must
/// not cost us the CIE.
fn skip_pointer(bytes: &[u8], cursor: &mut usize, encoding: u8, width: usize) -> Option<()> {
    if encoding == OMIT {
        return Some(());
    }
    match encoding & 0x0f {
        // uleb128 / sleb128: variable length.
        0x01 | 0x09 => loop {
            let byte = *bytes.get(*cursor)?;
            *cursor += 1;
            if byte & 0x80 == 0 {
                return Some(());
            }
        },
        0x00 | 0x08 => *cursor = cursor.checked_add(width)?,
        0x02 | 0x0a => *cursor = cursor.checked_add(2)?,
        0x03 | 0x0b => *cursor = cursor.checked_add(4)?,
        0x04 | 0x0c => *cursor = cursor.checked_add(8)?,
        _ => return None,
    }
    (*cursor <= bytes.len()).then_some(())
}

/// A NUL-terminated augmentation string.
fn augmentation<'a>(bytes: &'a [u8], cursor: &mut usize) -> Option<&'a [u8]> {
    let start = *cursor;
    let end = bytes[start..].iter().position(|byte| *byte == 0)? + start;
    *cursor = end + 1;
    Some(&bytes[start..end])
}

/// The section bytes and virtual address of one named section.
fn section_bytes<'a>(
    data: &'a [u8],
    sections: &[ElfSection],
    name: &str,
) -> Option<(&'a [u8], u64)> {
    let section = sections
        .iter()
        .find(|section| section.name == name && section.size != 0 && section.typ != 8)?;
    let start = usize::try_from(section.off).ok()?;
    let end = start.checked_add(usize::try_from(section.size).ok()?)?;
    Some((data.get(start..end)?, section.addr))
}

/// Parses one CIE's augmentation, leaving the encodings an FDE needs.
fn read_cie(bytes: &[u8], mut cursor: usize, width: usize) -> Option<Cie> {
    let version = *bytes.get(cursor)?;
    cursor += 1;
    if version != 1 && version != 3 {
        return None;
    }
    let letters = augmentation(bytes, &mut cursor)?;
    uleb(bytes, &mut cursor)?; // code alignment factor
    sleb(bytes, &mut cursor)?; // data alignment factor
    if version == 1 {
        cursor += 1; // return address register, one byte in version 1
    } else {
        uleb(bytes, &mut cursor)?;
    }
    let mut cie = Cie { pointer: 0, lsda: OMIT, sized: false };
    if letters.first() != Some(&b'z') {
        // Without a `z` block there is no LSDA pointer to find.
        return Some(cie);
    }
    cie.sized = true;
    let length = uleb(bytes, &mut cursor)?;
    let end = cursor.checked_add(usize::try_from(length).ok()?)?;
    for letter in &letters[1..] {
        match letter {
            b'P' => {
                let encoding = *bytes.get(cursor)?;
                cursor += 1;
                skip_pointer(bytes, &mut cursor, encoding, width)?;
            }
            b'L' => {
                cie.lsda = *bytes.get(cursor)?;
                cursor += 1;
            }
            b'R' => {
                cie.pointer = *bytes.get(cursor)?;
                cursor += 1;
            }
            // `S` (signal frame) and `B`/`G` carry no data in this block.
            b'S' | b'B' | b'G' => {}
            _ => return None,
        }
        if cursor > end {
            return None;
        }
    }
    Some(cie)
}

/// Every call site the LSDA at `address` protects, for the function `function`.
fn read_lsda(
    data: &[u8],
    sections: &[ElfSection],
    address: u64,
    function: u64,
    width: usize,
    be: bool,
) -> Option<Vec<ExceptionSite>> {
    let section = sections.iter().find(|section| {
        section.size != 0
            && section.typ != 8
            && address >= section.addr
            && address - section.addr < section.size
    })?;
    let start = usize::try_from(section.off).ok()?;
    let end = start.checked_add(usize::try_from(section.size).ok()?)?;
    let bytes = data.get(start..end)?;
    let mut cursor = usize::try_from(address - section.addr).ok()?;

    let lp_encoding = *bytes.get(cursor)?;
    cursor += 1;
    let lp_start = if lp_encoding == OMIT {
        function
    } else {
        decode(bytes, &mut cursor, lp_encoding, section.addr, width, be)?
    };
    let ttype_encoding = *bytes.get(cursor)?;
    cursor += 1;
    if ttype_encoding != OMIT {
        uleb(bytes, &mut cursor)?; // offset to the type table; unused here
    }
    let site_encoding = *bytes.get(cursor)?;
    cursor += 1;
    let table_length = usize::try_from(uleb(bytes, &mut cursor)?).ok()?;
    let table_end = cursor.checked_add(table_length)?;
    if table_end > bytes.len() {
        return None;
    }
    let mut sites = Vec::new();
    while cursor < table_end {
        let position = decode(bytes, &mut cursor, site_encoding, section.addr, width, be)?;
        let length = decode(bytes, &mut cursor, site_encoding, section.addr, width, be)?;
        let landing_pad = decode(bytes, &mut cursor, site_encoding, section.addr, width, be)?;
        uleb(bytes, &mut cursor)?; // action record offset
        if landing_pad == 0 || length == 0 {
            continue;
        }
        let start = lp_start.checked_add(position)?;
        sites.push(ExceptionSite {
            function,
            start,
            end: start.checked_add(length)?.checked_sub(1)?,
            landing_pad: lp_start.checked_add(landing_pad)?,
        });
    }
    Some(sites)
}

/// Records every protected call site the image's `.eh_frame` chain declares.
pub(super) fn collect(
    data: &[u8],
    sections: &[ElfSection],
    import: &mut NativeImport,
    width: usize,
    be: bool,
) {
    let Some((frame, frame_addr)) = section_bytes(data, sections, ".eh_frame") else {
        return;
    };
    let read_u32 = |cursor: usize| -> Option<u32> {
        let chunk: [u8; 4] = frame.get(cursor..cursor + 4)?.try_into().ok()?;
        Some(if be { u32::from_be_bytes(chunk) } else { u32::from_le_bytes(chunk) })
    };
    let read_u64 = |cursor: usize| -> Option<u64> {
        let chunk: [u8; 8] = frame.get(cursor..cursor + 8)?.try_into().ok()?;
        Some(if be { u64::from_be_bytes(chunk) } else { u64::from_le_bytes(chunk) })
    };
    let mut cies: std::collections::HashMap<usize, Cie> = std::collections::HashMap::new();
    let mut cursor = 0usize;
    while cursor + 4 <= frame.len() {
        let record = cursor;
        let Some(short) = read_u32(cursor) else { break };
        cursor += 4;
        // A zero-length record terminates the section; a 0xffffffff length
        // introduces the 64-bit form.
        if short == 0 {
            break;
        }
        let (length, id_size) = if short == u32::MAX {
            let Some(long) = read_u64(cursor) else { break };
            cursor += 8;
            (long, 8usize)
        } else {
            (u64::from(short), 4usize)
        };
        let Some(end) = usize::try_from(length).ok().and_then(|len| cursor.checked_add(len)) else {
            break;
        };
        if end > frame.len() {
            break;
        }
        let id_position = cursor;
        let identifier = if id_size == 4 {
            match read_u32(cursor) {
                Some(value) => u64::from(value),
                None => break,
            }
        } else {
            match read_u64(cursor) {
                Some(value) => value,
                None => break,
            }
        };
        cursor += id_size;
        if identifier == 0 {
            if let Some(cie) = read_cie(frame, cursor, width) {
                cies.insert(record, cie);
            }
            cursor = end;
            continue;
        }
        // An FDE's CIE pointer counts backwards from the pointer's own
        // position, which is how the same CIE serves many FDEs.
        let Some(cie_at) = usize::try_from(identifier).ok().and_then(|back| id_position.checked_sub(back))
        else {
            cursor = end;
            continue;
        };
        let Some(cie) = cies.get(&cie_at).copied() else {
            cursor = end;
            continue;
        };
        let mut fde = cursor;
        let Some(function) = decode(frame, &mut fde, cie.pointer, frame_addr, width, be) else {
            cursor = end;
            continue;
        };
        // The range is a length, never an address: only the value's width
        // comes from the encoding.
        if decode(frame, &mut fde, cie.pointer & 0x0f, frame_addr, width, be).is_none() {
            cursor = end;
            continue;
        }
        if cie.sized {
            let Some(block) = uleb(frame, &mut fde) else {
                cursor = end;
                continue;
            };
            let block_end = usize::try_from(block).ok().and_then(|len| fde.checked_add(len));
            if cie.lsda != OMIT {
                if let Some(lsda) = decode(frame, &mut fde, cie.lsda, frame_addr, width, be) {
                    if lsda != 0 {
                        if let Some(sites) =
                            read_lsda(data, sections, lsda, function, width, be)
                        {
                            import.exception_sites.extend(sites);
                        }
                    }
                }
            }
            if let Some(block_end) = block_end {
                fde = block_end;
            }
        }
        let _ = fde;
        cursor = end;
    }
    import
        .exception_sites
        .sort_unstable_by_key(|site| (site.start, site.end, site.landing_pad));
    import.exception_sites.dedup();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `.eh_frame` with one `zPLR` CIE and one FDE whose LSDA has two call
    /// sites -- one with a handler, one without -- plus a second FDE whose
    /// CIE omits `L`, which must contribute nothing.
    fn fixture(be: bool) -> (Vec<u8>, Vec<ElfSection>) {
        let word = |value: u32| if be { value.to_be_bytes() } else { value.to_le_bytes() };
        let mut frame = Vec::new();
        // CIE: length, id 0, version 1, "zR", code align, data align, ra reg,
        // aug length 1, pointer encoding udata4 (0x03).
        let mut cie = Vec::new();
        cie.extend_from_slice(&0u32.to_ne_bytes()[..0]);
        let mut body = vec![1u8];
        body.extend_from_slice(b"zLR\0");
        body.push(1); // code alignment
        body.push(0x7c); // data alignment (sleb -4)
        body.push(16); // return address register
        body.push(2); // augmentation data length
        body.push(0x03); // L: LSDA encoding udata4
        body.push(0x03); // R: pointer encoding udata4
        while (4 + body.len()) % 4 != 0 {
            body.push(0);
        }
        cie.extend_from_slice(&word(body.len() as u32));
        cie.extend_from_slice(&word(0));
        cie.extend_from_slice(&body[..]);
        // The id field is inside the length; rebuild with the real length.
        let mut fixed = Vec::new();
        fixed.extend_from_slice(&word((4 + body.len()) as u32));
        fixed.extend_from_slice(&word(0));
        fixed.extend_from_slice(&body[..]);
        frame.extend_from_slice(&fixed);
        let cie_at = 0usize;

        // FDE: length, cie pointer (back to the CIE), initial location,
        // range, aug length, LSDA pointer.
        let mut fde_body = Vec::new();
        fde_body.extend_from_slice(&word(0x1000)); // initial location
        fde_body.extend_from_slice(&word(0x40)); // range
        fde_body.push(4); // augmentation data length
        fde_body.extend_from_slice(&word(0x3000)); // LSDA
        let fde_at = frame.len();
        frame.extend_from_slice(&word((4 + fde_body.len()) as u32));
        frame.extend_from_slice(&word((fde_at + 4 - cie_at) as u32));
        frame.extend_from_slice(&fde_body[..]);
        frame.extend_from_slice(&word(0)); // terminator

        // LSDA: LPStart omitted, TType omitted, call sites udata4.
        let mut lsda = vec![OMIT, OMIT, 0x03];
        let mut table = Vec::new();
        for (position, length, pad) in [(0x10u32, 0x10u32, 0x30u32), (0x24, 4, 0)] {
            table.extend_from_slice(&word(position));
            table.extend_from_slice(&word(length));
            table.extend_from_slice(&word(pad));
            table.push(0); // action
        }
        lsda.push(table.len() as u8);
        lsda.extend_from_slice(&table);

        let sections = vec![
            ElfSection {
                name: ".eh_frame".into(),
                addr: 0x2000,
                off: 0,
                size: frame.len() as u64,
                typ: 1,
                flags: 2,
                link: 0,
                entry_size: 0,
            },
            ElfSection {
                name: ".gcc_except_table".into(),
                addr: 0x3000,
                off: frame.len() as u64,
                size: lsda.len() as u64,
                typ: 1,
                flags: 2,
                link: 0,
                entry_size: 0,
            },
        ];
        let mut data = frame;
        data.extend_from_slice(&lsda);
        (data, sections)
    }

    #[test]
    fn a_call_site_with_a_handler_is_recorded_and_one_without_is_not() {
        for be in [false, true] {
            let (data, sections) = fixture(be);
            let mut import = NativeImport::default();
            collect(&data, &sections, &mut import, 4, be);
            assert_eq!(
                import.exception_sites,
                vec![ExceptionSite {
                    function: 0x1000,
                    start: 0x1010,
                    end: 0x101f,
                    landing_pad: 0x1030,
                }],
                "be={be}: the record whose landing pad is zero has no handler"
            );
        }
    }

    #[test]
    fn a_truncated_table_records_nothing_rather_than_guessing() {
        let (data, sections) = fixture(false);
        for cut in [1usize, 4, 8, 12] {
            let mut import = NativeImport::default();
            collect(&data[..data.len() - cut], &sections, &mut import, 4, false);
            assert!(
                import.exception_sites.len() <= 1,
                "a short table must not invent sites"
            );
        }
        // No `.eh_frame` at all is silence, not an error.
        let mut import = NativeImport::default();
        collect(&data, &sections[1..], &mut import, 4, false);
        assert!(import.exception_sites.is_empty());
    }
}
