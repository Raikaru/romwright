//! Null-terminated data strings. Length is measured in Unicode scalar values.
use super::NativeImport;
use lre_model::{Address, StringRow};

#[derive(Clone, Copy)]
enum Encoding {
    Ascii,
    Utf8,
    Utf16(bool),
}

#[derive(Clone, Copy)]
struct Candidate {
    start: usize,
    content: usize,
    end: usize,
    encoding: Encoding,
    priority: u8,
    utf8_len: usize,
}

fn printable(character: char) -> bool {
    let value = character as u32;
    (matches!(character, '\t' | '\n' | '\r') || !character.is_control())
        && value & 0xffff != 0xfffe
        && value & 0xffff != 0xffff
        && !(0xfdd0..=0xfdef).contains(&value)
}

fn narrow_candidates(bytes: &[u8], candidates: &mut Vec<Candidate>) {
    let mut block_start = 0;
    for (end, &byte) in bytes.iter().enumerate() {
        if byte != 0 {
            continue;
        }
        let mut start = block_start;
        let mut remaining = &bytes[start..end];
        loop {
            match std::str::from_utf8(remaining) {
                Ok(text) => {
                    let skip = text
                        .char_indices()
                        .filter(|(_, character)| !printable(*character))
                        .map(|(offset, character)| offset + character.len_utf8())
                        .next_back()
                        .unwrap_or(0);
                    start += skip;
                    let text = &text[skip..];
                    let bom = text.starts_with('\u{feff}');
                    let content = if bom { &text[3..] } else { text };
                    if content.chars().count() >= 4 {
                        candidates.push(Candidate {
                            start,
                            content: start + if bom { 3 } else { 0 },
                            end: end + 1,
                            encoding: if content.is_ascii() && !bom {
                                Encoding::Ascii
                            } else {
                                Encoding::Utf8
                            },
                            priority: if bom { 0 } else { 3 },
                            utf8_len: content.len(),
                        });
                    }
                    break;
                }
                Err(error) => {
                    let skip = error.valid_up_to()
                        + error
                            .error_len()
                            .unwrap_or(remaining.len() - error.valid_up_to());
                    start += skip;
                    remaining = &remaining[skip..];
                }
            }
        }
        block_start = end + 1;
    }
}

fn unit(bytes: &[u8], offset: usize, big_endian: bool) -> u16 {
    let pair = [bytes[offset], bytes[offset + 1]];
    if big_endian {
        u16::from_be_bytes(pair)
    } else {
        u16::from_le_bytes(pair)
    }
}

fn wide_candidates(
    bytes: &[u8],
    big_endian: bool,
    require_bom: bool,
    candidates: &mut Vec<Candidate>,
) {
    for alignment in 0..2 {
        let mut offset = alignment;
        let (mut start, mut content, mut count, mut utf8_len) = (alignment, alignment, 0, 0);
        let mut bom = false;
        while offset + 1 < bytes.len() {
            let at = offset;
            let first = unit(bytes, offset, big_endian);
            offset += 2;
            if first == 0 {
                if count >= 4 && (!require_bom || bom) {
                    candidates.push(Candidate {
                        start,
                        content,
                        end: offset,
                        encoding: Encoding::Utf16(big_endian),
                        priority: if bom { 0 } else { 4 },
                        utf8_len,
                    });
                }
                count = 0;
                utf8_len = 0;
                bom = false;
                continue;
            }
            if first == 0xfeff && count == 0 && !bom {
                start = at;
                content = offset;
                bom = true;
                continue;
            }
            if require_bom && !bom {
                continue;
            }
            let character = if (0xd800..=0xdbff).contains(&first) {
                if offset + 1 < bytes.len() {
                    let low = unit(bytes, offset, big_endian);
                    if (0xdc00..=0xdfff).contains(&low) {
                        offset += 2;
                        char::from_u32(
                            0x10000 + ((first as u32 - 0xd800) << 10) + low as u32 - 0xdc00,
                        )
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                char::from_u32(first as u32)
            };
            if let Some(character) = character.filter(|character| printable(*character)) {
                if count == 0 && !bom {
                    start = at;
                    content = at;
                }
                count += 1;
                utf8_len += character.len_utf8();
            } else {
                count = 0;
                utf8_len = 0;
                bom = false;
            }
        }
    }
}

// Resolve priority groups against the already accepted, disjoint intervals.
// Compact in place; sorting the accepted prefix never touches an unread group.
fn resolve_candidates(candidates: &mut Vec<Candidate>) {
    if candidates.len() < 2 {
        return;
    }
    candidates.sort_unstable_by_key(|candidate| (candidate.priority, candidate.start));
    let (mut next, mut accepted) = (0, 0);
    while next < candidates.len() {
        let priority = candidates[next].priority;
        let end =
            next + candidates[next..].partition_point(|candidate| candidate.priority == priority);
        let higher = accepted;
        let (mut occupied, mut previous_end) = (0, 0);
        for index in next..end {
            let candidate = candidates[index];
            if candidate.start < previous_end {
                continue;
            }
            while occupied < higher && candidates[occupied].end <= candidate.start {
                occupied += 1;
            }
            if occupied < higher && candidates[occupied].start < candidate.end {
                continue;
            }
            candidates[accepted] = candidate;
            accepted += 1;
            previous_end = candidate.end;
        }
        candidates[..accepted].sort_unstable_by_key(|candidate| candidate.start);
        next = end;
    }
    candidates.truncate(accepted);
}

pub(super) fn discover(import: &NativeImport) -> Vec<StringRow> {
    let big_endian = import.language.split(':').nth(1) == Some("BE");
    let mut targets: Vec<_> = import
        .xrefs
        .iter()
        .filter(|xref| matches!(xref.kind.as_str(), "READ" | "WRITE" | "READ_WRITE" | "DATA"))
        .map(|xref| xref.to)
        .collect();
    targets.sort_unstable();
    targets.dedup();
    let mut rows = Vec::new();
    let mut candidates = Vec::new();
    for mapping in import
        .mappings
        .iter()
        .filter(|mapping| mapping.flags & 6 == 2)
    {
        let size = usize::try_from(mapping.size)
            .unwrap_or(usize::MAX)
            .min(mapping.bytes.len());
        let bytes = &mapping.bytes[..size];
        if import.string_tables.iter().any(|table| {
            table.address.space == lre_model::AddressSpace::Ram
                && table.address.offset <= mapping.vaddr
                && mapping.vaddr + size as u64 <= table.address.offset + table.size
        }) {
            continue;
        }
        candidates.clear();
        narrow_candidates(bytes, &mut candidates);
        wide_candidates(bytes, big_endian, false, &mut candidates);
        wide_candidates(bytes, !big_endian, true, &mut candidates);
        candidates.retain(|candidate| {
            !import.string_tables.iter().any(|table| {
                table.address.space == lre_model::AddressSpace::Ram
                    && table.address.offset < mapping.vaddr + candidate.end as u64
                    && mapping.vaddr + (candidate.start as u64) < table.address.offset + table.size
            })
        });
        // BOM, referenced byte/wide text, byte text, aligned/unaligned wide text.
        // Unaligned strings remain eligible; stronger evidence wins overlaps.
        for candidate in &mut candidates {
            if candidate.priority == 0 {
                continue;
            }
            let address = mapping.vaddr + candidate.start as u64;
            let wide = matches!(candidate.encoding, Encoding::Utf16(_));
            if targets.binary_search(&address).is_ok() {
                candidate.priority = if wide { 2 } else { 1 };
            } else if wide {
                candidate.priority = 4 + (address & 1) as u8;
            }
        }
        resolve_candidates(&mut candidates);
        for candidate in &candidates {
            let address = mapping.vaddr + candidate.start as u64;
            let (kind, value) = match candidate.encoding {
                Encoding::Ascii | Encoding::Utf8 => {
                    let text = std::str::from_utf8(&bytes[candidate.content..candidate.end - 1])
                        .expect("validated UTF-8 candidate");
                    (
                        if matches!(candidate.encoding, Encoding::Ascii) {
                            "ASCII"
                        } else {
                            "UTF-8"
                        },
                        text.to_owned(),
                    )
                }
                Encoding::Utf16(big_endian) => {
                    let mut text = String::with_capacity(candidate.utf8_len);
                    let units = (candidate.content..candidate.end - 2)
                        .step_by(2)
                        .map(|offset| unit(bytes, offset, big_endian));
                    for character in char::decode_utf16(units) {
                        text.push(character.expect("validated UTF-16 candidate"));
                    }
                    (if big_endian { "UTF-16BE" } else { "UTF-16LE" }, text)
                }
            };
            rows.push(StringRow {
                address: Address::ram(address),
                value,
                kind: kind.into(),
            });
        }
    }
    rows
}
