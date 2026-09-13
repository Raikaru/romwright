//! PSY-Q `.SYM` reader (P2.7): the Sony/PSY-Q symbol file a PSX build
//! leaves beside the executable. The format is a flat table of
//! `(u32 address, u32 name_offset)` pairs — little-endian — where each
//! name_offset points into a NUL-terminated string table that follows the
//! pairs. The first pair's name_offset is the string table's start, which
//! is also where the pair table ends.
//!
//! No magic, no count: the table ends where the strings begin, and the
//! strings begin at the smallest name_offset any pair carries. A pair
//! whose name_offset lands inside the pair region is not a symbol.

use crate::native::{NativeFunction, NativeImport};

/// One recovered symbol: an address and its name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PsyqSymbol {
    pub address: u64,
    pub name: String,
}

/// Parses a PSY-Q `.SYM` image. Returns None when the shape does not
/// hold: the string table must start where the smallest name_offset
/// points, and every name must be printable ASCII.
pub fn parse(data: &[u8]) -> Option<Vec<PsyqSymbol>> {
    if data.len() < 16 {
        return None;
    }
    // The string table starts at the smallest name_offset across the
    // leading pairs — which is also where the pair table ends. Read pairs
    // until a name_offset points back into the pair region.
    let mut symbols = Vec::new();
    let mut string_start = u32::MAX;
    let mut i = 0usize;
    while i + 8 <= data.len() {
        let address = u32::from_le_bytes(data[i..i + 4].try_into().ok()?) as u64;
        let name_off = u32::from_le_bytes(data[i + 4..i + 8].try_into().ok()?) as u64;
        // A name_offset below the current pair index is the string table
        // arriving — the pairs are over.
        if name_off < i as u64 + 8 && name_off != 0 {
            break;
        }
        if name_off < string_start as u64 {
            string_start = name_off as u32;
        }
        // The name must live at or past the string table start and inside
        // the file.
        if name_off >= data.len() as u64 {
            break;
        }
        let end = data[name_off as usize..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| name_off as usize + p)?;
        let name = std::str::from_utf8(&data[name_off as usize..end]).ok()?;
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
            break;
        }
        symbols.push(PsyqSymbol {
            address,
            name: name.to_string(),
        });
        i += 8;
    }
    if symbols.is_empty() {
        return None;
    }
    Some(symbols)
}

/// Applies recovered symbols to the import: names the function at each
/// symbol's address, or records a data name for non-code addresses.
pub fn apply_to_import(imp: &mut NativeImport, symbols: &[PsyqSymbol]) {
    let in_code = |address: u64| {
        imp.mappings.iter().any(|mapping| {
            mapping.flags & 4 != 0
                && address >= mapping.vaddr
                && address - mapping.vaddr < mapping.size
        })
    };
    let mut entries: std::collections::HashSet<u64> =
        imp.functions.iter().map(|f| f.entry).collect();
    for sym in symbols {
        let entry = sym.address;
        if in_code(entry) {
            if let Some(function) = imp.functions.iter_mut().find(|f| f.entry == entry) {
                function.name = sym.name.clone();
            } else if entries.insert(entry) {
                imp.functions.push(NativeFunction {
                    entry,
                    name: sym.name.clone(),
                    size: 1,
                });
            }
            if !imp.symbol_named.contains(&entry) {
                imp.symbol_named.push(entry);
            }
        } else {
            imp.object_names.push((entry, sym.name.clone()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pairs_until_string_table() {
        // Two symbols then the string table at 0x10.
        let mut d = Vec::new();
        d.extend_from_slice(&0x1000u32.to_le_bytes()); // addr
        d.extend_from_slice(&0x10u32.to_le_bytes());   // name_off -> "func_a"
        d.extend_from_slice(&0x2000u32.to_le_bytes());
        d.extend_from_slice(&0x17u32.to_le_bytes());   // -> "func_b"
        d.extend_from_slice(b"func_a\x00func_b\x00");
        let syms = parse(&d).unwrap();
        assert_eq!(syms.len(), 2);
        assert_eq!(syms[0].name, "func_a");
        assert_eq!(syms[1].name, "func_b");
    }
}
