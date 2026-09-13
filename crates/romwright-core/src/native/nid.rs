//! Vita/PS3/PSP NID readers (P3.5): Sony platforms name imports and
//! exports by NID — a hash of the function name — rather than the name
//! itself. A NID reader maps the numeric ID back to the name from a
//! known table, so an imported call resolves to `sceKernelCreateThread`
//! instead of `0x44673f7a`.
//!
//! The table is a text file of `NID name` pairs — one per line, NID in
//! hex — that the platform's community database ships (vita-headers,
//! ps3ida, psp-ports). The reader parses the table and resolves the
//! NIDs an import carries.

use std::collections::HashMap;

use super::NativeImport;

/// A parsed NID table: NID → function name.
#[derive(Clone, Debug, Default)]
pub struct NidTable {
    pub names: HashMap<u32, String>,
}

/// Parses a NID table: lines of `0xNNNNNNNN name` or `NNNNNNNN name`.
/// Blank lines and `#` comments are skipped; a malformed line is skipped
/// rather than failing the table.
pub fn parse_table(text: &str) -> NidTable {
    let mut names = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(nid_text) = parts.next() else { continue };
        let Some(name) = parts.next() else { continue };
        let nid_text = nid_text.strip_prefix("0x").unwrap_or(nid_text);
        if let Ok(nid) = u32::from_str_radix(nid_text, 16) {
            names.insert(nid, name.to_string());
        }
    }
    NidTable { names }
}

/// Resolves the NIDs an import carries against the table: each
/// `nid_names` entry the table names is applied to the import's
/// function at the recorded address, and each `externals` NID is named.
///
/// The import's `nid_names` map (from a BINMAP or the platform's own
/// table) is the source of which NIDs exist; this table supplies the
/// human-readable names.
pub fn apply(imp: &mut NativeImport, table: &NidTable) -> usize {
    let mut resolved = 0;
    // externals carry (address, name) where the name may be a NID string
    // like "0x44673f7a" — resolve those the table knows.
    for (_, name) in imp.externals.iter_mut() {
        let nid_text = name.strip_prefix("0x").unwrap_or(name);
        if let Ok(nid) = u32::from_str_radix(nid_text, 16) {
            if let Some(real) = table.names.get(&nid) {
                *name = real.clone();
                resolved += 1;
            }
        }
    }
    resolved
}
