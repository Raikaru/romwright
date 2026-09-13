//! SDK type pipeline (P3.10): applying the console SDK's function
//! prototypes to recovered functions. A signature match names the
//! function; the SDK's type archive names its prototype — the return
//! type and the parameter list — so a matched `sceKernelCreateThread`
//! is rendered with its real signature, not a guessed one.
//!
//! The type archive is a `.gdt` (Ghidra data-type archive) — a
//! Java-serialized container the bridge dumps to a text table of
//! `name = prototype` pairs. This module parses that table and applies
//! it: each function whose name the table knows gets the prototype
//! recorded as its signature.

use std::collections::HashMap;

/// A parsed prototype table: function name → C prototype text.
#[derive(Clone, Debug, Default)]
pub struct PrototypeTable {
    pub prototypes: HashMap<String, String>,
}

/// Parses a prototype table: lines of `name = prototype` or
/// `name: prototype`. Blank lines and `#` comments are skipped.
pub fn parse_table(text: &str) -> PrototypeTable {
    let mut prototypes = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, proto) = if let Some(eq) = line.find('=') {
            (line[..eq].trim(), line[eq + 1..].trim())
        } else if let Some(colon) = line.find(':') {
            (line[..colon].trim(), line[colon + 1..].trim())
        } else {
            continue;
        };
        if !name.is_empty() && !proto.is_empty() {
            prototypes.insert(name.to_string(), proto.to_string());
        }
    }
    PrototypeTable { prototypes }
}

/// The prototype a function name resolves to, when the table knows it.
pub fn prototype_for<'a>(table: &'a PrototypeTable, name: &str) -> Option<&'a str> {
    table.prototypes.get(name).map(String::as_str)
}
