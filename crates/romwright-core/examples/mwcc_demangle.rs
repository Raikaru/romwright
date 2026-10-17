//! Reads symbol names on stdin and prints `name<TAB>demangled` (or `-` when
//! the MWCC demangler refuses). Driver for `benchmarks/mwcc_demangle_diff.py`,
//! which compares this output against `dtk demangle`.
//!
//! Default dialect is `dtk`'s (no `T`/`N` back-references) so the two are
//! comparable name for name; `--extensions` turns the back-reference
//! expansion on.

use romwright_core::qualified_prototypes::mwcc_demangle::{Options, demangle_with};
use std::io::{BufRead, Write};

fn main() {
    let options = if std::env::args().any(|arg| arg == "--extensions") {
        Options::default()
    } else {
        Options::DTK
    };
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    for line in stdin.lock().lines() {
        let Ok(name) = line else { break };
        let shown = demangle_with(&name, options).map_or_else(|| "-".to_string(), |d| d.text);
        let _ = writeln!(out, "{name}\t{shown}");
    }
}
