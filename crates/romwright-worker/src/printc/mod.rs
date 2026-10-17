//! The Rust C printer: every decompiled function's C is printed here.
//!
//! `ghidra_opt` exports a printer IR (`native/romwright_printir.hh`) holding
//! the function's unstructured control-flow graph and its statements; this
//! module builds the block tree from the graph ([`collapse`], a port of
//! Ghidra's `CollapseStructure`), structures it further ([`structure`], every
//! model by default) and prints it, producing the same packed markup PrintC
//! does, so the token decoder, post-processing and consumers are unchanged.
//! `ghidra_opt` asks [`query`] mid-decompile what Ghidra's structurer would
//! have done to the p-code. PrintC's markup (and Ghidra's own tree) exist only
//! on the stock path (`ROMWRIGHT_NATIVE_STRUCTURE=1`): the reference of the
//! printer differential ([`reference`], benchmarks/printer_diff.py) and of the
//! structuring differential (benchmarks/structure_handoff.py). See
//! docs/printer-ir.md.

pub mod casts;
pub mod collapse;
mod expr;
pub mod gte;
pub mod ir;
pub mod merge;
mod ownership;
pub mod pretty;
mod printer;
pub mod query;
pub mod render;
pub mod structure;
pub mod tree;

pub use ownership::PrintStats;

/// `ELEM_ROMWRIGHT_PRINTIR` (native/romwright_printir.hh).
pub const ELEM_PRINTIR: u32 = 4091;
const ELEM_DOC: u32 = crate::wire::elem::DOC;
const ELEM_FUNCTION: u32 = crate::wire::elem::FUNCTION;
const ATTRIB_CONTENT: u32 = 1;

/// Where the block tree comes from (`ROMWRIGHT_STRUCTURE`): unset builds it
/// in Rust from the exported graph when the decompiler did not structure the
/// function, and uses the decompiler's own tree when it did
/// (`ROMWRIGHT_NATIVE_STRUCTURE=1` in `ghidra_opt`); `rust` always builds it;
/// `native` requires the decompiler's; `verify` builds it, compares it with
/// the decompiler's tree (appending one JSON line per function to
/// `ROMWRIGHT_STRUCTURE_VERIFY_FILE`, or the differences to stderr) and
/// prints the decompiler's.
fn materialize(ir: &mut ir::PrinterIr) -> Result<(), String> {
    let mode = std::env::var("ROMWRIGHT_STRUCTURE").unwrap_or_default();
    let have_tree = !ir.body.is_empty();
    let build = match mode.as_str() {
        "" => !have_tree,
        "rust" | "verify" => true,
        "native" => false,
        other => return Err(format!("ROMWRIGHT_STRUCTURE={other}: expected rust, native or verify")),
    };
    if !build {
        if !have_tree {
            return Err("the decompiler did not structure the function".into());
        }
        ir.cfg = None;
        ir.native_tree = true;
        return Ok(());
    }
    let Some(mut cfg) = ir.cfg.take() else {
        return Err("printer IR has no control-flow graph".into());
    };
    let tree = collapse::build(&mut cfg)?;
    if mode == "verify" && have_tree {
        // The decompiler's tree has no statements for the loops' header ops (it
        // marked them non-printing); the worker's takes them out the same way.
        let mut native = ir.body.clone();
        collapse::take_loop_ops(&mut native);
        let ours: Vec<String> = tree.body.iter().map(collapse::shape).collect();
        let theirs: Vec<String> = native.iter().map(collapse::shape).collect();
        let name = ir.declaration.0.iter().find_map(|event| match event {
            ir::Event::FuncName { name, .. } => Some(name.clone()),
            _ => None,
        });
        let line = if ours != theirs {
            serde_json::json!({"structure_verify": {"function": name, "equal": false,
                "rust": ours.join(" "), "native": theirs.join(" ")}})
        } else {
            serde_json::json!({"structure_verify": {"function": name, "equal": true}})
        };
        // The worker's stderr does not reach the caller: a file collects the lines.
        if let Some(path) = std::env::var_os("ROMWRIGHT_STRUCTURE_VERIFY_FILE") {
            use std::io::Write;
            if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
                let _ = writeln!(file, "{line}");
            }
        } else if ours != theirs {
            eprintln!("{line}");
        }
        return Ok(());
    }
    ir.body = tree.body;
    ir.native_tree = false;
    Ok(())
}

/// Prints a decoded IR. Two passes: the first counts the TokenSplit ids the
/// function consumes, the second starts the counter where PrintC's did.
pub fn print(ir: &ir::PrinterIr) -> Result<Vec<u8>, String> {
    let (_, consumed) = printer::print_function(ir, 0)?;
    let (markup, _) = printer::print_function(ir, ir.count_after.wrapping_sub(consumed))?;
    Ok(markup)
}

/// Decodes and prints a `<romwright_printir>` blob, after the structuring
/// models `ROMWRIGHT_RUST_STRUCTURING` selects (all of them when unset;
/// docs/printer-ir.md). A restructured tree that does not print falls back
/// to Ghidra's.
pub fn render(blob: &[u8]) -> Result<Vec<u8>, String> {
    render_with_stats(blob).map(|(markup, _)| markup)
}

/// [`print`], also accounting for where the printed tokens came from.
fn print_counted(ir: &ir::PrinterIr) -> Result<(Vec<u8>, ownership::TokenStats), String> {
    let (_, consumed, _) = printer::print_function_counted(ir, 0)?;
    let (markup, _, counts) =
        printer::print_function_counted(ir, ir.count_after.wrapping_sub(consumed))?;
    Ok((markup, ownership::TokenStats::from_counts(&counts)))
}

/// [`render`], also returning the ownership accounting of the printed
/// function (docs/ownership.md). The text is [`render`]'s.
pub fn render_with_stats(blob: &[u8]) -> Result<(Vec<u8>, PrintStats), String> {
    let mut ir = ir::decode(blob)?;
    materialize(&mut ir)?;
    let settings = structure::settings_from_env()?;
    // psyq-style GTE macros: on the decoded IR, so `reference` never sees it.
    let gte = if gte::enabled() {
        gte::lift(&mut ir)
    } else {
        gte::GteStats::default()
    };
    let mut stats = PrintStats {
        expressions: ir.expressions.clone(),
        gte,
        cast_types: ir.cast_types.clone(),
        call_types: std::mem::take(&mut ir.call_types),
        cast_edits: std::mem::take(&mut ir.cast_edits),
        ..PrintStats::default()
    };
    if !settings.models.is_empty() {
        let original = ir.body.clone();
        let outcome = structure::restructure(&mut ir, &settings);
        stats.gotos = [outcome.before.gotos as u64, outcome.after.gotos as u64];
        stats.labels = [outcome.before.labels as u64, outcome.after.labels as u64];
        stats.applied = outcome
            .applied
            .iter()
            .filter(|(_, count)| *count > 0)
            .map(|(model, count)| (model.name().to_string(), *count as u64))
            .collect();
        stats.structuring_refused = outcome.refused.clone();
        if std::env::var_os("ROMWRIGHT_RUST_STRUCTURING_LOG").is_some() {
            let applied: serde_json::Map<String, serde_json::Value> = outcome
                .applied
                .iter()
                .map(|(model, count)| (model.name().to_string(), (*count).into()))
                .collect();
            eprintln!(
                "{}",
                serde_json::json!({"structuring": {
                    "function": ir.declaration.0.iter().find_map(|event| match event {
                        ir::Event::FuncName { name, .. } => Some(name.as_str()),
                        _ => None,
                    }),
                    "before": [outcome.before.gotos, outcome.before.labels],
                    "after": [outcome.after.gotos, outcome.after.labels],
                    "applied": applied,
                    "remaining": outcome.remaining,
                    "refused": outcome.refused,
                    "attempts": outcome.attempts,
                    "ordered": outcome.ordered,
                }})
            );
        }
        if outcome.changed()
            && let Ok((markup, tokens)) = print_counted(&ir)
        {
            // The constructs the worker's own structure builds are all its own.
            stats.constructs = ownership::construct_stats(
                if ir.native_tree { &original } else { &[] },
                &ir.body,
            );
            stats.tokens = tokens;
            stats.restructured = true;
            return Ok((markup, stats));
        }
        ir.body = original;
    }
    // The printed tree is Ghidra's: models off, none kept, or the rewrite
    // did not print.
    stats.restructured = false;
    stats.applied.clear();
    let (markup, tokens) = print_counted(&ir)?;
    stats.constructs = ownership::construct_stats(if ir.native_tree { &ir.body } else { &[] }, &ir.body);
    stats.tokens = tokens;
    if let Ok(counts) = structure::counts(&ir) {
        stats.gotos = [counts.gotos as u64; 2];
        stats.labels = [counts.labels as u64; 2];
    }
    Ok((markup, stats))
}

/// Prints a `<romwright_printir>` blob as Ghidra structured it, without the
/// structuring models: what the printer differential compares against
/// PrintC's markup byte for byte.
pub fn reference(blob: &[u8]) -> Result<Vec<u8>, String> {
    reference_with_stats(blob).map(|(markup, _)| markup)
}

/// [`reference`], also returning what the expression printer did with each
/// expression (`ROMWRIGHT_RUST_EXPRESSIONS`; docs/printer-ir.md).
pub fn reference_with_stats(blob: &[u8]) -> Result<(Vec<u8>, render::ExprStats), String> {
    let mut ir = ir::decode(blob)?;
    materialize(&mut ir)?;
    Ok((print(&ir)?, ir.expressions))
}

/// The two printer outputs a decompile response can carry.
#[derive(Debug, Default)]
pub struct Sections<'a> {
    /// PrintC's `<function>` markup (the second `<function>` under `<doc>`;
    /// the first is `Funcdata::encode`).
    pub markup: Option<&'a [u8]>,
    /// The printer IR blob.
    pub printer_ir: Option<&'a [u8]>,
}

/// Splits a packed `<doc>` response into PrintC's markup and the printer IR.
pub fn sections(doc: &[u8]) -> Result<Sections<'_>, String> {
    let mut sections = Sections::default();
    let mut position = 0usize;
    let mut stack: Vec<u32> = Vec::new();
    let mut functions = 0usize;
    let mut child_start = 0usize;
    let byte = |position: usize| {
        doc.get(position)
            .copied()
            .ok_or("packed document truncated")
    };
    while position < doc.len() {
        let start = position;
        let header = byte(position)?;
        position += 1;
        let mut id = u32::from(header & 0x1f);
        if header & 0x20 != 0 {
            id = (id << 7) | u32::from(byte(position)? & 0x7f);
            position += 1;
        }
        match header & 0xc0 {
            0x40 => {
                if stack.len() == 1 {
                    child_start = start;
                }
                stack.push(id);
            }
            0x80 => {
                if stack.pop() != Some(id) {
                    return Err("packed document closes the wrong element".into());
                }
                if stack.len() == 1 && stack[0] == ELEM_DOC && id == ELEM_FUNCTION {
                    functions += 1;
                    if functions == 2 {
                        sections.markup = Some(&doc[child_start..position]);
                    }
                }
            }
            0xc0 => {
                let type_byte = byte(position)?;
                position += 1;
                let length = usize::from(type_byte & 0x0f);
                let mut value = 0u64;
                match type_byte >> 4 {
                    1 | 6 => {}
                    2..=5 | 7 => {
                        for _ in 0..length {
                            value = (value << 7) | u64::from(byte(position)? & 0x7f);
                            position += 1;
                        }
                    }
                    other => return Err(format!("packed attribute type {other}")),
                }
                if type_byte >> 4 == 7 {
                    let length = usize::try_from(value).map_err(|_| "packed string length")?;
                    let end = position.checked_add(length).ok_or("packed string length")?;
                    let bytes = doc.get(position..end).ok_or("packed document truncated")?;
                    if id == ATTRIB_CONTENT
                        && stack.last() == Some(&ELEM_PRINTIR)
                        && stack.len() == 2
                    {
                        sections.printer_ir = Some(bytes);
                    }
                    position = end;
                }
            }
            _ => return Err("packed document has a bad header".into()),
        }
    }
    if !stack.is_empty() {
        return Err("packed document is incomplete".into());
    }
    Ok(sections)
}

#[cfg(test)]
mod tests;
