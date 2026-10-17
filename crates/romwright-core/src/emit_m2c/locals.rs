//! Local storage the C type of its declaration cannot express.
//!
//! Ghidra declares a stack local by the bytes it covers (`undefined1 auStack_40[8]`, `undefined7 uStack_c0`)
//! and prints an access the declaration does not fit in three ways C has no spelling for:
//!
//! - **A mismatch use**: a varnode at the symbol's address whose width is not the symbol's prints `_NAME`
//!   (`PrintC::pushMismatchSymbol`), a name nothing declares.
//! - **A partial member**: `NAME._4_4_`, `NAME._0_8_`, the piece of a symbol at an offset and width.
//! - **A whole-array value**: an 8-byte store into an 8-byte array prints as `NAME = value`, which C rejects.
//!
//! Each is the same bytes read or written at the same address, so each is printed as that: a dereference of
//! the symbol's address cast to the scalar of the access's width (`(*(unsigned long long *)NAME)`), the type
//! the decompiler's own evidence gives it where it has any. A width with no C type (3, 5, 6, 7) has no lvalue
//! and is left as printed. An odd-width declaration (`undefined7`) is a byte array of that size.
//!
//! Switches (each `off` disables its rule): `ROMWRIGHT_EXPORT_ODD_WIDTHS` (the declarations),
//! `ROMWRIGHT_EXPORT_LOCAL_VIEWS` (partial members and whole-array values), `ROMWRIGHT_EXPORT_MISMATCH_NAMES`
//! (the `_NAME` uses).
use super::scalar_name;
use romwright_model::function_ir::{FunctionIr, HighVariable, ValueId};
use romwright_model::{DecompDoc, TokenKind};
use std::collections::BTreeMap;

/// Whether the rule behind `switch` is on: everything but `off`.
pub(super) fn enabled(switch: &str) -> bool {
    std::env::var(switch).map_or(true, |mode| mode != "off")
}

pub(super) const ODD_WIDTHS: &str = "ROMWRIGHT_EXPORT_ODD_WIDTHS";
pub(super) const LOCAL_VIEWS: &str = "ROMWRIGHT_EXPORT_LOCAL_VIEWS";
pub(super) const MISMATCH_NAMES: &str = "ROMWRIGHT_EXPORT_MISMATCH_NAMES";

/// The byte count of a Ghidra placeholder type name (`undefined7`) that no C type has the width of.
pub(super) fn odd_undefined(name: &str) -> Option<u64> {
    let size: u64 = name.strip_prefix("undefined")?.parse().ok()?;
    (size > 0 && !matches!(size, 1 | 2 | 4 | 8)).then_some(size)
}

fn unsigned_of(width: u32) -> Option<&'static str> {
    match width {
        1 => Some("unsigned char"),
        2 => Some("unsigned short"),
        4 => Some("unsigned int"),
        8 => Some("unsigned long long"),
        _ => None,
    }
}

/// The scalar a `width`-byte access of `id` is read and written as.
fn scalar(ir: &FunctionIr, high: &HighVariable, id: ValueId, width: u32) -> Option<String> {
    let unsigned = unsigned_of(width)?;
    let refined = (!high.type_locked)
        .then(|| ir.type_evidence.get(&id).copied())
        .flatten()
        .and_then(scalar_name)
        .filter(|name| match name.as_str() {
            "char" | "signed char" | "unsigned char" => width == 1,
            "short" | "unsigned short" => width == 2,
            "int" | "unsigned int" | "float" => width == 4,
            "long long" | "unsigned long long" | "double" => width == 8,
            _ => false,
        });
    Some(refined.unwrap_or_else(|| unsigned.to_string()))
}

fn blank(doc: &DecompDoc, index: usize) -> bool {
    doc.tokens[index].kind != TokenKind::Break && doc.tokens[index].text.trim().is_empty()
}

fn next(doc: &DecompDoc, mut index: usize) -> Option<usize> {
    while index + 1 < doc.tokens.len() {
        index += 1;
        if !blank(doc, index) {
            return Some(index);
        }
    }
    None
}

/// `_<offset>_<size>_`, the printer's name for a piece of a symbol no field covers.
fn unnamed_field(text: &str) -> Option<(u64, u32)> {
    let inner = text.strip_prefix('_')?.strip_suffix('_')?;
    let (offset, size) = inner.split_once('_')?;
    Some((offset.parse().ok()?, size.parse().ok()?))
}

/// The replacements, by token index, for the document's local variables. `names` is the generated-name
/// mapping the rendering applies to a variable token this does not replace.
pub(super) fn edits(doc: &DecompDoc, names: &BTreeMap<String, String>) -> BTreeMap<usize, String> {
    let mut edits = BTreeMap::new();
    let Some(ir) = &doc.function_ir else { return edits };
    let odd = enabled(ODD_WIDTHS);
    let views = enabled(LOCAL_VIEWS);
    let mismatch = enabled(MISMATCH_NAMES);
    if !odd && !views && !mismatch {
        return edits;
    }
    let owners: BTreeMap<ValueId, &HighVariable> = ir
        .high_variables
        .iter()
        .filter(|high| high.symbol.as_ref().is_some_and(|symbol| !symbol.global) && high.class != "global")
        .flat_map(|high| high.members.iter().map(move |member| (*member, high)))
        .collect();
    let shown = |name: &str| names.get(name).map_or(name, String::as_str).to_string();
    for (index, token) in doc.tokens.iter().enumerate() {
        if odd && token.kind == TokenKind::Type && token.symbol_id.is_some() {
            if let Some(size) = odd_undefined(&token.text)
                && let Some(var) = next(doc, index).filter(|&var| {
                    doc.tokens[var].kind == TokenKind::Variable && doc.tokens[var].symbol_id == token.symbol_id
                })
                && next(doc, var).is_none_or(|after| doc.tokens[after].text != "[")
            {
                edits.insert(index, "unsigned char".to_string());
                edits.insert(var, format!("{} [{size}]", shown(doc.tokens[var].text.trim())));
            }
            continue;
        }
        if token.kind != TokenKind::Variable || token.symbol_id.is_some() {
            continue;
        }
        let Some(id) = token.varnode else { continue };
        let Some(high) = owners.get(&id).copied() else { continue };
        let (Some(symbol), Some(value)) = (high.symbol.as_ref(), ir.values.get(&id)) else { continue };
        let Some(width) = value.size else { continue };
        let name = token.text.trim();
        if mismatch && name.strip_prefix('_') == Some(symbol.name.as_str()) && high.symbol_offset.unwrap_or(0) == 0 {
            if let Some(scalar) = scalar(ir, high, id, width) {
                edits.insert(index, format!("(*({scalar} *)&{})", shown(&symbol.name)));
            }
            continue;
        }
        // the unnamed location of an access that starts inside a symbol (`stack0xfffffe98`)
        let inside = high.symbol_offset.unwrap_or(0);
        if mismatch && inside > 0 && name.starts_with("stack0x") {
            if let Some(scalar) = scalar(ir, high, id, width) {
                edits.insert(index, format!("(*({scalar} *)((unsigned char *)&{} + {inside}))", shown(&symbol.name)));
            }
            continue;
        }
        if !views || name != symbol.name {
            continue;
        }
        // `NAME._off_width_`: the piece of the symbol at that offset
        let dot = next(doc, index).filter(|&dot| doc.tokens[dot].kind == TokenKind::Op && doc.tokens[dot].text == ".");
        let field = dot.and_then(|dot| next(doc, dot));
        if let (Some(dot), Some(field)) = (dot, field)
            && doc.tokens[field].kind == TokenKind::Syntax
            && let Some((offset, size)) = unnamed_field(doc.tokens[field].text.trim())
            && size == width
            && let Some(scalar) = scalar(ir, high, id, width)
        {
            edits.insert(index, format!("(*({scalar} *)((unsigned char *)&{} + {offset}))", shown(name)));
            edits.insert(dot, String::new());
            edits.insert(field, String::new());
            continue;
        }
        // an array stored or read whole: `NAME = value`
        let whole = high.symbol_offset.unwrap_or(0) == 0
            && symbol.data_type.metatype.as_deref() == Some("array")
            && symbol.data_type.size == Some(u64::from(width))
            && symbol.data_type.element_count.is_some_and(|count| count > 1);
        if whole && let Some(scalar) = scalar(ir, high, id, width) {
            edits.insert(index, format!("(*({scalar} *){})", shown(name)));
        }
    }
    edits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_widths_without_a_c_type_are_byte_arrays() {
        for size in [3, 5, 6, 7, 12] {
            assert_eq!(odd_undefined(&format!("undefined{size}")), Some(size));
        }
        for name in ["undefined", "undefined1", "undefined2", "undefined4", "undefined8", "uint", "undefined0", "undefinedX"] {
            assert_eq!(odd_undefined(name), None, "{name}");
        }
    }

    #[test]
    fn a_partial_member_names_its_offset_and_width() {
        assert_eq!(unnamed_field("_4_4_"), Some((4, 4)));
        assert_eq!(unnamed_field("_0_8_"), Some((0, 8)));
        assert_eq!(unnamed_field("u4"), None);
        assert_eq!(unnamed_field("_x_4_"), None);
    }
}
