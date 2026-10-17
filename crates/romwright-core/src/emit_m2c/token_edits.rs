//! Token-level edits whose evidence is the function's machine code, which the
//! decompiler's IR no longer states.
//!
//! - **Narrow loads keep the extension the instruction performed.** `lhu` is
//!   an unsigned halfword and `lh` a signed one, but once the value is only
//!   used at its own width the decompiler drops the extension and types the
//!   access by whatever the arithmetic around it suggests (`*(short *)p - 1`
//!   for a `lhu`). The load's operation names its instruction; the cast's type
//!   is made to agree with it. A recompile that is given the other signedness
//!   emits the other load.
//! - **One store instruction is one store.** A `sh` of a constant is printed
//!   as two byte stores when the pointer is a byte pointer; the two stores
//!   come from the same instruction, and a compiler given two statements
//!   emits two `sb`. They are printed as the one store they were.
use super::machine::Machine;
use romwright_model::function_ir::{IrSpace, Opcode, OperationId};
use romwright_model::{DecompDoc, TokenKind};
use std::collections::BTreeMap;

/// The replacements, by token index, for the document's tokens.
pub(super) fn edits(doc: &DecompDoc, machine: &Machine<'_>) -> BTreeMap<usize, String> {
    let mut edits = BTreeMap::new();
    narrow_loads(doc, machine, &mut edits);
    merged_stores(doc, &mut edits);
    edits
}

fn blank(doc: &DecompDoc, index: usize) -> bool {
    doc.tokens[index].kind != TokenKind::Break && doc.tokens[index].text.trim().is_empty()
}

fn previous(doc: &DecompDoc, mut index: usize) -> Option<usize> {
    while index > 0 {
        index -= 1;
        if !blank(doc, index) {
            return Some(index);
        }
    }
    None
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

fn literal(text: &str) -> Option<u64> {
    let text = text.trim();
    match text.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => text.parse().ok(),
    }
}

/// The type names a decompiler prints for a one-byte or two-byte integer.
fn narrow_type(text: &str) -> Option<u32> {
    match text {
        "char" | "signed char" | "unsigned char" | "byte" | "undefined1" | "uchar" | "sbyte" => Some(1),
        "short" | "unsigned short" | "ushort" | "undefined2" | "word" => Some(2),
        _ => None,
    }
}

fn narrow_loads(doc: &DecompDoc, machine: &Machine<'_>, edits: &mut BTreeMap<usize, String>) {
    let Some(ir) = &doc.function_ir else { return };
    let loads: BTreeMap<OperationId, _> = ir
        .blocks
        .iter()
        .flat_map(|block| &block.operations)
        .filter(|op| op.opcode == Opcode::LOAD)
        .filter_map(|op| machine.code.narrow_load(op.address.offset).map(|load| (op.id, load)))
        .collect();
    if loads.is_empty() {
        return;
    }
    for (index, token) in doc.tokens.iter().enumerate() {
        let Some(load) = token.operation.filter(|_| token.kind == TokenKind::Op && token.text == "*")
            .and_then(|operation| loads.get(&operation))
        else {
            continue;
        };
        // `*(T *)(`: the type is the third visible token after the dereference
        let Some(open) = next(doc, index).filter(|&open| doc.tokens[open].text == "(") else { continue };
        let Some(ty) = next(doc, open).filter(|&ty| doc.tokens[ty].kind == TokenKind::Type) else { continue };
        let Some(star) = next(doc, ty).filter(|&star| doc.tokens[star].text == "*") else { continue };
        if next(doc, star).is_none_or(|close| doc.tokens[close].text != ")") {
            continue;
        }
        if narrow_type(&doc.tokens[ty].text) != Some(load.bytes) {
            continue;
        }
        let name = match (load.bytes, load.signed) {
            (1, true) => "signed char",
            (1, false) => "unsigned char",
            (_, true) => "short",
            (_, false) => "unsigned short",
        };
        if doc.tokens[ty].text != name {
            edits.insert(ty, name.to_string());
        }
    }
}

/// One byte store printed as `base[offset] = value;` and the tokens that make it up.
struct ByteStore {
    base: String,
    offset: u64,
    value: u64,
    /// The Break that starts the statement, its `[`, `]`, value token and `;`.
    start: usize,
    open: usize,
    close: usize,
    value_token: usize,
    end: usize,
}

fn byte_store(doc: &DecompDoc, operation: OperationId, value: u64) -> Option<ByteStore> {
    let equals = doc.tokens.iter().position(|t| t.kind == TokenKind::Op && t.text == "=" && t.operation == Some(operation))?;
    let close = previous(doc, equals).filter(|&i| doc.tokens[i].text == "]")?;
    let offset_token = previous(doc, close)?;
    let open = previous(doc, offset_token).filter(|&i| doc.tokens[i].text == "[")?;
    let base_token = previous(doc, open).filter(|&i| doc.tokens[i].kind == TokenKind::Variable)?;
    let offset = literal(&doc.tokens[offset_token].text)?;
    let value_token = next(doc, equals).filter(|&i| doc.tokens[i].kind == TokenKind::Variable)?;
    literal(&doc.tokens[value_token].text).filter(|&printed| printed & 0xff == value)?;
    let end = next(doc, value_token).filter(|&i| doc.tokens[i].text == ";")?;
    let mut start = base_token;
    while start > 0 {
        start -= 1;
        if doc.tokens[start].kind == TokenKind::Break {
            break;
        }
        if !blank(doc, start) {
            return None;
        }
    }
    (doc.tokens[start].kind == TokenKind::Break).then(|| ByteStore {
        base: doc.tokens[base_token].text.clone(),
        offset,
        value,
        start,
        open,
        close,
        value_token,
        end,
    })
}

fn merged_stores(doc: &DecompDoc, edits: &mut BTreeMap<usize, String>) {
    let Some(ir) = &doc.function_ir else { return };
    // the constant one-byte stores of each instruction
    let mut by_instruction: BTreeMap<u64, Vec<(OperationId, u64)>> = BTreeMap::new();
    for op in ir.blocks.iter().flat_map(|block| &block.operations).filter(|op| op.opcode == Opcode::STORE) {
        let Some(romwright_model::function_ir::Operand::Value(data)) = op.inputs.get(2) else { continue };
        let Some(data) = ir.values.get(data) else { continue };
        if data.space == IrSpace::Index(0) && data.size == Some(1)
            && let Some(value) = data.offset {
                by_instruction.entry(op.address.offset).or_default().push((op.id, value));
            }
    }
    for stores in by_instruction.into_values().filter(|stores| matches!(stores.len(), 2 | 4 | 8)) {
        let Some(mut stores) = stores.into_iter().map(|(op, value)| byte_store(doc, op, value)).collect::<Option<Vec<_>>>() else {
            continue;
        };
        stores.sort_by_key(|store| store.offset);
        let first = &stores[0];
        let adjacent = stores.windows(2).all(|pair| {
            let (a, b) = (&pair[0], &pair[1]);
            a.base == b.base
                && b.offset == a.offset + 1
                && (a.end + 1..b.start).all(|i| blank(doc, i))
                && b.start > a.end
        });
        if !adjacent || first.base.is_empty() {
            continue;
        }
        let width = stores.len();
        let value = stores.iter().enumerate().fold(0u64, |acc, (i, store)| acc | (store.value << (8 * i)));
        let (ty, suffix) = match width {
            2 => ("unsigned short", ""),
            4 => ("unsigned int", if value > 0x7fff_ffff { "U" } else { "" }),
            _ => ("unsigned long long", "ULL"),
        };
        let indent = doc.tokens[first.start].indent.unwrap_or(0).clamp(0, 256) as usize;
        edits.insert(first.start, format!("\n{}*({ty} *)(", " ".repeat(indent)));
        edits.insert(first.open, " + ".to_string());
        edits.insert(first.close, ")".to_string());
        edits.insert(first.value_token, if value < 10 && suffix.is_empty() { value.to_string() } else { format!("{value:#x}{suffix}") });
        for store in &stores[1..] {
            for index in store.start..=store.end {
                edits.insert(index, String::new());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emit_m2c::machine::MachineCode;
    use serde_json::{Value, json};
    use std::collections::BTreeSet;

    fn token(text: &str, kind: &str, operation: Option<u64>, indent: Option<i64>) -> Value {
        json!({"text": text, "kind": kind, "color": 0, "operation": operation, "indent": indent})
    }

    fn statement(out: &mut Vec<Value>, base: &str, offset: &str, store: u64, value: &str) {
        out.push(token("", "Break", None, Some(2)));
        out.push(token(base, "Variable", Some(1), None));
        out.push(token("[", "Syntax", None, None));
        out.push(token(offset, "Variable", Some(1), None));
        out.push(token("]", "Syntax", None, None));
        out.push(token(" ", "Syntax", None, None));
        out.push(token("=", "Op", Some(store), None));
        out.push(token(" ", "Syntax", None, None));
        out.push(token(value, "Variable", Some(store), None));
        out.push(token(";", "Syntax", None, None));
    }

    fn store(id: u64, address: u64, data: u64) -> Value {
        json!({"id": id, "address": {"space": "Ram", "offset": address}, "opcode": "STORE", "output": null,
               "inputs": [{"kind": "space", "value": {"kind": "index", "value": 3}},
                          {"kind": "value", "value": 500}, {"kind": "value", "value": data}]})
    }

    fn load(id: u64, address: u64) -> Value {
        json!({"id": id, "address": {"space": "Ram", "offset": address}, "opcode": "LOAD", "output": 501,
               "inputs": [{"kind": "space", "value": {"kind": "index", "value": 3}}, {"kind": "value", "value": 500}]})
    }

    fn constant(id: u64, value: u64, size: u32) -> Value {
        json!({"id": id, "space": {"kind": "index", "value": 0}, "offset": value, "size": size, "pieces": [],
               "input": false, "persistent": false, "address_tied": false, "unaffected": false, "volatile": false})
    }

    fn doc(tokens: Vec<Value>, operations: Vec<Value>, constants: Vec<Value>) -> DecompDoc {
        let values: serde_json::Map<String, Value> =
            constants.into_iter().map(|v| (v["id"].to_string(), v)).collect();
        serde_json::from_value(json!({
            "tokens": tokens, "address": {"space": "Ram", "offset": 0x1000}, "revision": 1,
            "function_ir": {"values": values,
                "blocks": [{"id": 0, "operations": operations, "predecessors": [], "successors": []}],
                "high_variables": []}
        }))
        .expect("test document")
    }

    fn render(doc: &DecompDoc, edits: &BTreeMap<usize, String>) -> String {
        crate::emit_m2c::render_named_doc(doc, &BTreeMap::new(), &BTreeMap::new(), edits)
    }

    fn machine(words: &[u32]) -> MachineCode {
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        MachineCode::new("r5900:LE:32:default", 0x1000, &bytes)
    }

    fn with_machine<T>(code: &MachineCode, f: impl FnOnce(&Machine<'_>) -> T) -> T {
        let constants = BTreeSet::new();
        let names = BTreeMap::new();
        f(&Machine { code, constants: &constants, names: &names })
    }

    #[test]
    fn two_byte_stores_of_one_instruction_are_one_halfword_store() {
        // sh zero, 0x10c(s0): printed as two byte stores
        let mut tokens = Vec::new();
        statement(&mut tokens, "param_1", "0x10c", 10, "0");
        statement(&mut tokens, "param_1", "0x10d", 11, "0");
        tokens.push(token("", "Break", None, Some(2)));
        tokens.push(token("return", "Syntax", None, None));
        let doc = doc(tokens, vec![store(10, 0x1000, 20), store(11, 0x1000, 21)], vec![constant(20, 0, 1), constant(21, 0, 1)]);
        let text = with_machine(&machine(&[0]), |m| render(&doc, &edits(&doc, m)));
        assert_eq!(text, "\n  *(unsigned short *)(param_1 + 0x10c) = 0;\n  return");
    }

    #[test]
    fn stores_of_two_instructions_stay_two_stores() {
        let mut tokens = Vec::new();
        statement(&mut tokens, "p", "4", 10, "0");
        statement(&mut tokens, "p", "5", 11, "0");
        let doc = doc(tokens, vec![store(10, 0x1000, 20), store(11, 0x1004, 21)], vec![constant(20, 0, 1), constant(21, 0, 1)]);
        let text = with_machine(&machine(&[0, 0]), |m| render(&doc, &edits(&doc, m)));
        assert_eq!(text, render(&doc, &BTreeMap::new()));
    }

    #[test]
    fn the_merged_constant_is_little_endian() {
        // sh v1, 8(v0) with v1 = 0x0201: stores of 1 then 2
        let mut tokens = Vec::new();
        statement(&mut tokens, "p", "8", 10, "1");
        statement(&mut tokens, "p", "9", 11, "2");
        let doc = doc(tokens, vec![store(10, 0x1000, 20), store(11, 0x1000, 21)], vec![constant(20, 1, 1), constant(21, 2, 1)]);
        let text = with_machine(&machine(&[0]), |m| render(&doc, &edits(&doc, m)));
        assert_eq!(text, "\n  *(unsigned short *)(p + 8) = 0x201;");
    }

    fn deref(out: &mut Vec<Value>, load: u64, ty: &str) {
        out.push(token("", "Break", None, Some(2)));
        out.push(token("*", "Op", Some(load), None));
        out.push(token("(", "Syntax", None, None));
        out.push(json!({"text": ty, "kind": "Type", "color": 0, "datatype_id": 7}));
        out.push(token(" ", "Syntax", None, None));
        out.push(token("*", "Op", None, None));
        out.push(token(")", "Syntax", None, None));
        out.push(token("p", "Variable", None, None));
    }

    #[test]
    fn a_narrow_load_has_the_signedness_of_its_instruction() {
        let lhu = 0x25u32 << 26;
        let lb = 0x20u32 << 26;
        let lh = 0x21u32 << 26;
        // `*(short *)p` that was a lhu, `*(unsigned char *)p` that was a lb, `*(short *)p` that was a lh
        let mut tokens = Vec::new();
        deref(&mut tokens, 10, "short");
        deref(&mut tokens, 11, "unsigned char");
        deref(&mut tokens, 12, "short");
        let doc = doc(tokens, vec![load(10, 0x1000), load(11, 0x1004), load(12, 0x1008)], vec![]);
        let text = with_machine(&machine(&[lhu, lb, lh]), |m| render(&doc, &edits(&doc, m)));
        assert_eq!(
            text,
            "\n  *(unsigned short *)p\n  *(signed char *)p\n  *(short *)p"
        );
    }
}
