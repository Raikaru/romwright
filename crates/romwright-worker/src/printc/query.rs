//! The worker's side of `romwright_structure.hh`: answers the structuring
//! query `ghidra_opt` sends whenever `ActionBlockStructure` would have built
//! its block tree (docs/printer-ir.md, "Unstructured handoff").

use super::tree::{PtrsubKind, Tables};
use super::{casts, collapse, ir, render};
use std::cell::RefCell;

/// `ELEM_ROMWRIGHT_STRUCTURE` (native/ghidra-opt-sleigh.patch, ghidra_arch.cc).
pub const QUERY_ID: u32 = 4092;

fn put(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = 0x40 | (value & 0x3f) as u8;
        value >>= 6;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

/// Structures the graph `payload` describes and answers what Ghidra's
/// structurer would have done to the p-code: the blocks whose condition it
/// negates, and for `ActionReturnSplit` the return-block edges that are
/// `goto`s.
pub fn answer(payload: &[u8]) -> Result<Vec<u8>, String> {
    // A structuring query starts with its block count, never zero; a cast
    // query starts with a zero.
    if payload.first() == Some(&0x40) {
        // The second value is the kind: 0 and 1 casts, 2 the merge query, 3 names, 4 the merge verify dump.
        return Ok(match payload.get(1).map(|b| b & 0x3f) {
            Some(2) => super::merge::answer_merge(payload),
            Some(3) => super::merge::names::answer_names(payload),
            Some(4) => super::merge::answer_dump(payload),
            _ => answer_casts(payload),
        });
    }
    let cfg = ir::decode_structure_query(payload)?;
    let analysis = collapse::analyze(&cfg)?;
    let mut out = Vec::new();
    put(&mut out, analysis.flips.len() as u64);
    for &block in &analysis.flips {
        put(&mut out, block as u64);
    }
    put(&mut out, analysis.returns.len() as u64);
    for (block, slots) in &analysis.returns {
        put(&mut out, *block as u64);
        put(&mut out, slots.len() as u64);
        for &slot in slots {
            put(&mut out, slot as u64);
        }
    }
    put(&mut out, analysis.splits.len() as u64);
    for split in &analysis.splits {
        put_split(&mut out, split);
    }
    put(&mut out, analysis.loops.len() as u64);
    for &(head, test, tail) in &analysis.loops {
        put(&mut out, head as u64);
        put(&mut out, test as u64);
        put(&mut out, tail as u64);
    }
    Ok(out)
}

fn put_split(out: &mut Vec<u8>, split: &collapse::Split) {
    match split {
        collapse::Split::None => put(out, 0),
        collapse::Split::Leaf(block) => {
            put(out, 1);
            put(out, *block as u64);
        }
        collapse::Split::Cond(_, left, right) => {
            put(out, 2);
            put_split(out, left);
            put_split(out, right);
        }
    }
}

thread_local! {
    /// `ROMWRIGHT_RUST_CASTS=verify`: the worker's cast statements, as text,
    /// until the decompiler's own casts of the same function arrive.
    static VERIFY: RefCell<Option<Vec<String>>> = const { RefCell::new(None) };
}

/// `ROMWRIGHT_RUST_CASTS`: `on` (default) the worker decides the casts of the
/// functions it can, `off` the decompiler always does, `verify` the
/// decompiler casts and the worker's casts are compared with its.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CastMode {
    On,
    Off,
    Verify,
}

fn cast_mode() -> CastMode {
    match std::env::var("ROMWRIGHT_RUST_CASTS").as_deref() {
        Ok("off" | "0" | "native") => CastMode::Off,
        Ok("verify") => CastMode::Verify,
        _ => CastMode::On,
    }
}

fn log_cast(line: serde_json::Value) {
    if let Some(path) = std::env::var_os("ROMWRIGHT_RUST_CASTS_LOG") {
        use std::io::Write;
        if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(file, "{line}");
        }
    }
}

fn declined(reason: &str) -> Vec<u8> {
    log_cast(serde_json::json!({"cast_declined": reason}));
    b"n".to_vec()
}

/// Answers `romwrightFinishCasts`: `o` and the pointer warnings
/// `ActionSetCasts::checkPointerIssues` would have added when the worker
/// casts the function, `v` when it does and the decompiler should too (verify
/// mode), `n` when the decompiler must.
fn answer_casts(payload: &[u8]) -> Vec<u8> {
    let mode = cast_mode();
    if mode == CastMode::Off {
        return declined("off");
    }
    if render::ExprMode::from_env() != render::ExprMode::On {
        return declined("expressions-off");
    }
    let query = match ir::decode_cast_query(payload) {
        Ok(query) => query,
        Err(reason) => return declined(&format!("decode:{reason}")),
    };
    let ir::CastQuery {
        marker,
        mut tables,
        options,
        statements,
        loop_ops,
    } = query;
    if marker == 1 {
        return compare_with_decompiler(&mut tables, &options, statements);
    }
    if std::env::var_os("ROMWRIGHT_RUST_CASTS_DEBUG").is_some() {
        for (index, statement) in statements.iter().enumerate() {
            eprintln!("cast-debug statement {index}: {}", casts::debug_text(&tables, statement));
        }
    }
    let cast = match casts::cast_function(&mut tables, &options, &casts::current_rules(), statements, loop_ops) {
        Ok(cast) => cast,
        Err(reason) => return declined(&reason),
    };
    let mut texts = Vec::with_capacity(cast.trees.len());
    let mut canon = Vec::with_capacity(cast.trees.len());
    for tree in &cast.trees {
        let normal = match render::render(&tables, &options, tree, false, false) {
            Ok(fragment) => fragment,
            Err(reason) => return declined(&format!("render:{reason}")),
        };
        if let super::tree::PNode::Op(root) = &tree.root
            && root.code == render::opc::CBRANCH {
                for (comma, invert) in [(true, false), (false, true), (true, true)] {
                    if let Err(reason) = render::render(&tables, &options, tree, comma, invert) {
                        return declined(&format!("render:{reason}"));
                    }
                }
            }
        texts.push(render::fragment_text(&normal));
        canon.push(tree_text(&tables, tree));
    }
    if tree_uses_no_ptrsub(&cast.trees) {
        return declined("ptrsub:no");
    }
    log_cast(serde_json::json!({"cast_ok": cast.stats}));
    if mode == CastMode::Verify {
        let _ = texts;
        VERIFY.with(|slot| *slot.borrow_mut() = Some(canon));
        return b"v".to_vec();
    }
    let mut out = vec![b'o'];
    put(&mut out, cast.warnings.len() as u64);
    for (time, code) in &cast.warnings {
        put(&mut out, *time);
        put(&mut out, u64::from(*code));
    }
    out
}

fn tree_uses_no_ptrsub(trees: &[super::tree::PrintTree]) -> bool {
    fn walk(node: &super::tree::PNode) -> bool {
        match node {
            super::tree::PNode::Op(op) => {
                matches!(&op.extra, super::tree::Extra::Ptrsub(PtrsubKind::No(_)))
                    || op.kids.iter().any(walk)
            }
            _ => false,
        }
    }
    trees.iter().any(|tree| walk(&tree.root))
}

/// A canonical text of a type: names and shape, never table indices.
fn type_text(tables: &Tables, index: usize, depth: usize) -> String {
    let ty = &tables.types[index];
    if depth > 6 {
        return "..".into();
    }
    match (ty.meta, ty.base) {
        (super::tree::meta::PTR | super::tree::meta::PTRREL, Some(base)) => {
            format!("*{}", type_text(tables, base, depth + 1))
        }
        (super::tree::meta::ARRAY, Some(base)) => {
            format!("{}[{}]", type_text(tables, base, depth + 1), ty.elements)
        }
        _ if ty.name.is_empty() => format!("<m{}s{}>", ty.meta, ty.size),
        _ => ty.name.clone(),
    }
}

fn node_text(tables: &Tables, node: &super::tree::PNode, out: &mut String) {
    use super::tree::{Extra, PNode};
    match node {
        PNode::No(reason) => out.push_str(&format!("(no {reason})")),
        PNode::Const(c) => out.push_str(&format!(
            "#{:x}:{}{}{}",
            c.value,
            type_text(tables, c.ty, 0),
            if c.unsigned_print { "u" } else { "" },
            if c.long_print { "l" } else { "" }
        )),
        PNode::Atom { event, .. } => out.push_str(&format!("(atom {event:?})")),
        PNode::Symbol { sym, .. } => out.push_str(&tables.symbols[*sym].name),
        PNode::Partial(p) => out.push_str(&format!("{}@{}", tables.symbols[p.sym].name, p.offset)),
        PNode::Op(op) => {
            out.push_str(&format!("({}", op.code));
            match &op.extra {
                Extra::Ext { out: o, input, implied, .. } => out.push_str(&format!(
                    "<{}<-{} implied={}>",
                    type_text(tables, *o, 0),
                    type_text(tables, *input, 0),
                    implied
                )),
                Extra::Subpiece { out: o, input, .. } => out.push_str(&format!(
                    "<{}<-{}>",
                    type_text(tables, *o, 0),
                    type_text(tables, *input, 0)
                )),
                Extra::Cast { out: o, .. } | Extra::Int2Float { out: o } => {
                    out.push_str(&format!("<{}>", type_text(tables, *o, 0)))
                }
                Extra::Ptrsub(kind) => out.push_str(&format!("<{}>", match kind {
                    PtrsubKind::Struct { field, .. } => format!("field {field}"),
                    PtrsubKind::Array => "array".into(),
                    PtrsubKind::Spacebase { symbol_kind, .. } => format!("space{symbol_kind}"),
                    PtrsubKind::No(reason) => reason.clone(),
                })),
                _ => {}
            }
            for kid in &op.kids {
                out.push(' ');
                node_text(tables, kid, out);
            }
            out.push(')');
        }
    }
}

fn tree_text(tables: &Tables, tree: &super::tree::PrintTree) -> String {
    let mut out = String::new();
    if let Some(leaf) = &tree.out {
        node_text(tables, leaf, &mut out);
        out.push_str(" = ");
    }
    node_text(tables, &tree.root, &mut out);
    out
}

/// Verify mode: the decompiler's own casts of the function the worker just
/// decided, against the worker's. Differences go to `ROMWRIGHT_RUST_CASTS_LOG`.
fn compare_with_decompiler(
    tables: &mut Tables,
    options: &super::tree::Options,
    statements: Vec<casts::CTree>,
) -> Vec<u8> {
    let Some(ours) = VERIFY.with(|slot| slot.borrow_mut().take()) else {
        return b"n".to_vec();
    };
    let rules = casts::current_rules();
    let mut pass = casts::Pass::new(tables, options, &rules);
    let mut theirs = Vec::with_capacity(statements.len());
    for statement in statements {
        match pass.finish(statement) {
            Ok(tree) => theirs.push(tree),
            Err(reason) => {
                log_cast(serde_json::json!({"cast_mismatch": {"decompiler_tree_error": reason}}));
                return b"n".to_vec();
            }
        }
    }
    let texts: Vec<String> = theirs.iter().map(|tree| tree_text(tables, tree)).collect();
    if texts.len() != ours.len() {
        log_cast(serde_json::json!({"cast_mismatch": {"statements": [ours.len(), texts.len()]}}));
        return b"n".to_vec();
    }
    for (index, (ours, theirs)) in ours.iter().zip(texts.iter()).enumerate() {
        if ours == theirs {
            log_cast(serde_json::json!({"cast_verified": 1}));
        } else {
            log_cast(serde_json::json!({"cast_mismatch": {"statement": index, "worker": ours, "decompiler": theirs}}));
        }
    }
    b"n".to_vec()
}
