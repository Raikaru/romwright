//! m2c-parity emission layer (P4.6): deterministic post-processing that
//! renders a [`romwright_model::DecompDoc`] token stream as m2c-shaped C.
//!
//! The decompiler's own output is a token stream (`DecompDoc::tokens`);
//! the only render layer the tree has is the Qt view splitting lines on
//! Break tokens. This module is the batch/CLI equivalent plus the
//! canonicalizations a matching project needs before it can diff our C
//! against m2c's:
//!
//! - **Render** ([`render_doc_text`]): Break tokens end a line and indent
//!   the next by their `indent` count, every other token appends its
//!   text. This mirrors `crates/romwright-desktop/src/panels/decompiler/source.rs`
//!   ("Break tokens end a line and indent the next").
//! - **Deterministic temporaries** ([`TempNamer`]): decompiler-generated
//!   locals (`uVar1`, `local_10`, …) become `temp_v0`/`temp_f0`-shaped
//!   typed temps, stack slots become `sp<HEX>` (`sp1C`), in first-use
//!   order. Names that already carry meaning — prototype params,
//!   address-named globals (`DAT_*`, `FUN_*`, …), irregular inputs
//!   (`in_*`), caller-kept names — pass through untouched.
//! - **Honesty markers** ([`mark_irregular`]): where structuring failed
//!   (unstructured edges, `goto`s, `in_*` irregular inputs) a
//!   `/* irregular: … */` comment is inserted after the body's opening
//!   brace. m2c-shaped output must never silently present a goto salad
//!   as structured C.
//! - **Stack-struct dump** ([`emit_stack_struct`]): the db's
//!   `StackVariableRow`s rendered as a `{fn}_stack` struct whose fields
//!   are named `sp<HEX>` so they line up with the renamed locals.
//! - **Globals emission**: native symbol declarations refined by whole-value
//!   SSA evidence, never by address-looking identifier spelling.
//! - Semantic helper canonicalization runs in the native backend before
//!   printing. This formatter cannot rewrite calls from their names.
//!
//! Clean-room note: only m2c's *documented output conventions* (short
//! `temp_*` stems, `sp<offset>` stack names, `/`/`%` for division,
//! `__cntlzw` for count-leading-zeros) are reproduced. No m2c
//! (GPL-3.0) source was read or ported; the plan's legal register
//! allows an out-of-process handoff only.
//!
//! Hook: call [`emit_doc`] on the [`romwright_model::DecompDoc`]
//! returned by `Core::decompile_native_doc`
//! (`native_runtime::decompile_native_doc`). The store-supplied pieces
//! (stack rows, globals, unstructured edges from
//! [`crate::structuring`]) travel in [`FuncInputs`].

use std::collections::BTreeMap;

use romwright_model::{DecompDoc, StackVariableRow, TokenKind};
use romwright_model::function_ir::OperationId;

mod addresses;
pub use addresses::{Named, address_names};
mod token_edits;
mod machine;
pub use machine::{Machine, MachineCode};
mod canonical;
mod conform;
mod declarations;
pub use declarations::DeclaredPrototypes;
mod dependencies;
mod globals;
mod imports;
mod locals;
mod storage;
mod struct_params;
pub(crate) use storage::UnitLayouts;
use globals::GlobalRef;
pub(crate) use imports::stdcall_imports_enabled;

/// Honesty marker stem emitted where structuring failed.
pub const IRREGULAR_STEM: &str = "irregular";

/// Options for [`emit_doc`]/[`emit_function_text`].
#[derive(Clone, Debug)]
pub struct M2cOptions {
    /// Insert `/* irregular */` markers on unstructured flow.
    pub mark_irregular_flow: bool,
    /// Prepend the stack-struct dump.
    pub emit_stack_struct: bool,
    /// Prepend the globals block.
    pub emit_globals: bool,
    /// Semantic passes the native backend must apply before presentation.
    /// Unknown or unapplied passes fail emission instead of publishing C.
    pub transforms: Vec<String>,
    /// Wall-clock bound for a whole export job; `None` is the interactive
    /// default (`exec::DEFAULT_BUDGET`). Whole-program exports need more.
    pub budget: Option<std::time::Duration>,
    /// Names the project's own headers already declare (`--context`): the
    /// export neither redeclares them nor disagrees with their types.
    pub declared: std::collections::BTreeSet<String>,
    /// The project's header itself (`--context`): the printed function is made
    /// to agree with the types it declares (see `conform`).
    pub context: String,
    /// The program's compiler id (`programs.compiler`): the key of the
    /// printer's compiler rules. Empty is unknown.
    pub compiler: String,
    /// Environment the decompiler worker gets for this export (the printing
    /// variant of `match_search`); empty is the stock printing.
    pub worker_env: Vec<(String, String)>,
    /// The import-table slots (virtual addresses) of a 32-bit Windows image whose calls are `__stdcall` (`imports`).
    pub stdcall_imports: std::collections::BTreeSet<u64>,
}

impl Default for M2cOptions {
    fn default() -> Self {
        Self {
            mark_irregular_flow: true,
            emit_stack_struct: true,
            emit_globals: true,
            transforms: crate::func_ir::default_pass_names(),
            budget: None,
            declared: std::collections::BTreeSet::new(),
            context: String::new(),
            compiler: String::new(),
            worker_env: Vec::new(),
            stdcall_imports: std::collections::BTreeSet::new(),
        }
    }
}

/// The functions and objects a C header declares (typedefs, macros and types
/// excluded), for [`M2cOptions::declared`].
pub fn declared_names(header: &str) -> std::collections::BTreeSet<String> {
    fn identifier<'a>(node: tree_sitter::Node<'_>, source: &'a str) -> Option<&'a str> {
        let mut node = node;
        loop {
            if node.kind() == "identifier" {
                return Some(&source[node.byte_range()]);
            }
            // `(*name[])(args)`: the parentheses hold the declarator without naming the field
            node = match node.child_by_field_name("declarator") {
                Some(inner) => inner,
                None if node.kind() == "parenthesized_declarator" && locals::enabled("ROMWRIGHT_EXPORT_CONTEXT_NAMES") => {
                    node.named_child(0)?
                }
                None => return None,
            };
        }
    }
    fn walk(node: tree_sitter::Node<'_>, source: &str, names: &mut std::collections::BTreeSet<String>) {
        if node.kind() == "function_definition" {
            return;
        }
        if node.kind() == "declaration" {
            let mut cursor = node.walk();
            for declarator in node.children_by_field_name("declarator", &mut cursor) {
                let declarator = if declarator.kind() == "init_declarator" {
                    declarator.child_by_field_name("declarator").unwrap_or(declarator)
                } else {
                    declarator
                };
                if let Some(name) = identifier(declarator, source) {
                    names.insert(name.to_string());
                }
            }
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            walk(child, source, names);
        }
    }
    let mut names = std::collections::BTreeSet::new();
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&tree_sitter_c::LANGUAGE.into()).is_ok()
        && let Some(tree) = parser.parse(header, None)
    {
        walk(tree.root_node(), header, &mut names);
    }
    names
}

/// `extern` lines of a declaration block whose name the project declares.
fn without_declared(text: &str, declared: &std::collections::BTreeSet<String>) -> String {
    if declared.is_empty() {
        return text.to_string();
    }
    text.split_inclusive('\n')
        .filter(|line| {
            let Some(rest) = line.strip_prefix("extern ") else { return true };
            let head = rest.split(['(', '[', ';']).next().unwrap_or("");
            let name: String = head
                .trim_end()
                .chars()
                .rev()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            !declared.contains(&name)
        })
        .collect()
}

/// Store-supplied context [`emit_doc`] cannot read from the document.
#[derive(Clone, Debug, Default)]
pub struct FuncInputs<'a> {
    /// The db's stack rows for this function.
    pub stack: &'a [StackVariableRow],
    /// Generated-local names the token scan cannot see (e.g. locals the
    /// decompiler declared but this body never uses), with optional C
    /// type hints for typed-temp classification.
    pub generated_extra: &'a [(String, Option<String>)],
    /// Names that must never be renamed (project symbols, macros).
    pub keep: &'a [String],
    /// Authoritative C declarations, before native type recovery loses qualifiers.
    pub asserted_prototypes: Option<&'a DeclaredPrototypes>,
    /// The global pointer in force at the function's entry, where the
    /// architecture has one (decides which globals were small data).
    pub gp: Option<u64>,
    /// The function's machine code and what it says about addresses (see
    /// `machine`, `addresses`).
    pub machine: Option<Machine<'a>>,
}
/// What emission produced, besides the text itself.
#[derive(Clone, Debug)]
pub struct Emitted {
    /// The m2c-shaped C (stack struct + globals + processed body).
    pub text: String,
    /// Generated name → emitted temp, in allocation order.
    pub temps: BTreeMap<String, String>,
    /// Unresolved flow, inputs or native warnings, independent of marker display.
    pub irregular: bool,
    pub warnings: Vec<String>,
}

/// Render a document's tokens to C text: every non-break token appends
/// its text, a Break token ends the line and indents the next by its
/// `indent` spaces (negative indents clamp to zero; absurd indents cap
/// at 256 columns so a corrupt document cannot blow up memory).
pub fn render_doc_text(doc: &DecompDoc) -> String {
    render_named_doc(doc, &BTreeMap::new(), &BTreeMap::new(), &BTreeMap::new())
}

fn render_named_doc(
    doc: &DecompDoc,
    names: &BTreeMap<String, String>,
    intrinsics: &BTreeMap<OperationId, String>,
    storage: &BTreeMap<usize, String>,
) -> String {
    let declarations = declaration_types(doc);
    let type_names = primitive_types(doc);
    let mut out = String::new();
    for (index, token) in doc.tokens.iter().enumerate() {
        if token.kind == TokenKind::Break {
            if let Some(text) = storage.get(&index) {
                out.push_str(text);
                continue;
            }
            out.push('\n');
            let indent = token.indent.unwrap_or(0).clamp(0, 256) as usize;
            out.extend(std::iter::repeat_n(' ', indent));
        } else {
            let replacement = match token.kind {
                TokenKind::Variable => names.get(&token.text).map(String::as_str)
                    .or_else(|| boolean_constant(doc, token)),
                TokenKind::FuncName | TokenKind::Op if is_c_ident(&token.text) => token.operation
                    .and_then(|operation| intrinsics.get(&operation).map(String::as_str)),
                TokenKind::Type => token.symbol_id.zip(token.datatype_id)
                    .and_then(|identity| declarations.get(&identity).map(String::as_str))
                    .or_else(|| token.datatype_id.and_then(|id| type_names.get(&id).copied())),
                // The printer's own loop headers (`while (true)`); C89 has no `true`.
                TokenKind::Syntax => match token.text.as_str() {
                    "true" => Some("1"),
                    "false" => Some("0"),
                    _ => None,
                },
                _ => None,
            };
            let single = (token.kind == TokenKind::Variable).then(|| single_float_literal(doc, token)).flatten();
            out.push_str(
                storage
                    .get(&index)
                    .map(String::as_str)
                    .or(replacement)
                    .or(single.as_deref())
                    .unwrap_or(token.text.as_str()),
            );
        }
    }
    out
}

fn boolean_constant(doc: &DecompDoc, token: &romwright_model::DecompToken) -> Option<&'static str> {
    let (value, text) = match token.text.as_str() {
        "false" => (0, "0"),
        "true" => (1, "1"),
        _ => return None,
    };
    let native = doc.function_ir.as_ref()?.values.get(&token.varnode?)?;
    // Constant space is native space zero. An ordinary symbol named "true"
    // must not be rewritten merely because it resembles a C++ keyword.
    (native.space == romwright_model::function_ir::IrSpace::Index(0)
        && native.size == Some(1)
        && native.offset == Some(value))
        .then_some(text)
}

/// A 4-byte float constant, spelled `f`-suffixed: an unsuffixed C literal is a
/// double, and `x * 0.5` is then a double multiplication (a library call on a
/// target without double hardware) where the machine code multiplied floats.
fn single_float_literal(doc: &DecompDoc, token: &romwright_model::DecompToken) -> Option<String> {
    let text = token.text.trim();
    if !is_unsuffixed_float_literal(text) {
        return None;
    }
    let value = doc.function_ir.as_ref()?.values.get(&token.varnode?)?;
    (value.space == romwright_model::function_ir::IrSpace::Index(0) && value.size == Some(4))
        .then(|| format!("{text}f"))
}

/// `0.5`, `-1e-3`, `800.0`: a decimal floating literal without a suffix.
fn is_unsuffixed_float_literal(text: &str) -> bool {
    let digits = text.strip_prefix('-').unwrap_or(text);
    digits.bytes().all(|b| b.is_ascii_digit() || matches!(b, b'.' | b'e' | b'E' | b'+' | b'-'))
        && digits.bytes().next().is_some_and(|b| b.is_ascii_digit())
        && digits.bytes().any(|b| matches!(b, b'.' | b'e' | b'E'))
}

fn primitive_types(doc: &DecompDoc) -> BTreeMap<u64, &'static str> {
    fn collect(ty: &romwright_model::DecompType, result: &mut BTreeMap<u64, &'static str>, depth: usize) {
        if depth > 32 { return; }
        if let (Some(id), Some(name)) = (ty.id, globals::primitive(ty)) {
            // Preserve user-defined typedef names; replace only native shorthand.
            if ty.name.as_deref().is_some_and(|name| globals::primitive_name(name).is_some()) {
                result.insert(id, name);
            }
        }
        if let Some(target) = &ty.target { collect(target, result, depth + 1); }
        if let Some(prototype) = &ty.prototype {
            collect(&prototype.return_type, result, depth + 1);
            for parameter in &prototype.parameters { collect(&parameter.data_type, result, depth + 1); }
        }
    }
    let mut result = BTreeMap::new();
    if let Some(prototype) = &doc.prototype {
        collect(&prototype.return_type, &mut result, 0);
        for parameter in &prototype.parameters { collect(&parameter.data_type, &mut result, 0); }
    }
    if let Some(ir) = &doc.function_ir {
        for high in &ir.high_variables {
            collect(&high.data_type, &mut result, 0);
            if let Some(symbol) = &high.symbol { collect(&symbol.data_type, &mut result, 0); }
        }
        for cast_type in &ir.cast_types { collect(cast_type, &mut result, 0); }
    }
    result
}

fn scalar_name(class: romwright_model::type_evidence::Class) -> Option<String> {
    use romwright_model::type_evidence::Class;
    match class {
        Class::Int(8 | 16 | 32 | 64) | Class::Uint(8 | 16 | 32 | 64) | Class::Float(32 | 64) => {
            Some(class.c_name())
        }
        _ => None,
    }
}

/// Native stack symbols may remain undefined even after their SSA highs
/// acquire scalar types. Refine only unlocked, whole scalar declarations,
/// linked by symbol and datatype IDs rather than their printed spellings.
fn declaration_types(doc: &DecompDoc) -> BTreeMap<(u64, u64), String> {
    use romwright_model::type_evidence::Class;
    let Some(ir) = &doc.function_ir else {
        return BTreeMap::new();
    };
    let mut classes: BTreeMap<_, Class> = BTreeMap::new();
    for high in &ir.high_variables {
        let Some(symbol) = &high.symbol else { continue };
        if symbol.global
            || high.type_locked
            || high.symbol_offset.unwrap_or(0) != 0
            || symbol.data_type.metatype.as_deref() != Some("unknown")
            || symbol.data_type.size != high.data_type.size
        {
            continue;
        }
        let (Some(type_id), Some(size)) = (symbol.data_type.id, symbol.data_type.size) else {
            continue;
        };
        let class = high
            .members
            .iter()
            .filter(|id| {
                ir.values
                    .get(id)
                    .and_then(|value| value.size)
                    .map(u64::from)
                    == Some(size)
            })
            .filter_map(|id| ir.type_evidence.get(id))
            .copied()
            .fold(Class::Unknown, Class::join);
        let class = if matches!(
            class,
            Class::Unknown | Class::Opaque(_) | Class::Num(_) | Class::IntOrUint(_)
        ) {
            let Some(bits) = size
                .checked_mul(8)
                .and_then(|bits| u32::try_from(bits).ok())
            else {
                continue;
            };
            match high.data_type.metatype.as_deref() {
                Some("int") => Class::Int(bits),
                Some("uint") => Class::Uint(bits),
                Some("float") if !matches!(class, Class::IntOrUint(_)) => Class::Float(bits),
                _ => continue,
            }
        } else {
            class
        };
        let entry = classes.entry((symbol.id, type_id)).or_default();
        *entry = entry.join(class);
    }
    classes
        .into_iter()
        .filter_map(|(identity, class)| scalar_name(class).map(|name| (identity, name)))
        .collect()
}

fn unresolved_values(doc: &DecompDoc) -> Vec<String> {
    use romwright_model::function_ir::{IrSpace, Opcode, Operand};
    let Some(ir) = &doc.function_ir else { return Vec::new() };
    let calls: std::collections::BTreeSet<_> = ir.blocks.iter().flat_map(|block| &block.operations)
        .filter(|op| matches!(op.opcode, Opcode::CALL | Opcode::CALLIND)).map(|op| op.id).collect();
    let clobbered: std::collections::BTreeSet<_> = ir.blocks.iter().flat_map(|block| &block.operations)
        .filter(|op| op.opcode == Opcode::INDIRECT)
        .filter(|op| matches!(op.inputs.get(1), Some(Operand::Operation(id)) if calls.contains(id)))
        .filter(|op| matches!(op.inputs.first(), Some(Operand::Value(id))
            if ir.values.get(id).is_some_and(|value| value.space == IrSpace::Index(0) && value.offset == Some(0))))
        .filter_map(|op| op.output)
        .filter(|id| ir.values.get(id).is_some_and(|value| !value.address_tied && !value.persistent))
        .collect();
    let unresolved: BTreeMap<_, _> = ir.high_variables.iter()
        .filter(|high| high.class != "param" && high.class != "global")
        .flat_map(|high| high.members.iter().filter_map(|id| {
            let value = ir.values.get(id)?;
            (clobbered.contains(id) || (value.input && !value.persistent))
                .then_some((*id, clobbered.contains(id)))
        })).collect();
    doc.tokens.iter().filter_map(|token| {
        let call = unresolved.get(&token.varnode?)?;
        Some(format!("{} {} requires supplied context",
            if *call { "unmodelled call-clobbered value" } else { "unresolved entry value" }, token.text))
    }).collect::<std::collections::BTreeSet<_>>().into_iter().collect()
}

/// Formatting consumes the native projection of an already-applied semantic
/// plan. It cannot substitute token guesses for a missing transformation.
fn render_transformed(
    doc: &DecompDoc,
    opts: &M2cOptions,
    names: &BTreeMap<String, String>,
    intrinsics: &BTreeMap<OperationId, String>,
    storage: &BTreeMap<usize, String>,
) -> Result<String, String> {
    crate::func_ir::Pipeline::from_names(&opts.transforms)?;
    for name in &opts.transforms {
        if !doc
            .function_ir
            .as_ref()
            .is_some_and(|ir| ir.passes.iter().any(|pass| &pass.name == name))
        {
            return Err(format!(
                "semantic pass {name:?} was not applied by the native backend"
            ));
        }
    }
    Ok(render_named_doc(doc, names, intrinsics, storage))
}

/// True for names the decompiler invents per-function (Ghidra's
/// `uVar`/`iVar`/`local_`/`auStack`/`extraout_` families). Prototype
/// params (`param_N`), address-named symbols (`DAT_*`, …), irregular
/// inputs (`in_*`), and m2c-shaped names are NOT generated: they carry
/// meaning and pass through.
pub fn is_generated_name(name: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "uVar",
        "iVar",
        "bVar",
        "cVar",
        "dVar",
        "fVar",
        "lVar",
        "pVar",
        "sVar",
        "auVar",
        "local_",
        "auStack",
        "abStack",
        "extraout_",
    ];
    PREFIXES.iter().any(|p| name.starts_with(p))
}

/// True for names already in m2c shape: `temp_*`/`phi_*` temps,
/// `sp<HEX>` stack slots, `arg*`/`param_*` parameters, and the
/// address-named `DAT_*`/`PTR_*`/`FUN_*`/`LAB_*`/`switchD_*` symbols.
pub fn is_m2c_name(name: &str) -> bool {
    if name.starts_with("temp_")
        || name.starts_with("phi_")
        || name.starts_with("param_")
        || name.starts_with("arg")
        || name.starts_with("DAT_")
        || name.starts_with("PTR_")
        || name.starts_with("FUN_")
        || name.starts_with("LAB_")
        || name.starts_with("switchD_")
        || name.starts_with("switchd_")
    {
        return true;
    }
    if let Some(hex) = name.strip_prefix("sp") {
        return !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit());
    }
    false
}

/// Classify a C type hint for typed-temp naming: float-likes name
/// `temp_f<N>`, everything else (including unknown) names `temp_v<N>`.
pub fn is_float_hint(hint: Option<&str>) -> bool {
    let Some(hint) = hint else { return false };
    let hint = hint.to_ascii_lowercase();
    hint.contains("float") || hint.contains("double") || hint == "f32" || hint == "f64"
}

/// Deterministic temporary namer: generated locals become typed temps
/// (`temp_v0`, `temp_f0`, …), stack slots become `sp<HEX>`, everything
/// else passes through. Allocation order is first use, so the same
/// token stream always yields the same names.
#[derive(Clone, Debug, Default)]
pub struct TempNamer {
    map: BTreeMap<String, String>,
    next_v: usize,
    next_f: usize,
}

impl TempNamer {
    pub fn new() -> Self {
        Self::default()
    }

    /// The `sp<HEX>` name for a stack offset (magnitude in uppercase
    /// hex, matching m2c's `sp1C` style).
    pub fn stack_slot_name(offset: i64) -> String {
        format!("sp{:X}", offset.unsigned_abs())
    }

    /// Name one generated local, allocating a typed temp on first use.
    /// `type_hint` is a C type spelling (`None` = unknown → `temp_v`).
    pub fn for_generated(&mut self, name: &str, type_hint: Option<&str>) -> String {
        if let Some(known) = self.map.get(name) {
            return known.clone();
        }
        let fresh = if is_float_hint(type_hint) {
            let fresh = format!("temp_f{}", self.next_f);
            self.next_f += 1;
            fresh
        } else {
            let fresh = format!("temp_v{}", self.next_v);
            self.next_v += 1;
            fresh
        };
        self.map.insert(name.to_string(), fresh.clone());
        fresh
    }

    pub fn mapping(&self) -> &BTreeMap<String, String> {
        &self.map
    }
}

fn is_ident_char(c: Option<char>) -> bool {
    matches!(c, Some(c) if c.is_ascii_alphanumeric() || c == '_' || c == '$')
}

fn prev_char(text: &str, i: usize) -> Option<char> {
    text[..i].chars().next_back()
}

fn next_char(rest: &str) -> Option<char> {
    rest.chars().next()
}

/// If `i` opens a comment/string/char literal, return the index just
/// past it.
fn skip_trivia(text: &str, i: usize) -> Option<usize> {
    let rest = &text[i..];
    if rest.starts_with("//") {
        let end = rest.find('\n').map(|p| i + p).unwrap_or(text.len());
        return Some(end);
    }
    if rest.starts_with("/*") {
        let end = rest.find("*/").map(|p| i + p + 2).unwrap_or(text.len());
        return Some(end);
    }
    if rest.starts_with('"') || rest.starts_with('\'') {
        let quote = rest.as_bytes()[0];
        let mut j = i + 1;
        let bytes = text.as_bytes();
        while j < bytes.len() {
            if bytes[j] == b'\\' {
                j += 2;
                continue;
            }
            j += 1;
            if bytes[j - 1] == quote {
                break;
            }
        }
        return Some(j.min(text.len()));
    }
    None
}
/// Full `type name` declaration fragment for one stack field (arrays
/// keep their length on the name: `u8 sp20[16]`).
fn stack_field_decl(row: &StackVariableRow, field: &str) -> String {
    if let Some(ty) = row
        .type_name
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
    {
        return format!("{} {field}", globals::primitive_name(ty).unwrap_or(ty));
    }
    match row.size {
        Some(1) => format!("signed char {field}"),
        Some(2) => format!("short {field}"),
        Some(4) => format!("int {field}"),
        Some(8) => format!("long long {field}"),
        Some(n) => format!("unsigned char {field}[{n}] /* unchecked */"),
        None => format!("int {field} /* unchecked */"),
    }
}
pub fn count_gotos(text: &str) -> usize {
    let bytes = text.as_bytes();
    let mut count = 0;
    let mut i = 0;
    while i < bytes.len() {
        if let Some(skip) = skip_trivia(text, i) {
            i = skip;
            continue;
        }
        if text[i..].starts_with("goto")
            && !is_ident_char(prev_char(text, i))
            && !is_ident_char(next_char(&text[i + 4..]))
        {
            count += 1;
            i += 4;
        } else {
            let len = text[i..].chars().next().map(|c| c.len_utf8()).unwrap_or(1);
            i += len;
        }
    }
    count
}

/// Build the `/* irregular: … */` marker, or `None` when the flow is
/// clean. Any unstructured edge, any `goto`, or any irregular input
/// marks the body.
pub fn irregular_marker(
    unstructured_edges: usize,
    goto_count: usize,
    irregular_inputs: &[&str],
    warning_count: usize,
) -> Option<String> {
    if unstructured_edges == 0 && goto_count == 0 && irregular_inputs.is_empty() && warning_count == 0 {
        return None;
    }
    let mut parts = Vec::new();
    if unstructured_edges > 0 {
        parts.push(format!("{unstructured_edges} unstructured edge(s)"));
    }
    if goto_count > 0 {
        parts.push(format!("{goto_count} goto(s)"));
    }
    if !irregular_inputs.is_empty() {
        parts.push(format!(
            "irregular input(s): {}",
            irregular_inputs.join(", ")
        ));
    }
    if warning_count > 0 {
        parts.push(format!("{warning_count} native warning(s); review required"));
    }
    Some(format!("/* {IRREGULAR_STEM}: {} */", parts.join("; ")))
}

/// Insert the irregularity `marker` after the body's opening brace so
/// the comment reads as part of the function; bodies without a brace
/// get it prepended.
pub fn mark_irregular(body: &str, marker: &str) -> String {
    match body.find('{') {
        Some(open) => {
            let (head, tail) = body.split_at(open + 1);
            format!("{head}\n{marker}{tail}")
        }
        None => format!("{marker}\n{body}"),
    }
}

/// Emit the stack-struct dump for `fn_name`: one `sp<HEX>` field per
/// distinct stack-slot magnitude, sorted by magnitude, typed from the
/// row or sized from it. `None` when there are no rows. Slots sharing
/// a magnitude keep the lowest-ordinal row as the field and list the
/// rest in a comment; rows without an offset become `field_<ordinal>`
/// with an `offset unknown` note.
pub fn emit_stack_struct(fn_name: &str, rows: &[StackVariableRow]) -> Option<String> {
    if rows.is_empty() {
        return None;
    }
    let mut by_mag: BTreeMap<u64, Vec<&StackVariableRow>> = BTreeMap::new();
    let mut no_offset: Vec<&StackVariableRow> = Vec::new();
    for row in rows {
        match row.offset {
            Some(off) => by_mag.entry(off.unsigned_abs()).or_default().push(row),
            None => no_offset.push(row),
        }
    }
    for group in by_mag.values_mut() {
        group.sort_by_key(|row| row.ordinal);
    }
    no_offset.sort_by_key(|row| row.ordinal);

    let total: u64 = rows.iter().filter_map(|row| row.size).sum();
    let struct_name = sanitize_ident(&format!("{fn_name}_stack"));
    let mut out = format!(
        "/* stack frame of {fn_name}: {} slot(s), {total} byte(s) */\ntypedef struct {{\n",
        rows.len()
    );
    for (mag, group) in &by_mag {
        let first = group[0];
        let field = format!("sp{mag:X}");
        let mut comment = format!("/* {:#x}: {} */", mag, first.name);
        if group.len() > 1 {
            let others: Vec<String> = group[1..].iter().map(|row| row.name.clone()).collect();
            comment.push_str(&format!(" /* also at {:#x}: {} */", mag, others.join(", ")));
        }
        out.push_str(&format!(
            "    {}; {comment}\n",
            stack_field_decl(first, &field)
        ));
    }
    for row in &no_offset {
        let field = format!("field_{}", row.ordinal);
        out.push_str(&format!(
            "    {}; /* {}: offset unknown */\n",
            stack_field_decl(row, &field),
            row.name
        ));
    }
    out.push_str(&format!("}} {struct_name};"));
    Some(out)
}

fn is_c_ident(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn sanitize_ident(name: &str) -> String {
    let clean: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if clean.starts_with(|c: char| c.is_ascii_digit()) {
        format!("_{clean}")
    } else if clean.is_empty() {
        "_stack".to_string()
    } else {
        clean
    }
}

/// Formats an already-transformed body and its proven declarations.
fn emit_function_text(
    mut body: String,
    namer: TempNamer,
    stack: &[StackVariableRow],
    globals: &[GlobalRef],
    dependencies: &str,
    unstructured: &[(usize, usize)],
    irregular_inputs: &[String],
    warnings: Vec<String>,
    opts: &M2cOptions,
) -> Emitted {
    let inputs: Vec<&str> = irregular_inputs.iter().map(String::as_str).collect();
    let marker = irregular_marker(unstructured.len(), count_gotos(&body), &inputs, warnings.len());
    let irregular = marker.is_some();
    if opts.mark_irregular_flow {
        if let Some(marker) = marker {
            body = mark_irregular(&body, &marker);
        }
    }
    let mut out = String::new();
    if opts.emit_stack_struct {
        let fn_name = fn_name_of(&body);
        if let Some(dump) = emit_stack_struct(&fn_name, stack) {
            out.push_str(&dump);
            out.push_str("\n\n");
        }
    }
    if opts.emit_globals && !globals.is_empty() {
        out.push_str(&without_declared(&globals::render(globals), &opts.declared));
        out.push('\n');
    }
    if !dependencies.is_empty() {
        out.push_str(&without_declared(dependencies, &opts.declared));
        out.push('\n');
    }
    out.push_str(&body);
    Emitted {
        text: out,
        temps: namer.map,
        irregular,
        warnings,
    }
}

/// Emit a whole document in m2c shape: render its tokens, discover
/// generated locals from Variable tokens (first-use order), then run
/// [`emit_function_text`]. `in_*` storage names count as irregular
/// inputs and are never renamed.
pub fn emit_doc(
    doc: &DecompDoc,
    inputs: &FuncInputs<'_>,
    opts: &M2cOptions,
) -> Result<Emitted, String> {
    let layouts = if opts.emit_globals { UnitLayouts::new([doc])? } else { UnitLayouts::default() };
    emit_doc_in_unit(doc, inputs, opts, &layouts)
}

pub(crate) fn emit_doc_in_unit(
    doc: &DecompDoc,
    inputs: &FuncInputs<'_>,
    opts: &M2cOptions,
    layouts: &UnitLayouts,
) -> Result<Emitted, String> {
    let params: Vec<String> = doc
        .prototype
        .as_ref()
        .map(|proto| proto.parameters.iter().map(|p| p.name.clone()).collect())
        .unwrap_or_default();
    let mut generated: Vec<(String, Option<String>)> = Vec::new();
    let mut seen: BTreeMap<String, ()> = BTreeMap::new();
    for token in &doc.tokens {
        if token.kind != TokenKind::Variable {
            continue;
        }
        let name = token.text.trim();
        if name.is_empty()
            || !is_c_ident(name)
            || !is_generated_name(name)
            || is_m2c_name(name)
            || params.iter().any(|p| p == name)
            || inputs.keep.iter().any(|k| k == name)
            || seen.contains_key(name)
        {
            continue;
        }
        seen.insert(name.to_string(), ());
        let hint = inputs
            .generated_extra
            .iter()
            .find(|(n, _)| n == name)
            .and_then(|(_, h)| h.clone())
            .or_else(|| {
                let id = token.varnode?;
                let class = doc.function_ir.as_ref()?.type_evidence.get(&id)?;
                matches!(class, romwright_model::type_evidence::Class::Float(_))
                    .then(|| "float".into())
            });
        generated.push((name.to_string(), hint));
    }
    for (name, hint) in inputs.generated_extra {
        if seen.contains_key(name) {
            continue;
        }
        seen.insert(name.clone(), ());
        generated.push((name.clone(), hint.clone()));
    }
    let irregular_inputs: Vec<String> = doc
        .storage
        .iter()
        .map(|s| s.name.clone())
        .filter(|n| n.starts_with("in_"))
        .collect();
    let global_names: std::collections::BTreeSet<_> = doc
        .function_ir
        .as_ref()
        .into_iter()
        .flat_map(|ir| &ir.high_variables)
        .filter_map(|high| high.symbol.as_ref())
        .filter(|symbol| symbol.global)
        .map(|symbol| symbol.name.as_str())
        .collect();
    let mut namer = TempNamer::new();
    for (name, hint) in &generated {
        if !params.contains(name)
            && !inputs.keep.contains(name)
            && !global_names.contains(name.as_str())
        {
            namer.for_generated(name, hint.as_deref());
        }
    }
    let mut dependencies = dependencies::from_doc(doc, inputs.keep, opts.emit_globals, inputs.asserted_prototypes, opts.compiler.starts_with("msvc") || opts.compiler.starts_with("mingw"))?;
    let mut globals = if opts.emit_globals {
        globals::from_doc(doc, layouts, inputs.machine.as_ref().and_then(|machine| machine.code.little_endian()), &opts.declared)?
    } else {
        globals::Globals::default()
    };
    // a function used as a value and called: the callee's declaration says more than the global's `int f();`, and the two disagree
    // on the return type (`ROMWRIGHT_EXPORT_CALLEE_OVER_CODE_REF=off` keeps both)
    if (opts.compiler.starts_with("msvc") || opts.compiler.starts_with("mingw")) && locals::enabled("ROMWRIGHT_EXPORT_CALLEE_OVER_CODE_REF") {
        globals.refs.retain(|global| {
            !(global.definition.is_empty() && global.declaration == format!("int {}()", global.name) && dependencies.declared.contains(&global.name))
        });
    }
    if let Some(machine) = &inputs.machine {
        for (index, text) in token_edits::edits(doc, machine) {
            globals.replacements.entry(index).or_insert(text);
        }
    }
    for (index, text) in locals::edits(doc, namer.mapping()) {
        globals.replacements.entry(index).or_insert(text);
    }
    let body = render_transformed(doc, opts, namer.mapping(), &dependencies.names, &globals.replacements)?;
    let body = match inputs.asserted_prototypes {
        Some(prototypes) => prototypes.definition(&doc.address, body)?,
        None => body,
    };
    let body = canonical::apply(&body, &opts.compiler);
    let body = match &inputs.machine {
        Some(machine) => {
            let (body, refs, functions) = {
                let declared = |name: &str| {
                    dependencies.text.contains(&format!(" {name}(")) || globals.refs.iter().any(|global| global.name == name)
                };
                addresses::rewrite(&body, machine.constants, machine.names, &declared)
            };
            globals.refs.extend(refs);
            dependencies.text.push_str(&functions);
            body
        }
        None => body,
    };
    let (body, prelude) = conform_text(body, &mut dependencies.text, &mut globals.refs, inputs.gp, opts);
    // After `conform`: the project's own declaration, not the decompiler's, is what the header finally says.
    let body = struct_params::cast_struct_params(doc, body);
    let cuts: Vec<_> = doc
        .function_ir
        .as_ref()
        .into_iter()
        .flat_map(|ir| &ir.control_flow_cuts)
        .map(|cut| (cut.source.0 as usize, cut.target.0 as usize))
        .collect();
    // Native comments are tokenized word by word, with Syntax whitespace
    // between them. Keep the complete diagnostic, not just "WARNING:".
    let mut warnings: Vec<String> = doc.tokens.iter().enumerate()
        .filter(|(_, token)| token.kind == TokenKind::Comment && token.text.contains("WARNING:"))
        .map(|(index, first)| {
            let mut warning = String::new();
            for (offset, token) in doc.tokens[index..].iter().enumerate() {
                if token.kind == TokenKind::Break {
                    warning.push('\n');
                    continue;
                }
                if token.kind != TokenKind::Comment && !token.text.trim().is_empty() {
                    break;
                }
                let text = if offset == 0 {
                    &first.text[first.text.find("WARNING:").unwrap()..]
                } else {
                    &token.text
                };
                if let Some(end) = text.find("*/") {
                    warning.push_str(&text[..end]);
                    break;
                }
                warning.push_str(text);
            }
            warning.truncate(warning.trim_end().len());
            warning
        }).collect();
    warnings.extend(dependencies.warnings);
    warnings.extend(globals.warnings);
    warnings.extend(unresolved_values(doc));
    let mut emitted = emit_function_text(
        body,
        namer,
        inputs.stack,
        &globals.refs,
        &dependencies.text,
        &cuts,
        &irregular_inputs,
        warnings,
        opts,
    );
    emitted.text.insert_str(0, prelude);
    Ok(emitted)
}

/// Spells the printed function and its declarations for the project's compiler
/// and makes them agree with the project's own declarations (`conform`).
fn conform_text(
    body: String,
    dependencies: &mut String,
    globals: &mut [globals::GlobalRef],
    gp: Option<u64>,
    opts: &M2cOptions,
) -> (String, &'static str) {
    let (mut body, mut uses_code) = conform::spelled(&body);
    for global in globals.iter_mut() {
        let (text, code) = conform::spelled(&format!("extern {};", global.declaration));
        uses_code |= code;
        if let Some(declaration) = text.strip_prefix("extern ").and_then(|t| t.strip_suffix(';')) {
            global.declaration = declaration.to_string();
        }
    }
    let (text, code) = conform::spelled(dependencies);
    uses_code |= code;
    *dependencies = text;
    if let Some(gp) = gp {
        let mut sizes = conform::Decls::new();
        sizes.add_source(&opts.context);
        let names = conform::gp_arrays(
            globals
                .iter()
                .filter(|global| !opts.declared.contains(&global.name))
                .map(|global| (global.name.as_str(), global.declaration.as_str(), global.address)),
            gp,
            &sizes,
        );
        for global in globals.iter_mut().filter(|global| names.contains(&global.name)) {
            global.declaration.push_str("[]");
        }
        body = conform::index_arrays(&body, &names);
    }
    // The project's header last: where it and the printed declarations disagree
    // (the printed ones are the lines it makes the export leave out) it is right.
    let mut decls = conform::Decls::new();
    decls.add_source(&globals::render(globals));
    decls.add_source(dependencies);
    decls.remember_printed();
    decls.add_source(&opts.context);
    decls.zero_compare = opts.compiler.starts_with("msvc");
    decls.string_ops = opts.compiler.starts_with("msvc");
    decls.void_pointer_arithmetic = crate::compiler::rules::applies(
        "mwcc-void-pointer-arithmetic",
        &crate::compiler::rules::Ctx::new(&opts.compiler, "", ""),
    );
    let body = conform::apply(&body, &decls);
    imports::stdcall_calls(body, globals, &opts.stdcall_imports, uses_code)
}

/// Best-effort function name for the stack-struct title: the last
/// identifier before the body's opening brace, else `"func"`.
fn fn_name_of(body: &str) -> String {
    let head = body.split('{').next().unwrap_or("");
    let mut name = "func".to_string();
    let mut word = String::new();
    for c in head.chars().chain(std::iter::once(' ')) {
        if c.is_ascii_alphanumeric() || c == '_' {
            word.push(c);
        } else if !word.is_empty() {
            name = std::mem::take(&mut word);
        }
    }
    if name.is_empty() {
        "func".to_string()
    } else {
        name
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use romwright_model::Address;

    #[test]
    fn warning_only_output_requires_review_even_when_markers_are_hidden() {
        let opts = M2cOptions { mark_irregular_flow: false, ..Default::default() };
        let emitted = emit_function_text(
            "void sample(void) {}".into(), TempNamer::new(), &[], &[], "", &[], &[],
            vec!["WARNING: Could not recover jumptable".into()], &opts,
        );
        assert!(emitted.irregular, "a native recovery warning must prevent a clean export verdict");
        let clean = emit_function_text(
            "void sample(void) {}".into(), TempNamer::new(), &[], &[], "", &[], &[], Vec::new(), &opts,
        );
        assert!(!clean.irregular);
    }

    #[test]
    fn only_decimal_floating_literals_take_the_single_precision_suffix() {
        for text in ["0.5", "-500.0", "800.0", "1e-3", "3.25"] {
            assert!(is_unsuffixed_float_literal(text), "{text}");
        }
        for text in ["0x40", "12", "0.5f", "x.5", "", "-", "temp_f0"] {
            assert!(!is_unsuffixed_float_literal(text), "{text}");
        }
    }

    #[test]
    fn a_header_declares_the_names_the_export_leaves_out() {
        let header = "#ifndef X\n#define X\ntypedef unsigned int u32;\nextern u32 gRngValue;\n\
            extern const unsigned char sDigits[];\nu16 Random(void);\nvoid *memset(void *s, int c, u32 n);\n#endif\n";
        let declared = declared_names(header);
        assert_eq!(
            declared.iter().map(String::as_str).collect::<Vec<_>>(),
            ["Random", "gRngValue", "memset", "sDigits"]
        );
        let text = "extern int gRngValue; /* 0x3005d80 */\nextern int other;\nextern unsigned short Random(void);\n";
        assert_eq!(without_declared(text, &declared), "extern int other;\n");
    }

    #[test]
    fn a_table_of_function_pointers_is_a_declared_name() {
        let header = "extern void (*BCommJmpTbl[])(ENE_WRK *ew);\nextern void (*handler)(int);\nextern int plain;\n";
        let declared = declared_names(header);
        assert_eq!(declared.iter().map(String::as_str).collect::<Vec<_>>(), ["BCommJmpTbl", "handler", "plain"]);
        let text = "extern unsigned char BCommJmpTbl[84]; /* 0x322720 */\nextern int other;\n";
        assert_eq!(without_declared(text, &declared), "extern int other;\n");
    }

    #[test]
    fn temporaries_are_typed_and_stable() {
        let mut namer = TempNamer::new();
        assert_eq!(namer.for_generated("uVar1", None), "temp_v0");
        assert_eq!(namer.for_generated("fVar2", Some("float")), "temp_f0");
        assert_eq!(namer.for_generated("dVar3", Some("double")), "temp_f1");
        // Stable: re-request returns the same temp.
        assert_eq!(namer.for_generated("uVar1", Some("float")), "temp_v0");
    }

    #[test]
    fn stack_slots_name_as_sp_hex_and_dump_struct() {
        assert_eq!(TempNamer::stack_slot_name(-0x1c), "sp1C");
        assert_eq!(TempNamer::stack_slot_name(0x4), "sp4");
        let rows = vec![
            StackVariableRow {
                function: Address::ram(0x8000_1000),
                ordinal: 1,
                name: "local_1c".to_string(),
                storage: "stack".to_string(),
                type_name: None,
                offset: Some(-0x1c),
                size: Some(4),
            },
            StackVariableRow {
                function: Address::ram(0x8000_1000),
                ordinal: 0,
                name: "local_8".to_string(),
                storage: "stack".to_string(),
                type_name: Some("s32".to_string()),
                offset: Some(-0x8),
                size: Some(4),
            },
        ];
        let dump = emit_stack_struct("demo", &rows).expect("rows dump");
        let pos8 = dump.find("sp8;").expect("sp8 field");
        let pos1c = dump.find("sp1C;").expect("sp1C field");
        assert!(pos8 < pos1c, "fields sorted by magnitude:\n{dump}");
        assert!(dump.contains("demo_stack"), "struct named for fn:\n{dump}");
        assert!(
            dump.contains("0x8: local_8"),
            "original names kept:\n{dump}"
        );
    }
}
