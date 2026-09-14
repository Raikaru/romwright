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
//!   text. This mirrors `desktop/romwright-qt/src/decompiler_view.cpp`
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
//! - **Globals emission** ([`emit_globals`]): sorted `extern`
//!   declarations with address comments.
//! - **Canonicalizers** ([`canonicalize_helpers`]): software-division
//!   helpers (`__divsi3`, `__aeabi_idiv`, …) fold to `/`/`%`, and every
//!   `cntlzw` spelling (`CNTLZW`, `__builtin_clz`, …) folds to the
//!   PPC `__cntlzw` intrinsic m2c emits.
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

/// Canonical software-division/modulo helpers folded to operators:
/// (helper, operator). Covers the GCC libgcc si/di forms the decompiler
/// leaves as calls on targets without hardware division (PSX MIPS,
/// N64 MIPS, GBA ARM) and the ARM EABI forms agbcc-era code lowers to.
pub const DIVMOD_HELPERS: &[(&str, &str)] = &[
    ("__divsi3", "/"),
    ("__modsi3", "%"),
    ("__udivsi3", "/"),
    ("__umodsi3", "%"),
    ("__divdi3", "/"),
    ("__moddi3", "%"),
    ("__udivdi3", "/"),
    ("__umoddi3", "%"),
    ("__aeabi_idiv", "/"),
    ("__aeabi_uidiv", "/"),
];

/// Spellings folded to [`CNTLZW_CANONICAL`]: the decompiler's raw
/// case-preserved mnemonic, its zero-suffixed intrinsic form, and the
/// GCC builtins compilers lower `cntlzw` source idioms to.
pub const CNTLZW_ALIASES: &[&str] = &[
    "cntlzw",
    "CNTLZW",
    "__cntlzw0",
    "__builtin_clz",
    "__builtin_clzl",
];

/// The canonical count-leading-zeros spelling m2c emits for PPC.
pub const CNTLZW_CANONICAL: &str = "__cntlzw";

/// Honesty marker stem emitted where structuring failed.
pub const IRREGULAR_STEM: &str = "irregular";

/// Options for [`emit_doc`]/[`emit_function_text`].
#[derive(Clone, Debug)]
pub struct M2cOptions {
    /// Fold div/mod helpers and `cntlzw` spellings.
    pub canonicalize: bool,
    /// Insert `/* irregular */` markers on unstructured flow.
    pub mark_irregular_flow: bool,
    /// Prepend the stack-struct dump.
    pub emit_stack_struct: bool,
    /// Prepend the globals block.
    pub emit_globals: bool,
}

impl Default for M2cOptions {
    fn default() -> Self {
        Self {
            canonicalize: true,
            mark_irregular_flow: true,
            emit_stack_struct: true,
            emit_globals: true,
        }
    }
}

/// One global referenced by the function, for [`emit_globals`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GlobalRef {
    pub name: String,
    /// C type; `None` emits `s32` with an `unchecked type` marker.
    pub type_name: Option<String>,
    /// Link address for the trailing comment; `None` notes it unknown.
    pub address: Option<u64>,
}

/// Store-supplied context [`emit_doc`] cannot read from the document.
#[derive(Clone, Debug, Default)]
pub struct FuncInputs<'a> {
    /// The db's stack rows for this function.
    pub stack: &'a [StackVariableRow],
    /// Globals to declare above the body.
    pub globals: &'a [GlobalRef],
    /// Unstructured `(from, to)` block edges from
    /// `crate::structuring::Structured::unstructured`.
    pub unstructured: &'a [(usize, usize)],
    /// Generated-local names the token scan cannot see (e.g. locals the
    /// decompiler declared but this body never uses), with optional C
    /// type hints for typed-temp classification.
    pub generated_extra: &'a [(String, Option<String>)],
    /// Names that must never be renamed (project symbols, macros).
    pub keep: &'a [String],
}

/// What emission produced, besides the text itself.
#[derive(Clone, Debug)]
pub struct Emitted {
    /// The m2c-shaped C (stack struct + globals + processed body).
    pub text: String,
    /// Generated name → emitted temp, in allocation order.
    pub temps: BTreeMap<String, String>,
    /// Canonicalizer rewrites applied, in [`DIVMOD_HELPERS`] then
    /// [`CNTLZW_ALIASES`] order (e.g. `"__divsi3 -> /"`).
    pub rewrites: Vec<String>,
    /// True when an `/* irregular */` marker was inserted.
    pub irregular: bool,
}

/// Render a document's tokens to C text: every non-break token appends
/// its text, a Break token ends the line and indents the next by its
/// `indent` spaces (negative indents clamp to zero; absurd indents cap
/// at 256 columns so a corrupt document cannot blow up memory).
pub fn render_doc_text(doc: &DecompDoc) -> String {
    let mut out = String::new();
    for token in &doc.tokens {
        if token.kind == TokenKind::Break {
            out.push('\n');
            let indent = token.indent.unwrap_or(0).clamp(0, 256) as usize;
            out.extend(std::iter::repeat_n(' ', indent));
        } else {
            out.push_str(&token.text);
        }
    }
    out
}

/// True for names the decompiler invents per-function (Ghidra's
/// `uVar`/`iVar`/`local_`/`auStack`/`extraout_` families). Prototype
/// params (`param_N`), address-named symbols (`DAT_*`, …), irregular
/// inputs (`in_*`), and m2c-shaped names are NOT generated: they carry
/// meaning and pass through.
pub fn is_generated_name(name: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "uVar", "iVar", "bVar", "cVar", "dVar", "fVar", "lVar", "pVar", "sVar", "auVar",
        "local_", "auStack", "abStack", "extraout_",
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

    /// Rename every whole-identifier occurrence of each mapped name in
    /// `text`. Longest names first so `uVar1` never shadows `uVar10`.
    pub fn apply(&self, text: &str) -> String {
        let mut renamed: Vec<(&String, &String)> = self.map.iter().collect();
        renamed.sort_by(|a, b| b.0.len().cmp(&a.0.len()).then(a.0.cmp(b.0)));
        let mut out = text.to_string();
        for (from, to) in renamed {
            out = replace_ident(&out, from, to);
        }
        out
    }

    pub fn mapping(&self) -> &BTreeMap<String, String> {
        &self.map
    }
}

/// Replace whole-identifier occurrences of `from` with `to`, skipping
/// `//`/`/* */` comments and string/char literals.
fn replace_ident(text: &str, from: &str, to: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < bytes.len() {
        if let Some(skip) = skip_trivia(text, i) {
            out.push_str(&text[i..skip]);
            i = skip;
            continue;
        }
        if text[i..].starts_with(from)
            && !is_ident_char(prev_char(text, i))
            && !is_ident_char(next_char(&text[i + from.len()..]))
        {
            out.push_str(to);
            i += from.len();
        } else {
            let len = text[i..].chars().next().map(|c| c.len_utf8()).unwrap_or(1);
            out.push_str(&text[i..i + len]);
            i += len;
        }
    }
    out
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
        let end = rest
            .find("*/")
            .map(|p| i + p + 2)
            .unwrap_or(text.len());
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
    if let Some(ty) = row.type_name.as_deref().map(str::trim).filter(|t| !t.is_empty()) {
        return format!("{ty} {field}");
    }
    match row.size {
        Some(1) => format!("s8 {field}"),
        Some(2) => format!("s16 {field}"),
        Some(4) => format!("s32 {field}"),
        Some(8) => format!("s64 {field}"),
        Some(n) => format!("u8 {field}[{n}] /* unchecked */"),
        None => format!("s32 {field} /* unchecked */"),
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
) -> Option<String> {
    if unstructured_edges == 0 && goto_count == 0 && irregular_inputs.is_empty() {
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
        parts.push(format!("irregular input(s): {}", irregular_inputs.join(", ")));
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

    let total: u64 = rows
        .iter()
        .filter_map(|row| row.size)
        .sum();
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
            let others: Vec<String> =
                group[1..].iter().map(|row| row.name.clone()).collect();
            comment.push_str(&format!(" /* also at {:#x}: {} */", mag, others.join(", ")));
        }
        out.push_str(&format!("    {}; {comment}\n", stack_field_decl(first, &field)));
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


/// Emit sorted `extern` declarations for `globals`: by address (known
/// first, ascending) then name. Unknown types become `s32` with an
/// `unchecked type` note; non-C-identifier names are skipped with a
/// comment so the output always parses.
pub fn emit_globals(globals: &[GlobalRef]) -> String {
    let mut sorted: Vec<&GlobalRef> = globals.iter().collect();
    sorted.sort_by(|a, b| {
        (a.address.is_none(), a.address.unwrap_or(u64::MAX), &a.name)
            .cmp(&(b.address.is_none(), b.address.unwrap_or(u64::MAX), &b.name))
    });
    let mut out = String::new();
    for global in sorted {
        if !is_c_ident(&global.name) {
            out.push_str(&format!("/* skipped non-C name: {} */\n", global.name));
            continue;
        }
        let mut notes = Vec::new();
        let ty = match global.type_name.as_deref().map(str::trim) {
            Some(ty) if !ty.is_empty() => ty.to_string(),
            _ => {
                notes.push("unchecked type".to_string());
                "s32".to_string()
            }
        };
        match global.address {
            Some(addr) => notes.push(format!("{addr:#x}")),
            None => notes.push("address unknown".to_string()),
        }
        out.push_str(&format!(
            "extern {ty} {}; /* {} */\n",
            global.name,
            notes.join(", ")
        ));
    }
    out
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

/// Split the argument list opened at `open` (index of `(`) into
/// top-level arguments, comment/string aware. Returns the arguments
/// (trimmed) and the index just past the closing `)`.
fn split_call_args(text: &str, open: usize) -> Option<(Vec<String>, usize)> {
    let bytes = text.as_bytes();
    if bytes.get(open) != Some(&b'(') {
        return None;
    }
    let mut args = Vec::new();
    let mut depth = 0usize;
    let mut start = open + 1;
    let mut i = open;
    while i < bytes.len() {
        if let Some(skip) = skip_trivia(text, i) {
            i = skip;
            continue;
        }
        match bytes[i] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    args.push(text[start..i].trim().to_string());
                    return Some((args, i + 1));
                }
            }
            b',' if depth == 1 => {
                args.push(text[start..i].trim().to_string());
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Find the next whole-identifier call to `name` at or after `from`:
/// returns the identifier start and the `(` index.
fn find_ident_call(text: &str, name: &str, from: usize) -> Option<(usize, usize)> {
    let mut i = from;
    while i < text.len() {
        if let Some(skip) = skip_trivia(text, i) {
            i = skip;
            continue;
        }
        if text[i..].starts_with(name)
            && !is_ident_char(prev_char(text, i))
        {
            let mut j = i + name.len();
            while text[j..].starts_with(|c: char| c.is_whitespace()) {
                j += 1;
            }
            if text[j..].starts_with('(') {
                return Some((i, j));
            }
            i += name.len();
        } else {
            let len = text[i..].chars().next().map(|c| c.len_utf8()).unwrap_or(1);
            i += len;
        }
    }
    None
}

/// Apply the div/mod + `cntlzw` canonicalizers to C text. Helpers fold
/// inside-out (bounded fixpoint, 32 rounds) so nested calls like
/// `__divsi3(__modsi3(a, b), c)` fully canonicalize. Returns the text
/// plus one `"helper -> replacement"` entry per helper name applied.
pub fn canonicalize_helpers(text: &str) -> (String, Vec<String>) {
    let mut out = text.to_string();
    let mut rewrites = Vec::new();
    // Div/mod first (they take two args; a cntlzw arg may nest inside).
    for (helper, op) in DIVMOD_HELPERS {
        let mut changed = false;
        for _ in 0..32 {
            let Some((at, open)) = find_ident_call(&out, helper, 0) else {
                break;
            };
            // Restart the scan past nothing: after a rewrite the text
            // changed, so re-scan from the top; bail out if the call
            // does not parse as exactly two arguments.
            let (args, close) = match split_call_args(&out, open) {
                Some(parsed) if parsed.0.len() == 2 => parsed,
                _ => break,
            };
            // arg1 already parenthesises when it is itself a folded helper
            // or a parenthesised expression; wrap only a bare operand so
            // nested folds do not double-wrap.
            let a1 = args[1].trim_start();
            let self_paren = a1.starts_with('(')
                || DIVMOD_HELPERS.iter().any(|(h, _)| a1.starts_with(h))
                || CNTLZW_ALIASES.iter().any(|h| a1.starts_with(h));
            let arg1 = if self_paren { args[1].clone() } else { format!("({})", args[1]) };
            let replacement = format!("(({}) {op} {arg1})", args[0]);
            out.replace_range(at..close, &replacement);
            changed = true;
        }
        if changed {
            rewrites.push(format!("{helper} -> {op}"));
        }
    }
    for alias in CNTLZW_ALIASES {
        if *alias == CNTLZW_CANONICAL {
            continue;
        }
        let mut changed = false;
        // One scan per alias, left to right: later matches shift as
        // earlier ones are replaced, so resume past each replacement.
        let mut from = 0;
        while let Some((at, open)) = find_ident_call(&out, alias, from) {
            let (args, close) = match split_call_args(&out, open) {
                Some(parsed) if parsed.0.len() == 1 => parsed,
                _ => break,
            };
            let replacement = format!("{CNTLZW_CANONICAL}({})", args[0]);
            out.replace_range(at..close, &replacement);
            from = at + replacement.len();
            changed = true;
        }
        if changed {
            rewrites.push(format!("{alias} -> {CNTLZW_CANONICAL}"));
        }
    }
    (out, rewrites)
}

/// Emit one function body (already-rendered C) in m2c shape: rename
/// generated locals, canonicalize helpers, mark irregular flow, and
/// prepend the stack struct + globals blocks.
pub fn emit_function_text(
    body_c: &str,
    params: &[String],
    generated: &[(String, Option<String>)],
    stack: &[StackVariableRow],
    globals: &[GlobalRef],
    unstructured: &[(usize, usize)],
    irregular_inputs: &[String],
    keep: &[String],
    opts: &M2cOptions,
) -> Emitted {
    let mut namer = TempNamer::new();
    for (name, hint) in generated {
        if params.iter().any(|p| p == name) || keep.iter().any(|k| k == name) {
            continue;
        }
        namer.for_generated(name, hint.as_deref());
    }
    let mut body = namer.apply(body_c);
    let mut rewrites = Vec::new();
    if opts.canonicalize {
        let (text, applied) = canonicalize_helpers(&body);
        body = text;
        rewrites = applied;
    }
    let mut irregular = false;
    if opts.mark_irregular_flow {
        let inputs: Vec<&str> = irregular_inputs.iter().map(String::as_str).collect();
        if let Some(marker) =
            irregular_marker(unstructured.len(), count_gotos(&body), &inputs)
        {
            body = mark_irregular(&body, &marker);
            irregular = true;
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
        out.push_str(&emit_globals(globals));
        out.push('\n');
    }
    out.push_str(&body);
    Emitted {
        text: out,
        temps: namer.mapping().clone(),
        rewrites,
        irregular,
    }
}

/// Emit a whole document in m2c shape: render its tokens, discover
/// generated locals from Variable tokens (first-use order), then run
/// [`emit_function_text`]. `in_*` storage names count as irregular
/// inputs and are never renamed.
pub fn emit_doc(doc: &DecompDoc, inputs: &FuncInputs<'_>, opts: &M2cOptions) -> Emitted {
    let params: Vec<String> = doc
        .prototype
        .as_ref()
        .map(|proto| proto.parameters.iter().map(|p| p.name.clone()).collect())
        .unwrap_or_default();
    let mut generated: Vec<(String, Option<String>)> = Vec::new();
    let mut seen: BTreeMap<String, ()> = BTreeMap::new();
    for token in &doc.tokens {
        if token.kind != TokenKind::Variable && token.kind != TokenKind::FuncName {
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
            .and_then(|(_, h)| h.clone());
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
    let body = render_doc_text(doc);
    emit_function_text(
        &body,
        &params,
        &generated,
        inputs.stack,
        inputs.globals,
        inputs.unstructured,
        &irregular_inputs,
        inputs.keep,
        opts,
    )
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
    if name.is_empty() { "func".to_string() } else { name }
}

#[cfg(test)]
mod tests {
    use super::*;
    use romwright_model::{
        Address, DecompReference, DecompToken, FuncParam, FuncProto, StorageSymbol, TokenKind,
    };

    fn tok(kind: TokenKind, text: &str) -> DecompToken {
        DecompToken {
            text: text.to_string(),
            kind,
            color: 0,
            symbol: None,
            address: None,
            reference: None,
            datatype_id: None,
            indent: None,
        }
    }

    fn brk(indent: i64) -> DecompToken {
        DecompToken {
            text: String::new(),
            kind: TokenKind::Break,
            color: 0,
            symbol: None,
            address: None,
            reference: None,
            datatype_id: None,
            indent: Some(indent),
        }
    }

    /// Synthetic decompiler output for:
    /// `s32 demo(s32 param_1, s32 param_2)` whose body divides via a
    /// libgcc helper and counts leading zeros via a raw-mnemonic
    /// spelling — the P4.6 gate fixture.
    fn synthetic_div_cntlzw_doc() -> DecompDoc {
        use TokenKind as K;
        let tokens = vec![
            tok(K::Type, "s32"),
            tok(K::Syntax, " "),
            tok(K::FuncName, "demo"),
            tok(K::Syntax, "(s32 param_1, s32 param_2)"),
            brk(0),
            tok(K::Syntax, "{"),
            brk(4),
            tok(K::Type, "s32"),
            tok(K::Syntax, " "),
            tok(K::Variable, "uVar1"),
            tok(K::Syntax, ";"),
            brk(4),
            tok(K::Type, "s32"),
            tok(K::Syntax, " "),
            tok(K::Variable, "uVar2"),
            tok(K::Syntax, ";"),
            brk(4),
            tok(K::Variable, "uVar1"),
            tok(K::Syntax, " = "),
            tok(K::FuncName, "__divsi3"),
            tok(K::Syntax, "(param_1, param_2);"),
            brk(4),
            tok(K::Variable, "uVar2"),
            tok(K::Syntax, " = "),
            tok(K::FuncName, "CNTLZW"),
            tok(K::Syntax, "(uVar1);"),
            brk(4),
            tok(K::Syntax, "return "),
            tok(K::Variable, "uVar2"),
            tok(K::Syntax, ";"),
            brk(0),
            tok(K::Syntax, "}"),
        ];
        DecompDoc {
            tokens,
            prototype: Some(FuncProto {
                calling_convention: "default".to_string(),
                return_type: romwright_model::DecompType {
                    name: Some("s32".to_string()),
                    id: None,
                    size: Some(4),
                    metatype: None,
                    element_count: None,
                    target: None,
                    prototype: None,
                },
                parameters: vec![
                    FuncParam {
                        ordinal: 0,
                        name: "param_1".to_string(),
                        data_type: romwright_model::DecompType {
                            name: Some("s32".to_string()),
                            id: None,
                            size: Some(4),
                            metatype: None,
                            element_count: None,
                            target: None,
                            prototype: None,
                        },
                    },
                    FuncParam {
                        ordinal: 1,
                        name: "param_2".to_string(),
                        data_type: romwright_model::DecompType {
                            name: Some("s32".to_string()),
                            id: None,
                            size: Some(4),
                            metatype: None,
                            element_count: None,
                            target: None,
                            prototype: None,
                        },
                    },
                ],
                variadic: false,
                no_return: false,
                parameter_source: None,
            }),
            jump_tables: None,
            address: Address::ram(0x8000_1000),
            revision: 1,
            storage: Vec::new(),
        }
    }

    #[test]
    fn div_and_cntlzw_emit_canonical_m2c_shape() {
        let doc = synthetic_div_cntlzw_doc();
        let inputs = FuncInputs::default();
        let opts = M2cOptions::default();
        let first = emit_doc(&doc, &inputs, &opts);
        let second = emit_doc(&doc, &inputs, &opts);
        assert_eq!(first.text, second.text, "emission must be deterministic");
        assert!(
            first.text.contains("temp_v0 = ((param_1) / (param_2));"),
            "div helper folds to /:\n{}",
            first.text
        );
        assert!(
            first.text.contains("temp_v1 = __cntlzw(temp_v0);"),
            "cntlzw spelling canonicalizes:\n{}",
            first.text
        );
        assert!(
            first.text.contains("s32 temp_v0;") && first.text.contains("s32 temp_v1;"),
            "generated locals renamed to typed temps:\n{}",
            first.text
        );
        for leftover in ["uVar1", "uVar2", "__divsi3", "CNTLZW("] {
            assert!(
                !first.text.contains(leftover),
                "no {leftover} survives:\n{}",
                first.text
            );
        }
        assert!(
            first.text.contains("param_1") && first.text.contains("param_2"),
            "prototype params pass through:\n{}",
            first.text
        );
        assert_eq!(first.rewrites.len(), 2, "both rewrites reported: {:?}", first.rewrites);
        assert!(!first.irregular, "structured flow stays unmarked");
        assert_eq!(
            first.temps.get("uVar1").map(String::as_str),
            Some("temp_v0")
        );
    }

    #[test]
    fn temporaries_are_typed_stable_and_passthrough() {
        let mut namer = TempNamer::new();
        assert_eq!(namer.for_generated("uVar1", None), "temp_v0");
        assert_eq!(namer.for_generated("fVar2", Some("float")), "temp_f0");
        assert_eq!(namer.for_generated("dVar3", Some("double")), "temp_f1");
        // Stable: re-request returns the same temp.
        assert_eq!(namer.for_generated("uVar1", Some("float")), "temp_v0");
        let renamed = namer.apply("uVar1 = (float)fVar2 + dVar3; // uVar1 kept out");
        assert!(
            renamed.starts_with("temp_v0 = (float)temp_f0 + temp_f1;"),
            "code renamed, comment kept: {renamed}"
        );
        // Prefix collisions rename longest-first.
        let mut namer = TempNamer::new();
        namer.for_generated("uVar1", None);
        namer.for_generated("uVar10", None);
        assert_eq!(namer.apply("uVar10 + uVar1"), "temp_v1 + temp_v0");
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
        assert!(dump.contains("0x8: local_8"), "original names kept:\n{dump}");
    }

    #[test]
    fn irregular_marker_only_when_needed() {
        assert_eq!(irregular_marker(0, 0, &[]), None);
        let marker = irregular_marker(2, 1, &["in_r3"]).expect("marker");
        assert!(marker.contains("irregular"), "stem present: {marker}");
        assert!(marker.contains("2 unstructured edge(s)"), "edges: {marker}");
        assert!(marker.contains("1 goto(s)"), "gotos: {marker}");
        assert!(marker.contains("in_r3"), "inputs: {marker}");
        let marked = mark_irregular("s32 f(void)\n{\nreturn 0;\n}", &marker);
        assert!(
            marked.contains("{\n/* irregular:"),
            "marker sits inside body:\n{marked}"
        );
        assert_eq!(count_gotos("goto lab; /* goto */ \"goto\""), 1);
    }

    #[test]
    fn in_storage_names_force_irregular_and_survive() {
        let mut doc = synthetic_div_cntlzw_doc();
        doc.storage.push(StorageSymbol {
            name: "in_r3".to_string(),
            space: "register".to_string(),
            offset: 3,
            size: 4,
        });
        let emitted = emit_doc(&doc, &FuncInputs::default(), &M2cOptions::default());
        assert!(emitted.irregular, "irregular input marks body");
        assert!(emitted.text.contains("/* irregular:"), "marker text:\n{}", emitted.text);
        assert!(emitted.text.contains("in_r3"), "input name kept:\n{}", emitted.text);
    }

    #[test]
    fn globals_emit_sorted_externs() {
        let globals = vec![
            GlobalRef {
                name: "gScore".to_string(),
                type_name: None,
                address: Some(0x8000_2000),
            },
            GlobalRef {
                name: "gFlags".to_string(),
                type_name: Some("u32".to_string()),
                address: Some(0x8000_1000),
            },
            GlobalRef {
                name: "not an ident".to_string(),
                type_name: None,
                address: None,
            },
        ];
        let text = emit_globals(&globals);
        let pos_flags = text.find("gFlags").expect("flags");
        let pos_score = text.find("gScore").expect("score");
        assert!(pos_flags < pos_score, "sorted by address:\n{text}");
        assert!(text.contains("extern u32 gFlags; /* 0x80001000 */"), "typed:\n{text}");
        assert!(
            text.contains("extern s32 gScore; /* unchecked type, 0x80002000 */"),
            "unchecked type:\n{text}"
        );
        assert!(text.contains("skipped non-C name"), "bad names skipped:\n{text}");
    }

    #[test]
    fn render_breaks_indent_and_helpers_nest() {
        let (text, rewrites) =
            canonicalize_helpers("x = __divsi3(__modsi3(a, b), __aeabi_uidiv(c, d));");
        assert_eq!(text, "x = ((((a) % (b))) / ((c) / (d)));", "nested folds: {text}");
        assert_eq!(rewrites.len(), 3, "each helper reported once: {rewrites:?}");

        let doc = synthetic_div_cntlzw_doc();
        let raw = render_doc_text(&doc);
        assert!(raw.contains("\n    s32"), "break indents next line: {raw:?}");
        // Reference-carrying tokens render by text; metadata is untouched.
        let _ = DecompReference {
            kind: romwright_model::DecompReferenceKind::Varnode,
            id: 7,
        };
    }
}
