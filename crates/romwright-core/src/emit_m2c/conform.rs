//! Conformance of one printed function to the declarations it is compiled
//! against.
//!
//! The decompiler types a function from the machine code and the prototypes it
//! was given; a project compiles that text against its own declarations. Where
//! the two disagree a strict C compiler (MWCC, agbcc `-Werror`) rejects the
//! text, though the machine code is the same either way. Each rule here makes
//! the printed C agree with a declaration it can read, and none changes what
//! the function computes:
//!
//! - **A cast where C has no implicit conversion**: a pointer passed where an
//!   integer is declared and the reverse, a pointer to one type where a
//!   pointer to another is declared, a function address stored through a
//!   function-pointer slot of another signature, a value called that is not a
//!   function pointer.
//! - **A local takes the type its callee returns**: `v = f();` with `f`
//!   declared to return a pointer retypes an integer local that is only ever
//!   assigned from such calls and only used where a pointer works as is.
//! - **The project's own spelling of the target's signature**: the definition
//!   is printed with the parameter and return types the context declares, so
//!   the two do not conflict.
//! - **A call passes what the callee declares**: arguments beyond a callee's
//!   declared parameters (a decompiler that recovered more than the project
//!   knows) are not printed.
//! - **Type spellings that mean one thing everywhere**: `long` is a 32-bit
//!   integer to the decompiler and a 64-bit one to MWCC for the EE, so a
//!   4-byte integer is spelled `int`; Ghidra's function type `code` is spelled
//!   by a typedef the output defines itself.
//! - **Out-of-reach globals are not small data**: a scalar whose address no
//!   `$gp`-relative access can reach was not small data in the original; it is
//!   declared as an array of unknown size (what `D_xxxxxxxx[0]` is in a
//!   decompilation project) and every use indexes it.
//! - **What a strict front end rejects** (armcc, `Decls::strict`): pointers against integers, arithmetic on function
//!   pointers, floats and pointers cast to each other, pieces of a variable no C type has the width of; see [`strict`].
//!
//! The declarations come from the project's header, the printer's own
//! global declarations and the asserted prototypes; an expression whose type
//! the text does not determine is left alone.
use std::collections::BTreeMap;
use tree_sitter::{Node, Parser, Tree};

mod strict;
pub(super) use strict::{function_name, helper_definitions, normalize_primitives, without_declarations_of};
use strict::{code_values, odd_array_locals, odd_casts, partial_members, strict_expressions, terminate_labels};

/// A stage 4 rule is on unless its own switch is `off` or `ROMWRIGHT_NATIVE_TYPES=1` (every one of them off: the output
/// of the build before stage 4).
fn stage4(switch: &str) -> bool {
    !std::env::var("ROMWRIGHT_NATIVE_TYPES").is_ok_and(|mode| mode == "1") && super::locals::enabled(switch)
}

/// Integer types by what the compiler distinguishes (`long` and `int` are
/// distinct types to MWCC even where both are 32 bits).
// The variants are C's type names (`int`, `unsigned int`), so `Int::Int` and `Int::UInt` stay.
#[allow(clippy::enum_variant_names)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Int {
    Char,
    SChar,
    UChar,
    Short,
    UShort,
    Int,
    UInt,
    Long,
    ULong,
    LongLong,
    ULongLong,
}

#[derive(Clone, Debug, PartialEq)]
pub(super) enum Ty {
    Void,
    Int(Int),
    Float(u8),
    Ptr(Box<Ty>),
    /// Element type and the element count where the declaration gives one (`float [4]`).
    Array(Box<Ty>, Option<u64>),
    /// Return type, parameters (`None`: unspecified, a K&R declaration).
    Func(Box<Ty>, Option<Vec<Ty>>),
    /// `...` as the last parameter.
    Ellipsis,
    Agg(String),
    Named(String, Box<Ty>),
    Unknown,
}

fn resolve(ty: &Ty) -> &Ty {
    let mut ty = ty;
    while let Ty::Named(_, inner) = ty {
        ty = inner;
    }
    ty
}

/// What an expression of this type is when used as a value.
fn decayed(ty: &Ty) -> Ty {
    match resolve(ty) {
        Ty::Array(element, _) => Ty::Ptr(element.clone()),
        function @ Ty::Func(..) => Ty::Ptr(Box::new(function.clone())),
        other => other.clone(),
    }
}

fn size_of(ty: &Ty) -> Option<u64> {
    Some(match resolve(ty) {
        Ty::Int(Int::Char | Int::SChar | Int::UChar) => 1,
        Ty::Int(Int::Short | Int::UShort) => 2,
        Ty::Int(Int::Int | Int::UInt) => 4,
        Ty::Int(_) => 8,
        Ty::Float(width) => u64::from(*width),
        Ty::Ptr(_) => 4,
        _ => return None,
    })
}

/// Whether two types are the same type to the compiler (`None`: not decided).
fn same(a: &Ty, b: &Ty) -> Option<bool> {
    let (a, b) = (resolve(a), resolve(b));
    match (a, b) {
        (Ty::Unknown, _) | (_, Ty::Unknown) => None,
        (Ty::Void, Ty::Void) => Some(true),
        (Ty::Int(x), Ty::Int(y)) => Some(x == y),
        (Ty::Float(x), Ty::Float(y)) => Some(x == y),
        (Ty::Agg(x), Ty::Agg(y)) => Some(x == y),
        (Ty::Ptr(x) | Ty::Array(x, _), Ty::Ptr(y) | Ty::Array(y, _)) => same(x, y),
        (Ty::Func(r1, p1), Ty::Func(r2, p2)) => {
            if !same(r1, r2)? {
                return Some(false);
            }
            match (p1, p2) {
                (Some(p1), Some(p2)) => {
                    if p1.len() != p2.len() {
                        return Some(false);
                    }
                    let mut verdict = Some(true);
                    for (x, y) in p1.iter().zip(p2) {
                        match same(x, y) {
                            Some(false) => return Some(false),
                            None => verdict = None,
                            Some(true) => {}
                        }
                    }
                    verdict
                }
                _ => Some(true),
            }
        }
        (Ty::Ellipsis, Ty::Ellipsis) => Some(true),
        _ => Some(false),
    }
}

/// `to` receives a value of type `from` with no implicit conversion in C.
fn needs_cast(to: &Ty, from: &Ty, zero_constant: bool) -> bool {
    let to = decayed(to);
    let from = decayed(from);
    match (&to, &from) {
        (Ty::Ptr(target), Ty::Ptr(source)) => {
            if matches!(resolve(target), Ty::Void) || matches!(resolve(source), Ty::Void) {
                return false;
            }
            same(target, source) == Some(false)
        }
        (Ty::Ptr(_), Ty::Int(_)) => !zero_constant,
        (Ty::Int(_), Ty::Ptr(_)) => true,
        _ => false,
    }
}

/// C spelling of a type usable in a cast (`None`: no spelling).
fn spell(ty: &Ty) -> Option<String> {
    Some(match ty {
        Ty::Void => "void".into(),
        Ty::Int(kind) => match kind {
            Int::Char => "char",
            Int::SChar => "signed char",
            Int::UChar => "unsigned char",
            Int::Short => "short",
            Int::UShort => "unsigned short",
            Int::Int => "int",
            Int::UInt => "unsigned int",
            Int::Long => "long",
            Int::ULong => "unsigned long",
            Int::LongLong => "long long",
            Int::ULongLong => "unsigned long long",
        }
        .into(),
        Ty::Float(4) => "float".into(),
        Ty::Float(_) => "double".into(),
        Ty::Named(name, _) => name.clone(),
        Ty::Agg(name) => name.clone(),
        Ty::Ptr(target) | Ty::Array(target, _) => match target.as_ref() {
            Ty::Func(ret, params) => {
                let params = match params {
                    None => String::new(),
                    Some(list) if list.is_empty() => "void".into(),
                    Some(list) => list
                        .iter()
                        .map(|p| if matches!(p, Ty::Ellipsis) { Some("...".to_string()) } else { spell(p) })
                        .collect::<Option<Vec<_>>>()?
                        .join(", "),
                };
                format!("{} (*)({params})", spell(ret)?)
            }
            Ty::Array(..) if matches!(ty, Ty::Ptr(_)) && stage4("ROMWRIGHT_EXPORT_MATRIX_CASTS") => {
                // a pointer to an array: `float (*)[4]`, not a pointer to the decayed element
                let (mut dims, mut element) = (String::new(), target.as_ref());
                while let Ty::Array(inner, count) = element {
                    dims.push_str(&format!("[{}]", (*count)?));
                    element = inner;
                }
                format!("{} (*){dims}", spell(element)?)
            }
            _ => {
                let inner = spell(target)?;
                if inner.ends_with('*') { format!("{inner}*") } else { format!("{inner} *") }
            }
        },
        Ty::Func(..) | Ty::Ellipsis | Ty::Unknown => return None,
    })
}

/// The types a project's declarations give names.
#[derive(Default)]
pub(super) struct Decls {
    typedefs: BTreeMap<String, Ty>,
    funcs: BTreeMap<String, Ty>,
    objects: BTreeMap<String, Ty>,
    /// The objects as the printer declared them, before the project's header replaced any
    /// ([`Decls::remember_printed`]).
    printed: BTreeMap<String, Ty>,
    /// The compiler rejects arithmetic on a `void *` (rule
    /// `mwcc-void-pointer-arithmetic`): do it on a `char *`.
    pub(super) void_pointer_arithmetic: bool,
    /// Visual C++ compares a signed value with zero (`test`) and with `-1` (`cmp`) differently: `-1 < x`, which the decompiler
    /// canonicalises `x >= 0` to, is printed `x >= 0`.
    pub(super) zero_compare: bool,
    /// Visual C++ expands `memcpy`/`memset` of a known size or length into `rep movs`/`rep stos`, which the decompiler prints as
    /// the counted loops it is: those loops are printed as the calls they came from.
    pub(super) string_ops: bool,
    /// armcc: the C front end rejects what the printed text leaves to implicit conversions ([`strict_expressions`]).
    pub(super) strict: bool,
    /// The members of the structures and unions the declarations define, by `struct tag` (or the anonymous name
    /// `base_type` gives), for the type of `p->member`.
    structs: BTreeMap<String, BTreeMap<String, Ty>>,
}

fn text_of<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    &source[node.byte_range()]
}

fn parse(text: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser.set_language(&tree_sitter_c::LANGUAGE.into()).ok()?;
    parser.parse(text, None)
}

fn named_children<'t>(node: Node<'t>) -> Vec<Node<'t>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).filter(|n| n.kind() != "comment").collect()
}

fn int_of(words: &[&str]) -> Option<Ty> {
    let count = |word: &str| words.iter().filter(|w| **w == word).count();
    let unsigned = count("unsigned") > 0;
    let signed = count("signed") > 0;
    let kind = if count("char") > 0 {
        if unsigned {
            Int::UChar
        } else if signed {
            Int::SChar
        } else {
            Int::Char
        }
    } else if count("short") > 0 {
        if unsigned { Int::UShort } else { Int::Short }
    } else if count("long") >= 2 {
        if unsigned { Int::ULongLong } else { Int::LongLong }
    } else if count("long") == 1 {
        if words.contains(&"double") {
            return Some(Ty::Float(8));
        }
        if unsigned { Int::ULong } else { Int::Long }
    } else if count("int") > 0 || unsigned || signed {
        if unsigned { Int::UInt } else { Int::Int }
    } else {
        return None;
    };
    Some(Ty::Int(kind))
}

impl Decls {
    pub(super) fn new() -> Self {
        let mut decls = Self::default();
        // Ghidra's function type, as the output defines it.
        decls.typedefs.insert(
            CODE_TYPE.into(),
            Ty::Func(Box::new(Ty::Int(Int::Int)), None),
        );
        decls
    }

    /// The compiler is strict about conversions ([`Decls::strict`]); the project header's primitive names
    /// (`romwright_types.h`) are the types the decompiler prints, so they are known before any other declaration.
    pub(super) fn enable_strict(&mut self) {
        self.strict = true;
        self.add_source(GHIDRA_PRIMITIVES);
    }

    /// The members a structure or union specifier with a body defines.
    fn register_struct(&mut self, node: Node<'_>, source: &str) {
        if !matches!(node.kind(), "struct_specifier" | "union_specifier") {
            return;
        }
        let Some(body) = node.child_by_field_name("body") else { return };
        let Ty::Agg(key) = self.base_type(node, source) else { return };
        let mut members: BTreeMap<String, Ty> = BTreeMap::new();
        for field in named_children(body) {
            if field.kind() != "field_declaration" {
                continue;
            }
            let Some(spec) = field.child_by_field_name("type") else { continue };
            self.register_struct(spec, source);
            let base = self.base_type(spec, source);
            let mut cursor = field.walk();
            let declarators: Vec<_> = field.children_by_field_name("declarator", &mut cursor).collect();
            if declarators.is_empty() {
                // an anonymous member structure or union: its members are this one's
                if let Ty::Agg(inner) = &base && let Some(inner) = self.structs.get(inner) {
                    members.extend(inner.clone());
                }
                continue;
            }
            for declarator in declarators {
                if let Some((Some(name), ty)) = self.declarator(base.clone(), declarator, source) {
                    members.insert(name, ty);
                }
            }
        }
        self.structs.insert(key, members);
    }

    /// Adds the declarations of one C text (a project header, the printer's
    /// own extern lines).
    pub(super) fn add_source(&mut self, text: &str) {
        let Some(tree) = parse(text) else { return };
        for node in named_children(tree.root_node()) {
            self.add_item(node, text);
        }
    }

    /// The objects declared so far are the printer's own; the project's header, added next, replaces them
    /// where it declares the same name.
    pub(super) fn remember_printed(&mut self) {
        self.printed = self.objects.clone();
    }

    fn base_type(&self, node: Node<'_>, source: &str) -> Ty {
        match node.kind() {
            "primitive_type" => match text_of(node, source) {
                "void" => Ty::Void,
                "float" => Ty::Float(4),
                "double" => Ty::Float(8),
                other => int_of(&[other]).unwrap_or(Ty::Unknown),
            },
            "sized_type_specifier" => {
                let words: Vec<&str> = text_of(node, source).split_whitespace().collect();
                int_of(&words).unwrap_or(Ty::Unknown)
            }
            "type_identifier" => {
                let name = text_of(node, source);
                match self.typedefs.get(name) {
                    Some(target) => Ty::Named(name.to_string(), Box::new(target.clone())),
                    None => Ty::Named(name.to_string(), Box::new(Ty::Unknown)),
                }
            }
            "struct_specifier" | "union_specifier" => {
                let keyword = if node.kind() == "struct_specifier" { "struct" } else { "union" };
                match node.child_by_field_name("name") {
                    Some(name) => Ty::Agg(format!("{keyword} {}", text_of(name, source))),
                    // an unnamed structure is still an aggregate, distinct from every other
                    None => Ty::Agg(format!("{keyword} <anonymous {}>", node.start_byte())),
                }
            }
            "enum_specifier" => Ty::Int(Int::Int),
            _ => Ty::Unknown,
        }
    }

    /// The element count an array declarator spells as a plain integer (`[4]`, `[0x10]`).
    fn array_len(&self, node: Node<'_>, source: &str) -> Option<u64> {
        let size = text_of(node.child_by_field_name("size")?, source).trim();
        match size.strip_prefix("0x").or_else(|| size.strip_prefix("0X")) {
            Some(hex) => u64::from_str_radix(hex, 16).ok(),
            None => size.parse().ok(),
        }
    }

    /// `(name, type)` of a declarator applied to `base`.
    fn declarator(&self, base: Ty, node: Node<'_>, source: &str) -> Option<(Option<String>, Ty)> {
        match node.kind() {
            "identifier" | "type_identifier" | "field_identifier" => {
                Some((Some(text_of(node, source).to_string()), base))
            }
            "pointer_declarator" | "abstract_pointer_declarator" => match node.child_by_field_name("declarator") {
                Some(inner) => self.declarator(Ty::Ptr(Box::new(base)), inner, source),
                None => Some((None, Ty::Ptr(Box::new(base)))),
            },
            "array_declarator" | "abstract_array_declarator" => match node.child_by_field_name("declarator") {
                Some(inner) => self.declarator(Ty::Array(Box::new(base), self.array_len(node, source)), inner, source),
                None => Some((None, Ty::Array(Box::new(base), self.array_len(node, source)))),
            },
            "function_declarator" | "abstract_function_declarator" => {
                let params = node.child_by_field_name("parameters").map(|list| self.parameters(list, source));
                let ty = Ty::Func(Box::new(base), params.flatten().map(|(types, _)| types));
                match node.child_by_field_name("declarator") {
                    Some(inner) => self.declarator(ty, inner, source),
                    None => Some((None, ty)),
                }
            }
            "parenthesized_declarator" | "abstract_parenthesized_declarator" => {
                let inner = named_children(node).into_iter().next()?;
                self.declarator(base, inner, source)
            }
            "init_declarator" => self.declarator(base, node.child_by_field_name("declarator")?, source),
            _ => None,
        }
    }

    /// Parameter types (and names) of a parameter list; `None` when the list
    /// is empty (unspecified, a K&R declaration).
    fn parameters(&self, list: Node<'_>, source: &str) -> Option<(Vec<Ty>, Vec<Option<String>>)> {
        let items = named_children(list);
        if items.is_empty() {
            return None;
        }
        let mut types = Vec::new();
        let mut names = Vec::new();
        for item in items {
            match item.kind() {
                "variadic_parameter" => {
                    types.push(Ty::Ellipsis);
                    names.push(None);
                }
                "parameter_declaration" => {
                    let base = item
                        .child_by_field_name("type")
                        .map_or(Ty::Unknown, |ty| self.base_type(ty, source));
                    let (name, ty) = match item.child_by_field_name("declarator") {
                        Some(declarator) => self.declarator(base, declarator, source).unwrap_or((None, Ty::Unknown)),
                        None => (None, base),
                    };
                    // A lone `void` is no parameter.
                    if name.is_none() && matches!(ty, Ty::Void) {
                        continue;
                    }
                    types.push(decayed_param(ty));
                    names.push(name);
                }
                _ => {
                    types.push(Ty::Unknown);
                    names.push(None);
                }
            }
        }
        Some((types, names))
    }

    fn add_item(&mut self, node: Node<'_>, source: &str) {
        match node.kind() {
            "struct_specifier" | "union_specifier" => self.register_struct(node, source),
            "type_definition" => {
                if let Some(spec) = node.child_by_field_name("type") {
                    self.register_struct(spec, source);
                }
                let base = node
                    .child_by_field_name("type")
                    .map_or(Ty::Unknown, |ty| self.base_type(ty, source));
                let mut cursor = node.walk();
                let declarators: Vec<_> = node.children_by_field_name("declarator", &mut cursor).collect();
                for declarator in declarators {
                    if let Some((Some(name), ty)) = self.declarator(base.clone(), declarator, source) {
                        self.typedefs.insert(name, ty);
                    }
                }
            }
            "declaration" => {
                if let Some(spec) = node.child_by_field_name("type") {
                    self.register_struct(spec, source);
                }
                let base = node
                    .child_by_field_name("type")
                    .map_or(Ty::Unknown, |ty| self.base_type(ty, source));
                let mut cursor = node.walk();
                let declarators: Vec<_> = node.children_by_field_name("declarator", &mut cursor).collect();
                for declarator in declarators {
                    if let Some((Some(name), ty)) = self.declarator(base.clone(), declarator, source) {
                        match ty {
                            Ty::Func(..) => {
                                self.funcs.insert(name, ty);
                            }
                            other => {
                                self.objects.insert(name, other);
                            }
                        }
                    }
                }
            }
            "function_definition" => {
                if let Some((name, ty, _)) = self.header(node, source) {
                    self.funcs.insert(name, ty);
                }
            }
            "preproc_ifdef" | "preproc_if" | "preproc_else" => {
                for child in named_children(node) {
                    self.add_item(child, source);
                }
            }
            _ => {}
        }
    }

    /// `(name, function type, parameter names)` of a function definition.
    fn header(&self, node: Node<'_>, source: &str) -> Option<(String, Ty, Vec<Option<String>>)> {
        let base = node
            .child_by_field_name("type")
            .map_or(Ty::Unknown, |ty| self.base_type(ty, source));
        let declarator = node.child_by_field_name("declarator")?;
        let (name, ty) = self.declarator(base, declarator, source)?;
        let mut names = Vec::new();
        let mut inner = Some(declarator);
        while let Some(current) = inner {
            if current.kind() == "function_declarator" {
                if let Some(list) = current.child_by_field_name("parameters")
                    && let Some((_, parameter_names)) = self.parameters(list, source) {
                        names = parameter_names;
                    }
                break;
            }
            inner = current.child_by_field_name("declarator");
        }
        Some((name?, ty, names))
    }
}

fn decayed_param(ty: Ty) -> Ty {
    match resolve(&ty) {
        Ty::Array(element, _) => Ty::Ptr(element.clone()),
        _ => ty,
    }
}

/// The typedef name a printed Ghidra `code` is spelled with.
pub(super) const CODE_TYPE: &str = "romwright_code";
/// What the output defines it as: a function type, which is what `code` is.
pub(super) const CODE_TYPEDEF: &str = "typedef int romwright_code();\n";

/// The primitive names of `romwright_types.h`, which the decompiler's output uses and tree-sitter cannot tell from
/// variables: with their widths known the conversions between them can be told.
const GHIDRA_PRIMITIVES: &str = "\
typedef signed char s8; typedef unsigned char u8; typedef short s16; typedef unsigned short u16;\n\
typedef int s32; typedef unsigned int u32; typedef long long s64; typedef unsigned long long u64;\n\
typedef float f32; typedef double f64;\n\
typedef unsigned char undefined; typedef unsigned char undefined1; typedef unsigned short undefined2;\n\
typedef unsigned char undefined3[3]; typedef unsigned int undefined4; typedef unsigned char undefined5[5];\n\
typedef unsigned char undefined6[6]; typedef unsigned char undefined7[7]; typedef unsigned long long undefined8;\n\
typedef unsigned char byte; typedef unsigned short word; typedef unsigned int dword; typedef unsigned long long qword;\n\
typedef unsigned char uchar; typedef unsigned short ushort; typedef unsigned int uint; typedef unsigned int ulong;\n\
typedef long long longlong; typedef unsigned long long ulonglong;\n\
typedef signed char sbyte; typedef short sword; typedef int sdword; typedef long long sqword;\n";

#[derive(Clone, Debug)]
struct Edit {
    start: usize,
    end: usize,
    text: String,
    /// 0: closes something that ends here, 1: replaces, 2: opens something that starts here.
    rank: u8,
    order: usize,
}

fn insert_before(edits: &mut Vec<Edit>, at: usize, text: String) {
    let order = edits.len();
    edits.push(Edit { start: at, end: at, text, rank: 0, order });
}

fn insert_after(edits: &mut Vec<Edit>, at: usize, text: String) {
    let order = usize::MAX - edits.len();
    edits.push(Edit { start: at, end: at, text, rank: 0, order });
}

fn replace(edits: &mut Vec<Edit>, start: usize, end: usize, text: String) {
    let order = edits.len();
    edits.push(Edit { start, end, text, rank: 1, order });
}

fn apply_edits(source: &str, mut edits: Vec<Edit>) -> Option<String> {
    if edits.is_empty() {
        return None;
    }
    edits.sort_by_key(|edit| (edit.start, edit.rank, edit.order));
    let mut out = String::with_capacity(source.len() + 32);
    let mut cursor = 0usize;
    for edit in edits {
        if edit.start < cursor {
            continue;
        }
        out.push_str(&source[cursor..edit.start]);
        out.push_str(&edit.text);
        cursor = cursor.max(edit.end);
    }
    out.push_str(&source[cursor..]);
    Some(out)
}

fn reparse(text: &str) -> Option<Tree> {
    parse(text).filter(|tree| !tree.root_node().has_error())
}

// ---------------------------------------------------------------------------
// Spellings
// ---------------------------------------------------------------------------

/// `long` is 32 bits to the decompiler and 64 bits to the EE compilers, so a
/// printed `long`/`unsigned long` (the decompiler's 4-byte integers) is
/// spelled `int`/`unsigned int`; Ghidra's function type `code` is spelled by
/// the output's own typedef. Returns the text and whether it names that typedef.
pub(super) fn spelled(text: &str) -> (String, bool) {
    let Some(tree) = parse(text) else { return (text.to_string(), false) };
    let mut edits = Vec::new();
    let mut uses_code = false;
    fn walk(node: Node<'_>, source: &str, edits: &mut Vec<Edit>, uses_code: &mut bool) {
        match node.kind() {
            "sized_type_specifier" => {
                let words: Vec<&str> = text_of(node, source).split_whitespace().collect();
                let longs = words.iter().filter(|w| **w == "long").count();
                if longs == 1 && !words.contains(&"double") {
                    let mut kept: Vec<&str> = words.into_iter().filter(|w| *w != "long").collect();
                    if !kept.iter().any(|w| matches!(*w, "int" | "char" | "short")) {
                        kept.push("int");
                    }
                    replace(edits, node.start_byte(), node.end_byte(), kept.join(" "));
                }
            }
            // `(int7)(x)` reads as a call of a parenthesized name until the name is known to be a type
            "identifier"
                if odd_int_spelling(text_of(node, source)).is_some()
                    && node.parent().is_some_and(|parent| parent.kind() == "parenthesized_expression")
                    && stage4("ROMWRIGHT_EXPORT_ODD_PIECES") =>
            {
                let spelling = odd_int_spelling(text_of(node, source)).unwrap_or_default();
                replace(edits, node.start_byte(), node.end_byte(), spelling.into());
            }
            "type_identifier" => match text_of(node, source) {
                "code" => {
                    *uses_code = true;
                    replace(edits, node.start_byte(), node.end_byte(), CODE_TYPE.into());
                }
                "ulong" => replace(edits, node.start_byte(), node.end_byte(), "unsigned int".into()),
                // Ghidra's integers of a width C has no type of (`(int7)x`, half of `CONCAT71`): the next wider integer
                name if odd_int_spelling(name).is_some() && stage4("ROMWRIGHT_EXPORT_ODD_PIECES") => {
                    replace(edits, node.start_byte(), node.end_byte(), odd_int_spelling(name).unwrap_or_default().into());
                }
                // `(undefined5 **)p`: a width C has no type of, behind a pointer, is what the pointer points at
                // without saying what: `void`
                name if super::locals::odd_undefined(name).is_some()
                    && stage4("ROMWRIGHT_EXPORT_ODD_POINTEES")
                    && node.parent().and_then(|parent| parent.child_by_field_name("declarator")).is_some_and(|declarator| {
                        matches!(declarator.kind(), "abstract_pointer_declarator" | "pointer_declarator")
                    }) =>
                {
                    replace(edits, node.start_byte(), node.end_byte(), "void".into());
                }
                _ => {}
            },
            _ => {}
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            walk(child, source, edits, uses_code);
        }
    }
    walk(tree.root_node(), text, &mut edits, &mut uses_code);
    match apply_edits(text, edits) {
        Some(next) if reparse(&next).is_some() => (next, uses_code),
        _ => (text.to_string(), false),
    }
}

/// The integer a Ghidra odd-width integer type name (`int7`, `uint3`) is spelled as.
fn odd_int_spelling(name: &str) -> Option<&'static str> {
    Some(match name {
        "int3" => "int",
        "uint3" => "unsigned int",
        "int5" | "int6" | "int7" => "long long",
        "uint5" | "uint6" | "uint7" => "unsigned long long",
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// Globals out of gp reach
// ---------------------------------------------------------------------------

/// The reach of a 16-bit `$gp`-relative offset.
pub(super) fn in_gp_reach(gp: u64, address: u64) -> bool {
    address >= gp.saturating_sub(0x8000) && address <= gp.saturating_add(0x7fff)
}

/// MWCC addresses a scalar of at most 8 bytes `$gp`-relative; a symbol no such
/// offset reaches was declared larger in the original. Returns the names that
/// are to be arrays of unknown size, with their declarations.
pub(super) fn gp_arrays<'g>(
    globals: impl Iterator<Item = (&'g str, &'g str, Option<u64>)>,
    gp: u64,
    decls: &Decls,
) -> Vec<String> {
    let mut names = Vec::new();
    for (name, declaration, address) in globals {
        let Some(address) = address else { continue };
        if in_gp_reach(gp, address) || declaration.contains(['[', '(']) {
            continue;
        }
        let mut probe = Decls::new();
        probe.typedefs = decls.typedefs.clone();
        probe.add_source(&format!("extern {declaration};"));
        let Some(ty) = probe.objects.get(name) else { continue };
        if size_of(ty).is_some_and(|size| size <= 8) {
            names.push(name.to_string());
        }
    }
    names
}

/// Indexes every use of the scalars `names` (`x` -> `x[0]`, `&x` -> `x`).
pub(super) fn index_arrays(source: &str, names: &[String]) -> String {
    if names.is_empty() {
        return source.to_string();
    }
    let Some(tree) = reparse(source) else { return source.to_string() };
    let mut edits = Vec::new();
    fn walk(node: Node<'_>, source: &str, names: &[String], edits: &mut Vec<Edit>) {
        if node.kind() == "identifier" && names.iter().any(|name| name == text_of(node, source)) {
            let parent = node.parent();
            let address_of = parent.filter(|p| {
                p.kind() == "pointer_expression"
                    && p.child_by_field_name("operator").is_some_and(|op| text_of(op, source) == "&")
                    && p.child_by_field_name("argument").is_some_and(|arg| arg.id() == node.id())
            });
            let declaring = parent.is_some_and(|p| matches!(p.kind(), "init_declarator" | "pointer_declarator" | "array_declarator"));
            match address_of {
                Some(p) => replace(edits, p.start_byte(), p.end_byte(), text_of(node, source).to_string()),
                None if !declaring => replace(edits, node.start_byte(), node.end_byte(), format!("{}[0]", text_of(node, source))),
                None => {}
            }
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            walk(child, source, names, edits);
        }
    }
    walk(tree.root_node(), source, names, &mut edits);
    match apply_edits(source, edits) {
        Some(next) if reparse(&next).is_some() => next,
        _ => source.to_string(),
    }
}

// ---------------------------------------------------------------------------
// The conformance pass
// ---------------------------------------------------------------------------

type Scope = BTreeMap<String, Ty>;

struct Function<'t> {
    node: Node<'t>,
    name: String,
    ty: Ty,
    scope: Scope,
}

fn function<'t>(tree: &'t Tree, decls: &Decls, source: &str) -> Option<Function<'t>> {
    let root = tree.root_node();
    let node = named_children(root).into_iter().find(|n| n.kind() == "function_definition")?;
    let (name, ty, names) = decls.header(node, source)?;
    let mut scope = Scope::new();
    if let Ty::Func(_, Some(params)) = &ty {
        for (param, name) in params.iter().zip(names) {
            if let Some(name) = name {
                scope.insert(name, param.clone());
            }
        }
    }
    if let Some(body) = node.child_by_field_name("body") {
        for item in named_children(body) {
            if item.kind() != "declaration" {
                continue;
            }
            let base = item
                .child_by_field_name("type")
                .map_or(Ty::Unknown, |ty| decls.base_type(ty, source));
            let mut cursor = item.walk();
            let declarators: Vec<_> = item.children_by_field_name("declarator", &mut cursor).collect();
            for declarator in declarators {
                if let Some((Some(name), ty)) = decls.declarator(base.clone(), declarator, source) {
                    scope.insert(name, ty);
                }
            }
        }
    }
    Some(Function { node, name, ty, scope })
}

struct Typer<'a> {
    decls: &'a Decls,
    scope: &'a Scope,
    source: &'a str,
    /// The function being conformed: its own calls (recursion) know its declaration.
    own: Option<(&'a str, &'a Ty)>,
}

fn operator<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    node.child_by_field_name("operator").map(|op| text_of(op, source))
}

fn strip_parens(mut node: Node<'_>) -> Node<'_> {
    while node.kind() == "parenthesized_expression" {
        match named_children(node).into_iter().next() {
            Some(inner) => node = inner,
            None => break,
        }
    }
    node
}

fn is_zero(node: Node<'_>, source: &str) -> bool {
    let node = strip_parens(node);
    match node.kind() {
        "number_literal" => matches!(text_of(node, source), "0" | "0x0" | "0U" | "0u"),
        "cast_expression" => node.child_by_field_name("value").is_some_and(|value| is_zero(value, source)),
        _ => false,
    }
}

/// `0x42ce0000` as `103.0f`: the single-precision value an integer literal's 32 bits are. `None` for zero (the
/// same either way), a literal wider than 32 bits, a denormal, infinite or NaN pattern, or with the rule off
/// (`ROMWRIGHT_EXPORT_FLOAT_ARGS=off`).
fn float_from_bits(node: Node<'_>, source: &str) -> Option<String> {
    if std::env::var("ROMWRIGHT_EXPORT_FLOAT_ARGS").is_ok_and(|mode| mode == "off") {
        return None;
    }
    let node = strip_parens(node);
    if node.kind() != "number_literal" {
        return None;
    }
    let text = text_of(node, source).trim_end_matches(['u', 'U', 'l', 'L']);
    let bits = match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).ok()?,
        None if text.bytes().all(|b| b.is_ascii_digit()) => text.parse().ok()?,
        None => return None,
    };
    // a normal number only: a small integer (a denormal pattern) was meant as a number, a NaN or infinity is not one
    let bits = u32::try_from(bits).ok().filter(|bits| !matches!((bits >> 23) & 0xff, 0 | 0xff))?;
    let spelled = format!("{:?}", f32::from_bits(bits));
    Some(if spelled.contains(['.', 'e', 'E']) { format!("{spelled}f") } else { format!("{spelled}.0f") })
}

impl Typer<'_> {
    fn type_descriptor(&self, node: Node<'_>) -> Ty {
        let base = node
            .child_by_field_name("type")
            .map_or(Ty::Unknown, |ty| self.decls.base_type(ty, self.source));
        match node.child_by_field_name("declarator") {
            Some(declarator) => self
                .decls
                .declarator(base, declarator, self.source)
                .map_or(Ty::Unknown, |(_, ty)| ty),
            None => base,
        }
    }

    fn of(&self, node: Node<'_>) -> Option<Ty> {
        let ty = self.value_type(node)?;
        (!matches!(resolve(&ty), Ty::Unknown)).then_some(ty)
    }

    fn value_type(&self, node: Node<'_>) -> Option<Ty> {
        match node.kind() {
            "identifier" => {
                let name = text_of(node, self.source);
                self.scope
                    .get(name)
                    .or_else(|| self.decls.objects.get(name))
                    .or_else(|| self.own.filter(|(own, _)| self.decls.strict && *own == name).map(|(_, ty)| ty))
                    .or_else(|| self.decls.funcs.get(name))
                    .cloned()
            }
            "number_literal" => {
                let text = text_of(node, self.source);
                if text.contains('.') || (!text.starts_with("0x") && text.ends_with(['f', 'F'])) {
                    Some(Ty::Float(if text.ends_with(['f', 'F']) { 4 } else { 8 }))
                } else {
                    Some(Ty::Int(Int::Int))
                }
            }
            "char_literal" => Some(Ty::Int(Int::Int)),
            "string_literal" | "concatenated_string" => Some(Ty::Ptr(Box::new(Ty::Int(Int::Char)))),
            "parenthesized_expression" => self.of(strip_parens(node)),
            "cast_expression" => Some(self.type_descriptor(node.child_by_field_name("type")?)),
            "pointer_expression" => {
                let argument = self.of(node.child_by_field_name("argument")?)?;
                match operator(node, self.source)? {
                    "*" => match decayed(&argument) {
                        Ty::Ptr(target) => Some(*target),
                        _ => None,
                    },
                    "&" => Some(Ty::Ptr(Box::new(argument))),
                    _ => None,
                }
            }
            "subscript_expression" => match decayed(&self.of(node.child_by_field_name("argument")?)?) {
                Ty::Ptr(target) => Some(*target),
                _ => None,
            },
            "call_expression" => {
                let callee = self.of(node.child_by_field_name("function")?)?;
                match decayed(&callee) {
                    Ty::Ptr(target) => match resolve(&target) {
                        Ty::Func(ret, _) => Some((**ret).clone()),
                        _ => None,
                    },
                    _ => None,
                }
            }
            "binary_expression" => {
                let op = operator(node, self.source)?;
                match op {
                    "==" | "!=" | "<" | ">" | "<=" | ">=" | "&&" | "||" => Some(Ty::Int(Int::Int)),
                    "+" | "-" => {
                        let left = decayed(&self.of(node.child_by_field_name("left")?)?);
                        let right = decayed(&self.of(node.child_by_field_name("right")?)?);
                        match (&left, &right) {
                            (Ty::Ptr(_), Ty::Ptr(_)) => Some(Ty::Int(Int::Int)),
                            (Ty::Ptr(_), Ty::Int(_)) => Some(left),
                            (Ty::Int(_), Ty::Ptr(_)) if op == "+" => Some(right),
                            (Ty::Float(_), _) | (_, Ty::Float(_)) => Some(Ty::Float(8)),
                            (Ty::Int(_), Ty::Int(_)) => Some(Ty::Int(Int::Int)),
                            _ => None,
                        }
                    }
                    "*" | "/" | "%" | "&" | "|" | "^" | "<<" | ">>" => {
                        let left = decayed(&self.of(node.child_by_field_name("left")?)?);
                        if self.decls.strict && matches!(op, "*" | "/") {
                            let right = decayed(&self.of(node.child_by_field_name("right")?)?);
                            match (&left, &right) {
                                (Ty::Float(a), Ty::Float(b)) => return Some(Ty::Float(if *a == 4 && *b == 4 { 4 } else { 8 })),
                                (Ty::Float(_), Ty::Int(_)) | (Ty::Int(_), Ty::Float(_)) => return Some(Ty::Float(8)),
                                _ => {}
                            }
                        }
                        match left {
                            Ty::Int(_) => Some(Ty::Int(Int::Int)),
                            Ty::Float(_) => Some(Ty::Float(8)),
                            _ => None,
                        }
                    }
                    _ => None,
                }
            }
            "conditional_expression" => {
                let a = self.of(node.child_by_field_name("consequence")?)?;
                let b = self.of(node.child_by_field_name("alternative")?)?;
                (same(&a, &b) == Some(true)).then_some(a)
            }
            "assignment_expression" => self.of(node.child_by_field_name("left")?),
            "comma_expression" => self.of(node.child_by_field_name("right")?),
            "field_expression" if self.decls.strict => {
                let argument = node.child_by_field_name("argument")?;
                let field = text_of(node.child_by_field_name("field")?, self.source);
                let arrow = self.source[argument.end_byte()..node.child_by_field_name("field")?.start_byte()].contains("->");
                let owner = self.of(argument)?;
                let owner = if arrow {
                    match decayed(&owner) {
                        Ty::Ptr(target) => *target,
                        _ => return None,
                    }
                } else {
                    owner
                };
                let Ty::Agg(key) = resolve(&owner) else { return None };
                self.decls.structs.get(key)?.get(field).cloned()
            }
            "unary_expression" if self.decls.strict => {
                let argument = self.of(node.child_by_field_name("argument")?)?;
                match operator(node, self.source)? {
                    "!" => Some(Ty::Int(Int::Int)),
                    "-" | "+" | "~" => match decayed(&argument) {
                        float @ Ty::Float(_) => Some(float),
                        Ty::Int(_) => Some(Ty::Int(Int::Int)),
                        _ => None,
                    },
                    _ => None,
                }
            }
            "update_expression" if self.decls.strict => self.of(node.child_by_field_name("argument")?),
            "sizeof_expression" if self.decls.strict => Some(Ty::Int(Int::UInt)),
            _ => None,
        }
    }
}

/// Expressions a cast binds tighter than.
fn is_prefix_safe(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "identifier"
            | "number_literal"
            | "char_literal"
            | "string_literal"
            | "call_expression"
            | "subscript_expression"
            | "field_expression"
            | "parenthesized_expression"
            | "pointer_expression"
            | "cast_expression"
            | "unary_expression"
            | "sizeof_expression"
    )
}

/// Casts `node` to `to`: `(T)node`, parenthesised when it is not a unary
/// expression; an existing cast changes its type instead.
fn cast_to(edits: &mut Vec<Edit>, node: Node<'_>, to: &Ty) {
    let Some(text) = spell(to) else { return };
    if node.kind() == "cast_expression"
        && let Some(descriptor) = node.child_by_field_name("type") {
            replace(edits, descriptor.start_byte(), descriptor.end_byte(), text);
            return;
        }
    if is_prefix_safe(node) {
        insert_before(edits, node.start_byte(), format!("({text})"));
    } else {
        insert_before(edits, node.start_byte(), format!("({text})("));
        insert_after(edits, node.end_byte(), ")".into());
    }
}

fn visit<'t>(node: Node<'t>, found: &mut dyn FnMut(Node<'t>)) {
    found(node);
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        visit(child, found);
    }
}

fn callee_name<'a>(call: Node<'_>, source: &'a str) -> Option<&'a str> {
    let function = strip_parens(call.child_by_field_name("function")?);
    (function.kind() == "identifier").then(|| text_of(function, source))
}

/// `return value;` in a function the project declares `void`: `return;` when the value has no effect, else
/// `{ value; return; }` (the braces keep a bare `if (c) return f();` one statement).
fn void_returns(body: Node<'_>, edits: &mut Vec<Edit>) {
    visit(body, &mut |node| {
        if node.kind() != "return_statement" {
            return;
        }
        let Some(value) = named_children(node).into_iter().next() else { return };
        let mut effects = false;
        visit(value, &mut |inner| {
            effects |= matches!(inner.kind(), "call_expression" | "assignment_expression" | "update_expression");
        });
        if effects {
            replace(edits, node.start_byte(), node.start_byte() + "return".len(), "{".into());
            insert_after(edits, node.end_byte(), " return; }".into());
        } else {
            replace(edits, node.start_byte(), node.end_byte(), "return;".into());
        }
    });
}

/// The signature the project's header declares for the printed function's own
/// definition replaces the printed one's types, parameter names kept.
fn reconcile_header(function: &Function<'_>, decls: &Decls, source: &str, edits: &mut Vec<Edit>) {
    let Some(Ty::Func(declared_ret, Some(declared_params))) = decls.funcs.get(&function.name) else { return };
    let Ty::Func(ret, Some(params)) = &function.ty else { return };
    if params.len() != declared_params.len() || params.iter().chain(declared_params).any(|p| matches!(p, Ty::Ellipsis)) {
        return;
    }
    // The decompiler lists a floating-point parameter before the integer ones, the order the registers
    // are read in; the declaration lists them as written. Printed parameter `i` is the declared
    // parameter `order[i]`: the identity unless only the floats-first order agrees on every kind.
    let is_float = |ty: &Ty| matches!(resolve(ty), Ty::Float(_));
    let agrees = |order: &[usize]| order.iter().enumerate().all(|(i, &o)| is_float(&params[i]) == is_float(&declared_params[o]));
    let identity: Vec<usize> = (0..declared_params.len()).collect();
    let floats_first: Vec<usize> = identity.iter().copied().filter(|&i| is_float(&declared_params[i]))
        .chain(identity.iter().copied().filter(|&i| !is_float(&declared_params[i]))).collect();
    let order = if agrees(&identity) {
        identity
    } else if agrees(&floats_first) {
        floats_first
    } else {
        return;
    };
    // The definition is itself in `decls` only when it was added as a source;
    // the printed text is parsed separately, so this is the header's own types.
    let differs = same(ret, declared_ret) == Some(false)
        || order.iter().enumerate().any(|(i, &o)| same(&params[i], &declared_params[o]) == Some(false))
        || order.iter().enumerate().any(|(i, &o)| i != o);
    if !differs {
        return;
    }
    let simple = |ty: &Ty| !matches!(resolve(ty), Ty::Agg(_) | Ty::Func(..) | Ty::Unknown)
        && !matches!(resolve(ty), Ty::Ptr(target) if matches!(resolve(target), Ty::Func(..)));
    if !simple(declared_ret) && !matches!(declared_ret.as_ref(), Ty::Void) {
        return;
    }
    // A structure passed by value arrives in registers: the printed parameter is an integer of the
    // structure's width, and the definition declares the structure and reads its bytes as that integer.
    let aggregate = |printed: &Ty, declared: &Ty| {
        matches!(resolve(declared), Ty::Agg(_))
            && matches!(resolve(printed), Ty::Int(Int::UInt | Int::Int | Int::ULongLong | Int::LongLong))
    };
    if !order.iter().enumerate().all(|(i, &o)| simple(&declared_params[o]) || aggregate(&params[i], &declared_params[o])) {
        return;
    }
    let Some(declarator) = function.node.child_by_field_name("declarator") else { return };
    let Some(type_node) = function.node.child_by_field_name("type") else { return };
    let mut parameters = None;
    let mut inner = Some(declarator);
    while let Some(current) = inner {
        if current.kind() == "function_declarator" {
            parameters = current.child_by_field_name("parameters");
            break;
        }
        inner = current.child_by_field_name("declarator");
    }
    let Some(parameters) = parameters else { return };
    let list = named_children(parameters);
    if list.len() != declared_params.len() || list.iter().any(|p| p.kind() != "parameter_declaration") {
        return;
    }
    // The return type: a pointer's stars belong to the declarator.
    let Some(ret_text) = spell(declared_ret) else { return };
    let mut function_declarator = declarator;
    while function_declarator.kind() == "pointer_declarator" {
        let Some(next) = function_declarator.child_by_field_name("declarator") else { return };
        function_declarator = next;
    }
    let Some(name_node) = function_declarator.child_by_field_name("declarator") else { return };
    replace(
        edits,
        type_node.start_byte(),
        name_node.end_byte(),
        format!("{ret_text} {}", text_of(name_node, source)),
    );
    if matches!(declared_ret.as_ref(), Ty::Void)
        && !matches!(resolve(ret), Ty::Void)
        && stage4("ROMWRIGHT_EXPORT_VOID_RETURNS")
    {
        // The decompiler recovered a return value the project's `void` function does not have (the last call's
        // result left in `v0`): the statement keeps what it evaluates and returns nothing.
        if let Some(body) = function.node.child_by_field_name("body") {
            void_returns(body, edits);
        }
    }
    for (position, (slot, declared)) in list.iter().zip(declared_params).enumerate() {
        // the printed parameter that is declared at this position keeps its name
        let Some(printed) = order.iter().position(|&o| o == position) else { return };
        let Some(declarator) = list[printed].child_by_field_name("declarator") else { return };
        let mut name = declarator;
        while matches!(name.kind(), "pointer_declarator" | "array_declarator") {
            match name.child_by_field_name("declarator") {
                Some(next) => name = next,
                None => return,
            }
        }
        let Some(text) = spell(declared) else { return };
        let separator = if text.ends_with('*') { "" } else { " " };
        replace(
            edits,
            slot.start_byte(),
            slot.end_byte(),
            format!("{text}{separator}{}", text_of(name, source)),
        );
        if aggregate(&params[printed], declared) {
            // the body treats the registers as the integer they were: read the structure's bytes as it
            let (Some(view), Some(body)) = (spell(&params[printed]), function.node.child_by_field_name("body")) else { return };
            let parameter_name = text_of(name, source);
            visit(body, &mut |node| {
                if node.kind() == "identifier" && text_of(node, source) == parameter_name {
                    replace(edits, node.start_byte(), node.end_byte(), format!("(*({view} *)&{parameter_name})"));
                }
            });
        }
    }
}

/// An integer local that every assignment takes from a call declared to return
/// a pointer, and that is only used where a pointer works unchanged, is that
/// pointer.
fn retype_locals(function: &Function<'_>, decls: &Decls, source: &str, edits: &mut Vec<Edit>) {
    let Some(body) = function.node.child_by_field_name("body") else { return };
    let typer = Typer { decls, scope: &function.scope, source, own: Some((&function.name, &function.ty)) };
    for item in named_children(body) {
        if item.kind() != "declaration" {
            continue;
        }
        let mut cursor = item.walk();
        let declarators: Vec<_> = item.children_by_field_name("declarator", &mut cursor).collect();
        if declarators.len() != 1 || declarators[0].kind() != "identifier" {
            continue;
        }
        let name = text_of(declarators[0], source);
        if !matches!(function.scope.get(name).map(resolve), Some(Ty::Int(_))) {
            continue;
        }
        let mut returned: Option<Ty> = None;
        let mut safe = true;
        visit(body, &mut |node| {
            if !safe || node.kind() != "identifier" || text_of(node, source) != name || node.id() == declarators[0].id() {
                return;
            }
            let Some(parent) = node.parent() else { return };
            if parent.kind() == "assignment_expression"
                && parent.child_by_field_name("left").is_some_and(|left| left.id() == node.id())
            {
                let Some(right) = parent.child_by_field_name("right") else {
                    safe = false;
                    return;
                };
                let right = strip_parens(right);
                let ret = (operator(parent, source) == Some("=") && right.kind() == "call_expression")
                    .then(|| typer.of(right))
                    .flatten()
                    .filter(|ret| matches!(resolve(ret), Ty::Ptr(target) if !matches!(resolve(target), Ty::Func(..))));
                match (ret, &returned) {
                    (Some(ret), None) => returned = Some(ret),
                    (Some(ret), Some(first)) if same(&ret, first) == Some(true) => {}
                    _ => safe = false,
                }
                return;
            }
            let usable = match parent.kind() {
                "argument_list" | "return_statement" => true,
                "cast_expression" => parent.child_by_field_name("value").is_some_and(|v| v.id() == node.id()),
                "pointer_expression" => operator(parent, source) == Some("*"),
                "unary_expression" => operator(parent, source) == Some("!"),
                "binary_expression" => {
                    let other = if parent.child_by_field_name("left").is_some_and(|l| l.id() == node.id()) {
                        parent.child_by_field_name("right")
                    } else {
                        parent.child_by_field_name("left")
                    };
                    matches!(operator(parent, source), Some("==" | "!=")) && other.is_some_and(|o| is_zero(o, source))
                }
                "parenthesized_expression" => parent.parent().is_some_and(|g| {
                    matches!(g.kind(), "if_statement" | "while_statement" | "do_statement")
                }),
                _ => false,
            };
            if !usable {
                safe = false;
            }
        });
        let Some(returned) = returned.filter(|_| safe) else { continue };
        let Some(text) = spell(&returned) else { continue };
        let separator = if text.ends_with('*') { "" } else { " " };
        replace(
            edits,
            item.start_byte(),
            declarators[0].start_byte(),
            format!("{text}{separator}"),
        );
    }
}

/// What the body's accesses to an object assume of its type is what the decompiler printed it as; where
/// the project's header gives the object another shape (an array of structures for the bytes the decompiler
/// indexed, a pointer table for words), the access still reads the same bytes at the same offsets: it goes
/// through the object's address, cast to the decompiler's element type, as `ene_wrk[i]` did on bytes.
/// An element of the same width (`int` for `unsigned int`) is the same access and is left alone.
/// `ROMWRIGHT_EXPORT_DECLARED_ACCESS=off` disables it.
fn reread_declared(function: &Function<'_>, decls: &Decls, source: &str, edits: &mut Vec<Edit>) {
    if std::env::var("ROMWRIGHT_EXPORT_DECLARED_ACCESS").is_ok_and(|mode| mode == "off") || decls.printed.is_empty() {
        return;
    }
    let Some(body) = function.node.child_by_field_name("body") else { return };
    fn element(ty: &Ty) -> &Ty {
        match resolve(ty) {
            Ty::Array(inner, _) => element(inner),
            other => other,
        }
    }
    visit(body, &mut |node| {
        if node.kind() != "identifier" {
            return;
        }
        let name = text_of(node, source);
        if function.scope.contains_key(name) {
            return;
        }
        let (Some(printed), Some(declared)) = (decls.printed.get(name), decls.objects.get(name)) else { return };
        // An object the project declares `void *` that the decompiler printed as a pointer to something: C does not
        // dereference or index a `void *`, so each such use goes through the pointer type the body assumed.
        if let (Ty::Ptr(shown), Ty::Ptr(header)) = (resolve(printed), resolve(declared))
            && matches!(resolve(header), Ty::Void)
            && !matches!(resolve(shown), Ty::Void | Ty::Unknown | Ty::Func(..))
            && stage4("ROMWRIGHT_EXPORT_VOID_POINTEES")
        {
            let used = node.parent().is_some_and(|parent| match parent.kind() {
                "pointer_expression" => operator(parent, source) == Some("*"),
                "subscript_expression" => parent.child_by_field_name("argument").is_some_and(|argument| argument.id() == node.id()),
                _ => false,
            });
            if let Some(spelled) = spell(printed).filter(|spelled| used && !spelled.contains("(*)")) {
                replace(edits, node.start_byte(), node.end_byte(), format!("(({spelled}){name})"));
            }
            return;
        }
        let (shown, header) = (resolve(element(printed)), resolve(element(declared)));
        let differs = match (shown, header) {
            (Ty::Unknown | Ty::Agg(_) | Ty::Void | Ty::Func(..), _) | (_, Ty::Unknown | Ty::Void | Ty::Func(..)) => false,
            (_, Ty::Agg(_)) => true,
            _ => matches!((size_of(shown), size_of(header)), (Some(a), Some(b)) if a != b),
        };
        if !differs {
            return;
        }
        let Some(spelled) = spell(shown).filter(|spelled| !spelled.contains("(*)")) else { return };
        // a declarator of the body itself, not a use
        if node.parent().is_some_and(|parent| {
            matches!(parent.kind(), "init_declarator" | "array_declarator" | "pointer_declarator" | "declaration")
        }) {
            return;
        }
        if matches!(resolve(printed), Ty::Array(..)) {
            let address = node.parent().filter(|parent| {
                parent.kind() == "pointer_expression" && operator(*parent, source) == Some("&")
            });
            match address {
                // `&name` of the whole array is the address of its first element for the cast that follows
                Some(parent) => replace(edits, parent.start_byte(), parent.end_byte(), format!("(({spelled} *)&{name})")),
                None => replace(edits, node.start_byte(), node.end_byte(), format!("(({spelled} *)&{name})")),
            }
        } else {
            replace(edits, node.start_byte(), node.end_byte(), format!("(*({spelled} *)&{name})"));
        }
    });
}

/// A pointer operand of an operator C defines on integers only (`& | ^ * / % << >>`, and `-` as `integer - pointer`) is
/// the unsigned integer of its width: the decompiler leaves a pointer bare where its word is untyped (its cast
/// strategy takes a pointer for an undefined word), and the project's declarations can make an object a pointer that
/// the decompiler printed as an integer (`lcp & 0xf` on a `void *`, `in_hi | (char *)&table`). `pointer - pointer` and
/// `pointer - integer` are C and are left alone. `ROMWRIGHT_EXPORT_POINTER_OPERANDS=off` disables it.
fn integer_operands(node: Node<'_>, typer: &Typer<'_>, source: &str, edits: &mut Vec<Edit>) {
    let Some(op) = operator(node, source) else { return };
    if !matches!(op, "&" | "|" | "^" | "*" | "/" | "%" | "<<" | ">>" | "-") {
        return;
    }
    let (Some(left), Some(right)) = (node.child_by_field_name("left"), node.child_by_field_name("right")) else { return };
    let is_pointer = |operand: Node<'_>| typer.of(operand).is_some_and(|ty| matches!(resolve(&decayed(&ty)), Ty::Ptr(_)));
    let is_integer = |operand: Node<'_>| typer.of(operand).is_some_and(|ty| matches!(resolve(&decayed(&ty)), Ty::Int(_)));
    for (operand, other, is_right) in [(left, right, false), (right, left, true)] {
        // `integer - pointer` is invalid; a pointer on the left of `-` is `pointer - x`, which is C
        let wanted = op != "-" || (is_right && is_integer(other));
        if wanted && is_pointer(operand) {
            cast_to(edits, operand, &Ty::Int(Int::UInt));
        }
    }
}

/// Casts where C converts nothing implicitly, and the arguments a callee does
/// not declare.
fn conform_expressions(function: &Function<'_>, decls: &Decls, source: &str, edits: &mut Vec<Edit>) {
    let Some(body) = function.node.child_by_field_name("body") else { return };
    let typer = Typer { decls, scope: &function.scope, source, own: Some((&function.name, &function.ty)) };
    let returns = match &function.ty {
        Ty::Func(ret, _) => Some((**ret).clone()),
        _ => None,
    };
    let mut temporaries: Vec<String> = Vec::new();
    visit(body, &mut |node| match node.kind() {
        "call_expression" => {
            let Some(callee) = node.child_by_field_name("function") else { return };
            let Some(arguments) = node.child_by_field_name("arguments") else { return };
            let args = named_children(arguments);
            // A value called that is not a function pointer.
            if let Some(ty) = typer.of(callee) {
                let callable = matches!(resolve(&decayed(&ty)), Ty::Ptr(target) if matches!(resolve(target), Ty::Func(..)));
                if !callable && !matches!(resolve(&ty), Ty::Func(..) | Ty::Unknown) {
                    let inner = strip_parens(callee);
                    let target = if inner.kind() == "pointer_expression" && operator(inner, source) == Some("*") {
                        inner.child_by_field_name("argument")
                    } else {
                        Some(inner)
                    };
                    if let Some(target) = target {
                        let text = text_of(target, source);
                        let wrapped = if is_prefix_safe(target) { text.to_string() } else { format!("({text})") };
                        replace(edits, callee.start_byte(), callee.end_byte(), format!("((int (*)()){wrapped})"));
                    }
                    return;
                }
            }
            let Some(name) = callee_name(node, source) else { return };
            let own = typer.own.filter(|(own, _)| decls.strict && *own == name).map(|(_, ty)| ty);
            let Some(Ty::Func(_, Some(params))) = own.or_else(|| decls.funcs.get(name)) else { return };
            let variadic = params.iter().any(|p| matches!(p, Ty::Ellipsis));
            let fixed = params.iter().filter(|p| !matches!(p, Ty::Ellipsis)).count();
            if !variadic && args.len() > fixed {
                // Arguments the project's declaration does not have.
                let start = match fixed {
                    0 => arguments.start_byte() + 1,
                    n => args[n - 1].end_byte(),
                };
                let end = args[args.len() - 1].end_byte();
                replace(edits, start, end, String::new());
                return;
            }
            if !variadic && args.len() < fixed && stage4("ROMWRIGHT_EXPORT_MISSING_ARGS") {
                // The decompiler recovered fewer arguments than the declaration takes (a register it took for dead
                // at the call): the call passes zero there, marked, so the compiler's arity check is met.
                let zeros: Option<Vec<&str>> = params[args.len()..fixed]
                    .iter()
                    .map(|param| match resolve(param) {
                        Ty::Int(_) | Ty::Ptr(_) => Some("0"),
                        Ty::Float(4) => Some("0.0f"),
                        Ty::Float(_) => Some("0.0"),
                        _ => None,
                    })
                    .collect();
                if let Some(zeros) = zeros {
                    let at = args.last().map_or(arguments.start_byte() + 1, |last| last.end_byte());
                    let lead = if args.is_empty() { "" } else { ", " };
                    let text: Vec<String> = zeros.iter().map(|zero| format!("/* unrecovered */ {zero}")).collect();
                    insert_after(edits, at, format!("{lead}{}", text.join(", ")));
                }
            }
            for (argument, param) in args.iter().zip(params.iter().take(fixed)) {
                // A structure passed by value arrives as the registers or the byte block it was: the decompiler passes
                // an integer or a byte array where the declaration takes the structure.
                if matches!(resolve(param), Ty::Agg(_)) && stage4("ROMWRIGHT_EXPORT_AGGREGATE_ARGS") {
                    let Some(from) = typer.of(*argument) else { continue };
                    let Some(aggregate) = spell(param) else { continue };
                    let inner = strip_parens(*argument);
                    let lvalue = matches!(inner.kind(), "identifier" | "field_expression" | "subscript_expression")
                        || (inner.kind() == "pointer_expression" && operator(inner, source) == Some("*"));
                    let (open, close) = if is_prefix_safe(*argument) { ("", "") } else { ("(", ")") };
                    match resolve(&from) {
                        Ty::Agg(_) | Ty::Func(..) | Ty::Void => {}
                        Ty::Array(..) => {
                            insert_before(edits, argument.start_byte(), format!("(*({aggregate} *){open}"));
                            insert_after(edits, argument.end_byte(), format!("{close})"));
                        }
                        _ if lvalue => {
                            insert_before(edits, argument.start_byte(), format!("(*({aggregate} *)&{open}"));
                            insert_after(edits, argument.end_byte(), format!("{close})"));
                        }
                        _ => {
                            // a value with no address: through a temporary the width of the registers
                            let name = format!("romwright_agg{}", temporaries.len());
                            insert_before(edits, argument.start_byte(), format!("({name} = (unsigned long long)("));
                            insert_after(edits, argument.end_byte(), format!("), *({aggregate} *)&{name})"));
                            temporaries.push(name);
                        }
                    }
                    continue;
                }
                // The decompiler's constant is a register's bits: a `float` parameter was handed `0x42ce0000`
                // (103.0f), which C converts as the number 1120403456.
                if matches!(resolve(param), Ty::Float(4)) && let Some(literal) = float_from_bits(*argument, source) {
                    replace(edits, argument.start_byte(), argument.end_byte(), literal);
                    continue;
                }
                if let Some(from) = typer.of(*argument)
                    && needs_cast(param, &from, is_zero(*argument, source)) {
                        cast_to(edits, *argument, param);
                    }
            }
        }
        "binary_expression" => {
            if decls.zero_compare && operator(node, source) == Some("<") && stage4("ROMWRIGHT_EXPORT_COMPARE_ZERO")
                && let (Some(left), Some(right)) = (node.child_by_field_name("left"), node.child_by_field_name("right")) {
                    let signed = matches!(typer.of(right).as_ref().map(resolve), Some(Ty::Int(Int::Int | Int::Short | Int::SChar | Int::Char | Int::Long)));
                    if signed && text_of(left, source).trim() == "-1" {
                        replace(edits, left.start_byte(), right.start_byte(), String::new());
                        insert_after(edits, right.end_byte(), " >= 0".into());
                    }
                }
            if decls.void_pointer_arithmetic && matches!(operator(node, source), Some("+" | "-")) {
                // A global the project declares `void *` (that the decompiler typed as an integer) added to or
                // subtracted from is cast to `char *`: byte arithmetic, which the compiler would reject on `void *`.
                // Parameters and locals are left alone: their `+ 1` counts elements of the type the decompiler
                // inferred, not bytes, and a sum that is itself an operand has had its own cast.
                for field in ["left", "right"] {
                    let Some(operand) = node.child_by_field_name(field) else { continue };
                    let inner = strip_parens(operand);
                    if inner.kind() != "identifier" || typer.scope.contains_key(text_of(inner, source)) {
                        continue;
                    }
                    let Some(ty) = typer.of(operand) else { continue };
                    if matches!(decayed(&ty), Ty::Ptr(target) if matches!(resolve(&target), Ty::Void)) {
                        cast_to(edits, operand, &Ty::Ptr(Box::new(Ty::Int(Int::Char))));
                    }
                }
            }
            if stage4("ROMWRIGHT_EXPORT_POINTER_OPERANDS") {
                integer_operands(node, &typer, source, edits);
            }
        }
        "assignment_expression" if operator(node, source) == Some("=") => {
            let (Some(left), Some(right)) = (node.child_by_field_name("left"), node.child_by_field_name("right")) else { return };
            let (Some(to), Some(from)) = (typer.of(left), typer.of(right)) else { return };
            // A float stored through an integer-typed pointer: the printer shows the value's own type (`p[1] = (float)x;`),
            // but the store the program does is the float's bits (`fstp dword [p + 4]`), not a conversion to the integer
            // (which would be `fistp`). The location is read as the float it holds.
            if let (Ty::Int(_), Ty::Float(width @ (4 | 8))) = (resolve(&to), resolve(&from))
                && size_of(&to) == Some(u64::from(*width))
                    && matches!(strip_parens(left).kind(), "subscript_expression" | "pointer_expression" | "field_expression")
                    && stage4("ROMWRIGHT_EXPORT_FLOAT_STORES")
                {
                    let spelling = if *width == 4 { "float" } else { "double" };
                    insert_before(edits, left.start_byte(), format!("*({spelling} *)&"));
                    return;
                }
            if needs_cast(&to, &from, is_zero(right, source)) {
                cast_to(edits, right, &to);
            }
        }
        "init_declarator" => {
            let (Some(left), Some(right)) = (node.child_by_field_name("declarator"), node.child_by_field_name("value")) else { return };
            let (Some(to), Some(from)) = (typer.of(left), typer.of(right)) else { return };
            if needs_cast(&to, &from, is_zero(right, source)) {
                cast_to(edits, right, &to);
            }
        }
        "return_statement" => {
            let (Some(to), Some(value)) = (&returns, named_children(node).into_iter().next()) else { return };
            if let Some(from) = typer.of(value)
                && needs_cast(to, &from, is_zero(value, source)) {
                    cast_to(edits, value, to);
                }
        }
        _ => {}
    });
    // the temporaries a structure argument without an address went through, declared first in the body
    for name in &temporaries {
        insert_after(edits, body.start_byte() + 1, format!("\n  unsigned long long {name};"));
    }
}

/// One counted loop `for (T = count; T != 0; T = T - 1) { *D = *S; S = S + 1; D = D + 1; }` (what `rep movs` is) or
/// `{ *D = 0; D = D + 1; }` (`rep stos` of zero).
struct StringLoop {
    start: usize,
    end: usize,
    counter: String,
    /// The initial count, as written.
    count: Option<String>,
    dest: String,
    src: Option<String>,
    width: u64,
}

/// The identifier a pointer expression is made of (`p`, `(unsigned int *)p`).
fn pointer_base<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    let node = strip_parens(node);
    match node.kind() {
        "identifier" => Some(text_of(node, source)),
        "cast_expression" => pointer_base(node.child_by_field_name("value")?, source),
        _ => None,
    }
}

/// `X = X + K` (a typed pointer's elements) or `X = (T *)((int)X + K)` (bytes): the bytes X advances.
fn pointer_step(statement: Node<'_>, typer: &Typer<'_>, source: &str) -> Option<(String, u64)> {
    let assignment = statement.named_child(0).filter(|n| n.kind() == "assignment_expression" && operator(*n, source) == Some("="))?;
    let left = assignment.child_by_field_name("left").filter(|n| n.kind() == "identifier")?;
    let name = text_of(left, source);
    let mut right = strip_parens(assignment.child_by_field_name("right")?);
    let mut in_bytes = false;
    if right.kind() == "cast_expression" {
        right = strip_parens(right.child_by_field_name("value")?);
        in_bytes = true;
    }
    if right.kind() != "binary_expression" || operator(right, source) != Some("+") {
        return None;
    }
    let (base, step) = (right.child_by_field_name("left")?, right.child_by_field_name("right")?);
    let base_name = if in_bytes {
        let cast = strip_parens(base);
        (cast.kind() == "cast_expression").then(|| pointer_base(cast.child_by_field_name("value")?, source)).flatten()?
    } else {
        pointer_base(base, source)?
    };
    if base_name != name || step.kind() != "number_literal" {
        return None;
    }
    let amount: u64 = parse_number(text_of(step, source))?;
    let element = if in_bytes {
        1
    } else {
        match decayed(&typer.of(left)?) {
            Ty::Ptr(target) => size_of(&target)?,
            _ => return None,
        }
    };
    Some((name.to_string(), amount * element))
}

fn parse_number(text: &str) -> Option<u64> {
    let text = text.trim_end_matches(['u', 'U', 'l', 'L']);
    match text.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => text.parse().ok(),
    }
}

fn string_loop(node: Node<'_>, typer: &Typer<'_>, source: &str) -> Option<StringLoop> {
    if node.kind() != "for_statement" {
        return None;
    }
    let condition = node.child_by_field_name("condition")?;
    let update = node.child_by_field_name("update")?;
    let body = node.child_by_field_name("body").filter(|n| n.kind() == "compound_statement")?;
    // `T != 0` and `T = T - 1`
    let counter = if condition.kind() == "binary_expression" && operator(condition, source) == Some("!=") {
        let left = condition.child_by_field_name("left").filter(|n| n.kind() == "identifier")?;
        (text_of(condition.child_by_field_name("right")?, source) == "0").then(|| text_of(left, source))?
    } else {
        return None;
    };
    let counter_step = update.kind() == "assignment_expression"
        && operator(update, source) == Some("=")
        && text_of(update.child_by_field_name("left")?, source) == counter
        && text_of(update.child_by_field_name("right")?, source).replace(' ', "") == format!("{counter}-1");
    if !counter_step {
        return None;
    }
    let count = node.child_by_field_name("initializer").and_then(|init| {
        let (left, right) = (init.child_by_field_name("left")?, init.child_by_field_name("right")?);
        (init.kind() == "assignment_expression" && text_of(left, source) == counter).then(|| text_of(right, source).to_string())
    });
    let mut store: Option<(Node<'_>, Node<'_>)> = None;
    let mut steps: Vec<(String, u64)> = Vec::new();
    for statement in named_children(body) {
        if statement.kind() != "expression_statement" {
            return None;
        }
        if let Some(step) = pointer_step(statement, typer, source) {
            steps.push(step);
            continue;
        }
        let assignment = statement.named_child(0).filter(|n| n.kind() == "assignment_expression" && operator(*n, source) == Some("="))?;
        let (left, right) = (assignment.child_by_field_name("left")?, assignment.child_by_field_name("right")?);
        if left.kind() != "pointer_expression" || operator(left, source) != Some("*") || store.is_some() {
            return None;
        }
        store = Some((left, right));
    }
    let (left, right) = store?;
    let width = size_of(&typer.of(left)?)?;
    let dest = pointer_base(left.child_by_field_name("argument")?, source)?.to_string();
    let src = if text_of(right, source) == "0" {
        None
    } else if right.kind() == "pointer_expression" && operator(right, source) == Some("*") {
        if size_of(&typer.of(right)?)? != width {
            return None;
        }
        Some(pointer_base(right.child_by_field_name("argument")?, source)?.to_string())
    } else {
        return None;
    };
    let moved: Vec<&str> = std::iter::once(dest.as_str()).chain(src.as_deref()).collect();
    if steps.len() != moved.len() || !moved.iter().all(|name| steps.iter().any(|(step, bytes)| step == name && *bytes == width)) {
        return None;
    }
    Some(StringLoop { start: node.start_byte(), end: node.end_byte(), counter: counter.to_string(), count, dest, src, width })
}

fn mentions(text: &str, name: &str) -> usize {
    let bytes = text.as_bytes();
    let wide = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let mut found = 0;
    let mut from = 0;
    while let Some(at) = text[from..].find(name) {
        let start = from + at;
        let end = start + name.len();
        if (start == 0 || !wide(bytes[start - 1])) && (end >= bytes.len() || !wide(bytes[end])) {
            found += 1;
        }
        from = end;
    }
    found
}

/// The strict rules spell byte pointers and integers where the printed text had other types: the casts between those
/// types and the project's declarations are made again.
fn conform_after_strict(function: &Function<'_>, decls: &Decls, source: &str, edits: &mut Vec<Edit>) {
    if decls.strict {
        conform_expressions(function, decls, source, edits);
    }
}

/// `rep movs` / `rep stos` printed as counted loops are `memcpy` / `memset`: the pair of loops (`n >> 2` dwords, then `n & 3` bytes) of
/// a copy of `n` bytes, and a loop of a constant count. The pointers and counters must be dead afterwards (the loops advanced them) and
/// the pointers used nowhere else (`ROMWRIGHT_EXPORT_STRING_OPS=off` keeps the loops).
fn string_loops(function: &Function<'_>, decls: &Decls, source: &str, edits: &mut Vec<Edit>) {
    if !decls.string_ops || !stage4("ROMWRIGHT_EXPORT_STRING_OPS") {
        return;
    }
    let Some(body) = function.node.child_by_field_name("body") else { return };
    let typer = Typer { decls, scope: &function.scope, source, own: Some((&function.name, &function.ty)) };
    // every mention of a name in the body's statements (the declarations at its head are not uses)
    let uses = |name: &str| -> usize {
        named_children(body).iter().filter(|child| child.kind() != "declaration").map(|child| mentions(text_of(*child, source), name)).sum()
    };
    let mut declared = (false, false);
    visit(body, &mut |block| {
        if block.kind() != "compound_statement" {
            return;
        }
        let statements = named_children(block);
        let mut index = 0;
        while index < statements.len() {
            let Some(first) = string_loop(statements[index], &typer, source) else {
                index += 1;
                continue;
            };
            let second = statements.get(index + 1).and_then(|next| string_loop(*next, &typer, source));
            // a copy of `n` bytes: `n >> 2` dwords, then `n & 3` bytes
            let pair = second.filter(|second| {
                let (a, b) = (first.count.as_deref().unwrap_or(""), second.count.as_deref().unwrap_or(""));
                first.width == 4 && second.width == 1 && first.src.is_some() && second.src.is_some()
                    && first.dest == second.dest && first.src == second.src
                    && a.strip_suffix(">> 2").is_some_and(|n| b.strip_suffix("& 3").is_some_and(|m| n.trim() == m.trim()))
            });
            let (last_end, call, names): (usize, String, Vec<&str>) = match (&pair, &first.count) {
                (Some(second), Some(count)) => {
                    let n = count.strip_suffix(">> 2").unwrap_or(count.as_str()).trim();
                    let src = first.src.as_deref().unwrap_or_default();
                    declared.0 = true;
                    (second.end, format!("memcpy({}, {src}, {n});", first.dest), vec![first.dest.as_str(), src, first.counter.as_str(), second.counter.as_str()])
                }
                (None, Some(count)) => {
                    let Some(bytes) = parse_number(count).map(|c| c * first.width) else { index += 1; continue };
                    match first.src.as_deref() {
                        Some(src) => {
                            declared.0 = true;
                            (first.end, format!("memcpy({}, {src}, {bytes});", first.dest), vec![first.dest.as_str(), src, first.counter.as_str()])
                        }
                        None => {
                            declared.1 = true;
                            (first.end, format!("memset({}, 0, {bytes});", first.dest), vec![first.dest.as_str(), first.counter.as_str()])
                        }
                    }
                }
                _ => {
                    index += 1;
                    continue;
                }
            };
            // dead afterwards, and the pointers used nowhere but the loops and the assignments just before them
            let after = &source[last_end..body.end_byte()];
            let mut allowed = vec![(first.start, last_end)];
            for earlier in statements[..index].iter().rev().take(3) {
                if let Some(assignment) = earlier.named_child(0).filter(|n| n.kind() == "assignment_expression")
                    && assignment.child_by_field_name("left").is_some_and(|l| l.kind() == "identifier") {
                        allowed.push((earlier.start_byte(), earlier.end_byte()));
                    }
            }
            let pointers = &names[..if pair.is_some() { 2 } else { names.len() - 1 }];
            let counters = &names[pointers.len()..];
            let inside = |name: &str| allowed.iter().map(|(a, b)| mentions(&source[*a..*b], name)).sum::<usize>();
            let ok = pointers.iter().all(|name| mentions(after, name) == 0 && uses(name) == inside(name))
                && counters.iter().all(|name| mentions(after, name) == 0);
            if ok {
                replace(edits, first.start, last_end, call);
            }
            index += if pair.is_some() { 2 } else { 1 };
        }
    });
    let mut header = String::new();
    if declared.0 {
        header.push_str("void *memcpy(void *, const void *, unsigned int);\n");
    }
    if declared.1 {
        header.push_str("void *memset(void *, int, unsigned int);\n");
    }
    if !header.is_empty() && !edits.is_empty() {
        insert_before(edits, function.node.start_byte(), header);
    }
}

/// One conformance rule: reads the function and the declarations, adds edits.
type Rule = fn(&Function<'_>, &Decls, &str, &mut Vec<Edit>);

/// Runs every rule on one printed function definition against `decls`.
pub(super) fn apply(source: &str, decls: &Decls) -> String {
    if std::env::var("ROMWRIGHT_NO_CONFORM").is_ok() {
        return source.to_string();
    }
    let mut text = if decls.strict { terminate_labels(source) } else { source.to_string() };
    let rules: [Rule; 11] = [
        code_values,
        partial_members,
        odd_array_locals,
        odd_casts,
        reconcile_header,
        retype_locals,
        reread_declared,
        conform_expressions,
        strict_expressions,
        conform_after_strict,
        string_loops,
    ];
    for rule in rules {
        let Some(tree) = reparse(&text) else { return text };
        let Some(function) = function(&tree, decls, &text) else { return text };
        let mut edits = Vec::new();
        rule(&function, decls, &text, &mut edits);
        if edits.is_empty() {
            continue;
        }
        if let Some(next) = apply_edits(&text, edits.clone())
            && reparse(&next).is_some()
        {
            text = next;
        } else if decls.strict {
            // one edit that breaks the text must not cost the others: keep those that leave it parseable
            edits.sort_by_key(|edit| (edit.start, edit.rank, edit.order));
            let mut kept: Vec<Edit> = Vec::new();
            for edit in edits {
                kept.push(edit);
                let parses = apply_edits(&text, kept.clone()).is_some_and(|next| reparse(&next).is_some());
                if !parses {
                    kept.pop();
                }
            }
            if let Some(next) = apply_edits(&text, kept) {
                text = next;
            }
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decls(header: &str) -> Decls {
        let mut decls = Decls::new();
        decls.add_source(header);
        decls
    }

    const HEADER: &str = "typedef unsigned char u8;\ntypedef unsigned int u32;\ntypedef int (*fn_t)();\n\
        u8 * get_task();\nvoid log_at(char * file, int line);\nvoid take(u8 * p, int n);\nint two(float a, float b);\n\
        extern u8 * g_ptr;\nu32 id(int x);\n";

    #[test]
    fn a_callee_returning_a_pointer_retypes_the_integer_local_it_is_assigned_to() {
        let out = apply(
            "int f(void)\n{\n  unsigned long long temp_v1;\n  temp_v1 = get_task();\n  take(temp_v1, 2);\n  return temp_v1 != 0;\n}\n",
            &decls(HEADER),
        );
        assert!(out.contains("u8 *temp_v1;"), "{out}");
        assert!(!out.contains("(u8 *)temp_v1"), "{out}");
    }

    #[test]
    fn a_pointer_result_used_as_a_number_is_cast_at_the_assignment() {
        let out = apply(
            "int f(void)\n{\n  int temp_v0;\n  temp_v0 = get_task();\n  return temp_v0 + 4;\n}\n",
            &decls(HEADER),
        );
        assert!(out.contains("int temp_v0;"), "{out}");
        assert!(out.contains("temp_v0 = (int)get_task();"), "{out}");
    }

    #[test]
    fn arithmetic_on_a_void_pointer_is_done_on_a_char_pointer_when_the_compiler_rejects_it() {
        let mut d = decls("extern void * edit_info;\nextern int light_no;\n");
        let source = "void f(void)\n{\n  *(unsigned int *)(light_no * 0x10 + edit_info + 0x70) = 0;\n}\n";
        assert!(apply(source, &d).contains("(light_no * 0x10 + edit_info + 0x70)"));
        d.void_pointer_arithmetic = true;
        let out = apply(source, &d);
        assert!(out.contains("(light_no * 0x10 + (char *)edit_info + 0x70)"), "{out}");
        // A parameter's `+ 1` counts elements of the type the decompiler inferred, not bytes: left alone.
        let source = "void f(void *param_1)\n{\n  take((short *)(param_1 + 1), (short *)(((fn_arg0 *)param_1) + 1));\n}\n";
        assert!(!apply(source, &d).contains("(char *)"), "{}", apply(source, &d));
    }

    #[test]
    fn an_integer_passed_where_a_pointer_is_declared_is_cast() {
        let out = apply("void f(int a)\n{\n  take(a + 0x30, 2);\n  take(0, 2);\n}\n", &decls(HEADER));
        assert!(out.contains("take((u8 *)(a + 0x30), 2);"), "{out}");
        assert!(out.contains("take(0, 2);"), "{out}");
    }

    #[test]
    fn a_local_array_passed_for_a_matrix_parameter_is_cast_to_a_pointer_to_the_row_array() {
        let d = decls("typedef float sceVu0FMATRIX[4][4];\ntypedef float sceVu0FVECTOR[4];\nvoid unit(sceVu0FMATRIX m);\nvoid vec(sceVu0FVECTOR v);\n");
        let out = apply("void f(void)\n{\n  float afStack_40 [16];\n  unit(afStack_40);\n  vec(afStack_40);\n}\n", &d);
        assert!(out.contains("unit((float (*)[4])afStack_40);"), "{out}");
        assert!(!out.contains("float **"), "{out}");
        // a vector is a pointer to its element: the array already has that type
        assert!(out.contains("vec(afStack_40);"), "{out}");
    }

    #[test]
    fn a_pointer_operand_of_an_integer_operator_is_the_unsigned_integer_of_its_width() {
        let d = decls("extern void * lcp;\nextern int count;\n");
        let out = apply(
            "int f(unsigned long long in_hi)\n{\n  if ((lcp & 0xf) == 0) {\n    return (int)(in_hi | (char *)&table);\n  }\n  return (int)lcp - (char *)&table + (lcp - lcp) + count;\n}\n",
            &d,
        );
        assert!(out.contains("(((unsigned int)lcp) & 0xf)") || out.contains("((unsigned int)lcp & 0xf)"), "{out}");
        assert!(out.contains("in_hi | (unsigned int)&table"), "{out}");
        assert!(out.contains("(int)lcp - (unsigned int)&table"), "{out}");
        // a pointer difference is C
        assert!(out.contains("(lcp - lcp)"), "{out}");
    }

    #[test]
    fn a_structure_passed_by_value_is_read_from_the_bytes_or_registers_the_decompiler_passed() {
        let d = decls("typedef struct Vec2f { float x; float y; } Vec2f;\ntypedef struct { char b[16]; } Rect;\nvoid place(Vec2f at, int n);\nvoid draw(Rect r);\n");
        let out = apply(
            "void f(void)\n{\n  unsigned char buf [16];\n  int v;\n  draw(buf);\n  place(0x42ce0000, 1);\n  place(v, 2);\n}\n",
            &d,
        );
        assert!(out.contains("draw((*(Rect *)buf));"), "{out}");
        assert!(out.contains("place((romwright_agg0 = (unsigned long long)(0x42ce0000), *(Vec2f *)&romwright_agg0), 1);"), "{out}");
        assert!(out.contains("place((*(Vec2f *)&v), 2);"), "{out}");
        assert!(out.contains("unsigned long long romwright_agg0;"), "{out}");
    }

    #[test]
    fn arguments_the_declaration_takes_and_the_decompiler_did_not_recover_are_passed_as_marked_zeros() {
        let d = decls("void three(int a, float b, char * c);\n");
        let out = apply("void f(void)\n{\n  three(1);\n  three();\n}\n", &d);
        assert!(out.contains("three(1, /* unrecovered */ 0.0f, /* unrecovered */ 0);"), "{out}");
        assert!(out.contains("three(/* unrecovered */ 0, /* unrecovered */ 0.0f, /* unrecovered */ 0);"), "{out}");
    }

    #[test]
    fn an_integer_literal_passed_where_a_float_is_declared_is_the_float_its_bits_spell() {
        let out = apply("void f(int a)\n{\n  two(0x42ce0000, 0);\n  two(0x3f800000U, a);\n  two(0x7f800000, 3);\n}\n", &decls(HEADER));
        assert!(out.contains("two(103.0f, 0);"), "{out}");
        assert!(out.contains("two(1.0f, a);"), "{out}");
        // a small integer, an infinity or a NaN is left alone
        assert!(out.contains("two(0x7f800000, 3);"), "{out}");
    }

    #[test]
    fn bytes_indexed_in_an_object_the_header_declares_as_structures_go_through_its_address() {
        let mut d = Decls::new();
        d.add_source("extern unsigned char ene_wrk[]; extern unsigned char camera[560]; extern unsigned int same_w[4]; extern int count;");
        d.remember_printed();
        d.add_source("typedef struct { int a; } ENE_WRK;\nextern ENE_WRK ene_wrk[8];\ntypedef struct { float f; } CAM;\nextern CAM camera;\n\
            extern int same_w[4];\nextern unsigned int count;\n");
        let out = apply("void f(int i)\n{\n  ene_wrk[i + 0x11] = 1;\n  g((float *)camera);\n  same_w[1] = 2;\n  count = 3;\n  h(&camera);\n}\n", &d);
        assert!(out.contains("((unsigned char *)&ene_wrk)[i + 0x11] = 1;"), "{out}");
        assert!(out.contains("g((float *)((unsigned char *)&camera));"), "{out}");
        assert!(out.contains("h(((unsigned char *)&camera));"), "{out}");
        // the same width of another signedness is the same access
        assert!(out.contains("same_w[1] = 2;") && out.contains("count = 3;"), "{out}");
    }

    #[test]
    fn a_void_pointer_object_the_decompiler_printed_as_an_int_pointer_is_cast_where_it_is_dereferenced() {
        let mut d = Decls::new();
        d.add_source("extern int * names;");
        d.remember_printed();
        d.add_source("extern void * names;");
        let out = apply("void f(int a)\n{\n  *names = a;\n  names[1] = a;\n  g(names);\n}\n", &d);
        assert!(out.contains("*((int *)names) = a;"), "{out}");
        assert!(out.contains("((int *)names)[1] = a;"), "{out}");
        assert!(out.contains("g(names);"), "{out}");
    }

    #[test]
    fn a_byte_string_passed_as_char_pointer_is_cast() {
        let mut d = decls(HEADER);
        d.add_source("extern unsigned char LAB_005e4298;");
        let out = apply("void f(void)\n{\n  log_at(&LAB_005e4298, 0x1c3);\n}\n", &d);
        assert!(out.contains("log_at((char *)&LAB_005e4298, 0x1c3);"), "{out}");
    }

    #[test]
    fn a_function_address_stored_through_a_function_pointer_slot_is_cast() {
        let mut d = decls("void handler(void * p);\n");
        d.typedefs.insert("code".into(), Ty::Ptr(Box::new(Ty::Func(Box::new(Ty::Int(Int::Int)), None))));
        let out = apply("void f(unsigned char * pbVar1)\n{\n  *(code **)(pbVar1 + 8) = handler;\n}\n", &d);
        assert!(out.contains("= (code *)handler;"), "{out}");
    }

    #[test]
    fn a_function_address_stored_in_a_typedef_slot_of_the_output_is_cast() {
        let d = decls("void handler(void * p);\n");
        let out = apply("void f(unsigned char * pbVar1)\n{\n  *(romwright_code **)(pbVar1 + 8) = handler;\n}\n", &d);
        assert!(out.contains("= (romwright_code *)handler;"), "{out}");
    }

    #[test]
    fn a_pointer_that_is_called_through_a_void_pointer_is_cast_to_a_function_pointer() {
        let out = apply(
            "int f(void * param_1, int a)\n{\n  int temp_v0;\n  temp_v0 = (*param_1)(a, 2);\n  return temp_v0;\n}\n",
            &decls(HEADER),
        );
        assert!(out.contains("((int (*)())param_1)(a, 2)"), "{out}");
    }

    #[test]
    fn arguments_beyond_the_declared_parameters_are_dropped() {
        let out = apply("int f(float a, float b)\n{\n  int x;\n  return two(a, b, &x);\n}\n", &decls(HEADER));
        assert!(out.contains("two(a, b)"), "{out}");
        let out = apply("int f(float a)\n{\n  return two(a, 1.0, 2);\n}\n", &decls(HEADER));
        assert!(out.contains("two(a, 1.0)"), "{out}");
    }

    #[test]
    fn the_definition_takes_the_types_the_context_declares() {
        let d = decls("typedef unsigned char u8;\nu8 task_run(long a, int b);\n");
        let out = apply("unsigned char task_run(int param_1, int param_2)\n{\n  return param_1 + param_2;\n}\n", &d);
        assert!(out.contains("u8 task_run(long param_1, int param_2)"), "{out}");
    }

    #[test]
    fn a_value_returned_by_a_function_the_project_declares_void_is_dropped() {
        let d = decls("void set_dir(char * p);\nvoid tail(char * p);\n");
        let out = apply("int set_dir(char *param_1)\n{\n  if (*param_1 == 0) return 0;\n  if (*param_1 == 1) return other(param_1);\n  return (int)param_1;\n}\n", &d);
        assert!(out.contains("void set_dir(char *param_1)"), "{out}");
        assert!(out.contains("if (*param_1 == 0) return;"), "{out}");
        assert!(out.contains("if (*param_1 == 1) { other(param_1); return; }"), "{out}");
        assert!(!out.contains("return (int)"), "{out}");
    }

    #[test]
    fn a_structure_passed_by_value_is_declared_as_such_and_read_as_its_registers() {
        let d = decls("typedef struct Vec2f { float x; float y; } Vec2f;\ntypedef unsigned char u8;\nvoid place(u8 * a, Vec2f at, int n);\n");
        let out = apply(
            "void place(unsigned char * param_1, unsigned long long param_2, int param_3)\n{\n  use(param_2 >> 0x20, param_2);\n}\n",
            &d,
        );
        assert!(out.contains("void place(u8 *param_1, Vec2f param_2, int param_3)"), "{out}");
        assert!(out.contains("use((*(unsigned long long *)&param_2) >> 0x20, (*(unsigned long long *)&param_2))"), "{out}");
    }

    #[test]
    fn an_unnamed_structure_passed_by_value_is_an_aggregate_too() {
        let d = decls("typedef struct { float x; float y; } Vec2f;\ntypedef Vec2f YVec2f;\nvoid place(char * a, YVec2f at);\n");
        let out = apply("void place(int param_1, unsigned long long param_2)\n{\n  use(param_1, param_2);\n}\n", &d);
        assert!(out.contains("void place(char *param_1, YVec2f param_2)"), "{out}");
        assert!(out.contains("use(param_1, (*(unsigned long long *)&param_2))"), "{out}");
    }

    #[test]
    fn the_decompilers_float_first_parameter_order_is_the_declared_order() {
        let d = decls("void scale(int count, float factor, short mode);\n");
        let out = apply("void scale(float param_1, int param_2, int param_3)\n{\n  use(param_1, param_2, param_3);\n}\n", &d);
        assert!(out.contains("void scale(int param_2, float param_1, short param_3)"), "{out}");
        assert!(out.contains("use(param_1, param_2, param_3)"), "{out}");
    }

    #[test]
    fn a_declared_return_type_of_the_same_spelling_leaves_the_definition_alone() {
        let source = "u32 id(int param_1)\n{\n  return param_1;\n}\n";
        assert_eq!(apply(source, &decls(HEADER)), source);
    }

    #[test]
    fn long_is_spelled_by_its_size_and_ghidras_code_by_a_typedef() {
        let (out, code) = spelled("extern code * DAT_1;\nlong f(unsigned long a, long long b, long * c)\n{\n  return (long)a;\n}\n");
        assert!(out.contains("extern romwright_code * DAT_1;"), "{out}");
        assert!(out.contains("int f(unsigned int a, long long b, int * c)"), "{out}");
        assert!(out.contains("(int)a"), "{out}");
        assert!(code);
        let (out, code) = spelled("extern int x;\n");
        assert_eq!((out.as_str(), code), ("extern int x;\n", false));
    }

    #[test]
    fn a_width_c_has_no_type_of_behind_a_pointer_is_void() {
        let (out, _) = spelled("void f(int p)\n{\n  *(undefined5 **)(p + 4) = &x;\n  *(undefined4 *)p = 0;\n}\n");
        assert!(out.contains("*(void **)(p + 4) = &x;"), "{out}");
        assert!(out.contains("*(undefined4 *)p = 0;"), "{out}");
    }

    #[test]
    fn integers_of_a_width_c_has_no_type_of_are_the_next_wider_integer() {
        let (out, _) = spelled("void f(long long x)\n{\n  y = CONCAT71((int7)(x >> 8), 0x48);\n  z = (uint3)x;\n}\n");
        assert!(out.contains("CONCAT71((long long)(x >> 8), 0x48)"), "{out}");
        assert!(out.contains("(unsigned int)x"), "{out}");
    }

    #[test]
    fn scalars_out_of_gp_reach_are_arrays_of_unknown_size() {
        let decls = Decls::new();
        let globals = [
            ("DAT_far", "unsigned int DAT_far", Some(0x8873f4)),
            ("DAT_near", "unsigned int DAT_near", Some(0x7690f0 - 0x6430)),
            ("DAT_table", "unsigned int DAT_table[4]", Some(0x887000)),
            ("DAT_big", "struct S DAT_big", Some(0x887000)),
        ];
        let names = gp_arrays(globals.iter().map(|(n, d, a)| (*n, *d, *a)), 0x7690f0, &decls);
        assert_eq!(names, ["DAT_far"]);
        let out = index_arrays(
            "int f(void)\n{\n  g(&DAT_far);\n  DAT_far = DAT_far + 1;\n  return DAT_near;\n}\n",
            &names,
        );
        assert!(out.contains("g(DAT_far);"), "{out}");
        assert!(out.contains("DAT_far[0] = DAT_far[0] + 1;"), "{out}");
        assert!(out.contains("return DAT_near;"), "{out}");
    }

    #[test]
    fn a_text_that_does_not_parse_is_returned_unchanged() {
        let source = "int f(void) { return ";
        assert_eq!(apply(source, &decls(HEADER)), source);
    }

    #[test]
    fn a_float_stored_through_an_integer_pointer_is_a_store_of_the_float() {
        let out = apply("void f(unsigned int * p, float x)\n{\n  p[1] = (float)x;\n  p[2] = 7;\n}\n", &decls(""));
        assert!(out.contains("*(float *)&p[1] = (float)x;"), "{out}");
        assert!(out.contains("p[2] = 7;"), "{out}");
    }

    #[test]
    fn minus_one_less_than_a_signed_value_is_a_compare_with_zero_for_visual_c() {
        let mut d = decls("");
        d.zero_compare = true;
        let out = apply("int f(int x, unsigned int y)\n{\n  if (-1 < x) {\n    return 1;\n  }\n  return -1 < y;\n}\n", &d);
        assert!(out.contains("if (x >= 0)"), "{out}");
        assert!(out.contains("return -1 < y;"), "an unsigned operand keeps its comparison: {out}");
        let plain = apply("int f(int x)\n{\n  return -1 < x;\n}\n", &decls(""));
        assert!(plain.contains("-1 < x"), "{plain}");
    }

    #[test]
    fn the_loops_of_a_rep_movs_and_a_rep_stos_are_the_calls_they_came_from_for_visual_c() {
        let mut d = decls("");
        d.string_ops = true;
        let copy = "void f(unsigned int * a, unsigned int * b, unsigned int n)\n{\n  unsigned int temp_v2;\n  unsigned int * puVar5;\n  unsigned int * puVar6;\n  \
            puVar5 = b;\n  puVar6 = a;\n  \
            for (temp_v2 = n >> 2; temp_v2 != 0; temp_v2 = temp_v2 - 1) {\n    *puVar6 = *puVar5;\n    puVar5 = puVar5 + 1;\n    puVar6 = puVar6 + 1;\n  }\n  \
            for (temp_v2 = n & 3; temp_v2 != 0; temp_v2 = temp_v2 - 1) {\n    *(unsigned char *)puVar6 = *(unsigned char *)puVar5;\n    \
            puVar5 = (unsigned int *)((int)puVar5 + 1);\n    puVar6 = (unsigned int *)((int)puVar6 + 1);\n  }\n}\n";
        let out = apply(copy, &d);
        assert!(out.contains("memcpy(puVar6, puVar5, n);") && !out.contains("for ("), "{out}");
        assert!(out.contains("void *memcpy(void *, const void *, unsigned int);"), "{out}");
        let fill = "void g(unsigned int * p)\n{\n  unsigned int temp_v0;\n  for (temp_v0 = 0xd; temp_v0 != 0; temp_v0 = temp_v0 - 1) {\n    *p = 0;\n    p = p + 1;\n  }\n}\n";
        assert!(apply(fill, &d).contains("memset(p, 0, 52);"), "{}", apply(fill, &d));
        // the pointer is used afterwards: the loop advanced it, so the loop stays
        let used = "unsigned int * h(unsigned int * p)\n{\n  unsigned int temp_v0;\n  for (temp_v0 = 0xd; temp_v0 != 0; temp_v0 = temp_v0 - 1) {\n    *p = 0;\n    p = p + 1;\n  }\n  return p;\n}\n";
        assert!(apply(used, &d).contains("for ("), "{}", apply(used, &d));
        assert!(apply(fill, &decls("")).contains("for ("));
    }
}
