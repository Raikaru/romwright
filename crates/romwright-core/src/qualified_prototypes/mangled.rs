//! What an import does with MWCC-mangled names: the display name a reader
//! sees, the identifier the decompiler prints, and the prototype the mangled
//! parameter list proves.
//!
//! The mangled name stays the function's linkage name (`functions.name`, the
//! symbol row the loader read), exactly as the Itanium path keeps
//! `_ZTIi` beside the `typeinfo` it derives. This module only derives.
//!
//! # Dialect
//!
//! The import uses the default dialect, which expands `T<i>`/`N<n><i>`
//! repeated-parameter back-references. MWCC emits them for any function with
//! two parameters of one class type (`MulMatrix0__FPC6MATRIXT0P6MATRIX`), so
//! the `dtk`-only dialect would leave those names mangled and give them no
//! parameter count, and its refusal is not evidence that the name is
//! malformed: the 267 corpus names it refuses are all back-reference forms.
//! Every name `dtk demangle` accepts renders identically in both dialects
//! (`benchmarks/mwcc_demangle_diff.py` reports the delta).
//!
//! # What the parameter list does and does not say
//!
//! The mangling carries parameter types and, for template instances, a
//! return type. It does not carry the return type of anything else, and it
//! does not say whether a non-const member takes `this`: MWCC marks no static
//! members, so `Class::f(int)` may be a static taking one argument or an
//! instance method taking two. Measured on Bond.elf (1,500 mangled functions
//! decompiled with the decompiler's own recovery), 71% of such members
//! print `this` plus the spelled parameters and 21% print the spelled
//! parameters alone, so a prototype that assumed either would be wrong one
//! time in five or three. The prototype is therefore built only where the
//! name proves the arity: free functions (no `this`), constructors,
//! destructors and const members (always `this`). A destructor also takes
//! MWCC's delete flag, which the mangling omits: the recovery printed two
//! parameters for 82 of 82 destructors. Any other scoped function is left to
//! the decompiler's recovery.
//!
//! The prototype's return type is a placeholder the C parser needs
//! (`undefined4`): the worker applies these rows in the decompiler's
//! `params` mode, which locks the parameters and leaves the return value to
//! the decompiler. Locking it was measured: it made 44% of the functions the
//! recovery printed `void` return a value.

use super::mwcc_demangle::{self, Demangled, Kind};
use super::{c_identifier, c_type};
use romwright_model::{
    Address, FactKind, FactProvenance, PrototypeRow, SymbolRow,
};
use std::collections::{HashMap, HashSet};

/// Provenance of the display symbol derived from a mangled name.
pub const DISPLAY_SOURCE: &str = "native-analysis:mwcc-demangle";
/// Provenance of a prototype built from a mangled parameter list.
pub const PROTOTYPE_SOURCE: &str = "native-analysis:mwcc-prototype";

/// The display symbols for the names an image holds: one row per name that
/// demangles, at the address that carries it, named with `dtk`'s spelling
/// (`UberBond::Update(char*)`). Names that do not demangle, and names whose
/// demangling is the name itself, produce nothing.
pub fn display_symbols<'a>(
    names: impl IntoIterator<Item = (Address, &'a str, bool)>,
) -> Vec<SymbolRow> {
    // A function and the symbol row that names the same address arrive as
    // one name twice; the display row is one fact.
    let mut seen: HashSet<(u64, String)> = HashSet::new();
    names
        .into_iter()
        .filter_map(|(address, name, external)| {
            let demangled = mwcc_demangle::demangle(name)?;
            (demangled.text != name && seen.insert((address.offset, demangled.text.clone())))
                .then(|| SymbolRow {
                    name: demangled.text,
                    address,
                    external,
                    source: DISPLAY_SOURCE.into(),
                })
        })
        .collect()
}

/// A C identifier spelling `text`: `::` becomes `_`, any other run of
/// characters outside `[0-9A-Za-z_]` becomes one `_`, `~` reads `dtor_`, and
/// a leading digit is guarded.
fn identifier(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut pending_separator = false;
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            if pending_separator && !out.is_empty() && !out.ends_with('_') {
                out.push('_');
            }
            pending_separator = false;
            out.push(ch);
        } else if ch == '~' {
            if !out.is_empty() && !out.ends_with('_') {
                out.push('_');
            }
            out.push_str("dtor");
            pending_separator = true;
        } else {
            pending_separator = true;
        }
    }
    if out.is_empty() {
        out.push_str("symbol");
    } else if out.as_bytes()[0].is_ascii_digit() {
        out.insert(0, '_');
    }
    out
}

/// An operator spelled with words (`operator=` is `operator_eq`), so that the
/// operators of one class print as distinct identifiers; any other name is
/// returned unchanged.
fn operator_word(name: &str) -> String {
    let Some(rest) = name.strip_prefix("operator") else {
        return name.to_string();
    };
    if rest.starts_with(' ') || rest.is_empty() {
        // `operator new[]`, `operator delete`, `operator char*`.
        return format!("operator_{}", rest.trim().replace("[]", "_array"));
    }
    let words: Vec<&str> = rest
        .chars()
        .map(|c| match c {
            '=' => "eq",
            '+' => "plus",
            '-' => "minus",
            '*' => "mul",
            '/' => "div",
            '%' => "mod",
            '<' => "lt",
            '>' => "gt",
            '!' => "not",
            '&' => "and",
            '|' => "or",
            '^' => "xor",
            '~' => "compl",
            '[' | ']' => "idx",
            '(' | ')' => "call",
            ',' => "comma",
            _ => "op",
        })
        .collect();
    format!("operator_{}", words.join("_"))
}

/// The identifier a symbol prints as. Overloads share `Class::name`, so a
/// qualified name held by several symbols is spelled with its parameter
/// types, and one that still collides falls back to its mangled name, which
/// is already a C identifier and unique by construction.
///
/// Takes every `(address, mangled name)` the program holds; returns only the
/// symbols that demangle.
pub fn print_names<'a>(
    names: impl IntoIterator<Item = (u64, &'a str)>,
) -> HashMap<u64, String> {
    let demangled: Vec<(u64, &str, Demangled)> = names
        .into_iter()
        .filter_map(|(address, name)| Some((address, name, mwcc_demangle::demangle(name)?)))
        .collect();
    let bare = |d: &Demangled| {
        // A function-local static prints as its full text: `Get()::x`.
        if d.kind == Kind::LocalStatic {
            return identifier(&d.text);
        }
        let name = operator_word(&d.name);
        let base = if d.scope.is_empty() { name } else { format!("{}::{name}", d.scope) };
        identifier(&base)
    };
    let mut claims: HashMap<String, usize> = HashMap::new();
    for (_, _, d) in &demangled {
        *claims.entry(bare(d)).or_default() += 1;
    }
    let mut spelled: HashMap<String, usize> = HashMap::new();
    let mut chosen: Vec<(u64, &str, String)> = Vec::with_capacity(demangled.len());
    for (address, name, d) in &demangled {
        let base = bare(d);
        let text = if claims[&base] > 1 { identifier(&d.text) } else { base };
        *spelled.entry(text.clone()).or_default() += 1;
        chosen.push((*address, *name, text));
    }
    // Last resort: the mangled name, which is a C identifier. Two static
    // functions of one name in different units mangle identically, so a name
    // still shared is told apart by its address.
    let mut linkage: HashMap<&str, usize> = HashMap::new();
    for (_, name, text) in &chosen {
        if spelled[text] != 1 {
            *linkage.entry(*name).or_default() += 1;
        }
    }
    chosen
        .iter()
        .map(|(address, name, text)| {
            let printed = if spelled[text] == 1 {
                text.clone()
            } else if linkage[name] == 1 {
                c_identifier(name)
            } else {
                format!("{}_{address:x}", c_identifier(name))
            };
            (*address, printed)
        })
        .collect()
}

/// The receiver and parameter C declarations of a demangled function, in
/// declaration order, or `None` when a type has no C spelling.
fn c_signature_parts(
    function: &Demangled,
    known_types: &HashSet<String>,
) -> Option<(Vec<String>, bool)> {
    let mut parts = Vec::with_capacity(function.parameters.len() + 1);
    if !function.scope.is_empty() {
        let plain = function.scope.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        let receiver = if plain && known_types.contains(function.scope.as_str()) {
            function.scope.as_str()
        } else if known_types.contains("void") {
            "void"
        } else {
            return None;
        };
        parts.push(format!("{receiver} * this"));
    }
    // MWCC passes a destructor a second argument, the delete flag.
    if function.is_destructor {
        parts.push(format!("{} param_1", c_type("short", known_types, false)?));
    }
    let skipped = parts.len() - usize::from(!function.scope.is_empty());
    let mut variadic = false;
    for (index, parameter) in function.parameters.iter().enumerate() {
        if parameter == "..." {
            variadic = true;
            continue;
        }
        let c_type = c_type(parameter, known_types, true)?;
        parts.push(format!("{c_type} param_{}", index + 1 + skipped));
    }
    Some((parts, variadic))
}

/// Whether the name proves the function's arity: a free function never takes
/// `this`; a constructor, destructor or const member always does. Any other
/// scoped function may be static, and the name does not say.
fn arity_is_proven(function: &Demangled) -> bool {
    function.scope.is_empty()
        || function.is_constructor
        || function.is_destructor
        || function.is_const
}

/// The prototype a function's mangled parameter list proves, as a C
/// declaration the decompiler's parser accepts. `None` when the name is not a
/// function, or a parameter type has no C spelling.
pub fn prototype_signature(
    mangled: &str,
    known_types: &HashSet<String>,
) -> Option<(String, String)> {
    let function = mwcc_demangle::demangle(mangled)?;
    if function.kind != Kind::Function || !function.has_parameter_list || !arity_is_proven(&function)
    {
        return None;
    }
    let unknown = ["undefined4"]
        .into_iter()
        .find(|name| known_types.contains(*name))?;
    let return_type = match &function.return_type {
        Some(ret) => c_type(ret, known_types, true).unwrap_or_else(|| unknown.to_string()),
        None => unknown.to_string(),
    };
    let (mut parts, variadic) = c_signature_parts(&function, known_types)?;
    if variadic {
        parts.push("...".to_string());
    }
    let list = if parts.is_empty() { "void".to_string() } else { parts.join(", ") };
    let name = identifier(&function.name);
    Some((format!("{return_type} {name}({list})"), return_type))
}

/// The prototype rows for the functions an image holds.
pub fn prototype_rows<'a>(
    functions: impl IntoIterator<Item = (u64, &'a str)>,
    known_types: &HashSet<String>,
) -> Vec<PrototypeRow> {
    functions
        .into_iter()
        .filter_map(|(entry, name)| {
            let (signature, return_type) = prototype_signature(name, known_types)?;
            Some(PrototypeRow {
                function: Address::ram(entry),
                signature,
                calling_convention: None,
                return_type: Some(return_type),
                provenance: FactProvenance {
                    kind: FactKind::Inferred,
                    source: PROTOTYPE_SOURCE.into(),
                    confidence: None,
                },
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn types(names: &[&str]) -> HashSet<String> {
        names.iter().map(|name| (*name).to_string()).collect()
    }

    fn known() -> HashSet<String> {
        types(&[
            "void", "int", "uint", "char", "short", "ushort", "float", "double", "bool", "byte",
            "sbyte", "longlong", "undefined4", "UberBond", "long", "ulong", "short",
        ])
    }

    #[test]
    fn display_rows_carry_dtks_spelling_and_skip_everything_else() {
        let rows = display_symbols([
            (Address::ram(0x100), "Update__8UberBondFPc", false),
            (Address::ram(0x200), "__vt__8UberBond", false),
            (Address::ram(0x300), "printf", false),
            (Address::ram(0x400), "DrawFontChar__Fiiii", true),
            (Address::ram(0x500), "Update__8UberBondFv.NON_MATCHING", false),
        ]);
        let shown: Vec<(u64, &str, bool)> =
            rows.iter().map(|r| (r.address.offset, r.name.as_str(), r.external)).collect();
        assert_eq!(
            shown,
            [
                (0x100, "UberBond::Update(char*)", false),
                (0x200, "UberBond::__vtable", false),
                (0x400, "DrawFontChar(int, int, int, int)", true),
            ]
        );
        assert!(rows.iter().all(|r| r.source == DISPLAY_SOURCE));
    }

    #[test]
    fn printed_identifiers_are_valid_c_and_overloads_stay_distinct() {
        let names = print_names([
            (0x10, "Update__8UberBondFPc"),
            (0x20, "__ct__8UberBondFv"),
            (0x30, "__dt__8UberBondFv"),
            (0x40, "Load__8UberBondFPc"),
            (0x50, "Load__8UberBondFi"),
            (0x60, "DrawFontChar__Fiiii"),
            (0x70, "AddObject__12Container<i>FRCi"),
            (0x80, "__as__3strFPCc"),
            (0x90, "printf"),
        ]);
        assert_eq!(names[&0x10], "UberBond_Update");
        assert_eq!(names[&0x20], "UberBond_UberBond");
        assert_eq!(names[&0x30], "UberBond_dtor_UberBond");
        assert_eq!(names[&0x60], "DrawFontChar");
        assert_eq!(names[&0x70], "Container_int_AddObject");
        assert_eq!(names[&0x80], "str_operator_eq");
        // The overloads share `UberBond::Load`: parameters tell them apart.
        assert_eq!(names[&0x40], "UberBond_Load_char");
        assert_eq!(names[&0x50], "UberBond_Load_int");
        assert!(!names.contains_key(&0x90));
        for name in names.values() {
            assert!(
                name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                    && !name.as_bytes()[0].is_ascii_digit(),
                "{name}"
            );
        }
    }

    #[test]
    fn operators_print_as_words_so_a_class_keeps_them_apart() {
        let names = print_names([
            (0x10, "__as__3strFPCc"),
            (0x20, "__eq__3strFPCc"),
            (0x30, "__nw__FUlP7JKRHeapi"),
            (0x40, "__nwa__FUlP7JKRHeapi"),
            (0x50, "__vc__3strFi"),
            (0x60, "__opPc__3strFv"),
        ]);
        assert_eq!(names[&0x10], "str_operator_eq");
        assert_eq!(names[&0x20], "str_operator_eq_eq");
        assert_eq!(names[&0x30], "operator_new");
        assert_eq!(names[&0x40], "operator_new_array");
        assert_eq!(names[&0x50], "str_operator_idx_idx");
        assert_eq!(names[&0x60], "str_operator_char");
    }

    #[test]
    fn one_mangled_name_at_two_addresses_is_told_apart_by_address() {
        let names = print_names([(0x100, "calcSum__FPUcUl"), (0x200, "calcSum__FPUcUl")]);
        assert_eq!(names[&0x100], "calcSum__FPUcUl_100");
        assert_eq!(names[&0x200], "calcSum__FPUcUl_200");
    }

    #[test]
    fn names_that_still_collide_print_as_their_mangled_name() {
        // Same qualified name and same parameter spelling after sanitizing.
        let names = print_names([(0x10, "f__FPc"), (0x20, "f__FRc")]);
        assert_eq!(names[&0x10], "f__FPc");
        assert_eq!(names[&0x20], "f__FRc");
    }

    #[test]
    fn prototypes_carry_the_mangled_parameters_and_the_receiver() {
        let known = known();
        let (free, _) = prototype_signature("DrawFontChar__Fiiii", &known).unwrap();
        assert_eq!(
            free,
            "undefined4 DrawFontChar(int param_1, int param_2, int param_3, int param_4)"
        );
        let (member, ret) = prototype_signature("Update__8UberBondCFPcUi", &known).unwrap();
        assert_eq!(member, "undefined4 Update(UberBond * this, char * param_1, uint param_2)");
        assert_eq!(ret, "undefined4");
        // An undeclared class degrades to `void *`, keeping the slot.
        let (unknown, _) = prototype_signature("Handle__5ActorCFP5EventRC6COORD3", &known).unwrap();
        assert_eq!(
            unknown,
            "undefined4 Handle(void * this, void * param_1, void * param_2)"
        );
        // A template instance's mangled return type is used.
        let (templated, ret) = prototype_signature("foo<i>__Fv_i", &known).unwrap();
        assert_eq!((templated.as_str(), ret.as_str()), ("int foo_int(void)", "int"));
        // Variadic, const members, ctors and dtors.
        let (variadic, _) = prototype_signature("Log__6LoggerCFPCce", &known).unwrap();
        assert_eq!(variadic, "undefined4 Log(void * this, char * param_1, ...)");
        let (ctor, _) = prototype_signature("__ct__8UberBondFv", &known).unwrap();
        assert_eq!(ctor, "undefined4 UberBond(UberBond * this)");
        // A destructor also takes the delete flag the mangling omits.
        let (dtor, _) = prototype_signature("__dt__8UberBondFv", &known).unwrap();
        assert_eq!(dtor, "undefined4 dtor_UberBond(UberBond * this, short param_1)");
        // Long long and back-references.
        let (wide, _) = prototype_signature("f__Fxf", &known).unwrap();
        assert_eq!(wide, "undefined4 f(longlong param_1, float param_2)");
        let (repeated, _) = prototype_signature("g__FP3FooT0", &known).unwrap();
        assert_eq!(repeated, "undefined4 g(void * param_1, void * param_2)");
    }

    #[test]
    fn what_has_no_c_spelling_or_no_parameter_list_gets_no_prototype() {
        let known = known();
        for name in [
            "__vt__8UberBond",                      // data
            "fNumBumperCameras__13RPlayerCamera",   // data member
            "x$localstatic0$Get__3FooFv",           // function-local static
            "printf",                               // not mangled
            "Draw__8UberBondF5Event",               // by-value class: size unknown
            "Call__8UberBondFM3FooFPCvPv_v",        // member-function pointer: two words
            "Update__8UberBondFv",                  // static or instance: the name cannot say
            "Update__8UberBondFPcUi",
        ] {
            assert_eq!(prototype_signature(name, &known), None, "{name}");
        }
        // A language without `undefined4` has no honest return type to declare.
        assert_eq!(prototype_signature("f__Fv", &types(&["void", "int"])), None);
    }

    #[test]
    fn prototype_rows_carry_their_own_provenance() {
        let known = known();
        let rows = prototype_rows(
            [(0x100u64, "Update__8UberBondCFPc"), (0x200, "printf"), (0x300, "__vt__8UberBond")],
            &known,
        );
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].function, Address::ram(0x100));
        assert_eq!(rows[0].provenance.source, PROTOTYPE_SOURCE);
        assert_eq!(rows[0].provenance.kind, FactKind::Inferred);
        assert_eq!(rows[0].calling_convention, None);
    }
}
