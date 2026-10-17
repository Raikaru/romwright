//! Qualified-name prototypes (P1.8): namespace/class scope on the prototype path.
//!
//! A library table declares free functions by bare name, but SDK headers
//! declare methods as `Class::method`. Two table shapes are accepted: a key
//! that is already qualified (`"UberBond::Update"`), or a bare key with the
//! declaration's `scope` set (`"Update"` + `scope: "UberBond"`).
//!
//! Symbols arrive mangled. MWCC (CodeWarrior) member names carry their class
//! as a length-prefixed segment — `__ct__8UberBondFv` is
//! `UberBond::UberBond()`, `__dt__8UberBondFv` the dtor, and
//! `Update__8UberBondFv` is `UberBond::Update` — so the lookup demangles the
//! symbol to its qualified name before consulting the table. The full
//! grammar (free functions, operators, templates, `Q` scopes, parameter
//! types) is in [`mwcc_demangle`]; a table key may be the bare name, the
//! qualified name, or the exact demangled spelling that tells overloads
//! apart (`UberBond::Load(char*)`). Names that are already qualified
//! (`A::f`, e.g. from a MAP reader) match bare scoped keys the same way.
//!
//! The C signature handed to the decompiler keeps a bare, parser-safe
//! identifier: Ghidra's C parser rejects `::`, and one unresolvable
//! declaration fails the whole decompile. Qualification travels beside the
//! signature — as the `qualified` name to apply at the address, plus the
//! calling convention and receiver type the library path records.

use crate::library_types::{Declaration, Table, representable, signature, signature_with_receiver};
use romwright_model::{Address, FactKind, FactProvenance, PrototypeRow};
use std::collections::HashSet;

pub mod mangled;
pub mod mwcc_demangle;

/// One MWCC member name: its class scope and its `Class::method` spelling.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberName {
    /// The class scope (`"UberBond"`, `"ns::Outer"`, `"Container<int>"`).
    pub class: String,
    /// The method: `"Update"`, the class name for a ctor, `"~Class"` for a
    /// dtor, `"operator="` for an operator.
    pub method: String,
    /// The qualified name: `"UberBond::Update"`.
    pub qualified: String,
    /// True for `__ct__` (the method is the class name).
    pub ctor: bool,
    /// True for `__dt__` (the method is `~Class`).
    pub dtor: bool,
    /// Rendered parameter types (`["const int&"]`), empty for `()`. Only
    /// meaningful when `has_parameter_list`; empty when the name was
    /// recognised by scope alone.
    pub parameters: Vec<String>,
    /// True when the mangled name carried a full parameter list.
    pub has_parameter_list: bool,
    /// True for a `C` (const) member.
    pub is_const: bool,
    /// Return type, mangled only for template instances.
    pub return_type: Option<String>,
    /// The full demangled text, `dtk demangle`'s spelling
    /// (`"UberBond::Update(char*) const"`); `None` when the name was
    /// recognised by scope alone.
    pub demangled: Option<String>,
}

impl MemberName {
    /// The parameter list as C declarations the decompiler's parser takes
    /// (`["char * param_1", "int param_2"]`), receiver excluded (it travels
    /// as `this_type`, as for a table declaration). References become
    /// pointers; `const`/`volatile` are dropped; a by-value class,
    /// function pointer, array, or any type `known_types` lacks makes the
    /// whole list unrepresentable (`None`), since one unresolvable type
    /// fails the whole decompile. `...` is returned as the final `"..."`.
    pub fn c_parameters(&self, known_types: &HashSet<String>) -> Option<Vec<String>> {
        if !self.has_parameter_list {
            return None;
        }
        let mut declarations = Vec::with_capacity(self.parameters.len());
        for (index, parameter) in self.parameters.iter().enumerate() {
            if parameter == "..." {
                declarations.push("...".to_string());
                continue;
            }
            let c_type = c_type(parameter, known_types, false)?;
            declarations.push(format!("{c_type} param_{}", index + 1));
        }
        Some(declarations)
    }

    /// A C signature built from the mangled parameter types, e.g.
    /// `int Update(char * param_1)`. The mangling carries no return type
    /// (only template instances do), so the caller names it — from a
    /// table, or the convention for the symbol kind. The name is the bare
    /// identifier, never `::`-qualified.
    pub fn c_signature(&self, return_type: &str, known_types: &HashSet<String>) -> Option<String> {
        let parameters = self.c_parameters(known_types)?;
        let list = if parameters.is_empty() { "void".to_string() } else { parameters.join(", ") };
        Some(format!("{return_type} {}({list})", c_identifier(&self.method)))
    }
}

/// How a table declaration's scope must relate to the symbol's.
enum Scope {
    Any,
    /// The declaration must not be scoped (the symbol is a free function).
    Unscoped,
    /// The declaration's scope must equal this.
    Is(String),
}

/// Maps one rendered C++ parameter type to the C spelling the decompiler's
/// parser resolves, or `None` when it has no such spelling.
///
/// `lenient` keeps a parameter's slot when its target type is not one the
/// decompiler has: a pointer or reference to an undeclared class, a function
/// pointer, or a decayed array becomes `void *`. Arity and pointer-ness
/// survive; a by-value class (size unknown), a member-function pointer (two
/// words) and any other shape still return `None`.
pub(crate) fn c_type(rendered: &str, known_types: &HashSet<String>, lenient: bool) -> Option<String> {
    let rendered = rendered.trim();
    if lenient && !rendered.contains("::*") {
        let opaque_pointer = rendered.contains("(*")
            || rendered.contains("(&")
            || rendered.ends_with(']');
        if opaque_pointer && known_types.contains("void") {
            return Some("void *".to_string());
        }
    }
    let mut text = rendered;
    let mut depth = 0usize;
    loop {
        if let Some(rest) = text.strip_suffix(" const").or_else(|| text.strip_suffix(" volatile")) {
            text = rest.trim_end();
        } else if let Some(rest) = text.strip_suffix('*').or_else(|| text.strip_suffix('&')) {
            depth += 1;
            text = rest.trim_end();
        } else {
            break;
        }
    }
    let mut base = text;
    let mut unsigned = false;
    let mut signed = false;
    loop {
        if let Some(rest) = base.strip_prefix("const ").or_else(|| base.strip_prefix("volatile ")) {
            base = rest;
        } else if let Some(rest) = base.strip_prefix("unsigned ") {
            unsigned = true;
            base = rest;
        } else if let Some(rest) = base.strip_prefix("signed ") {
            signed = true;
            base = rest;
        } else {
            break;
        }
    }
    // The names the decompiler's core types use for each C++ builtin.
    let mapped: &[&str] = match (base, unsigned, signed) {
        ("char", false, false) => &["char"],
        ("char", true, _) => &["uchar", "byte", "unsigned char"],
        ("char", false, true) => &["schar", "sbyte", "signed char"],
        ("short", false, _) => &["short"],
        ("short", true, _) => &["ushort", "unsigned short"],
        ("int", false, _) => &["int"],
        ("int", true, _) => &["uint", "unsigned int"],
        ("long", false, _) => &["long"],
        ("long", true, _) => &["ulong", "unsigned long"],
        ("long long", false, _) => &["longlong", "long long"],
        ("long long", true, _) => &["ulonglong", "unsigned long long"],
        ("float", ..) => &["float"],
        ("double", ..) => &["double"],
        ("bool", ..) => &["bool"],
        ("void", ..) if depth > 0 => &["void"],
        _ => &[],
    };
    let base_type = if mapped.is_empty() {
        // A class: only behind a pointer (by-value aggregates have no C
        // spelling here), only when it is a plain declared name.
        let plain = !base.is_empty()
            && base.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if depth == 0 {
            return None;
        }
        if plain && known_types.contains(base) {
            base.to_string()
        } else if lenient && known_types.contains("void") {
            "void".to_string()
        } else {
            return None;
        }
    } else {
        mapped.iter().find(|name| known_types.contains(**name))?.to_string()
    };
    if depth == 0 {
        return Some(base_type);
    }
    Some(format!("{base_type} {}", vec!["*"; depth].join(" ")))
}

/// Parses one length-prefixed scope run (`8UberBond`, `2ns5Class`): the
/// segments plus the bytes consumed. Byte-wise, so a hostile length can only
/// fail, never slice a char boundary.
fn scope_segments(rest: &[u8]) -> Option<(Vec<String>, usize)> {
    let mut segments = Vec::new();
    let mut pos = 0;
    while pos < rest.len() && rest[pos].is_ascii_digit() {
        let digits = pos;
        while pos < rest.len() && rest[pos].is_ascii_digit() {
            pos += 1;
        }
        let len: usize = std::str::from_utf8(&rest[digits..pos]).ok()?.parse().ok()?;
        if len == 0 || pos.checked_add(len)? > rest.len() {
            return None;
        }
        let name = std::str::from_utf8(&rest[pos..pos + len]).ok()?;
        if name.is_empty() {
            return None;
        }
        segments.push(name.to_string());
        pos += len;
    }
    (!segments.is_empty()).then_some((segments, pos))
}

/// Demangles an MWCC symbol to the class member it names, or refuses it.
///
/// The full demangler runs first, so the result carries the parameter
/// types, const marker, operator spelling (`operator=`), and template
/// arguments (`Container<int>::AddObject`). A name it cannot fully parse
/// but whose class scope is well-formed (`Update__8UberBond` followed by
/// decoration it does not know, such as a `.NON_MATCHING` suffix) still
/// resolves by scope, with no parameter list: the scope is the evidence the
/// qualified lookup needs. Free functions (`foo__Fv`), vtables
/// (`__vt__..`), RTTI descriptors, and non-MWCC names return `None`.
pub fn demangle_mwcc_member(mangled: &str) -> Option<MemberName> {
    // Vtables and RTTI descriptors name a class but are not member
    // functions; resolving them as `Class::__vt` would mistype data.
    if mangled.starts_with("__vt__") || mangled.starts_with("__RTTI__") {
        return None;
    }
    match mwcc_demangle::demangle(mangled) {
        Some(full) => member_from_demangled(full),
        None => member_from_scope(mangled),
    }
}

fn member_from_demangled(full: mwcc_demangle::Demangled) -> Option<MemberName> {
    use mwcc_demangle::Kind;
    if full.scope.is_empty() || !matches!(full.kind, Kind::Function | Kind::Data) {
        return None;
    }
    Some(MemberName {
        qualified: format!("{}::{}", full.scope, full.name),
        class: full.scope,
        method: full.name,
        ctor: full.is_constructor,
        dtor: full.is_destructor,
        parameters: full.parameters,
        has_parameter_list: full.has_parameter_list,
        is_const: full.is_const,
        return_type: full.return_type,
        demangled: Some(full.text),
    })
}

/// The scope-only parse for names the full demangler refuses.
fn member_from_scope(mangled: &str) -> Option<MemberName> {
    let scoped = |class: String, method: String, ctor: bool, dtor: bool| MemberName {
        qualified: format!("{class}::{method}"),
        class,
        method,
        ctor,
        dtor,
        parameters: Vec::new(),
        has_parameter_list: false,
        is_const: false,
        return_type: None,
        demangled: None,
    };
    if mangled.starts_with("__ct__") || mangled.starts_with("__dt__") {
        // The proven `__ct__`/`__dt__` membership parse names the class;
        // the member follows from the kind.
        let (class, kind) = crate::rtti::mwcc::member_class(mangled)?;
        let ctor = kind == "ctor";
        let method = if ctor { class.to_string() } else { format!("~{class}") };
        return Some(scoped(class.to_string(), method, ctor, !ctor));
    }
    // A general member is `method__scope`: scan the `__` splits and take the
    // first whose remainder opens a length-prefixed scope, so a method that
    // itself contains `__` still splits at the scope boundary.
    let bytes = mangled.as_bytes();
    let mut split = 0;
    while split < bytes.len() {
        let Some(offset) = bytes[split..].windows(2).position(|w| w == b"__") else {
            break;
        };
        let bar = split + offset;
        let after = &bytes[bar + 2..];
        if after.first().is_some_and(u8::is_ascii_digit)
            && let Some((segments, _)) = scope_segments(after) {
                let method = &mangled[..bar];
                if !method.is_empty() {
                    return Some(scoped(segments.join("::"), method.to_string(), false, false));
                }
            }
        split = bar + 2;
    }
    None
}

/// Splits an already-qualified name (`A::f`, `a::B::f`) into scope + bare.
fn split_qualified(name: &str) -> Option<(&str, &str)> {
    let split = name.rfind("::")?;
    let (scope, bare) = (&name[..split], &name[split + 2..]);
    (!scope.is_empty() && !bare.is_empty()).then_some((scope, bare))
}

/// A C identifier for the signature's name position: the decompiler parses
/// this text, so `~Dtor` (and anything else outside `[0-9A-Za-z_]`) is
/// transported as `_`. Valid identifiers pass through unchanged.
fn c_identifier(name: &str) -> String {
    let mut text: String =
        name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' }).collect();
    if text.is_empty() {
        text.push_str("member");
    } else if text.as_bytes()[0].is_ascii_digit() {
        text.insert(0, '_');
    }
    text
}

/// One library application with its qualification: the `Class::method` name
/// to apply at the address, the C signature (bare identifier only), and the
/// calling convention + receiver type the library path records.
#[derive(Debug)]
pub struct LibraryPrototype<'a> {
    pub address: u64,
    /// `Class::method`, or the bare name when nothing scopes it.
    pub qualified: String,
    /// C declaration to hand the decompiler; never contains `::`.
    pub signature: String,
    pub declaration: &'a Declaration,
    /// The declaration's convention model, if it states one.
    pub calling_convention: Option<String>,
    pub return_type: String,
    /// Explicit `this_type`, else `{scope} *` when the name is scoped.
    pub this_type: Option<String>,
}

impl<'a> LibraryPrototype<'a> {
    /// The durable row. `PrototypeRow` has no receiver field, so a member's
    /// `this` rides in the signature as its first parameter: without it the
    /// decompiler would type every declared argument one register early. The
    /// receiver is the declaration's class when the language's parser has
    /// that type, else `void *`. `calling_convention` is carried as stated.
    pub fn to_prototype_row(&self, source: &str, known_types: &HashSet<String>) -> PrototypeRow {
        let receiver = self.this_type.as_deref().and_then(|this_type| {
            let class = this_type.strip_suffix('*').unwrap_or(this_type).trim();
            if known_types.contains(class) {
                Some(format!("{class} *"))
            } else if known_types.contains("void") {
                Some("void *".to_string())
            } else {
                None
            }
        });
        let signature = match receiver {
            Some(receiver) => signature_with_receiver(
                &c_identifier(Declaration::bare_name(&self.qualified)),
                self.declaration,
                Some(&receiver),
            ),
            None => self.signature.clone(),
        };
        PrototypeRow {
            function: Address::ram(self.address),
            signature,
            calling_convention: self.calling_convention.clone(),
            return_type: Some(self.return_type.clone()),
            provenance: FactProvenance {
                kind: FactKind::Inferred,
                source: source.into(),
                confidence: None,
            },
        }
    }
}

/// The declarations that apply to the names an image imports, with
/// namespace/class qualification.
///
/// Exact names match first, so a C library function resolves as it always
/// did; additionally an MWCC-mangled member (`Update__8UberBondFv`) or an
/// already-qualified name (`UberBond::Update`) resolves against a qualified
/// key or a bare key whose declaration scope agrees. A bare key with no (or
/// a disagreeing) scope never matches a scoped symbol, so a member never
/// collides with a same-named free function. Unrepresentable declarations
/// stay untyped, exactly as in the unqualified path.
pub fn declared_qualified_for<'a>(
    table: &'a Table,
    names: impl IntoIterator<Item = (u64, &'a str)>,
    known_types: &HashSet<String>,
) -> Vec<LibraryPrototype<'a>> {
    let mut applied = Vec::new();
    for (address, name) in names {
        // Candidates in priority order: (table key, qualified name,
        // scope requirement). The exact name always runs first, so free
        // functions keep their existing resolution.
        let mut candidates: Vec<(String, String, Scope)> =
            vec![(name.to_string(), name.to_string(), Scope::Any)];
        if let Some(full) = mwcc_demangle::demangle(name) {
            // The demangled spelling, parameters included, is the one key
            // that tells overloads apart (`A::f(int)` vs `A::f(char*)`).
            let spelled = full.text.clone();
            if full.scope.is_empty() {
                candidates.push((spelled, full.name.clone(), Scope::Unscoped));
                candidates.push((full.name.clone(), full.name, Scope::Unscoped));
            } else if matches!(full.kind, mwcc_demangle::Kind::Function | mwcc_demangle::Kind::Data)
            {
                let qualified = format!("{}::{}", full.scope, full.name);
                candidates.push((spelled, qualified.clone(), Scope::Any));
                candidates.push((qualified.clone(), qualified.clone(), Scope::Any));
                candidates.push((full.name, qualified, Scope::Is(full.scope)));
            }
        } else if let Some(member) = demangle_mwcc_member(name) {
            candidates.push((member.qualified.clone(), member.qualified.clone(), Scope::Any));
            candidates.push((member.method.clone(), member.qualified.clone(), Scope::Is(member.class)));
        } else if let Some((scope, bare)) = split_qualified(name) {
            candidates.push((bare.to_string(), name.to_string(), Scope::Is(scope.to_string())));
        }
        for (key, qualified, required_scope) in &candidates {
            let Some(declaration) = table.functions.get(key.as_str()) else {
                continue;
            };
            let declared = declaration.scope.as_deref().filter(|scope| !scope.is_empty());
            let scope_agrees = match required_scope {
                Scope::Any => true,
                Scope::Unscoped => declared.is_none(),
                Scope::Is(scope) => declared == Some(scope.as_str()),
            };
            if !scope_agrees {
                continue;
            }
            if !representable(declaration, known_types) {
                continue;
            }
            // The table's own scope qualifies bare hits (`Update` + scope
            // `UberBond` is `UberBond::Update`); mangled and pre-qualified
            // hits already carry theirs.
            let resolved = declaration.qualified_name(qualified);
            let c_name = c_identifier(Declaration::bare_name(&resolved));
            applied.push(LibraryPrototype {
                address,
                signature: signature(&c_name, declaration),
                calling_convention: declaration.calling_convention.clone(),
                return_type: declaration.return_type.clone(),
                this_type: declaration.this_type_for(&resolved),
                qualified: resolved,
                declaration,
            });
            break;
        }
    }
    applied
}

/// Provenance for facts this pass writes.
pub const SOURCE: &str = crate::library_types::SOURCE;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library_types::Parameter;
    use std::collections::HashMap;

    fn types(names: &[&str]) -> HashSet<String> {
        names.iter().map(|name| (*name).to_string()).collect()
    }

    fn declaration(
        return_type: &str,
        parameters: Vec<(&str, &str)>,
        scope: Option<&str>,
        calling_convention: Option<&str>,
    ) -> Declaration {
        Declaration {
            return_type: return_type.into(),
            varargs: false,
            parameters: parameters
                .into_iter()
                .map(|(name, data_type)| Parameter {
                    name: name.into(),
                    data_type: data_type.into(),
                })
                .collect(),
            scope: scope.map(str::to_string),
            calling_convention: calling_convention.map(str::to_string),
            this_type: None,
        }
    }

    fn table(entries: Vec<(String, Declaration)>) -> Table {
        Table {
            archive: "test".into(),
            archive_sha256: "test".into(),
            functions: entries.into_iter().collect::<HashMap<_, _>>(),
        }
    }

    #[test]
    fn mwcc_members_demangle_to_qualified_names() {
        let ctor = demangle_mwcc_member("__ct__8UberBondFv").unwrap();
        assert_eq!(ctor.class, "UberBond");
        assert_eq!(ctor.method, "UberBond");
        assert_eq!(ctor.qualified, "UberBond::UberBond");
        assert!(ctor.ctor && !ctor.dtor);
        let dtor = demangle_mwcc_member("__dt__8UberBondFv").unwrap();
        assert_eq!(dtor.qualified, "UberBond::~UberBond");
        assert!(dtor.dtor && !dtor.ctor);
        let method = demangle_mwcc_member("Update__8UberBondFv").unwrap();
        assert_eq!(
            (method.class.as_str(), method.method.as_str(), method.qualified.as_str()),
            ("UberBond", "Update", "UberBond::Update")
        );
        // A const member and a `__`-containing method still scope correctly.
        assert_eq!(
            demangle_mwcc_member("Render__8UberBondCFv").unwrap().qualified,
            "UberBond::Render"
        );
        assert_eq!(
            demangle_mwcc_member("my__init__8UberBondFv").unwrap().qualified,
            "UberBond::my__init"
        );
        // Free functions, vtables, and garbage carry no member scope.
        assert_eq!(demangle_mwcc_member("printf"), None);
        assert_eq!(demangle_mwcc_member("foo__Fv"), None);
        assert_eq!(demangle_mwcc_member("__vt__8UberBond"), None);
        assert_eq!(demangle_mwcc_member(""), None);
        assert_eq!(demangle_mwcc_member("__ct__"), None);
        // A hostile length fails instead of slicing past the name.
        assert_eq!(demangle_mwcc_member("__ct__9ShortFv"), None);
        assert_eq!(demangle_mwcc_member("Update__9ShortFv"), None);
    }

    #[test]
    fn a_class_scoped_symbol_resolves_with_its_qualified_name_and_this_type() {
        let table = table(vec![
            (
                "UberBond::Update".into(),
                declaration(
                    "int",
                    vec![("target", "char *")],
                    None,
                    Some("__thiscall"),
                ),
            ),
            (
                "UberBond::UberBond".into(),
                declaration("void", vec![], None, Some("__thiscall")),
            ),
        ]);
        let known = types(&["int", "char", "void", "UberBond"]);
        let applied = declared_qualified_for(
            &table,
            [(0x1000u64, "Update__8UberBondFv"), (0x1040u64, "__ct__8UberBondFv")],
            &known,
        );
        assert_eq!(applied.len(), 2);
        // The C signature keeps a bare parser-safe identifier; the
        // qualification, convention, and receiver travel beside it.
        assert_eq!(applied[0].qualified, "UberBond::Update");
        assert_eq!(applied[0].signature, "int Update(char * target)");
        assert_eq!(applied[0].calling_convention.as_deref(), Some("__thiscall"));
        assert_eq!(applied[0].this_type.as_deref(), Some("UberBond *"));
        assert_eq!(applied[1].qualified, "UberBond::UberBond");
        assert_eq!(applied[1].this_type.as_deref(), Some("UberBond *"));
        // The durable row records the convention the declaration states.
        let row = applied[0].to_prototype_row(SOURCE, &known);
        assert_eq!(row.calling_convention.as_deref(), Some("__thiscall"));
        assert_eq!(row.return_type.as_deref(), Some("int"));
        // The receiver is the first parameter: the row has no field for it.
        assert_eq!(row.signature, "int Update(UberBond * this, char * target)");
    }

    #[test]
    fn the_row_receiver_degrades_to_void_pointer_when_the_class_is_not_a_known_type() {
        let table = table(vec![(
            "UberBond::Update".into(),
            declaration("int", vec![("target", "char *")], None, None),
        )]);
        let known = types(&["int", "char", "void"]);
        let applied = declared_qualified_for(&table, [(0x1000u64, "Update__8UberBondFv")], &known);
        // The unqualified signature is untouched; the row adds the receiver.
        assert_eq!(applied[0].signature, "int Update(char * target)");
        assert_eq!(
            applied[0].to_prototype_row(SOURCE, &known).signature,
            "int Update(void * this, char * target)"
        );
        // A free function has no receiver.
        let free = self::table(vec![(
            "Free".into(),
            declaration("int", vec![("target", "char *")], None, None),
        )]);
        let applied = declared_qualified_for(&free, [(0x2000u64, "Free")], &known);
        assert_eq!(
            applied[0].to_prototype_row(SOURCE, &known).signature,
            "int Free(char * target)"
        );
    }

    #[test]
    fn a_scope_field_qualifies_bare_keys_without_inventing_receivers() {
        let scoped = table(vec![(
            "Update".into(),
            declaration("int", vec![("target", "char *")], Some("UberBond"), None),
        )]);
        let known = types(&["int", "char"]);
        // Both the mangled member and the already-qualified name resolve;
        // the receiver derives from the scope, the convention stays absent
        // because the declaration states none.
        for name in ["Update__8UberBondFv", "UberBond::Update", "Update"] {
            let applied = declared_qualified_for(&scoped, [(0x1000u64, name)], &known);
            assert_eq!(applied.len(), 1, "{name} should resolve");
            assert_eq!(applied[0].qualified, "UberBond::Update");
            assert_eq!(applied[0].this_type.as_deref(), Some("UberBond *"));
            assert_eq!(applied[0].calling_convention, None);
        }
        // A member never collides with a same-named free function: a bare
        // key with no scope does not match a scoped symbol.
        let free = table(vec![("Update".into(), declaration("int", vec![], None, None))]);
        assert!(
            declared_qualified_for(&free, [(0x1000u64, "Update__8UberBondFv")], &known).is_empty()
        );
        // ...while the same bare symbol still resolves as a free function.
        assert_eq!(
            declared_qualified_for(&free, [(0x1000u64, "Update")], &known).len(),
            1
        );
    }

    #[test]
    fn namespaces_qualify_and_unrepresentable_methods_stay_untyped() {
        let table = table(vec![
            (
                "Update".into(),
                declaration("int", vec![("w", "Widget *")], Some("app::Widget"), None),
            ),
            (
                "Load".into(),
                declaration("int", vec![("stream", "FILE *")], Some("app::Widget"), None),
            ),
        ]);
        let known = types(&["int", "Widget"]);
        let applied =
            declared_qualified_for(&table, [(0x1000u64, "app::Widget::Update")], &known);
        assert_eq!(applied.len(), 1);
        assert_eq!(applied[0].qualified, "app::Widget::Update");
        assert_eq!(applied[0].this_type.as_deref(), Some("app::Widget *"));
        // `FILE *` is not a type the decompiler has: applying it would fail
        // the decompile, so the method stays untyped like free functions do.
        assert!(
            declared_qualified_for(&table, [(0x2000u64, "app::Widget::Load")], &known).is_empty()
        );
    }

    #[test]
    fn dtors_keep_a_parser_safe_signature_beside_the_qualified_name() {
        let table = table(vec![(
            "UberBond::~UberBond".into(),
            declaration("void", vec![], None, Some("__thiscall")),
        )]);
        let known = types(&["void"]);
        let applied =
            declared_qualified_for(&table, [(0x1040u64, "__dt__8UberBondFv")], &known);
        assert_eq!(applied.len(), 1);
        assert_eq!(applied[0].qualified, "UberBond::~UberBond");
        assert_eq!(applied[0].this_type.as_deref(), Some("UberBond *"));
        assert!(!applied[0].signature.contains("::"));
        assert!(!applied[0].signature.contains('~'));
    }
    #[test]
    fn members_carry_parameters_constness_operators_and_templates() {
        let update = demangle_mwcc_member("Update__8UberBondFPci").unwrap();
        assert_eq!(update.qualified, "UberBond::Update");
        assert_eq!(update.parameters, ["char*", "int"]);
        assert!(update.has_parameter_list && !update.is_const);
        assert_eq!(update.demangled.as_deref(), Some("UberBond::Update(char*, int)"));

        let constant = demangle_mwcc_member("GetName__10ASmackableCFv").unwrap();
        assert!(constant.is_const && constant.parameters.is_empty());

        // Operator tokens become `operator=`, not the `__as` fragment.
        let assign = demangle_mwcc_member("__as__3strFPCc").unwrap();
        assert_eq!(
            (assign.class.as_str(), assign.method.as_str(), assign.qualified.as_str()),
            ("str", "operator=", "str::operator=")
        );
        assert_eq!(assign.parameters, ["const char*"]);

        // Template arguments are decoded, in the scope and the ctor name.
        let add = demangle_mwcc_member("AddObject__12Container<i>FRCi").unwrap();
        assert_eq!(add.class, "Container<int>");
        assert_eq!(add.qualified, "Container<int>::AddObject");
        assert_eq!(add.parameters, ["const int&"]);
        let ctor = demangle_mwcc_member("__ct__19Container<P6Entity>Fv").unwrap();
        assert_eq!(ctor.qualified, "Container<Entity*>::Container");
        assert!(ctor.ctor);

        // Q-qualified nested scopes.
        let nested = demangle_mwcc_member("Decode__Q23SND12CEAXABLKDecfFPPfi").unwrap();
        assert_eq!(nested.class, "SND::CEAXABLKDecf");
        assert_eq!(nested.qualified, "SND::CEAXABLKDecf::Decode");
        assert_eq!(nested.parameters, ["float**", "int"]);

        // Data members and thunks.
        let data = demangle_mwcc_member("fNumBumperCameras__13RPlayerCamera").unwrap();
        assert_eq!(data.qualified, "RPlayerCamera::fNumBumperCameras");
        assert!(!data.has_parameter_list);
        let thunk = demangle_mwcc_member("@64@Render__9ActWeaponFv").unwrap();
        assert_eq!(thunk.qualified, "ActWeapon::@64@Render");

        // Not members: free functions, vtables, RTTI, function-local statics.
        for name in [
            "DrawFontChar__Fiiii",
            "__vt__10BackWheels",
            "__RTTI__7JKRAram",
            "fgRefCounter$localstatic0$Get__14URefCounter<c>Fv",
        ] {
            assert_eq!(demangle_mwcc_member(name), None, "{name}");
        }
    }

    #[test]
    fn a_decorated_name_still_resolves_by_scope() {
        // The full demangler refuses trailing decoration; the scope parse
        // keeps the pre-existing behaviour for it.
        let member = demangle_mwcc_member("Update__8UberBondFv.NON_MATCHING").unwrap();
        assert_eq!(member.qualified, "UberBond::Update");
        assert!(!member.has_parameter_list && member.demangled.is_none());
    }

    #[test]
    fn mangled_parameters_become_a_c_signature() {
        let known = types(&["int", "uint", "char", "float", "void", "bool", "Event"]);
        let member = demangle_mwcc_member("Update__8UberBondFPcUiRC5EventPPf").unwrap();
        // `float**` needs `float` (known); `Event` behind a reference is a pointer.
        assert_eq!(
            member.c_parameters(&known).unwrap(),
            ["char * param_1", "uint param_2", "Event * param_3", "float * * param_4"]
        );
        assert_eq!(
            member.c_signature("int", &known).unwrap(),
            "int Update(char * param_1, uint param_2, Event * param_3, float * * param_4)"
        );
        let none = demangle_mwcc_member("Reset__8UberBondFv").unwrap();
        assert_eq!(none.c_signature("void", &known).unwrap(), "void Reset(void)");
        // By-value class, unknown base type, function pointer: no C spelling.
        for name in [
            "A__8UberBondF5Event",
            "B__8UberBondFP4Nope",
            "C__8UberBondFPFi_v",
            "D__8UberBondFUl",
        ] {
            let member = demangle_mwcc_member(name).unwrap();
            assert_eq!(member.c_parameters(&known), None, "{name}");
        }
        // A symbol recognised by scope alone has no parameter list to use.
        let decorated = demangle_mwcc_member("Update__8UberBondFv.NON_MATCHING").unwrap();
        assert_eq!(decorated.c_parameters(&known), None);
        // Variadics survive as `...`.
        let variadic = demangle_mwcc_member("Log__6LoggerFPCce").unwrap();
        assert_eq!(variadic.c_parameters(&known).unwrap(), ["char * param_1", "..."]);
    }

    #[test]
    fn free_functions_and_overloads_resolve_through_the_demangled_name() {
        let known = types(&["int", "char", "void"]);
        let table = table(vec![
            ("DrawFontChar".into(), declaration("void", vec![("x", "int")], None, None)),
            // Overload keys use the demangled spelling, parameters included.
            (
                "UberBond::Load(char*)".into(),
                declaration("int", vec![("path", "char *")], None, Some("__thiscall")),
            ),
            (
                "UberBond::Load(int)".into(),
                declaration("int", vec![("slot", "int")], None, Some("__thiscall")),
            ),
            // A scoped bare key must not capture a free function.
            ("Update".into(), declaration("int", vec![], Some("UberBond"), None)),
        ]);
        let applied = declared_qualified_for(
            &table,
            [
                (0x10u64, "DrawFontChar__Fiiii"),
                (0x20, "Load__8UberBondFPc"),
                (0x30, "Load__8UberBondFi"),
                (0x40, "Update__Fv"),
                (0x50, "Update__8UberBondFv"),
            ],
            &known,
        );
        let by_address = |address: u64| applied.iter().find(|p| p.address == address);
        assert_eq!(by_address(0x10).unwrap().qualified, "DrawFontChar");
        assert_eq!(by_address(0x10).unwrap().this_type, None);
        assert_eq!(by_address(0x20).unwrap().signature, "int Load(char * path)");
        assert_eq!(by_address(0x30).unwrap().signature, "int Load(int slot)");
        assert!(by_address(0x40).is_none());
        assert_eq!(by_address(0x50).unwrap().qualified, "UberBond::Update");
    }

    #[test]
    fn template_and_nested_scopes_resolve_against_table_keys() {
        let known = types(&["int", "void"]);
        let table = table(vec![
            (
                "Container<int>::AddObject".into(),
                declaration("void", vec![("item", "int")], None, Some("__thiscall")),
            ),
            (
                "SND::CEAXABLKDecf::Decode".into(),
                declaration("int", vec![], None, Some("__thiscall")),
            ),
            ("operator=".into(), declaration("void", vec![], Some("str"), None)),
        ]);
        let applied = declared_qualified_for(
            &table,
            [
                (0x10u64, "AddObject__12Container<i>FRCi"),
                (0x20, "Decode__Q23SND12CEAXABLKDecfFPPfi"),
                (0x30, "__as__3strFPCc"),
            ],
            &known,
        );
        assert_eq!(applied.len(), 3);
        assert_eq!(applied[0].qualified, "Container<int>::AddObject");
        assert_eq!(applied[1].qualified, "SND::CEAXABLKDecf::Decode");
        assert_eq!(applied[2].qualified, "str::operator=");
        // `operator=` is not a C identifier: the signature name is bare.
        assert_eq!(applied[2].signature, "void operator_(void)");
    }
}
