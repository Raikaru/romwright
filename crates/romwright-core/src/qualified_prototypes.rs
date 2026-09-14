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
//! symbol to its qualified name before consulting the table. Names that are
//! already qualified (`A::f`, e.g. from a MAP reader) match bare scoped keys
//! the same way.
//!
//! The C signature handed to the decompiler keeps a bare, parser-safe
//! identifier: Ghidra's C parser rejects `::`, and one unresolvable
//! declaration fails the whole decompile. Qualification travels beside the
//! signature — as the `qualified` name to apply at the address, plus the
//! calling convention and receiver type the library path records.

use crate::library_types::{Declaration, Table, representable, signature};
use romwright_model::{Address, FactKind, FactProvenance, PrototypeRow};
use std::collections::HashSet;

/// One MWCC member name: its class scope and its `Class::method` spelling.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberName {
    /// The class scope (`"UberBond"`, or `"ns::Outer"` for nested scopes).
    pub class: String,
    /// The method: `"Update"`, the class name for a ctor, `"~Class"` for a dtor.
    pub method: String,
    /// The qualified name: `"UberBond::Update"`.
    pub qualified: String,
    /// True for `__ct__` (the method is the class name).
    pub ctor: bool,
    /// True for `__dt__` (the method is `~Class`).
    pub dtor: bool,
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

/// Demangles an MWCC member name to its class scope, or refuses it.
///
/// Covered forms: `__ct__<scope><sig>` (ctor), `__dt__<scope><sig>` (dtor),
/// and `<method>__<scope>[C]<sig>` (a plain or const member). Everything
/// after the scope — const marker, signature — is evidence the scope parsed,
/// not grammar this demangles, so it is ignored. Free functions
/// (`foo__Fv`), vtables (`__vt__..`), and non-MWCC names return `None`.
pub fn demangle_mwcc_member(mangled: &str) -> Option<MemberName> {
    // Vtables and RTTI descriptors name a class but are not member
    // functions; resolving them as `Class::__vt` would mistype data.
    if mangled.starts_with("__vt__") || mangled.starts_with("__RTTI__") {
        return None;
    }
    if mangled.starts_with("__ct__") || mangled.starts_with("__dt__") {
        // The proven `__ct__`/`__dt__` membership parse names the class;
        // the member follows from the kind.
        let (class, kind) = crate::rtti::mwcc::member_class(mangled)?;
        let ctor = kind == "ctor";
        let method =
            if ctor { class.to_string() } else { format!("~{class}") };
        return Some(MemberName {
            qualified: format!("{class}::{method}"),
            class: class.to_string(),
            method,
            ctor,
            dtor: !ctor,
        });
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
        if after.first().is_some_and(u8::is_ascii_digit) {
            if let Some((segments, _)) = scope_segments(after) {
                let method = &mangled[..bar];
                if !method.is_empty() {
                    let class = segments.join("::");
                    return Some(MemberName {
                        qualified: format!("{class}::{method}"),
                        class,
                        method: method.to_string(),
                        ctor: false,
                        dtor: false,
                    });
                }
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
    /// The durable row. `calling_convention` is carried; `this_type` has no
    /// `PrototypeRow` field yet (see the P1.8 model report) and is kept on
    /// `self.this_type` until the parent adds it — one line then sets it.
    pub fn to_prototype_row(&self, source: &str) -> PrototypeRow {
        PrototypeRow {
            function: Address::ram(self.address),
            signature: self.signature.clone(),
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
/// This is `declared_for` plus scope: exact names match exactly as before,
/// and additionally an MWCC-mangled member (`Update__8UberBondFv`) or an
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
        // required scope). The exact name always runs first, so free
        // functions keep their existing resolution.
        let mut candidates: Vec<(String, String, Option<String>)> =
            vec![(name.to_string(), name.to_string(), None)];
        if let Some(member) = demangle_mwcc_member(name) {
            candidates.push((member.qualified.clone(), member.qualified.clone(), None));
            candidates.push((member.method.clone(), member.qualified.clone(), Some(member.class)));
        } else if let Some((scope, bare)) = split_qualified(name) {
            candidates.push((bare.to_string(), name.to_string(), Some(scope.to_string())));
        }
        for (key, qualified, required_scope) in &candidates {
            let Some(declaration) = table.functions.get(key.as_str()) else {
                continue;
            };
            if let Some(scope) = required_scope {
                if declaration.scope.as_deref() != Some(scope.as_str()) {
                    continue;
                }
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
        let known = types(&["int", "char", "void"]);
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
        let row = applied[0].to_prototype_row(SOURCE);
        assert_eq!(row.calling_convention.as_deref(), Some("__thiscall"));
        assert_eq!(row.return_type.as_deref(), Some("int"));
        assert_eq!(row.signature, "int Update(char * target)");
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
}
