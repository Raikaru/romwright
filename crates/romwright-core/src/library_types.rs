//! Declarations the pinned C library type archive holds, applied to imports.
//!
//! The archive itself is a Ghidra packed database; a parser for it in the
//! JVM-free path would be a lot of format for one table of names, so the table
//! is exported once by `scripts/gen_library_prototypes.py` and committed with
//! the archive's hash. This module reads that table and types the imports the
//! image names, and nothing else.
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::path::Path;

pub mod helpers;

/// The provenance every fact this pass writes carries.
pub const SOURCE: &str = "native-import:type-archive";

/// Base type names the decompiler always has, from its own core type table
/// (`native/specs/coretypes.xml`). A declaration naming anything else is left
/// alone: the C parser the worker feeds would reject it, and a rejected
/// signature fails the decompile rather than improving it.

/// One declaration: what it returns, what it takes, whether it is variadic.
///
/// `scope` names the namespace or class that owns the function, so a table
/// built from SDK headers can declare `Update` once with `scope: "UberBond"`
/// (or key it directly as `"UberBond::Update"`). `calling_convention` is a
/// decompiler prototype-model name (e.g. `__thiscall`) the declaration
/// requires; it is recorded, never invented, because a model the language
/// does not declare makes the worker skip the fact. `this_type` is the C
/// type of the receiver; when scoped and unset it derives as `{scope} *`.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct Declaration {
    pub return_type: String,
    #[serde(default)]
    pub varargs: bool,
    #[serde(default)]
    pub parameters: Vec<Parameter>,
    /// Namespace/class scope, e.g. `"UberBond"` or `"app::Widget"`.
    #[serde(default)]
    pub scope: Option<String>,
    /// Decompiler calling-convention model, e.g. `"__thiscall"`.
    #[serde(default)]
    pub calling_convention: Option<String>,
    /// C type of `this`; derived as `"{scope} *"` when scoped and unset.
    #[serde(default)]
    pub this_type: Option<String>,
}

impl Declaration {
    /// The `Class::method` name for a table `key`: already-qualified keys
    /// pass through, bare keys gain the declaration's scope, unscoped keys
    /// are unchanged.
    pub fn qualified_name(&self, key: &str) -> String {
        if key.contains("::") {
            return key.to_string();
        }
        match &self.scope {
            Some(scope) if !scope.is_empty() => format!("{scope}::{key}"),
            _ => key.to_string(),
        }
    }

    /// The bare function name: whatever follows the last `::`, or the whole
    /// key when unqualified.
    pub fn bare_name(key: &str) -> &str {
        key.rsplit("::").next().unwrap_or(key)
    }

    /// The receiver type for `qualified` (a `qualified_name` result): the
    /// explicit `this_type`, else `{scope} *` when the name is scoped.
    pub fn this_type_for(&self, qualified: &str) -> Option<String> {
        if let Some(explicit) = &self.this_type {
            if !explicit.is_empty() {
                return Some(explicit.clone());
            }
        }
        qualified
            .rfind("::")
            .map(|split| format!("{} *", &qualified[..split]))
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct Parameter {
    pub name: String,
    #[serde(rename = "type")]
    pub data_type: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct Table {
    pub archive: String,
    pub archive_sha256: String,
    pub functions: HashMap<String, Declaration>,
}

/// Reads the committed table. A missing table is not an error: the pass simply
/// has nothing to say, exactly as it does for a name the archive omits.
pub fn load(path: &Path) -> Option<Table> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

/// The type names one language's own core-type document declares: exactly
/// what the decompiler's C parser can resolve. This is not a constant: a
/// 32-bit language's `coretypes.xml` names `longlong` and no `long`, so
/// applying `long strtol(...)` there fails the parse -- and one failed parse
/// fails the whole decompile, not just that prototype.
pub fn core_type_names(specs: &Path) -> Option<std::collections::HashSet<String>> {
    let text = std::fs::read_to_string(specs.join("coretypes.xml")).ok()?;
    let mut names = std::collections::HashSet::new();
    let mut rest = text.as_str();
    while let Some(position) = rest.find("<type ") {
        let tag = &rest[position..];
        rest = &tag[1..];
        let Some(end) = tag.find('>') else { break };
        let header = &tag[..end];
        let Some(start) = header.find("name=\"") else { continue };
        let value = &header[start + 6..];
        if let Some(close) = value.find('"') {
            names.insert(value[..close].to_string());
        }
    }
    (!names.is_empty()).then_some(names)
}

/// One C base type the language declares a width for, and the metatype the
/// decompiler needs to build it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BaseType {
    pub size: u32,
    /// `int`, `uint` or `float`, as `TypeFactory::decodeType` reads it.
    pub metatype: &'static str,
}

/// The C base types one language's *compiler spec* declares a width for.
///
/// A 32-bit language's `coretypes.xml` names `longlong` and no `long`, but its
/// `cspec.xml` says `<long_size value="4"/>` -- which is exactly how stock
/// applies `long strtol(...)` on a 32-bit target: its Java side resolves the
/// declaration against the program's data organization and hands the
/// decompiler a type. The decompiler asks the client for any type name it does
/// not hold (`TypeFactoryGhidra::findById`, `typegrp_ghidra.cc`:20-36), so
/// this table is both the filter for what may be applied and the answer to
/// that question (m4-025).
pub fn language_base_types(specs: &Path) -> BTreeMap<String, BaseType> {
    let Ok(cspec) = std::fs::read_to_string(specs.join("cspec.xml")) else {
        return BTreeMap::new();
    };
    // A compiler spec may omit the whole block -- PowerPC's does -- and then
    // Ghidra's own defaults apply: `char` 1, `short` 2, `int` 4, `long` 4,
    // `long long` 8, `float` 4, `double` 8, `long double` 8
    // (`DataOrganizationImpl`:43-53, and `getDefaultOrganization` adjusts only
    // the pointer size from the language). Guessing anything else would make
    // `long` a different width from the one stock applies.
    let size = |tag: &str, default: u32| -> u32 {
        let marker = format!("<{tag} value=\"");
        let Some(position) = cspec.find(&marker) else {
            return default;
        };
        let start = position + marker.len();
        cspec[start..]
            .find('"')
            .and_then(|end| cspec[start..start + end].parse().ok())
            .unwrap_or(default)
    };
    let mut types = BTreeMap::new();
    let mut integer = |signed: &str, unsigned: &str, size: u32| {
        types.insert(signed.to_string(), BaseType { size, metatype: "int" });
        types.insert(unsigned.to_string(), BaseType { size, metatype: "uint" });
    };
    integer("short", "ushort", size("short_size", 2));
    integer("int", "uint", size("integer_size", 4));
    integer("long", "ulong", size("long_size", 4));
    integer("longlong", "ulonglong", size("long_long_size", 8));
    for (name, tag, default) in [
        ("float", "float_size", 4),
        ("double", "double_size", 8),
        ("longdouble", "long_double_size", 8),
    ] {
        types.insert(
            name.to_string(),
            BaseType { size: size(tag, default), metatype: "float" },
        );
    }
    types
}

/// Whether every type in a declaration is one the decompiler already has, in
/// a shape its C parser accepts. Pointer depth is not a limit -- the parser's
/// `pointer` rule is recursive and stock applies `char **__endptr` -- but the
/// base type has to be one this language declares.
pub(crate) fn representable(declaration: &Declaration, known_types: &std::collections::HashSet<String>) -> bool {
    // `char * *` (`grammar.y`'s `pointer` rule is recursive), and stock applies
    // exactly that declaration to `strtol`. What has to be known is the base
    // type the pointers end at.
    let known = |text: &str| {
        let base = text.trim_end_matches(['*', ' ']).trim();
        known_types.contains(base)
    };
    known(&declaration.return_type)
        && declaration
            .parameters
            .iter()
            .all(|parameter| known(&parameter.data_type))
}

/// The C declaration to hand the decompiler, e.g. `int printf(char * p1, ...)`.
pub fn signature(name: &str, declaration: &Declaration) -> String {
    signature_with_receiver(name, declaration, None)
}

/// [`signature`] with a leading `this` parameter of type `receiver`
/// (`UberBond *`): a member's receiver is its first argument, and a
/// prototype without it types every other argument one slot early.
pub fn signature_with_receiver(
    name: &str,
    declaration: &Declaration,
    receiver: Option<&str>,
) -> String {
    let mut text = format!("{} {name}(", declaration.return_type);
    let mut parts: Vec<String> = receiver
        .map(|receiver| format!("{receiver} this"))
        .into_iter()
        .collect();
    parts.extend(declaration
        .parameters
        .iter()
        .enumerate()
        .map(|(index, parameter)| {
            // A declared parameter name may be a reserved word or empty; the
            // position is what the prototype needs.
            let identifier = if parameter.name.is_empty() {
                format!("param_{}", index + 1)
            } else {
                parameter.name.replace(|c: char| !c.is_alphanumeric() && c != '_', "_")
            };
            format!("{} {identifier}", parameter.data_type)
        }));
    if declaration.varargs {
        parts.push("...".into());
    }
    if parts.is_empty() {
        text.push_str("void");
    } else {
        text.push_str(&parts.join(", "));
    }
    text.push(')');
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qualified_prototypes::declared_qualified_for;

    fn printf() -> Declaration {
        Declaration {
            return_type: "int".into(),
            varargs: true,
            parameters: vec![Parameter {
                name: "__format".into(),
                data_type: "char *".into(),
            }],
            scope: None,
            calling_convention: None,
            this_type: None,
        }
    }

    #[test]
    fn a_variadic_declaration_composes_the_c_the_parser_needs() {
        assert_eq!(
            signature("printf", &printf()),
            "int printf(char * __format, ...)"
        );
    }

    #[test]
    fn a_declaration_with_no_parameters_is_void_not_empty() {
        let declaration = Declaration {
            return_type: "int".into(),
            varargs: false,
            parameters: Vec::new(),
            scope: None,
            calling_convention: None,
            this_type: None,
        };
        assert_eq!(signature("getpid", &declaration), "int getpid(void)");
    }

    fn types(names: &[&str]) -> std::collections::HashSet<String> {
        names.iter().map(|name| (*name).to_string()).collect()
    }

    #[test]
    fn base_type_widths_come_from_the_spec_and_fall_back_to_ghidra_defaults() {
        let directory = std::env::temp_dir().join(format!(
            "romwright-cspec-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(
            directory.join("cspec.xml"),
            "<compiler_spec><data_organization><long_size value=\"8\"/>\
             <long_double_size value=\"16\"/></data_organization></compiler_spec>",
        )
        .unwrap();
        let declared = language_base_types(&directory);
        assert_eq!(declared["long"], BaseType { size: 8, metatype: "int" });
        assert_eq!(declared["ulong"], BaseType { size: 8, metatype: "uint" });
        assert_eq!(declared["longdouble"], BaseType { size: 16, metatype: "float" });
        // Tags the spec omits take Ghidra's defaults, not a guess.
        assert_eq!(declared["int"], BaseType { size: 4, metatype: "int" });
        assert_eq!(declared["longlong"], BaseType { size: 8, metatype: "int" });

        // A spec with no data organization at all -- PowerPC's shape.
        std::fs::write(directory.join("cspec.xml"), "<compiler_spec/>").unwrap();
        let defaults = language_base_types(&directory);
        assert_eq!(defaults["long"], BaseType { size: 4, metatype: "int" });
        assert_eq!(defaults["short"], BaseType { size: 2, metatype: "int" });
        assert_eq!(defaults["double"], BaseType { size: 8, metatype: "float" });

        // No spec is no answer, and no panic.
        std::fs::remove_file(directory.join("cspec.xml")).unwrap();
        assert!(language_base_types(&directory).is_empty());
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn a_declaration_is_applied_only_where_the_language_has_its_types() {
        // Pointer depth is not the question -- the parser's `pointer` rule is
        // recursive -- but the base type is: a 32-bit language's coretypes
        // name `longlong` and no `long`, and `long strtol(...)` there reaches
        // the parser as a syntax error that fails the whole decompile.
        let declaration = Declaration {
            return_type: "long".into(),
            varargs: false,
            parameters: vec![Parameter {
                name: "endptr".into(),
                data_type: "char * *".into(),
            }],
            scope: None,
            calling_convention: None,
            this_type: None,
        };
        let table = Table {
            archive: "a".into(),
            archive_sha256: "b".into(),
            functions: HashMap::from([("strtol".into(), declaration)]),
        };
        let wide = types(&["long", "char", "int"]);
        let narrow = types(&["longlong", "char", "int"]);
        assert_eq!(
            declared_qualified_for(&table, [(0x30u64, "strtol")], &wide)
                .iter()
                .map(|applied| (applied.address, applied.signature.clone()))
                .collect::<Vec<_>>(),
            vec![(0x30, "long strtol(char * * endptr)".to_string())]
        );
        assert!(declared_qualified_for(&table, [(0x30u64, "strtol")], &narrow).is_empty());
    }

    #[test]
    fn the_type_names_come_from_the_language_document() {
        let directory = std::env::temp_dir().join(format!(
            "romwright-coretypes-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(
            directory.join("coretypes.xml"),
            "<coretypes><type name=\"int\" size=\"4\" metatype=\"int\"/>\
             <type name=\"longlong\" size=\"8\" metatype=\"int\"/></coretypes>",
        )
        .unwrap();
        let names = core_type_names(&directory).unwrap();
        assert!(names.contains("longlong") && names.contains("int"));
        assert!(!names.contains("long"));
        // A document with no types names nothing, and the caller applies
        // nothing rather than guessing.
        std::fs::write(directory.join("coretypes.xml"), "<coretypes/>").unwrap();
        assert!(core_type_names(&directory).is_none());
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn a_type_the_decompiler_does_not_have_is_left_alone() {
        // `FILE *` is a real declaration in the archive and a type the C
        // parser has never heard of: applying it would fail the decompile.
        let declaration = Declaration {
            return_type: "int".into(),
            varargs: false,
            parameters: vec![Parameter {
                name: "stream".into(),
                data_type: "FILE *".into(),
            }],
            scope: None,
            calling_convention: None,
            this_type: None,
        };
        let table = Table {
            archive: "a".into(),
            archive_sha256: "b".into(),
            functions: HashMap::from([
                ("fclose".into(), declaration),
                ("printf".into(), printf()),
            ]),
        };

        let applied = declared_qualified_for(
            &table,
            [(0x10u64, "fclose"), (0x20u64, "printf")],
            &types(&["int", "char"]),
        );
        assert_eq!(
            applied
                .iter()
                .map(|applied| (applied.address, applied.signature.clone()))
                .collect::<Vec<_>>(),
            vec![(0x20, "int printf(char * __format, ...)".to_string())]
        );
    }
    #[test]
    fn scope_qualifies_bare_keys_and_derives_the_receiver() {
        let declaration = Declaration {
            return_type: "int".into(),
            varargs: false,
            parameters: Vec::new(),
            scope: Some("UberBond".into()),
            calling_convention: Some("__thiscall".into()),
            this_type: None,
        };
        assert_eq!(declaration.qualified_name("Update"), "UberBond::Update");
        assert_eq!(
            declaration.qualified_name("UberBond::Update"),
            "UberBond::Update"
        );
        assert_eq!(Declaration::bare_name("UberBond::Update"), "Update");
        assert_eq!(
            declaration.this_type_for("UberBond::Update"),
            Some("UberBond *".into())
        );
        assert_eq!(declaration.this_type_for("Update"), None);
        // An unscoped declaration neither qualifies nor invents a receiver.
        let free = Declaration { scope: None, ..declaration.clone() };
        assert_eq!(free.qualified_name("Update"), "Update");
        assert_eq!(free.this_type_for("Update"), None);
    }
}
