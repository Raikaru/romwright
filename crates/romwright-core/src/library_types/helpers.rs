//! Compiler run-time helper routines (`__adddf3`, `__udivdi3`, `__aeabi_dadd`),
//! declared by mode and resolved against one image's own type widths.
//!
//! The committed table (`oracle/library-prototypes-v1/runtime_helpers.json`,
//! written by `scripts/gen_runtime_helpers.py`) is transcribed from two public
//! documents: GCC Internals' "The GCC low-level runtime library" and Arm's
//! Run-time ABI. The first states the routines by machine mode (`SImode`,
//! `DImode`, `SFmode`, `DFmode`) with illustrative C types: `long` for
//! `DImode` is true on an LP64 target and false on the 32-bit ones, where
//! `DImode` is `long long`. So the table carries modes, and this module maps a
//! mode to the type of that width the language declares. A mode the language
//! has no type of that width for (`TImode` on a 32-bit target, a quad float
//! anywhere) drops the routines that use it rather than approximating.
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

use super::{BaseType, Declaration, Parameter};

#[derive(Debug, Clone, serde::Deserialize)]
pub struct Row {
    #[serde(rename = "return")]
    pub return_mode: String,
    pub parameters: Vec<RowParameter>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct RowParameter {
    pub name: String,
    #[serde(rename = "type")]
    pub mode: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct Helpers {
    pub functions: HashMap<String, Row>,
}

/// Reads the committed table; absent or unreadable means no rows, as for the
/// library table.
pub fn load(path: &Path) -> Option<Helpers> {
    serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()
}

/// The widths one language declares: its C base types and its pointer size.
#[derive(Debug, Clone)]
pub struct Widths {
    pub base: BTreeMap<String, BaseType>,
    pub pointer_size: u32,
}

impl Widths {
    /// From a language's spec bundle (`cspec.xml` data organization).
    pub fn from_specs(specs: &Path) -> Option<Self> {
        let base = super::language_base_types(specs);
        if base.is_empty() {
            return None;
        }
        let cspec = std::fs::read_to_string(specs.join("cspec.xml")).ok()?;
        let marker = "<pointer_size value=\"";
        let start = cspec.find(marker)? + marker.len();
        let pointer_size = cspec[start..start + cspec[start..].find('"')?].parse().ok()?;
        Some(Self { base, pointer_size })
    }

    fn integer(&self, size: u32, unsigned: bool) -> Option<&'static str> {
        let candidates: [&'static str; 4] = if unsigned {
            ["uint", "ulong", "ulonglong", "ushort"]
        } else {
            ["int", "long", "longlong", "short"]
        };
        candidates
            .into_iter()
            .find(|name| self.base.get(*name).is_some_and(|base| base.size == size))
    }

    fn float(&self, size: u32) -> Option<&'static str> {
        ["float", "double", "longdouble"]
            .into_iter()
            .find(|name| self.base.get(*name).is_some_and(|base| base.size == size))
    }

    /// The language's spelling of one mode, `None` when it has no such type.
    fn spell(&self, mode: &str, known: &HashSet<String>) -> Option<String> {
        if let Some(pointee) = mode.strip_suffix('*') {
            let pointee = self.spell(pointee, known)?;
            return Some(format!("{pointee} *"));
        }
        let name = match mode {
            "void" => Some("void"),
            "si" => self.integer(4, false),
            "usi" => self.integer(4, true),
            "di" => self.integer(8, false),
            "udi" => self.integer(8, true),
            "ti" => self.integer(16, false),
            "uti" => self.integer(16, true),
            "hi" => self.integer(2, false),
            // CMPtype is "typically word-sized" and a target hook may change
            // it; only the 32-bit word is claimed.
            "cmp" if self.pointer_size == 4 => self.integer(4, false),
            "usize" => self.integer(self.pointer_size, true),
            "sf" => self.float(4),
            "df" => self.float(8),
            // x87 extended precision: the 80-bit type stored in 12 or 16
            // bytes. IEEE quad (`tf`) is a different type no language
            // document here declares.
            "xf" => ["longdouble"]
                .into_iter()
                .find(|name| self.base.get(*name).is_some_and(|base| matches!(base.size, 12 | 16))),
            _ => None,
        }?;
        known.contains(name).then(|| name.to_string())
    }
}

/// Every helper whose modes the language can spell, as declarations.
pub fn declarations(
    helpers: &Helpers,
    widths: &Widths,
    known: &HashSet<String>,
) -> HashMap<String, Declaration> {
    helpers
        .functions
        .iter()
        .filter_map(|(name, row)| {
            let parameters = row
                .parameters
                .iter()
                .map(|parameter| {
                    Some(Parameter {
                        name: parameter.name.clone(),
                        data_type: widths.spell(&parameter.mode, known)?,
                    })
                })
                .collect::<Option<Vec<_>>>()?;
            Some((
                name.clone(),
                Declaration {
                    return_type: widths.spell(&row.return_mode, known)?,
                    varargs: false,
                    parameters,
                    scope: None,
                    calling_convention: None,
                    this_type: None,
                },
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn widths(long: u32, long_double: u32, pointer_size: u32) -> (Widths, HashSet<String>) {
        let mut base = BTreeMap::new();
        for (signed, unsigned, size) in [("short", "ushort", 2), ("int", "uint", 4), ("long", "ulong", long), ("longlong", "ulonglong", 8)] {
            base.insert(signed.to_string(), BaseType { size, metatype: "int" });
            base.insert(unsigned.to_string(), BaseType { size, metatype: "uint" });
        }
        for (name, size) in [("float", 4), ("double", 8), ("longdouble", long_double)] {
            base.insert(name.to_string(), BaseType { size, metatype: "float" });
        }
        let known = base.keys().cloned().chain(["void".to_string()]).collect();
        (Widths { base, pointer_size }, known)
    }

    fn table() -> Helpers {
        let row = |ret: &str, parameters: &[(&str, &str)]| Row {
            return_mode: ret.into(),
            parameters: parameters
                .iter()
                .map(|(name, mode)| RowParameter { name: (*name).into(), mode: (*mode).into() })
                .collect(),
        };
        Helpers {
            functions: HashMap::from([
                ("__adddf3".into(), row("df", &[("a", "df"), ("b", "df")])),
                ("__udivdi3".into(), row("udi", &[("a", "udi"), ("b", "udi")])),
                ("__multi3".into(), row("ti", &[("a", "ti"), ("b", "ti")])),
                ("__cmpdf2".into(), row("cmp", &[("a", "df"), ("b", "df")])),
                ("__addxf3".into(), row("xf", &[("a", "xf"), ("b", "xf")])),
                ("__addtf3".into(), row("tf", &[("a", "tf"), ("b", "tf")])),
                ("__udivmoddi4".into(), row("udi", &[("a", "udi"), ("b", "udi"), ("c", "udi*")])),
                ("__aeabi_memcpy".into(), row("void", &[("dest", "void*"), ("src", "void*"), ("n", "usize")])),
            ]),
        }
    }

    fn signatures(widths: (Widths, HashSet<String>)) -> BTreeMap<String, String> {
        declarations(&table(), &widths.0, &widths.1)
            .into_iter()
            .map(|(name, declaration)| (name.clone(), crate::library_types::signature(&name, &declaration)))
            .collect()
    }

    /// A 32-bit target: `DImode` is `long long`, `size_t` is `uint`, there is
    /// no 16-byte integer, no extended float, and `__cmpdf2` returns `int`.
    #[test]
    fn modes_resolve_to_the_widths_of_a_32_bit_language() {
        let got = signatures(widths(4, 8, 4));
        assert_eq!(got["__adddf3"], "double __adddf3(double a, double b)");
        assert_eq!(got["__udivdi3"], "ulonglong __udivdi3(ulonglong a, ulonglong b)");
        assert_eq!(got["__udivmoddi4"], "ulonglong __udivmoddi4(ulonglong a, ulonglong b, ulonglong * c)");
        assert_eq!(got["__cmpdf2"], "int __cmpdf2(double a, double b)");
        assert_eq!(got["__aeabi_memcpy"], "void __aeabi_memcpy(void * dest, void * src, uint n)");
        for dropped in ["__multi3", "__addxf3", "__addtf3"] {
            assert!(!got.contains_key(dropped), "{dropped} has no type on this target");
        }
    }

    /// LP64 with an 80-bit `long double`: `DImode` is `long`, `TImode` has no
    /// integer type here, `__cmpdf2`'s target-defined result is not claimed.
    #[test]
    fn modes_resolve_to_the_widths_of_a_64_bit_language() {
        let got = signatures(widths(8, 16, 8));
        assert_eq!(got["__udivdi3"], "ulong __udivdi3(ulong a, ulong b)");
        assert_eq!(got["__addxf3"], "longdouble __addxf3(longdouble a, longdouble b)");
        assert_eq!(got["__aeabi_memcpy"], "void __aeabi_memcpy(void * dest, void * src, ulong n)");
        assert!(!got.contains_key("__cmpdf2"));
        assert!(!got.contains_key("__multi3") && !got.contains_key("__addtf3"));
    }

    /// A name outside the language's known types is dropped, never spelled.
    #[test]
    fn a_type_the_parser_lacks_drops_the_routine() {
        let (widths, mut known) = widths(4, 8, 4);
        known.remove("double");
        let got = declarations(&table(), &widths, &known);
        assert!(!got.contains_key("__adddf3") && got.contains_key("__udivdi3"));
    }

    /// The committed table parses and every mode in it is one `spell` knows.
    #[test]
    fn the_committed_table_uses_only_known_modes() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../oracle/library-prototypes-v1/runtime_helpers.json");
        let helpers = load(&path).expect("runtime_helpers.json parses");
        assert!(helpers.functions.len() > 200);
        let mut modes: HashSet<&str> = HashSet::new();
        for row in helpers.functions.values() {
            modes.insert(&row.return_mode);
            modes.extend(row.parameters.iter().map(|parameter| parameter.mode.as_str()));
        }
        for mode in modes {
            let probe = mode.trim_end_matches('*');
            assert!(
                ["void", "si", "usi", "di", "udi", "ti", "uti", "hi", "cmp", "usize", "sf", "df", "xf", "tf"].contains(&probe),
                "unknown mode {mode}"
            );
        }
        assert!(helpers.functions.contains_key("__adddf3") && helpers.functions.contains_key("__aeabi_dadd"));
    }
}
