//! MWCC constructor/destructor symbols establish class membership, not RTTI
//! or vtable bindings. Preserve that evidence without inventing ABI addresses.

use super::ClassReport;
use romwright_model::{ClassKind, ClassRow, FactProvenance};
use std::collections::BTreeMap;

pub const SOURCE: &str = "mwcc-rtti-less";

/// The MWCC mangled membership marker: `__ct__8UberBondFv` is
/// `UberBond::UberBond()`, `__dt__8UberBondFv` the dtor. The class name is
/// the length-prefixed segment between `__ct__`/`__dt__` and the `F`
/// signature start.
pub(crate) fn member_class(mangled: &str) -> Option<(&str, &str)> {
    for marker in ["__ct__", "__dt__"] {
        if let Some(rest) = mangled.strip_prefix(marker) {
            // Length-prefixed class name: digits then that many chars.
            let digits: usize = rest.chars().take_while(|c| c.is_ascii_digit()).count();
            if digits == 0 {
                continue;
            }
            let len: usize = rest[..digits].parse().ok()?;
            let name = &rest[digits..];
            let Some(class) = name.get(..len) else {
                continue;
            };
            if !name.get(len..).is_some_and(|suffix| suffix.starts_with('F')) {
                continue;
            }
            let kind = if marker == "__ct__" { "ctor" } else { "dtor" };
            return Some((class, kind));
        }
    }
    None
}

/// Recover named membership. Class identity uses the encoded type name when
/// no ABI descriptor exists; constructor and destructor spellings coalesce.
pub fn recover(symbols: &BTreeMap<u64, String>) -> (Vec<ClassRow>, ClassReport) {
    let mut classes = BTreeMap::new();
    for mangled in symbols.values() {
        let Some((class, _)) = member_class(mangled) else {
            continue;
        };
        classes.entry(class.to_owned()).or_insert_with(|| ClassRow {
            typeinfo: None,
            vtable: None,
            name: class.to_owned(),
            mangled: format!("{}{class}", class.len()),
            kind: ClassKind::Plain,
            vtable_slots: 0,
            bases: Vec::new(),
            provenance: FactProvenance {
                kind: romwright_model::FactKind::Inferred,
                source: SOURCE.into(),
                confidence: None,
            },
        });
    }
    let report = ClassReport {
        classes: classes.len(),
        ..Default::default()
    };
    (classes.into_values().collect(), report)
}
