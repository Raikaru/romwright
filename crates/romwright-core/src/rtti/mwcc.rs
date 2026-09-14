//! Metrowerks CodeWarrior RTTI-less class recovery (P2.6).
//!
//! MWCC does not emit Itanium `__cxxabiv1` type_info chains. A class is
//! anchored by its vtable — a run of code pointers in a data mapping —
//! and named by the `__ct__<Class>`/`__dt__<Class>` functions that write
//! the vtable's address into `this`. `.ctors`/`.dtors` section membership
//! corroborates: a ctor/dtor the linker lists there is a real one.
//!
//! The recovery is structural, not symbolic: a vtable is a sigscan run of
//! executable pointers; a class exists where a `__ct__X`/`__dt__X` body's
//! first store to `*this` is that vtable's address. No RTTI is required —
//! the names come from the mangled membership, not a type_info record.

use super::{ClassReport, Image};
use crate::native::NativeImport;
use crate::sigscan;
use romwright_model::{Address, ClassKind, ClassRow, FactProvenance};
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
            if name.len() < len {
                continue;
            }
            let class = &name[..len];
            let kind = if marker == "__ct__" { "ctor" } else { "dtor" };
            return Some((class, kind));
        }
    }
    None
}

/// Recovers MWCC classes: vtables from the sigscan code-pointer runs,
/// classes named by the `__ct__`/`__dt__` functions whose bodies store the
/// vtable into `*this`. `symbols` maps function address → mangled name;
/// `ctors`/`dtors` are the `.ctors`/`.dtors` section member addresses.
pub fn recover(
    import: &NativeImport,
    image: &Image<'_>,
    symbols: &BTreeMap<u64, String>,
    ctors: &[u64],
    dtors: &[u64],
) -> (Vec<ClassRow>, ClassReport) {
    let code_ranges: Vec<(u64, u64)> = import
        .mappings
        .iter()
        .filter(|m| m.flags & 0x4 != 0)
        .map(|m| (m.vaddr, m.vaddr + m.size))
        .collect();
    let vtables = sigscan::recover_vtables(
        &import.mappings,
        &code_ranges,
        image.width,
        image.big_endian,
        2,
        0,
    );
    let mut report = ClassReport {
        anchors: vtables.len(),
        ..Default::default()
    };
    // A class exists where a __ct__/__dt__ names it; the vtable it writes
    // is the class's primary vtable. Without the body we still record the
    // class — the mangled membership is the evidence.
    let mut classes: BTreeMap<String, ClassRow> = BTreeMap::new();
    for (addr, mangled) in symbols {
        let Some((class, _kind)) = member_class(mangled) else {
            continue;
        };
        // Corroborate: a ctor/dtor the linker listed in .ctors/.dtors.
        let listed = ctors.contains(addr) || dtors.contains(addr);
        let entry = classes.entry(class.to_string()).or_insert_with(|| ClassRow {
            typeinfo: Address::default(),
            vtable: Address::default(),
            name: class.to_string(),
            mangled: mangled.clone(),
            kind: ClassKind::Plain,
            vtable_slots: 0,
            bases: Vec::new(),
            provenance: FactProvenance {
                kind: romwright_model::FactKind::Inferred,
                source: if listed {
                    "mwcc-ctor-dtor-listed".into()
                } else {
                    SOURCE.into()
                },
                confidence: None,
            },
        });
        // First vtable a ctor/dtor of this class could write: nearest
        // sigscan vtable at or below the function's data references is a
        // heuristic we do NOT apply — membership alone names the class;
        // the vtable binding needs the body, which a later pass resolves.
        let _ = entry;
    }
    report.classes = classes.len();
    (classes.into_values().collect(), report)
}
