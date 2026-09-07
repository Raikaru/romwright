//! Itanium C++ ABI class recovery.
//!
//! Evidence chain, all of it in the image: a loader-bound relocation names one
//! of the ABI's `__cxxabiv1` type_info vtables, so any data word holding that
//! vtable's address point is a `type_info`'s vptr. The word after it points at
//! the mangled type name, the `__si`/`__vmi` shapes carry the base list, and a
//! data word holding the type_info's own address is a vtable's type_info slot,
//! two pointers into the object.
//!
//! Layouts follow the Itanium C++ ABI sections 2.9.5 (RTTI) and 2.5.2 (vtable
//! layout); the ABI vtable names follow the same document's mangling rules and
//! are matched literally.
use super::{ClassReport, Image, demangle_type, slots};
use crate::native::NativeImport;
use lre_model::{Address, ClassBase, ClassKind, ClassRow, FactKind, FactProvenance};
use std::collections::BTreeMap;

pub const SOURCE: &str = "itanium-rtti";

const CLASS_TYPE_INFO: &str = "_ZTVN10__cxxabiv117__class_type_infoE";
const SI_CLASS_TYPE_INFO: &str = "_ZTVN10__cxxabiv120__si_class_type_infoE";
const VMI_CLASS_TYPE_INFO: &str = "_ZTVN10__cxxabiv121__vmi_class_type_infoE";

/// Recovers every class the image describes, with no store access.
pub fn recover(import: &NativeImport, image: &Image<'_>) -> (Vec<ClassRow>, ClassReport) {
    let width = image.width;
    let mut report = ClassReport::default();
    // Two evidence forms. A COPY relocation duplicates one of the ABI's
    // type_info vtables into this image, so a vptr *holds* its address point.
    // Every other named binding rewrites the vptr slot itself, so that slot
    // *is* a type_info's first word.
    let mut anchors: BTreeMap<u64, ClassKind> = BTreeMap::new();
    let mut bound: BTreeMap<u64, ClassKind> = BTreeMap::new();
    for relocation in &import.named_relocations {
        let kind = match relocation.symbol.as_str() {
            CLASS_TYPE_INFO => ClassKind::Plain,
            SI_CLASS_TYPE_INFO => ClassKind::SingleBase,
            VMI_CLASS_TYPE_INFO => ClassKind::MultipleBase,
            _ => continue,
        };
        if relocation.copies {
            // Objects hold the address point: two pointers into the vtable.
            if let Some(anchor) = relocation.address.checked_add(2 * width as u64) {
                anchors.insert(anchor, kind);
            }
        } else {
            bound.insert(relocation.address, kind);
        }
    }
    report.anchors = anchors.len() + bound.len();
    if report.anchors == 0 {
        // No image binds an ABI type_info vtable, so no Itanium class exists
        // here and nothing needs scanning.
        return (Vec::new(), report);
    }
    let named = |candidate: u64| {
        image
            .word(candidate + width as u64)
            .and_then(|pointer| image.type_name(pointer))
    };
    let mut typeinfo: BTreeMap<u64, (ClassKind, String)> = BTreeMap::new();
    for (&address, &kind) in &bound {
        if let Some(name) = named(address) {
            typeinfo.insert(address, (kind, name));
        }
    }
    // type_info objects: a data word holding an anchor, followed by a name.
    for mapping in import.mappings.iter().filter(|mapping| mapping.flags & 4 == 0) {
        let mut address = mapping.vaddr;
        let end = mapping.vaddr + mapping.bytes.len() as u64;
        while address + 2 * width as u64 <= end {
            let candidate = address;
            address += width as u64;
            let Some(vptr) = image.word(candidate) else {
                continue;
            };
            let Some(&kind) = anchors.get(&vptr) else {
                continue;
            };
            let Some(name) = named(candidate) else {
                continue;
            };
            typeinfo.insert(candidate, (kind, name));
        }
    }
    report.typeinfo = typeinfo.len();
    // Vtables: a data word holding a type_info address is the vtable's
    // type_info slot, one pointer past `offset_to_top`.
    let mut vtables: BTreeMap<u64, u64> = BTreeMap::new();
    for mapping in import.mappings.iter().filter(|mapping| mapping.flags & 4 == 0) {
        let mut address = mapping.vaddr;
        let end = mapping.vaddr + mapping.bytes.len() as u64;
        while address + width as u64 <= end {
            let slot = address;
            address += width as u64;
            let Some(value) = image.word(slot) else {
                continue;
            };
            if !typeinfo.contains_key(&value) || slot < mapping.vaddr + width as u64 {
                continue;
            }
            // The primary vtable is the one whose `offset_to_top` is zero.
            if image.signed(slot - width as u64) != Some(0) {
                continue;
            }
            vtables.entry(value).or_insert(slot - width as u64);
        }
    }
    let mut rows = Vec::new();
    for (&address, (kind, mangled)) in &typeinfo {
        let Some(&vtable) = vtables.get(&address) else {
            report.without_vtable += 1;
            continue;
        };
        let bases = bases(&image, address, *kind, &typeinfo);
        report.bases += bases.len();
        rows.push(ClassRow {
            typeinfo: Address::ram(address),
            vtable: Address::ram(vtable),
            name: demangle_type(mangled),
            mangled: mangled.clone(),
            kind: *kind,
            vtable_slots: slots(&image, vtable),
            bases,
            provenance: FactProvenance {
                kind: FactKind::Inferred,
                source: SOURCE.into(),
                confidence: None,
            },
        });
    }
    report.classes = rows.len();
    (rows, report)
}

/// Base list exactly as the ABI records it for this type_info shape.
fn bases(
    image: &Image<'_>,
    address: u64,
    kind: ClassKind,
    typeinfo: &BTreeMap<u64, (ClassKind, String)>,
) -> Vec<ClassBase> {
    let width = image.width as u64;
    let named = |target: u64| {
        typeinfo
            .get(&target)
            .map(|(_, mangled)| mangled.clone())
            .unwrap_or_default()
    };
    match kind {
        ClassKind::Plain => Vec::new(),
        ClassKind::SingleBase => match image.word(address + 2 * width) {
            Some(base) if base != 0 => vec![ClassBase {
                typeinfo: Address::ram(base),
                mangled: named(base),
                offset: 0,
                virtual_base: false,
                public_base: true,
            }],
            _ => Vec::new(),
        },
        ClassKind::MultipleBase => {
            // __vmi_class_type_info: flags, base count, then base_class_type_info
            // pairs of (type_info*, offset_flags).
            let Some(count) = image.u32(address + 2 * width + 4) else {
                return Vec::new();
            };
            let mut bases = Vec::new();
            for index in 0..count.min(1024) as u64 {
                let entry = address + 2 * width + 8 + index * 2 * width;
                let (Some(base), Some(flags)) =
                    (image.word(entry), image.signed(entry + width))
                else {
                    break;
                };
                if base == 0 {
                    break;
                }
                bases.push(ClassBase {
                    typeinfo: Address::ram(base),
                    mangled: named(base),
                    // Itanium ABI: the low byte holds the flags, the rest is a
                    // signed offset in bytes.
                    offset: flags >> 8,
                    virtual_base: flags & 1 != 0,
                    public_base: flags & 2 != 0,
                });
            }
            bases
        }
    }
}
