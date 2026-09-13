//! C++ class recovery: the Itanium ABI for ELF images, the MSVC ABI for PE.
//!
//! Both passes work from the image alone and share one fact model. Nothing
//! here guesses: a candidate that fails any structural step produces no class,
//! and the ABI-specific evidence chains live in `itanium` and `msvc`.
use crate::native::{self, ImportError, Mapping, NativeImport};
use romwright_model::ClassRow;

mod itanium;
mod msvc;
mod mwcc;

/// Counts from one recovery pass. `anchors` counts the ABI structures that
/// start each chain: bound `__cxxabiv1` type_info vtables for Itanium, proven
/// complete object locators for MSVC.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct ClassReport {
    pub anchors: usize,
    pub typeinfo: usize,
    pub classes: usize,
    pub bases: usize,
    /// type_info objects with no vtable pointing at them: no class row.
    pub without_vtable: usize,
    pub revision: u64,
}

/// Reader over the loaded image: pointer width, byte order and mapped words.
pub(crate) struct Image<'a> {
    pub(crate) mappings: &'a [Mapping],
    pub(crate) width: usize,
    pub(crate) big_endian: bool,
}

impl<'a> Image<'a> {
    pub(crate) fn bytes(&self, address: u64, len: usize) -> Option<&'a [u8]> {
        self.mappings.iter().find_map(|mapping| {
            let offset = address.checked_sub(mapping.vaddr)? as usize;
            mapping.bytes.get(offset..offset.checked_add(len)?)
        })
    }

    pub(crate) fn word(&self, address: u64) -> Option<u64> {
        let bytes = self.bytes(address, self.width)?;
        Some(bytes.iter().enumerate().fold(0u64, |value, (index, &byte)| {
            let shift = if self.big_endian {
                self.width - 1 - index
            } else {
                index
            };
            value | (byte as u64) << (8 * shift)
        }))
    }

    /// True when `address` lies in an executable mapping: a function pointer.
    pub(crate) fn executable(&self, address: u64) -> bool {
        address != 0
            && self.mappings.iter().any(|mapping| {
                mapping.flags & 4 != 0
                    && address >= mapping.vaddr
                    && address - mapping.vaddr < mapping.size
            })
    }

    pub(crate) fn u32(&self, address: u64) -> Option<u32> {
        let bytes = self.bytes(address, 4)?;
        let bytes: [u8; 4] = bytes.try_into().ok()?;
        Some(if self.big_endian {
            u32::from_be_bytes(bytes)
        } else {
            u32::from_le_bytes(bytes)
        })
    }

    /// Signed 32-bit field, for MSVC's displacement triples.
    pub(crate) fn signed_u32(&self, address: u64) -> Option<i32> {
        Some(self.u32(address)? as i32)
    }

    /// Signed word, for the ABI's `ptrdiff_t` and `long` fields.
    pub(crate) fn signed(&self, address: u64) -> Option<i64> {
        let value = self.word(address)?;
        Some(if self.width == 8 {
            value as i64
        } else {
            value as u32 as i32 as i64
        })
    }

    /// A NUL-terminated Itanium type name: `<number><identifier>` or a nested
    /// `N...E` form. Anything else is not a type name and ends the candidate.
    pub(crate) fn type_name(&self, address: u64) -> Option<String> {
        let bytes = self.bytes(address, 1)?;
        if !bytes[0].is_ascii_digit() && bytes[0] != b'N' {
            return None;
        }
        let mut name = String::new();
        for step in 0..1024u64 {
            let byte = self.bytes(address + step, 1)?[0];
            if byte == 0 {
                return (!name.is_empty()).then_some(name);
            }
            if !byte.is_ascii_graphic() {
                return None;
            }
            name.push(byte as char);
        }
        None
    }
}

/// Itanium `<source-name>` and nested `N ... E` names only; anything else is
/// reported in its mangled form rather than guessed at.
pub fn demangle_type(mangled: &str) -> String {
    fn components(text: &str) -> Option<Vec<String>> {
        let mut rest = text;
        let mut parts = Vec::new();
        while !rest.is_empty() {
            let digits = rest.find(|c: char| !c.is_ascii_digit())?;
            if digits == 0 {
                return None;
            }
            let (length, tail) = rest.split_at(digits);
            let length: usize = length.parse().ok()?;
            if tail.len() < length {
                return None;
            }
            let (component, tail) = tail.split_at(length);
            parts.push(component.to_string());
            rest = tail;
        }
        (!parts.is_empty()).then_some(parts)
    }
    let inner = mangled
        .strip_prefix('N')
        .and_then(|rest| rest.strip_suffix('E'))
        .unwrap_or(mangled);
    match components(inner) {
        Some(parts) => parts.join("::"),
        None => mangled.to_string(),
    }
}

impl crate::Core {
    pub fn classes(&self, program: &str) -> crate::Result<Vec<ClassRow>> {
        let id = self.db.program_id(program)?;
        Ok(self.db.classes(id)?)
    }

    /// Recovers C++ classes from a byte snapshot and publishes them.
    pub fn recover_classes(
        &self,
        binary: &std::path::Path,
        program: &str,
    ) -> crate::Result<ClassReport> {
        let id = self.db.program_id(program)?;
        let mut import = native::parse_native(&std::fs::read(binary)?)?;
        native::select_language(&mut import, &self.config)?;
        if import.language != self.db.program_language(id)? {
            return Err(ImportError::Bad("class input and stored language differ".into()).into());
        }
        let mut recovery = recover(&import);
        self.db
            .replace_inferred_classes(id, recovery.source, &recovery.classes)?;
        recovery.report.revision = self.db.revision(id)?;
        Ok(recovery.report)
    }
}


/// Classes one pass recovered, and which producer owns them.
pub struct Recovery {
    pub source: &'static str,
    pub classes: Vec<ClassRow>,
    pub report: ClassReport,
}

/// Recovers every class the image describes, with no store access. The image's
/// format picks the ABI: PE carries MSVC RTTI, everything else Itanium.
pub fn recover(import: &NativeImport) -> Recovery {
    let image = Image {
        mappings: &import.mappings,
        width: if import.language.contains(":64:") { 8 } else { 4 },
        big_endian: import.language.contains(":BE:") || import.language.contains(":LEBE:"),
    };
    if import.format == "PE" {
        let (classes, report) = msvc::recover(&image);
        return Recovery {
            source: msvc::SOURCE,
            classes,
            report,
        };
    }
    let (classes, report) = itanium::recover(import, &image);
    // MWCC (CodeWarrior) emits no __cxxabiv1 type_info chain: an ELF image
    // whose Itanium pass anchored nothing but that carries __ct__/__dt__
    // members is an MWCC image, and its classes come from the RTTI-less
    // membership pass instead.
    if report.anchors == 0 {
        let symbols: std::collections::BTreeMap<u64, String> = import
            .functions
            .iter()
            .map(|f| (f.entry, f.name.clone()))
            .collect();
        let has_mwcc_members = symbols
            .values()
            .any(|n| n.contains("__ct__") || n.contains("__dt__"));
        if has_mwcc_members {
            let (classes, report) = mwcc::recover(import, &image, &symbols, &[], &[]);
            return Recovery {
                source: mwcc::SOURCE,
                classes,
                report,
            };
        }
    }
    Recovery {
        source: itanium::SOURCE,
        classes,
        report,
    }
}

/// Virtual function slots after the address point. A vtable slot holds a
/// function pointer, so the run ends at the first word that does not point
/// into executable memory — which is exactly where the next vtable, a pure
/// virtual entry or the padding begins.
pub(crate) fn slots(image: &Image<'_>, vtable: u64) -> u64 {
    let width = image.width as u64;
    let mut slot = vtable + 2 * width;
    let mut count = 0;
    while let Some(value) = image.word(slot) {
        if !image.executable(value) {
            break;
        }
        count += 1;
        slot += width;
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_grammar_this_build_parses_is_demangled() {
        assert_eq!(demangle_type("4Base"), "Base");
        assert_eq!(demangle_type("N3app6WidgetE"), "app::Widget");
        assert_eq!(demangle_type("6Middle"), "Middle");
        // Templates and pointers are left mangled rather than half-decoded.
        assert_eq!(demangle_type("1AIiE"), "1AIiE");
        assert_eq!(demangle_type("Pi"), "Pi");
        assert_eq!(demangle_type("9"), "9");
    }
}
