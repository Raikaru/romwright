//! Builds a `.vsig` database from one static archive.
//!
//! Package and license are supplied by the caller, never inferred: a signature
//! derived from someone else's compiled code is only auditable when the exact
//! package build and its license travel with it.
use crate::{
    Signature, SignatureDb, VsigError,
    archive::{self, ArchiveError},
    object::{self, ObjectError},
};
use std::collections::BTreeMap;

#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("archive: {0}")]
    Archive(#[from] ArchiveError),
    #[error("member {member}: {source}")]
    Object {
        member: String,
        #[source]
        source: ObjectError,
    },
    #[error("container: {0}")]
    Container(#[from] VsigError),
    #[error("archive holds no relocatable objects")]
    NoObjects,
    #[error("member {member} is {found:#x}/{class}, the archive started {expected:#x}/{first}")]
    MixedMachines {
        member: String,
        found: u16,
        class: &'static str,
        expected: u16,
        first: &'static str,
    },
    #[error("no language is configured for machine {machine:#x}")]
    UnsupportedMachine { machine: u16 },
}

/// What one archive produced. Counts, not adjectives.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BuildReport {
    pub language: String,
    pub members: usize,
    /// Exported functions the objects defined, before policy.
    pub functions: usize,
    pub records: usize,
    /// Local function bodies kept only as competitors.
    pub competitors: usize,
    /// Skip counts keyed by reason, including this pass's own policy.
    pub skipped: BTreeMap<String, usize>,
}

/// One extracted body. Weak bodies are competitors, never records.
struct Body {
    bytes: (Vec<u8>, Vec<u8>),
    weak: bool,
}

/// Minimum compared bytes a record must carry to be worth storing. A short
/// prologue that every function shares identifies nothing.
pub const MIN_COMPARED: usize = 16;

fn class_name(class64: bool) -> &'static str {
    if class64 { "64" } else { "32" }
}

/// Extracts every exported function of every object in `bytes`.
///
/// `resolve_language` maps the archive's ELF identity to a Ghidra language id;
/// callers pass the project's single mapping instead of a second copy here.
pub fn from_archive(
    bytes: &[u8],
    package: &str,
    license: &str,
    min_compared: usize,
    resolve_language: &dyn Fn(u16, bool, u32) -> Option<String>,
) -> Result<(SignatureDb, BuildReport), BuildError> {
    let mut report = BuildReport::default();
    let mut identity: Option<(u16, bool, bool, u32)> = None;
    // name -> body, or None once two members disagreed about it.
    let mut candidates: BTreeMap<String, Option<Body>> = BTreeMap::new();
    // Local bodies never carry a name outside their object, but an exported
    // record indistinguishable from one would name it by mistake.
    let mut competitors: Vec<Body> = Vec::new();
    for member in archive::members(bytes)? {
        let object = match object::relocatable(member.data, crate::MAX_PATTERN) {
            Ok(object) => object,
            // Archives carry non-objects too; only a malformed object is fatal.
            Err(ObjectError::NotElf) => continue,
            Err(source) => {
                return Err(BuildError::Object {
                    member: member.name,
                    source,
                });
            }
        };
        report.members += 1;
        match identity {
            None => identity = Some((object.machine, object.big_endian, object.class64, object.flags)),
            Some((machine, big_endian, class64, _))
                if (machine, big_endian, class64)
                    != (object.machine, object.big_endian, object.class64) =>
            {
                return Err(BuildError::MixedMachines {
                    member: member.name,
                    found: object.machine,
                    class: class_name(object.class64),
                    expected: machine,
                    first: class_name(class64),
                });
            }
            Some(_) => {}
        }
        for skip in &object.skipped {
            *report
                .skipped
                .entry(skip.reason.as_str().to_string())
                .or_default() += 1;
        }
        for function in object.locals {
            competitors.push(Body {
                weak: function.mask.iter().filter(|&&keep| keep != 0).count() < min_compared,
                bytes: (function.pattern, function.mask),
            });
        }
        for function in object.functions {
            report.functions += 1;
            // Weak bodies never become records, but they still compete: a
            // record that cannot be told apart from one would name it.
            let weak =
                function.mask.iter().filter(|&&keep| keep != 0).count() < min_compared;
            if weak {
                *report.skipped.entry("too-weak".to_string()).or_default() += 1;
            }
            let body = Body {
                bytes: (function.pattern, function.mask),
                weak,
            };
            match candidates.entry(function.name) {
                std::collections::btree_map::Entry::Vacant(slot) => {
                    slot.insert(Some(body));
                }
                std::collections::btree_map::Entry::Occupied(mut slot) => {
                    // One name with two different bodies cannot name anything.
                    if slot.get().as_ref().map(|kept| &kept.bytes) != Some(&body.bytes) {
                        if slot.get().is_some() {
                            *report.skipped.entry("conflicting".to_string()).or_default() += 1;
                        }
                        *report.skipped.entry("conflicting".to_string()).or_default() += 1;
                        slot.insert(None);
                    }
                }
            }
        }
    }
    let Some((machine, big_endian, _, flags)) = identity else {
        return Err(BuildError::NoObjects);
    };
    let language = resolve_language(machine, big_endian, flags)
        .ok_or(BuildError::UnsupportedMachine { machine })?;
    report.language = language.clone();
    // Masks can make one body match another function: glibc's tunable setters
    // and alias wrappers differ only where a relocation was masked out. Two
    // records that no window can tell apart identify nothing, so both go.
    report.competitors = competitors.len();
    let mut bodies: Vec<(Option<&String>, &Body)> = candidates
        .iter()
        .filter_map(|(name, body)| body.as_ref().map(|body| (Some(name), body)))
        .collect();
    bodies.extend(competitors.iter().map(|body| (None, body)));
    let mut ambiguous = vec![false; bodies.len()];
    for (left, (_, first)) in bodies.iter().enumerate() {
        for (right, (_, second)) in bodies.iter().enumerate().skip(left + 1) {
            if !indistinguishable(&first.bytes, &second.bytes) {
                continue;
            }
            // A body below the evidence threshold still competes when it is
            // the same length: at one entry either name would fit.
            let same_length = first.bytes.0.len() == second.bytes.0.len();
            if !first.weak || same_length {
                ambiguous[right] = true;
            }
            if !second.weak || same_length {
                ambiguous[left] = true;
            }
        }
    }
    let mut signatures = Vec::new();
    for (index, (name, body)) in bodies.iter().enumerate() {
        let Some(name) = name else {
            continue;
        };
        if body.weak {
            continue;
        }
        if ambiguous[index] {
            *report.skipped.entry("ambiguous".to_string()).or_default() += 1;
            continue;
        }
        signatures.push(Signature::new(
            &language, name, package, license, &body.bytes.0, &body.bytes.1,
        )?);
    }
    report.records = signatures.len();
    Ok((SignatureDb::from_signatures(signatures)?, report))
}

/// True when some byte window satisfies both records: they agree wherever both
/// compare, over the shorter pattern.
fn indistinguishable(left: &(Vec<u8>, Vec<u8>), right: &(Vec<u8>, Vec<u8>)) -> bool {
    let shared = left.0.len().min(right.0.len());
    (0..shared).all(|index| {
        left.1[index] == 0 || right.1[index] == 0 || left.0[index] == right.0[index]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn language(machine: u16, big_endian: bool, _flags: u32) -> Option<String> {
        match (machine, big_endian) {
            (0x3e, false) => Some("x86:LE:64:default".into()),
            _ => None,
        }
    }

    /// Two members: one defines `shared` and `only_here`, the other repeats
    /// `shared` with different bytes and adds a short function.
    fn archive_bytes() -> Vec<u8> {
        let mut bytes = b"!<arch>\n".to_vec();
        for (name, data) in [
            ("first.o", object_bytes(&[0x90; 24], &[("shared", 0, 24), ("only_here", 0, 20)])),
            ("second.o", object_bytes(&[0xcc; 24], &[("shared", 0, 24), ("tiny", 0, 4)])),
            ("notes.txt", b"not an object".to_vec()),
        ] {
            bytes.extend(
                format!("{name:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n", 0, 0, 0, 100644, data.len())
                    .into_bytes(),
            );
            bytes.extend(&data);
            if data.len() % 2 == 1 {
                bytes.push(b'\n');
            }
        }
        bytes
    }

    /// Minimal x86-64 ET_REL object with exported functions and no relocations.
    fn object_bytes(code: &[u8], symbols: &[(&str, u64, u64)]) -> Vec<u8> {
        let word = |value: u64, size: usize| -> Vec<u8> {
            (0..size).map(|index| (value >> (8 * index)) as u8).collect()
        };
        let mut strings = vec![0u8];
        let mut table = vec![0u8; 24];
        for &(name, value, size) in symbols {
            let offset = strings.len() as u32;
            strings.extend(name.as_bytes());
            strings.push(0);
            table.extend(word(offset as u64, 4));
            table.push(0x12);
            table.push(0);
            table.extend(word(1, 2));
            table.extend(word(value, 8));
            table.extend(word(size, 8));
        }
        let shoff = 64usize;
        let code_at = shoff + 4 * 64;
        let symbols_at = code_at + code.len();
        let strings_at = symbols_at + table.len();
        let mut bytes = b"\x7fELF\x02\x01\x01".to_vec();
        bytes.resize(16, 0);
        bytes.extend(word(1, 2));
        bytes.extend(word(0x3e, 2));
        bytes.extend(word(1, 4));
        bytes.extend(word(0, 8));
        bytes.extend(word(0, 8));
        bytes.extend(word(shoff as u64, 8));
        bytes.extend(word(0, 4));
        bytes.extend(word(64, 2));
        bytes.extend(word(0, 2));
        bytes.extend(word(0, 2));
        bytes.extend(word(64, 2));
        bytes.extend(word(4, 2));
        bytes.extend(word(3, 2));
        for (typ, flags, offset, size, link, entry) in [
            (0u64, 0u64, 0usize, 0usize, 0u64, 0u64),
            (1, 6, code_at, code.len(), 0, 0),
            (2, 0, symbols_at, table.len(), 3, 24),
            (3, 0, strings_at, strings.len(), 0, 0),
        ] {
            bytes.extend(word(0, 4));
            bytes.extend(word(typ, 4));
            bytes.extend(word(flags, 8));
            bytes.extend(word(0, 8));
            bytes.extend(word(offset as u64, 8));
            bytes.extend(word(size as u64, 8));
            bytes.extend(word(link, 4));
            bytes.extend(word(0, 4));
            bytes.extend(word(1, 8));
            bytes.extend(word(entry, 8));
        }
        bytes.extend(code);
        bytes.extend(table);
        bytes.extend(strings);
        bytes
    }

    #[test]
    fn conflicting_names_and_weak_patterns_never_reach_the_database() {
        let (database, report) =
            from_archive(&archive_bytes(), "test-1.0", "MIT", MIN_COMPARED, &language).unwrap();
        assert_eq!(report.members, 2, "a text member is not an object");
        assert_eq!(report.functions, 4);
        assert_eq!(report.language, "x86:LE:64:default");
        assert_eq!(
            database
                .signatures()
                .iter()
                .map(|signature| signature.name.as_str())
                .collect::<Vec<_>>(),
            ["only_here"],
            "`shared` disagrees between members and `tiny` compares too little"
        );
        assert_eq!(report.records, 1);
        assert_eq!(report.skipped.get("too-weak"), Some(&1));
        assert_eq!(report.skipped.get("conflicting"), Some(&2));
        let record = &database.signatures()[0];
        assert_eq!(record.package, "test-1.0");
        assert_eq!(record.license, "MIT");
        assert_eq!(record.compared_bytes(), 20);
    }

    #[test]
    fn an_unmapped_machine_is_a_refusal_not_a_guess() {
        let error = from_archive(&archive_bytes(), "p", "MIT", MIN_COMPARED, &|_, _, _| None)
            .unwrap_err();
        assert!(
            matches!(error, BuildError::UnsupportedMachine { machine: 0x3e }),
            "{error}"
        );
        assert!(matches!(
            from_archive(b"!<arch>\n", "p", "MIT", MIN_COMPARED, &language),
            Err(BuildError::NoObjects)
        ));
    }
}
