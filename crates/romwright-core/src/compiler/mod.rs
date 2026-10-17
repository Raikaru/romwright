//! Compiler identity and compiler rules.
//!
//! Every program carries one canonical compiler id (`programs.compiler`),
//! detected from the image's own bytes at import or set by `--compiler`.
//! Compiler-specific behaviour is declared as data (`rules`), keyed by that
//! id; the engines that execute the data stay in code.
//!
//! * [`detect`] -- the detectors, one per platform family, and the evidence
//!   each reports. An image no detector can prove anything about is
//!   [`UNKNOWN`]; nothing is guessed from the platform alone.
//! * [`ps2`] -- the PlayStation 2 linker/section evidence, shared with
//!   `new-project`.
//! * [`rules`] -- the embedded rule files, the per-rule switches and the
//!   lookups the engines call.
//!
//! `docs/compiler-rules.md` documents the id grammar, the rule format and
//! the leave-one-out policy a rule must pass to ship `on`.

pub mod detect;
pub mod ps2;
pub mod rules;

use serde::Serialize;

pub use detect::{identify, ImageFacts};
pub use ps2::{CompilerFamily, Ps2Verdict};

/// The id of an image no detector could name. Rules with `unknown: true`
/// fall back to the platform key they had before compilers were detected.
pub const UNKNOWN: &str = "unknown";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

/// Where an id came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Source {
    /// A detector read it off the image.
    Detected,
    /// The importer was told (`romwright-cli import --compiler`).
    Override,
}

/// One program's compiler identity and the evidence behind it.
#[derive(Debug, Clone, Serialize)]
pub struct Detection {
    /// Canonical id: `family[-version-class]`, or [`UNKNOWN`].
    pub id: String,
    pub confidence: Confidence,
    pub source: Source,
    /// One line per observation that carried the verdict, strongest first;
    /// for [`UNKNOWN`], what was looked for and not found.
    pub evidence: Vec<String>,
}

impl Detection {
    pub fn unknown(evidence: Vec<String>) -> Self {
        Self { id: UNKNOWN.into(), confidence: Confidence::Low, source: Source::Detected, evidence }
    }

    pub fn found(id: impl Into<String>, confidence: Confidence, evidence: Vec<String>) -> Self {
        Self { id: id.into(), confidence, source: Source::Detected, evidence }
    }

    pub fn overridden(id: &str) -> Self {
        Self {
            id: id.trim().to_ascii_lowercase(),
            confidence: Confidence::High,
            source: Source::Override,
            evidence: vec![format!("`--compiler {id}` on the import")],
        }
    }

    pub fn is_unknown(&self) -> bool {
        self.id == UNKNOWN
    }

    /// The family of the id (`ee-gcc-2.9x` -> `ee-gcc`).
    pub fn family(&self) -> &str {
        family_of(&self.id)
    }

    /// The one line the import records as a diagnostic.
    pub fn summary(&self) -> String {
        let source = match self.source {
            Source::Detected => "detected",
            Source::Override => "set by --compiler",
        };
        format!(
            "compiler {} ({source}, {:?} confidence): {}",
            self.id,
            self.confidence,
            self.evidence.first().map_or("no evidence", String::as_str)
        )
    }
}

/// Families an id can start with, longest first so `ee-gcc-2.9x` is not a
/// `gcc` and `devkitarm-gcc` is not an `arm`.
const FAMILIES: [&str; 18] = [
    "devkita64-gcc",
    "devkitarm-gcc",
    "devkitppc-gcc",
    "allegrex-gcc",
    "mwcc-ps2",
    "mwcc-psp",
    "mwcc-gc",
    "mwcc-wii",
    "mwcc-arm",
    "sn-prodg",
    "ee-gcc",
    "n64-gcc",
    "agbcc",
    "ido",
    "clang",
    "msvc",
    "mingw-gcc",
    "gcc",
];

/// The family part of a canonical id; an id naming no known family is its own.
pub fn family_of(id: &str) -> &str {
    FAMILIES
        .iter()
        .find(|family| covers(family, id))
        .copied()
        .unwrap_or(id)
}

/// Whether `pattern` names `id`: `*` names every detected compiler, any
/// other pattern names itself and everything built on it (`ee-gcc` names
/// `ee-gcc-2.9x`, not `gcc-4`).
pub fn covers(pattern: &str, id: &str) -> bool {
    if pattern == "*" {
        return id != UNKNOWN && !id.is_empty();
    }
    id == pattern || id.strip_prefix(pattern).is_some_and(|rest| rest.starts_with('-'))
}

/// [`identify`] for an image of a container: when the detectors find nothing,
/// the compiler an earlier image of the same container and language was
/// identified as (an NDS overlay carries none of the NitroSDK banners its ARM9
/// main binary does, a REL module none of its DOL's).
pub fn identify_in_container(imp: &crate::native::NativeImport, earlier: &[(String, Detection)]) -> Detection {
    let found = identify(imp);
    if !found.is_unknown() || imp.cfg.compiler.is_some() {
        return found;
    }
    match earlier.iter().find(|(language, _)| *language == imp.language) {
        Some((_, parent)) => Detection {
            id: parent.id.clone(),
            confidence: Confidence::Low,
            source: Source::Detected,
            evidence: vec![format!("inherited from the container's earlier {} image: {}", imp.language, parent.id)],
        },
        None => found,
    }
}

/// The compiler id of an import: the detection the importer made, or
/// [`UNKNOWN`] before it ran.
pub fn id_of(imp: &crate::native::NativeImport) -> &str {
    imp.identity.as_ref().map_or(UNKNOWN, |found| found.id.as_str())
}

/// What the rules are matched against for an import.
pub fn ctx_of(imp: &crate::native::NativeImport) -> rules::Ctx<'_> {
    rules::Ctx::new(id_of(imp), &imp.language, &imp.format)
}

/// The ids the detectors can produce, for `--compiler` help and the docs.
pub const KNOWN_IDS: [&str; 29] = [
    "mwcc-ps2",
    "mwcc-ps2-2.3",
    "mwcc-ps2-2.4",
    "mwcc-psp",
    "mwcc-gc",
    "mwcc-wii",
    "mwcc-arm",
    "ee-gcc-2.9x",
    "ee-gcc-3.x",
    "sn-prodg",
    "allegrex-gcc",
    "ido",
    "n64-gcc",
    "agbcc",
    "devkitarm-gcc",
    "devkitppc-gcc",
    "devkita64-gcc",
    "gcc-<major>",
    "clang-<major>",
    "msvc-10",
    "msvc-11",
    "msvc-12",
    "msvc-13",
    "msvc-13.1",
    "msvc-14",
    "msvc-15",
    "msvc-16",
    "mingw-gcc-<major>",
    UNKNOWN,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_overlay_the_detectors_know_nothing_about_takes_the_compilers_of_its_containers_earlier_image() {
        use crate::native::{Mapping, NativeImport};
        let overlay = |language: &str| NativeImport {
            language: language.into(),
            format: "nds".into(),
            mappings: vec![Mapping { vaddr: 0x0200_0000, size: 4, file_off: 0, flags: 5, bytes: vec![0; 4] }],
            ..Default::default()
        };
        let earlier = vec![("ARM:LE:32:v5t".to_string(), Detection::found("mwcc-arm", Confidence::Medium, vec!["banner".into()]))];
        let inherited = identify_in_container(&overlay("ARM:LE:32:v5t"), &earlier);
        assert_eq!(inherited.id, "mwcc-arm");
        assert_eq!(inherited.confidence, Confidence::Low);
        // The ARM7 binary is another processor: nothing says it shares the ARM9's compiler.
        assert!(identify_in_container(&overlay("ARM:LE:32:v4t"), &earlier).is_unknown());
        // `--compiler` is the user's word and is never replaced by an inheritance.
        let mut told = overlay("ARM:LE:32:v5t");
        told.cfg.compiler = Some("agbcc".into());
        assert_eq!(identify_in_container(&told, &earlier).id, "agbcc");
    }

    #[test]
    fn an_id_is_covered_by_its_family_and_by_nothing_it_merely_ends_with() {
        assert!(covers("ee-gcc", "ee-gcc-2.9x"));
        assert!(covers("ee-gcc-2.9x", "ee-gcc-2.9x"));
        assert!(!covers("gcc", "ee-gcc-2.9x"));
        assert!(!covers("gcc", "devkitarm-gcc"));
        assert!(covers("gcc", "gcc-4"));
        assert!(covers("*", "agbcc"));
        assert!(!covers("*", UNKNOWN));
        assert_eq!(family_of("ee-gcc-3.x"), "ee-gcc");
        assert_eq!(family_of("msvc-16"), "msvc");
        assert_eq!(family_of("something-new"), "something-new");
    }
}
