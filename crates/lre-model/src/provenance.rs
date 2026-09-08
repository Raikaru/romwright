//! What each provenance class means, in one sentence, in one place.
//!
//! A fact's `source` names the pass that produced it. Every surface -- the
//! API, the CLI, the desktop -- reads these sentences instead of keeping its
//! own mapping, so a class cannot mean one thing in a window and another on a
//! terminal. `tests/m9-001_provenance_explained.py` fails when a class the
//! crates can emit has no entry here.

/// What kind of evidence a class rests on. These are the only three the
/// importer has, and the distinction is what a consumer needs to rank two
/// facts that disagree: the image said so, the decoder proved it, or a pass
/// concluded it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    /// The image or the platform states it: a header, a directory, a
    /// relocation table, a declared memory map.
    Declared,
    /// SLEIGH decoded the instruction that performs it.
    Decoded,
    /// A pass concluded it from decoded code; the corpus gates score it.
    Inferred,
}

impl EvidenceKind {
    /// The kind named by a request, or `None` -- a caller asking for a kind
    /// that does not exist is refused, never answered with an empty page.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "declared" => Some(Self::Declared),
            "decoded" => Some(Self::Decoded),
            "inferred" => Some(Self::Inferred),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Declared => "declared",
            Self::Decoded => "decoded",
            Self::Inferred => "inferred",
        }
    }
}

/// One provenance class: its sentence, what kind of evidence it is, and
/// whether anything derives a number for it. A class that derives no number
/// carries `confidence: null` rather than a figure nobody computed.
pub struct Class {
    pub source: &'static str,
    pub explanation: &'static str,
    pub evidence: EvidenceKind,
    pub derives_confidence: bool,
}

/// Every provenance class and the evidence behind it.
pub const CLASSES: &[Class] = &[
    Class {
        source: "native-import",
        explanation:         "Read from the image's own headers by the native loader: a section, an \
         entry point, or a symbol the file declares.",
        evidence: EvidenceKind::Declared,
        derives_confidence: false,
    },
    Class {
        source: "native-import:branch",
        explanation:         "A transfer of control the SLEIGH decoder proved by decoding the \
         instruction that performs it.",
        evidence: EvidenceKind::Decoded,
        derives_confidence: false,
    },
    Class {
        source: "native-import:known-name",
        explanation:         "A function whose name is on the list Ghidra ships of functions that \
         do not return (`Base/data/ElfFunctionsThatDoNotReturn`), matched the \
         way its own analyzer matches them.",
        evidence: EvidenceKind::Declared,
        derives_confidence: false,
    },
    Class {
        source: "native-import:type-archive",
        explanation:         "A declaration the pinned C library type archive holds for a name the \
         image imports, applied only when every type in it is one the \
         decompiler already has.",
        evidence: EvidenceKind::Declared,
        derives_confidence: false,
    },
    Class {
        source: "native-import:plt-reserved",
        explanation:         "A word the System V ABI reserves at DT_PLTGOT -- the .dynamic \
         address, the link-map, the resolver -- each of which holds a pointer.",
        evidence: EvidenceKind::Declared,
        derives_confidence: false,
    },
    Class {
        source: "ghidra-bridge:recovered-signature",
        explanation:         "A signature stock Ghidra says it recovered, exported by the Stage-1 \
         bridge with the source that says so; its own placeholder signature is \
         not recorded.",
        evidence: EvidenceKind::Decoded,
        derives_confidence: false,
    },
    Class {
        source: "native-analysis:data-width",
        explanation:         "How many bytes an instruction touches at a location, from the p-code \
         access that reaches it: a load's output, a store's value, or a \
         memory operand's own size.",
        evidence: EvidenceKind::Decoded,
        derives_confidence: false,
    },
    Class {
        source: "native-analysis:shared-return",
        explanation:         "An unconditional branch that leaves its own function for another \
         function's entry: the transfer is a call whose callee returns to this \
         function's caller, proved by decoding the branch.",
        evidence: EvidenceKind::Decoded,
        derives_confidence: false,
    },
    Class {
        source: "native-import:dynamic-tag",
        explanation:         "An address the image's own dynamic table names: the table itself, \
         or the target of a tag whose value is an address, labelled where \
         nothing else names it.",
        evidence: EvidenceKind::Declared,
        derives_confidence: false,
    },
    Class {
        source: "native-import:entry-convention",
        explanation:         "The address the operating system enters the process at, carrying \
         the platform's process-entry model: an ELF executable or shared \
         object's e_entry under a Linux or unspecified OS ABI, where the \
         language declares such a model.",
        evidence: EvidenceKind::Declared,
        derives_confidence: false,
    },
    Class {
        source: "native-import:plt-header",
        explanation:         "An indirect transfer that reads the word the System V ABI reserves \
         for the dynamic linker's resolver (DT_PLTGOT plus two pointers), so it \
         behaves like a call.",
        evidence: EvidenceKind::Declared,
        derives_confidence: false,
    },
    Class {
        source: "native-import:thunk",
        explanation:         "A stub whose whole body transfers to another address, proved by \
         decoding it; the reference is the transfer it performs.",
        evidence: EvidenceKind::Decoded,
        derives_confidence: false,
    },
    Class {
        source: "native-import:elf-pointer",
        explanation:         "A pointer to code stored in ELF data, confirmed by decoding what it \
         points at rather than by its shape.",
        evidence: EvidenceKind::Inferred,
        derives_confidence: false,
    },
    Class {
        source: "native-import:elf-reloc",
        explanation:         "An ELF relocation: the loader will write this address into that slot, \
         so the linker named the target.",
        evidence: EvidenceKind::Declared,
        derives_confidence: false,
    },
    Class {
        source: "native-import:elf-unwind",
        explanation:         "An entry in the ELF `.eh_frame_hdr` index: the compiler recorded \
         unwind data for a function starting here.",
        evidence: EvidenceKind::Declared,
        derives_confidence: false,
    },
    Class {
        source: "native-import:elf-relocation-map",
        explanation:         "A relocation-masked signature match: the bytes agree once the \
         relocated fields are ignored.",
        evidence: EvidenceKind::Inferred,
        derives_confidence: true,
    },
    Class {
        source: "native-import:elf-pointer-table",
        explanation:         "A contiguous table of code pointers in ELF data, every entry of which \
         decoded as code.",
        evidence: EvidenceKind::Inferred,
        derives_confidence: false,
    },
    Class {
        source: "native-import:pe-reloc",
        explanation:         "A PE base relocation: the loader will rebase this slot, so the value \
         in it is an address rather than a number.",
        evidence: EvidenceKind::Declared,
        derives_confidence: false,
    },
    Class {
        source: "native-import:pe-unwind",
        explanation:         "A `RUNTIME_FUNCTION` record in the PE exception directory: the \
         compiler recorded unwind data for a function starting here.",
        evidence: EvidenceKind::Declared,
        derives_confidence: false,
    },
    Class {
        source: "native-import:pe-tls",
        explanation:         "A slot in the PE TLS callback array: the loader calls this address \
         before the entry point runs.",
        evidence: EvidenceKind::Declared,
        derives_confidence: false,
    },
    Class {
        source: "native-import:pe-export",
        explanation:         "A slot in the PE export directory: the image publishes this address \
         under the name recorded here.",
        evidence: EvidenceKind::Declared,
        derives_confidence: false,
    },
    Class {
        source: "native-import:platform-map",
        explanation:         "Declared by the platform rather than the file: a console's memory map \
         names this region, and the cartridge carries no header for it.",
        evidence: EvidenceKind::Declared,
        derives_confidence: false,
    },
    Class {
        source: "native-analysis",
        explanation:         "Derived by a native analysis pass over decoded instructions, not read \
         from the image.",
        evidence: EvidenceKind::Inferred,
        derives_confidence: false,
    },
    Class {
        source: "native-analysis:constant-propagation",
        explanation:         "A constant the decompiler propagated to this instruction: the address \
         is computed by the code, not stored in the image.",
        evidence: EvidenceKind::Inferred,
        derives_confidence: false,
    },
];

/// The class, or `None` when nothing here describes that source.
pub fn class(source: &str) -> Option<&'static Class> {
    CLASSES.iter().find(|entry| entry.source == source)
}

/// The sentence for a provenance class, or `None` when nothing explains it.
pub fn explain(source: &str) -> Option<&'static str> {
    class(source).map(|entry| entry.explanation)
}

/// What kind of evidence the class rests on, or `None` for an unknown source.
pub fn evidence(source: &str) -> Option<EvidenceKind> {
    class(source).map(|entry| entry.evidence)
}

/// Every class of one kind. A filter is built from this rather than from a
/// list kept beside it, so asking for `declared` cannot mean one set in a
/// query and another in the fact it returns.
pub fn sources(kind: EvidenceKind) -> Vec<&'static str> {
    CLASSES
        .iter()
        .filter(|entry| entry.evidence == kind)
        .map(|entry| entry.source)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_class_is_named_once_and_reads_as_a_sentence() {
        let mut seen = std::collections::HashSet::new();
        for entry in CLASSES {
            assert!(seen.insert(entry.source), "{} is explained twice", entry.source);
            assert!(
                entry.explanation.ends_with('.') && entry.explanation.len() > 40,
                "{} needs a sentence, not a label: {:?}",
                entry.source,
                entry.explanation
            );
        }
        assert_eq!(explain("native-import:invented"), None);
        assert_eq!(evidence("native-import:invented"), None);
    }

    #[test]
    fn a_declared_class_derives_no_number_and_a_derived_one_is_not_declared() {
        // A header either says a thing or it does not; there is nothing to be
        // partially confident about. A number belongs to a pass that computes
        // one -- today only the signature matcher's share of compared bytes.
        for entry in CLASSES {
            if entry.evidence == EvidenceKind::Declared {
                assert!(
                    !entry.derives_confidence,
                    "{} is declared, so a confidence would be invented",
                    entry.source
                );
            }
        }
        assert_eq!(evidence("native-import:pe-tls"), Some(EvidenceKind::Declared));
        assert_eq!(evidence("native-import:branch"), Some(EvidenceKind::Decoded));
        assert_eq!(
            evidence("native-analysis:constant-propagation"),
            Some(EvidenceKind::Inferred)
        );
    }
}
