//! What each provenance class means, in one sentence, in one place.
//!
//! A fact's `source` names the pass that produced it. Every surface -- the
//! API, the CLI, the desktop -- reads these sentences instead of keeping its
//! own mapping, so a class cannot mean one thing in a window and another on a
//! terminal. `tests/m9-001_provenance_explained.py` fails when a class the
//! crates can emit has no entry here.

/// Every provenance class and the evidence behind it.
pub const EXPLANATIONS: &[(&str, &str)] = &[
    (
        "native-import",
        "Read from the image's own headers by the native loader: a section, an \
         entry point, or a symbol the file declares.",
    ),
    (
        "native-import:branch",
        "A transfer of control the SLEIGH decoder proved by decoding the \
         instruction that performs it.",
    ),
    (
        "native-import:thunk",
        "A stub whose whole body transfers to another address, proved by \
         decoding it; the reference is the transfer it performs.",
    ),
    (
        "native-import:elf-pointer",
        "A pointer to code stored in ELF data, confirmed by decoding what it \
         points at rather than by its shape.",
    ),
    (
        "native-import:elf-reloc",
        "An ELF relocation: the loader will write this address into that slot, \
         so the linker named the target.",
    ),
    (
        "native-import:elf-unwind",
        "An entry in the ELF `.eh_frame_hdr` index: the compiler recorded \
         unwind data for a function starting here.",
    ),
    (
        "native-import:elf-relocation-map",
        "A relocation-masked signature match: the bytes agree once the \
         relocated fields are ignored.",
    ),
    (
        "native-import:elf-pointer-table",
        "A contiguous table of code pointers in ELF data, every entry of which \
         decoded as code.",
    ),
    (
        "native-import:pe-reloc",
        "A PE base relocation: the loader will rebase this slot, so the value \
         in it is an address rather than a number.",
    ),
    (
        "native-import:pe-unwind",
        "A `RUNTIME_FUNCTION` record in the PE exception directory: the \
         compiler recorded unwind data for a function starting here.",
    ),
    (
        "native-import:pe-tls",
        "A slot in the PE TLS callback array: the loader calls this address \
         before the entry point runs.",
    ),
    (
        "native-import:pe-export",
        "A slot in the PE export directory: the image publishes this address \
         under the name recorded here.",
    ),
    (
        "native-import:platform-map",
        "Declared by the platform rather than the file: a console's memory map \
         names this region, and the cartridge carries no header for it.",
    ),
    (
        "native-analysis",
        "Derived by a native analysis pass over decoded instructions, not read \
         from the image.",
    ),
    (
        "native-analysis:constant-propagation",
        "A constant the decompiler propagated to this instruction: the address \
         is computed by the code, not stored in the image.",
    ),
];

/// The sentence for a provenance class, or `None` when nothing explains it.
pub fn explain(source: &str) -> Option<&'static str> {
    EXPLANATIONS
        .iter()
        .find(|(name, _)| *name == source)
        .map(|(_, sentence)| *sentence)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_class_is_named_once_and_reads_as_a_sentence() {
        let mut seen = std::collections::HashSet::new();
        for (name, sentence) in EXPLANATIONS {
            assert!(seen.insert(*name), "{name} is explained twice");
            assert!(
                sentence.ends_with('.') && sentence.len() > 40,
                "{name} needs a sentence, not a label: {sentence:?}"
            );
        }
        assert_eq!(explain("native-import:pe-tls"), Some(EXPLANATIONS
            .iter()
            .find(|(name, _)| *name == "native-import:pe-tls")
            .unwrap()
            .1));
        assert_eq!(explain("native-import:invented"), None);
    }
}
