//! Compiler identification for PlayStation 2 executables.
//!
//! The question is "which toolchain linked this image". PS2 images are
//! mixed: a Metrowerks game links Sony's ee-gcc-built SDK libraries, so a
//! symbol such as `gcc2_compiled.` says nothing on its own. Evidence is
//! therefore taken from what the *linker* writes into the image, strongest
//! first:
//!
//! 1. `.comment`: `MW MIPS C Compiler (x.y.z.w)` is the Metrowerks linker's
//!    stamp, `GCC: (GNU) x.y.z` is a GNU toolchain's.
//! 2. Section vocabulary: `.mwcats`, `main`/`heap`/`.relmain` are `mwldps2`
//!    output; `.mdebug`, `.vutext`, `.DVP.*`, `.lit4` belong to the Sony
//!    ee-gcc/ee-ld toolchain, `.sndata` to SN Systems' ProDG.
//! 3. Symbol names, when the image has a symbol table: runtime helpers only
//!    one family emits (`__register_global_object`, `__do_global_ctors`).
//!
//! Version evidence is much thinner than family evidence and is reported as a
//! *class* with the evidence behind it, never as a proven build: the MWCC
//! linker stamp names the linker (`2.3.1.01`, `2.4.1.01`), not the compiler
//! build, and ee-gcc images carry no version string at all unless `.comment`
//! survives.
//!
//! The scoring lives here, not in `new_project`, so `new-project`'s manifest
//! suggestion and the importer's `programs.compiler` read one detector.

use serde::Serialize;

use super::detect::{gcc_stamp, mwcc_stamp, ImageFacts};
use super::Confidence;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CompilerFamily {
    MwccPs2,
    EeGcc,
    SnProdg,
    Unknown,
}

impl CompilerFamily {
    pub fn id(self) -> &'static str {
        match self {
            CompilerFamily::MwccPs2 => "mwcc-ps2",
            CompilerFamily::EeGcc => "ee-gcc",
            CompilerFamily::SnProdg => "sn-prodg",
            CompilerFamily::Unknown => "unknown",
        }
    }
}

#[derive(Default)]
struct Score {
    mwcc: i32,
    gcc: i32,
    sn: i32,
}

/// The verdict before `new-project` attaches its manifest vocabulary.
#[derive(Debug, Clone)]
pub struct Ps2Verdict {
    pub family: CompilerFamily,
    pub confidence: Confidence,
    pub evidence: Vec<String>,
    /// The Metrowerks linker stamp (`2.4.1.01`), when one was read.
    pub mwcc_stamp: Option<String>,
    /// The GNU stamp's version (`3.2.2`), when one was read.
    pub gcc_version: Option<String>,
}

impl Ps2Verdict {
    /// The canonical compiler id: `mwcc-ps2-2.3` / `mwcc-ps2-2.4` (by the
    /// Metrowerks linker stamp, `2.3.x` for CodeWarrior PS2 2.3, `2.4.x` for
    /// 3.0 and later; `mwcc-ps2` when no stamp survived), `ee-gcc-2.9x`,
    /// `ee-gcc-3.x`, `sn-prodg` or `unknown`.
    pub fn canonical_id(&self) -> &'static str {
        match self.family {
            CompilerFamily::MwccPs2 => match self.mwcc_stamp.as_deref() {
                Some(stamp) if stamp.starts_with("2.3.") => "mwcc-ps2-2.3",
                Some(_) => "mwcc-ps2-2.4",
                None => "mwcc-ps2",
            },
            CompilerFamily::SnProdg => "sn-prodg",
            CompilerFamily::EeGcc => match self.gcc_version.as_deref() {
                Some(version) if version.starts_with("3.") => "ee-gcc-3.x",
                _ => "ee-gcc-2.9x",
            },
            CompilerFamily::Unknown => "unknown",
        }
    }
}

/// Identifies the toolchain behind a PS2 image from what `facts` read of it
/// and the symbol names it carries. Never fails: an image nothing recognises
/// comes back `Unknown` with the evidence list explaining why.
pub fn classify<'a>(facts: &ImageFacts, symbols: impl IntoIterator<Item = &'a str>) -> Ps2Verdict {
    let mut score = Score::default();
    let mut evidence = Vec::new();
    let mut mwcc_stamp_value = None;
    let mut gcc_version = None;
    let mut mwcc_symbols = 0usize;
    let mut gcc_symbols = 0usize;

    if facts.parsed_elf {
        if let Some(stamp) = mwcc_stamp(&facts.comment) {
            score.mwcc += 10;
            evidence.push(format!(".comment: Metrowerks linker stamp `MW MIPS C Compiler ({stamp})`"));
            mwcc_stamp_value = Some(stamp);
        }
        if let Some(version) = gcc_stamp(&facts.comment) {
            score.gcc += 10;
            evidence.push(format!(".comment: `GCC: (GNU) {version}`"));
            gcc_version = Some(version);
        }
        if facts.has(".mwcats") {
            score.mwcc += 6;
            let types: std::collections::BTreeSet<String> = facts
                .sections
                .iter()
                .filter(|(name, _)| name == ".mwcats")
                .map(|(_, sh_type)| format!("{sh_type:#x}"))
                .collect();
            evidence.push(format!(
                ".mwcats section(s), sh_type {}",
                types.into_iter().collect::<Vec<_>>().join("/")
            ));
        }
        if facts.has("main") && facts.has("heap") {
            score.mwcc += 5;
            evidence.push("section names `main` + `heap` (mwldps2 output layout)".into());
        }
        if facts.has(".relmain") {
            score.mwcc += 2;
            evidence.push("`.relmain` relocation section (mwldps2 -rel output)".into());
        }
        if facts.has(".debug") && facts.has(".line") {
            score.mwcc += 2;
            evidence.push("DWARF 1 `.debug` + `.line` (Metrowerks debug format)".into());
        }
        if facts.has(".mdebug") || facts.has(".mdebug.eabi64") {
            score.gcc += 3;
            evidence.push(format!(
                "`{}` ECOFF debug section (GNU toolchain)",
                if facts.has(".mdebug") { ".mdebug" } else { ".mdebug.eabi64" }
            ));
        }
        if facts.has(".vutext") || facts.has_prefix(".DVP.") {
            score.gcc += 2;
            evidence.push("`.vutext`/`.DVP.*` sections (Sony ee-ld/dvp-as output)".into());
        }
        if facts.has(".lit4") || facts.has(".lit8") || facts.has(".lit") {
            score.gcc += 2;
            evidence.push("`.lit*` literal-pool sections (GNU MIPS output)".into());
        }
        if facts.has(".sndata") {
            score.sn += 8;
            score.gcc += 2;
            evidence.push("`.sndata` section (SN Systems ProDG small data)".into());
        }
        if facts.has(".ctors") || facts.has(".dtors") || facts.has(".gcc_except_table") {
            score.gcc += 1;
            evidence.push("`.ctors`/`.dtors`/`.gcc_except_table` (GNU C++ runtime sections)".into());
        }
        for name in symbols {
            match name {
                "__register_global_object" | "__initialize_cpp_rts" | "__construct_array"
                | "__destroy_arr" | "__ptmf_scall" => mwcc_symbols += 1,
                "__do_global_ctors" | "__do_global_dtors" | "__builtin_vec_new" | "__start_cp_handler"
                | "__gccmain" | "__main" => gcc_symbols += 1,
                _ => {}
            }
        }
        if mwcc_symbols > 0 {
            score.mwcc += 3;
            evidence.push(format!("{mwcc_symbols} Metrowerks runtime symbol(s) (`__register_global_object`, ...)"));
        }
        if gcc_symbols > 0 {
            score.gcc += 3;
            evidence.push(format!("{gcc_symbols} libgcc/crtstuff symbol(s) (`__do_global_ctors`, ...)"));
        }
    } else {
        evidence.push("not a parseable ELF32: only byte-string evidence is available".into());
    }

    // Byte-string evidence works on section-stripped images too. A GNU
    // stamp or the Metrowerks stamp anywhere in the file counts, but weaker
    // than the `.comment` section itself (already scored above).
    if score.mwcc == 0 {
        if let Some(stamp) = &facts.file_mwcc_stamp {
            score.mwcc += 6;
            evidence.push(format!("string `MW MIPS C Compiler ({stamp})` in the image"));
            mwcc_stamp_value = Some(stamp.clone());
        } else if facts.file_mw_gas {
            score.mwcc += 4;
            evidence.push("string `Metrowerks MW GAS R5900 Assembler` in the image".into());
        }
    }
    if score.gcc == 0
        && let Some(version) = &facts.file_gcc_stamp {
            score.gcc += 6;
            evidence.push(format!("string `GCC: (GNU) {version}` in the image"));
            gcc_version = Some(version.clone());
        }

    let sn = score.sn >= 8;
    let (family, top, second) = if sn {
        (CompilerFamily::SnProdg, score.sn + score.gcc, score.mwcc)
    } else if score.mwcc > score.gcc {
        (CompilerFamily::MwccPs2, score.mwcc, score.gcc)
    } else if score.gcc > score.mwcc {
        (CompilerFamily::EeGcc, score.gcc, score.mwcc)
    } else {
        (CompilerFamily::Unknown, 0, 0)
    };
    let confidence = if family == CompilerFamily::Unknown || top < 4 {
        Confidence::Low
    } else if top >= 8 && top - second >= 6 {
        Confidence::High
    } else {
        Confidence::Medium
    };
    let family = if family != CompilerFamily::Unknown && top < 3 { CompilerFamily::Unknown } else { family };
    Ps2Verdict { family, confidence, evidence, mwcc_stamp: mwcc_stamp_value, gcc_version }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn comment(text: &[u8]) -> ImageFacts {
        ImageFacts { parsed_elf: true, comment: text.to_vec(), sections: vec![(".comment".into(), 1)], ..Default::default() }
    }

    #[test]
    fn the_metrowerks_stamp_picks_the_version_class_of_the_id() {
        let id = |text: &[u8]| classify(&comment(text), std::iter::empty::<&str>()).canonical_id();
        // The stamp of Dark Cloud (CodeWarrior PS2 2.3.3) and of Dark Chronicle / Persona 4 (3.0.x).
        assert_eq!(id(b"MW MIPS C Compiler (2.3.1.01)\0"), "mwcc-ps2-2.3");
        assert_eq!(id(b"MW MIPS C Compiler (2.4.1.01)\0"), "mwcc-ps2-2.4");
        // Metrowerks sections without a surviving stamp name the family and no class.
        let sections = ImageFacts {
            parsed_elf: true,
            sections: vec![(".mwcats".into(), 1), ("main".into(), 1), ("heap".into(), 1)],
            ..Default::default()
        };
        assert_eq!(classify(&sections, std::iter::empty::<&str>()).canonical_id(), "mwcc-ps2");
    }
}
