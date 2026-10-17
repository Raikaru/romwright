//! Compiler identification for PlayStation 2 executables, as `new-project`
//! needs it: the shared detector's verdict (`crate::compiler::ps2`, the same
//! one the importer records in `programs.compiler`) plus the manifest
//! vocabulary a scaffolded project is written with (splat's `compiler:`
//! name, the toolchain-profile kind, a suggested pinned compiler).

use serde::Serialize;

use super::elf::Elf32;
use crate::compiler::detect::ImageFacts;
pub use crate::compiler::{ps2::CompilerFamily, Confidence};

#[derive(Debug, Clone, Serialize)]
pub struct Ps2CompilerDetection {
    pub family: CompilerFamily,
    /// Human text, e.g. `MWCC PS2 (linker stamp 2.4.1.01)`; empty when nothing names a version.
    pub version: String,
    /// Stable key for the version evidence: `mwcc-2.3`, `mwcc-2.4`,
    /// `gcc-3.2`, `gcc-2.9-ee`, `gcc-2.95-2.96`, `sn-prodg`, or empty.
    pub version_class: String,
    pub confidence: Confidence,
    pub evidence: Vec<String>,
    /// splat's `compiler:` option.
    pub splat_compiler: &'static str,
    /// Toolchain-profile kind: `mwcc-ps2` or `ee-gcc`.
    pub profile_kind: &'static str,
    /// Id of the pinned-manifest compiler this evidence points at. A default
    /// for the version class, not a statement about the exact build.
    pub suggested_tool: &'static str,
}

/// Identifies the toolchain behind a PS2 ELF. Never fails: an image nothing
/// recognises comes back `Unknown` with the evidence list explaining why.
/// The family verdict is the shared detector's (`crate::compiler::ps2`); this
/// adds the manifest vocabulary `new-project` writes.
pub fn detect_ps2_compiler(image: &[u8]) -> Ps2CompilerDetection {
    let elf = Elf32::parse(image).ok();
    let mut facts = match &elf {
        Some(elf) => ImageFacts::from_elf(
            image,
            elf.sections.iter().map(|s| (s.name.as_str(), s.sh_type, u64::from(s.offset), u64::from(s.size))),
        ),
        None => ImageFacts::default(),
    };
    // Byte-string evidence works on section-stripped images too, whatever
    // the ELF header says about the machine.
    facts.scan_file_stamps(image);
    let symbols: Vec<String> = elf.iter().flat_map(|elf| elf.symbols()).map(|symbol| symbol.name).collect();
    let verdict = crate::compiler::ps2::classify(&facts, symbols.iter().map(String::as_str));
    let (family, confidence, evidence) = (verdict.family, verdict.confidence, verdict.evidence);
    let (mwcc_stamp_value, gcc_version) = (verdict.mwcc_stamp, verdict.gcc_version);
    let has = |name: &str| facts.has(name);

    let (version, version_class, suggested_tool) = match family {
        CompilerFamily::MwccPs2 => match mwcc_stamp_value.as_deref() {
            Some(stamp) if stamp.starts_with("2.3.") => (
                format!("MWCC PS2 2.3.x (linker stamp {stamp})"),
                "mwcc-2.3",
                "mwcps2-2.3.3-000906",
            ),
            Some(stamp) => (
                format!("MWCC PS2 2.4 - 3.0.x (linker stamp {stamp})"),
                "mwcc-2.4",
                "mwcps2-3.0.1b210-060308",
            ),
            None => ("MWCC PS2".to_string(), "mwcc", "mwcps2-3.0.1b210-060308"),
        },
        CompilerFamily::SnProdg => (
            "SN ProDG (gcc 2.95-based)".to_string(),
            "sn-prodg",
            "ee-gcc2.95.3-136",
        ),
        CompilerFamily::EeGcc => match gcc_version.as_deref() {
            Some(v) if v.starts_with("3.") => (format!("GNU gcc {v} (EE)"), "gcc-3.2", "ee-gcc3.2-030926"),
            Some(v) => (format!("GNU gcc {v} (EE)"), "gcc-2.9x", "ee-gcc2.96"),
            None if has(".mdebug") => (
                "EE GCC 2.9-ee era (ECOFF .mdebug)".to_string(),
                "gcc-2.9-ee",
                "ee-gcc2.9-991111",
            ),
            None if has(".mdebug.eabi64") => (
                "EE GCC 2.95 - 2.96 era (.mdebug.eabi64)".to_string(),
                "gcc-2.95-2.96",
                "ee-gcc2.96",
            ),
            None => (
                "EE GCC 2.9x era (no debug section, no version string)".to_string(),
                "gcc-2.9x",
                "ee-gcc2.95.2-273a",
            ),
        },
        CompilerFamily::Unknown => (String::new(), "", "mwcps2-3.0.1b210-060308"),
    };
    let (splat_compiler, profile_kind) = match family {
        CompilerFamily::MwccPs2 => ("MWCCPS2", "mwcc-ps2"),
        // splat has no SN ProDG preset; ProDG is a gcc 2.95 derivative and
        // the decomp projects that use it configure splat as EEGCC.
        CompilerFamily::EeGcc | CompilerFamily::SnProdg => ("EEGCC", "ee-gcc"),
        // Most PS2 retail code is ee-gcc; an unidentified image gets the
        // majority default, and the Low confidence says it is a default.
        CompilerFamily::Unknown => ("EEGCC", "ee-gcc"),
    };
    let suggested_tool = if family == CompilerFamily::Unknown { "ee-gcc2.96" } else { suggested_tool };
    Ps2CompilerDetection {
        family,
        version,
        version_class: version_class.to_string(),
        confidence,
        evidence,
        splat_compiler,
        profile_kind,
        suggested_tool,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal ELF32 LE with the named sections (type, bytes).
    fn image(sections: &[(&str, u32, &[u8])]) -> Vec<u8> {
        let mut data = vec![0u8; 0x34];
        data[..4].copy_from_slice(b"\x7fELF");
        data[4] = 1;
        data[5] = 1;
        let mut names = vec![0u8];
        let mut rows = vec![[0u32; 10]];
        let mut blobs: Vec<(u32, usize)> = vec![(0, 0)];
        for (name, sh_type, bytes) in sections {
            let name_at = names.len() as u32;
            names.extend_from_slice(name.as_bytes());
            names.push(0);
            let offset = data.len() as u32;
            data.extend_from_slice(bytes);
            rows.push([name_at, *sh_type, 0, 0, offset, bytes.len() as u32, 0, 0, 0, 0]);
            blobs.push((offset, bytes.len()));
        }
        let shstr_name = names.len() as u32;
        names.extend_from_slice(b".shstrtab\0");
        let names_at = data.len() as u32;
        data.extend_from_slice(&names);
        rows.push([shstr_name, 3, 0, 0, names_at, names.len() as u32, 0, 0, 0, 0]);
        let shoff = data.len() as u32;
        for row in &rows {
            for word in row {
                data.extend_from_slice(&word.to_le_bytes());
            }
        }
        data[0x20..0x24].copy_from_slice(&shoff.to_le_bytes());
        data[0x2e..0x30].copy_from_slice(&40u16.to_le_bytes());
        data[0x30..0x32].copy_from_slice(&(rows.len() as u16).to_le_bytes());
        data[0x32..0x34].copy_from_slice(&((rows.len() - 1) as u16).to_le_bytes());
        data
    }

    #[test]
    fn metrowerks_comment_is_high_confidence_and_classed_by_stamp() {
        let elf = image(&[
            ("main", 1, b"\0\0\0\0"),
            ("heap", 1, b""),
            (".comment", 1, b"MW MIPS C Compiler (2.3.1.01)\0PlayStation2\0"),
        ]);
        let found = detect_ps2_compiler(&elf);
        assert_eq!(found.family, CompilerFamily::MwccPs2);
        assert_eq!(found.confidence, Confidence::High);
        assert_eq!(found.version_class, "mwcc-2.3");
        assert_eq!(found.splat_compiler, "MWCCPS2");
        let later = detect_ps2_compiler(&image(&[(".comment", 1, b"MW MIPS C Compiler (2.4.1.01)\0")]));
        assert_eq!(later.version_class, "mwcc-2.4");
    }

    #[test]
    fn gnu_stamp_and_sony_sections_mean_ee_gcc() {
        let elf = image(&[
            (".text", 1, b"\0\0\0\0"),
            (".mdebug", 1, b"x"),
            (".vutext", 1, b""),
            (".comment", 1, b"\0GCC: (GNU) 3.2.2\0"),
        ]);
        let found = detect_ps2_compiler(&elf);
        assert_eq!(found.family, CompilerFamily::EeGcc);
        assert_eq!(found.version_class, "gcc-3.2");
        assert_eq!(found.splat_compiler, "EEGCC");
    }

    #[test]
    fn sndata_marks_sn_prodg_and_ecoff_without_stamp_marks_the_2_9_era() {
        let sn = image(&[(".text", 1, b""), (".sndata", 1, b""), (".mdebug.eabi64", 1, b"")]);
        assert_eq!(detect_ps2_compiler(&sn).family, CompilerFamily::SnProdg);
        let era = image(&[(".text", 1, b""), (".mdebug", 1, b""), (".lit4", 1, b""), (".vutext", 1, b"")]);
        let found = detect_ps2_compiler(&era);
        assert_eq!((found.family, found.version_class.as_str()), (CompilerFamily::EeGcc, "gcc-2.9-ee"));
    }

    #[test]
    fn nothing_recognisable_is_unknown_with_low_confidence() {
        let found = detect_ps2_compiler(&image(&[(".text", 1, b"")]));
        assert_eq!(found.family, CompilerFamily::Unknown);
        assert_eq!(found.confidence, Confidence::Low);
        assert_eq!(found.splat_compiler, "EEGCC");
    }
}
