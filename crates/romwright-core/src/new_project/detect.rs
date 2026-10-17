//! Compiler detection for the splat-based MIPS platforms other than the
//! PlayStation 2: Nintendo 64 (IDO vs the GCC family), PlayStation (the PSY-Q
//! library generation) and PSP (Metrowerks vs psp-gcc).
//!
//! Each verdict names a *family*, a version *class*, a confidence, the evidence
//! and the manifest compiler it points at. The family is evidence the bytes
//! carry; the manifest compiler is a default for that class, never a claim
//! about the exact build, and the README of a generated project says so.
//! The N64 and PSP family rules are the importer's (`crate::compiler::detect`),
//! measured over the corpus there; this adds the version vocabulary and the
//! PSY-Q rule, which the importer does not have.

use serde::Serialize;

use super::elf::Elf32;
use crate::compiler::detect::{find, gcc_stamp, mwcc_stamp, ImageFacts};
pub use crate::compiler::Confidence;

#[derive(Debug, Clone, Serialize)]
pub struct MipsDetection {
    /// `ido`, `gcc`, `psyq`, `mwcc-psp`, `psp-gcc` or `unknown`.
    pub family: &'static str,
    /// Human text; empty when nothing names a version.
    pub version: String,
    /// Stable key of the version evidence (`ido`, `gcc`, `psyq-3.x`, ...); empty when none.
    pub version_class: &'static str,
    pub confidence: Confidence,
    pub evidence: Vec<String>,
    /// splat's `compiler:` option.
    pub splat_compiler: &'static str,
    /// Id of the pinned-manifest compiler this evidence points at (a default for the class).
    pub suggested_tool: &'static str,
}

// ----------------------------------------------------------------------- N64

/// `move` is `or rd,rs,$zero` under IDO and `addu rd,rs,$zero` under the GCC
/// family (KMC, pmret's gcc 2.8.1). Over the nine corpus ROMs the `or` share is
/// 0.866-0.994 for every IDO game and 0.000-0.033 for both GCC games.
const N64_MIN_MOVES: u64 = 50;
const N64_IDO_SHARE: f64 = 0.75;
const N64_GCC_SHARE: f64 = 0.25;

/// `code` are `(file offset, size)` ranges that are raw code in the ROM.
pub fn detect_n64(image: &[u8], code: &[(u64, u64)]) -> MipsDetection {
    let (mut or, mut addu) = (0u64, 0u64);
    for &(offset, size) in code {
        let end = (offset + size).min(image.len() as u64) as usize;
        let Some(bytes) = image.get(offset as usize..end) else { continue };
        for word in bytes.as_chunks::<4>().0 {
            let w = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
            // SPECIAL, rs != 0, rt == 0, rd != 0, shamt == 0
            if w >> 26 == 0 && (w >> 16) & 31 == 0 && (w >> 21) & 31 != 0 && (w >> 11) & 31 != 0 && (w >> 6) & 31 == 0 {
                match w & 63 {
                    0x25 => or += 1,
                    0x21 => addu += 1,
                    _ => {}
                }
            }
        }
    }
    let total = or + addu;
    let share = if total == 0 { 0.0 } else { or as f64 / total as f64 };
    let line = format!("`move` is `or rd,rs,$zero` {or} times and `addu rd,rs,$zero` {addu} times (or-share {share:.3}) in the raw code");
    if total >= N64_MIN_MOVES && share >= N64_IDO_SHARE {
        MipsDetection {
            family: "ido",
            version: "IDO (5.3 and 7.1 emit the same `move`; 5.3 is the default)".into(),
            version_class: "ido",
            confidence: Confidence::Medium,
            evidence: vec![line],
            splat_compiler: "IDO",
            suggested_tool: "ido5.3",
        }
    } else if total >= N64_MIN_MOVES && share <= N64_GCC_SHARE {
        MipsDetection {
            family: "gcc",
            version: "GCC family (2.7.2 KMC / 2.8.1; 2.7.2 is the default)".into(),
            version_class: "gcc",
            confidence: Confidence::Medium,
            evidence: vec![line],
            splat_compiler: "GCC",
            suggested_tool: "gcc2.7.2kmc",
        }
    } else {
        MipsDetection {
            family: "unknown",
            version: String::new(),
            version_class: "",
            confidence: Confidence::Low,
            evidence: vec![line, "too few moves, or a share between the bands: no family claimed (IDO is the default)".into()],
            splat_compiler: "IDO",
            suggested_tool: "ido5.3",
        }
    }
}

// ----------------------------------------------------------------------- PSX

/// `$Id: sys.c,v 1.140 1998/01/12 07:52:27 noda Exp $` (a Sony library
/// revision stamp) -> `(revision, year, month)`.
fn libsys_stamp(image: &[u8]) -> Option<(String, u32, u32)> {
    let at = find(image, b"$Id: sys.c,v ")?;
    let rest = image.get(at + b"$Id: sys.c,v ".len()..(at + 80).min(image.len()))?;
    let text = String::from_utf8_lossy(rest);
    let mut parts = text.split_whitespace();
    let revision = parts.next()?.to_string();
    let mut date = parts.next()?.split('/');
    let year = date.next()?.parse().ok()?;
    let month = date.next()?.parse().ok()?;
    Some((revision, year, month))
}

/// PSY-Q's libraries carry no version string, but each links Sony's CVS `$Id$`
/// stamps; the date of `libsys`'s `sys.c` bounds the SDK release the game built
/// against (a 1998-01 `sys.c` is in every 4.x SDK this was compared with). The
/// class is a window, not a build: the importer measures no byte-level tell for
/// the compiler itself ("Psy-Q GCC and CodeWarrior images share the library strings").
pub fn detect_psx(image: &[u8]) -> MipsDetection {
    match libsys_stamp(image) {
        Some((revision, year, month)) => {
            let (class, tool, version) = if year <= 1996 {
                ("psyq-3.x", "psyq3.5", "PSY-Q 3.x era (libsys of 1996 or earlier)")
            } else if year == 1997 {
                ("psyq-3.6-4.0", "psyq4.0", "PSY-Q 3.6 - 4.0 era (libsys of 1997)")
            } else {
                ("psyq-4.x", "psyq4.3", "PSY-Q 4.x era (libsys of 1998 or later)")
            };
            MipsDetection {
                family: "psyq",
                version: version.into(),
                version_class: class,
                confidence: Confidence::Low,
                evidence: vec![format!("`$Id: sys.c,v {revision} {year}/{month:02}` (Sony libsys revision stamp) dates the library generation")],
                splat_compiler: "PSYQ",
                suggested_tool: tool,
            }
        }
        None => MipsDetection {
            family: "unknown",
            version: String::new(),
            version_class: "",
            confidence: Confidence::Low,
            evidence: vec!["no Sony libsys `$Id: sys.c` stamp: no PSY-Q generation claimed (psyq4.3 is the default)".into()],
            splat_compiler: "PSYQ",
            suggested_tool: "psyq4.3",
        },
    }
}

// ----------------------------------------------------------------------- PSP

pub fn detect_psp(image: &[u8]) -> MipsDetection {
    let elf = Elf32::parse(image).ok();
    let mut facts = match &elf {
        Some(elf) => ImageFacts::from_elf(
            image,
            elf.sections.iter().map(|s| (s.name.as_str(), s.sh_type, u64::from(s.offset), u64::from(s.size))),
        ),
        None => ImageFacts::default(),
    };
    facts.scan_file_stamps(image);
    let mwcc = |family_tool: (&'static str, &'static str), confidence, evidence: Vec<String>| MipsDetection {
        family: family_tool.0,
        version: if family_tool.0 == "mwcc-psp" { "Metrowerks CodeWarrior for PSP".into() } else { "GNU C for the Allegrex (psp-gcc)".into() },
        version_class: family_tool.0,
        confidence,
        evidence,
        splat_compiler: "GCC",
        suggested_tool: family_tool.1,
    };
    const MW: (&str, &str) = ("mwcc-psp", "mwccpsp-3.0.1-219");
    const GCC: (&str, &str) = ("psp-gcc", "psp-gcc-1.7.1");
    if let Some(stamp) = mwcc_stamp(&facts.comment).or_else(|| facts.file_mwcc_stamp.clone()) {
        return mwcc(MW, Confidence::High, vec![format!("`MW MIPS C Compiler ({stamp})` stamp")]);
    }
    if let Some(version) = gcc_stamp(&facts.comment).or_else(|| facts.file_gcc_stamp.clone()) {
        return mwcc(GCC, Confidence::High, vec![format!("`GCC: (GNU) {version}` stamp on a PSP image")]);
    }
    if facts.has(".gcc_compiled_long32") {
        return mwcc(GCC, Confidence::High, vec!["`.gcc_compiled_long32` section (GCC's own marker)".into()]);
    }
    if facts.has(".mwcats") {
        return mwcc(MW, Confidence::Medium, vec!["`.mwcats` section (CodeWarrior)".into()]);
    }
    if facts.has(".mdebug.eabi32") {
        return mwcc(GCC, Confidence::Medium, vec!["`.mdebug.eabi32` ECOFF debug section (GNU linker output)".into()]);
    }
    if facts.has(".debug") && facts.has(".line") {
        return mwcc(MW, Confidence::Medium, vec!["DWARF 1 `.debug` + `.line` sections without a GNU ECOFF section (CodeWarrior)".into()]);
    }
    if find(image, b"Metrowerks::").is_some() {
        return mwcc(MW, Confidence::Low, vec!["Metrowerks Standard Library symbol names in the image".into()]);
    }
    let mut unknown = mwcc(GCC, Confidence::Low, vec!["no linker stamp, section vocabulary or library name identified a compiler (psp-gcc is the default)".into()]);
    unknown.family = "unknown";
    unknown.version = String::new();
    unknown.version_class = "";
    unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn n64_family_follows_the_move_spelling() {
        let word = |op: u32| ((4u32 << 21) | (5 << 11) | op).to_be_bytes();
        let ido: Vec<u8> = (0..100).flat_map(|_| word(0x25)).collect();
        let gcc: Vec<u8> = (0..100).flat_map(|_| word(0x21)).collect();
        assert_eq!(detect_n64(&ido, &[(0, 400)]).family, "ido");
        assert_eq!(detect_n64(&gcc, &[(0, 400)]).family, "gcc");
        assert_eq!(detect_n64(&gcc, &[(0, 40)]).family, "unknown");
    }

    #[test]
    fn psx_generation_comes_from_the_libsys_stamp() {
        let image = b"....$Id: sys.c,v 1.140 1998/01/12 07:52:27 noda Exp $....";
        let found = detect_psx(image);
        assert_eq!((found.family, found.version_class, found.suggested_tool), ("psyq", "psyq-4.x", "psyq4.3"));
        let old = detect_psx(b"$Id: sys.c,v 1.120 1996/05/01 12:09:07 noda Exp $");
        assert_eq!(old.version_class, "psyq-3.x");
        assert_eq!(detect_psx(b"nothing").family, "unknown");
    }
}
