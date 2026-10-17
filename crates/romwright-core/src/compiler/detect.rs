//! Compiler detectors: one per platform family, each reading only what the
//! image's own bytes prove.
//!
//! The importer calls [`identify`] once per image, after the loader and the
//! linker MAP have supplied the symbols and before discovery, so a rule that
//! changes discovery can already see the compiler.
//!
//! What each detector reads, and the measurement behind its thresholds
//! (`benchmarks/compiler_detection_accuracy.py`, report
//! `benchmarks/reports/compiler_detection_accuracy.{json,md}`):
//!
//! | platform | evidence | ids |
//! |---|---|---|
//! | PS2 | linker `.comment`, section vocabulary, runtime symbols (`ps2`) | `mwcc-ps2`, `ee-gcc-2.9x`, `ee-gcc-3.x`, `sn-prodg` |
//! | PSP | `.comment` stamps, `.mwcats`, `.gcc_compiled_long32`, `.mdebug.eabi32`, DWARF 1 `.debug` + `.line` | `mwcc-psp`, `allegrex-gcc` |
//! | GameCube / Wii | SDK banner strings (`<< Dolphin SDK`, `<< RVL_SDK`), the Metrowerks TRK string, MWCC runtime symbols | `mwcc-gc`, `mwcc-wii` |
//! | NDS | the NitroSDK banner (`[SDK+NINTENDO:`) | `mwcc-arm` |
//! | GBA | how Thumb code returns: the agbcc mix of `pop {..,pc}` and `pop {rX}; bx rX`, or `bx` on every return (GCC 4+) | `agbcc`, `devkitarm-gcc` |
//! | N64 | how `move` is spelled: IDO `or rd,rs,$zero`, GCC `addu rd,rs,$zero` | `ido`, `n64-gcc` |
//! | Xbox 360 | the PE optional header's linker version | `msvc-14`, `msvc-15`, `msvc-16` |
//! | any ELF | `.comment`: `GCC: (devkitARM ...)`, `GCC: (GNU) x.y`, `clang version N` | `devkitarm-gcc`, `devkitppc-gcc`, `devkita64-gcc`, `gcc-<major>`, `clang-<major>` |
//!
//! PlayStation 1 is not here on purpose: Psy-Q GCC and CodeWarrior images
//! carry the same Sony library strings and the same `move` spelling, and the
//! code-shape features tried (load-delay `nop` rate, `$gp` traffic, branch
//! `nop` rate) did not separate the one CodeWarrior image from the seven GCC
//! ones. It stays [`UNKNOWN`](super::UNKNOWN) until a byte-level tell exists.

use crate::native::NativeImport;

use super::ps2;
use super::{Confidence, Detection};

/// Byte-level observations an ELF loader hands over: what `.comment` says,
/// which sections exist, and (MIPS images) the stamps found anywhere in the
/// file. Carried on the import so a detector never re-reads the file.
#[derive(Debug, Clone, Default)]
pub struct ImageFacts {
    /// True when the facts came from a parsed ELF section table.
    pub parsed_elf: bool,
    /// Section name and `sh_type`, in table order.
    pub sections: Vec<(String, u32)>,
    /// The `.comment` section's bytes (capped).
    pub comment: Vec<u8>,
    /// `MW MIPS C Compiler (x)` anywhere in the file (MIPS ELF only).
    pub file_mwcc_stamp: Option<String>,
    /// `GCC: (GNU) x` anywhere in the file (MIPS ELF only).
    pub file_gcc_stamp: Option<String>,
    /// `Metrowerks MW GAS R5900` anywhere in the file (MIPS ELF only).
    pub file_mw_gas: bool,
    /// PE optional header `MajorLinkerVersion`, `MinorLinkerVersion`.
    pub pe_linker: Option<(u8, u8)>,
    /// A `Rich` header sits between the DOS stub and the PE signature (Microsoft's linker, 5.0 and later).
    pub pe_rich: bool,
    /// The text of the commonest `GCC: (...) x.y.z` stamp anywhere in the file (PE images: every object's `.rdata$zzz`
    /// ident string, so the program's own objects outvote the older libraries).
    pub pe_gcc_stamp: Option<String>,
    /// The `Rich` header's entries: (product id, build number, object count), Microsoft's linker's record of every
    /// object and import library it combined and the tool that made each.
    pub pe_comp_ids: Vec<(u16, u16, u32)>,
    /// The C runtime DLL the image imports, lower-case (`msvcr71.dll`), when it names one.
    pub pe_crt_dll: Option<String>,
}

const COMMENT_CAP: usize = 64 * 1024;
const EM_MIPS: u16 = 8;

impl ImageFacts {
    /// Facts of an ELF image: `sections` are `(name, sh_type, offset, size)`
    /// rows of its section table.
    pub fn from_elf<'a>(data: &[u8], sections: impl IntoIterator<Item = (&'a str, u32, u64, u64)>) -> Self {
        let mut facts = Self { parsed_elf: true, ..Self::default() };
        for (name, sh_type, offset, size) in sections {
            if name == ".comment" && size > 0 {
                let start = usize::try_from(offset).unwrap_or(usize::MAX);
                let end = start.saturating_add(usize::try_from(size).unwrap_or(usize::MAX)).min(data.len());
                if let Some(bytes) = data.get(start..end) {
                    facts.comment.extend_from_slice(&bytes[..bytes.len().min(COMMENT_CAP)]);
                }
            }
            facts.sections.push((name.to_string(), sh_type));
        }
        // The file-wide stamp search is for the PlayStation images, which
        // are MIPS and sometimes keep a stamp where no section names it.
        let be = data.get(5) == Some(&2);
        let machine = data
            .get(18..20)
            .map(|b| if be { u16::from_be_bytes([b[0], b[1]]) } else { u16::from_le_bytes([b[0], b[1]]) });
        if machine == Some(EM_MIPS) {
            facts.scan_file_stamps(data);
        }
        facts
    }

    /// Searches the whole file for the stamps a PlayStation linker leaves
    /// where no section names them.
    pub fn scan_file_stamps(&mut self, data: &[u8]) {
        self.file_mwcc_stamp = mwcc_stamp(data);
        self.file_gcc_stamp = gcc_stamp(data);
        self.file_mw_gas = find(data, b"Metrowerks MW GAS R5900").is_some();
    }

    pub fn has(&self, section: &str) -> bool {
        self.sections.iter().any(|(name, _)| name == section)
    }

    pub fn has_prefix(&self, prefix: &str) -> bool {
        self.sections.iter().any(|(name, _)| name.starts_with(prefix))
    }
}

/// First occurrence of `needle` in `haystack`.
pub(crate) fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    let first = *needle.first()?;
    let last_start = haystack.len().checked_sub(needle.len())?;
    let mut at = 0;
    while at <= last_start {
        at += haystack[at..=last_start].iter().position(|&b| b == first)?;
        if &haystack[at..at + needle.len()] == needle {
            return Some(at);
        }
        at += 1;
    }
    None
}

/// `MW MIPS C Compiler (2.4.1.01)` -> `2.4.1.01`.
pub(crate) fn mwcc_stamp(bytes: &[u8]) -> Option<String> {
    let at = find(bytes, b"MW MIPS C Compiler")?;
    let rest = &bytes[at..bytes.len().min(at + 128)];
    let open = rest.iter().position(|&b| b == b'(')?;
    let close = rest[open..].iter().position(|&b| b == b')')? + open;
    Some(String::from_utf8_lossy(&rest[open + 1..close]).into_owned())
}

/// `GCC: (GNU) 3.2.2` -> `3.2.2` (the first such stamp).
pub(crate) fn gcc_stamp(bytes: &[u8]) -> Option<String> {
    let marker = b"GCC: (GNU)";
    let at = find(bytes, marker)?;
    let rest = &bytes[at + marker.len()..bytes.len().min(at + marker.len() + 64)];
    let rest = &rest[rest.iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(rest.len())..];
    let end = rest.iter().position(|b| !(b.is_ascii_digit() || *b == b'.' || *b == b'-')).unwrap_or(rest.len());
    let version = String::from_utf8_lossy(&rest[..end]);
    let version = version.trim_end_matches('.');
    (!version.is_empty()).then(|| version.to_string())
}

fn mapped_contains(imp: &NativeImport, needle: &[u8]) -> bool {
    imp.mappings.iter().any(|mapping| find(&mapping.bytes, needle).is_some())
}

fn code_mappings(imp: &NativeImport) -> impl Iterator<Item = &crate::native::Mapping> {
    imp.mappings.iter().filter(|mapping| mapping.flags & 4 != 0)
}

/// The compiler of an image. `--compiler` on the import wins; otherwise the
/// detector for the image's platform, and [`UNKNOWN`] when it finds nothing.
pub fn identify(imp: &NativeImport) -> Detection {
    if let Some(id) = imp.cfg.compiler.as_deref().filter(|id| !id.trim().is_empty()) {
        return Detection::overridden(id);
    }
    detect(imp)
}

/// [`identify`] without the override: what the bytes say.
pub fn detect(imp: &NativeImport) -> Detection {
    let language = imp.language.as_str();
    let format = imp.format.as_str();
    let found = if language.starts_with("r5900:") {
        ps2_image(imp)
    } else if is_psp(imp) {
        psp_image(imp)
    } else if format == "n64" || format == "N64-overlay" {
        n64_image(imp)
    } else if format == "gba" {
        gba_image(imp)
    } else if format == "nds" {
        nds_image(imp)
    } else if format == "xex" {
        xenon_image(imp)
    } else if format == "PE" && language.starts_with("x86:LE:") {
        pe_x86_image(imp)
    } else if language.starts_with("PowerPC:BE:32") && matches!(format, "dol" | "DOL") {
        dol_image(imp)
    } else if language.starts_with("PSX") {
        return Detection::unknown(vec![
            "PlayStation 1: Psy-Q GCC and CodeWarrior images share the Sony library strings and the `move` spelling; no byte-level tell is measured".into(),
        ]);
    } else {
        None
    };
    found
        .or_else(|| comment_stamp(&imp.image_facts))
        .unwrap_or_else(|| Detection::unknown(vec!["no detector found evidence in this image".into()]))
}

// ---------------------------------------------------------------- ELF .comment

/// The `.comment` verdict shared by every ELF platform that has no better
/// evidence: the toolchain vendor tags devkitPro builds carry, then a GNU
/// or LLVM version stamp.
fn comment_stamp(facts: &ImageFacts) -> Option<Detection> {
    for chunk in facts.comment.split(|&b| b == 0) {
        let text = String::from_utf8_lossy(chunk);
        let text = text.trim();
        if text.is_empty() {
            continue;
        }
        let vendor = [("devkitARM", "devkitarm-gcc"), ("devkitPPC", "devkitppc-gcc"), ("devkitA64", "devkita64-gcc")]
            .into_iter()
            .find(|(tag, _)| text.starts_with("GCC:") && text.contains(&format!("({tag}")));
        if let Some((_, id)) = vendor {
            return Some(Detection::found(id, Confidence::High, vec![format!(".comment: `{text}`")]));
        }
        if let Some(rest) = text.strip_prefix("GCC:") {
            let version = rest.split_whitespace().last().unwrap_or("");
            if let Some(major) = leading_number(version) {
                return Some(Detection::found(format!("gcc-{major}"), Confidence::High, vec![format!(".comment: `{text}`")]));
            }
        }
        if let Some(at) = text.find("clang version ")
            && let Some(major) = leading_number(&text[at + "clang version ".len()..]) {
                return Some(Detection::found(format!("clang-{major}"), Confidence::High, vec![format!(".comment: `{text}`")]));
            }
    }
    None
}

fn leading_number(text: &str) -> Option<u32> {
    let end = text.find(|c: char| !c.is_ascii_digit()).unwrap_or(text.len());
    text[..end].parse().ok()
}

// ----------------------------------------------------------------------- PS2

fn ps2_image(imp: &NativeImport) -> Option<Detection> {
    let symbols = imp
        .functions
        .iter()
        .map(|function| function.name.as_str())
        .chain(imp.object_names.iter().map(|(_, name)| name.as_str()));
    let verdict = ps2::classify(&imp.image_facts, symbols);
    (verdict.family != ps2::CompilerFamily::Unknown)
        .then(|| Detection::found(verdict.canonical_id(), verdict.confidence, verdict.evidence))
}

// ----------------------------------------------------------------------- PSP

/// A PSP module: the importer's Allegrex language, or the PSP linker's
/// `.rodata.sceModuleInfo` on an executable it loaded as generic MIPS.
fn is_psp(imp: &NativeImport) -> bool {
    imp.language.starts_with("Allegrex") || imp.image_facts.has(".rodata.sceModuleInfo")
}

/// PSP: the linker's stamps and debug-section vocabulary. A CodeWarrior-for-PSP
/// image carries the Metrowerks `.comment` stamp (or `.mwcats`, or DWARF 1
/// `.debug` + `.line` with no ECOFF `.mdebug.eabi32`); a psp-gcc image the GNU
/// stamp, the `.gcc_compiled_long32` marker or the ECOFF `.mdebug.eabi32`
/// section the GNU linker keeps. Measured over the six corpus PSP images.
fn psp_image(imp: &NativeImport) -> Option<Detection> {
    let facts = &imp.image_facts;
    if let Some(stamp) = mwcc_stamp(&facts.comment).or_else(|| facts.file_mwcc_stamp.clone()) {
        return Some(Detection::found("mwcc-psp", Confidence::High, vec![format!("`MW MIPS C Compiler ({stamp})` stamp")]));
    }
    if let Some(version) = gcc_stamp(&facts.comment).or_else(|| facts.file_gcc_stamp.clone()) {
        return Some(Detection::found(
            "allegrex-gcc",
            Confidence::High,
            vec![format!("`GCC: (GNU) {version}` stamp on a PSP image")],
        ));
    }
    if facts.has(".gcc_compiled_long32") {
        return Some(Detection::found("allegrex-gcc", Confidence::High, vec!["`.gcc_compiled_long32` section (GCC's own marker)".into()]));
    }
    if facts.has(".mwcats") {
        return Some(Detection::found("mwcc-psp", Confidence::Medium, vec!["`.mwcats` section (CodeWarrior)".into()]));
    }
    if facts.has(".mdebug.eabi32") {
        return Some(Detection::found("allegrex-gcc", Confidence::Medium, vec!["`.mdebug.eabi32` ECOFF debug section (GNU linker output)".into()]));
    }
    if facts.has(".debug") && facts.has(".line") {
        return Some(Detection::found("mwcc-psp", Confidence::Medium, vec!["DWARF 1 `.debug` + `.line` sections without a GNU ECOFF section (CodeWarrior)".into()]));
    }
    None
}

// ----------------------------------------------------------------------- N64

/// N64: IDO spells `move rd,rs` as `or rd,rs,$zero`; GCC-based toolchains
/// (KMC GCC, pmret's gcc 2.8.1) spell it `addu rd,rs,$zero`. Measured over
/// the nine corpus games the share of `or` among the two is 0.866-0.994 for
/// every IDO game and 0.000-0.033 for both GCC games, so the cut sits well
/// inside the gap; a share between the bands, or too few moves to count,
/// proves nothing.
const N64_MIN_MOVES: u64 = 50;
const N64_IDO_SHARE: f64 = 0.75;
const N64_GCC_SHARE: f64 = 0.25;

fn n64_image(imp: &NativeImport) -> Option<Detection> {
    let (mut or, mut addu) = (0u64, 0u64);
    for mapping in code_mappings(imp) {
        for word in mapping.bytes.as_chunks::<4>().0 {
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
    if total < N64_MIN_MOVES {
        return None;
    }
    let share = or as f64 / total as f64;
    let evidence = vec![format!("`move` is `or rd,rs,$zero` {or} times and `addu rd,rs,$zero` {addu} times (or-share {share:.3})")];
    if share >= N64_IDO_SHARE {
        Some(Detection::found("ido", Confidence::Medium, evidence))
    } else if share <= N64_GCC_SHARE {
        Some(Detection::found("n64-gcc", Confidence::Medium, evidence))
    } else {
        None
    }
}

// ----------------------------------------------------------------------- GBA

/// GBA: how Thumb code returns. ARMv4T has no interworking `pop {pc}`, so a
/// compiler either mixes `pop {..,pc}` with `pop {rX}; bx rX` (agbcc and the
/// GCC 2.9x snapshots it descends from return with `pop {..,pc}` from the
/// functions only Thumb code calls) or returns through `bx` everywhere (GCC 4
/// and later, the devkitARM generation). Share of `pop {rX}; bx rX` among all
/// Thumb returns:
///
/// * 0.106-0.562 over the six corpus GBA games (agbcc, old_agbcc, agscc);
/// * 0.000-0.003 over the six NDS images, CodeWarrior Thumb (ARMv5T `pop {pc}`);
/// * 1.000 over a control, 193 of pokeemerald's C files compiled with
///   `arm-none-eabi-gcc` 15.2 `-mthumb -march=armv4t -O2`, both with and without
///   `-mthumb-interwork` (4,926 `bx` returns, no `pop {pc}`).
///
/// The control is a modern GCC, not a devkitARM ROM: no devkitARM game was
/// available, so that verdict is `low` confidence and is the idiom of the
/// lineage, not a toolchain stamp (`.comment`, when an ELF keeps it, is).
const GBA_MIN_BX_POP: u64 = 200;
const GBA_AGBCC_MIN_SHARE: f64 = 0.05;
const GBA_AGBCC_MAX_SHARE: f64 = 0.75;
const GBA_MODERN_MIN_SHARE: f64 = 0.90;

fn gba_image(imp: &NativeImport) -> Option<Detection> {
    let (mut bx_pop, mut pop_pc) = (0u64, 0u64);
    for mapping in &imp.mappings {
        let halves: Vec<u16> = mapping.bytes.as_chunks::<2>().0.iter().map(|h| u16::from_le_bytes([h[0], h[1]])).collect();
        for pair in halves.windows(2) {
            let (h, next) = (pair[0], pair[1]);
            // pop {rX}; bx rX  (X in r0..r3)
            if h & 0xff00 == 0xbc00 && matches!(h & 0xff, 1 | 2 | 4 | 8) {
                let register = (h & 0xff).trailing_zeros() as u16;
                if next == 0x4700 | register << 3 {
                    bx_pop += 1;
                }
            }
            if h & 0xff00 == 0xbd00 {
                pop_pc += 1;
            }
        }
    }
    let share = bx_pop as f64 / (bx_pop + pop_pc).max(1) as f64;
    if bx_pop < GBA_MIN_BX_POP {
        return None;
    }
    let evidence = vec![format!("{bx_pop} Thumb `pop {{rX}}; bx rX` returns against {pop_pc} `pop {{..,pc}}` (share {share:.3})")];
    if (GBA_AGBCC_MIN_SHARE..=GBA_AGBCC_MAX_SHARE).contains(&share) {
        Some(Detection::found("agbcc", Confidence::Medium, evidence))
    } else if share >= GBA_MODERN_MIN_SHARE {
        Some(Detection::found("devkitarm-gcc", Confidence::Low, evidence))
    } else {
        None
    }
}

// ----------------------------------------------------------------------- NDS

/// NDS: NitroSDK is built with CodeWarrior and stamps `[SDK+NINTENDO:<lib>]`
/// into every program that links one of its libraries; all six corpus images
/// carry it. It names the SDK's compiler and the one nearly every title's own
/// code uses, which is why the confidence is medium.
fn nds_image(imp: &NativeImport) -> Option<Detection> {
    mapped_contains(imp, b"[SDK+NINTENDO:").then(|| {
        Detection::found("mwcc-arm", Confidence::Medium, vec!["NitroSDK banner `[SDK+NINTENDO:...]` (SDK libraries are built with CodeWarrior)".into()])
    })
}

// ------------------------------------------------------------------- GC / Wii

/// GameCube and Wii: the SDK libraries are CodeWarrior builds and announce
/// themselves (`<< Dolphin SDK - AI release build`, `<< RVL_SDK - AI`); the
/// Metrowerks Target Resident Kernel string and the CodeWarrior runtime
/// symbols say the same without naming the console.
fn dol_image(imp: &NativeImport) -> Option<Detection> {
    if mapped_contains(imp, b"<< RVL_SDK") || mapped_contains(imp, b"<< RVL_") {
        return Some(Detection::found("mwcc-wii", Confidence::High, vec!["`<< RVL_SDK - ...` library banner (Revolution SDK, CodeWarrior)".into()]));
    }
    if mapped_contains(imp, b"<< Dolphin SDK") {
        return Some(Detection::found("mwcc-gc", Confidence::High, vec!["`<< Dolphin SDK - ...` library banner (Dolphin SDK, CodeWarrior)".into()]));
    }
    if mapped_contains(imp, b"Metrowerks Target Resident Kernel") {
        return Some(Detection::found("mwcc-gc", Confidence::Medium, vec!["`Metrowerks Target Resident Kernel` string (no SDK banner names the console)".into()]));
    }
    let runtime = imp
        .functions
        .iter()
        .any(|function| matches!(function.name.as_str(), "__init_registers" | "__start" | "__ppc_eabi_init"));
    runtime.then(|| Detection::found("mwcc-gc", Confidence::Medium, vec!["CodeWarrior runtime symbols (`__init_registers`, `__start`, `__ppc_eabi_init`)".into()]))
}

// ----------------------------------------------------------------- Xbox 360

/// Xbox 360: the PE optional header's linker version. The shipped toolchains
/// pair linker 8/9/10 with compiler 14/15/16 (Visual C++ 2005/2008/2010); the
/// six corpus images' PDB `S_COMPILE3` records agree with the pairing.
fn xenon_image(imp: &NativeImport) -> Option<Detection> {
    let (major, minor) = imp.image_facts.pe_linker?;
    let compiler = match major {
        8 => 14,
        9 => 15,
        10 => 16,
        _ => return None,
    };
    Some(Detection::found(
        format!("msvc-{compiler}"),
        Confidence::Medium,
        vec![format!("PE optional header linker version {major}.{minor} (compiler {compiler}.x)")],
    ))
}

// ------------------------------------------------------------- Windows x86 PE

/// A Windows PE (i386 or x86-64). Microsoft's linker writes its own version into the optional header (4.x for
/// Visual C++ 4, 5.x, 6.x, 7.0, 7.10, 8.0, ...: the compiler is six major versions above it, `cl` 10.x ... 18.x, the
/// pairing the Xbox 360 rule below uses too; linker 14.x is `cl` 19.x, 2015 to 2022); the `Rich` header after the DOS
/// stub says it was Microsoft's and, per object, which build of which tool compiled it; the C runtime DLL an image
/// imports names the compiler too (`msvcr71.dll` is Visual C++ 2003). MinGW leaves libgcc's and every object's
/// `GCC: (...) x.y.z` string in the image. Other 32-bit Windows linkers (Borland's TLINK, GNU ld) report 2.x and say
/// nothing else.
fn pe_x86_image(imp: &NativeImport) -> Option<Detection> {
    let facts = &imp.image_facts;
    if let Some(stamp) = &facts.pe_gcc_stamp {
        let major = gcc_version(stamp).and_then(leading_number)?;
        return Some(Detection::found(
            format!("mingw-gcc-{major}"),
            Confidence::Medium,
            vec![format!("GCC stamp in the image: `{stamp}` (the commonest one)")],
        ));
    }
    let (major, minor) = facts.pe_linker?;
    if !(4..=14).contains(&major) {
        return None;
    }
    // Visual C++ .NET 2003 (cl 13.10) is linker 7.10; 2002 (cl 13.00) is 7.00.
    let compiler = match (major, minor) {
        (7, minor) if minor >= 10 => "13.1".to_string(),
        (14, _) => "19".to_string(),
        (major, _) => (major + 6).to_string(),
    };
    let confidence = if facts.pe_rich { Confidence::High } else { Confidence::Medium };
    let mut evidence = vec![format!("PE optional header linker version {major}.{minor} (cl {compiler}.x)")];
    if facts.pe_rich {
        evidence.push("a `Rich` header: Microsoft's linker".into());
    }
    if let Some((build, objects)) = rich_dominant_build(&facts.pe_comp_ids) {
        evidence.push(format!("Rich header: {objects} objects, most built by tool build {build}"));
    }
    if let Some(dll) = &facts.pe_crt_dll {
        evidence.push(format!("imports the C runtime `{dll}`"));
    }
    Some(Detection::found(format!("msvc-{compiler}"), confidence, evidence))
}

/// The version after `GCC: (...)`: `GCC: (GNU) 3.4.5 (mingw-vista special r3)` -> `3.4.5`; the parenthesised vendor
/// text may itself hold a comma or a version (`(x86_64-win32-sjlj-rev0, Built by MinGW-W64 project) 8.1.0`).
fn gcc_version(stamp: &str) -> Option<&str> {
    let open = stamp.find('(')?;
    let mut depth = 0usize;
    let mut close = None;
    for (index, ch) in stamp[open..].char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    close = Some(open + index + 1);
                    break;
                }
            }
            _ => {}
        }
    }
    stamp[close?..].split_whitespace().next().filter(|token| token.starts_with(|c: char| c.is_ascii_digit()))
}

/// The `Rich` header's entries: the dwords between `DanS` and `Rich` are XORed with the key that follows `Rich`.
pub(crate) fn rich_comp_ids(header: &[u8]) -> Vec<(u16, u16, u32)> {
    let Some(rich) = find(header, b"Rich") else { return Vec::new() };
    let Some(key) = header.get(rich + 4..rich + 8).map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])) else {
        return Vec::new();
    };
    let word = |at: usize| u32::from_le_bytes([header[at], header[at + 1], header[at + 2], header[at + 3]]) ^ key;
    let mut at = rich;
    let start = loop {
        if at < 0x40 + 4 {
            return Vec::new();
        }
        at -= 4;
        if word(at) == 0x536e_6144 {
            break at;
        }
    };
    // `DanS` and three zero dwords, then (comp id, count) pairs.
    let mut entries = Vec::new();
    let mut at = start + 16;
    while at + 8 <= rich {
        let comp = word(at);
        entries.push(((comp >> 16) as u16, comp as u16, word(at + 4)));
        at += 8;
    }
    entries
}

/// The build number most objects of a Rich header were produced by, and how many: product ids 0 and 1 are padding
/// and the import records.
fn rich_dominant_build(entries: &[(u16, u16, u32)]) -> Option<(u16, u32)> {
    let mut by_build: std::collections::BTreeMap<u16, u32> = std::collections::BTreeMap::new();
    for &(product, build, count) in entries {
        if product > 1 && build > 0 {
            *by_build.entry(build).or_default() += count;
        }
    }
    by_build.into_iter().max_by_key(|&(build, count)| (count, build))
}

/// The C runtime DLL name an image imports (the `msvcr*.dll` family), lower-case.
pub(crate) fn crt_dll_name(bytes: &[u8]) -> Option<String> {
    let lower: Vec<u8> = bytes.iter().map(u8::to_ascii_lowercase).collect();
    for name in ["vcruntime140", "msvcr120", "msvcr110", "msvcr100", "msvcr90", "msvcr80", "msvcr71", "msvcr70", "msvcrt"] {
        let wanted = format!("{name}.dll");
        if find(&lower, wanted.as_bytes()).is_some() {
            return Some(wanted);
        }
    }
    None
}

/// The commonest `GCC: (...) x.y.z` string of an image (every object carries one): ties go to the later version.
pub(crate) fn gcc_stamp_text(bytes: &[u8]) -> Option<String> {
    let mut counts: std::collections::BTreeMap<String, u32> = std::collections::BTreeMap::new();
    let mut from = 0;
    while let Some(offset) = find(&bytes[from..], b"GCC: (") {
        let at = from + offset;
        let rest = &bytes[at..bytes.len().min(at + 128)];
        let end = rest.iter().position(|&b| b == 0 || !(0x20..0x7f).contains(&b)).unwrap_or(rest.len());
        *counts.entry(String::from_utf8_lossy(&rest[..end]).into_owned()).or_default() += 1;
        from = at + 6;
    }
    counts.into_iter().max_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0))).map(|(text, _)| text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::{Mapping, NativeFunction};

    fn image(language: &str, format: &str, bytes: Vec<u8>) -> NativeImport {
        NativeImport {
            language: language.into(),
            format: format.into(),
            mappings: vec![Mapping { vaddr: 0x8000_0000, size: bytes.len() as u64, file_off: 0, flags: 7, bytes }],
            ..Default::default()
        }
    }

    fn be(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|w| w.to_be_bytes()).collect()
    }

    #[test]
    fn n64_moves_spelled_with_or_are_ido_and_with_addu_are_gcc() {
        let move_or = 0x0000_0025 | 16 << 21 | 4 << 11; // or a0,s0,$zero
        let move_addu = 0x0000_0021 | 16 << 21 | 4 << 11; // addu a0,s0,$zero
        let ido = image("MIPS:BE:64:64-32addr", "n64", be(&vec![move_or; 80]));
        assert_eq!(detect(&ido).id, "ido");
        let gcc = image("MIPS:BE:64:64-32addr", "n64", be(&vec![move_addu; 80]));
        assert_eq!(detect(&gcc).id, "n64-gcc");
        let few = image("MIPS:BE:64:64-32addr", "n64", be(&[move_or; 10]));
        assert!(detect(&few).is_unknown(), "ten moves are not evidence");
        let mixed = image("MIPS:BE:64:64-32addr", "n64", be(&[vec![move_or; 40], vec![move_addu; 40]].concat()));
        assert!(detect(&mixed).is_unknown(), "an even split is not evidence");
    }

    #[test]
    fn an_sdk_banner_names_the_console_and_a_runtime_symbol_alone_is_medium() {
        let wii = image("PowerPC:BE:32:Gekko_Broadway", "dol", b"\0<< RVL_SDK - AI \trelease build\0".to_vec());
        assert_eq!(detect(&wii).id, "mwcc-wii");
        let gc = image("PowerPC:BE:32:Gekko_Broadway", "dol", b"\0<< Dolphin SDK - AI\trelease build\0".to_vec());
        assert_eq!(detect(&gc).id, "mwcc-gc");
        assert_eq!(detect(&gc).confidence, Confidence::High);
        let mut symbols = image("PowerPC:BE:32:Gekko_Broadway", "dol", vec![0; 16]);
        symbols.functions.push(NativeFunction { entry: 0x8000_0000, size: 4, name: "__init_registers".into() });
        let found = detect(&symbols);
        assert_eq!((found.id.as_str(), found.confidence), ("mwcc-gc", Confidence::Medium));
        assert!(detect(&image("PowerPC:BE:32:Gekko_Broadway", "dol", vec![0; 16])).is_unknown());
    }

    #[test]
    fn a_devkitpro_comment_is_its_own_compiler_and_a_plain_gnu_stamp_is_the_major() {
        let mut facts = ImageFacts {
            comment: b"\0GCC: (devkitARM release 46) 13.1.0\0".to_vec(),
            ..Default::default()
        };
        assert_eq!(comment_stamp(&facts).unwrap().id, "devkitarm-gcc");
        facts.comment = b"GCC: (GNU) 4.9.2\0clang version 11.0.0 (https://x)\0".to_vec();
        assert_eq!(comment_stamp(&facts).unwrap().id, "gcc-4");
        facts.comment = b"Android (7019983 based on r365631c3) clang version 9.0.8\0".to_vec();
        assert_eq!(comment_stamp(&facts).unwrap().id, "clang-9");
        facts.comment = b"unrelated\0".to_vec();
        assert!(comment_stamp(&facts).is_none());
    }

    #[test]
    fn gba_thumb_returns_tell_the_agbcc_mix_from_the_bx_everywhere_of_modern_gcc() {
        // pop {r4}; pop {r0}; bx r0 is 0xb410 0xbc01 0x4700; the agbcc return pop {r4, pc} is 0xbd10.
        let halves = |bx: usize, pc: usize| -> Vec<u8> {
            let mut out = Vec::new();
            for _ in 0..bx {
                out.extend_from_slice(&[0x01, 0xbc, 0x00, 0x47]);
            }
            for _ in 0..pc {
                out.extend_from_slice(&[0x10, 0xbd]);
            }
            out
        };
        let rom = |bx, pc| image("ARM:LE:32:v4t", "gba", halves(bx, pc));
        assert_eq!(detect(&rom(300, 700)).id, "agbcc", "share 0.30: the agbcc mix");
        let modern = detect(&rom(300, 0));
        assert_eq!((modern.id.as_str(), modern.confidence), ("devkitarm-gcc", Confidence::Low));
        assert!(detect(&rom(300, 60)).is_unknown(), "0.83 sits between the two bands");
        assert!(detect(&rom(30, 0)).is_unknown(), "thirty returns are not evidence");
        assert!(detect(&rom(5, 5000)).is_unknown(), "almost no bx returns: CodeWarrior's pop {{pc}}");
    }

    #[test]
    fn psp_images_are_told_apart_by_the_sections_their_linker_leaves() {
        let psp = |names: &[&str], comment: &[u8]| {
            let mut imp = image("MIPS:LE:32:default", "elf32", Vec::new());
            imp.image_facts = ImageFacts {
                parsed_elf: true,
                sections: [".rodata.sceModuleInfo"].iter().chain(names).map(|name| (name.to_string(), 1)).collect(),
                comment: comment.to_vec(),
                ..Default::default()
            };
            detect(&imp)
        };
        // BOOT.BIN of a CodeWarrior title: loaded as generic MIPS, stamped in `.comment`.
        assert_eq!(psp(&[".debug", ".line", ".comment"], b"MW MIPS C Compiler (2.4.1.01)\0").id, "mwcc-psp");
        // A CodeWarrior module without the stamp: DWARF 1 and no GNU ECOFF section.
        assert_eq!(psp(&[".debug", ".line"], b"").id, "mwcc-psp");
        // psp-gcc 3.3.3 with no `.comment`: the GNU linker's ECOFF section.
        assert_eq!(psp(&[".mdebug.eabi32", ".debug_info"], b"").id, "allegrex-gcc");
        // The same sections plus `.debug` + `.line` stay GNU: `.mdebug.eabi32` is checked first.
        assert_eq!(psp(&[".mdebug.eabi32", ".debug", ".line"], b"").id, "allegrex-gcc");
        assert!(psp(&[".text"], b"").is_unknown());
    }

    #[test]
    fn an_i386_pe_names_visual_cpp_by_its_linker_and_mingw_by_its_gcc_string() {
        let mut pe = image("x86:LE:32:default", "PE", vec![]);
        assert!(detect(&pe).is_unknown());
        pe.image_facts.pe_linker = Some((6, 0));
        assert_eq!(detect(&pe).id, "msvc-12");
        assert_eq!(detect(&pe).confidence, Confidence::Medium);
        pe.image_facts.pe_rich = true;
        assert_eq!(detect(&pe).confidence, Confidence::High);
        pe.image_facts.pe_linker = Some((4, 20));
        assert_eq!(detect(&pe).id, "msvc-10");
        pe.image_facts.pe_linker = Some((7, 10));
        assert_eq!(detect(&pe).id, "msvc-13.1");
        pe.image_facts.pe_linker = Some((7, 0));
        assert_eq!(detect(&pe).id, "msvc-13");
        // GNU ld and Borland's linker report 2.x: no verdict from the version alone
        pe.image_facts.pe_linker = Some((2, 25));
        assert!(detect(&pe).is_unknown());
        pe.image_facts.pe_gcc_stamp = Some("GCC: (x86_64-win32-sjlj-rev0, Built by MinGW-W64 project) 8.1.0".into());
        assert_eq!(detect(&pe).id, "mingw-gcc-8");
        assert_eq!(gcc_stamp_text(b"\0GCC: (GNU) 3.4.5 (mingw-vista special r3)\0more").as_deref(), Some("GCC: (GNU) 3.4.5 (mingw-vista special r3)"));
        // every object carries its stamp: the commonest one is the program's, the older library is outvoted
        let mut many = b"GCC: (GNU) 15.2.1 20250808\0".to_vec();
        for _ in 0..3 {
            many.extend_from_slice(b"\0GCC: (GNU) 16.2.1 20260819\0");
        }
        assert_eq!(gcc_stamp_text(&many).as_deref(), Some("GCC: (GNU) 16.2.1 20260819"));
        assert_eq!(gcc_version("GCC: (GNU) 3.4.5 (mingw-vista special r3)"), Some("3.4.5"));
        assert_eq!(gcc_version("GCC: (x86_64-win32-sjlj-rev0, Built by MinGW-W64 project) 8.1.0"), Some("8.1.0"));
        pe.image_facts.pe_gcc_stamp = None;
        pe.image_facts.pe_linker = Some((14, 36));
        assert_eq!(detect(&pe).id, "msvc-19");
    }

    #[test]
    fn the_rich_header_is_decoded_with_its_key() {
        let key = 0xdead_beefu32;
        let mut header = vec![0u8; 0x80];
        let push = |header: &mut Vec<u8>, word: u32| header.extend_from_slice(&(word ^ key).to_le_bytes());
        push(&mut header, 0x536e_6144);
        for _ in 0..3 {
            push(&mut header, 0);
        }
        push(&mut header, (0x00f1 << 16) | 50727);
        push(&mut header, 1);
        push(&mut header, (0x00ff << 16) | 50727);
        push(&mut header, 73);
        header.extend_from_slice(b"Rich");
        header.extend_from_slice(&key.to_le_bytes());
        let entries = rich_comp_ids(&header);
        assert_eq!(entries, vec![(0xf1, 50727, 1), (0xff, 50727, 73)]);
        assert_eq!(rich_dominant_build(&entries), Some((50727, 74)));
        assert!(rich_comp_ids(b"MZ no header").is_empty());
        assert_eq!(crt_dll_name(b"..KERNEL32.dll..MSVCR71.dll\0").as_deref(), Some("msvcr71.dll"));
    }

    #[test]
    fn the_override_wins_over_every_detector() {
        let mut imp = image("PowerPC:BE:32:Gekko_Broadway", "dol", b"<< Dolphin SDK - AI".to_vec());
        imp.cfg.compiler = Some(" MWCC-Wii ".into());
        let found = identify(&imp);
        assert_eq!(found.id, "mwcc-wii");
        assert_eq!(found.source, super::super::Source::Override);
    }

    #[test]
    fn the_stamp_readers_find_a_stamp_in_bytes_that_are_not_text() {
        let mut data = vec![0xffu8; 40];
        data.extend_from_slice(b"MW MIPS C Compiler (2.4.1.01)\0");
        data.extend_from_slice(&[0x80; 9]);
        data.extend_from_slice(b"GCC: (GNU) 3.2.2\0");
        assert_eq!(mwcc_stamp(&data).as_deref(), Some("2.4.1.01"));
        assert_eq!(gcc_stamp(&data).as_deref(), Some("3.2.2"));
        assert_eq!(gcc_stamp(b"GCC: (GNU) \0"), None);
    }
}
