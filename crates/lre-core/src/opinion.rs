//! ELF language selection from the pinned install's own opinion files.
//!
//! Ghidra's ELF loader does not decide the language from a table: it asks the
//! opinion database which languages a machine allows.
//! `ElfLoader.findSupportedLoadSpecs` queries with `e_machine` as the primary
//! key and `e_flags` as the secondary one, then keeps only the answers whose
//! endianness and pointer size match the image. The constraint that matches
//! names the processor and the compiler spec, and -- for ARM, AArch64, x86-64
//! and 64-bit RISC-V -- the variant as well.
//!
//! Two consequences this module exists for:
//!
//! * The variant is data, not opinion of ours. `ARM.opinion` pins `v8` (and
//!   `v8LEInstruction` behind the `EF_ARM_BE8` bit); a hand-written table that
//!   said `v7` decoded ARM images with the wrong language while the pinned
//!   install said otherwise.
//! * Where the data pins *no* variant -- PowerPC, MIPS, 32-bit RISC-V -- the
//!   choice is genuinely open, and Ghidra's importer resolves it by taking the
//!   first element of a `HashSet<QueryResult>` iteration over candidates that
//!   are all equally "preferred": for a flags-0, 32-bit, big-endian PowerPC
//!   ELF that is `PowerPC:BE:32:e500`, with `PowerPC:BE:32:default` twelfth in
//!   the same set. Hash order is not a fact about the image, so this selects
//!   the neutral `default` variant where the install declares one, and the
//!   first language it declares otherwise.

use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum OpinionError {
    #[error("opinion tree: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Unsupported(String),
}

pub type Result<T> = std::result::Result<T, OpinionError>;

/// What an ELF header says about the machine it targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ElfMachine {
    /// `e_machine`.
    pub machine: u16,
    /// `e_flags`, the secondary opinion key.
    pub flags: u32,
    /// Pointer size from `EI_CLASS`, in bits.
    pub bits: u32,
    /// Data order from `EI_DATA`.
    pub big_endian: bool,
    /// `e_type`: a PSP image is a MIPS ELF whose `e_type` is the SCE
    /// processor-specific `0xffa0` (ET_SCE_PSP_RELEXEC), which is what
    /// distinguishes it from a generic MIPS binary for Allegrex.
    pub e_type: u16,
}

/// The language id and compiler spec id a load selects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    pub language: String,
    pub compiler: String,
}

/// `Loader.getName()` for the ELF loader, as the opinion files spell it.
const ELF_LOADER: &str = "Executable and Linking Format (ELF)";
/// The variant to take when the data leaves the choice open.
const NEUTRAL: &str = "default";

/// One leaf `<constraint>` row, with the attributes its ancestors supply.
#[derive(Debug, Clone)]
struct Constraint {
    /// `e_machine` values; `primary="8,10"` lists several (MIPS).
    primaries: Vec<u32>,
    secondary: Option<String>,
    processor: String,
    endian: Option<String>,
    size: Option<String>,
    variant: Option<String>,
    compiler: String,
}

/// One `<language>` the install declares, in declaration order.
#[derive(Debug, Clone)]
struct Language {
    id: String,
    processor: String,
    endian: String,
    size: String,
    variant: String,
    compilers: Vec<String>,
}

/// The answers the pinned install gives for the machines this loader is
/// measured on, for use when no install is reachable at all.
///
/// An import needs no Ghidra install (`tests/m2-015_native_default.py`): the
/// SLEIGH data a *decompile* reads is not needed to record which language a
/// machine wants. Every row here is what `elf_selection` returns for the same
/// header against the pinned tree, and
/// `the_offline_rows_match_the_pinned_install` fails if one drifts.
fn offline_selection(image: ElfMachine) -> Option<Selection> {
    /// `EF_ARM_BE8`: big-endian data, little-endian instructions.
    const EF_ARM_BE8: u32 = 0x0080_0000;
    let order = if image.big_endian { "BE" } else { "LE" };
    let (language, compiler) = match (image.machine, image.bits) {
        (0x03, 32) if !image.big_endian => ("x86:LE:32:default".to_string(), "gcc"),
        (0x3e, 64) if !image.big_endian => ("x86:LE:64:default".to_string(), "gcc"),
        (0xb7, 64) if !image.big_endian => ("AARCH64:LE:64:v8A".to_string(), "default"),
        (0x28, 32) if image.big_endian && image.flags & EF_ARM_BE8 != 0 => {
            ("ARM:LEBE:32:v8LEInstruction".to_string(), "default")
        }
        (0x28, 32) => (format!("ARM:{order}:32:v8"), "default"),
        // A PSP image is a MIPS ELF whose e_type is SCE's 0xffa0; it decodes
        // as Allegrex (MIPS + VFPU), not generic MIPS.
        (0x08, 32) if image.e_type == 0xffa0 => ("Allegrex:LE:32:default".to_string(), "default"),
        (0x08, 32) => (format!("MIPS:{order}:32:default"), "default"),
        (0x14, 32) => (format!("PowerPC:{order}:32:default"), "default"),
        (0x15, 64) => (format!("PowerPC:{order}:64:default"), "default"),
        // Cell SPU: e_machine 23, a 128-bit big-endian standalone core
        // (GhidraSPU spu.opinion: primary 23, size 128).
        (0x17, _) if image.big_endian => ("SPU:BE:128:default".to_string(), "default"),
        (0xf3, 64) if !image.big_endian => ("RISCV:LE:64:default".to_string(), "gcc"),
        (0xf3, 32) if !image.big_endian => ("RISCV:LE:32:default".to_string(), "gcc"),
        _ => return None,
    };
    Some(Selection { language, compiler: compiler.to_string() })
}

/// Selects the language and compiler spec for one ELF image.
pub fn elf_selection(install: &Path, image: ElfMachine) -> Result<Selection> {
    // A PSP image is a MIPS ELF whose e_type is SCE's 0xffa0. No generic ELF
    // opinion names it (the Allegrex extension keys its opinion to a custom
    // "PSP Executable" loader), so it is resolved here, before the install.
    if image.machine == 0x08 && image.e_type == 0xffa0 {
        return Ok(Selection {
            language: "Allegrex:LE:32:default".to_string(),
            compiler: "default".to_string(),
        });
    }
    if !install.join("Ghidra/Processors").is_dir() {
        return offline_selection(image).ok_or_else(|| {
            OpinionError::Unsupported(format!(
                "no install at {} and no offline answer for machine {:#x}",
                install.display(),
                image.machine
            ))
        });
    }
    let constraints = elf_constraints(install)?;
    let machine = u32::from(image.machine);
    let matching: Vec<&Constraint> = constraints
        .iter()
        .filter(|constraint| constraint.primaries.contains(&machine))
        .collect();
    if matching.is_empty() {
        return Err(OpinionError::Unsupported(format!(
            "no ELF opinion constraint for machine {machine:#x} in {}",
            install.display()
        )));
    }
    // A secondary key that matches the image's flags wins; Ghidra falls back
    // to the constraints that carry no secondary key at all
    // (`QueryOpinionService.getSpecs`).
    let keyed: Vec<&Constraint> = matching
        .iter()
        .copied()
        .filter(|constraint| {
            constraint
                .secondary
                .as_deref()
                .is_some_and(|key| secondary_matches(key, image.flags))
        })
        .collect();
    let chosen: Vec<&Constraint> = if keyed.is_empty() {
        matching
            .iter()
            .copied()
            .filter(|constraint| constraint.secondary.is_none())
            .collect()
    } else {
        keyed
    };
    if chosen.is_empty() {
        return Err(OpinionError::Unsupported(format!(
            "no ELF opinion constraint for machine {machine:#x} matches flags {:#x}",
            image.flags
        )));
    }
    let endian = if image.big_endian { "big" } else { "little" };
    let bits = image.bits.to_string();
    let declared = declared_languages(install)?;
    let mut candidates: Vec<(&Language, &str)> = Vec::new();
    for constraint in &chosen {
        for language in &declared {
            if language.processor != constraint.processor {
                continue;
            }
            // A constraint narrows; the image decides. `ElfLoader` drops any
            // candidate wider than a 32-bit image or no wider than a 64-bit
            // one, and any whose data order differs -- which is what keeps
            // RISCV's two unkeyed constraints (32 and 64) from answering for
            // each other.
            if language.endian != endian {
                continue;
            }
            if constraint
                .endian
                .as_deref()
                .is_some_and(|declared| language.endian != declared)
            {
                continue;
            }
            let size: u32 = language.size.parse().unwrap_or(0);
            if image.bits == 32 && size > 32 {
                continue;
            }
            if image.bits == 64 && size <= 32 {
                continue;
            }
            if constraint
                .size
                .as_deref()
                .is_some_and(|declared| language.size != declared)
            {
                continue;
            }
            if constraint
                .variant
                .as_deref()
                .is_some_and(|variant| language.variant != variant)
            {
                continue;
            }
            // A pair the install does not declare is not a pair Ghidra's
            // query can return.
            if !language.compilers.iter().any(|id| id == &constraint.compiler) {
                continue;
            }
            candidates.push((language, constraint.compiler.as_str()));
        }
    }
    let (language, compiler) = candidates
        .iter()
        .find(|(language, _)| language.variant == NEUTRAL)
        .or_else(|| candidates.first())
        .ok_or_else(|| {
            OpinionError::Unsupported(format!(
                "the install declares no {endian}-endian {bits}-bit language for machine \
                 {machine:#x}"
            ))
        })?;
    Ok(Selection {
        language: language.id.clone(),
        compiler: (*compiler).to_string(),
    })
}

/// Whether one secondary key matches these flags.
///
/// A `0b` pattern masks don't-care bits with `.`, which is how `ARM.opinion`
/// names `EF_ARM_BE8` (`QueryOpinionService.getQueryResultWithSecondaryMasking`);
/// a decimal or `0x` key compares equal. Anything else is a compiler name
/// (`golang`, `swift`) that this loader does not detect, so it never matches.
fn secondary_matches(key: &str, flags: u32) -> bool {
    let text = key.trim();
    if let Some(pattern) = text.strip_prefix("0b") {
        let bits: Vec<char> = pattern
            .chars()
            .filter(|symbol| !symbol.is_whitespace() && *symbol != '_')
            .collect();
        if bits.len() != 32 {
            return false;
        }
        return bits.iter().enumerate().all(|(index, symbol)| match symbol {
            '.' => true,
            '0' => (flags >> (31 - index)) & 1 == 0,
            '1' => (flags >> (31 - index)) & 1 == 1,
            _ => false,
        });
    }
    let parsed = match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u32::from_str_radix(hex, 16).ok(),
        None => text.parse::<u32>().ok(),
    };
    parsed == Some(flags)
}

/// Every ELF-loader constraint the install declares, with inherited
/// `loader`/`compilerSpecID` attributes.
fn elf_constraints(install: &Path) -> Result<Vec<Constraint>> {
    let mut rows = Vec::new();
    for path in language_files(install, "opinion")? {
        let xml = strip_comments(&std::fs::read_to_string(&path)?);
        let mut stack: Vec<Vec<(String, String)>> = Vec::new();
        let mut rest = xml.as_str();
        while let Some(position) = rest.find('<') {
            let tail = &rest[position..];
            let Some(end) = tail.find('>') else { break };
            let tag = &tail[1..end];
            rest = &tail[end + 1..];
            if let Some(stripped) = tag.strip_prefix("constraint") {
                let mut merged = stack.last().cloned().unwrap_or_default();
                merged.extend(attributes(stripped));
                if let Some(constraint) = leaf(&merged) {
                    rows.push(constraint);
                }
                if !tag.trim_end().ends_with('/') {
                    stack.push(merged);
                }
            } else if tag.trim() == "/constraint" {
                stack.pop();
            }
        }
    }
    Ok(rows)
}

/// A leaf row: one that names a machine, for the ELF loader.
fn leaf(attributes: &[(String, String)]) -> Option<Constraint> {
    let value = |name: &str| {
        attributes
            .iter()
            .rev()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
    };
    if value("loader").as_deref() != Some(ELF_LOADER) {
        return None;
    }
    let primaries: Vec<u32> = value("primary")?
        .split(',')
        .filter_map(|item| {
            let text = item.trim();
            match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
                Some(hex) => u32::from_str_radix(hex, 16).ok(),
                None => text.parse::<u32>().ok(),
            }
        })
        .collect();
    if primaries.is_empty() {
        return None;
    }
    Some(Constraint {
        primaries,
        secondary: value("secondary"),
        processor: value("processor")?,
        endian: value("endian"),
        size: value("size"),
        variant: value("variant"),
        compiler: value("compilerSpecID").unwrap_or_else(|| NEUTRAL.to_string()),
    })
}

/// Every language the install declares, in file then declaration order.
///
/// A deprecated language is not a choice: `.ldefs` marks those, and selecting
/// one would decode with a decoder the install itself retired.
fn declared_languages(install: &Path) -> Result<Vec<Language>> {
    let mut rows = Vec::new();
    for path in language_files(install, "ldefs")? {
        let xml = strip_comments(&std::fs::read_to_string(&path)?);
        let mut rest = xml.as_str();
        while let Some(position) = rest.find("<language ") {
            let tail = &rest[position..];
            let Some(header_end) = tail.find('>') else { break };
            let header = &tail[1..header_end];
            let body_end = tail.find("</language>").unwrap_or(header_end);
            let body = &tail[..body_end];
            rest = &tail[header_end + 1..];
            let header_attributes = attributes(header.trim_start_matches("language"));
            let value = |name: &str| {
                header_attributes
                    .iter()
                    .find(|(key, _)| key == name)
                    .map(|(_, value)| value.clone())
            };
            if value("deprecated").as_deref() == Some("true") {
                continue;
            }
            let (Some(id), Some(processor), Some(endian), Some(size), Some(variant)) = (
                value("id"),
                value("processor"),
                value("endian"),
                value("size"),
                value("variant"),
            ) else {
                continue;
            };
            let mut compilers = Vec::new();
            let mut inner = body;
            while let Some(at) = inner.find("<compiler ") {
                let compiler = &inner[at..];
                let Some(end) = compiler.find('>') else { break };
                if let Some((_, id)) = attributes(&compiler[1..end])
                    .into_iter()
                    .find(|(key, _)| key == "id")
                {
                    compilers.push(id);
                }
                inner = &compiler[end + 1..];
            }
            rows.push(Language {
                id,
                processor,
                endian,
                size,
                variant,
                compilers,
            });
        }
    }
    Ok(rows)
}

/// Files of one extension below any module of the install's `Ghidra` tree, in
/// a stable order so declaration order is reproducible.
///
/// Ghidra loads opinions and language definitions from every module it finds,
/// not only `Processors`: an installed extension is a module too, and the
/// install used here answers a PlayStation 2 executable with
/// `r5900:LE:32:default` from `Ghidra/Extensions/ghidra-emotionengine-reloaded`.
/// Reading only `Processors` made that language invisible and typed the image
/// as plain MIPS32 (`QueryOpinionService.initialize` walks
/// `Application.findFilesByExtensionInApplication`).
fn language_files(install: &Path, extension: &str) -> Result<Vec<std::path::PathBuf>> {
    let root = install.join("Ghidra");
    if !root.is_dir() {
        return Ok(Vec::new());
    }
    let mut groups: Vec<std::path::PathBuf> = std::fs::read_dir(&root)?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.is_dir())
        .collect();
    groups.sort();
    let mut files = Vec::new();
    for group in groups {
        let mut modules: Vec<std::path::PathBuf> = std::fs::read_dir(&group)?
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .collect();
        modules.sort();
        for module in modules {
            let languages = module.join("data/languages");
            if !languages.is_dir() {
                continue;
            }
            let mut here: Vec<std::path::PathBuf> = std::fs::read_dir(&languages)?
                .filter_map(|entry| entry.ok().map(|entry| entry.path()))
                .filter(|path| path.extension().is_some_and(|ext| ext == extension))
                .collect();
            here.sort();
            files.extend(here);
        }
    }
    Ok(files)
}

/// `name="value"` pairs of one tag, in order.
///
/// Whitespace is allowed around the `=` and inside a value: `ARM.opinion`
/// writes `secondary= "0b .... .... 1... ..."`, and reading that pair is the
/// difference between honouring `EF_ARM_BE8` and ignoring it.
fn attributes(tag: &str) -> Vec<(String, String)> {
    let bytes = tag.as_bytes();
    let named = |byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b':' | b'-');
    let mut pairs = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        while index < bytes.len() && !named(bytes[index]) {
            index += 1;
        }
        let start = index;
        while index < bytes.len() && named(bytes[index]) {
            index += 1;
        }
        if start == index {
            break;
        }
        let name = &tag[start..index];
        let mut cursor = index;
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if bytes.get(cursor) != Some(&b'=') {
            continue;
        }
        cursor += 1;
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if bytes.get(cursor) != Some(&b'"') {
            continue;
        }
        cursor += 1;
        let value_start = cursor;
        while cursor < bytes.len() && bytes[cursor] != b'"' {
            cursor += 1;
        }
        if cursor >= bytes.len() {
            break;
        }
        pairs.push((name.to_string(), tag[value_start..cursor].to_string()));
        index = cursor + 1;
    }
    pairs
}

/// XML comments hold documentation that mentions constraints and flags; they
/// are not data.
fn strip_comments(xml: &str) -> String {
    let mut out = String::with_capacity(xml.len());
    let mut rest = xml;
    while let Some(start) = rest.find("<!--") {
        out.push_str(&rest[..start]);
        match rest[start..].find("-->") {
            Some(end) => rest = &rest[start + end + 3..],
            None => return out,
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn install(constraints: &str, languages: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "ventris-opinion-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let dir = root.join("Ghidra/Processors/Probe/data/languages");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("Probe.opinion"), constraints).unwrap();
        std::fs::write(dir.join("Probe.ldefs"), languages).unwrap();
        root
    }

    const LANGUAGES: &str = r#"<language_definitions>
  <!-- declaration order decides ties -->
  <language processor="Probe" endian="big" size="32" variant="fancy" id="Probe:BE:32:fancy">
    <compiler name="default" id="default"/>
  </language>
  <language processor="Probe" endian="big" size="32" variant="default" id="Probe:BE:32:default">
    <compiler name="default" id="default"/>
    <compiler name="gcc" id="gcc"/>
  </language>
  <language processor="Probe" endian="little" size="32" variant="default" id="Probe:LE:32:default">
    <compiler name="default" id="default"/>
  </language>
  <language processor="Probe" endian="big" size="32" variant="masked" id="Probe:BE:32:masked">
    <compiler name="default" id="default"/>
  </language>
  <language processor="Probe" endian="big" size="32" variant="retired" id="Probe:BE:32:retired"
      deprecated="true">
    <compiler name="default" id="default"/>
  </language>
</language_definitions>"#;

    fn machine(flags: u32, big_endian: bool) -> ElfMachine {
        ElfMachine { machine: 40, flags, bits: 32, big_endian , e_type: 0}
    }

    #[test]
    fn a_pinned_variant_is_the_selection() {
        let root = install(
            r#"<opinions>
  <constraint loader="Executable and Linking Format (ELF)" compilerSpecID="gcc">
    <constraint primary="40" processor="Probe" size="32" variant="fancy"/>
  </constraint>
</opinions>"#,
            LANGUAGES,
        );
        // `fancy` declares no `gcc` spec, so the pair the install does not
        // declare cannot be selected -- and nothing else satisfies the pin.
        assert!(matches!(
            elf_selection(&root, machine(0, true)),
            Err(OpinionError::Unsupported(_))
        ));
        std::fs::remove_dir_all(&root).unwrap();

        let root = install(
            r#"<opinions>
  <constraint loader="Executable and Linking Format (ELF)" compilerSpecID="default">
    <constraint primary="40" processor="Probe" size="32" variant="fancy"/>
  </constraint>
</opinions>"#,
            LANGUAGES,
        );
        assert_eq!(
            elf_selection(&root, machine(0, true)).unwrap(),
            Selection { language: "Probe:BE:32:fancy".into(), compiler: "default".into() }
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn an_unpinned_variant_takes_the_neutral_language() {
        // The PowerPC shape: one constraint, no variant, several installed
        // candidates. Endianness and size come from the image, so the
        // little-endian sibling is not a candidate.
        let root = install(
            r#"<opinions>
  <constraint loader="Executable and Linking Format (ELF)" compilerSpecID="gcc">
    <constraint primary="40" processor="Probe" size="32"/>
  </constraint>
</opinions>"#,
            LANGUAGES,
        );
        assert_eq!(
            elf_selection(&root, machine(0, true)).unwrap(),
            Selection { language: "Probe:BE:32:default".into(), compiler: "gcc".into() }
        );
        assert!(
            matches!(elf_selection(&root, machine(0, false)), Err(OpinionError::Unsupported(_))),
            "the little-endian language declares no gcc spec"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_masked_secondary_key_selects_from_the_flags() {
        // The ARM shape: two constraints separated by one flag bit.
        let root = install(
            r#"<opinions>
  <constraint loader="Executable and Linking Format (ELF)" compilerSpecID="default">
    <constraint primary="40" processor="Probe" size="32" variant="default"
        secondary="0b .... .... 0... .... .... .... .... ...."/>
    <constraint primary="40" processor="Probe" size="32" variant="masked"
        secondary="0b .... .... 1... .... .... .... .... ...."/>
  </constraint>
</opinions>"#,
            LANGUAGES,
        );
        assert_eq!(
            elf_selection(&root, machine(0x0500_0000, true)).unwrap().language,
            "Probe:BE:32:default"
        );
        assert_eq!(
            elf_selection(&root, machine(0x0580_0000, true)).unwrap().language,
            "Probe:BE:32:masked",
            "the masked bit selects the other variant"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn an_unknown_machine_is_refused_and_a_retired_language_is_not_a_choice() {
        let root = install(
            r#"<opinions>
  <constraint loader="Executable and Linking Format (ELF)" compilerSpecID="default">
    <constraint primary="40" processor="Probe" size="32" variant="retired"/>
  </constraint>
  <constraint loader="Portable Executable (PE)" compilerSpecID="default">
    <constraint primary="99" processor="Probe" size="32"/>
  </constraint>
</opinions>"#,
            LANGUAGES,
        );
        let unknown = ElfMachine { machine: 0xfff, flags: 0, bits: 32, big_endian: true, e_type: 0 };
        assert!(matches!(
            elf_selection(&root, unknown),
            Err(OpinionError::Unsupported(_))
        ));
        // Another loader's constraint is not an ELF answer, and the only
        // language this ELF constraint pins is deprecated.
        let other = ElfMachine { machine: 99, flags: 0, bits: 32, big_endian: true, e_type: 0 };
        assert!(matches!(
            elf_selection(&root, other),
            Err(OpinionError::Unsupported(_))
        ));
        assert!(matches!(
            elf_selection(&root, machine(0, true)),
            Err(OpinionError::Unsupported(_))
        ));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn the_pinned_install_answers_for_every_machine_the_corpus_holds() {
        // The answers stock prints for the same bytes
        // (`analyzeHeadless -import -noanalysis`), except PowerPC, where the
        // data pins no variant and stock takes its first hash-ordered
        // candidate (`PowerPC:BE:32:e500`).
        let install = crate::session::RuntimeConfig::from_env().ghidra_install;
        if !install.join("Ghidra/Processors").is_dir() {
            eprintln!("SKIP: no pinned install at {}", install.display());
            return;
        }
        let cases = [
            (0x3e, 0u32, 64, false, "x86:LE:64:default", "gcc"),
            (0x03, 0, 32, false, "x86:LE:32:default", "gcc"),
            (0xb7, 0, 64, false, "AARCH64:LE:64:v8A", "default"),
            (0x14, 0, 32, true, "PowerPC:BE:32:default", "default"),
            (0x15, 0, 64, true, "PowerPC:BE:64:default", "default"),
            (0x28, 0x0500_0000, 32, false, "ARM:LE:32:v8", "default"),
            (0x28, 0x0500_0000, 32, true, "ARM:BE:32:v8", "default"),
            (0x28, 0x0580_0000, 32, true, "ARM:LEBE:32:v8LEInstruction", "default"),
            (0x08, 0, 32, true, "MIPS:BE:32:default", "default"),
            (0xf3, 0, 64, false, "RISCV:LE:64:default", "gcc"),
        ];
        for (machine, flags, bits, big_endian, language, compiler) in cases {
            let image = ElfMachine { machine, flags, bits, big_endian , e_type: 0};
            assert_eq!(
                elf_selection(&install, image).unwrap(),
                Selection { language: language.into(), compiler: compiler.into() },
                "machine {machine:#x} flags {flags:#x}"
            );
        }
        let unsupported = ElfMachine { machine: 0xfffe, flags: 0, bits: 32, big_endian: false, e_type: 0 };
        assert!(elf_selection(&install, unsupported).is_err());
    }

    #[test]
    fn the_offline_rows_match_the_pinned_install() {
        // The fallback stands in for the install's data, so it may never
        // answer differently: an import without an install and an import with
        // one record the same language.
        let install = crate::session::RuntimeConfig::from_env().ghidra_install;
        if !install.join("Ghidra/Processors").is_dir() {
            eprintln!("SKIP: no pinned install at {}", install.display());
            return;
        }
        let rows = [
            (0x03u16, 0u32, 32u32, false),
            (0x3e, 0, 64, false),
            (0xb7, 0, 64, false),
            (0x28, 0x0500_0000, 32, false),
            (0x28, 0x0500_0000, 32, true),
            (0x28, 0x0580_0000, 32, true),
            (0x08, 0, 32, false),
            (0x08, 0, 32, true),
            (0x14, 0, 32, false),
            (0x14, 0, 32, true),
            (0x15, 0, 64, false),
            (0x15, 0, 64, true),
            (0xf3, 0, 64, false),
            (0xf3, 0, 32, false),
        ];
        for (machine, flags, bits, big_endian) in rows {
            let image = ElfMachine { machine, flags, bits, big_endian , e_type: 0};
            let offline = offline_selection(image)
                .unwrap_or_else(|| panic!("no offline row for {machine:#x}/{bits}"));
            assert_eq!(
                offline,
                elf_selection(&install, image).unwrap(),
                "offline row for machine {machine:#x} flags {flags:#x} bits {bits} \
                 big_endian {big_endian}"
            );
        }
        // A machine with no offline row and no install is refused, not guessed.
        let nowhere = Path::new("/ventris/does/not/exist");
        assert!(elf_selection(nowhere, ElfMachine {
            machine: 0xfffe, flags: 0, bits: 32, big_endian: false, e_type: 0
        })
        .is_err());
        assert_eq!(
            elf_selection(nowhere, ElfMachine {
                machine: 0x3e, flags: 0, bits: 64, big_endian: false, e_type: 0
            })
            .unwrap()
            .language,
            "x86:LE:64:default",
            "an import needs no install to record a language"
        );
    }

    #[test]
    fn a_secondary_list_and_key_shapes_are_read_as_ghidra_reads_them() {
        assert!(secondary_matches("0", 0));
        assert!(secondary_matches("0x800000", 0x0080_0000));
        assert!(!secondary_matches("0x800000", 0));
        assert!(!secondary_matches("golang", 0));
        assert!(secondary_matches("0b .... .... 1... .... .... .... .... ....", 0x0080_0000));
        assert!(!secondary_matches("0b .... .... 1... .... .... .... .... ....", 0x0040_0000));
        assert!(!secondary_matches("0b 1010", 0xa000_0000), "a short pattern is not a mask");
    }
}
