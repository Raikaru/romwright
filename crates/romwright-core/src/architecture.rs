//! Architecture discovery from an installed Ghidra processor tree.
//!
//! This is metadata discovery only: it never edits the pinned upstream tree.
//! Each returned language points at the directory whose `.sla` files can be
//! selected by a native consumer.

use romwright_model::ArchitectureSpec;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum ArchitectureError {
    #[error("architecture tree: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, ArchitectureError>;

/// Enumerates language definitions below every module of `install/Ghidra`.
///
/// Ghidra finds languages in every module, not only `Processors`: an
/// installed extension is a module too, and this install answers a
/// PlayStation 2 executable with `r5900:LE:32:default` from
/// `Ghidra/Extensions/ghidra-emotionengine-reloaded`. A consumer needs that
/// directory, because that is where the language's `.sla` lives.
pub fn discover(install: &Path) -> Result<Vec<ArchitectureSpec>> {
    let root = install.join("Ghidra");
    if !root.is_dir() {
        return Ok(Vec::new());
    }
    let mut groups: Vec<PathBuf> = std::fs::read_dir(&root)?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.is_dir())
        .collect();
    groups.sort();
    let mut specs = Vec::new();
    for group in groups {
        let mut modules: Vec<PathBuf> = std::fs::read_dir(&group)?
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| path.is_dir())
            .collect();
        modules.sort();
        for module in modules {
            let language_dir = module.join("data/languages");
            if !language_dir.is_dir() {
                continue;
            }
            let mut sla_count = 0;
            for entry in std::fs::read_dir(&language_dir)? {
                if entry?.path().extension().is_some_and(|ext| ext == "sla") {
                    sla_count += 1;
                }
            }
            for ldefs in language_dir_files(&language_dir)? {
                let xml = std::fs::read_to_string(&ldefs)?;
                for language in tags(&xml, "language") {
                    let Some(id) = attribute(language, "id") else {
                        continue;
                    };
                    let processor_name = attribute(language, "processor").unwrap_or_else(|| {
                        module
                            .file_name()
                            .map(|name| name.to_string_lossy().into_owned())
                            .unwrap_or_default()
                    });
                    let endian = attribute(language, "endian").unwrap_or_default();
                    let bits = attribute(language, "size").and_then(|size| size.parse().ok());
                    specs.push(ArchitectureSpec {
                        id,
                        processor: processor_name,
                        endian,
                        bits,
                        language_dir: language_dir.to_string_lossy().into_owned(),
                        sla_count,
                    });
                }
            }
        }
    }
    specs.sort_by(|left, right| left.id.cmp(&right.id));
    specs.dedup_by(|left, right| left.id == right.id);
    Ok(specs)
}
/// Finds the installed language directory containing `id`.
pub fn directory_for_id(install: &Path, id: &str) -> Result<Option<PathBuf>> {
    Ok(discover(install)?
        .into_iter()
        .find(|spec| spec.id == id)
        .map(|spec| PathBuf::from(spec.language_dir)))
}


/// Finds the compiled SLA file name for a language id by scanning the
/// language dir's .ldefs for the matching `<language ... slafile="...">`.
pub fn slafile_for_id(language_dir: &Path, id: &str) -> Result<Option<String>> {
    for ldefs in language_dir_files(language_dir)? {
        let xml = std::fs::read_to_string(&ldefs)?;
        for language in tags(&xml, "language") {
            if attribute(language, "id").as_deref() == Some(id) {
                return Ok(attribute(language, "slafile"));
            }
        }
    }
    Ok(None)
}

/// Test gate for a test that lifts with language `id`: true when `install`
/// holds its compiled `.sla`. Otherwise the test is skipped with a message that
/// says what to run, because a missing language (romwright compiles PSX, r5900,
/// VU, RSP, Xenon and Gekko itself, `python setup.py`) is not a defect in the
/// code under test. CI sets `ROMWRIGHT_REQUIRE_LANGUAGES` after provisioning the
/// languages, so there a missing one fails instead of silently dropping coverage.
#[cfg(test)]
pub(crate) fn language_installed(install: &Path, id: &str) -> bool {
    let compiled = directory_for_id(install, id)
        .ok()
        .flatten()
        .and_then(|dir| Some(dir.join(slafile_for_id(&dir, id).ok().flatten()?)))
        .is_some_and(|sla| sla.is_file());
    if compiled {
        return true;
    }
    let message = format!(
        "language {id} is not installed in {}; run `python setup.py` \
         (packaging/languages.py compiles romwright's own languages)",
        install.display()
    );
    if std::env::var_os("ROMWRIGHT_REQUIRE_LANGUAGES").is_some() {
        panic!("{message}");
    }
    eprintln!("SKIP: {message}");
    false
}

fn language_dir_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = std::fs::read_dir(dir)?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().is_some_and(|ext| ext == "ldefs"))
        .collect::<Vec<_>>();
    files.sort();
    Ok(files)
}

fn tags<'a>(xml: &'a str, _name: &str) -> impl Iterator<Item = &'a str> {
    let mut found = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find("<language ") {
        let tag = &rest[start..];
        let Some(end) = tag.find('>') else {
            break;
        };
        found.push(&tag[..end]);
        rest = &tag[end..];
    }
    found.into_iter()
}

fn attribute(tag: &str, name: &str) -> Option<String> {
    let marker = format!("{name}=\"");
    let start = tag.find(&marker)? + marker.len();
    let end = tag[start..].find('"')?;
    Some(tag[start..start + end].to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn discovers_language_metadata_without_mutating_tree() {
        let root = std::env::temp_dir().join(format!(
            "romwright-arch-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let languages = root.join("Ghidra/Processors/ARM/data/languages");
        fs::create_dir_all(&languages).unwrap();
        fs::write(
            languages.join("ARM.ldefs"),
            r#"<language_definitions><language id="ARM:LE:32:v8" processor="ARM" endian="little" size="32"/></language_definitions>"#,
        )
        .unwrap();
        fs::write(languages.join("ARM8_le.sla"), b"sla").unwrap();
        let specs = discover(&root).unwrap();
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].id, "ARM:LE:32:v8");
        assert_eq!(specs[0].bits, Some(32));
        assert_eq!(specs[0].sla_count, 1);
        assert!(languages.join("ARM.ldefs").is_file());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn resolves_installed_xenon_language() {
        let install = crate::native_runtime::ghidra_dir();
        let id = "PowerPC:BE:64:Xenon-32addr";
        if !language_installed(&install, id) {
            return;
        }
        let dir = directory_for_id(&install, id).unwrap().expect("language_installed found it");
        let sla = slafile_for_id(&dir, id).unwrap().expect("no slafile in xenon.ldefs");
        assert!(dir.join(sla).is_file(), "xenon.sla missing in {}", dir.display());
    }
}
