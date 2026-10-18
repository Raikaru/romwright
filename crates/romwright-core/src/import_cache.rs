//! Reuse of an import whose inputs have not changed.
//!
//! Analysing the same bytes with the same analyser twice produces the same
//! facts, and the gates do it constantly: 72 of them shell out to `romwright-cli
//! import`, and before this only 14 shared any reuse at all, so one CI run
//! re-analysed the same twenty corpus binaries dozens of times. The cache
//! lives inside the importer rather than in each gate, so every consumer --
//! gates, the CLI, the GUI, an agent -- gets it without asking.
//!
//! What an import depends on, and therefore what the key is:
//!
//! * the image's own bytes;
//! * the analyser that read them -- this executable (which carries the in-process
//!   SLEIGH lifter) and the decompiler worker, by content digest. This is the m4-014 lesson: a
//!   stale worker drove a measurement for three rounds, and a key that named
//!   anything less would bring that back;
//! * the configuration that changes facts (the language and spec pins, and
//!   each analysis switch). Decoder lane count is deliberately absent: it
//!   changes wall time, never facts;
//! * the store schema, since a cached database is restored wholesale.
//!
//! A cached entry is the project database itself, restored by copy. That is
//! only sound when the project holds exactly this one program, which is the
//! shape every gate uses; an import into a project that already holds other
//! programs bypasses the cache entirely rather than risk overwriting them.
//!
//! `ROMWRIGHT_NO_IMPORT_CACHE=1` switches reuse off. A gate that measures
//! import cost must set it, or it measures a file copy.

use std::path::{Path, PathBuf};

use crate::session::RuntimeConfig;

/// Where cached imports live, or `None` when reuse is switched off.
pub fn cache_root() -> Option<PathBuf> {
    if std::env::var_os("ROMWRIGHT_NO_IMPORT_CACHE").is_some() {
        return None;
    }
    if let Some(configured) = std::env::var_os("ROMWRIGHT_IMPORT_CACHE") {
        let path = PathBuf::from(configured);
        return (!path.as_os_str().is_empty()).then_some(path);
    }
    let home = std::env::home_dir()?;
    Some(home.join(".cache/romwright/imports"))
}

/// SHA-256 of a file's bytes, or `None` when it cannot be read.
///
/// Hashed as a stream: the file may be a multi-gigabyte disc image, and the
/// caller (a cache key) only needs the hash.
pub fn digest(path: &Path) -> Option<String> {
    let file = std::fs::File::open(path).ok()?;
    crate::sha256::digest_reader(file).ok().map(crate::sha256::hex)
}

/// SHA-256 of the bytes an import reads from `path`: the program view of a
/// large 3DS card (`native::read_input`), else the whole file (streamed). It
/// is the digest of the input artifact the import stores.
pub fn input_digest(path: &Path) -> Option<String> {
    match crate::native::threeds::program_view(path).ok()? {
        Some(view) => Some(digest_bytes(&view)),
        None => digest(path),
    }
}

/// SHA-256 of arbitrary bytes, hex-encoded.
pub fn digest_bytes(bytes: &[u8]) -> String {
    sha256(bytes)
}

/// SHA-256, from the same implementation the rest of the crate uses.
fn sha256(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let hash = crate::sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in hash {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Fingerprint of every installed language definition the lifter could decode with.
///
/// The key is built before the image's language is known, and the language
/// behind an id lives in the Ghidra install (`Ghidra/<group>/<module>/data/
/// languages`), not in anything the configuration names: reinstalling a
/// language (a new `.sla`, a changed `.pspec`/`.cspec`/`.ldefs`) changes the
/// facts an import produces under the same id. So every `.sla`, `.ldefs`,
/// `.pspec` and `.cspec` of the install enters the key by relative path, size
/// and modification time. Metadata rather than content: the `.sla` files total
/// well over a hundred megabytes and the key is computed for every import. A
/// touched file only costs a cache miss.
pub(crate) fn languages_fingerprint(install: &Path) -> String {
    let mut files = Vec::new();
    let root = install.join("Ghidra");
    let subdirectories = |dir: &Path| -> Vec<PathBuf> {
        std::fs::read_dir(dir)
            .map(|entries| entries.filter_map(|entry| entry.ok().map(|entry| entry.path())).collect())
            .unwrap_or_default()
    };
    for group in subdirectories(&root) {
        for module in subdirectories(&group) {
            let languages = module.join("data/languages");
            for file in subdirectories(&languages) {
                let relevant = file
                    .extension()
                    .is_some_and(|ext| ["sla", "ldefs", "pspec", "cspec"].iter().any(|want| ext == *want));
                let Ok(meta) = std::fs::metadata(&file) else { continue };
                if !relevant || !meta.is_file() {
                    continue;
                }
                let modified = meta
                    .modified()
                    .ok()
                    .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                    .map_or(0, |elapsed| elapsed.as_nanos());
                let relative = file.strip_prefix(install).unwrap_or(&file);
                files.push(format!("{}:{}:{modified}", relative.display(), meta.len()));
            }
        }
    }
    files.sort();
    sha256(files.join("\n").as_bytes())
}

/// The key an import's facts depend on.
///
/// `flavour` names everything about the request that changes the stored
/// facts but is not part of the configuration: whether analysis ran, and
/// which signature databases were applied, since a matched signature renames
/// functions in the store.
pub fn key(binary: &Path, program: &str, config: &RuntimeConfig) -> Option<String> {
    let image = input_digest(binary)?;
    // The analyser: this executable, plus the worker child that produces
    // facts. A missing child is named as missing rather than ignored.
    let mut analyser = String::new();
    for path in [
        std::env::current_exe().ok(),
        Some(config.worker_path.clone()),
    ] {
        analyser.push('|');
        match path.as_deref().and_then(digest) {
            Some(hash) => analyser.push_str(&hash),
            None => analyser.push_str("absent"),
        }
    }
    // Configuration that changes facts. Lane count is not here: it changes
    // wall time, never an answer.
    let settings = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        config.language_id,
        config.language_dir.display(),
        config
            .sla_path
            .as_ref()
            .map_or_else(String::new, |p| p.display().to_string()),
        config.register_params,
        config.promote_tailcalls,
        config.switch_vsa,
        config.switch_decompiler,
        config.branchind_candidates,
        config.branchind_recovery,
        config.switch_work_budget,
        // The compiler identity and the rules keyed by it change facts.
        config.compiler.as_deref().unwrap_or(""),
        crate::compiler::rules::fingerprint(),
    );
    // v2: v1 entries published under tmpfs pressure held degraded facts
    // (a disk-starved run stored partial analyses that read back fine),
    // so every v1 entry is suspect. Old files linger inertly; only v2
    // keys are ever queried.
    // v3: the installed language definitions entered the key (a reinstalled
    // `.sla` under an unchanged id served stale facts from v2 entries).
    let languages = languages_fingerprint(&config.ghidra_install);
    Some(sha256(
        format!(
            "v3|{image}|{program}|{analyser}|{settings}|{languages}|schema{}",
            romwright_db::SCHEMA_VERSION
        )
        .as_bytes(),
    ))
}

/// Where the entry for `key` lives, when reuse is on.
pub fn entry(key: &str) -> Option<PathBuf> {
    cache_root().map(|root| root.join(format!("{key}.sqlite")))
}

/// The entry for `key`, when it exists.
pub fn hit(key: &str) -> Option<PathBuf> {
    entry(key).filter(|path| path.is_file())
}

/// Publishes `source` as the entry for `key`, best effort.
///
/// The write goes to a sibling and is renamed, which is atomic within a
/// filesystem, so a concurrent reader never sees half an entry.
pub fn publish(key: &str, source: &Path) {
    let Some(target) = entry(key) else {
        return;
    };
    let Some(root) = target.parent() else {
        return;
    };
    if std::fs::create_dir_all(root).is_err() {
        return;
    }
    let staging = root.join(format!("{key}.writing.{}", std::process::id()));
    if std::fs::rename(source, &staging).is_ok() || std::fs::copy(source, &staging).is_ok() {
        let _ = std::fs::rename(&staging, &target);
    }
    let _ = std::fs::remove_file(&staging);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn install(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("romwright-cache-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let languages = root.join("Ghidra/Extensions/RomwrightPsx/data/languages");
        std::fs::create_dir_all(&languages).unwrap();
        std::fs::write(languages.join("psx.sla"), b"first sla").unwrap();
        std::fs::write(languages.join("psx.slaspec"), b"source, not part of the fingerprint").unwrap();
        root
    }

    #[test]
    fn a_reinstalled_language_changes_the_fingerprint() {
        let root = install("fingerprint");
        let sla = root.join("Ghidra/Extensions/RomwrightPsx/data/languages/psx.sla");
        let before = languages_fingerprint(&root);
        assert_eq!(before, languages_fingerprint(&root), "stable while nothing changes");
        std::fs::write(&sla, b"a different, longer sla").unwrap();
        assert_ne!(before, languages_fingerprint(&root));
        let after = languages_fingerprint(&root);
        std::fs::write(sla.with_file_name("psx.slaspec"), b"edited source").unwrap();
        assert_eq!(after, languages_fingerprint(&root), "only compiled/spec files count");
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_reinstalled_language_is_a_new_import_key() {
        let root = install("key");
        let image = root.join("image.bin");
        std::fs::write(&image, b"\x00\x01\x02\x03").unwrap();
        let mut config = RuntimeConfig::from_env();
        config.ghidra_install = root.clone();
        let before = key(&image, "p", &config).expect("key");
        assert_eq!(Some(before.clone()), key(&image, "p", &config));
        std::fs::write(
            root.join("Ghidra/Extensions/RomwrightPsx/data/languages/psx.sla"),
            b"recompiled sla with other semantics",
        )
        .unwrap();
        assert_ne!(Some(before), key(&image, "p", &config));
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn an_install_without_languages_still_has_a_fingerprint() {
        let root = std::env::temp_dir().join(format!("romwright-cache-none-{}", std::process::id()));
        assert_eq!(languages_fingerprint(&root), languages_fingerprint(&root));
    }
}
