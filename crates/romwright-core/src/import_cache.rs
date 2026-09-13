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
//! * the analyser that read them -- this executable, the SLEIGH console and
//!   the decompiler worker, by content digest. This is the m4-014 lesson: a
//!   stale worker drove a measurement for three rounds, and a key that named
//!   anything less would bring that back;
//! * the configuration that changes facts (the language and spec pins, and
//!   each analysis switch). Console shard count is deliberately absent: it
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
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".cache/romwright/imports"))
}

/// SHA-256 of a file's bytes, or `None` when it cannot be read.
fn digest(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    Some(sha256(&bytes))
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

/// The key an import's facts depend on.
///
/// `flavour` names everything about the request that changes the stored
/// facts but is not part of the configuration: whether analysis ran, and
/// which signature databases were applied, since a matched signature renames
/// functions in the store.
pub fn key(binary: &Path, program: &str, config: &RuntimeConfig) -> Option<String> {
    let image = digest(binary)?;
    // The analyser: this executable, plus the two children that produce
    // facts. A missing child is named as missing rather than ignored.
    let mut analyser = String::new();
    for path in [
        std::env::current_exe().ok(),
        config.console_path.clone(),
        Some(config.worker_path.clone()),
    ] {
        analyser.push('|');
        match path.as_deref().and_then(digest) {
            Some(hash) => analyser.push_str(&hash),
            None => analyser.push_str("absent"),
        }
    }
    // Configuration that changes facts. Shard count is not here: it changes
    // wall time, never an answer.
    let settings = format!(
        "{}|{}|{}|{}|{}|{}|{}",
        config.language_id,
        config.language_dir.display(),
        config.sla_path.as_ref().map_or_else(String::new, |p| p.display().to_string()),
        config.register_params,
        config.promote_tailcalls,
        config.switch_vsa,
        config.switch_decompiler,
    );
    // v2: v1 entries published under tmpfs pressure held degraded facts
    // (a disk-starved run stored partial analyses that read back fine),
    // so every v1 entry is suspect. Old files linger inertly; only v2
    // keys are ever queried.
    Some(sha256(
        format!(
            "v2|{image}|{program}|{analyser}|{settings}|schema{}",
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
