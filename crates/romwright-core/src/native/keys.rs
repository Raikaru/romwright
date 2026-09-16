//! User-supplied console keys, loaded from a file the analyst provides.
//!
//! The console loaders decrypt with bundled *public* keys where those exist
//! (the XEX retail key, the PS3 APP vault, the Vita public MetaKeys, the 3DS
//! zeros fixed key). What they cannot invent is the other class: keys the
//! console holds in its keyblobs (Switch `prod.keys`, PSP KIRK device keys),
//! per-title licenses (PS3 RAP, Vita klic, 3DS titlekeys), and the 3DS
//! console-provisioned keyslots. AGENTS.md II.1 forbids fetching any of that
//! at runtime, so the only honest source is a file the user dumps from their
//! own console and points the importer at.
//!
//! `KeyStore` is that channel. It parses the two shapes key material
//! actually arrives in:
//!
//! - **Named text** (`prod.keys`, `keys.txt`, `boot9` dumps): one
//!   `name = hex` per line, `#`/`;` comments, blank lines ignored. This is
//!   the hactool/Lockpick `prod.keys` format and the GodMode9 `aes_keys.txt`
//!   format, so an existing dump drops in unchanged.
//! - **Raw binary** (`.rap`, `.klic`, a single key blob): the file *is* the
//!   key. The loader that needs it names the expected length; a raw file is
//!   surfaced under its file name so `keys.get("title.rap")` works.
//!
//! A loader asks for a key by the name its format documentation uses —
//! `header_key`, `key_area_key_application`, `rap`, `klic`, `slot0x2C` — and
//! gets `Option<&[u8]>`. `None` means "the user did not supply it", which the
//! loader reports as the same clear key-gap error it raises today; the only
//! change is that a supplied key now reaches the decrypt path instead of the
//! error being unconditional.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::ImportError;

fn err(message: impl Into<String>) -> ImportError {
    ImportError::Bad(message.into())
}

/// Keys the user supplied, keyed by the name a loader asks for.
///
/// Text files contribute every `name = hex` line; a raw binary file
/// contributes one entry under its file name (and, for a `.rap`/`.klic`,
/// under the extension-less stem too, so `title.rap` answers `rap` lookups
/// scoped to that title).
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct KeyStore {
    /// `name -> key bytes`, lower-cased name.
    keys: BTreeMap<String, Vec<u8>>,
    /// Raw binary key files, in the order given, for loaders that match a
    /// key by length or content rather than by name.
    raw: Vec<(String, Vec<u8>)>,
}

impl KeyStore {
    /// An empty store: every lookup is `None`, so loaders behave exactly as
    /// they did before a key channel existed.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Loads one key source. `path` may be a named text file (`prod.keys`,
    /// `keys.txt`, `aes_keys.txt`) or a raw binary key (`.rap`, `.klic`, a
    /// bare key blob). The format is sniffed: a file that parses as
    /// `name = hex` lines is text; anything else is raw.
    pub fn load(path: &Path) -> Result<Self, ImportError> {
        let bytes = std::fs::read(path).map_err(|e| err(format!("{}: {e}", path.display())))?;
        let mut store = Self::empty();
        if let Some(text) = Self::as_text(&bytes) {
            store.parse_text(&text, path)?;
        }
        // A raw file is always also recorded under its name so a loader can
        // ask for it directly; a text file's raw bytes are not a key.
        if store.keys.is_empty() || Self::is_raw_name(path) {
            let name = path
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "key".into());
            store.raw.push((name.clone(), bytes.clone()));
            store.keys.entry(name.to_lowercase()).or_insert(bytes);
        }
        Ok(store)
    }

    /// Merges several key sources (a `--keys` flag given more than once, or a
    /// directory of dumps). Later files override earlier ones on a name
    /// collision — the more specific file wins.
    pub fn load_all(paths: &[PathBuf]) -> Result<Self, ImportError> {
        let mut store = Self::empty();
        for path in paths {
            let part = Self::load(path)?;
            store.keys.extend(part.keys);
            store.raw.extend(part.raw);
        }
        Ok(store)
    }

    /// The key named `name`, case-insensitive, if the user supplied it.
    pub fn get(&self, name: &str) -> Option<&[u8]> {
        self.keys.get(&name.to_lowercase()).map(Vec::as_slice)
    }

    /// The key named `name` decoded to exactly `N` bytes, or `None` when
    /// absent or the wrong length (a wrong-length key is a malformed dump,
    /// not a missing one — the loader reports it as a key gap either way).
    pub fn get_array<const N: usize>(&self, name: &str) -> Option<[u8; N]> {
        self.get(name)?.try_into().ok()
    }

    /// Every raw binary key file, for loaders that select a key by length or
    /// by trying each candidate (a RAP is matched to its SELF by decryption
    /// succeeding, not by name).
    pub fn raw_keys(&self) -> &[(String, Vec<u8>)] {
        &self.raw
    }

    /// True when no key material was supplied at all.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty() && self.raw.is_empty()
    }

    /// A file counts as raw when its extension names a binary key container.
    fn is_raw_name(path: &Path) -> bool {
        matches!(
            path.extension().and_then(|e| e.to_str()).map(|e| e.to_lowercase()),
            Some(ext) if matches!(ext.as_str(), "rap" | "klic" | "key" | "bin" | "dat")
        )
    }

    /// Interprets `bytes` as UTF-8 text only when it looks like a key file:
    /// at least one `name = hex` line. A binary blob that happens to be
    /// valid UTF-8 but has no `=` is not a text key file.
    fn as_text(bytes: &[u8]) -> Option<String> {
        let text = String::from_utf8(bytes.to_vec()).ok()?;
        let has_entry = text.lines().any(|line| {
            let line = line.trim();
            !line.is_empty()
                && !line.starts_with('#')
                && !line.starts_with(';')
                && line.contains('=')
        });
        has_entry.then_some(text)
    }

    /// Parses `name = hex` lines into the store. `name` is lower-cased; the
    /// hex may carry `0x`, spaces, or colons. A malformed line is skipped, not
    /// fatal — real `prod.keys` files carry comments and section headers.
    fn parse_text(&mut self, text: &str, path: &Path) -> Result<(), ImportError> {
        for (lineno, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            let Some((name, hex)) = line.split_once('=') else {
                continue;
            };
            let name = name.trim().to_lowercase();
            let hex: String = hex
                .trim()
                .trim_start_matches("0x")
                .trim_start_matches("0X")
                .chars()
                .filter(|c| !c.is_whitespace() && *c != ':')
                .collect();
            let Ok(bytes) = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(hex.get(i..i + 2).unwrap_or("0"), 16))
                .collect::<Result<Vec<u8>, _>>()
            else {
                continue; // not hex — a comment or header line, skip it
            };
            if name.is_empty() || bytes.is_empty() {
                continue;
            }

            self.keys.insert(name, bytes);
        }
        if self.keys.is_empty() && !Self::is_raw_name(path) {
            return Err(err(format!(
                "{}: no `name = hex` key lines parsed",
                path.display()
            )));
        }
        Ok(())
    }

    /// Test-only: parse `name = hex` text directly, without a file.
    #[cfg(test)]
    pub(crate) fn parse_text_for_test(&mut self, text: &str) {
        let _ = self.parse_text(text, Path::new("test.keys"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_tmp(name: &str, bytes: &[u8]) -> PathBuf {
        let path = std::env::temp_dir().join(format!("keystore-test-{name}"));
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(bytes).unwrap();
        path
    }

    #[test]
    fn prod_keys_text_parses_named_hex() {
        let path = write_tmp(
            "prod.keys",
            b"# Lockpick dump\nheader_key = AABBCCDDEEFF00112233445566778899\n\
              ; comment\nkey_area_key_application_00 = 00112233445566778899AABBCCDDEEFF\n",
        );
        let store = KeyStore::load(&path).unwrap();
        assert_eq!(
            store.get("HEADER_KEY").unwrap(),
            &[
                0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                0x88, 0x99
            ]
        );
        assert!(store.get("key_area_key_application_00").is_some());
        assert!(store.get("missing").is_none());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn raw_rap_file_is_a_key_under_its_name() {
        let path = write_tmp("title.rap", &[0xabu8; 16]);
        let store = KeyStore::load(&path).unwrap();
        // A raw file registers under its full file name.
        let fname = path.file_name().unwrap().to_string_lossy().to_lowercase();
        assert_eq!(store.get(&fname).unwrap(), &[0xabu8; 16]);
        assert_eq!(store.raw_keys().len(), 1);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn get_array_enforces_length() {
        let path = write_tmp("len.keys", b"short = aabb\nlong = aabbcc\n");
        let store = KeyStore::load(&path).unwrap();
        assert!(store.get_array::<2>("short").is_some());
        assert!(store.get_array::<16>("short").is_none()); // wrong length
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn empty_store_answers_none() {
        let store = KeyStore::empty();
        assert!(store.is_empty());
        assert!(store.get("header_key").is_none());
    }
}
