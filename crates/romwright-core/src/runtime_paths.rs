//! Where the runtime's own files are looked for when no environment variable
//! names them.
//!
//! A release archive unpacks anywhere (`bin/`, `share/romwright/`), a source
//! checkout keeps the same files under the repository, and the pinned Ghidra
//! language data may sit in the user's home directory. Each resource therefore
//! has an ordered candidate list, first existing candidate wins:
//!
//! 1. beside the running executable (`<exe dir>/ghidra_opt`,
//!    `<exe dir>/../share/romwright/...`): a release archive;
//! 2. inside the source checkout the binary was built from
//!    (`CARGO_MANIFEST_DIR/../..`): `native/build/ghidra_opt`,
//!    `native/specs`, `oracle/library-prototypes-v1`, `build/ghidra`
//!    (where `setup.py` extracts the language data);
//! 3. the user's home directory (`~/ghidra_12.1.3_PUBLIC`, Ghidra only).
//!
//! An environment variable (`ROMWRIGHT_GHIDRA_OPT`, `ROMWRIGHT_SPECS`,
//! `ROMWRIGHT_LIBRARY_PROTOTYPES`, `ROMWRIGHT_GHIDRA`) is read by the caller
//! and beats all of this. When nothing exists, the last candidate is returned
//! anyway so a message can name a path.

use std::path::{Path, PathBuf};

/// Directory the pinned Ghidra language data is extracted to inside a source
/// checkout by `setup.py` (relative to the repository root).
pub const CHECKOUT_GHIDRA: &str = "build/ghidra";

/// The roots the candidates are built from. A value, not process state, so the
/// order is testable.
#[derive(Debug, Clone)]
pub struct Layout {
    /// Directory holding the running executable.
    pub exe_dir: Option<PathBuf>,
    /// The source checkout the binary was built from (may not exist on the
    /// machine a shipped binary runs on).
    pub repo_root: PathBuf,
    /// The user's home directory.
    pub home: Option<PathBuf>,
}

impl Layout {
    /// The layout of the running process.
    pub fn current() -> Self {
        Self {
            exe_dir: std::env::current_exe()
                .ok()
                .and_then(|exe| exe.parent().map(Path::to_path_buf)),
            repo_root: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."),
            home: std::env::home_dir(),
        }
    }

    /// `<exe dir>/../share/romwright`, the data directory of a release archive.
    fn share(&self) -> Option<PathBuf> {
        self.exe_dir
            .as_ref()
            .map(|dir| dir.join("..").join("share").join("romwright"))
    }

    fn first_existing(candidates: Vec<PathBuf>, exists: impl Fn(&Path) -> bool) -> Option<PathBuf> {
        candidates.into_iter().find(|candidate| exists(candidate))
    }

    /// The patched decompiler: `<exe dir>/ghidra_opt[.exe]`, then
    /// `native/build/ghidra_opt[.exe]` in the checkout.
    pub fn decompiler(&self) -> PathBuf {
        let name = format!("ghidra_opt{}", std::env::consts::EXE_SUFFIX);
        let checkout = self.repo_root.join("native/build").join(&name);
        let mut candidates = Vec::new();
        if let Some(dir) = &self.exe_dir {
            candidates.push(dir.join(&name));
        }
        candidates.push(checkout.clone());
        Self::first_existing(candidates, Path::is_file).unwrap_or(checkout)
    }

    /// The spec bundle root: `<exe dir>/../share/romwright/specs`, then
    /// `native/specs`.
    pub fn specs(&self) -> PathBuf {
        let checkout = self.repo_root.join("native/specs");
        let mut candidates = Vec::new();
        if let Some(share) = self.share() {
            candidates.push(share.join("specs"));
        }
        candidates.push(checkout.clone());
        Self::first_existing(candidates, Path::is_dir).unwrap_or(checkout)
    }

    /// The library prototypes file:
    /// `<exe dir>/../share/romwright/library-prototypes-v1/generic_clib_64.json`,
    /// then `oracle/library-prototypes-v1/generic_clib_64.json`.
    pub fn library_prototypes(&self) -> PathBuf {
        let file = Path::new("library-prototypes-v1/generic_clib_64.json");
        let checkout = self.repo_root.join("oracle").join(file);
        let mut candidates = Vec::new();
        if let Some(share) = self.share() {
            candidates.push(share.join(file));
        }
        candidates.push(checkout.clone());
        Self::first_existing(candidates, Path::is_file).unwrap_or(checkout)
    }

    /// The Ghidra install root whose `Ghidra/Processors/*/data` is read:
    /// `<exe dir>/../share/romwright/ghidra`, then `build/ghidra` in the
    /// checkout, then `~/ghidra_12.1.3_PUBLIC`. A candidate counts when its
    /// `Ghidra` directory exists.
    pub fn ghidra(&self) -> PathBuf {
        let home = self
            .home
            .clone()
            .unwrap_or_default()
            .join("ghidra_12.1.3_PUBLIC");
        let mut candidates = Vec::new();
        if let Some(share) = self.share() {
            candidates.push(share.join("ghidra"));
        }
        candidates.push(self.repo_root.join(CHECKOUT_GHIDRA));
        candidates.push(home.clone());
        Self::first_existing(candidates, |root| root.join("Ghidra").is_dir()).unwrap_or(home)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(label: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "romwright-paths-{label}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir_all(&root).unwrap();
            Self(root)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn touch(path: &Path) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, b"x").unwrap();
    }

    fn layout(root: &Path) -> Layout {
        Layout {
            exe_dir: Some(root.join("pkg/bin")),
            repo_root: root.join("checkout"),
            home: Some(root.join("home")),
        }
    }

    #[test]
    fn archive_files_beat_checkout_files() {
        let scratch = Scratch::new("archive");
        let root = &scratch.0;
        let name = format!("ghidra_opt{}", std::env::consts::EXE_SUFFIX);
        for path in [
            root.join("pkg/bin").join(&name),
            root.join("checkout/native/build").join(&name),
            root.join("pkg/share/romwright/specs/x/pspec.xml"),
            root.join("checkout/native/specs/x/pspec.xml"),
            root.join("pkg/share/romwright/library-prototypes-v1/generic_clib_64.json"),
            root.join("checkout/oracle/library-prototypes-v1/generic_clib_64.json"),
            root.join("pkg/share/romwright/ghidra/Ghidra/Processors/x86/data/a"),
            root.join("checkout/build/ghidra/Ghidra/Processors/x86/data/a"),
            root.join("home/ghidra_12.1.3_PUBLIC/Ghidra/Processors/x86/data/a"),
        ] {
            touch(&path);
        }
        let layout = layout(root);
        assert_eq!(layout.decompiler(), root.join("pkg/bin").join(&name));
        assert_eq!(layout.specs(), root.join("pkg/bin/../share/romwright/specs"));
        assert_eq!(
            layout.library_prototypes(),
            root.join("pkg/bin/../share/romwright/library-prototypes-v1/generic_clib_64.json")
        );
        assert_eq!(layout.ghidra(), root.join("pkg/bin/../share/romwright/ghidra"));
    }

    #[test]
    fn checkout_files_beat_the_home_install() {
        let scratch = Scratch::new("checkout");
        let root = &scratch.0;
        let name = format!("ghidra_opt{}", std::env::consts::EXE_SUFFIX);
        for path in [
            root.join("checkout/native/build").join(&name),
            root.join("checkout/native/specs/x/pspec.xml"),
            root.join("checkout/oracle/library-prototypes-v1/generic_clib_64.json"),
            root.join("checkout/build/ghidra/Ghidra/Processors/x86/data/a"),
            root.join("home/ghidra_12.1.3_PUBLIC/Ghidra/Processors/x86/data/a"),
        ] {
            touch(&path);
        }
        let layout = layout(root);
        assert_eq!(layout.decompiler(), root.join("checkout/native/build").join(&name));
        assert_eq!(layout.specs(), root.join("checkout/native/specs"));
        assert_eq!(
            layout.library_prototypes(),
            root.join("checkout/oracle/library-prototypes-v1/generic_clib_64.json")
        );
        assert_eq!(layout.ghidra(), root.join("checkout/build/ghidra"));
    }

    #[test]
    fn the_home_install_is_the_last_resort_and_the_default_name() {
        let scratch = Scratch::new("home");
        let root = &scratch.0;
        let layout = layout(root);
        // Nothing exists: the home path is still named, for the message.
        assert_eq!(layout.ghidra(), root.join("home/ghidra_12.1.3_PUBLIC"));
        touch(&root.join("home/ghidra_12.1.3_PUBLIC/Ghidra/Processors/x86/data/a"));
        assert_eq!(layout.ghidra(), root.join("home/ghidra_12.1.3_PUBLIC"));
    }

    #[test]
    fn a_ghidra_directory_without_a_ghidra_subdirectory_does_not_count() {
        let scratch = Scratch::new("empty");
        let root = &scratch.0;
        fs::create_dir_all(root.join("pkg/share/romwright/ghidra")).unwrap();
        touch(&root.join("checkout/build/ghidra/Ghidra/Processors/x86/data/a"));
        assert_eq!(layout(root).ghidra(), root.join("checkout/build/ghidra"));
    }
}
