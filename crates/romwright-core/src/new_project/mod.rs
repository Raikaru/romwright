//! `romwright new-project`: bootstrap a ready-to-decompile repository from a
//! retail image, the way decomp-toolkit's dtk-template does for GameCube/Wii.
//!
//! The framework is a [`platforms`] matrix (what is implemented and what each
//! other platform needs), a pinned tool [`manifest`], compiler detection
//! ([`compiler`]) and one plugin per platform. A plugin is a pure function from
//! an image plus the facts romwright already holds to a list of files, so its
//! output is testable without a store, a toolchain or a network. Only PS2
//! ([`ps2`]) is implemented; see `docs/new-project.md` for the rest.
//!
//! romwright never downloads or bundles a tool. The generated project's
//! `configure.py` fetches the entries of its `config/toolchain.json` (url +
//! sha256 each) or uses the tools a toolchain profile names.

pub mod compiler;
pub mod detect;
pub mod dol_layout;
pub mod elf;
pub mod gc;
pub mod gc_compiler;
pub mod iso;
pub mod manifest;
pub mod mips;
pub mod n64;
pub mod platforms;
pub mod ps2;
pub mod psp;
pub mod psx;
pub mod rel_layout;
pub mod scaffold;
pub mod scaffold_obj;
pub mod arm;
pub mod gba;
pub mod nds;
pub mod pe;

use std::path::Path;

/// One file of a generated project.
#[derive(Debug, Clone)]
pub struct GeneratedFile {
    /// Project-relative, `/`-separated.
    pub path: String,
    pub bytes: Vec<u8>,
    pub executable: bool,
}

/// Writes `files` below `outdir`. Existing files are overwritten: a generated
/// project is regenerated, never merged. `orig/` and the store are not touched.
pub fn write_files(outdir: &Path, files: &[GeneratedFile]) -> std::io::Result<()> {
    for file in files {
        let path = outdir.join(&file.path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, &file.bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = if file.executable { 0o755 } else { 0o644 };
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))?;
        }
    }
    Ok(())
}

/// A PS2 image is identified for platform routing by its ELF header alone:
/// 32-bit little-endian MIPS, which is what the Emotion Engine boot file is.
pub fn looks_like_ps2_elf(image: &[u8]) -> bool {
    image.len() > 20
        && &image[..4] == b"\x7fELF"
        && image[4] == 1
        && image[5] == 1
        && u16::from_le_bytes([image[18], image[19]]) == 8
        && !psp::looks_like_psp_elf(image)
}

/// The platform of a PSP ELF, a PS-X EXE or a cartridge ROM in any dump order
/// (the MIPS platforms `new-project` splits with splat besides the PS2).
pub fn detect_mips_platform(image: &[u8]) -> Option<&'static str> {
    if psp::looks_like_psp_elf(image) {
        Some("psp")
    } else if psx::looks_like_psx_exe(image) {
        Some("psx")
    } else if n64::byte_order(image).is_some() {
        Some("n64")
    } else {
        None
    }
}

/// The platform of a GBA or Nintendo DS cartridge ROM (the ARM platforms `new-project` builds without splat).
pub fn detect_arm_platform(image: &[u8]) -> Option<&'static str> {
    if gba::looks_like_gba_rom(image) {
        Some("gba")
    } else if nds::looks_like_nds_rom(image) {
        Some("nds")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_files_creates_directories_and_sets_modes() {
        let dir = std::env::temp_dir().join(format!("romwright-newproject-{}", std::process::id()));
        let files = vec![
            GeneratedFile { path: "a/b/c.txt".into(), bytes: b"x".to_vec(), executable: false },
            GeneratedFile { path: "run.py".into(), bytes: b"#!".to_vec(), executable: true },
        ];
        write_files(&dir, &files).unwrap();
        assert_eq!(std::fs::read(dir.join("a/b/c.txt")).unwrap(), b"x");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(dir.join("run.py")).unwrap().permissions().mode() & 0o111, 0o111);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn routes_only_mips_le_elf_to_ps2() {
        let mut image = vec![0u8; 64];
        image[..4].copy_from_slice(b"\x7fELF");
        image[4] = 1;
        image[5] = 1;
        image[18] = 8;
        assert!(looks_like_ps2_elf(&image));
        image[18] = 3;
        assert!(!looks_like_ps2_elf(&image));
    }
}
