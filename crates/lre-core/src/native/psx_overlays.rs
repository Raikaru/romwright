//! PSX overlay sets (P3.2): a PSX game is rarely one PS-EXE. The main
//! executable loads overlay binaries at runtime — each a PS-EXE with its
//! own destination address — and calls across them. An overlay set is
//! the main EXE plus every overlay, each mapped at its declared
//! destination so cross-overlay calls resolve.
//!
//! The set is described by a manifest the caller supplies: a list of
//! (name, file bytes) pairs where the first is the main executable and
//! the rest are overlays. Each is parsed by the PS-EXE loader; the
//! imports are returned as separate images so the program database
//! holds them as siblings.

use super::{psx, NativeImport, Result};

/// One overlay set member: its name and the parsed import.
pub struct OverlayMember {
    pub name: String,
    pub import: NativeImport,
}

/// Imports a PSX overlay set: each member is a PS-EXE parsed on its own,
/// returned in manifest order. The main executable is first.
///
/// Overlays that share a destination address are legal — the console
/// swaps them — so no overlap check runs across members. Each member's
/// own header is still validated by the PS-EXE loader.
pub fn import_set(members: &[(String, Vec<u8>)]) -> Result<Vec<OverlayMember>> {
    let mut out = Vec::with_capacity(members.len());
    for (name, data) in members {
        if !psx::is_executable(data) {
            return super::err(&format!(
                "overlay set member {name} is not a PS-EXE"
            ));
        }
        let import = psx::import(data)?;
        out.push(OverlayMember {
            name: name.clone(),
            import,
        });
    }
    Ok(out)
}
