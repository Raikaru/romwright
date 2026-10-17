//! The mapped image a file path loads as.
use super::{NativeRuntimeError, Result};
use crate::native::NativeImport;
use std::io::Read;
use std::path::Path;

/// The native import of an ELF or DOL at `binary`, which keeps loader mode
/// facts beside the mappings (byte chunks alone cannot distinguish ARM from
/// Thumb); `None` for a PE or a raw image.
pub(super) fn parse_binary(
    cfg: &crate::session::RuntimeConfig,
    binary: &Path,
) -> Result<Option<NativeImport>> {
    let mut file = std::fs::File::open(binary)
        .map_err(|e| NativeRuntimeError(format!("image probe: {e}")))?;
    let mut prefix = [0; 4];
    let size = file
        .read(&mut prefix)
        .map_err(|e| NativeRuntimeError(format!("image probe: {e}")))?;
    if prefix[..2] == *b"MZ" {
        return Ok(None);
    }
    let mut bytes = prefix[..size].to_vec();
    file.read_to_end(&mut bytes)
        .map_err(|e| NativeRuntimeError(format!("mapped image read: {e}")))?;
    if prefix == *b"\x7fELF" {
        let mut import = crate::native::import_elf(&bytes)
            .map_err(|e| NativeRuntimeError(format!("ELF image: {e}")))?;
        crate::native::select_language(&mut import, cfg)
            .map_err(|e| NativeRuntimeError(format!("ELF image: {e}")))?;
        return Ok(Some(import));
    }
    // DOL has no magic. Non-DOL raw images load as raw images.
    match crate::native::dol::import(&bytes) {
        Ok(import) => Ok(Some(import)),
        Err(_) => Ok(None),
    }
}

/// The `ram` byte chunks a mapped load installs, in document order: every
/// file-backed mapping, then each relocated word no mapping holds. BSS is
/// non-executable and has no instruction bytes; native `ProgramImage`
/// supplies its zero-fill to memory/worker consumers. The in-process
/// lifter's `LoadImageXml` image (`super::lift`) holds these chunks.
pub(super) fn chunks(import: &NativeImport) -> impl Iterator<Item = (u64, &[u8])> {
    let mapped = import
        .mappings
        .iter()
        .filter(|mapping| !mapping.bytes.is_empty())
        .map(|mapping| (mapping.vaddr, mapping.bytes.as_slice()));
    let relocated = import
        .relocations
        .iter()
        .filter(|relocation| {
            !import.mappings.iter().any(|m| {
                relocation.address >= m.vaddr
                    && relocation.address - m.vaddr < m.bytes.len() as u64
            })
        })
        .map(|relocation| (relocation.address, &relocation.bytes[..relocation.width]));
    mapped.chain(relocated)
}
