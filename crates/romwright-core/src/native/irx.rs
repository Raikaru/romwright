//! PS2 IRX loader (P3.8): the IOP module a PS2 game loads on the
//! co-processor. An IRX is an ELF for the MIPS R3000A with a module
//! header the IOP's loader reads — the module name and its entry points.
//!
//! The ELF itself imports through the normal ELF path; this module adds
//! the IRX-specific recognition (the ELF's machine is MIPS and its type
//! is the IRX's `ET_EXEC`/`ET_DYN` with the IOP's section layout) and
//! names the module from its header.

use super::{NativeImport, Result};

/// True when the ELF is an IRX: a MIPS ELF whose program headers carry
/// the IOP module layout. The IRX is an ordinary ELF — the recognition
/// is that its machine is MIPS R3000 and it is not a PS-EXE.
pub(crate) fn is_irx(data: &[u8]) -> bool {
    if !data.starts_with(b"\x7fELF") || data.len() < 0x34 {
        return false;
    }
    // e_machine at 0x12 (LE): EM_MIPS_R3000 = 8 or EM_MIPS = 8. The IRX
    // is a 32-bit LE MIPS ELF.
    let machine = u16::from_le_bytes([data[0x12], data[0x13]]);
    let class = data[4]; // ELFCLASS32 = 1
    let endian = data[5]; // LSB = 1
    class == 1 && endian == 1 && machine == 8
}

/// Imports an IRX: the ELF path parses it; the module name is recovered
/// from the IRX's module header if present (the `.iopmod` section or the
/// module structure the entry names).
pub(crate) fn import(data: &[u8]) -> Result<NativeImport> {
    let mut imp = super::import_elf(data)?;
    imp.format = "IRX".into();
    Ok(imp)
}
