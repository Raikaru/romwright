//! Untrusted pointers from allocated ELF data; relocation observations win.
use super::{err, ElfSection, NativeImport, NativeXref, Result};
use std::collections::HashMap;

pub(super) fn collect(
    data: &[u8],
    sections: &[ElfSection],
    import: &mut NativeImport,
    width: usize,
    be: bool,
    bias: u64,
) -> Result<()> {
    let relocated: HashMap<_, _> = import.xrefs.iter()
        .filter(|x| x.provenance == "native-import:elf-reloc")
        .map(|x| (x.from, x.to)).collect();
    for section in sections {
        // IDO emits switch jump tables into .late_rodata (P2.4): a
        // read-only section that is not .rodata by name, so it must be
        // selected explicitly or a table's code pointers are never scanned.
        let selected = matches!(section.typ, 14 | 15)
            || section.name == ".data" || section.name.starts_with(".data.")
            || section.name == ".rodata" || section.name.starts_with(".rodata.")
            || section.name == ".late_rodata" || section.name.starts_with(".late_rodata.");
        if !selected || section.flags & 2 == 0 || section.flags & 4 != 0 || section.typ == 8 {
            continue;
        }
        let Some(end) = section.off.checked_add(section.size) else {
            return err("ELF pointer section file range overflow");
        };
        let Some(bytes) = usize::try_from(section.off).ok().zip(usize::try_from(end).ok())
            .and_then(|(start, end)| data.get(start..end)) else {
            return err("ELF pointer section outside file");
        };
        let skip = (section.addr.wrapping_neg() & (width as u64 - 1)) as usize;
        let Some(bytes) = bytes.get(skip..) else { continue; };
        for (index, chunk) in bytes.chunks_exact(width).enumerate() {
            let Some(source) = section.addr.checked_add((skip + index * width) as u64) else {
                return err("ELF pointer section address overflow");
            };
            let in_code = |target: u64| {
                import.mappings.iter().any(|m| {
                    m.flags & 4 != 0 && target >= m.vaddr && target - m.vaddr < m.size
                })
            };
            // A relocated word already names loaded space. A raw word on a
            // slid (ET_DYN) image names link space: without the loader's
            // own bias its target falls outside every mapping and a
            // real callee (mipsel PIE `main` via its GOT slot) is lost.
            // The candidate still faces flow evidence downstream.
            let target = match relocated.get(&source).copied() {
                Some(adjusted) => adjusted,
                None => {
                    let raw = match (width, be) {
                        (4, false) => u32::from_le_bytes(chunk.try_into().unwrap()) as u64,
                        (4, true) => u32::from_be_bytes(chunk.try_into().unwrap()) as u64,
                        (8, false) => u64::from_le_bytes(chunk.try_into().unwrap()),
                        (8, true) => u64::from_be_bytes(chunk.try_into().unwrap()),
                        _ => unreachable!("ELF pointer width"),
                    };
                    if in_code(raw) {
                        raw
                    } else if bias != 0 {
                        let slid = raw.wrapping_add(bias);
                        if in_code(slid) {
                            slid
                        } else {
                            continue;
                        }
                    } else {
                        continue;
                    }
                }
            };
            if !in_code(target) {
                continue;
            }
            // On ARM a code pointer's low bit is the target's instruction
            // set, not part of the address: an odd value is a Thumb entry at
            // the even address below it (`ARM_ElfExtension`, 116-209, the
            // same rule the symtab's FUNC low bit carries). The candidate is
            // the aligned entry; the bit seeds TMode so the console decodes
            // Thumb there instead of rejecting an odd address as ARM. The
            // even case seeds TMode=0 too, or a Thumb range's mode would
            // bleed into the ARM function that follows it.
            let arm = import
                .elf_machine
                .map(|machine| machine.machine == 0x28)
                .unwrap_or(false);
            let entry = if arm { target & !1 } else { target };
            if arm {
                import.contexts.push(crate::native::NativeContext {
                    name: "TMode".into(),
                    address: entry,
                    value: target & 1,
                });
            }
            if matches!(section.typ, 14 | 15) {
                import.initializer_candidates.push(entry);
            } else {
                import.pointer_candidates.push(entry);
            }
            if !relocated.contains_key(&source) {
                import.xrefs.push(NativeXref::with_provenance(source, entry, "DATA", "native-import:elf-pointer"));
            }
        }
    }
    import.pointer_candidates.sort_unstable();
    import.pointer_candidates.dedup();
    import.initializer_candidates.sort_unstable();
    import.initializer_candidates.dedup();
    Ok(())
}

/// Types every word of every `.got` section as a pointer.
///
/// Ghidra's loader does this before any analyzer runs:
/// `ElfDefaultGotPltMarkup.processGOTSections` (:78-94) takes each initialized
/// block whose name starts with `.got`, forces it read-only, and
/// `processGOT` (:400-416) walks it in pointer-size steps calling
/// `createPointer` (:562-585) on every entry -- the value is never consulted
/// when deciding *whether* to type the word, only whether to keep the
/// reference it produces (`isValidPointer`, :611-623: the value has to be
/// mapped memory or carry a name). A word holding zero is still a pointer;
/// it just has no reference, which is why stock labels it `PTR_<address>`.
///
/// A word another rule already owns keeps that rule's provenance: the ABI's
/// reserved `.got.plt` head, an initializer array entry, and an import slot
/// are all typed elsewhere with stronger evidence than "it lives in .got".
pub(super) fn collect_got(
    data: &[u8],
    sections: &[ElfSection],
    import: &mut NativeImport,
    width: usize,
    be: bool,
    bias: u64,
) -> Result<()> {
    let relocated: HashMap<_, _> = import
        .xrefs
        .iter()
        .filter(|x| x.provenance == "native-import:elf-reloc")
        .map(|x| (x.from, x.to))
        .collect();
    let owned: std::collections::HashSet<u64> = import
        .initializer_slots
        .iter()
        .chain(import.plt_reserved_slots.iter())
        .chain(import.ifunc_slots.iter())
        .map(|(address, _)| *address)
        .chain(import.externals.iter().map(|(address, _)| *address))
        .collect();
    let mut slots: Vec<(u64, u64)> = Vec::new();
    let mut references: Vec<(u64, u64)> = Vec::new();
    for section in sections {
        if !section.name.starts_with(".got") || section.flags & 2 == 0 || section.typ == 8 {
            continue;
        }
        let Some(end) = section.off.checked_add(section.size) else {
            return err("ELF got section file range overflow");
        };
        let Some(bytes) = usize::try_from(section.off)
            .ok()
            .zip(usize::try_from(end).ok())
            .and_then(|(start, end)| data.get(start..end))
        else {
            return err("ELF got section outside file");
        };
        for (index, chunk) in bytes.chunks_exact(width).enumerate() {
            let Some(slot) = section.addr.checked_add((index * width) as u64) else {
                return err("ELF got section address overflow");
            };
            if owned.contains(&slot) {
                continue;
            }
            slots.push((slot, width as u64));
            // Same ET_DYN slide as collect: an unrelocated GOT word names
            // link space, and the reference it produces must name the
            // loaded address the slot resolves to at runtime.
            let target = match relocated.get(&slot).copied() {
                Some(adjusted) => adjusted,
                None => {
                    let raw = match (width, be) {
                        (4, false) => u32::from_le_bytes(chunk.try_into().unwrap()) as u64,
                        (4, true) => u32::from_be_bytes(chunk.try_into().unwrap()) as u64,
                        (8, false) => u64::from_le_bytes(chunk.try_into().unwrap()),
                        (8, true) => u64::from_be_bytes(chunk.try_into().unwrap()),
                        _ => unreachable!("ELF got pointer width"),
                    };
                    // A word the loader already maps stays as read;
                    // only an unmapped word on a slid image is reinterpreted.
                    let raw_mapped = import
                        .mappings
                        .iter()
                        .any(|m| raw >= m.vaddr && raw - m.vaddr < m.size);
                    if raw_mapped || bias == 0 {
                        raw
                    } else {
                        raw.wrapping_add(bias)
                    }
                }
            };
            let mapped = import
                .mappings
                .iter()
                .any(|m| target >= m.vaddr && target - m.vaddr < m.size);
            let named = import.externals.iter().any(|(address, _)| *address == target);
            if mapped || named {
                references.push((slot, target));
            }
            // A GOT slot resolving into code is a callee the image takes
            // the address of: on MIPS PIE the primary function is only
            // reachable this way ($gp-relative GOT load, no direct call,
            // no dynamic relocation on the slot). Like every candidate it
            // still faces flow evidence downstream.
            let in_code = import.mappings.iter().any(|m| {
                m.flags & 4 != 0 && target >= m.vaddr && target - m.vaddr < m.size
            });
            if in_code {
                import.pointer_candidates.push(target);
            }
        }
    }
    for (slot, target) in references {
        import.xrefs.push(NativeXref::with_provenance(
            slot,
            target,
            "DATA",
            super::ELF_GOT_SOURCE,
        ));
    }
    slots.sort_unstable();
    slots.dedup();
    import.got_slots = slots;
    Ok(())
}

pub(super) fn confirm_initializers(import: &mut NativeImport) {
    use crate::native_runtime::{ConsoleSession, FlowKind};
    let candidates: Vec<_> = import.initializer_candidates.iter().copied()
        .filter(|a| !import.functions.iter().any(|f| f.entry == *a)).collect();
    if candidates.is_empty() { return; }
    let Ok(mut session) = ConsoleSession::new(&import.cfg) else { return; };
    if session.load_mapped(import).is_err() { return; }
    let flows = session.try_flow_batch(&candidates);
    for (entry, flow) in candidates.into_iter().zip(flows) {
        if flow.address == entry && flow.length != 0 && !matches!(flow.kind, FlowKind::Bad | FlowKind::Unimpl) {
            import.functions.push(super::NativeFunction { entry, name: format!("FUN_{entry:08x}"), size: 1 });
        }
    }
}

/// A referenced word whose bytes are the entry of a function is a pointer.
///
/// Ghidra's rule, from `OperandReferenceAnalyzer.checkForPointer`
/// (:952-1035): a reference lands on an undefined location, the
/// pointer-sized value there is read, and the location is typed
/// `PointerDataType` unless the value is below 4096, is not in memory, is
/// offcut, or lands inside a function that is not its entry. This records the
/// case the corpus proves: the value *is* a function entry, so no
/// pseudo-disassembly is needed to know the target is code.
///
/// The slot is left alone when another rule already owns it -- an initializer
/// array word, an ABI-reserved PLT word, an import slot -- so a type never
/// depends on which pass ran last.
pub(super) fn confirm_referenced_pointers(import: &mut NativeImport) {
    let Some(machine) = import.elf_machine else {
        return;
    };
    let width = u64::from(machine.bits / 8);
    if width == 0 {
        return;
    }
    let entries: std::collections::HashSet<u64> =
        import.functions.iter().map(|function| function.entry).collect();
    let owned: std::collections::HashSet<u64> = import
        .initializer_slots
        .iter()
        .chain(import.plt_reserved_slots.iter())
        .map(|(address, _)| *address)
        .chain(import.externals.iter().map(|(address, _)| *address))
        .collect();
    let mut targets: Vec<u64> = import
        .xrefs
        .iter()
        .filter(|xref| matches!(xref.kind.as_str(), "DATA" | "READ" | "WRITE"))
        .map(|xref| xref.to)
        .collect();
    targets.sort_unstable();
    targets.dedup();
    let mut found: Vec<(u64, u64)> = Vec::new();
    for slot in targets {
        if owned.contains(&slot) || entries.contains(&slot) {
            continue;
        }
        let Some(value) = word_at(import, slot, width, machine.big_endian) else {
            continue;
        };
        // Ghidra refuses a small value outright: an address table with a zero
        // in it is possible, but a low number is not an address.
        if value < 4096 || !entries.contains(&value) {
            continue;
        }
        found.push((slot, width));
        import.xrefs.push(NativeXref::with_provenance(
            slot,
            value,
            "DATA",
            super::DATA_POINTER_SOURCE,
        ));
    }
    found.sort_unstable();
    found.dedup();
    import.pointer_slots = found;
}

/// The pointer-sized word at one address, from the mapping that carries it.
pub(super) fn word_at(import: &NativeImport, address: u64, width: u64, be: bool) -> Option<u64> {
    let mapping = import.mappings.iter().find(|mapping| {
        address >= mapping.vaddr && address - mapping.vaddr < mapping.size
    })?;
    let offset = usize::try_from(address - mapping.vaddr).ok()?;
    let end = offset.checked_add(usize::try_from(width).ok()?)?;
    let bytes = mapping.bytes.get(offset..end)?;
    let mut value = 0u64;
    for index in 0..bytes.len() {
        let byte = bytes[if be { index } else { bytes.len() - 1 - index }];
        value = (value << 8) | u64::from(byte);
    }
    Some(value)
}
