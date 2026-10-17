//! Metrowerks register-save sleds (P2.3).
//!
//! MWCC prologues for functions that keep more than a few callee-saved
//! registers call into the runtime instead of spilling inline:
//!
//! ```text
//!     stwu  r1,-0x40(r1)
//!     mflr  r0
//!     stw   r0,0x44(r1)
//!     addi  r11,r1,0x40       ; r11 = the caller's sp
//!     bl    _savegpr_26       ; stw r26,-0x18(r11) ... stw r31,-4(r11); blr
//! ```
//!
//! The runtime holds four sleds, each a run of one instruction per register
//! ending in `blr`; a call enters at the entry for the lowest register to
//! keep:
//!
//! | helper            | instruction                       | slot of rN/fN      |
//! |-------------------|-----------------------------------|--------------------|
//! | `_savegpr_N`      | `stw rN,-4*(32-N)(r11)`           | N = 14..31         |
//! | `_restgpr_N`      | `lwz rN,-4*(32-N)(r11)`           | N = 14..31         |
//! | `_savefpr_N`      | `stfd fN,-8*(32-N)(r11)`          | N = 14..31         |
//! | `_restfpr_N`      | `lfd fN,-8*(32-N)(r11)`           | N = 14..31         |
//!
//! Stripped images name none of the entries, so the decompiler sees a call to
//! an unknown function: it assumes the call may overwrite `r3`..`r12`, and
//! the `mr r31,r3` that follows the prologue reads the call's result instead
//! of the caller's first argument (Animal Crossing `restore_fgdata_all(play)`
//! printed no parameter). The compiler specification carries a call fixup per
//! helper (`romwright-worker` `specs.rs`), but a fixup fires on the callee's
//! *name*. This pass names an entry when the bytes prove it: the words from
//! that entry to the end of the sled are exactly the helper's instructions and
//! a `blr` closes the run. Only a generated name is replaced.
//!
//! The layout is read off the retail bytes (Animal Crossing `main.dol`
//! 0x8009ae00..0x8009af2c) and agrees with the dtk/decomp-toolkit labels the
//! ac-decomp project assigns (`config/GAFE01_00/symbols.txt`).

use super::NativeImport;
use crate::compiler::rules::{self, SledFamily, SledSet};

const BLR: u32 = 0x4E80_0020;
const R11: u32 = 11;

/// The instruction of `family` for register `reg`: `op reg,-slot*(32-reg)(r11)`.
fn word(family: &SledFamily, reg: u32) -> u32 {
    let displacement = (0x1_0000 - family.slot * (32 - reg)) & 0xFFFF;
    (family.opcode << 26) | (reg << 21) | (R11 << 16) | displacement
}

/// Helper entries in `bytes` (big-endian words from `base`): `(address, name)`.
pub(crate) fn find_entries(sleds: &SledSet, base: u64, bytes: &[u8]) -> Vec<(u64, String)> {
    let words: Vec<u32> = bytes
        .as_chunks::<4>().0.iter()
        .map(|chunk| u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
        .collect();
    let mut found = Vec::new();
    for family in &sleds.families {
        for (index, &candidate) in words.iter().enumerate() {
            // The opcode and r11 base are common to the whole sled; the
            // register is the S/D field.
            if candidate >> 26 != family.opcode || (candidate >> 16) & 0x1F != R11 {
                continue;
            }
            let reg = (candidate >> 21) & 0x1F;
            if !(sleds.first..=sleds.last).contains(&reg) || candidate != word(family, reg) {
                continue;
            }
            // Every register up to the last, then `blr`.
            let tail = (sleds.last + 1 - reg) as usize;
            let run = words.get(index..index + tail + 1);
            let proven = run.is_some_and(|run| {
                (0..tail).all(|offset| run[offset] == word(family, reg + offset as u32)) && run[tail] == BLR
            });
            if proven {
                found.push((base + 4 * index as u64, format!("{}{}", family.prefix, reg)));
            }
        }
    }
    found
}

/// Names the helper entries discovery has already made functions, when the
/// `mwcc-register-sleds` rule covers the program (a 32-bit PowerPC image
/// whose compiler is CodeWarrior, or not yet known).
pub(super) fn name_register_sleds(imp: &mut NativeImport) {
    let Some(sleds) = rules::register_sleds(&crate::compiler::ctx_of(imp)) else {
        return;
    };
    let mut names = std::collections::HashMap::new();
    for mapping in imp.mappings.iter().filter(|mapping| mapping.flags & 4 != 0) {
        for (address, name) in find_entries(sleds, mapping.vaddr, &mapping.bytes) {
            names.insert(address, name);
        }
    }
    if names.is_empty() {
        return;
    }
    for function in imp.functions.iter_mut() {
        if function.name.starts_with("FUN_")
            && let Some(name) = names.get(&function.entry) {
                function.name = name.clone();
            }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PowerPC D-form opcodes: stw, lwz, stfd, lfd.
    const STW: u32 = 36;
    const LWZ: u32 = 32;
    const STFD: u32 = 54;
    const LFD: u32 = 50;

    fn sleds() -> &'static SledSet {
        rules::sled_definition(rules::MWCC_SLEDS).expect("the shipped rule file defines the sleds")
    }

    fn sled(opcode: u32, stride: u32, from: u32) -> Vec<u8> {
        let kind = sleds().families.iter().find(|s| s.opcode == opcode && s.slot == stride).unwrap();
        let mut out: Vec<u8> = (from..32).flat_map(|reg| word(kind, reg).to_be_bytes()).collect();
        out.extend(BLR.to_be_bytes());
        out
    }

    #[test]
    fn the_words_are_the_retail_ones() {
        // Animal Crossing main.dol: `_savegpr_14` first word, `_restgpr_14`,
        // `_savefpr_14`, `_restfpr_14`.
        assert_eq!(word(&sleds().families[0], 14), 0x91CB_FFB8);
        assert_eq!(word(&sleds().families[0], 31), 0x93EB_FFFC);
        assert_eq!(word(&sleds().families[1], 14), 0x81CB_FFB8);
        assert_eq!(word(&sleds().families[2], 14), 0xD9CB_FF70);
        assert_eq!(word(&sleds().families[2], 31), 0xDBEB_FFF8);
        assert_eq!(word(&sleds().families[3], 14), 0xC9CB_FF70);
    }

    #[test]
    fn every_entry_of_a_full_sled_is_named() {
        let mut image = vec![0u8; 8];
        image.extend(sled(STW, 4, 14));
        let found = find_entries(sleds(), 0x8009_AE90, &image);
        assert_eq!(found.len(), 18);
        assert_eq!(found[0], (0x8009_AE98, "_savegpr_14".into()));
        // `bl _savegpr_26` enters 12 words in.
        assert!(found.contains(&(0x8009_AE98 + 4 * 12, "_savegpr_26".into())));
        assert_eq!(found.last().unwrap(), &(0x8009_AE98 + 4 * 17, "_savegpr_31".into()));
    }

    #[test]
    fn all_four_helpers_are_told_apart() {
        let mut image = Vec::new();
        for (opcode, stride) in [(STFD, 8), (LFD, 8), (STW, 4), (LWZ, 4)] {
            image.extend(sled(opcode, stride, 14));
        }
        let names: Vec<String> = find_entries(sleds(), 0x8009_AE00, &image).into_iter().map(|(_, name)| name).collect();
        for prefix in ["_savefpr_", "_restfpr_", "_savegpr_", "_restgpr_"] {
            assert_eq!(names.iter().filter(|name| name.starts_with(prefix)).count(), 18, "{prefix}");
        }
    }

    #[test]
    fn a_run_without_its_blr_is_not_a_sled() {
        let mut image = sled(STW, 4, 14);
        let len = image.len();
        image[len - 4..].copy_from_slice(&0x6000_0000u32.to_be_bytes()); // nop, not blr
        assert!(find_entries(sleds(), 0, &image).is_empty());
    }

    #[test]
    fn a_wrong_slot_breaks_the_run() {
        // r20 stored at r21's slot: not the helper's layout.
        let mut image = sled(STW, 4, 14);
        image[4 * 6..4 * 6 + 4].copy_from_slice(&word(&sleds().families[0], 21).to_be_bytes());
        let names: Vec<String> = find_entries(sleds(), 0, &image).into_iter().map(|(_, name)| name).collect();
        // Entries after the damage still prove themselves; those before do not.
        assert!(!names.contains(&"_savegpr_14".to_string()));
        assert!(names.contains(&"_savegpr_21".to_string()));
    }

    #[test]
    fn a_base_register_other_than_r11_is_not_the_helper() {
        let mut image = sled(STW, 4, 14);
        // rewrite every word's rA to r12
        for chunk in image.as_chunks_mut::<4>().0.iter_mut().take(18) {
            let word = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) & !(0x1F << 16) | (12 << 16);
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        assert!(find_entries(sleds(), 0, &image).is_empty());
    }
}
