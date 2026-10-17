//! What the function's own instructions say, for the passes whose evidence the
//! decompiler's IR no longer carries: whether a narrow load extended with sign
//! or zeros, which constants were built as relocated addresses.
//!
//! Only little-endian `r5900` code is read (the EE; other MIPS targets are not
//! measured). For any other language the code is empty and every query says
//! "no evidence".
use super::addresses::Named;
use std::collections::{BTreeMap, BTreeSet};

/// Everything the printer is told about the machine code of the function it
/// prints: its instructions, the constants it builds as relocated addresses,
/// and the project's names for addresses.
#[derive(Clone, Copy, Debug)]
pub struct Machine<'a> {
    pub code: &'a MachineCode,
    pub constants: &'a BTreeSet<u64>,
    pub names: &'a BTreeMap<u64, Named>,
}

/// One function's instructions, with its entry address.
#[derive(Clone, Debug, Default)]
pub struct MachineCode {
    entry: u64,
    words: Vec<u32>,
    byte_order: Option<bool>,
}

/// How a narrow load extends into the register.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NarrowLoad {
    pub bytes: u32,
    pub signed: bool,
}

impl MachineCode {
    pub fn new(language: &str, entry: u64, code: &[u8]) -> Self {
        let words = if language.starts_with("r5900:LE") {
            code.as_chunks::<4>().0.iter().map(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]])).collect()
        } else {
            Vec::new()
        };
        let byte_order = if language.contains(":LE:") {
            Some(true)
        } else if language.contains(":BE:") {
            Some(false)
        } else {
            None
        };
        Self { entry, words, byte_order }
    }

    /// Whether the target is little-endian, when the language says.
    pub fn little_endian(&self) -> Option<bool> {
        self.byte_order
    }

    fn word_at(&self, address: u64) -> Option<u32> {
        let offset = address.checked_sub(self.entry)?;
        (offset % 4 == 0).then(|| self.words.get((offset / 4) as usize).copied()).flatten()
    }

    /// `lb`, `lbu`, `lh` or `lhu` at `address`.
    pub fn narrow_load(&self, address: u64) -> Option<NarrowLoad> {
        match self.word_at(address)? >> 26 {
            0x20 => Some(NarrowLoad { bytes: 1, signed: true }),
            0x24 => Some(NarrowLoad { bytes: 1, signed: false }),
            0x21 => Some(NarrowLoad { bytes: 2, signed: true }),
            0x25 => Some(NarrowLoad { bytes: 2, signed: false }),
            _ => None,
        }
    }

    /// The addresses the code builds with a `lui` followed, with the same
    /// register as source, by an `addiu`, that `mapped` says are in the image.
    pub fn address_pairs(&self, mapped: impl Fn(u64) -> bool) -> BTreeSet<u64> {
        let mut found = BTreeSet::new();
        for (index, &word) in self.words.iter().enumerate() {
            if word >> 26 != 0x0f {
                continue;
            }
            let register = (word >> 16) & 31;
            let high = i64::from(word & 0xffff) << 16;
            for &next in self.words.iter().skip(index + 1).take(8) {
                // `addiu rd, rt, lo` with the `lui` register as the source
                if next >> 26 == 0x09 && (next >> 21) & 31 == register {
                    let address = (high + i64::from(next as u16 as i16)) as u64 & 0xffff_ffff;
                    if mapped(address) {
                        found.insert(address);
                    }
                    break;
                }
                // the register is built again: this `lui` has no pair
                if next >> 26 == 0x0f && (next >> 16) & 31 == register {
                    break;
                }
            }
        }
        found
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EE: &str = "r5900:LE:32:default";

    fn word(op: u32, rs: u32, rt: u32, imm: u32) -> [u8; 4] {
        ((op << 26) | (rs << 21) | (rt << 16) | (imm & 0xffff)).to_le_bytes()
    }

    fn code(words: &[[u8; 4]]) -> MachineCode {
        MachineCode::new(EE, 0x1000, &words.concat())
    }

    #[test]
    fn a_lui_addiu_pair_is_an_address_and_a_lui_ori_pair_is_not() {
        // lui v0,0x5f / addiu a1,v0,0x5e8: 0x5f05e8. lui v0,0x31 / ori v0,v0,0x3131: a number.
        let text = code(&[word(0x0f, 0, 2, 0x5f), word(0x09, 2, 5, 0x5e8), word(0x0f, 0, 2, 0x31), word(0x0d, 2, 2, 0x3131)]);
        assert_eq!(text.address_pairs(|_| true), BTreeSet::from([0x5f05e8]));
    }

    #[test]
    fn a_negative_low_half_borrows_from_the_high_half() {
        // lui a5,0x1e / addiu a5,a5,-0x4730: 0x1db8d0
        let text = code(&[word(0x0f, 0, 13, 0x1e), word(0x09, 13, 13, 0xb8d0)]);
        assert_eq!(text.address_pairs(|_| true), BTreeSet::from([0x1db8d0]));
    }

    #[test]
    fn only_mapped_addresses_of_the_ee_are_read() {
        let words = [word(0x0f, 0, 4, 0x1001), word(0x09, 4, 4, 0xf000)];
        assert!(code(&words).address_pairs(|a| a < 0x1000_0000).is_empty());
        assert!(MachineCode::new("MIPS:LE:32:default", 0, &words.concat()).address_pairs(|_| true).is_empty());
    }

    #[test]
    fn a_lui_that_is_overwritten_has_no_pair() {
        let text = code(&[word(0x0f, 0, 2, 0x5f), word(0x0f, 0, 2, 0x60), word(0x09, 2, 5, 0x10)]);
        assert_eq!(text.address_pairs(|_| true), BTreeSet::from([0x600010]));
    }

    #[test]
    fn narrow_loads_say_how_they_extend() {
        let text = code(&[word(0x25, 4, 2, 0xa0), word(0x21, 4, 2, 0), word(0x24, 4, 2, 0), word(0x20, 4, 2, 0), word(0x23, 4, 2, 0)]);
        assert_eq!(text.narrow_load(0x1000), Some(NarrowLoad { bytes: 2, signed: false }));
        assert_eq!(text.narrow_load(0x1004), Some(NarrowLoad { bytes: 2, signed: true }));
        assert_eq!(text.narrow_load(0x1008), Some(NarrowLoad { bytes: 1, signed: false }));
        assert_eq!(text.narrow_load(0x100c), Some(NarrowLoad { bytes: 1, signed: true }));
        assert_eq!(text.narrow_load(0x1010), None);
        assert_eq!(text.narrow_load(0x1014), None);
        assert_eq!(text.narrow_load(0x0ffc), None);
    }
}
