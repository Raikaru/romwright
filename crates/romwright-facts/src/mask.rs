//! Relocation masking: the one function both the pack build and the apply
//! pass run over code bytes.
//!
//! A linker rewrites exactly the operand bits that hold addresses; the rest
//! of a function's bytes are the compiler's output and are identical in every
//! build of the same source. [`mask`] zeroes the address-bearing bits and
//! keeps everything else, so two builds of one function hash alike while two
//! different functions do not.
//!
//! The mask depends only on the bytes it is given. A rule that needs the body
//! bounds (a branch that stays inside the function is position-independent
//! and is kept; one that leaves it is a link-time target and is zeroed) takes
//! them from `bytes.len()`. [`MASK_VERSION`] is stored in every pack and
//! checked on open; any rule change bumps it.
//!
//! Rules, per [`Family`]:
//!
//! * **MIPS** (LE and BE): `j`/`jal` targets; `lui` immediates; the 16-bit
//!   immediate of `addi`/`daddi`/`addiu`/`daddiu`/`ori` and of every load,
//!   store, cache and prefetch opcode (`0x20..=0x3f`, `lq`/`sq`) whose base
//!   register is neither `$zero` nor `$sp`. That covers `%hi`/`%lo` halves and
//!   `$gp`-relative offsets; it also covers struct-field offsets from other
//!   bases, a deliberate over-mask.
//! * **PowerPC** (Gekko/Broadway included): `bl`, `bla`, `ba` targets, and a
//!   `b`/`bc` whose target lies outside the body; the immediate of `addis`
//!   (`lis`); the immediate of `addi`/`ori`/load/store whose base register
//!   was set by an earlier `lis`/`addis` and not yet consumed (the `@l`
//!   half); and the displacement of any `addi`/load/store based on `r2` or
//!   `r13` (small-data areas).
//! * **ARM**: `bl`/`blx` targets, a `b` leaving the body, and every
//!   `ldr rd, [pc, #imm]` literal-pool word inside the body whose value is an
//!   address in the GBA/NDS memory map ([`is_image_address`]).
//! * **Thumb**: both halves of a `bl`/`blx` pair, a `b`/`b<cond>` leaving the
//!   body, and literal-pool words as for ARM.

/// Bumped whenever any rule below changes: a pack built under another version
/// holds digests this code cannot reproduce.
pub const MASK_VERSION: u32 = 1;

/// Instruction-set families the masking rules are defined for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Family {
    MipsLe,
    MipsBe,
    PpcBe,
    Arm,
    Thumb,
}

impl Family {
    /// The family of a Ghidra language id and instruction-set mode. `thumb`
    /// is the low-bit code mode in effect at the function: Thumb on ARM, a
    /// MIPS16/microMIPS body on MIPS (which has no rules, so no family).
    pub fn of(language_id: &str, thumb: bool) -> Option<Family> {
        let mut parts = language_id.split(':');
        let (arch, endian) = (parts.next()?, parts.next()?);
        match (arch, endian) {
            ("MIPS" | "r5900" | "Allegrex" | "PSX", "LE") => (!thumb).then_some(Family::MipsLe),
            ("MIPS", "BE") => (!thumb).then_some(Family::MipsBe),
            ("PowerPC", "BE") => Some(Family::PpcBe),
            ("ARM", "LE") => Some(if thumb { Family::Thumb } else { Family::Arm }),
            _ => None,
        }
    }

    /// Stable text form stored in the pack.
    pub fn as_str(self) -> &'static str {
        match self {
            Family::MipsLe => "mips-le",
            Family::MipsBe => "mips-be",
            Family::PpcBe => "ppc-be",
            Family::Arm => "arm",
            Family::Thumb => "thumb",
        }
    }

    pub fn parse(text: &str) -> Option<Family> {
        Some(match text {
            "mips-le" => Family::MipsLe,
            "mips-be" => Family::MipsBe,
            "ppc-be" => Family::PpcBe,
            "arm" => Family::Arm,
            "thumb" => Family::Thumb,
            _ => return None,
        })
    }

    /// Instruction alignment: the stride a scan probes at.
    pub fn alignment(self) -> usize {
        match self {
            Family::Thumb => 2,
            _ => 4,
        }
    }

    /// Whether the language id names an ARM processor (both modes matter).
    pub fn is_arm_language(language_id: &str) -> bool {
        language_id.starts_with("ARM:LE")
    }
}

/// Zeroes the operand bits of `bytes` that hold link-time addresses. The
/// result has the same length; a trailing partial instruction is kept as is.
pub fn mask(family: Family, bytes: &[u8]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    match family {
        Family::MipsLe => mips(&mut out, false),
        Family::MipsBe => mips(&mut out, true),
        Family::PpcBe => ppc(&mut out),
        Family::Arm => arm(&mut out),
        Family::Thumb => thumb(&mut out),
    }
    out
}

fn word(bytes: &[u8], at: usize, big: bool) -> u32 {
    let raw = [bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]];
    if big { u32::from_be_bytes(raw) } else { u32::from_le_bytes(raw) }
}

fn put(bytes: &mut [u8], at: usize, value: u32, big: bool) {
    let raw = if big { value.to_be_bytes() } else { value.to_le_bytes() };
    bytes[at..at + 4].copy_from_slice(&raw);
}

fn half(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

fn put_half(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn sign_extend(value: u32, bits: u32) -> i64 {
    let shift = 64 - bits;
    ((value as i64) << shift) >> shift
}

/// Whether a branch from byte `at` to `at + displacement` leaves a body of
/// `len` bytes.
fn leaves(at: usize, displacement: i64, len: usize) -> bool {
    let target = at as i64 + displacement;
    target < 0 || target >= len as i64
}

fn mips(bytes: &mut [u8], big: bool) {
    for at in (0..bytes.len() / 4 * 4).step_by(4) {
        let w = word(bytes, at, big);
        let op = w >> 26;
        let base = (w >> 21) & 31;
        let masked = match op {
            // j, jal
            2 | 3 => w & !0x03FF_FFFF,
            // lui
            0x0F => w & !0xFFFF,
            // addi, addiu, daddi, daddiu, ori, and every load/store/cache op
            0x08 | 0x09 | 0x18 | 0x19 | 0x0D | 0x1E | 0x1F | 0x20..=0x3F
                if base != 0 && base != 29 =>
            {
                w & !0xFFFF
            }
            _ => w,
        };
        if masked != w {
            put(bytes, at, masked, big);
        }
    }
}

fn ppc(bytes: &mut [u8]) {
    let len = bytes.len();
    // Registers a `lis`/`addis` set whose low half has not been seen yet.
    let mut high: u32 = 0;
    for at in (0..len / 4 * 4).step_by(4) {
        let w = word(bytes, at, true);
        let op = w >> 26;
        let rt = (w >> 21) & 31; // rD/rS
        let ra = (w >> 16) & 31;
        let mut masked = w;
        match op {
            // b, bl, ba, bla: LI field.
            18 => {
                let displacement = sign_extend(w & 0x03FF_FFFC, 26);
                if w & 3 != 0 || leaves(at, displacement, len) {
                    masked &= !0x03FF_FFFC;
                }
            }
            // bc, bcl, bca, bcla: BD field.
            16 => {
                let displacement = sign_extend(w & 0xFFFC, 16);
                if w & 2 != 0 || leaves(at, displacement, len) {
                    masked &= !0xFFFC;
                }
            }
            // addis / lis: the high half; its destination awaits a low half.
            15 => {
                masked &= !0xFFFF;
                high |= 1 << rt;
            }
            // addi, ori, integer and floating-point loads and stores,
            // lmw/stmw; DS-form ld/lwa (58) and std (62).
            14 | 24 | 32..=55 | 58 | 62 => {
                let source = if op == 24 { rt } else { ra };
                let mask_bits = if op == 58 || op == 62 { 0xFFFC } else { 0xFFFF };
                let small_data = op != 24 && (ra == 2 || ra == 13);
                if small_data || high & (1 << source) != 0 {
                    masked &= !mask_bits;
                }
                // The low half consumes the pair when it rewrites the register.
                if high & (1 << source) != 0 && (op == 14 || op == 24) && rt == source {
                    high &= !(1 << source);
                }
                if matches!(op, 32..=35 | 40..=43) && rt == source {
                    high &= !(1 << source);
                }
            }
            _ => {}
        }
        if masked != w {
            put(bytes, at, masked, true);
        }
    }
}

/// Whether a literal-pool word is an address in the GBA/NDS memory map that a
/// linker, not the compiler, chose: RAM (`0x01000000..0x04000000`, which
/// holds the NDS ITCM/main RAM/shared WRAM and the GBA EWRAM/IWRAM) and the
/// cartridge ROM windows (`0x08000000..0x0E000000`). I/O registers, VRAM and
/// palette addresses are hardware constants, identical in every build, and
/// stay.
pub fn is_image_address(value: u32) -> bool {
    (0x0100_0000..0x0400_0000).contains(&value) || (0x0800_0000..0x0E00_0000).contains(&value)
}

fn arm(bytes: &mut [u8]) {
    let len = bytes.len();
    let words = len / 4;
    // Literal-pool words an `ldr rd, [pc, #±imm]` in this body loads.
    let mut pool = vec![false; words];
    for index in 0..words {
        if pool[index] {
            continue;
        }
        let w = word(bytes, index * 4, false);
        // cond 01 0 P U 0 W 1 1111 Rd imm12 with P=1, W=0, byte=0.
        if w >> 28 != 0xF
            && w & 0x0E5F_0000 == 0x041F_0000
            && w & (1 << 24) != 0
            && w & (1 << 21) == 0
        {
            let offset = (w & 0xFFF) as i64;
            let target = index as i64 * 4 + 8 + if w & (1 << 23) != 0 { offset } else { -offset };
            if target >= 0 && target % 4 == 0 && (target as usize / 4) < words {
                pool[target as usize / 4] = true;
            }
        }
    }
    for (index, &pooled) in pool.iter().enumerate().take(words) {
        let at = index * 4;
        let w = word(bytes, at, false);
        if pooled {
            if is_image_address(w) {
                put(bytes, at, 0, false);
            }
            continue;
        }
        // cond 101 L imm24: b, bl; cond 1111 101 H imm24: blx.
        if (w >> 25) & 7 == 0b101 {
            let call = w >> 28 == 0xF || w & (1 << 24) != 0;
            let displacement = sign_extend(w & 0x00FF_FFFF, 24) * 4 + 8;
            if call || leaves(at, displacement, len) {
                put(bytes, at, w & !0x00FF_FFFF, false);
            }
        }
    }
}

fn thumb(bytes: &mut [u8]) {
    let len = bytes.len();
    let halves = len / 2;
    let mut covered = vec![false; halves];
    let mut pool: Vec<usize> = Vec::new();
    for index in 0..halves {
        if covered[index] {
            continue;
        }
        let h = half(bytes, index * 2);
        // ldr rd, [pc, #imm8 * 4]
        if h & 0xF800 == 0x4800 {
            let target = ((index * 2 + 4) & !3) + (h & 0xFF) as usize * 4;
            if target + 4 <= len && !covered[target / 2] {
                covered[target / 2] = true;
                covered[target / 2 + 1] = true;
                pool.push(target);
            }
        }
    }
    for target in pool {
        let value = word(bytes, target, false);
        if is_image_address(value) {
            put(bytes, target, 0, false);
        }
    }
    let mut index = 0;
    while index < halves {
        if covered[index] {
            index += 1;
            continue;
        }
        let at = index * 2;
        let h = half(bytes, at);
        match h & 0xF800 {
            // bl/blx pair: the offset halves are a link-time target.
            0xF000 => {
                put_half(bytes, at, h & !0x07FF);
                if index + 1 < halves && !covered[index + 1] {
                    let next = half(bytes, at + 2);
                    if matches!(next & 0xF800, 0xF800 | 0xE800) {
                        put_half(bytes, at + 2, next & !0x07FF);
                        index += 1;
                    }
                }
            }
            // b
            0xE000 => {
                let displacement = sign_extend((h & 0x07FF) as u32, 11) * 2 + 4;
                if leaves(at, displacement, len) {
                    put_half(bytes, at, h & !0x07FF);
                }
            }
            _ => {
                // b<cond>
                if h & 0xF000 == 0xD000 && (h >> 8) & 15 < 14 {
                    let displacement = sign_extend((h & 0xFF) as u32, 8) * 2 + 4;
                    if leaves(at, displacement, len) {
                        put_half(bytes, at, h & !0x00FF);
                    }
                }
            }
        }
        index += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn le(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

    fn be(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|w| w.to_be_bytes()).collect()
    }

    fn halves(values: &[u16]) -> Vec<u8> {
        values.iter().flat_map(|h| h.to_le_bytes()).collect()
    }

    #[test]
    fn family_from_language() {
        assert_eq!(Family::of("MIPS:LE:64:default", false), Some(Family::MipsLe));
        assert_eq!(Family::of("r5900:LE:32:default", false), Some(Family::MipsLe));
        assert_eq!(Family::of("Allegrex:LE:32:default", false), Some(Family::MipsLe));
        assert_eq!(Family::of("PSX:LE:32:default", false), Some(Family::MipsLe));
        assert_eq!(Family::of("MIPS:BE:64:64-32addr", false), Some(Family::MipsBe));
        assert_eq!(Family::of("PowerPC:BE:64:Xenon-32addr", false), Some(Family::PpcBe));
        assert_eq!(Family::of("ARM:LE:32:v5t", false), Some(Family::Arm));
        assert_eq!(Family::of("MIPS:BE:64:default", false), Some(Family::MipsBe));
        assert_eq!(Family::of("MIPS:LE:32:default", true), None);
        assert_eq!(Family::of("PowerPC:BE:32:Gekko_Broadway", false), Some(Family::PpcBe));
        assert_eq!(Family::of("PowerPC:LE:32:default", false), None);
        assert_eq!(Family::of("ARM:LE:32:v4t", false), Some(Family::Arm));
        assert_eq!(Family::of("ARM:LE:32:v4t", true), Some(Family::Thumb));
        assert_eq!(Family::of("ARM:BE:32:v4t", true), None);
        assert_eq!(Family::of("x86:LE:64:default", false), None);
        for family in [Family::MipsLe, Family::MipsBe, Family::PpcBe, Family::Arm, Family::Thumb] {
            assert_eq!(Family::parse(family.as_str()), Some(family));
        }
    }

    #[test]
    fn mips_masks_calls_halves_and_offsets() {
        let jal = 0x0C00_1234; // jal target
        let j = 0x0800_0042;
        let lui = 0x3C04_8001; // lui a0, 0x8001
        let addiu_lo = 0x2484_5678; // addiu a0, a0, 0x5678
        let lw_gp = 0x8F82_8010; // lw v0, -0x7ff0($gp)
        let lw_sp = 0x8FA2_0010; // lw v0, 0x10($sp): frame offset, kept
        let li = 0x2402_0001; // addiu v0, zero, 1: constant, kept
        let ori_zero = 0x3402_00FF; // ori v0, zero, 0xff: constant, kept
        let sw_field = 0xAC85_0008; // sw a1, 8(a0): struct field, masked
        let beq = 0x1000_FFFE; // branch, kept
        let out = mask(Family::MipsLe, &le(&[jal, j, lui, addiu_lo, lw_gp, lw_sp, li, ori_zero, sw_field, beq]));
        assert_eq!(
            out,
            le(&[0x0C00_0000, 0x0800_0000, 0x3C04_0000, 0x2484_0000, 0x8F82_0000, lw_sp, li, ori_zero, 0xAC85_0000, beq])
        );
    }

    #[test]
    fn mips_big_endian_reads_words_big_endian() {
        let out = mask(Family::MipsBe, &be(&[0x0C00_1234, 0x3C04_8001, 0x03E0_0008]));
        assert_eq!(out, be(&[0x0C00_0000, 0x3C04_0000, 0x03E0_0008]));
        // The same bytes read little-endian are a different instruction stream.
        assert_ne!(mask(Family::MipsLe, &be(&[0x0C00_1234])), be(&[0x0C00_0000]));
    }

    #[test]
    fn mips_leaves_a_trailing_partial_word() {
        let mut bytes = le(&[0x0C00_1234]);
        bytes.extend_from_slice(&[0xAA, 0xBB]);
        let out = mask(Family::MipsLe, &bytes);
        assert_eq!(&out[4..], &[0xAA, 0xBB]);
        assert_eq!(out.len(), 6);
    }

    #[test]
    fn mips_ldc1_and_lq_are_masked_with_a_base() {
        let ldc1 = 0xD4A2_0010; // ldc1 f2, 0x10(a1)
        let lq = 0x7885_0020; // lq a1, 0x20(a0)
        let out = mask(Family::MipsLe, &le(&[ldc1, lq]));
        assert_eq!(out, le(&[0xD4A2_0000, 0x7885_0000]));
    }

    #[test]
    fn ppc_masks_calls_and_branches_leaving_the_body() {
        // bl +0x100; b +8 (inside); b -0x1000 (leaves); bc 12,2,+8 (inside);
        // bc 12,2,+0x4000 (leaves); bla; blr
        let words = [
            0x4800_0101, // bl +0x100
            0x4800_0008, // b +8
            0x4BFF_F000, // b -0x1000
            0x4182_0008, // beq +8
            0x4182_4000, // beq +0x4000
            0x4800_0003, // bla 0
            0x4E80_0020, // blr
            0x6000_0000, // nop
        ];
        let out = mask(Family::PpcBe, &be(&words));
        assert_eq!(
            out,
            be(&[0x4800_0001, 0x4800_0008, 0x4800_0000, 0x4182_0008, 0x4182_0000, 0x4800_0003, 0x4E80_0020, 0x6000_0000])
        );
    }

    #[test]
    fn ppc_masks_lis_pairs_and_small_data() {
        let lis = 0x3C60_8030; // lis r3, 0x8030
        let addi = 0x3863_1234; // addi r3, r3, 0x1234 (the @l half)
        let later = 0x3863_0004; // addi r3, r3, 4: the pair is consumed, kept
        let lwz_field = 0x8083_0008; // lwz r4, 8(r3): consumed base, kept
        let lis2 = 0x3C80_8031; // lis r4, 0x8031
        let lwz_lo = 0x80A4_0010; // lwz r5, 0x10(r4): low half, masked
        let sda13 = 0x80AD_8020; // lwz r5, -0x7fe0(r13)
        let sda2 = 0xC022_8004; // lfs f1, -0x7ffc(r2)
        let sp = 0x9421_FFE0; // stwu r1, -0x20(r1): frame, kept
        let ori_const = 0x6063_00FF; // ori r3, r3, 0xff with r3 not a pending hi: kept
        let out = mask(
            Family::PpcBe,
            &be(&[lis, addi, later, lwz_field, lis2, lwz_lo, sda13, sda2, sp, ori_const]),
        );
        assert_eq!(
            out,
            be(&[
                0x3C60_0000,
                0x3863_0000,
                later,
                lwz_field,
                0x3C80_0000,
                0x80A4_0000,
                0x80AD_0000,
                0xC022_0000,
                sp,
                ori_const
            ])
        );
    }

    #[test]
    fn ppc_ds_form_keeps_the_extended_opcode_bits() {
        // ld r3, 8(r13): the low two bits are the extended opcode.
        let out = mask(Family::PpcBe, &be(&[0xE86D_0009]));
        assert_eq!(out, be(&[0xE86D_0001]));
    }

    #[test]
    fn arm_masks_calls_branches_leaving_and_pool_addresses() {
        // 0: ldr r0, [pc, #8] -> pool at 0+8+8 = 16
        // 4: bl <far>
        // 8: beq +4 words (inside)
        // 12: b <far, leaves>
        // 16: pool word 0x03001234 (IWRAM address)
        // 20: ldr r1, [pc, #0] -> pool at 20+8 = 28
        // 24: blx <far>
        // 28: pool word 0x04000208 (I/O register: hardware constant, kept)
        let words = [
            0xE59F_0008,
            0xEB00_0123,
            0x0A00_0002,
            0xEA7F_FFF0,
            0x0300_1234,
            0xE59F_1000,
            0xFA00_0456,
            0x0400_0208,
        ];
        let out = mask(Family::Arm, &le(&words));
        assert_eq!(
            out,
            le(&[0xE59F_0008, 0xEB00_0000, 0x0A00_0002, 0xEA00_0000, 0x0000_0000, 0xE59F_1000, 0xFA00_0000, 0x0400_0208])
        );
    }

    #[test]
    fn arm_pool_value_is_not_decoded_as_an_instruction() {
        // The pool word 0xEB000123 would read as a bl, but it is data.
        let out = mask(Family::Arm, &le(&[0xE59F_0000, 0xE12F_FF1E, 0xEB00_0123]));
        assert_eq!(out, le(&[0xE59F_0000, 0xE12F_FF1E, 0xEB00_0123]));
    }

    #[test]
    fn thumb_masks_bl_pairs_and_branches_leaving() {
        let body = halves(&[
            0xF000, 0xF812, // bl
            0xF001, 0xE9AB, // blx
            0xE002, // b +4 (inside)
            0xE7F0, // b -32 (leaves)
            0xD001, // beq +2 (inside)
            0xD0F0, // beq -32 (leaves)
            0x2000, // movs r0, #0
            0x4770, // bx lr
        ]);
        let out = mask(Family::Thumb, &body);
        assert_eq!(
            out,
            halves(&[0xF000, 0xF800, 0xF000, 0xE800, 0xE002, 0xE000, 0xD001, 0xD000, 0x2000, 0x4770])
        );
    }

    #[test]
    fn thumb_masks_pool_addresses_but_not_constants() {
        // 0: ldr r0, [pc, #4] loads the word at ((0+4)&!3)+4 = 8
        // 2: ldr r1, [pc, #8] loads the word at ((2+4)&!3)+8 = 12
        // 4: bx lr  6: nop  8..12: address pool  12..16: constant pool
        let body = {
            let mut bytes = halves(&[0x4801, 0x4902, 0x4770, 0x46C0]);
            bytes.extend_from_slice(&0x0800_1235u32.to_le_bytes()); // ROM function pointer
            bytes.extend_from_slice(&0x0000_FFFFu32.to_le_bytes()); // constant
            bytes
        };
        let out = mask(Family::Thumb, &body);
        let mut expected = halves(&[0x4801, 0x4902, 0x4770, 0x46C0]);
        expected.extend_from_slice(&0u32.to_le_bytes());
        expected.extend_from_slice(&0x0000_FFFFu32.to_le_bytes());
        assert_eq!(out, expected);
    }

    #[test]
    fn identical_bodies_with_different_targets_mask_alike() {
        let a = le(&[0x27BD_FFE0, 0x0C00_1000, 0x3C04_8001, 0x2484_0010, 0x03E0_0008]);
        let b = le(&[0x27BD_FFE0, 0x0C00_2468, 0x3C04_8123, 0x2484_BEEF, 0x03E0_0008]);
        assert_eq!(mask(Family::MipsLe, &a), mask(Family::MipsLe, &b));
        let c = le(&[0x27BD_FFE0, 0x0C00_1000, 0x3C04_8001, 0x2484_0010, 0x03E0_0009]);
        assert_ne!(mask(Family::MipsLe, &a), mask(Family::MipsLe, &c));
    }
}
