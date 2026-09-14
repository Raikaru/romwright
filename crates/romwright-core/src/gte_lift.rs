//! PSX GTE psyq inline-macro lifter (P4.1).
//!
//! [`crate::gte`] decodes the raw COP2/GTE instruction set. The psyq SDK,
//! however, never emits a bare GTE command: every inline macro (`gte_rtps`,
//! `gte_rtpt`, `gte_nclip`, `gte_avsz3`, `gte_mvmva`, …) expands to a short
//! documented word sequence — two hazard-slot words (canonically `nop;
//! nop`, the GTE read/write delay the SDK docs require after any
//! `mtc2`/`ctc2`/`lwc2` write and before any `mfc2`/`cfc2`/`swc2` read)
//! followed by one COP2 command word (`cop2 <cofun>`), where the 25-bit
//! `cofun` immediate selects the operation and its flag fields
//! (`sf`, `mx`, `v`, `cv`, `lm`).
//!
//! A stock MIPS disassembler shows each such expansion as three (or more)
//! raw lines. This module folds every recognised expansion to a single
//! named-call fact ([`GteCall`], e.g. `gte_RTPS()`), so the listing and the
//! decompiler emit one call instead of raw COP2 noise.
//!
//! Clean-room sources (facts and public constants only, no copied code):
//! - psx-spx "GTE" section: COP2 encoding (`opcode 0x12`, `bit25 = 1`
//!   selects a GTE command, command number in bits 0:5), the GTE data /
//!   control register map, and the per-command flag fields (`sf` = bit 19,
//!   `mx` = bits 17:18, `v` = bits 15:16, `cv` = bits 13:14, `lm` =
//!   bit 10 for `mvmva`; `sf` for `sqr`/`op`/`gpf`/`gpl`).
//! - The vendored PSX language (`native/languages/psx/inline_s.sinc`):
//!   the exact `cofun` immediates each inline macro assembles to
//!   (`nop; nop; cop2 <cofun>`), mirrored here as a plain constant table.
//!   The bare-command constructors (`native/languages/psx/
//!   gte_fallback.sinc`) motivate the command-number fallback for
//!   flag combinations outside the documented set.
//! - The GTE command numbers themselves are shared with [`crate::gte`]
//!   (verified against rabbitizer's R3000GTE decoder).
//!
//! The API is deliberately decoupled from [`crate::gte`]: entry points take
//! plain `(address, word)` pairs, so callers map whatever decode they hold
//! (e.g. `gte::disassemble` output via `(insn.address, insn.word)`).

/// MIPS major opcode of every COP2/GTE word.
pub const OP_COP2: u32 = 0x12;
/// Bit selecting a GTE command over a COP2 register move.
pub const COP2_COMMAND_BIT: u32 = 1 << 25;
/// Full COP2 command word base: `opcode << 26 | bit25`.
pub const COP2_BASE: u32 = (OP_COP2 << 26) | COP2_COMMAND_BIT;
/// Mask of the 25-bit `cofun` command/flag immediate.
pub const COFUN_MASK: u32 = 0x01FF_FFFF;
/// MIPS `nop` (`sll $0, $0, 0`): the canonical GTE hazard-slot filler.
pub const NOP_WORD: u32 = 0;
/// `sf` flag bit inside `cofun` (bit 19 of the word).
pub const SF_BIT: u32 = 1 << 19;

/// Documented `cofun` immediates, one per psyq inline macro.
/// Same values the vendored PSX language matches in `inline_s.sinc`.
pub mod cofun {
    pub const RTPS: u32 = 0x0018_0001;
    pub const RTPT: u32 = 0x0028_0030;
    pub const RTV0: u32 = 0x0048_6012;
    pub const RTV1: u32 = 0x0048_E012;
    pub const RTV2: u32 = 0x0049_6012;
    pub const RTIR: u32 = 0x0049_E012;
    pub const RTIR_SF0: u32 = 0x0041_E012;
    pub const RT: u32 = 0x0048_0012;
    pub const RTV1TR: u32 = 0x0048_8012;
    pub const RTV2TR: u32 = 0x0049_0012;
    pub const RTIRTR: u32 = 0x0049_8012;
    pub const RTV0BK: u32 = 0x0048_2012;
    pub const RTV1BK: u32 = 0x0048_A012;
    pub const RTV2BK: u32 = 0x0049_2012;
    pub const RTIRBK: u32 = 0x0049_A012;
    pub const LL: u32 = 0x004A_6412;
    pub const LLV0: u32 = 0x004A_6012;
    pub const LLV1: u32 = 0x004A_E012;
    pub const LLV2: u32 = 0x004B_6012;
    pub const LLIR: u32 = 0x004B_E012;
    pub const LLV0TR: u32 = 0x004A_0012;
    pub const LLV1TR: u32 = 0x004A_8012;
    pub const LLV2TR: u32 = 0x004B_0012;
    pub const LLIRTR: u32 = 0x004B_8012;
    pub const LLV0BK: u32 = 0x004A_2012;
    pub const LLV1BK: u32 = 0x004A_A012;
    pub const LLV2BK: u32 = 0x004B_2012;
    pub const LLIRBK: u32 = 0x004B_A012;
    pub const LC: u32 = 0x004D_A412;
    pub const LCV0: u32 = 0x004C_6012;
    pub const LCV1: u32 = 0x004C_E012;
    pub const LCV2: u32 = 0x004D_6012;
    pub const LCIR: u32 = 0x004D_E012;
    pub const LCV0TR: u32 = 0x004C_0012;
    pub const LCV1TR: u32 = 0x004C_8012;
    pub const LCV2TR: u32 = 0x004D_0012;
    pub const LCIRTR: u32 = 0x004D_8012;
    pub const LCV0BK: u32 = 0x004C_2012;
    pub const LCV1BK: u32 = 0x004C_A012;
    pub const LCV2BK: u32 = 0x004D_2012;
    pub const LCIRBK: u32 = 0x004D_A012;
    pub const DPCL: u32 = 0x0068_0029;
    pub const DPCS: u32 = 0x0078_0010;
    pub const DPCT: u32 = 0x00F8_002A;
    pub const INTPL: u32 = 0x0098_0011;
    pub const SQR12: u32 = 0x00A8_0428;
    pub const SQR0: u32 = 0x00A0_0428;
    pub const NCS: u32 = 0x00C8_041E;
    pub const NCT: u32 = 0x00D8_0420;
    pub const NCDS: u32 = 0x00E8_0413;
    pub const NCDT: u32 = 0x00F8_0416;
    pub const NCCS: u32 = 0x0108_041B;
    pub const NCCT: u32 = 0x0118_043F;
    pub const CDP: u32 = 0x0128_0414;
    pub const CC: u32 = 0x0138_041C;
    pub const NCLIP: u32 = 0x0140_0006;
    pub const AVSZ3: u32 = 0x0158_002D;
    pub const AVSZ4: u32 = 0x0168_002E;
    pub const OP12: u32 = 0x0178_000C;
    pub const OP0: u32 = 0x0170_000C;
    pub const GPF12: u32 = 0x0198_003D;
    pub const GPF0: u32 = 0x0190_003D;
    pub const GPL12: u32 = 0x01A8_003E;
    pub const GPL0: u32 = 0x01A0_003E;
}

/// `mvmva` selector fields inside `cofun` (psx-spx GTE flag layout).
pub mod mvmva {
    /// Bits 0:9 must equal the `mvmva` command for the parametric form.
    pub const SELECT_MASK: u32 = 0x01F0_03FF;
    /// Bits 20:24 = `0x4`, bits 0:9 = `0x12` (`mvmva` command).
    pub const SELECT_VALUE: u32 = 0x0040_0012;
}

/// Decoded `mvmva` flag fields (psx-spx GTE flag layout, shared with
/// [`crate::gte`]'s `mvmva` operand order `mx, v, cv, lm, sf`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MvmvaParams {
    pub sf: u32,
    pub mx: u32,
    pub v: u32,
    pub cv: u32,
    pub lm: u32,
}

/// One lifted psyq inline-macro call: the single named-call fact that
/// replaces `len` raw COP2 lines (`len == 3` for the documented
/// `nop; nop; cop2` expansion, `len == 1` for a bare command word).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GteCall {
    /// Address of the first folded word (first hazard slot, or the
    /// command word itself for a bare lift).
    pub address: u64,
    /// Address of the COP2 command word.
    pub command_address: u64,
    /// Canonical psyq name, e.g. `"gte_RTPS"`.
    pub name: &'static str,
    /// GTE command number (bits 0:5), e.g. `0x01` for `RTPS`.
    pub command: u8,
    /// Full 25-bit `cofun` immediate of the command word.
    pub cofun: u32,
    /// Raw instruction words folded into this call.
    pub len: usize,
    /// True when `cofun` is one of the documented inline-macro
    /// immediates; false for a flag-variant fallback by command number.
    pub exact: bool,
    /// `sf` flag for the `sf`-carrying ops (`SQR0`/`OP0`/`GPF0`/`GPL0`).
    pub sf: Option<u32>,
    /// Flag fields for `MVMVA` (exact `RT…`/`LL…`/`LC…` family members
    /// report `None`: their flags are fixed by the macro).
    pub mvmva: Option<MvmvaParams>,
}

impl GteCall {
    /// First address past the folded sequence.
    pub fn end_address(self) -> u64 {
        self.address + 4 * self.len as u64
    }

    /// C-shaped call text, e.g. `gte_RTPS()` or
    /// `gte_MVMVA(0, 1, 0, 2, 1)`.
    pub fn render(self) -> String {
        if let Some(m) = self.mvmva {
            return format!(
                "{}(sf={}, mx={}, v={}, cv={}, lm={})",
                self.name, m.sf, m.mx, m.v, m.cv, m.lm
            );
        }
        if let Some(sf) = self.sf {
            return format!("{}(sf={sf})", self.name);
        }
        format!("{}()", self.name)
    }
}

impl std::fmt::Display for GteCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} @ {:#x} [{} insn{}]",
            self.render(),
            self.address,
            self.len,
            if self.len == 1 { "" } else { "s" }
        )
    }
}

/// True for the MIPS `nop` word (the canonical GTE hazard-slot filler).
pub fn is_nop(word: u32) -> bool {
    word == NOP_WORD
}

/// True when `word` is a GTE command (`opcode 0x12`, `bit25 = 1`).
pub fn is_gte_command_word(word: u32) -> bool {
    word & 0xFE00_0000 == COP2_BASE
}

/// The 25-bit `cofun` immediate of a COP2 word.
pub fn cofun_of(word: u32) -> u32 {
    word & COFUN_MASK
}

/// GTE command number (bits 0:5) of a COP2 word.
pub fn command_of(word: u32) -> u8 {
    (word & 0x3F) as u8
}

/// Decode the `mvmva` flag fields of a `cofun` immediate.
pub fn mvmva_params(cofun: u32) -> MvmvaParams {
    MvmvaParams {
        sf: (cofun >> 19) & 1,
        mx: (cofun >> 17) & 3,
        v: (cofun >> 15) & 3,
        cv: (cofun >> 13) & 3,
        lm: (cofun >> 10) & 1,
    }
}

/// Classify a `cofun` immediate: `(name, sf, mvmva, exact)`.
///
/// The exact table mirrors the documented inline-macro immediates
/// ([`cofun`]); anything else with a recognised parametric `mvmva`
/// selector decodes its flag fields; anything else with a known command
/// number falls back to the generic command name (as the vendored
/// language's fallback constructors do for bare flag combinations).
fn classify_cofun(
    cofun: u32,
) -> Option<(&'static str, Option<u32>, Option<MvmvaParams>, bool)> {
    let entry: Option<(&'static str, Option<u32>)> = Some(match cofun {
        cofun::RTPS => ("gte_RTPS", None),
        cofun::RTPT => ("gte_RTPT", None),
        cofun::RTV0 => ("gte_RTV0", None),
        cofun::RTV1 => ("gte_RTV1", None),
        cofun::RTV2 => ("gte_RTV2", None),
        cofun::RTIR => ("gte_RTIR", None),
        cofun::RTIR_SF0 => ("gte_RTIR_SF0", None),
        cofun::RT => ("gte_RT", None),
        cofun::RTV1TR => ("gte_RTV1TR", None),
        cofun::RTV2TR => ("gte_RTV2TR", None),
        cofun::RTIRTR => ("gte_RTIRTR", None),
        cofun::RTV0BK => ("gte_RTV0BK", None),
        cofun::RTV1BK => ("gte_RTV1BK", None),
        cofun::RTV2BK => ("gte_RTV2BK", None),
        cofun::RTIRBK => ("gte_RTIRBK", None),
        cofun::LL => ("gte_LL", None),
        cofun::LLV0 => ("gte_LLV0", None),
        cofun::LLV1 => ("gte_LLV1", None),
        cofun::LLV2 => ("gte_LLV2", None),
        cofun::LLIR => ("gte_LLIR", None),
        cofun::LLV0TR => ("gte_LLV0TR", None),
        cofun::LLV1TR => ("gte_LLV1TR", None),
        cofun::LLV2TR => ("gte_LLV2TR", None),
        cofun::LLIRTR => ("gte_LLIRTR", None),
        cofun::LLV0BK => ("gte_LLV0BK", None),
        cofun::LLV1BK => ("gte_LLV1BK", None),
        cofun::LLV2BK => ("gte_LLV2BK", None),
        cofun::LLIRBK => ("gte_LLIRBK", None),
        cofun::LC => ("gte_LC", None),
        cofun::LCV0 => ("gte_LCV0", None),
        cofun::LCV1 => ("gte_LCV1", None),
        cofun::LCV2 => ("gte_LCV2", None),
        cofun::LCIR => ("gte_LCIR", None),
        cofun::LCV0TR => ("gte_LCV0TR", None),
        cofun::LCV1TR => ("gte_LCV1TR", None),
        cofun::LCV2TR => ("gte_LCV2TR", None),
        cofun::LCIRTR => ("gte_LCIRTR", None),
        cofun::LCV0BK => ("gte_LCV0BK", None),
        cofun::LCV1BK => ("gte_LCV1BK", None),
        cofun::LCV2BK => ("gte_LCV2BK", None),
        cofun::LCIRBK => ("gte_LCIRBK", None),
        cofun::DPCL => ("gte_DPCL", None),
        cofun::DPCS => ("gte_DPCS", None),
        cofun::DPCT => ("gte_DPCT", None),
        cofun::INTPL => ("gte_INTPL", None),
        cofun::SQR12 => ("gte_SQR12", None),
        cofun::SQR0 => ("gte_SQR0", Some(0)),
        cofun::NCS => ("gte_NCS", None),
        cofun::NCT => ("gte_NCT", None),
        cofun::NCDS => ("gte_NCDS", None),
        cofun::NCDT => ("gte_NCDT", None),
        cofun::NCCS => ("gte_NCCS", None),
        cofun::NCCT => ("gte_NCCT", None),
        cofun::CDP => ("gte_CDP", None),
        cofun::CC => ("gte_CC", None),
        cofun::NCLIP => ("gte_NCLIP", None),
        cofun::AVSZ3 => ("gte_AVSZ3", None),
        cofun::AVSZ4 => ("gte_AVSZ4", None),
        cofun::OP12 => ("gte_OP12", None),
        cofun::OP0 => ("gte_OP0", Some(0)),
        cofun::GPF12 => ("gte_GPF12", None),
        cofun::GPF0 => ("gte_GPF0", Some(0)),
        cofun::GPL12 => ("gte_GPL12", None),
        cofun::GPL0 => ("gte_GPL0", Some(0)),
        _ => return classify_fallback(cofun),
    });
    entry.map(|(name, sf)| (name, sf, None, true))
}

/// Non-exact classification: parametric `mvmva` first, then the generic
/// command-number fallback. Returns `None` for unknown commands.
fn classify_fallback(
    cofun: u32,
) -> Option<(&'static str, Option<u32>, Option<MvmvaParams>, bool)> {
    if cofun & mvmva::SELECT_MASK == mvmva::SELECT_VALUE {
        return Some(("gte_MVMVA", None, Some(mvmva_params(cofun)), false));
    }
    let name = match (cofun & 0x3F) as u8 {
        0x01 => "gte_RTPS",
        0x06 => "gte_NCLIP",
        0x0C => "gte_OP",
        0x10 => "gte_DPCS",
        0x11 => "gte_INTPL",
        0x12 => return Some(("gte_MVMVA", None, Some(mvmva_params(cofun)), false)),
        0x13 => "gte_NCDS",
        0x14 => "gte_CDP",
        0x16 => "gte_NCDT",
        0x1B => "gte_NCCS",
        0x1C => "gte_CC",
        0x1E => "gte_NCS",
        0x20 => "gte_NCT",
        0x28 => "gte_SQR",
        0x29 => "gte_DPCL",
        0x2A => "gte_DPCT",
        0x2D => "gte_AVSZ3",
        0x2E => "gte_AVSZ4",
        0x30 => "gte_RTPT",
        0x3D => "gte_GPF",
        0x3E => "gte_GPL",
        0x3F => "gte_NCCT",
        _ => return None,
    };
    Some((name, None, None, false))
}

/// Classify one full COP2 word into a call skeleton (addresses filled in
/// by the caller). Returns `None` for non-command words and for command
/// words with an unrecognised command number.
fn classify_word(word: u32) -> Option<GteCall> {
    if !is_gte_command_word(word) {
        return None;
    }
    let cofun = cofun_of(word);
    let (name, sf, mvmva, exact) = classify_cofun(cofun)?;
    Some(GteCall {
        address: 0,
        command_address: 0,
        name,
        command: command_of(word),
        cofun,
        len: 1,
        exact,
        sf,
        mvmva,
    })
}

/// Lift a contiguous COP2 word stream at `base` (word `i` lives at
/// `base + 4 * i`).
///
/// At each position the documented 3-word expansion (`nop; nop; cop2`)
/// wins over a bare command word; a bare command word still lifts on its
/// own (covering delay slots the compiler filled with useful
/// instructions, and hand-written command words). Non-command words pass
/// through silently.
pub fn lift_words(words: &[u32], base: u64) -> Vec<GteCall> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < words.len() {
        if i + 2 < words.len()
            && is_nop(words[i])
            && is_nop(words[i + 1])
            && let Some(mut call) = classify_word(words[i + 2])
        {
            call.address = base + 4 * i as u64;
            call.command_address = base + 4 * (i + 2) as u64;
            call.len = 3;
            out.push(call);
            i += 3;
            continue;
        }
        if let Some(mut call) = classify_word(words[i]) {
            call.address = base + 4 * i as u64;
            call.command_address = call.address;
            out.push(call);
        }
        i += 1;
    }
    out
}

/// Lift little-endian words from `bytes` at virtual address `vaddr`.
/// A trailing partial word is ignored.
pub fn lift_bytes(bytes: &[u8], vaddr: u64) -> Vec<GteCall> {
    let words: Vec<u32> = bytes
        .chunks_exact(4)
        .map(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]))
        .collect();
    lift_words(&words, vaddr)
}

/// Lift an explicitly addressed stream (e.g. mapped from
/// `gte::disassemble` output as `(insn.address, insn.word)`).
///
/// Unlike [`lift_words`], no contiguity is assumed: a 3-word expansion
/// only folds when its words sit at consecutive `+4` addresses, so gaps
/// (branches, data in code) can never fuse two unrelated embargoes into
/// one call.
pub fn lift_pairs(pairs: &[(u64, u32)]) -> Vec<GteCall> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < pairs.len() {
        let triple = i + 2 < pairs.len()
            && is_nop(pairs[i].1)
            && is_nop(pairs[i + 1].1)
            && pairs[i + 1].0 == pairs[i].0.wrapping_add(4)
            && pairs[i + 2].0 == pairs[i].0.wrapping_add(8);
        if triple && let Some(mut call) = classify_word(pairs[i + 2].1) {
            call.address = pairs[i].0;
            call.command_address = pairs[i + 2].0;
            call.len = 3;
            out.push(call);
            i += 3;
            continue;
        }
        if let Some(mut call) = classify_word(pairs[i].1) {
            call.address = pairs[i].0;
            call.command_address = pairs[i].0;
            out.push(call);
        }
        i += 1;
    }
    out
}

/// One output line of [`annotate`]: either an untouched raw word or a
/// folded named call replacing `len` raw lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiftedLine {
    Raw { address: u64, word: u32 },
    Folded(GteCall),
}

/// Annotate an addressed stream, folding every recognised expansion to a
/// single [`LiftedLine::Folded`] fact and passing the rest through as
/// [`LiftedLine::Raw`]. `Folded` lines always cover `call.len`
/// consecutive raw words, so `annotate(pairs).len() <= pairs.len()`.
pub fn annotate(pairs: &[(u64, u32)]) -> Vec<LiftedLine> {
    let mut out = Vec::with_capacity(pairs.len());
    let mut i = 0;
    while i < pairs.len() {
        let triple = i + 2 < pairs.len()
            && is_nop(pairs[i].1)
            && is_nop(pairs[i + 1].1)
            && pairs[i + 1].0 == pairs[i].0.wrapping_add(4)
            && pairs[i + 2].0 == pairs[i].0.wrapping_add(8);
        if triple && let Some(mut call) = classify_word(pairs[i + 2].1) {
            call.address = pairs[i].0;
            call.command_address = pairs[i + 2].0;
            call.len = 3;
            out.push(LiftedLine::Folded(call));
            i += 3;
            continue;
        }
        if let Some(mut call) = classify_word(pairs[i].1) {
            call.address = pairs[i].0;
            call.command_address = pairs[i].0;
            out.push(LiftedLine::Folded(call));
        } else {
            out.push(LiftedLine::Raw {
                address: pairs[i].0,
                word: pairs[i].1,
            });
        }
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Assemble a COP2 command word from a `cofun` immediate.
    fn cop2(cofun: u32) -> u32 {
        COP2_BASE | cofun
    }

    #[test]
    fn rtps_sequence_lifts_to_one_call() {
        // The documented psyq `gte_rtps` expansion: two hazard-slot nops
        // followed by `cop2 0x00180001`.
        let words = [NOP_WORD, NOP_WORD, cop2(cofun::RTPS)];
        let calls = lift_words(&words, 0x8001_0000);
        assert_eq!(calls.len(), 1, "expected one call, got {calls:?}");
        let call = calls[0];
        assert_eq!(call.name, "gte_RTPS");
        assert_eq!(call.command, 0x01);
        assert_eq!(call.address, 0x8001_0000);
        assert_eq!(call.command_address, 0x8001_0008);
        assert_eq!(call.len, 3);
        assert!(call.exact);
        assert_eq!(call.render(), "gte_RTPS()");
    }

    #[test]
    fn rtpt_nclip_avsz3_sequences_lift() {
        for (cofun, name, command) in [
            (cofun::RTPT, "gte_RTPT", 0x30),
            (cofun::NCLIP, "gte_NCLIP", 0x06),
            (cofun::AVSZ3, "gte_AVSZ3", 0x2D),
            (cofun::AVSZ4, "gte_AVSZ4", 0x2E),
        ] {
            let words = [NOP_WORD, NOP_WORD, cop2(cofun)];
            let calls = lift_words(&words, 0x8002_0000);
            assert_eq!(calls.len(), 1, "expected one {name} call");
            assert_eq!(calls[0].name, name);
            assert_eq!(calls[0].command, command);
            assert_eq!(calls[0].len, 3);
            assert!(calls[0].exact);
        }
    }

    #[test]
    fn mvmva_lift_decodes_flag_fields() {
        // sf=0, mx=1, v=0, cv=2, lm=1: not a documented fixed macro, so
        // the parametric path decodes the fields.
        let cofun =
            (0x4 << 20) | (1 << 17) | (0 << 15) | (2 << 13) | (1 << 10) | 0x12;
        assert_eq!(cofun & mvmva::SELECT_MASK, mvmva::SELECT_VALUE);
        let words = [NOP_WORD, NOP_WORD, cop2(cofun)];
        let calls = lift_words(&words, 0x8003_0000);
        assert_eq!(calls.len(), 1, "expected one call, got {calls:?}");
        let call = calls[0];
        assert_eq!(call.name, "gte_MVMVA");
        assert_eq!(call.command, 0x12);
        assert_eq!(
            call.mvmva,
            Some(MvmvaParams { sf: 0, mx: 1, v: 0, cv: 2, lm: 1 })
        );
        assert_eq!(call.render(), "gte_MVMVA(sf=0, mx=1, v=0, cv=2, lm=1)");
    }

    #[test]
    fn bare_command_word_lifts_len_one() {
        // A hand-written command with filled delay slots still lifts.
        let words = [0x2408_0001, cop2(cofun::RTPS)];
        let calls = lift_words(&words, 0x8004_0000);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "gte_RTPS");
        assert_eq!(calls[0].len, 1);
        assert_eq!(calls[0].address, 0x8004_0004);
    }

    #[test]
    fn unknown_flags_fall_back_to_command_name() {
        // Bare `rtps` flag combination: known command, undocumented flags.
        let words = [cop2(0x0000_0001)];
        let calls = lift_words(&words, 0x8005_0000);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "gte_RTPS");
        assert!(!calls[0].exact);
    }

    #[test]
    fn unknown_command_and_moves_are_ignored() {
        // Command 0x00 is not a GTE command; mtc2/cfc2 moves are COP2
        // traffic but not macro calls.
        let mtc2 = (OP_COP2 << 26) | (4 << 21) | (8 << 16) | (0 << 11);
        let cfc2 = (OP_COP2 << 26) | (2 << 21) | (8 << 16) | (31 << 11);
        let words = [mtc2, cfc2, cop2(0x0000_0000)];
        assert!(lift_words(&words, 0x8006_0000).is_empty());
        // A zero-length stream lifts to nothing.
        assert!(lift_words(&[], 0x8006_0000).is_empty());
    }

    #[test]
    fn annotate_folds_three_lines_into_one_fact() {
        let base = 0x8007_0000u64;
        let pairs = [
            (base, 0x2408_0001u32), // addiu $t0, $zero, 1 (untouched)
            (base + 4, NOP_WORD),
            (base + 8, NOP_WORD),
            (base + 12, cop2(cofun::RTPS)),
            (base + 16, 0x0000_0000u32), // lone nop stays raw
        ];
        let lines = annotate(&pairs);
        assert_eq!(lines.len(), 3, "expected 3 lines, got {lines:?}");
        assert!(matches!(lines[0], LiftedLine::Raw { .. }));
        match lines[1] {
            LiftedLine::Folded(call) => {
                assert_eq!(call.name, "gte_RTPS");
                assert_eq!(call.len, 3);
            }
            other => panic!("expected folded call, got {other:?}"),
        }
        assert!(matches!(lines[2], LiftedLine::Raw { .. }));
    }

    #[test]
    fn lift_pairs_requires_contiguous_addresses() {
        // Same words but with an address gap: the nops must not fuse
        // with a far-away command word.
        let pairs = [
            (0x8008_0000u64, NOP_WORD),
            (0x8008_0004u64, NOP_WORD),
            (0x9000_0000u64, cop2(cofun::RTPS)),
        ];
        let calls = lift_pairs(&pairs);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].len, 1, "gap must force a bare lift");
        assert_eq!(calls[0].command_address, 0x9000_0000);
    }

    #[test]
    fn lift_bytes_decodes_little_endian_stream() {
        let mut bytes = Vec::new();
        for word in [NOP_WORD, NOP_WORD, cop2(cofun::NCLIP)] {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        bytes.extend_from_slice(&[0xAA, 0xBB]); // trailing partial ignored
        let calls = lift_bytes(&bytes, 0x8009_0000);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "gte_NCLIP");
        assert_eq!(calls[0].render(), "gte_NCLIP()");
        assert_eq!(
            calls[0].to_string(),
            "gte_NCLIP() @ 0x80090000 [3 insns]"
        );
    }
}
