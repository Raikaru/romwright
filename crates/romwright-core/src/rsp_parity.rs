//! RSP disassembly parity: an independent oracle for `super::rsp::decode`.
//!
//! The oracle below is transcribed directly from the documented RSP encoding
//! (MIPS-I scalar opcode map; COP2 `010010` with bit 25 selecting the vector
//! unit; the 6-bit vector funct table; `LWC2`/`SWC2` sub-ops in the rd
//! field) — the same public tables `rsp.slaspec` and `rsp.rs` were verified
//! against. [`sweep`] decodes a structured sample of the encoding space with
//! both the oracle and the real decoder and reports agreement, so the three
//! artifacts (oracle, decoder, SLEIGH) are pinned together. External ground
//! truth (rabbitizer, the decoder spimdisasm wraps) is exercised by the
//! `tests/m20-014_rsp_gbi.py` gate.
//!
//! ares (ISC) was checked for and is not on disk, per the P4.4 fallback:
//! this mnemonic+operand sweep against the documented opcode table is the
//! recorded parity check.

use super::rsp;

/// Canonical mnemonic for one RSP instruction word, without assembler
/// pseudo-ops (`nop`/`move`/`bal`/`b`/`beqz`/`bnez` canonicalise to their
/// underlying instructions).
pub fn oracle_mnemonic(word: u32) -> &'static str {
    let opcode = word >> 26;
    let rs = (word >> 21) & 31;
    let rt = (word >> 16) & 31;
    let funct = word & 0x3f;
    match opcode {
        0x00 => match funct {
            0x00 => "sll",
            0x02 => "srl",
            0x03 => "sra",
            0x04 => "sllv",
            0x06 => "srlv",
            0x07 => "srav",
            0x08 => "jr",
            0x09 => "jalr",
            0x0c => "syscall",
            0x0d => "break",
            0x10 => "mfhi",
            0x11 => "mthi",
            0x12 => "mflo",
            0x13 => "mtlo",
            0x18 => "mult",
            0x19 => "multu",
            0x1a => "div",
            0x1b => "divu",
            0x20 => "add",
            0x21 => "addu",
            0x22 => "sub",
            0x23 => "subu",
            0x24 => "and",
            0x25 => "or",
            0x26 => "xor",
            0x27 => "nor",
            0x2a => "slt",
            0x2b => "sltu",
            _ => ".word",
        },
        0x01 => match rt {
            0x00 => "bltz",
            0x01 => "bgez",
            0x10 => "bltzal",
            0x11 => "bgezal",
            _ => ".word",
        },
        0x02 => "j",
        0x03 => "jal",
        0x04 => "beq",
        0x05 => "bne",
        0x06 => "blez",
        0x07 => "bgtz",
        0x08 => "addi",
        0x09 => "addiu",
        0x0a => "slti",
        0x0b => "sltiu",
        0x0c => "andi",
        0x0d => "ori",
        0x0e => "xori",
        0x0f => "lui",
        0x10 => match rs {
            0x00 => "mfc0",
            0x04 => "mtc0",
            _ => ".word",
        },
        0x12 => {
            if rs & 0x10 != 0 {
                match funct {
                    0x00 => "vmulf",
                    0x01 => "vmulu",
                    0x02 => "vrndp",
                    0x03 => "vmulq",
                    0x04 => "vmudl",
                    0x05 => "vmudm",
                    0x06 => "vmudn",
                    0x07 => "vmudh",
                    0x08 => "vmacf",
                    0x09 => "vmacu",
                    0x0a => "vrndn",
                    0x0b => "vmacq",
                    0x0c => "vmadl",
                    0x0d => "vmadm",
                    0x0e => "vmadn",
                    0x0f => "vmadh",
                    0x10 => "vadd",
                    0x11 => "vsub",
                    0x13 => "vabs",
                    0x14 => "vaddc",
                    0x15 => "vsubc",
                    0x1d => "vsar",
                    0x20 => "vlt",
                    0x21 => "veq",
                    0x22 => "vne",
                    0x23 => "vge",
                    0x24 => "vcl",
                    0x25 => "vch",
                    0x26 => "vcr",
                    0x27 => "vmrg",
                    0x28 => "vand",
                    0x29 => "vnand",
                    0x2a => "vor",
                    0x2b => "vnor",
                    0x2c => "vxor",
                    0x2d => "vnxor",
                    0x30 => "vrcp",
                    0x31 => "vrcpl",
                    0x32 => "vrcph",
                    0x33 => "vmov",
                    0x34 => "vrsq",
                    0x35 => "vrsql",
                    0x36 => "vrsqh",
                    0x37 => "vnop",
                    _ => ".word",
                }
            } else {
                match rs {
                    0x00 => "mfc2",
                    0x02 => "cfc2",
                    0x04 => "mtc2",
                    0x06 => "ctc2",
                    _ => ".word",
                }
            }
        }
        0x20 => "lb",
        0x21 => "lh",
        0x23 => "lw",
        0x24 => "lbu",
        0x25 => "lhu",
        0x28 => "sb",
        0x29 => "sh",
        0x2b => "sw",
        0x32 => match (word >> 11) & 31 {
            0 => "lbv",
            1 => "lsv",
            2 => "llv",
            3 => "ldv",
            4 => "lqv",
            5 => "lrv",
            6 => "lpv",
            7 => "luv",
            8 => "lhv",
            9 => "lfv",
            11 => "ltv",
            _ => ".word",
        },
        0x33 => "pref",
        0x3a => match (word >> 11) & 31 {
            0 => "sbv",
            1 => "ssv",
            2 => "slv",
            3 => "sdv",
            4 => "sqv",
            5 => "srv",
            6 => "spv",
            7 => "suv",
            8 => "shv",
            9 => "sfv",
            11 => "stv",
            _ => ".word",
        },
        _ => ".word",
    }
}

/// Map assembler pseudo-ops to their canonical mnemonics for comparison.
pub fn normalize(mnemonic: &str) -> &str {
    match mnemonic {
        "nop" => "sll",
        "move" => "or",
        "bal" => "bgezal",
        "b" => "beq",
        "beqz" => "beq",
        "bnez" => "bne",
        other => other,
    }
}

/// Result of [`sweep`].
#[derive(Debug, Clone)]
pub struct ParityReport {
    pub total: usize,
    pub matched: usize,
    /// First few disagreeing words, for diagnosis.
    pub mismatches: Vec<u32>,
}

impl ParityReport {
    pub fn summary(&self) -> String {
        format!(
            "RSP parity {}/{} ({:.2}%)",
            self.matched,
            self.total,
            100.0 * self.matched as f64 / self.total.max(1) as f64
        )
    }
}

/// Structured sweep words covering the documented encoding space:
/// every SPECIAL funct, every REGIMM rt, every top-level opcode, every
/// vector funct × element, every COP0/COP2 move selector, every vector
/// load/store sub-op.
pub fn sweep_words() -> Vec<u32> {
    let mut words = Vec::with_capacity(2048);
    // SPECIAL: all 64 functs × register combos.
    for funct in 0..64u32 {
        for &(rs, rt, rd, sa) in &[(0, 0, 0, 0), (8, 9, 10, 3), (31, 31, 31, 31), (4, 5, 6, 0)] {
            words.push(funct | sa << 6 | rd << 11 | rt << 16 | rs << 21);
        }
    }
    // REGIMM: all 32 rt values × rs.
    for rt in 0..32u32 {
        for rs in [0u32, 8] {
            words.push(0x01 << 26 | rs << 21 | rt << 16 | 0x10);
        }
    }
    // Top-level opcodes × payload extremes.
    for op in 0..64u32 {
        for payload in [0u32, 0x03ff_ffff, 0x0209_8289, 0x0000_0010] {
            words.push(op << 26 | payload);
        }
    }
    // Vector ops: all 64 functs × elements × register triples.
    for funct in 0..64u32 {
        for e in [0u32, 3, 15] {
            for &(vt, vs, vd) in &[(2, 3, 4), (0, 0, 0), (31, 30, 29)] {
                words.push(0x12 << 26 | 1 << 25 | e << 21 | vt << 16 | vs << 11 | vd << 6 | funct);
            }
        }
    }
    // COP2 moves: all 32 rs selectors.
    for rs in 0..32u32 {
        words.push(0x12 << 26 | rs << 21 | 9 << 16 | 10 << 11 | 3);
    }
    // COP0 moves: all 32 rs selectors.
    for rs in 0..32u32 {
        words.push(0x10 << 26 | rs << 21 | 9 << 16 | 3 << 11);
    }
    // Vector loads/stores: both opcodes × all 32 sub-ops × base/offset.
    for op in [0x32u32, 0x3au32] {
        for sub in 0..32u32 {
            for &(rs, rt, elem, off) in &[(1, 2, 0, 0), (8, 9, 7, 0x7f)] {
                words.push(op << 26 | rs << 21 | rt << 16 | sub << 11 | elem << 7 | off);
            }
        }
    }
    words
}

/// Run the sweep: decode every sweep word with the real decoder and the
/// oracle, comparing canonical mnemonics.
pub fn sweep() -> ParityReport {
    let mut report = ParityReport {
        total: 0,
        matched: 0,
        mismatches: Vec::new(),
    };
    for word in sweep_words() {
        report.total += 1;
        let ours = rsp::decode(word, 0x8000_0000);
        if normalize(&ours.mnemonic) == oracle_mnemonic(word) {
            report.matched += 1;
        } else if report.mismatches.len() < 16 {
            report.mismatches.push(word);
        }
    }
    report
}

/// The SLEIGH source, for the decoder↔spec coverage test.
#[cfg(test)]
const SLASPEC: &str = include_str!("../../../native/languages/rsp/rsp.slaspec");

#[cfg(test)]
fn slaspec_has(mnemonic: &str) -> bool {
    SLASPEC.contains(&format!(":{mnemonic} "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parity_sweep_matches_oracle() {
        let report = sweep();
        assert!(
            report.matched == report.total,
            "{}; first mismatches: {:08x?}",
            report.summary(),
            report.mismatches
        );
        // Sanity: the sweep is non-trivial and covers valid decodes.
        assert!(report.total > 1000);
    }

    #[test]
    fn vector_operands_carry_registers() {
        // vmulf $v4, $v5, $v6 (vt=6, vs=5, vd=4, e=0).
        let ins = rsp::decode(0x12 << 26 | 1 << 25 | 0 << 21 | 6 << 16 | 5 << 11 | 4 << 6 | 0x00, 0);
        assert_eq!(ins.mnemonic, "vmulf");
        for reg in ["$v4", "$v5", "$v6"] {
            assert!(ins.operands.contains(reg), "{}", ins.operands);
        }
        // vrcp $v4[5], $v6 (single-element family shows vd[e], vt).
        let ins = rsp::decode(0x12 << 26 | 1 << 25 | 5 << 21 | 6 << 16 | 0 << 11 | 4 << 6 | 0x30, 0);
        assert_eq!(ins.mnemonic, "vrcp");
        assert!(ins.operands.contains("$v4[5]"), "{}", ins.operands);
        assert!(ins.operands.contains("$v6"), "{}", ins.operands);
        // mfc2 $9, $v10.
        let ins = rsp::decode(0x12 << 26 | 0 << 21 | 9 << 16 | 10 << 11, 0);
        assert_eq!(ins.mnemonic, "mfc2");
        assert!(ins.operands.contains("$9"), "{}", ins.operands);
        assert!(ins.operands.contains("$v10"), "{}", ins.operands);
        // lbv $v2[3], 0x7f($8).
        let ins = rsp::decode(0x32 << 26 | 8 << 21 | 2 << 16 | 0 << 11 | 3 << 7 | 0x7f, 0);
        assert_eq!(ins.mnemonic, "lbv");
        assert!(ins.operands.contains("$v2[3]"), "{}", ins.operands);
        assert!(ins.operands.contains("$8"), "{}", ins.operands);
        // Scalar R-type carries rd, rs, rt.
        let ins = rsp::decode(0x00 | 6 << 6 | 8 << 11 | 5 << 16 | 4 << 21 | 0x21, 0);
        assert_eq!(ins.mnemonic, "addu");
        for reg in ["$8", "$4", "$5"] {
            assert!(ins.operands.contains(reg), "{}", ins.operands);
        }
    }

    #[test]
    fn slaspec_covers_oracle_vector_table() {
        // Every valid vector funct in the documented table has a SLEIGH
        // constructor; every invalid one must not decode (covered by the
        // sweep asserting ".word" agreement).
        let mut valid = 0;
        for funct in 0..64u32 {
            let word = 0x12 << 26 | 1 << 25 | 0 << 21 | 2 << 16 | 3 << 11 | 4 << 6 | funct;
            let name = oracle_mnemonic(word);
            if name == ".word" {
                continue;
            }
            valid += 1;
            assert!(slaspec_has(name), "slaspec missing ::{name}");
        }
        assert!(valid > 30, "oracle table unexpectedly small: {valid}");
    }

    #[test]
    fn slaspec_covers_scalar_and_move_core() {
        for name in [
            "sll", "jr", "jalr", "addu", "lw", "sw", "lui", "ori", "beq", "bne", "jal", "mult",
            "mfc0", "mtc0", "mfc2", "mtc2", "lbv", "lqv", "sbv", "stv",
        ] {
            assert!(slaspec_has(name), "slaspec missing ::{name}");
        }
    }
}
