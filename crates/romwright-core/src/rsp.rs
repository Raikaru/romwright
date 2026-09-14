//! N64 RSP disassembly: the scalar unit is MIPS-I; the vector unit is
//! COP2. Opcode tables verified against rabbitizer (the decoder
//! spimdisasm/rspDisasm wraps) — the N64 decomp community's reference.
//!
//! Encoding:
//!   scalar: standard MIPS-I (SPECIAL/REGIMM/opcode fields).
//!   vector: `010010 1 eeee vt vs vd funct` — COP2, bit25=1.
//!   vector load/store: LWC2 `110010` / SWC2 `111010`, the rd field
//!   (bits 15:11) selects the sub-op (lbv..ltv / sbv..stv).

/// One decoded RSP instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RspInsn {
    pub address: u64,
    pub word: u32,
    pub mnemonic: String,
    pub operands: String,
}

fn gpr(n: u32) -> String {
    format!("${n}")
}

fn vr(n: u32) -> String {
    format!("$v{n}")
}

/// The COP2 vector funct table (bits 5:0), verified against rabbitizer.
/// `None` = invalid encoding.
const VECTOR_FUNCT: [Option<&str>; 64] = [
    /* 00 */ Some("vmulf"), Some("vmulu"), Some("vrndp"), Some("vmulq"),
    /* 04 */ Some("vmudl"), Some("vmudm"), Some("vmudn"), Some("vmudh"),
    /* 08 */ Some("vmacf"), Some("vmacu"), Some("vrndn"), Some("vmacq"),
    /* 0c */ Some("vmadl"), Some("vmadm"), Some("vmadn"), Some("vmadh"),
    /* 10 */ Some("vadd"),  Some("vsub"),  None,          Some("vabs"),
    /* 14 */ Some("vaddc"), Some("vsubc"), None,          None,
    /* 18 */ None,          None,          None,          None,
    /* 1c */ None,          Some("vsar"),  None,          None,
    /* 20 */ Some("vlt"),   Some("veq"),   Some("vne"),   Some("vge"),
    /* 24 */ Some("vcl"),   Some("vch"),   Some("vcr"),   Some("vmrg"),
    /* 28 */ Some("vand"),  Some("vnand"), Some("vor"),   Some("vnor"),
    /* 2c */ Some("vxor"),  Some("vnxor"), None,          None,
    /* 30 */ Some("vrcp"),  Some("vrcpl"), Some("vrcph"), Some("vmov"),
    /* 34 */ Some("vrsq"),  Some("vrsql"), Some("vrsqh"), Some("vnop"),
    /* 38 */ None,          None,          None,          None,
    /* 3c */ None,          None,          None,          None,
];

/// LWC2/SWC2 vector load/store sub-ops (rd field, bits 15:11).
const VECTOR_LOAD: [Option<&str>; 32] = [
    Some("lbv"), Some("lsv"), Some("llv"), Some("ldv"),
    Some("lqv"), Some("lrv"), Some("lpv"), Some("luv"),
    Some("lhv"), Some("lfv"), None,        Some("ltv"),
    None, None, None, None, None, None, None, None,
    None, None, None, None, None, None, None, None,
    None, None, None, None,
];
const VECTOR_STORE: [Option<&str>; 32] = [
    Some("sbv"), Some("ssv"), Some("slv"), Some("sdv"),
    Some("sqv"), Some("srv"), Some("spv"), Some("suv"),
    Some("shv"), Some("sfv"), None,        Some("stv"),
    None, None, None, None, None, None, None, None,
    None, None, None, None, None, None, None, None,
    None, None, None, None,
];

/// SPECIAL (opcode 0) funct table — MIPS-I scalar.
fn special(funct: u32, word: u32) -> Option<(&'static str, String)> {
    let rs = (word >> 21) & 31;
    let rt = (word >> 16) & 31;
    let rd = (word >> 11) & 31;
    let sa = (word >> 6) & 31;
    let (name, ops) = match funct {
        0x00 => ("sll", format!("{}, {}, {}", gpr(rd), gpr(rt), sa)),
        0x02 => ("srl", format!("{}, {}, {}", gpr(rd), gpr(rt), sa)),
        0x03 => ("sra", format!("{}, {}, {}", gpr(rd), gpr(rt), sa)),
        0x04 => ("sllv", format!("{}, {}, {}", gpr(rd), gpr(rt), gpr(rs))),
        0x06 => ("srlv", format!("{}, {}, {}", gpr(rd), gpr(rt), gpr(rs))),
        0x07 => ("srav", format!("{}, {}, {}", gpr(rd), gpr(rt), gpr(rs))),
        0x08 => ("jr", gpr(rs)),
        0x09 => ("jalr", format!("{}, {}", gpr(rd), gpr(rs))),
        0x0c => ("syscall", String::new()),
        0x0d => ("break", String::new()),
        0x10 => ("mfhi", gpr(rd)),
        0x11 => ("mthi", gpr(rs)),
        0x12 => ("mflo", gpr(rd)),
        0x13 => ("mtlo", gpr(rs)),
        0x18 => ("mult", format!("{}, {}", gpr(rs), gpr(rt))),
        0x19 => ("multu", format!("{}, {}", gpr(rs), gpr(rt))),
        0x1a => ("div", format!("{}, {}", gpr(rs), gpr(rt))),
        0x1b => ("divu", format!("{}, {}", gpr(rs), gpr(rt))),
        0x20 => ("add", format!("{}, {}, {}", gpr(rd), gpr(rs), gpr(rt))),
        0x21 => ("addu", format!("{}, {}, {}", gpr(rd), gpr(rs), gpr(rt))),
        0x22 => ("sub", format!("{}, {}, {}", gpr(rd), gpr(rs), gpr(rt))),
        0x23 => ("subu", format!("{}, {}, {}", gpr(rd), gpr(rs), gpr(rt))),
        0x24 => ("and", format!("{}, {}, {}", gpr(rd), gpr(rs), gpr(rt))),
        0x25 => ("or", format!("{}, {}, {}", gpr(rd), gpr(rs), gpr(rt))),
        0x26 => ("xor", format!("{}, {}, {}", gpr(rd), gpr(rs), gpr(rt))),
        0x27 => ("nor", format!("{}, {}, {}", gpr(rd), gpr(rs), gpr(rt))),
        0x2a => ("slt", format!("{}, {}, {}", gpr(rd), gpr(rs), gpr(rt))),
        0x2b => ("sltu", format!("{}, {}, {}", gpr(rd), gpr(rs), gpr(rt))),
        _ => return None,
    };
    Some((name, ops))
}

/// REGIMM (opcode 1) rt-field table.
fn regimm(rt: u32, word: u32) -> Option<(&'static str, String)> {
    let rs = (word >> 21) & 31;
    let imm = (word & 0xffff) as i16;
    let name = match rt {
        0x00 => "bltz",
        0x01 => "bgez",
        0x10 => "bltzal",
        0x11 => "bgezal",
        _ => return None,
    };
    Some((name, format!("{}, . + 4 + ({:#x} << 2)", gpr(rs), imm)))
}

/// Decode one big-endian RSP instruction word.
pub fn decode(word: u32, address: u64) -> RspInsn {
    let opcode = word >> 26;
    let rs = (word >> 21) & 31;
    let rt = (word >> 16) & 31;
    let rd = (word >> 11) & 31;
    let imm = (word & 0xffff) as i16;
    let target = word & 0x03ff_ffff;

    let (mnemonic, operands): (String, String) = match opcode {
        0x00 => {
            let (n, o) = special(word & 0x3f, word)
                .map(|(n, o)| (n.to_string(), o))
                .unwrap_or_else(|| (".word".into(), format!("{word:#010x}")));
            // Pseudo: sll $0,$0,0 -> nop; or/addu/daddu $d,$s,$0 -> move.
            if word == 0 { ("nop".into(), String::new()) }
            else if n == "or" && rt == 0 { ("move".into(), format!("{}, {}", gpr(rd), gpr(rs))) }
            else { (n, o) }
        }
        0x01 => {
            let (n, o) = regimm(rt, word)
                .map(|(n, o)| (n.to_string(), o))
                .unwrap_or_else(|| (".word".into(), format!("{word:#010x}")));
            // Pseudo: bgezal $0 -> bal.
            if n == "bgezal" && rs == 0 { ("bal".into(), format!(". + 4 + ({:#x} << 2)", imm)) }
            else { (n, o) }
        }
        0x02 => ("j".into(), format!("{:#x}", (address & 0xf000_0000) | ((target as u64) << 2))),
        0x03 => ("jal".into(), format!("{:#x}", (address & 0xf000_0000) | ((target as u64) << 2))),
        0x04 => {
            if rs == 0 && rt == 0 { ("b".into(), format!(". + 4 + ({:#x} << 2)", imm)) }
            else if rt == 0 { ("beqz".into(), format!("{}, . + 4 + ({:#x} << 2)", gpr(rs), imm)) }
            else { ("beq".into(), format!("{}, {}, . + 4 + ({:#x} << 2)", gpr(rs), gpr(rt), imm)) }
        }
        0x05 => {
            if rt == 0 { ("bnez".into(), format!("{}, . + 4 + ({:#x} << 2)", gpr(rs), imm)) }
            else { ("bne".into(), format!("{}, {}, . + 4 + ({:#x} << 2)", gpr(rs), gpr(rt), imm)) }
        }
        0x06 => ("blez".into(), format!("{}, . + 4 + ({:#x} << 2)", gpr(rs), imm)),
        0x07 => ("bgtz".into(), format!("{}, . + 4 + ({:#x} << 2)", gpr(rs), imm)),
        0x08 => ("addi".into(), format!("{}, {}, {:#x}", gpr(rt), gpr(rs), imm)),
        0x09 => ("addiu".into(), format!("{}, {}, {:#x}", gpr(rt), gpr(rs), imm)),
        0x0a => ("slti".into(), format!("{}, {}, {:#x}", gpr(rt), gpr(rs), imm)),
        0x0b => ("sltiu".into(), format!("{}, {}, {:#x}", gpr(rt), gpr(rs), imm)),
        0x0c => ("andi".into(), format!("{}, {}, {:#x}", gpr(rt), gpr(rs), imm as u16)),
        0x0d => ("ori".into(), format!("{}, {}, {:#x}", gpr(rt), gpr(rs), imm as u16)),
        0x0e => ("xori".into(), format!("{}, {}, {:#x}", gpr(rt), gpr(rs), imm as u16)),
        0x0f => ("lui".into(), format!("{}, {:#x}", gpr(rt), imm as u16)),
        // COP0: mfc0/mtc0 — RSP's SP/DMA/status registers.
        0x10 => {
            let name = match rs {
                0x00 => "mfc0",
                0x04 => "mtc0",
                _ => "",
            };
            if name.is_empty() {
                (".word".into(), format!("{word:#010x}"))
            } else {
                (name.to_string(), format!("{}, ${}", gpr(rt), rd))
            }
        }
        // COP2: bit25=1 -> vector op; bit25=0 -> mfc2/mtc2/cfc2/ctc2.
        0x12 => {
            if rs & 0x10 != 0 {
                // Vector op: e(24:21) vt(20:16) vs(15:11) vd(10:6) funct(5:0)
                let e = (word >> 21) & 0xf;
                let vt = (word >> 16) & 31;
                let vs = (word >> 11) & 31;
                let vd = (word >> 6) & 31;
                let funct = word & 0x3f;
                match VECTOR_FUNCT[funct as usize] {
                    Some(name) => {
                        // vnop is the vector nop: it takes no operands.
                        if name == "vnop" {
                            (name.to_string(), String::new())
                        // vrcp/vrsq family and vmov take vd[e], vt.
                        } else if matches!(name, "vrcp" | "vrcpl" | "vrcph" | "vmov"
                                    | "vrsq" | "vrsql" | "vrsqh") {
                            (name.to_string(), format!("{}[{}], {}", vr(vd), e, vr(vt)))
                        } else {
                            (name.to_string(),
                             format!("{}, {}, {}", vr(vd), vr(vs), vr(vt)))
                        }
                    }
                    None => (".word".into(), format!("{word:#010x}")),
                }
            } else {
                // mfc2/mtc2/cfc2/ctc2: rs field selects.
                let name = match rs {
                    0x00 => "mfc2",
                    0x02 => "cfc2",
                    0x04 => "mtc2",
                    0x06 => "ctc2",
                    _ => "",
                };
                if name.is_empty() {
                    (".word".into(), format!("{word:#010x}"))
                } else {
                    (name.to_string(), format!("{}, {}", gpr(rt), vr(rd)))
                }
            }
        }
        // LWC2/SWC2: rd field (15:11) is the vector sub-op.
        0x32 | 0x3a => {
            let table = if opcode == 0x32 { &VECTOR_LOAD } else { &VECTOR_STORE };
            match table[rd as usize] {
                Some(name) => {
                    let e = (word >> 7) & 0xf;
                    let off = (word & 0x7f) as i8;
                    (name.to_string(),
                     format!("{}[{}], {:#x}({})", vr(rt), e, off, gpr(rs)))
                }
                None => (".word".into(), format!("{word:#010x}")),
            }
        }
        0x20 => ("lb".into(), format!("{}, {:#x}({})", gpr(rt), imm, gpr(rs))),
        0x21 => ("lh".into(), format!("{}, {:#x}({})", gpr(rt), imm, gpr(rs))),
        0x23 => ("lw".into(), format!("{}, {:#x}({})", gpr(rt), imm, gpr(rs))),
        0x24 => ("lbu".into(), format!("{}, {:#x}({})", gpr(rt), imm, gpr(rs))),
        0x25 => ("lhu".into(), format!("{}, {:#x}({})", gpr(rt), imm, gpr(rs))),
        0x28 => ("sb".into(), format!("{}, {:#x}({})", gpr(rt), imm, gpr(rs))),
        0x29 => ("sh".into(), format!("{}, {:#x}({})", gpr(rt), imm, gpr(rs))),
        0x2b => ("sw".into(), format!("{}, {:#x}({})", gpr(rt), imm, gpr(rs))),
        0x33 => ("pref".into(), format!("{}, {:#x}({})", gpr(rt), imm, gpr(rs))),
        _ => (".word".into(), format!("{word:#010x}")),
    };
    RspInsn { address, word, mnemonic, operands }
}

/// Disassemble `count` big-endian words from `bytes` at `vaddr`.
pub fn disassemble(bytes: &[u8], vaddr: u64, count: usize) -> Vec<RspInsn> {
    (0..count)
        .filter_map(|i| {
            let off = i * 4;
            let word = u32::from_be_bytes(
                bytes.get(off..off + 4)?.try_into().ok()?,
            );
            Some(decode(word, vaddr + off as u64))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vector_ops_decode() {
        // vmulf $v4, $v5, $v6 — verified against rabbitizer.
        let ins = decode(0x4a062900, 0x80000000);
        assert_eq!(ins.mnemonic, "vmulf");
        assert_eq!(ins.operands, "$v4, $v5, $v6");
    }

    #[test]
    fn vector_load_decode() {
        // lqv $v2[0], 0x0($1) — LWC2 rd=4.
        let ins = decode(0xc8222000, 0x80000000);
        assert_eq!(ins.mnemonic, "lqv");
    }

    #[test]
    fn scalar_addu() {
        let ins = decode(0x00a62021, 0x80000000); // addu $4,$5,$6
        assert_eq!(ins.mnemonic, "addu");
        assert_eq!(ins.operands, "$4, $5, $6");
    }

    #[test]
    fn invalid_is_word() {
        let ins = decode(0x4a021912, 0x80000000); // funct 0x12 invalid
        assert_eq!(ins.mnemonic, ".word");
    }
}
