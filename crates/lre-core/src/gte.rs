//! PSX R3000 COP2 — the GTE (Geometry Transformation Engine).
//! Command table verified against rabbitizer's R3000GTE decoder.
//!
//! Encoding: opcode 0x12 (cop2), bit25=1 selects a GTE command;
//! the command number is bits 0:5. Flag fields:
//!   sf = bit19 (shift fraction), lm = bit10 (lower matrix? — actually
//!   "load to IR0" / saturation flag), and for mvmva:
//!   mx=(17,18) matrix, v=(15,16) vector, cv=(13,14) control-vector.
//! mfc2/mtc2/cfc2/ctc2/lwc2/swc2 use the standard COP2 register forms.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GteInsn {
    pub address: u64,
    pub word: u32,
    pub mnemonic: String,
    pub operands: String,
}

fn gpr(n: u32) -> String { format!("${n}") }

/// GTE command table (bits 0:5 of a cop2 word with bit25=1).
/// Verified against rabbitizer R3000GTE.
fn gte_cmd(cmd: u32) -> Option<&'static str> {
    Some(match cmd {
        0x01 => "rtps",  0x06 => "nclip", 0x0c => "op",
        0x10 => "dpcs",  0x11 => "intpl", 0x12 => "mvmva",
        0x13 => "ncds",  0x14 => "cdp",   0x16 => "ncdt",
        0x1b => "nccs",  0x1c => "cc",    0x1e => "ncs",
        0x20 => "nct",   0x28 => "sqr",   0x29 => "dpcl",
        0x2a => "dpct",  0x2d => "avsz3", 0x2e => "avsz4",
        0x30 => "rtpt",  0x3d => "gpf",   0x3e => "gpl",
        0x3f => "ncct",
        _ => return None,
    })
}

/// Decode one PSX GTE/COP2 instruction word (little-endian host order).
pub fn decode(word: u32, address: u64) -> GteInsn {
    let opcode = word >> 26;
    let rs = (word >> 21) & 31;
    let rt = (word >> 16) & 31;
    let rd = (word >> 11) & 31;
    let imm = (word & 0xffff) as i16;

    let (mnemonic, operands): (String, String) = match opcode {
        // lwc2/swc2: rt is the GTE data register.
        0x32 => ("lwc2".into(), format!("{}, {:#x}({})", gpr(rt), imm, gpr(rs))),
        0x3a => ("swc2".into(), format!("{}, {:#x}({})", gpr(rt), imm, gpr(rs))),
        0x12 if rs & 0x10 == 0 => {
            match rs {
                0x00 => ("mfc2".into(), format!("{}, {}", gpr(rt), gpr(rd))),
                0x02 => ("cfc2".into(), format!("{}, {}", gpr(rt), gpr(rd))),
                0x04 => ("mtc2".into(), format!("{}, {}", gpr(rt), gpr(rd))),
                0x06 => ("ctc2".into(), format!("{}, {}", gpr(rt), gpr(rd))),
                _ => (".word".into(), format!("{word:#010x}")),
            }
        }
        0x12 => {
            let cmd = word & 0x3f;
            match gte_cmd(cmd) {
                Some("mvmva") => {
                    let mx = (word >> 17) & 3;
                    let v = (word >> 15) & 3;
                    let cv = (word >> 13) & 3;
                    let lm = (word >> 10) & 1;
                    let sf = (word >> 19) & 1;
                    ("mvmva".into(),
                     format!("{}, {}, {}, {}, {}", mx, v, cv, lm, sf))
                }
                Some(name @ ("op" | "sqr" | "gpf" | "gpl")) => {
                    // These take an sf flag operand.
                    let sf = (word >> 19) & 1;
                    (name.into(), format!("{}", sf))
                }
                Some(name) => (name.into(), String::new()),
                None => (".word".into(), format!("{word:#010x}")),
            }
        }
        _ => (".word".into(), format!("{word:#010x}")),
    };
    GteInsn { address, word, mnemonic, operands }
}

/// Disassemble `count` little-endian words from `bytes` at `vaddr`.
pub fn disassemble(bytes: &[u8], vaddr: u64, count: usize) -> Vec<GteInsn> {
    (0..count)
        .filter_map(|i| {
            let off = i * 4;
            let word = u32::from_le_bytes(
                bytes.get(off..off + 4)?.try_into().ok()?,
            );
            Some(decode(word, vaddr + off as u64))
        })
        .collect()
}
