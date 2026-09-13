//! PS2 Emotion Engine COP2 — the VU macro-mode instruction set.
//! Tables transcribed from Ghidra's `languages/ps2/vuupper.sinc` +
//! `cop2.sinc` (vendored ground truth); operand order verified against
//! rabbitizer's R5900 decoder on real PS2 game code.
//!
//! Encoding (inside opcode 0x12 = COP2; bit25=1 selects vector ops):
//!   vufd=(6,10) vufs=(11,15) vuft=(16,20) vudest=(21,24)
//!   vubc=(0,1) vufsf=(21,22) vuftf=(23,24)
//!   vuit=(16,20) vuis=(11,15) vuid=(6,10) vuimm5=(6,10) signed
//!   funct6 = bits 0:5, funct11 = bits 0:10.
//! lqc2/sqc2 are top-level opcodes 0x36/0x3e, not COP2.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VuInsn {
    pub address: u64,
    pub word: u32,
    pub mnemonic: String,
    pub operands: String,
}

fn vf(n: u32) -> String { format!("$vf{n}") }
fn vi(n: u32) -> String { format!("$vi{n}") }
fn gpr(n: u32) -> String { format!("${n}") }

fn dest_suffix(d: u32) -> &'static str {
    match d & 0xf {
        0x0 => "", 0x1 => ".w", 0x2 => ".z", 0x3 => ".zw",
        0x4 => ".y", 0x5 => ".yw", 0x6 => ".yz", 0x7 => ".yzw",
        0x8 => ".x", 0x9 => ".xw", 0xa => ".xz", 0xb => ".xzw",
        0xc => ".xy", 0xd => ".xyw", 0xe => ".xyz", _ => ".xyzw",
    }
}
fn elem(e: u32) -> &'static str {
    match e & 3 { 0 => "x", 1 => "y", 2 => "z", _ => "w" }
}

/// funct11 specials — exact vuop_0_10 values from vuupper.sinc.
/// Returns (mnemonic-base, operand-kind).
fn special(f: u32) -> Option<(&'static str, u8)> {
    Some(match f {
        0x1fd => ("vabs", 1),   0x2bc => ("vadda", 2),
        0x23e => ("vaddai", 3), 0x23c => ("vaddaq", 4),
        0x1ff => ("vclip", 5),  0x3bc => ("vdiv", 6),
        0x17c => ("vftoi0", 1), 0x17d => ("vftoi4", 1),
        0x17e => ("vftoi12", 1), 0x17f => ("vftoi15", 1),
        0x3fe => ("vilwr", 7),  0x3ff => ("viswr", 8),
        0x13c => ("vitof0", 1), 0x13d => ("vitof4", 1),
        0x13e => ("vitof12", 1), 0x13f => ("vitof15", 1),
        0x37e => ("vlqd", 9),   0x37c => ("vlqi", 10),
        0x2bd => ("vmadda", 2), 0x23f => ("vmaddai", 3),
        0x23d => ("vmaddaq", 4),
        0x3fd => ("vmfir", 11), 0x33c => ("vmove", 1),
        0x33d => ("vmr32", 1),
        0x2fd => ("vmsuba", 2), 0x27f => ("vmsubai", 3),
        0x27d => ("vmsubaq", 4),
        0x3fc => ("vmtir", 12),
        0x2be => ("vmula", 2),  0x1fe => ("vmulai", 3),
        0x1fc => ("vmulaq", 4),
        0x2ff => ("vnop", 0),   0x2fe => ("vopmula", 2),
        0x43d => ("vrget", 13), 0x43e => ("vrinit", 14),
        0x43c => ("vrnext", 13), 0x3be => ("vrsqrt", 15),
        0x43f => ("vrxor", 14),
        0x37f => ("vsqd", 16),  0x37d => ("vsqi", 17),
        0x3bd => ("vsqrt", 18),
        0x2fc => ("vsuba", 2),  0x27e => ("vsubai", 3),
        0x27c => ("vsubaq", 4),
        0x3bf => ("vwaitq", 0),
        _ => return None,
    })
}

/// funct6 three-operand fp ops.
fn funct6_op(f: u32) -> Option<&'static str> {
    Some(match f {
        0x28 => "vadd", 0x29 => "vmadd", 0x2a => "vmul",
        0x2b => "vmax", 0x2c => "vsub", 0x2d => "vmsub",
        0x2e => "vopmsub", 0x2f => "vmini",
        _ => return None,
    })
}
/// funct6 integer ops (vi registers).
fn funct6_int(f: u32) -> Option<&'static str> {
    Some(match f {
        0x30 => "viadd", 0x31 => "visub", 0x34 => "viand",
        0x35 => "vior",
        _ => return None,
    })
}
fn funct6_iq(f: u32) -> Option<(&'static str, char)> {
    Some(match f {
        0x1c => ("vmulq", 'Q'), 0x1d => ("vmaxi", 'I'),
        0x1e => ("vmuli", 'I'), 0x1f => ("vminii", 'I'),
        0x20 => ("vaddq", 'Q'), 0x21 => ("vmaddq", 'Q'),
        0x22 => ("vaddi", 'I'), 0x23 => ("vmaddi", 'I'),
        0x24 => ("vsubq", 'Q'), 0x25 => ("vmsubq", 'Q'),
        0x26 => ("vsubi", 'I'), 0x27 => ("vmsubi", 'I'),
        _ => return None,
    })
}
/// Broadcast accumulator ops: funct11 = (vuop_2_10 << 2) | bc.
fn bc_acc(f11: u32) -> Option<&'static str> {
    Some(match f11 & !3 {
        0x03c => "vadda", 0x0bc => "vmadda", 0x0fc => "vmsuba",
        0x1bc => "vmula", 0x07c => "vsuba",
        _ => return None,
    })
}
/// Broadcast non-acc ops: funct6 = (op << 2) | bc, op in bits 2:5.
fn bc_op(f6: u32) -> Option<&'static str> {
    Some(match f6 >> 2 {
        0x0 => "vadd", 0x1 => "vsub", 0x2 => "vmadd",
        0x3 => "vmsub", 0x4 => "vmax", 0x5 => "vmini",
        0x6 => "vmul",
        _ => return None,
    })
}

pub fn decode(word: u32, address: u64) -> VuInsn {
    let opcode = word >> 26;
    let rs = (word >> 21) & 31;
    let rt = (word >> 16) & 31;
    let rd = (word >> 11) & 31;
    let imm = (word & 0xffff) as i16;

    let (mnemonic, operands): (String, String) = match opcode {
        // lqc2/sqc2: top-level, rt field is the vf register.
        0x36 => ("lqc2".into(), format!("{}, {:#x}({})", vf(rt), imm, gpr(rs))),
        0x3e => ("sqc2".into(), format!("{}, {:#x}({})", vf(rt), imm, gpr(rs))),
        0x12 if rs & 0x10 == 0 => {
            let ilock = if word & 1 != 0 { ".i" } else { ".ni" };
            match rs {
                0x00 => (format!("mfc2{ilock}"), format!("{}, {}", gpr(rt), vf(rd))),
                0x01 => (format!("qmfc2{ilock}"), format!("{}, {}", gpr(rt), vf(rd))),
                0x02 => (format!("cfc2{ilock}"), format!("{}, {}", gpr(rt), vi(rd))),
                0x04 => (format!("mtc2{ilock}"), format!("{}, {}", gpr(rt), vf(rd))),
                0x05 => (format!("qmtc2{ilock}"), format!("{}, {}", gpr(rt), vf(rd))),
                0x06 => (format!("ctc2{ilock}"), format!("{}, {}", gpr(rt), vi(rd))),
                0x08 => {
                    let name = match rt & 3 {
                        0 => "bc2f", 1 => "bc2t", 2 => "bc2fl", _ => "bc2tl",
                    };
                    (name.into(), format!(". + 4 + ({:#x} << 2)", imm))
                }
                _ => (".word".into(), format!("{word:#010x}")),
            }
        }
        0x12 => {
            let f6 = word & 0x3f;
            let f11 = word & 0x7ff;
            let bc = word & 3;
            let dest = (word >> 21) & 0xf;
            let ft = (word >> 16) & 31;
            let fs = (word >> 11) & 31;
            let fd = (word >> 6) & 31;
            let fsf = (word >> 21) & 3;
            let ftf = (word >> 23) & 3;
            let ds = dest_suffix(dest);

            // vcallms / vcallmsr first (funct6 0x38/0x39, dest=0).
            if f6 == 0x38 && dest == 0 {
                ("vcallms".into(), format!("{:#x}", (word & 0x7fff) * 8))
            } else if f6 == 0x39 && dest == 0 && ft == 0 && fs == 0x1b {
                ("vcallmsr".into(), "$vi27".into())
            } else if let Some((base, kind)) = special(f11) {
                // Whether the mnemonic carries the dest suffix.
                let has_ds = !matches!(kind, 5 | 6 | 12 | 14 | 15 | 18);
                let name = if has_ds { format!("{base}{ds}") } else { base.into() };
                let ops = match kind {
                    0 => String::new(),
                    // ft[dest], fs
                    1 => format!("{}, {}", vf(ft), vf(fs)),
                    // ACC, fs, ft
                    2 => format!("$ACC, {}, {}", vf(fs), vf(ft)),
                    // ACC, fs, I
                    3 => format!("$ACC, {}, I", vf(fs)),
                    // ACC, fs, Q
                    4 => format!("$ACC, {}, Q", vf(fs)),
                    // vclipw: fs, ft[w]
                    5 => return VuInsn { address, word,
                        mnemonic: "vclipw".into(),
                        operands: format!("{}, {}w", vf(fs), vf(ft)) },
                    // vdiv: Q, fs[fsf], ft[ftf]
                    6 => format!("$Q, {}{}, {}{}", vf(fs), elem(fsf), vf(ft), elem(ftf)),
                    // vilwr: vi(ft)[dest], (vi(fs))
                    7 => format!("{}{}, ({})", vi(ft), ds, vi(fs)),
                    // viswr: vi(ft)[dest], (vi(fs))
                    8 => format!("{}{}, ({})", vi(ft), ds, vi(fs)),
                    // vlqd: vf(ft)[dest], (--vi(fs))
                    9 => format!("{}, (--{})", vf(ft), vi(fs)),
                    // vlqi: vf(ft)[dest], (vi(fs)++)
                    10 => format!("{}, ({}++)", vf(ft), vi(fs)),
                    // vmfir: vf(ft)[dest], vi(fs)
                    11 => format!("{}, {}", vf(ft), vi(fs)),
                    // vmtir: vi(ft), fs[fsf]
                    12 => format!("{}, {}{}", vi(ft), vf(fs), elem(fsf)),
                    // vrget/vrnext: vf(ft)[dest], R
                    13 => format!("{}, $R", vf(ft)),
                    // vrinit/vrxor: R, fs[fsf]
                    14 => format!("$R, {}{}", vf(fs), elem(fsf)),
                    // vrsqrt: Q, fs[fsf], ft[ftf]
                    15 => format!("$Q, {}{}, {}{}", vf(fs), elem(fsf), vf(ft), elem(ftf)),
                    // vsqd: fs[dest], (--vi(ft))
                    16 => format!("{}, (--{})", vf(fs), vi(ft)),
                    // vsqi: fs[dest], (vi(ft)++)
                    17 => format!("{}, ({}++)", vf(fs), vi(ft)),
                    // vsqrt: Q, ft[ftf]
                    18 => format!("$Q, {}{}", vf(ft), elem(ftf)),
                    _ => String::new(),
                };
                (name, ops)
            } else if let Some(base) = bc_acc(f11) {
                // vadday.xyzw ACC, fs, ft[bc]
                (format!("{base}{}{}", elem(bc), ds),
                 format!("ACC, {}, {}{}", vf(fs), vf(ft), elem(bc)))
            } else if f6 < 0x1c {
                if let Some(base) = bc_op(f6) {
                    // vaddy.x fd, fs, ft[bc]
                    (format!("{base}{}{}", elem(bc), ds),
                     format!("{}{}, {}, {}{}", vf(fd), "", vf(fs), vf(ft), elem(bc)))
                } else {
                    (".word".into(), format!("{word:#010x}"))
                }
            } else if f6 == 0x32 {
                // viaddi: vi(ft), vi(fs), imm5
                let imm5 = ((word >> 6) & 0x1f) as i32;
                let imm5 = if imm5 & 0x10 != 0 { imm5 - 0x20 } else { imm5 };
                ("viaddi".into(), format!("{}, {}, {}", vi(ft), vi(fs), imm5))
            } else if let Some(name) = funct6_int(f6) {
                (name.into(), format!("{}, {}, {}", vi(fd), vi(fs), vi(ft)))
            } else if let Some(name) = funct6_op(f6) {
                (format!("{name}{ds}"),
                 format!("{}, {}, {}", vf(fd), vf(fs), vf(ft)))
            } else if let Some((name, q)) = funct6_iq(f6) {
                (format!("{name}{ds}"),
                 format!("{}, {}, {}", vf(fd), vf(fs), q))
            } else {
                (".word".into(), format!("{word:#010x}"))
            }
        }
        _ => (".word".into(), format!("{word:#010x}")),
    };
    VuInsn { address, word, mnemonic, operands }
}

/// Disassemble `count` little-endian words from `bytes` at `vaddr`.
pub fn disassemble(bytes: &[u8], vaddr: u64, count: usize) -> Vec<VuInsn> {
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
