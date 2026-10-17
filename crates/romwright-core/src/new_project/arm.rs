//! An ARMv4T/ARMv5TE decoder for generated projects: GNU `as` unified syntax
//! for the assembly units of a GBA repository (`gba.rs`), and the control-flow
//! facts (branch targets, PC-relative literal loads) the NDS plugin derives
//! relocations from.
//!
//! Written from the ARM Architecture Reference Manual encodings (ARMv5TE
//! A32/T16 chapters). Every text this module prints is checked against the
//! retail word by the project's `tools/asm.py` after GNU `as` encoded it, and
//! the encodings it cannot print (or `as` would encode differently) become raw
//! data there, so a wrong spelling here costs readability, not bytes.

use std::fmt::Write as _;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Mode {
    Arm,
    Thumb,
}

/// What an instruction does to the instruction stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flow {
    /// Falls through to the next instruction.
    Next,
    /// Ends the path with no known successor (`bx lr`, `pop {pc}`, `ldr pc, ...`).
    Stop,
    /// Unconditional branch to `target`; the path ends.
    Jump(u32),
    /// Conditional branch to `target`; also falls through.
    CondJump(u32),
    /// `bl`/`blx` to `target`; falls through (the callee returns).
    Call(u32, Mode),
}

/// A word load from a literal pool (`ldr rd, [pc, #off]`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoolLoad {
    /// Address of the loaded word.
    pub address: u32,
    /// The instruction up to the operand: `ldr r0, `.
    pub prefix: String,
    /// The raw operand when no label names the pool word: `[pc, #40]`.
    pub raw: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Insn {
    pub len: u32,
    /// Raw encoding: a halfword, or both halfwords of a Thumb `bl` (first in the high half).
    pub word: u32,
    /// Complete text (no operand for a branch with a `target`, no label for a pool load).
    pub text: String,
    pub flow: Flow,
    pub pool: Option<PoolLoad>,
    /// Instruction set the branch target is entered in (`bx`/`blx` change it, `b`/`bl` keep it).
    pub target_mode: Option<Mode>,
}

pub const REG: [&str; 16] = [
    "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc",
];
const COND: [&str; 16] = ["eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "", "nv"];

fn sext(value: u32, bits: u32) -> i32 {
    ((value << (32 - bits)) as i32) >> (32 - bits)
}

fn reglist(bits: u32, extra: Option<(u32, &str)>) -> String {
    let mut out = String::from("{");
    let mut first = true;
    let mut i = 0;
    while i < 16 {
        if bits & (1 << i) != 0 {
            let mut j = i;
            while j + 1 < 16 && bits & (1 << (j + 1)) != 0 {
                j += 1;
            }
            if !first {
                out.push_str(", ");
            }
            first = false;
            if j >= i + 2 {
                let _ = write!(out, "{}-{}", REG[i as usize], REG[j as usize]);
            } else if j == i + 1 {
                let _ = write!(out, "{}, {}", REG[i as usize], REG[j as usize]);
            } else {
                out.push_str(REG[i as usize]);
            }
            i = j + 1;
        } else {
            i += 1;
        }
    }
    if let Some((flag, name)) = extra
        && flag != 0 {
            if !first {
                out.push_str(", ");
            }
            out.push_str(name);
        }
    out.push('}');
    out
}

fn imm(value: u32) -> String {
    if value < 10 {
        format!("#{value}")
    } else {
        format!("#{value:#x}")
    }
}

// ---------------------------------------------------------------------------
// ARM (A32)
// ---------------------------------------------------------------------------

/// The 8-bit-rotated immediate `as` would pick: the smallest even rotation.
fn arm_imm_text(imm8: u32, rot: u32) -> String {
    let value = imm8.rotate_right(rot * 2);
    for r in 0..16u32 {
        if value.rotate_left(r * 2) < 256 {
            if r == rot {
                return format!("#{}", &imm(value)[1..]);
            }
            break;
        }
    }
    // A rotation `as` would not choose: spell it out.
    format!("#{imm8}, #{}", rot * 2)
}

fn arm_shift(word: u32) -> String {
    let rm = REG[(word & 0xf) as usize];
    let ty = (word >> 5) & 3;
    let name = ["lsl", "lsr", "asr", "ror"][ty as usize];
    if word & 0x10 != 0 {
        return format!("{rm}, {name} {}", REG[((word >> 8) & 0xf) as usize]);
    }
    let amount = (word >> 7) & 0x1f;
    match (ty, amount) {
        (0, 0) => rm.to_string(),
        (3, 0) => format!("{rm}, rrx"),
        (1 | 2, 0) => format!("{rm}, {name} #32"),
        _ => format!("{rm}, {name} #{amount}"),
    }
}

pub fn decode_arm(word: u32, address: u32) -> Option<Insn> {
    let cond_bits = word >> 28;
    let cond = COND[cond_bits as usize];
    let mut insn = Insn { len: 4, word, text: String::new(), flow: Flow::Next, pool: None, target_mode: None };
    let always = cond_bits == 14;
    if cond_bits == 15 {
        // Unconditional space: blx imm, pld.
        if word >> 25 == 0b1111101 {
            let offset = (sext(word & 0xff_ffff, 24) << 2) + (((word >> 24) & 1) << 1) as i32;
            let target = address.wrapping_add(8).wrapping_add(offset as u32);
            insn.text = "blx".into();
            insn.flow = Flow::Call(target, Mode::Thumb);
            insn.target_mode = Some(Mode::Thumb);
            return Some(insn);
        }
        if word & 0xfd70_f000 == 0xf550_f000 {
            // pld [rn, #+-imm12] (immediate) -- the register form is rare
            let rn = REG[((word >> 16) & 0xf) as usize];
            let off = word & 0xfff;
            let sign = if word & 0x0080_0000 != 0 { "" } else { "-" };
            insn.text = if off == 0 && word & 0x0080_0000 != 0 { format!("pld [{rn}]") } else { format!("pld [{rn}, #{sign}{off:#x}]") };
            return Some(insn);
        }
        return None;
    }
    let rd = REG[((word >> 12) & 0xf) as usize];
    let rn = REG[((word >> 16) & 0xf) as usize];
    let rm = REG[(word & 0xf) as usize];
    let rs = REG[((word >> 8) & 0xf) as usize];

    match (word >> 25) & 7 {
        0b000 => {
            if word & 0x0fff_fff0 == 0x012f_ff10 {
                insn.text = format!("bx{cond} {rm}");
                insn.flow = if always { Flow::Stop } else { Flow::Next };
                return Some(insn);
            }
            if word & 0x0fff_fff0 == 0x012f_ff30 {
                insn.text = format!("blx{cond} {rm}");
                return Some(insn);
            }
            if word & 0x0fff_0ff0 == 0x016f_0f10 {
                insn.text = format!("clz{cond} {rd}, {rm}");
                return Some(insn);
            }
            if word & 0x0f90_0ff0 == 0x0100_0050 {
                let op = ["qadd", "qsub", "qdadd", "qdsub"][((word >> 21) & 3) as usize];
                insn.text = format!("{op}{cond} {rd}, {rm}, {rn}");
                return Some(insn);
            }
            if word & 0x0ff0_0070 == 0x0120_0070 {
                insn.text = format!("bkpt {}", imm(((word >> 4) & 0xfff0) | (word & 0xf)));
                return Some(insn);
            }
            // Multiplies and swaps: bit 7 and bit 4 set, bits 6:5 == 00.
            if word & 0x0000_00f0 == 0x90 {
                if word & 0x0fc0_00f0 == 0x0000_0090 && (word & (1 << 21) != 0 || word & 0xf000 == 0) {
                    let s = if word & (1 << 20) != 0 { "s" } else { "" };
                    let rd_m = REG[((word >> 16) & 0xf) as usize];
                    let rn_m = REG[((word >> 12) & 0xf) as usize];
                    insn.text = if word & (1 << 21) != 0 {
                        format!("mla{s}{cond} {rd_m}, {rm}, {rs}, {rn_m}")
                    } else {
                        format!("mul{s}{cond} {rd_m}, {rm}, {rs}")
                    };
                    return Some(insn);
                }
                if word & 0x0f80_00f0 == 0x0080_0090 {
                    let s = if word & (1 << 20) != 0 { "s" } else { "" };
                    let name = ["umull", "umlal", "smull", "smlal"][((word >> 21) & 3) as usize];
                    let hi = REG[((word >> 16) & 0xf) as usize];
                    let lo = REG[((word >> 12) & 0xf) as usize];
                    insn.text = format!("{name}{s}{cond} {lo}, {hi}, {rm}, {rs}");
                    return Some(insn);
                }
                if word & 0x0fb0_0ff0 == 0x0100_0090 {
                    let b = if word & (1 << 22) != 0 { "b" } else { "" };
                    insn.text = format!("swp{b}{cond} {rd}, {rm}, [{rn}]");
                    return Some(insn);
                }
                return None;
            }
            // Halfword/signed/doubleword transfers: bit 7 and bit 4 set, bits 6:5 != 00.
            if word & 0x90 == 0x90 {
                return decode_arm_extra_load_store(word, cond, insn);
            }
            // DSP multiplies (ARMv5E): smlaxy, smlawy, smulwy, smlalxy, smulxy.
            if word & 0x0f90_0090 == 0x0100_0080 {
                let x = if word & 0x20 != 0 { "t" } else { "b" };
                let y = if word & 0x40 != 0 { "t" } else { "b" };
                let rd_m = REG[((word >> 16) & 0xf) as usize];
                let rn_m = REG[((word >> 12) & 0xf) as usize];
                insn.text = match (word >> 21) & 3 {
                    0 => format!("smla{x}{y}{cond} {rd_m}, {rm}, {rs}, {rn_m}"),
                    1 if word & 0x20 == 0 => format!("smlaw{y}{cond} {rd_m}, {rm}, {rs}, {rn_m}"),
                    1 => format!("smulw{y}{cond} {rd_m}, {rm}, {rs}"),
                    2 => format!("smlal{x}{y}{cond} {rn_m}, {rd_m}, {rm}, {rs}"),
                    _ => format!("smul{x}{y}{cond} {rd_m}, {rm}, {rs}"),
                };
                return Some(insn);
            }
            // mrs/msr register forms and data processing.
            if word & 0x0fbf_0fff == 0x010f_0000 {
                let psr = if word & (1 << 22) != 0 { "spsr" } else { "cpsr" };
                insn.text = format!("mrs{cond} {rd}, {psr}");
                return Some(insn);
            }
            if word & 0x0fb0_fff0 == 0x0120_f000 {
                let psr = if word & (1 << 22) != 0 { "spsr" } else { "cpsr" };
                let mask = fields(word);
                insn.text = format!("msr{cond} {psr}_{mask}, {rm}");
                return Some(insn);
            }
            decode_arm_data(word, cond, always, insn, false)
        }
        0b001 => {
            if word & 0x0fb0_f000 == 0x0320_f000 {
                let psr = if word & (1 << 22) != 0 { "spsr" } else { "cpsr" };
                let mask = fields(word);
                insn.text = format!("msr{cond} {psr}_{mask}, {}", arm_imm_text(word & 0xff, (word >> 8) & 0xf));
                return Some(insn);
            }
            // The mask ignores bit 22: movw (0x30) and movt (0x34) are both 0x0300_0000 under it.
            if word & 0x0fb0_0000 == 0x0300_0000 {
                return None; // movw/movt are ARMv6T2
            }
            decode_arm_data(word, cond, always, insn, true)
        }
        0b010 | 0b011 => {
            if word & 0x0e00_0010 == 0x0600_0010 {
                return None; // media instructions
            }
            let reg_offset = word & (1 << 25) != 0;
            let (pre, up, byte, wb, load) = (
                word & (1 << 24) != 0,
                word & (1 << 23) != 0,
                word & (1 << 22) != 0,
                word & (1 << 21) != 0,
                word & (1 << 20) != 0,
            );
            let name = if load { "ldr" } else { "str" };
            let b = if byte { "b" } else { "" };
            let t = if !pre && wb { "t" } else { "" };
            let mnemonic = format!("{name}{b}{t}{cond}");
            let sign = if up { "" } else { "-" };
            if !reg_offset && word & 0x000f_0000 == 0x000f_0000 && pre && !wb && load && !byte {
                let off = word & 0xfff;
                let address_of = if up { address.wrapping_add(8).wrapping_add(off) } else { address.wrapping_add(8).wrapping_sub(off) };
                let raw = if off == 0 && up { "[pc]".to_string() } else { format!("[pc, #{sign}{off:#x}]") };
                insn.text = format!("{mnemonic} {rd}, {raw}");
                insn.pool = Some(PoolLoad { address: address_of, prefix: format!("{mnemonic} {rd}, "), raw });
                if always && ((word >> 12) & 0xf) == 15 {
                    insn.flow = Flow::Stop;
                }
                return Some(insn);
            }
            let operand = if reg_offset {
                if word & (1 << 4) != 0 {
                    return None;
                }
                let inner = format!("{sign}{}", arm_shift(word));
                if pre {
                    format!("[{rn}, {inner}]{}", if wb { "!" } else { "" })
                } else {
                    format!("[{rn}], {inner}")
                }
            } else {
                let off = word & 0xfff;
                if pre {
                    if off == 0 && up {
                        format!("[{rn}]{}", if wb { "!" } else { "" })
                    } else {
                        format!("[{rn}, #{sign}{off:#x}]{}", if wb { "!" } else { "" })
                    }
                } else {
                    format!("[{rn}], #{sign}{off:#x}")
                }
            };
            insn.text = format!("{mnemonic} {rd}, {operand}");
            if load && ((word >> 12) & 0xf) == 15 && always {
                insn.flow = Flow::Stop;
            }
            Some(insn)
        }
        0b100 => {
            let (pre, up, s, wb, load) = (
                word & (1 << 24) != 0,
                word & (1 << 23) != 0,
                word & (1 << 22) != 0,
                word & (1 << 21) != 0,
                word & (1 << 20) != 0,
            );
            let mode = match (pre, up) {
                (false, true) => "ia",
                (true, true) => "ib",
                (false, false) => "da",
                (true, false) => "db",
            };
            let list = word & 0xffff;
            if list == 0 {
                return None;
            }
            let caret = if s { "^" } else { "" };
            let bang = if wb { "!" } else { "" };
            let list_text = reglist(list, None);
            insn.text = format!("{}{mode}{cond} {rn}{bang}, {list_text}{caret}", if load { "ldm" } else { "stm" });
            if load && list & 0x8000 != 0 && always {
                insn.flow = Flow::Stop;
            }
            Some(insn)
        }
        0b101 => {
            let offset = sext(word & 0xff_ffff, 24) << 2;
            let target = address.wrapping_add(8).wrapping_add(offset as u32);
            let link = word & (1 << 24) != 0;
            insn.text = format!("{}{cond}", if link { "bl" } else { "b" });
            insn.target_mode = Some(Mode::Arm);
            insn.flow = if link {
                Flow::Call(target, Mode::Arm)
            } else if always {
                Flow::Jump(target)
            } else {
                Flow::CondJump(target)
            };
            Some(insn)
        }
        0b110 => {
            // ldc/stc and mcrr/mrrc.
            if word & 0x0fe0_0000 == 0x0c40_0000 {
                let cp = (word >> 8) & 0xf;
                let op = (word >> 4) & 0xf;
                let crm = word & 0xf;
                let name = if word & (1 << 20) != 0 { "mrrc" } else { "mcrr" };
                insn.text = format!("{name}{cond} p{cp}, {op}, {rd}, {rn}, c{crm}");
                return Some(insn);
            }
            let (pre, up, n, wb, load) = (
                word & (1 << 24) != 0,
                word & (1 << 23) != 0,
                word & (1 << 22) != 0,
                word & (1 << 21) != 0,
                word & (1 << 20) != 0,
            );
            let cp = (word >> 8) & 0xf;
            if (9..=11).contains(&cp) {
                return None;
            }
            let crd = (word >> 12) & 0xf;
            let off = (word & 0xff) * 4;
            let name = if load { "ldc" } else { "stc" };
            let l = if n { "l" } else { "" };
            let sign = if up { "" } else { "-" };
            let operand = if pre {
                if off == 0 && up && !wb { format!("[{rn}]") } else { format!("[{rn}, #{sign}{off}]{}", if wb { "!" } else { "" }) }
            } else if wb {
                format!("[{rn}], #{sign}{off}")
            } else {
                return None;
            };
            insn.text = format!("{name}{l}{cond} p{cp}, c{crd}, {operand}");
            Some(insn)
        }
        _ => {
            if word & (1 << 24) != 0 {
                insn.text = format!("svc{cond} {}", imm(word & 0xff_ffff));
                return Some(insn);
            }
            let cp = (word >> 8) & 0xf;
            if (9..=11).contains(&cp) {
                return None; // VFP: `as` re-encodes these as floating-point instructions
            }
            if word & (1 << 4) == 0 {
                let op1 = (word >> 20) & 0xf;
                let crn = (word >> 16) & 0xf;
                let crd = (word >> 12) & 0xf;
                let op2 = (word >> 5) & 7;
                let crm = word & 0xf;
                insn.text = format!("cdp{cond} p{cp}, {op1}, c{crd}, c{crn}, c{crm}, {op2}");
            } else {
                let op1 = (word >> 21) & 7;
                let crn = (word >> 16) & 0xf;
                let rt = REG[((word >> 12) & 0xf) as usize];
                let op2 = (word >> 5) & 7;
                let crm = word & 0xf;
                let name = if word & (1 << 20) != 0 { "mrc" } else { "mcr" };
                insn.text = format!("{name}{cond} p{cp}, {op1}, {rt}, c{crn}, c{crm}, {op2}");
            }
            Some(insn)
        }
    }
}

fn fields(word: u32) -> String {
    let mut out = String::new();
    for (bit, c) in [(16, 'c'), (17, 'x'), (18, 's'), (19, 'f')] {
        if word & (1 << bit) != 0 {
            out.push(c);
        }
    }
    out
}

fn decode_arm_extra_load_store(word: u32, cond: &str, mut insn: Insn) -> Option<Insn> {
    let rd_i = (word >> 12) & 0xf;
    let rd = REG[rd_i as usize];
    let rn_i = (word >> 16) & 0xf;
    let rn = REG[rn_i as usize];
    let (pre, up, imm_form, wb, load) = (
        word & (1 << 24) != 0,
        word & (1 << 23) != 0,
        word & (1 << 22) != 0,
        word & (1 << 21) != 0,
        word & (1 << 20) != 0,
    );
    let sh = (word >> 5) & 3;
    let name = match (load, sh) {
        (false, 1) => "strh",
        (true, 1) => "ldrh",
        (true, 2) => "ldrsb",
        (true, 3) => "ldrsh",
        (false, 2) => "ldrd",
        (false, 3) => "strd",
        _ => return None,
    };
    if !pre && wb {
        return None;
    }
    let sign = if up { "" } else { "-" };
    let mnemonic = format!("{name}{cond}");
    let operand = if imm_form {
        let off = ((word >> 4) & 0xf0) | (word & 0xf);
        if pre {
            if off == 0 && up {
                format!("[{rn}]{}", if wb { "!" } else { "" })
            } else {
                format!("[{rn}, #{sign}{off:#x}]{}", if wb { "!" } else { "" })
            }
        } else {
            format!("[{rn}], #{sign}{off:#x}")
        }
    } else {
        if word & 0xf00 != 0 {
            return None;
        }
        let rm = REG[(word & 0xf) as usize];
        if pre {
            format!("[{rn}, {sign}{rm}]{}", if wb { "!" } else { "" })
        } else {
            format!("[{rn}], {sign}{rm}")
        }
    };
    insn.text = format!("{mnemonic} {rd}, {operand}");
    Some(insn)
}

fn decode_arm_data(word: u32, cond: &str, always: bool, mut insn: Insn, immediate: bool) -> Option<Insn> {
    let opcode = (word >> 21) & 0xf;
    let s = word & (1 << 20) != 0;
    let rd_i = (word >> 12) & 0xf;
    let rd = REG[rd_i as usize];
    let rn = REG[((word >> 16) & 0xf) as usize];
    let names = ["and", "eor", "sub", "rsb", "add", "adc", "sbc", "rsc", "tst", "teq", "cmp", "cmn", "orr", "mov", "bic", "mvn"];
    let test = (8..=11).contains(&opcode);
    if test && !s {
        return None; // misc space handled by the caller
    }
    let operand2 = if immediate { arm_imm_text(word & 0xff, (word >> 8) & 0xf) } else { arm_shift(word) };
    let s_text = if s && !test { "s" } else { "" };
    let name = names[opcode as usize];
    let p = if s && test && rd_i == 15 { "p" } else { "" };
    insn.text = if test {
        if rd_i != 0 && rd_i != 15 {
            return None;
        }
        format!("{name}{cond}{p} {rn}, {operand2}")
    } else if opcode == 13 || opcode == 15 {
        if (word >> 16) & 0xf != 0 {
            return None;
        }
        format!("{name}{s_text}{cond} {rd}, {operand2}")
    } else {
        format!("{name}{s_text}{cond} {rd}, {rn}, {operand2}")
    };
    if !test && rd_i == 15 && always && !s {
        insn.flow = Flow::Stop;
    }
    Some(insn)
}

// ---------------------------------------------------------------------------
// Thumb (T16)
// ---------------------------------------------------------------------------

/// Decodes the Thumb instruction at `address`; `next` is the following halfword (for `bl`).
pub fn decode_thumb(half: u16, next: Option<u16>, address: u32) -> Option<Insn> {
    let h = u32::from(half);
    let mut insn = Insn { len: 2, word: h, text: String::new(), flow: Flow::Next, pool: None, target_mode: None };
    let lo = |shift: u32| REG[((h >> shift) & 7) as usize];
    match h >> 11 {
        0b00000..=0b00010 => {
            let offset = (h >> 6) & 0x1f;
            let (name, offset) = match h >> 11 {
                0 => ("lsls", offset),
                1 => ("lsrs", if offset == 0 { 32 } else { offset }),
                _ => ("asrs", if offset == 0 { 32 } else { offset }),
            };
            insn.text = if h >> 11 == 0 && offset == 0 {
                format!("movs {}, {}", lo(0), lo(3))
            } else {
                format!("{name} {}, {}, #{offset}", lo(0), lo(3))
            };
        }
        0b00011 => {
            let name = if h & (1 << 9) != 0 { "subs" } else { "adds" };
            insn.text = if h & (1 << 10) != 0 {
                format!("{name} {}, {}, #{}", lo(0), lo(3), (h >> 6) & 7)
            } else {
                format!("{name} {}, {}, {}", lo(0), lo(3), lo(6))
            };
        }
        0b00100..=0b00111 => {
            let name = ["movs", "cmps", "adds", "subs"][((h >> 11) & 3) as usize];
            let name = if name == "cmps" { "cmp" } else { name };
            insn.text = format!("{name} {}, {}", lo(8), imm(h & 0xff));
        }
        0b01000 => {
            if h & (1 << 10) == 0 {
                let ops = [
                    "ands", "eors", "lsls", "lsrs", "asrs", "adcs", "sbcs", "rors", "tst", "negs", "cmp", "cmn", "orrs", "muls", "bics", "mvns",
                ];
                let op = ((h >> 6) & 0xf) as usize;
                insn.text = if op == 13 {
                    format!("muls {}, {}, {}", lo(0), lo(3), lo(0))
                } else {
                    format!("{} {}, {}", ops[op], lo(0), lo(3))
                };
            } else {
                let rd = REG[(((h >> 4) & 8) | (h & 7)) as usize];
                let rs = REG[((h >> 3) & 0xf) as usize];
                match (h >> 8) & 3 {
                    0 => {
                        insn.text = format!("add {rd}, {rs}");
                        if ((h >> 4) & 8) | (h & 7) == 15 {
                            insn.flow = Flow::Stop;
                        }
                    }
                    1 => insn.text = format!("cmp {rd}, {rs}"),
                    2 => {
                        insn.text = format!("mov {rd}, {rs}");
                        if ((h >> 4) & 8) | (h & 7) == 15 {
                            insn.flow = Flow::Stop;
                        }
                    }
                    _ => {
                        if h & 7 != 0 {
                            return None;
                        }
                        if h & (1 << 7) != 0 {
                            insn.text = format!("blx {rs}");
                        } else {
                            insn.text = format!("bx {rs}");
                            insn.flow = Flow::Stop;
                        }
                    }
                }
            }
        }
        0b01001 => {
            let target = (address.wrapping_add(4) & !3).wrapping_add((h & 0xff) * 4);
            let raw = format!("[pc, #{:#x}]", (h & 0xff) * 4);
            let rd = lo(8);
            insn.text = format!("ldr {rd}, {raw}");
            insn.pool = Some(PoolLoad { address: target, prefix: format!("ldr {rd}, "), raw });
        }
        0b01010 | 0b01011 => {
            let name = ["str", "strh", "strb", "ldrsb", "ldr", "ldrh", "ldrb", "ldrsh"][((h >> 9) & 7) as usize];
            insn.text = format!("{name} {}, [{}, {}]", lo(0), lo(3), lo(6));
        }
        0b01100..=0b01111 => {
            let byte = h & (1 << 12) != 0;
            let load = h & (1 << 11) != 0;
            let name = match (load, byte) {
                (false, false) => "str",
                (true, false) => "ldr",
                (false, true) => "strb",
                (true, true) => "ldrb",
            };
            let off = ((h >> 6) & 0x1f) * if byte { 1 } else { 4 };
            insn.text = if off == 0 {
                format!("{name} {}, [{}]", lo(0), lo(3))
            } else {
                format!("{name} {}, [{}, #{off:#x}]", lo(0), lo(3))
            };
        }
        0b10000 | 0b10001 => {
            let name = if h & (1 << 11) != 0 { "ldrh" } else { "strh" };
            let off = ((h >> 6) & 0x1f) * 2;
            insn.text = if off == 0 {
                format!("{name} {}, [{}]", lo(0), lo(3))
            } else {
                format!("{name} {}, [{}, #{off:#x}]", lo(0), lo(3))
            };
        }
        0b10010 | 0b10011 => {
            let name = if h & (1 << 11) != 0 { "ldr" } else { "str" };
            let off = (h & 0xff) * 4;
            insn.text = if off == 0 {
                format!("{name} {}, [sp]", lo(8))
            } else {
                format!("{name} {}, [sp, #{off:#x}]", lo(8))
            };
        }
        0b10100 | 0b10101 => {
            let base = if h & (1 << 11) != 0 { "sp" } else { "pc" };
            insn.text = format!("add {}, {base}, #{:#x}", lo(8), (h & 0xff) * 4);
        }
        0b10110 | 0b10111 => {
            if h & 0xff00 == 0xb000 {
                let off = (h & 0x7f) * 4;
                insn.text = format!("{} sp, #{off:#x}", if h & 0x80 != 0 { "sub" } else { "add" });
            } else if h & 0xf600 == 0xb400 {
                let list = reglist(h & 0xff, Some((h & 0x100, if h & (1 << 11) != 0 { "pc" } else { "lr" })));
                if h & 0x1ff == 0 {
                    return None;
                }
                insn.text = format!("{} {list}", if h & (1 << 11) != 0 { "pop" } else { "push" });
                if h & (1 << 11) != 0 && h & 0x100 != 0 {
                    insn.flow = Flow::Stop;
                }
            } else if h & 0xff00 == 0xbe00 {
                insn.text = format!("bkpt {}", imm(h & 0xff));
            } else {
                return None;
            }
        }
        0b11000 | 0b11001 => {
            let load = h & (1 << 11) != 0;
            let rb = lo(8);
            let list_bits = h & 0xff;
            if list_bits == 0 {
                return None;
            }
            let list = reglist(list_bits, None);
            insn.text = if load {
                let bang = if list_bits & (1 << ((h >> 8) & 7)) != 0 { "" } else { "!" };
                format!("ldmia {rb}{bang}, {list}")
            } else {
                format!("stmia {rb}!, {list}")
            };
        }
        0b11010 | 0b11011 => {
            let cond = (h >> 8) & 0xf;
            if cond == 0xe {
                return None;
            }
            if cond == 0xf {
                insn.text = format!("svc {}", imm(h & 0xff));
            } else {
                let target = address.wrapping_add(4).wrapping_add((sext(h & 0xff, 8) << 1) as u32);
                insn.text = format!("b{}", COND[cond as usize]);
                insn.flow = Flow::CondJump(target);
                insn.target_mode = Some(Mode::Thumb);
            }
        }
        0b11100 => {
            let target = address.wrapping_add(4).wrapping_add((sext(h & 0x7ff, 11) << 1) as u32);
            insn.text = "b".into();
            insn.flow = Flow::Jump(target);
            insn.target_mode = Some(Mode::Thumb);
        }
        0b11110 => {
            let second = u32::from(next?);
            let hi = sext(h & 0x7ff, 11);
            let blx = second & 0xf800 == 0xe800;
            if second & 0xf800 != 0xf800 && !blx {
                return None;
            }
            if blx && second & 1 != 0 {
                return None;
            }
            let mut target = address.wrapping_add(4).wrapping_add(((hi << 12) as u32).wrapping_add((second & 0x7ff) << 1));
            insn.len = 4;
            insn.word = (h << 16) | second;
            if blx {
                target &= !3;
                insn.text = "blx".into();
                insn.flow = Flow::Call(target, Mode::Arm);
                insn.target_mode = Some(Mode::Arm);
            } else {
                insn.text = "bl".into();
                insn.flow = Flow::Call(target, Mode::Thumb);
                insn.target_mode = Some(Mode::Thumb);
            }
        }
        _ => return None,
    }
    Some(insn)
}

/// Decodes one instruction from `bytes` (at least the instruction's bytes) at `address`.
pub fn decode(bytes: &[u8], address: u32, mode: Mode) -> Option<Insn> {
    match mode {
        Mode::Arm => {
            let word = u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?);
            decode_arm(word, address)
        }
        Mode::Thumb => {
            let half = u16::from_le_bytes(bytes.get(..2)?.try_into().ok()?);
            let next = bytes.get(2..4).map(|b| u16::from_le_bytes([b[0], b[1]]));
            decode_thumb(half, next, address)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arm(word: u32) -> String {
        decode_arm(word, 0x0800_0000).map(|i| i.text).unwrap_or_else(|| "?".into())
    }

    fn thumb(half: u16) -> String {
        decode_thumb(half, None, 0x0800_0000).map(|i| i.text).unwrap_or_else(|| "?".into())
    }

    #[test]
    fn thumb_prologue_and_return() {
        assert_eq!(thumb(0xb510), "push {r4, lr}");
        assert_eq!(thumb(0xbd10), "pop {r4, pc}");
        assert_eq!(thumb(0x4770), "bx lr");
        assert_eq!(thumb(0x1c08), "adds r0, r1, #0");
        assert_eq!(thumb(0x0008), "movs r0, r1");
        assert_eq!(thumb(0x2001), "movs r0, #1");
        assert_eq!(thumb(0x4802), "ldr r0, [pc, #0x8]");
        assert_eq!(thumb(0xb084), "sub sp, #0x10");
    }

    #[test]
    fn arm_common_forms() {
        assert_eq!(arm(0xe12fff1e), "bx lr");
        assert_eq!(arm(0xe3a00001), "mov r0, #1");
        assert_eq!(arm(0xe92d4010), "stmdb sp!, {r4, lr}");
        assert_eq!(arm(0xe59f0004), "ldr r0, [pc, #0x4]");
        assert_eq!(arm(0xe1a00001), "mov r0, r1");
        assert_eq!(arm(0x0a000001), "beq");
        assert_eq!(arm(0xe1a0f00e), "mov pc, lr");
        assert_eq!(arm(0xe0010092), "mul r1, r2, r0");
    }

    #[test]
    fn thumb_bl_pair_target() {
        let insn = decode_thumb(0xf000, Some(0xf802), 0x0800_0100).unwrap();
        assert_eq!(insn.len, 4);
        assert_eq!(insn.flow, Flow::Call(0x0800_0100 + 4 + 4, Mode::Thumb));
        // Backwards: first half 0xf7ff (hi = -1), second 0xfffe (lo = 0x7fe) = -4 + 4.
        let back = decode_thumb(0xf7ff, Some(0xfffe), 0x0800_0100).unwrap();
        assert_eq!(back.flow, Flow::Call(0x0800_0100, Mode::Thumb), "{back:?}");
    }
}
