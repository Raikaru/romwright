//! Code a Game Boy Advance game keeps in ROM but runs from RAM.
//!
//! A cartridge's code window is slow (gbatek "GBA Memory Control": 16-bit
//! bus, wait states), so games copy hot code into IWRAM/EWRAM, send a
//! multiboot client image over the link cable, or keep code packed and unpack
//! it into a RAM window when a scene starts. The importer sees only the ROM:
//! the bytes at the ROM load address are the *stored* form of code whose
//! absolute pointers (literal pools, function tables) are valid at the *run*
//! address. This module finds those images, from evidence the ROM itself
//! carries, and says where each one runs. It never consults a game's name or
//! a table of known games.
//!
//! Public specs used (no vendor code): gbatek "BIOS Memory Copy" (`CpuSet`
//! SWI 0Bh, `CpuFastSet` SWI 0Ch: r0 source, r1 destination, r2 length and
//! mode), "BIOS Decompression Functions" (`LZ77UnCompWram` SWI 11h,
//! `LZ77UnCompVram` SWI 12h: header word, then flag bytes read MSB first),
//! "GBA Cartridge Header" (logo, fixed byte 96h at B2h, complement check at
//! BDh) and "BIOS Multi Boot Function" (a multiboot image has that header and
//! is loaded at 02000000h), plus the ARMv4T instruction encodings.
//!
//! Five sources of evidence, each with its own soundness check:
//!
//! * **BIOS copy call.** A `CpuSet`/`CpuFastSet` call whose source is a ROM
//!   address and destination a RAM address, both constants the code loaded
//!   in straight-line code before the call. Sound only if the copied bytes
//!   decode as code ([`Coverage`]) from their first word.
//! * **BIOS LZ77 call.** The same, with the stream a valid LZ77 header and
//!   body that expands to exactly its declared size, and the *expanded*
//!   bytes decode as code.
//! * **Embedded multiboot image.** A second cartridge header (the logo
//!   bytes of the real one, the fixed byte, a correct complement check, an
//!   entry branch that stays inside the image) at a non-zero ROM offset:
//!   an image the BIOS would load at 02000000h.
//! * **Resource tables.** An array of `{start, end}` ROM address pairs
//!   whose entries unpack with a codec the ROM carries and whose unpacked
//!   bytes decode as code (the packed overlays of a scene loader).
//! * **Self-addressed code.** An extent of ROM that decodes as code and
//!   whose absolute RAM pointers hit its *own* function entries only under
//!   one run address (`align`), with almost nothing pointing at it by ROM
//!   address. The pointer evidence must beat its runner-up by a margin.
//!
//! Soundness stays with the check that accepts an image; nothing here
//! rewrites the ROM. The caller maps each image at its run address.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

/// Where cartridge ROM sits in the console's address space.
pub(super) const ROM_BASE: u32 = 0x0800_0000;
/// gbatek "Memory Map": EWRAM, 256 KiB at 02000000h.
const EWRAM: (u32, u32) = (0x0200_0000, 0x0204_0000);
/// gbatek "Memory Map": IWRAM, 32 KiB at 03000000h.
const IWRAM: (u32, u32) = (0x0300_0000, 0x0300_8000);
/// A multiboot image runs from the start of EWRAM.
pub(super) const MULTIBOOT_BASE: u32 = EWRAM.0;

const FLAG_THUMB: u8 = 1;
const FLAG_ARM: u8 = 2;
const FLAG_LITERAL: u8 = 4;

fn half(data: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([data[at], data[at + 1]])
}

fn word(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]])
}

/// What the next instruction does to straight-line decoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Flow {
    Next,
    Cond(usize),
    Jump(usize),
    Call(usize),
    Stop,
    Bad,
}

/// One Thumb-1 (ARMv4T) instruction at `at`: its length, flow, and the
/// literal-pool word it loads, if any. A halfword the architecture leaves
/// unallocated on ARMv4T (the `0xB1xx` group, `0xBExx`, `0xDExx`, a lone
/// `bl` half, `blx`) is [`Flow::Bad`].
fn thumb_step(data: &[u8], at: usize) -> (usize, Flow, Option<usize>) {
    let bad = (2, Flow::Bad, None);
    if at + 2 > data.len() {
        return bad;
    }
    let x = half(data, at);
    if x == 0 {
        // `lsls r0, r0, #0`: zero fill, which no compiler emits as code.
        return bad;
    }
    match x >> 11 {
        0x1E => {
            // `bl` is a prefix/suffix pair.
            if at + 4 > data.len() || half(data, at + 2) & 0xF800 != 0xF800 {
                return bad;
            }
            let y = half(data, at + 2);
            let mut off = (i64::from(x & 0x7FF) << 12) | (i64::from(y & 0x7FF) << 1);
            if off & 0x40_0000 != 0 {
                off -= 0x80_0000;
            }
            let target = at as i64 + 4 + off;
            if target < 0 || target as usize >= data.len() {
                return (4, Flow::Bad, None);
            }
            return (4, Flow::Call(target as usize), None);
        }
        0x1D | 0x1F => return bad,
        0x1C => {
            let mut off = i64::from(x & 0x7FF) << 1;
            if off & 0x800 != 0 {
                off -= 0x1000;
            }
            let target = at as i64 + 4 + off;
            if target < 0 || target as usize >= data.len() {
                return bad;
            }
            return (2, Flow::Jump(target as usize), None);
        }
        _ => {}
    }
    match x >> 12 {
        0xD => {
            let condition = (x >> 8) & 0xF;
            if condition == 0xE {
                return bad;
            }
            if condition == 0xF {
                return (2, Flow::Next, None);
            }
            let mut off = i64::from(x & 0xFF) << 1;
            if off & 0x100 != 0 {
                off -= 0x200;
            }
            let target = at as i64 + 4 + off;
            if target < 0 || target as usize >= data.len() {
                return bad;
            }
            return (2, Flow::Cond(target as usize), None);
        }
        0xB => {
            return match x & 0xFF00 {
                0xB000 | 0xB400 | 0xB500 | 0xBC00 => (2, Flow::Next, None),
                0xBD00 => (2, Flow::Stop, None),
                _ => bad,
            };
        }
        _ => {}
    }
    if x & 0xFF00 == 0x4700 {
        // `bx rm`; the high-register form with H1 set is `blx`, ARMv5.
        return if x & 0x80 != 0 { bad } else { (2, Flow::Stop, None) };
    }
    if x & 0xFC00 == 0x4400 {
        let op = (x >> 8) & 3;
        let rd = u32::from(x & 7) | u32::from((x >> 4) & 8);
        if op == 3 {
            return bad;
        }
        if rd == 15 && op != 1 {
            return (2, Flow::Stop, None);
        }
        return (2, Flow::Next, None);
    }
    if x & 0xF800 == 0x4800 {
        let literal = ((at + 4) & !3) + (usize::from(x & 0xFF) << 2);
        return (2, Flow::Next, (literal + 4 <= data.len()).then_some(literal));
    }
    (2, Flow::Next, None)
}

/// One ARM (ARMv4T) instruction at `at`. The undefined space, the
/// coprocessor space, condition `NV`, and the ARMv5 additions (`clz`, `ldrd`,
/// `strd`) are [`Flow::Bad`]: the GBA's ARM7TDMI faults on them.
fn arm_step(data: &[u8], at: usize) -> (usize, Flow, Option<usize>) {
    let bad = (4, Flow::Bad, None);
    if !at.is_multiple_of(4) || at + 4 > data.len() {
        return bad;
    }
    let x = word(data, at);
    let condition = x >> 28;
    if condition == 0xF || x == 0 {
        // Condition NV is undefined on ARMv4T, and `andeq r0, r0, r0` is zero fill.
        return bad;
    }
    let always = condition == 0xE;
    match (x >> 25) & 7 {
        5 => {
            let mut off = i64::from(x & 0x00FF_FFFF) << 2;
            if off & 0x0200_0000 != 0 {
                off -= 0x0400_0000;
            }
            let target = at as i64 + 8 + off;
            if target < 0 || target as usize >= data.len() {
                return bad;
            }
            let target = target as usize;
            return if x & 0x0100_0000 != 0 {
                (4, Flow::Call(target), None)
            } else if always {
                (4, Flow::Jump(target), None)
            } else {
                (4, Flow::Cond(target), None)
            };
        }
        3 if x & 0x10 != 0 => return bad,
        6 | 7 if (x >> 24) & 0xF != 0xF => return bad,
        _ => {}
    }
    if x & 0x0FFF_FFF0 == 0x012F_FF10 {
        return (4, if always { Flow::Stop } else { Flow::Next }, None);
    }
    if x & 0x0FFF_0FF0 == 0x016F_0F10 {
        return bad;
    }
    let register = (x >> 12) & 0xF;
    if (x >> 25) & 7 == 0 && x & 0x90 == 0x90 {
        // Multiply, swap and halfword transfers; ARMv5 `ldrd`/`strd` use the
        // S/H codes 2 and 3 with the load bit clear.
        if x & 0x60 != 0 && x & 0x0010_0000 == 0 && (x >> 5) & 3 >= 2 {
            return bad;
        }
        return (4, Flow::Next, None);
    }
    match (x >> 26) & 3 {
        0 => {
            let op = (x >> 21) & 0xF;
            let test = (8..=11).contains(&op);
            if !test && register == 15 && always {
                return (4, Flow::Stop, None);
            }
        }
        1 => {
            let load = x & 0x0010_0000 != 0;
            if load && register == 15 && always {
                return (4, Flow::Stop, None);
            }
            if load && (x >> 16) & 0xF == 15 && x & 0x0200_0000 == 0 && x & 0x0100_0000 != 0 {
                let up = x & 0x0080_0000 != 0;
                let imm = i64::from(x & 0xFFF);
                let literal = at as i64 + 8 + if up { imm } else { -imm };
                if literal >= 0 && literal as usize + 4 <= data.len() {
                    return (4, Flow::Next, Some(literal as usize));
                }
            }
        }
        2
            // `ldm` with pc in the list returns.
            if x & 0x0200_0000 == 0 && x & 0x0010_0000 != 0 && x & 0x8000 != 0 && always => {
                return (4, Flow::Stop, None);
            }
        _ => {}
    }
    (4, Flow::Next, None)
}

/// What recursive descent decoded over a byte range.
pub(super) struct Coverage {
    /// Per halfword: [`FLAG_THUMB`], [`FLAG_ARM`], [`FLAG_LITERAL`] bits.
    flags: Vec<u8>,
    /// Every entry the descent started from or reached by a call, with its
    /// instruction set (true: ARM).
    pub(super) entries: BTreeMap<usize, bool>,
    /// The entries a direct call reached: code something else in the image
    /// calls, which a bare prologue match does not prove.
    pub(super) called: BTreeMap<usize, bool>,
    /// Returns, `bx` and computed jumps the descent reached: code ends,
    /// zero-filled or random data does not.
    pub(super) stops: usize,
}

impl Coverage {
    /// Halfwords in `[lo, hi)` the descent decoded or claimed as literals.
    pub(super) fn covered_halfwords(&self, lo: usize, hi: usize) -> usize {
        self.flags[lo / 2..(hi / 2).min(self.flags.len())]
            .iter()
            .filter(|&&flag| flag != 0)
            .count()
    }

    fn is_covered(&self, halfword: usize) -> bool {
        self.flags.get(halfword).is_some_and(|&flag| flag != 0)
    }
}

/// Recursive descent from `seeds` (offset, ARM?): follows direct branches and
/// calls inside `data`, stops at a return, an unconditional branch, a
/// computed jump or an undecodable instruction. A `Call` target is an entry.
pub(super) fn descend(data: &[u8], seeds: &[(usize, bool)]) -> Coverage {
    let mut flags = vec![0u8; data.len() / 2];
    let mut entries: BTreeMap<usize, bool> = BTreeMap::new();
    let mut called: BTreeMap<usize, bool> = BTreeMap::new();
    let mut stack: Vec<(usize, bool)> = Vec::new();
    let mut stops = 0usize;
    for &(offset, arm) in seeds {
        if offset < data.len() && offset % if arm { 4 } else { 2 } == 0 {
            entries.insert(offset, arm);
            stack.push((offset, arm));
        }
    }
    while let Some((start, arm)) = stack.pop() {
        let bit = if arm { FLAG_ARM } else { FLAG_THUMB };
        let mut at = start;
        let mut steps = 0usize;
        while at < data.len() && steps < 1 << 20 {
            if flags[at / 2] & bit != 0 {
                break;
            }
            let (length, flow, literal) = if arm { arm_step(data, at) } else { thumb_step(data, at) };
            if flow == Flow::Bad {
                break;
            }
            for flag in &mut flags[at / 2..(at + length) / 2] {
                *flag |= bit;
            }
            if let Some(literal) = literal {
                flags[literal / 2] |= FLAG_LITERAL;
                flags[literal / 2 + 1] |= FLAG_LITERAL;
            }
            steps += 1;
            match flow {
                Flow::Next => at += length,
                Flow::Cond(target) => {
                    stack.push((target, arm));
                    at += length;
                }
                Flow::Jump(target) => {
                    stack.push((target, arm));
                    break;
                }
                Flow::Call(target) => {
                    called.insert(target, arm);
                    if entries.insert(target, arm).is_none() {
                        stack.push((target, arm));
                    }
                    at += length;
                }
                Flow::Stop => {
                    stops += 1;
                    break;
                }
                Flow::Bad => break,
            }
        }
    }
    Coverage { flags, entries, called, stops }
}

/// Offsets that open a function by the compilers' own convention: a Thumb
/// `push {..., lr}` (2-aligned) or an ARM `stmdb sp!, {..., lr}` (4-aligned).
fn prologue_seeds(data: &[u8]) -> Vec<(usize, bool)> {
    let mut seeds = Vec::new();
    for at in (0..data.len().saturating_sub(1)).step_by(2) {
        if half(data, at) & 0xFF00 == 0xB500 {
            seeds.push((at, false));
        }
        if at % 4 == 0 && at + 4 <= data.len() {
            let x = word(data, at);
            if x & 0xFFFF_0000 == 0xE92D_0000 && x & 0x4000 != 0 {
                seeds.push((at, true));
            }
        }
    }
    seeds
}

/// Whether `data` is code from its first instruction on: descent from the
/// start (as ARM, then as Thumb, whichever decodes more) plus every
/// prologue, with the share of the buffer it decoded. `None` when it
/// decodes less than `minimum_ratio` of the buffer or fewer than
/// `minimum_bytes` bytes.
pub(super) struct CodeCheck {
    pub(super) coverage: Coverage,
    pub(super) ratio: f32,
    /// The instruction set the buffer's first instruction decodes in.
    pub(super) start_arm: bool,
}

pub(super) fn code_check(data: &[u8], minimum_ratio: f32, minimum_bytes: usize) -> Option<CodeCheck> {
    if data.len() < 8 {
        return None;
    }
    // The first instruction's set is whichever decodes more of what follows
    // it, with nothing else seeded: a prologue elsewhere in the buffer says
    // nothing about the start.
    let as_arm = descend(data, &[(0, true)]).covered_halfwords(0, data.len());
    let as_thumb = descend(data, &[(0, false)]).covered_halfwords(0, data.len());
    let start_arm = as_arm > as_thumb;
    let mut seeds = prologue_seeds(data);
    seeds.push((0, start_arm));
    let coverage = descend(data, &seeds);
    let covered = coverage.covered_halfwords(0, data.len()) * 2;
    let ratio = covered as f32 / data.len() as f32;
    let started = coverage.flags[0] & if start_arm { FLAG_ARM } else { FLAG_THUMB } != 0;
    (covered >= minimum_bytes && ratio >= minimum_ratio && started && coverage.stops >= 1)
        .then_some(CodeCheck { coverage, ratio, start_arm })
}

/// The run address of byte 0 of a buffer that makes the buffer's own
/// absolute RAM pointers land on its own function entries.
pub(super) struct Alignment {
    /// Run address of the buffer's first byte.
    pub(super) base: u32,
    /// Distinct pointer values that land on an entry of the matching
    /// instruction set under `base`.
    pub(super) hits: usize,
    /// The same count for the best other base.
    pub(super) runner_up: usize,
}

/// Votes for the run address of `data[lo..hi]`'s first byte: each distinct
/// RAM-looking word (02xxxxxxh/03xxxxxxh) at `pointers` that is odd (a Thumb
/// entry) or word-aligned (an ARM entry) names, for each entry of the right
/// set in `entries`, one candidate base; the base with the most distinct
/// pointer values wins. A buffer that was never run at that address has no
/// reason to hold many such words.
pub(super) fn align(
    data: &[u8],
    pointers: std::ops::Range<usize>,
    entries: &BTreeMap<usize, bool>,
    window: std::ops::Range<usize>,
) -> Option<Alignment> {
    let mut values: BTreeSet<u32> = BTreeSet::new();
    let end = pointers.end.min(data.len());
    let mut at = pointers.start.next_multiple_of(4);
    while at + 4 <= end {
        let value = word(data, at);
        if matches!(value >> 24, 2 | 3) {
            values.insert(value);
        }
        at += 4;
    }
    let candidates: Vec<(usize, bool)> = entries.range(window).map(|(&offset, &arm)| (offset, arm)).collect();
    let mut votes: HashMap<u32, HashSet<u32>> = HashMap::new();
    for &value in &values {
        let arm_pointer = value & 3 == 0;
        let thumb_pointer = value & 1 == 1;
        let target = value & !1;
        for &(offset, arm) in &candidates {
            if (arm && !arm_pointer) || (!arm && !thumb_pointer) {
                continue;
            }
            let base = target.wrapping_sub(offset as u32);
            votes.entry(base).or_default().insert(value);
        }
    }
    let mut ranked: Vec<(u32, usize)> = votes.iter().map(|(&base, set)| (base, set.len())).collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let (base, hits) = *ranked.first()?;
    let runner_up = ranked.get(1).map_or(0, |entry| entry.1);
    Some(Alignment { base, hits, runner_up })
}

/// How many distinct RAM-looking words of `data` land on an entry of the
/// matching instruction set when `data[0]` runs at `base`.
pub(super) fn hits_at(data: &[u8], base: u32, entries: &BTreeMap<usize, bool>) -> usize {
    let mut values: BTreeSet<u32> = BTreeSet::new();
    let mut at = 0usize;
    while at + 4 <= data.len() {
        let value = word(data, at);
        if matches!(value >> 24, 2 | 3) {
            values.insert(value);
        }
        at += 4;
    }
    values
        .iter()
        .filter(|&&value| {
            let arm = value & 3 == 0;
            let offset = (value & !1).wrapping_sub(base) as usize;
            (arm || value & 1 == 1) && entries.get(&offset) == Some(&arm)
        })
        .count()
}

// ---- BIOS decompression and the ROM's own packed-resource codecs ----------

/// Largest image that fits the RAM windows a cartridge can run from.
const MAX_IMAGE: usize = 0x4_0000;

/// BIOS `LZ77UnComp` (gbatek "BIOS Decompression Functions"): `stream[0]` is
/// the type byte 10h, then the decompressed size in 24 bits, then blocks of a
/// flag byte (MSB first; a set bit is a 2-byte reference, length
/// `(b0 >> 4) + 3`, displacement `((b0 & 15) << 8 | b1) + 1`) and its eight
/// items. Returns the bytes and the stored length; `None` unless the stream is
/// valid and fills exactly the declared size.
pub(super) fn lz77(stream: &[u8]) -> Option<(Vec<u8>, usize)> {
    if stream.len() < 4 || stream[0] != 0x10 {
        return None;
    }
    let size = u32::from_le_bytes([stream[1], stream[2], stream[3], 0]) as usize;
    if size == 0 || size > MAX_IMAGE {
        return None;
    }
    let mut out: Vec<u8> = Vec::with_capacity(size);
    let mut at = 4usize;
    while out.len() < size {
        let flags = *stream.get(at)?;
        at += 1;
        for bit in 0..8 {
            if out.len() >= size {
                break;
            }
            if flags & (0x80 >> bit) != 0 {
                let first = usize::from(*stream.get(at)?);
                let second = usize::from(*stream.get(at + 1)?);
                at += 2;
                let length = (first >> 4) + 3;
                let displacement = ((first & 0xF) << 8 | second) + 1;
                if displacement > out.len() {
                    return None;
                }
                for _ in 0..length {
                    if out.len() >= size {
                        break;
                    }
                    out.push(out[out.len() - displacement]);
                }
            } else {
                out.push(*stream.get(at)?);
                at += 1;
            }
        }
    }
    Some((out, at))
}

/// The packed-resource codec a scene loader in the ROM implements: a type
/// byte, then a body. Type 1 is an LZSS: a flag byte read MSB first (a set
/// bit is a reference), literals, and references of two bytes (12-bit
/// displacement, 4-bit length; a zero length takes one more byte, plus 16;
/// a zero displacement ends the stream), each copying length + 1 bytes.
/// Type 0 is a bit stream read LSB first from the byte after the type byte:
/// a set bit is a literal byte; a clear bit starts a unary length (2 to 7,
/// or an escape that adds 2 or 7 more bits for 8 to 10 and 11 to 137, zero
/// ending the stream) followed by a distance: a set bit and 5 bits for
/// 1..=32, or a clear bit and a value that is 12 bits wide once 800h bytes
/// have been written beyond 21h and otherwise as wide as that count, plus
/// 21h.
///
/// Both were written from the loader routine's machine code in the ROMs
/// this module was developed against (a bit reader that refills a halfword
/// at a time, which is the same stream as reading the bytes in order), not
/// from any decompression source.
pub(super) fn resource_unpack(stream: &[u8]) -> Option<(Vec<u8>, usize)> {
    match *stream.first()? {
        0 => resource_bit_lz(stream),
        1 => resource_byte_lz(stream),
        _ => None,
    }
}

fn resource_byte_lz(stream: &[u8]) -> Option<(Vec<u8>, usize)> {
    let mut at = 1usize;
    let mut out: Vec<u8> = Vec::new();
    loop {
        let flags = *stream.get(at)?;
        at += 1;
        for index in 0..8 {
            if flags & (0x80 >> index) == 0 {
                out.push(*stream.get(at)?);
                at += 1;
            } else {
                let first = usize::from(*stream.get(at)?);
                let second = usize::from(*stream.get(at + 1)?);
                at += 2;
                let displacement = ((first & 0xF0) << 4) | second;
                let mut length = first & 0xF;
                if length == 0 {
                    if displacement == 0 {
                        return Some((out, at));
                    }
                    length = usize::from(*stream.get(at)?) + 0x10;
                    at += 1;
                }
                if displacement == 0 || displacement > out.len() {
                    return None;
                }
                for _ in 0..=length {
                    out.push(out[out.len() - displacement]);
                }
            }
            if out.len() > MAX_IMAGE {
                return None;
            }
        }
    }
}

struct LsbBits<'a> {
    stream: &'a [u8],
    position: usize,
}

impl LsbBits<'_> {
    fn bit(&mut self) -> Option<u32> {
        let byte = *self.stream.get(self.position >> 3)?;
        let value = u32::from(byte >> (self.position & 7)) & 1;
        self.position += 1;
        Some(value)
    }

    fn bits(&mut self, width: u32) -> Option<u32> {
        let mut value = 0;
        for index in 0..width {
            value |= self.bit()? << index;
        }
        Some(value)
    }
}

fn resource_bit_lz(stream: &[u8]) -> Option<(Vec<u8>, usize)> {
    let mut reader = LsbBits { stream, position: 8 };
    let mut out: Vec<u8> = Vec::new();
    loop {
        if out.len() > MAX_IMAGE {
            return None;
        }
        if reader.bit()? == 1 {
            out.push(reader.bits(8)? as u8);
            continue;
        }
        let length: usize = if reader.bit()? == 0 {
            2
        } else if reader.bit()? == 0 {
            3
        } else if reader.bit()? == 0 {
            4
        } else if reader.bit()? == 0 {
            5
        } else if reader.bit()? == 1 {
            let extra = reader.bits(2)? as usize;
            if extra != 0 {
                extra + 7
            } else {
                let wide = reader.bits(7)? as usize;
                if wide == 0 {
                    return Some((out, reader.position.div_ceil(8)));
                }
                wide + 10
            }
        } else if reader.bit()? == 0 {
            6
        } else {
            7
        };
        let distance = if reader.bit()? == 1 {
            reader.bits(5)? as usize + 1
        } else {
            let produced = out.len() as i64 - 0x21;
            let width = if produced >= 0x800 {
                12
            } else if produced > 0 {
                64 - (produced as u64).leading_zeros()
            } else {
                1
            };
            reader.bits(width)? as usize + 0x21
        };
        if distance > out.len() {
            return None;
        }
        for _ in 0..length {
            out.push(out[out.len() - distance]);
        }
    }
}

/// The encoder behind the resource codec stores each Thumb `bl` pair's
/// operand as the callee's offset from the start of the unpacked buffer
/// (less 2) so repeated calls compress; the loader turns it back into a
/// pc-relative operand. `buffer[o..o + 4]` being a `bl` pair, the stored
/// 22-bit half-word operand is `relative + o + 2`.
pub(super) fn unfilter_calls(buffer: &[u8]) -> Vec<u8> {
    let mut out = buffer.to_vec();
    let mut at = 0usize;
    while at + 4 <= out.len() {
        let first = half(&out, at);
        let second = half(&out, at + 2);
        if first & 0xF800 == 0xF000 && second & 0xF800 == 0xF800 {
            let stored = (u32::from(first & 0x7FF) << 12) | (u32::from(second & 0x7FF) << 1);
            let relative = stored.wrapping_sub(at as u32 + 2) & 0x7F_FFFF;
            let first = 0xF000 | ((relative >> 12) & 0x7FF) as u16;
            let second = 0xF800 | ((relative >> 1) & 0x7FF) as u16;
            out[at..at + 2].copy_from_slice(&first.to_le_bytes());
            out[at + 2..at + 4].copy_from_slice(&second.to_le_bytes());
            at += 4;
        } else {
            at += 2;
        }
    }
    out
}

// ---- straight-line constant propagation, for BIOS call arguments ------------

pub(super) type Registers = [Option<u32>; 16];

/// Registers a Thumb straight-line run `[from, to)` leaves with known values.
/// Any branch forgets everything (a join point could carry another value);
/// a call forgets r0-r3, r12 and lr.
fn thumb_registers(data: &[u8], from: usize, to: usize) -> Registers {
    let mut regs: Registers = [None; 16];
    let mut at = from;
    while at + 2 <= to && at + 2 <= data.len() {
        let x = half(data, at);
        let reg_low = usize::from(x & 7);
        let reg_mid = usize::from((x >> 8) & 7);
        let source = usize::from((x >> 3) & 7);
        if x & 0xF800 == 0xF000 && at + 4 <= data.len() && half(data, at + 2) & 0xF800 == 0xF800 {
            for index in [0, 1, 2, 3, 12, 14] {
                regs[index] = None;
            }
            at += 4;
            continue;
        }
        match x >> 11 {
            0x00..=0x02 => {
                // Shift by immediate.
                let amount = u32::from((x >> 6) & 31);
                regs[reg_low] = regs[source].map(|value| match x >> 11 {
                    0 => value << amount,
                    1 => value.checked_shr(if amount == 0 { 32 } else { amount }).unwrap_or(0),
                    _ => ((value as i32) >> if amount == 0 { 31 } else { amount }) as u32,
                });
            }
            0x03 => {
                // Add/subtract register or 3-bit immediate.
                let operand = if x & 0x0400 != 0 {
                    Some(u32::from((x >> 6) & 7))
                } else {
                    regs[usize::from((x >> 6) & 7)]
                };
                regs[reg_low] = match (regs[source], operand) {
                    (Some(a), Some(b)) => Some(if x & 0x0200 != 0 { a.wrapping_sub(b) } else { a.wrapping_add(b) }),
                    _ => None,
                };
            }
            0x04..=0x07 => {
                let immediate = u32::from(x & 0xFF);
                match (x >> 11) & 3 {
                    0 => regs[reg_mid] = Some(immediate),
                    1 => {}
                    2 => regs[reg_mid] = regs[reg_mid].map(|value| value.wrapping_add(immediate)),
                    _ => regs[reg_mid] = regs[reg_mid].map(|value| value.wrapping_sub(immediate)),
                }
            }
            0x08 if x & 0x0400 == 0 => {
                // ALU operations.
                let operation = (x >> 6) & 0xF;
                let (a, b) = (regs[reg_low], regs[source]);
                regs[reg_low] = match operation {
                    0x0 => a.zip(b).map(|(a, b)| a & b),
                    0x1 => a.zip(b).map(|(a, b)| a ^ b),
                    0x2 => a.zip(b).map(|(a, b)| a.checked_shl(b & 0xFF).unwrap_or(0)),
                    0x3 => a.zip(b).map(|(a, b)| a.checked_shr(b & 0xFF).unwrap_or(0)),
                    0x9 => b.map(|b| 0u32.wrapping_sub(b)),
                    0xC => a.zip(b).map(|(a, b)| a | b),
                    0xE => a.zip(b).map(|(a, b)| a & !b),
                    0xF => b.map(|b| !b),
                    0x8 | 0xA | 0xB => a,
                    _ => None,
                };
            }
            0x08 => {
                // Hi-register operations and `bx`.
                let rd = reg_low | usize::from((x >> 4) & 8);
                let rs = source | usize::from((x >> 3) & 8);
                let read = |index: usize, regs: &Registers| -> Option<u32> {
                    if index == 15 { Some(at as u32 + 4) } else { regs[index] }
                };
                match (x >> 8) & 3 {
                    0 => regs[rd] = read(rd, &regs).zip(read(rs, &regs)).map(|(a, b)| a.wrapping_add(b)),
                    1 => {}
                    2 => regs[rd] = read(rs, &regs),
                    _ => regs = [None; 16],
                }
            }
            0x09 => {
                let literal = ((at + 4) & !3) + (usize::from(x & 0xFF) << 2);
                regs[reg_mid] = (literal + 4 <= data.len()).then(|| word(data, literal));
            }
            0x0A | 0x0B => {
                // Register-offset load/store.
                if (x >> 9) & 7 >= 3 {
                    regs[reg_low] = None;
                }
            }
            0x0C..=0x0F => {
                if x & 0x0800 != 0 {
                    regs[reg_low] = None;
                }
            }
            0x10 | 0x11 => {
                if x & 0x0800 != 0 {
                    regs[reg_low] = None;
                }
            }
            0x12 | 0x13 => {
                if x & 0x0800 != 0 {
                    regs[reg_mid] = None;
                }
            }
            0x14 | 0x15 => {
                // Address of a pc- or sp-relative word.
                let offset = u32::from(x & 0xFF) << 2;
                regs[reg_mid] = if x & 0x0800 == 0 { Some((((at + 4) & !3) as u32).wrapping_add(offset)) } else { None };
            }
            0x16 | 0x17 => {
                match x & 0xFF00 {
                    0xBC00 | 0xBD00 => {
                        for (index, reg) in regs.iter_mut().enumerate().take(8) {
                            if x & (1 << index) != 0 {
                                *reg = None;
                            }
                        }
                        if x & 0x0100 != 0 {
                            regs = [None; 16];
                        }
                    }
                    _ => {}
                }
            }
            0x18 | 0x19 => {
                regs[reg_mid] = None;
                if x & 0x0800 != 0 {
                    for (index, reg) in regs.iter_mut().enumerate().take(8) {
                        if x & (1 << index) != 0 {
                            *reg = None;
                        }
                    }
                }
            }
            0x1A | 0x1B => {
                if x >> 8 == 0xDF {
                    for index in [0, 1, 2, 3] {
                        regs[index] = None;
                    }
                } else {
                    regs = [None; 16];
                }
            }
            0x1C => regs = [None; 16],
            _ => {}
        }
        at += 2;
    }
    regs
}

/// Registers an ARM straight-line run leaves with known values: `ldr rd,
/// [pc, #imm]`, `mov`/`mvn`/`add`/`sub`/`orr` with a rotated immediate or a
/// known register; anything else that writes a register forgets it.
fn arm_registers(data: &[u8], from: usize, to: usize) -> Registers {
    let mut regs: Registers = [None; 16];
    let mut at = from;
    while at + 4 <= to && at + 4 <= data.len() {
        let x = word(data, at);
        let condition = x >> 28;
        let rd = ((x >> 12) & 0xF) as usize;
        let rn = ((x >> 16) & 0xF) as usize;
        match (x >> 25) & 7 {
            5 => regs = [None; 16],
            0 | 1 if x & 0x0FFF_FFF0 == 0x012F_FF10 => regs = [None; 16],
            0 | 1 if !(x & 0x90 == 0x90 && (x >> 25) & 7 == 0) => {
                let operation = (x >> 21) & 0xF;
                let operand = if x & 0x0200_0000 != 0 {
                    Some((x & 0xFF).rotate_right(((x >> 8) & 0xF) * 2))
                } else if x & 0x0FF0 == 0 {
                    regs[(x & 0xF) as usize]
                } else {
                    None
                };
                if (8..=11).contains(&operation) {
                    // Flag-only operations write nothing.
                } else if condition != 0xE {
                    regs[rd] = None;
                } else {
                    regs[rd] = match operation {
                        0xD => operand,
                        0xF => operand.map(|value| !value),
                        0x4 => regs[rn].zip(operand).map(|(a, b)| a.wrapping_add(b)),
                        0x2 => regs[rn].zip(operand).map(|(a, b)| a.wrapping_sub(b)),
                        0xC => regs[rn].zip(operand).map(|(a, b)| a | b),
                        _ => None,
                    };
                }
            }
            2 | 3 => {}
            _ => {}
        }
        if (x >> 26) & 3 == 1 {
            let load = x & 0x0010_0000 != 0;
            if load {
                regs[rd] = None;
                if rn == 15 && x & 0x0200_0000 == 0 && x & 0x0100_0000 != 0 && condition == 0xE {
                    let up = x & 0x0080_0000 != 0;
                    let immediate = i64::from(x & 0xFFF);
                    let literal = at as i64 + 8 + if up { immediate } else { -immediate };
                    if literal >= 0 && literal as usize + 4 <= data.len() {
                        regs[rd] = Some(word(data, literal as usize));
                    }
                }
            }
        } else if (x >> 25) & 7 == 4 && x & 0x0010_0000 != 0 {
            for (index, reg) in regs.iter_mut().enumerate().take(16) {
                if x & (1 << index) != 0 {
                    *reg = None;
                }
            }
        } else if (x >> 24) & 0xF == 0xF {
            for index in [0, 1, 2, 3] {
                regs[index] = None;
            }
        }
        at += 4;
    }
    regs
}

// ---- finding images ---------------------------------------------------------

/// How an image was found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    /// A BIOS `CpuSet`/`CpuFastSet` call.
    Copy,
    /// A BIOS `LZ77UnComp` call.
    Lz77,
    /// An embedded multiboot image.
    Multiboot,
    /// An entry of a `{start, end}` resource table.
    Resource,
    /// Code whose own pointers fix its run address.
    Aligned,
}

impl Kind {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Copy => "bios-copy",
            Self::Lz77 => "bios-lz77",
            Self::Multiboot => "multiboot",
            Self::Resource => "resource-table",
            Self::Aligned => "self-addressed",
        }
    }
}

/// One image the game runs from RAM.
pub(super) struct Image {
    pub(super) kind: Kind,
    /// File offset of the stored bytes and how many of them there are.
    pub(super) rom_start: usize,
    pub(super) rom_len: usize,
    /// Run address of `bytes[0]`.
    pub(super) run: u32,
    /// The image as the CPU sees it at `run`.
    pub(super) bytes: Vec<u8>,
    /// Function entries decoded inside the image: run address, ARM?
    pub(super) entries: Vec<(u32, bool)>,
    /// The ROM bytes at `rom_start..rom_start + rom_len` are a load image no
    /// code runs from, so the ROM is not code there.
    pub(super) demote: bool,
    /// Further ROM spans holding byte-identical copies of this image (a
    /// cartridge that embeds the same multiboot client twice): load images
    /// too, though only one is placed.
    pub(super) copies: Vec<(usize, usize)>,
    /// Another image runs at an overlapping address: they cannot share one
    /// program's address space.
    pub(super) overlay: bool,
    /// Distinct words elsewhere in the ROM that point into the image's run
    /// window with the right instruction set at an entry.
    pub(super) callers: usize,
    /// Why this image is believed, in a form a diagnostic can print.
    pub(super) evidence: String,
}

fn region_contains(address: u32, length: usize) -> bool {
    let end = u64::from(address) + length as u64;
    [EWRAM, IWRAM]
        .iter()
        .any(|&(lo, hi)| address >= lo && end <= u64::from(hi))
}

/// ROM offset of an address in the cartridge window (mirrors included), if it
/// is inside the image.
fn rom_offset(address: u32, len: usize) -> Option<usize> {
    if !(0x08..=0x0D).contains(&(address >> 24)) {
        return None;
    }
    let offset = (address & 0x01FF_FFFF) as usize;
    (offset < len).then_some(offset)
}

/// Contiguous covered stretches of `coverage`, joined across gaps of up to
/// 512 bytes (literal pools, padding, functions no call reaches): `(lo, hi)`
/// byte offsets, at least 1 KiB long and a quarter decoded.
fn extents(coverage: &Coverage, length: usize) -> Vec<(usize, usize)> {
    let halfwords = length / 2;
    let mut out = Vec::new();
    let mut start: Option<usize> = None;
    let mut last = 0usize;
    for index in 0..=halfwords {
        let covered = index < halfwords && coverage.is_covered(index);
        match (covered, start) {
            (true, None) => {
                start = Some(index);
                last = index;
            }
            (true, Some(_)) => last = index,
            (false, Some(first)) if index - last > 256 || index == halfwords => {
                let (lo, hi) = (first * 2, (last + 1) * 2);
                if hi - lo >= 1024 && coverage.covered_halfwords(lo, hi) * 4 >= (hi - lo) {
                    out.push((lo, hi));
                }
                start = None;
            }
            _ => {}
        }
    }
    out
}

/// Header of a cartridge or a multiboot image at `at`: the logo of the real
/// header, the fixed byte, and a correct complement check (gbatek "GBA
/// Cartridge Header").
fn header_at(rom: &[u8], at: usize) -> bool {
    if at + 0xC0 > rom.len() || rom[at + 3] != 0xEA || rom[at + 4..at + 0xA0] != rom[4..0xA0] || rom[at + 0xB2] != 0x96 {
        return false;
    }
    let sum: u32 = rom[at + 0xA0..at + 0xBD].iter().map(|&byte| u32::from(byte)).sum();
    (0u32.wrapping_sub(sum + 0x19) & 0xFF) as u8 == rom[at + 0xBD]
}

struct Context<'a> {
    rom: &'a [u8],
    coverage: Coverage,
    /// Every distinct RAM-looking word (02xxxxxxh/03xxxxxxh) in the ROM.
    ram_words: BTreeSet<u32>,
    /// Header offsets of embedded multiboot images.
    headers: Vec<usize>,
    images: Vec<Image>,
}

impl Context<'_> {
    fn overlaps_existing(&self, start: usize, end: usize) -> bool {
        self.images
            .iter()
            .any(|image| matches!(image.kind, Kind::Multiboot | Kind::Aligned) && start < image.rom_start + image.rom_len && image.rom_start < end)
    }
}

/// Finds every RAM image `rom` carries. `rom` is the whole cartridge.
pub(super) fn find(rom: &[u8]) -> Vec<Image> {
    if rom.len() < 0x200 || rom.len() > 0x0200_0000 {
        return Vec::new();
    }
    let mut headers = Vec::new();
    for at in (4..rom.len().saturating_sub(0xC0)).step_by(4) {
        if word(rom, at + 4) == word(rom, 4) && header_at(rom, at) {
            headers.push(at);
        }
    }
    let mut seeds = prologue_seeds(rom);
    seeds.push((0, true));
    // Each embedded header's own entry branch starts code.
    seeds.extend(headers.iter().map(|&at| (at, true)));
    let coverage = descend(rom, &seeds);
    let mut ram_words: BTreeSet<u32> = BTreeSet::new();
    for at in (0..rom.len() - 3).step_by(4) {
        let value = word(rom, at);
        if matches!(value >> 24, 2 | 3) {
            ram_words.insert(value);
        }
    }
    let mut context = Context { rom, coverage, ram_words, headers, images: Vec::new() };
    multiboot_images(&mut context);
    aligned_images(&mut context);
    copy_images(&mut context);
    resource_images(&mut context);
    let Context { mut images, ram_words, .. } = context;
    images.sort_by_key(|image| (image.run, image.rom_start, image.bytes.len()));
    let mut kept: Vec<Image> = Vec::new();
    for image in images {
        match kept.iter_mut().find(|other| other.run == image.run && other.bytes == image.bytes) {
            Some(first) => {
                if image.demote {
                    first.copies.push((image.rom_start, image.rom_len));
                }
            }
            None => kept.push(image),
        }
    }
    let mut images = kept;
    // Pointers elsewhere that name an entry of the image's run window: the
    // calls a ROM caller makes into the RAM copy.
    for image in &mut images {
        let entries: HashSet<(u32, bool)> = image.entries.iter().copied().collect();
        image.callers = ram_words
            .iter()
            .filter(|&&value| {
                let arm = value & 1 == 0;
                entries.contains(&(value & !1, arm)) && (arm && value & 3 == 0 || !arm)
            })
            .count();
    }
    let windows: Vec<(u32, u32)> = images.iter().map(|image| (image.run, image.run + image.bytes.len() as u32)).collect();
    for (index, image) in images.iter_mut().enumerate() {
        image.overlay = windows
            .iter()
            .enumerate()
            .any(|(other, &(lo, hi))| other != index && image.run < hi && lo < image.run + image.bytes.len() as u32);
    }
    images
}

/// The entries of `coverage[lo..hi]` something vouches for, as run addresses
/// with `data[lo]` at `run`: a call that reached them, a RAM word in `words`
/// that names them (with the instruction set the word's low bits say), and
/// the start of the image. A bare prologue match is not enough to call
/// something a function.
fn entries_at(
    coverage: &Coverage,
    lo: usize,
    hi: usize,
    run: u32,
    words: impl Iterator<Item = u32>,
) -> Vec<(u32, bool)> {
    let origin = run.wrapping_sub(lo as u32);
    let mut found: BTreeMap<usize, bool> = coverage.called.range(lo..hi).map(|(&offset, &arm)| (offset, arm)).collect();
    if let Some(&arm) = coverage.entries.get(&lo) {
        found.insert(lo, arm);
    }
    for value in words {
        let arm = value & 1 == 0;
        if arm && value & 3 != 0 {
            continue;
        }
        let offset = (value & !1).wrapping_sub(origin) as usize;
        if (lo..hi).contains(&offset) && coverage.entries.get(&offset) == Some(&arm) {
            found.insert(offset, arm);
        }
    }
    found.into_iter().map(|(offset, arm)| (origin.wrapping_add(offset as u32), arm)).collect()
}

/// The RAM-looking words of `data`.
fn ram_words_of(data: &[u8]) -> Vec<u32> {
    (0..data.len().saturating_sub(3))
        .step_by(4)
        .map(|at| word(data, at))
        .filter(|value| matches!(value >> 24, 2 | 3))
        .collect()
}

fn multiboot_images(context: &mut Context<'_>) {
    let rom = context.rom;
    let headers = context.headers.clone();
    for (index, &start) in headers.iter().enumerate() {
        // The entry branch must stay inside the image the BIOS would load.
        let immediate = i64::from(((word(rom, start) & 0x00FF_FFFF) << 8) as i32 >> 8);
        let target = start as i64 + 8 + immediate * 4;
        let limit = headers.get(index + 1).copied().unwrap_or(rom.len()).min(start + MAX_IMAGE).min(rom.len());
        if target < start as i64 || target as usize >= limit {
            continue;
        }
        // The image runs to the last decoded or literal halfword, allowing
        // gaps of up to 512 bytes between code stretches.
        let mut end = start + 0xC0;
        let mut at = end;
        while at < limit {
            if context.coverage.is_covered(at / 2) {
                end = at + 2;
            } else if at - end > 512 {
                break;
            }
            at += 2;
        }
        let end = end.next_multiple_of(4).min(limit);
        // Entry must itself decode.
        if end - start < 0xC4 || !context.coverage.is_covered(target as usize / 2) {
            continue;
        }
        let entries = entries_at(&context.coverage, start, end, MULTIBOOT_BASE, context.ram_words.iter().copied());
        context.images.push(Image {
            kind: Kind::Multiboot,
            rom_start: start,
            rom_len: end - start,
            run: MULTIBOOT_BASE,
            bytes: rom[start..end].to_vec(),
            entries,
            demote: true,
            copies: Vec::new(),
            overlay: false,
            callers: 0,
            evidence: format!(
                "cartridge header with logo, fixed byte and complement check at ROM offset {start:#x}; entry branch to {target:#x}"
            ),
        });
    }
}

fn aligned_images(context: &mut Context<'_>) {
    let rom = context.rom;
    let found = extents(&context.coverage, rom.len());
    // Pointers to a function entry by ROM address, anywhere in the ROM, per
    // extent: code that runs from the ROM is addressed in the ROM.
    let mut rom_pointers: Vec<HashSet<u32>> = vec![HashSet::new(); found.len()];
    for at in (0..rom.len() - 3).step_by(4) {
        let value = word(rom, at);
        let Some(offset) = rom_offset(value, rom.len()) else { continue };
        let arm = value & 1 == 0;
        let index = found.partition_point(|&(_, hi)| hi <= offset);
        if let Some(&(lo, hi)) = found.get(index)
            && offset >= lo && offset < hi && context.coverage.entries.get(&(offset & !1)) == Some(&arm) && (!arm || value & 3 == 0) {
                rom_pointers[index].insert(value);
            }
    }
    for (index, &(lo, hi)) in found.iter().enumerate() {
        if context.overlaps_existing(lo, hi) {
            continue;
        }
        let pointer_range = lo.saturating_sub(0x800)..(hi + 0x800).min(rom.len());
        let Some(alignment) = align(rom, pointer_range, &context.coverage.entries, lo..hi) else {
            continue;
        };
        let run = alignment.base.wrapping_add(lo as u32);
        let rom_hits = rom_pointers[index].len();
        let accepted = alignment.hits >= 8
            && alignment.hits > 2 * alignment.runner_up
            && alignment.hits >= 3 * (rom_hits + 1)
            && run % 2 == 0
            && region_contains(run, hi - lo);
        if !accepted {
            continue;
        }
        let (lo, hi, coverage) = grow(rom, &context.ram_words, alignment.base, lo, hi);
        let run = alignment.base.wrapping_add(lo as u32);
        if !region_contains(run, hi - lo) {
            continue;
        }
        context.images.push(Image {
            kind: Kind::Aligned,
            rom_start: lo,
            rom_len: hi - lo,
            run,
            bytes: rom[lo..hi].to_vec(),
            entries: entries_at(&coverage, lo, hi, run, context.ram_words.iter().copied()),
            demote: true,
            copies: Vec::new(),
            overlay: false,
            callers: 0,
            evidence: format!(
                "{} distinct RAM pointers land on function entries only under run address {run:#x} (next best {}); {rom_hits} ROM pointers name its entries",
                alignment.hits, alignment.runner_up
            ),
        });
    }
}

/// Grows an accepted image over code no prologue or call reached. Every RAM
/// word in the ROM that lands, under `base`, inside 4 KiB around the image
/// is an entry too (a Thumb function table, or the ARM pointer a loader
/// jumps through); descent from those and the prologues around the image can
/// reach past its first and last decoded byte. Returns the new bounds and
/// the coverage of the whole ROM re-run with those seeds.
fn grow(rom: &[u8], ram_words: &BTreeSet<u32>, base: u32, lo: usize, hi: usize) -> (usize, usize, Coverage) {
    const SLACK: usize = 0x1000;
    let mut seeds = prologue_seeds(rom);
    seeds.push((0, true));
    let (mut lo, mut hi) = (lo, hi);
    for _ in 0..3 {
        let window = lo.saturating_sub(SLACK)..(hi + SLACK).min(rom.len());
        for &value in ram_words {
            let offset = (value & !1).wrapping_sub(base) as usize;
            if !window.contains(&offset) {
                continue;
            }
            if value & 1 == 1 {
                seeds.push((offset, false));
            } else if value & 3 == 0 {
                // An ARM pointer is only an entry when what it names runs for
                // a while and returns.
                let probe = descend(rom, &[(offset, true)]);
                if probe.stops >= 1 && probe.covered_halfwords(offset, (offset + 0x200).min(rom.len())) >= 16 {
                    seeds.push((offset, true));
                }
            }
        }
        let coverage = descend(rom, &seeds);
        let found = extents(&coverage, rom.len());
        let (mut new_lo, mut new_hi) = (lo, hi);
        for &(first, last) in &found {
            if first < hi && lo < last {
                new_lo = new_lo.min(first.max(lo.saturating_sub(SLACK)));
                new_hi = new_hi.max(last.min(hi + SLACK));
            }
        }
        if (new_lo, new_hi) == (lo, hi) {
            return (lo, hi, coverage);
        }
        (lo, hi) = (new_lo, new_hi);
    }
    let coverage = descend(rom, &seeds);
    (lo, hi, coverage)
}

/// BIOS calls by SWI number (gbatek "BIOS Function Summary").
const SWI_CPU_SET: u8 = 0x0B;
const SWI_CPU_FAST_SET: u8 = 0x0C;
const SWI_LZ77_WRAM: u8 = 0x11;
const SWI_LZ77_VRAM: u8 = 0x12;

fn is_copy_swi(number: u8) -> bool {
    matches!(number, SWI_CPU_SET | SWI_CPU_FAST_SET | SWI_LZ77_WRAM | SWI_LZ77_VRAM)
}

pub(super) struct BiosCall {
    pub(super) number: u8,
    pub(super) registers: Registers,
}

pub(super) fn bios_calls(rom: &[u8]) -> Vec<BiosCall> {
    let mut thumb_wrappers: HashMap<usize, u8> = HashMap::new();
    let mut arm_wrappers: HashMap<usize, u8> = HashMap::new();
    for at in (0..rom.len().saturating_sub(5)).step_by(2) {
        let x = half(rom, at);
        if x >> 8 == 0xDF && is_copy_swi(x as u8) && half(rom, at + 2) == 0x4770 {
            thumb_wrappers.insert(at, x as u8);
        }
        if at % 4 == 0 && at + 8 <= rom.len() {
            let y = word(rom, at);
            if y & 0xFF00_FFFF == 0xEF00_0000 && is_copy_swi((y >> 16) as u8) && word(rom, at + 4) == 0xE12F_FF1E {
                arm_wrappers.insert(at, (y >> 16) as u8);
            }
        }
    }
    let mut calls = Vec::new();
    for at in (0..rom.len().saturating_sub(3)).step_by(2) {
        let x = half(rom, at);
        if x & 0xF800 == 0xF000 && half(rom, at + 2) & 0xF800 == 0xF800 {
            let (_, flow, _) = thumb_step(rom, at);
            if let Flow::Call(target) = flow
                && let Some(&number) = thumb_wrappers.get(&target) {
                    calls.push(BiosCall { number, registers: thumb_registers(rom, at.saturating_sub(48) & !1, at) });
                }
        } else if x >> 8 == 0xDF && is_copy_swi(x as u8) && half(rom, at + 2) != 0x4770 {
            calls.push(BiosCall { number: x as u8, registers: thumb_registers(rom, at.saturating_sub(48) & !1, at) });
        }
        if at % 4 == 0 && at + 4 <= rom.len() {
            let y = word(rom, at);
            if y >> 24 == 0xEB {
                if let (_, Flow::Call(target), _) = arm_step(rom, at)
                    && let Some(&number) = arm_wrappers.get(&target) {
                        calls.push(BiosCall { number, registers: arm_registers(rom, at.saturating_sub(64), at) });
                    }
            } else if y & 0xFF00_FFFF == 0xEF00_0000 && is_copy_swi((y >> 16) as u8) && word(rom, at + 4) != 0xE12F_FF1E {
                calls.push(BiosCall { number: (y >> 16) as u8, registers: arm_registers(rom, at.saturating_sub(64), at) });
            }
        }
    }
    calls
}

/// Whether the decoded bytes are code, and the entries inside.
fn accept_code(bytes: &[u8]) -> Option<(CodeCheck, f32)> {
    let check = code_check(bytes, 0.3, 128)?;
    let ratio = check.ratio;
    Some((check, ratio))
}

fn copy_images(context: &mut Context<'_>) {
    let rom = context.rom;
    let mut seen: HashSet<(usize, u32, usize, u8)> = HashSet::new();
    for call in bios_calls(rom) {
        let (Some(source), Some(destination)) = (call.registers[0], call.registers[1]) else { continue };
        let Some(source_offset) = rom_offset(source & !3, rom.len()) else { continue };
        match call.number {
            SWI_CPU_SET | SWI_CPU_FAST_SET => {
                let Some(control) = call.registers[2] else { continue };
                if control & 0x0100_0000 != 0 {
                    // Fill mode repeats one word.
                    continue;
                }
                let word_units = call.number == SWI_CPU_FAST_SET || control & 0x0400_0000 != 0;
                let length = (control & 0x1F_FFFF) as usize * if word_units { 4 } else { 2 };
                let destination = destination & !1;
                if !(32..=MAX_IMAGE).contains(&length)
                    || source_offset + length > rom.len()
                    || !region_contains(destination, length)
                    || !seen.insert((source_offset, destination, length, call.number))
                {
                    continue;
                }
                let bytes = &rom[source_offset..source_offset + length];
                let Some((check, ratio)) = accept_code(bytes) else { continue };
                let entries = entries_at(&check.coverage, 0, length, destination, context.ram_words.iter().copied());
                context.images.push(Image {
                    kind: Kind::Copy,
                    rom_start: source_offset,
                    rom_len: length,
                    run: destination,
                    bytes: bytes.to_vec(),
                    entries,
                    demote: false,
                    copies: Vec::new(),
                    overlay: false,
                    callers: 0,
                    evidence: format!(
                        "BIOS {} copies {length:#x} bytes from ROM {:#x} to {destination:#x}; {:.0}% of them decode as {} code",
                        if call.number == SWI_CPU_SET { "CpuSet" } else { "CpuFastSet" },
                        ROM_BASE as usize + source_offset,
                        ratio * 100.0,
                        if check.start_arm { "ARM" } else { "Thumb" },
                    ),
                });
            }
            _ => {
                let Some((bytes, stored)) = lz77(&rom[source_offset..]) else { continue };
                if !region_contains(destination, bytes.len()) || !seen.insert((source_offset, destination, bytes.len(), call.number)) {
                    continue;
                }
                let Some((check, ratio)) = accept_code(&bytes) else { continue };
                let entries = entries_at(&check.coverage, 0, bytes.len(), destination, ram_words_of(&bytes).into_iter());
                context.images.push(Image {
                    kind: Kind::Lz77,
                    rom_start: source_offset,
                    rom_len: stored,
                    run: destination,
                    bytes,
                    entries,
                    demote: false,
                    copies: Vec::new(),
                    overlay: false,
                    callers: 0,
                    evidence: format!(
                        "BIOS LZ77 call unpacks ROM {:#x} to {destination:#x}; {:.0}% of the result decodes as {} code",
                        ROM_BASE as usize + source_offset,
                        ratio * 100.0,
                        if check.start_arm { "ARM" } else { "Thumb" },
                    ),
                });
            }
        }
    }
}

/// Runs of at least 16 strictly ascending ROM addresses in consecutive words:
/// a resource index. Resource `k` is stored in `[table[k], table[k + 1])`.
/// Returns the `(start, end)` file ranges of every resource.
pub(super) fn resource_tables(rom: &[u8]) -> Vec<Vec<(usize, usize)>> {
    let pointer = |at: usize| -> Option<usize> {
        if at + 4 > rom.len() || word(rom, at) >> 24 != 8 {
            return None;
        }
        rom_offset(word(rom, at), rom.len() + 1)
    };
    let mut tables = Vec::new();
    let mut at = 0usize;
    while at + 4 <= rom.len() {
        let Some(first) = pointer(at) else {
            at += 4;
            continue;
        };
        let begin = at;
        let mut run = vec![first];
        at += 4;
        while let Some(next) = pointer(at) {
            let previous = *run.last().unwrap_or(&0);
            if next <= previous || next - previous > MAX_IMAGE {
                break;
            }
            run.push(next);
            at += 4;
        }
        if run.len() >= 16 {
            let mut resources: Vec<(usize, usize)> = run.windows(2).map(|pair| (pair[0], pair[1])).collect();
            // The last resource has no successor to bound it; the codec's
            // own end marker does.
            if let Some(&last) = run.last() {
                resources.push((last, (last + MAX_IMAGE).min(rom.len())));
            }
            tables.push(resources);
        }
        if at == begin {
            at += 4;
        }
    }
    tables
}

fn resource_images(context: &mut Context<'_>) {
    let rom = context.rom;
    struct Candidate {
        offset: usize,
        stored: usize,
        buffer: Vec<u8>,
        check: CodeCheck,
        alignment: Option<Alignment>,
        filtered: bool,
    }
    let mut candidates: Vec<Candidate> = Vec::new();
    let mut seen: HashSet<usize> = HashSet::new();
    for table in resource_tables(rom) {
        for (start, end) in table {
            if !seen.insert(start) || !matches!(rom[start], 0 | 1) {
                continue;
            }
            let Some((raw, stored)) = resource_unpack(&rom[start..end]) else { continue };
            if raw.len() < 64 {
                continue;
            }
            // The call operands are stored absolute; undo that when it makes
            // the buffer decode better.
            let plain = code_check(&raw, 0.25, 64);
            let unfiltered = unfilter_calls(&raw);
            let restored = code_check(&unfiltered, 0.25, 64);
            let (buffer, check, filtered) = match (plain, restored) {
                (Some(a), Some(b)) if a.ratio > b.ratio => (raw, a, false),
                (_, Some(b)) => (unfiltered, b, true),
                (Some(a), None) => (raw, a, false),
                (None, None) => continue,
            };
            let alignment = align(&buffer, 0..buffer.len(), &check.coverage.entries, 0..buffer.len());
            candidates.push(Candidate { offset: start, stored, buffer, check, alignment, filtered });
        }
    }
    // A scene loader unpacks every code resource into the same window: the
    // run address most candidates vote for is shared evidence none of them
    // has alone.
    let mut tally: HashMap<u32, usize> = HashMap::new();
    for candidate in &candidates {
        if let Some(alignment) = &candidate.alignment
            && alignment.hits >= 2 && alignment.hits > alignment.runner_up {
                *tally.entry(alignment.base).or_default() += 1;
            }
    }
    let consensus = tally.iter().max_by_key(|&(&base, &count)| (count, base)).map(|(&base, &count)| (base, count));
    for candidate in candidates {
        let Some(alignment) = &candidate.alignment else { continue };
        // A small overlay can tie between two bases, or have only a pointer
        // or two; the shared run address settles it when a pointer lands on
        // an entry under it and the overlay's own best base has at most four
        // times as many. The overlay already unpacked to code.
        let shared_base = consensus.filter(|&(_, count)| count >= 3).map(|(base, _)| base);
        let shared_hits = shared_base.map_or(0, |base| {
            hits_at(&candidate.buffer, base, &candidate.check.coverage.entries)
        });
        let shared = shared_base.is_some() && shared_hits >= 1 && 4 * shared_hits >= alignment.hits;
        let alone = alignment.hits >= 8 && alignment.hits > 2 * alignment.runner_up;
        let run = if shared { shared_base.unwrap_or(alignment.base) } else { alignment.base };
        if !(shared || alone) || !region_contains(run, candidate.buffer.len()) || run % 2 != 0 {
            continue;
        }
        context.images.push(Image {
            kind: Kind::Resource,
            rom_start: candidate.offset,
            rom_len: candidate.stored,
            run,
            entries: entries_at(&candidate.check.coverage, 0, candidate.buffer.len(), run, ram_words_of(&candidate.buffer).into_iter()),
            bytes: candidate.buffer,
            demote: false,
            copies: Vec::new(),
            overlay: false,
            callers: 0,
            evidence: format!(
                "resource table entry at ROM {:#x} unpacks to code ({:.0}% decoded{}); {} pointers land on its entries at {run:#x}{}",
                ROM_BASE as usize + candidate.offset,
                candidate.check.ratio * 100.0,
                if candidate.filtered { ", call operands restored" } else { "" },
                if shared { shared_hits } else { alignment.hits },
                if shared { format!(", the run address {} resources share", consensus.map_or(0, |c| c.1)) } else { String::new() },
            ),
        });
    }
}

/// Synthetic ROMs for the tests here and in the loader: Thumb code written
/// out halfword by halfword, never bytes of any game.
#[cfg(test)]
pub(super) mod fixture {
    use super::{half, unfilter_calls};

    pub(crate) fn put_half(rom: &mut [u8], at: usize, value: u16) {
        rom[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }

    pub(crate) fn put_word(rom: &mut [u8], at: usize, value: u32) {
        rom[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    /// The two halfwords of a Thumb `bl` at `from` to `to`.
    pub(crate) fn bl(from: usize, to: usize) -> [u16; 2] {
        let offset = (to as i64 - (from as i64 + 4)) >> 1;
        [0xF000 | ((offset >> 11) & 0x7FF) as u16, 0xF800 | (offset & 0x7FF) as u16]
    }

    /// `functions` Thumb functions (push, two moves, an add, a call to the
    /// next one, pop, then a varying run of no-ops so the entries are spaced
    /// irregularly), then one word per function: its entry as a Thumb pointer
    /// for a blob run at `run`.
    pub(crate) fn code_blob(run: u32, functions: usize) -> Vec<u8> {
        let sizes: Vec<usize> = (0..functions).map(blob_size).collect();
        let total: usize = sizes.iter().sum();
        let mut blob = vec![0u8; total + functions * 4];
        let mut at = 0usize;
        for (index, &size) in sizes.iter().enumerate().take(functions) {
            put_half(&mut blob, at, 0xB510);
            put_half(&mut blob, at + 2, 0x2001);
            put_half(&mut blob, at + 4, 0x2102);
            put_half(&mut blob, at + 6, 0x1840);
            if index + 1 < functions {
                let [first, second] = bl(at + 8, at + size);
                put_half(&mut blob, at + 8, first);
                put_half(&mut blob, at + 10, second);
            } else {
                put_half(&mut blob, at + 8, 0x2000);
                put_half(&mut blob, at + 10, 0x2000);
            }
            put_half(&mut blob, at + 12, 0xBD10);
            for pad in (at + 14..at + size).step_by(2) {
                put_half(&mut blob, pad, 0x46C0);
            }
            put_word(&mut blob, total + index * 4, run + at as u32 + 1);
            at += size;
        }
        blob
    }

    /// Function `index` of a blob: 16 bytes of code and 0 to 12 of no-ops.
    pub(crate) fn blob_size(index: usize) -> usize {
        16 + 4 * (((index as u64 + 1).wrapping_mul(2_654_435_761) >> 7) % 4) as usize
    }

    /// The offsets `code_blob` puts its functions at.
    pub(crate) fn blob_entries(functions: usize) -> Vec<usize> {
        let mut at = 0usize;
        (0..functions)
            .map(|index| {
                let entry = at;
                at += blob_size(index);
                entry
            })
            .collect()
    }

    /// The inverse of `unfilter_calls`: each `bl` operand stored as the
    /// callee's offset (less 2) from the start of the buffer.
    pub(crate) fn filter_calls(buffer: &[u8]) -> Vec<u8> {
        let mut out = buffer.to_vec();
        let mut at = 0usize;
        while at + 4 <= out.len() {
            let first = half(&out, at);
            let second = half(&out, at + 2);
            if first & 0xF800 == 0xF000 && second & 0xF800 == 0xF800 {
                let relative = (u32::from(first & 0x7FF) << 12) | (u32::from(second & 0x7FF) << 1);
                let stored = relative.wrapping_add(at as u32 + 2) & 0x7F_FFFF;
                put_half(&mut out, at, 0xF000 | ((stored >> 12) & 0x7FF) as u16);
                put_half(&mut out, at + 2, 0xF800 | ((stored >> 1) & 0x7FF) as u16);
                at += 4;
            } else {
                at += 2;
            }
        }
        debug_assert_eq!(unfilter_calls(&out), buffer);
        out
    }

    /// Packs `bytes` with the type 1 resource codec, literals only.
    pub(crate) fn pack_byte_lz(bytes: &[u8]) -> Vec<u8> {
        let mut out = vec![1u8];
        let mut chunks = bytes.chunks(8).peekable();
        while let Some(chunk) = chunks.next() {
            if chunk.len() == 8 {
                out.push(0);
                out.extend_from_slice(chunk);
                if chunks.peek().is_none() {
                    out.extend_from_slice(&[0x80, 0, 0]);
                }
            } else {
                out.push(0x80 >> chunk.len());
                out.extend_from_slice(chunk);
                out.extend_from_slice(&[0, 0]);
            }
        }
        out
    }

    /// Packs `bytes` as a BIOS LZ77 stream, literals only.
    pub(crate) fn pack_lz77(bytes: &[u8]) -> Vec<u8> {
        let mut out = vec![0x10, bytes.len() as u8, (bytes.len() >> 8) as u8, (bytes.len() >> 16) as u8];
        for chunk in bytes.chunks(8) {
            out.push(0);
            out.extend_from_slice(chunk);
        }
        out
    }

    /// Thumb `ldr rd, [pc, #literal - pc]` at `at` for a literal word at `literal`.
    pub(crate) fn ldr_pc(register: u16, at: usize, literal: usize) -> u16 {
        let base = (at + 4) & !3;
        0x4800 | (register << 8) | ((literal - base) / 4) as u16
    }

    /// A ROM with a BIOS wrapper (`swi number; bx lr`) at 0x180 and, at 0x100,
    /// a caller loading r0, r1, r2 from three literals and calling it.
    pub(crate) fn bios_call(rom: &mut [u8], number: u8, arguments: [u32; 3]) {
        put_half(rom, 0x100, ldr_pc(0, 0x100, 0x10C));
        put_half(rom, 0x102, ldr_pc(1, 0x102, 0x110));
        put_half(rom, 0x104, ldr_pc(2, 0x104, 0x114));
        let [first, second] = bl(0x106, 0x180);
        put_half(rom, 0x106, first);
        put_half(rom, 0x108, second);
        put_half(rom, 0x10A, 0x4770);
        for (index, value) in arguments.iter().enumerate() {
            put_word(rom, 0x10C + index * 4, *value);
        }
        put_half(rom, 0x180, 0xDF00 | u16::from(number));
        put_half(rom, 0x182, 0x4770);
    }

    /// A ROM whose index at 0x100 names `codes` code resources and some
    /// others, all type 1; the code ones unpack to code run at 0x02008000.
    pub(crate) fn resource_rom(codes: usize) -> Vec<u8> {
        let mut image = vec![0u8; 0x6000];
        let mut starts = Vec::new();
        let mut at = 0x1000usize;
        for index in 0..20 {
            starts.push(at);
            let packed = if index < codes {
                pack_byte_lz(&filter_calls(&code_blob(0x0200_8000, 6 + index)))
            } else {
                // Not code: a counting pattern.
                pack_byte_lz(&(0..200u32).map(|value| (value * 7) as u8).collect::<Vec<u8>>())
            };
            image[at..at + packed.len()].copy_from_slice(&packed);
            at += packed.len().next_multiple_of(4);
        }
        starts.push(at);
        resource_index(&mut image, 0x100, &starts);
        image
    }

    /// An ascending index of `count` ROM addresses starting at `at` whose
    /// resources start at `starts` (and end at the next entry's start).
    pub(crate) fn resource_index(rom: &mut [u8], at: usize, starts: &[usize]) {
        for (index, start) in starts.iter().enumerate() {
            put_word(rom, at + index * 4, 0x0800_0000 + *start as u32);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::*;
    use super::*;

    fn rom(len: usize) -> Vec<u8> {
        vec![0u8; len]
    }

    #[test]
    fn a_cpuset_copy_of_code_is_placed_at_its_destination() {
        let mut image = rom(0x2000);
        let blob = code_blob(0x0300_0100, 12);
        image[0x1000..0x1000 + blob.len()].copy_from_slice(&blob);
        // 0x100 bytes as 64 words, 32-bit mode.
        bios_call(&mut image, 0x0B, [0x0800_1000, 0x0300_0100, 0x0400_0000 | 64]);
        let images = find(&image);
        let copy = images.iter().find(|candidate| candidate.kind == Kind::Copy).expect("the copy");
        assert_eq!(copy.run, 0x0300_0100);
        assert_eq!(copy.bytes, image[0x1000..0x1100]);
        assert!(!copy.demote, "the ROM copy of a function the game also runs in place stays code");
        assert!(copy.entries.contains(&(0x0300_0100, false)));
        assert!(copy.entries.contains(&(0x0300_0100 + blob_entries(12)[1] as u32, false)));
    }

    #[test]
    fn a_copy_of_data_is_not_code() {
        let mut image = rom(0x2000);
        // Zero fill and a counting pattern.
        for (index, byte) in image[0x1000..0x1100].iter_mut().enumerate() {
            *byte = if index < 0x80 { 0 } else { index as u8 };
        }
        bios_call(&mut image, 0x0B, [0x0800_1000, 0x0300_0100, 0x0400_0000 | 64]);
        assert!(find(&image).iter().all(|candidate| candidate.kind != Kind::Copy));
    }

    #[test]
    fn a_fill_or_a_rom_destination_is_not_a_copy() {
        let mut image = rom(0x2000);
        let blob = code_blob(0x0300_0100, 12);
        image[0x1000..0x1000 + blob.len()].copy_from_slice(&blob);
        bios_call(&mut image, 0x0B, [0x0800_1000, 0x0300_0100, 0x0500_0000 | 64]);
        assert!(find(&image).is_empty(), "bit 24 selects fill");
        bios_call(&mut image, 0x0B, [0x0800_1000, 0x0800_1800, 0x0400_0000 | 64]);
        assert!(find(&image).is_empty(), "the destination must be RAM");
        bios_call(&mut image, 0x0B, [0x0800_1000, 0x0300_7F80, 0x0400_0000 | 64]);
        assert!(find(&image).is_empty(), "the copy must fit the window");
    }

    #[test]
    fn an_lz77_call_places_the_unpacked_code() {
        let mut image = rom(0x3000);
        let blob = code_blob(0x0200_4000, 20);
        let packed = pack_lz77(&blob);
        image[0x1000..0x1000 + packed.len()].copy_from_slice(&packed);
        bios_call(&mut image, 0x11, [0x0800_1000, 0x0200_4000, 0]);
        let images = find(&image);
        let unpacked = images.iter().find(|candidate| candidate.kind == Kind::Lz77).expect("the unpack");
        assert_eq!(unpacked.run, 0x0200_4000);
        assert_eq!(unpacked.bytes, blob);
        assert_eq!(unpacked.rom_len, packed.len());
    }

    #[test]
    fn an_lz77_stream_must_fill_its_declared_size() {
        let blob = code_blob(0x0200_4000, 20);
        let mut packed = pack_lz77(&blob);
        packed[1] = packed[1].wrapping_add(1);
        packed.truncate(packed.len() - 9);
        assert!(lz77(&packed).is_none());
        assert!(lz77(&[0x30, 4, 0, 0, 0, 1, 2, 3, 4]).is_none(), "type byte 10h only");
        let (bytes, stored) = lz77(&[0x10, 6, 0, 0, 0x40, 7, 0x20, 0x00]).expect("a reference");
        assert_eq!((bytes, stored), (vec![7, 7, 7, 7, 7, 7], 8));
    }

    #[test]
    fn the_resource_codecs_decode_streams_of_their_own_format() {
        let bytes: Vec<u8> = (0..37u8).collect();
        assert_eq!(resource_unpack(&pack_byte_lz(&bytes)).map(|(unpacked, _)| unpacked), Some(bytes.clone()));
        // Three literals, a reference (displacement 3, length nibble 3: four
        // bytes), then the end marker: flags 0001 1000.
        let stream = [1u8, 0x18, 1, 2, 3, 0x03, 0x03, 0x00, 0x00];
        assert_eq!(resource_unpack(&stream), Some((vec![1, 2, 3, 1, 2, 3, 1], stream.len())));
        // Type 0, LSB first: literal 0x41 ('1' then 8 bits), then the end escape:
        // 0,1,1,1,1,1 (escape), 00 (extra), 0000000 (zero width).
        let mut bits: Vec<u8> = vec![1];
        bits.extend((0..8).map(|index| (0x41u8 >> index) & 1));
        bits.extend([0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let mut packed = vec![0u8];
        for chunk in bits.chunks(8) {
            packed.push(chunk.iter().enumerate().fold(0u8, |byte, (index, &bit)| byte | bit << index));
        }
        assert_eq!(resource_unpack(&packed), Some((vec![0x41], packed.len())));
        assert!(resource_unpack(&[2, 0, 0]).is_none(), "only types 0 and 1");
        assert!(resource_unpack(&[1, 0x80, 0x05, 0x01]).is_none(), "a reference before any output");
    }

    #[test]
    fn call_operands_stored_absolute_are_restored() {
        let blob = code_blob(0, 6);
        let stored = filter_calls(&blob);
        assert_ne!(stored, blob);
        assert_eq!(unfilter_calls(&stored), blob);
    }

    fn header_at_offset(image: &mut [u8], at: usize, with_branch: u32) {
        let logo: Vec<u8> = (0..0x9C).map(|index| (index as u8).wrapping_mul(7) | 1).collect();
        image[4..0xA0].copy_from_slice(&logo);
        image[at..at + 4].copy_from_slice(&with_branch.to_le_bytes());
        image[at + 4..at + 0xA0].copy_from_slice(&logo);
        image[at + 0xB2] = 0x96;
        let sum: u32 = image[at + 0xA0..at + 0xBD].iter().map(|&byte| u32::from(byte)).sum();
        image[at + 0xBD] = (0u32.wrapping_sub(sum + 0x19) & 0xFF) as u8;
    }

    #[test]
    fn an_embedded_multiboot_header_places_the_image_at_ewram() {
        let mut image = rom(0x1000);
        header_at_offset(&mut image, 0, 0xEA00_002E);
        header_at_offset(&mut image, 0x400, 0xEA00_002E);
        // ARM at the entry: mov r0, #0; bx lr.
        put_word(&mut image, 0x4C0, 0xE3A0_0000);
        put_word(&mut image, 0x4C4, 0xE12F_FF1E);
        let images = find(&image);
        let embedded = images.iter().find(|candidate| candidate.kind == Kind::Multiboot).expect("the image");
        assert_eq!((embedded.rom_start, embedded.run), (0x400, MULTIBOOT_BASE));
        assert!(embedded.demote);
        assert_eq!(embedded.bytes[..4], image[0x400..0x404]);
        assert!(images.len() == 1, "the real header at offset 0 is the cartridge, not an image");
    }

    #[test]
    fn identical_embedded_images_are_placed_once_and_both_load_images_demoted() {
        let mut image = rom(0x1000);
        header_at_offset(&mut image, 0, 0xEA00_002E);
        for at in [0x400usize, 0x800] {
            header_at_offset(&mut image, at, 0xEA00_002E);
            put_word(&mut image, at + 0xC0, 0xE3A0_0000);
            put_word(&mut image, at + 0xC4, 0xE12F_FF1E);
        }
        let images = find(&image);
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].rom_start, 0x400);
        assert_eq!(images[0].copies, vec![(0x800, images[0].rom_len)]);
    }

    #[test]
    fn a_header_with_a_wrong_check_byte_is_not_an_image() {
        let mut image = rom(0x1000);
        header_at_offset(&mut image, 0, 0xEA00_002E);
        header_at_offset(&mut image, 0x400, 0xEA00_002E);
        image[0x400 + 0xBD] ^= 1;
        put_word(&mut image, 0x4C0, 0xE3A0_0000);
        put_word(&mut image, 0x4C4, 0xE12F_FF1E);
        assert!(find(&image).is_empty());
    }

    #[test]
    fn code_resources_share_one_run_address_and_become_overlays() {
        let image = resource_rom(5);
        let images = find(&image);
        let resources: Vec<&Image> = images.iter().filter(|candidate| candidate.kind == Kind::Resource).collect();
        assert_eq!(resources.len(), 5);
        assert!(resources.iter().all(|candidate| candidate.run == 0x0200_8000 && candidate.overlay));
        assert!(resources.iter().all(|candidate| !candidate.demote));
        assert!(resources[0].entries.contains(&(0x0200_8000, false)));
    }

    #[test]
    fn two_code_resources_are_not_enough_to_agree_on_a_window() {
        let image = resource_rom(2);
        let images = find(&image);
        assert!(images.iter().all(|candidate| candidate.kind != Kind::Resource) || images.iter().all(|candidate| {
            candidate.kind != Kind::Resource || !candidate.entries.is_empty()
        }));
    }

    #[test]
    fn code_whose_own_pointers_fix_its_address_is_placed_and_demoted() {
        let mut image = rom(0x4000);
        let blob = code_blob(0x0200_1000, 80);
        image[0x1000..0x1000 + blob.len()].copy_from_slice(&blob);
        let images = find(&image);
        let aligned = images.iter().find(|candidate| candidate.kind == Kind::Aligned).expect("the module");
        assert_eq!(aligned.run, 0x0200_1000);
        assert_eq!(aligned.rom_start, 0x1000);
        assert!(aligned.demote);
        assert_eq!(aligned.bytes[..16], image[0x1000..0x1010]);
        assert!(aligned.entries.contains(&(0x0200_1000 + blob_entries(80)[5] as u32, false)));
    }

    #[test]
    fn code_addressed_in_the_rom_is_not_a_ram_image() {
        let mut image = rom(0x4000);
        let blob = code_blob(0x0800_1000, 80);
        image[0x1000..0x1000 + blob.len()].copy_from_slice(&blob);
        assert!(find(&image).is_empty());
    }

    #[test]
    fn code_pointed_at_by_rom_address_as_well_is_not_moved() {
        let mut image = rom(0x4000);
        let blob = code_blob(0x0200_1000, 80);
        image[0x1000..0x1000 + blob.len()].copy_from_slice(&blob);
        // The ROM also names 40 of the entries by ROM address, as a ROM
        // function table would.
        for (index, entry) in blob_entries(80).iter().take(40).enumerate() {
            put_word(&mut image, 0x3000 + index * 4, 0x0800_1000 + *entry as u32 + 1);
        }
        assert!(find(&image).iter().all(|candidate| candidate.kind != Kind::Aligned));
    }

    #[test]
    fn fewer_than_eight_pointers_do_not_fix_an_address() {
        let mut image = rom(0x4000);
        let blob = code_blob(0x0200_1000, 80);
        image[0x1000..0x1000 + blob.len()].copy_from_slice(&blob);
        // Zero all but 5 of the pointer words.


        let total: usize = (0..80).map(blob_size).sum();
        for index in 5..80 {
            put_word(&mut image, 0x1000 + total + index * 4, 0);
        }
        assert!(find(&image).iter().all(|candidate| candidate.kind != Kind::Aligned));
    }
}
