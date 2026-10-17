//! Segment layout discovery for Nintendo 64 ROMs, from the ROM's own bytes.
//!
//! `n64_segments` applies a layout someone wrote down. This module finds one:
//! where each code segment and overlay sits in the ROM, how it is packed and
//! at which address the game runs it, without a per-game table. Every claim
//! rests on evidence in the bytes, and a segment that the evidence does not
//! settle is left out, so the ROM keeps the linear view for it
//! (`n64.rs`); a segment is never placed at an address the bytes do not prove.
//!
//! # What the evidence is
//!
//! A code blob built for address `B` carries `B` in itself. Its `jal`
//! instructions name absolute targets (MIPS III `JAL`: a 26-bit word index
//! in the 256 MB region of the call), and its data holds
//! function pointers as full 32-bit addresses. If `B` is the base, nearly
//! every target that falls inside the blob lands on a function entry: the
//! `addiu sp, sp, -N` of a prologue, or the first instruction after a
//! `jr ra` and its delay slot. For a wrong base that share is chance, about
//! one target in twenty-five. [`Probe`] counts the calls and the pointers
//! that land in range (`hits`, `calls`); a base is accepted only when at
//! least three agree, most of the calls that land in range agree (a
//! pointer can point at data, a call cannot), and the runner-up base has
//! at most half as many.
//!
//! A `jal` carries no top nibble, so the evidence alone cannot tell
//! `0x80001050` from `0x70001050` (Perfect Dark's TLB-mapped library). The
//! cached-RDRAM nibble (`0x8`) is therefore claimed only when something in
//! the bytes carries it: a pointer word that starts with `0x80`, a
//! `lui`/`addiu` constant into the blob, a call from resident code, or the
//! full address a ROM table gives. Without it the blob is refused.
//!
//! # Where candidates come from
//!
//! * **Boot segment.** The ROM from `0x1000` (IPL3 loads it to the entry
//!   point, n64brew "CIC-NUS"), up to where the code stops. The entry
//!   point is the header's word at `0x08`, `-0x100000` for the CIC 6103 and
//!   `-0x200000` for the 6106 (n64brew "CIC-NUS"). Rather than recognise the
//!   chip, each of the three is scored against the boot code's own `jal`
//!   evidence and the best that the evidence supports is taken.
//! * **Packed files found by their magic.** Yaz0, MIO0 and Yay0 headers, and
//!   Rare's `0x1172` header with a 4-byte length (Banjo-Kazooie). A stream
//!   must decode to its declared length, hold code (below) and place by the
//!   evidence above, with the already-placed resident code excluded so that
//!   calls into it do not outvote the blob's own.
//! * **ROM ranges the game names.** A pair of ROM offsets next to a RDRAM
//!   address, as a descriptor in a table (`{rom start, rom end, ram}`) or as
//!   the arguments the code materialises for a DMA call (`lui`/`addiu`
//!   constants). The pair delimits a raw range, the address is the base to
//!   test, and the evidence must confirm it. Most hits are noise (a pair of
//!   offsets that happen to follow each other); the code check and the
//!   evidence discard them.
//! * **Headerless streams the boot code points at.** An offset the boot
//!   code loads that is neither code nor a known stream is tried as raw
//!   DEFLATE (Dr. Mario 64's `main_segment`).
//!
//! # "Holds code"
//!
//! At least one `jr ra`, and the first 512 words overwhelmingly valid MIPS
//! (reserved opcodes and non-zero must-be-zero fields do not occur in
//! compiler output). A blob that starts with data (a table, a texture
//! header) fails this and stays unplaced.
//!
//! # Overlays that share an address
//!
//! Overlays loaded into the same RDRAM window cannot be one address space.
//! Segments whose address ranges overlap are reported as such and `n64.rs`
//! gives each its own program, as `nds_overlays` does for DS overlays.
//!
//! # Limits
//!
//! Only KSEG0 (`0x80000000`..`0x81000000`) is proven, and only code the
//! `jal`/pointer evidence can pin. TLB-mapped segments (Perfect Dark's
//! library and demand-paged game segment) are not discoverable this way;
//! its layout stays in the catalog. Blobs that are mostly data, have a
//! handful of internal calls and no pointer, or whose table lists no
//! address are left unplaced. Sources: n64brew "CIC-NUS" (the entry point
//! per CIC variant) and the MIPS III instruction encodings; the Yaz0, MIO0
//! and Rare formats are described in `n64_codec`.

use super::n64_codec::Codec;
use super::n64_segments::{Layout, Part, Place, Segment};
use std::collections::{BTreeMap, HashSet};

const CODE_OFFSET: usize = 0x1000;
const SEGMENT_LIMIT: usize = 8 << 20;
const LOW28: u32 = 0x0fff_ffff;
const KSEG0: u32 = 0x8000_0000;
/// Link addresses seen above RDRAM (Zelda's overlays are linked past
/// 8 MB and relocated when loaded), so the bound is the 16 MB the 26-bit
/// jump field and the 0x80 prefix leave comfortable, not RDRAM's size.
const VRAM_LIMIT: u32 = 0x0100_0000;
/// A candidate needs this much code to be worth a probe.
const MIN_WORDS: usize = 16;
/// Resident code is excluded from later blobs' evidence once it is this big
/// or the boot code loads it.
const RESIDENT_BYTES: usize = 0x4_0000;
/// Hints are looked for this many words around a pair of ROM offsets.
const HINT_WORDS: usize = 6;
/// Instructions around a pair of ROM constants in code that hint the base.
const HINT_INSTRUCTIONS: usize = 12;
/// How far past the end of the boot code its data may run, when another
/// segment starts there.
const TAIL_BYTES: usize = 0x4_0000;

fn be_words(bytes: &[u8]) -> Vec<u32> {
    bytes.as_chunks::<4>().0.iter().map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]])).collect()
}

/// One word that a compiler could have emitted for the VR4300: valid opcode,
/// and fields the encoding requires to be zero are zero.
fn plausible(w: u32) -> bool {
    let op = w >> 26;
    let (rs, rt, rd, sa, funct) = ((w >> 21) & 31, (w >> 16) & 31, (w >> 11) & 31, (w >> 6) & 31, w & 63);
    match op {
        0 => match funct {
            0 | 2 | 3 => rs == 0,
            4 | 6 | 7 => sa == 0,
            8 => rt == 0 && rd == 0 && sa == 0,
            9 => rt == 0 && sa == 0,
            16 | 18 => rs == 0 && rt == 0 && sa == 0,
            17 | 19 => rt == 0 && rd == 0 && sa == 0,
            24..=31 => rd == 0 && sa == 0,
            32..=39 | 42..=47 => sa == 0,
            12 | 13 | 15 | 48..=52 | 54 => true,
            _ => false,
        },
        1 => matches!(rt, 0..=3 | 8..=12 | 14 | 16..=19),
        2..=5 | 8..=14 | 16 | 17 | 20..=23 | 24..=27 | 32..=38 | 40..=43 | 46 | 47 | 49 | 53 | 55 | 57 | 61 | 63 => true,
        6 | 7 => rt == 0,
        15 => rs == 0,
        _ => false,
    }
}

fn is_jr_ra(w: u32) -> bool {
    w == 0x03e0_0008
}

/// A function entry the compiler produced: the `addiu sp, sp, -N` of a
/// prologue.
fn is_prologue(w: u32) -> bool {
    w >> 16 == 0x27bd && w & 0x8000 != 0
}

/// Whether `words` begin like code: the first 512 words mostly valid
/// instructions.
fn starts_like_code(words: &[u32]) -> bool {
    if words.len() < MIN_WORDS {
        return false;
    }
    let head = &words[..words.len().min(512)];
    let valid = head.iter().filter(|&&w| plausible(w)).count();
    valid * 100 >= head.len() * 85
}

/// Whether `words` hold code: it begins like code and returns somewhere.
fn holds_code(words: &[u32]) -> bool {
    starts_like_code(words) && words.iter().any(|&w| is_jr_ra(w))
}

/// `holds_code` for a ROM range a table names, which may begin with data
/// (an overlay that links its tables first): a return somewhere, and either
/// a start that looks like code or at least a quarter of an even sample of
/// the range's 1 KB blocks that do. The address evidence decides the rest.
fn range_holds_code(bytes: &[u8]) -> bool {
    const BLOCK: usize = 0x400;
    if bytes.len() < MIN_WORDS * 4 || !bytes.as_chunks::<4>().0.contains(&[0x03, 0xe0, 0x00, 0x08]) {
        return false;
    }
    if starts_like_code(&be_words(&bytes[..bytes.len().min(0x800)])) {
        return true;
    }
    let blocks = bytes.len() / BLOCK;
    let step = (blocks / 64).max(1);
    let (mut seen, mut code) = (0usize, 0usize);
    for index in (0..blocks).step_by(step) {
        let words = be_words(&bytes[index * BLOCK..(index + 1) * BLOCK]);
        seen += 1;
        let used = words.iter().filter(|&&w| w != 0).count();
        code += usize::from(starts_like_code(&words) && used * 4 >= words.len());
    }
    seen > 0 && code * 4 >= seen
}

/// `lui rt, hi` completed within six instructions by an `addiu`, `ori` or a
/// load/store off `rt`: the 32-bit constants compilers build with a pair.
/// Each is returned with the index of its `lui`.
fn constants(words: &[u32]) -> Vec<(usize, u32)> {
    let mut out = Vec::new();
    for (at, &w) in words.iter().enumerate() {
        if w >> 26 != 15 {
            continue;
        }
        let reg = (w >> 16) & 31;
        if reg == 0 {
            continue;
        }
        let hi = (w & 0xffff) << 16;
        for &next in words.iter().skip(at + 1).take(6) {
            let (op, rs, rt, imm) = (next >> 26, (next >> 21) & 31, (next >> 16) & 31, next & 0xffff);
            if rs != reg {
                // Something overwrote the register: the lui is dead.
                if rt == reg && matches!(op, 15 | 9 | 13 | 32..=39) {
                    break;
                }
                continue;
            }
            let signed = imm as u16 as i16 as i32 as u32;
            match op {
                // addi, addiu, daddi, daddiu, loads and stores: signed offset.
                8 | 9 | 24 | 25 | 32..=38 | 40..=43 | 46 | 49 | 53 | 55 | 57 | 61 | 63 => {
                    out.push((at, hi.wrapping_add(signed)));
                    if rt == reg && matches!(op, 8 | 9 | 24 | 25 | 32..=38 | 55) {
                        break;
                    }
                }
                13 => {
                    out.push((at, hi | imm));
                    if rt == reg {
                        break;
                    }
                }
                _ => {}
            }
        }
    }
    out
}

/// What a blob says about the address it runs at, with the part of the world
/// a caller wants ignored (calls into resident code) already left out.
struct Probe {
    words: usize,
    /// Word indices that look like function entries.
    entries: Vec<bool>,
    /// Sorted unique `jal` targets (low 28 bits) outside the exclusions.
    jal: Vec<u32>,
    /// Sorted unique `0x80`-prefixed aligned words (low 28 bits) outside the
    /// exclusions: pointers to code or data in cached RDRAM.
    ptr: Vec<u32>,
    /// `jal` targets and pointers together, sorted unique.
    all: Vec<u32>,
    /// Sorted unique full constants in cached RDRAM, from `lui` pairs.
    consts: Vec<u32>,
}

fn excluded(exclude: &[(u32, u32)], value: u32) -> bool {
    exclude.iter().any(|&(lo, hi)| (lo..hi).contains(&value))
}

impl Probe {
    fn new(words: &[u32], exclude: &[(u32, u32)]) -> Probe {
        let n = words.len();
        let mut entries = vec![false; n];
        let (mut jal, mut ptr) = (Vec::new(), Vec::new());
        for (at, &w) in words.iter().enumerate() {
            if is_prologue(w) {
                entries[at] = true;
            } else if is_jr_ra(w) {
                let mut next = at + 2;
                while words.get(next) == Some(&0) {
                    next += 1;
                }
                if next < n {
                    entries[next] = true;
                }
            }
            match w >> 26 {
                3 => {
                    let target = (w & 0x03ff_ffff) << 2;
                    if !excluded(exclude, target) {
                        jal.push(target);
                    }
                }
                _ if w >> 24 == 0x80 && w & 3 == 0 => {
                    let low = w & LOW28;
                    if low < VRAM_LIMIT && !excluded(exclude, low) {
                        ptr.push(low);
                    }
                }
                _ => {}
            }
        }
        if n > 0 {
            entries[0] = true;
        }
        let mut consts: Vec<u32> = constants(words)
            .into_iter()
            .map(|(_, value)| value)
            .filter(|value| value >> 24 == 0x80 && value & LOW28 < VRAM_LIMIT)
            .collect();
        consts.sort_unstable();
        consts.dedup();
        for list in [&mut jal, &mut ptr] {
            list.sort_unstable();
            list.dedup();
        }
        let mut all: Vec<u32> = jal.iter().chain(&ptr).copied().collect();
        all.sort_unstable();
        all.dedup();
        Probe { words: n, entries, jal, ptr, all, consts }
    }

    /// How much of what lands in `[base, base + size)` agrees with `base`.
    /// Calls count for and against (a call always names an entry); a
    /// pointer only counts for (data points at data as well as at code).
    fn evidence(&self, base: u32) -> Evidence {
        let lo = self.all.partition_point(|&v| v < base);
        let end = u64::from(base) + 4 * self.words as u64;
        let mut evidence = Evidence::default();
        for &value in &self.all[lo..] {
            if u64::from(value) >= end {
                break;
            }
            let offset = value - base;
            let on_entry = offset.is_multiple_of(4) && self.entries[(offset / 4) as usize];
            let call = self.jal.binary_search(&value).is_ok();
            let pointer = self.ptr.binary_search(&value).is_ok();
            evidence.calls += usize::from(call);
            if on_entry {
                evidence.hits += 1;
                evidence.calls_ok += usize::from(call);
                evidence.pointers += usize::from(pointer);
            }
        }
        evidence
    }

    /// Constants that point into the blob placed at cached `vram`.
    fn constants_in(&self, vram: u32) -> usize {
        let end = u64::from(vram) + 4 * self.words as u64;
        let lo = self.consts.partition_point(|&v| v < vram);
        self.consts[lo..].iter().take_while(|&&v| u64::from(v) < end).count()
    }

    /// Calls from `outside` (sorted jal targets of resident code) into the
    /// blob at `base` that land on an entry.
    fn calls_into(&self, outside: &[u32], base: u32) -> usize {
        let end = u64::from(base) + 4 * self.words as u64;
        let lo = outside.partition_point(|&v| v < base);
        outside[lo..]
            .iter()
            .take_while(|&&v| u64::from(v) < end)
            .filter(|&&v| (v - base).is_multiple_of(4) && self.entries[((v - base) / 4) as usize])
            .count()
    }

    /// Bases the evidence suggests, best first: every (value, entry) pair of
    /// a sample of the values votes for the base it implies.
    fn bases(&self) -> Vec<u32> {
        if self.all.is_empty() {
            return Vec::new();
        }
        let entries: Vec<u32> = (0..self.words as u32).filter(|&i| self.entries[i as usize]).collect();
        let step = (self.all.len() / 48).max(1);
        let mut votes: Vec<u32> = Vec::new();
        for &value in self.all.iter().step_by(step) {
            for &entry in &entries {
                if let Some(base) = value.checked_sub(entry * 4) {
                    votes.push(base);
                }
            }
        }
        votes.sort_unstable();
        let mut counted: Vec<(usize, u32)> = Vec::new();
        let mut at = 0;
        while at < votes.len() {
            let mut end = at;
            while end < votes.len() && votes[end] == votes[at] {
                end += 1;
            }
            if end - at >= 2 && votes[at].is_multiple_of(4) {
                counted.push((end - at, votes[at]));
            }
            at = end;
        }
        counted.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        counted.into_iter().take(8).map(|(_, base)| base).collect()
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Evidence {
    /// Distinct call targets and pointers in range that land on a function entry.
    hits: usize,
    /// Of `hits`, the `0x80`-prefixed words (which carry the top nibble).
    pointers: usize,
    /// Distinct call targets that land in range at all, and how many of
    /// them land on an entry.
    calls: usize,
    calls_ok: usize,
}

impl Evidence {
    /// Enough, and the calls mostly agree.
    fn convincing(&self) -> bool {
        self.hits >= 3 && self.calls_ok * 2 >= self.calls
    }

    /// The weaker form a ROM table's own address may use: few hits, but
    /// every call that lands in range agrees.
    fn consistent(&self) -> bool {
        self.convincing() || (self.hits >= 2 && self.calls >= 2 && self.calls_ok == self.calls)
    }

    fn describe(&self) -> String {
        format!("{} entries agree ({} of {} calls in range, {} pointers)", self.hits, self.calls_ok, self.calls, self.pointers)
    }
}

/// The best base for a blob and how unambiguous it is.
struct Located {
    base: u32,
    evidence: Evidence,
    /// Calls from resident code that land on an entry.
    external: usize,
}

fn locate(probe: &Probe, outside: &[u32]) -> Option<Located> {
    let mut scored: Vec<(Evidence, u32)> = probe
        .bases()
        .into_iter()
        .filter(|&base| base < VRAM_LIMIT)
        .map(|base| (probe.evidence(base), base))
        .collect();
    scored.sort_by(|a, b| b.0.hits.cmp(&a.0.hits).then(a.1.cmp(&b.1)));
    let (evidence, base) = *scored.first()?;
    let runner = scored.get(1).map_or(0, |&(e, _)| e.hits);
    if !evidence.convincing() || runner * 2 > evidence.hits {
        return None;
    }
    let external = probe.calls_into(outside, base);
    // The top nibble: proven by a pointer, a constant, or a caller in
    // resident (cached) code; a `jal` alone does not carry it.
    let proven = evidence.pointers > 0 || probe.constants_in(KSEG0 | base) > 0 || external > 0;
    proven.then_some(Located { base, evidence, external })
}

/// A segment discovery settled.
#[derive(Clone, Debug)]
pub struct Found {
    pub name: String,
    pub rom: (usize, usize),
    pub codec: Codec,
    pub vram: u32,
    pub size: usize,
    /// Resident (the boot code loads it) as against an overlay.
    pub resident: bool,
    /// Targets and pointers that agree with the chosen address.
    pub hits: usize,
    /// Why it was accepted.
    pub evidence: String,
    pub bytes: Vec<u8>,
}

/// The outcome: the boot segment, what else was settled, and what was seen
/// but refused.
#[derive(Debug)]
pub struct Discovered {
    pub boot: u64,
    pub boot_rom: (usize, usize),
    pub segments: Vec<Found>,
    pub refused: Vec<String>,
}

impl Discovered {
    /// The segments as a [`Layout`], boot first. Overlays whose address
    /// ranges overlap are in it too; `n64.rs` splits them into programs.
    pub fn layout(&self, rom: &[u8]) -> Layout {
        let word = |at: usize| u32::from_be_bytes([rom[at], rom[at + 1], rom[at + 2], rom[at + 3]]);
        let mut segments = vec![Segment {
            name: "boot".into(),
            flags: 7,
            kind: "code".into(),
            place: Place::Boot,
            size: Some((self.boot_rom.1 - self.boot_rom.0) as u64),
            parts: vec![Part { rom: (self.boot_rom.0 as u64, self.boot_rom.1 as u64), codec: Codec::Raw }],
        }];
        for found in &self.segments {
            segments.push(Segment {
                name: found.name.clone(),
                flags: 7,
                kind: if found.resident { "code".into() } else { "overlay".into() },
                place: Place::At(u64::from(found.vram)),
                size: Some(found.size as u64),
                parts: vec![Part { rom: (found.rom.0 as u64, found.rom.1 as u64), codec: found.codec }],
            });
        }
        let mut code = [0u8; 4];
        code.copy_from_slice(&rom[0x3b..0x3f]);
        Layout {
            id: "discovered".into(),
            title: format!("discovered from the ROM's bytes ({} segments)", segments.len()),
            crc1: word(0x10),
            crc2: word(0x14),
            game_code: code,
            segments,
        }
    }

    /// For the boot segment (index 0) and then each of `segments`: whether
    /// its address range overlaps another's.
    pub fn clashes(&self) -> Vec<bool> {
        let boot = self.boot as u32 & LOW28;
        let mut ranges = vec![(boot, boot + (self.boot_rom.1 - self.boot_rom.0) as u32)];
        ranges.extend(self.segments.iter().map(|s| vram_range(s.vram, s.size)));
        let mut out = vec![false; ranges.len()];
        for a in 0..ranges.len() {
            for b in a + 1..ranges.len() {
                if ranges[a].0 < ranges[b].1 && ranges[b].0 < ranges[a].1 {
                    out[a] = true;
                    out[b] = true;
                }
            }
        }
        out
    }
}

fn rom_word(rom: &[u8], at: usize) -> Option<u32> {
    rom.get(at..at + 4).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// The end of the code that starts at the beginning of `bytes`: the last
/// 1 KB block of the first run of code-like blocks, tolerating short gaps
/// (a table inside a code segment).
fn code_extent(bytes: &[u8]) -> usize {
    const BLOCK: usize = 0x400;
    const GAP_BLOCKS: usize = 4;
    let mut last = 0;
    let mut gap = 0;
    for (index, block) in bytes.chunks(BLOCK).enumerate() {
        let words = be_words(block);
        let valid = words.iter().filter(|&&w| plausible(w)).count();
        let used = words.iter().filter(|&&w| w != 0).count();
        let code = !words.is_empty() && valid * 100 >= words.len() * 80 && used * 4 >= words.len();
        if code {
            last = (index + 1) * BLOCK;
            gap = 0;
        } else {
            gap += 1;
            if gap > GAP_BLOCKS {
                break;
            }
        }
    }
    last.min(bytes.len())
}

/// The entry point the CPU starts at: the header's word, `-0x100000` or
/// `-0x200000` (n64brew "CIC-NUS" lists the chips that offset it), whichever
/// the boot code's own calls agree with; the header's word when none does.
pub(crate) fn entry_address(rom: &[u8], header: u64) -> u64 {
    let Some(head) = rom.get(CODE_OFFSET..) else { return header };
    let run = code_extent(&head[..head.len().min(0x4_0000)]);
    if run < 0x40 {
        return header;
    }
    let probe = Probe::new(&be_words(&head[..run & !3]), &[]);
    entry_from(&probe, header).unwrap_or(header)
}

fn entry_from(probe: &Probe, header: u64) -> Option<u64> {
    let mut best: Option<(usize, u64)> = None;
    for shift in [0u64, 0x10_0000, 0x20_0000] {
        let Some(candidate) = header.checked_sub(shift) else { continue };
        if candidate < u64::from(KSEG0) || candidate & 3 != 0 {
            continue;
        }
        let evidence = probe.evidence((candidate as u32) & LOW28);
        if evidence.convincing() && best.is_none_or(|(hits, _)| evidence.hits > hits) {
            best = Some((evidence.hits, candidate));
        }
    }
    best.map(|(_, entry)| entry)
}

struct Stream {
    start: usize,
    end: usize,
    codec: Codec,
    bytes: Vec<u8>,
}

/// Every packed file the ROM carries whose header this module knows, decoded
/// and holding code.
fn scan_streams(rom: &[u8]) -> Vec<Stream> {
    let mut out = Vec::new();
    let mut at = CODE_OFFSET;
    while at + 16 <= rom.len() {
        let word = u32::from_be_bytes([rom[at], rom[at + 1], rom[at + 2], rom[at + 3]]);
        let (codec, declared) = match word {
            0x5961_7a30 => (Codec::Yaz0, rom_word(rom, at + 4)),
            0x4d49_4f30 => (Codec::Mio0, rom_word(rom, at + 4)),
            0x5961_7930 => (Codec::Yay0, rom_word(rom, at + 4)),
            w if w >> 8 == 0x0011_7200 => (Codec::Rare1172Sized, rom_word(rom, at + 2)),
            _ => {
                at += 4;
                continue;
            }
        };
        let start = at;
        at += 4;
        let declared = declared.unwrap_or(0) as usize;
        if !(0x40..=SEGMENT_LIMIT).contains(&declared) || !declared.is_multiple_of(4) {
            continue;
        }
        let Ok((bytes, used)) = codec.decode_extent(&rom[start..], SEGMENT_LIMIT) else { continue };
        if holds_code(&be_words(&bytes)) {
            out.push(Stream { start, end: start + used, codec, bytes });
        }
    }
    out
}

/// A pair of ROM offsets as a table or constants name them, with the
/// cached-RDRAM addresses seen beside them.
#[derive(Default)]
struct Named {
    hints: HashSet<u32>,
}

fn rom_pair(a: u32, b: u32, len: usize) -> bool {
    a >= CODE_OFFSET as u32
        && a.is_multiple_of(4)
        && b.is_multiple_of(4)
        && b > a
        && b as usize <= len
        && (0x40..=SEGMENT_LIMIT as u32).contains(&(b - a))
}

fn ram_like(w: u32) -> bool {
    w >> 24 == 0x80 && w & 3 == 0 && (w & LOW28) < VRAM_LIMIT
}

/// Pairs of ROM offsets in the ROM's data words and in the constants of its
/// code, each with the RDRAM addresses nearby.
fn named_ranges(rom: &[u8]) -> BTreeMap<(u32, u32), Named> {
    let words = be_words(&rom[..rom.len() & !3]);
    let mut out: BTreeMap<(u32, u32), Named> = BTreeMap::new();
    for at in 0..words.len().saturating_sub(1) {
        let (a, b) = (words[at], words[at + 1]);
        if !rom_pair(a, b, rom.len()) {
            continue;
        }
        let from = at.saturating_sub(HINT_WORDS);
        let to = (at + 2 + HINT_WORDS).min(words.len());
        let hints: Vec<u32> = (from..to).filter(|&i| i != at && i != at + 1).map(|i| words[i]).filter(|&w| ram_like(w)).collect();
        if !hints.is_empty() {
            out.entry((a, b)).or_default().hints.extend(hints);
        }
    }
    let consts = constants(&words);
    let rom_like: Vec<(usize, u32)> =
        consts.iter().copied().filter(|&(_, v)| v >= CODE_OFFSET as u32 && v as usize <= rom.len() && v % 4 == 0).collect();
    let ram: Vec<(usize, u32)> = consts.iter().copied().filter(|&(_, v)| ram_like(v)).collect();
    for (index, &(at, first)) in rom_like.iter().enumerate() {
        for &(_, second) in rom_like[index + 1..].iter().take_while(|&&(next, _)| next <= at + HINT_INSTRUCTIONS) {
            let (a, b) = if first < second { (first, second) } else { (second, first) };
            if !rom_pair(a, b, rom.len()) {
                continue;
            }
            let from = ram.partition_point(|&(i, _)| i + HINT_INSTRUCTIONS < at);
            let hints: Vec<u32> =
                ram[from..].iter().take_while(|&&(i, _)| i <= at + 2 * HINT_INSTRUCTIONS).map(|&(_, v)| v).collect();
            if !hints.is_empty() {
                out.entry((a, b)).or_default().hints.extend(hints);
            }
        }
    }
    out
}

/// Offsets the words and constants of the boot code name.
fn referenced_offsets(words: &[u32], len: usize) -> HashSet<u32> {
    let valid = |v: u32| (CODE_OFFSET as u32..len as u32).contains(&v) && v.is_multiple_of(4);
    let mut out: HashSet<u32> = words.iter().copied().filter(|&w| valid(w)).collect();
    out.extend(constants(words).into_iter().map(|(_, value)| value).filter(|&v| valid(v)));
    out
}

fn overlaps(a: (usize, usize), b: (usize, usize)) -> bool {
    a.0 < b.1 && b.0 < a.1
}

fn vram_range(vram: u32, size: usize) -> (u32, u32) {
    let low = vram & LOW28;
    (low, low.saturating_add(size as u32))
}

/// Finds the layout of `rom`, or `None` when the bytes settle nothing
/// beyond the boot segment.
pub fn discover(rom: &[u8]) -> Option<Discovered> {
    let header = u64::from(rom_word(rom, 8)?);
    let head_bytes = rom.get(CODE_OFFSET..)?;
    // The boot code: the run of code from the start of the ROM past the header.
    let run = code_extent(&head_bytes[..head_bytes.len().min(SEGMENT_LIMIT)]);
    if run < 0x40 {
        return None;
    }
    let head_words = be_words(&head_bytes[..run & !3]);
    let head_probe = Probe::new(&head_words, &[]);
    let boot = entry_from(&head_probe, header)?;
    let boot_low = (boot as u32) & LOW28;
    let referenced = referenced_offsets(&head_words, rom.len());
    let mut refused: Vec<String> = Vec::new();
    let mut found: Vec<Found> = Vec::new();

    // ROM ranges the game names, each with the addresses beside them.
    let mut by_start: BTreeMap<u32, Vec<Found>> = BTreeMap::new();
    for (&(a, b), named) in &named_ranges(rom) {
        let (start, end) = (a as usize, b as usize);
        let bytes = &rom[start..end];
        if !range_holds_code(bytes) {
            continue;
        }
        let words = be_words(bytes);
        let probe = Probe::new(&words, &[]);
        let mut best: Option<(Evidence, u32)> = None;
        for &hint in &named.hints {
            let evidence = probe.evidence(hint & LOW28);
            if evidence.consistent() && best.is_none_or(|(e, _)| evidence.hits > e.hits) {
                best = Some((evidence, hint));
            }
        }
        if let Some((evidence, vram)) = best {
            by_start.entry(a).or_default().push(Found {
                name: format!("ovl_{a:x}"),
                rom: (start, end),
                codec: Codec::Raw,
                vram,
                size: end - start,
                resident: referenced.contains(&a),
                hits: evidence.hits,
                evidence: format!("ROM range the ROM names, base {vram:#x} from the table or constants beside it: {}", evidence.describe()),
                bytes: bytes.to_vec(),
            });
        }
    }
    // One end per start: the nearest.
    for (_, mut ends) in by_start {
        ends.sort_by_key(|f| f.rom.1);
        found.extend(ends.into_iter().next());
    }

    // The boot segment ends where another raw segment, at an address the
    // linear mapping would not give it, begins, and where its own calls
    // stop agreeing with its address.
    let linear_vram = |rom_at: usize| (u64::from(boot_low) + (rom_at - CODE_OFFSET) as u64) as u32;
    found.retain(|s| {
        let inside = (CODE_OFFSET..CODE_OFFSET + run).contains(&s.rom.0);
        !(inside && s.vram & LOW28 == linear_vram(s.rom.0))
    });
    let mut boot_end = CODE_OFFSET + run;
    for segment in &found {
        if segment.rom.0 > CODE_OFFSET && segment.rom.0 < boot_end {
            boot_end = segment.rom.0;
        }
    }
    let mut exclude = vec![(boot_low, boot_low + (boot_end - CODE_OFFSET) as u32)];
    let mut outside: Vec<u32> = Probe::new(&head_words[..(boot_end - CODE_OFFSET) / 4], &[]).jal;
    for segment in found.iter().filter(|s| s.resident) {
        exclude.push(vram_range(segment.vram, segment.size));
        outside.extend(Probe::new(&be_words(&segment.bytes), &[]).jal);
    }
    outside.sort_unstable();
    outside.dedup();

    // Packed files, biggest first so resident code is placed before the
    // overlays that call into it.
    let mut streams = scan_streams(rom);
    streams.sort_by(|a, b| b.bytes.len().cmp(&a.bytes.len()).then(a.start.cmp(&b.start)));
    for stream in streams {
        let words = be_words(&stream.bytes);
        let probe = Probe::new(&words, &exclude);
        match locate(&probe, &outside) {
            Some(located) => {
                let vram = KSEG0 | located.base;
                let resident = referenced.contains(&(stream.start as u32));
                if resident || stream.bytes.len() >= RESIDENT_BYTES {
                    exclude.push(vram_range(vram, stream.bytes.len()));
                    outside.extend(probe.jal.iter().copied());
                    outside.sort_unstable();
                    outside.dedup();
                }
                found.push(Found {
                    name: format!("ovl_{:x}", stream.start),
                    rom: (stream.start, stream.end),
                    codec: stream.codec,
                    vram,
                    size: stream.bytes.len(),
                    resident,
                    hits: located.evidence.hits,
                    evidence: format!(
                        "{} stream: {} ({} calls from resident code land on entries)",
                        stream.codec.name(),
                        located.evidence.describe(),
                        located.external
                    ),
                    bytes: stream.bytes,
                });
            }
            None => refused.push(format!(
                "{} stream at {:#x} ({:#x} bytes): the bytes do not pin an address",
                stream.codec.name(),
                stream.start,
                stream.bytes.len()
            )),
        }
    }

    // Headerless deflate where the boot code points.
    let mut refs: Vec<u32> = referenced.iter().copied().collect();
    refs.sort_unstable();
    for offset in refs {
        let at = offset as usize;
        let covered = found.iter().any(|s| s.rom.0 <= at && at < s.rom.1) || (CODE_OFFSET..boot_end).contains(&at);
        if covered || rom[at] >> 1 & 3 == 3 || holds_code(&be_words(&rom[at..(at + 0x400).min(rom.len())])) {
            continue;
        }
        let Ok((bytes, used)) = Codec::Deflate.decode_extent(&rom[at..], SEGMENT_LIMIT) else { continue };
        if bytes.len() < 0x400 || bytes.len() % 4 != 0 {
            continue;
        }
        let words = be_words(&bytes);
        if !holds_code(&words) {
            continue;
        }
        let probe = Probe::new(&words, &exclude);
        match locate(&probe, &outside) {
            Some(located) => {
                let vram = KSEG0 | located.base;
                exclude.push(vram_range(vram, bytes.len()));
                found.push(Found {
                    name: format!("ovl_{at:x}"),
                    rom: (at, at + used),
                    codec: Codec::Deflate,
                    vram,
                    size: bytes.len(),
                    resident: true,
                    hits: located.evidence.hits,
                    evidence: format!("raw deflate the boot code names: {}", located.evidence.describe()),
                    bytes,
                });
            }
            None => refused.push(format!("deflate stream at {at:#x} ({:#x} bytes): the bytes do not pin an address", bytes.len())),
        }
    }

    // Overlaps in the ROM: keep the better supported, then the smaller.
    found.sort_by(|a, b| b.hits.cmp(&a.hits).then(a.size.cmp(&b.size)).then(a.rom.0.cmp(&b.rom.0)));
    let mut kept: Vec<Found> = Vec::new();
    for segment in found {
        if !kept.iter().any(|k| overlaps(k.rom, segment.rom)) {
            kept.push(segment);
        }
    }
    kept.sort_by_key(|s| s.rom.0);

    // The boot segment ends where the first segment kept inside its run
    // begins: the linear mapping is not what that run holds from there on.
    // When none does, it runs on over its data (tables, strings, floats) up
    // to the next segment that starts shortly after the code stops.
    let clipped = kept.iter().map(|s| s.rom.0).filter(|&start| start > CODE_OFFSET && start < boot_end).min();
    let boot_end = match clipped {
        Some(start) => start,
        None => kept
            .iter()
            .map(|s| s.rom.0)
            .filter(|&start| start >= boot_end && start - boot_end <= TAIL_BYTES)
            .min()
            .unwrap_or(boot_end),
    };
    let boot_rom = (CODE_OFFSET, boot_end);
    kept.retain(|s| !overlaps(s.rom, boot_rom));
    if kept.is_empty() {
        return None;
    }
    Some(Discovered { boot, boot_rom, segments: kept, refused })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A function that calls `calls` (absolute targets) and returns, then
    /// `pad` nops: ten words for two calls, as a compiler lays them out.
    fn function(calls: [u32; 2], pad: usize) -> Vec<u32> {
        let jal = |target: u32| 0x0c00_0000 | ((target & LOW28) >> 2);
        let mut words = vec![0x27bd_ffe8, 0xafbf_0014, jal(calls[0]), 0, jal(calls[1]), 0, 0x8fbf_0014, 0x27bd_0018, 0x03e0_0008, 0];
        words.extend(std::iter::repeat_n(0, pad));
        words
    }

    /// `count` functions linked at `base`, each calling two others, then a
    /// table of pointers to them when `pointers`. The functions differ in
    /// length, as real ones do, so no shifted base agrees with the code.
    pub(crate) fn blob(base: u32, count: usize, pointers: bool) -> Vec<u8> {
        let pad = |index: usize| (index * index * 3 + index * 5) % 7;
        let mut starts = Vec::new();
        let mut at = 0u32;
        for index in 0..count {
            starts.push(base + at);
            at += 4 * (10 + pad(index)) as u32;
        }
        let mut words = Vec::new();
        for index in 0..count {
            words.extend(function([starts[(index + 1) % count], starts[(index + 3) % count]], pad(index)));
        }
        if pointers {
            words.extend(starts.iter().copied());
        }
        words.iter().flat_map(|w| w.to_be_bytes()).collect()
    }

    /// Code with no calls and no pointers: nothing in it names its address.
    fn mute(count: usize) -> Vec<u8> {
        let words: Vec<u32> = (0..count).flat_map(|_| [0x27bd_ffe8u32, 0xafbf_0014, 0x8fbf_0014, 0x27bd_0018, 0x03e0_0008, 0]).collect();
        words.iter().flat_map(|w| w.to_be_bytes()).collect()
    }

    /// Yaz0 with literals only: valid for the decoder, no compression.
    pub(crate) fn yaz0(data: &[u8]) -> Vec<u8> {
        let mut out = b"Yaz0".to_vec();
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(&[0; 8]);
        for group in data.chunks(8) {
            out.push(0xff);
            out.extend_from_slice(group);
        }
        out
    }

    pub(crate) fn put(rom: &mut [u8], at: usize, bytes: &[u8]) {
        rom[at..at + bytes.len()].copy_from_slice(bytes);
    }

    pub(crate) const BOOT: u32 = 0x8000_0400;
    pub(crate) const OVERLAY: u32 = 0x8030_0000;
    pub(crate) const RAW: u32 = 0x8040_0000;

    /// A ROM with: boot code at `BOOT` (header says `header`), two packed
    /// overlays that both run at `OVERLAY`, a packed blob that is noise, a
    /// packed blob that names no address, a raw code range a table names
    /// with the right address, and one the table names with a wrong one.
    pub(crate) fn synthetic_rom(header: u32) -> Vec<u8> {
        let mut rom = vec![0u8; 0x20000];
        put(&mut rom, 0, &0x8037_1240u32.to_be_bytes());
        put(&mut rom, 8, &header.to_be_bytes());
        put(&mut rom, 0x3b, b"NSYN");
        put(&mut rom, 0x1000, &blob(BOOT, 12, false));
        put(&mut rom, 0x10000, &yaz0(&blob(OVERLAY, 8, true)));
        put(&mut rom, 0x14000, &yaz0(&blob(OVERLAY, 10, true)));
        let mut state = 0x1234_5678u32;
        let noise: Vec<u8> = (0..0x800)
            .map(|_| {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (state >> 24) as u8
            })
            .collect();
        put(&mut rom, 0x18000, &yaz0(&noise));
        put(&mut rom, 0x1c000, &yaz0(&mute(20)));
        // Raw code ranges, and a table naming them: ROM start, end, address.
        let right = blob(RAW, 9, true);
        put(&mut rom, 0x4000, &right);
        put(&mut rom, 0x6000, &blob(0x8060_0000, 9, true));
        let table: Vec<u32> = vec![0x4000, 0x4000 + right.len() as u32, RAW, 0, 0x6000, 0x6000 + right.len() as u32, 0x8050_0000];
        put(&mut rom, 0x3000, &table.iter().flat_map(|w| w.to_be_bytes()).collect::<Vec<u8>>());
        rom
    }

    #[test]
    fn evidence_pins_a_blob_to_the_address_it_was_linked_for() {
        let code = be_words(&blob(OVERLAY, 8, true));
        let probe = Probe::new(&code, &[]);
        let right = probe.evidence(OVERLAY & LOW28);
        assert_eq!((right.hits, right.calls, right.calls_ok, right.pointers), (8, 8, 8, 8));
        assert!(right.convincing());
        // The same code taken to be linked 0x10 higher agrees with nothing.
        let wrong = probe.evidence((OVERLAY & LOW28) + 0x10);
        assert!(!wrong.consistent(), "{wrong:?}");
        let located = locate(&probe, &[]).expect("the base is pinned");
        assert_eq!(KSEG0 | located.base, OVERLAY);
        // A caller in resident code is evidence of the nibble too; code that
        // carries no 0x80-prefixed word and no constant needs one.
        let calls_only = be_words(&blob(OVERLAY, 8, false));
        let probe = Probe::new(&calls_only, &[]);
        assert!(locate(&probe, &[]).is_none(), "a jal does not carry the top nibble");
        let caller = [(OVERLAY & LOW28)];
        assert_eq!(KSEG0 | locate(&probe, &caller).expect("resident caller").base, OVERLAY);
    }

    #[test]
    fn discovery_places_what_the_bytes_prove_and_nothing_else() {
        let rom = synthetic_rom(BOOT);
        let found = discover(&rom).expect("layout");
        assert_eq!(found.boot, u64::from(BOOT));
        let placed: Vec<(usize, u32, &str)> = found.segments.iter().map(|s| (s.rom.0, s.vram, s.codec.name())).collect();
        assert_eq!(
            placed,
            [(0x4000, RAW, "raw"), (0x10000, OVERLAY, "yaz0"), (0x14000, OVERLAY, "yaz0")],
            "{:#?} {:#?}",
            found.segments.iter().map(|s| &s.evidence).collect::<Vec<_>>(),
            found.refused
        );
        // The noise, the mute code and the table's wrong address stay unplaced.
        assert!(found.segments.iter().all(|s| ![0x6000, 0x18000, 0x1c000].contains(&s.rom.0)));
        assert!(found.refused.iter().any(|r| r.contains("0x1c000")), "{:?}", found.refused);
        // The two overlays share an address; the raw range does not.
        assert_eq!(found.clashes(), [false, false, true, true]);
        // The boot segment is the run of code (0x1000..0x1400) and the data
        // after it up to the first segment found (the raw range at 0x4000),
        // not the whole ROM.
        assert_eq!(found.boot_rom, (0x1000, 0x4000));
        // And the layout it describes carries the packed parts.
        let layout = found.layout(&rom);
        assert_eq!(layout.segments[1].parts[0].codec, Codec::Raw);
        assert_eq!(layout.segments[2].place, Place::At(u64::from(OVERLAY)));
        assert_eq!(layout.segments[2].parts[0].codec, Codec::Yaz0);
    }

    #[test]
    fn the_entry_point_is_the_one_the_boot_code_agrees_with() {
        // Header word 0x100000 above the address the code is linked for, as a
        // CIC 6103 cartridge writes it.
        let rom = synthetic_rom(BOOT + 0x10_0000);
        assert_eq!(entry_address(&rom, u64::from(BOOT + 0x10_0000)), u64::from(BOOT));
        assert_eq!(discover(&rom).expect("layout").boot, u64::from(BOOT));
        // Code that agrees with none of them keeps the header's word.
        let mut stub = vec![0u8; 0x2000];
        put(&mut stub, 0x1000, &mute(30));
        assert_eq!(entry_address(&stub, 0x8010_0400), 0x8010_0400);
    }

    #[test]
    fn a_rom_with_nothing_proven_has_no_layout() {
        let mut rom = vec![0u8; 0x8000];
        put(&mut rom, 0, &0x8037_1240u32.to_be_bytes());
        put(&mut rom, 8, &BOOT.to_be_bytes());
        put(&mut rom, 0x1000, &blob(BOOT, 12, false));
        assert!(discover(&rom).is_none());
    }

    /// Prints what discovery finds in the ROM `N64_ROM` names, as JSON lines.
    #[test]
    #[ignore = "needs a ROM: N64_ROM=path cargo test layout_report -- --ignored --nocapture"]
    fn layout_report() {
        let path = std::env::var("N64_ROM").expect("N64_ROM");
        let rom = std::fs::read(path).expect("ROM");
        let started = std::time::Instant::now();
        let found = discover(&rom);
        let seconds = started.elapsed().as_secs_f64();
        match found {
            None => println!("{{\"discovered\":false,\"seconds\":{seconds:.2}}}"),
            Some(found) => {
                println!(
                    "{{\"discovered\":true,\"seconds\":{seconds:.2},\"boot\":\"{:#x}\",\"boot_rom\":[\"{:#x}\",\"{:#x}\"],\"segments\":{},\"refused\":{}}}",
                    found.boot, found.boot_rom.0, found.boot_rom.1, found.segments.len(), found.refused.len()
                );
                let clashes = found.clashes();
                for (index, s) in found.segments.iter().enumerate() {
                    println!(
                        "SEG {{\"name\":\"{}\",\"rom\":[\"{:#x}\",\"{:#x}\"],\"codec\":\"{}\",\"vram\":\"{:#x}\",\"size\":\"{:#x}\",\"resident\":{},\"clash\":{},\"hits\":{},\"evidence\":\"{}\"}}",
                        s.name, s.rom.0, s.rom.1, s.codec.name(), s.vram, s.size, s.resident, clashes[index + 1], s.hits, s.evidence
                    );
                }
            }
        }
    }
}
