//! PS2 VIF MPG/MSCAL code finder + VU-micro decode parity (P4.5).
//!
//! Two parts, one file:
//!
//! * **(a) VIF finder.** A PS2 image carries VU-micro programs inside VIF
//!   DMA streams: a `MPG` VIFcode uploads `NUM` 64-bit micro-instructions
//!   to VU micro memory at `IMM`, and `MSCAL`/`MSCALF` starts execution at
//!   an `IMM` micro address. Stock tools leave those uploaded blobs as
//!   data. [`scan_vif`] finds the upload blobs and the call sites so a
//!   loader can mark the blobs as code (vs data) and seed functions at
//!   the called micro addresses.
//! * **(b) VU-micro decode parity.** [`decode_upper`]/[`decode_lower`]/
//!   [`decode_liw`] classify every 64-bit LIW with the documented VU-micro
//!   encoding (upper vector-FP pipe + lower integer/branch pipe, `I` bit
//!   selecting `LOI`). The tables mirror `native/languages/vu/vu.slaspec`
//!   bit for bit; the tests sweep the opcode spaces exhaustively and pin
//!   hand-computed vectors from the documented encoding.
//!
//! Format facts (public constants, never GPL code):
//!
//! * VIFcode is one little-endian 32-bit word: `IMM` bits 0-15, `NUM`
//!   bits 16-23, `CMD` bits 24-30, interrupt flag bit 31. Command numbers
//!   (`MPG = 0x4A`, `MSCAL = 0x14`, `MSCALF = 0x15`, `MSCNT = 0x17`, …)
//!   are the documented VIF set (PS2Tek VIF reference, Unlicense;
//!   ps2sdk `vif.h`, AFL).
//! * `MPG`: `IMM` is the first VU micro-memory word (8-byte units;
//!   VU0 holds 512, VU1 holds 2048), `NUM` is the microword count with
//!   `0` encoding 256, and `NUM * 8` payload bytes follow the VIFcode.
//! * `MSCAL`/`MSCALF`: `IMM` is the micro entry address, `NUM` is 0.
//! * VU-micro LIW: bits 0-31 are the lower word, bits 32-63 the upper
//!   word. Upper primary opcode is upper bits 0-5 (special when bits 2-5
//!   read `0xF`, sub-op `low2 | high5 << 2`); lower uses upper-bit-31 = 0
//!   group (`l_op2` = bits 25-30) vs bit-31 = 1 group (`l_op` = bits 0-5,
//!   special on the same `0xF` trigger). Upper bit 31 is the `I` bit:
//!   the lower word is then a 32-bit `LOI` immediate, not an instruction.
//!
//! The finder scans rather than walks DMA chains: without the EE DMA tags
//! a stream start is not recoverable statically, so every 4-aligned word
//! is tested as a VIFcode and an `MPG` candidate only survives when its
//! whole payload decodes as VU-micro code. Random data essentially never
//! passes a multi-LIW all-valid gate, which is the code-vs-data verdict.

/// VIF transfer commands.
pub const VIF_CMD_NOP: u8 = 0x00;
pub const VIF_CMD_STCYCL: u8 = 0x01;
pub const VIF_CMD_OFFSET: u8 = 0x02;
pub const VIF_CMD_BASE: u8 = 0x03;
pub const VIF_CMD_ITOP: u8 = 0x04;
pub const VIF_CMD_STMOD: u8 = 0x05;
pub const VIF_CMD_MSKPATH3: u8 = 0x06;
pub const VIF_CMD_MARK: u8 = 0x07;
pub const VIF_CMD_FLUSHE: u8 = 0x10;
pub const VIF_CMD_FLUSH: u8 = 0x11;
pub const VIF_CMD_FLUSHA: u8 = 0x13;
/// Start VU-micro execution at `IMM`.
pub const VIF_CMD_MSCAL: u8 = 0x14;
/// Start VU-micro execution at `IMM` after flushing the path.
pub const VIF_CMD_MSCALF: u8 = 0x15;
/// Resume VU-micro execution (no address).
pub const VIF_CMD_MSCNT: u8 = 0x17;
pub const VIF_CMD_STMASK: u8 = 0x20;
pub const VIF_CMD_STROW: u8 = 0x30;
pub const VIF_CMD_STCOL: u8 = 0x31;
/// Upload `NUM` microwords to VU micro memory at `IMM`.
pub const VIF_CMD_MPG: u8 = 0x4A;
pub const VIF_CMD_DIRECT: u8 = 0x50;
pub const VIF_CMD_DIRECTHL: u8 = 0x51;
/// Base of the UNPACK family (`0x60 | m << 4 | vn << 2 | vl`).
pub const VIF_CMD_UNPACK_BASE: u8 = 0x60;

/// VU0 micro memory: 4 KiB = 512 eight-byte instructions.
pub const VU0_MICRO_INSNS: u32 = 512;
/// VU1 micro memory: 16 KiB = 2048 eight-byte instructions.
pub const VU1_MICRO_INSNS: u32 = 2048;

/// Which VIF path (and so which VU micro memory) an image is scanned for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VifChannel {
    /// VIF0 feeds VU0 (512 microwords).
    Vif0,
    /// VIF1 feeds VU1 (2048 microwords).
    Vif1,
}

impl VifChannel {
    /// Micro-memory capacity in 8-byte instructions.
    pub fn micro_insns(self) -> u32 {
        match self {
            VifChannel::Vif0 => VU0_MICRO_INSNS,
            VifChannel::Vif1 => VU1_MICRO_INSNS,
        }
    }
}

/// One decoded VIFcode word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VifCode {
    /// Interrupt flag (bit 31).
    pub irq: bool,
    /// 7-bit command (bits 24-30).
    pub cmd: u8,
    /// Element count (bits 16-23); `0` encodes 256 for data commands.
    pub num: u8,
    /// Immediate / address (bits 0-15).
    pub imm: u16,
}

/// Split a little-endian VIFcode word into its fields.
pub fn parse_vifcode(word: u32) -> VifCode {
    VifCode {
        imm: (word & 0xFFFF) as u16,
        num: ((word >> 16) & 0xFF) as u8,
        cmd: ((word >> 24) & 0x7F) as u8,
        irq: word >> 31 != 0,
    }
}

/// `NUM` field with the documented `0 == 256` rule applied.
pub fn vif_count(num: u8) -> u32 {
    if num == 0 { 256 } else { num as u32 }
}

/// Documented VIF command name, if `cmd` is a fixed (non-UNPACK) command.
pub fn cmd_name(cmd: u8) -> Option<&'static str> {
    Some(match cmd {
        0x00 => "nop",
        0x01 => "stcycl",
        0x02 => "offset",
        0x03 => "base",
        0x04 => "itop",
        0x05 => "stmod",
        0x06 => "mskpath3",
        0x07 => "mark",
        0x10 => "flushe",
        0x11 => "flush",
        0x13 => "flusha",
        0x14 => "mscal",
        0x15 => "mscalf",
        0x17 => "mscnt",
        0x20 => "stmask",
        0x30 => "strow",
        0x31 => "stcol",
        0x4A => "mpg",
        0x50 => "direct",
        0x51 => "directhl",
        _ => return None,
    })
}

/// True for the `0x60-0x7F` UNPACK family.
pub fn is_unpack(cmd: u8) -> bool {
    cmd & 0x60 == 0x60
}

/// 32-bit input words one UNPACK packet consumes, or `None` when `cmd`
/// is not an UNPACK or its `vl` field (bits 1-0) is the reserved `0b11`.
///
/// Encoding `0x60 | m << 4 | vn << 2 | vl`: `vn + 1` vectors per element,
/// `vl` selecting 32/16/8-bit elements (`0/1/2`). Input size is the
/// packed element count rounded up to whole words; masking (`m`) changes
/// which lanes retire, not how much input is consumed.
pub fn unpack_input_words(cmd: u8, num: u8) -> Option<usize> {
    if !is_unpack(cmd) {
        return None;
    }
    let vn = ((cmd >> 2) & 3) as usize;
    let elements = vif_count(num) as usize * (vn + 1);
    Some(match cmd & 3 {
        0 => elements,
        1 => elements.div_ceil(2),
        2 => elements.div_ceil(4),
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// VU-micro decode (mirrors native/languages/vu/vu.slaspec).
// ---------------------------------------------------------------------------

/// Upper-pipe special sub-op: `(sopl, soph)` with `sopl = op & 3` and
/// `soph = (word >> 6) & 0x1F`, taken when upper bits 2-5 read `0xF`.
fn upper_special(sopl: u32, soph: u32) -> Option<&'static str> {
    Some(match (soph, sopl) {
        (0x00, _) => "addabc",
        (0x01, _) => "subabc",
        (0x02, _) => "maddabc",
        (0x03, _) => "msubabc",
        (0x04, 0) => "itof0",
        (0x04, 1) => "itof4",
        (0x04, 2) => "itof12",
        (0x04, 3) => "itof15",
        (0x05, 0) => "ftoi0",
        (0x05, 1) => "ftoi4",
        (0x05, 2) => "ftoi12",
        (0x05, 3) => "ftoi15",
        (0x06, _) => "mulabc",
        (0x07, 0) => "mulaq",
        (0x07, 1) => "abs",
        (0x07, 2) => "mulai",
        (0x07, 3) => "clip",
        (0x08, 0) => "addaq",
        (0x08, 1) => "maddaq",
        (0x08, 2) => "addai",
        (0x08, 3) => "maddai",
        (0x09, 1) => "msubaq",
        (0x09, 2) => "subai",
        (0x09, 3) => "msubai",
        (0x0A, 0) => "adda",
        (0x0A, 1) => "madda",
        (0x0A, 2) => "mula",
        (0x0B, 0) => "suba",
        (0x0B, 1) => "msuba",
        (0x0B, 2) => "opmula",
        (0x0B, 3) => "nop",
        _ => return None,
    })
}

/// Classify an upper-pipe word: the FMAC/broadcast mnemonic, or `None`
/// for a reserved encoding.
pub fn decode_upper(word: u32) -> Option<&'static str> {
    let op = word & 0x3F;
    if (op >> 2) & 0xF == 0xF {
        return upper_special(op & 3, (word >> 6) & 0x1F);
    }
    Some(match op {
        0x00..=0x03 => "addbc",
        0x04..=0x07 => "subbc",
        0x08..=0x0B => "maddbc",
        0x0C..=0x0F => "msubbc",
        0x10..=0x13 => "maxbc",
        0x14..=0x17 => "minibc",
        0x18..=0x1B => "mulbc",
        0x1C => "mulq",
        0x1D => "maxi",
        0x1E => "muli",
        0x1F => "minii",
        0x20 => "addq",
        0x21 => "maddq",
        0x22 => "addi",
        0x23 => "maddi",
        0x24 => "subq",
        0x25 => "msubq",
        0x26 => "subi",
        0x27 => "msubi",
        0x28 => "add",
        0x29 => "madd",
        0x2A => "mul",
        0x2B => "max",
        0x2C => "sub",
        0x2D => "msub",
        0x2E => "opmsub",
        0x2F => "mini",
        // Documented reserved-but-NOP upper primaries.
        0x30..=0x3B => "nop",
        _ => return None,
    })
}

/// Lower-pipe special sub-op: `(soph, sopl)` with `soph = (word >> 6) &
/// 0x1F`, `sopl = word & 3`, taken when bit 31 is set and bits 2-5 read
/// `0xF`.
fn lower_special(soph: u32, sopl: u32) -> Option<&'static str> {
    Some(match (soph, sopl) {
        (0x0C, 0) => "move",
        (0x0C, 1) => "mr32",
        (0x0D, 0) => "lqi",
        (0x0D, 1) => "sqi",
        (0x0D, 2) => "lqd",
        (0x0D, 3) => "sqd",
        (0x0E, 0) => "div",
        (0x0E, 1) => "sqrt",
        (0x0E, 2) => "rsqrt",
        (0x0E, 3) => "waitq",
        (0x0F, 0) => "mtir",
        (0x0F, 1) => "mfir",
        (0x0F, 2) => "ilwr",
        (0x0F, 3) => "iswr",
        (0x10, 0) => "rnext",
        (0x10, 1) => "rget",
        (0x10, 2) => "rinit",
        (0x10, 3) => "rxor",
        (0x19, 0) => "mfp",
        (0x1A, 0) => "xtop",
        (0x1A, 1) => "xitop",
        (0x1B, 0) => "xgkick",
        (0x1C, 0) => "esadd",
        (0x1C, 1) => "ersadd",
        (0x1C, 2) => "eleng",
        (0x1C, 3) => "erleng",
        (0x1D, 0) => "eatanxy",
        (0x1D, 1) => "eatanxz",
        (0x1D, 2) => "esum",
        (0x1E, 0) => "esqrt",
        (0x1E, 1) => "ersqrt",
        (0x1E, 2) => "ercpr",
        (0x1E, 3) => "waitp",
        (0x1F, 0) => "esin",
        (0x1F, 1) => "eatan",
        (0x1F, 2) => "eexp",
        (0x1F, 3) => "nop",
        _ => return None,
    })
}

/// Classify a lower-pipe word, or `None` for a reserved encoding.
/// (When the upper `I` bit is set the lower word is an `LOI` immediate
/// and must not be passed here — see [`decode_liw`].)
pub fn decode_lower(word: u32) -> Option<&'static str> {
    if word >> 31 == 0 {
        return Some(match (word >> 25) & 0x3F {
            0x00 => "lq",
            0x01 => "sq",
            0x04 => "ilw",
            0x05 => "isw",
            0x08 => "iaddiu",
            0x09 => "isubiu",
            0x10 => "fceq",
            0x11 => "fcset",
            0x12 => "fcand",
            0x13 => "fcor",
            0x14 => "fseq",
            0x15 => "fsset",
            0x16 => "fsand",
            0x17 => "fsor",
            0x18 => "fmeq",
            0x1A => "fmand",
            0x1B => "fmor",
            0x1C => "fcget",
            0x20 => "b",
            0x21 => "bal",
            0x24 => "jr",
            0x25 => "jalr",
            0x28 => "ibeq",
            0x29 => "ibne",
            0x2C => "ibltz",
            0x2D => "ibgtz",
            0x2E => "iblez",
            0x2F => "ibgez",
            _ => return None,
        });
    }
    let op = word & 0x3F;
    if (op >> 2) & 0xF == 0xF {
        return lower_special((word >> 6) & 0x1F, word & 3);
    }
    Some(match op {
        0x30 => "iadd",
        0x31 => "isub",
        0x32 => "iaddi",
        0x34 => "iand",
        0x35 => "ior",
        // Documented reserved-but-NOP lower primaries (bit31 group).
        0x00 | 0x33 | 0x36..=0x3B => "nop",
        _ => return None,
    })
}

/// Decode one 64-bit VU-micro LIW (`lower | upper << 32`) to its
/// `(upper, lower)` mnemonics, or `None` when either pipe is reserved.
/// An `I`-bit upper makes the lower word an `LOI` immediate, which is
/// always a valid pairing when the upper itself decodes.
pub fn decode_liw(liw: u64) -> Option<(&'static str, &'static str)> {
    let lower = liw as u32;
    let upper = (liw >> 32) as u32;
    let up = decode_upper(upper)?;
    if upper >> 31 != 0 {
        return Some((up, "loi"));
    }
    Some((up, decode_lower(lower)?))
}

/// The code-vs-data verdict for one LIW: both pipes decode (with the
/// `LOI` rule), so the word is plausibly VU-micro code.
pub fn liw_is_code(liw: u64) -> bool {
    decode_liw(liw).is_some()
}

// ---------------------------------------------------------------------------
// Finder.
// ---------------------------------------------------------------------------

/// One validated `MPG` upload: a VU-micro blob that decoded as code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MpgBlob {
    /// File offset of the `MPG` VIFcode word.
    pub file_off: usize,
    /// Virtual address of the `MPG` VIFcode word (`base_vaddr + file_off`).
    pub vaddr: u64,
    /// First VU micro-memory word uploaded (`IMM`).
    pub vu_base: u32,
    /// Uploaded microword count (`NUM`, with `0 == 256` applied).
    pub count: u32,
    /// File offset of the first payload LIW (always `file_off + 4`).
    pub payload_off: usize,
    /// An `MSCAL`/`MSCALF` in the image targets inside this blob.
    pub called: bool,
}

impl MpgBlob {
    /// Payload span as `(vaddr, len)` over the image mapping: the range
    /// a loader marks as VU-micro code.
    pub fn code_span(&self, base_vaddr: u64) -> (u64, u64) {
        (
            base_vaddr + self.payload_off as u64,
            self.count as u64 * 8,
        )
    }
}

/// One `MSCAL`/`MSCALF` microprogram call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MscalCall {
    /// File offset of the call's VIFcode word.
    pub file_off: usize,
    /// Virtual address of the call's VIFcode word.
    pub vaddr: u64,
    /// Called VU micro-memory word (`IMM`).
    pub vu_target: u32,
    /// True for `MSCALF` (flush variant), false for `MSCAL`.
    pub flush: bool,
}

/// Result of [`scan_vif`]: uploaded code blobs plus their call sites.
/// Every address outside the blobs is data as far as the VIF stream is
/// concerned.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VifScan {
    /// Validated uploads, sorted by file offset, non-overlapping.
    pub blobs: Vec<MpgBlob>,
    /// Microprogram calls, sorted by file offset.
    pub calls: Vec<MscalCall>,
}

impl VifScan {
    /// Payload spans `(vaddr, len)` of every blob: the code ranges.
    pub fn code_spans(&self, base_vaddr: u64) -> Vec<(u64, u64)> {
        self.blobs
            .iter()
            .map(|blob| blob.code_span(base_vaddr))
            .collect()
    }
}

fn word_at(image: &[u8], off: usize) -> Option<u32> {
    image
        .get(off..off + 4)
        .map(|slice| u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn liw_at(image: &[u8], off: usize) -> Option<u64> {
    image
        .get(off..off + 8)
        .map(|slice| u64::from_le_bytes(slice.try_into().expect("8-byte slice")))
}

/// Scan `image` (loaded at `base_vaddr`) for VIF `MPG` uploads of
/// `channel`'s VU and `MSCAL`/`MSCALF` calls.
///
/// An `MPG` candidate survives only when the upload fits the channel's
/// micro memory, its payload fits the image, and **every** payload LIW
/// decodes as VU-micro code — that all-valid gate is what marks the blob
/// as code vs data. Blobs are deduplicated so a candidate starting inside
/// an accepted blob's span is dropped.
pub fn scan_vif(image: &[u8], base_vaddr: u64, channel: VifChannel) -> VifScan {
    let mem = channel.micro_insns();
    let mut scan = VifScan::default();

    // MSCAL pass: fixed-size codes, no payload to validate.
    let mut off = 0;
    while off + 4 <= image.len() {
        if let Some(word) = word_at(image, off) {
            let code = parse_vifcode(word);
            if (code.cmd == VIF_CMD_MSCAL || code.cmd == VIF_CMD_MSCALF)
                && code.num == 0
                && (code.imm as u32) < mem
            {
                scan.calls.push(MscalCall {
                    file_off: off,
                    vaddr: base_vaddr + off as u64,
                    vu_target: code.imm as u32,
                    flush: code.cmd == VIF_CMD_MSCALF,
                });
            }
        }
        off += 4;
    }

    // MPG pass: validate bounds, then the payload, then deduplicate.
    let mut blobs: Vec<MpgBlob> = Vec::new();
    let mut off = 0;
    while off + 4 <= image.len() {
        let Some(word) = word_at(image, off) else {
            break;
        };
        let code = parse_vifcode(word);
        if code.cmd == VIF_CMD_MPG {
            let count = vif_count(code.num);
            let vu_base = code.imm as u32;
            let payload_off = off + 4;
            let payload_len = count as usize * 8;
            let fits_vu = vu_base < mem
                && count <= mem
                && vu_base.checked_add(count).is_some_and(|end| end <= mem);
            let fits_image = payload_off
                .checked_add(payload_len)
                .is_some_and(|end| end <= image.len());
            if fits_vu && fits_image {
                let mut at = payload_off;
                let mut valid = true;
                while at < payload_off + payload_len {
                    let Some(liw) = liw_at(image, at) else {
                        valid = false;
                        break;
                    };
                    if !liw_is_code(liw) {
                        valid = false;
                        break;
                    }
                    at += 8;
                }
                if valid {
                    blobs.push(MpgBlob {
                        file_off: off,
                        vaddr: base_vaddr + off as u64,
                        vu_base,
                        count,
                        payload_off,
                        called: false,
                    });
                }
            }
        }
        off += 4;
    }

    // Dedup: keep earliest; drop candidates inside an accepted span.
    blobs.sort_by_key(|blob| blob.file_off);
    let mut end = 0usize;
    for blob in blobs {
        let span_end = blob.payload_off + blob.count as usize * 8;
        if blob.file_off < end {
            continue;
        }
        end = span_end;
        scan.blobs.push(blob);
    }

    // Cross-reference calls into uploads.
    for blob in &mut scan.blobs {
        let top = blob.vu_base + blob.count;
        blob.called = scan
            .calls
            .iter()
            .any(|call| (blob.vu_base..top).contains(&call.vu_target));
    }
    scan
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word(cmd: u8, num: u8, imm: u16) -> u32 {
        (imm as u32) | ((num as u32) << 16) | ((cmd as u32) << 24)
    }

    fn liw(lower: u32, upper: u32) -> u64 {
        (lower as u64) | ((upper as u64) << 32)
    }

    /// Upper `ADD.xyzw vf1, vf2, vf3` + lower `LQ`.
    fn add_lq() -> u64 {
        let upper = 0x28 | (1 << 6) | (2 << 11) | (3 << 16) | (0xF << 21);
        let lower = (1 << 16) | (2 << 11);
        liw(lower, upper)
    }

    /// Canonical `NOP` pair: upper `nop` + lower `nop`.
    fn nop_pair() -> u64 {
        liw(0x8000_07FF, 0x2FF)
    }

    fn push_word(image: &mut Vec<u8>, word: u32) {
        image.extend_from_slice(&word.to_le_bytes());
    }

    fn push_liw(image: &mut Vec<u8>, value: u64) {
        image.extend_from_slice(&value.to_le_bytes());
    }

    /// Synthetic VIF stream: NOP, MPG upload of two LIWs, MSCAL to its
    /// base, then unrelated data words.
    fn stream() -> Vec<u8> {
        let mut image = Vec::new();
        push_word(&mut image, word(VIF_CMD_NOP, 0, 0));
        push_word(&mut image, word(VIF_CMD_MPG, 2, 0));
        push_liw(&mut image, add_lq());
        push_liw(&mut image, nop_pair());
        push_word(&mut image, word(VIF_CMD_MSCAL, 0, 0));
        push_word(&mut image, 0xDEAD_BEEF);
        push_word(&mut image, 0xFFFF_FFFF);
        image
    }

    #[test]
    fn vifcode_fields_split_as_documented() {
        let code = parse_vifcode(0x8000_0000 | word(VIF_CMD_MPG, 2, 0x10));
        assert!(code.irq);
        assert_eq!(code.cmd, VIF_CMD_MPG);
        assert_eq!(code.num, 2);
        assert_eq!(code.imm, 0x10);
        // NUM = 0 encodes 256.
        assert_eq!(vif_count(0), 256);
        assert_eq!(vif_count(3), 3);
    }

    #[test]
    fn mpg_upload_marks_the_blob_and_mscal_confirms_the_call() {
        let image = stream();
        let scan = scan_vif(&image, 0x1000_0000, VifChannel::Vif0);
        assert_eq!(scan.blobs.len(), 1, "one upload blob: {scan:?}");
        let blob = &scan.blobs[0];
        assert_eq!(blob.file_off, 4);
        assert_eq!(blob.vaddr, 0x1000_0004);
        assert_eq!(blob.vu_base, 0);
        assert_eq!(blob.count, 2);
        assert_eq!(blob.payload_off, 8);
        assert!(blob.called, "MSCAL 0 targets the blob");
        assert_eq!(blob.code_span(0x1000_0000), (0x1000_0008, 16));

        assert_eq!(scan.calls.len(), 1, "one call: {scan:?}");
        assert_eq!(
            scan.calls[0],
            MscalCall {
                file_off: 24,
                vaddr: 0x1000_0018,
                vu_target: 0,
                flush: false,
            }
        );
        // The trailing data words are data: no second blob, no call.
        assert_eq!(scan.code_spans(0x1000_0000), vec![(0x1000_0008, 16)]);
    }

    #[test]
    fn mpg_with_a_data_payload_is_left_as_data() {
        // Same framing, but the "payload" is not VU-micro code.
        let mut image = Vec::new();
        push_word(&mut image, word(VIF_CMD_MPG, 2, 0));
        // Payload LIWs whose lower pipe is a reserved encoding (op2 0x03):
        // not VU-micro code, so the upload stays data.
        push_liw(&mut image, liw(0x0600_0000, 0x0000_02FF));
        push_liw(&mut image, liw(0x0600_0000, 0x0000_02FF));
        let scan = scan_vif(&image, 0, VifChannel::Vif0);
        assert!(scan.blobs.is_empty(), "data is not code: {scan:?}");
    }

    #[test]
    fn mpg_bounds_are_checked_against_channel_and_image() {
        // Upload past the end of VU0 micro memory.
        let mut image = Vec::new();
        push_word(&mut image, word(VIF_CMD_MPG, 20, 500));
        for _ in 0..20 {
            push_liw(&mut image, nop_pair());
        }
        assert!(scan_vif(&image, 0, VifChannel::Vif0).blobs.is_empty());
        // Same upload fits VU1.
        let scan = scan_vif(&image, 0, VifChannel::Vif1);
        assert_eq!(scan.blobs.len(), 1);

        // Truncated payload (claims 2 LIWs, holds 1).
        let mut short = Vec::new();
        push_word(&mut short, word(VIF_CMD_MPG, 2, 0));
        push_liw(&mut short, nop_pair());
        assert!(scan_vif(&short, 0, VifChannel::Vif0).blobs.is_empty());

        // MSCAL past micro memory is ignored on both channels.
        let mut call = Vec::new();
        push_word(&mut call, word(VIF_CMD_MSCAL, 0, 900));
        assert!(scan_vif(&call, 0, VifChannel::Vif0).calls.is_empty());
        assert_eq!(scan_vif(&call, 0, VifChannel::Vif1).calls.len(), 1);
    }

    #[test]
    fn mscalf_sets_the_flush_variant() {
        let mut image = Vec::new();
        push_word(&mut image, word(VIF_CMD_MSCALF, 0, 8));
        let scan = scan_vif(&image, 0, VifChannel::Vif0);
        assert_eq!(scan.calls.len(), 1);
        assert!(scan.calls[0].flush);
        assert_eq!(scan.calls[0].vu_target, 8);
    }

    #[test]
    fn spot_vectors_match_the_documented_encoding() {
        // (word, expected mnemonic): hand-computed from the documented
        // VU-micro encoding, not from the tables under test.
        let upper: &[(u32, &str)] = &[
            (0x0000_02FF, "nop"),    // upper nop: op 0x3F, fd 0x0B
            (0x01E3_1068, "add"),    // ADD.xyzw vf1, vf2, vf3
            (0x01E3_1040, "addbc"),  // ADDx.xyzw vf1, vf2, vf3[x]
            (0x01E0_105C, "mulq"),   // MULq.xyzw vf1, vf2
            (0x0000_02FE, "opmula"), // OPMULA: special (0x0B, 2)
            (0x0000_013C, "itof0"),  // ITOF0: special (0x04, 0)
            (0x0000_0030, "nop"),    // reserved-but-NOP primary
        ];
        for &(encoding, name) in upper {
            assert_eq!(decode_upper(encoding), Some(name), "{encoding:#010x}");
        }
        let lower: &[(u32, &str)] = &[
            (0x0001_1000, "lq"),
            (0x0201_1000, "sq"),
            (0x4000_0004, "b"),
            (0x4800_1800, "jr"),
            (0x8000_0030, "iadd"),
            (0x8000_03BC, "div"), // lower special (0x0E, 0)
            (0x8000_067C, "mfp"), // lower special (0x19, 0)
            (0x8000_07FF, "nop"), // lower nop: special (0x1F, 3)
            (0x8000_0000, "nop"), // reserved-but-NOP primary, bit31 group
        ];
        for &(encoding, name) in lower {
            assert_eq!(decode_lower(encoding), Some(name), "{encoding:#010x}");
        }
        // I-bit upper pairs with anything as LOI.
        assert_eq!(decode_liw(liw(0xDEAD_BEEF, 0xC000_02FF)), Some(("nop", "loi")));
        // Reserved halves fail the LIW.
        assert_eq!(decode_liw(liw(0x0600_0000, 0x2FF)), None); // lower op2 0x03: reserved
        assert_eq!(decode_liw(liw(0x0400_0000, 0x2FF)), None); // lower op2 0x02: reserved
        assert_eq!(decode_liw(liw(0x8000_07FF, 0x0000_043C)), None); // upper special (0x10, 0): reserved
    }

    #[test]
    fn opcode_sweep_matches_the_documented_tables() {
        // Exhaustive over the opcode spaces (not over register fields):
        // every upper primary with zeroed fields, every lower primary in
        // both bit31 groups, and every special sub-op pair.
        let upper_plain: [Option<&str>; 64] = [
            Some("addbc"), Some("addbc"), Some("addbc"), Some("addbc"), // 00-03
            Some("subbc"), Some("subbc"), Some("subbc"), Some("subbc"), // 04-07
            Some("maddbc"), Some("maddbc"), Some("maddbc"), Some("maddbc"), // 08-0B
            Some("msubbc"), Some("msubbc"), Some("msubbc"), Some("msubbc"), // 0C-0F
            Some("maxbc"), Some("maxbc"), Some("maxbc"), Some("maxbc"), // 10-13
            Some("minibc"), Some("minibc"), Some("minibc"), Some("minibc"), // 14-17
            Some("mulbc"), Some("mulbc"), Some("mulbc"), Some("mulbc"), // 18-1B
            Some("mulq"), Some("maxi"), Some("muli"), Some("minii"), // 1C-1F
            Some("addq"), Some("maddq"), Some("addi"), Some("maddi"), // 20-23
            Some("subq"), Some("msubq"), Some("subi"), Some("msubi"), // 24-27
            Some("add"), Some("madd"), Some("mul"), Some("max"), // 28-2B
            Some("sub"), Some("msub"), Some("opmsub"), Some("mini"), // 2C-2F
            Some("nop"), Some("nop"), Some("nop"), Some("nop"), // 30-33
            Some("nop"), Some("nop"), Some("nop"), Some("nop"), // 34-37
            Some("nop"), Some("nop"), Some("nop"), Some("nop"), // 38-3B
            None, None, None, None, // 3C-3F: special trigger, decided below
        ];
        for op in 0..64u32 {
            let got = decode_upper(op);
            if op < 0x3C {
                assert_eq!(got, upper_plain[op as usize], "upper {op:#04x}");
            } else {
                // Zeroed fields give (sopl = op & 3, soph = 0): addabc.
                assert_eq!(got, Some("addabc"), "upper {op:#04x}");
            }
        }

        // Lower bit31 = 0 group: full 6-bit op2 space.
        let mut lower0: [Option<&str>; 64] = [None; 64];
        for (op, name) in [
            (0x00, "lq"), (0x01, "sq"), (0x04, "ilw"), (0x05, "isw"),
            (0x08, "iaddiu"), (0x09, "isubiu"), (0x10, "fceq"), (0x11, "fcset"),
            (0x12, "fcand"), (0x13, "fcor"), (0x14, "fseq"), (0x15, "fsset"),
            (0x16, "fsand"), (0x17, "fsor"), (0x18, "fmeq"), (0x1A, "fmand"),
            (0x1B, "fmor"), (0x1C, "fcget"), (0x20, "b"), (0x21, "bal"),
            (0x24, "jr"), (0x25, "jalr"), (0x28, "ibeq"), (0x29, "ibne"),
            (0x2C, "ibltz"), (0x2D, "ibgtz"), (0x2E, "iblez"), (0x2F, "ibgez"),
        ] {
            lower0[op] = Some(name);
        }
        for op in 0..64u32 {
            assert_eq!(
                decode_lower(op << 25),
                lower0[op as usize],
                "lower0 {op:#04x}"
            );
        }

        // Lower bit31 = 1 group: full 6-bit primary space.
        for op in 0..64u32 {
            let encoding = 0x8000_0000 | op;
            let trigger = (op >> 2) & 0xF == 0xF;
            let expected = if trigger {
                lower_special((encoding >> 6) & 0x1F, encoding & 3)
            } else {
                match op {
                    0x30 => Some("iadd"),
                    0x31 => Some("isub"),
                    0x32 => Some("iaddi"),
                    0x34 => Some("iand"),
                    0x35 => Some("ior"),
                    0x00 | 0x33 | 0x36..=0x3B => Some("nop"),
                    _ => None,
                }
            };
            assert_eq!(decode_lower(encoding), expected, "lower1 {op:#04x}");
        }

        // Upper special space, exhaustively: every (soph, sopl) pair.
        for soph in 0..32u32 {
            for sopl in 0..4u32 {
                let encoding = 0x3Cu32 | sopl | (soph << 6);
                assert_eq!(
                    decode_upper(encoding),
                    upper_special(sopl, soph),
                    "upper special ({soph:#04x}, {sopl})"
                );
            }
        }
        // Lower special space, exhaustively: every (soph, sopl) pair.
        for soph in 0..32u32 {
            for sopl in 0..4u32 {
                let encoding = 0x8000_0000 | 0x3C | sopl | (soph << 6);
                assert_eq!(
                    decode_lower(encoding),
                    lower_special(soph, sopl),
                    "lower special ({soph:#04x}, {sopl})"
                );
            }
        }
    }

    #[test]
    fn documented_reserved_encodings_stay_reserved() {
        // Gaps the documented encoding leaves open must not decode.
        assert_eq!(decode_lower(0x0400_0000), None); // op2 0x02
        assert_eq!(decode_lower(0x3200_0000), None); // op2 0x19: reserved gap before fmand
        assert_eq!(decode_lower(0x0600_0000), None); // op2 0x03
        assert_eq!(decode_lower(0x8000_0001), None); // bit31 group primary 0x01
        assert_eq!(decode_upper(0x0000_043C), None); // upper special (0x10, 0): reserved
        assert_eq!(decode_upper(0x0000_07FC), None); // upper special (0x1F, 0): reserved
        assert_eq!(decode_lower(0x8000_047C), None); // lower special (0x11, 0): reserved
        // UNPACK vl=0b11 is reserved.
        assert_eq!(unpack_input_words(0x63, 4), None);
        assert_eq!(unpack_input_words(VIF_CMD_MPG, 4), None);
    }

    #[test]
    fn unpack_sizes_follow_the_packed_element_count() {
        // V4_32 x3: 3 elements * 4 vectors, 4 bytes each.
        assert_eq!(unpack_input_words(0x6C, 3), Some(12));
        // V2_16 x2: 2 * 2 16-bit elements = 4 words of input pairs.
        assert_eq!(unpack_input_words(0x65, 2), Some(2));
        // V1_8 x5: 5 bytes round up to 2 words.
        assert_eq!(unpack_input_words(0x60 | (0 << 2) | 2, 5), Some(2));
        // NUM = 0 encodes 256 elements.
        assert_eq!(unpack_input_words(0x6C, 0), Some(1024));
    }
}
